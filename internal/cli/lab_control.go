package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"dynamicflow/internal/lab"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/sshkeys"
)

type labControlPlane struct {
	ctx      *commandContext
	timeout  time.Duration
	interval time.Duration
}

func (control *labControlPlane) RotateSSHKey(operation context.Context, host lab.Host) (uint64, error) {
	if control == nil || control.ctx == nil {
		return 0, errors.New("lab control plane is unavailable")
	}
	local, err := loadLocalEnrollment(control.ctx, host.Name)
	if err != nil || local.State == "revoked" || local.KeyScope != sshkeys.Instance || local.KeyName != host.Name {
		return 0, errors.New("lab key rotation requires the active dedicated per-instance key")
	}
	manager := sshkeys.NewManager(control.ctx.store)
	active, err := manager.Get(local.KeyScope, local.KeyName)
	if err != nil || active.Status != sshkeys.ActiveStatus {
		return 0, errors.New("dedicated instance key is unavailable")
	}
	// A previous interrupted lab may already have rotated locally or published
	// the overlap generation. Resume it; never manufacture another generation.
	if active.Generation == local.KeyGeneration && !local.RotationPending {
		if status := runLabNested(control.ctx, func(nested *commandContext) int {
			return commandKey(nested, []string{"rotate", "--name", local.KeyName, "--scope", string(sshkeys.Instance)})
		}); status != exitOK {
			return 0, errors.New("local per-instance key rotation failed")
		}
	}
	if !local.RotationPending {
		if status := runLabNested(control.ctx, func(nested *commandContext) int {
			return instanceApplyHTTPS(nested, []string{host.Name, "--profile", local.Profile})
		}); status != exitOK {
			return 0, errors.New("signed overlap desired state was not published")
		}
		local, err = loadLocalEnrollment(control.ctx, host.Name)
		if err != nil || !local.RotationPending {
			return 0, errors.New("rotation overlap checkpoint was not stored")
		}
	}
	overlapGeneration := local.Desired.State.Generation
	if err := control.waitForStatus(operation, host.Name, overlapGeneration, func(report serving.StatusReport) bool {
		return report.State == "ready" && report.AppliedGeneration == overlapGeneration
	}); err != nil {
		return 0, errors.New("target did not acknowledge the SSH overlap generation")
	}
	if status := runLabNested(control.ctx, func(nested *commandContext) int {
		return instanceApplyHTTPS(nested, []string{host.Name, "--profile", local.Profile})
	}); status != exitOK {
		return 0, errors.New("signed old-key removal generation was not published")
	}
	local, err = loadLocalEnrollment(control.ctx, host.Name)
	if err != nil || local.RotationPending || local.Desired.State.Generation <= overlapGeneration || len(local.Desired.State.AuthorizedSSHKeys) != 1 {
		return 0, errors.New("old-key removal checkpoint is incomplete")
	}
	finalGeneration := local.Desired.State.Generation
	if err := control.waitForStatus(operation, host.Name, finalGeneration, func(report serving.StatusReport) bool {
		return report.State == "ready" && report.AppliedGeneration == finalGeneration
	}); err != nil {
		return 0, errors.New("target did not acknowledge removal of the old SSH key")
	}
	return finalGeneration, nil
}

func (control *labControlPlane) RotateVNCSecret(_ context.Context, host lab.Host) error {
	if control == nil || control.ctx == nil || host.Role != "pbp" {
		return errors.New("lab VNC credential rotation requires the PBP role")
	}
	var stdout, stderr bytes.Buffer
	nested := *control.ctx
	nested.out = &emitter{json: true, stdout: &stdout, stderr: &stderr}
	defer func() {
		clear(stdout.Bytes())
		clear(stderr.Bytes())
	}()
	status := instanceSecret(&nested, []string{"rotate", host.Name, "--secret", "vnc"})
	if status != exitOK || stdout.Len() == 0 || stdout.Len() > 4096 || stderr.Len() != 0 {
		audit(control.ctx, "test.lab.control.vnc-rotate", "failure", map[string]any{"instance": host.Name, "output_suppressed": true})
		return errors.New("fixed VNC credential rotation failed")
	}
	audit(control.ctx, "test.lab.control.vnc-rotate", "success", map[string]any{"instance": host.Name, "output_suppressed": true})
	return nil
}

func (control *labControlPlane) RevokeInstance(operation context.Context, host lab.Host) (uint64, error) {
	if control == nil || control.ctx == nil {
		return 0, errors.New("lab control plane is unavailable")
	}
	local, err := loadLocalEnrollment(control.ctx, host.Name)
	if err != nil {
		return 0, errors.New("local enrollment metadata is unavailable")
	}
	if local.State != "revoked" {
		if status := runLabNested(control.ctx, func(nested *commandContext) int {
			return instanceRevokeHTTPS(nested, []string{host.Name})
		}); status != exitOK {
			return 0, errors.New("signed revocation was not published")
		}
		local, err = loadLocalEnrollment(control.ctx, host.Name)
		if err != nil {
			return 0, errors.New("local revocation checkpoint is unavailable")
		}
	}
	generation := local.Desired.State.Generation
	if generation == 0 || !local.Desired.State.Revoked || len(local.Desired.State.AuthorizedSSHKeys) != 0 {
		return 0, errors.New("local desired state is not fail-closed revoked")
	}
	if err := control.waitForStatus(operation, host.Name, generation, func(report serving.StatusReport) bool {
		return report.DesiredGeneration == generation && serving.IsRevocationAcknowledgement(report)
	}); err != nil {
		return 0, errors.New("target did not report the signed fail-closed revocation acknowledgement")
	}
	if err := control.waitForRevocationLog(operation, host.Name); err != nil {
		return 0, errors.New("target revocation acknowledgement lacks the finite critical fail-closed log event")
	}
	return generation, nil
}

func (control *labControlPlane) waitForRevocationLog(operation context.Context, name string) error {
	remote, err := loadRemoteServing(control.ctx)
	if err != nil {
		return err
	}
	timeout := control.timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	interval := control.interval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	waitContext, cancel := context.WithTimeout(operation, timeout)
	defer cancel()
	for {
		requestContext, requestCancel := context.WithTimeout(waitContext, 30*time.Second)
		var snapshot serving.LogSnapshot
		requestErr := remote.controlJSON(requestContext, http.MethodGet, "/v1/admin/instances/"+name+"/logs/ssh", nil, &snapshot, http.StatusOK)
		requestCancel()
		if requestErr == nil && serving.ValidateLogSnapshot(snapshot) == nil && snapshot.Instance == name && snapshot.Component == "ssh" {
			for _, event := range snapshot.Events {
				if event.Level == "critical" && event.Event == "phase_fail_closed" && event.Code == "revoked" {
					return nil
				}
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return waitContext.Err()
		case <-timer.C:
		}
	}
}

func (control *labControlPlane) waitForStatus(operation context.Context, name string, generation uint64, accepted func(serving.StatusReport) bool) error {
	remote, err := loadRemoteServing(control.ctx)
	if err != nil {
		return err
	}
	timeout := control.timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	interval := control.interval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	waitContext, cancel := context.WithTimeout(operation, timeout)
	defer cancel()
	for {
		requestContext, requestCancel := context.WithTimeout(waitContext, 30*time.Second)
		var report serving.StatusReport
		requestErr := remote.controlJSON(requestContext, http.MethodGet, "/v1/admin/instances/"+name+"/status", nil, &report, http.StatusOK)
		requestCancel()
		if requestErr == nil && serving.ValidateStatus(report) == nil && report.Instance == name &&
			report.DesiredGeneration == generation && accepted(report) {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return waitContext.Err()
		case <-timer.C:
		}
	}
}

func runLabNested(ctx *commandContext, command func(*commandContext) int) int {
	var stdout, stderr bytes.Buffer
	nested := *ctx
	nested.out = &emitter{json: true, stdout: &stdout, stderr: &stderr}
	status := command(&nested)
	if status != exitOK {
		audit(ctx, "test.lab.control", "failure", map[string]any{"exit_code": status, "output_suppressed": true})
		return status
	}
	if stdout.Len() == 0 || stdout.Len() > 1<<20 || stderr.Len() != 0 {
		audit(ctx, "test.lab.control", "failure", map[string]any{"exit_code": exitVerify, "invalid_envelope": true})
		return exitVerify
	}
	envelope := cliEnvelopeForLab{}
	if err := decodeSingleLabEnvelope(stdout.Bytes(), &envelope); err != nil || !envelope.OK {
		audit(ctx, "test.lab.control", "failure", map[string]any{"exit_code": exitVerify, "invalid_envelope": true})
		return exitVerify
	}
	return exitOK
}

type cliEnvelopeForLab struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Data    any    `json:"data"`
}

func decodeSingleLabEnvelope(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
