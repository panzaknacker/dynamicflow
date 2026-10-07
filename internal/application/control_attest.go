package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controltransport"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/netpolicy"
	"dynamicflow/internal/sshtransport"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

type AttestControlRequest struct {
	Meta RequestMeta `json:"meta"`
	Name string      `json:"name"`
}

type AttestControlPlan struct {
	Plan                  bool     `json:"plan"`
	SystemID              string   `json:"system_id"`
	ControlName           string   `json:"control_name"`
	ManagementFingerprint string   `json:"management_fingerprint"`
	HostKeyFingerprint    string   `json:"host_key_fingerprint"`
	PolicyGeneration      uint64   `json:"policy_generation"`
	EnvelopeDigest        string   `json:"envelope_digest"`
	Route                 string   `json:"route"`
	NetworkConnections    int      `json:"network_connections"`
	ResumesFailedTask     bool     `json:"resumes_failed_task"`
	Changes               []string `json:"changes"`
	ControlReady          bool     `json:"control_ready"`
}

// ControlProofEvidence is an owner-local receipt of a fresh challenge response.
// It proves management access only. It never authorizes bootstrap revocation
// or transitions the system, topology or Control lifecycle to ready.
type ControlProofEvidence struct {
	SchemaVersion         int       `json:"schema_version"`
	SystemID              string    `json:"system_id"`
	ControlName           string    `json:"control_name"`
	ManagementFingerprint string    `json:"management_fingerprint"`
	ManagementGeneration  uint64    `json:"management_generation"`
	HostKeyFingerprint    string    `json:"host_key_fingerprint"`
	PolicyGeneration      uint64    `json:"policy_generation"`
	EnvelopeDigest        string    `json:"envelope_digest"`
	ExecutableDigest      string    `json:"executable_digest"`
	VerifiedAt            time.Time `json:"verified_at"`
	RemoteObservedAt      time.Time `json:"remote_observed_at"`
}

type AttestControlResult struct {
	Verified           bool                               `json:"verified"`
	Evidence           ControlProofEvidence               `json:"evidence"`
	Transport          controltransport.AttestationResult `json:"transport"`
	Task               workflow.Task                      `json:"task"`
	NetworkConnections int                                `json:"network_connections"`
	BootstrapRevoked   bool                               `json:"bootstrap_revoked"`
	ControlReady       bool                               `json:"control_ready"`
}

type controlAttestationContext struct {
	system   systemstate.System
	store    *localstate.Store
	binding  controlBindingContext
	record   controlnodes.Record
	prepared preparedControlEnvelope
	install  controlInstallEvidence
	pending  sshtransport.PendingControlProof
}

func (application *Application) PlanControlAttest(ctx context.Context, request AttestControlRequest) (AttestControlPlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return AttestControlPlan{}, appError("cancelled", 8, "Control attestation plan was cancelled.", "Retry the plan.", nil)
	}
	if err := application.checkSystemExpectation(request.Meta); err != nil {
		return AttestControlPlan{}, err
	}
	state, err := application.controlAttestationContext(request.Name)
	if err != nil {
		return AttestControlPlan{}, err
	}
	if err := validateSystemExpectation(request.Meta, state.system.ID); err != nil {
		return AttestControlPlan{}, err
	}
	return AttestControlPlan{
		Plan: true, SystemID: state.system.ID, ControlName: state.record.Name,
		ManagementFingerprint: state.record.Access.Pending.Fingerprint, HostKeyFingerprint: state.record.HostFingerprint,
		PolicyGeneration: state.install.PolicyGeneration, EnvelopeDigest: state.prepared.digest,
		Route: string(netpolicy.ModeDirectControlProof), NetworkConnections: 1,
		ResumesFailedTask: state.binding.task.Phase == workflow.PhaseFailedSafe,
		Changes:           []string{"authenticate once with the staged management key and independently pinned host key", "verify a fresh challenge against the exact installed policy", "persist management-access evidence; bootstrap revocation and activation remain pending"},
	}, nil
}

func (application *Application) AttestControl(ctx context.Context, request AttestControlRequest, observer Observer) (AttestControlResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return AttestControlResult{}, appError("cancelled", 8, "Control attestation was cancelled.", "Retry the explicit attestation.", nil)
	}
	if application == nil || application.store == nil || application.systems == nil {
		return AttestControlResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	active, err := application.systems.Active()
	if err != nil {
		return AttestControlResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Install the first Control runtime.", err)
	}
	if err := validateSystemExpectation(request.Meta, active.ID); err != nil {
		return AttestControlResult{}, err
	}
	var result AttestControlResult
	err = application.store.WithTryLock(filepath.Join("systems", active.ID, "operations", "control-bootstrap.lock"), func() error {
		state, err := application.controlAttestationContext(request.Name)
		if err != nil {
			return err
		}
		if state.system.ID != active.ID {
			return errors.New("active system changed during attestation")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		task := state.binding.task
		if task.Phase == workflow.PhaseFailedSafe {
			task, err = state.binding.workflows.Resume(task.ID, task.Revision)
			if err != nil {
				return err
			}
		}
		decision, err := authorizeFirstControlNetwork(state.system.ID, state.record, netpolicy.ActionControlAttest)
		if err != nil {
			return err
		}
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.attest", "outcome": "intent",
			"fields": map[string]any{"system_id": state.system.ID, "control": state.record.Name, "task_id": task.ID, "network_policy": decision, "management_fingerprint": state.record.Access.Pending.Fingerprint, "envelope_digest": state.prepared.digest},
		}); err != nil {
			return err
		}
		notify(observer, "control_attest", "running", "proving the staged management identity through one pinned challenge-response session")
		transport := controltransport.New(sshtransport.NewBuilder(state.store), application.controlRunner, controltransport.WithClock(application.now))
		proof, err := transport.AttestPendingControl(ctx, controltransport.AttestationRequest{
			Pending: state.pending, SystemID: state.system.ID, ControlName: state.record.Name,
			Generation: state.install.PolicyGeneration, EnvelopeDigest: state.prepared.digest,
		})
		if err != nil {
			_, checkpointErr := state.binding.workflows.FailSafe(task.ID, task.Revision, "control_attestation", "Run flow control attest with the same Control name after repairing the management path.")
			if checkpointErr != nil {
				return checkpointErr
			}
			if auditErr := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
				"time": application.now().UTC(), "action": "control.attest", "outcome": "failed",
				"fields": map[string]any{"system_id": state.system.ID, "control": state.record.Name, "attempts": proof.Attempts},
			}); auditErr != nil {
				return auditErr
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return appError("cancelled", 8, "Control attestation stopped at a fail-safe checkpoint.", "Explicitly retry flow control attest to request a fresh challenge.", err)
			}
			return appError("control_attestation", 7, "The staged Control management identity or active policy could not be verified.", "Inspect Control status and explicitly retry flow control attest; no fallback was used.", err)
		}
		evidence := ControlProofEvidence{
			SchemaVersion: 1, SystemID: state.system.ID, ControlName: state.record.Name,
			ManagementFingerprint: state.record.Access.Pending.Fingerprint, ManagementGeneration: state.record.Access.Pending.Generation,
			HostKeyFingerprint: state.record.HostFingerprint, PolicyGeneration: state.install.PolicyGeneration,
			EnvelopeDigest: state.prepared.digest, ExecutableDigest: state.install.ExecutableDigest,
			VerifiedAt: application.now().UTC(), RemoteObservedAt: proof.Response.ObservedAt,
		}
		if err := state.store.WriteJSON(controlProofRelative(state.record.Name), evidence); err != nil {
			return err
		}
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": evidence.VerifiedAt, "action": "control.attest", "outcome": "verified",
			"fields": map[string]any{"system_id": state.system.ID, "control": state.record.Name, "management_fingerprint": evidence.ManagementFingerprint, "envelope_digest": evidence.EnvelopeDigest, "network_connections": proof.Attempts, "control_ready": false},
		}); err != nil {
			return err
		}
		result = AttestControlResult{Verified: true, Evidence: evidence, Transport: proof, Task: task, NetworkConnections: proof.Attempts}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return AttestControlResult{}, failure
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return AttestControlResult{}, appError("cancelled", 8, "Control attestation was interrupted.", "Retry the explicit attestation.", err)
		}
		if errors.Is(err, localstate.ErrLockBusy) || errors.Is(err, workflow.ErrConflict) || errors.Is(err, controlnodes.ErrRevisionConflict) {
			return AttestControlResult{}, appError("control_conflict", 6, "Another Control operation is active or the checkpoint changed.", "Refresh Control status and retry the explicit attestation.", err)
		}
		return AttestControlResult{}, appError("control_attestation_state", 5, "The Control attestation checkpoint could not be verified or saved.", "Inspect the private task and audit state before retrying.", err)
	}
	notify(observer, "control_attest", "complete", "management access verified; bootstrap revocation and Control activation remain pending")
	return result, nil
}

func (application *Application) controlAttestationContext(name string) (controlAttestationContext, error) {
	if application == nil || application.systems == nil || application.store == nil {
		return controlAttestationContext{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	system, store, binding, manager, record, err := application.controlInstallContextWithResume(name, true)
	if err != nil {
		return controlAttestationContext{}, err
	}
	validTask := binding.task.Phase == workflow.PhaseAttesting ||
		(binding.task.Phase == workflow.PhaseFailedSafe && binding.task.ResumePhase == workflow.PhaseAttesting && binding.task.Failure != nil && binding.task.Failure.Code == "control_attestation")
	if !validTask || system.Bootstrap.State != systemstate.BootstrapProvisioning || record.Lifecycle != controlnodes.LifecycleInstalling || record.Access.Phase != controlnodes.AccessStaged {
		return controlAttestationContext{}, appError("control_attestation_checkpoint", 6, "Control is not at the installed management-attestation checkpoint.", "Run flow control apply for the prepared Control first.", nil)
	}
	prepared, err := application.readPreparedControlEnvelope(store, system, record)
	if err != nil {
		return controlAttestationContext{}, appError("control_install_envelope", 5, "The signed installed Control envelope is invalid or expired.", "Recover the exact policy before opening a connection.", err)
	}
	if err := preparedEnvelopeMatchesRecord(prepared, record); err != nil {
		return controlAttestationContext{}, appError("control_install_envelope", 5, "The installed policy does not match the staged management identity.", "Recover the exact prepared policy and key.", err)
	}
	installed, err := readControlInstallEvidence(store, system.ID, record.Name, prepared)
	if err != nil {
		return controlAttestationContext{}, appError("control_install_evidence", 5, "Authenticated Control installation evidence is unavailable.", "Complete or recover the exact Control installation.", err)
	}
	document, err := topology.NewStore(store).Load()
	expected := topology.Control{Name: record.Name, Host: record.Host, SSHPort: record.Port, SSHUser: record.SSHUser, Trust: topology.TrustPinned, HostKeyFingerprint: record.HostFingerprint}
	if err != nil || document.Control == nil || *document.Control != expected || document.ControlReady {
		return controlAttestationContext{}, appError("topology_state", 5, "Control topology differs from the independently pinned pending route.", "Recover the exact Control topology; no alternate endpoint is permitted.", err)
	}
	if _, err := authorizeFirstControlNetwork(system.ID, record, netpolicy.ActionControlAttest); err != nil {
		return controlAttestationContext{}, err
	}
	material, err := manager.PendingAccessMaterial(system.ID, record.Name)
	if err != nil {
		return controlAttestationContext{}, appError("management_identity", 5, "The exact staged management identity is unavailable.", "Recover the original management key; no bootstrap fallback is permitted.", err)
	}
	identity, err := sshtransport.NewPrivateIdentity(material.IdentityPath)
	if err != nil {
		return controlAttestationContext{}, appError("management_identity", 5, "The staged management private key is unsafe.", "Repair its ownership, mode and single-link file invariant.", err)
	}
	state := controlAttestationContext{system: system, store: store, binding: binding, record: record, prepared: prepared, install: installed,
		pending: sshtransport.PendingControlProof{
			Control: sshtransport.Endpoint{Alias: record.Name, Role: sshtransport.RoleControl, Host: record.Host, Port: record.Port,
				User: material.SSHUser, Identity: identity, IdentityFingerprint: material.Identity.Fingerprint,
				HostKey: strings.Join(strings.Fields(record.HostPublicKey)[:2], " "), HostKeyFingerprint: record.HostFingerprint},
			ControlHostKeyFingerprint: record.HostFingerprint, BootstrapIdentityFingerprint: record.BootstrapKey.Fingerprint, Phase: sshtransport.PhasePendingManagementProof,
		},
	}
	var previous ControlProofEvidence
	if err := store.ReadJSON(controlProofRelative(record.Name), &previous); err == nil {
		if previous.SchemaVersion != 1 || previous.SystemID != system.ID || previous.ControlName != record.Name ||
			previous.ManagementFingerprint != record.Access.Pending.Fingerprint || previous.ManagementGeneration != record.Access.Pending.Generation ||
			previous.HostKeyFingerprint != record.HostFingerprint || previous.PolicyGeneration != installed.PolicyGeneration ||
			previous.EnvelopeDigest != prepared.digest || previous.ExecutableDigest != installed.ExecutableDigest ||
			!validUTCTime(previous.VerifiedAt) || !validUTCTime(previous.RemoteObservedAt) {
			return controlAttestationContext{}, appError("control_proof_evidence", 5, "Existing management proof belongs to inconsistent Control state.", "Inspect the owner-local proof before retrying.", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return controlAttestationContext{}, appError("control_proof_evidence", 5, "Existing management proof could not be read safely.", "Inspect the owner-local proof before retrying.", err)
	}
	return state, nil
}

func controlProofRelative(name string) string {
	return filepath.Join("control", "install", name, "management-proof-g1.json")
}
