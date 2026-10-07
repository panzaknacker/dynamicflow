package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/applyplan"
	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instanceclient"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/profiles"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/targetapply"
)

type runtimeInputCall struct {
	prompt string
	hidden bool
	limit  int
}

type fakeRuntimeInput struct {
	fields    [][]byte
	calls     []runtimeInputCall
	index     int
	finalized bool
	closed    bool
}

func (input *fakeRuntimeInput) ReadField(prompt string, hidden bool, maximum int) ([]byte, error) {
	input.calls = append(input.calls, runtimeInputCall{prompt: prompt, hidden: hidden, limit: maximum})
	if input.index >= len(input.fields) {
		return nil, io.EOF
	}
	value := append([]byte(nil), input.fields[input.index]...)
	input.index++
	return value, nil
}

func (input *fakeRuntimeInput) Finalize() error {
	input.finalized = true
	if input.index != len(input.fields) {
		return errRuntimeInput
	}
	return nil
}

func (input *fakeRuntimeInput) Close() error {
	input.closed = true
	return nil
}

type fakeRuntimeClient struct {
	keyID        string
	state        instanceclient.State
	enrollResult instanceclient.EnrollmentResult
	enrollError  error
	fetchResult  instanceclient.EnrollmentResult
	fetchError   error
	enrollmentID string
	secret       []byte
	readSecret   bool
	enrollCalls  int
	fetchCalls   int
	closeCalls   int
	downloads    []release.Component
	statuses     []serving.StatusReport
	logs         []serving.LogBatch
	downloadData map[string][]byte
	downloadErr  error
	statusErr    error
	logErr       error
}

func (client *fakeRuntimeClient) Enroll(_ context.Context, enrollmentID string, secret io.Reader) (instanceclient.EnrollmentResult, error) {
	client.enrollCalls++
	client.enrollmentID = enrollmentID
	if client.readSecret {
		value, err := io.ReadAll(secret)
		if err != nil {
			return instanceclient.EnrollmentResult{}, err
		}
		client.secret = value
	}
	return client.enrollResult, client.enrollError
}

func (client *fakeRuntimeClient) FetchDesired(_ context.Context) (instanceclient.EnrollmentResult, error) {
	client.fetchCalls++
	return client.fetchResult, client.fetchError
}

func (client *fakeRuntimeClient) DownloadArtifact(_ context.Context, _ release.SignedManifest, component release.Component, destination io.Writer) error {
	client.downloads = append(client.downloads, component)
	if client.downloadErr != nil {
		return client.downloadErr
	}
	data, exists := client.downloadData[component.Digest]
	if !exists {
		return instanceclient.ErrArtifactNotBound
	}
	_, err := destination.Write(data)
	return err
}

func (client *fakeRuntimeClient) ReportStatus(_ context.Context, report serving.StatusReport) error {
	client.statuses = append(client.statuses, report)
	return client.statusErr
}

func (client *fakeRuntimeClient) ReportLogs(_ context.Context, batch serving.LogBatch) error {
	client.logs = append(client.logs, batch)
	return client.logErr
}

func (client *fakeRuntimeClient) State() instanceclient.State { return client.state }
func (client *fakeRuntimeClient) IdentityKeyID() string       { return client.keyID }
func (client *fakeRuntimeClient) Close() error {
	client.closeCalls++
	return nil
}

type runtimeTestFixture struct {
	stateRoot   string
	caPath      string
	releasePath string
	desiredPath string
	server      string
	pin         string
	instance    string
	profile     string
	id          string
	secret      string
	keyID       string
	adminUser   string
	now         time.Time
	result      instanceclient.EnrollmentResult
	publicData  map[string][]byte
	artifacts   map[string][]byte
	desiredKey  ed25519.PrivateKey
}

func TestInstanceRuntimeEnrollNoCredentialLeak(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	var receivedConfig instanceclient.Config
	deps := fixture.dependencies(input, func(config instanceclient.Config) (instanceRuntimeClient, error) {
		receivedConfig = config
		return client, nil
	})
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" {
		t.Fatalf("enroll status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if client.enrollCalls != 1 || client.fetchCalls != 0 || client.enrollmentID != fixture.id || string(client.secret) != fixture.secret {
		t.Fatalf("client did not receive exact in-memory credential: enroll=%d fetch=%d", client.enrollCalls, client.fetchCalls)
	}
	if receivedConfig.Instance != fixture.instance || receivedConfig.Profile != fixture.profile ||
		receivedConfig.StateDir != fixture.stateRoot || receivedConfig.ExpectedIdentityKeyID != "" {
		t.Fatalf("unexpected client config: %+v", receivedConfig)
	}
	if len(input.calls) != 4 || input.calls[0].hidden || input.calls[1].hidden || !input.calls[2].hidden || !input.calls[3].hidden ||
		!input.finalized || !input.closed {
		t.Fatalf("TTY visibility/finalization contract violated: %+v finalized=%v closed=%v", input.calls, input.finalized, input.closed)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.instance, fixture.profile, fixture.id, fixture.secret)
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "instance-runtime.enroll" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	configPath := filepath.Join(fixture.stateRoot, instanceRuntimeConfigPath)
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != localstate.FileMode {
		t.Fatalf("runtime config is not regular mode 0600: %v, %v", info, err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(fixture.id)) || bytes.Contains(data, []byte(fixture.secret)) {
		t.Fatal("runtime config persisted enrollment credential")
	}
	var persisted instanceRuntimeConfig
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Instance != fixture.instance || persisted.Profile != fixture.profile || persisted.AdminUser != fixture.adminUser || persisted.IdentityKeyID != fixture.keyID {
		t.Fatalf("public runtime binding was not persisted: %+v", persisted)
	}
	assertRuntimeTreeDoesNotContain(t, fixture.stateRoot, fixture.id, fixture.secret)
	if joined := strings.Join(fixture.enrollArguments(), "\x00"); strings.Contains(joined, fixture.instance) ||
		strings.Contains(joined, fixture.profile) || strings.Contains(joined, fixture.id) || strings.Contains(joined, fixture.secret) {
		t.Fatal("instance binding or enrollment credential entered argv")
	}
}

func TestInstanceRuntimeSecretIsLazyAndHidden(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.enrollError = instanceclient.ErrTLSPin
	client.readSecret = false
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitVerify || stdout != "" {
		t.Fatalf("wrong-pin status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if len(input.calls) != 3 || input.calls[0].hidden || input.calls[1].hidden || !input.calls[2].hidden {
		t.Fatalf("secret was requested before client trust preflight: %+v", input.calls)
	}
	if input.finalized {
		t.Fatal("stdin was finalized even though the secret was never requested")
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.instance, fixture.profile, fixture.id, fixture.secret)
	if _, err := os.Lstat(filepath.Join(fixture.stateRoot, instanceRuntimeConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime config written after failed verification: %v", err)
	}
}

func TestInstanceRuntimeRecoversUnknownEnrollmentOutcome(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	client.enrollError = fmt.Errorf("%w: connection closed", instanceclient.ErrEnrollmentOutcomeUnknown)
	client.fetchResult = fixture.result
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" || client.enrollCalls != 1 || client.fetchCalls != 1 {
		t.Fatalf("recovery status=%d enroll=%d fetch=%d stdout=%q stderr=%q", status, client.enrollCalls, client.fetchCalls, stdout, stderr)
	}
	if !strings.Contains(stdout, `"recovered":true`) {
		t.Fatalf("recovery not represented in JSON: %s", stdout)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.id, fixture.secret)
	assertRuntimeTreeDoesNotContain(t, fixture.stateRoot, fixture.id, fixture.secret)

	// A subsequent idempotent enroll uses the public config and pinned stable
	// identity; it must not open or consume credential input again.
	second := newFakeRuntimeClient(fixture)
	second.fetchResult = fixture.result
	inputOpened := false
	secondDeps := fixture.dependencies(nil, func(config instanceclient.Config) (instanceRuntimeClient, error) {
		if config.ExpectedIdentityKeyID != fixture.keyID {
			t.Fatalf("expected stable identity pin %q, got %q", fixture.keyID, config.ExpectedIdentityKeyID)
		}
		return second, nil
	})
	secondDeps.openInput = func(io.Reader) (instanceRuntimeInput, error) {
		inputOpened = true
		return nil, errors.New("must not open input")
	}
	status, stdout, stderr = invokeInstanceRuntime(t, fixture.enrollArguments(), secondDeps)
	if status != exitOK || stderr != "" || inputOpened || second.fetchCalls != 1 || second.enrollCalls != 0 {
		t.Fatalf("idempotent recovery status=%d input=%v enroll=%d fetch=%d stdout=%q stderr=%q", status, inputOpened, second.enrollCalls, second.fetchCalls, stdout, stderr)
	}
}

func TestInstanceRuntimeRejectsCredentialArgumentsWithoutEcho(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	tests := [][]string{
		append(fixture.enrollArguments(), fixture.secret),
		append(fixture.enrollArguments(), "--secret="+fixture.secret),
		append(fixture.enrollArguments(), "--instance="+fixture.instance),
		append(fixture.enrollArguments(), "--profile="+fixture.profile),
		append(fixture.enrollArguments(), "--enrollment-id="+fixture.id),
	}
	for index, arguments := range tests {
		inputOpened := false
		deps := fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) {
			t.Fatal("client created for rejected argv")
			return nil, nil
		})
		deps.openInput = func(io.Reader) (instanceRuntimeInput, error) {
			inputOpened = true
			return nil, errRuntimeInput
		}
		status, stdout, stderr := invokeInstanceRuntime(t, arguments, deps)
		if status != exitUsage || stdout != "" || inputOpened {
			t.Fatalf("case %d status=%d input=%v stdout=%q stderr=%q", index, status, inputOpened, stdout, stderr)
		}
		assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.instance, fixture.profile, fixture.id, fixture.secret)
	}
}

func TestInstanceRuntimePlatformChecksBeforeInputStateOrNetwork(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	for _, test := range []struct {
		name string
		goos string
		uid  int
		euid int
		want int
	}{
		{name: "non-linux", goos: "freebsd", uid: 0, euid: 0, want: exitConfig},
		{name: "real uid", goos: "linux", uid: 1000, euid: 0, want: exitAuth},
		{name: "effective uid", goos: "linux", uid: 0, euid: 1000, want: exitAuth},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputOpened, fileRead, clientCreated := false, false, false
			deps := fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) {
				clientCreated = true
				return nil, errors.New("unexpected")
			})
			deps.goos, deps.uid, deps.euid = test.goos, func() int { return test.uid }, func() int { return test.euid }
			deps.openInput = func(io.Reader) (instanceRuntimeInput, error) {
				inputOpened = true
				return nil, errRuntimeInput
			}
			deps.readPublicFile = func(string, int64) ([]byte, error) {
				fileRead = true
				return nil, errRuntimeConfiguration
			}
			status, _, _ := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
			if status != test.want || inputOpened || fileRead || clientCreated {
				t.Fatalf("status=%d input=%v file=%v client=%v", status, inputOpened, fileRead, clientCreated)
			}
			if _, err := os.Lstat(fixture.stateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state touched before platform preflight: %v", err)
			}
		})
	}
}

func TestInstanceRuntimeValidatesAdminBeforeCredentialInputOrNetwork(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	inputOpened, clientCreated := false, false
	deps := fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) {
		clientCreated = true
		return nil, errors.New("unexpected")
	})
	deps.validateAdmin = func(name string) error {
		if name != fixture.adminUser {
			t.Fatalf("validated admin=%q", name)
		}
		return targetapply.ErrInvalidConfig
	}
	deps.openInput = func(io.Reader) (instanceRuntimeInput, error) {
		inputOpened = true
		return nil, errRuntimeInput
	}
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitConfig || stdout != "" || inputOpened || clientCreated {
		t.Fatalf("status=%d input=%v client=%v stdout=%q stderr=%q", status, inputOpened, clientCreated, stdout, stderr)
	}
	if _, err := os.Lstat(fixture.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state opened before admin validation: %v", err)
	}
	unsafeArguments := fixture.enrollArguments()
	for index := range unsafeArguments {
		if unsafeArguments[index] == fixture.adminUser {
			unsafeArguments[index] = "root"
		}
	}
	status, stdout, stderr = invokeInstanceRuntime(t, unsafeArguments, deps)
	if status != exitUsage || stdout != "" || inputOpened || clientCreated {
		t.Fatalf("unsafe root status=%d input=%v client=%v stdout=%q stderr=%q", status, inputOpened, clientCreated, stdout, stderr)
	}
}

func TestInstanceRuntimeReconcileAndLocalStatus(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	persistRuntimeFixtureConfig(t, fixture)
	reconcileClient := newFakeRuntimeClient(fixture)
	reconcileClient.fetchResult = fixture.result
	deps := fixture.dependencies(nil, func(config instanceclient.Config) (instanceRuntimeClient, error) {
		if config.ExpectedIdentityKeyID != fixture.keyID {
			t.Fatalf("identity key was not pinned: %+v", config)
		}
		return reconcileClient, nil
	})
	status, stdout, stderr := invokeInstanceRuntime(t, []string{"reconcile", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || stderr != "" || reconcileClient.fetchCalls != 1 || reconcileClient.enrollCalls != 0 {
		t.Fatalf("reconcile status=%d fetch=%d stdout=%q stderr=%q", status, reconcileClient.fetchCalls, stdout, stderr)
	}

	statusClient := newFakeRuntimeClient(fixture)
	statusClient.state = fixture.result.State
	deps = fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) { return statusClient, nil })
	status, stdout, stderr = invokeInstanceRuntime(t, []string{"status", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || stderr != "" || statusClient.fetchCalls != 0 || statusClient.enrollCalls != 0 ||
		!strings.Contains(stdout, `"local_only":true`) {
		t.Fatalf("status status=%d fetch=%d stdout=%q stderr=%q", status, statusClient.fetchCalls, stdout, stderr)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.instance, fixture.profile, fixture.id, fixture.secret)
}

func TestInstanceRuntimeAppliesVerifiedPlanDownloadsExactArtifactsAndReports(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	var phaseNames []string
	deps.runApply = func(ctx context.Context, config targetapply.Config) (targetapply.Result, error) {
		if config.StateRoot != fixture.stateRoot || config.AdminUser != fixture.adminUser || config.Plan.Profile != "pbp" {
			t.Fatalf("apply config was not bound to runtime config: %#v", config)
		}
		for _, phase := range config.Plan.Phases {
			phaseNames = append(phaseNames, phase.Profile)
			for _, step := range phase.Steps {
				var downloaded bytes.Buffer
				if err := config.FetchArtifact(ctx, step.Artifact, &downloaded); err != nil {
					t.Fatalf("download %s: %v", step.ID, err)
				}
				if !bytes.Equal(downloaded.Bytes(), fixture.artifacts[step.Artifact.Digest]) {
					t.Fatalf("download %s differs from signed payload", step.ID)
				}
			}
			for _, state := range []string{"preflight", "applying", "verifying", "complete"} {
				config.Event(phase.Profile, state, "")
			}
		}
		return successfulRuntimeApplyResult(config.Plan, fixture.now), nil
	}
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" {
		t.Fatalf("apply status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	wantPhases := []string{"flow", "ssh", "ssh-gui", "vpn-pbp-de", "pbp"}
	if strings.Join(phaseNames, ",") != strings.Join(wantPhases, ",") {
		t.Fatalf("PBP phases=%v, want %v", phaseNames, wantPhases)
	}
	for _, phase := range phaseNames {
		if phase == "vpn" {
			t.Fatal("normal Firefox VPN phase entered PBP apply")
		}
	}
	if len(client.downloads) != len(wantPhases) {
		t.Fatalf("downloads=%d, want %d", len(client.downloads), len(wantPhases))
	}
	for _, component := range client.downloads {
		found := false
		for _, signedComponent := range fixture.result.Release.Manifest.Components {
			if component == signedComponent {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("download was not an exact signed component: %#v", component)
		}
	}
	if len(client.statuses) < 3 || client.statuses[0].State != "pending" || client.statuses[0].AppliedGeneration != 0 {
		t.Fatalf("missing pre-apply status: %#v", client.statuses)
	}
	finalStatus := client.statuses[len(client.statuses)-1]
	if finalStatus.State != "ready" || finalStatus.AppliedGeneration != fixture.result.Desired.State.Generation ||
		finalStatus.SSHHostKey != runtimeTestOpenSSHKey(false) {
		t.Fatalf("wrong final status: %#v", finalStatus)
	}
	for _, component := range finalStatus.Components {
		if component.State != "ready" || component.Code != "" {
			t.Fatalf("non-ready final component: %#v", component)
		}
	}
	wantEvents := map[string]bool{
		"reconcile_started": true, "phase_preflight": true, "phase_applying": true,
		"phase_verifying": true, "phase_complete": true, "reconcile_complete": true,
	}
	lastSequence := map[string]uint64{}
	for _, batch := range client.logs {
		if len(batch.Events) != 1 || !wantEvents[batch.Events[0].Event] || batch.Events[0].Code != "" {
			t.Fatalf("unsafe or unexpected log batch: %#v", batch)
		}
		event := batch.Events[0]
		if event.Sequence != lastSequence[batch.Component]+1 {
			t.Fatalf("component %s sequence=%d after %d", batch.Component, event.Sequence, lastSequence[batch.Component])
		}
		lastSequence[batch.Component] = event.Sequence
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var data struct {
		ProfileApplied    bool   `json:"profile_applied"`
		AppliedGeneration uint64 `json:"applied_generation"`
		PlanID            string `json:"plan_id"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil || !data.ProfileApplied ||
		data.AppliedGeneration != fixture.result.Desired.State.Generation || !strings.HasPrefix(data.PlanID, "sha256:") {
		t.Fatalf("apply result=%#v err=%v", data, err)
	}
}

func TestInstanceRuntimeDoesNotApplyWhenInitialSignedReportingFails(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	client.statusErr = &instanceclient.HTTPError{StatusCode: 503, Code: "status_unavailable"}
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	applyCalls := 0
	deps.runApply = func(context.Context, targetapply.Config) (targetapply.Result, error) {
		applyCalls++
		return targetapply.Result{}, nil
	}
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitRemote || stdout != "" || applyCalls != 0 || len(client.statuses) != 1 {
		t.Fatalf("status=%d apply=%d reports=%d stdout=%q stderr=%q", status, applyCalls, len(client.statuses), stdout, stderr)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.id, fixture.secret)
}

func TestInstanceRuntimeReportsAppliedTrueOnPostApplyReportingPartial(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	deps.runApply = func(_ context.Context, config targetapply.Config) (targetapply.Result, error) {
		client.logErr = &instanceclient.HTTPError{StatusCode: 503, Code: "logs_unavailable"}
		config.Event("ssh", "complete", "")
		return successfulRuntimeApplyResult(config.Plan, fixture.now), nil
	}
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitPartial || stdout != "" {
		t.Fatalf("partial status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "reporting_partial" {
		t.Fatalf("unexpected partial envelope: %#v", envelope)
	}
	var data struct {
		ProfileApplied    bool `json:"profile_applied"`
		ReportingDegraded bool `json:"reporting_degraded"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil || !data.ProfileApplied || !data.ReportingDegraded {
		t.Fatalf("partial data=%#v err=%v", data, err)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.id, fixture.secret)
}

func TestInstanceRuntimeVerifiedRevocationRunsOnlyFixedFailClosedPath(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	revokedState := fixture.result.Desired.State
	revokedState.Generation++
	revokedState.Revoked = true
	revokedState.AuthorizedSSHKeys = nil
	revoked, err := enrollment.SignDesiredState(revokedState, fixture.desiredKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.result.Desired = revoked
	fixture.result.State.Desired = &revoked
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	applyCalls, revokeCalls := 0, 0
	deps.runApply = func(context.Context, targetapply.Config) (targetapply.Result, error) {
		applyCalls++
		return targetapply.Result{}, nil
	}
	deps.revoke = func(_ context.Context, root, admin, profile string) error {
		revokeCalls++
		if root != fixture.stateRoot || admin != fixture.adminUser || profile != fixture.profile {
			t.Fatalf("revocation not locally bound: root=%q admin=%q profile=%q", root, admin, profile)
		}
		return nil
	}
	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" || applyCalls != 0 || revokeCalls != 1 || len(client.statuses) != 1 || len(client.logs) != 1 {
		t.Fatalf("status=%d apply=%d revoke=%d statuses=%d logs=%d stdout=%q stderr=%q", status, applyCalls, revokeCalls, len(client.statuses), len(client.logs), stdout, stderr)
	}
	report := client.statuses[0]
	if report.State != "revoked" || !report.Revoked || !report.FailClosed ||
		report.DesiredGeneration != revoked.State.Generation || report.AppliedGeneration != 0 ||
		report.ReleaseSet != revoked.State.ReleaseSet || report.SSHHostKey != "" || len(report.Components) != 1 ||
		report.Components[0].Name != "ssh" || report.Components[0].State != "blocked" || report.Components[0].Code != "revoked" {
		t.Fatalf("invalid revocation acknowledgement: %#v", report)
	}
	batch := client.logs[0]
	if batch.Component != "ssh" || len(batch.Events) != 1 || batch.Events[0].Level != "critical" ||
		batch.Events[0].Event != "phase_fail_closed" || batch.Events[0].Code != "revoked" {
		t.Fatalf("invalid finite revocation event: %#v", batch)
	}
	var data struct {
		Revoked        bool `json:"revoked"`
		FailClosed     bool `json:"fail_closed"`
		ProfileApplied bool `json:"profile_applied"`
	}
	if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &data); err != nil || !data.Revoked || !data.FailClosed || data.ProfileApplied {
		t.Fatalf("revocation result=%#v err=%v", data, err)
	}
}

func TestInstanceRuntimeRevocationAckFailureIsPartialAndTimerRetrySafe(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	revokedState := fixture.result.Desired.State
	revokedState.Generation++
	revokedState.Revoked = true
	revokedState.AuthorizedSSHKeys = nil
	revoked, err := enrollment.SignDesiredState(revokedState, fixture.desiredKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.result.Desired = revoked
	fixture.result.State.Desired = &revoked
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	client.statusErr = &instanceclient.HTTPError{StatusCode: 503, Code: "status_unavailable"}
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	applyCalls, revokeCalls, timerCalls := 0, 0, 0
	deps.runApply = func(context.Context, targetapply.Config) (targetapply.Result, error) {
		applyCalls++
		return targetapply.Result{}, nil
	}
	deps.revoke = func(context.Context, string, string, string) error {
		revokeCalls++
		return nil
	}
	deps.installTimer = func(string) (bool, error) {
		timerCalls++
		return false, nil
	}

	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitPartial || stdout != "" || applyCalls != 0 || revokeCalls != 1 || timerCalls != 1 ||
		len(client.statuses) != 1 || len(client.logs) != 1 {
		t.Fatalf("partial status=%d apply=%d revoke=%d timer=%d statuses=%d logs=%d stdout=%q stderr=%q",
			status, applyCalls, revokeCalls, timerCalls, len(client.statuses), len(client.logs), stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "reporting_partial" {
		t.Fatalf("unexpected revocation partial envelope: %#v", envelope)
	}
	var partial struct {
		Revoked           bool `json:"revoked"`
		FailClosed        bool `json:"fail_closed"`
		ReportingDegraded bool `json:"reporting_degraded"`
	}
	if err := json.Unmarshal(envelope.Data, &partial); err != nil || !partial.Revoked || !partial.FailClosed || !partial.ReportingDegraded {
		t.Fatalf("partial revocation data=%#v err=%v", partial, err)
	}

	// A later timer tick refetches the same signed revocation, repeats the
	// idempotent local fail-closed action, and completes the signed ack. It does
	// not run an installer or require credential input.
	client.statusErr = nil
	status, stdout, stderr = invokeInstanceRuntime(t, []string{"reconcile", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || stderr != "" || applyCalls != 0 || revokeCalls != 2 || timerCalls != 1 ||
		client.fetchCalls != 1 || len(client.statuses) != 2 || len(client.logs) != 2 {
		t.Fatalf("retry status=%d apply=%d revoke=%d timer=%d fetch=%d statuses=%d logs=%d stdout=%q stderr=%q",
			status, applyCalls, revokeCalls, timerCalls, client.fetchCalls, len(client.statuses), len(client.logs), stdout, stderr)
	}
	if client.logs[0].Events[0].Sequence >= client.logs[1].Events[0].Sequence {
		t.Fatalf("revocation log sequence did not advance across retry: %#v", client.logs)
	}
}

func TestRuntimeArtifactAdapterRequiresOneExactManifestBinding(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	component := fixture.result.Release.Manifest.Components[0]
	artifact := applyplan.Artifact{
		Component: component.Name, Version: component.Version, Target: component.Target,
		Path: component.Artifact, Digest: component.Digest, Size: component.Size,
	}
	if got, err := releaseComponentForRuntimeArtifact(fixture.result.Release, artifact); err != nil || got != component {
		t.Fatalf("exact component=%#v err=%v", got, err)
	}
	tampered := artifact
	tampered.Path += ".other"
	if _, err := releaseComponentForRuntimeArtifact(fixture.result.Release, tampered); !errors.Is(err, instanceclient.ErrArtifactNotBound) {
		t.Fatalf("tampered artifact error=%v", err)
	}
	duplicate := fixture.result.Release
	duplicate.Manifest.Components = append(duplicate.Manifest.Components, component)
	if _, err := releaseComponentForRuntimeArtifact(duplicate, artifact); !errors.Is(err, instanceclient.ErrArtifactNotBound) {
		t.Fatalf("ambiguous artifact error=%v", err)
	}
}

func TestInstanceRuntimeLogSequencesPersistAndSerializeAcrossRuns(t *testing.T) {
	root := filepath.Join(privateTempDir(t), "runtime")
	const workers = 64
	sequences := make(chan uint64, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			sequence, err := allocateInstanceRuntimeLogSequence(root, "pbp")
			if err != nil {
				errorsChannel <- err
				return
			}
			sequences <- sequence
		}()
	}
	wait.Wait()
	close(sequences)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("allocate sequence: %v", err)
	}
	got := make([]int, 0, workers)
	for sequence := range sequences {
		got = append(got, int(sequence))
	}
	sort.Ints(got)
	for index, sequence := range got {
		if sequence != index+1 {
			t.Fatalf("sequences=%v", got)
		}
	}
	next, err := allocateInstanceRuntimeLogSequence(root, "pbp")
	if err != nil || next != workers+1 {
		t.Fatalf("persistent next=%d err=%v", next, err)
	}
}

func TestInstanceRuntimeLocalStatusOnlyClaimsAppliedForExactCheckpoint(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	persistRuntimeFixtureConfig(t, fixture)
	client := newFakeRuntimeClient(fixture)
	deps := fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	deps.loadCheckpoint = func(string) (applyplan.Checkpoint, string, error) {
		return applyplan.Checkpoint{
			ReleaseGeneration: fixture.result.Release.Manifest.Generation,
			ReleaseSet:        fixture.result.Release.Manifest.SetID,
			DesiredGeneration: fixture.result.Desired.State.Generation,
			DesiredStateID:    "sha256:" + strings.Repeat("d", 64),
		}, "", nil
	}
	status, stdout, stderr := invokeInstanceRuntime(t, []string{"status", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || stderr != "" || !strings.Contains(stdout, `"profile_applied":true`) {
		t.Fatalf("matching checkpoint status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	deps.loadCheckpoint = func(string) (applyplan.Checkpoint, string, error) {
		return applyplan.Checkpoint{ReleaseGeneration: fixture.result.Release.Manifest.Generation, ReleaseSet: fixture.result.Release.Manifest.SetID, DesiredGeneration: fixture.result.Desired.State.Generation - 1, DesiredStateID: "sha256:" + strings.Repeat("c", 64)}, "", nil
	}
	status, stdout, stderr = invokeInstanceRuntime(t, []string{"status", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || stderr != "" || !strings.Contains(stdout, `"profile_applied":false`) {
		t.Fatalf("stale checkpoint status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func TestNormalizeRuntimeSSHHostKeyStripsCommentAndRejectsMultipleLines(t *testing.T) {
	want := runtimeTestOpenSSHKey(false)
	got, err := normalizeRuntimeSSHHostKey([]byte(runtimeTestOpenSSHKey(true) + "\n"))
	if err != nil || got != want {
		t.Fatalf("normalized host key=%q err=%v, want %q", got, err, want)
	}
	for _, invalid := range [][]byte{
		[]byte(want + "\n" + want),
		[]byte("ssh-rsa invalid"),
		[]byte("not-an-openssh-public-key"),
	} {
		if _, err := normalizeRuntimeSSHHostKey(invalid); err == nil {
			t.Fatalf("accepted unsafe host key %q", invalid)
		}
	}
}

func TestInstanceRuntimeRawHelpIgnoresOperatorEnvironment(t *testing.T) {
	t.Setenv("FLOW_HOME", filepath.Join(t.TempDir(), "does-not-exist", "operator"))
	t.Setenv("FLOW_PROFILES_DIR", filepath.Join(t.TempDir(), "profiles"))
	status, stdout, stderr := invokeCLI(t, "--json", "instance-runtime", "--help")
	if status != exitOK || stderr != "" || !strings.Contains(stdout, "Dynamicflow target runtime") {
		t.Fatalf("runtime help status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if _, err := os.Lstat(os.Getenv("FLOW_HOME")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dispatcher opened FLOW_HOME: %v", err)
	}
}

func TestStreamRuntimeInputDoesNotPrefetchSecretAndRequiresEOF(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	content := strings.Join([]string{fixture.instance, fixture.profile, fixture.id, fixture.secret}, "\n") + "\n"
	reader := &auditedOneByteReader{data: []byte(content)}
	input := &streamInstanceRuntimeInput{reader: reader}
	fields, err := readInstanceRuntimeEnrollmentInput(input)
	if err != nil {
		t.Fatalf("read public enrollment fields: %v", err)
	}
	defer fields.clear()
	if strings.Contains(string(reader.data[:reader.offset]), fixture.secret) {
		t.Fatal("stdin reader prefetched the secret before client requested it")
	}
	secret := &deferredRuntimeSecret{input: input}
	value, err := io.ReadAll(secret)
	if err != nil || string(value) != fixture.secret || !input.finalized {
		t.Fatalf("deferred secret=%q err=%v", value, err)
	}
	clearRuntimeBytes(value)

	extra := &streamInstanceRuntimeInput{reader: strings.NewReader(content + "unexpected\n")}
	fields, err = readInstanceRuntimeEnrollmentInput(extra)
	if err != nil {
		t.Fatal(err)
	}
	defer fields.clear()
	if _, err := io.ReadAll(&deferredRuntimeSecret{input: extra}); err == nil {
		t.Fatal("fifth stdin line was accepted")
	}
}

type auditedOneByteReader struct {
	data   []byte
	offset int
	maxAsk int
}

func (reader *auditedOneByteReader) Read(target []byte) (int, error) {
	if len(target) > reader.maxAsk {
		reader.maxAsk = len(target)
	}
	if reader.offset >= len(reader.data) {
		return 0, io.EOF
	}
	target[0] = reader.data[reader.offset]
	reader.offset++
	return 1, nil
}

func newRuntimeTestFixture(t *testing.T) runtimeTestFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	releasePublic, releasePrivate, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, desiredPrivate, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releasePEM, err := signing.MarshalPublicPEM(releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	desiredPEM, err := signing.MarshalPublicPEM(desiredPublic)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(privateTempDir(t), "runtime")
	instance := "pbp-runtime-01"
	profile := "pbp"
	keyID := strings.Repeat("a", 64)
	registry, err := profiles.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	artifactDirectory := privateTempDir(t)
	inputs := make([]release.ArtifactInput, 0, 6)
	payloads := map[string][]byte{}
	for _, definition := range []struct{ name, target string }{
		{"flow", "linux-amd64"},
		{"ssh", "any"}, {"vpn", "any"}, {"pbp", "linux-amd64"},
		{"decepticon", "any"}, {"examstation", "any"},
	} {
		payload := []byte("signed-test-artifact-" + definition.name + "-" + definition.target)
		artifactName := definition.name + ".tar.gz"
		mode := os.FileMode(0o600)
		if definition.name == "flow" {
			artifactName = "flow"
			mode = 0o755
		}
		path := filepath.Join(artifactDirectory, definition.name+"-"+definition.target+"-"+artifactName)
		if err := os.WriteFile(path, payload, mode); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, release.ArtifactInput{
			Component: definition.name, Version: "v1.0.0", Target: definition.target,
			ArtifactName: artifactName, SourcePath: path,
		})
	}
	declarations := registry.List(true)
	manifestProfiles := make([]release.Profile, 0, len(declarations))
	for _, declaration := range declarations {
		manifestProfiles = append(manifestProfiles, release.Profile{
			Name: declaration.Name, DependsOn: declaration.DependsOn, Components: declaration.Components,
		})
	}
	manifest, err := release.BuildFromArtifacts(7, inputs, manifestProfiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedRelease, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range manifest.Components {
		for _, input := range inputs {
			if component.Name == input.Component && component.Target == input.Target {
				data, readErr := os.ReadFile(input.SourcePath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				payloads[component.Digest] = data
			}
		}
	}
	desired, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: instance, Profile: profile,
		Generation: 4, ReleaseSet: manifest.SetID,
		AuthorizedSSHKeys: []string{runtimeTestOpenSSHKey(true)},
		IssuedAt:          now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	state := instanceclient.State{
		Schema: 1, Instance: instance, Profile: profile, IdentityKeyID: keyID, Enrolled: true,
		ReleaseGeneration: manifest.Generation, ReleaseSet: desired.State.ReleaseSet, Desired: &desired, UpdatedAt: now.Unix(),
	}
	fixture := runtimeTestFixture{
		stateRoot: root, caPath: "/etc/dynamicflow-test/serving-ca.pem",
		releasePath: "/etc/dynamicflow-test/release.public.pem", desiredPath: "/etc/dynamicflow-test/desired.public.pem",
		server: "https://serving.example.test:8443", pin: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		instance: instance, profile: profile,
		adminUser: "operator", now: now,
		id:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		secret:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		keyID:      keyID,
		result:     instanceclient.EnrollmentResult{Release: signedRelease, Desired: desired, State: state},
		publicData: map[string][]byte{},
		artifacts:  payloads,
		desiredKey: append(ed25519.PrivateKey(nil), desiredPrivate...),
	}
	fixture.publicData[fixture.caPath] = []byte("test CA bytes")
	fixture.publicData[fixture.releasePath] = releasePEM
	fixture.publicData[fixture.desiredPath] = desiredPEM
	return fixture
}

func newFakeRuntimeClient(fixture runtimeTestFixture) *fakeRuntimeClient {
	return &fakeRuntimeClient{
		keyID: fixture.keyID, state: fixture.result.State,
		enrollResult: fixture.result, fetchResult: fixture.result,
		downloadData: fixture.artifacts,
	}
}

func (fixture runtimeTestFixture) enrollArguments() []string {
	return []string{
		"enroll", "--server", fixture.server, "--tls-ca", fixture.caPath,
		"--tls-pin", fixture.pin, "--release-public-key", fixture.releasePath,
		"--desired-public-key", fixture.desiredPath, "--admin-user", fixture.adminUser,
		"--state-root", fixture.stateRoot,
	}
}

func (fixture runtimeTestFixture) dependencies(input instanceRuntimeInput, factory func(instanceclient.Config) (instanceRuntimeClient, error)) instanceRuntimeDependencies {
	return instanceRuntimeDependencies{
		goos: "linux", goarch: "amd64", uid: func() int { return 0 }, euid: func() int { return 0 },
		now: func() time.Time { return fixture.now }, stdin: strings.NewReader(""), sshConnection: func() string { return "" },
		openInput: func(io.Reader) (instanceRuntimeInput, error) {
			if input == nil {
				return nil, errRuntimeInput
			}
			return input, nil
		},
		readPublicFile: func(path string, maximum int64) ([]byte, error) {
			value, exists := fixture.publicData[path]
			if !exists || int64(len(value)) > maximum {
				return nil, errRuntimeConfiguration
			}
			return append([]byte(nil), value...), nil
		},
		readSSHHostKey: func() (string, error) {
			return runtimeTestOpenSSHKey(false), nil
		},
		validateAdmin: func(string) error { return nil },
		newClient:     factory,
		loadCheckpoint: func(string) (applyplan.Checkpoint, string, error) {
			return applyplan.Checkpoint{}, "", nil
		},
		runApply: func(_ context.Context, config targetapply.Config) (targetapply.Result, error) {
			for _, phase := range config.Plan.Phases {
				for _, state := range []string{"preflight", "applying", "verifying", "complete"} {
					config.Event(phase.Profile, state, "")
				}
			}
			return targetapply.Result{PlanID: config.Plan.ID, Checkpoint: targetapply.Checkpoint{
				Schema: 1, ReleaseGeneration: config.Plan.ReleaseGeneration, ReleaseSet: config.Plan.ReleaseSet,
				DesiredGeneration: config.Plan.DesiredGeneration, DesiredStateID: config.Plan.DesiredStateID,
				PlanID: config.Plan.ID, AppliedAt: fixture.now.Unix(),
			}}, nil
		},
		revoke: func(context.Context, string, string, string) error { return nil },
		installTimer: func(string) (bool, error) {
			return false, nil
		},
	}
}

func runtimeTestOpenSSHKey(withComment bool) string {
	var wire bytes.Buffer
	for _, value := range [][]byte{[]byte("ssh-ed25519"), bytes.Repeat([]byte{0x42}, 32)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		wire.Write(size[:])
		wire.Write(value)
	}
	key := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire.Bytes())
	if withComment {
		key += " dynamicflow-test"
	}
	return key
}

func successfulRuntimeApplyResult(plan applyplan.Plan, now time.Time) targetapply.Result {
	return targetapply.Result{PlanID: plan.ID, Checkpoint: targetapply.Checkpoint{
		Schema: 1, ReleaseGeneration: plan.ReleaseGeneration, ReleaseSet: plan.ReleaseSet,
		DesiredGeneration: plan.DesiredGeneration, DesiredStateID: plan.DesiredStateID,
		PlanID: plan.ID, AppliedAt: now.Unix(),
	}}
}

func persistRuntimeFixtureConfig(t *testing.T, fixture runtimeTestFixture) {
	t.Helper()
	store, err := localstate.Open(fixture.stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := instanceRuntimeConfig{
		Schema: instanceRuntimeConfigSchema, Server: fixture.server, TLSCA: fixture.caPath, TLSPin: fixture.pin,
		ReleasePublicKey: fixture.releasePath, DesiredPublicKey: fixture.desiredPath,
		StateRoot: fixture.stateRoot, Instance: fixture.instance, Profile: fixture.profile, AdminUser: fixture.adminUser,
		IdentityKeyID: fixture.keyID, RequestTimeout: defaultRuntimeTimeout.String(), EnrolledAt: time.Now().Unix(),
	}
	if err := store.WriteJSON(instanceRuntimeConfigPath, config); err != nil {
		t.Fatal(err)
	}
}

func invokeInstanceRuntime(t *testing.T, arguments []string, deps instanceRuntimeDependencies) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	out := &emitter{json: true, stdout: &stdout, stderr: &stderr}
	status := runInstanceRuntime(arguments, out, deps)
	return status, stdout.String(), stderr.String()
}

func assertRuntimeOutputDoesNotContain(t *testing.T, output string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(output, value) {
			t.Fatalf("runtime output disclosed input value %q in %q", value, output)
		}
	}
}

func assertRuntimeTreeDoesNotContain(t *testing.T, root string, values ...string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range values {
			if bytes.Contains(data, []byte(value)) {
				t.Errorf("runtime state %s contains forbidden credential", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan runtime state: %v", err)
	}
}

func TestInstanceRuntimeVNCSecretOneShotHasFixedContract(t *testing.T) {
	const secret = "Ab3dE5gH"
	for _, action := range []string{"reveal", "rotate"} {
		t.Run(action, func(t *testing.T) {
			value := []byte(secret)
			called := ""
			deps := instanceRuntimeDependencies{
				goos: "linux", uid: func() int { return 0 }, euid: func() int { return 0 },
				vncReveal: func() ([]byte, error) { called = "reveal"; return value, nil },
				vncRotate: func() ([]byte, error) { called = "rotate"; return value, nil },
			}
			var stdout, stderr bytes.Buffer
			status := runInstanceRuntime([]string{"secret", action, "--secret", "vnc"}, &emitter{stdout: &stdout, stderr: &stderr}, deps)
			if status != exitOK || stdout.String() != secret+"\n" || stderr.String() != "" || called != action {
				t.Fatalf("status=%d stdout=%q stderr=%q called=%q", status, stdout.String(), stderr.String(), called)
			}
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatalf("returned secret backing memory was not cleared: %q", value)
			}
		})
	}

	for _, arguments := range [][]string{
		{"secret", "reveal", "--secret", "vnc", "extra"},
		{"secret", "reveal", "--secret", "other"},
		{"secret", "reveal", "--path", "/root/file"},
		{"secret", "arbitrary", "--secret", "vnc"},
	} {
		called := false
		deps := instanceRuntimeDependencies{
			goos: "linux", uid: func() int { return 0 }, euid: func() int { return 0 },
			vncReveal: func() ([]byte, error) { called = true; return nil, nil },
		}
		var stdout, stderr bytes.Buffer
		if status := runInstanceRuntime(arguments, &emitter{stdout: &stdout, stderr: &stderr}, deps); status != exitUsage || called {
			t.Fatalf("arguments=%v status=%d called=%t stdout=%q stderr=%q", arguments, status, called, stdout.String(), stderr.String())
		}
	}
}

func TestInstanceRuntimeVNCSecretFailureDoesNotDiscloseSecret(t *testing.T) {
	const secret = "Leak1234"
	deps := instanceRuntimeDependencies{
		goos: "linux", uid: func() int { return 0 }, euid: func() int { return 0 },
		vncReveal: func() ([]byte, error) { return nil, errors.New(secret) },
	}
	var stdout, stderr bytes.Buffer
	status := runInstanceRuntime([]string{"secret", "reveal", "--secret", "vnc"}, &emitter{stdout: &stdout, stderr: &stderr}, deps)
	if status != exitFailure || strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestInstanceRuntimeVNCSecretRequiresRootAndRejectsJSONRawChannel(t *testing.T) {
	called := false
	operation := func() ([]byte, error) { called = true; return []byte("Ab3dE5gH"), nil }
	for _, test := range []struct {
		name string
		uid  int
		euid int
		json bool
		want int
	}{
		{"real uid", 1000, 0, false, exitAuth},
		{"effective uid", 0, 1000, false, exitAuth},
		{"json raw channel", 0, 0, true, exitUsage},
	} {
		t.Run(test.name, func(t *testing.T) {
			called = false
			deps := instanceRuntimeDependencies{
				goos: "linux", uid: func() int { return test.uid }, euid: func() int { return test.euid },
				vncReveal: operation,
			}
			var stdout, stderr bytes.Buffer
			status := runInstanceRuntime([]string{"secret", "reveal", "--secret", "vnc"}, &emitter{json: test.json, stdout: &stdout, stderr: &stderr}, deps)
			if status != test.want || called || strings.Contains(stdout.String()+stderr.String(), "Ab3dE5gH") {
				t.Fatalf("status=%d called=%t stdout=%q stderr=%q", status, called, stdout.String(), stderr.String())
			}
		})
	}
}
