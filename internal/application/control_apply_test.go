package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/controlinstalltransport"
	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/workflow"
)

type controlApplyRunner struct {
	mu          sync.Mutex
	calls       [][]string
	payloads    [][]byte
	failInstall bool
	secret      string
}

func (runner *controlApplyRunner) Run(_ context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, append([]string(nil), argv...))
	if len(argv) > 0 && argv[len(argv)-1] == "/bin/true" {
		if stdin != nil {
			return errors.New("connectivity check received stdin")
		}
		return nil
	}
	if len(argv) == 0 || !strings.Contains(argv[len(argv)-1], "control-runtime install") || stdin == nil {
		return errors.New("unexpected control operation")
	}
	payload, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	runner.payloads = append(runner.payloads, payload)
	_, _ = io.WriteString(stdout, runner.secret)
	_, _ = io.WriteString(stderr, runner.secret)
	if runner.failInstall {
		return errors.New("remote secret: " + runner.secret)
	}
	return nil
}

func (runner *controlApplyRunner) setFail(value bool) {
	runner.mu.Lock()
	runner.failInstall = value
	runner.mu.Unlock()
}

func (runner *controlApplyRunner) snapshot() ([][]string, [][]byte) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	calls := make([][]string, len(runner.calls))
	for index := range runner.calls {
		calls[index] = append([]string(nil), runner.calls[index]...)
	}
	payloads := make([][]byte, len(runner.payloads))
	for index := range runner.payloads {
		payloads[index] = append([]byte(nil), runner.payloads[index]...)
	}
	return calls, payloads
}

func TestInstallPreparedControlUsesOnePinnedSessionThenEvidenceIsNetworkFree(t *testing.T) {
	runner := &controlApplyRunner{secret: "discarded-install-output"}
	app, store, systemID, executablePath, executableBytes := preparedControlApplyFixture(t, runner)
	plan, err := app.PlanPreparedControlInstall(context.Background(), InstallPreparedControlRequest{Name: "control-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.NetworkConnections != 1 || plan.Route != "direct_first_control" ||
		plan.FixedOperation != "control-runtime install" || plan.Retry != "none" || plan.Fallback != "none" ||
		plan.PolicyGeneration != 1 || plan.ExecutableBytes != int64(len(executableBytes)) ||
		plan.ExecutableDigest == "" || plan.EnvelopeDigest == "" || len(plan.Changes) != 4 {
		t.Fatalf("remote install plan = %+v", plan)
	}
	evidencePath, err := store.Path(filepath.Join("systems", systemID, controlInstallEvidenceRelative("control-1")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(evidencePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plan created install evidence: %v", err)
	}

	result, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || result.AlreadyInstalled || result.Reconciled || result.NetworkConnections != 1 ||
		result.Task.Phase != workflow.PhaseAttesting || result.Control.Lifecycle != controlnodes.LifecycleInstalling ||
		result.Control.Access.Phase != controlnodes.AccessStaged || result.Transport.Attempts != 1 ||
		result.Transport.Route != "direct_first_control" || result.EnvelopeDigest != plan.EnvelopeDigest ||
		result.ExecutableDigest != plan.ExecutableDigest {
		t.Fatalf("remote install result = %+v", result)
	}
	calls, payloads := runner.snapshot()
	if len(calls) != 2 || len(payloads) != 1 || !strings.Contains(calls[1][len(calls[1])-1], "control-runtime install") ||
		!bytes.HasPrefix(payloads[0], executableBytes) {
		t.Fatalf("runner calls=%#v payloads=%d", calls, len(payloads))
	}
	for _, forbidden := range []string{executablePath, "203.0.113.40", runner.secret} {
		if strings.Contains(strings.Join(calls[1], "\n"), forbidden) {
			t.Fatalf("remote install argv leaked %q", forbidden)
		}
	}
	info, err := os.Lstat(evidencePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("install evidence mode=%v err=%v", info, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(executablePath)) || bytes.Contains(encoded, executableBytes) || bytes.Contains(encoded, []byte(runner.secret)) {
		t.Fatalf("install result leaked private/raw data: %s", encoded)
	}

	again, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Installed || !again.AlreadyInstalled || again.NetworkConnections != 0 || again.Task != result.Task ||
		again.EnvelopeDigest != result.EnvelopeDigest || again.ExecutableDigest != result.ExecutableDigest {
		t.Fatalf("network-free replay = %+v", again)
	}
	if calls, _ := runner.snapshot(); len(calls) != 2 {
		t.Fatalf("idempotent replay opened another connection: %d", len(calls))
	}
	alreadyPlan, err := app.PlanPreparedControlInstall(context.Background(), InstallPreparedControlRequest{Name: "control-1"})
	if err != nil || !alreadyPlan.AlreadyInstalled || alreadyPlan.NetworkConnections != 0 || len(alreadyPlan.Changes) != 0 {
		t.Fatalf("already-installed plan=%+v err=%v", alreadyPlan, err)
	}
}

func TestInstallPreparedControlFailureIsFailSafeAndExplicitlyResumable(t *testing.T) {
	runner := &controlApplyRunner{failInstall: true, secret: "remote-private-install-detail"}
	app, store, _, _, _ := preparedControlApplyFixture(t, runner)
	_, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	failure := AsError(err)
	if failure.Code != "control_install" || failure.ExitCode != 7 || strings.Contains(failure.SafeText, runner.secret) ||
		strings.Contains(failure.Next, runner.secret) {
		t.Fatalf("unsafe install failure=%+v err=%v", failure, err)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Tasks) != 1 || status.Tasks[0].Phase != workflow.PhaseFailedSafe ||
		status.Tasks[0].ResumePhase != workflow.PhaseInstalling || status.Tasks[0].Failure == nil ||
		status.Tasks[0].Failure.Code != "control_install" || status.Controls[0].Lifecycle != controlnodes.LifecycleInstalling {
		t.Fatalf("failed-safe install status = %+v", status)
	}
	plan, err := app.PlanPreparedControlInstall(context.Background(), InstallPreparedControlRequest{Name: "control-1"})
	if err != nil || !plan.ResumesFailedTask || plan.NetworkConnections != 1 || plan.Retry != "none" || plan.Fallback != "none" {
		t.Fatalf("resume plan=%+v err=%v", plan, err)
	}
	runner.setFail(false)
	result, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Task.Phase != workflow.PhaseAttesting || result.Task.Attempt != 2 || result.NetworkConnections != 1 {
		t.Fatalf("resumed install=%+v", result)
	}
	if calls, _ := runner.snapshot(); len(calls) != 3 {
		t.Fatalf("connectivity + failed + explicit retry calls=%d", len(calls))
	}
	audit, err := os.ReadFile(filepath.Join(store.Root(), "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(runner.secret)) {
		t.Fatalf("audit leaked remote output: %s", audit)
	}
}

func TestInstallPreparedControlReconcilesPersistedEvidenceWithoutNetwork(t *testing.T) {
	runner := &controlApplyRunner{}
	app, _, systemID, executablePath, _ := preparedControlApplyFixture(t, runner)
	store, err := app.openSystemStore(systemID)
	if err != nil {
		t.Fatal(err)
	}
	active, err := app.systems.Active()
	if err != nil {
		t.Fatal(err)
	}
	_, _, bindingContext, _, record, err := app.controlInstallContext("control-1")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := app.readPreparedControlEnvelope(store, active, record)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := controlinstalltransport.NewExecutable(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	evidence := controlInstallEvidence{
		SchemaVersion: controlInstallEvidenceSchema, SystemID: systemID, ControlName: "control-1",
		EnvelopeDigest: prepared.digest, ExecutableDigest: executable.Digest(), ExecutableBytes: executable.Size(),
		PolicyGeneration: 1, Route: "direct_first_control", Attempts: 1, InstalledAt: app.now().UTC(),
	}
	if err := store.WriteJSON(controlInstallEvidenceRelative("control-1"), evidence); err != nil {
		t.Fatal(err)
	}
	if bindingContext.task.Phase != workflow.PhaseInstalling {
		t.Fatalf("fixture task unexpectedly advanced: %+v", bindingContext.task)
	}
	plan, err := app.PlanPreparedControlInstall(context.Background(), InstallPreparedControlRequest{Name: "control-1"})
	if err != nil || !plan.ReconcilesEvidence || plan.NetworkConnections != 0 {
		t.Fatalf("evidence reconciliation plan=%+v err=%v", plan, err)
	}
	result, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.AlreadyInstalled || !result.Reconciled || result.NetworkConnections != 0 || result.Task.Phase != workflow.PhaseAttesting {
		t.Fatalf("evidence reconciliation result=%+v", result)
	}
	if calls, _ := runner.snapshot(); len(calls) != 1 {
		t.Fatalf("reconciliation repeated remote install: calls=%d", len(calls))
	}
}

func preparedControlApplyFixture(t *testing.T, runner *controlApplyRunner) (*Application, *localstate.Store, string, string, []byte) {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(t.TempDir(), "flow")
	executableBytes := []byte("fixture-flow-control-runtime")
	if err := os.WriteFile(executablePath, executableBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	app, err := Open(Config{
		Store: store, Clock: func() time.Time { return clock }, Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 256)),
		SSHKeygen: keygen, ControlRunner: runner, ExecutablePath: executablePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "apply-lab", ControlName: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	return app, store, initialized.System.ID, executablePath, executableBytes
}
