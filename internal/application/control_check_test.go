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

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/workflow"
)

type applicationControlRunner struct {
	mu     sync.Mutex
	calls  int
	argv   []string
	fail   bool
	secret string
}

func (runner *applicationControlRunner) Run(_ context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	if stdin != nil {
		return errors.New("unexpected stdin")
	}
	_, _ = io.WriteString(stdout, runner.secret)
	_, _ = io.WriteString(stderr, runner.secret)
	if runner.fail {
		return errors.New("remote detail must stay private: " + runner.secret)
	}
	return nil
}

func (runner *applicationControlRunner) snapshot() (int, []string) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.calls, append([]string(nil), runner.argv...)
}

func (runner *applicationControlRunner) setFail(value bool) {
	runner.mu.Lock()
	runner.fail = value
	runner.mu.Unlock()
}

func TestControlCheckUsesOneFixedAttemptThenBecomesNetworkFree(t *testing.T) {
	runner := &applicationControlRunner{secret: "discarded-control-output"}
	app, store := openApplicationWithControlRunner(t, runner)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "check-lab"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := app.BindControl(context.Background(), testControlBindRequest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	transportPath, err := store.Path(filepath.Join("systems", initialized.System.ID, "sshtransport"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.PlanControlCheck(context.Background(), CheckControlRequest{Name: "control-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.NetworkConnections != 1 || plan.FixedRemoteCommand != "/bin/true" ||
		plan.AlreadyVerified || plan.ResumesFailedTask || len(plan.Changes) != 3 {
		t.Fatalf("check plan = %+v", plan)
	}
	if _, err := os.Lstat(transportPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only check plan wrote transport state: %v", err)
	}

	events := []Event{}
	checked, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, ObserverFunc(func(event Event) {
		events = append(events, event)
	}))
	if err != nil {
		t.Fatal(err)
	}
	calls, argv := runner.snapshot()
	if calls != 1 || len(argv) != 6 || argv[len(argv)-1] != "/bin/true" || argv[0] != "-F" || argv[2] != "-S" || argv[3] != "none" {
		t.Fatalf("runner calls=%d argv=%#v", calls, argv)
	}
	if !checked.Verified || checked.AlreadyVerified || checked.Reconciled || checked.NetworkConnections != 1 ||
		checked.Transport.Attempts != 1 || checked.Transport.Route != "direct_first_control" ||
		checked.Control.Lifecycle != controlnodes.LifecycleConnectivityVerified ||
		checked.Task.Phase != workflow.PhaseConnectivityOK || len(events) < 2 {
		t.Fatalf("checked = %+v events=%+v", checked, events)
	}
	if checked.Transport.StdoutBytes != int64(len(runner.secret)) || checked.Transport.StderrBytes != int64(len(runner.secret)) {
		t.Fatalf("bounded output metadata = %+v", checked.Transport)
	}
	encoded, err := json.Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	privatePath, err := store.Path(filepath.Join("systems", initialized.System.ID, "keys", "bootstrap", "control-1", "generations", "000001", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(runner.secret)) || bytes.Contains(encoded, []byte(privatePath)) {
		t.Fatalf("check result leaked output or private path: %s", encoded)
	}

	again, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("idempotent check opened another connection: %d", calls)
	}
	if !again.Verified || !again.AlreadyVerified || again.NetworkConnections != 0 || again.Control != checked.Control ||
		again.Task != checked.Task {
		t.Fatalf("idempotent check = %+v", again)
	}
	verifiedPlan, err := app.PlanControlCheck(context.Background(), CheckControlRequest{Name: "control-1"})
	if err != nil || !verifiedPlan.AlreadyVerified || verifiedPlan.NetworkConnections != 0 || len(verifiedPlan.Changes) != 0 {
		t.Fatalf("verified plan = %+v err=%v", verifiedPlan, err)
	}
	if bound.Control.HostFingerprint != checked.Control.HostFingerprint {
		t.Fatal("connectivity changed the pinned host identity")
	}
}

func TestControlCheckFailureIsSanitizedPersistentAndExplicitlyResumable(t *testing.T) {
	runner := &applicationControlRunner{fail: true, secret: "remote-secret-and-private-path"}
	app, store := openApplicationWithControlRunner(t, runner)
	if _, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "retry-lab"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	_, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
	failure := AsError(err)
	if failure.Code != "control_connectivity" || failure.ExitCode != 7 ||
		strings.Contains(failure.SafeText, runner.secret) || strings.Contains(failure.Next, runner.secret) {
		t.Fatalf("unsafe connectivity failure = %+v (%v)", failure, err)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Controls) != 1 || status.Controls[0].Lifecycle != controlnodes.LifecycleBound ||
		len(status.Tasks) != 1 || status.Tasks[0].Phase != workflow.PhaseFailedSafe ||
		status.Tasks[0].ResumePhase != workflow.PhaseHostKeyVerified || status.Tasks[0].Failure == nil ||
		status.Tasks[0].Failure.Code != "control_connectivity" {
		t.Fatalf("failed-safe status = %+v", status)
	}
	plan, err := app.PlanControlCheck(context.Background(), CheckControlRequest{Name: "control-1"})
	if err != nil || !plan.ResumesFailedTask || plan.NetworkConnections != 1 || plan.FixedRemoteCommand != "/bin/true" {
		t.Fatalf("retry plan = %+v err=%v", plan, err)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("plan invoked runner: %d", calls)
	}

	runner.setFail(false)
	checked, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls, _ := runner.snapshot(); calls != 2 {
		t.Fatalf("explicit retry calls = %d", calls)
	}
	if !checked.Verified || checked.Task.Phase != workflow.PhaseConnectivityOK || checked.Task.Attempt != 2 ||
		checked.Control.Lifecycle != controlnodes.LifecycleConnectivityVerified {
		t.Fatalf("resumed check = %+v", checked)
	}
	audit, err := os.ReadFile(filepath.Join(store.Root(), "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(runner.secret)) {
		t.Fatalf("audit leaked remote output: %s", audit)
	}
}

func TestControlCheckReconcilesCommittedEvidenceWithoutAnotherConnection(t *testing.T) {
	runner := &applicationControlRunner{secret: "never-written"}
	app, store := openApplicationWithControlRunner(t, runner)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "crash-recovery"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := app.BindControl(context.Background(), testControlBindRequest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(initialized.System.ID)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(systemStore, sshkeys.WithSSHKeygen(app.sshKeygen), sshkeys.WithClock(app.now))
	manager, err := controlnodes.NewManager(store, keys, controlnodes.WithClock(app.now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Transition(initialized.System.ID, "control-1", bound.Control.Revision, controlnodes.LifecycleConnectivityVerified); err != nil {
		t.Fatal(err)
	}

	reconciled, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("reconciliation repeated network proof: %d", calls)
	}
	if !reconciled.Verified || !reconciled.Reconciled || reconciled.NetworkConnections != 0 ||
		reconciled.Task.Phase != workflow.PhaseConnectivityOK ||
		reconciled.Control.Lifecycle != controlnodes.LifecycleConnectivityVerified {
		t.Fatalf("reconciled result = %+v", reconciled)
	}
}

func openApplicationWithControlRunner(t *testing.T, runner *applicationControlRunner) (*Application, *localstate.Store) {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	app, err := Open(Config{
		Store: store, Clock: func() time.Time { return clock },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 256)), SSHKeygen: keygen,
		ControlRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return app, store
}
