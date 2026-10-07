package application

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/workflow"
)

type cancelControlRunner struct {
	cancel context.CancelFunc
	calls  int
}

func (runner *cancelControlRunner) Run(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	runner.calls++
	runner.cancel()
	return nil // A cancellation racing with exit zero is still not proof.
}

func TestControlCheckCancellationPersistsResumableCheckpoint(t *testing.T) {
	runner := &applicationControlRunner{}
	app, _ := openApplicationWithControlRunner(t, runner)
	if _, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "cancel-check"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := &cancelControlRunner{cancel: cancel}
	app.controlRunner = cancelling
	result, err := app.CheckControl(ctx, CheckControlRequest{Name: "control-1"}, nil)
	if failure := AsError(err); failure.Code != "cancelled" || failure.ExitCode != 8 || result.Verified || cancelling.calls != 1 {
		t.Fatalf("cancelled check: result=%+v failure=%+v calls=%d", result, failure, cancelling.calls)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil || len(status.Tasks) != 1 || status.Tasks[0].Phase != workflow.PhaseFailedSafe ||
		status.Tasks[0].ResumePhase != workflow.PhaseHostKeyVerified || status.Controls[0].Lifecycle != controlnodes.LifecycleBound {
		t.Fatalf("checkpoint was not persisted before return: %+v err=%v", status, err)
	}
	app.controlRunner = runner
	retried, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
	if err != nil || !retried.Verified || retried.Task.Attempt != 2 {
		t.Fatalf("explicit retry failed: %+v err=%v", retried, err)
	}
}

func TestControlApplyCancellationPersistsResumableCheckpoint(t *testing.T) {
	runner := &controlApplyRunner{}
	app, store, systemID, _, _ := preparedControlApplyFixture(t, runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := &cancelControlRunner{cancel: cancel}
	app.controlRunner = cancelling
	result, err := app.InstallPreparedControl(ctx, InstallPreparedControlRequest{Name: "control-1"}, nil)
	if failure := AsError(err); failure.Code != "cancelled" || failure.ExitCode != 8 || result.Installed || cancelling.calls != 1 {
		t.Fatalf("cancelled apply: result=%+v failure=%+v calls=%d", result, failure, cancelling.calls)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil || len(status.Tasks) != 1 || status.Tasks[0].Phase != workflow.PhaseFailedSafe ||
		status.Tasks[0].ResumePhase != workflow.PhaseInstalling || status.Controls[0].Lifecycle != controlnodes.LifecycleInstalling {
		t.Fatalf("checkpoint was not persisted before return: %+v err=%v", status, err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root(), "systems", systemID, controlInstallEvidenceRelative("control-1"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled install produced a success receipt: %v", err)
	}
	app.controlRunner = runner
	retried, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
	if err != nil || !retried.Installed || retried.Task.Attempt != 2 {
		t.Fatalf("explicit retry failed: %+v err=%v", retried, err)
	}
}

func TestControlNetworkOperationsFailFastWhenBootstrapLockIsHeld(t *testing.T) {
	runner := &controlApplyRunner{}
	app, store, systemID, _, _ := preparedControlApplyFixture(t, runner)
	beforeCalls, _ := runner.snapshot()
	before, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = store.WithLock(filepath.Join("systems", systemID, "operations", "control-bootstrap.lock"), func() error {
		_, checkErr := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil)
		_, applyErr := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil)
		for _, err := range []error{checkErr, applyErr} {
			if failure := AsError(err); failure.Code != "control_conflict" || failure.ExitCode != 6 {
				t.Fatalf("busy operation: %+v", failure)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := app.ControlStatus(context.Background())
	afterCalls, _ := runner.snapshot()
	if err != nil || len(afterCalls) != len(beforeCalls) || after.Tasks[0] != before.Tasks[0] || after.Controls[0] != before.Controls[0] {
		t.Fatalf("lock conflict changed state or opened a connection: %+v err=%v", after, err)
	}
}
