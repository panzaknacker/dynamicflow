package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

func testManager(t *testing.T) (*Manager, *localstate.Store) {
	t.Helper()
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	return NewManager(store, WithClock(func() time.Time { return clock })), store
}

func testKey() KeyReference {
	return KeyReference{Scope: sshkeys.Bootstrap, Name: "control-1", Generation: 1, Fingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}
}

func TestControlBootstrapIsIdempotentAndResumable(t *testing.T) {
	manager, _ := testManager(t)
	created, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
	if err != nil {
		t.Fatal(err)
	}
	again, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
	if err != nil || again != created {
		t.Fatalf("idempotent create = %+v, %v", again, err)
	}
	failed, err := manager.FailSafe(created.ID, created.Revision, "cloud_wait", "Create the VM and resume.")
	if err != nil || failed.Phase != PhaseFailedSafe || failed.ResumePhase != PhaseAwaitingCloudVM {
		t.Fatalf("fail safe = %+v, %v", failed, err)
	}
	resumed, err := manager.Resume(failed.ID, failed.Revision)
	if err != nil || resumed.Phase != PhaseAwaitingCloudVM || resumed.Attempt != 2 || resumed.Key != created.Key {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
}

func TestTransitionsAndRevisionConflictsFailClosed(t *testing.T) {
	manager, _ := testManager(t)
	task, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Advance(task.ID, task.Revision, PhaseInstalling); !errors.Is(err, ErrInvalidPhase) {
		t.Fatalf("skipped trust gates error = %v", err)
	}
	next, err := manager.Advance(task.ID, task.Revision, PhaseAwaitingEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Advance(task.ID, task.Revision, PhaseAwaitingOOBHostKey); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision error = %v", err)
	}
	if next.NextAction != ActionSubmitEndpoint {
		t.Fatalf("next action = %q", next.NextAction)
	}
}

func TestHostTrustGatePrecedesConnectivity(t *testing.T) {
	manager, _ := testManager(t)
	task, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []Phase{PhaseAwaitingEndpoint, PhaseAwaitingOOBHostKey, PhaseHostKeyVerified, PhaseConnectivityOK} {
		task, err = manager.Advance(task.ID, task.Revision, phase)
		if err != nil {
			t.Fatalf("advance to %s: %v", phase, err)
		}
	}
	if task.Phase != PhaseConnectivityOK || task.NextAction != ActionInstallControl {
		t.Fatalf("connectivity checkpoint = %+v", task)
	}
}

func TestConcurrentCreateReturnsOneTask(t *testing.T) {
	manager, _ := testManager(t)
	const workers = 12
	results := make(chan Task, workers)
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			task, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
			results <- task
			errorsOut <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	for task := range results {
		if task.Revision != 1 || task.ID != "control-bootstrap-control-1" {
			t.Fatalf("concurrent result = %+v", task)
		}
	}
	tasks, err := manager.List()
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks = %+v, %v", tasks, err)
	}
}

func TestCorruptOrUnknownStateIsRejected(t *testing.T) {
	manager, store := testManager(t)
	task, err := manager.CreateControlBootstrap("sys-abc", "control-1", testKey())
	if err != nil {
		t.Fatal(err)
	}
	path, _ := store.Path(taskRelative(task.ID))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(string(data[:len(data)-2]) + `,"private_key":"forbidden"}` + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Get(task.ID); err == nil {
		t.Fatal("unknown secret-bearing field was accepted")
	}
}
