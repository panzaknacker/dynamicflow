package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/systemstate"
)

func TestSystemSelectPlanCommitAndNoopPreserveIdentities(t *testing.T) {
	app, store := openSelectionApplication(t)
	first := initializeSelectionSystem(t, app, "alpha")
	second := initializeSelectionSystem(t, app, "beta")
	active, err := app.systems.Active()
	if err != nil || active.ID != first.System.ID || first.System.ID == second.System.ID {
		t.Fatalf("second initialization changed active system: active=%+v err=%v", active, err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	initialRegistry, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]map[string]string{}
	for _, system := range initialRegistry.Systems {
		identities[system.ID] = selectionStateSnapshot(t, filepath.Join(store.Root(), "systems", system.ID), true)
	}

	for _, selection := range []struct {
		selector string
		id       string
	}{
		{second.System.Name, second.System.ID},
		{first.System.ID, first.System.ID},
		{"id:" + second.System.ID, second.System.ID},
	} {
		before := selectionStateSnapshot(t, store.Root(), false)
		registry, err := app.systems.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		request := SelectSystemRequest{Selector: selection.selector, ExpectedRegistryRevision: registry.Revision}
		plan, err := app.PlanSystemSelect(context.Background(), request)
		if err != nil || !plan.Plan || plan.AlreadyActive || plan.System.ID != selection.id ||
			plan.PreviousSystemID != registry.ActiveSystemID || plan.RegistryRevision != registry.Revision || plan.NetworkConnections != 0 {
			t.Fatalf("selection plan=%+v err=%v", plan, err)
		}
		if !reflect.DeepEqual(before, selectionStateSnapshot(t, store.Root(), false)) {
			t.Fatal("read-only selection plan changed private state")
		}
		result, err := app.SelectSystem(context.Background(), request, nil)
		if err != nil || !result.Changed || result.System.ID != selection.id ||
			result.PreviousSystemID != registry.ActiveSystemID || result.RegistryRevision != registry.Revision+1 || result.NetworkConnections != 0 {
			t.Fatalf("selection result=%+v err=%v", result, err)
		}
		current, err := app.systems.Snapshot()
		if err != nil || current.ActiveSystemID != selection.id || !reflect.DeepEqual(current.Systems, initialRegistry.Systems) {
			t.Fatalf("selection changed system lifecycle or trust metadata: err=%v", err)
		}
		for _, system := range current.Systems {
			if !reflect.DeepEqual(identities[system.ID], selectionStateSnapshot(t, filepath.Join(store.Root(), "systems", system.ID), true)) {
				t.Fatalf("selection changed identities, tasks or pins for %s", system.Name)
			}
		}
	}

	dashboard, err := app.Dashboard(context.Background())
	if err != nil || dashboard.ActiveSystemID != second.System.ID || dashboard.Bootstrap == nil ||
		dashboard.Bootstrap.PublicKey != second.Cloud.PublicKey || dashboard.Bootstrap.PublicKey == first.Cloud.PublicKey {
		t.Fatalf("dashboard uses wrong selected identity: err=%v", err)
	}
	beforeNoop := selectionStateSnapshot(t, store.Root(), false)
	result, err := app.SelectSystem(context.Background(), SelectSystemRequest{Selector: second.System.Name}, nil)
	if err != nil || result.Changed || result.RegistryRevision != dashboard.RegistryRevision || result.PreviousSystemID != second.System.ID {
		t.Fatalf("idempotent selection=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(beforeNoop, selectionStateSnapshot(t, store.Root(), false)) {
		t.Fatal("idempotent selection changed registry, audit or private state")
	}

	audit, err := os.ReadFile(filepath.Join(store.Root(), "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	intents, successes := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var event struct {
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
			Fields  struct {
				Previous string `json:"previous_system_id"`
				System   string `json:"system_id"`
				Network  int    `json:"network_connections"`
			} `json:"fields"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Action != "system.select" {
			continue
		}
		if event.Fields.Previous == "" || event.Fields.System == "" || event.Fields.Previous == event.Fields.System || event.Fields.Network != 0 {
			t.Fatalf("selection audit does not bind both local contexts: %+v", event)
		}
		switch event.Outcome {
		case "intent":
			intents++
		case "success":
			successes++
		default:
			t.Fatalf("unexpected selection audit outcome %q", event.Outcome)
		}
	}
	if intents != 3 || successes != 3 {
		t.Fatalf("selection audit intents=%d successes=%d, want exactly three each", intents, successes)
	}
}

func TestSystemSelectRejectsAmbiguityAndSupportsExplicitID(t *testing.T) {
	app, _ := openSelectionApplication(t)
	first, _, err := app.systems.CreateOrGet("alpha")
	if err != nil {
		t.Fatal(err)
	}
	collision, _, err := app.systems.CreateOrGet(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.PlanSystemSelect(context.Background(), SelectSystemRequest{Selector: first.ID})
	assertSelectionError(t, err, "system_ambiguous", 6)
	_, err = app.SelectSystem(context.Background(), SelectSystemRequest{Selector: first.ID}, nil)
	assertSelectionError(t, err, "system_ambiguous", 6)
	after, err := app.systems.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("ambiguous selector mutated registry: err=%v", err)
	}
	for _, id := range []string{collision.ID, first.ID} {
		result, err := app.SelectSystem(context.Background(), SelectSystemRequest{Selector: "id:" + id}, nil)
		if err != nil || !result.Changed || result.System.ID != id {
			t.Fatalf("explicit ID selected the wrong system: result=%+v err=%v", result, err)
		}
	}
	_, err = app.PlanSystemSelect(context.Background(), SelectSystemRequest{Selector: "id:alpha"})
	assertSelectionError(t, err, "system_not_found", 3)
}

func TestSystemSelectRejectsStaleRetiredMissingAndCancelledWithoutMutation(t *testing.T) {
	app, store := openSelectionApplication(t)
	first, _, err := app.systems.CreateOrGet("alpha")
	if err != nil {
		t.Fatal(err)
	}
	retired, _, err := app.systems.CreateOrGet("retired")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.PlanSystemSelect(context.Background(), SelectSystemRequest{Selector: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.systems.Update(retired.ID, retired.Revision, func(system *systemstate.System) error {
		system.Status = systemstate.StatusRetired
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		request SelectSystemRequest
		code    string
		exit    int
	}{
		{"stale revision", SelectSystemRequest{Selector: first.ID, ExpectedRegistryRevision: plan.RegistryRevision}, "system_conflict", 6},
		{"retired", SelectSystemRequest{Selector: retired.ID}, "system_retired", 6},
		{"missing", SelectSystemRequest{Selector: "missing"}, "system_not_found", 3},
		{"case mismatch", SelectSystemRequest{Selector: "Alpha"}, "system_not_found", 3},
		{"empty", SelectSystemRequest{}, "system_not_found", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := selectionStateSnapshot(t, store.Root(), false)
			_, err := app.PlanSystemSelect(context.Background(), test.request)
			assertSelectionError(t, err, test.code, test.exit)
			_, err = app.SelectSystem(context.Background(), test.request, nil)
			assertSelectionError(t, err, test.code, test.exit)
			if !reflect.DeepEqual(before, selectionStateSnapshot(t, store.Root(), false)) {
				t.Fatal("rejected selection changed state")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := selectionStateSnapshot(t, store.Root(), false)
	_, err = app.SelectSystem(ctx, SelectSystemRequest{Selector: first.ID}, nil)
	assertSelectionError(t, err, "cancelled", 8)
	if !reflect.DeepEqual(before, selectionStateSnapshot(t, store.Root(), false)) {
		t.Fatal("cancelled selection changed state")
	}
}

func TestSystemSelectFailsImmediatelyWhenEitherControlContextIsBusy(t *testing.T) {
	app, store := openSelectionApplication(t)
	first := initializeSelectionSystem(t, app, "alpha")
	second := initializeSelectionSystem(t, app, "beta")
	for _, id := range []string{first.System.ID, second.System.ID} {
		if err := store.WithLock(systemSelectionLock(id), func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ name, id string }{{"previous context", first.System.ID}, {"selected context", second.System.ID}} {
		t.Run(test.name, func(t *testing.T) {
			release := holdSelectionOperationLock(t, store, systemSelectionLock(test.id))
			defer release()
			before := selectionStateSnapshot(t, store.Root(), false)
			done := make(chan error, 1)
			go func() {
				_, err := app.SelectSystem(context.Background(), SelectSystemRequest{Selector: second.System.ID}, nil)
				done <- err
			}()
			select {
			case err := <-done:
				assertSelectionError(t, err, "system_conflict", 6)
			case <-time.After(2 * time.Second):
				release()
				<-done
				t.Fatal("selection waited for a busy Control operation instead of rejecting immediately")
			}
			if !reflect.DeepEqual(before, selectionStateSnapshot(t, store.Root(), false)) {
				t.Fatal("busy selection changed registry, audit or workflow state")
			}
		})
	}
}

func TestSystemSelectConcurrentRegistryChangeCannotCommitConfirmedPlan(t *testing.T) {
	app, store := openSelectionApplication(t)
	first, _, err := app.systems.CreateOrGet("alpha")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := app.systems.CreateOrGet("beta")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.PlanSystemSelect(context.Background(), SelectSystemRequest{Selector: second.ID})
	if err != nil {
		t.Fatal(err)
	}
	concurrentID := ""
	observer := ObserverFunc(func(event Event) {
		if event.Phase == "system_selection" && event.Status == "running" {
			concurrent, _, err := app.systems.CreateOrGet("concurrent")
			if err != nil {
				t.Fatal(err)
			}
			concurrentID = concurrent.ID
		}
	})
	_, err = app.SelectSystem(context.Background(), SelectSystemRequest{
		Selector: second.ID, ExpectedRegistryRevision: plan.RegistryRevision,
	}, observer)
	assertSelectionError(t, err, "system_conflict", 6)
	registry, err := app.systems.Snapshot()
	if err != nil || concurrentID == "" || registry.ActiveSystemID != first.ID || len(registry.Systems) != 3 || registry.Revision != plan.RegistryRevision+1 {
		t.Fatalf("selection overwrote concurrent registry work: registry=%+v err=%v", registry, err)
	}
	audit, err := os.ReadFile(filepath.Join(store.Root(), "logs", "audit.jsonl"))
	if err != nil || strings.Contains(string(audit), `"outcome":"success"`) {
		t.Fatalf("stale selection claimed a success audit: err=%v", err)
	}
}

func TestSystemSelectCancellationAtCommitKeepsPreviousContext(t *testing.T) {
	app, _ := openSelectionApplication(t)
	first, _, err := app.systems.CreateOrGet("alpha")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := app.systems.CreateOrGet("beta")
	if err != nil {
		t.Fatal(err)
	}
	before, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = app.SelectSystem(ctx, SelectSystemRequest{Selector: second.ID}, ObserverFunc(func(event Event) {
		if event.Phase == "system_selection" && event.Status == "running" {
			cancel()
		}
	}))
	assertSelectionError(t, err, "cancelled", 8)
	after, err := app.systems.Snapshot()
	if err != nil || after.ActiveSystemID != first.ID || !reflect.DeepEqual(before, after) {
		t.Fatalf("cancelled selection changed the confirmed registry: err=%v", err)
	}
}

func openSelectionApplication(t *testing.T) (*Application, *localstate.Store) {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &applicationControlRunner{fail: true}
	app, err := Open(Config{Store: store, SSHKeygen: keygen, ControlRunner: runner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if calls, _ := runner.snapshot(); calls != 0 {
			t.Errorf("system selection invoked the network runner %d times", calls)
		}
	})
	return app, store
}

func initializeSelectionSystem(t *testing.T, app *Application, name string) InitSystemResult {
	t.Helper()
	result, err := app.InitSystem(context.Background(), InitSystemRequest{Name: name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSelectionError(t *testing.T, err error, code string, exit int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s (exit %d), got success", code, exit)
	}
	failure := AsError(err)
	if failure.Code != code || failure.ExitCode != exit {
		t.Fatalf("selection error=%+v, want %s (exit %d)", failure, code, exit)
	}
}

func selectionStateSnapshot(t *testing.T, root string, ignoreOperationLocks bool) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if ignoreOperationLocks && entry.IsDir() && relative == "operations" {
			return filepath.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative] = info.Mode().String()
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[relative] = fmt.Sprintf("%s:%d:%x", info.Mode(), info.ModTime().UnixNano(), sha256.Sum256(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func holdSelectionOperationLock(t *testing.T, store *localstate.Store, relative string) func() {
	t.Helper()
	held, unlock, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- store.WithLock(relative, func() error {
			close(held)
			<-unlock
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-done:
		t.Fatalf("hold operation lock: %v", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(unlock)
			if err := <-done; err != nil {
				t.Errorf("release operation lock: %v", err)
			}
		})
	}
}
