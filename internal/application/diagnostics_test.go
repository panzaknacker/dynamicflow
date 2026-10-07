package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

func TestDiagnosticsFreshAndBoundSystemAreLocallyHealthyWithoutNetwork(t *testing.T) {
	runner := &applicationControlRunner{}
	app, store := openApplicationWithControlRunner(t, runner)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "diagnostics"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"fresh", "bound"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "bound" {
				if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
					t.Fatal(err)
				}
			}
			before := diagnosticTreeSnapshot(t, store.Root())
			result, err := app.Diagnose(context.Background())
			if err != nil || !result.Healthy || result.Scope != "system" || result.SystemID != initialized.System.ID || result.ControlReady || result.NetworkConnections != 0 {
				t.Fatalf("diagnostics=%+v err=%v", result, err)
			}
			if check := diagnosticCheckByName(result, "control:checkpoint"); check == nil || check.Status != DiagnosticPending {
				t.Fatalf("incomplete setup is not pending: %+v", result)
			}
			if calls, _ := runner.snapshot(); calls != 0 {
				t.Fatalf("diagnostics started %d connections", calls)
			}
			if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
				t.Fatal("read-only diagnostics mutated local state")
			}
			encoded, _ := json.Marshal(result)
			for _, forbidden := range []string{store.Root(), ".private.pem", "PRIVATE KEY", "id_ed25519", "ssh-ed25519 "} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("diagnostics disclosed private paths or key material: %s", encoded)
				}
			}
		})
	}
}

func TestDiagnosticsRejectMissingTrustAndMismatchedSystemWithoutRepair(t *testing.T) {
	app, store := openApplication(t)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "diagnostic-failures"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root(), "systems", initialized.System.ID, "keys/signing/release.private.pem")
	private, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := diagnosticTreeSnapshot(t, store.Root())
	result, err := app.Diagnose(context.Background())
	if err != nil || result.Healthy || diagnosticCheckByName(result, "trust:roots").Status != DiagnosticFailed {
		t.Fatalf("missing trust not diagnosed: %+v %v", result, err)
	}
	if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("diagnostics repaired a missing trust root")
	}
	if err := os.WriteFile(path, private, 0o600); err != nil {
		t.Fatal(err)
	}
	var registry systemstate.Registry
	if err := store.ReadJSON("systems/registry.json", &registry); err != nil {
		t.Fatal(err)
	}
	registry.Systems[0].Trust.ReleaseKeyID, registry.Systems[0].Trust.DesiredStateKeyID = registry.Systems[0].Trust.DesiredStateKeyID, registry.Systems[0].Trust.ReleaseKeyID
	if err := store.WriteJSON("systems/registry.json", registry); err != nil {
		t.Fatal(err)
	}
	before = diagnosticTreeSnapshot(t, store.Root())
	result, err = app.Diagnose(context.Background())
	if err != nil || result.Healthy || diagnosticCheckByName(result, "trust:binding").Status != DiagnosticFailed {
		t.Fatalf("mismatched roots not diagnosed: %+v %v", result, err)
	}
	if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("diagnostics rewrote mismatched trust metadata")
	}
}

func TestDiagnosticsExpiredBootstrapIsFailureOnlyWhileItIsNeeded(t *testing.T) {
	t.Run("awaiting VM", func(t *testing.T) {
		app, _ := openApplication(t)
		if _, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "expired"}, nil); err != nil {
			t.Fatal(err)
		}
		now := app.now().Add(3 * time.Hour)
		app.now = func() time.Time { return now }
		result, err := app.Diagnose(context.Background())
		if err != nil || result.Healthy || diagnosticCheckByName(result, "bootstrap:validity").Status != DiagnosticFailed {
			t.Fatalf("expired required bootstrap accepted: %+v %v", result, err)
		}
	})
	t.Run("connectivity reconciliation still needs installation", func(t *testing.T) {
		runner := &applicationControlRunner{}
		app, store := openApplicationWithControlRunner(t, runner)
		initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "expired-reconciliation"}, nil)
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
		keys := sshkeys.NewManager(systemStore, sshkeys.WithClock(app.now))
		manager, err := controlnodes.NewManager(store, keys, controlnodes.WithClock(app.now))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Transition(initialized.System.ID, "control-1", bound.Control.Revision, controlnodes.LifecycleConnectivityVerified); err != nil {
			t.Fatal(err)
		}
		now := app.now().Add(3 * time.Hour)
		app.now = func() time.Time { return now }
		plan, err := app.PlanControlCheck(context.Background(), CheckControlRequest{Name: "control-1"})
		if err != nil || plan.NetworkConnections != 0 {
			t.Fatalf("fixture is not a local reconciliation: %+v %v", plan, err)
		}
		before := diagnosticTreeSnapshot(t, store.Root())
		result, err := app.Diagnose(context.Background())
		if err != nil || result.Healthy || diagnosticCheckByName(result, "bootstrap:validity").Status != DiagnosticFailed {
			t.Fatalf("expired key for later installation accepted: %+v %v", result, err)
		}
		if calls, _ := runner.snapshot(); calls != 0 {
			t.Fatalf("diagnostics opened %d connections", calls)
		}
		if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
			t.Fatal("expired-checkpoint diagnostics changed state")
		}
	})
	t.Run("installed management path", func(t *testing.T) {
		app, store, _, runner := installedControlAttestFixture(t)
		now := app.now().Add(3 * time.Hour)
		app.now = func() time.Time { return now }
		before := diagnosticTreeSnapshot(t, store.Root())
		result, err := app.Diagnose(context.Background())
		if err != nil || !result.Healthy || result.ControlReady || result.NetworkConnections != 0 || runner.calls != 0 {
			t.Fatalf("installed checkpoint requires expired bootstrap or opened a connection: %+v %v calls=%d", result, err, runner.calls)
		}
		if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
			t.Fatal("installed-checkpoint diagnostics mutated local state")
		}
	})
}

func TestDiagnosticsRejectInconsistentBindingsAndFalseReadiness(t *testing.T) {
	app, store := openApplication(t)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "inconsistent-diagnostics"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(initialized.System.ID)
	if err != nil {
		t.Fatal(err)
	}
	taskPath := filepath.Join("workflows/tasks", initialized.Task.ID+".json")
	changedTask := initialized.Task
	changedTask.Key.Generation++
	if err := systemStore.WriteJSON(taskPath, changedTask); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "bootstrap:identity")
	if err := systemStore.WriteJSON(taskPath, initialized.Task); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	registry, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	hostFingerprint := registry.Systems[0].Bootstrap.HostKeyFingerprint
	registry.Systems[0].Bootstrap.HostKeyFingerprint = initialized.Task.Key.Fingerprint
	if err := store.WriteJSON("systems/registry.json", registry); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "control:binding")
	registry.Systems[0].Bootstrap.HostKeyFingerprint = hostFingerprint
	if err := store.WriteJSON("systems/registry.json", registry); err != nil {
		t.Fatal(err)
	}
	document, err := topology.NewStore(systemStore).Load()
	if err != nil {
		t.Fatal(err)
	}
	document.ControlReady = true
	if err := systemStore.WriteJSON("topology/topology.json", document); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "control:readiness")
}

func TestDiagnosticsCancellationDoesNotReadOrInitializeState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiagnoseLocal(ctx, Config{}); AsError(err).Code != "cancelled" || AsError(err).ExitCode != 8 {
		t.Fatalf("cancelled diagnostics = %v", err)
	}
}

func TestDiagnosticsReadyRequiresExactStoredProofWithoutOpeningConnection(t *testing.T) {
	app, store, systemID, runner := installedControlAttestFixture(t)
	proof, err := app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(systemID)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(systemStore, sshkeys.WithClock(app.now), sshkeys.WithControlScope())
	manager, err := controlnodes.NewManager(store, keys, controlnodes.WithClock(app.now))
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.Get(systemID, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	// Construct the eventual committed local activation checkpoint using local
	// stores only. The application deliberately exposes no activation workflow.
	if _, err := keys.Revoke(record.BootstrapKey.Scope, record.BootstrapKey.Name); err != nil {
		t.Fatal(err)
	}
	record, _, err = manager.Activate(systemID, record.Name, record.Revision, controlnodes.ActivationConfirmation{
		ControlKey: record.Access.Pending, AccessUser: record.Access.PendingAccessUser,
		ManagementProofVerified: true, BootstrapRevocationVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Transition(systemID, record.Name, record.Revision, controlnodes.LifecycleReady); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.NewManager(systemStore, workflow.WithClock(app.now)).Advance(proof.Task.ID, proof.Task.Revision, workflow.PhaseReady); err != nil {
		t.Fatal(err)
	}
	system, err := app.systems.Active()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.systems.Update(systemID, system.Revision, func(candidate *systemstate.System) error {
		candidate.Status = systemstate.StatusActive
		candidate.Bootstrap.State = systemstate.BootstrapControlActive
		candidate.Bootstrap.BootstrapKeyRevoked = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	document, err := topology.NewStore(systemStore).Load()
	if err != nil {
		t.Fatal(err)
	}
	document.ControlReady = true
	if err := systemStore.WriteJSON("topology/topology.json", document); err != nil {
		t.Fatal(err)
	}
	before := diagnosticTreeSnapshot(t, store.Root())
	result, err := app.Diagnose(context.Background())
	if err != nil || !result.Healthy || !result.ControlReady || result.NetworkConnections != 0 || runner.calls != 1 {
		t.Fatalf("ready metadata diagnostics=%+v err=%v calls=%d", result, err, runner.calls)
	}
	if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("ready diagnostics changed state")
	}
	proofPath, _ := systemStore.Path(controlProofRelative(record.Name))
	if err := os.Remove(proofPath); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "control:readiness")
	changedProof := proof.Evidence
	changedProof.ManagementGeneration++
	if err := systemStore.WriteJSON(controlProofRelative(record.Name), changedProof); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "control:readiness")
	if err := systemStore.WriteJSON(controlProofRelative(record.Name), proof.Evidence); err != nil {
		t.Fatal(err)
	}
	now := app.now().Add(initialControlPolicyLifetime + time.Second)
	app.now = func() time.Time { return now }
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "control:readiness")
	if runner.calls != 1 {
		t.Fatalf("readiness diagnostics opened another connection: calls=%d", runner.calls)
	}
}

func TestDiagnosticsRejectCorruptRegistryWithoutLegacyFallback(t *testing.T) {
	_, store := openApplication(t)
	if err := store.WriteFile("systems/registry.json", []byte(`{"schema":999}`)); err != nil {
		t.Fatal(err)
	}
	before := diagnosticTreeSnapshot(t, store.Root())
	result, err := DiagnoseLocal(context.Background(), Config{Store: store})
	if err != nil || result.Scope != "system" || result.Healthy || result.ControlReady || result.NetworkConnections != 0 {
		t.Fatalf("corrupt registry fell back: %+v %v", result, err)
	}
	if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("corrupt registry was repaired")
	}
}

func TestDiagnosticsUnregisteredSystemDataDoesNotUseLegacyScope(t *testing.T) {
	app, store := openApplication(t)
	if _, err := store.EnsureDir("systems/sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "system:registry")
	result, err := DiagnoseLocal(context.Background(), Config{Store: store})
	if err != nil || result.Scope != "system" || result.Healthy {
		t.Fatalf("orphaned system fell back to legacy scope: %+v %v", result, err)
	}
}

func TestDiagnosticsIncompleteInitializationChecksAnyCommittedTrust(t *testing.T) {
	app, store := openApplication(t)
	system, _, err := app.systems.CreateOrGet("partial-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	assertPending := func(t *testing.T) {
		t.Helper()
		before := diagnosticTreeSnapshot(t, store.Root())
		result, err := app.Diagnose(context.Background())
		check := diagnosticCheckByName(result, "system:initialization")
		if err != nil || !result.Healthy || result.ControlReady || check == nil || check.Status != DiagnosticPending {
			t.Fatalf("incomplete initialization not healthy/pending: %+v %v", result, err)
		}
		if after := diagnosticTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
			t.Fatal("pending-initialization diagnostics changed state")
		}
	}
	assertPending(t)
	if _, err := store.EnsureDir(filepath.Join("systems", system.ID)); err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(system.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertPending(t)
	if _, err := operatortrust.Ensure(systemStore); err != nil {
		t.Fatal(err)
	}
	assertPending(t)
	privatePath, _ := systemStore.Path("keys/signing/system-root.private.pem")
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	assertDiagnosticFailureWithoutMutation(t, app, store.Root(), "trust:roots")
}

func diagnosticCheckByName(result DiagnosticsResult, name string) *DiagnosticCheck {
	for index := range result.Checks {
		if result.Checks[index].Name == name {
			return &result.Checks[index]
		}
	}
	return nil
}

func assertDiagnosticFailureWithoutMutation(t *testing.T, app *Application, root, name string) {
	t.Helper()
	before := diagnosticTreeSnapshot(t, root)
	result, err := app.Diagnose(context.Background())
	check := diagnosticCheckByName(result, name)
	if err != nil || result.Healthy || result.ControlReady || result.NetworkConnections != 0 || check == nil || check.Status != DiagnosticFailed {
		t.Fatalf("inconsistent state not rejected by %s: %+v %v", name, result, err)
	}
	if after := diagnosticTreeSnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("diagnostic check %s changed local state", name)
	}
}

func diagnosticTreeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		value := fmt.Sprintf("%v:%d", info.Mode(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(data))
			clear(data)
		}
		result[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
