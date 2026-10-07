package application

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
)

func TestInitNeverReplacesCommittedTrustOrBootstrapIdentity(t *testing.T) {
	for _, scenario := range []string{"registry missing", "trust binding missing", "trust manifest missing", "trust pair missing", "replacement trust bundle", "bootstrap missing", "task missing", "different Control name", "changed expiry"} {
		t.Run(scenario, func(t *testing.T) {
			app, store := openApplication(t)
			request := InitSystemRequest{Name: "immutable", ControlName: "control-1"}
			first, err := app.InitSystem(context.Background(), request, nil)
			if err != nil {
				t.Fatal(err)
			}
			systemStore, err := app.openSystemStore(first.System.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "registry missing":
				removeIdentityFixture(t, store, "systems/registry.json")
			case "trust binding missing":
				registry, err := app.systems.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				registry.Systems[0].Trust = systemstate.TrustMetadata{}
				if err := store.WriteJSON("systems/registry.json", registry); err != nil {
					t.Fatal(err)
				}
			case "trust manifest missing":
				removeIdentityFixture(t, systemStore, "keys/signing/trust.json")
			case "trust pair missing":
				removeIdentityFixture(t, systemStore, "keys/signing/control-policy.private.pem")
				removeIdentityFixture(t, systemStore, "keys/signing/control-policy.public.pem")
			case "replacement trust bundle":
				removeIdentityFixture(t, systemStore, "keys/signing/control-policy.private.pem")
				removeIdentityFixture(t, systemStore, "keys/signing/control-policy.public.pem")
				private, _ := systemStore.Path("keys/signing/control-policy.private.pem")
				public, _ := systemStore.Path("keys/signing/control-policy.public.pem")
				if _, err := signing.GenerateFiles(private, public); err != nil {
					t.Fatal(err)
				}
				key, err := signing.LoadPublicFile(public)
				if err != nil {
					t.Fatal(err)
				}
				bundle := first.Trust
				bundle.ControlPolicy, err = signing.KeyID(key)
				if err != nil {
					t.Fatal(err)
				}
				if err := systemStore.WriteJSON("keys/signing/trust.json", bundle); err != nil {
					t.Fatal(err)
				}
				if _, err := operatortrust.Load(systemStore); err != nil {
					t.Fatalf("replacement bundle must be internally valid for this regression: %v", err)
				}
			case "bootstrap missing":
				if err := os.RemoveAll(filepath.Join(systemStore.Root(), "keys", "bootstrap", "control-1")); err != nil {
					t.Fatal(err)
				}
			case "task missing":
				removeIdentityFixture(t, systemStore, filepath.Join("workflows", "tasks", first.Task.ID+".json"))
			case "different Control name":
				request.ControlName = "control-other"
			case "changed expiry":
				_, err = app.systems.Update(first.System.ID, first.System.Revision, func(candidate *systemstate.System) error {
					expiry := candidate.Bootstrap.ExpiresAt.Add(time.Hour)
					candidate.Bootstrap.ExpiresAt = &expiry
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			before := identityFileSnapshot(t, store.Root())
			if _, err := app.PlanSystemInit(request); err == nil {
				t.Fatal("initialization plan accepted changed or lost identity state")
			}
			_, err = app.InitSystem(context.Background(), request, nil)
			if err == nil {
				t.Fatal("reinitialization accepted changed or lost identity state")
			}
			if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
				t.Fatal("failed reinitialization generated or rewrote committed state")
			}
		})
	}
}

func TestInitPreservesExistingTrustGeneration(t *testing.T) {
	app, store := openApplication(t)
	request := InitSystemRequest{Name: "versioned", ControlName: "control-1"}
	first, err := app.InitSystem(context.Background(), request, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.systems.Update(first.System.ID, first.System.Revision, func(candidate *systemstate.System) error {
		candidate.Trust.Generation = 4
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := identityFileSnapshot(t, filepath.Join(store.Root(), "systems", first.System.ID))
	plan, err := app.PlanSystemInit(request)
	if err != nil || plan.GeneratesPrivateKeys || plan.ExistingSystemID != first.System.ID {
		t.Fatalf("valid resumed plan does not preserve identity: plan=%+v err=%v", plan, err)
	}
	again, err := app.InitSystem(context.Background(), request, nil)
	if err != nil || again.System.Trust.Generation != 4 || again.Cloud.PublicKey != first.Cloud.PublicKey || again.Trust != first.Trust {
		t.Fatalf("resume changed committed generation: result=%+v err=%v", again, err)
	}
	if after := identityFileSnapshot(t, filepath.Join(store.Root(), "systems", first.System.ID)); !reflect.DeepEqual(before, after) {
		t.Fatal("idempotent initialization rewrote committed system identity files")
	}
}

func TestInitPartialCheckpointNeverRepairsLostTrust(t *testing.T) {
	for _, checkpoint := range []string{"task", "key", "key-generation-started"} {
		for _, lostPair := range []bool{false, true} {
			name := checkpoint + "/manifest"
			if lostPair {
				name += "-and-pair"
			}
			t.Run(name, func(t *testing.T) {
				app, store := openApplication(t)
				request := InitSystemRequest{Name: "interrupted-trust", ControlName: "control-1"}
				initialized, err := app.InitSystem(context.Background(), request, nil)
				if err != nil {
					t.Fatal(err)
				}
				registry, err := app.systems.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				registry.Systems[0].Trust = systemstate.TrustMetadata{}
				registry.Systems[0].Bootstrap = systemstate.BootstrapMetadata{State: systemstate.BootstrapNotStarted}
				if err := store.WriteJSON("systems/registry.json", registry); err != nil {
					t.Fatal(err)
				}
				systemStore, err := app.openSystemStore(initialized.System.ID)
				if err != nil {
					t.Fatal(err)
				}
				if checkpoint != "task" {
					removeIdentityFixture(t, systemStore, filepath.Join("workflows", "tasks", initialized.Task.ID+".json"))
				}
				if checkpoint == "key-generation-started" {
					if err := os.RemoveAll(filepath.Join(systemStore.Root(), "keys", "bootstrap", "control-1")); err != nil {
						t.Fatal(err)
					}
				}
				removeIdentityFixture(t, systemStore, "keys/signing/trust.json")
				if lostPair {
					removeIdentityFixture(t, systemStore, "keys/signing/control-policy.private.pem")
					removeIdentityFixture(t, systemStore, "keys/signing/control-policy.public.pem")
				}
				before := identityFileSnapshot(t, store.Root())
				_, planErr := app.PlanSystemInit(request)
				_, applyErr := app.InitSystem(context.Background(), request, nil)
				if AsError(planErr).Code != "system_trust" || AsError(applyErr).Code != "system_trust" {
					t.Fatalf("lost checkpoint-bound trust was accepted: plan=%v apply=%v", planErr, applyErr)
				}
				if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
					t.Fatal("checkpoint-bound initialization repaired or replaced missing trust")
				}
			})
		}
	}
}

func TestInitResumesBeforeTaskCheckpointWithoutReplacingTrust(t *testing.T) {
	for _, keyReady := range []bool{false, true} {
		name := "key-generation-started"
		if keyReady {
			name = "key-ready"
		}
		t.Run(name, func(t *testing.T) {
			app, store := openApplication(t)
			request := InitSystemRequest{Name: "before-task", ControlName: "control-1"}
			system, _, err := app.systems.CreateOrGet(request.Name)
			if err != nil {
				t.Fatal(err)
			}
			systemStore, err := app.ensureSystemStore(system.ID)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := operatortrust.Ensure(systemStore)
			if err != nil {
				t.Fatal(err)
			}
			var key sshkeys.Record
			if keyReady {
				key, err = sshkeys.NewManager(systemStore).Create(context.Background(), sshkeys.Bootstrap, request.ControlName)
			} else {
				_, err = systemStore.EnsureDir("keys/bootstrap/control-1/generations/000001")
			}
			if err != nil {
				t.Fatal(err)
			}
			before := identityFileSnapshot(t, store.Root())
			plan, err := app.PlanSystemInit(request)
			if err != nil || plan.GeneratesPrivateKeys == keyReady {
				t.Fatalf("partial key checkpoint plan: plan=%+v err=%v", plan, err)
			}
			if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
				t.Fatal("partial key checkpoint plan changed state")
			}
			resumed, err := app.InitSystem(context.Background(), request, nil)
			if err != nil || resumed.Trust != trust || resumed.System.ID != system.ID || (keyReady && resumed.Cloud.PublicKey != key.PublicKey) {
				t.Fatalf("partial key checkpoint resume: result=%+v err=%v", resumed, err)
			}
		})
	}
}

func TestInitRejectsUnusableControlNamesBeforeCreatingAnyState(t *testing.T) {
	app, store := openApplication(t)
	before := identityFileSnapshot(t, store.Root())
	for _, name := range []string{"UPPER", "control_name", "control.name", "1control", "-control", strings.Repeat("a", 64), "control\nnext"} {
		request := InitSystemRequest{Name: "must-not-exist", ControlName: name}
		if _, err := app.PlanSystemInit(request); AsError(err).ExitCode != 2 {
			t.Errorf("invalid Control name plan was accepted: %q err=%v", name, err)
		}
		if _, err := app.InitSystem(context.Background(), request, nil); AsError(err).ExitCode != 2 {
			t.Errorf("invalid Control name init was accepted: %q err=%v", name, err)
		}
	}
	if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("invalid Control name created registry, trust or bootstrap files")
	}
}

func TestInitPlanAndExecutionBothRejectAdvancedBootstrap(t *testing.T) {
	app, store := openApplication(t)
	request := InitSystemRequest{Name: "already-bound", ControlName: "control-1"}
	if _, err := app.InitSystem(context.Background(), request, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	before := identityFileSnapshot(t, store.Root())
	_, planErr := app.PlanSystemInit(request)
	_, applyErr := app.InitSystem(context.Background(), request, nil)
	if AsError(planErr).Code != "system_bootstrap_advanced" || AsError(applyErr).Code != "system_bootstrap_advanced" {
		t.Fatalf("plan and action diverged: plan=%v apply=%v", planErr, applyErr)
	}
	if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("reinitialization of bound Control mutated state")
	}
}

func removeIdentityFixture(t *testing.T, store *localstate.Store, relative string) {
	t.Helper()
	path, err := store.Path(relative)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

type identityFileState struct {
	Mode   fs.FileMode
	Digest [sha256.Size]byte
}

func identityFileSnapshot(t *testing.T, root string) map[string]identityFileState {
	t.Helper()
	result := make(map[string]identityFileState)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		state := identityFileState{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			state.Digest = sha256.Sum256(data)
		}
		result[relative] = state
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
