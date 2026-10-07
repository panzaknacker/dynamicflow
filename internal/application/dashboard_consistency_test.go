package application

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"dynamicflow/internal/systemstate"
)

func TestDashboardRetainsOneSystemSnapshotDuringSelection(t *testing.T) {
	app, _ := openSelectionApplication(t)
	first := initializeSelectionSystem(t, app, "first")
	bound, err := app.BindControl(context.Background(), testControlBindRequest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	second := initializeSelectionSystem(t, app, "second")
	before, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// ObservedAt is read after the registry snapshot but before per-system
	// tasks, keys and Controls. Switch at that boundary without relying on a
	// scheduler race; each application read must retain the first system.
	clock := app.now
	switched := false
	app.now = func() time.Time {
		if !switched {
			switched = true
			if _, err := app.systems.SetActive(second.System.ID, before.Revision); err != nil {
				t.Fatal(err)
			}
		}
		return clock()
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveSystemID != first.System.ID || snapshot.RegistryRevision != before.Revision ||
		snapshot.Bootstrap == nil || snapshot.Bootstrap.SystemID != first.System.ID ||
		snapshot.Bootstrap.PublicKey != first.Cloud.PublicKey || snapshot.Bootstrap.HostTrustRequired ||
		len(snapshot.Controls) != 1 || snapshot.Controls[0] != bound.Control ||
		len(snapshot.Tasks) != 1 || snapshot.Tasks[0].SystemID != first.System.ID ||
		!reflect.DeepEqual(snapshot.Systems, before.Systems) {
		t.Fatalf("dashboard combined different system snapshots: %+v", snapshot)
	}
	active, err := app.systems.Active()
	if err != nil || active.ID != second.System.ID {
		t.Fatalf("selection fixture did not advance: active=%+v err=%v", active, err)
	}
}

func TestDashboardRejectsLostCommittedSystemState(t *testing.T) {
	app, store := openApplication(t)
	initialized := initializeSelectionSystem(t, app, "missing-committed")
	directory := filepath.Join(store.Root(), "systems", initialized.System.ID)
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	_, err := app.Dashboard(context.Background())
	if AsError(err).Code != "system_state" {
		t.Fatalf("missing committed state looked like uninitialized state: %v", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("dashboard recreated lost state: %v", err)
	}
}

func TestDashboardRejectsBootstrapFingerprintMismatch(t *testing.T) {
	app, _ := openApplication(t)
	initialized := initializeSelectionSystem(t, app, "mismatched-bootstrap")
	_, err := app.systems.Update(initialized.System.ID, initialized.System.Revision, func(candidate *systemstate.System) error {
		candidate.Bootstrap.BootstrapKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.Dashboard(context.Background())
	if AsError(err).Code != "bootstrap_identity" {
		t.Fatalf("dashboard displayed key from a different bootstrap binding: %v", err)
	}
}

func TestDashboardAllowsTaskBeforeInitializationCheckpoint(t *testing.T) {
	app, store := openApplication(t)
	initialized := initializeSelectionSystem(t, app, "interrupted-checkpoint")
	registry, err := app.systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate process loss after the task was committed and before the
	// registry received the complete identity checkpoint.
	registry.Systems[0].Trust = systemstate.TrustMetadata{}
	registry.Systems[0].Bootstrap = systemstate.BootstrapMetadata{State: systemstate.BootstrapNotStarted}
	if err := store.WriteJSON("systems/registry.json", registry); err != nil {
		t.Fatal(err)
	}
	before := identityFileSnapshot(t, store.Root())
	plan, err := app.PlanSystemInit(InitSystemRequest{Name: "interrupted-checkpoint"})
	if err != nil || plan.GeneratesPrivateKeys {
		t.Fatalf("prepared partial checkpoint would generate replacement identities: plan=%+v err=%v", plan, err)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil || snapshot.Bootstrap != nil || len(snapshot.Tasks) != 1 {
		t.Fatalf("resumable initialization was unavailable: snapshot=%+v err=%v", snapshot, err)
	}
	for _, capability := range snapshot.Capabilities {
		if capability.Action != "system.init" && capability.Allowed {
			t.Fatalf("uncommitted initialization offered operation: %+v", capability)
		}
	}
	if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("dashboard changed the interrupted checkpoint")
	}
	resumed := initializeSelectionSystem(t, app, "interrupted-checkpoint")
	if resumed.Trust != initialized.Trust || resumed.Task != initialized.Task || resumed.Cloud.PublicKey != initialized.Cloud.PublicKey {
		t.Fatal("resumption replaced the original identity")
	}
}
