package application

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
)

func openApplication(t *testing.T) (*Application, *localstate.Store) {
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
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
	application, err := Open(Config{Store: store, Clock: func() time.Time { return clock }, Random: random, SSHKeygen: keygen})
	if err != nil {
		t.Fatal(err)
	}
	return application, store
}

func TestInitSystemCreatesRealStableControlBootstrap(t *testing.T) {
	application, store := openApplication(t)
	events := []Event{}
	observer := ObserverFunc(func(event Event) { events = append(events, event) })
	first, err := application.InitSystem(context.Background(), InitSystemRequest{Name: "lab", ControlName: "control-1"}, observer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := application.InitSystem(context.Background(), InitSystemRequest{Name: "lab", ControlName: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || second.Created || !second.Resumed || first.System.ID != second.System.ID ||
		first.Cloud.PublicKey != second.Cloud.PublicKey || first.Cloud.PublicKeyFingerprint != second.Cloud.PublicKeyFingerprint || first.Task.Key != second.Task.Key {
		t.Fatalf("init/resume changed identity: first=%+v second=%+v", first, second)
	}
	if len(events) < 3 || first.Task.Phase != "awaiting_cloud_vm" || first.System.Bootstrap.State != "key_prepared" {
		t.Fatalf("events/task/system = %+v %+v %+v", events, first.Task, first.System)
	}
	privatePath, _ := store.Path(filepath.Join("systems", first.System.ID, "keys", "bootstrap", "control-1", "generations", "000001", "id_ed25519"))
	info, err := os.Lstat(privatePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private bootstrap key = %v, %v", info, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, private) || strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), privatePath) {
		t.Fatal("application result leaked private key material or path")
	}
}

func TestDashboardBlocksServingAndInstancesUntilControlReady(t *testing.T) {
	application, _ := openApplication(t)
	fresh, err := application.Dashboard(context.Background())
	if err != nil || len(fresh.Systems) != 0 || len(fresh.Tasks) != 0 {
		t.Fatalf("fresh dashboard = %+v, %v", fresh, err)
	}
	if _, err := application.InitSystem(context.Background(), InitSystemRequest{Name: "lab"}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := application.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Bootstrap == nil || snapshot.Bootstrap.PublicKey == "" || snapshot.Bootstrap.TaskID != "control-bootstrap-control-1" {
		t.Fatalf("resumable bootstrap guide = %+v", snapshot.Bootstrap)
	}
	for _, capability := range snapshot.Capabilities {
		if (capability.Action == "serving.create" || capability.Action == "instance.create" || capability.Action == "instance.ssh") &&
			(capability.Allowed || capability.Reason != "control_required") {
			t.Fatalf("unsafe capability = %+v", capability)
		}
	}
}

func TestDashboardExposesPinnedControlTopologyAndNextTrustGate(t *testing.T) {
	application, _ := openApplication(t)
	if _, err := application.InitSystem(context.Background(), InitSystemRequest{Name: "dashboard-control"}, nil); err != nil {
		t.Fatal(err)
	}
	bound, err := application.BindControl(context.Background(), testControlBindRequest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := application.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Controls) != 1 || snapshot.Controls[0] != bound.Control || snapshot.Topology == nil ||
		snapshot.Topology.Generation != 1 || snapshot.Topology.ControlReady {
		t.Fatalf("dashboard Control state = %+v", snapshot)
	}
	var bind, check *Capability
	for index := range snapshot.Capabilities {
		capability := &snapshot.Capabilities[index]
		switch capability.Action {
		case "control.bind":
			bind = capability
		case "control.check":
			check = capability
		}
	}
	if bind == nil || bind.Allowed || bind.Reason != "control_already_bound" ||
		check == nil || !check.Allowed || check.Reason != "" {
		t.Fatalf("dashboard capabilities = %+v", snapshot.Capabilities)
	}
}

func TestConcurrentInitCreatesOneSystemAndOneKey(t *testing.T) {
	application, _ := openApplication(t)
	const workers = 8
	results := make(chan InitSystemResult, workers)
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := application.InitSystem(context.Background(), InitSystemRequest{Name: "parallel"}, nil)
			results <- result
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
	var systemID, fingerprint string
	created := 0
	for result := range results {
		if result.Created {
			created++
		}
		if systemID == "" {
			systemID, fingerprint = result.System.ID, result.Cloud.PublicKeyFingerprint
		}
		if result.System.ID != systemID || result.Cloud.PublicKeyFingerprint != fingerprint {
			t.Fatal("concurrent init produced different system or key")
		}
	}
	if created != 1 {
		t.Fatalf("created results = %d", created)
	}
}

func TestDashboardDoesNotCreateMissingPerSystemState(t *testing.T) {
	application, store := openApplication(t)
	system, _, err := application.systems.CreateOrGet("interrupted")
	if err != nil {
		t.Fatal(err)
	}
	directory, _ := store.Path(filepath.Join("systems", system.ID))
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("test precondition: system directory exists: %v", err)
	}
	snapshot, err := application.Dashboard(context.Background())
	if err != nil || len(snapshot.Systems) != 1 || len(snapshot.Tasks) != 0 {
		t.Fatalf("interrupted dashboard = %+v, %v", snapshot, err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("read-only dashboard created system directory: %v", err)
	}
}

func TestSystemInitPlanIsReadOnlyAndNetworkFree(t *testing.T) {
	application, store := openApplication(t)
	plan, err := application.PlanSystemInit(InitSystemRequest{Name: "planned"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.NetworkConnections != 0 || !plan.GeneratesPrivateKeys || !plan.DisplaysPublicOnly || !plan.RequiresOOBHostKey {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := os.Lstat(filepath.Join(store.Root(), "systems")); !os.IsNotExist(err) {
		t.Fatalf("plan created system state: %v", err)
	}
}
