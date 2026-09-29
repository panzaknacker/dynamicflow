package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

func TestControlBindPlanAndCommitAreNetworkFreeIdempotentAndPublicOnly(t *testing.T) {
	app, store := openApplication(t)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "lab", ControlName: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testControlBindRequest(t)
	controlsPath, err := store.Path(filepath.Join("systems", initialized.System.ID, "control-nodes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(controlsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected pre-plan Control state: %v", err)
	}
	plan, err := app.PlanControlBind(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.NetworkConnections != 0 || plan.GeneratesPrivateKeys ||
		plan.ControlName != "control-1" || plan.HostKeyFingerprint == "" || len(plan.Changes) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := os.Lstat(controlsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created Control state: %v", err)
	}

	events := []Event{}
	first, err := app.BindControl(context.Background(), request, ObserverFunc(func(event Event) {
		events = append(events, event)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Resumed || first.NetworkConnections != 0 || first.TopologyGeneration != 1 ||
		first.Control.Lifecycle != controlnodes.LifecycleBound || first.Task.Phase != workflow.PhaseHostKeyVerified ||
		first.System.Bootstrap.State != systemstate.BootstrapHostBound ||
		first.System.Bootstrap.ControlNodeID != "control-1" ||
		first.System.Bootstrap.HostKeyFingerprint != first.Control.HostFingerprint || len(events) < 4 {
		t.Fatalf("first bind = %+v events=%+v", first, events)
	}
	second, err := app.BindControl(context.Background(), request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || !second.Resumed || second.Control != first.Control || second.Task != first.Task ||
		second.System.Revision != first.System.Revision || second.TopologyGeneration != first.TopologyGeneration {
		t.Fatalf("idempotent bind changed checkpoint: first=%+v second=%+v", first, second)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Controls) != 1 || status.Controls[0] != first.Control || status.Topology == nil ||
		status.Topology.ControlReady || status.Topology.Control == nil ||
		status.Topology.Control.HostKeyFingerprint != first.Control.HostFingerprint {
		t.Fatalf("Control status = %+v", status)
	}

	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	privatePath, err := store.Path(filepath.Join("systems", first.System.ID, "keys", "bootstrap", "control-1", "generations", "000001", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, privateBytes) || bytes.Contains(encoded, []byte(privatePath)) || bytes.Contains(encoded, []byte("PRIVATE KEY")) {
		t.Fatalf("Control result leaked private material: %s", encoded)
	}
}

func TestControlBindConflictsFailClosedWithoutChangingPin(t *testing.T) {
	app, _ := openApplication(t)
	if _, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "lab"}, nil); err != nil {
		t.Fatal(err)
	}
	request := testControlBindRequest(t)
	first, err := app.BindControl(context.Background(), request, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "203.0.113.99"
	_, err = app.BindControl(context.Background(), request, nil)
	failure := AsError(err)
	if failure.Code != "control_binding_conflict" || failure.ExitCode != 6 {
		t.Fatalf("conflicting rebind error = %+v (%v)", failure, err)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Controls) != 1 || status.Controls[0] != first.Control {
		t.Fatalf("conflict changed immutable pin: %+v", status.Controls)
	}
}

func TestControlBindRejectsBootstrapKeyAsHostKey(t *testing.T) {
	app, _ := openApplication(t)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "lab"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testControlBindRequest(t)
	request.HostPublicKey = initialized.Cloud.PublicKey
	_, err = app.BindControl(context.Background(), request, nil)
	failure := AsError(err)
	if failure.Code != "control_hostkey" || failure.ExitCode != 5 {
		t.Fatalf("shared auth/host key error = %+v (%v)", failure, err)
	}
	status, statusErr := app.ControlStatus(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if len(status.Controls) != 0 || status.Topology != nil {
		t.Fatalf("rejected shared key committed state: %+v", status)
	}
}

func TestConcurrentControlBindCreatesOneImmutableBinding(t *testing.T) {
	app, _ := openApplication(t)
	if _, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "parallel-control"}, nil); err != nil {
		t.Fatal(err)
	}
	request := testControlBindRequest(t)
	const workers = 6
	results := make(chan BindControlResult, workers)
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := app.BindControl(context.Background(), request, nil)
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
	created := 0
	var fingerprint string
	for result := range results {
		if result.Created {
			created++
		}
		if fingerprint == "" {
			fingerprint = result.Control.HostFingerprint
		}
		if result.Control.HostFingerprint != fingerprint || result.Task.Phase != workflow.PhaseHostKeyVerified {
			t.Fatalf("concurrent result = %+v", result)
		}
	}
	if created != 1 {
		t.Fatalf("created bindings = %d, want 1", created)
	}
}

func testControlBindRequest(t *testing.T) BindControlRequest {
	t.Helper()
	return BindControlRequest{
		Meta: applicationTestMeta(), Name: "control-1", Host: "203.0.113.40", Port: 22,
		SSHUser: "debian", OperatingSystem: controlnodes.OSDebian13,
		HostPublicKey: testHostPublicKey(t), EvidenceSource: controlnodes.EvidenceProviderConsole,
	}
}

func applicationTestMeta() RequestMeta {
	return RequestMeta{Surface: SurfaceCLI, CorrelationID: "test-control-bind"}
}

func testHostPublicKey(t *testing.T) string {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	base := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")
	command := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "untrusted-comment", "-f", base)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate host key: %v: %s", err, output)
	}
	data, err := os.ReadFile(base + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sshkeys.ValidateEd25519PublicKey(string(data)); err != nil {
		t.Fatalf("generated host key: %v", err)
	}
	return string(data)
}
