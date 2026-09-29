package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

func TestPrepareControlInstallIsLocalPublicOnlyAndIdempotent(t *testing.T) {
	app, store, systemID := checkedControlForInstall(t)
	controlKeysPath, err := store.Path(filepath.Join("systems", systemID, "keys", "control"))
	if err != nil {
		t.Fatal(err)
	}
	envelopePath, err := store.Path(filepath.Join("systems", systemID, controlEnvelopeRelative("control-1")))
	if err != nil {
		t.Fatal(err)
	}

	plan, err := app.PlanControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || !plan.GeneratesPrivateKeys || plan.NetworkConnections != 0 || plan.RouteCount != 0 ||
		plan.ManagementUser != controlnodes.ManagementAccessUser || plan.PolicyGeneration != 1 || len(plan.Changes) != 4 {
		t.Fatalf("install plan = %+v", plan)
	}
	if _, err := os.Lstat(controlKeysPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created Control key state: %v", err)
	}
	if _, err := os.Lstat(envelopePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created envelope state: %v", err)
	}
	dashboard, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capability := capabilityByAction(dashboard.Capabilities, "control.install"); capability == nil || !capability.Allowed {
		t.Fatalf("Control install capability before preparation = %+v", dashboard.Capabilities)
	}

	events := []Event{}
	first, err := app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, ObserverFunc(func(event Event) {
		events = append(events, event)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Prepared || first.Resumed || first.NetworkConnections != 0 || first.ManagementPublicKey == "" ||
		first.ManagementUser != controlnodes.ManagementAccessUser || first.PolicyGeneration != 1 ||
		first.Control.Lifecycle != controlnodes.LifecycleInstalling || first.Control.Access.Phase != controlnodes.AccessStaged ||
		first.Control.Access.Active.Scope != sshkeys.Bootstrap || first.Control.Access.Pending.Scope != sshkeys.Control ||
		first.Task.Phase != workflow.PhaseInstalling || first.System.Bootstrap.State != systemstate.BootstrapProvisioning ||
		!strings.HasPrefix(first.EnvelopeDigest, "sha256:") || len(first.EnvelopeDigest) != 71 || len(events) < 3 {
		t.Fatalf("prepared install = %+v events=%+v", first, events)
	}
	if first.ManagementIdentity != first.Control.Access.Pending {
		t.Fatalf("result identity does not match staged identity: %+v", first)
	}

	systemStore, err := app.openSystemStore(systemID)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(systemStore, sshkeys.WithSSHKeygen(app.sshKeygen), sshkeys.WithClock(app.now), sshkeys.WithControlScope())
	manager, err := controlnodes.NewManager(store, keys, controlnodes.WithClock(app.now))
	if err != nil {
		t.Fatal(err)
	}
	active, err := manager.AccessMaterial(systemID, "control-1")
	if err != nil || active.Identity.Scope != sshkeys.Bootstrap || active.SSHUser != "debian" {
		t.Fatalf("bootstrap access changed before proof: material=%+v err=%v", active, err)
	}
	pending, err := manager.PendingAccessMaterial(systemID, "control-1")
	if err != nil || pending.Identity != first.ManagementIdentity || pending.SSHUser != controlnodes.ManagementAccessUser {
		t.Fatalf("pending management material = %+v err=%v", pending, err)
	}
	privateBytes, err := os.ReadFile(pending.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(pending.IdentityPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("management private key mode = %v err=%v", info, err)
	}
	encodedResult, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedResult, privateBytes) || bytes.Contains(encodedResult, []byte(pending.IdentityPath)) ||
		bytes.Contains(encodedResult, []byte("PRIVATE KEY")) {
		t.Fatalf("public prepare result leaked private material: %s", encodedResult)
	}

	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := controlruntime.ParseCanonical(envelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := controlruntime.VerifyEnvelope(envelope, app.now().UTC(), systemID, "control-1", 1); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Policy.Policy.Routes) != 0 || len(envelope.Policy.Policy.ManagementKeys) != 1 ||
		envelope.Policy.Policy.ManagementKeys[0].Fingerprint != first.ManagementIdentity.Fingerprint ||
		bytes.Contains(envelopeBytes, privateBytes) || bytes.Contains(envelopeBytes, []byte("PRIVATE KEY")) {
		t.Fatalf("unsafe initial envelope: %+v", envelope.Policy.Policy)
	}

	second, err := app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Prepared || !second.Resumed || second.ManagementIdentity != first.ManagementIdentity ||
		second.EnvelopeDigest != first.EnvelopeDigest || second.Control != first.Control || second.Task != first.Task ||
		second.System.Revision != first.System.Revision {
		t.Fatalf("idempotent preparation changed checkpoint: first=%+v second=%+v", first, second)
	}
	preparedPlan, err := app.PlanControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"})
	if err != nil || !preparedPlan.AlreadyPrepared || preparedPlan.GeneratesPrivateKeys || len(preparedPlan.Changes) != 0 {
		t.Fatalf("prepared plan = %+v err=%v", preparedPlan, err)
	}
	dashboard, err = app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capability := capabilityByAction(dashboard.Capabilities, "control.install"); capability == nil || !capability.Allowed {
		t.Fatalf("resumable Control install capability = %+v", dashboard.Capabilities)
	}
}

func TestPrepareControlInstallConcurrentCallsCommitOneIdentity(t *testing.T) {
	app, _, _ := checkedControlForInstall(t)
	const workers = 6
	results := make(chan PrepareControlInstallResult, workers)
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, nil)
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
	var reference controlnodes.AccessKeyRef
	var digest string
	for result := range results {
		if !result.Resumed {
			created++
		}
		if reference == (controlnodes.AccessKeyRef{}) {
			reference, digest = result.ManagementIdentity, result.EnvelopeDigest
		}
		if result.ManagementIdentity != reference || result.EnvelopeDigest != digest || result.Control.Access.Phase != controlnodes.AccessStaged {
			t.Fatalf("parallel result changed identity: %+v", result)
		}
	}
	if created != 1 {
		t.Fatalf("fresh preparations = %d, want 1", created)
	}
}

func TestPreparedControlEnvelopeCorruptionFailsClosedWithoutRotation(t *testing.T) {
	app, store, systemID := checkedControlForInstall(t)
	prepared, err := app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(systemID)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(systemStore, sshkeys.WithSSHKeygen(app.sshKeygen), sshkeys.WithClock(app.now), sshkeys.WithControlScope())
	before, err := keys.Get(sshkeys.Control, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := systemStore.WriteFile(controlEnvelopeRelative("control-1"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	_, err = app.PlanControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"})
	if err == nil || AsError(err).Code != "control_install_envelope" {
		t.Fatalf("corrupt envelope plan error = %+v (%v)", AsError(err), err)
	}
	_, err = app.PrepareControlInstall(context.Background(), PrepareControlInstallRequest{Name: "control-1"}, nil)
	if err == nil || AsError(err).Code != "control_install_prepare" {
		t.Fatalf("corrupt envelope prepare error = %+v (%v)", AsError(err), err)
	}
	after, err := keys.Get(sshkeys.Control, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation || after.Fingerprint != prepared.ManagementIdentity.Fingerprint {
		t.Fatalf("corrupt envelope rotated management key: before=%+v after=%+v", before, after)
	}
	audit, err := os.ReadFile(filepath.Join(store.Root(), "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(before.PublicKey)) {
		t.Fatal("audit contains full management public key instead of bounded fingerprint")
	}
}

func checkedControlForInstall(t *testing.T) (*Application, *localstate.Store, string) {
	t.Helper()
	runner := &applicationControlRunner{}
	app, store := openApplicationWithControlRunner(t, runner)
	initialized, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "install-lab", ControlName: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), testControlBindRequest(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CheckControl(context.Background(), CheckControlRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	return app, store, initialized.System.ID
}

func capabilityByAction(capabilities []Capability, action string) *Capability {
	for index := range capabilities {
		if capabilities[index].Action == action {
			return &capabilities[index]
		}
	}
	return nil
}
