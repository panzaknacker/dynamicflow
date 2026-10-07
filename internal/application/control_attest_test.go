package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

type managementProofRunner struct {
	app      *Application
	envelope []byte
	calls    int
	argv     []string
	fail     bool
	nonces   []string
}

func (runner *managementProofRunner) Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	if stdin != nil || len(argv) != 6 {
		return errors.New("unexpected management transport")
	}
	command := argv[len(argv)-1]
	fields := strings.Split(command, " ")
	if len(fields) != 5 || fields[0] != controlruntime.AttestationCommandV1 {
		return errors.New("unexpected attestation command")
	}
	runner.nonces = append(runner.nonces, fields[4])
	_, _ = io.WriteString(stderr, "discarded private remote detail")
	if runner.fail {
		return errors.New("private management authentication detail")
	}
	// Exercise the real remote ForceCommand verifier against the envelope that
	// was installed by the preceding application operation.
	session, err := controlruntime.NewSessionWithDependencies(controlruntime.SessionConfig{StateRoot: controlruntime.DefaultStateRoot}, controlruntime.SessionDependencies{
		LookupEnvironment: func(name string) (string, bool) {
			switch name {
			case "SSH_ORIGINAL_COMMAND":
				return command, true
			case "SSH_CONNECTION":
				return "192.0.2.10 54321 203.0.113.40 22", true
			default:
				return "", false
			}
		},
		CurrentIdentity: func() (controlruntime.SessionIdentity, error) {
			return controlruntime.SessionIdentity{Username: controlruntime.ManagementUser, UID: 1001, EffectiveUID: 1001}, nil
		},
		ReadActiveEnvelope: func(string) ([]byte, error) { return runner.envelope, nil }, Now: runner.app.now,
	})
	if err != nil {
		return err
	}
	response, err := session.Execute(ctx, controlruntime.SessionRequest{StateRoot: controlruntime.DefaultStateRoot})
	if err != nil {
		return err
	}
	_, err = stdout.Write(response)
	return err
}

func installedControlAttestFixture(t *testing.T) (*Application, *localstate.Store, string, *managementProofRunner) {
	t.Helper()
	installer := &controlApplyRunner{}
	app, store, systemID, _, _ := preparedControlApplyFixture(t, installer)
	if _, err := app.InstallPreparedControl(context.Background(), InstallPreparedControlRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	systemStore, err := app.openSystemStore(systemID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := systemStore.ReadFile(controlEnvelopeRelative("control-1"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &managementProofRunner{app: app, envelope: envelope}
	app.controlRunner = runner
	return app, store, systemID, runner
}

func TestControlAttestationPlanIsReadOnlyAndProofDoesNotActivateControl(t *testing.T) {
	app, store, systemID, runner := installedControlAttestFixture(t)
	before, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.PlanControlAttest(context.Background(), AttestControlRequest{Name: "control-1"})
	if err != nil || !plan.Plan || plan.NetworkConnections != 1 || plan.ControlReady || plan.Route != "direct_pending_control" || runner.calls != 0 {
		t.Fatalf("plan=%+v calls=%d err=%v", plan, runner.calls, err)
	}
	proofPath, _ := store.Path(filepath.Join("systems", systemID, controlProofRelative("control-1")))
	if _, err := os.Lstat(proofPath); !os.IsNotExist(err) {
		t.Fatalf("plan created proof: %v", err)
	}
	for range 2 {
		result, err := app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
		if err != nil || !result.Verified || result.NetworkConnections != 1 || result.BootstrapRevoked || result.ControlReady || result.Task.Phase != workflow.PhaseAttesting {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if result.Evidence.ManagementFingerprint != before.Controls[0].Access.Pending.Fingerprint || result.Evidence.EnvelopeDigest != plan.EnvelopeDigest {
			t.Fatalf("proof has wrong identity: %+v", result.Evidence)
		}
		serialized, err := json.Marshal(result)
		if err != nil || bytes.Contains(serialized, []byte("private remote detail")) || bytes.Contains(serialized, []byte("IdentityFile")) {
			t.Fatalf("proof leaked details: %s %v", serialized, err)
		}
	}
	if runner.calls != 2 || len(runner.nonces) != 2 || runner.nonces[0] == runner.nonces[1] {
		t.Fatalf("explicit repeat did not use exactly one fresh challenge: calls=%d nonces=%v", runner.calls, runner.nonces)
	}
	info, err := os.Stat(proofPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("proof permissions=%v err=%v", info, err)
	}
	state, err := app.controlAttestationContext("control-1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, manager, _, err := app.controlInstallContextWithResume("control-1", true)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := manager.PendingAccessMaterial(systemID, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := manager.AccessMaterial(systemID, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(runner.argv[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte(pending.IdentityPath)) || bytes.Contains(config, []byte(bootstrap.IdentityPath)) {
		t.Fatal("proof transport did not use the exclusive staged identity")
	}
	after, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.System, before.System) || !reflect.DeepEqual(after.Controls[0], before.Controls[0]) || !reflect.DeepEqual(after.Tasks[0], before.Tasks[0]) || after.Topology.ControlReady || state.record.Lifecycle != controlnodes.LifecycleInstalling {
		t.Fatalf("proof activated Control or changed lifecycle: %+v", after)
	}
}

func TestControlAttestationFailureResumesExplicitlyWithoutBootstrapFallback(t *testing.T) {
	app, _, _, runner := installedControlAttestFixture(t)
	runner.fail = true
	_, err := app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
	failure := AsError(err)
	if failure.Code != "control_attestation" || failure.ExitCode != 7 || strings.Contains(failure.Error(), "private management") || runner.calls != 1 {
		t.Fatalf("failure=%+v calls=%d", failure, runner.calls)
	}
	status, err := app.ControlStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Tasks[0].Phase != workflow.PhaseFailedSafe || status.Tasks[0].ResumePhase != workflow.PhaseAttesting || status.System.Bootstrap.State != systemstate.BootstrapProvisioning || status.Topology.ControlReady {
		t.Fatalf("failed proof checkpoint=%+v", status)
	}
	plan, err := app.PlanControlAttest(context.Background(), AttestControlRequest{Name: "control-1"})
	if err != nil || !plan.ResumesFailedTask || runner.calls != 1 {
		t.Fatalf("plan=%+v calls=%d err=%v", plan, runner.calls, err)
	}
	runner.fail = false
	result, err := app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
	if err != nil || !result.Verified || result.Task.Phase != workflow.PhaseAttesting || result.Task.Attempt != status.Tasks[0].Attempt+1 || runner.calls != 2 {
		t.Fatalf("resumed proof=%+v calls=%d err=%v", result, runner.calls, err)
	}
}

func TestControlAttestationRequiresInstalledEvidenceAndExactStateBeforeConnection(t *testing.T) {
	for _, mutation := range []string{"missing-install", "wrong-proof", "expired-policy", "changed-remote-policy"} {
		t.Run(mutation, func(t *testing.T) {
			app, store, systemID, runner := installedControlAttestFixture(t)
			systemStore, err := app.openSystemStore(systemID)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing-install":
				path, _ := store.Path(filepath.Join("systems", systemID, controlInstallEvidenceRelative("control-1")))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "wrong-proof":
				if err := systemStore.WriteJSON(controlProofRelative("control-1"), ControlProofEvidence{SchemaVersion: 1, SystemID: "wrong-system"}); err != nil {
					t.Fatal(err)
				}
			case "expired-policy":
				now := app.now().Add(30 * 24 * time.Hour)
				app.now = func() time.Time { return now }
			case "changed-remote-policy":
				runner.envelope = bytes.ReplaceAll(runner.envelope, []byte(`"generation":1`), []byte(`"generation":2`))
			}
			_, err = app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
			if err == nil {
				t.Fatal("inconsistent state accepted")
			}
			wantCalls := 0
			if mutation == "changed-remote-policy" {
				wantCalls = 1
			}
			if runner.calls != wantCalls {
				t.Fatalf("opened %d connections, want %d", runner.calls, wantCalls)
			}
		})
	}
}

func TestControlAttestationLockConflictAndCancellationOpenNoConnection(t *testing.T) {
	app, store, systemID, runner := installedControlAttestFixture(t)
	if err := store.WithLock(filepath.Join("systems", systemID, "operations", "control-bootstrap.lock"), func() error {
		_, err := app.AttestControl(context.Background(), AttestControlRequest{Name: "control-1"}, nil)
		if failure := AsError(err); failure.Code != "control_conflict" || failure.ExitCode != 6 {
			t.Fatalf("concurrent operation result=%+v", failure)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := app.AttestControl(ctx, AttestControlRequest{Name: "control-1"}, nil)
	if failure := AsError(err); failure.Code != "cancelled" || failure.ExitCode != 8 {
		t.Fatalf("cancelled operation=%+v", failure)
	}
	if runner.calls != 0 {
		t.Fatalf("blocked operation opened %d connections", runner.calls)
	}
}
