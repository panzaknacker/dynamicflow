package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestControlInstallCLIPlanCommitAndResumeAreLocalAndPublicOnly(t *testing.T) {
	fixture := newControlCLIFixture(t)
	if status, stdout, stderr := invokeCLI(t, fixture.bindArguments(false)...); status != exitOK || stderr != "" {
		t.Fatalf("bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	callsPath, _ := installFakeControlSSH(t, 0, "discarded-connectivity-output")
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1"); status != exitOK || stderr != "" {
		t.Fatalf("check status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertSSHCallCount(t, callsPath, 1)

	before := snapshotCLIState(t, fixture.home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", fixture.home, "control", "install", "control-1", "--plan")
	if status != exitOK || stderr != "" {
		t.Fatalf("install plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	planEnvelope := decodeCLIEnvelope(t, stdout)
	if !planEnvelope.OK || planEnvelope.Command != "control.install.plan" {
		t.Fatalf("install plan envelope = %+v", planEnvelope)
	}
	var plan controlInstallPlanOutput
	if err := json.Unmarshal(planEnvelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.ControlName != "control-1" || plan.CurrentLifecycle != "connectivity_verified" ||
		plan.CurrentTaskPhase != "connectivity_verified" || plan.PolicyGeneration != 1 || plan.RouteCount != 0 ||
		!plan.RouteFree || plan.NetworkConnections != 0 || !plan.GeneratesPrivateKeys || plan.AlreadyPrepared ||
		plan.RemoteInstallationPerformed || plan.ControlReady || len(plan.Changes) != 4 {
		t.Fatalf("install plan = %+v", plan)
	}
	if after := snapshotCLIState(t, fixture.home); !reflect.DeepEqual(before, after) {
		t.Fatalf("install --plan changed state:\nbefore=%v\nafter=%v", before, after)
	}
	assertSSHCallCount(t, callsPath, 1)
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	status, humanPlan, stderr := invokeCLI(t, "--home", fixture.home, "control", "install", "--plan", "control-1")
	if status != exitOK || stderr != "" || !strings.Contains(humanPlan, "Network connections: 0") ||
		!strings.Contains(humanPlan, "Routes authorized: 0 (route-free)") ||
		!strings.Contains(humanPlan, "Remote installation performed: no") ||
		!strings.Contains(humanPlan, "Control ready: no") {
		t.Fatalf("human install plan status=%d stdout=%q stderr=%q", status, humanPlan, stderr)
	}
	if after := snapshotCLIState(t, fixture.home); !reflect.DeepEqual(before, after) {
		t.Fatalf("human install --plan changed state:\nbefore=%v\nafter=%v", before, after)
	}
	assertSSHCallCount(t, callsPath, 1)

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "install", "control-1")
	if status != exitOK || stderr != "" {
		t.Fatalf("install commit status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	resultEnvelope := decodeCLIEnvelope(t, stdout)
	if !resultEnvelope.OK || resultEnvelope.Command != "control.install" {
		t.Fatalf("install envelope = %+v", resultEnvelope)
	}
	var result controlInstallOutput
	if err := json.Unmarshal(resultEnvelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Prepared || result.Resumed || result.ControlName != "control-1" ||
		result.ControlLifecycle != "installing" || result.AccessPhase != "staged" ||
		result.TaskPhase != "installing" || result.ManagementScope != "control" ||
		result.ManagementGeneration != 1 || result.ManagementPublicKey == "" ||
		!strings.HasPrefix(result.ManagementFingerprint, "SHA256:") || result.PolicyGeneration != 1 ||
		!strings.HasPrefix(result.EnvelopeDigest, "sha256:") || result.RouteCount != 0 || !result.RouteFree ||
		result.NetworkConnections != 0 || result.RemoteInstallationPerformed || result.ControlReady {
		t.Fatalf("install result = %+v", result)
	}
	assertSSHCallCount(t, callsPath, 1)
	assertControlInstallOutputHasNoLocalCheckpoint(t, fixture, stdout+stderr, result.ManagementPublicKey)

	status, human, stderr := invokeCLI(t, "--home", fixture.home, "control", "install", "control-1")
	if status != exitOK || strings.Contains(stderr, "ERROR") || !strings.Contains(human, "preparation resumed") ||
		!strings.Contains(human, result.ManagementPublicKey) || !strings.Contains(human, "Routes authorized: 0 (route-free)") ||
		!strings.Contains(human, "Network connections: 0") ||
		!strings.Contains(human, "REMOTE INSTALLATION PERFORMED: NO") ||
		!strings.Contains(human, "CONTROL READY: NO") ||
		!strings.Contains(stderr, "[control_management_key] running") ||
		!strings.Contains(stderr, "[control_policy] complete") {
		t.Fatalf("human install commit status=%d stdout=%q stderr=%q", status, human, stderr)
	}
	assertSSHCallCount(t, callsPath, 1)
	assertControlInstallOutputHasNoLocalCheckpoint(t, fixture, human+stderr, result.ManagementPublicKey)
}

func TestControlInstallCLIHelpUsageAndCheckpointExitCode(t *testing.T) {
	home := filepath.Join(t.TempDir(), "must-not-exist")
	for _, args := range [][]string{
		{"--home", home, "control", "install", "--help"},
		{"--json", "--home", home, "control", "install", "-h"},
	} {
		status, stdout, stderr := invokeCLI(t, args...)
		if status != exitOK || stderr != "" || !strings.Contains(stdout, "flow control install NAME [--plan]") ||
			!strings.Contains(stdout, "network connections") || !strings.Contains(stdout, "never marks") ||
			!strings.Contains(stdout, "Control ready") {
			t.Fatalf("install help args=%v status=%d stdout=%q stderr=%q", args, status, stdout, stderr)
		}
		if _, err := os.Lstat(home); !os.IsNotExist(err) {
			t.Fatalf("install help opened operator state: %v", err)
		}
	}
	if got := requestedCommandID([]string{"control", "install", "operator-secret-name"}); got != "control.install" {
		t.Fatalf("requested command ID = %q", got)
	}

	fixture := newControlCLIFixture(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", fixture.home, "control", "install", "control-1", "--plan")
	if status != exitConfig || stdout != "" {
		t.Fatalf("early install status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.OK || failure.Command != "control.install" || failure.Error == nil ||
		failure.Error.Code != "control_binding" || failure.Error.Next == "" {
		t.Fatalf("early install failure = %+v", failure)
	}

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "install")
	if status != exitUsage || stdout != "" {
		t.Fatalf("usage status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure = decodeCLIEnvelope(t, stderr)
	if failure.Command != "control.install" || failure.Error == nil || failure.Error.Code != "usage" {
		t.Fatalf("usage failure = %+v", failure)
	}
}

func assertSSHCallCount(t *testing.T, path string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SSH calls: %v", err)
	}
	if got := strings.Count(string(data), "call\n"); got != want {
		t.Fatalf("SSH calls = %d, want %d: %q", got, want, data)
	}
}

func assertControlInstallOutputHasNoLocalCheckpoint(t *testing.T, fixture controlCLIFixture, output, allowedPublicKey string) {
	t.Helper()
	privatePath := filepath.Join(fixture.home, "systems", fixture.systemID, "keys", "control", "control-1", "generations", "000001", "id_ed25519")
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(fixture.home, "systems", fixture.systemID, "control", "install", "control-1", "envelope-g1.json")
	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		fixture.home, privatePath, envelopePath, filepath.Join(fixture.home, "logs", "audit.jsonl"),
		string(privateBytes), string(envelopeBytes), "OPENSSH PRIVATE KEY", `"audit_log"`, `"envelope":`,
	} {
		if forbidden != "" && strings.Contains(output, forbidden) {
			t.Fatalf("Control install output leaked a local checkpoint or private value %q", forbidden)
		}
	}
	if allowedPublicKey == "" || !strings.Contains(output, allowedPublicKey) {
		t.Fatal("Control install output omitted the deliberate public management key")
	}
}
