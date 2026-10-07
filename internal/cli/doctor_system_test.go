package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dynamicflow/internal/application"
)

func TestDoctorSystemJSONAndHumanAreReadOnlyWithoutCheckout(t *testing.T) {
	home, systemID := doctorSystemFixture(t)
	missingCheckout := filepath.Join(t.TempDir(), "no-checkout")
	t.Setenv("FLOW_PROFILES_DIR", filepath.Join(missingCheckout, "no-profiles"))
	before := snapshotCLIState(t, home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "--source-root", missingCheckout, "doctor")
	if status != exitOK || stderr != "" {
		t.Fatalf("doctor status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "doctor" {
		t.Fatalf("doctor envelope=%+v", envelope)
	}
	var result application.DiagnosticsResult
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "system" || result.SystemID != systemID || !result.Healthy || result.ControlReady || result.NetworkConnections != 0 {
		t.Fatalf("fresh system diagnostics=%+v", result)
	}
	checks := make(map[string]application.DiagnosticStatus)
	for _, check := range result.Checks {
		checks[check.Name] = check.Status
	}
	for _, name := range []string{"system:registry", "tool:ssh", "tool:ssh-keygen", "trust:roots", "trust:binding", "workflow:task", "bootstrap:identity"} {
		if checks[name] != application.DiagnosticOK {
			t.Errorf("missing healthy check %s: %+v", name, result.Checks)
		}
	}
	if checks["control:checkpoint"] != application.DiagnosticPending {
		t.Fatal("fresh bootstrap was not explicitly pending")
	}
	if _, legacy := checks["profiles"]; legacy {
		t.Fatal("system doctor requires legacy profile checkout")
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
	if after := snapshotCLIState(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("JSON diagnostics changed local state or wrote an audit")
	}
	status, stdout, stderr = invokeCLI(t, "--home", home, "--source-root", missingCheckout, "doctor")
	if status != exitOK || stderr != "" {
		t.Fatalf("human doctor status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	for _, wanted := range []string{"Local diagnostics", systemID, "PENDING", "Control ready: no", "Network connections: 0", "remote availability was not checked", "Local checks passed."} {
		if !strings.Contains(stdout, wanted) {
			t.Errorf("human doctor omitted %q: %s", wanted, stdout)
		}
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
	if after := snapshotCLIState(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("human diagnostics changed local state or wrote an audit")
	}
}

func TestDoctorSystemMissingTrustFailsWithoutRepair(t *testing.T) {
	home, systemID := doctorSystemFixture(t)
	for _, name := range []string{"release.private.pem", "release.public.pem"} {
		if err := os.Remove(filepath.Join(home, "systems", systemID, "keys", "signing", name)); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotCLIState(t, home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "doctor")
	if status != exitConfig || stdout != "" {
		t.Fatalf("missing trust status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.OK || envelope.Command != "doctor" || envelope.Error == nil || envelope.Error.Code != "doctor_failed" {
		t.Fatalf("missing trust envelope=%+v", envelope)
	}
	var result application.DiagnosticsResult
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "system" || result.SystemID != systemID || result.Healthy || result.ControlReady || result.NetworkConnections != 0 {
		t.Fatalf("missing trust result=%+v", result)
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
	if after := snapshotCLIState(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("doctor repaired a deleted committed signing pair")
	}
	status, stdout, stderr = invokeCLI(t, "--home", home, "doctor")
	if status != exitConfig || !strings.Contains(stdout, "FAILED") || !strings.Contains(stdout, "trust:roots") || !strings.Contains(stdout, "Control ready: no") {
		t.Fatalf("human failure contract status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
	if after := snapshotCLIState(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("human doctor repaired a deleted committed signing pair")
	}
}

func TestDoctorCorruptSystemRegistryDoesNotUseHealthyLegacyRoots(t *testing.T) {
	home := privateTempDir(t)
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "init"); status != exitOK {
		t.Fatalf("legacy init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if err := os.Mkdir(filepath.Join(home, "systems"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "systems", "registry.json"), []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotCLIState(t, home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "doctor")
	if status != exitConfig || stdout != "" {
		t.Fatalf("corrupt registry status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	var result application.DiagnosticsResult
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "system" || result.Healthy || result.ControlReady || len(result.Checks) != 1 || result.Checks[0].Name != "system:registry" || result.Checks[0].Status != application.DiagnosticFailed {
		t.Fatalf("corrupt registry silently fell back to legacy roots: %+v", result)
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
	if after := snapshotCLIState(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("corrupt registry diagnostics changed state")
	}
}

func TestDoctorSystemMissingToolsAreLocalFailures(t *testing.T) {
	home, _ := doctorSystemFixture(t)
	t.Setenv("PATH", t.TempDir())
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "doctor")
	if status != exitConfig || stdout != "" {
		t.Fatalf("missing tools status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var result application.DiagnosticsResult
	if err := json.Unmarshal(decodeCLIEnvelope(t, stderr).Data, &result); err != nil {
		t.Fatal(err)
	}
	failedTools := make(map[string]bool)
	for _, check := range result.Checks {
		if check.Status == application.DiagnosticFailed {
			failedTools[check.Name] = true
		}
	}
	if !failedTools["tool:ssh"] || !failedTools["tool:ssh-keygen"] || result.Healthy || result.ControlReady || result.NetworkConnections != 0 {
		t.Fatalf("missing tool result=%+v", result)
	}
	assertDoctorSystemPublicOnly(t, stdout+stderr, home)
}

func doctorSystemFixture(t *testing.T) (string, string) {
	t.Helper()
	for _, executable := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(executable); err != nil {
			t.Skipf("%s is unavailable", executable)
		}
	}
	home := privateTempDir(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "init", "--name", "doctor-system")
	if status != exitOK || stderr != "" {
		t.Fatalf("system init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var initialized application.InitSystemResult
	if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &initialized); err != nil {
		t.Fatal(err)
	}
	return home, initialized.System.ID
}

func assertDoctorSystemPublicOnly(t *testing.T, output, home string) {
	t.Helper()
	for _, forbidden := range []string{home, ".private.pem", "id_ed25519", "PRIVATE KEY", "ssh-ed25519 "} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("doctor disclosed private paths or key bytes: %s", output)
		}
	}
}
