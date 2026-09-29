package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemInitCLIJSONIsStableAndPublicOnly(t *testing.T) {
	home := privateTempDir(t)
	arguments := []string{"--json", "--home", home, "system", "init", "--name", "lab"}
	status, stdout, stderr := invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("system init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	first := decodeCLIEnvelope(t, stdout)
	if !first.OK || first.Command != "system.init" {
		t.Fatalf("first envelope = %+v", first)
	}
	var data struct {
		System struct {
			ID string `json:"id"`
		} `json:"system"`
		Task struct {
			ID    string `json:"id"`
			Phase string `json:"phase"`
		} `json:"task"`
		Cloud struct {
			PublicKey   string `json:"public_key"`
			Fingerprint string `json:"public_key_fingerprint"`
		} `json:"cloud"`
	}
	if err := json.Unmarshal(first.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(data.System.ID, "sys-") || data.Task.ID != "control-bootstrap-control-1" ||
		data.Task.Phase != "awaiting_cloud_vm" || !strings.HasPrefix(data.Cloud.PublicKey, "ssh-ed25519 ") ||
		!strings.HasPrefix(data.Cloud.Fingerprint, "SHA256:") {
		t.Fatalf("system init data = %+v", data)
	}
	privatePath := filepath.Join(home, "systems", data.System.ID, "keys", "bootstrap", "control-1", "generations", "000001", "id_ed25519")
	private, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, string(private)) || strings.Contains(stdout, privatePath) || strings.Contains(stdout, "PRIVATE KEY") {
		t.Fatal("JSON output leaked private key material or path")
	}

	status, resumedOut, stderr := invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("resume status=%d stdout=%q stderr=%q", status, resumedOut, stderr)
	}
	resumed := decodeCLIEnvelope(t, resumedOut)
	var resumedData struct {
		Resumed bool `json:"resumed"`
		Cloud   struct {
			PublicKey string `json:"public_key"`
		} `json:"cloud"`
	}
	if err := json.Unmarshal(resumed.Data, &resumedData); err != nil {
		t.Fatal(err)
	}
	if !resumedData.Resumed || resumedData.Cloud.PublicKey != data.Cloud.PublicKey {
		t.Fatalf("resume replaced bootstrap identity: %+v", resumedData)
	}
}

func TestDashboardJSONUsesApplicationSnapshot(t *testing.T) {
	home := privateTempDir(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "dashboard")
	if status != exitOK || stderr != "" {
		t.Fatalf("fresh dashboard status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	fresh := decodeCLIEnvelope(t, stdout)
	if !fresh.OK || fresh.Command != "dashboard" || !strings.Contains(string(fresh.Data), `"systems":[]`) {
		t.Fatalf("fresh dashboard = %+v %s", fresh, fresh.Data)
	}
	status, _, stderr = invokeCLI(t, "--json", "--home", home, "system", "init", "--name", "lab")
	if status != exitOK || stderr != "" {
		t.Fatalf("init status=%d stderr=%q", status, stderr)
	}
	status, stdout, stderr = invokeCLI(t, "--json", "--home", home, "dashboard")
	if status != exitOK || stderr != "" {
		t.Fatalf("dashboard status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	dashboard := decodeCLIEnvelope(t, stdout)
	if !strings.Contains(string(dashboard.Data), `"reason":"control_required"`) ||
		!strings.Contains(string(dashboard.Data), `"phase":"awaiting_cloud_vm"`) {
		t.Fatalf("dashboard did not expose trust gate/task: %s", dashboard.Data)
	}
}

func TestSystemCommandsRejectBadFlagsAsOneJSONDocument(t *testing.T) {
	home := privateTempDir(t)
	for _, arguments := range [][]string{
		{"--json", "--home", home, "system", "init", "--unknown"},
		{"--json", "--home", home, "system", "status", "extra"},
		{"--json", "--home", home, "dashboard", "extra"},
	} {
		status, stdout, stderr := invokeCLI(t, arguments...)
		if status != exitUsage || stdout != "" {
			t.Fatalf("arguments=%v status=%d stdout=%q stderr=%q", arguments, status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Error == nil || envelope.Error.Code != "usage" {
			t.Fatalf("arguments=%v envelope=%+v", arguments, envelope)
		}
	}
}

func TestSystemInitPlanDoesNotGenerateKeys(t *testing.T) {
	home := privateTempDir(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "init", "--name", "planned", "--plan")
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if envelope.Command != "system.init.plan" || !strings.Contains(string(envelope.Data), `"network_connections":0`) {
		t.Fatalf("plan envelope = %+v %s", envelope, envelope.Data)
	}
	if _, err := os.Lstat(filepath.Join(home, "systems")); !os.IsNotExist(err) {
		t.Fatalf("plan created systems or keys: %v", err)
	}
}
