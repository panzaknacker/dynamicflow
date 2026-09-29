package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dynamicflow/internal/profiles"
	"dynamicflow/internal/sshkeys"
)

func TestKeyCommandsNeverEmitPrivateMaterial(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is unavailable")
	}
	home := privateTempDir(t)
	root := repositoryRoot(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", root, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "key", "create", "--name", "operator-test")
	if status != exitOK || stderr != "" {
		t.Fatalf("key create status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var record sshkeys.Record
	if err := json.Unmarshal(envelope.Data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Name != "operator-test" || record.PublicKey == "" || record.Fingerprint == "" {
		t.Fatalf("public key record = %+v", record)
	}
	privatePath := filepath.Join(home, "keys", "operator", "operator-test", "generations", "000001", "id_ed25519")
	privateData, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %04o", info.Mode().Perm())
	}
	marker := strings.Join([]string{"-----BEGIN", "OPENSSH", "PRIVATE", "KEY-----"}, " ")
	if !strings.Contains(string(privateData), marker) {
		t.Fatal("fixture is not an OpenSSH private key")
	}

	status, listed, listError := invokeCLI(t, "--json", "--home", home, "key", "list")
	if status != exitOK || listError != "" {
		t.Fatalf("key list status=%d stdout=%q stderr=%q", status, listed, listError)
	}
	audit, err := os.ReadFile(filepath.Join(home, "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for label, output := range map[string]string{
		"create stdout": stdout,
		"create stderr": stderr,
		"list stdout":   listed,
		"list stderr":   listError,
		"audit":         string(audit),
	} {
		if strings.Contains(output, marker) || strings.Contains(output, string(privateData)) {
			t.Fatalf("%s leaked private key material", label)
		}
	}

	status, _, duplicateError := invokeCLI(t, "--json", "--home", home, "key", "create", "--name", "operator-test")
	if status != exitConflict {
		t.Fatalf("duplicate key status = %d, stderr=%q", status, duplicateError)
	}
	if failure := decodeCLIEnvelope(t, duplicateError); failure.Error == nil || failure.Error.Code != "key" {
		t.Fatalf("duplicate key response = %+v", failure)
	}
}

func TestProfilePBPGraphUsesOnlySpecialVPNMode(t *testing.T) {
	t.Setenv("FLOW_PROFILES_DIR", "")
	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t),
		"profile", "show", "pbp",
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("profile show status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var result struct {
		Profile    profiles.Profile `json:"profile"`
		Order      []string         `json:"order"`
		Components []string         `json:"components"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if want := []string{"ssh", "ssh-gui", "vpn-pbp-de", "pbp"}; !reflect.DeepEqual(result.Order, want) {
		t.Fatalf("PBP order = %v, want %v", result.Order, want)
	}
	if want := []string{"ssh", "vpn", "pbp"}; !reflect.DeepEqual(result.Components, want) {
		t.Fatalf("PBP artifacts = %v, want %v", result.Components, want)
	}
	for _, name := range result.Order {
		if name == "vpn" {
			t.Fatal("normal Firefox VPN profile is a PBP dependency")
		}
	}

	status, stdout, stderr = invokeCLI(t,
		"--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t),
		"profile", "list",
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("profile list status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	listEnvelope := decodeCLIEnvelope(t, stdout)
	var listed []profiles.Profile
	if err := json.Unmarshal(listEnvelope.Data, &listed); err != nil {
		t.Fatal(err)
	}
	for _, profile := range listed {
		if profile.Name == "vpn-pbp-de" {
			t.Fatal("internal PBP VPN mode appeared in the normal profile list")
		}
	}
}
