package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStrictInventory(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	if err := os.WriteFile(key, []byte("contents are deliberately not parsed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lab.yaml")
	data := "version: 2\nhosts:\n  - name: vm-one\n    role: pbp\n    address: 192.0.2.1\n    ssh_user: admin\n    os: Debian 13\n    identity_file: " + key + "\n    host_key_fingerprint: SHA256:" + strings.Repeat("A", 43) + "\n    host_key_verified_out_of_band: false\n    disposable: false\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].Name != "vm-one" || got.Hosts[0].Disposable {
		t.Fatalf("unexpected inventory: %#v", got)
	}
}

func TestRejectsUnsafeModeAndYAMLFeatures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lab.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nhosts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("expected mode error, got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsupported YAML rejection")
	}
}

func inventoryFixture(key, role, gates string) string {
	value := "version: 2\nhosts:\n  - name: vm-one\n    role: " + role + "\n    address: 192.0.2.1\n    ssh_user: admin\n    os: Debian 13\n    identity_file: " + key + "\n    host_key_fingerprint: SHA256:" + strings.Repeat("A", 43) + "\n    host_key_verified_out_of_band: true\n"
	if gates != "" {
		value += "    attested_gates: " + gates + "\n"
	}
	return value + "    disposable: true\n"
}

func TestInventoryValidatesIdentityMetadataWithoutReadingContents(t *testing.T) {
	directory := t.TempDir()
	identity := filepath.Join(directory, "opaque-private-key")
	if err := os.WriteFile(identity, []byte("not parsed and never returned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(directory, "lab.yaml")
	if err := os.WriteFile(inventory, []byte(inventoryFixture(identity, "pbp", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err != nil {
		t.Fatalf("metadata-only identity was rejected: %v", err)
	}
	if err := os.Chmod(identity, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err == nil || !strings.Contains(err.Error(), "mode-0600") {
		t.Fatalf("non-0600 identity accepted: %v", err)
	}
}

func TestInventoryRejectsSymlinksHardlinksAndWrongRoleAttestations(t *testing.T) {
	directory := t.TempDir()
	identity := filepath.Join(directory, "identity")
	if err := os.WriteFile(identity, []byte("opaque\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(directory, "lab.yaml")
	write := func(key, role, gates string) error {
		return os.WriteFile(inventory, []byte(inventoryFixture(key, role, gates)), 0o600)
	}
	linked := filepath.Join(directory, "identity-link")
	if err := os.Symlink(identity, linked); err != nil {
		t.Fatal(err)
	}
	if err := write(linked, "pbp", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err == nil {
		t.Fatal("symlink identity accepted")
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(identity, linked); err != nil {
		t.Fatal(err)
	}
	if err := write(identity, "pbp", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err == nil {
		t.Fatal("hardlinked identity accepted")
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if err := write(identity, "pbp", GateEnrollmentReplayRejected); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err == nil || !strings.Contains(err.Error(), "not valid for role") {
		t.Fatalf("wrong-role attestation error = %v", err)
	}
	if err := write(identity, "enrollment", GateEnrollmentReplayRejected+","+GateEnrollmentReplayRejected); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(inventory); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate attestation error = %v", err)
	}
}

func TestInventoryRejectsSymlinkFileAndNoncanonicalFingerprint(t *testing.T) {
	directory := t.TempDir()
	identity := filepath.Join(directory, "identity")
	if err := os.WriteFile(identity, []byte("opaque\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	realInventory := filepath.Join(directory, "real.yaml")
	if err := os.WriteFile(realInventory, []byte(inventoryFixture(identity, "pbp", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedInventory := filepath.Join(directory, "linked.yaml")
	if err := os.Symlink(realInventory, linkedInventory); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(linkedInventory); err == nil {
		t.Fatal("symlink inventory accepted")
	}
	invalid := strings.Replace(inventoryFixture(identity, "pbp", ""), "SHA256:"+strings.Repeat("A", 43), "SHA256:not-canonical", 1)
	if err := os.WriteFile(realInventory, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(realInventory); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("fingerprint error = %v", err)
	}
}
