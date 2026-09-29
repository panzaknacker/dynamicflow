package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instances"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

func TestInstanceHostKeyRotationIsExplicitOfflineAndRejectsSymlink(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
	identity, err := keys.Create(context.Background(), sshkeys.Instance, "hostkey-test")
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := keys.Create(context.Background(), sshkeys.Instance, "replacement-hostkey")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJSON(filepath.Join("enrollments", "hostkey-test.json"), localEnrollment{
		Schema: 1, Name: "hostkey-test", Profile: "ssh", State: "issued",
		KeyScope: sshkeys.Instance, KeyName: "hostkey-test", KeyGeneration: identity.Generation,
		Desired: enrollment.SignedDesiredState{State: enrollment.DesiredState{Instance: "hostkey-test"}},
		Host:    "192.0.2.7", SSHUser: "debian", SSHPort: 22,
	}); err != nil {
		t.Fatal(err)
	}
	manager := instances.NewManager(store, keys)
	publicPath := filepath.Join(t.TempDir(), "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(publicPath, []byte(identity.PublicKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "instance", "hostkey", "pin", "hostkey-test",
		"--public-key-file", publicPath,
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("rotate status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var result struct {
		OldFingerprint    string `json:"old_fingerprint"`
		NewFingerprint    string `json:"new_fingerprint"`
		Changed           bool   `json:"changed"`
		NetworkConnection bool   `json:"network_connection"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || !result.Changed || result.NetworkConnection ||
		result.OldFingerprint != "" || result.NewFingerprint != identity.Fingerprint {
		t.Fatalf("pin result = %+v envelope=%+v", result, envelope)
	}
	before, err := manager.Get("hostkey-test")
	if err != nil || before.HostKeyFingerprint != identity.Fingerprint {
		t.Fatalf("pinned record = %+v err=%v", before, err)
	}

	if err := os.WriteFile(publicPath, []byte(replacement.PublicKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr = invokeCLI(t,
		"--json", "--home", home, "instance", "hostkey", "rotate", "hostkey-test",
		"--public-key-file", publicPath,
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("rotate status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope = decodeCLIEnvelope(t, stdout)
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || !result.Changed || result.NetworkConnection ||
		result.OldFingerprint != before.HostKeyFingerprint || result.NewFingerprint != replacement.Fingerprint {
		t.Fatalf("rotation result = %+v envelope=%+v", result, envelope)
	}
	after, err := manager.Get("hostkey-test")
	if err != nil {
		t.Fatal(err)
	}
	if after.HostKeyFingerprint != replacement.Fingerprint || after.PreviousHostKeyFingerprint != before.HostKeyFingerprint {
		t.Fatalf("rotated record = %+v", after)
	}

	symlink := filepath.Join(t.TempDir(), "hostkey-link.pub")
	if err := os.Symlink(publicPath, symlink); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr = invokeCLI(t,
		"--json", "--home", home, "instance", "hostkey", "rotate", "hostkey-test",
		"--public-key-file", symlink,
	)
	if status != exitConfig || stdout != "" {
		t.Fatalf("symlink status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.OK || failure.Error == nil || failure.Error.Code != "ssh_host_key" {
		t.Fatalf("symlink failure = %+v", failure)
	}
}
