package operatortrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
)

func TestEnsureCreatesSeparatedStableRoots(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Ensure(store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Ensure(store)
	if err != nil || second != first {
		t.Fatalf("idempotent ensure = %+v, %v", second, err)
	}
	if err := Validate(first); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), ".private.pem") {
		t.Fatalf("bundle leaked private material or path: %s", encoded)
	}
	for _, item := range roles {
		path, _ := store.Path(filepath.Join("keys", "signing", item.base+".private.pem"))
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("%s private mode = %v", item.name, info.Mode())
		}
	}
}

func TestEnsureRejectsIncompletePair(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("keys/signing/release.private.pem", []byte("not a key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(store); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete pair error = %v", err)
	}
}

func TestControlPolicySigningKeepsPrivateRootInsideTrustBoundary(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Ensure(store)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, fingerprint := operatorTrustTestSSHKey(37)
	now := time.Date(2026, 7, 23, 17, 0, 0, 0, time.UTC)
	policy := controlpolicy.Policy{
		SchemaVersion: controlpolicy.SchemaVersion,
		SystemID:      "sys-0123456789abcdef0123456789abcdef",
		ControlName:   "control-1", Generation: 1,
		IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		ManagementKeys: []controlpolicy.ManagementKey{{
			Name: "control-1", Generation: 1, State: controlpolicy.KeyActive,
			PublicKey: publicKey, Fingerprint: fingerprint,
		}},
		Routes: []controlpolicy.Route{},
	}
	signed, err := SignControlPolicy(store, policy)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, keyID, err := ControlPolicyPublic(store)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != bundle.ControlPolicy || strings.Contains(string(publicPEM), "PRIVATE KEY") {
		t.Fatalf("public Control-policy identity = %s %q", keyID, publicPEM)
	}
	parsed, err := signing.ParsePublicPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := controlpolicy.Verify(signed, parsed, now, policy.SystemID, policy.ControlName, 1); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	privatePath, err := store.Path("keys/signing/control-policy.private.pem")
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, privateBytes) || bytes.Contains(encoded, []byte(privatePath)) || bytes.Contains(encoded, []byte("PRIVATE KEY")) {
		t.Fatalf("signed policy leaked private signer material: %s", encoded)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignControlPolicy(store, policy); err == nil {
		t.Fatal("unsafe Control-policy private key mode was accepted")
	}
}

func operatorTrustTestSSHKey(seed byte) (string, string) {
	algorithm := []byte("ssh-ed25519")
	blob := operatorTrustAppendSSHField(nil, algorithm)
	blob = operatorTrustAppendSSHField(blob, bytes.Repeat([]byte{seed}, 32))
	digest := sha256.Sum256(blob)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
		"SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func operatorTrustAppendSSHField(destination, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination = append(destination, size[:]...)
	return append(destination, value...)
}
