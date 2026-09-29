package enrollment

import (
	"errors"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

func TestDesiredStateBindingSignatureAndExpiry(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	otherPublic, _, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	keyB := testOpenSSHKey(t, "second operator key")
	keyA := testOpenSSHKey(t, "first operator key")
	state := DesiredState{
		Schema: DesiredStateSchema, Instance: "pbp-01", Profile: "pbp", Generation: 7,
		ReleaseSet: "sha256:" + strings.Repeat("a", 64), AuthorizedSSHKeys: []string{keyB, keyA},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
	}
	signed, err := SignDesiredState(state, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.State.AuthorizedSSHKeys[0] != keyA && signed.State.AuthorizedSSHKeys[0] != keyB {
		t.Fatal("keys were not retained")
	}
	if signed.State.AuthorizedSSHKeys[0] > signed.State.AuthorizedSSHKeys[1] {
		t.Fatal("SignDesiredState did not canonicalize authorized keys")
	}
	expectation := DesiredExpectation{
		Instance: "pbp-01", Profile: "pbp", ReleaseSet: state.ReleaseSet,
		MinGeneration: 7, Now: now, MaxClockSkew: time.Minute,
	}
	if err := VerifyDesiredState(signed, publicKey, expectation); err != nil {
		t.Fatalf("verify desired state: %v", err)
	}
	wrongInstance := expectation
	wrongInstance.Instance = "pbp-02"
	if err := VerifyDesiredState(signed, publicKey, wrongInstance); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong instance: got %v, want ErrBinding", err)
	}
	rollback := expectation
	rollback.MinGeneration = 8
	if err := VerifyDesiredState(signed, publicKey, rollback); !errors.Is(err, ErrInvalidDesiredState) {
		t.Fatalf("rollback: got %v, want ErrInvalidDesiredState", err)
	}
	expired := expectation
	expired.Now = now.Add(15 * time.Minute)
	if err := VerifyDesiredState(signed, publicKey, expired); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: got %v, want ErrExpired", err)
	}
	if err := VerifyDesiredState(signed, otherPublic, expectation); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("wrong signing key: got %v, want invalid signature", err)
	}
	if err := VerifyDesiredStateForRenewal(signed, publicKey, expired); err != nil {
		t.Fatalf("expired signed predecessor could not be authenticated for renewal: %v", err)
	}
	future := expired
	future.Now = now.Add(-2 * time.Minute)
	future.MaxClockSkew = time.Minute
	if err := VerifyDesiredStateForRenewal(signed, publicKey, future); !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("future-issued predecessor accepted for renewal: %v", err)
	}
	tampered := signed
	tampered.State.Profile = "ssh"
	tamperedExpectation := expectation
	tamperedExpectation.Profile = "ssh"
	if err := VerifyDesiredState(tampered, publicKey, tamperedExpectation); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("tampered profile: got %v, want invalid signature", err)
	}
}

func TestDesiredStateRejectsMalformedOrNonCanonicalKeys(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	validKey := testOpenSSHKey(t, "operator")
	state := DesiredState{
		Schema: DesiredStateSchema, Instance: "vm-01", Profile: "ssh", Generation: 1,
		ReleaseSet: "sha256:" + strings.Repeat("b", 64), AuthorizedSSHKeys: []string{validKey},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	malformed := state
	malformed.AuthorizedSSHKeys = []string{"ssh-ed25519 not-base64 operator"}
	if _, err := SignDesiredState(malformed, privateKey); !errors.Is(err, ErrInvalidDesiredState) {
		t.Fatalf("malformed key: got %v", err)
	}
	duplicate := state
	duplicate.AuthorizedSSHKeys = []string{validKey, validKey}
	if _, err := SignDesiredState(duplicate, privateKey); !errors.Is(err, ErrInvalidDesiredState) {
		t.Fatalf("duplicate key: got %v", err)
	}
	signed, err := SignDesiredState(state, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signed.State.AuthorizedSSHKeys = append([]string{testOpenSSHKey(t, "aaa")}, signed.State.AuthorizedSSHKeys...)
	if err := VerifyDesiredState(signed, publicKey, DesiredExpectation{Instance: "vm-01", Profile: "ssh", Now: now}); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("tampered keys: got %v, want invalid signature", err)
	}
}
