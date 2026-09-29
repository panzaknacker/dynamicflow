package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

func TestStoreSecretNeverPersistedAndConsumeIsBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	store, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("pbp-01", "pbp", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(credential.Secret)
	if err != nil || len(secretBytes) != 32 {
		t.Fatalf("secret does not contain 256 bits: len=%d err=%v", len(secretBytes), err)
	}
	serialized, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(credential.Secret)) {
		t.Fatal("Credential JSON disclosed its one-time secret")
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(credential.Secret)) {
		t.Fatal("state file persisted the plaintext enrollment secret")
	}
	assertMode(t, path, 0o600)
	assertMode(t, path+".lock", 0o600)

	_, _, publicPEM := testIdentity(t)
	wrongSecret, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	baseRequest := ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: credential.Instance,
		Profile: credential.Profile, InstancePublicKeyPEM: publicPEM,
	}
	wrongBinding := baseRequest
	wrongBinding.Instance = "other-instance"
	if _, err := store.Consume(wrongBinding); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong instance: got %v, want ErrBinding", err)
	}
	wrongCredential := baseRequest
	wrongCredential.Secret = wrongSecret
	if _, err := store.Consume(wrongCredential); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("wrong secret: got %v, want ErrInvalidSecret", err)
	}
	record, err := store.Consume(baseRequest)
	if err != nil {
		t.Fatal(err)
	}
	if record.Instance != "pbp-01" || record.Profile != "pbp" || record.ConsumedAt != now.Unix() || record.InstanceKeyID == "" {
		t.Fatalf("unexpected consumed record: %#v", record)
	}
	if _, err := store.Consume(baseRequest); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume: got %v, want ErrConsumed", err)
	}
	reopened, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.FindInstance("pbp-01")
	if err != nil || persisted.InstanceKeyID != record.InstanceKeyID {
		t.Fatalf("identity not persisted: record=%#v err=%v", persisted, err)
	}
}

func TestEnrollmentExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("instance-01", "ssh", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, publicPEM := testIdentity(t)
	now = now.Add(time.Minute)
	_, err = store.Consume(ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: "instance-01", Profile: "ssh",
		InstancePublicKeyPEM: publicPEM,
	})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestEnrollmentFailsClosedWhenClockMovesBeforeCreation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("instance-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, publicPEM := testIdentity(t)
	now = now.Add(-time.Hour)
	_, err = store.Consume(ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: "instance-01", Profile: "ssh",
		InstancePublicKeyPEM: publicPEM,
	})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("clock rollback: got %v, want fail-closed ErrExpired", err)
	}
}

func TestConcurrentConsumeExactlyOnceAcrossStores(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	creator, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := creator.Create("instance-01", "pbp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, publicPEM := testIdentity(t)
	request := ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: "instance-01", Profile: "pbp",
		InstancePublicKeyPEM: publicPEM,
	}

	const callers = 32
	stores := make([]*Store, callers)
	for index := range stores {
		stores[index], err = NewStore(path, WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	var group sync.WaitGroup
	for _, candidate := range stores {
		group.Add(1)
		go func(store *Store) {
			defer group.Done()
			<-start
			_, err := store.Consume(request)
			results <- err
		}(candidate)
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	consumed := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrConsumed):
			consumed++
		default:
			t.Fatalf("unexpected concurrent consume error: %v", result)
		}
	}
	if successes != 1 || consumed != callers-1 {
		t.Fatalf("successes=%d consumed=%d", successes, consumed)
	}
}

func TestConcurrentCreatesDoNotLoseRecords(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	const callers = 24
	stores := make([]*Store, callers)
	var err error
	for index := range stores {
		stores[index], err = NewStore(path, WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	credentials := make(chan Credential, callers)
	errorsChannel := make(chan error, callers)
	var group sync.WaitGroup
	for index, candidate := range stores {
		group.Add(1)
		go func(index int, store *Store) {
			defer group.Done()
			<-start
			credential, createErr := store.Create(fmt.Sprintf("vm-%02d", index), "ssh", time.Hour)
			if createErr != nil {
				errorsChannel <- createErr
				return
			}
			credentials <- credential
		}(index, candidate)
	}
	close(start)
	group.Wait()
	close(credentials)
	close(errorsChannel)
	for createErr := range errorsChannel {
		t.Fatalf("concurrent create: %v", createErr)
	}
	verifier, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for credential := range credentials {
		if _, err := verifier.Get(credential.ID); err != nil {
			t.Fatalf("lost created enrollment %q: %v", credential.ID, err)
		}
		count++
	}
	if count != callers {
		t.Fatalf("got %d credentials, want %d", count, callers)
	}
}

func TestStoreRejectsUnsafeFilesAndSymlinkParents(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("vm-01", "ssh", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("missing"); !errors.Is(err, ErrUnsafeStore) {
		t.Fatalf("mode 0644: got %v, want ErrUnsafeStore", err)
	}

	realParent := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Join(linkParent, "state.json")); !errors.Is(err, ErrUnsafeStore) {
		t.Fatalf("symlink parent: got %v, want ErrUnsafeStore", err)
	}
}

func TestStoreRejectsHardlinkedStateAndLockFiles(t *testing.T) {
	t.Run("state", func(t *testing.T) {
		path := testStorePath(t)
		store, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := store.Create("vm-01", "ssh", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, path+".alias"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(credential.ID); !errors.Is(err, ErrUnsafeStore) {
			t.Fatalf("hardlinked state: got %v, want ErrUnsafeStore", err)
		}
	})

	t.Run("lock", func(t *testing.T) {
		path := testStorePath(t)
		store, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := store.Create("vm-01", "ssh", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path+".lock", path+".lock.alias"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(credential.ID); !errors.Is(err, ErrUnsafeStore) {
			t.Fatalf("hardlinked lock: got %v, want ErrUnsafeStore", err)
		}
	})
}

func TestStoreRejectsStructurallyTamperedState(t *testing.T) {
	path := testStorePath(t)
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(credential.ID), []byte("invalid-enrollment-id"), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(credential.ID); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("tampered state: got %v, want ErrInvalidStore", err)
	}
}

func TestStoreRejectsEnrollmentLifetimeExtendedOnDisk(t *testing.T) {
	path := testStorePath(t)
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	record := state.Enrollments[credential.ID]
	record.ExpiresAt = record.CreatedAt + int64((24*time.Hour)/time.Second) + 1
	state.Enrollments[credential.ID] = record
	data, err = signing.CanonicalJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(credential.ID); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("extended enrollment lifetime: got %v, want ErrInvalidStore", err)
	}
}

func TestEnrollmentConflictExpiryListAndRevoke(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("vm-01", "ssh", time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate active enrollment: got %v, want ErrConflict", err)
	}
	revoked, err := store.Revoke(first.ID)
	if err != nil || revoked.RevokedAt != now.Unix() {
		t.Fatalf("revoke=%#v err=%v", revoked, err)
	}
	revokedAgain, err := store.Revoke(first.ID)
	if err != nil || revokedAgain.RevokedAt != revoked.RevokedAt {
		t.Fatalf("idempotent revoke=%#v err=%v", revokedAgain, err)
	}
	_, _, publicPEM := testIdentity(t)
	if _, err := store.Consume(ConsumeRequest{
		ID: first.ID, Secret: first.Secret, Instance: first.Instance, Profile: first.Profile,
		InstancePublicKeyPEM: publicPEM,
	}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("consume revoked enrollment: got %v, want ErrRevoked", err)
	}
	second, err := store.Create("vm-01", "ssh", time.Minute)
	if err != nil {
		t.Fatalf("replacement after revoke: %v", err)
	}
	now = now.Add(time.Minute)
	third, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatalf("replacement after expiry: %v", err)
	}
	if third.ID == second.ID {
		t.Fatal("replacement enrollment reused an identifier")
	}
	records, err := store.List()
	if err != nil || len(records) != 3 {
		t.Fatalf("list=%#v err=%v", records, err)
	}
	serialized, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(first.Secret)) || bytes.Contains(serialized, []byte(second.Secret)) ||
		bytes.Contains(serialized, []byte("secret_digest")) {
		t.Fatalf("public enrollment list leaked secret material: %s", serialized)
	}
}

func TestRevokedConsumedIdentityIsNoLongerAuthenticated(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, publicPEM := testIdentity(t)
	record, err := store.Consume(ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: credential.Instance, Profile: credential.Profile,
		InstancePublicKeyPEM: publicPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindInstance("vm-01"); err != nil {
		t.Fatalf("consumed identity not found: %v", err)
	}
	if _, err := store.Revoke(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindInstance("vm-01"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked identity remained authenticated: got %v", err)
	}
}

func TestRevokeClampsClockRollbackWithoutCorruptingStore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	store, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Get(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(-time.Hour)
	revoked, err := store.Revoke(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt != created.CreatedAt {
		t.Fatalf("revoked_at=%d, want clamped created_at=%d", revoked.RevokedAt, created.CreatedAt)
	}
	reopened, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("clock rollback corrupted persisted store: %v", err)
	}
	loaded, err := reopened.Get(credential.ID)
	if err != nil || loaded.RevokedAt != created.CreatedAt {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
}

func testIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := signing.MarshalPublicPEM(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey, publicPEM
}

func testStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "private", "state.json")
}

func testOpenSSHKey(t *testing.T, comment string) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	writeSSHString := func(value []byte) {
		if err := binary.Write(&blob, binary.BigEndian, uint32(len(value))); err != nil {
			t.Fatal(err)
		}
		if _, err := blob.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	writeSSHString([]byte("ssh-ed25519"))
	writeSSHString(publicKey)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " " + comment
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != expected || !info.Mode().IsRegular() {
		t.Fatalf("%s mode/type = %v, want regular %04o", path, info.Mode(), expected)
	}
}
