package serving

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/signing"
)

func TestDesiredStoreVerifiesSignatureReleaseExpiryAndGeneration(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("a", 64)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDesiredStore(filepath.Join(t.TempDir(), "private", "desired"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	first := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	if err := store.Put(first, releaseSet, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Exact retries are idempotent.
	if err := store.Put(first, releaseSet, now, time.Minute); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	path := filepath.Join(store.directory, "vm-01.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("desired file mode/type=%v err=%v", info.Mode(), err)
	}
	loaded, err := store.Get("vm-01")
	if err != nil || !reflect.DeepEqual(loaded, first) {
		t.Fatalf("loaded=%#v err=%v, want %#v", loaded, err, first)
	}

	equalGenerationDifferent := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(2*time.Hour), false)
	if err := store.Put(equalGenerationDifferent, releaseSet, now, time.Minute); !errors.Is(err, enrollment.ErrInvalidDesiredState) {
		t.Fatalf("equal generation changed content: got %v", err)
	}
	second := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 2, now, now.Add(time.Hour), false)
	if err := store.Put(second, releaseSet, now, time.Minute); err != nil {
		t.Fatalf("generation 2: %v", err)
	}
	if err := store.Put(first, releaseSet, now, time.Minute); !errors.Is(err, enrollment.ErrInvalidDesiredState) {
		t.Fatalf("generation rollback: got %v", err)
	}
	revoked := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 3, now, now.Add(time.Hour), true)
	if err := store.Put(revoked, releaseSet, now, time.Minute); err != nil {
		t.Fatalf("signed revocation: %v", err)
	}

	wrongRelease := signDesiredFixture(t, privateKey, "vm-02", "ssh", "sha256:"+strings.Repeat("b", 64), 1, now, now.Add(time.Hour), false)
	if err := store.Put(wrongRelease, releaseSet, now, time.Minute); !errors.Is(err, enrollment.ErrBinding) {
		t.Fatalf("wrong release: got %v, want ErrBinding", err)
	}
	expired := signDesiredFixture(t, privateKey, "vm-03", "ssh", releaseSet, 1, now.Add(-2*time.Hour), now.Add(-time.Hour), false)
	if err := store.Put(expired, releaseSet, now, time.Minute); !errors.Is(err, enrollment.ErrExpired) {
		t.Fatalf("expired desired: got %v, want ErrExpired", err)
	}
	future := signDesiredFixture(t, privateKey, "vm-04", "ssh", releaseSet, 1, now.Add(2*time.Minute), now.Add(time.Hour), false)
	if err := store.Put(future, releaseSet, now, time.Minute); !errors.Is(err, enrollment.ErrStaleRequest) {
		t.Fatalf("future desired: got %v, want ErrStaleRequest", err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner := signDesiredFixture(t, wrongPrivate, "vm-05", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	if err := store.Put(wrongSigner, releaseSet, now, time.Minute); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("wrong desired signer: got %v, want invalid signature", err)
	}
}

func TestDesiredStoreConcurrentIdempotentPut(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("c", 64)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDesiredStore(filepath.Join(t.TempDir(), "private", "desired"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	desired := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	const callers = 24
	start := make(chan struct{})
	errorsChannel := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errorsChannel <- store.Put(desired, releaseSet, now, time.Minute)
		}()
	}
	close(start)
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent desired Put: %v", err)
		}
	}
	loaded, err := store.Get("vm-01")
	if err != nil || !reflect.DeepEqual(loaded, desired) {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
}

func TestDesiredStoreGetRejectsCanonicalDiskTamper(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("d", 64)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDesiredStore(filepath.Join(t.TempDir(), "private", "desired"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	desired := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	if err := store.Put(desired, releaseSet, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	tampered := desired
	tampered.State.Profile = "pbp"
	tamperedData, err := signing.CanonicalJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.directory, "vm-01.json"), tamperedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("vm-01"); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("canonical disk tamper: got %v, want invalid signature", err)
	}
}

func TestDesiredStoreMonotonicAcrossIndependentStoreObjects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("e", 64)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private", "desired")
	storeOne, err := NewDesiredStore(directory, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	storeTwo, err := NewDesiredStore(directory, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		instance := fmt.Sprintf("vm-%02d", index)
		first := signDesiredFixture(t, privateKey, instance, "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
		second := signDesiredFixture(t, privateKey, instance, "ssh", releaseSet, 2, now, now.Add(time.Hour), false)
		third := signDesiredFixture(t, privateKey, instance, "ssh", releaseSet, 3, now, now.Add(time.Hour), false)
		if err := storeOne.Put(first, releaseSet, now, time.Minute); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() { <-start; results <- storeOne.Put(second, releaseSet, now, time.Minute) }()
		go func() { <-start; results <- storeTwo.Put(third, releaseSet, now, time.Minute) }()
		close(start)
		for attempt := 0; attempt < 2; attempt++ {
			result := <-results
			if result != nil && !errors.Is(result, enrollment.ErrInvalidDesiredState) {
				t.Fatalf("independent store Put: %v", result)
			}
		}
		loaded, err := storeOne.Get(instance)
		if err != nil || loaded.State.Generation != 3 {
			t.Fatalf("%s final generation=%d err=%v, want 3", instance, loaded.State.Generation, err)
		}
	}
	lockInfo, err := os.Lstat(filepath.Join(directory, ".desired.lock"))
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("desired lock mode/type=%v err=%v", lockInfo.Mode(), err)
	}
}

func TestDesiredStoreRejectsSymlinkLock(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("f", 64)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private", "desired")
	store, err := NewDesiredStore(directory, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, ".desired.lock")); err != nil {
		t.Fatal(err)
	}
	desired := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	if err := store.Put(desired, releaseSet, now, time.Minute); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlink desired lock: got %v, want ErrUnsafeState", err)
	}
	controlTarget := filepath.Join(t.TempDir(), "control-lock-target")
	if err := os.WriteFile(controlTarget, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(controlTarget, filepath.Join(directory, ".control.lock")); err != nil {
		t.Fatal(err)
	}
	if err := store.WithControlTransaction(func() error { return nil }); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlink control lock: got %v, want ErrUnsafeState", err)
	}
}

func TestDesiredStoreRejectsHardlinkedLocks(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "desired")
	store, err := NewDesiredStore(directory, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	releaseSet := "sha256:" + strings.Repeat("a", 64)
	desired := signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 1, now, now.Add(time.Hour), false)
	if err := store.Put(desired, releaseSet, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, ".desired.lock")
	if err := os.Link(lockPath, lockPath+".alias"); err != nil {
		t.Fatal(err)
	}
	desired = signDesiredFixture(t, privateKey, "vm-01", "ssh", releaseSet, 2, now, now.Add(time.Hour), false)
	if err := store.Put(desired, releaseSet, now, time.Minute); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("hardlinked desired lock: got %v, want ErrUnsafeState", err)
	}
}

func signDesiredFixture(t *testing.T, privateKey ed25519.PrivateKey, instance, profile, releaseSet string, generation uint64, issuedAt, expiresAt time.Time, revoked bool) enrollment.SignedDesiredState {
	t.Helper()
	keys := []string{testAuthorizedKey(t)}
	if revoked {
		keys = nil
	}
	signed, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: instance, Profile: profile, Generation: generation,
		ReleaseSet: releaseSet, AuthorizedSSHKeys: keys, Revoked: revoked,
		IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
