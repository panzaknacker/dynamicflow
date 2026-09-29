package serving

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/signing"
)

// DesiredStore holds only operator-signed desired-state documents. the
// serving process receives the verification key, never the corresponding
// private signing key.
type DesiredStore struct {
	directory string
	publicKey ed25519.PublicKey
	mu        sync.RWMutex
	controlMu sync.Mutex
}

func NewDesiredStore(directory string, publicKey ed25519.PublicKey) (*DesiredStore, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrUnsafeState
	}
	if err := secureDirectory(directory); err != nil {
		return nil, err
	}
	return &DesiredStore{directory: filepath.Clean(directory), publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

// Put verifies binding, freshness, release and monotonic generation before an
// atomic replacement. Equal-generation retries are accepted only when the
// complete signed document is byte-for-byte identical.
func (store *DesiredStore) Put(signed enrollment.SignedDesiredState, releaseSet string, now time.Time, maxSkew time.Duration) error {
	if err := enrollment.VerifyDesiredState(signed, store.publicKey, enrollment.DesiredExpectation{
		Instance: signed.State.Instance, Profile: signed.State.Profile, ReleaseSet: releaseSet,
		MinGeneration: 1, Now: now, MaxClockSkew: maxSkew,
	}); err != nil {
		return err
	}
	data, err := signing.CanonicalJSON(signed)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := lockDesiredFile(filepath.Join(store.directory, ".desired.lock"))
	if err != nil {
		return err
	}
	defer unlockDesiredFile(lock)
	path := filepath.Join(store.directory, signed.State.Instance+".json")
	if existing, readErr := readDesired(path); readErr == nil {
		if existing.State.Generation > signed.State.Generation {
			return fmt.Errorf("%w: desired-state generation rollback", enrollment.ErrInvalidDesiredState)
		}
		existingData, canonicalErr := signing.CanonicalJSON(existing)
		if canonicalErr != nil {
			return canonicalErr
		}
		if existing.State.Generation == signed.State.Generation {
			if bytes.Equal(existingData, data) {
				return nil
			}
			return fmt.Errorf("%w: generation already has different content", enrollment.ErrInvalidDesiredState)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	return writeAtomicPrivate(path, data)
}

func (store *DesiredStore) Get(instance string) (enrollment.SignedDesiredState, error) {
	if !validStatusName(instance) {
		return enrollment.SignedDesiredState{}, enrollment.ErrInvalidDesiredState
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	signed, err := readDesired(filepath.Join(store.directory, instance+".json"))
	if err != nil {
		return enrollment.SignedDesiredState{}, err
	}
	// verify the signature and structural binding on every disk read. full
	// release/freshness expectations are applied by the serving handler.
	if err := enrollment.VerifyDesiredState(signed, store.publicKey, enrollment.DesiredExpectation{
		Instance: instance, Profile: signed.State.Profile, MinGeneration: 1,
		Now: time.Unix(signed.State.IssuedAt, 0).UTC(), MaxClockSkew: 0,
	}); err != nil {
		return enrollment.SignedDesiredState{}, err
	}
	return signed, nil
}

// WithControlTransaction serializes the enrollment/desired compound update
// across goroutines and serving processes. the callback must not invoke this
// method recursively.
func (store *DesiredStore) WithControlTransaction(callback func() error) error {
	store.controlMu.Lock()
	defer store.controlMu.Unlock()
	lock, err := lockDesiredFile(filepath.Join(store.directory, ".control.lock"))
	if err != nil {
		return err
	}
	defer unlockDesiredFile(lock)
	return callback()
}

func readDesired(path string) (enrollment.SignedDesiredState, error) {
	data, err := readPrivateFile(path)
	if err != nil {
		return enrollment.SignedDesiredState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var signed enrollment.SignedDesiredState
	if err := decoder.Decode(&signed); err != nil {
		return enrollment.SignedDesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return enrollment.SignedDesiredState{}, enrollment.ErrInvalidDesiredState
	}
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil || !bytes.Equal(canonical, data) {
		return enrollment.SignedDesiredState{}, enrollment.ErrInvalidDesiredState
	}
	return signed, nil
}

func lockDesiredFile(path string) (*os.File, error) {
	existed := false
	if info, err := os.Lstat(path); err == nil {
		existed = true
		if !privateStateFileInfo(info, 0o600, 1<<20) {
			return nil, ErrUnsafeState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || stat.Mode&0o077 != 0 ||
		(existed && stat.Mode&0o777 != 0o600) {
		file.Close()
		return nil, ErrUnsafeState
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func unlockDesiredFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
