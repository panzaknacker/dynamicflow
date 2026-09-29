// package enrollment implements dynamicflow's short-lived, one-time VM
// enrollment credentials and instance-bound identity records.
package enrollment

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"dynamicflow/internal/signing"
)

const storeVersion = 1

const (
	maxStoreBytes = 16 << 20
	maxNonceCount = 100_000
)

var (
	ErrInvalidStore      = errors.New("invalid enrollment store")
	ErrUnsafeStore       = errors.New("unsafe enrollment store path")
	ErrNotFound          = errors.New("enrollment not found")
	ErrInvalidSecret     = errors.New("invalid enrollment secret")
	ErrExpired           = errors.New("enrollment expired")
	ErrConsumed          = errors.New("enrollment already consumed")
	ErrRevoked           = errors.New("enrollment revoked")
	ErrConflict          = errors.New("active enrollment already exists for instance")
	ErrBinding           = errors.New("enrollment binding mismatch")
	ErrReplay            = errors.New("instance request replayed")
	ErrStaleRequest      = errors.New("instance request timestamp outside allowed window")
	ErrInvalidEnrollment = errors.New("invalid enrollment")
)

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Credential is returned exactly once when an enrollment is created. Secret
// is intentionally excluded from JSON so accidental API/log serialization
// cannot disclose it.
type Credential struct {
	ID        string `json:"id"`
	Secret    string `json:"-"`
	Instance  string `json:"instance"`
	Profile   string `json:"profile"`
	ExpiresAt int64  `json:"expires_at"`
}

// Record is the non-secret enrollment and instance-identity metadata safe to
// expose to an authenticated operator.
type Record struct {
	ID                   string `json:"id"`
	Instance             string `json:"instance"`
	Profile              string `json:"profile"`
	CreatedAt            int64  `json:"created_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ConsumedAt           int64  `json:"consumed_at,omitempty"`
	RevokedAt            int64  `json:"revoked_at,omitempty"`
	InstanceKeyID        string `json:"instance_key_id,omitempty"`
	InstancePublicKeyPEM string `json:"instance_public_key_pem,omitempty"`
}

// ConsumeRequest binds the one-time credential to the intended instance,
// profile and freshly generated instance identity public key.
type ConsumeRequest struct {
	ID                   string
	Secret               string
	Instance             string
	Profile              string
	InstancePublicKeyPEM []byte
}

type diskEnrollment struct {
	ID                   string `json:"id"`
	SecretDigest         string `json:"secret_digest"`
	Instance             string `json:"instance"`
	Profile              string `json:"profile"`
	CreatedAt            int64  `json:"created_at"`
	ExpiresAt            int64  `json:"expires_at"`
	ConsumedAt           int64  `json:"consumed_at,omitempty"`
	RevokedAt            int64  `json:"revoked_at,omitempty"`
	InstanceKeyID        string `json:"instance_key_id,omitempty"`
	InstancePublicKeyPEM string `json:"instance_public_key_pem,omitempty"`
}

type diskState struct {
	Version     int                       `json:"version"`
	Enrollments map[string]diskEnrollment `json:"enrollments"`
	Nonces      map[string]int64          `json:"nonces,omitempty"`
}

// Option configures a Store.
type Option func(*Store)

// WithClock supplies a testable clock. production callers should omit it.
func WithClock(now func() time.Time) Option {
	return func(store *Store) {
		if now != nil {
			store.now = now
		}
	}
}

// Store persists credential digests, consumption state and request nonces in
// a single atomically replaced 0600 JSON file. a separate 0600 flock serializes
// writers across Store objects and processes.
type Store struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

func NewStore(path string, options ...Option) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: store path must be an absolute file path", ErrUnsafeStore)
	}
	store := &Store{path: filepath.Clean(path), now: time.Now}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	if err := ensurePrivateDirectory(filepath.Dir(store.path)); err != nil {
		return nil, err
	}
	if err := validateExistingStore(store.path); err != nil {
		return nil, err
	}
	return store, nil
}

// Create returns a 256-bit base64url secret. only a domain-separated digest is
// persisted; callers must deliberately deliver the returned secret once.
func (store *Store) Create(instance, profile string, ttl time.Duration) (Credential, error) {
	if !validIdentifier(instance) || !validIdentifier(profile) || ttl <= 0 || ttl > 24*time.Hour {
		return Credential{}, ErrInvalidEnrollment
	}
	var result Credential
	err := store.withLockedState(true, func(state *diskState) (bool, error) {
		now := store.now().UTC().Unix()
		if len(state.Enrollments) >= 100_000 {
			return false, fmt.Errorf("%w: enrollment capacity reached", ErrInvalidStore)
		}
		for _, existing := range state.Enrollments {
			if existing.Instance == instance && existing.RevokedAt == 0 && (existing.ConsumedAt != 0 || existing.ExpiresAt > now) {
				return false, ErrConflict
			}
		}
		for attempts := 0; attempts < 8; attempts++ {
			id, err := randomToken(16)
			if err != nil {
				return false, err
			}
			if _, exists := state.Enrollments[id]; exists {
				continue
			}
			secret, err := randomToken(32)
			if err != nil {
				return false, err
			}
			digest, err := enrollmentSecretDigest(id, secret)
			if err != nil {
				return false, err
			}
			issued := store.now().UTC()
			now := issued.Unix()
			expires := issued.Add(ttl).Unix()
			// a non-monotonic injected clock must not create a non-expiring code.
			if expires <= now {
				return false, ErrInvalidEnrollment
			}
			record := diskEnrollment{
				ID: id, SecretDigest: digest, Instance: instance, Profile: profile,
				CreatedAt: now, ExpiresAt: expires,
			}
			state.Enrollments[id] = record
			result = Credential{ID: id, Secret: secret, Instance: instance, Profile: profile, ExpiresAt: expires}
			return true, nil
		}
		return false, errors.New("could not allocate unique enrollment identifier")
	})
	return result, err
}

// HasActiveInstance reports whether an unrevoked consumed identity or live
// pending credential already owns the instance name.
func (store *Store) HasActiveInstance(instance string) (bool, error) {
	if !validIdentifier(instance) {
		return false, ErrInvalidEnrollment
	}
	active := false
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		now := store.now().UTC().Unix()
		for _, record := range state.Enrollments {
			if record.Instance == instance && record.RevokedAt == 0 && (record.ConsumedAt != 0 || record.ExpiresAt > now) {
				active = true
				break
			}
		}
		return false, nil
	})
	return active, err
}

// Consume atomically burns a credential and records the instance identity.
// exactly one concurrent caller can succeed.
func (store *Store) Consume(request ConsumeRequest) (Record, error) {
	if !validIdentifier(request.Instance) || !validIdentifier(request.Profile) || request.ID == "" {
		return Record{}, ErrInvalidEnrollment
	}
	publicKey, err := signing.ParsePublicPEM(request.InstancePublicKeyPEM)
	if err != nil {
		return Record{}, fmt.Errorf("instance identity: %w", ErrInvalidEnrollment)
	}
	canonicalPublicKey, err := signing.MarshalPublicPEM(publicKey)
	if err != nil {
		return Record{}, err
	}
	keyID, err := signing.KeyID(publicKey)
	if err != nil {
		return Record{}, err
	}
	providedDigest, err := enrollmentSecretDigest(request.ID, request.Secret)
	if err != nil {
		return Record{}, ErrInvalidSecret
	}
	var result Record
	err = store.withLockedState(false, func(state *diskState) (bool, error) {
		record, exists := state.Enrollments[request.ID]
		if !exists {
			return false, ErrNotFound
		}
		now := store.now().UTC().Unix()
		if now < record.CreatedAt || now >= record.ExpiresAt {
			return false, ErrExpired
		}
		if record.ConsumedAt != 0 {
			return false, ErrConsumed
		}
		if record.RevokedAt != 0 {
			return false, ErrRevoked
		}
		if record.Instance != request.Instance || record.Profile != request.Profile {
			return false, ErrBinding
		}
		expected, decodeErr := hex.DecodeString(record.SecretDigest)
		provided, providedErr := hex.DecodeString(providedDigest)
		if decodeErr != nil || providedErr != nil || len(expected) != sha256.Size ||
			subtle.ConstantTimeCompare(expected, provided) != 1 {
			return false, ErrInvalidSecret
		}
		record.ConsumedAt = now
		record.InstanceKeyID = keyID
		record.InstancePublicKeyPEM = string(canonicalPublicKey)
		state.Enrollments[request.ID] = record
		result = publicRecord(record)
		return true, nil
	})
	return result, err
}

// List returns public, non-secret enrollment records in deterministic order.
func (store *Store) List() ([]Record, error) {
	result := []Record{}
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		for _, record := range state.Enrollments {
			result = append(result, publicRecord(record))
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].Instance == result[j].Instance {
				if result[i].CreatedAt == result[j].CreatedAt {
					return result[i].ID < result[j].ID
				}
				return result[i].CreatedAt < result[j].CreatedAt
			}
			return result[i].Instance < result[j].Instance
		})
		return false, nil
	})
	return result, err
}

// Revoke burns an enrollment credential without deleting its audit evidence.
// it is idempotent and also prevents a consumed instance identity from being
// selected by FindInstance.
func (store *Store) Revoke(id string) (Record, error) {
	if id == "" || len(id) > 128 {
		return Record{}, ErrInvalidEnrollment
	}
	var result Record
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		record, exists := state.Enrollments[id]
		if !exists {
			return false, ErrNotFound
		}
		if record.RevokedAt == 0 {
			record.RevokedAt = store.now().UTC().Unix()
			if record.RevokedAt < record.CreatedAt {
				record.RevokedAt = record.CreatedAt
			}
			state.Enrollments[id] = record
			result = publicRecord(record)
			return true, nil
		}
		result = publicRecord(record)
		return false, nil
	})
	return result, err
}

func (store *Store) Get(id string) (Record, error) {
	var result Record
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		record, exists := state.Enrollments[id]
		if !exists {
			return false, ErrNotFound
		}
		result = publicRecord(record)
		return false, nil
	})
	return result, err
}

// FindInstance returns the consumed identity for an instance name.
func (store *Store) FindInstance(instance string) (Record, error) {
	var result Record
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		for _, record := range state.Enrollments {
			if record.Instance == instance && record.ConsumedAt != 0 && record.RevokedAt == 0 {
				if result.ConsumedAt == 0 || record.ConsumedAt > result.ConsumedAt ||
					(record.ConsumedAt == result.ConsumedAt && record.ID > result.ID) {
					result = publicRecord(record)
				}
			}
		}
		if result.ConsumedAt == 0 {
			return false, ErrNotFound
		}
		return false, nil
	})
	return result, err
}

// SetInstanceProfile updates the binding of an already consumed, unrevoked
// instance identity after a separately signed desired-state profile change.
// pending credentials remain immutable and profile-bound.
func (store *Store) SetInstanceProfile(instance, profile string) (Record, error) {
	if !validIdentifier(instance) || !validIdentifier(profile) {
		return Record{}, ErrInvalidEnrollment
	}
	var result Record
	err := store.withLockedState(false, func(state *diskState) (bool, error) {
		selectedID := ""
		var selected diskEnrollment
		for id, record := range state.Enrollments {
			if record.Instance == instance && record.ConsumedAt != 0 && record.RevokedAt == 0 &&
				(selectedID == "" || record.ConsumedAt > selected.ConsumedAt) {
				selectedID, selected = id, record
			}
		}
		if selectedID == "" {
			return false, ErrNotFound
		}
		if selected.Profile == profile {
			result = publicRecord(selected)
			return false, nil
		}
		selected.Profile = profile
		state.Enrollments[selectedID] = selected
		result = publicRecord(selected)
		return true, nil
	})
	return result, err
}

func validIdentifier(value string) bool {
	return identifierRE.MatchString(value) && value != "." && value != ".."
}

func randomToken(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func enrollmentSecretDigest(id, secret string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return "", ErrInvalidSecret
	}
	hash := sha256.New()
	hash.Write([]byte("dynamicflow-enrollment-secret-v1\x00"))
	hash.Write([]byte(id))
	hash.Write([]byte{0})
	hash.Write(decoded)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func publicRecord(record diskEnrollment) Record {
	return Record{
		ID: record.ID, Instance: record.Instance, Profile: record.Profile,
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, ConsumedAt: record.ConsumedAt,
		RevokedAt:     record.RevokedAt,
		InstanceKeyID: record.InstanceKeyID, InstancePublicKeyPEM: record.InstancePublicKeyPEM,
	}
}

func emptyState() diskState {
	return diskState{
		Version: storeVersion, Enrollments: make(map[string]diskEnrollment),
		Nonces: make(map[string]int64),
	}
}

// withLockedState serializes every read as well as every mutation. serializing
// reads avoids observing a rename half-way through a concurrent operation on
// platforms/filesystems with weaker metadata visibility.
func (store *Store) withLockedState(createIfMissing bool, mutate func(*diskState) (bool, error)) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := lockFile(store.path + ".lock")
	if err != nil {
		return err
	}
	defer unlockFile(lock)

	state, exists, err := readState(store.path)
	if err != nil {
		return err
	}
	if !exists {
		state = emptyState()
		if !createIfMissing {
			// the callback decides whether an absent store is semantically an
			// empty store (for example, a lookup returns ErrNotFound).
		}
	}
	changed, err := mutate(&state)
	if err != nil {
		return err
	}
	if changed {
		return writeState(store.path, state)
	}
	return nil
}

func lockFile(path string) (*os.File, error) {
	existed := false
	if info, err := os.Lstat(path); err == nil {
		existed = true
		if !safePrivateFileInfo(info, 0o600, -1) {
			return nil, fmt.Errorf("%w: unsafe lock file", ErrUnsafeStore)
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
		return nil, errors.New("open enrollment lock")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || stat.Mode&0o077 != 0 ||
		(existed && stat.Mode&0o777 != 0o600) {
		file.Close()
		return nil, fmt.Errorf("%w: lock is not a regular file", ErrUnsafeStore)
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

func unlockFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func readState(path string) (diskState, bool, error) {
	file, info, err := openExistingStore(path)
	if errors.Is(err, os.ErrNotExist) {
		return diskState{}, false, nil
	}
	if err != nil {
		return diskState{}, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStoreBytes+1))
	if err != nil {
		return diskState{}, false, err
	}
	if len(data) > maxStoreBytes || int64(len(data)) != info.Size() {
		return diskState{}, false, fmt.Errorf("%w: state file changed while reading", ErrInvalidStore)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state diskState
	if err := decoder.Decode(&state); err != nil {
		return diskState{}, false, fmt.Errorf("%w: decode: %v", ErrInvalidStore, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return diskState{}, false, fmt.Errorf("%w: trailing JSON", ErrInvalidStore)
	}
	if state.Version != storeVersion || state.Enrollments == nil {
		return diskState{}, false, ErrInvalidStore
	}
	if state.Nonces == nil {
		state.Nonces = make(map[string]int64)
	}
	if err := validateDiskState(state); err != nil {
		return diskState{}, false, err
	}
	return state, true, nil
}

func writeState(path string, state diskState) error {
	data, err := signing.CanonicalJSON(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".enrollment-state-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func validateExistingStore(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !safePrivateFileInfo(info, 0o600, maxStoreBytes) {
		return fmt.Errorf("%w: state file must be regular mode 0600", ErrUnsafeStore)
	}
	return nil
}

func openExistingStore(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, ErrUnsafeStore
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, ErrUnsafeStore
	}
	info, err := file.Stat()
	if err != nil || !safePrivateFileInfo(info, 0o600, maxStoreBytes) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: state file must be a single-link owner-only regular file", ErrUnsafeStore)
	}
	return file, info, nil
}

func safePrivateFileInfo(info os.FileInfo, mode os.FileMode, maxSize int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode ||
		info.Size() < 0 || maxSize >= 0 && info.Size() > maxSize {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && int(stat.Uid) == os.Geteuid()
}

func validateDiskState(state diskState) error {
	if len(state.Enrollments) > 100_000 || len(state.Nonces) > maxNonceCount {
		return ErrInvalidStore
	}
	for id, record := range state.Enrollments {
		decodedID, idErr := base64.RawURLEncoding.DecodeString(id)
		digest, digestErr := hex.DecodeString(record.SecretDigest)
		if idErr != nil || len(decodedID) != 16 || record.ID != id || digestErr != nil || len(digest) != sha256.Size ||
			!validIdentifier(record.Instance) || !validIdentifier(record.Profile) || record.CreatedAt <= 0 || record.ExpiresAt <= record.CreatedAt {
			return ErrInvalidStore
		}
		if record.ExpiresAt-record.CreatedAt > int64((24*time.Hour)/time.Second) ||
			record.RevokedAt != 0 && record.RevokedAt < record.CreatedAt {
			return ErrInvalidStore
		}
		if record.ConsumedAt == 0 {
			if record.InstanceKeyID != "" || record.InstancePublicKeyPEM != "" {
				return ErrInvalidStore
			}
			continue
		}
		if record.ConsumedAt < record.CreatedAt || record.ConsumedAt >= record.ExpiresAt || record.InstanceKeyID == "" || record.InstancePublicKeyPEM == "" {
			return ErrInvalidStore
		}
		publicKey, err := signing.ParsePublicPEM([]byte(record.InstancePublicKeyPEM))
		if err != nil {
			return ErrInvalidStore
		}
		keyID, err := signing.KeyID(publicKey)
		if err != nil || keyID != record.InstanceKeyID {
			return ErrInvalidStore
		}
	}
	for key, expiresAt := range state.Nonces {
		parts := strings.Split(key, "\x00")
		validNamespace := len(parts) == 3 && parts[0] == "control" && parts[1] == "operator"
		if len(parts) == 3 && parts[0] == "instance" && validIdentifier(parts[1]) {
			validNamespace = true
		}
		// accept legacy instance-name\0nonce entries written before the
		// explicit namespace prefix was introduced; they expire naturally.
		if len(parts) == 2 && validIdentifier(parts[0]) {
			validNamespace = true
		}
		if !validNamespace || expiresAt <= 0 {
			return ErrInvalidStore
		}
		nonce, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
		if err != nil || len(nonce) != 32 {
			return ErrInvalidStore
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return fmt.Errorf("%w: invalid private directory", ErrUnsafeStore)
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: directory path contains a symlink or non-directory", ErrUnsafeStore)
		}
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: parent directory must be mode 0700 or stricter", ErrUnsafeStore)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: parent directory must be mode 0700 or stricter", ErrUnsafeStore)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
