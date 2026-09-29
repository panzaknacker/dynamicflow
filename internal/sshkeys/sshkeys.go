// package sshkeys manages owner-local Ed25519 identities. Private key material
// is written only to mode-0600 files and is never returned by this package.
package sshkeys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/localstate"
)

const SchemaVersion = 1

type Scope string

const (
	Operator  Scope = "operator"
	Instance  Scope = "instance"
	Bootstrap Scope = "bootstrap"
	// Control is the long-lived owner-local management identity for a Control
	// node. managers must opt in explicitly with WithControlScope so adding the
	// internal scope cannot expose it through the existing generic key CLI.
	Control Scope = "control"
)

type Status string

const (
	ActiveStatus  Status = "active"
	RevokedStatus Status = "revoked"
)

var (
	ErrAlreadyExists = errors.New("SSH key already exists")
	ErrInvalidKey    = errors.New("invalid SSH key")
	ErrInvalidName   = errors.New("invalid SSH key name")
	ErrNotFound      = errors.New("SSH key not found")
	ErrRevoked       = errors.New("SSH key is revoked")
	ErrGeneration    = errors.New("SSH key generation conflict")
	keyName          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Record contains only public metadata. it deliberately has no private-key
// field or private-key bytes.
type Record struct {
	SchemaVersion       int        `json:"schema_version"`
	Scope               Scope      `json:"scope"`
	Name                string     `json:"name"`
	Generation          uint64     `json:"generation"`
	Status              Status     `json:"status"`
	PublicKey           string     `json:"public_key"`
	Fingerprint         string     `json:"fingerprint"`
	PreviousFingerprint string     `json:"previous_fingerprint,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

// Paths identifies files needed by an SSH client. Private is intentionally
// excluded from JSON serialization to avoid accidental CLI disclosure.
type Paths struct {
	Private string `json:"-"`
	Public  string `json:"public"`
}

type Manager struct {
	store     *localstate.Store
	sshKeygen string
	now       func() time.Time
	control   bool
}

type Option func(*Manager)

func WithSSHKeygen(path string) Option {
	return func(manager *Manager) { manager.sshKeygen = path }
}

func WithClock(clock func() time.Time) Option {
	return func(manager *Manager) { manager.now = clock }
}

// WithControlScope enables the internal long-lived Control identity scope for
// this manager. Operator-facing generic managers intentionally omit it.
func WithControlScope() Option {
	return func(manager *Manager) { manager.control = true }
}

func NewManager(store *localstate.Store, options ...Option) *Manager {
	manager := &Manager{
		store:     store,
		sshKeygen: "ssh-keygen",
		now:       time.Now,
	}
	for _, option := range options {
		option(manager)
	}
	return manager
}

// ValidateEd25519PublicKey normalizes a public Ed25519 key and returns its
// OpenSSH SHA256 fingerprint. it never accepts private key material.
func ValidateEd25519PublicKey(publicKey string) (normalized string, fingerprint string, err error) {
	return parsePublicKey([]byte(publicKey))
}

// Create generates the first immutable generation for one named identity.
func (m *Manager) Create(ctx context.Context, scope Scope, name string) (Record, error) {
	if err := m.validateIdentity(scope, name); err != nil {
		return Record{}, err
	}
	var result Record
	err := m.store.WithLock(lockRelative(scope, name), func() error {
		if _, err := m.getUnlocked(scope, name); err == nil {
			return ErrAlreadyExists
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		record, err := m.ensureGeneration(ctx, scope, name, 1, "")
		if err != nil {
			return err
		}
		if err := m.store.WriteJSON(currentRelative(scope, name), record); err != nil {
			return fmt.Errorf("activate SSH key: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

// Rotate creates a new immutable generation and atomically switches metadata
// to it. a complete pending generation is reused after an interrupted switch.
func (m *Manager) Rotate(ctx context.Context, scope Scope, name string) (Record, error) {
	return m.rotate(ctx, scope, name, 0)
}

// RotateIfGeneration performs the generation check and rotation under the
// same identity lock. it prevents two concurrent operator commands from
// advancing a target-bound identity more than one unacknowledged generation.
func (m *Manager) RotateIfGeneration(ctx context.Context, scope Scope, name string, expected uint64) (Record, error) {
	if expected == 0 {
		return Record{}, ErrGeneration
	}
	return m.rotate(ctx, scope, name, expected)
}

func (m *Manager) rotate(ctx context.Context, scope Scope, name string, expected uint64) (Record, error) {
	if err := m.validateIdentity(scope, name); err != nil {
		return Record{}, err
	}
	var result Record
	err := m.store.WithLock(lockRelative(scope, name), func() error {
		current, err := m.getUnlocked(scope, name)
		if err != nil {
			return err
		}
		if current.Status == RevokedStatus {
			return ErrRevoked
		}
		if expected != 0 && current.Generation != expected {
			return ErrGeneration
		}
		record, err := m.ensureGeneration(ctx, scope, name, current.Generation+1, current.Fingerprint)
		if err != nil {
			return err
		}
		if err := m.store.WriteJSON(currentRelative(scope, name), record); err != nil {
			return fmt.Errorf("activate rotated SSH key: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

// Revoke marks the current identity unusable without deleting local evidence.
func (m *Manager) Revoke(scope Scope, name string) (Record, error) {
	if err := m.validateIdentity(scope, name); err != nil {
		return Record{}, err
	}
	var result Record
	err := m.store.WithLock(lockRelative(scope, name), func() error {
		record, err := m.getUnlocked(scope, name)
		if err != nil {
			return err
		}
		if record.Status == RevokedStatus {
			result = record
			return nil
		}
		now := m.now().UTC()
		record.Status = RevokedStatus
		record.RevokedAt = &now
		if err := m.store.WriteJSON(currentRelative(scope, name), record); err != nil {
			return fmt.Errorf("revoke SSH key: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

// Get returns validated public metadata for the current generation.
func (m *Manager) Get(scope Scope, name string) (Record, error) {
	if err := m.validateIdentity(scope, name); err != nil {
		return Record{}, err
	}
	return m.getUnlocked(scope, name)
}

// Current returns validated current-generation metadata and owner-local paths
// for internal audit/revocation checks. Paths remain excluded from JSON.
func (m *Manager) Current(scope Scope, name string) (Record, Paths, error) {
	record, err := m.Get(scope, name)
	if err != nil {
		return Record{}, Paths{}, err
	}
	paths, err := m.pathsFor(record)
	return record, paths, err
}

// Active returns metadata and paths only when the identity is not revoked.
func (m *Manager) Active(scope Scope, name string) (Record, Paths, error) {
	record, paths, err := m.Current(scope, name)
	if err != nil {
		return Record{}, Paths{}, err
	}
	if record.Status != ActiveStatus {
		return Record{}, Paths{}, ErrRevoked
	}
	return record, paths, nil
}

// Previous returns the immediately preceding generation only when it is
// cryptographically linked from the active record. SSH clients use this
// narrowly during the desired-state overlap window so a local rotation cannot
// lock the operator out before the target acknowledges the new public key.
func (m *Manager) Previous(scope Scope, name string) (Record, Paths, error) {
	current, err := m.Get(scope, name)
	if err != nil {
		return Record{}, Paths{}, err
	}
	if current.Status != ActiveStatus {
		return Record{}, Paths{}, ErrRevoked
	}
	if current.Generation <= 1 || current.PreviousFingerprint == "" {
		return Record{}, Paths{}, ErrNotFound
	}
	var previous Record
	if err := m.store.ReadJSON(generationMetadataRelative(scope, name, current.Generation-1), &previous); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, Paths{}, ErrNotFound
		}
		return Record{}, Paths{}, err
	}
	if err := m.validateRecord(previous, scope, name); err != nil ||
		previous.Generation != current.Generation-1 || previous.Fingerprint != current.PreviousFingerprint ||
		previous.Status != ActiveStatus {
		return Record{}, Paths{}, fmt.Errorf("%w: previous generation binding mismatch", ErrInvalidKey)
	}
	paths, err := m.pathsFor(previous)
	return previous, paths, err
}

// List returns validated public records sorted by name.
func (m *Manager) List(scope Scope) ([]Record, error) {
	if !m.validScope(scope) {
		return nil, fmt.Errorf("%w: scope %q", ErrInvalidKey, scope)
	}
	directory, err := m.store.EnsureDir(filepath.Join("keys", string(scope)))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrInvalidKey, entry.Name())
		}
		if !keyName.MatchString(entry.Name()) {
			return nil, fmt.Errorf("%w: unexpected key directory %q", ErrInvalidName, entry.Name())
		}
		record, err := m.Get(scope, entry.Name())
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, nil
}

func (m *Manager) ensureGeneration(ctx context.Context, scope Scope, name string, generation uint64, previous string) (Record, error) {
	metadataRelative := generationMetadataRelative(scope, name, generation)
	var existing Record
	if err := m.store.ReadJSON(metadataRelative, &existing); err == nil {
		if err := m.validateRecord(existing, scope, name); err != nil {
			return Record{}, fmt.Errorf("validate pending SSH key: %w", err)
		}
		if existing.Generation != generation || existing.PreviousFingerprint != previous {
			return Record{}, fmt.Errorf("%w: pending generation does not match rotation", ErrInvalidKey)
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, err
	}

	directoryRelative := generationDirectory(scope, name, generation)
	directory, err := m.store.EnsureDir(directoryRelative)
	if err != nil {
		return Record{}, err
	}
	temporary, err := os.MkdirTemp(directory, ".ssh-keygen-")
	if err != nil {
		return Record{}, fmt.Errorf("create SSH key generation directory: %w", err)
	}
	defer os.RemoveAll(temporary) // generated path is private and narrowly scoped
	if err := os.Chmod(temporary, localstate.DirMode); err != nil {
		return Record{}, fmt.Errorf("secure SSH key generation directory: %w", err)
	}
	base := filepath.Join(temporary, "id_ed25519")
	comment := fmt.Sprintf("dynamicflow:%s:%s:g%d", scope, name, generation)
	command := exec.CommandContext(ctx, m.sshKeygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", base)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return Record{}, fmt.Errorf("ssh-keygen failed: %w", err)
	}
	privateData, err := readGenerated(base, true)
	if err != nil {
		return Record{}, err
	}
	defer clear(privateData)
	publicData, err := readGenerated(base+".pub", false)
	if err != nil {
		return Record{}, err
	}
	publicKey, fingerprint, err := parsePublicKey(publicData)
	if err != nil {
		return Record{}, err
	}
	record := Record{
		SchemaVersion:       SchemaVersion,
		Scope:               scope,
		Name:                name,
		Generation:          generation,
		Status:              ActiveStatus,
		PublicKey:           publicKey,
		Fingerprint:         fingerprint,
		PreviousFingerprint: previous,
		CreatedAt:           m.now().UTC(),
	}
	if err := m.store.WriteFile(privateRelative(scope, name, generation), privateData); err != nil {
		return Record{}, fmt.Errorf("store private SSH key: %w", err)
	}
	if err := m.store.WriteFile(publicRelative(scope, name, generation), append([]byte(publicKey), '\n')); err != nil {
		return Record{}, fmt.Errorf("store public SSH key: %w", err)
	}
	if err := m.store.WriteJSON(metadataRelative, record); err != nil {
		return Record{}, fmt.Errorf("store SSH key generation metadata: %w", err)
	}
	return record, nil
}

func (m *Manager) getUnlocked(scope Scope, name string) (Record, error) {
	var record Record
	if err := m.store.ReadJSON(currentRelative(scope, name), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	if err := m.validateRecord(record, scope, name); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (m *Manager) validateRecord(record Record, scope Scope, name string) error {
	if record.SchemaVersion != SchemaVersion || record.Scope != scope || record.Name != name || record.Generation == 0 {
		return fmt.Errorf("%w: metadata identity mismatch", ErrInvalidKey)
	}
	if record.Status != ActiveStatus && record.Status != RevokedStatus {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidKey, record.Status)
	}
	if record.Status == ActiveStatus && record.RevokedAt != nil {
		return fmt.Errorf("%w: active key has revocation time", ErrInvalidKey)
	}
	if record.Status == RevokedStatus && record.RevokedAt == nil {
		return fmt.Errorf("%w: revoked key has no revocation time", ErrInvalidKey)
	}
	publicKey, fingerprint, err := parsePublicKey([]byte(record.PublicKey))
	if err != nil || publicKey != record.PublicKey || fingerprint != record.Fingerprint {
		return fmt.Errorf("%w: public metadata mismatch", ErrInvalidKey)
	}
	publicData, err := m.store.ReadFile(publicRelative(scope, name, record.Generation))
	if err != nil {
		return fmt.Errorf("read public SSH key: %w", err)
	}
	if strings.TrimSpace(string(publicData)) != record.PublicKey {
		return fmt.Errorf("%w: public key file differs from metadata", ErrInvalidKey)
	}
	paths, err := m.pathsFor(record)
	if err != nil {
		return err
	}
	if err := validatePrivateFile(paths.Private); err != nil {
		return err
	}
	return nil
}

func (m *Manager) pathsFor(record Record) (Paths, error) {
	privatePath, err := m.store.Path(privateRelative(record.Scope, record.Name, record.Generation))
	if err != nil {
		return Paths{}, err
	}
	publicPath, err := m.store.Path(publicRelative(record.Scope, record.Name, record.Generation))
	if err != nil {
		return Paths{}, err
	}
	return Paths{Private: privatePath, Public: publicPath}, nil
}

func readGenerated(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect generated SSH key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: generated key is not a regular file", ErrInvalidKey)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: generated private key mode is %04o", ErrInvalidKey, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read generated SSH key: %w", err)
	}
	if len(data) == 0 || len(data) > 64<<10 {
		return nil, fmt.Errorf("%w: generated key has invalid size", ErrInvalidKey)
	}
	return data, nil
}

func parsePublicKey(data []byte) (string, string, error) {
	line := strings.TrimSpace(string(data))
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", "", fmt.Errorf("%w: public key must be one line", ErrInvalidKey)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return "", "", fmt.Errorf("%w: expected Ed25519 public key", ErrInvalidKey)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || !validEd25519Blob(blob) {
		return "", "", fmt.Errorf("%w: malformed Ed25519 public key", ErrInvalidKey)
	}
	digest := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	return strings.Join(fields, " "), fingerprint, nil
}

func validEd25519Blob(blob []byte) bool {
	algorithm, rest, ok := readSSHString(blob)
	if !ok || string(algorithm) != "ssh-ed25519" {
		return false
	}
	key, rest, ok := readSSHString(rest)
	return ok && len(key) == 32 && len(rest) == 0
}

func readSSHString(data []byte) ([]byte, []byte, bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	length := uint64(binary.BigEndian.Uint32(data[:4]))
	if length > uint64(len(data)-4) {
		return nil, nil, false
	}
	end := 4 + int(length)
	return data[4:end], data[end:], true
}

func validatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private SSH key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != localstate.FileMode {
		return fmt.Errorf("%w: private SSH key must be a regular mode-0600 file", ErrInvalidKey)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: private SSH key has wrong owner", ErrInvalidKey)
	}
	return nil
}

func (m *Manager) validateIdentity(scope Scope, name string) error {
	if !m.validScope(scope) {
		return fmt.Errorf("%w: scope %q", ErrInvalidKey, scope)
	}
	if !keyName.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

func (m *Manager) validScope(scope Scope) bool {
	return scope == Operator || scope == Instance || scope == Bootstrap ||
		(scope == Control && m != nil && m.control)
}

func baseRelative(scope Scope, name string) string {
	return filepath.Join("keys", string(scope), name)
}

func lockRelative(scope Scope, name string) string {
	return filepath.Join(baseRelative(scope, name), ".lock")
}

func currentRelative(scope Scope, name string) string {
	return filepath.Join(baseRelative(scope, name), "current.json")
}

func generationDirectory(scope Scope, name string, generation uint64) string {
	return filepath.Join(baseRelative(scope, name), "generations", fmt.Sprintf("%06d", generation))
}

func generationMetadataRelative(scope Scope, name string, generation uint64) string {
	return filepath.Join(generationDirectory(scope, name, generation), "metadata.json")
}

func privateRelative(scope Scope, name string, generation uint64) string {
	return filepath.Join(generationDirectory(scope, name, generation), "id_ed25519")
}

func publicRelative(scope Scope, name string, generation uint64) string {
	return filepath.Join(generationDirectory(scope, name, generation), "id_ed25519.pub")
}
