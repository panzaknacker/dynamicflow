// package instances manages operator-local instance metadata, pinned host keys,
// and hardened OpenSSH arguments. it never performs a network connection.
package instances

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

const SchemaVersion = 1

type Status string

const (
	ActiveStatus  Status = "active"
	RevokedStatus Status = "revoked"
)

var (
	ErrHostKeyChanged  = errors.New("instance SSH host key changed")
	ErrInvalidInstance = errors.New("invalid instance")
	ErrNotFound        = errors.New("instance not found")
	ErrRevoked         = errors.New("instance is revoked")
	instanceName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	profileName        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sshUser            = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// KeyRef selects an owner-local operator or per-instance SSH identity.
type KeyRef struct {
	Scope sshkeys.Scope `json:"scope"`
	Name  string        `json:"name"`
}

// Record contains no secrets. HostKey is the explicitly trusted public host
// key received through enrollment or another authenticated channel.
type Record struct {
	SchemaVersion              int        `json:"schema_version"`
	Name                       string     `json:"name"`
	Profile                    string     `json:"profile"`
	Host                       string     `json:"host"`
	SSHPort                    int        `json:"ssh_port"`
	SSHUser                    string     `json:"ssh_user"`
	Key                        KeyRef     `json:"key"`
	HostKey                    string     `json:"host_key"`
	HostKeyFingerprint         string     `json:"host_key_fingerprint"`
	PreviousHostKeyFingerprint string     `json:"previous_host_key_fingerprint,omitempty"`
	Status                     Status     `json:"status"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	RevokedAt                  *time.Time `json:"revoked_at,omitempty"`
}

type Manager struct {
	store *localstate.Store
	keys  *sshkeys.Manager
	now   func() time.Time
}

type Option func(*Manager)

func WithClock(clock func() time.Time) Option {
	return func(manager *Manager) { manager.now = clock }
}

func NewManager(store *localstate.Store, keys *sshkeys.Manager, options ...Option) *Manager {
	manager := &Manager{store: store, keys: keys, now: time.Now}
	for _, option := range options {
		option(manager)
	}
	return manager
}

// Put creates or updates an instance. an existing host key may only be changed
// through RotateHostKey, making trust-boundary changes explicit.
func (m *Manager) Put(input Record) (Record, error) {
	record, err := m.normalizeInput(input)
	if err != nil {
		return Record{}, err
	}
	if m.keys == nil {
		return Record{}, fmt.Errorf("%w: SSH key manager is required", ErrInvalidInstance)
	}
	if _, _, err := m.keys.Active(record.Key.Scope, record.Key.Name); err != nil {
		return Record{}, fmt.Errorf("validate instance SSH identity: %w", err)
	}
	var result Record
	err = m.store.WithLock(lockRelative(record.Name), func() error {
		existing, getErr := m.readMetadata(record.Name)
		switch {
		case getErr == nil:
			if existing.Status == RevokedStatus {
				return ErrRevoked
			}
			if existing.HostKey != record.HostKey {
				return fmt.Errorf("%w: %s (expected %s, received %s)", ErrHostKeyChanged, record.Name, existing.HostKeyFingerprint, record.HostKeyFingerprint)
			}
			record.CreatedAt = existing.CreatedAt
			record.PreviousHostKeyFingerprint = existing.PreviousHostKeyFingerprint
		case errors.Is(getErr, ErrNotFound):
			record.CreatedAt = m.now().UTC()
		case getErr != nil:
			return getErr
		}
		record.UpdatedAt = m.now().UTC()
		if err := m.writeKnownHosts(record); err != nil {
			return err
		}
		if err := m.store.WriteJSON(metadataRelative(record.Name), record); err != nil {
			return fmt.Errorf("write instance metadata: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

// RotateHostKey performs an explicit pinned host-key transition.
func (m *Manager) RotateHostKey(name, publicKey string) (Record, error) {
	if err := validateName(name); err != nil {
		return Record{}, err
	}
	canonical, fingerprint, err := normalizeHostKey(publicKey)
	if err != nil {
		return Record{}, err
	}
	var result Record
	err = m.store.WithLock(lockRelative(name), func() error {
		record, err := m.readMetadata(name)
		if err != nil {
			return err
		}
		if record.Status == RevokedStatus {
			return ErrRevoked
		}
		if record.HostKey == canonical {
			if err := m.writeKnownHosts(record); err != nil {
				return err
			}
			result = record
			return nil
		}
		record.PreviousHostKeyFingerprint = record.HostKeyFingerprint
		record.HostKey = canonical
		record.HostKeyFingerprint = fingerprint
		record.UpdatedAt = m.now().UTC()
		if err := m.writeKnownHosts(record); err != nil {
			return err
		}
		if err := m.store.WriteJSON(metadataRelative(name), record); err != nil {
			return fmt.Errorf("write rotated host key metadata: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

// Revoke prevents future SSH argument construction while retaining trust data
// for audit and recovery.
func (m *Manager) Revoke(name string) (Record, error) {
	if err := validateName(name); err != nil {
		return Record{}, err
	}
	var result Record
	err := m.store.WithLock(lockRelative(name), func() error {
		record, err := m.getUnlocked(name)
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
		record.UpdatedAt = now
		if err := m.store.WriteJSON(metadataRelative(name), record); err != nil {
			return fmt.Errorf("revoke instance: %w", err)
		}
		result = record
		return nil
	})
	return result, err
}

func (m *Manager) Get(name string) (Record, error) {
	if err := validateName(name); err != nil {
		return Record{}, err
	}
	return m.getUnlocked(name)
}

// List returns validated records sorted by instance name.
func (m *Manager) List() ([]Record, error) {
	directory, err := m.store.EnsureDir("instances")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrInvalidInstance, entry.Name())
		}
		record, err := m.Get(entry.Name())
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, nil
}

// SSHArgs returns hardened OpenSSH arguments containing only the active
// identity. offering an older private generation is never the safe default:
// callers must prove that the instance is in its signed rotation-overlap
// window and then opt in through SSHArgsWithPrevious.
func (m *Manager) SSHArgs(name string) ([]string, error) {
	return m.sshArgs(name, false)
}

// SSHArgsWithPrevious additionally offers the cryptographically linked
// immediately preceding identity. this is only for a locally verified
// desired-state overlap window; it must stop as soon as old-key removal is
// published.
func (m *Manager) SSHArgsWithPrevious(name string) ([]string, error) {
	return m.sshArgs(name, true)
}

func (m *Manager) sshArgs(name string, includePrevious bool) ([]string, error) {
	record, err := m.Get(name)
	if err != nil {
		return nil, err
	}
	if record.Status != ActiveStatus {
		return nil, ErrRevoked
	}
	if m.keys == nil {
		return nil, fmt.Errorf("%w: SSH key manager is required", ErrInvalidInstance)
	}
	_, paths, err := m.keys.Active(record.Key.Scope, record.Key.Name)
	if err != nil {
		return nil, fmt.Errorf("resolve SSH identity: %w", err)
	}
	identityPaths := []string{paths.Private}
	if includePrevious {
		if _, previousPaths, previousErr := m.keys.Previous(record.Key.Scope, record.Key.Name); previousErr == nil {
			identityPaths = append(identityPaths, previousPaths.Private)
		} else if !errors.Is(previousErr, sshkeys.ErrNotFound) {
			return nil, fmt.Errorf("resolve previous SSH identity: %w", previousErr)
		}
	}
	knownHosts, err := m.store.Path(knownHostsRelative(name))
	if err != nil {
		return nil, err
	}
	options := []string{
		"BatchMode=yes",
		"IdentitiesOnly=yes",
		"IdentityAgent=none",
		"StrictHostKeyChecking=yes",
		"UpdateHostKeys=no",
		"VerifyHostKeyDNS=no",
		"CheckHostIP=no",
		"UserKnownHostsFile=" + knownHosts,
		"GlobalKnownHostsFile=/dev/null",
		"HostKeyAlgorithms=ssh-ed25519",
		"PubkeyAcceptedAlgorithms=ssh-ed25519",
		"PasswordAuthentication=no",
		"KbdInteractiveAuthentication=no",
		"ChallengeResponseAuthentication=no",
		"PreferredAuthentications=publickey",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ClearAllForwardings=yes",
		"PermitLocalCommand=no",
		"CanonicalizeHostname=no",
		"ConnectTimeout=15",
		"ConnectionAttempts=1",
		"ServerAliveInterval=15",
		"ServerAliveCountMax=2",
	}
	args := []string{"-F", "none", "-S", "none"}
	for _, option := range options {
		args = append(args, "-o", option)
	}
	for _, identityPath := range identityPaths {
		args = append(args, "-i", identityPath)
	}
	args = append(args,
		"-p", strconv.Itoa(record.SSHPort),
		"-l", record.SSHUser,
		record.Host,
	)
	return args, nil
}

func (m *Manager) normalizeInput(input Record) (Record, error) {
	if err := validateName(input.Name); err != nil {
		return Record{}, err
	}
	if !profileName.MatchString(input.Profile) {
		return Record{}, fmt.Errorf("%w: invalid profile %q", ErrInvalidInstance, input.Profile)
	}
	host, err := normalizeHost(input.Host)
	if err != nil {
		return Record{}, err
	}
	port := input.SSHPort
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return Record{}, fmt.Errorf("%w: invalid SSH port %d", ErrInvalidInstance, port)
	}
	if !sshUser.MatchString(input.SSHUser) {
		return Record{}, fmt.Errorf("%w: invalid SSH user %q", ErrInvalidInstance, input.SSHUser)
	}
	if input.Key.Scope != sshkeys.Operator && input.Key.Scope != sshkeys.Instance {
		return Record{}, fmt.Errorf("%w: invalid SSH key scope %q", ErrInvalidInstance, input.Key.Scope)
	}
	if !instanceName.MatchString(input.Key.Name) {
		return Record{}, fmt.Errorf("%w: invalid SSH key name %q", ErrInvalidInstance, input.Key.Name)
	}
	hostKey, fingerprint, err := normalizeHostKey(input.HostKey)
	if err != nil {
		return Record{}, err
	}
	return Record{
		SchemaVersion:      SchemaVersion,
		Name:               input.Name,
		Profile:            input.Profile,
		Host:               host,
		SSHPort:            port,
		SSHUser:            input.SSHUser,
		Key:                input.Key,
		HostKey:            hostKey,
		HostKeyFingerprint: fingerprint,
		Status:             ActiveStatus,
	}, nil
}

// ValidateEndpoint validates and canonicalizes the operator-supplied SSH
// destination without contacting it. Host-key trust is established separately
// from the authenticated instance status; ssh-keyscan is never used.
func ValidateEndpoint(host, user string, port int) (string, error) {
	normalized, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	if !sshUser.MatchString(user) || port < 1 || port > 65535 {
		return "", fmt.Errorf("%w: invalid SSH endpoint", ErrInvalidInstance)
	}
	return normalized, nil
}

func (m *Manager) getUnlocked(name string) (Record, error) {
	record, err := m.readMetadata(name)
	if err != nil {
		return Record{}, err
	}
	expected := knownHostsLine(record)
	actual, err := m.store.ReadFile(knownHostsRelative(name))
	if err != nil {
		return Record{}, fmt.Errorf("read pinned known_hosts: %w", err)
	}
	if string(actual) != expected {
		return Record{}, fmt.Errorf("%w: pinned known_hosts differs from instance metadata", ErrInvalidInstance)
	}
	return record, nil
}

func (m *Manager) readMetadata(name string) (Record, error) {
	var record Record
	if err := m.store.ReadJSON(metadataRelative(name), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	if err := validateRecord(record, name); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (m *Manager) writeKnownHosts(record Record) error {
	if err := m.store.WriteFile(knownHostsRelative(record.Name), []byte(knownHostsLine(record))); err != nil {
		return fmt.Errorf("write pinned known_hosts: %w", err)
	}
	return nil
}

func validateRecord(record Record, expectedName string) error {
	if record.SchemaVersion != SchemaVersion || record.Name != expectedName {
		return fmt.Errorf("%w: metadata identity mismatch", ErrInvalidInstance)
	}
	if err := validateName(record.Name); err != nil {
		return err
	}
	if !profileName.MatchString(record.Profile) || !sshUser.MatchString(record.SSHUser) || record.SSHPort < 1 || record.SSHPort > 65535 {
		return fmt.Errorf("%w: malformed metadata", ErrInvalidInstance)
	}
	host, err := normalizeHost(record.Host)
	if err != nil || host != record.Host {
		return fmt.Errorf("%w: malformed host", ErrInvalidInstance)
	}
	if record.Key.Scope != sshkeys.Operator && record.Key.Scope != sshkeys.Instance || !instanceName.MatchString(record.Key.Name) {
		return fmt.Errorf("%w: malformed key reference", ErrInvalidInstance)
	}
	publicKey, fingerprint, err := normalizeHostKey(record.HostKey)
	if err != nil || publicKey != record.HostKey || fingerprint != record.HostKeyFingerprint {
		return fmt.Errorf("%w: host key metadata mismatch", ErrInvalidInstance)
	}
	if record.Status != ActiveStatus && record.Status != RevokedStatus {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidInstance, record.Status)
	}
	if record.Status == ActiveStatus && record.RevokedAt != nil || record.Status == RevokedStatus && record.RevokedAt == nil {
		return fmt.Errorf("%w: inconsistent revocation metadata", ErrInvalidInstance)
	}
	if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: missing timestamps", ErrInvalidInstance)
	}
	return nil
}

func validateName(name string) error {
	if !instanceName.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidInstance, name)
	}
	return nil
}

func normalizeHost(host string) (string, error) {
	if host == "" || host != strings.TrimSpace(host) || len(host) > 253 || strings.ContainsAny(host, " /\\@%[]\t\r\n") || strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("%w: invalid host %q", ErrInvalidInstance, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("%w: host must not have a trailing dot", ErrInvalidInstance)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: invalid DNS host %q", ErrInvalidInstance, host)
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return "", fmt.Errorf("%w: invalid DNS host %q", ErrInvalidInstance, host)
			}
		}
	}
	return strings.ToLower(host), nil
}

func normalizeHostKey(publicKey string) (string, string, error) {
	normalized, fingerprint, err := sshkeys.ValidateEd25519PublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidInstance, err)
	}
	fields := strings.Fields(normalized)
	return strings.Join(fields[:2], " "), fingerprint, nil
}

func knownHostsLine(record Record) string {
	host := record.Host
	if record.SSHPort != 22 {
		host = "[" + host + "]:" + strconv.Itoa(record.SSHPort)
	}
	return host + " " + record.HostKey + "\n"
}

func baseRelative(name string) string       { return filepath.Join("instances", name) }
func lockRelative(name string) string       { return filepath.Join(baseRelative(name), ".lock") }
func metadataRelative(name string) string   { return filepath.Join(baseRelative(name), "instance.json") }
func knownHostsRelative(name string) string { return filepath.Join(baseRelative(name), "known_hosts") }
