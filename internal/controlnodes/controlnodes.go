// Package controlnodes persists the operator-local binding for a system's
// control node. It validates trust material but deliberately never opens a
// network connection or executes an SSH client.
package controlnodes

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dynamicflow/internal/instances"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

const SchemaVersion = 2

var (
	ErrInvalidManager        = errors.New("invalid control-node manager")
	ErrInvalidControlNode    = errors.New("invalid control node")
	ErrNotFound              = errors.New("control node not found")
	ErrBindingConflict       = errors.New("control-node binding conflict")
	ErrBootstrapKeyMismatch  = errors.New("bootstrap SSH key binding mismatch")
	ErrManagementKeyMismatch = errors.New("Control management SSH key binding mismatch")
	ErrPendingAccessConflict = errors.New("pending Control access identity conflict")
	ErrNoPendingAccess       = errors.New("no pending Control access identity")
	ErrActivationProof       = errors.New("Control access activation proof is incomplete")
	ErrBootstrapRevocation   = errors.New("bootstrap SSH key revocation is not verified")
	ErrKnownHostsMismatch    = errors.New("pinned known_hosts mismatch")
	ErrRevisionConflict      = errors.New("control-node revision conflict")
	ErrInvalidTransition     = errors.New("invalid control-node lifecycle transition")
	ErrRevoked               = errors.New("control node is revoked")

	systemIDRE = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	nodeNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	keyNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sshUserRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

const ManagementAccessUser = "dynamicflow-control"

// ValidName reports the name grammar shared by Control records, signed policy
// and their fixed SSH command bindings. Bootstrap must use it before keygen.
func ValidName(name string) bool { return nodeNameRE.MatchString(name) }

// OperatingSystem identifies the narrowly supported control-node base image.
type OperatingSystem string

const (
	OSDebian13   OperatingSystem = "debian-13"
	OSUbuntu2404 OperatingSystem = "ubuntu-24.04"
)

// EvidenceSource records the independent channel through which the initial
// SSH host public key was authenticated. A network observation is not valid
// evidence and is intentionally absent from this enum.
type EvidenceSource string

const (
	EvidenceProviderConsole     EvidenceSource = "provider-console"
	EvidenceProviderAttestation EvidenceSource = "provider-attestation"
)

// Lifecycle is monotonic. Revoked is a terminal fail-closed state reachable
// from every other state.
type Lifecycle string

const (
	LifecycleBound                Lifecycle = "bound"
	LifecycleConnectivityVerified Lifecycle = "connectivity_verified"
	LifecycleInstalling           Lifecycle = "installing"
	LifecycleReady                Lifecycle = "ready"
	LifecycleRevoked              Lifecycle = "revoked"
)

// AccessPhase identifies which exact owner-local identity is authoritative.
// Staged never changes the active Bootstrap identity.
type AccessPhase string

const (
	AccessBootstrap  AccessPhase = "bootstrap"
	AccessStaged     AccessPhase = "staged"
	AccessManagement AccessPhase = "management"
)

// AccessKeyRef pins one exact public SSH-key generation. It contains no path
// or private key bytes.
type AccessKeyRef struct {
	Scope       sshkeys.Scope `json:"scope"`
	Name        string        `json:"name"`
	Generation  uint64        `json:"generation"`
	Fingerprint string        `json:"fingerprint"`
}

// BootstrapKeyRef remains the explicit immutable bootstrap-evidence type used
// by the binding API.
type BootstrapKeyRef = AccessKeyRef

// AccessState is comparable and contains public audit metadata only. Stage
// fills Pending without changing Active; Activate clears Pending atomically.
type AccessState struct {
	Phase                         AccessPhase  `json:"phase"`
	Active                        AccessKeyRef `json:"active"`
	ActiveAccessUser              string       `json:"active_access_user"`
	Pending                       AccessKeyRef `json:"pending"`
	PendingAccessUser             string       `json:"pending_access_user"`
	ManagementProofVerifiedAt     time.Time    `json:"management_proof_verified_at"`
	BootstrapRevocationVerifiedAt time.Time    `json:"bootstrap_revocation_verified_at"`
}

// ActivationConfirmation is supplied only after an external connection with
// PendingAccessMaterial proved the exact management key and independently
// confirmed removal of bootstrap authorization on the Control node.
type ActivationConfirmation struct {
	ControlKey                  AccessKeyRef
	AccessUser                  string
	ManagementProofVerified     bool
	BootstrapRevocationVerified bool
}

// BindInput is the complete immutable trust-boundary input for a control node.
// Port zero is normalized to the OpenSSH default, 22.
type BindInput struct {
	SystemID        string
	Name            string
	Host            string
	Port            int
	SSHUser         string
	OperatingSystem OperatingSystem
	BootstrapKey    BootstrapKeyRef
	HostPublicKey   string
	EvidenceSource  EvidenceSource
}

// Record contains only public, bounded metadata. HostPublicKey is the complete
// normalized Ed25519 public-key line supplied through the evidence source.
type Record struct {
	SchemaVersion   int             `json:"schema_version"`
	SystemID        string          `json:"system_id"`
	Name            string          `json:"name"`
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	SSHUser         string          `json:"ssh_user"`
	OperatingSystem OperatingSystem `json:"operating_system"`
	BootstrapKey    BootstrapKeyRef `json:"bootstrap_key"`
	Access          AccessState     `json:"access"`
	HostPublicKey   string          `json:"host_public_key"`
	HostFingerprint string          `json:"host_fingerprint"`
	EvidenceSource  EvidenceSource  `json:"evidence_source"`
	Lifecycle       Lifecycle       `json:"lifecycle"`
	Revision        uint64          `json:"revision"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	RevokedAt       *time.Time      `json:"revoked_at,omitempty"`
}

// AccessMaterial is safe to serialize: operator-local paths that expose the
// private identity location and pinned known_hosts file are explicitly
// excluded from JSON.
type AccessMaterial struct {
	SystemID        string       `json:"system_id"`
	Name            string       `json:"name"`
	Host            string       `json:"host"`
	Port            int          `json:"port"`
	SSHUser         string       `json:"ssh_user"`
	HostFingerprint string       `json:"host_fingerprint"`
	Identity        AccessKeyRef `json:"identity"`
	IdentityPath    string       `json:"-"`
	KnownHostsPath  string       `json:"-"`
}

type Option func(*Manager)

// WithClock injects the clock used for revisions in deterministic tests.
func WithClock(clock func() time.Time) Option {
	return func(manager *Manager) {
		if clock != nil {
			manager.now = clock
		}
	}
}

// Manager owns control bindings in the root local state while resolving the
// corresponding system-local Bootstrap and Control identities through keys.
type Manager struct {
	store *localstate.Store
	keys  *sshkeys.Manager
	now   func() time.Time
}

// NewManager creates a local-only manager. It does not inspect an endpoint or
// perform any network operation.
func NewManager(store *localstate.Store, keys *sshkeys.Manager, options ...Option) (*Manager, error) {
	if store == nil || keys == nil {
		return nil, ErrInvalidManager
	}
	manager := &Manager{store: store, keys: keys, now: time.Now}
	for _, option := range options {
		if option != nil {
			option(manager)
		}
	}
	if manager.now == nil {
		return nil, ErrInvalidManager
	}
	return manager, nil
}

// Bind creates an immutable system-local endpoint and host-trust binding. An
// exact repeat is an idempotent read; any changed immutable value fails closed.
func (manager *Manager) Bind(input BindInput) (result Record, created bool, err error) {
	normalized, err := manager.normalizeBindInput(input)
	if err != nil {
		return Record{}, false, err
	}
	err = manager.store.WithLock(lockRelative(normalized.SystemID, normalized.Name), func() error {
		existing, getErr := manager.getUnlocked(normalized.SystemID, normalized.Name)
		switch {
		case getErr == nil:
			if !sameBinding(existing, normalized) {
				return ErrBindingConflict
			}
			if existing.Lifecycle == LifecycleRevoked {
				return ErrRevoked
			}
			result = existing
			return nil
		case !errors.Is(getErr, ErrNotFound):
			return getErr
		}
		if _, _, err := manager.resolveBootstrapKey(normalized.SystemID, normalized.BootstrapKey); err != nil {
			return err
		}

		now, clockErr := manager.currentTime(time.Time{})
		if clockErr != nil {
			return clockErr
		}
		record := Record{
			SchemaVersion:   SchemaVersion,
			SystemID:        normalized.SystemID,
			Name:            normalized.Name,
			Host:            normalized.Host,
			Port:            normalized.Port,
			SSHUser:         normalized.SSHUser,
			OperatingSystem: normalized.OperatingSystem,
			BootstrapKey:    normalized.BootstrapKey,
			Access: AccessState{
				Phase: AccessBootstrap, Active: AccessKeyRef(normalized.BootstrapKey),
				ActiveAccessUser: normalized.SSHUser,
			},
			HostPublicKey:   normalized.HostPublicKey,
			HostFingerprint: normalized.HostFingerprint,
			EvidenceSource:  normalized.EvidenceSource,
			Lifecycle:       LifecycleBound,
			Revision:        1,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := validateRecord(record, normalized.SystemID, normalized.Name); err != nil {
			return err
		}
		if err := manager.writeKnownHosts(record); err != nil {
			return err
		}
		if err := manager.store.WriteJSON(metadataRelative(record.SystemID, record.Name), record); err != nil {
			return fmt.Errorf("write control-node metadata: %w", err)
		}
		result = record
		created = true
		return nil
	})
	return result, created, err
}

// Get returns a validated record only when its private mode-0600 known_hosts
// file exactly matches the immutable host trust in metadata.
func (manager *Manager) Get(systemID, name string) (Record, error) {
	if err := validateIdentity(systemID, name); err != nil {
		return Record{}, err
	}
	return manager.getUnlocked(systemID, name)
}

// List returns one system's validated control nodes sorted by name.
func (manager *Manager) List(systemID string) ([]Record, error) {
	if !systemIDRE.MatchString(systemID) {
		return nil, ErrInvalidControlNode
	}
	directory, err := manager.store.Path(controlsRelative(systemID))
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return []Record{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect control-node directory: %w", err)
	}
	// EnsureDir is also the localstate directory validator. The existence check
	// above keeps this read-only path from creating an absent directory.
	directory, err = manager.store.EnsureDir(controlsRelative(systemID))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("list control nodes: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !nodeNameRE.MatchString(entry.Name()) {
			return nil, fmt.Errorf("%w: unexpected control-node entry %q", ErrInvalidControlNode, entry.Name())
		}
		record, err := manager.Get(systemID, entry.Name())
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Name < records[right].Name })
	return records, nil
}

// Transition compare-and-swaps one strictly forward lifecycle step. Revocation
// is an explicit terminal transition available from every non-revoked state.
func (manager *Manager) Transition(systemID, name string, expectedRevision uint64, next Lifecycle) (result Record, err error) {
	if err := validateIdentity(systemID, name); err != nil || expectedRevision == 0 {
		return Record{}, ErrInvalidControlNode
	}
	err = manager.store.WithLock(lockRelative(systemID, name), func() error {
		current, getErr := manager.getUnlocked(systemID, name)
		if getErr != nil {
			return getErr
		}
		if current.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if !validTransition(current.Lifecycle, next) {
			if current.Lifecycle == LifecycleRevoked {
				return ErrRevoked
			}
			return ErrInvalidTransition
		}
		if next == LifecycleReady && current.Access.Phase != AccessManagement {
			return ErrBootstrapRevocation
		}
		if next != LifecycleRevoked {
			if _, _, keyErr := manager.resolveActiveAccessKey(current); keyErr != nil {
				return keyErr
			}
		}
		if current.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		now, clockErr := manager.currentTime(current.UpdatedAt)
		if clockErr != nil {
			return clockErr
		}
		current.Lifecycle = next
		current.Revision++
		current.UpdatedAt = now
		if next == LifecycleRevoked {
			revokedAt := now
			current.RevokedAt = &revokedAt
		}
		if err := validateRecord(current, systemID, name); err != nil {
			return err
		}
		if err := manager.store.WriteJSON(metadataRelative(systemID, name), current); err != nil {
			return fmt.Errorf("write control-node transition: %w", err)
		}
		result = current
		return nil
	})
	return result, err
}

// Stage compare-and-swaps an exact active sshkeys.Control generation into the
// pending slot with the dedicated access user. The authoritative Access pair
// remains Bootstrap. Replaying the same pair is an idempotent read; a different
// pending key or user conflicts.
func (manager *Manager) Stage(systemID, name string, expectedRevision uint64, controlKey AccessKeyRef, accessUser string) (result Record, staged bool, err error) {
	if err := validateIdentity(systemID, name); err != nil || expectedRevision == 0 ||
		!validAccessKeyRef(controlKey, sshkeys.Control) || !validAccessUser(accessUser) {
		return Record{}, false, ErrInvalidControlNode
	}
	err = manager.store.WithLock(lockRelative(systemID, name), func() error {
		current, getErr := manager.getUnlocked(systemID, name)
		if getErr != nil {
			return getErr
		}
		if current.Lifecycle == LifecycleRevoked {
			return ErrRevoked
		}
		switch current.Access.Phase {
		case AccessManagement:
			if current.Access.Active != controlKey || current.Access.ActiveAccessUser != accessUser {
				return ErrPendingAccessConflict
			}
			if _, _, keyErr := manager.resolveActiveAccessKey(current); keyErr != nil {
				return keyErr
			}
			result = current
			return nil
		case AccessStaged:
			if current.Access.Pending != controlKey || current.Access.PendingAccessUser != accessUser {
				return ErrPendingAccessConflict
			}
			if _, _, keyErr := manager.resolveManagementKey(systemID, controlKey); keyErr != nil {
				return keyErr
			}
			result = current
			return nil
		case AccessBootstrap:
		default:
			return ErrInvalidControlNode
		}
		if current.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if accessUser != ManagementAccessUser || accessUser == current.SSHUser {
			return ErrInvalidControlNode
		}
		if controlKey.Fingerprint == current.BootstrapKey.Fingerprint {
			return ErrManagementKeyMismatch
		}
		if _, _, keyErr := manager.resolveActiveAccessKey(current); keyErr != nil {
			return keyErr
		}
		if _, _, keyErr := manager.resolveManagementKey(systemID, controlKey); keyErr != nil {
			return keyErr
		}
		if current.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		now, clockErr := manager.currentTime(current.UpdatedAt)
		if clockErr != nil {
			return clockErr
		}
		current.Access.Phase = AccessStaged
		current.Access.Pending = controlKey
		current.Access.PendingAccessUser = accessUser
		current.Revision++
		current.UpdatedAt = now
		if err := validateRecord(current, systemID, name); err != nil {
			return err
		}
		if err := manager.store.WriteJSON(metadataRelative(systemID, name), current); err != nil {
			return fmt.Errorf("stage Control access identity: %w", err)
		}
		result = current
		staged = true
		return nil
	})
	return result, staged, err
}

// Activate atomically switches Access from Bootstrap to the exact staged
// Control identity only after external proof, explicit target-side bootstrap
// revocation confirmation and matching local bootstrap revocation. No previous
// identity fallback is retained.
func (manager *Manager) Activate(systemID, name string, expectedRevision uint64, confirmation ActivationConfirmation) (result Record, activated bool, err error) {
	if err := validateIdentity(systemID, name); err != nil || expectedRevision == 0 ||
		!validAccessKeyRef(confirmation.ControlKey, sshkeys.Control) ||
		!validAccessUser(confirmation.AccessUser) {
		return Record{}, false, ErrInvalidControlNode
	}
	if !confirmation.ManagementProofVerified || !confirmation.BootstrapRevocationVerified {
		return Record{}, false, ErrActivationProof
	}
	err = manager.store.WithLock(lockRelative(systemID, name), func() error {
		current, getErr := manager.getUnlocked(systemID, name)
		if getErr != nil {
			return getErr
		}
		if current.Lifecycle == LifecycleRevoked {
			return ErrRevoked
		}
		if current.Access.Phase == AccessManagement {
			if current.Access.Active != confirmation.ControlKey ||
				current.Access.ActiveAccessUser != confirmation.AccessUser {
				return ErrPendingAccessConflict
			}
			if _, _, keyErr := manager.resolveManagementKey(systemID, confirmation.ControlKey); keyErr != nil {
				return keyErr
			}
			if keyErr := manager.verifyRevokedBootstrap(current); keyErr != nil {
				return keyErr
			}
			result = current
			return nil
		}
		if current.Access.Phase != AccessStaged || isZeroKeyRef(current.Access.Pending) {
			return ErrNoPendingAccess
		}
		if current.Access.Pending != confirmation.ControlKey ||
			current.Access.PendingAccessUser != confirmation.AccessUser {
			return ErrPendingAccessConflict
		}
		if current.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if _, _, keyErr := manager.resolveManagementKey(systemID, confirmation.ControlKey); keyErr != nil {
			return keyErr
		}
		if keyErr := manager.verifyRevokedBootstrap(current); keyErr != nil {
			return keyErr
		}
		if current.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		now, clockErr := manager.currentTime(current.UpdatedAt)
		if clockErr != nil {
			return clockErr
		}
		current.Access.Phase = AccessManagement
		current.Access.Active = confirmation.ControlKey
		current.Access.ActiveAccessUser = current.Access.PendingAccessUser
		current.Access.Pending = AccessKeyRef{}
		current.Access.PendingAccessUser = ""
		current.Access.ManagementProofVerifiedAt = now
		current.Access.BootstrapRevocationVerifiedAt = now
		current.Revision++
		current.UpdatedAt = now
		if err := validateRecord(current, systemID, name); err != nil {
			return err
		}
		if err := manager.store.WriteJSON(metadataRelative(systemID, name), current); err != nil {
			return fmt.Errorf("activate Control access identity: %w", err)
		}
		result = current
		activated = true
		return nil
	})
	return result, activated, err
}

// AccessMaterial resolves exactly the authoritative access identity. Stage
// leaves this strictly on Bootstrap; activation switches it strictly to the
// management key with no previous-key fallback.
func (manager *Manager) AccessMaterial(systemID, name string) (AccessMaterial, error) {
	record, err := manager.Get(systemID, name)
	if err != nil {
		return AccessMaterial{}, err
	}
	if record.Lifecycle == LifecycleRevoked {
		return AccessMaterial{}, ErrRevoked
	}
	_, paths, err := manager.resolveActiveAccessKey(record)
	if err != nil {
		return AccessMaterial{}, err
	}
	knownHosts, err := manager.store.Path(knownHostsRelative(systemID, name))
	if err != nil {
		return AccessMaterial{}, err
	}
	return AccessMaterial{
		SystemID: record.SystemID, Name: record.Name, Host: record.Host, Port: record.Port,
		SSHUser: record.Access.ActiveAccessUser, HostFingerprint: record.HostFingerprint,
		Identity: record.Access.Active, IdentityPath: paths.Private, KnownHostsPath: knownHosts,
	}, nil
}

// PendingAccessMaterial resolves only the exact staged Control identity for a
// later explicit proof connection. It never falls back to the active Bootstrap
// identity and is unavailable before Stage or after Activate.
func (manager *Manager) PendingAccessMaterial(systemID, name string) (AccessMaterial, error) {
	record, err := manager.Get(systemID, name)
	if err != nil {
		return AccessMaterial{}, err
	}
	if record.Lifecycle == LifecycleRevoked {
		return AccessMaterial{}, ErrRevoked
	}
	if record.Access.Phase != AccessStaged || isZeroKeyRef(record.Access.Pending) {
		return AccessMaterial{}, ErrNoPendingAccess
	}
	_, paths, err := manager.resolveManagementKey(record.SystemID, record.Access.Pending)
	if err != nil {
		return AccessMaterial{}, err
	}
	knownHosts, err := manager.store.Path(knownHostsRelative(systemID, name))
	if err != nil {
		return AccessMaterial{}, err
	}
	return AccessMaterial{
		SystemID: record.SystemID, Name: record.Name, Host: record.Host, Port: record.Port,
		SSHUser: record.Access.PendingAccessUser, HostFingerprint: record.HostFingerprint,
		Identity: record.Access.Pending, IdentityPath: paths.Private, KnownHostsPath: knownHosts,
	}, nil
}

type normalizedBinding struct {
	SystemID        string
	Name            string
	Host            string
	Port            int
	SSHUser         string
	OperatingSystem OperatingSystem
	BootstrapKey    BootstrapKeyRef
	HostPublicKey   string
	HostFingerprint string
	EvidenceSource  EvidenceSource
}

func (manager *Manager) normalizeBindInput(input BindInput) (normalizedBinding, error) {
	if err := validateIdentity(input.SystemID, input.Name); err != nil {
		return normalizedBinding{}, err
	}
	port := input.Port
	if port == 0 {
		port = 22
	}
	host, err := instances.ValidateEndpoint(input.Host, input.SSHUser, port)
	if err != nil || input.SSHUser == "root" || input.SSHUser == ManagementAccessUser {
		return normalizedBinding{}, fmt.Errorf("%w: unsafe SSH endpoint", ErrInvalidControlNode)
	}
	if !validOperatingSystem(input.OperatingSystem) || !validEvidenceSource(input.EvidenceSource) {
		return normalizedBinding{}, ErrInvalidControlNode
	}
	hostPublicKey, hostFingerprint, err := sshkeys.ValidateEd25519PublicKey(input.HostPublicKey)
	if err != nil {
		return normalizedBinding{}, fmt.Errorf("%w: invalid Ed25519 host key", ErrInvalidControlNode)
	}
	return normalizedBinding{
		SystemID: input.SystemID, Name: input.Name, Host: host, Port: port, SSHUser: input.SSHUser,
		OperatingSystem: input.OperatingSystem, BootstrapKey: input.BootstrapKey,
		HostPublicKey: hostPublicKey, HostFingerprint: hostFingerprint, EvidenceSource: input.EvidenceSource,
	}, nil
}

func (manager *Manager) resolveBootstrapKey(systemID string, reference BootstrapKeyRef) (sshkeys.Record, sshkeys.Paths, error) {
	return manager.resolveAccessKey(systemID, reference, sshkeys.Bootstrap, ErrBootstrapKeyMismatch)
}

func (manager *Manager) resolveManagementKey(systemID string, reference AccessKeyRef) (sshkeys.Record, sshkeys.Paths, error) {
	return manager.resolveAccessKey(systemID, reference, sshkeys.Control, ErrManagementKeyMismatch)
}

func (manager *Manager) resolveAccessKey(systemID string, reference AccessKeyRef, scope sshkeys.Scope, mismatch error) (sshkeys.Record, sshkeys.Paths, error) {
	if !validAccessKeyRef(reference, scope) {
		return sshkeys.Record{}, sshkeys.Paths{}, mismatch
	}
	record, paths, err := manager.keys.Active(reference.Scope, reference.Name)
	if err != nil {
		return sshkeys.Record{}, sshkeys.Paths{}, fmt.Errorf("%w: %v", mismatch, err)
	}
	if !keyMatchesReference(record, reference) {
		return sshkeys.Record{}, sshkeys.Paths{}, mismatch
	}
	if !manager.pathsBelongToSystem(systemID, paths) {
		return sshkeys.Record{}, sshkeys.Paths{}, fmt.Errorf("%w: identity is outside the selected system", mismatch)
	}
	return record, paths, nil
}

func (manager *Manager) resolveActiveAccessKey(record Record) (sshkeys.Record, sshkeys.Paths, error) {
	switch record.Access.Active.Scope {
	case sshkeys.Bootstrap:
		return manager.resolveBootstrapKey(record.SystemID, record.Access.Active)
	case sshkeys.Control:
		if err := manager.verifyRevokedBootstrap(record); err != nil {
			return sshkeys.Record{}, sshkeys.Paths{}, err
		}
		return manager.resolveManagementKey(record.SystemID, record.Access.Active)
	default:
		return sshkeys.Record{}, sshkeys.Paths{}, ErrInvalidControlNode
	}
}

func (manager *Manager) verifyRevokedBootstrap(record Record) error {
	if !validAccessKeyRef(record.BootstrapKey, sshkeys.Bootstrap) {
		return ErrBootstrapRevocation
	}
	current, paths, err := manager.keys.Current(sshkeys.Bootstrap, record.BootstrapKey.Name)
	if err != nil || current.Status != sshkeys.RevokedStatus || !keyMatchesReference(current, record.BootstrapKey) ||
		!manager.pathsBelongToSystem(record.SystemID, paths) {
		return fmt.Errorf("%w: exact local bootstrap identity remains active or mismatched", ErrBootstrapRevocation)
	}
	return nil
}

func (manager *Manager) pathsBelongToSystem(systemID string, paths sshkeys.Paths) bool {
	systemRoot, err := manager.store.Path(filepath.Join("systems", systemID))
	return err == nil && pathWithin(systemRoot, paths.Private) && pathWithin(systemRoot, paths.Public)
}

func keyMatchesReference(record sshkeys.Record, reference AccessKeyRef) bool {
	return record.Scope == reference.Scope && record.Name == reference.Name &&
		record.Generation == reference.Generation && record.Fingerprint == reference.Fingerprint
}

func validAccessKeyRef(reference AccessKeyRef, scope sshkeys.Scope) bool {
	return reference.Scope == scope && keyNameRE.MatchString(reference.Name) &&
		reference.Generation > 0 && validFingerprint(reference.Fingerprint)
}

func isZeroKeyRef(reference AccessKeyRef) bool {
	return reference == (AccessKeyRef{})
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && relative != ".." && !filepath.IsAbs(relative) &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (manager *Manager) getUnlocked(systemID, name string) (Record, error) {
	record, err := manager.readMetadata(systemID, name)
	if err != nil {
		return Record{}, err
	}
	expected := knownHostsLine(record)
	actual, err := manager.store.ReadFile(knownHostsRelative(systemID, name))
	if err != nil {
		return Record{}, fmt.Errorf("%w: read pinned known_hosts: %v", ErrKnownHostsMismatch, err)
	}
	if string(actual) != expected {
		return Record{}, ErrKnownHostsMismatch
	}
	return cloneRecord(record), nil
}

func (manager *Manager) readMetadata(systemID, name string) (Record, error) {
	var record Record
	if err := manager.store.ReadJSON(metadataRelative(systemID, name), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("%w: read metadata: %v", ErrInvalidControlNode, err)
	}
	if err := validateRecord(record, systemID, name); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (manager *Manager) writeKnownHosts(record Record) error {
	if err := manager.store.WriteFile(knownHostsRelative(record.SystemID, record.Name), []byte(knownHostsLine(record))); err != nil {
		return fmt.Errorf("write pinned known_hosts: %w", err)
	}
	return nil
}

func validateRecord(record Record, expectedSystemID, expectedName string) error {
	if record.SchemaVersion != SchemaVersion || record.SystemID != expectedSystemID || record.Name != expectedName ||
		record.Revision == 0 || !systemIDRE.MatchString(record.SystemID) || !nodeNameRE.MatchString(record.Name) ||
		record.SSHUser == "root" || record.SSHUser == ManagementAccessUser ||
		!validOperatingSystem(record.OperatingSystem) ||
		!validEvidenceSource(record.EvidenceSource) || !validLifecycle(record.Lifecycle) {
		return ErrInvalidControlNode
	}
	host, err := instances.ValidateEndpoint(record.Host, record.SSHUser, record.Port)
	if err != nil || host != record.Host {
		return fmt.Errorf("%w: non-canonical endpoint", ErrInvalidControlNode)
	}
	if !validAccessKeyRef(record.BootstrapKey, sshkeys.Bootstrap) {
		return fmt.Errorf("%w: invalid bootstrap key reference", ErrInvalidControlNode)
	}
	hostPublicKey, fingerprint, err := sshkeys.ValidateEd25519PublicKey(record.HostPublicKey)
	if err != nil || hostPublicKey != record.HostPublicKey || fingerprint != record.HostFingerprint {
		return fmt.Errorf("%w: host-key metadata mismatch", ErrInvalidControlNode)
	}
	if !validTimestamp(record.CreatedAt) || !validTimestamp(record.UpdatedAt) ||
		record.UpdatedAt.Before(record.CreatedAt) {
		return fmt.Errorf("%w: invalid timestamps", ErrInvalidControlNode)
	}
	if err := validateAccessState(record); err != nil {
		return err
	}
	if record.Lifecycle == LifecycleRevoked {
		if record.RevokedAt == nil || !validTimestamp(*record.RevokedAt) ||
			record.RevokedAt.Before(record.CreatedAt) || !record.RevokedAt.Equal(record.UpdatedAt) {
			return fmt.Errorf("%w: invalid revocation metadata", ErrInvalidControlNode)
		}
	} else if record.RevokedAt != nil {
		return fmt.Errorf("%w: revocation metadata on active lifecycle", ErrInvalidControlNode)
	}
	if record.Lifecycle == LifecycleReady && record.Access.Phase != AccessManagement {
		return fmt.Errorf("%w: ready lifecycle requires verified management access", ErrInvalidControlNode)
	}
	return nil
}

func validateAccessState(record Record) error {
	bootstrap := AccessKeyRef(record.BootstrapKey)
	proofsEmpty := record.Access.ManagementProofVerifiedAt.IsZero() &&
		record.Access.BootstrapRevocationVerifiedAt.IsZero()
	switch record.Access.Phase {
	case AccessBootstrap:
		if record.Access.Active != bootstrap || record.Access.ActiveAccessUser != record.SSHUser ||
			!isZeroKeyRef(record.Access.Pending) || record.Access.PendingAccessUser != "" || !proofsEmpty {
			return fmt.Errorf("%w: invalid bootstrap access state", ErrInvalidControlNode)
		}
	case AccessStaged:
		if record.Access.Active != bootstrap || record.Access.ActiveAccessUser != record.SSHUser ||
			!validAccessKeyRef(record.Access.Pending, sshkeys.Control) ||
			record.Access.Pending.Fingerprint == bootstrap.Fingerprint ||
			record.Access.PendingAccessUser != ManagementAccessUser ||
			record.Access.PendingAccessUser == record.SSHUser || !proofsEmpty {
			return fmt.Errorf("%w: invalid staged access state", ErrInvalidControlNode)
		}
	case AccessManagement:
		if !validAccessKeyRef(record.Access.Active, sshkeys.Control) ||
			record.Access.Active.Fingerprint == bootstrap.Fingerprint ||
			record.Access.ActiveAccessUser != ManagementAccessUser ||
			record.Access.ActiveAccessUser == record.SSHUser ||
			!isZeroKeyRef(record.Access.Pending) || record.Access.PendingAccessUser != "" ||
			!validProofTimestamp(record.Access.ManagementProofVerifiedAt, record) ||
			!validProofTimestamp(record.Access.BootstrapRevocationVerifiedAt, record) {
			return fmt.Errorf("%w: invalid management access state", ErrInvalidControlNode)
		}
	default:
		return fmt.Errorf("%w: unknown access phase", ErrInvalidControlNode)
	}
	return nil
}

func validProofTimestamp(value time.Time, record Record) bool {
	return validTimestamp(value) && !value.Before(record.CreatedAt) && !value.After(record.UpdatedAt)
}

func sameBinding(record Record, binding normalizedBinding) bool {
	return record.SystemID == binding.SystemID && record.Name == binding.Name &&
		record.Host == binding.Host && record.Port == binding.Port && record.SSHUser == binding.SSHUser &&
		record.OperatingSystem == binding.OperatingSystem && record.BootstrapKey == binding.BootstrapKey &&
		record.HostPublicKey == binding.HostPublicKey && record.HostFingerprint == binding.HostFingerprint &&
		record.EvidenceSource == binding.EvidenceSource
}

func validTransition(current, next Lifecycle) bool {
	if next == LifecycleRevoked {
		return current != LifecycleRevoked && validLifecycle(current)
	}
	switch current {
	case LifecycleBound:
		return next == LifecycleConnectivityVerified
	case LifecycleConnectivityVerified:
		return next == LifecycleInstalling
	case LifecycleInstalling:
		return next == LifecycleReady
	default:
		return false
	}
}

func validOperatingSystem(system OperatingSystem) bool {
	return system == OSDebian13 || system == OSUbuntu2404
}

func validEvidenceSource(source EvidenceSource) bool {
	return source == EvidenceProviderConsole || source == EvidenceProviderAttestation
}

func validLifecycle(lifecycle Lifecycle) bool {
	switch lifecycle {
	case LifecycleBound, LifecycleConnectivityVerified, LifecycleInstalling, LifecycleReady, LifecycleRevoked:
		return true
	default:
		return false
	}
}

func validFingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32 && value == prefix+base64.RawStdEncoding.EncodeToString(decoded)
}

func validAccessUser(user string) bool {
	return sshUserRE.MatchString(user) && user != "root"
}

func validTimestamp(value time.Time) bool {
	if value.IsZero() || value.Unix() <= 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func (manager *Manager) currentTime(minimum time.Time) (time.Time, error) {
	now := manager.now().UTC()
	if !validTimestamp(now) || (!minimum.IsZero() && now.Before(minimum)) {
		return time.Time{}, fmt.Errorf("%w: invalid clock", ErrInvalidControlNode)
	}
	return now, nil
}

func knownHostsLine(record Record) string {
	host := record.Host
	if record.Port != 22 {
		host = "[" + host + "]:" + strconv.Itoa(record.Port)
	}
	return host + " " + record.HostPublicKey + "\n"
}

func cloneRecord(record Record) Record {
	result := record
	if record.RevokedAt != nil {
		revokedAt := *record.RevokedAt
		result.RevokedAt = &revokedAt
	}
	return result
}

func validateIdentity(systemID, name string) error {
	if !systemIDRE.MatchString(systemID) || !nodeNameRE.MatchString(name) {
		return ErrInvalidControlNode
	}
	return nil
}

func controlsRelative(systemID string) string {
	return filepath.Join("systems", systemID, "control-nodes")
}

func baseRelative(systemID, name string) string {
	return filepath.Join(controlsRelative(systemID), name)
}

func lockRelative(systemID, name string) string {
	return filepath.Join(baseRelative(systemID, name), ".lock")
}

func metadataRelative(systemID, name string) string {
	return filepath.Join(baseRelative(systemID, name), "control.json")
}

func knownHostsRelative(systemID, name string) string {
	return filepath.Join(baseRelative(systemID, name), "known_hosts")
}
