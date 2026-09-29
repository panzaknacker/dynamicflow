// package systemstate stores the operator's provider-independent systems.

// the store deliberately contains only bounded public metadata. private key
// paths, bootstrap credentials, bearer tokens and other secrets have no field
// in this schema. all mutations are serialized by localstate's owner-only
// flock and committed through one atomic registry replacement.
package systemstate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"dynamicflow/internal/localstate"
)

const (
	RegistrySchema = 1
	SystemSchema   = 1

	registryPath = "systems/registry.json"
	registryLock = "systems/registry.lock"
	maxSystems   = 4096
	systemIDSize = 16
)

var (
	ErrInvalidStore      = errors.New("invalid system registry")
	ErrInvalidSystem     = errors.New("invalid system metadata")
	ErrInvalidName       = errors.New("invalid system name")
	ErrNotFound          = errors.New("system not found")
	ErrNoActiveSystem    = errors.New("no active system")
	ErrRevisionConflict  = errors.New("system revision conflict")
	ErrImmutableField    = errors.New("immutable system field changed")
	ErrInvalidTransition = errors.New("invalid system status transition")
	ErrActiveSystem      = errors.New("active system cannot be retired")
	ErrCapacity          = errors.New("system registry capacity reached")
	ErrInvalidClock      = errors.New("invalid system clock")

	systemNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	systemIDRE   = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	keyIDRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errorCodeRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Status is the lifecycle state of one complete dynamicflow system. the
// registry's ActiveSystemID is an operator selection and is intentionally
// independent from this runtime status.
type Status string

const (
	StatusInitializing Status = "initializing"
	StatusActive       Status = "active"
	StatusDegraded     Status = "degraded"
	StatusRetired      Status = "retired"
)

// BootstrapState records only the non-secret progress of the first control
// bootstrap. the private bootstrap identity and one-time material live in
// their purpose-built stores, never here.
type BootstrapState string

const (
	BootstrapNotStarted    BootstrapState = "not_started"
	BootstrapKeyPrepared   BootstrapState = "key_prepared"
	BootstrapHostBound     BootstrapState = "host_bound"
	BootstrapProvisioning  BootstrapState = "provisioning"
	BootstrapControlActive BootstrapState = "control_active"
	BootstrapFailed        BootstrapState = "failed"
	BootstrapRevoked       BootstrapState = "revoked"
)

// TrustMetadata contains public key identifiers only. Generation zero means
// that the complete trust set has not been committed yet. a committed set is
// all-or-nothing and every role must use a distinct key.
type TrustMetadata struct {
	Generation         uint64 `json:"generation"`
	SystemRootKeyID    string `json:"system_root_key_id,omitempty"`
	ReleaseKeyID       string `json:"release_key_id,omitempty"`
	DesiredStateKeyID  string `json:"desired_state_key_id,omitempty"`
	ServingAdminKeyID  string `json:"serving_admin_key_id,omitempty"`
	ControlPolicyKeyID string `json:"control_policy_key_id,omitempty"`
}

// BootstrapMetadata is bounded audit metadata. fingerprints are canonical
// OpenSSH SHA256 fingerprints; no public-key body, private path or secret is
// accepted by this schema.
type BootstrapMetadata struct {
	State                   BootstrapState `json:"state"`
	ControlNodeID           string         `json:"control_node_id,omitempty"`
	BootstrapKeyFingerprint string         `json:"bootstrap_key_fingerprint,omitempty"`
	HostKeyFingerprint      string         `json:"host_key_fingerprint,omitempty"`
	ExpiresAt               *time.Time     `json:"expires_at,omitempty"`
	BootstrapKeyRevoked     bool           `json:"bootstrap_key_revoked,omitempty"`
	FailureCode             string         `json:"failure_code,omitempty"`
}

// System is one provider-independent dynamicflow control domain. Revision is
// an optimistic-concurrency token managed exclusively by Store.Update.
type System struct {
	Schema    int               `json:"schema"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Revision  uint64            `json:"revision"`
	Status    Status            `json:"status"`
	Trust     TrustMetadata     `json:"trust"`
	Bootstrap BootstrapMetadata `json:"bootstrap"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Registry is the atomically committed collection. Systems are persisted in
// deterministic name/ID order and ActiveSystemID selects the operator context.
type Registry struct {
	Schema         int      `json:"schema"`
	Revision       uint64   `json:"revision"`
	ActiveSystemID string   `json:"active_system_id,omitempty"`
	Systems        []System `json:"systems"`
}

// Option configures a Store. production callers should normally omit all
// options and use crypto/rand.Reader plus time.Now.
type Option func(*Store)

// WithClock injects a clock for deterministic tests.
func WithClock(clock func() time.Time) Option {
	return func(store *Store) {
		if clock != nil {
			store.now = clock
		}
	}
}

// WithRandomReader injects the entropy source used only for system ids.
func WithRandomReader(reader io.Reader) Option {
	return func(store *Store) {
		if reader != nil {
			store.random = reader
		}
	}
}

// Store owns the private system registry within one localstate root.
type Store struct {
	state  *localstate.Store
	now    func() time.Time
	random io.Reader
}

// New validates any existing registry immediately. corruption and unknown
// schemas are never treated as an empty registry.
func New(state *localstate.Store, options ...Option) (*Store, error) {
	if state == nil {
		return nil, fmt.Errorf("%w: local state is required", ErrInvalidStore)
	}
	store := &Store{state: state, now: time.Now, random: rand.Reader}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	if store.now == nil || store.random == nil {
		return nil, fmt.Errorf("%w: clock and entropy source are required", ErrInvalidStore)
	}
	if _, err := store.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return store, nil
}

// Snapshot returns a detached, validated registry snapshot. Before the first
// system is created it returns schema 1, revision 0 and an empty slice.
func (store *Store) Snapshot() (Registry, error) {
	registry, err := store.load()
	if errors.Is(err, os.ErrNotExist) {
		return emptyRegistry(), nil
	}
	return cloneRegistry(registry), err
}

// List returns systems in deterministic name/ID order.
func (store *Store) List() ([]System, error) {
	registry, err := store.Snapshot()
	if err != nil {
		return nil, err
	}
	return cloneSystems(registry.Systems), nil
}

// Get returns one system by its opaque sys-* identifier.
func (store *Store) Get(id string) (System, error) {
	if !systemIDRE.MatchString(id) {
		return System{}, ErrNotFound
	}
	registry, err := store.Snapshot()
	if err != nil {
		return System{}, err
	}
	for _, system := range registry.Systems {
		if system.ID == id {
			return cloneSystem(system), nil
		}
	}
	return System{}, ErrNotFound
}

// GetByName returns one system by its unique operator-facing name.
func (store *Store) GetByName(name string) (System, error) {
	if !systemNameRE.MatchString(name) {
		return System{}, ErrInvalidName
	}
	registry, err := store.Snapshot()
	if err != nil {
		return System{}, err
	}
	for _, system := range registry.Systems {
		if system.Name == name {
			return cloneSystem(system), nil
		}
	}
	return System{}, ErrNotFound
}

// Active returns the selected operator system. a non-empty registry is always
// required to have an active selection.
func (store *Store) Active() (System, error) {
	registry, err := store.Snapshot()
	if err != nil {
		return System{}, err
	}
	if registry.ActiveSystemID == "" {
		return System{}, ErrNoActiveSystem
	}
	for _, system := range registry.Systems {
		if system.ID == registry.ActiveSystemID {
			return cloneSystem(system), nil
		}
	}
	return System{}, fmt.Errorf("%w: active system is missing", ErrInvalidStore)
}

// CreateOrGet atomically creates the first revision for name or returns the
// exact existing record. concurrent callers for the same name observe one ID;
// only one receives created=true. the first system becomes the active context.
func (store *Store) CreateOrGet(name string) (result System, created bool, err error) {
	if !systemNameRE.MatchString(name) {
		return System{}, false, ErrInvalidName
	}
	err = store.state.WithLock(registryLock, func() error {
		registry, loadErr := store.loadForMutation()
		if loadErr != nil {
			return loadErr
		}
		for _, system := range registry.Systems {
			if system.Name == name {
				result = cloneSystem(system)
				return nil
			}
		}
		if len(registry.Systems) >= maxSystems {
			return ErrCapacity
		}
		id, idErr := store.allocateID(registry)
		if idErr != nil {
			return idErr
		}
		now, clockErr := store.currentTime(time.Time{})
		if clockErr != nil {
			return clockErr
		}
		result = System{
			Schema: SystemSchema, ID: id, Name: name, Revision: 1,
			Status: StatusInitializing, Bootstrap: BootstrapMetadata{State: BootstrapNotStarted},
			CreatedAt: now, UpdatedAt: now,
		}
		registry.Systems = append(registry.Systems, result)
		sortSystems(registry.Systems)
		if registry.ActiveSystemID == "" {
			registry.ActiveSystemID = result.ID
		}
		if registry.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		registry.Revision++
		if err := validateRegistry(registry); err != nil {
			return err
		}
		if err := store.state.WriteJSON(registryPath, registry); err != nil {
			return err
		}
		created = true
		result = cloneSystem(result)
		return nil
	})
	return result, created, err
}

// Update performs a compare-and-swap mutation of status, trust and bootstrap
// metadata. Schema, identity, name, revisions and timestamps are store-owned.
// the callback operates on a detached copy and cannot partially mutate disk.
func (store *Store) Update(id string, expectedRevision uint64, mutate func(*System) error) (result System, err error) {
	if !systemIDRE.MatchString(id) || expectedRevision == 0 || mutate == nil {
		return System{}, ErrInvalidSystem
	}
	err = store.state.WithLock(registryLock, func() error {
		registry, loadErr := store.loadForMutation()
		if loadErr != nil {
			return loadErr
		}
		index := systemIndex(registry.Systems, id)
		if index < 0 {
			return ErrNotFound
		}
		current := cloneSystem(registry.Systems[index])
		if current.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		candidate := cloneSystem(current)
		if err := mutate(&candidate); err != nil {
			return err
		}
		if candidate.Schema != current.Schema || candidate.ID != current.ID || candidate.Name != current.Name ||
			candidate.Revision != current.Revision || !candidate.CreatedAt.Equal(current.CreatedAt) || !candidate.UpdatedAt.Equal(current.UpdatedAt) {
			return ErrImmutableField
		}
		if !validStatusTransition(current.Status, candidate.Status) {
			return ErrInvalidTransition
		}
		if candidate.Status == StatusRetired && registry.ActiveSystemID == candidate.ID {
			return ErrActiveSystem
		}
		if current.Revision == ^uint64(0) || registry.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		now, clockErr := store.currentTime(current.UpdatedAt)
		if clockErr != nil {
			return clockErr
		}
		candidate.Revision++
		candidate.UpdatedAt = now
		if err := validateSystem(candidate); err != nil {
			return err
		}
		registry.Systems[index] = candidate
		registry.Revision++
		if err := validateRegistry(registry); err != nil {
			return err
		}
		if err := store.state.WriteJSON(registryPath, registry); err != nil {
			return err
		}
		result = cloneSystem(candidate)
		return nil
	})
	return result, err
}

// SetActive compare-and-swaps the registry selection. retired systems cannot
// become active. re-selecting the current system is an idempotent no-op when
// the supplied registry revision is current.
func (store *Store) SetActive(id string, expectedRegistryRevision uint64) (result System, err error) {
	if !systemIDRE.MatchString(id) || expectedRegistryRevision == 0 {
		return System{}, ErrInvalidSystem
	}
	err = store.state.WithLock(registryLock, func() error {
		registry, loadErr := store.loadForMutation()
		if loadErr != nil {
			return loadErr
		}
		if registry.Revision != expectedRegistryRevision {
			return ErrRevisionConflict
		}
		index := systemIndex(registry.Systems, id)
		if index < 0 {
			return ErrNotFound
		}
		if registry.Systems[index].Status == StatusRetired {
			return ErrInvalidTransition
		}
		result = cloneSystem(registry.Systems[index])
		if registry.ActiveSystemID == id {
			return nil
		}
		if registry.Revision == ^uint64(0) {
			return ErrRevisionConflict
		}
		registry.ActiveSystemID = id
		registry.Revision++
		if err := validateRegistry(registry); err != nil {
			return err
		}
		return store.state.WriteJSON(registryPath, registry)
	})
	return result, err
}

func (store *Store) loadForMutation() (Registry, error) {
	registry, err := store.load()
	if errors.Is(err, os.ErrNotExist) {
		return emptyRegistry(), nil
	}
	return registry, err
}

func (store *Store) load() (Registry, error) {
	var registry Registry
	if err := store.state.ReadJSON(registryPath, &registry); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Registry{}, os.ErrNotExist
		}
		return Registry{}, fmt.Errorf("%w: %v", ErrInvalidStore, err)
	}
	if err := validateRegistry(registry); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (store *Store) allocateID(registry Registry) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var raw [systemIDSize]byte
		if _, err := io.ReadFull(store.random, raw[:]); err != nil {
			return "", fmt.Errorf("allocate system ID: %w", err)
		}
		id := "sys-" + hex.EncodeToString(raw[:])
		if systemIndex(registry.Systems, id) < 0 {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: could not allocate a unique system ID", ErrInvalidStore)
}

func (store *Store) currentTime(minimum time.Time) (time.Time, error) {
	now := store.now().UTC()
	if now.IsZero() || now.Unix() <= 0 || (!minimum.IsZero() && now.Before(minimum)) {
		return time.Time{}, ErrInvalidClock
	}
	return now, nil
}

func emptyRegistry() Registry {
	return Registry{Schema: RegistrySchema, Systems: []System{}}
}

func validateRegistry(registry Registry) error {
	if registry.Schema != RegistrySchema || registry.Revision == 0 || len(registry.Systems) == 0 ||
		len(registry.Systems) > maxSystems || registry.ActiveSystemID == "" {
		return ErrInvalidStore
	}
	ids := make(map[string]struct{}, len(registry.Systems))
	names := make(map[string]struct{}, len(registry.Systems))
	activeFound := false
	for index, system := range registry.Systems {
		if err := validateSystem(system); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidStore, err)
		}
		if _, exists := ids[system.ID]; exists {
			return fmt.Errorf("%w: duplicate system ID", ErrInvalidStore)
		}
		if _, exists := names[system.Name]; exists {
			return fmt.Errorf("%w: duplicate system name", ErrInvalidStore)
		}
		ids[system.ID] = struct{}{}
		names[system.Name] = struct{}{}
		if system.ID == registry.ActiveSystemID {
			if system.Status == StatusRetired {
				return fmt.Errorf("%w: active system is retired", ErrInvalidStore)
			}
			activeFound = true
		}
		if index > 0 && systemLess(system, registry.Systems[index-1]) {
			return fmt.Errorf("%w: systems are not canonically ordered", ErrInvalidStore)
		}
	}
	if !activeFound {
		return fmt.Errorf("%w: active system is missing", ErrInvalidStore)
	}
	return nil
}

func validateSystem(system System) error {
	if system.Schema != SystemSchema || !systemIDRE.MatchString(system.ID) || !systemNameRE.MatchString(system.Name) ||
		system.Revision == 0 || !validStatus(system.Status) || !validTimestamp(system.CreatedAt) || !validTimestamp(system.UpdatedAt) ||
		system.UpdatedAt.Before(system.CreatedAt) {
		return ErrInvalidSystem
	}
	if err := validateTrust(system.Trust); err != nil {
		return err
	}
	if err := validateBootstrap(system.Bootstrap, system.CreatedAt); err != nil {
		return err
	}
	if system.Status == StatusActive && (system.Trust.Generation == 0 || system.Bootstrap.State != BootstrapControlActive) {
		return fmt.Errorf("%w: active status requires committed trust and an active control", ErrInvalidSystem)
	}
	return nil
}

func validateTrust(trust TrustMetadata) error {
	values := []string{
		trust.SystemRootKeyID, trust.ReleaseKeyID, trust.DesiredStateKeyID,
		trust.ServingAdminKeyID, trust.ControlPolicyKeyID,
	}
	if trust.Generation == 0 {
		for _, value := range values {
			if value != "" {
				return fmt.Errorf("%w: partial trust metadata", ErrInvalidSystem)
			}
		}
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !keyIDRE.MatchString(value) {
			return fmt.Errorf("%w: invalid trust key ID", ErrInvalidSystem)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: trust roles share a key", ErrInvalidSystem)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateBootstrap(bootstrap BootstrapMetadata, createdAt time.Time) error {
	if !validBootstrapState(bootstrap.State) ||
		(bootstrap.ControlNodeID != "" && !identifierRE.MatchString(bootstrap.ControlNodeID)) ||
		(bootstrap.BootstrapKeyFingerprint != "" && !validSSHFingerprint(bootstrap.BootstrapKeyFingerprint)) ||
		(bootstrap.HostKeyFingerprint != "" && !validSSHFingerprint(bootstrap.HostKeyFingerprint)) ||
		(bootstrap.FailureCode != "" && !errorCodeRE.MatchString(bootstrap.FailureCode)) {
		return ErrInvalidSystem
	}
	if bootstrap.ExpiresAt != nil && (!validTimestamp(*bootstrap.ExpiresAt) || !bootstrap.ExpiresAt.After(createdAt)) {
		return ErrInvalidSystem
	}
	switch bootstrap.State {
	case BootstrapNotStarted:
		if bootstrap.ControlNodeID != "" || bootstrap.BootstrapKeyFingerprint != "" || bootstrap.HostKeyFingerprint != "" ||
			bootstrap.ExpiresAt != nil || bootstrap.BootstrapKeyRevoked || bootstrap.FailureCode != "" {
			return ErrInvalidSystem
		}
	case BootstrapKeyPrepared:
		if bootstrap.BootstrapKeyFingerprint == "" || bootstrap.ExpiresAt == nil || bootstrap.BootstrapKeyRevoked || bootstrap.FailureCode != "" ||
			bootstrap.ControlNodeID != "" || bootstrap.HostKeyFingerprint != "" {
			return ErrInvalidSystem
		}
	case BootstrapHostBound, BootstrapProvisioning:
		if bootstrap.ControlNodeID == "" || bootstrap.BootstrapKeyFingerprint == "" || bootstrap.HostKeyFingerprint == "" ||
			bootstrap.ExpiresAt == nil || bootstrap.BootstrapKeyRevoked || bootstrap.FailureCode != "" {
			return ErrInvalidSystem
		}
	case BootstrapControlActive:
		if bootstrap.ControlNodeID == "" || bootstrap.BootstrapKeyFingerprint == "" || bootstrap.HostKeyFingerprint == "" ||
			bootstrap.ExpiresAt == nil || !bootstrap.BootstrapKeyRevoked || bootstrap.FailureCode != "" {
			return ErrInvalidSystem
		}
	case BootstrapFailed:
		if bootstrap.BootstrapKeyFingerprint == "" || bootstrap.ExpiresAt == nil || bootstrap.FailureCode == "" {
			return ErrInvalidSystem
		}
	case BootstrapRevoked:
		if bootstrap.BootstrapKeyFingerprint == "" || bootstrap.ExpiresAt == nil || !bootstrap.BootstrapKeyRevoked {
			return ErrInvalidSystem
		}
	}
	return nil
}

func validStatus(status Status) bool {
	switch status {
	case StatusInitializing, StatusActive, StatusDegraded, StatusRetired:
		return true
	default:
		return false
	}
}

func validBootstrapState(state BootstrapState) bool {
	switch state {
	case BootstrapNotStarted, BootstrapKeyPrepared, BootstrapHostBound, BootstrapProvisioning,
		BootstrapControlActive, BootstrapFailed, BootstrapRevoked:
		return true
	default:
		return false
	}
}

func validStatusTransition(from, to Status) bool {
	if from == to {
		return true
	}
	switch from {
	case StatusInitializing:
		return to == StatusActive || to == StatusDegraded || to == StatusRetired
	case StatusActive:
		return to == StatusDegraded || to == StatusRetired
	case StatusDegraded:
		return to == StatusActive || to == StatusRetired
	case StatusRetired:
		return false
	default:
		return false
	}
}

func validTimestamp(value time.Time) bool {
	if value.IsZero() || value.Unix() <= 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func validSSHFingerprint(value string) bool {
	const prefix = "SHA256:"
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value[len(prefix):])
	return err == nil && len(decoded) == 32 && value == prefix+base64.RawStdEncoding.EncodeToString(decoded)
}

func systemIndex(systems []System, id string) int {
	for index := range systems {
		if systems[index].ID == id {
			return index
		}
	}
	return -1
}

func sortSystems(systems []System) {
	sort.Slice(systems, func(left, right int) bool { return systemLess(systems[left], systems[right]) })
}

func systemLess(left, right System) bool {
	if left.Name == right.Name {
		return left.ID < right.ID
	}
	return left.Name < right.Name
}

func cloneRegistry(registry Registry) Registry {
	result := registry
	result.Systems = cloneSystems(registry.Systems)
	return result
}

func cloneSystems(systems []System) []System {
	result := make([]System, len(systems))
	for index := range systems {
		result[index] = cloneSystem(systems[index])
	}
	return result
}

func cloneSystem(system System) System {
	result := system
	if system.Bootstrap.ExpiresAt != nil {
		expires := *system.Bootstrap.ExpiresAt
		result.Bootstrap.ExpiresAt = &expires
	}
	return result
}
