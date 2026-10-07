// Package topology models the operator-local SSH access graph.
//
// A topology has exactly one directly reachable control node. Once that
// control is ready, every target must be reached through a fingerprint-bound
// route which ultimately terminates at the control. The package only manages
// local state; it never opens a network connection or executes a process.
package topology

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"dynamicflow/internal/localstate"
)

const SchemaVersion = 1

const (
	stateRelative = "topology/topology.json"
	lockRelative  = "topology/.lock"
)

var (
	ErrInvalidTopology            = errors.New("invalid topology")
	ErrNotFound                   = errors.New("topology not found")
	ErrMissingControl             = errors.New("control is missing")
	ErrControlUnpinned            = errors.New("control is not pinned")
	ErrControlRevoked             = errors.New("control is revoked")
	ErrTargetUnpinned             = errors.New("target is not pinned")
	ErrTargetRevoked              = errors.New("target is revoked")
	ErrUnsafeHost                 = errors.New("unsafe host")
	ErrInvalidFingerprint         = errors.New("invalid host-key fingerprint")
	ErrInvalidRoute               = errors.New("invalid route")
	ErrRouteBinding               = errors.New("route fingerprint binding mismatch")
	ErrSelfJump                   = errors.New("route jumps through its own target")
	ErrCycle                      = errors.New("route cycle")
	ErrDirectAfterControlReady    = errors.New("direct target access is forbidden after control is ready")
	ErrDuplicateManagementAddress = errors.New("duplicate management address")
	ErrControlReadyRollback       = errors.New("control-ready state cannot be rolled back")
	ErrGeneration                 = errors.New("topology generation conflict")
)

var (
	nodeNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sshUserRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// TrustState is the out-of-band host-key trust state of a node.
type TrustState string

const (
	TrustUnpinned TrustState = "unpinned"
	TrustPinned   TrustState = "pinned"
	TrustRevoked  TrustState = "revoked"
)

// AccessMode selects how the operator reaches a target.
type AccessMode string

const (
	AccessDirect  AccessMode = "direct"
	AccessControl AccessMode = "control"
)

// Control is the sole directly reachable SSH transit node. Host is an
// operator-reachable address; its host-key fingerprint must be established
// out of band before the topology can be stored.
type Control struct {
	Name               string     `json:"name"`
	Host               string     `json:"host"`
	SSHPort            int        `json:"ssh_port"`
	SSHUser            string     `json:"ssh_user"`
	Trust              TrustState `json:"trust"`
	HostKeyFingerprint string     `json:"host_key_fingerprint"`
}

// Target describes one managed SSH endpoint. DirectHost is present only
// during the pre-control bootstrap phase. A control-routed target obtains its
// destination from exactly one Route.
type Target struct {
	Name               string     `json:"name"`
	Access             AccessMode `json:"access"`
	DirectHost         string     `json:"direct_host,omitempty"`
	SSHPort            int        `json:"ssh_port"`
	SSHUser            string     `json:"ssh_user"`
	Trust              TrustState `json:"trust"`
	HostKeyFingerprint string     `json:"host_key_fingerprint"`
}

// Route binds a target management address to both ends of the trust path.
// Via names either the control or another control-routed target. Every chain
// must be acyclic and terminate at the topology's control.
type Route struct {
	Target             string `json:"target"`
	Via                string `json:"via"`
	ManagementAddress  string `json:"management_address"`
	ControlFingerprint string `json:"control_fingerprint"`
	TargetFingerprint  string `json:"target_fingerprint"`
}

// Topology is the complete local access graph. ControlReady is monotonic in
// Store: once persisted as true, it can never be cleared to re-enable direct
// target access.
type Topology struct {
	Schema       int      `json:"schema"`
	Generation   uint64   `json:"generation"`
	ControlReady bool     `json:"control_ready"`
	Control      *Control `json:"control"`
	Targets      []Target `json:"targets"`
	Routes       []Route  `json:"routes"`
}

// Store persists one topology through localstate's private, no-symlink,
// atomic file operations.
type Store struct {
	local *localstate.Store
}

func NewStore(local *localstate.Store) *Store {
	return &Store{local: local}
}

// Validate checks the complete graph without changing it.
func Validate(document Topology) error {
	if document.Schema != SchemaVersion || document.Generation == 0 {
		return invalid(nil, "schema must be %d and generation must be positive", SchemaVersion)
	}
	if document.Control == nil {
		return invalid(ErrMissingControl, "exactly one control is required")
	}
	control := *document.Control
	if err := validateControl(control); err != nil {
		return err
	}

	targets := make(map[string]Target, len(document.Targets))
	for _, target := range document.Targets {
		if _, exists := targets[target.Name]; exists {
			return invalid(nil, "duplicate target %q", target.Name)
		}
		if target.Name == control.Name {
			return invalid(nil, "target %q collides with the control name", target.Name)
		}
		if err := validateTarget(target, document.ControlReady); err != nil {
			return err
		}
		targets[target.Name] = target
	}

	routes := make(map[string]Route, len(document.Routes))
	addresses := make(map[string]string, len(document.Routes))
	for _, route := range document.Routes {
		target, exists := targets[route.Target]
		if !exists {
			return invalid(ErrInvalidRoute, "route references unknown target %q", route.Target)
		}
		if _, duplicate := routes[route.Target]; duplicate {
			return invalid(ErrInvalidRoute, "target %q has more than one route", route.Target)
		}
		if target.Access != AccessControl {
			return invalid(ErrInvalidRoute, "direct target %q must not have a control route", route.Target)
		}
		if route.Via == route.Target {
			return invalid(ErrSelfJump, "target %q names itself as jump", route.Target)
		}
		if !nodeNameRE.MatchString(route.Via) {
			return invalid(ErrInvalidRoute, "target %q has an invalid jump name", route.Target)
		}
		address, err := canonicalHost(route.ManagementAddress)
		if err != nil || address != route.ManagementAddress {
			return invalid(ErrUnsafeHost, "target %q has an unsafe or non-canonical management address", route.Target)
		}
		if previous, duplicate := addresses[address]; duplicate {
			return invalid(ErrDuplicateManagementAddress, "targets %q and %q share %q", previous, route.Target, address)
		}
		addresses[address] = route.Target
		if route.ControlFingerprint != control.HostKeyFingerprint ||
			route.TargetFingerprint != target.HostKeyFingerprint {
			return invalid(ErrRouteBinding, "route for target %q does not bind the pinned control and target fingerprints", route.Target)
		}
		routes[route.Target] = route
	}

	for _, target := range document.Targets {
		_, hasRoute := routes[target.Name]
		switch target.Access {
		case AccessDirect:
			if hasRoute {
				return invalid(ErrInvalidRoute, "direct target %q has a route", target.Name)
			}
		case AccessControl:
			if !document.ControlReady {
				return invalid(ErrInvalidRoute, "target %q uses control before it is ready", target.Name)
			}
			if !hasRoute {
				return invalid(ErrInvalidRoute, "control target %q has no route", target.Name)
			}
		}
	}

	return validateRouteGraph(control.Name, targets, routes)
}

func validateControl(control Control) error {
	if !nodeNameRE.MatchString(control.Name) {
		return invalid(nil, "invalid control name")
	}
	if control.Trust == TrustRevoked {
		return invalid(ErrControlRevoked, "control %q is revoked", control.Name)
	}
	if control.Trust != TrustPinned {
		return invalid(ErrControlUnpinned, "control %q has not been pinned out of band", control.Name)
	}
	if !validFingerprint(control.HostKeyFingerprint) {
		return invalid(ErrInvalidFingerprint, "control %q has an invalid Ed25519 fingerprint", control.Name)
	}
	if err := validateEndpoint(control.Host, control.SSHUser, control.SSHPort); err != nil {
		return invalid(err, "control %q has an invalid endpoint", control.Name)
	}
	return nil
}

func validateTarget(target Target, controlReady bool) error {
	if !nodeNameRE.MatchString(target.Name) {
		return invalid(nil, "invalid target name")
	}
	if target.Trust == TrustRevoked {
		return invalid(ErrTargetRevoked, "target %q is revoked", target.Name)
	}
	if target.Trust != TrustPinned {
		return invalid(ErrTargetUnpinned, "target %q has not been pinned out of band", target.Name)
	}
	if !validFingerprint(target.HostKeyFingerprint) {
		return invalid(ErrInvalidFingerprint, "target %q has an invalid Ed25519 fingerprint", target.Name)
	}
	if !sshUserRE.MatchString(target.SSHUser) || target.SSHUser == "root" || target.SSHPort < 1 || target.SSHPort > 65535 {
		return invalid(nil, "target %q has an invalid non-root SSH endpoint", target.Name)
	}
	switch target.Access {
	case AccessDirect:
		if controlReady {
			return invalid(ErrDirectAfterControlReady, "target %q is direct", target.Name)
		}
		host, err := canonicalHost(target.DirectHost)
		if err != nil || host != target.DirectHost {
			return invalid(ErrUnsafeHost, "target %q has an unsafe or non-canonical direct host", target.Name)
		}
	case AccessControl:
		if target.DirectHost != "" {
			return invalid(ErrInvalidRoute, "control target %q also has a direct host", target.Name)
		}
	default:
		return invalid(nil, "target %q has invalid access mode %q", target.Name, target.Access)
	}
	return nil
}

func validateEndpoint(host, user string, port int) error {
	canonical, err := canonicalHost(host)
	if err != nil || canonical != host {
		return ErrUnsafeHost
	}
	if !sshUserRE.MatchString(user) || user == "root" || port < 1 || port > 65535 {
		return ErrInvalidTopology
	}
	return nil
}

func validateRouteGraph(controlName string, targets map[string]Target, routes map[string]Route) error {
	const (
		unseen = iota
		visiting
		complete
	)
	state := make(map[string]int, len(routes))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return invalid(ErrCycle, "route cycle reaches %q", name)
		case complete:
			return nil
		}
		state[name] = visiting
		route, exists := routes[name]
		if !exists {
			return invalid(ErrInvalidRoute, "target %q has no route to control", name)
		}
		switch route.Via {
		case controlName:
			// The chain terminates only at the one pinned control.
		default:
			via, exists := targets[route.Via]
			if !exists || via.Access != AccessControl {
				return invalid(ErrInvalidRoute, "target %q jumps through unknown or direct node %q", name, route.Via)
			}
			if err := visit(route.Via); err != nil {
				return err
			}
		}
		state[name] = complete
		return nil
	}
	for name := range routes {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

// Save validates and atomically persists document. Changed documents advance
// exactly one generation. Re-saving an identical document is idempotent.
func (store *Store) Save(document Topology) error {
	if store == nil || store.local == nil {
		return invalid(nil, "local state store is unavailable")
	}
	document = normalize(document)
	if err := Validate(document); err != nil {
		return err
	}
	return store.local.WithLock(lockRelative, func() error {
		current, err := store.loadUnlocked()
		switch {
		case errors.Is(err, ErrNotFound):
			if document.Generation != 1 {
				return fmt.Errorf("%w: first topology generation must be 1", ErrGeneration)
			}
		case err != nil:
			return err
		default:
			if reflect.DeepEqual(current, document) {
				return nil
			}
			if current.ControlReady && !document.ControlReady {
				return ErrControlReadyRollback
			}
			if document.Generation != current.Generation+1 {
				return fmt.Errorf("%w: got %d, want %d", ErrGeneration, document.Generation, current.Generation+1)
			}
		}
		return store.local.WriteJSON(stateRelative, document)
	})
}

// Load returns the validated persisted topology.
func (store *Store) Load() (Topology, error) {
	if store == nil || store.local == nil {
		return Topology{}, invalid(nil, "local state store is unavailable")
	}
	return store.loadUnlocked()
}

func (store *Store) loadUnlocked() (Topology, error) {
	var document Topology
	if err := store.local.ReadJSON(stateRelative, &document); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Topology{}, ErrNotFound
		}
		return Topology{}, err
	}
	if err := Validate(document); err != nil {
		return Topology{}, err
	}
	return normalize(document), nil
}

func normalize(document Topology) Topology {
	result := document
	if document.Control != nil {
		control := *document.Control
		result.Control = &control
	}
	result.Targets = append([]Target(nil), document.Targets...)
	result.Routes = append([]Route(nil), document.Routes...)
	sort.Slice(result.Targets, func(left, right int) bool {
		return result.Targets[left].Name < result.Targets[right].Name
	})
	sort.Slice(result.Routes, func(left, right int) bool {
		return result.Routes[left].Target < result.Routes[right].Target
	})
	if result.Targets == nil {
		result.Targets = []Target{}
	}
	if result.Routes == nil {
		result.Routes = []Route{}
	}
	return result
}

func canonicalHost(host string) (string, error) {
	if host == "" || host != strings.TrimSpace(host) || len(host) > 253 ||
		strings.ContainsAny(host, " /\\@%[]\t\r\n\x00") || strings.HasPrefix(host, "-") {
		return "", ErrUnsafeHost
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", ErrUnsafeHost
		}
		return ip.String(), nil
	}
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return "", ErrUnsafeHost
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrUnsafeHost
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' || character == '-') {
				return "", ErrUnsafeHost
			}
		}
	}
	return host, nil
}

func validFingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(digest) == 32 &&
		value == prefix+base64.RawStdEncoding.EncodeToString(digest)
}

func invalid(cause error, format string, arguments ...any) error {
	detail := fmt.Sprintf(format, arguments...)
	if cause == nil || errors.Is(cause, ErrInvalidTopology) {
		return fmt.Errorf("%w: %s", ErrInvalidTopology, detail)
	}
	return fmt.Errorf("%w: %w: %s", ErrInvalidTopology, cause, detail)
}
