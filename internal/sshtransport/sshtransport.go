// Package sshtransport builds the four explicitly supported SSH transports:
// the one-time direct bootstrap of the first control, the pre-ready proof of a
// staged management identity, the permanent direct management connection to a
// verified ready control, and an end-to-end target connection routed through
// that control.
//
// The package writes only managed OpenSSH configuration and known-hosts files.
// It never starts SSH, invokes a shell, or provides a direct-target fallback.
package sshtransport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

var (
	ErrInvalidTransport                 = errors.New("invalid SSH transport")
	ErrCapabilityRequired               = errors.New("first-control bootstrap capability is required")
	ErrPendingControlCapabilityRequired = errors.New("pending Control proof capability is required")
	ErrReadyControlCapabilityRequired   = errors.New("verified ready-control capability is required")
	ErrUnsafeEndpoint                   = errors.New("unsafe SSH endpoint")
	ErrUnsafeIdentity                   = errors.New("unsafe SSH private identity")
	ErrManagementIdentity               = errors.New("distinct Control management identity is required")
	ErrPendingControlState              = errors.New("Control must be in the pending management-proof phase")
	ErrDistinctRouteRequired            = errors.New("control and target must use distinct endpoints and keys")
	ErrHostKeyBinding                   = errors.New("SSH route host-key binding mismatch")
	ErrPrivatePathJSON                  = errors.New("private identity paths cannot be serialized as JSON")
	ErrVNCForward                       = errors.New("invalid managed VNC forward")
)

var (
	aliasRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	userRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// Capability is the explicit authority required by the one-time direct
// bootstrap transport.
type Capability string

const CapabilityFirstControlBootstrap Capability = "first_control_bootstrap"

// PendingControlProofCapability is deliberately not assignment-compatible
// with either the one-time bootstrap Capability or ReadyControlCapability. It
// authorizes only construction of the pre-ready management-key proof path.
type PendingControlProofCapability uint16

const CapabilityPendingControlProof PendingControlProofCapability = 0x5043

// ReadyControlCapability is deliberately not assignment-compatible with the
// first-Control bootstrap Capability. It authorizes only the direct
// management path to a Control whose ready state was verified by the caller.
type ReadyControlCapability uint8

const CapabilityVerifiedReadyControl ReadyControlCapability = 1

// ReadyControlUser is the sole non-root account accepted by both staged proof
// and permanent operator-to-Control management transports.
const ReadyControlUser = "dynamicflow-control"

// PendingControlPhase is an explicit lifecycle assertion supplied by the
// authoritative caller. The pending proof transport rejects the ready phase
// and the zero value rather than silently treating either as pre-ready.
type PendingControlPhase string

const PhasePendingManagementProof PendingControlPhase = "pending_management_proof"

// EndpointRole prevents a target endpoint from being passed to either
// direct-control method (and vice versa).
type EndpointRole string

const (
	RoleControl EndpointRole = "control"
	RoleTarget  EndpointRole = "target"
)

// PrivateIdentity wraps a validated local private-key path. Its path is
// intentionally unavailable to encoding/json and is revalidated at build time.
type PrivateIdentity struct {
	path string
}

// NewPrivateIdentity validates a local private-key file without reading its
// contents. The file must remain an owner-only, single-link regular file.
func NewPrivateIdentity(path string) (PrivateIdentity, error) {
	if _, err := validatePrivateIdentity(path); err != nil {
		return PrivateIdentity{}, err
	}
	return PrivateIdentity{path: path}, nil
}

func (PrivateIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrPrivatePathJSON
}

// Endpoint contains only public connection metadata except for Identity,
// which is omitted from JSON. HostKey must be the canonical two-field
// OpenSSH Ed25519 public host key.
type Endpoint struct {
	Alias               string          `json:"alias"`
	Role                EndpointRole    `json:"role"`
	Host                string          `json:"host"`
	Port                int             `json:"port"`
	User                string          `json:"user"`
	Identity            PrivateIdentity `json:"-"`
	IdentityFingerprint string          `json:"identity_fingerprint"`
	HostKey             string          `json:"host_key"`
	HostKeyFingerprint  string          `json:"host_key_fingerprint"`
}

// Route binds both pinned host identities to one routed target connection.
type Route struct {
	Control                   Endpoint `json:"control"`
	Target                    Endpoint `json:"target"`
	ControlHostKeyFingerprint string   `json:"control_host_key_fingerprint"`
	TargetHostKeyFingerprint  string   `json:"target_host_key_fingerprint"`
}

// ReadyControl binds one verified ready Control to the long-lived owner-local
// management identity. BootstrapIdentityFingerprint is retained solely to
// prove that the management identity is a different key; it is public data.
type ReadyControl struct {
	Control                      Endpoint `json:"control"`
	ControlHostKeyFingerprint    string   `json:"control_host_key_fingerprint"`
	BootstrapIdentityFingerprint string   `json:"bootstrap_identity_fingerprint"`
}

// PendingControlProof binds the staged management identity to the exact
// already-pinned Control host while that Control is explicitly not ready.
// BootstrapIdentityFingerprint is public comparison material only. The
// private management-key path remains non-serializable through Endpoint.
type PendingControlProof struct {
	Control                      Endpoint            `json:"control"`
	ControlHostKeyFingerprint    string              `json:"control_host_key_fingerprint"`
	BootstrapIdentityFingerprint string              `json:"bootstrap_identity_fingerprint"`
	Phase                        PendingControlPhase `json:"phase"`
}

// Invocation is an immutable SSH argv prefix. Callers may append only their
// explicit remote command after Arguments; transport options stay managed.
type Invocation struct {
	arguments   []string
	routed      bool
	vnc         bool
	destination string
}

// Arguments returns a defensive copy of the managed SSH argument vector.
func (invocation Invocation) Arguments() []string {
	return append([]string(nil), invocation.arguments...)
}

// Builder writes managed transport files into a private localstate store.
type Builder struct {
	store *localstate.Store
}

func NewBuilder(store *localstate.Store) *Builder {
	return &Builder{store: store}
}

// BuildDirectFirstControl is the sole direct path that may use the bootstrap
// identity before the Control runtime is installed. It requires the literal
// one-shot bootstrap capability and can only target a control endpoint.
func (builder *Builder) BuildDirectFirstControl(capability Capability, control Endpoint) (Invocation, error) {
	if capability != CapabilityFirstControlBootstrap {
		return Invocation{}, ErrCapabilityRequired
	}
	validated, err := validateEndpoint(control, RoleControl)
	if err != nil {
		return Invocation{}, err
	}
	managedAlias := controlAlias(validated.Alias)
	return builder.writeManaged("first-control", validated.Alias, []validatedEndpoint{validated}, managedAlias, "", true)
}

// BuildDirectPendingControlProof builds the sole pre-ready connection that may
// authenticate with a staged Control management key. It reuses the exact
// independently pinned Control host identity, fixes the remote user to
// dynamicflow-control, and rejects reuse of the bootstrap identity.
//
// The result is only an argv prefix in a separate content-addressed namespace.
// This method does not start a process, add a command, configure a jump, or
// permit forwarding. The caller must later append its fixed attestation
// command, which the installed remote ForceCommand mediates.
func (builder *Builder) BuildDirectPendingControlProof(capability PendingControlProofCapability, pending PendingControlProof) (Invocation, error) {
	if capability != CapabilityPendingControlProof {
		return Invocation{}, ErrPendingControlCapabilityRequired
	}
	if pending.Phase != PhasePendingManagementProof {
		return Invocation{}, ErrPendingControlState
	}
	control, err := validateEndpoint(pending.Control, RoleControl)
	if err != nil {
		return Invocation{}, err
	}
	if control.User != ReadyControlUser ||
		!validFingerprint(pending.BootstrapIdentityFingerprint) ||
		control.IdentityFingerprint == pending.BootstrapIdentityFingerprint {
		return Invocation{}, ErrManagementIdentity
	}
	if pending.ControlHostKeyFingerprint != control.HostKeyFingerprint {
		return Invocation{}, ErrHostKeyBinding
	}
	return builder.writeManaged(
		"pending-control-proof", control.Alias, []validatedEndpoint{control},
		controlAlias(control.Alias), "", false,
	)
}

// BuildDirectReadyControl builds the permanent operator-to-Control management
// transport. Its distinct capability and ReadyControl input cannot be
// accidentally substituted for the one-time bootstrap API. The endpoint must
// use the fixed unprivileged management account, an independently pinned
// Ed25519 host key, and a local management identity distinct from bootstrap.
//
// This method only writes managed files. It never starts ssh, a shell, or any
// other process.
func (builder *Builder) BuildDirectReadyControl(capability ReadyControlCapability, ready ReadyControl) (Invocation, error) {
	if capability != CapabilityVerifiedReadyControl {
		return Invocation{}, ErrReadyControlCapabilityRequired
	}
	control, err := validateEndpoint(ready.Control, RoleControl)
	if err != nil {
		return Invocation{}, err
	}
	if control.User != ReadyControlUser ||
		!validFingerprint(ready.BootstrapIdentityFingerprint) ||
		control.IdentityFingerprint == ready.BootstrapIdentityFingerprint {
		return Invocation{}, ErrManagementIdentity
	}
	if ready.ControlHostKeyFingerprint != control.HostKeyFingerprint {
		return Invocation{}, ErrHostKeyBinding
	}
	return builder.writeManaged(
		"ready-control", control.Alias, []validatedEndpoint{control},
		controlAlias(control.Alias), "", false,
	)
}

// BuildRoutedTarget creates an end-to-end target transport whose only jump is
// the managed control alias. There is deliberately no direct-target API.
func (builder *Builder) BuildRoutedTarget(route Route) (Invocation, error) {
	control, err := validateEndpoint(route.Control, RoleControl)
	if err != nil {
		return Invocation{}, fmt.Errorf("control: %w", err)
	}
	target, err := validateEndpoint(route.Target, RoleTarget)
	if err != nil {
		return Invocation{}, fmt.Errorf("target: %w", err)
	}
	if route.ControlHostKeyFingerprint != control.HostKeyFingerprint ||
		route.TargetHostKeyFingerprint != target.HostKeyFingerprint {
		return Invocation{}, ErrHostKeyBinding
	}
	if err := validateDistinct(control, target); err != nil {
		return Invocation{}, err
	}
	return builder.writeManaged(
		"routes", target.Alias, []validatedEndpoint{control, target},
		targetAlias(target.Alias), controlAlias(control.Alias), true,
	)
}

// WithVNCForward enables exactly one final-target loopback forward. It cannot
// be applied to the direct control bootstrap or widened to another address.
func WithVNCForward(invocation Invocation, localPort int) (Invocation, error) {
	if !invocation.routed || invocation.vnc || localPort < 1024 || localPort > 65535 ||
		len(invocation.arguments) < 5 || invocation.destination == "" ||
		invocation.arguments[len(invocation.arguments)-1] != invocation.destination {
		return Invocation{}, ErrVNCForward
	}
	result := invocation
	result.arguments = append([]string(nil), invocation.arguments[:len(invocation.arguments)-1]...)
	result.arguments = append(result.arguments,
		"-o", "ClearAllForwardings=no",
		"-o", "ExitOnForwardFailure=yes",
		"-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:5901", localPort),
		invocation.destination,
	)
	result.vnc = true
	return result, nil
}

type validatedEndpoint struct {
	Endpoint
	canonicalHostKey string
	identityInfo     identityInfo
}

type identityInfo struct {
	device uint64
	inode  uint64
}

func validateEndpoint(endpoint Endpoint, expectedRole EndpointRole) (validatedEndpoint, error) {
	if endpoint.Role != expectedRole || !aliasRE.MatchString(endpoint.Alias) || !safeHost(endpoint.Host) ||
		!userRE.MatchString(endpoint.User) || endpoint.User == "root" ||
		endpoint.Port < 1 || endpoint.Port > 65535 {
		return validatedEndpoint{}, ErrUnsafeEndpoint
	}
	info, err := validatePrivateIdentity(endpoint.Identity.path)
	if err != nil {
		return validatedEndpoint{}, err
	}
	if !validFingerprint(endpoint.IdentityFingerprint) {
		return validatedEndpoint{}, fmt.Errorf("%w: invalid identity fingerprint", ErrUnsafeIdentity)
	}
	normalized, fingerprint, err := sshkeys.ValidateEd25519PublicKey(endpoint.HostKey)
	if err != nil {
		return validatedEndpoint{}, fmt.Errorf("%w: invalid Ed25519 host key", ErrUnsafeEndpoint)
	}
	fields := strings.Fields(normalized)
	if len(fields) < 2 {
		return validatedEndpoint{}, fmt.Errorf("%w: invalid Ed25519 host key", ErrUnsafeEndpoint)
	}
	canonical := strings.Join(fields[:2], " ")
	if endpoint.HostKey != canonical || endpoint.HostKeyFingerprint != fingerprint ||
		!validFingerprint(endpoint.HostKeyFingerprint) {
		return validatedEndpoint{}, ErrHostKeyBinding
	}
	return validatedEndpoint{Endpoint: endpoint, canonicalHostKey: canonical, identityInfo: info}, nil
}

func validateDistinct(control, target validatedEndpoint) error {
	if control.Alias == target.Alias ||
		control.Host == target.Host && control.Port == target.Port ||
		control.Identity.path == target.Identity.path ||
		control.identityInfo == target.identityInfo ||
		control.IdentityFingerprint == target.IdentityFingerprint ||
		control.HostKeyFingerprint == target.HostKeyFingerprint {
		return ErrDistinctRouteRequired
	}
	return nil
}

func validatePrivateIdentity(path string) (identityInfo, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) || strings.ContainsRune(path, '\x00') ||
		strings.ContainsAny(path, "\\\"'%#") ||
		strings.IndexFunc(path, unicode.IsSpace) >= 0 ||
		strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return identityInfo{}, ErrUnsafeIdentity
	}
	info, err := os.Lstat(path)
	if err != nil {
		return identityInfo{}, fmt.Errorf("%w: %v", ErrUnsafeIdentity, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != localstate.FileMode || int(stat.Uid) != os.Geteuid() ||
		stat.Nlink != 1 {
		return identityInfo{}, ErrUnsafeIdentity
	}
	return identityInfo{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func (builder *Builder) writeManaged(kind, name string, endpoints []validatedEndpoint, destination, jump string, renderProxyJump bool) (Invocation, error) {
	if builder == nil || builder.store == nil || !aliasRE.MatchString(name) {
		return Invocation{}, ErrInvalidTransport
	}
	version := transportVersion(kind, endpoints, destination, jump, renderProxyJump)
	base := filepath.Join("sshtransport", kind, name, version)
	configRelative := filepath.Join(base, "ssh_config")
	knownHostsRelative := filepath.Join(base, "known_hosts")
	configPath, err := builder.store.Path(configRelative)
	if err != nil {
		return Invocation{}, err
	}
	knownHostsPath, err := builder.store.Path(knownHostsRelative)
	if err != nil {
		return Invocation{}, err
	}
	if !safeManagedPath(configPath) || !safeManagedPath(knownHostsPath) {
		return Invocation{}, ErrInvalidTransport
	}
	knownHosts := renderKnownHosts(endpoints)
	config := renderConfig(endpoints, knownHostsPath, jump, renderProxyJump)
	lock := filepath.Join("sshtransport", kind, name, ".lock")
	if err := builder.store.WithLock(lock, func() error {
		if err := builder.store.WriteFile(knownHostsRelative, []byte(knownHosts)); err != nil {
			return err
		}
		return builder.store.WriteFile(configRelative, []byte(config))
	}); err != nil {
		return Invocation{}, err
	}
	return Invocation{
		arguments: []string{"-F", configPath, "-S", "none", destination},
		routed:    jump != "", destination: destination,
	}, nil
}

func renderKnownHosts(endpoints []validatedEndpoint) string {
	var result strings.Builder
	for index, endpoint := range endpoints {
		alias := controlAlias(endpoint.Alias)
		if index == len(endpoints)-1 && len(endpoints) > 1 {
			alias = targetAlias(endpoint.Alias)
		}
		fmt.Fprintf(&result, "%s %s\n", alias, endpoint.canonicalHostKey)
	}
	return result.String()
}

func renderConfig(endpoints []validatedEndpoint, knownHostsPath, jump string, renderProxyJump bool) string {
	var result strings.Builder
	for index, endpoint := range endpoints {
		alias := controlAlias(endpoint.Alias)
		proxyJump := "none"
		if index == len(endpoints)-1 && len(endpoints) > 1 {
			alias = targetAlias(endpoint.Alias)
			proxyJump = jump
		}
		fmt.Fprintf(&result, "Host %s\n", alias)
		fmt.Fprintf(&result, "    HostName %s\n", endpoint.Host)
		fmt.Fprintf(&result, "    Port %d\n", endpoint.Port)
		fmt.Fprintf(&result, "    User %s\n", endpoint.User)
		fmt.Fprintf(&result, "    IdentityFile %s\n", quoteConfigPath(endpoint.Identity.path))
		fmt.Fprintf(&result, "    HostKeyAlias %s\n", alias)
		fmt.Fprintf(&result, "    UserKnownHostsFile %s\n", quoteConfigPath(knownHostsPath))
		result.WriteString("    GlobalKnownHostsFile /dev/null\n")
		result.WriteString("    BatchMode yes\n")
		result.WriteString("    IdentitiesOnly yes\n")
		result.WriteString("    IdentityAgent none\n")
		result.WriteString("    StrictHostKeyChecking yes\n")
		result.WriteString("    HostKeyAlgorithms ssh-ed25519\n")
		result.WriteString("    PubkeyAcceptedAlgorithms ssh-ed25519\n")
		result.WriteString("    PasswordAuthentication no\n")
		result.WriteString("    KbdInteractiveAuthentication no\n")
		result.WriteString("    ChallengeResponseAuthentication no\n")
		result.WriteString("    PreferredAuthentications publickey\n")
		result.WriteString("    ForwardAgent no\n")
		result.WriteString("    ForwardX11 no\n")
		result.WriteString("    ClearAllForwardings yes\n")
		result.WriteString("    UpdateHostKeys no\n")
		result.WriteString("    VerifyHostKeyDNS no\n")
		result.WriteString("    CheckHostIP no\n")
		result.WriteString("    ControlMaster no\n")
		result.WriteString("    ControlPath none\n")
		result.WriteString("    ControlPersist no\n")
		result.WriteString("    PermitLocalCommand no\n")
		result.WriteString("    CanonicalizeHostname no\n")
		if renderProxyJump {
			fmt.Fprintf(&result, "    ProxyJump %s\n", proxyJump)
		}
		result.WriteByte('\n')
	}
	return result.String()
}

func transportVersion(kind string, endpoints []validatedEndpoint, destination, jump string, renderProxyJump bool) string {
	hash := sha256.New()
	writeHashField(hash, kind)
	writeHashField(hash, destination)
	writeHashField(hash, jump)
	writeHashField(hash, fmt.Sprint(renderProxyJump))
	for _, endpoint := range endpoints {
		for _, value := range []string{
			endpoint.Alias, string(endpoint.Role), endpoint.Host, fmt.Sprint(endpoint.Port), endpoint.User,
			endpoint.Identity.path, endpoint.IdentityFingerprint,
			endpoint.canonicalHostKey, endpoint.HostKeyFingerprint,
		} {
			writeHashField(hash, value)
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeHashField(writer hashWriter, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

func controlAlias(alias string) string {
	return "flow-control-" + alias
}

func targetAlias(alias string) string {
	return "flow-target-" + alias
}

func safeHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || len(host) > 253 ||
		strings.ContainsAny(host, " /\\@%[]\t\r\n\x00") || strings.HasPrefix(host, "-") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == host
	}
	numeric := true
	for _, character := range host {
		if !(character >= '0' && character <= '9' || character == '.') {
			numeric = false
			break
		}
	}
	if numeric {
		// Avoid libc/OpenSSH legacy numeric-address interpretations such as
		// one-component IPv4 or octal-looking dotted forms.
		return false
	}
	// Endpoint hosts are already canonicalized by topology. Retaining the same
	// conservative ASCII grammar here prevents ssh_config token injection.
	if strings.HasSuffix(host, ".") || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
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

func safeManagedPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\r\n\x00%")
}

func quoteConfigPath(path string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(path) + `"`
}

// Ensure compile-time enforcement that the private path cannot silently gain a
// default JSON representation through future field exports.
var _ json.Marshaler = PrivateIdentity{}
