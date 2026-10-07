// Package controlpolicy defines the signed, narrowly scoped forwarding policy
// installed on a Dynamicflow Control node. The policy contains public trust
// material only; it never carries SSH private keys, bearer tokens or commands.
package controlpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
)

const (
	SchemaVersion     = 1
	SignatureDomain   = "dynamicflow.control-policy.v1"
	MaxCanonicalBytes = 256 << 10
	MaxPolicyLifetime = 31 * 24 * time.Hour
	MaxRoutes         = 512
	ForcedSession     = "/usr/local/bin/flow control-runtime session --state-root /var/lib/dynamicflow/control"
)

var (
	ErrInvalidPolicy = errors.New("invalid Control policy")
	ErrPolicyExpired = errors.New("Control policy is not currently valid")
	ErrPolicyBinding = errors.New("Control policy binding mismatch")
	ErrGeneration    = errors.New("Control policy generation rollback")
	ErrNonCanonical  = errors.New("Control policy JSON is not canonical")

	systemIDRE = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type KeyState string

const (
	KeyActive  KeyState = "active"
	KeyPending KeyState = "pending"
)

type RouteKind string

const (
	RouteSSH   RouteKind = "ssh"
	RouteHTTPS RouteKind = "https"
)

type Action string

const (
	ActionInstanceBootstrap Action = "instance_bootstrap"
	ActionControlMesh       Action = "control_mesh"
	ActionSSH               Action = "ssh"
	ActionExec              Action = "exec"
	ActionVNC               Action = "vnc"
	ActionServingAdmin      Action = "serving_admin"
)

// ManagementKey is an owner-local public SSH identity authorized on Control.
// A policy has exactly one active key and at most one overlapping pending key.
type ManagementKey struct {
	Name        string   `json:"name"`
	Generation  uint64   `json:"generation"`
	State       KeyState `json:"state"`
	PublicKey   string   `json:"public_key"`
	Fingerprint string   `json:"fingerprint"`
}

// Route is one explicitly pinned destination available to SSH stdio
// forwarding. TLS/SSH authentication remains end-to-end at the operator.
type Route struct {
	Target             string    `json:"target"`
	Kind               RouteKind `json:"kind"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	HostKeyFingerprint string    `json:"host_key_fingerprint,omitempty"`
	TLSPin             string    `json:"tls_pin,omitempty"`
	Actions            []Action  `json:"actions"`
}

type Policy struct {
	SchemaVersion  int             `json:"schema_version"`
	SystemID       string          `json:"system_id"`
	ControlName    string          `json:"control_name"`
	Generation     uint64          `json:"generation"`
	IssuedAt       time.Time       `json:"issued_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	ManagementKeys []ManagementKey `json:"management_keys"`
	Routes         []Route         `json:"routes"`
}

type SignedPolicy struct {
	Policy    Policy            `json:"policy"`
	Signature signing.Signature `json:"signature"`
}

func Validate(policy Policy) error {
	if policy.SchemaVersion != SchemaVersion || !systemIDRE.MatchString(policy.SystemID) ||
		!nameRE.MatchString(policy.ControlName) || policy.Generation == 0 ||
		!validTime(policy.IssuedAt) || !validTime(policy.ExpiresAt) ||
		!policy.ExpiresAt.After(policy.IssuedAt) || policy.ExpiresAt.Sub(policy.IssuedAt) > MaxPolicyLifetime ||
		len(policy.ManagementKeys) < 1 || len(policy.ManagementKeys) > 2 || len(policy.Routes) > MaxRoutes {
		return ErrInvalidPolicy
	}
	active, pending := 0, 0
	keyNames := make(map[string]struct{}, len(policy.ManagementKeys))
	keyFingerprints := make(map[string]struct{}, len(policy.ManagementKeys))
	for index, key := range policy.ManagementKeys {
		normalized, fingerprint, err := sshkeys.ValidateEd25519PublicKey(key.PublicKey)
		fields := strings.Fields(normalized)
		if err != nil || len(fields) < 2 || key.PublicKey != strings.Join(fields[:2], " ") ||
			!nameRE.MatchString(key.Name) || key.Generation == 0 || fingerprint != key.Fingerprint {
			return fmt.Errorf("%w: invalid management key", ErrInvalidPolicy)
		}
		switch key.State {
		case KeyActive:
			active++
		case KeyPending:
			pending++
		default:
			return fmt.Errorf("%w: invalid management key state", ErrInvalidPolicy)
		}
		identity := key.Name + "\x00" + strconv.FormatUint(key.Generation, 10)
		if _, duplicate := keyNames[identity]; duplicate {
			return fmt.Errorf("%w: duplicate management key", ErrInvalidPolicy)
		}
		if _, duplicate := keyFingerprints[key.Fingerprint]; duplicate {
			return fmt.Errorf("%w: shared management key fingerprint", ErrInvalidPolicy)
		}
		keyNames[identity] = struct{}{}
		keyFingerprints[key.Fingerprint] = struct{}{}
		if index > 0 && !managementKeyLess(policy.ManagementKeys[index-1], key) {
			return fmt.Errorf("%w: management keys are not canonical", ErrInvalidPolicy)
		}
	}
	if active != 1 || pending > 1 || len(policy.ManagementKeys) == 2 && pending != 1 {
		return fmt.Errorf("%w: policy requires one active and at most one pending key", ErrInvalidPolicy)
	}
	routeNames := make(map[string]struct{}, len(policy.Routes))
	addresses := make(map[string]struct{}, len(policy.Routes))
	for index, route := range policy.Routes {
		if !nameRE.MatchString(route.Target) || route.Target == policy.ControlName ||
			!safeHost(route.Host) || route.Port < 1 || route.Port > 65535 || len(route.Actions) == 0 {
			return fmt.Errorf("%w: invalid route endpoint", ErrInvalidPolicy)
		}
		if _, duplicate := routeNames[route.Target]; duplicate {
			return fmt.Errorf("%w: duplicate route target", ErrInvalidPolicy)
		}
		address := route.Host + "\x00" + strconv.Itoa(route.Port)
		if _, duplicate := addresses[address]; duplicate {
			return fmt.Errorf("%w: duplicate route address", ErrInvalidPolicy)
		}
		routeNames[route.Target] = struct{}{}
		addresses[address] = struct{}{}
		if index > 0 && policy.Routes[index-1].Target >= route.Target {
			return fmt.Errorf("%w: routes are not canonical", ErrInvalidPolicy)
		}
		switch route.Kind {
		case RouteSSH:
			if !validFingerprint(route.HostKeyFingerprint) || route.TLSPin != "" {
				return fmt.Errorf("%w: SSH route lacks an exclusive host-key pin", ErrInvalidPolicy)
			}
		case RouteHTTPS:
			if !validFingerprint(route.TLSPin) || route.HostKeyFingerprint != "" {
				return fmt.Errorf("%w: HTTPS route lacks an exclusive TLS pin", ErrInvalidPolicy)
			}
		default:
			return fmt.Errorf("%w: invalid route kind", ErrInvalidPolicy)
		}
		seenActions := make(map[Action]struct{}, len(route.Actions))
		for actionIndex, action := range route.Actions {
			if !validRouteAction(route.Kind, action) {
				return fmt.Errorf("%w: action is not valid for route kind", ErrInvalidPolicy)
			}
			if _, duplicate := seenActions[action]; duplicate {
				return fmt.Errorf("%w: duplicate route action", ErrInvalidPolicy)
			}
			seenActions[action] = struct{}{}
			if actionIndex > 0 && route.Actions[actionIndex-1] >= action {
				return fmt.Errorf("%w: route actions are not canonical", ErrInvalidPolicy)
			}
		}
	}
	return nil
}

func Sign(policy Policy, privateKey ed25519.PrivateKey) (SignedPolicy, error) {
	if err := Validate(policy); err != nil {
		return SignedPolicy{}, err
	}
	signature, err := signing.SignCanonical(privateKey, SignatureDomain, policy)
	if err != nil {
		return SignedPolicy{}, err
	}
	return SignedPolicy{Policy: clonePolicy(policy), Signature: signature}, nil
}

// Verify checks the signature, exact target binding, monotonic generation and
// exclusive validity window. expires_at is an exclusive upper bound.
func Verify(signed SignedPolicy, publicKey ed25519.PublicKey, now time.Time, expectedSystemID, expectedControlName string, minimumGeneration uint64) error {
	if err := Validate(signed.Policy); err != nil {
		return err
	}
	if signed.Policy.SystemID != expectedSystemID || signed.Policy.ControlName != expectedControlName {
		return ErrPolicyBinding
	}
	if minimumGeneration > 0 && signed.Policy.Generation < minimumGeneration {
		return ErrGeneration
	}
	now = now.UTC()
	if !validTime(now) || now.Before(signed.Policy.IssuedAt) || !now.Before(signed.Policy.ExpiresAt) {
		return ErrPolicyExpired
	}
	if err := signing.VerifyCanonical(publicKey, SignatureDomain, signed.Policy, signed.Signature); err != nil {
		return err
	}
	return nil
}

func MarshalCanonical(signed SignedPolicy) ([]byte, error) {
	if err := Validate(signed.Policy); err != nil {
		return nil, err
	}
	encoded, err := signing.CanonicalJSON(signed)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxCanonicalBytes {
		return nil, ErrInvalidPolicy
	}
	return encoded, nil
}

func ParseCanonical(data []byte) (SignedPolicy, error) {
	var signed SignedPolicy
	if len(data) == 0 || len(data) > MaxCanonicalBytes {
		return signed, ErrInvalidPolicy
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedPolicy{}, ErrInvalidPolicy
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SignedPolicy{}, ErrInvalidPolicy
	}
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil || !bytes.Equal(data, canonical) {
		return SignedPolicy{}, ErrNonCanonical
	}
	if err := Validate(signed.Policy); err != nil {
		return SignedPolicy{}, err
	}
	return signed, nil
}

// RenderAuthorizedKeys creates a deterministic forced-command key set. With
// zero routes, port forwarding remains disabled by restrict. With routes,
// forwarding is re-enabled only for the exact permitopen allowlist.
func RenderAuthorizedKeys(policy Policy) ([]byte, error) {
	if err := Validate(policy); err != nil {
		return nil, err
	}
	var output strings.Builder
	for _, key := range policy.ManagementKeys {
		options := []string{`restrict`, `command="` + ForcedSession + `"`}
		if len(policy.Routes) > 0 {
			options = append(options, "port-forwarding")
			for _, route := range policy.Routes {
				options = append(options, `permitopen="`+permitAddress(route.Host, route.Port)+`"`)
			}
		}
		fmt.Fprintf(&output, "%s %s dynamicflow-control:%s:g%d:%s\n",
			strings.Join(options, ","), key.PublicKey, key.Name, key.Generation, key.State)
	}
	return []byte(output.String()), nil
}

func managementKeyLess(left, right ManagementKey) bool {
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.Generation < right.Generation
}

func validRouteAction(kind RouteKind, action Action) bool {
	switch kind {
	case RouteSSH:
		switch action {
		case ActionInstanceBootstrap, ActionControlMesh, ActionSSH, ActionExec, ActionVNC:
			return true
		}
	case RouteHTTPS:
		return action == ActionServingAdmin
	}
	return false
}

func validTime(value time.Time) bool {
	if value.IsZero() || value.Unix() <= 0 || value.Nanosecond() != 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(decoded) == 32 && value == "SHA256:"+base64.RawStdEncoding.EncodeToString(decoded)
}

func safeHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || len(host) > 253 ||
		strings.ContainsAny(host, " /\\@%[]\t\r\n\x00\"") || strings.HasPrefix(host, "-") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == host
	}
	numericAddress := true
	for _, character := range host {
		if !((character >= '0' && character <= '9') || character == '.') {
			numericAddress = false
			break
		}
	}
	if numericAddress {
		// Reject legacy numeric IPv4 spellings rather than allowing libc/OpenSSH
		// to reinterpret them differently from the policy verifier.
		return false
	}
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func permitAddress(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func clonePolicy(policy Policy) Policy {
	result := policy
	result.ManagementKeys = append([]ManagementKey(nil), policy.ManagementKeys...)
	result.Routes = make([]Route, len(policy.Routes))
	for index, route := range policy.Routes {
		result.Routes[index] = route
		result.Routes[index].Actions = append([]Action(nil), route.Actions...)
	}
	return result
}

// SortCanonical is an explicit construction helper. Validation itself never
// silently sorts signed input.
func SortCanonical(policy Policy) Policy {
	result := clonePolicy(policy)
	sort.Slice(result.ManagementKeys, func(left, right int) bool {
		return managementKeyLess(result.ManagementKeys[left], result.ManagementKeys[right])
	})
	sort.Slice(result.Routes, func(left, right int) bool { return result.Routes[left].Target < result.Routes[right].Target })
	for index := range result.Routes {
		sort.Slice(result.Routes[index].Actions, func(left, right int) bool {
			return result.Routes[index].Actions[left] < result.Routes[index].Actions[right]
		})
	}
	return result
}
