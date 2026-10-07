package controlruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dynamicflow/internal/signing"
)

const (
	SessionResponseSchema   = 1
	AttestationCommandV1    = "dynamicflow-attest-v1"
	MaxSessionCommandBytes  = 256
	MaxSSHConnectionBytes   = 256
	MaxSessionResponseBytes = 2 << 10
)

var (
	// ErrSessionDenied is the only public result for an invalid forced-command
	// request, execution identity, SSH transport context or state-root binding.
	// It deliberately carries no rejected input or underlying error.
	ErrSessionDenied = errors.New("Control session denied")

	// ErrSessionUnavailable is the only public result for unreadable, unsafe,
	// invalid, expired or unauthentic active Control state. It deliberately
	// does not distinguish filesystem failures from signature failures.
	ErrSessionUnavailable = errors.New("Control attestation unavailable")

	sessionSystemIDRE = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	sessionControlRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sessionNonceRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SessionConfig binds the ForceCommand handler to one exact canonical state
// root. Production uses DefaultStateRoot; tests may bind an isolated fixture.
type SessionConfig struct {
	StateRoot string
}

// SessionRequest represents the fixed --state-root value passed by the
// installer-owned ForceCommand. All attestation fields come exclusively from
// SSH_ORIGINAL_COMMAND and cannot be supplied through this API.
type SessionRequest struct {
	StateRoot string
}

// SessionIdentity is obtained from the operating system without trusting USER
// or other client-influenced environment variables.
type SessionIdentity struct {
	Username     string
	UID          int
	EffectiveUID int
}

// SessionDependencies are narrow read-only seams for deterministic tests.
// Production implementations read two SSH environment variables, the local
// account database and one protected envelope file. There is deliberately no
// process runner, shell, network client or write callback.
type SessionDependencies struct {
	LookupEnvironment  func(string) (string, bool)
	CurrentIdentity    func() (SessionIdentity, error)
	ReadActiveEnvelope func(string) ([]byte, error)
	Now                func() time.Time
}

// SessionResponse is the complete public attestation response. It contains no
// route, key, address, path, command, environment or error-detail field.
type SessionResponse struct {
	Schema         int       `json:"schema"`
	System         string    `json:"system"`
	Control        string    `json:"control"`
	Generation     uint64    `json:"generation"`
	EnvelopeSHA256 string    `json:"envelope_sha256"`
	Nonce          string    `json:"nonce"`
	ObservedAt     time.Time `json:"observed_at"`
}

// Session implements the read-only ForceCommand attestation boundary.
type Session struct {
	stateRoot    string
	dependencies SessionDependencies
}

type attestationRequest struct {
	system     string
	control    string
	generation uint64
	nonce      string
}

// NewSession constructs the production session bound to the exact state root
// embedded in controlpolicy.ForcedSession.
func NewSession() *Session {
	session, err := NewSessionWithDependencies(
		SessionConfig{StateRoot: DefaultStateRoot},
		defaultSessionDependencies(),
	)
	if err != nil {
		// The production configuration consists exclusively of compile-time
		// constants and package-owned functions. Keep callers free from a
		// constructor error that can never be actionable at runtime.
		return nil
	}
	return session
}

// NewSessionWithDependencies constructs a session with read-only injectable
// dependencies. The configured root remains immutable for the Session's
// lifetime and every Execute request must match it byte-for-byte.
func NewSessionWithDependencies(configuration SessionConfig, dependencies SessionDependencies) (*Session, error) {
	if !safeAbsolutePath(configuration.StateRoot) ||
		dependencies.LookupEnvironment == nil ||
		dependencies.CurrentIdentity == nil ||
		dependencies.ReadActiveEnvelope == nil ||
		dependencies.Now == nil {
		return nil, ErrSessionDenied
	}
	return &Session{
		stateRoot:    configuration.StateRoot,
		dependencies: dependencies,
	}, nil
}

// Execute authenticates one exact attestation request and returns canonical
// JSON. It performs no mutation, process execution or network access. On any
// failure it returns no response bytes and one fixed public error.
func (session *Session) Execute(ctx context.Context, request SessionRequest) ([]byte, error) {
	if session == nil || ctx == nil || session.dependencies.LookupEnvironment == nil ||
		session.dependencies.CurrentIdentity == nil || session.dependencies.ReadActiveEnvelope == nil ||
		session.dependencies.Now == nil || !safeAbsolutePath(session.stateRoot) ||
		request.StateRoot != session.stateRoot || !safeAbsolutePath(request.StateRoot) {
		return nil, ErrSessionDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrSessionUnavailable
	}

	originalCommand, present := session.dependencies.LookupEnvironment("SSH_ORIGINAL_COMMAND")
	if !present {
		return nil, ErrSessionDenied
	}
	parsed, valid := parseAttestationCommand(originalCommand)
	if !valid {
		return nil, ErrSessionDenied
	}

	sshConnection, present := session.dependencies.LookupEnvironment("SSH_CONNECTION")
	if !present || !validSSHConnection(sshConnection) {
		return nil, ErrSessionDenied
	}

	identity, err := session.dependencies.CurrentIdentity()
	if err != nil || identity.Username != ManagementUser || identity.UID <= 0 ||
		identity.EffectiveUID <= 0 || identity.UID != identity.EffectiveUID {
		return nil, ErrSessionDenied
	}

	envelopeJSON, err := session.dependencies.ReadActiveEnvelope(session.stateRoot)
	if err != nil || len(envelopeJSON) == 0 || len(envelopeJSON) > MaxEnvelopeBytes {
		return nil, ErrSessionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrSessionUnavailable
	}
	envelope, err := ParseCanonical(envelopeJSON)
	if err != nil {
		return nil, ErrSessionUnavailable
	}
	policy := envelope.Policy.Policy
	if policy.SystemID != parsed.system || policy.ControlName != parsed.control ||
		policy.Generation != parsed.generation {
		return nil, ErrSessionUnavailable
	}

	observedAt := session.dependencies.Now().UTC().Truncate(time.Second)
	if observedAt.Unix() <= 0 || observedAt.Nanosecond() != 0 {
		return nil, ErrSessionUnavailable
	}
	if err := VerifyEnvelope(
		envelope,
		observedAt,
		parsed.system,
		parsed.control,
		parsed.generation,
	); err != nil {
		return nil, ErrSessionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrSessionUnavailable
	}

	digest := sha256.Sum256(envelopeJSON)
	response := SessionResponse{
		Schema:         SessionResponseSchema,
		System:         parsed.system,
		Control:        parsed.control,
		Generation:     parsed.generation,
		EnvelopeSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		Nonce:          parsed.nonce,
		ObservedAt:     observedAt,
	}
	encoded, err := signing.CanonicalJSON(response)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxSessionResponseBytes {
		return nil, ErrSessionUnavailable
	}
	return append([]byte(nil), encoded...), nil
}

func parseAttestationCommand(command string) (attestationRequest, bool) {
	var result attestationRequest
	if len(command) == 0 || len(command) > MaxSessionCommandBytes ||
		strings.ContainsAny(command, "\t\r\n\x00") {
		return result, false
	}
	fields := strings.Split(command, " ")
	if len(fields) != 5 || fields[0] != AttestationCommandV1 ||
		!sessionSystemIDRE.MatchString(fields[1]) ||
		!sessionControlRE.MatchString(fields[2]) ||
		!sessionNonceRE.MatchString(fields[4]) {
		return result, false
	}
	generation, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != fields[3] {
		return result, false
	}
	return attestationRequest{
		system: fields[1], control: fields[2], generation: generation, nonce: fields[4],
	}, true
}

func validSSHConnection(value string) bool {
	if len(value) == 0 || len(value) > MaxSSHConnectionBytes ||
		strings.ContainsAny(value, "\t\r\n\x00") {
		return false
	}
	fields := strings.Split(value, " ")
	if len(fields) != 4 {
		return false
	}
	client, clientErr := netip.ParseAddr(fields[0])
	server, serverErr := netip.ParseAddr(fields[2])
	if clientErr != nil || serverErr != nil || client.IsUnspecified() || server.IsUnspecified() {
		return false
	}
	return validCanonicalPort(fields[1]) && validCanonicalPort(fields[3])
}

func validCanonicalPort(value string) bool {
	port, err := strconv.ParseUint(value, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == value
}
