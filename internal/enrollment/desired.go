package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"dynamicflow/internal/signing"
)

const (
	DesiredStateSchema     = 1
	DesiredSignatureDomain = "dynamicflow/desired-state/v1"
)

var (
	ErrInvalidDesiredState = errors.New("invalid desired state")
	digestRE               = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// DesiredState binds one instance to one profile and immutable release set.
// AuthorizedSSHKeys contains public OpenSSH Ed25519 keys only.
type DesiredState struct {
	Schema            int      `json:"schema"`
	Instance          string   `json:"instance"`
	Profile           string   `json:"profile"`
	Generation        uint64   `json:"generation"`
	ReleaseSet        string   `json:"release_set"`
	AuthorizedSSHKeys []string `json:"authorized_ssh_keys"`
	Revoked           bool     `json:"revoked,omitempty"`
	IssuedAt          int64    `json:"issued_at"`
	ExpiresAt         int64    `json:"expires_at"`
}

type SignedDesiredState struct {
	State     DesiredState      `json:"state"`
	Signature signing.Signature `json:"signature"`
}

// DesiredExpectation prevents a valid document intended for another instance,
// profile or older generation from being accepted.
type DesiredExpectation struct {
	Instance      string
	Profile       string
	ReleaseSet    string
	MinGeneration uint64
	Now           time.Time
	MaxClockSkew  time.Duration
}

func SignDesiredState(state DesiredState, privateKey ed25519.PrivateKey) (SignedDesiredState, error) {
	state = normalizeDesiredState(state)
	if err := validateDesiredState(state); err != nil {
		return SignedDesiredState{}, err
	}
	signature, err := signing.SignCanonical(privateKey, DesiredSignatureDomain, state)
	if err != nil {
		return SignedDesiredState{}, err
	}
	return SignedDesiredState{State: state, Signature: signature}, nil
}

func VerifyDesiredState(signed SignedDesiredState, publicKey ed25519.PublicKey, expected DesiredExpectation) error {
	return verifyDesiredState(signed, publicKey, expected, false)
}

// VerifyDesiredStateForRenewal authenticates a previously issued document as
// the predecessor of a strictly newer desired state. Expiry is intentionally
// ignored in this one narrow mode, while signature, instance/profile binding,
// generation rollback and future-issued checks remain mandatory. Installers
// must always use VerifyDesiredState instead.
func VerifyDesiredStateForRenewal(signed SignedDesiredState, publicKey ed25519.PublicKey, expected DesiredExpectation) error {
	return verifyDesiredState(signed, publicKey, expected, true)
}

func verifyDesiredState(signed SignedDesiredState, publicKey ed25519.PublicKey, expected DesiredExpectation, allowExpired bool) error {
	if err := validateDesiredState(signed.State); err != nil {
		return err
	}
	if err := signing.VerifyCanonical(publicKey, DesiredSignatureDomain, signed.State, signed.Signature); err != nil {
		return fmt.Errorf("verify desired state: %w", err)
	}
	if !equalStringSlices(signed.State.AuthorizedSSHKeys, normalizeDesiredState(signed.State).AuthorizedSSHKeys) {
		return fmt.Errorf("%w: authorized keys are not canonical", ErrInvalidDesiredState)
	}
	if signed.State.Instance != expected.Instance || signed.State.Profile != expected.Profile {
		return ErrBinding
	}
	if expected.ReleaseSet != "" && signed.State.ReleaseSet != expected.ReleaseSet {
		return ErrBinding
	}
	if signed.State.Generation < expected.MinGeneration {
		return fmt.Errorf("%w: desired-state generation rollback", ErrInvalidDesiredState)
	}
	now := expected.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := expected.MaxClockSkew
	if skew < 0 {
		return ErrInvalidDesiredState
	}
	unixNow := now.UTC().Unix()
	if !allowExpired && unixNow >= signed.State.ExpiresAt {
		return ErrExpired
	}
	if signed.State.IssuedAt > now.UTC().Add(skew).Unix() {
		return ErrStaleRequest
	}
	return nil
}

func validateDesiredState(state DesiredState) error {
	if state.Schema != DesiredStateSchema || !validIdentifier(state.Instance) || !validIdentifier(state.Profile) ||
		state.Generation == 0 || !digestRE.MatchString(state.ReleaseSet) || state.IssuedAt <= 0 || state.ExpiresAt <= state.IssuedAt ||
		len(state.AuthorizedSSHKeys) > 32 || (state.Revoked && len(state.AuthorizedSSHKeys) != 0) ||
		(!state.Revoked && len(state.AuthorizedSSHKeys) == 0) {
		return ErrInvalidDesiredState
	}
	seen := make(map[string]struct{}, len(state.AuthorizedSSHKeys))
	for _, key := range state.AuthorizedSSHKeys {
		if len(key) > 8192 || strings.ContainsAny(key, "\r\n\x00") || !validOpenSSHEd25519(key) {
			return ErrInvalidDesiredState
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate authorized key", ErrInvalidDesiredState)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func normalizeDesiredState(state DesiredState) DesiredState {
	result := state
	result.AuthorizedSSHKeys = append([]string(nil), state.AuthorizedSSHKeys...)
	sort.Strings(result.AuthorizedSSHKeys)
	return result
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validOpenSSHEd25519(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || strings.Join(fields, " ") != line {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	reader := bytes.NewReader(blob)
	algorithm, ok := readSSHString(reader)
	if !ok || string(algorithm) != "ssh-ed25519" {
		return false
	}
	key, ok := readSSHString(reader)
	return ok && len(key) == ed25519.PublicKeySize && reader.Len() == 0
}

func readSSHString(reader *bytes.Reader) ([]byte, bool) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size > uint32(reader.Len()) {
		return nil, false
	}
	value := make([]byte, size)
	if _, err := reader.Read(value); err != nil {
		return nil, false
	}
	return value, true
}
