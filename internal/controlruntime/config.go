// package controlruntime validates the public installation envelope and
// renders the narrow SSH gateway configuration used by a control node. OS
// mutation is intentionally kept outside this pure verification boundary.
package controlruntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/signing"
)

const (
	EnvelopeSchema    = 1
	MaxEnvelopeBytes  = 512 << 10
	ManagementUser    = "dynamicflow-control"
	DefaultStateRoot  = "/var/lib/dynamicflow/control"
	DefaultExecutable = "/usr/local/bin/flow"
	ActiveBundleName  = "active"
)

var (
	ErrInvalidEnvelope = errors.New("invalid Control installation envelope")
	ErrEnvelopeBinding = errors.New("Control installation envelope binding mismatch")
)

type InstallEnvelope struct {
	SchemaVersion          int                        `json:"schema_version"`
	SystemID               string                     `json:"system_id"`
	ControlName            string                     `json:"control_name"`
	ControlPolicyKeyID     string                     `json:"control_policy_key_id"`
	ControlPolicyPublicPEM string                     `json:"control_policy_public_pem"`
	Policy                 controlpolicy.SignedPolicy `json:"policy"`
}

// RenderedFiles contains public verified content only. destinations are fixed
// by the privileged installer and are deliberately not represented here.
type RenderedFiles struct {
	EnvelopeJSON    []byte
	PolicyJSON      []byte
	PolicyPublicPEM []byte
	AuthorizedKeys  []byte
	SSHDPolicy      []byte
}

func NewEnvelope(systemID, controlName string, publicPEM []byte, signed controlpolicy.SignedPolicy) (InstallEnvelope, error) {
	publicKey, err := signing.ParsePublicPEM(publicPEM)
	if err != nil {
		return InstallEnvelope{}, ErrInvalidEnvelope
	}
	keyID, err := signing.KeyID(publicKey)
	if err != nil {
		return InstallEnvelope{}, err
	}
	envelope := InstallEnvelope{
		SchemaVersion: EnvelopeSchema, SystemID: systemID, ControlName: controlName,
		ControlPolicyKeyID: keyID, ControlPolicyPublicPEM: string(publicPEM), Policy: signed,
	}
	if _, err := validateEnvelopeShape(envelope); err != nil {
		return InstallEnvelope{}, err
	}
	return envelope, nil
}

// VerifyEnvelope authenticates the policy against the independently delivered
// control-policy public root and exact system/node/generation binding.
func VerifyEnvelope(envelope InstallEnvelope, now time.Time, expectedSystemID, expectedControlName string, minimumGeneration uint64) error {
	publicKey, err := validateEnvelopeShape(envelope)
	if err != nil {
		return err
	}
	if envelope.SystemID != expectedSystemID || envelope.ControlName != expectedControlName {
		return ErrEnvelopeBinding
	}
	return controlpolicy.Verify(envelope.Policy, publicKey, now, expectedSystemID, expectedControlName, minimumGeneration)
}

func MarshalCanonical(envelope InstallEnvelope) ([]byte, error) {
	if _, err := validateEnvelopeShape(envelope); err != nil {
		return nil, err
	}
	encoded, err := signing.CanonicalJSON(envelope)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxEnvelopeBytes {
		return nil, ErrInvalidEnvelope
	}
	return encoded, nil
}

func ParseCanonical(data []byte) (InstallEnvelope, error) {
	var envelope InstallEnvelope
	if len(data) == 0 || len(data) > MaxEnvelopeBytes {
		return envelope, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return InstallEnvelope{}, ErrInvalidEnvelope
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InstallEnvelope{}, ErrInvalidEnvelope
	}
	canonical, err := signing.CanonicalJSON(envelope)
	if err != nil || !bytes.Equal(data, canonical) {
		return InstallEnvelope{}, ErrInvalidEnvelope
	}
	if _, err := validateEnvelopeShape(envelope); err != nil {
		return InstallEnvelope{}, err
	}
	return envelope, nil
}

// Render verifies before producing any privileged file content. the caller
// must still atomically install these bytes with root ownership, safe modes,
// sshd -t validation and rollback on reload failure.
func Render(envelope InstallEnvelope, now time.Time, expectedSystemID, expectedControlName string, minimumGeneration uint64, stateRoot string) (RenderedFiles, error) {
	if !safeAbsolutePath(stateRoot) {
		return RenderedFiles{}, ErrInvalidEnvelope
	}
	if err := VerifyEnvelope(envelope, now, expectedSystemID, expectedControlName, minimumGeneration); err != nil {
		return RenderedFiles{}, err
	}
	envelopeJSON, err := MarshalCanonical(envelope)
	if err != nil {
		return RenderedFiles{}, err
	}
	policyJSON, err := controlpolicy.MarshalCanonical(envelope.Policy)
	if err != nil {
		return RenderedFiles{}, err
	}
	authorized, err := controlpolicy.RenderAuthorizedKeys(envelope.Policy.Policy)
	if err != nil {
		return RenderedFiles{}, err
	}
	sshd, err := renderSSHDPolicy(stateRoot)
	if err != nil {
		return RenderedFiles{}, err
	}
	return RenderedFiles{
		EnvelopeJSON: append([]byte(nil), envelopeJSON...), PolicyJSON: append([]byte(nil), policyJSON...),
		PolicyPublicPEM: []byte(envelope.ControlPolicyPublicPEM), AuthorizedKeys: authorized, SSHDPolicy: []byte(sshd),
	}, nil
}

func validateEnvelopeShape(envelope InstallEnvelope) (ed25519.PublicKey, error) {
	if envelope.SchemaVersion != EnvelopeSchema || envelope.SystemID == "" || envelope.ControlName == "" ||
		envelope.SystemID != envelope.Policy.Policy.SystemID || envelope.ControlName != envelope.Policy.Policy.ControlName ||
		envelope.ControlPolicyKeyID == "" || envelope.ControlPolicyPublicPEM == "" {
		return nil, ErrInvalidEnvelope
	}
	publicKey, err := signing.ParsePublicPEM([]byte(envelope.ControlPolicyPublicPEM))
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	keyID, err := signing.KeyID(publicKey)
	if err != nil || keyID != envelope.ControlPolicyKeyID || envelope.Policy.Signature.KeyID != keyID {
		return nil, ErrInvalidEnvelope
	}
	if err := controlpolicy.Validate(envelope.Policy.Policy); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func renderSSHDPolicy(stateRoot string) (string, error) {
	if !safeAbsolutePath(stateRoot) {
		return "", ErrInvalidEnvelope
	}
	// the privileged installer activates all policy files as one directory.
	// keeping AuthorizedKeysFile inside that directory means a policy/key
	// rotation cannot expose a mixture of generations.
	authorizedKeys := filepath.Join(stateRoot, ActiveBundleName, "authorized_keys")
	return `# Managed by Dynamicflow. Local edits are replaced by a newer signed policy.
Match User ` + ManagementUser + `
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ChallengeResponseAuthentication no
    AuthorizedKeysFile ` + authorizedKeys + `
    ForceCommand ` + controlpolicy.ForcedSession + `
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    AllowTcpForwarding local
    GatewayPorts no
    PermitTunnel no
    PermitUserEnvironment no
    PermitUserRC no
`, nil
}

func safeAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" &&
		!strings.ContainsAny(value, " \t\r\n\x00\\\"'%")
}

func (files RenderedFiles) ValidateNoPrivateMaterial() error {
	for name, data := range map[string][]byte{
		"envelope": files.EnvelopeJSON, "policy": files.PolicyJSON, "public": files.PolicyPublicPEM,
		"authorized_keys": files.AuthorizedKeys, "sshd": files.SSHDPolicy,
	} {
		if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("BEGIN OPENSSH PRIVATE")) {
			return fmt.Errorf("%w: %s contains private-key marker", ErrInvalidEnvelope, name)
		}
	}
	return nil
}
