package enrollment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"dynamicflow/internal/signing"
)

const (
	InstanceRequestSchema = 1
	InstanceRequestDomain = "dynamicflow/instance-request/v1"
	ControlRequestSchema  = 1
	ControlRequestDomain  = "dynamicflow/control-request/v1"
)

var (
	ErrInvalidInstanceRequest = errors.New("invalid signed instance request")
	ErrInvalidControlRequest  = errors.New("invalid signed control request")
)

// InstanceRequest signs the exact HTTP intent and body digest. secrets are not
// part of this type, so it is safe for redacted audit metadata.
type InstanceRequest struct {
	Schema     int    `json:"schema"`
	Instance   string `json:"instance"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodyDigest string `json:"body_digest"`
}

type SignedInstanceRequest struct {
	Request   InstanceRequest   `json:"request"`
	Signature signing.Signature `json:"signature"`
}

// ControlRequest authenticates a single operator-to-serving HTTP action. it
// deliberately has a signature domain and trust key distinct from release and
// desired-state signing, so a deploy/control key cannot forge release content.
type ControlRequest struct {
	Schema     int    `json:"schema"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodyDigest string `json:"body_digest"`
}

type SignedControlRequest struct {
	Request   ControlRequest    `json:"request"`
	Signature signing.Signature `json:"signature"`
}

func NewSignedInstanceRequest(privateKey ed25519.PrivateKey, instance, method, path string, body []byte, now time.Time) (SignedInstanceRequest, error) {
	nonce, err := randomToken(32)
	if err != nil {
		return SignedInstanceRequest{}, err
	}
	request := InstanceRequest{
		Schema: InstanceRequestSchema, Instance: instance, Timestamp: now.UTC().Unix(), Nonce: nonce,
		Method: strings.ToUpper(method), Path: path, BodyDigest: bodyDigest(body),
	}
	if err := validateInstanceRequest(request); err != nil {
		return SignedInstanceRequest{}, err
	}
	signature, err := signing.SignCanonical(privateKey, InstanceRequestDomain, request)
	if err != nil {
		return SignedInstanceRequest{}, err
	}
	return SignedInstanceRequest{Request: request, Signature: signature}, nil
}

func NewSignedControlRequest(privateKey ed25519.PrivateKey, method, path string, body []byte, now time.Time) (SignedControlRequest, error) {
	return NewSignedControlRequestDigest(privateKey, method, path, bodyDigest(body), now)
}

// NewSignedControlRequestDigest authenticates a pre-hashed streaming body.
// callers must still compare the received stream with this digest before
// committing any mutation.
func NewSignedControlRequestDigest(privateKey ed25519.PrivateKey, method, path, digest string, now time.Time) (SignedControlRequest, error) {
	nonce, err := randomToken(32)
	if err != nil {
		return SignedControlRequest{}, err
	}
	request := ControlRequest{
		Schema: ControlRequestSchema, Timestamp: now.UTC().Unix(), Nonce: nonce,
		Method: strings.ToUpper(method), Path: path, BodyDigest: digest,
	}
	if err := validateControlRequest(request); err != nil {
		return SignedControlRequest{}, err
	}
	signature, err := signing.SignCanonical(privateKey, ControlRequestDomain, request)
	if err != nil {
		return SignedControlRequest{}, err
	}
	return SignedControlRequest{Request: request, Signature: signature}, nil
}

// VerifyInstanceRequest authenticates the exact request and then durably burns
// its nonce. replay protection survives serving restarts and concurrent calls.
func (store *Store) VerifyInstanceRequest(signed SignedInstanceRequest, publicKey ed25519.PublicKey, expectedInstance, method, path string, body []byte, maxSkew time.Duration) error {
	if err := validateInstanceRequest(signed.Request); err != nil {
		return err
	}
	if !validIdentifier(expectedInstance) || signed.Request.Instance != expectedInstance ||
		signed.Request.Method != strings.ToUpper(method) || signed.Request.Path != path ||
		signed.Request.BodyDigest != bodyDigest(body) {
		return ErrBinding
	}
	if maxSkew <= 0 || maxSkew > 24*time.Hour {
		return ErrInvalidInstanceRequest
	}
	now := store.now().UTC()
	oldest := now.Add(-maxSkew).Unix()
	newest := now.Add(maxSkew).Unix()
	if signed.Request.Timestamp < oldest || signed.Request.Timestamp > newest {
		return ErrStaleRequest
	}
	if err := signing.VerifyCanonical(publicKey, InstanceRequestDomain, signed.Request, signed.Signature); err != nil {
		return fmt.Errorf("verify instance request: %w", err)
	}
	nonceKey := "instance\x00" + signed.Request.Instance + "\x00" + signed.Request.Nonce
	legacyNonceKey := signed.Request.Instance + "\x00" + signed.Request.Nonce
	return store.withLockedState(true, func(state *diskState) (bool, error) {
		lockedNow := store.now().UTC()
		if signed.Request.Timestamp < lockedNow.Add(-maxSkew).Unix() ||
			signed.Request.Timestamp > lockedNow.Add(maxSkew).Unix() {
			return false, ErrStaleRequest
		}
		unixNow := lockedNow.Unix()
		for key, expiresAt := range state.Nonces {
			if expiresAt < unixNow {
				delete(state.Nonces, key)
			}
		}
		if _, exists := state.Nonces[nonceKey]; exists {
			return false, ErrReplay
		}
		if _, exists := state.Nonces[legacyNonceKey]; exists {
			return false, ErrReplay
		}
		if len(state.Nonces) >= maxNonceCount {
			return false, fmt.Errorf("%w: replay cache capacity reached", ErrInvalidStore)
		}
		// Timestamp granularity is one second and the accepted freshness
		// interval is inclusive. retain the nonce through the last second in
		// which the signed timestamp can still pass verification.
		state.Nonces[nonceKey] = time.Unix(signed.Request.Timestamp, 0).UTC().Add(maxSkew).Unix()
		return true, nil
	})
}

// VerifyControlRequest authenticates the exact admin request and durably burns
// its nonce in the same crash-safe store used by enrollment. it never accepts
// bearer credentials or URL secrets.
func (store *Store) VerifyControlRequest(signed SignedControlRequest, publicKey ed25519.PublicKey, method, path string, body []byte, maxSkew time.Duration) error {
	return store.VerifyControlRequestDigest(signed, publicKey, method, path, bodyDigest(body), maxSkew)
}

// VerifyControlRequestDigest verifies and burns a signed streaming request
// intent before the potentially large body is read. the handler must verify
// that the complete received body hashes to expectedBodyDigest before commit.
func (store *Store) VerifyControlRequestDigest(signed SignedControlRequest, publicKey ed25519.PublicKey, method, path, expectedBodyDigest string, maxSkew time.Duration) error {
	if err := validateControlRequest(signed.Request); err != nil {
		return err
	}
	if !digestRE.MatchString(expectedBodyDigest) || signed.Request.Method != strings.ToUpper(method) || signed.Request.Path != path || signed.Request.BodyDigest != expectedBodyDigest {
		return ErrBinding
	}
	if maxSkew <= 0 || maxSkew > 24*time.Hour {
		return ErrInvalidControlRequest
	}
	now := store.now().UTC()
	if signed.Request.Timestamp < now.Add(-maxSkew).Unix() || signed.Request.Timestamp > now.Add(maxSkew).Unix() {
		return ErrStaleRequest
	}
	if err := signing.VerifyCanonical(publicKey, ControlRequestDomain, signed.Request, signed.Signature); err != nil {
		return fmt.Errorf("verify control request: %w", err)
	}
	nonceKey := "control\x00operator\x00" + signed.Request.Nonce
	legacyNonceKey := "control\x00" + signed.Request.Nonce
	return store.withLockedState(true, func(state *diskState) (bool, error) {
		lockedNow := store.now().UTC()
		if signed.Request.Timestamp < lockedNow.Add(-maxSkew).Unix() ||
			signed.Request.Timestamp > lockedNow.Add(maxSkew).Unix() {
			return false, ErrStaleRequest
		}
		unixNow := lockedNow.Unix()
		for key, expiresAt := range state.Nonces {
			if expiresAt < unixNow {
				delete(state.Nonces, key)
			}
		}
		if _, exists := state.Nonces[nonceKey]; exists {
			return false, ErrReplay
		}
		if _, exists := state.Nonces[legacyNonceKey]; exists {
			return false, ErrReplay
		}
		if len(state.Nonces) >= maxNonceCount {
			return false, fmt.Errorf("%w: replay cache capacity reached", ErrInvalidStore)
		}
		state.Nonces[nonceKey] = time.Unix(signed.Request.Timestamp, 0).UTC().Add(maxSkew).Unix()
		return true, nil
	})
}

func validateInstanceRequest(request InstanceRequest) error {
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 || request.Schema != InstanceRequestSchema || !validIdentifier(request.Instance) ||
		request.Timestamp <= 0 || !validMethod(request.Method) || !validRequestPath(request.Path) || !digestRE.MatchString(request.BodyDigest) {
		return ErrInvalidInstanceRequest
	}
	return nil
}

func validateControlRequest(request ControlRequest) error {
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 || request.Schema != ControlRequestSchema || request.Timestamp <= 0 ||
		!validMethod(request.Method) || !validRequestPath(request.Path) || !digestRE.MatchString(request.BodyDigest) {
		return ErrInvalidControlRequest
	}
	return nil
}

func validMethod(method string) bool {
	if method == "" || method != strings.ToUpper(method) {
		return false
	}
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func validRequestPath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n\x00") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && parsed.IsAbs() == false && parsed.Host == ""
}

func bodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}
