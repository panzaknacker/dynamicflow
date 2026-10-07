// Package instanceclient implements the deliberately narrow, outbound-HTTPS
// client used by a Dynamicflow instance. It owns a stable instance identity,
// consumes a one-time enrollment credential, verifies independently signed
// release and desired-state documents, and authenticates subsequent desired
// and status requests with that identity.
package instanceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
)

const (
	defaultRequestTimeout = 20 * time.Second
	defaultMaxClockSkew   = 5 * time.Minute
	operationLockPath     = ".instance-client.lock"

	maxSecretInputBytes = 256
	maxManifestBody     = 1 << 20
	maxDesiredBody      = 256 << 10
	maxEnrollmentBody   = 256 << 10
	maxStatusBody       = 256 << 10
	maxLogBody          = 128 << 10
	maxErrorBody        = 16 << 10
)

var (
	ErrInvalidConfig            = errors.New("invalid instance client configuration")
	ErrAlreadyEnrolled          = errors.New("instance is already enrolled")
	ErrNotEnrolled              = errors.New("instance is not enrolled")
	ErrInvalidCredential        = errors.New("invalid enrollment credential")
	ErrResponseTooLarge         = errors.New("serving response is too large")
	ErrUnexpectedResponse       = errors.New("unexpected serving response")
	ErrEnrollmentOutcomeUnknown = errors.New("enrollment may have been consumed")
	ErrClosed                   = errors.New("instance client is closed")
	ErrRevoked                  = errors.New("instance is revoked")

	identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	errorCodeRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	keyIDRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config contains only non-secret, durable client configuration. The
// enrollment secret is deliberately supplied to Enroll through an io.Reader
// and is never part of Config, a URL, an environment variable, or state.
type Config struct {
	StateDir         string
	BaseURL          string
	CACertificatePEM []byte
	TLSPin           string
	DesiredPublicKey ed25519.PublicKey
	ReleasePublicKey ed25519.PublicKey
	Instance         string
	Profile          string
	// ExpectedIdentityKeyID prevents recovery commands from creating a new
	// identity if an already-enrolled VM has lost its key files.
	ExpectedIdentityKeyID string
	RequestTimeout        time.Duration
	MaxClockSkew          time.Duration
	Clock                 func() time.Time
}

// EnrollmentResult is the fully verified result of enrollment. Release and
// desired state have both been checked before State is committed.
type EnrollmentResult struct {
	Release release.SignedManifest        `json:"release"`
	Desired enrollment.SignedDesiredState `json:"desired"`
	State   State                         `json:"state"`
}

// Client is safe for concurrent use within one process. A private on-disk
// flock additionally serializes enrollment and state changes across clients
// and processes that share StateDir.
type Client struct {
	mu sync.Mutex

	store            *localstate.Store
	identity         identity
	state            State
	instance         string
	profile          string
	baseURL          *url.URL
	httpClient       *http.Client
	transport        *http.Transport
	desiredPublicKey ed25519.PublicKey
	releasePublicKey ed25519.PublicKey
	now              func() time.Time
	maxClockSkew     time.Duration
	closed           bool
}

type enrollRequest struct {
	EnrollmentID         string `json:"enrollment_id"`
	Secret               string `json:"secret"`
	Instance             string `json:"instance"`
	Profile              string `json:"profile"`
	InstancePublicKeyPEM string `json:"instance_public_key_pem"`
}

type enrollResponse struct {
	Instance      string                        `json:"instance"`
	Profile       string                        `json:"profile"`
	IdentityKeyID string                        `json:"identity_key_id"`
	Desired       enrollment.SignedDesiredState `json:"desired"`
}

type statusResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error struct {
		Code    string          `json:"code"`
		Message json.RawMessage `json:"message"`
	} `json:"error"`
}

// HTTPError reports only a bounded, syntactically safe API error code. Server
// messages and bodies are intentionally excluded so reflected credentials or
// other untrusted response data can never reach caller logs through Error().
type HTTPError struct {
	StatusCode int
	Code       string
}

func (err *HTTPError) Error() string {
	if err.Code == "" {
		return fmt.Sprintf("%v: HTTP %d", ErrUnexpectedResponse, err.StatusCode)
	}
	return fmt.Sprintf("%v: HTTP %d (%s)", ErrUnexpectedResponse, err.StatusCode, err.Code)
}

func (err *HTTPError) Unwrap() error { return ErrUnexpectedResponse }

type enrollmentOutcomeError struct{ cause error }

func (err *enrollmentOutcomeError) Error() string {
	return ErrEnrollmentOutcomeUnknown.Error() + ": " + err.cause.Error()
}

func (err *enrollmentOutcomeError) Unwrap() []error {
	return []error{ErrEnrollmentOutcomeUnknown, err.cause}
}

// New validates the complete trust configuration, creates or reuses the
// stable identity, and loads the atomically persisted public state. Existing
// identity material is never silently replaced.
func New(config Config) (*Client, error) {
	if config.StateDir == "" || !identifierRE.MatchString(config.Instance) || !identifierRE.MatchString(config.Profile) ||
		len(config.DesiredPublicKey) != ed25519.PublicKeySize || len(config.ReleasePublicKey) != ed25519.PublicKeySize ||
		bytes.Equal(config.DesiredPublicKey, config.ReleasePublicKey) ||
		(config.ExpectedIdentityKeyID != "" && !keyIDRE.MatchString(config.ExpectedIdentityKeyID)) {
		return nil, ErrInvalidConfig
	}
	timeout := config.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout < time.Second || timeout > 2*time.Minute {
		return nil, fmt.Errorf("%w: request timeout must be between one second and two minutes", ErrInvalidConfig)
	}
	maxClockSkew := config.MaxClockSkew
	if maxClockSkew == 0 {
		maxClockSkew = defaultMaxClockSkew
	}
	if maxClockSkew < time.Second || maxClockSkew > time.Hour {
		return nil, fmt.Errorf("%w: clock skew must be between one second and one hour", ErrInvalidConfig)
	}
	now := config.Clock
	if now == nil {
		now = time.Now
	}
	baseURL, err := parseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	httpClient, transport, err := newHTTPClient(baseURL, config.CACertificatePEM, config.TLSPin, timeout)
	if err != nil {
		return nil, err
	}
	store, err := localstate.Open(config.StateDir)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("open instance state: %w", err)
	}
	_, stateReadErr := store.ReadFile(statePath)
	stateExists := stateReadErr == nil
	if stateReadErr != nil && !errors.Is(stateReadErr, os.ErrNotExist) {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("inspect instance state: %w", stateReadErr)
	}
	instanceIdentity, err := ensureIdentity(store, !stateExists && config.ExpectedIdentityKeyID == "")
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if config.ExpectedIdentityKeyID != "" && instanceIdentity.keyID != config.ExpectedIdentityKeyID {
		clearBytes(instanceIdentity.privateKey)
		transport.CloseIdleConnections()
		return nil, ErrIdentityConflict
	}
	var state State
	err = store.WithLock(operationLockPath, func() error {
		var loadErr error
		state, loadErr = loadOrCreateState(
			store, config.Instance, config.Profile, instanceIdentity.keyID,
			now().UTC(), config.DesiredPublicKey,
		)
		return loadErr
	})
	if err != nil {
		clearBytes(instanceIdentity.privateKey)
		transport.CloseIdleConnections()
		return nil, err
	}
	return &Client{
		store: store, identity: instanceIdentity, state: state,
		instance: config.Instance, profile: config.Profile, baseURL: baseURL,
		httpClient: httpClient, transport: transport,
		desiredPublicKey: append(ed25519.PublicKey(nil), config.DesiredPublicKey...),
		releasePublicKey: append(ed25519.PublicKey(nil), config.ReleasePublicKey...),
		now:              now, maxClockSkew: maxClockSkew,
	}, nil
}

// State returns a defensive copy of the last state observed by this Client.
func (client *Client) State() State {
	client.mu.Lock()
	defer client.mu.Unlock()
	return cloneState(client.state)
}

// IdentityPublicPEM returns the public half of the stable instance identity.
func (client *Client) IdentityPublicPEM() []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]byte(nil), client.identity.publicPEM...)
}

func (client *Client) IdentityKeyID() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.identity.keyID
}

// Close drops idle connections and overwrites the Client's in-memory private
// key buffer. The durable 0600 identity remains available for the next run.
func (client *Client) Close() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil
	}
	client.closed = true
	client.transport.CloseIdleConnections()
	clearBytes(client.identity.privateKey)
	client.identity.privateKey = nil
	return nil
}

// Enroll consumes one enrollment ID and secret exactly once. The secret is
// read only after the release endpoint has passed TLS pinning and signature
// verification. Call FetchDesired after an ambiguous network failure: serving
// may have consumed the credential even if its response did not arrive.
func (client *Client) Enroll(ctx context.Context, enrollmentID string, secretReader io.Reader) (EnrollmentResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.ensureOpenLocked(); err != nil {
		return EnrollmentResult{}, err
	}
	if !validCredentialToken(enrollmentID, 16) || secretReader == nil {
		return EnrollmentResult{}, ErrInvalidCredential
	}
	var result EnrollmentResult
	err := client.store.WithLock(operationLockPath, func() error {
		if err := client.reloadStateLocked(); err != nil {
			return err
		}
		if client.state.Enrolled {
			return ErrAlreadyEnrolled
		}
		manifest, err := client.fetchReleaseManifestLocked(ctx)
		if err != nil {
			return err
		}
		secret, err := readEnrollmentSecret(secretReader)
		if err != nil {
			return err
		}
		defer clearBytes(secret)
		requestValue := enrollRequest{
			EnrollmentID:         enrollmentID,
			Secret:               string(secret),
			Instance:             client.instance,
			Profile:              client.profile,
			InstancePublicKeyPEM: string(client.identity.publicPEM),
		}
		body, err := signing.CanonicalJSON(requestValue)
		requestValue.Secret = ""
		if err != nil {
			return err
		}
		defer clearBytes(body)
		responseBody, err := client.doJSONLocked(ctx, http.MethodPost, "/v1/enroll", body, "", http.StatusCreated, maxEnrollmentBody)
		if err != nil {
			if enrollmentResponseMayHaveConsumed(err) {
				return &enrollmentOutcomeError{cause: err}
			}
			return err
		}
		defer clearBytes(responseBody)
		var response enrollResponse
		if err := decodeCanonicalJSON(responseBody, &response); err != nil {
			return &enrollmentOutcomeError{cause: fmt.Errorf("decode enrollment response: %w", err)}
		}
		if response.Instance != client.instance || response.Profile != client.profile || response.IdentityKeyID != client.identity.keyID {
			return &enrollmentOutcomeError{cause: enrollment.ErrBinding}
		}
		if err := client.verifyDesiredEnvelopeLocked(response.Desired); err != nil {
			return &enrollmentOutcomeError{cause: err}
		}
		if response.Desired.State.ReleaseSet != manifest.Manifest.SetID {
			manifest, err = client.fetchReleaseManifestByIDLocked(ctx, response.Desired.State.ReleaseSet)
			if err != nil {
				return &enrollmentOutcomeError{cause: err}
			}
		}
		if err := client.acceptDesiredLocked(response.Desired, manifest); err != nil {
			return &enrollmentOutcomeError{cause: err}
		}
		result = EnrollmentResult{Release: manifest, Desired: cloneSignedDesired(response.Desired), State: cloneState(client.state)}
		return nil
	})
	return result, err
}

func enrollmentResponseMayHaveConsumed(err error) bool {
	var httpError *HTTPError
	if errors.As(err, &httpError) {
		return httpError.Code == "desired_unavailable" || httpError.StatusCode >= http.StatusInternalServerError
	}
	// A transport or local response-processing failure after issuing the
	// non-replayable POST has an unknown server-side outcome.
	return true
}

// FetchDesired obtains the currently signed desired state using a fresh,
// instance-signed request. It intentionally also works before local Enrolled
// is true so a consumed enrollment with a lost response can be recovered.
func (client *Client) FetchDesired(ctx context.Context) (EnrollmentResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.ensureOpenLocked(); err != nil {
		return EnrollmentResult{}, err
	}
	var result EnrollmentResult
	err := client.store.WithLock(operationLockPath, func() error {
		if err := client.reloadStateLocked(); err != nil {
			return err
		}
		path := "/v1/instances/" + client.instance + "/desired"
		authorization, err := client.authorizationLocked(http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		responseBody, err := client.doJSONLocked(ctx, http.MethodGet, path, nil, authorization, http.StatusOK, maxDesiredBody)
		if err != nil {
			return err
		}
		defer clearBytes(responseBody)
		var desired enrollment.SignedDesiredState
		if err := decodeCanonicalJSON(responseBody, &desired); err != nil {
			return fmt.Errorf("decode desired state: %w", err)
		}
		if err := client.verifyDesiredEnvelopeLocked(desired); err != nil {
			return err
		}
		manifest, err := client.fetchReleaseManifestByIDLocked(ctx, desired.State.ReleaseSet)
		if err != nil {
			return err
		}
		if err := client.acceptDesiredLocked(desired, manifest); err != nil {
			return err
		}
		result = EnrollmentResult{Release: manifest, Desired: cloneSignedDesired(desired), State: cloneState(client.state)}
		return nil
	})
	return result, err
}

// ReportStatus validates all instance/profile/generation/release bindings,
// canonicalizes the report, and signs the exact POST path and body. It never
// opens an inbound connection or executes a remotely supplied command.
func (client *Client) ReportStatus(ctx context.Context, report serving.StatusReport) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.ensureOpenLocked(); err != nil {
		return err
	}
	return client.store.WithLock(operationLockPath, func() error {
		if err := client.reloadStateLocked(); err != nil {
			return err
		}
		if !client.state.Enrolled || client.state.Desired == nil {
			return ErrNotEnrolled
		}
		desired := client.state.Desired.State
		report = serving.NormalizeStatus(report)
		if err := serving.ValidateStatus(report); err != nil {
			return err
		}
		if report.Instance != client.instance || report.Profile != client.profile ||
			report.DesiredGeneration != desired.Generation || report.ReleaseSet != desired.ReleaseSet {
			return enrollment.ErrBinding
		}
		if desired.Revoked {
			if !serving.IsRevocationAcknowledgement(report) {
				return ErrRevoked
			}
		} else if serving.IsRevocationAcknowledgement(report) {
			return enrollment.ErrBinding
		}
		now := client.now().UTC()
		if report.ReportedAt < now.Add(-client.maxClockSkew).Unix() || report.ReportedAt > now.Add(client.maxClockSkew).Unix() {
			return enrollment.ErrStaleRequest
		}
		body, err := signing.CanonicalJSON(report)
		if err != nil {
			return err
		}
		defer clearBytes(body)
		if len(body) > maxStatusBody {
			return serving.ErrInvalidStatus
		}
		path := "/v1/instances/" + client.instance + "/status"
		authorization, err := client.authorizationLocked(http.MethodPost, path, body)
		if err != nil {
			return err
		}
		responseBody, err := client.doJSONLocked(ctx, http.MethodPost, path, body, authorization, http.StatusAccepted, maxErrorBody)
		if err != nil {
			return err
		}
		defer clearBytes(responseBody)
		var response statusResponse
		if err := decodeCanonicalJSON(responseBody, &response); err != nil || response.Status != "accepted" {
			return ErrUnexpectedResponse
		}
		return nil
	})
}

// ReportLogs uploads only the finite, sanitized LogEvent contract. It cannot
// transmit arbitrary stderr, URLs, enrollment material or secret-bearing text.
func (client *Client) ReportLogs(ctx context.Context, batch serving.LogBatch) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := client.ensureOpenLocked(); err != nil {
		return err
	}
	return client.store.WithLock(operationLockPath, func() error {
		if err := client.reloadStateLocked(); err != nil {
			return err
		}
		if !client.state.Enrolled || client.state.Desired == nil {
			return ErrNotEnrolled
		}
		if err := serving.ValidateLogBatch(batch); err != nil {
			return err
		}
		if batch.Instance != client.instance || batch.Profile != client.profile {
			return enrollment.ErrBinding
		}
		if client.state.Desired.State.Revoked {
			if !serving.IsRevocationLogBatch(batch) {
				return ErrRevoked
			}
		} else if serving.IsRevocationLogBatch(batch) {
			return enrollment.ErrBinding
		}
		now := client.now().UTC()
		for _, event := range batch.Events {
			if event.Timestamp < now.Add(-30*24*time.Hour).Unix() || event.Timestamp > now.Add(client.maxClockSkew).Unix() {
				return serving.ErrInvalidLog
			}
		}
		body, err := signing.CanonicalJSON(batch)
		if err != nil {
			return err
		}
		defer clearBytes(body)
		if len(body) > maxLogBody {
			return serving.ErrInvalidLog
		}
		path := "/v1/instances/" + client.instance + "/logs/" + batch.Component
		authorization, err := client.authorizationLocked(http.MethodPost, path, body)
		if err != nil {
			return err
		}
		responseBody, err := client.doJSONLocked(ctx, http.MethodPost, path, body, authorization, http.StatusAccepted, maxErrorBody)
		if err != nil {
			return err
		}
		defer clearBytes(responseBody)
		var response statusResponse
		if err := decodeCanonicalJSON(responseBody, &response); err != nil || response.Status != "accepted" {
			return ErrUnexpectedResponse
		}
		return nil
	})
}

func (client *Client) ensureOpenLocked() error {
	if client.closed {
		return ErrClosed
	}
	return nil
}

func (client *Client) reloadStateLocked() error {
	state, err := loadOrCreateState(
		client.store, client.instance, client.profile, client.identity.keyID,
		client.now().UTC(), client.desiredPublicKey,
	)
	if err != nil {
		return err
	}
	client.state = state
	return nil
}

func (client *Client) fetchReleaseManifestLocked(ctx context.Context) (release.SignedManifest, error) {
	return client.fetchReleaseManifestPathLocked(ctx, "/v1/releases/current/manifest", "")
}

func (client *Client) fetchReleaseManifestByIDLocked(ctx context.Context, setID string) (release.SignedManifest, error) {
	path, err := immutableReleaseManifestPath(setID)
	if err != nil {
		return release.SignedManifest{}, enrollment.ErrBinding
	}
	return client.fetchReleaseManifestPathLocked(ctx, path, setID)
}

func (client *Client) fetchReleaseManifestPathLocked(ctx context.Context, path, expectedSetID string) (release.SignedManifest, error) {
	body, err := client.doJSONLocked(ctx, http.MethodGet, path, nil, "", http.StatusOK, maxManifestBody)
	if err != nil {
		return release.SignedManifest{}, err
	}
	defer clearBytes(body)
	var signed release.SignedManifest
	if err := decodeCanonicalJSON(body, &signed); err != nil {
		return release.SignedManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := release.VerifyManifest(signed, client.releasePublicKey); err != nil {
		return release.SignedManifest{}, err
	}
	if expectedSetID != "" && signed.Manifest.SetID != expectedSetID {
		return release.SignedManifest{}, enrollment.ErrBinding
	}
	return signed, nil
}

func (client *Client) verifyDesiredEnvelopeLocked(signed enrollment.SignedDesiredState) error {
	minimum := uint64(1)
	if client.state.Desired != nil {
		minimum = client.state.Desired.State.Generation
	}
	return enrollment.VerifyDesiredState(signed, client.desiredPublicKey, enrollment.DesiredExpectation{
		Instance: client.instance, Profile: client.profile, MinGeneration: minimum,
		Now: client.now().UTC(), MaxClockSkew: client.maxClockSkew,
	})
}

func (client *Client) authorizationLocked(method, path string, body []byte) (string, error) {
	signed, err := enrollment.NewSignedInstanceRequest(
		client.identity.privateKey, client.instance, method, path, body, client.now().UTC(),
	)
	if err != nil {
		return "", err
	}
	return serving.EncodeAuthorization(signed)
}

func (client *Client) doJSONLocked(
	ctx context.Context,
	method, path string,
	body []byte,
	authorization string,
	expectedStatus int,
	responseLimit int64,
) ([]byte, error) {
	if ctx == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n\x00") || responseLimit <= 0 {
		return nil, ErrInvalidConfig
	}
	target := *client.baseURL
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create serving request: %w", err)
	}
	// A non-nil body with no GetBody prevents net/http from transparently
	// replaying even GETs. Callers explicitly retry with a fresh signed nonce.
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.GetBody = nil
	request.ContentLength = int64(len(body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "dynamicflow-instance/1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set(serving.AuthorizationHeader, authorization)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("serving request failed: %w", err)
	}
	defer response.Body.Close()
	limit := responseLimit
	if response.StatusCode != expectedStatus && limit > maxErrorBody {
		limit = maxErrorBody
	}
	if response.ContentLength > limit {
		return nil, ErrResponseTooLarge
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read serving response: %w", err)
	}
	if int64(len(responseBody)) > limit {
		clearBytes(responseBody)
		return nil, ErrResponseTooLarge
	}
	if response.StatusCode != expectedStatus {
		code := safeErrorCode(responseBody)
		clearBytes(responseBody)
		return nil, &HTTPError{StatusCode: response.StatusCode, Code: code}
	}
	if !isJSONContentType(response.Header.Get("Content-Type")) {
		clearBytes(responseBody)
		return nil, ErrUnexpectedResponse
	}
	return responseBody, nil
}

func readEnrollmentSecret(reader io.Reader) ([]byte, error) {
	input, err := io.ReadAll(io.LimitReader(reader, maxSecretInputBytes+1))
	if err != nil {
		clearBytes(input)
		return nil, fmt.Errorf("%w: could not read secret", ErrInvalidCredential)
	}
	if len(input) > maxSecretInputBytes {
		clearBytes(input)
		return nil, ErrInvalidCredential
	}
	if len(input) > 0 && input[len(input)-1] == '\n' {
		input = input[:len(input)-1]
		if len(input) > 0 && input[len(input)-1] == '\r' {
			input = input[:len(input)-1]
		}
	}
	if len(input) == 0 || bytes.IndexAny(input, "\r\n\x00 \t") >= 0 {
		clearBytes(input)
		return nil, ErrInvalidCredential
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(input))
	if err != nil || len(decoded) != 32 || string(input) != base64.RawURLEncoding.EncodeToString(decoded) {
		clearBytes(decoded)
		clearBytes(input)
		return nil, ErrInvalidCredential
	}
	clearBytes(decoded)
	return input, nil
}

func validCredentialToken(value string, decodedLength int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) == decodedLength && value == base64.RawURLEncoding.EncodeToString(decoded)
	clearBytes(decoded)
	return valid
}

func decodeCanonicalJSON(data []byte, destination any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return ErrUnexpectedResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrUnexpectedResponse
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrUnexpectedResponse
	}
	canonical, err := signing.CanonicalJSON(destination)
	if err != nil || !bytes.Equal(canonical, trimmed) {
		return ErrUnexpectedResponse
	}
	return nil
}

func safeErrorCode(data []byte) string {
	var response errorResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		clearBytes(response.Error.Message)
		return ""
	}
	defer clearBytes(response.Error.Message)
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || !errorCodeRE.MatchString(response.Error.Code) {
		return ""
	}
	return response.Error.Code
}

func isJSONContentType(value string) bool {
	contentType, _, err := mime.ParseMediaType(value)
	return err == nil && contentType == "application/json"
}

func clearBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
