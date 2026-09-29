// package serving exposes dynamicflow's deliberately narrow HTTPS distribution
// and enrollment API. it has no generic command or SSH initiation endpoint.
package serving

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

const (
	AuthorizationHeader        = "Dynamicflow-Instance-Authorization"
	ControlAuthorizationHeader = "Dynamicflow-Control-Authorization"
	maxEnrollmentBody          = 32 << 10
	maxAdminBody               = 128 << 10
	maxStatusBody              = 256 << 10
	maxLogBody                 = 128 << 10
	maxAuthorization           = 16 << 10
	maxReleaseBundle           = int64(16 << 30)
)

var (
	ErrInvalidConfig                = errors.New("invalid serving configuration")
	ErrBodyTooLarge                 = errors.New("request body too large")
	ErrAuthentication               = errors.New("instance request authentication failed")
	ErrReleaseUnavailable           = errors.New("verified current release unavailable")
	errInstanceNotEnrolled          = errors.New("instance is not enrolled")
	errProfileTransitionUnsupported = errors.New("in-place profile transition is unsupported")
)

type DesiredStateResolver func(context.Context, enrollment.Record) (enrollment.SignedDesiredState, error)

type Config struct {
	Enrollments      *enrollment.Store
	Statuses         *StatusStore
	Logs             *LogStore
	ReleaseRoot      string
	ReleasePublicKey ed25519.PublicKey
	DesiredPublicKey ed25519.PublicKey
	ResolveDesired   DesiredStateResolver
	DesiredStates    *DesiredStore
	ControlPublicKey ed25519.PublicKey
	Bootstrap        []byte
	Audit            AuditSink
	Clock            func() time.Time
	MaxClockSkew     time.Duration
}

type Server struct {
	enrollments      *enrollment.Store
	statuses         *StatusStore
	logs             *LogStore
	releaseRoot      string
	releasePublicKey ed25519.PublicKey
	desiredPublicKey ed25519.PublicKey
	desiredStates    *DesiredStore
	controlPublicKey ed25519.PublicKey
	resolveDesired   DesiredStateResolver
	bootstrap        []byte
	bootstrapDigest  string
	audit            AuditSink
	clock            func() time.Time
	maxClockSkew     time.Duration
	handler          http.Handler
	auditHealthy     atomic.Bool
	adminMu          sync.Mutex
}

func New(config Config) (*Server, error) {
	if config.Enrollments == nil || config.Statuses == nil || config.Logs == nil || (config.ResolveDesired == nil && config.DesiredStates == nil) ||
		len(config.ReleasePublicKey) != ed25519.PublicKeySize || len(config.DesiredPublicKey) != ed25519.PublicKeySize ||
		config.ReleaseRoot == "" || !filepath.IsAbs(config.ReleaseRoot) || len(config.Bootstrap) == 0 || len(config.Bootstrap) > 1<<20 ||
		config.Audit == nil {
		return nil, ErrInvalidConfig
	}
	if bytes.Equal(config.DesiredPublicKey, config.ReleasePublicKey) {
		return nil, fmt.Errorf("%w: release and desired-state trust keys must be distinct", ErrInvalidConfig)
	}
	if config.DesiredStates != nil && len(config.ControlPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: desired-state administration requires a control public key", ErrInvalidConfig)
	}
	if config.DesiredStates != nil && config.ResolveDesired != nil {
		return nil, fmt.Errorf("%w: desired store and external resolver are mutually exclusive", ErrInvalidConfig)
	}
	if len(config.ControlPublicKey) != 0 && (len(config.ControlPublicKey) != ed25519.PublicKeySize ||
		bytes.Equal(config.ControlPublicKey, config.ReleasePublicKey) || bytes.Equal(config.ControlPublicKey, config.DesiredPublicKey)) {
		return nil, fmt.Errorf("%w: control, release and desired-state keys must be distinct", ErrInvalidConfig)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	maxSkew := config.MaxClockSkew
	if maxSkew == 0 {
		maxSkew = 5 * time.Minute
	}
	if maxSkew < time.Second || maxSkew > time.Hour {
		return nil, fmt.Errorf("%w: invalid request clock skew", ErrInvalidConfig)
	}
	digest := sha256.Sum256(config.Bootstrap)
	resolver := config.ResolveDesired
	if resolver == nil {
		resolver = func(_ context.Context, record enrollment.Record) (enrollment.SignedDesiredState, error) {
			return config.DesiredStates.Get(record.Instance)
		}
	}
	server := &Server{
		enrollments: config.Enrollments, statuses: config.Statuses, logs: config.Logs, releaseRoot: filepath.Clean(config.ReleaseRoot),
		releasePublicKey: append(ed25519.PublicKey(nil), config.ReleasePublicKey...),
		desiredPublicKey: append(ed25519.PublicKey(nil), config.DesiredPublicKey...),
		desiredStates:    config.DesiredStates, controlPublicKey: append(ed25519.PublicKey(nil), config.ControlPublicKey...),
		resolveDesired: resolver, bootstrap: append([]byte(nil), config.Bootstrap...),
		bootstrapDigest: "sha256:" + hex.EncodeToString(digest[:]), audit: config.Audit, clock: clock, maxClockSkew: maxSkew,
	}
	server.auditHealthy.Store(true)
	server.handler = server.buildHandler()
	return server, nil
}

// Handler always requires a direct TLS connection. deployments terminating TLS
// in a reverse proxy must re-encrypt to serving instead of trusting spoofable
// forwarding headers.
func (server *Server) Handler() http.Handler { return server.handler }

// HTTPServer supplies bounded production-safe HTTP timeouts; callers still
// provide certificates with ListenAndServeTLS or ServeTLS.
func (server *Server) HTTPServer(address string) *http.Server {
	return &http.Server{
		Addr: address, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: time.Minute,
		MaxHeaderBytes: 32 << 10,
	}
}

func (server *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", server.handleHealth)
	mux.HandleFunc("/bootstrap", server.handleBootstrap)
	mux.HandleFunc("/v1/releases/current/manifest", server.handleCurrentManifest)
	mux.HandleFunc("/v1/releases/current/artifacts/", server.handleCurrentArtifact)
	mux.HandleFunc("/v1/releases/sets/", server.handleReleaseSet)
	mux.HandleFunc("/v1/enroll", server.handleEnroll)
	if server.desiredStates != nil {
		mux.HandleFunc("/v1/admin/enrollments", server.handleAdminEnrollments)
		mux.HandleFunc("/v1/admin/enrollments/", server.handleAdminEnrollmentAction)
		mux.HandleFunc("/v1/admin/instances/", server.handleAdminInstance)
		mux.HandleFunc("/v1/admin/releases/plan", server.handleAdminReleasePlan)
		mux.HandleFunc("/v1/admin/releases/import", server.handleAdminReleaseImport)
	}
	mux.HandleFunc("/v1/instances/", server.handleInstance)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if request.TLS == nil {
			writeAPIError(writer, http.StatusUpgradeRequired, "tls_required", "direct HTTPS is required")
			return
		}
		if request.URL.RawQuery != "" {
			writeAPIError(writer, http.StatusBadRequest, "query_not_allowed", "query parameters are not accepted")
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			if !server.auditHealthy.Load() || server.writeAudit(request, "mutation", "started", "", "") != nil {
				writeAPIError(writer, http.StatusServiceUnavailable, "audit_unavailable", "mutation audit is unavailable")
				return
			}
		}
		mux.ServeHTTP(writer, request)
	})
}

func (server *Server) handleAdminReleasePlan(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "content type must be application/json")
		return
	}
	body, err := readLimitedBody(writer, request, release.MaxManifestEnvelopeBytes)
	if err != nil {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "release plan request is too large")
		return
	}
	if err := server.authenticateControl(request, body); err != nil {
		server.recordAudit(request, "admin_release_plan", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
		return
	}
	var signed release.SignedManifest
	if err := decodeJSONBytes(body, &signed); err != nil {
		server.recordAudit(request, "admin_release_plan", "invalid", "", "")
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "release plan manifest is invalid")
		return
	}
	server.adminMu.Lock()
	err = release.CheckPublishPolicy(server.releaseRoot, signed, server.releasePublicKey)
	server.adminMu.Unlock()
	switch {
	case errors.Is(err, release.ErrReleaseRollback):
		server.recordAudit(request, "admin_release_plan", "rollback", "", "")
		writeAPIError(writer, http.StatusConflict, "release_rollback", "release generation rollback was refused")
		return
	case errors.Is(err, release.ErrVersionConflict):
		server.recordAudit(request, "admin_release_plan", "version_conflict", "", "")
		writeAPIError(writer, http.StatusConflict, "version_conflict", "component version is already bound to different bytes")
		return
	case err != nil:
		server.recordAudit(request, "admin_release_plan", "failed", "", "")
		writeAPIError(writer, http.StatusConflict, "release_policy_failed", "release destination policy could not be verified")
		return
	}
	server.recordAudit(request, "admin_release_plan", "allowed", "", "")
	writeJSON(writer, http.StatusOK, map[string]any{
		"status": "allowed", "set_id": signed.Manifest.SetID, "generation": signed.Manifest.Generation,
	})
}

func (server *Server) handleAdminReleaseImport(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	contentType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != release.BundleMediaType || len(parameters) != 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "release import content type is invalid")
		return
	}
	if request.ContentLength <= 0 || request.ContentLength > maxReleaseBundle {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "release bundle size is invalid")
		return
	}
	authorization, err := DecodeControlAuthorization(request.Header.Values(ControlAuthorizationHeader))
	if err != nil || server.authenticateControlDigest(request, authorization) != nil {
		server.recordAudit(request, "admin_release_import", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
		return
	}
	// the ordinary server timeout protects small API calls. a release may be
	// several GiB, so extend only this already authenticated request.
	_ = http.NewResponseController(writer).SetReadDeadline(time.Now().Add(2 * time.Hour))
	importsRoot := filepath.Join(server.releaseRoot, ".imports")
	if err := ensurePrivateImportDirectory(importsRoot); err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "release import staging is unavailable")
		return
	}
	stage, err := os.MkdirTemp(importsRoot, ".upload-")
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "release import staging is unavailable")
		return
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "release import staging is unavailable")
		return
	}
	limited := http.MaxBytesReader(writer, request.Body, maxReleaseBundle)
	defer limited.Close()
	signed, artifactPaths, size, digest, err := release.ReadBundle(limited, stage, server.releasePublicKey)
	if err != nil || size != request.ContentLength || subtle.ConstantTimeCompare([]byte(digest), []byte(authorization.Request.BodyDigest)) != 1 {
		server.recordAudit(request, "admin_release_import", "invalid", "", "")
		writeAPIError(writer, http.StatusBadRequest, "invalid_release_bundle", "release bundle verification failed")
		return
	}
	if err := server.writeAudit(request, "admin_release_import", "verified", "", ""); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "audit_unavailable", "release import audit is unavailable")
		return
	}
	server.adminMu.Lock()
	err = release.Publish(server.releaseRoot, signed, artifactPaths, server.releasePublicKey)
	server.adminMu.Unlock()
	if errors.Is(err, release.ErrReleaseRollback) {
		writeAPIError(writer, http.StatusConflict, "release_rollback", "release generation rollback was refused")
		return
	}
	if errors.Is(err, release.ErrVersionConflict) {
		writeAPIError(writer, http.StatusConflict, "version_conflict", "component version is already bound to different bytes")
		return
	}
	if err != nil {
		server.recordAudit(request, "admin_release_import", "failed", "", "")
		writeAPIError(writer, http.StatusBadRequest, "release_publish_failed", "verified release could not be activated")
		return
	}
	server.recordAudit(request, "admin_release_import", "activated", "", "")
	writeJSON(writer, http.StatusCreated, map[string]any{
		"status": "activated", "set_id": signed.Manifest.SetID, "generation": signed.Manifest.Generation,
		"bytes": size,
	})
}

func (server *Server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	if !server.auditHealthy.Load() {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "code": "audit_unavailable"})
		return
	}
	signed, _, err := release.Current(server.releaseRoot, server.releasePublicKey)
	if err != nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "code": "release_unavailable"})
		return
	}
	releaseKeyID, _ := signing.KeyID(server.releasePublicKey)
	desiredKeyID, _ := signing.KeyID(server.desiredPublicKey)
	response := map[string]any{
		"status": "ok", "release_set": signed.Manifest.SetID,
		"release_key_id": releaseKeyID, "desired_key_id": desiredKeyID,
	}
	if len(server.controlPublicKey) == ed25519.PublicKeySize {
		controlKeyID, _ := signing.KeyID(server.controlPublicKey)
		response["control_key_id"] = controlKeyID
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) handleBootstrap(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	writer.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Dynamicflow-Bootstrap-SHA256", server.bootstrapDigest)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(server.bootstrap)
}

func (server *Server) handleCurrentManifest(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	signed, _, err := release.Current(server.releaseRoot, server.releasePublicKey)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, signed)
}

func (server *Server) handleCurrentArtifact(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	logical := strings.TrimPrefix(request.URL.Path, "/v1/releases/current/artifacts/")
	signed, setPath, err := release.Current(server.releaseRoot, server.releasePublicKey)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
		return
	}
	server.serveReleaseArtifact(writer, request, signed, setPath, logical)
}

func (server *Server) handleReleaseSet(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	relative := strings.TrimPrefix(request.URL.Path, "/v1/releases/sets/")
	parts := strings.SplitN(relative, "/", 3)
	if len(parts) < 2 || len(parts[0]) != 64 {
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	signed, setPath, err := release.OpenSet(server.releaseRoot, "sha256:"+parts[0], server.releasePublicKey)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
		return
	}
	switch {
	case len(parts) == 2 && parts[1] == "manifest":
		writeJSON(writer, http.StatusOK, signed)
	case len(parts) == 3 && parts[1] == "artifacts" && parts[2] != "":
		server.serveReleaseArtifact(writer, request, signed, setPath, parts[2])
	default:
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (server *Server) serveReleaseArtifact(
	writer http.ResponseWriter,
	request *http.Request,
	signed release.SignedManifest,
	setPath string,
	logical string,
) {
	var component *release.Component
	for index := range signed.Manifest.Components {
		if signed.Manifest.Components[index].Artifact == logical {
			component = &signed.Manifest.Components[index]
			break
		}
	}
	if component == nil {
		writeAPIError(writer, http.StatusNotFound, "artifact_not_found", "artifact not found")
		return
	}
	path := filepath.Join(setPath, "artifacts", filepath.FromSlash(component.Artifact))
	file, err := openVerifiedArtifact(path, *component)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("ETag", `"`+strings.TrimPrefix(component.Digest, "sha256:")+`"`)
	http.ServeContent(writer, request, filepath.Base(component.Artifact), info.ModTime(), file)
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

// AdminEnrollmentCreateRequest contains no enrollment secret. the serving
// node creates the one-time secret only after authenticating this exact body
// and validating the independently signed desired state.
type AdminEnrollmentCreateRequest struct {
	Desired    enrollment.SignedDesiredState `json:"desired"`
	TTLSeconds int64                         `json:"ttl_seconds"`
}

type AdminEnrollmentCreateResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	Instance     string `json:"instance"`
	Profile      string `json:"profile"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (server *Server) handleEnroll(writer http.ResponseWriter, request *http.Request) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	var input enrollRequest
	if err := decodeJSONRequest(writer, request, maxEnrollmentBody, &input); err != nil {
		server.recordAudit(request, "enroll", "invalid", "", "")
		if errors.Is(err, ErrBodyTooLarge) {
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "enrollment request is too large")
			return
		}
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "invalid enrollment request")
		return
	}
	if len(input.Secret) > 128 || len(input.EnrollmentID) > 128 || len(input.InstancePublicKeyPEM) > 8192 {
		server.recordAudit(request, "enroll", "invalid", "", "")
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "invalid enrollment request")
		return
	}
	record, err := server.enrollments.Consume(enrollment.ConsumeRequest{
		ID: input.EnrollmentID, Secret: input.Secret, Instance: input.Instance, Profile: input.Profile,
		InstancePublicKeyPEM: []byte(input.InstancePublicKeyPEM),
	})
	if err != nil {
		// Instance and profile remain attacker-controlled until Consume has
		// authenticated the one-time credential and its exact bindings. never
		// copy those raw fields into the audit log: a secret is itself a valid
		// identifier-shaped token.
		server.recordAudit(request, "enroll", "rejected", "", "")
		if errors.Is(err, enrollment.ErrNotFound) || errors.Is(err, enrollment.ErrInvalidSecret) || errors.Is(err, enrollment.ErrExpired) ||
			errors.Is(err, enrollment.ErrConsumed) || errors.Is(err, enrollment.ErrRevoked) || errors.Is(err, enrollment.ErrBinding) {
			writeAPIError(writer, http.StatusUnauthorized, "enrollment_rejected", "enrollment credential was rejected")
			return
		}
		if errors.Is(err, enrollment.ErrInvalidEnrollment) {
			writeAPIError(writer, http.StatusBadRequest, "invalid_request", "invalid enrollment request")
			return
		}
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	desired, err := server.signedDesired(request.Context(), record)
	if err != nil {
		server.recordAudit(request, "enroll", "desired_failed", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusServiceUnavailable, "desired_unavailable", "enrollment identity accepted; retry desired-state fetch")
		return
	}
	server.recordAudit(request, "enroll", "accepted", record.Instance, record.Profile)
	writeJSON(writer, http.StatusCreated, enrollResponse{
		Instance: record.Instance, Profile: record.Profile, IdentityKeyID: record.InstanceKeyID, Desired: desired,
	})
}

func (server *Server) handleAdminEnrollments(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		body, err := readLimitedBody(writer, request, 1)
		if err != nil || len(body) != 0 || server.authenticateControl(request, body) != nil {
			server.recordAudit(request, "admin_enroll_list", "rejected", "", "")
			writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
			return
		}
		records, err := server.enrollments.List()
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "enrollment state is unavailable")
			return
		}
		server.recordAudit(request, "admin_enroll_list", "served", "", "")
		writeJSON(writer, http.StatusOK, map[string]any{"enrollments": records})
	case http.MethodPost:
		body, err := readLimitedBody(writer, request, maxAdminBody)
		if err != nil {
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "control request is too large")
			return
		}
		if err := server.authenticateControl(request, body); err != nil {
			server.recordAudit(request, "admin_enroll_create", "rejected", "", "")
			writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
			return
		}
		var input AdminEnrollmentCreateRequest
		if err := decodeJSONBytes(body, &input); err != nil || input.TTLSeconds < 60 || input.TTLSeconds > int64((24*time.Hour)/time.Second) ||
			input.Desired.State.Revoked || len(input.Desired.State.AuthorizedSSHKeys) == 0 {
			writeAPIError(writer, http.StatusBadRequest, "invalid_request", "invalid enrollment creation request")
			return
		}
		server.adminMu.Lock()
		defer server.adminMu.Unlock()
		current, _, err := release.Current(server.releaseRoot, server.releasePublicKey)
		if err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
			return
		}
		if err := enrollment.VerifyDesiredState(input.Desired, server.desiredPublicKey, enrollment.DesiredExpectation{
			Instance: input.Desired.State.Instance, Profile: input.Desired.State.Profile,
			ReleaseSet: current.Manifest.SetID, MinGeneration: 1, Now: server.clock().UTC(), MaxClockSkew: server.maxClockSkew,
		}); err != nil {
			server.recordAudit(request, "admin_enroll_create", "invalid", "", "")
			writeAPIError(writer, http.StatusBadRequest, "invalid_desired_state", "desired state failed verification")
			return
		}
		if !manifestHasProfile(current.Manifest, input.Desired.State.Profile) {
			writeAPIError(writer, http.StatusBadRequest, "profile_not_found", "profile is not present in the active release")
			return
		}
		var credential enrollment.Credential
		err = server.desiredStates.WithControlTransaction(func() error {
			active, checkErr := server.enrollments.HasActiveInstance(input.Desired.State.Instance)
			if checkErr != nil {
				return checkErr
			}
			if active {
				return enrollment.ErrConflict
			}
			// Desired state is committed first: a crash can leave a harmless,
			// resumable signed document but never a live credential without
			// desired state. the exact retry is idempotent.
			if putErr := server.desiredStates.Put(input.Desired, current.Manifest.SetID, server.clock().UTC(), server.maxClockSkew); putErr != nil {
				return putErr
			}
			credential, checkErr = server.enrollments.Create(input.Desired.State.Instance, input.Desired.State.Profile, time.Duration(input.TTLSeconds)*time.Second)
			return checkErr
		})
		if err != nil {
			status := http.StatusConflict
			code := "enrollment_conflict"
			if !errors.Is(err, enrollment.ErrConflict) && !errors.Is(err, enrollment.ErrInvalidDesiredState) {
				status, code = http.StatusInternalServerError, "state_unavailable"
			}
			writeAPIError(writer, status, code, "could not create enrollment")
			return
		}
		server.recordAudit(request, "admin_enroll_create", "created", credential.Instance, credential.Profile)
		writeJSON(writer, http.StatusCreated, AdminEnrollmentCreateResponse{
			EnrollmentID: credential.ID, Secret: credential.Secret, Instance: credential.Instance,
			Profile: credential.Profile, ExpiresAt: credential.ExpiresAt,
		})
	default:
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeAPIError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (server *Server) handleAdminEnrollmentAction(writer http.ResponseWriter, request *http.Request) {
	trimmed := strings.TrimPrefix(request.URL.Path, "/v1/admin/enrollments/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "revoke" || len(parts[0]) > 128 {
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	body, err := readLimitedBody(writer, request, 1)
	if err != nil || len(body) != 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "revocation body must be empty")
		return
	}
	if err := server.authenticateControl(request, body); err != nil {
		server.recordAudit(request, "admin_enroll_revoke", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
		return
	}
	record, err := server.enrollments.Get(parts[0])
	if errors.Is(err, enrollment.ErrNotFound) {
		writeAPIError(writer, http.StatusNotFound, "enrollment_not_found", "enrollment was not found")
		return
	}
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "enrollment state is unavailable")
		return
	}
	if record.ConsumedAt != 0 {
		writeAPIError(writer, http.StatusConflict, "instance_already_enrolled", "publish a signed revoked desired state for an enrolled instance")
		return
	}
	record, err = server.enrollments.Revoke(parts[0])
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "enrollment state is unavailable")
		return
	}
	server.recordAudit(request, "admin_enroll_revoke", "revoked", record.Instance, record.Profile)
	writeJSON(writer, http.StatusAccepted, record)
}

func (server *Server) handleAdminInstance(writer http.ResponseWriter, request *http.Request) {
	trimmed := strings.TrimPrefix(request.URL.Path, "/v1/admin/instances/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 3 && validStatusName(parts[0]) && parts[1] == "logs" && validLogComponent(parts[2]) {
		server.handleAdminLogs(writer, request, parts[0], parts[2])
		return
	}
	if len(parts) != 2 || !validStatusName(parts[0]) {
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	instance, resource := parts[0], parts[1]
	limit := int64(1)
	if resource == "desired" && request.Method == http.MethodPut {
		limit = maxAdminBody
	}
	body, err := readLimitedBody(writer, request, limit)
	if err != nil || (limit == 1 && len(body) != 0) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "invalid control request body")
		return
	}
	if err := server.authenticateControl(request, body); err != nil {
		server.recordAudit(request, "admin_instance", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
		return
	}
	switch {
	case resource == "status" && request.Method == http.MethodGet:
		report, err := server.statuses.Get(instance)
		if errors.Is(err, os.ErrNotExist) {
			writeAPIError(writer, http.StatusNotFound, "status_not_found", "instance has not reported status")
			return
		}
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "status state is unavailable")
			return
		}
		server.recordAudit(request, "admin_status", "served", instance, report.Profile)
		writeJSON(writer, http.StatusOK, report)
	case resource == "logs" && request.Method == http.MethodGet:
		if server.logs == nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "logs_unavailable", "sanitized instance logs are unavailable")
			return
		}
		snapshots, err := server.logs.List(instance)
		if errors.Is(err, os.ErrNotExist) {
			writeAPIError(writer, http.StatusNotFound, "logs_not_found", "instance has not reported logs")
			return
		}
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "sanitized log state is unavailable")
			return
		}
		server.recordAudit(request, "admin_logs", "served", instance, "")
		writeJSON(writer, http.StatusOK, map[string]any{"logs": snapshots})
	case resource == "desired" && request.Method == http.MethodGet:
		desired, err := server.desiredStates.Get(instance)
		if errors.Is(err, os.ErrNotExist) {
			writeAPIError(writer, http.StatusNotFound, "desired_not_found", "desired state was not found")
			return
		}
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "desired state is unavailable")
			return
		}
		if enrollment.VerifyDesiredState(desired, server.desiredPublicKey, enrollment.DesiredExpectation{
			Instance: instance, Profile: desired.State.Profile,
			MinGeneration: 1, Now: time.Unix(desired.State.IssuedAt, 0).UTC(), MaxClockSkew: 0,
		}) != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "desired_unavailable", "verified desired state is unavailable")
			return
		}
		server.recordAudit(request, "admin_desired", "served", instance, desired.State.Profile)
		writeJSON(writer, http.StatusOK, desired)
	case resource == "desired" && request.Method == http.MethodPut:
		var desired enrollment.SignedDesiredState
		if err := decodeJSONBytes(body, &desired); err != nil || desired.State.Instance != instance {
			writeAPIError(writer, http.StatusBadRequest, "invalid_desired_state", "desired state failed verification")
			return
		}
		current, _, err := release.Current(server.releaseRoot, server.releasePublicKey)
		if err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "release_unavailable", "verified release is unavailable")
			return
		}
		if err := enrollment.VerifyDesiredState(desired, server.desiredPublicKey, enrollment.DesiredExpectation{
			Instance: instance, Profile: desired.State.Profile, ReleaseSet: current.Manifest.SetID,
			MinGeneration: 1, Now: server.clock().UTC(), MaxClockSkew: server.maxClockSkew,
		}); err != nil {
			server.recordAudit(request, "admin_desired", "invalid", "", "")
			writeAPIError(writer, http.StatusConflict, "desired_state_conflict", "desired state was not activated")
			return
		}
		if !manifestHasProfile(current.Manifest, desired.State.Profile) {
			writeAPIError(writer, http.StatusBadRequest, "profile_not_found", "profile is not present in the active release")
			return
		}
		err = server.desiredStates.WithControlTransaction(func() error {
			record, findErr := server.enrollments.FindInstance(instance)
			switch {
			case findErr == nil && record.Profile != desired.State.Profile:
				// runtime configuration and client state bind the enrollment
				// profile. until they can migrate that binding atomically, do
				// not commit a desired document that would strand the target.
				return errProfileTransitionUnsupported
			case errors.Is(findErr, enrollment.ErrNotFound):
				existing, getErr := server.desiredStates.Get(instance)
				if getErr != nil || existing.State.Profile != desired.State.Profile {
					return errInstanceNotEnrolled
				}
			case findErr != nil:
				return findErr
			}
			return server.desiredStates.Put(desired, current.Manifest.SetID, server.clock().UTC(), server.maxClockSkew)
		})
		if errors.Is(err, errProfileTransitionUnsupported) {
			server.recordAudit(request, "admin_desired", "profile_transition_rejected", instance, desired.State.Profile)
			writeAPIError(writer, http.StatusConflict, "profile_transition_unsupported", "in-place profile transitions are not supported")
			return
		}
		if errors.Is(err, errInstanceNotEnrolled) {
			writeAPIError(writer, http.StatusConflict, "instance_not_enrolled", "desired state requires an existing enrollment binding")
			return
		}
		if err != nil {
			server.recordAudit(request, "admin_desired", "invalid", instance, desired.State.Profile)
			writeAPIError(writer, http.StatusConflict, "desired_state_conflict", "desired state was not activated")
			return
		}
		server.recordAudit(request, "admin_desired", "activated", instance, desired.State.Profile)
		writeJSON(writer, http.StatusAccepted, map[string]any{"status": "accepted", "generation": desired.State.Generation})
	default:
		writeAPIError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func manifestHasProfile(manifest release.Manifest, profile string) bool {
	for _, declared := range manifest.Profiles {
		if declared.Name == profile {
			return true
		}
	}
	return false
}

func (server *Server) handleInstance(writer http.ResponseWriter, request *http.Request) {
	trimmed := strings.TrimPrefix(request.URL.Path, "/v1/instances/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 3 && validStatusName(parts[0]) && parts[1] == "logs" && validLogComponent(parts[2]) {
		server.handleInstanceLogs(writer, request, parts[0], parts[2])
		return
	}
	if len(parts) != 2 || !validStatusName(parts[0]) {
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	switch parts[1] {
	case "desired":
		server.handleDesired(writer, request, parts[0])
	case "status":
		server.handleStatus(writer, request, parts[0])
	default:
		writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (server *Server) handleInstanceLogs(writer http.ResponseWriter, request *http.Request, instance, component string) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	if server.logs == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "logs_unavailable", "sanitized instance logs are unavailable")
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "content type must be application/json")
		return
	}
	body, err := readLimitedBody(writer, request, maxLogBody)
	if err != nil {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "log request is too large")
		return
	}
	record, err := server.authenticate(request, instance, body)
	if err != nil {
		server.recordAudit(request, "logs", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "request_authentication_failed", "instance request authentication failed")
		return
	}
	var batch LogBatch
	if err := decodeJSONBytes(body, &batch); err != nil || batch.Instance != record.Instance ||
		batch.Profile != record.Profile || batch.Component != component || ValidateLogBatch(batch) != nil {
		server.recordAudit(request, "logs", "invalid", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusBadRequest, "invalid_logs", "invalid sanitized log batch")
		return
	}
	now := server.clock().UTC()
	for _, event := range batch.Events {
		if event.Timestamp < now.Add(-30*24*time.Hour).Unix() || event.Timestamp > now.Add(server.maxClockSkew).Unix() {
			server.recordAudit(request, "logs", "invalid", record.Instance, record.Profile)
			writeAPIError(writer, http.StatusBadRequest, "invalid_logs", "invalid sanitized log batch")
			return
		}
	}
	desired, err := server.signedDesired(request.Context(), record)
	if err != nil {
		server.recordAudit(request, "logs", "desired_unavailable", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusServiceUnavailable, "desired_unavailable", "verified desired state is unavailable")
		return
	}
	if desired.State.Revoked != IsRevocationLogBatch(batch) {
		server.recordAudit(request, "logs", "desired_conflict", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusConflict, "desired_state_conflict", "log event does not match current desired state")
		return
	}
	if err := server.logs.Put(batch); errors.Is(err, ErrLogSequenceConflict) {
		server.recordAudit(request, "logs", "conflict", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusConflict, "log_sequence_conflict", "log sequence conflicts with retained state")
		return
	} else if errors.Is(err, ErrLogCapacity) {
		server.recordAudit(request, "logs", "capacity", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusConflict, "log_capacity_reached", "instance log component capacity is reached")
		return
	} else if err != nil {
		server.recordAudit(request, "logs", "failed", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "sanitized log state is unavailable")
		return
	}
	server.recordAudit(request, "logs", "accepted", record.Instance, record.Profile)
	writeJSON(writer, http.StatusAccepted, map[string]any{"status": "accepted"})
}

func (server *Server) handleAdminLogs(writer http.ResponseWriter, request *http.Request, instance, component string) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	body, err := readLimitedBody(writer, request, 1)
	if err != nil || len(body) != 0 || server.authenticateControl(request, body) != nil {
		server.recordAudit(request, "admin_logs", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "control_authentication_failed", "control request authentication failed")
		return
	}
	if server.logs == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "logs_unavailable", "sanitized instance logs are unavailable")
		return
	}
	snapshot, err := server.logs.Get(instance, component)
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(writer, http.StatusNotFound, "logs_not_found", "instance component has not reported logs")
		return
	}
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "state_unavailable", "sanitized log state is unavailable")
		return
	}
	server.recordAudit(request, "admin_logs", "served", instance, "")
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) handleDesired(writer http.ResponseWriter, request *http.Request, instance string) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}
	body, err := readLimitedBody(writer, request, 1)
	if err != nil || len(body) != 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "desired-state request body must be empty")
		return
	}
	record, err := server.authenticate(request, instance, body)
	if err != nil {
		server.recordAudit(request, "desired", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "request_authentication_failed", "instance request authentication failed")
		return
	}
	desired, err := server.signedDesired(request.Context(), record)
	if err != nil {
		server.recordAudit(request, "desired", "failed", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusServiceUnavailable, "desired_unavailable", "desired state is unavailable")
		return
	}
	server.recordAudit(request, "desired", "served", record.Instance, record.Profile)
	writeJSON(writer, http.StatusOK, desired)
}

func (server *Server) handleStatus(writer http.ResponseWriter, request *http.Request, instance string) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "content type must be application/json")
		return
	}
	body, err := readLimitedBody(writer, request, maxStatusBody)
	if err != nil {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "status request is too large")
		return
	}
	record, err := server.authenticate(request, instance, body)
	if err != nil {
		server.recordAudit(request, "status", "rejected", "", "")
		writeAPIError(writer, http.StatusUnauthorized, "request_authentication_failed", "instance request authentication failed")
		return
	}
	var report StatusReport
	if err := decodeJSONBytes(body, &report); err != nil || report.Instance != record.Instance || report.Profile != record.Profile {
		server.recordAudit(request, "status", "invalid", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusBadRequest, "invalid_status", "invalid instance status")
		return
	}
	report = NormalizeStatus(report)
	if err := ValidateStatus(report); err != nil {
		server.recordAudit(request, "status", "invalid", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusBadRequest, "invalid_status", "invalid instance status")
		return
	}
	now := server.clock().UTC()
	if report.ReportedAt < now.Add(-server.maxClockSkew).Unix() || report.ReportedAt > now.Add(server.maxClockSkew).Unix() {
		server.recordAudit(request, "status", "invalid", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusBadRequest, "invalid_status", "invalid instance status")
		return
	}
	desired, err := server.signedDesired(request.Context(), record)
	if err != nil {
		server.recordAudit(request, "status", "desired_unavailable", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusServiceUnavailable, "desired_unavailable", "verified desired state is unavailable")
		return
	}
	if report.DesiredGeneration != desired.State.Generation || report.ReleaseSet != desired.State.ReleaseSet ||
		desired.State.Revoked != IsRevocationAcknowledgement(report) {
		server.recordAudit(request, "status", "desired_conflict", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusConflict, "desired_state_conflict", "status does not match current desired state")
		return
	}
	if err := server.statuses.Put(report); err != nil {
		server.recordAudit(request, "status", "failed", record.Instance, record.Profile)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	server.recordAudit(request, "status", "accepted", record.Instance, record.Profile)
	writeJSON(writer, http.StatusAccepted, map[string]any{"status": "accepted"})
}

func (server *Server) authenticate(request *http.Request, instance string, body []byte) (enrollment.Record, error) {
	record, err := server.enrollments.FindInstance(instance)
	if err != nil {
		return enrollment.Record{}, ErrAuthentication
	}
	publicKey, err := signing.ParsePublicPEM([]byte(record.InstancePublicKeyPEM))
	if err != nil {
		return enrollment.Record{}, ErrAuthentication
	}
	authorization, err := DecodeAuthorization(request.Header.Values(AuthorizationHeader))
	if err != nil {
		return enrollment.Record{}, ErrAuthentication
	}
	if err := server.enrollments.VerifyInstanceRequest(
		authorization, publicKey, instance, request.Method, request.URL.Path, body, server.maxClockSkew,
	); err != nil {
		return enrollment.Record{}, ErrAuthentication
	}
	return record, nil
}

func (server *Server) authenticateControl(request *http.Request, body []byte) error {
	if len(server.controlPublicKey) != ed25519.PublicKeySize || server.desiredStates == nil {
		return ErrAuthentication
	}
	authorization, err := DecodeControlAuthorization(request.Header.Values(ControlAuthorizationHeader))
	if err != nil {
		return ErrAuthentication
	}
	if err := server.enrollments.VerifyControlRequest(
		authorization, server.controlPublicKey, request.Method, request.URL.Path, body, server.maxClockSkew,
	); err != nil {
		return ErrAuthentication
	}
	return nil
}

func (server *Server) authenticateControlDigest(request *http.Request, authorization enrollment.SignedControlRequest) error {
	if len(server.controlPublicKey) != ed25519.PublicKeySize || server.desiredStates == nil {
		return ErrAuthentication
	}
	if err := server.enrollments.VerifyControlRequestDigest(
		authorization, server.controlPublicKey, request.Method, request.URL.Path,
		authorization.Request.BodyDigest, server.maxClockSkew,
	); err != nil {
		return ErrAuthentication
	}
	return nil
}

func ensurePrivateImportDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrAuthentication
	}
	return nil
}

func (server *Server) signedDesired(ctx context.Context, record enrollment.Record) (enrollment.SignedDesiredState, error) {
	signed, err := server.resolveDesired(ctx, record)
	if err != nil {
		return enrollment.SignedDesiredState{}, err
	}
	if err := enrollment.VerifyDesiredState(signed, server.desiredPublicKey, enrollment.DesiredExpectation{
		Instance: record.Instance, Profile: record.Profile,
		MinGeneration: 1, Now: server.clock().UTC(), MaxClockSkew: server.maxClockSkew,
	}); err != nil {
		return enrollment.SignedDesiredState{}, err
	}
	bound, _, err := release.OpenSet(server.releaseRoot, signed.State.ReleaseSet, server.releasePublicKey)
	if err != nil {
		return enrollment.SignedDesiredState{}, ErrReleaseUnavailable
	}
	if !manifestHasProfile(bound.Manifest, signed.State.Profile) {
		return enrollment.SignedDesiredState{}, enrollment.ErrBinding
	}
	return signed, nil
}

// EncodeAuthorization canonicalizes a signed request for the single safe
// authentication header used by instance clients.
func EncodeAuthorization(request enrollment.SignedInstanceRequest) (string, error) {
	canonical, err := signing.CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	if len(canonical) > maxAuthorization {
		return "", ErrAuthentication
	}
	return base64.RawURLEncoding.EncodeToString(canonical), nil
}

func DecodeAuthorization(values []string) (enrollment.SignedInstanceRequest, error) {
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > base64.RawURLEncoding.EncodedLen(maxAuthorization) {
		return enrollment.SignedInstanceRequest{}, ErrAuthentication
	}
	data, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(data) > maxAuthorization {
		return enrollment.SignedInstanceRequest{}, ErrAuthentication
	}
	var request enrollment.SignedInstanceRequest
	if err := decodeJSONBytes(data, &request); err != nil {
		return enrollment.SignedInstanceRequest{}, ErrAuthentication
	}
	canonical, err := signing.CanonicalJSON(request)
	if err != nil || !bytes.Equal(canonical, data) {
		return enrollment.SignedInstanceRequest{}, ErrAuthentication
	}
	return request, nil
}

func EncodeControlAuthorization(request enrollment.SignedControlRequest) (string, error) {
	canonical, err := signing.CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	if len(canonical) > maxAuthorization {
		return "", ErrAuthentication
	}
	return base64.RawURLEncoding.EncodeToString(canonical), nil
}

func DecodeControlAuthorization(values []string) (enrollment.SignedControlRequest, error) {
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > base64.RawURLEncoding.EncodedLen(maxAuthorization) {
		return enrollment.SignedControlRequest{}, ErrAuthentication
	}
	data, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(data) > maxAuthorization {
		return enrollment.SignedControlRequest{}, ErrAuthentication
	}
	var request enrollment.SignedControlRequest
	if err := decodeJSONBytes(data, &request); err != nil {
		return enrollment.SignedControlRequest{}, ErrAuthentication
	}
	canonical, err := signing.CanonicalJSON(request)
	if err != nil || !bytes.Equal(canonical, data) {
		return enrollment.SignedControlRequest{}, ErrAuthentication
	}
	return request, nil
}

func (server *Server) recordAudit(request *http.Request, action, outcome, instance, profile string) {
	_ = server.writeAudit(request, action, outcome, instance, profile)
}

func (server *Server) writeAudit(request *http.Request, action, outcome, instance, profile string) error {
	if !validStatusName(instance) {
		instance = ""
	}
	if !validStatusName(profile) {
		profile = ""
	}
	event := AuditEvent{
		Timestamp: server.clock().UTC().Unix(), Action: action, Outcome: outcome,
		Instance: instance, Profile: profile, RemoteIP: remoteIP(request.RemoteAddr),
	}
	if err := server.audit.Record(event); err != nil {
		server.auditHealthy.Store(false)
		return err
	}
	return nil
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func requireMethod(writer http.ResponseWriter, request *http.Request, expected string) bool {
	if request.Method == expected {
		return true
	}
	writer.Header().Set("Allow", expected)
	writeAPIError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	return false
}

func readLimitedBody(writer http.ResponseWriter, request *http.Request, limit int64) ([]byte, error) {
	reader := http.MaxBytesReader(writer, request.Body, limit)
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, ErrBodyTooLarge
		}
		return nil, err
	}
	return data, nil
}

func decodeJSONRequest(writer http.ResponseWriter, request *http.Request, limit int64, destination any) error {
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		return errors.New("content type must be application/json")
	}
	data, err := readLimitedBody(writer, request, limit)
	if err != nil {
		return err
	}
	return decodeJSONBytes(data, destination)
}

func isJSONContentType(value string) bool {
	contentType, _, err := mime.ParseMediaType(value)
	return err == nil && contentType == "application/json"
}

func decodeJSONBytes(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must contain exactly one value")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	data, err := signing.CanonicalJSON(value)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(data, '\n'))
}

func writeAPIError(writer http.ResponseWriter, status int, code, message string) {
	data, _ := signing.CanonicalJSON(map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(data, '\n'))
}

func openVerifiedArtifact(path string, component release.Component) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, release.ErrUnsafePath
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != 0o444 || details.Nlink != 1 || details.Size != component.Size {
		return nil, release.ErrArtifactTampered
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if digest != component.Digest {
		return nil, release.ErrArtifactTampered
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	failed = false
	return file, nil
}
