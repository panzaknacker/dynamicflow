package instanceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
)

const (
	testInstance = "pbp-01"
	testProfile  = "pbp"
)

type capturedRequest struct {
	method        string
	path          string
	body          []byte
	authorization string
}

type integrationFixture struct {
	root                string
	now                 time.Time
	server              *httptest.Server
	config              Config
	credential          enrollment.Credential
	desired             enrollment.SignedDesiredState
	signedRelease       release.SignedManifest
	desiredPrivate      ed25519.PrivateKey
	releasePublic       ed25519.PublicKey
	releasePrivate      ed25519.PrivateKey
	desiredPublic       ed25519.PublicKey
	statusStore         *serving.StatusStore
	logStore            *serving.LogStore
	enrollmentStore     *enrollment.Store
	capturesMu          sync.Mutex
	captures            []capturedRequest
	hits                int
	enrollQuery         string
	enrollAuthorization string
	enrollContentType   string
}

func TestClientEnrollmentDesiredStatusAndReplay(t *testing.T) {
	fixture := newIntegrationFixture(t)
	client, err := New(fixture.config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	privatePath := filepath.Join(fixture.config.StateDir, identityPrivatePath)
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read private identity: %v", err)
	}
	keyID := client.IdentityKeyID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.Enroll(ctx, fixture.credential.ID, strings.NewReader(fixture.credential.Secret+"\n"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !result.State.Enrolled || result.State.ReleaseSet != fixture.signedRelease.Manifest.SetID ||
		result.Desired.State.Instance != testInstance || result.Release.Manifest.SetID != fixture.signedRelease.Manifest.SetID {
		t.Fatalf("unexpected enrollment result: %+v", result.State)
	}
	assertPrivateStateTree(t, fixture.config.StateDir, fixture.credential.Secret)

	if _, err := client.FetchDesired(ctx); err != nil {
		t.Fatalf("fetch desired one: %v", err)
	}
	if _, err := client.FetchDesired(ctx); err != nil {
		t.Fatalf("fetch desired two: %v", err)
	}
	report := serving.StatusReport{
		Schema: serving.StatusSchema, Instance: testInstance, Profile: testProfile,
		DesiredGeneration: fixture.desired.State.Generation, AppliedGeneration: fixture.desired.State.Generation,
		ReleaseSet: fixture.desired.State.ReleaseSet, State: "ready",
		Components: []serving.ComponentStatus{{Name: "pbp", Version: "v0.1.7", State: "ready"}},
		ReportedAt: fixture.now.Unix(),
	}
	if err := client.ReportStatus(ctx, report); err != nil {
		t.Fatalf("report status: %v", err)
	}
	stored, err := fixture.statusStore.Get(testInstance)
	if err != nil || stored.ReleaseSet != report.ReleaseSet || stored.State != "ready" {
		t.Fatalf("stored status mismatch: %+v, %v", stored, err)
	}

	fixture.capturesMu.Lock()
	captures := append([]capturedRequest(nil), fixture.captures...)
	enrollQuery := fixture.enrollQuery
	enrollAuthorization := fixture.enrollAuthorization
	enrollContentType := fixture.enrollContentType
	fixture.capturesMu.Unlock()
	if enrollQuery != "" || enrollAuthorization != "" || enrollContentType != "application/json" {
		t.Fatalf("unsafe enrollment request form: query=%q auth=%q content-type=%q", enrollQuery, enrollAuthorization, enrollContentType)
	}
	if len(captures) != 3 {
		t.Fatalf("expected two desired and one status request, got %d", len(captures))
	}
	publicKey, err := signing.ParsePublicPEM(client.IdentityPublicPEM())
	if err != nil {
		t.Fatalf("parse instance public key: %v", err)
	}
	replayStore, err := enrollment.NewStore(filepath.Join(fixture.root, "replay", "state.json"), enrollment.WithClock(func() time.Time { return fixture.now }))
	if err != nil {
		t.Fatalf("new replay store: %v", err)
	}
	seenNonces := make(map[string]struct{})
	var first enrollment.SignedInstanceRequest
	for index, capture := range captures {
		signed, err := serving.DecodeAuthorization([]string{capture.authorization})
		if err != nil {
			t.Fatalf("decode authorization %d: %v", index, err)
		}
		if _, exists := seenNonces[signed.Request.Nonce]; exists {
			t.Fatalf("nonce reused by request %d", index)
		}
		seenNonces[signed.Request.Nonce] = struct{}{}
		if err := replayStore.VerifyInstanceRequest(
			signed, publicKey, testInstance, capture.method, capture.path, capture.body, 5*time.Minute,
		); err != nil {
			t.Fatalf("request %d not bound to exact method/path/body: %v", index, err)
		}
		if index == 0 {
			first = signed
		}
	}
	if err := replayStore.VerifyInstanceRequest(
		first, publicKey, testInstance, captures[0].method, captures[0].path, captures[0].body, 5*time.Minute,
	); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	restarted, err := New(fixture.config)
	if err != nil {
		t.Fatalf("restart client: %v", err)
	}
	defer restarted.Close()
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("reread private identity: %v", err)
	}
	if keyID != restarted.IdentityKeyID() || !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("stable instance identity changed across restart")
	}
	unread := &countingReader{reader: strings.NewReader(fixture.credential.Secret)}
	if _, err := restarted.Enroll(ctx, fixture.credential.ID, unread); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("expected already enrolled, got %v", err)
	}
	if unread.reads != 0 {
		t.Fatal("secret was read even though state was already enrolled")
	}
}

func TestClientReportLogsSignsExactBindingAndRejectsUnsafeInputLocally(t *testing.T) {
	fixture := newIntegrationFixture(t)
	client, err := New(fixture.config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	if _, err := client.Enroll(context.Background(), fixture.credential.ID, strings.NewReader(fixture.credential.Secret)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	batch := serving.LogBatch{
		Schema: serving.LogSchema, Instance: testInstance, Profile: testProfile, Component: "pbp",
		Events: []serving.LogEvent{{Sequence: 1, Timestamp: fixture.now.Unix(), Level: "info", Event: "reconcile_started"}},
	}
	if err := client.ReportLogs(context.Background(), batch); err != nil {
		t.Fatalf("report logs: %v", err)
	}
	stored, err := fixture.logStore.Get(testInstance, "pbp")
	if err != nil || len(stored.Events) != 1 || stored.Events[0] != batch.Events[0] {
		t.Fatalf("stored logs=%#v err=%v", stored, err)
	}

	fixture.capturesMu.Lock()
	captures := append([]capturedRequest(nil), fixture.captures...)
	fixture.capturesMu.Unlock()
	if len(captures) != 1 {
		t.Fatalf("log request captures=%d, want 1", len(captures))
	}
	capture := captures[0]
	wantPath := "/v1/instances/" + testInstance + "/logs/pbp"
	wantBody, err := signing.CanonicalJSON(batch)
	if err != nil {
		t.Fatal(err)
	}
	if capture.method != http.MethodPost || capture.path != wantPath || !bytes.Equal(capture.body, wantBody) {
		t.Fatalf("log request method=%s path=%s body=%s", capture.method, capture.path, capture.body)
	}
	publicKey, err := signing.ParsePublicPEM(client.IdentityPublicPEM())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := serving.DecodeAuthorization([]string{capture.authorization})
	if err != nil {
		t.Fatalf("decode log authorization: %v", err)
	}
	replayStore, err := enrollment.NewStore(filepath.Join(fixture.root, "log-replay", "state.json"), enrollment.WithClock(func() time.Time { return fixture.now }))
	if err != nil {
		t.Fatal(err)
	}
	if err := replayStore.VerifyInstanceRequest(signed, publicKey, testInstance, http.MethodPost, wantPath, wantBody, 5*time.Minute); err != nil {
		t.Fatalf("log authorization binding: %v", err)
	}
	if err := replayStore.VerifyInstanceRequest(signed, publicKey, testInstance, http.MethodPost, wantPath, wantBody, 5*time.Minute); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatalf("log authorization replay=%v", err)
	}

	invalid := []struct {
		name  string
		batch serving.LogBatch
		want  error
	}{
		{name: "instance", batch: cloneLogBatch(batch), want: enrollment.ErrBinding},
		{name: "profile", batch: cloneLogBatch(batch), want: enrollment.ErrBinding},
		{name: "old", batch: cloneLogBatch(batch), want: serving.ErrInvalidLog},
		{name: "future", batch: cloneLogBatch(batch), want: serving.ErrInvalidLog},
		{name: "component", batch: cloneLogBatch(batch), want: serving.ErrInvalidLog},
	}
	invalid[0].batch.Instance = "other-vm"
	invalid[1].batch.Profile = "ssh"
	invalid[2].batch.Events[0].Timestamp = fixture.now.Add(-30*24*time.Hour - time.Second).Unix()
	invalid[3].batch.Events[0].Timestamp = fixture.now.Add(fixture.config.MaxClockSkew + time.Second).Unix()
	invalid[4].batch.Component = "../pbp"
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if err := client.ReportLogs(context.Background(), test.batch); !errors.Is(err, test.want) {
				t.Fatalf("report invalid logs=%v, want %v", err, test.want)
			}
		})
	}
	fixture.capturesMu.Lock()
	captureCount := len(fixture.captures)
	fixture.capturesMu.Unlock()
	if captureCount != 1 {
		t.Fatalf("locally rejected logs caused network requests: %d", captureCount)
	}

	if err := client.ReportLogs(context.Background(), batch); err != nil {
		t.Fatalf("freshly signed idempotent retry: %v", err)
	}
	collision := cloneLogBatch(batch)
	collision.Events[0].Code = "installer_failed"
	err = client.ReportLogs(context.Background(), collision)
	var remoteErr *HTTPError
	if !errors.As(err, &remoteErr) || remoteErr.StatusCode != http.StatusConflict || remoteErr.Code != "log_sequence_conflict" {
		t.Fatalf("client sequence conflict=%v", err)
	}
}

func TestClientRevokedIdentityCanSignOnlyExactFailClosedAcknowledgement(t *testing.T) {
	fixture := newIntegrationFixture(t)
	client, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Enroll(context.Background(), fixture.credential.ID, strings.NewReader(fixture.credential.Secret)); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	revokedState := fixture.desired.State
	revokedState.Generation++
	revokedState.Revoked = true
	revokedState.AuthorizedSSHKeys = nil
	fixture.desired, err = enrollment.SignDesiredState(revokedState, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.FetchDesired(context.Background())
	if err != nil || !result.Desired.State.Revoked || result.State.Desired == nil || !result.State.Desired.State.Revoked {
		t.Fatalf("fetch revoked desired result=%#v err=%v", result, err)
	}

	ack := serving.NormalizeStatus(serving.StatusReport{
		Schema: serving.StatusSchema, Instance: testInstance, Profile: testProfile,
		DesiredGeneration: revokedState.Generation, AppliedGeneration: revokedState.Generation - 1,
		ReleaseSet: revokedState.ReleaseSet, State: "revoked", Revoked: true, FailClosed: true,
		Components: []serving.ComponentStatus{{Name: "ssh", Version: "unknown", State: "blocked", Code: "revoked"}},
		ReportedAt: fixture.now.Unix(),
	})
	if err := client.ReportStatus(context.Background(), ack); err != nil {
		t.Fatalf("report revocation status: %v", err)
	}
	batch := serving.LogBatch{
		Schema: serving.LogSchema, Instance: testInstance, Profile: testProfile, Component: "ssh",
		Events: []serving.LogEvent{{
			Sequence: 1, Timestamp: fixture.now.Unix(), Level: "critical",
			Event: "phase_fail_closed", Code: "revoked",
		}},
	}
	if err := client.ReportLogs(context.Background(), batch); err != nil {
		t.Fatalf("report revocation log: %v", err)
	}
	persisted, err := fixture.statusStore.Get(testInstance)
	if err != nil || !persisted.Revoked || !persisted.FailClosed || persisted.State != "revoked" {
		t.Fatalf("persisted revocation status=%#v err=%v", persisted, err)
	}

	fixture.capturesMu.Lock()
	requestCount := len(fixture.captures)
	fixture.capturesMu.Unlock()
	normal := ack
	normal.State, normal.Revoked, normal.FailClosed = "ready", false, false
	normal.Components = []serving.ComponentStatus{{Name: "ssh", Version: "unknown", State: "ready"}}
	if err := client.ReportStatus(context.Background(), normal); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked identity normal status error=%v", err)
	}
	ordinary := batch
	ordinary.Events = []serving.LogEvent{{Sequence: 2, Timestamp: fixture.now.Unix(), Level: "info", Event: "reconcile_started"}}
	if err := client.ReportLogs(context.Background(), ordinary); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked identity ordinary log error=%v", err)
	}
	fixture.capturesMu.Lock()
	afterRejected := len(fixture.captures)
	fixture.capturesMu.Unlock()
	if afterRejected != requestCount {
		t.Fatalf("locally rejected revoked-identity reports reached serving: before=%d after=%d", requestCount, afterRejected)
	}
}

func TestConcurrentClientsConsumeEnrollmentOnce(t *testing.T) {
	fixture := newIntegrationFixture(t)
	first, err := New(fixture.config)
	if err != nil {
		t.Fatalf("new first client: %v", err)
	}
	defer first.Close()
	second, err := New(fixture.config)
	if err != nil {
		t.Fatalf("new second client: %v", err)
	}
	defer second.Close()
	if first.IdentityKeyID() != second.IdentityKeyID() {
		t.Fatal("clients sharing state did not reuse the same identity")
	}
	readers := []*countingReader{
		{reader: strings.NewReader(fixture.credential.Secret)},
		{reader: strings.NewReader(fixture.credential.Secret)},
	}
	clients := []*Client{first, second}
	errorsByClient := make([]error, len(clients))
	var wait sync.WaitGroup
	for index := range clients {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, errorsByClient[index] = clients[index].Enroll(context.Background(), fixture.credential.ID, readers[index])
		}(index)
	}
	wait.Wait()
	succeeded, alreadyEnrolled, unread := 0, 0, 0
	for index, err := range errorsByClient {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAlreadyEnrolled):
			alreadyEnrolled++
		default:
			t.Fatalf("client %d returned unexpected error: %v", index, err)
		}
		if readers[index].reads == 0 {
			unread++
		}
	}
	if succeeded != 1 || alreadyEnrolled != 1 || unread != 1 {
		t.Fatalf("parallel enrollment was not exactly once: success=%d already=%d unread=%d", succeeded, alreadyEnrolled, unread)
	}
	assertPrivateStateTree(t, fixture.config.StateDir, fixture.credential.Secret)
}

func TestClientRejectsWrongTLSPinBeforeReadingSecret(t *testing.T) {
	fixture := newIntegrationFixture(t)
	wrong := sha256.Sum256([]byte("not the serving certificate"))
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	config.TLSPin = "SHA256:" + base64.RawStdEncoding.EncodeToString(wrong[:])
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	reader := &countingReader{reader: strings.NewReader(fixture.credential.Secret)}
	_, err = client.Enroll(context.Background(), fixture.credential.ID, reader)
	if !errors.Is(err, ErrTLSPin) {
		t.Fatalf("expected TLS pin error, got %v", err)
	}
	if reader.reads != 0 {
		t.Fatal("secret was read before TLS pin validation")
	}
	fixture.capturesMu.Lock()
	hits := fixture.hits
	fixture.capturesMu.Unlock()
	if hits != 0 {
		t.Fatalf("HTTP handler ran despite pin mismatch (%d requests)", hits)
	}
}

func TestClientRequiresHTTPSOrigin(t *testing.T) {
	releasePublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		StateDir: filepath.Join(t.TempDir(), "state"), BaseURL: "http://serving.invalid",
		Instance: testInstance, Profile: testProfile,
		ReleasePublicKey: releasePublic, DesiredPublicKey: desiredPublic,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected HTTP origin rejection, got %v", err)
	}
}

func TestClientBoundsManifestBeforeReadingSecret(t *testing.T) {
	fixture := newIntegrationFixture(t)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte{'x'}, maxManifestBody+1))
	})
	server, caPEM, pin := startPinnedTLSServer(t, fixture.now, handler)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	config.BaseURL, config.CACertificatePEM, config.TLSPin = server.URL, caPEM, pin
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	reader := &countingReader{reader: strings.NewReader(fixture.credential.Secret)}
	_, err = client.Enroll(context.Background(), fixture.credential.ID, reader)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected response size rejection, got %v", err)
	}
	if reader.reads != 0 {
		t.Fatal("secret was read before bounded release verification")
	}
}

func TestClientRedactsReflectedServerError(t *testing.T) {
	fixture := newIntegrationFixture(t)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/releases/current/manifest":
			writeCanonicalTest(t, writer, http.StatusOK, fixture.signedRelease)
		case "/v1/enroll":
			writeCanonicalTest(t, writer, http.StatusUnauthorized, map[string]any{
				"error": map[string]any{
					"code": "enrollment_rejected", "message": "reflected " + fixture.credential.Secret,
				},
			})
		default:
			http.NotFound(writer, request)
		}
	})
	server, caPEM, pin := startPinnedTLSServer(t, fixture.now, handler)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	config.BaseURL, config.CACertificatePEM, config.TLSPin = server.URL, caPEM, pin
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	_, err = client.Enroll(context.Background(), fixture.credential.ID, strings.NewReader(fixture.credential.Secret))
	var httpError *HTTPError
	if !errors.As(err, &httpError) || !errors.Is(err, ErrUnexpectedResponse) ||
		httpError.StatusCode != http.StatusUnauthorized || httpError.Code != "enrollment_rejected" {
		t.Fatalf("unexpected HTTP error: %v", err)
	}
	if strings.Contains(err.Error(), fixture.credential.Secret) {
		t.Fatal("reflected enrollment secret reached error output")
	}
	assertPrivateStateTree(t, config.StateDir, fixture.credential.Secret)
}

func TestClientRecoversAfterEnrollmentResponseLoss(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	if _, err := fixture.enrollmentStore.Consume(enrollment.ConsumeRequest{
		ID: fixture.credential.ID, Secret: fixture.credential.Secret,
		Instance: testInstance, Profile: testProfile, InstancePublicKeyPEM: client.IdentityPublicPEM(),
	}); err != nil {
		t.Fatalf("simulate consumed enrollment: %v", err)
	}
	if client.State().Enrolled {
		t.Fatal("test precondition: client unexpectedly marked enrolled")
	}
	result, err := client.FetchDesired(context.Background())
	if err != nil {
		t.Fatalf("recover desired state: %v", err)
	}
	if !result.State.Enrolled || result.Desired.State.Generation != fixture.desired.State.Generation {
		t.Fatalf("recovery did not commit enrollment: %+v", result.State)
	}
	assertPrivateStateTree(t, config.StateDir, fixture.credential.Secret)
}

func TestClientUsesDesiredImmutableReleaseAfterCurrentAdvances(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Enroll(context.Background(), fixture.credential.ID, strings.NewReader(fixture.credential.Secret)); err != nil {
		t.Fatalf("enroll predecessor: %v", err)
	}
	secondArtifact := filepath.Join(t.TempDir(), "pbp-v2.tar")
	if err := os.WriteFile(secondArtifact, []byte("new current artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := release.BuildFromArtifacts(8, []release.ArtifactInput{{
		Component: "pbp", Version: "v0.1.8", Target: "linux-amd64", ArtifactName: "pbp-v2.tar", SourcePath: secondArtifact,
	}}, []release.Profile{{Name: testProfile, Components: []string{"pbp"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedSecond, err := release.SignManifest(second, fixture.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.Publish(filepath.Join(fixture.root, "releases"), signedSecond, map[string]string{
		second.Components[0].Artifact: secondArtifact,
	}, fixture.releasePublic); err != nil {
		t.Fatal(err)
	}
	result, err := client.FetchDesired(context.Background())
	if err != nil {
		t.Fatalf("fetch retained desired: %v", err)
	}
	if result.Release.Manifest.SetID != fixture.signedRelease.Manifest.SetID || result.Release.Manifest.SetID == second.SetID {
		t.Fatalf("desired was rebound to current: desired=%s current=%s", result.Release.Manifest.SetID, second.SetID)
	}
	var downloaded bytes.Buffer
	component := result.Release.Manifest.Components[0]
	if err := client.DownloadArtifact(context.Background(), result.Release, component, &downloaded); err != nil {
		t.Fatalf("download retained artifact: %v", err)
	}
	if downloaded.String() != "immutable test artifact\n" {
		t.Fatalf("retained artifact=%q", downloaded.String())
	}
}

func TestClientRejectsReleaseSignatureBeforeReadingSecret(t *testing.T) {
	fixture := newIntegrationFixture(t)
	wrongPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	config.ReleasePublicKey = wrongPublic
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	reader := &countingReader{reader: strings.NewReader(fixture.credential.Secret)}
	_, err = client.Enroll(context.Background(), fixture.credential.ID, reader)
	if !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("expected release signature rejection, got %v", err)
	}
	if reader.reads != 0 {
		t.Fatal("secret was read before release verification")
	}
}

func TestClientRejectsInvalidDesiredSignaturesAndBindings(t *testing.T) {
	fixture := newIntegrationFixture(t)
	wrongSignature := cloneDesired(fixture.desired)
	wrongSignature.Signature.Value[0] ^= 0xff
	wrongInstanceState := fixture.desired.State
	wrongInstanceState.Instance = "other-instance"
	wrongInstance, err := enrollment.SignDesiredState(wrongInstanceState, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wrongProfileState := fixture.desired.State
	wrongProfileState.Profile = "ssh"
	wrongProfile, err := enrollment.SignDesiredState(wrongProfileState, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wrongReleaseState := fixture.desired.State
	wrongReleaseState.ReleaseSet = "sha256:" + strings.Repeat("0", 64)
	wrongRelease, err := enrollment.SignDesiredState(wrongReleaseState, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		desired enrollment.SignedDesiredState
		want    error
	}{
		{name: "signature", desired: wrongSignature, want: signing.ErrInvalidSignature},
		{name: "instance binding", desired: wrongInstance, want: enrollment.ErrBinding},
		{name: "profile binding", desired: wrongProfile, want: enrollment.ErrBinding},
		{name: "release binding", desired: wrongRelease, want: enrollment.ErrBinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := badEnrollmentHandler(t, fixture.signedRelease, test.desired)
			server, caPEM, pin := startPinnedTLSServer(t, fixture.now, handler)
			config := fixture.config
			config.StateDir = filepath.Join(t.TempDir(), "state")
			config.BaseURL, config.CACertificatePEM, config.TLSPin = server.URL, caPEM, pin
			client, err := New(config)
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			defer client.Close()
			_, err = client.Enroll(context.Background(), fixture.credential.ID, strings.NewReader(fixture.credential.Secret))
			if !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
			if !errors.Is(err, ErrEnrollmentOutcomeUnknown) {
				t.Fatalf("completed enrollment POST was not marked outcome-unknown: %v", err)
			}
			if strings.Contains(err.Error(), fixture.credential.Secret) {
				t.Fatal("error disclosed enrollment secret")
			}
			if client.State().Enrolled {
				t.Fatal("invalid desired state was persisted as enrolled")
			}
			assertPrivateStateTree(t, config.StateDir, fixture.credential.Secret)
		})
	}
}

func TestClientRecoversPublicIdentityWithoutReplacingPrivateKey(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	keyID := client.IdentityKeyID()
	privatePath := filepath.Join(config.StateDir, identityPrivatePath)
	publicPath := filepath.Join(config.StateDir, identityPublicPath)
	privateBefore, _ := os.ReadFile(privatePath)
	publicBefore, _ := os.ReadFile(publicPath)
	_ = client.Close()
	if err := os.Remove(publicPath); err != nil {
		t.Fatalf("simulate interrupted identity creation: %v", err)
	}
	recovered, err := New(config)
	if err != nil {
		t.Fatalf("recover client: %v", err)
	}
	defer recovered.Close()
	privateAfter, _ := os.ReadFile(privatePath)
	publicAfter, _ := os.ReadFile(publicPath)
	if recovered.IdentityKeyID() != keyID || !bytes.Equal(privateBefore, privateAfter) || !bytes.Equal(publicBefore, publicAfter) {
		t.Fatal("public-key recovery replaced or changed the instance identity")
	}
	if info, err := os.Lstat(publicPath); err != nil || info.Mode().Perm() != localstate.FileMode {
		t.Fatalf("recovered public identity is not mode 0600: %v, %v", info, err)
	}
}

func TestClientRejectsSymlinkedIdentityPath(t *testing.T) {
	fixture := newIntegrationFixture(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, localstate.DirMode); err != nil {
		t.Fatalf("create private state directory: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(stateDir, "identity")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	config := fixture.config
	config.StateDir = stateDir
	_, err := New(config)
	if !errors.Is(err, localstate.ErrSymlink) {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestClientRejectsMismatchedIdentityWithoutReplacingPrivateKey(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	privatePath := filepath.Join(config.StateDir, identityPrivatePath)
	publicPath := filepath.Join(config.StateDir, identityPublicPath)
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	otherPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := signing.MarshalPublicPEM(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, otherPEM, localstate.FileMode); err != nil {
		t.Fatalf("replace public fixture: %v", err)
	}
	if _, err := New(config); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("client replaced private identity after public-key mismatch")
	}
}

func TestClientNeverRegeneratesMissingIdentityAfterStateExists(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	keyID := client.IdentityKeyID()
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	privatePath := filepath.Join(config.StateDir, identityPrivatePath)
	publicPath := filepath.Join(config.StateDir, identityPublicPath)
	if err := os.Remove(privatePath); err != nil {
		t.Fatalf("remove private identity fixture: %v", err)
	}
	if err := os.Remove(publicPath); err != nil {
		t.Fatalf("remove public identity fixture: %v", err)
	}
	if _, err := New(config); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("missing enrolled identity was not rejected: %v", err)
	}
	if _, err := os.Lstat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("client regenerated a missing private identity: %v", err)
	}
	config.ExpectedIdentityKeyID = keyID
	if _, err := New(config); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected identity binding did not reject missing keys: %v", err)
	}
}

func TestClientExpectedIdentityBindingRejectsDifferentExistingKey(t *testing.T) {
	fixture := newIntegrationFixture(t)
	config := fixture.config
	config.StateDir = filepath.Join(t.TempDir(), "state")
	client, err := New(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	privatePath := filepath.Join(config.StateDir, identityPrivatePath)
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	config.ExpectedIdentityKeyID = strings.Repeat("0", 64)
	if _, err := New(config); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected identity mismatch was not rejected: %v", err)
	}
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("identity binding failure replaced the private identity")
	}
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	releasePublic, releasePrivate, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, desiredPrivate, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "pbp.tar")
	if err := os.WriteFile(artifact, []byte("immutable test artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(7, []release.ArtifactInput{{
		Component: "pbp", Version: "v0.1.7", Target: "linux-amd64", ArtifactName: "pbp.tar", SourcePath: artifact,
	}}, []release.Profile{{Name: testProfile, Components: []string{"pbp"}}}, nil)
	if err != nil {
		t.Fatalf("build release: %v", err)
	}
	signedRelease, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatalf("sign release: %v", err)
	}
	releaseRoot := filepath.Join(root, "releases")
	if err := release.Publish(releaseRoot, signedRelease, map[string]string{manifest.Components[0].Artifact: artifact}, releasePublic); err != nil {
		t.Fatalf("publish release: %v", err)
	}
	desired, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: testInstance, Profile: testProfile,
		Generation: 3, ReleaseSet: manifest.SetID, AuthorizedSSHKeys: []string{testAuthorizedKey(t)},
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, desiredPrivate)
	if err != nil {
		t.Fatalf("sign desired: %v", err)
	}
	enrollmentStore, err := enrollment.NewStore(filepath.Join(root, "serving", "enrollments.json"), enrollment.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("new enrollment store: %v", err)
	}
	credential, err := enrollmentStore.Create(testInstance, testProfile, time.Hour)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	statusStore, err := serving.NewStatusStore(filepath.Join(root, "serving", "statuses"))
	if err != nil {
		t.Fatalf("new status store: %v", err)
	}
	logStore, err := serving.NewLogStore(filepath.Join(root, "serving", "logs"))
	if err != nil {
		t.Fatalf("new log store: %v", err)
	}
	fixture := &integrationFixture{
		root: root, now: now, credential: credential, desired: desired, signedRelease: signedRelease,
		desiredPrivate: desiredPrivate, releasePublic: releasePublic, releasePrivate: releasePrivate, desiredPublic: desiredPublic,
		statusStore: statusStore, logStore: logStore, enrollmentStore: enrollmentStore,
	}
	api, err := serving.New(serving.Config{
		Enrollments: enrollmentStore, Statuses: statusStore, Logs: logStore, ReleaseRoot: releaseRoot,
		ReleasePublicKey: releasePublic, DesiredPublicKey: desiredPublic,
		Audit: serving.AuditFunc(func(serving.AuditEvent) error { return nil }),
		ResolveDesired: func(_ context.Context, _ enrollment.Record) (enrollment.SignedDesiredState, error) {
			return fixture.desired, nil
		},
		Bootstrap: []byte("#!/bin/sh\nexit 0\n"), Clock: func() time.Time { return now }, MaxClockSkew: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("new serving API: %v", err)
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.capturesMu.Lock()
		fixture.hits++
		if request.URL.Path == "/v1/enroll" {
			fixture.enrollQuery = request.URL.RawQuery
			fixture.enrollAuthorization = request.Header.Get(serving.AuthorizationHeader)
			fixture.enrollContentType = request.Header.Get("Content-Type")
		}
		fixture.capturesMu.Unlock()
		if strings.HasPrefix(request.URL.Path, "/v1/instances/") {
			body, readErr := io.ReadAll(io.LimitReader(request.Body, maxStatusBody+1))
			if readErr != nil {
				http.Error(writer, "read failed", http.StatusBadRequest)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			fixture.capturesMu.Lock()
			fixture.captures = append(fixture.captures, capturedRequest{
				method: request.Method, path: request.URL.Path, body: append([]byte(nil), body...),
				authorization: request.Header.Get(serving.AuthorizationHeader),
			})
			fixture.capturesMu.Unlock()
		}
		api.Handler().ServeHTTP(writer, request)
	})
	server, caPEM, pin := startPinnedTLSServer(t, now, handler)
	fixture.server = server
	fixture.config = Config{
		StateDir: filepath.Join(root, "client"), BaseURL: server.URL, CACertificatePEM: caPEM, TLSPin: pin,
		DesiredPublicKey: desiredPublic, ReleasePublicKey: releasePublic,
		Instance: testInstance, Profile: testProfile, RequestTimeout: 5 * time.Second,
		MaxClockSkew: 5 * time.Minute, Clock: func() time.Time { return now },
	}
	return fixture
}

func badEnrollmentHandler(t *testing.T, manifest release.SignedManifest, desired enrollment.SignedDesiredState) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/releases/current/manifest":
			writeCanonicalTest(t, writer, http.StatusOK, manifest)
		case "/v1/enroll":
			body, err := io.ReadAll(io.LimitReader(request.Body, maxEnrollmentBody+1))
			if err != nil || len(body) > maxEnrollmentBody {
				http.Error(writer, "invalid", http.StatusBadRequest)
				return
			}
			var input enrollRequest
			if err := jsonDecodeStrict(body, &input); err != nil {
				http.Error(writer, "invalid", http.StatusBadRequest)
				return
			}
			publicKey, err := signing.ParsePublicPEM([]byte(input.InstancePublicKeyPEM))
			if err != nil {
				http.Error(writer, "invalid", http.StatusBadRequest)
				return
			}
			keyID, _ := signing.KeyID(publicKey)
			writeCanonicalTest(t, writer, http.StatusCreated, enrollResponse{
				Instance: input.Instance, Profile: input.Profile, IdentityKeyID: keyID, Desired: desired,
			})
		default:
			if strings.HasPrefix(request.URL.Path, immutableReleasePathPrefix) && strings.HasSuffix(request.URL.Path, "/manifest") {
				writeCanonicalTest(t, writer, http.StatusOK, manifest)
				return
			}
			http.NotFound(writer, request)
		}
	})
}

func startPinnedTLSServer(t *testing.T, now time.Time, handler http.Handler) (*httptest.Server, []byte, string) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Dynamicflow test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "serving.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafPrivate}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	digest := sha256.Sum256(leafDER)
	return server, caPEM, "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func writeCanonicalTest(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	data, err := signing.CanonicalJSON(value)
	if err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(data, '\n'))
}

func jsonDecodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrUnexpectedResponse
	}
	return nil
}

func testAuthorizedKey(t *testing.T) string {
	t.Helper()
	publicKey, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	_ = binary.Write(&blob, binary.BigEndian, uint32(len("ssh-ed25519")))
	_, _ = blob.WriteString("ssh-ed25519")
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(publicKey)))
	_, _ = blob.Write(publicKey)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " operator"
}

func cloneDesired(input enrollment.SignedDesiredState) enrollment.SignedDesiredState {
	result := input
	result.State.AuthorizedSSHKeys = append([]string(nil), input.State.AuthorizedSSHKeys...)
	result.Signature.Value = append([]byte(nil), input.Signature.Value...)
	return result
}

func cloneLogBatch(input serving.LogBatch) serving.LogBatch {
	result := input
	result.Events = append([]serving.LogEvent(nil), input.Events...)
	return result
}

func assertPrivateStateTree(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("state contains symlink %s", path)
			return nil
		}
		if entry.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("state directory %s has mode %04o", path, info.Mode().Perm())
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != localstate.FileMode {
			t.Errorf("state file %s is not regular mode 0600 (%v)", path, info.Mode())
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("enrollment secret persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk client state: %v", err)
	}
}

type countingReader struct {
	reader *strings.Reader
	reads  int
}

func (reader *countingReader) Read(target []byte) (int, error) {
	reader.reads++
	return reader.reader.Read(target)
}
