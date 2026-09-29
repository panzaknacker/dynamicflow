package serving

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

type servingFixture struct {
	now             time.Time
	server          *Server
	tls             *httptest.Server
	enrollments     *enrollment.Store
	statuses        *StatusStore
	logs            *LogStore
	credential      enrollment.Credential
	instancePublic  ed25519.PublicKey
	instancePrivate ed25519.PrivateKey
	instancePEM     []byte
	releaseSet      string
	releaseRoot     string
	releasePublic   ed25519.PublicKey
	releasePrivate  ed25519.PrivateKey
	artifact        []byte
	artifactLogical string
	desiredPublic   ed25519.PublicKey
	desiredPrivate  ed25519.PrivateKey
	desired         *enrollment.SignedDesiredState
	audit           *recordingAudit
}

type recordingAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (audit *recordingAudit) Record(event AuditEvent) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	return nil
}

func (audit *recordingAudit) snapshot() []AuditEvent {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return append([]AuditEvent(nil), audit.events...)
}

func newServingFixture(t *testing.T) *servingFixture {
	t.Helper()
	fixture := &servingFixture{now: time.Unix(1_800_000_000, 0).UTC(), artifact: []byte("immutable release artifact\n")}
	base := t.TempDir()
	artifactPath := filepath.Join(base, "component.tar")
	if err := os.WriteFile(artifactPath, fixture.artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(1, []release.ArtifactInput{{
		Component: "ssh", Version: "v1.0.0", Target: "linux-amd64", ArtifactName: "component.tar", SourcePath: artifactPath,
	}}, []release.Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(base, "releases")
	fixture.releaseRoot = releaseRoot
	fixture.releasePublic = append(ed25519.PublicKey(nil), releasePublic...)
	fixture.releasePrivate = append(ed25519.PrivateKey(nil), releasePrivate...)
	fixture.artifactLogical = manifest.Components[0].Artifact
	if err := release.Publish(releaseRoot, signedManifest, map[string]string{fixture.artifactLogical: artifactPath}, releasePublic); err != nil {
		t.Fatal(err)
	}
	fixture.releaseSet = manifest.SetID

	privateRoot := filepath.Join(base, "private")
	fixture.enrollments, err = enrollment.NewStore(filepath.Join(privateRoot, "enrollments.json"), enrollment.WithClock(func() time.Time { return fixture.now }))
	if err != nil {
		t.Fatal(err)
	}
	fixture.statuses, err = NewStatusStore(filepath.Join(privateRoot, "statuses"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.logs, err = NewLogStore(filepath.Join(privateRoot, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.credential, err = fixture.enrollments.Create("vm-01", "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.instancePublic, fixture.instancePrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.instancePEM, err = signing.MarshalPublicPEM(fixture.instancePublic)
	if err != nil {
		t.Fatal(err)
	}
	fixture.desiredPublic, fixture.desiredPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: "vm-01", Profile: "ssh", Generation: 1,
		ReleaseSet: fixture.releaseSet, AuthorizedSSHKeys: []string{testAuthorizedKey(t)},
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(30 * time.Minute).Unix(),
	}, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.desired = &desired
	fixture.audit = &recordingAudit{}
	fixture.server, err = New(Config{
		Enrollments: fixture.enrollments, Statuses: fixture.statuses, Logs: fixture.logs, ReleaseRoot: releaseRoot,
		ReleasePublicKey: releasePublic, DesiredPublicKey: fixture.desiredPublic,
		ResolveDesired: func(_ context.Context, _ enrollment.Record) (enrollment.SignedDesiredState, error) {
			return *fixture.desired, nil
		},
		Bootstrap: []byte("#!/bin/sh\nset -eu\n"), Audit: fixture.audit,
		Clock: func() time.Time { return fixture.now }, MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.tls = httptest.NewTLSServer(fixture.server.Handler())
	t.Cleanup(fixture.tls.Close)
	return fixture
}

func TestServingPublicRoutesRequireTLSAndServeVerifiedRelease(t *testing.T) {
	fixture := newServingFixture(t)
	plainRequest := httptest.NewRequest(http.MethodGet, "http://serving/v1/health", nil)
	plainResponse := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP status=%d, want %d", plainResponse.Code, http.StatusUpgradeRequired)
	}

	response := fixture.get(t, "/v1/health")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	if body := readResponse(t, response); !strings.Contains(body, fixture.releaseSet) {
		t.Fatalf("health did not identify verified release: %s", body)
	}
	response = fixture.get(t, "/bootstrap")
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Dynamicflow-Bootstrap-SHA256") == "" {
		t.Fatalf("bootstrap status=%d digest=%q", response.StatusCode, response.Header.Get("X-Dynamicflow-Bootstrap-SHA256"))
	}
	if body := readResponse(t, response); body != "#!/bin/sh\nset -eu\n" {
		t.Fatalf("unexpected bootstrap: %q", body)
	}
	response = fixture.get(t, "/v1/releases/current/manifest")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("manifest status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	manifestBody := readResponse(t, response)
	if !strings.Contains(manifestBody, fixture.releaseSet) || strings.Contains(manifestBody, "PRIVATE KEY") {
		t.Fatalf("unexpected manifest response: %s", manifestBody)
	}
	response = fixture.get(t, "/v1/releases/current/artifacts/"+fixture.artifactLogical)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("artifact status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	if body := []byte(readResponse(t, response)); !bytes.Equal(body, fixture.artifact) {
		t.Fatalf("artifact mismatch: %q", body)
	}
	setName := strings.TrimPrefix(fixture.releaseSet, "sha256:")
	response = fixture.get(t, "/v1/releases/sets/"+setName+"/manifest")
	if response.StatusCode != http.StatusOK || !strings.Contains(readResponse(t, response), fixture.releaseSet) {
		t.Fatal("immutable manifest endpoint did not serve the signed set")
	}
	response = fixture.get(t, "/v1/releases/sets/"+setName+"/artifacts/"+fixture.artifactLogical)
	if response.StatusCode != http.StatusOK || !bytes.Equal([]byte(readResponse(t, response)), fixture.artifact) {
		t.Fatal("immutable artifact endpoint did not serve the signed bytes")
	}
	response = fixture.get(t, "/v1/instances/vm-01/exec")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("generic command route unexpectedly exists: status=%d", response.StatusCode)
	}
}

func TestServingRetainsDesiredReleaseAfterCurrentAdvances(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.enroll(t)
	secondPath := filepath.Join(t.TempDir(), "component-v2.tar")
	if err := os.WriteFile(secondPath, []byte("second immutable release artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := release.BuildFromArtifacts(2, []release.ArtifactInput{{
		Component: "ssh", Version: "v2.0.0", Target: "linux-amd64", ArtifactName: "component-v2.tar", SourcePath: secondPath,
	}}, []release.Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedSecond, err := release.SignManifest(second, fixture.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.Publish(fixture.releaseRoot, signedSecond, map[string]string{second.Components[0].Artifact: secondPath}, fixture.releasePublic); err != nil {
		t.Fatal(err)
	}
	desiredPath := "/v1/instances/vm-01/desired"
	response := fixture.signedRequest(t, http.MethodGet, desiredPath, nil, fixture.authorization(t, http.MethodGet, desiredPath, nil))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("retained desired status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	if body := readResponse(t, response); !strings.Contains(body, fixture.releaseSet) || strings.Contains(body, second.SetID) {
		t.Fatalf("desired state was rebound during publish: %s", body)
	}
	setName := strings.TrimPrefix(fixture.releaseSet, "sha256:")
	response = fixture.get(t, "/v1/releases/sets/"+setName+"/artifacts/"+fixture.artifactLogical)
	if response.StatusCode != http.StatusOK || !bytes.Equal([]byte(readResponse(t, response)), fixture.artifact) {
		t.Fatal("retained desired artifact became unavailable after current advanced")
	}
}

func TestServingRejectsNonCanonicalReleaseSetPaths(t *testing.T) {
	fixture := newServingFixture(t)
	for _, path := range []string{
		"/v1/releases/sets/" + strings.Repeat("A", 64) + "/manifest",
		"/v1/releases/sets/" + strings.Repeat("a", 63) + "/manifest",
		"/v1/releases/sets/" + strings.Repeat("a", 64) + "/artifacts/../manifest",
	} {
		response := fixture.get(t, path)
		if response.StatusCode == http.StatusOK {
			t.Fatalf("unsafe release path was served: %s", path)
		}
		_ = readResponse(t, response)
	}
}

func TestOpenVerifiedArtifactPinsRegularReadOnlySingleLinkFile(t *testing.T) {
	contents := []byte("signed artifact bytes\n")
	digest := sha256.Sum256(contents)
	component := release.Component{
		Name: "ssh", Version: "v1.0.0", Target: "linux-amd64", Artifact: "ssh/v1.0.0/linux-amd64/a.tar",
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(contents)),
	}
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid")
	if err := os.WriteFile(valid, contents, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(valid, 0o444); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(valid); err != nil || info.Mode().Perm() != 0o444 || info.Size() != int64(len(contents)) {
		t.Fatalf("valid artifact fixture mode/size=%v/%d err=%v", info.Mode(), info.Size(), err)
	}
	file, err := openVerifiedArtifact(valid, component)
	if err != nil {
		t.Fatalf("open valid artifact: %v", err)
	}
	_ = file.Close()
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if file, err := openVerifiedArtifact(symlink, component); err == nil {
		_ = file.Close()
		t.Fatal("symlink artifact was accepted")
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(valid, hardlink); err != nil {
		t.Fatal(err)
	}
	if file, err := openVerifiedArtifact(valid, component); err == nil {
		_ = file.Close()
		t.Fatal("multiply linked artifact was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if file, err := openVerifiedArtifact(valid, component); err == nil {
		_ = file.Close()
		t.Fatal("writable published artifact was accepted")
	}
}

func TestServingMutationIsBlockedBeforeHandlerWhenAuditFails(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.server.audit = AuditFunc(func(AuditEvent) error {
		return errors.New("simulated audit sink failure")
	})
	response, err := fixture.tls.Client().Post(
		fixture.tls.URL+"/v1/enroll",
		"application/json",
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		body := readResponse(t, response)
		response.Body.Close()
		t.Fatalf("mutation with failed pre-audit status=%d body=%s", response.StatusCode, body)
	}
	body := readResponse(t, response)
	response.Body.Close()
	if !strings.Contains(body, "audit_unavailable") {
		t.Fatalf("mutation audit failure response=%s", body)
	}
}

func TestEnrollmentDesiredAndStatusAuthenticatedLifecycle(t *testing.T) {
	fixture := newServingFixture(t)
	secretShapedInstance := "A" + fixture.credential.Secret
	if !validStatusName(secretShapedInstance) {
		t.Fatalf("test secret-shaped instance is not a valid identifier: %q", secretShapedInstance)
	}
	untrustedBody, err := signing.CanonicalJSON(enrollRequest{
		EnrollmentID: fixture.credential.ID, Secret: fixture.credential.Secret,
		Instance: secretShapedInstance, Profile: "ssh", InstancePublicKeyPEM: string(fixture.instancePEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.post(t, "/v1/enroll", untrustedBody, "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-binding enrollment status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	auditJSON, err := json.Marshal(fixture.audit.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditJSON, []byte(fixture.credential.Secret)) {
		t.Fatalf("unauthenticated enrollment fields leaked a secret-shaped token into audit: %s", auditJSON)
	}

	enrollmentBody, err := signing.CanonicalJSON(enrollRequest{
		EnrollmentID: fixture.credential.ID, Secret: fixture.credential.Secret, Instance: "vm-01", Profile: "ssh",
		InstancePublicKeyPEM: string(fixture.instancePEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	response = fixture.post(t, "/v1/enroll", enrollmentBody, "")
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	enrollResponseBody := readResponse(t, response)
	if strings.Contains(enrollResponseBody, fixture.credential.Secret) || !strings.Contains(enrollResponseBody, fixture.releaseSet) {
		t.Fatalf("enrollment response leaked secret or omitted desired state: %s", enrollResponseBody)
	}
	response = fixture.post(t, "/v1/enroll", enrollmentBody, "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enrollment replay status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	rejectedBody := readResponse(t, response)
	if strings.Contains(rejectedBody, "consumed") || strings.Contains(rejectedBody, fixture.credential.Secret) {
		t.Fatalf("enrollment rejection leaked credential state: %s", rejectedBody)
	}

	desiredPath := "/v1/instances/vm-01/desired"
	authorization := fixture.authorization(t, http.MethodGet, desiredPath, nil)
	response = fixture.signedRequest(t, http.MethodGet, desiredPath, nil, authorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("desired status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	desiredBody := readResponse(t, response)
	if !strings.Contains(desiredBody, fixture.releaseSet) {
		t.Fatalf("desired response omitted release set: %s", desiredBody)
	}
	response = fixture.signedRequest(t, http.MethodGet, desiredPath, nil, authorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("desired replay status=%d body=%s", response.StatusCode, readResponse(t, response))
	}

	status := NormalizeStatus(StatusReport{
		Schema: StatusSchema, Instance: "vm-01", Profile: "ssh", DesiredGeneration: 1, AppliedGeneration: 1,
		ReleaseSet: fixture.releaseSet, State: "ready", ReportedAt: fixture.now.Unix(),
		Components: []ComponentStatus{{Name: "ssh", Version: "v1.0.0", State: "ready"}},
	})
	statusBody, err := signing.CanonicalJSON(status)
	if err != nil {
		t.Fatal(err)
	}
	statusPath := "/v1/instances/vm-01/status"
	statusAuthorization := fixture.authorization(t, http.MethodPost, statusPath, statusBody)
	response = fixture.signedRequest(t, http.MethodPost, statusPath, statusBody, statusAuthorization)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status report status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	persisted, err := fixture.statuses.Get("vm-01")
	if err != nil || !reflect.DeepEqual(persisted, status) {
		t.Fatalf("persisted status=%#v err=%v, want %#v", persisted, err, status)
	}
	tamperedBody := append([]byte(nil), statusBody...)
	tamperedBody = bytes.Replace(tamperedBody, []byte(`"ready"`), []byte(`"failed"`), 1)
	response = fixture.signedRequest(t, http.MethodPost, statusPath, tamperedBody, fixture.authorization(t, http.MethodPost, statusPath, statusBody))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered signed status=%d body=%s", response.StatusCode, readResponse(t, response))
	}

	auditJSON, err = json.Marshal(fixture.audit.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditJSON, []byte(fixture.credential.Secret)) || bytes.Contains(auditJSON, []byte(fixture.credential.ID)) {
		t.Fatalf("audit events leaked enrollment credential material: %s", auditJSON)
	}
}

func TestServingRejectsTamperedOrWrongReleaseDesiredState(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.enroll(t)
	desiredPath := "/v1/instances/vm-01/desired"

	tampered := *fixture.desired
	tampered.State.Profile = "pbp"
	fixture.desired = &tampered
	response := fixture.signedRequest(t, http.MethodGet, desiredPath, nil, fixture.authorization(t, http.MethodGet, desiredPath, nil))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("tampered desired status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	wrongRelease, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: "vm-01", Profile: "ssh", Generation: 2,
		ReleaseSet: "sha256:" + strings.Repeat("f", 64), AuthorizedSSHKeys: []string{testAuthorizedKey(t)},
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Hour).Unix(),
	}, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.desired = &wrongRelease
	response = fixture.signedRequest(t, http.MethodGet, desiredPath, nil, fixture.authorization(t, http.MethodGet, desiredPath, nil))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("wrong-release desired status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
}

func TestServingConfigContainsNoDesiredPrivateKeyAndSeparatesTrustKeys(t *testing.T) {
	configType := reflect.TypeOf(Config{})
	if _, exists := configType.FieldByName("DesiredSigningKey"); exists {
		t.Fatal("serving Config must not contain a desired-state private signing key")
	}
	fixture := newServingFixture(t)
	_, err := New(Config{
		Enrollments: fixture.enrollments, Statuses: fixture.statuses, ReleaseRoot: fixture.server.releaseRoot,
		ReleasePublicKey: fixture.desiredPublic, DesiredPublicKey: fixture.desiredPublic,
		ResolveDesired: func(context.Context, enrollment.Record) (enrollment.SignedDesiredState, error) {
			return *fixture.desired, nil
		},
		Bootstrap: []byte("bootstrap"),
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("same release/desired trust key: got %v, want ErrInvalidConfig", err)
	}
	_, err = New(Config{
		Enrollments: fixture.enrollments, Statuses: fixture.statuses, ReleaseRoot: fixture.server.releaseRoot,
		ReleasePublicKey: fixture.releasePublic, DesiredPublicKey: fixture.desiredPublic,
		ResolveDesired: func(context.Context, enrollment.Record) (enrollment.SignedDesiredState, error) {
			return *fixture.desired, nil
		},
		Bootstrap: []byte("bootstrap"),
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing structured log store: got %v, want ErrInvalidConfig", err)
	}
}

func (fixture *servingFixture) enroll(t *testing.T) {
	t.Helper()
	body, err := signing.CanonicalJSON(enrollRequest{
		EnrollmentID: fixture.credential.ID, Secret: fixture.credential.Secret, Instance: "vm-01", Profile: "ssh",
		InstancePublicKeyPEM: string(fixture.instancePEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.post(t, "/v1/enroll", body, "")
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
}

func (fixture *servingFixture) authorization(t *testing.T, method, path string, body []byte) string {
	t.Helper()
	signed, err := enrollment.NewSignedInstanceRequest(fixture.instancePrivate, "vm-01", method, path, body, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeAuthorization(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (fixture *servingFixture) get(t *testing.T, path string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, fixture.tls.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.tls.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (fixture *servingFixture) post(t *testing.T, path string, body []byte, authorization string) *http.Response {
	t.Helper()
	return fixture.signedRequest(t, http.MethodPost, path, body, authorization)
}

func (fixture *servingFixture) signedRequest(t *testing.T, method, path string, body []byte, authorization string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, fixture.tls.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set(AuthorizationHeader, authorization)
	}
	response, err := fixture.tls.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testAuthorizedKey(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	for _, value := range [][]byte{[]byte("ssh-ed25519"), publicKey} {
		if err := binary.Write(&blob, binary.BigEndian, uint32(len(value))); err != nil {
			t.Fatal(err)
		}
		if _, err := blob.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " dynamicflow:test"
}
