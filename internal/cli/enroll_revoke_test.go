package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/tlsutil"
)

func TestEnrollRevokeCLIContractsByIDAndName(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments func(string) []string
		wantPaths []string
	}{
		{
			name: "explicit id",
			arguments: func(id string) []string {
				return []string{"enroll", "revoke", "--id", id}
			},
			wantPaths: []string{"POST /v1/admin/enrollments/%s/revoke"},
		},
		{
			name: "instance name",
			arguments: func(string) []string {
				return []string{"enroll", "revoke", "--name", "pbp-01"}
			},
			wantPaths: []string{"GET /v1/admin/enrollments", "POST /v1/admin/enrollments/%s/revoke"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := testEnrollmentID(1)
			var requests synchronizedStrings
			fixture := newEnrollRevokeFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				requests.append(request.Method + " " + request.URL.Path)
				if request.Header.Get(serving.ControlAuthorizationHeader) == "" {
					t.Error("control request omitted authorization")
				}
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/v1/admin/enrollments":
					writeTestJSON(t, response, http.StatusOK, map[string]any{
						"enrollments": []enrollment.Record{liveEnrollmentRecord(id, "pbp-01")},
					})
				case request.Method == http.MethodPost && request.URL.Path == "/v1/admin/enrollments/"+id+"/revoke":
					record := liveEnrollmentRecord(id, "pbp-01")
					record.RevokedAt = time.Now().UTC().Unix()
					writeTestJSON(t, response, http.StatusAccepted, record)
				default:
					writeTestJSON(t, response, http.StatusNotFound, map[string]any{
						"error": map[string]string{"code": "not_found"},
					})
				}
			}))

			arguments := append([]string{"--json", "--home", fixture.home}, test.arguments(id)...)
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, arguments...)
			if status != exitOK || stderr != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stdout)
			if !envelope.OK || envelope.Command != "enroll.revoke" || envelope.Error != nil {
				t.Fatalf("envelope=%+v", envelope)
			}
			var data struct {
				EnrollmentID string `json:"enrollment_id"`
				Instance     string `json:"instance"`
				Profile      string `json:"profile"`
				Revoked      bool   `json:"revoked"`
			}
			if err := json.Unmarshal(envelope.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data.EnrollmentID != id || data.Instance != "pbp-01" || data.Profile != "pbp" || !data.Revoked {
				t.Fatalf("data=%+v", data)
			}
			wantPaths := make([]string, len(test.wantPaths))
			for index, path := range test.wantPaths {
				wantPaths[index] = strings.ReplaceAll(path, "%s", id)
			}
			if got := requests.snapshot(); !equalStrings(got, wantPaths) {
				t.Fatalf("requests=%v, want %v", got, wantPaths)
			}
		})
	}
}

func TestEnrollRevokeNameRejectsAmbiguousLiveRecords(t *testing.T) {
	firstID, secondID := testEnrollmentID(2), testEnrollmentID(3)
	var requests synchronizedStrings
	fixture := newEnrollRevokeFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.append(request.Method + " " + request.URL.Path)
		if request.Method != http.MethodGet || request.URL.Path != "/v1/admin/enrollments" {
			writeTestJSON(t, response, http.StatusInternalServerError, map[string]any{
				"error": map[string]string{"code": "unexpected_revoke"},
			})
			return
		}
		writeTestJSON(t, response, http.StatusOK, map[string]any{
			"enrollments": []enrollment.Record{
				liveEnrollmentRecord(firstID, "duplicate"),
				liveEnrollmentRecord(secondID, "duplicate"),
			},
		})
	}))

	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
		"--json", "--home", fixture.home, "enroll", "revoke", "--name", "duplicate",
	)
	if status != exitConflict || stdout != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "conflict" ||
		!strings.Contains(envelope.Error.Message, "multiple live enrollment") {
		t.Fatalf("envelope=%+v", envelope)
	}
	if got := requests.snapshot(); !equalStrings(got, []string{"GET /v1/admin/enrollments"}) {
		t.Fatalf("ambiguous name performed unexpected requests: %v", got)
	}
}

func TestEnrollRevokeRestoresMatchingLocalIssuedEnrollmentDraft(t *testing.T) {
	id := testEnrollmentID(4)
	fixture := newEnrollRevokeFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/admin/enrollments/"+id+"/revoke" {
			writeTestJSON(t, response, http.StatusNotFound, map[string]any{
				"error": map[string]string{"code": "not_found"},
			})
			return
		}
		record := liveEnrollmentRecord(id, "pbp-restore")
		record.RevokedAt = time.Now().UTC().Unix()
		writeTestJSON(t, response, http.StatusAccepted, record)
	}))
	createdAt := time.Now().UTC().Add(-time.Hour)
	local := localEnrollment{
		Schema: 1, Name: "pbp-restore", Profile: "pbp",
		KeyScope: sshkeys.Instance, KeyName: "pbp-restore", KeyGeneration: 1,
		Desired: enrollment.SignedDesiredState{
			State: enrollment.DesiredState{Instance: "pbp-restore", Profile: "pbp", Generation: 7},
		},
		State: "issued", EnrollmentID: id, ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if err := fixture.store.WriteJSON(filepath.Join("enrollments", local.Name+".json"), local); err != nil {
		t.Fatal(err)
	}

	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
		"--json", "--home", fixture.home, "enroll", "revoke", "--id", id,
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	_ = decodeCLIEnvelope(t, stdout)
	var restored localEnrollment
	if err := fixture.store.ReadJSON(filepath.Join("enrollments", local.Name+".json"), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.State != "draft" || restored.EnrollmentID != "" || restored.ExpiresAt != 0 {
		t.Fatalf("restored local enrollment=%+v", restored)
	}
	if restored.CreatedAt != createdAt || !restored.UpdatedAt.After(local.UpdatedAt) ||
		restored.Desired.State.Generation != local.Desired.State.Generation ||
		restored.KeyName != local.KeyName || restored.KeyGeneration != local.KeyGeneration {
		t.Fatalf("draft restoration changed stable binding: before=%+v after=%+v", local, restored)
	}
}

func TestEnrollRevokeServerErrorsUseRemoteFailureContract(t *testing.T) {
	id := testEnrollmentID(5)
	for _, test := range []struct {
		name       string
		arguments  []string
		wantMethod string
		wantPath   string
		status     int
		remoteCode string
	}{
		{
			name: "list by name", arguments: []string{"enroll", "revoke", "--name", "pbp-error"},
			wantMethod: http.MethodGet, wantPath: "/v1/admin/enrollments",
			status: http.StatusServiceUnavailable, remoteCode: "audit_unavailable",
		},
		{
			name: "revoke by id", arguments: []string{"enroll", "revoke", "--id", id},
			wantMethod: http.MethodPost, wantPath: "/v1/admin/enrollments/" + id + "/revoke",
			status: http.StatusInternalServerError, remoteCode: "state",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests synchronizedStrings
			fixture := newEnrollRevokeFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				requests.append(request.Method + " " + request.URL.Path)
				writeTestJSON(t, response, test.status, map[string]any{
					"error": map[string]string{"code": test.remoteCode},
				})
			}))
			arguments := append([]string{"--json", "--home", fixture.home}, test.arguments...)
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, arguments...)
			if status != exitRemote || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.OK || envelope.Error == nil || envelope.Error.Code != "enrollment" ||
				!strings.Contains(envelope.Error.Message, test.remoteCode) {
				t.Fatalf("envelope=%+v", envelope)
			}
			want := test.wantMethod + " " + test.wantPath
			if got := requests.snapshot(); !equalStrings(got, []string{want}) {
				t.Fatalf("requests=%v, want [%s]", got, want)
			}
		})
	}
}

func TestEnrollCreateRevokesValidIDFromInvalidCredentialResponse(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is unavailable")
	}
	name := "invalid-response"
	id := testEnrollmentID(9)
	secretMarker := "short-secret-marker"
	var signedRelease release.SignedManifest
	var requests synchronizedStrings
	fixture := newEnrollRevokeFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.append(request.Method + " " + request.URL.Path)
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/releases/current/manifest":
			writeTestJSON(t, response, http.StatusOK, signedRelease)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/admin/enrollments":
			writeTestJSON(t, response, http.StatusCreated, serving.AdminEnrollmentCreateResponse{
				EnrollmentID: id, Secret: secretMarker, Instance: name, Profile: "pbp",
				ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
			})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/admin/enrollments/"+id+"/revoke":
			record := liveEnrollmentRecord(id, name)
			record.RevokedAt = time.Now().UTC().Unix()
			writeTestJSON(t, response, http.StatusAccepted, record)
		default:
			writeTestJSON(t, response, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "not_found"}})
		}
	}))
	root := repositoryRoot(t)
	if status, _, stderr := invokeCLI(t, "--json", "--home", fixture.home, "--source-root", root, "init"); status != exitOK {
		t.Fatalf("init status=%d stderr=%s", status, stderr)
	}
	releasePrivatePath, _ := fixture.store.Path("keys/signing/release.private.pem")
	releasePublicPath, _ := fixture.store.Path("keys/signing/release.public.pem")
	releasePrivate, err := signing.LoadPrivateFile(releasePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	releasePublic, err := signing.LoadPublicFile(releasePublicPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "pbp.tar")
	if err := os.WriteFile(artifact, []byte("test release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(1, []release.ArtifactInput{{
		Component: "pbp", Version: "v0.1.8", Target: "linux-amd64", ArtifactName: "pbp.tar", SourcePath: artifact,
	}}, []release.Profile{{Name: "pbp", Components: []string{"pbp"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedRelease, err = release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	controlPublicPath, _ := fixture.store.Path("keys/signing/control.public.pem")
	desiredPublicPath, _ := fixture.store.Path("keys/signing/desired-state.public.pem")
	controlPublic, _ := signing.LoadPublicFile(controlPublicPath)
	desiredPublic, _ := signing.LoadPublicFile(desiredPublicPath)
	releaseKeyID, _ := signing.KeyID(releasePublic)
	controlKeyID, _ := signing.KeyID(controlPublic)
	desiredKeyID, _ := signing.KeyID(desiredPublic)
	var remote operatorServingConfig
	if err := fixture.store.ReadJSON("serving/remote.json", &remote); err != nil {
		t.Fatal(err)
	}
	remote.ReleaseSet, remote.ReleaseKeyID, remote.ControlKeyID, remote.DesiredKeyID = manifest.SetID, releaseKeyID, controlKeyID, desiredKeyID
	if err := fixture.store.WriteJSON("serving/remote.json", remote); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
		"--json", "--home", fixture.home, "--source-root", root,
		"enroll", "create", "--name", name, "--profile", "pbp",
	)
	if status != exitVerify || stdout != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.OK || failure.Error == nil || failure.Error.Code != "verification" || !strings.Contains(failure.Error.Message, "was revoked") {
		t.Fatalf("failure=%+v", failure)
	}
	if strings.Contains(stdout+stderr, secretMarker) {
		t.Fatal("invalid response secret reached CLI output")
	}
	want := []string{
		"GET /v1/releases/current/manifest",
		"POST /v1/admin/enrollments",
		"POST /v1/admin/enrollments/" + id + "/revoke",
	}
	if got := requests.snapshot(); !equalStrings(got, want) {
		t.Fatalf("requests=%v want=%v", got, want)
	}
	var local localEnrollment
	if err := fixture.store.ReadJSON(filepath.Join("enrollments", name+".json"), &local); err != nil {
		t.Fatal(err)
	}
	if local.State != "draft" || local.EnrollmentID != "" {
		t.Fatalf("invalid credential changed draft state: %+v", local)
	}
	auditBytes, err := os.ReadFile(filepath.Join(fixture.home, "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditBytes, []byte(secretMarker)) || !bytes.Contains(auditBytes, []byte("invalid_response_revoked")) {
		t.Fatalf("unexpected audit record: %s", auditBytes)
	}
}

type enrollRevokeFixture struct {
	home  string
	store *localstate.Store
}

func newEnrollRevokeFixture(t *testing.T, handler http.Handler) enrollRevokeFixture {
	t.Helper()
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureDir("keys/signing"); err != nil {
		t.Fatal(err)
	}
	controlPrivatePath, _ := store.Path("keys/signing/control.private.pem")
	controlPublicPath, _ := store.Path("keys/signing/control.public.pem")
	controlPublic, err := signing.GenerateFiles(controlPrivatePath, controlPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	controlKeyID, err := signing.KeyID(controlPublic)
	if err != nil {
		t.Fatal(err)
	}

	tlsRoot := privateTempDir(t)
	certificatePath := filepath.Join(tlsRoot, "serving.crt")
	privateKeyPath := filepath.Join(tlsRoot, "serving.key")
	pin, err := tlsutil.GenerateSelfSigned(certificatePath, privateKeyPath, []string{"127.0.0.1"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile(remoteCAPath, certificatePEM); err != nil {
		t.Fatal(err)
	}
	storedCA, _ := store.Path(remoteCAPath)
	if err := store.WriteJSON("serving/remote.json", operatorServingConfig{
		Schema: 1, BaseURL: server.URL, TLSPin: pin,
		ReleaseSet:    "sha256:" + strings.Repeat("a", 64),
		ConfiguredAt:  time.Now().UTC(),
		CACertificate: storedCA,
		ReleaseKeyID:  "test-release-key",
		ControlKeyID:  controlKeyID,
		DesiredKeyID:  "test-desired-key",
	}); err != nil {
		t.Fatal(err)
	}
	return enrollRevokeFixture{home: home, store: store}
}

func liveEnrollmentRecord(id, instance string) enrollment.Record {
	now := time.Now().UTC()
	return enrollment.Record{
		ID: id, Instance: instance, Profile: "pbp",
		CreatedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
}

func testEnrollmentID(marker byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 16))
}

func writeTestJSON(t *testing.T, response http.ResponseWriter, status int, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}

type synchronizedStrings struct {
	mutex  sync.Mutex
	values []string
}

func (values *synchronizedStrings) append(value string) {
	values.mutex.Lock()
	defer values.mutex.Unlock()
	values.values = append(values.values, value)
}

func (values *synchronizedStrings) snapshot() []string {
	values.mutex.Lock()
	defer values.mutex.Unlock()
	return append([]string(nil), values.values...)
}

func equalStrings(left, right []string) bool {
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
