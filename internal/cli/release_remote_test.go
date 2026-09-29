package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/tlsutil"
)

func TestReleasePublishUsesPinnedAuthenticatedRemoteStreamingImport(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "release", "build", "--generation", "71"); status != exitOK {
		t.Fatalf("build status=%d: %s", status, stderr)
	}
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	var stage stagedRelease
	if err := store.ReadJSON("releases/staged.json", &stage); err != nil {
		t.Fatal(err)
	}
	releasePublicPath, _ := store.Path("keys/signing/release.public.pem")
	controlPublicPath, _ := store.Path("keys/signing/control.public.pem")
	desiredPublicPath, _ := store.Path("keys/signing/desired-state.public.pem")
	releasePublic, err := signing.LoadPublicFile(releasePublicPath)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, err := signing.LoadPublicFile(controlPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, err := signing.LoadPublicFile(desiredPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	releaseKeyID, _ := signing.KeyID(releasePublic)
	controlKeyID, _ := signing.KeyID(controlPublic)
	desiredKeyID, _ := signing.KeyID(desiredPublic)

	var state remoteReleaseTestState
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		state.record(request.Method + " " + request.URL.Path)
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/admin/releases/plan":
			body, readErr := io.ReadAll(io.LimitReader(request.Body, release.MaxManifestEnvelopeBytes+1))
			authorization, authErr := serving.DecodeControlAuthorization(request.Header.Values(serving.ControlAuthorizationHeader))
			digest := sha256.Sum256(body)
			bodyDigest := "sha256:" + hex.EncodeToString(digest[:])
			var planned release.SignedManifest
			decodeErr := json.Unmarshal(body, &planned)
			if readErr != nil || authErr != nil || decodeErr != nil || authorization.Request.Method != http.MethodPost ||
				authorization.Request.Path != request.URL.Path || authorization.Request.BodyDigest != bodyDigest ||
				signing.VerifyCanonical(controlPublic, enrollment.ControlRequestDomain, authorization.Request, authorization.Signature) != nil ||
				release.VerifyManifest(planned, releasePublic) != nil || planned.Manifest.SetID != stage.Signed.Manifest.SetID {
				writeTestJSON(t, response, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "control_authentication_failed"}})
				return
			}
			writeTestJSON(t, response, http.StatusOK, map[string]any{
				"status": "allowed", "set_id": planned.Manifest.SetID, "generation": planned.Manifest.Generation,
			})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/admin/releases/import":
			if request.Header.Get("Content-Type") != release.BundleMediaType || request.Header.Get(serving.ControlAuthorizationHeader) == "" {
				writeTestJSON(t, response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_headers"}})
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(request.Body, 16<<20))
			if readErr != nil {
				writeTestJSON(t, response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "read_failed"}})
				return
			}
			authorization, authErr := serving.DecodeControlAuthorization(request.Header.Values(serving.ControlAuthorizationHeader))
			digest := sha256.Sum256(body)
			bodyDigest := "sha256:" + hex.EncodeToString(digest[:])
			if authErr != nil || authorization.Request.Method != http.MethodPost || authorization.Request.Path != request.URL.Path ||
				authorization.Request.BodyDigest != bodyDigest ||
				signing.VerifyCanonical(controlPublic, enrollment.ControlRequestDomain, authorization.Request, authorization.Signature) != nil {
				writeTestJSON(t, response, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "control_authentication_failed"}})
				return
			}
			stageDirectory := filepath.Join(t.TempDir(), "remote-import")
			if err := os.Mkdir(stageDirectory, 0o700); err != nil {
				writeTestJSON(t, response, http.StatusInternalServerError, map[string]any{"error": map[string]string{"code": "stage_failed"}})
				return
			}
			decoded, paths, size, decodedDigest, decodeErr := release.ReadBundle(bytes.NewReader(body), stageDirectory, releasePublic)
			if decodeErr != nil || release.VerifyArtifacts(decoded.Manifest, paths) != nil || decoded.Manifest.SetID != stage.Signed.Manifest.SetID ||
				size != int64(len(body)) || decodedDigest != bodyDigest {
				writeTestJSON(t, response, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "invalid_release_bundle"}})
				return
			}
			state.setBundle(body)
			writeTestJSON(t, response, http.StatusCreated, map[string]any{
				"status": "activated", "set_id": decoded.Manifest.SetID, "generation": decoded.Manifest.Generation, "bytes": size,
			})
		case request.Method == http.MethodGet && request.URL.Path == "/v1/releases/current/manifest":
			writeTestJSON(t, response, http.StatusOK, stage.Signed)
		default:
			writeTestJSON(t, response, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "not_found"}})
		}
	})
	server, certificatePEM, pin := startReleaseRemoteTLSServer(t, handler)
	if err := store.WriteFile(remoteCAPath, certificatePEM); err != nil {
		t.Fatal(err)
	}
	storedCA, _ := store.Path(remoteCAPath)
	if err := store.WriteJSON("serving/remote.json", operatorServingConfig{
		Schema: 1, BaseURL: server.URL, TLSPin: pin,
		ReleaseSet: "sha256:" + strings.Repeat("0", 64), ConfiguredAt: time.Now().UTC(), CACertificate: storedCA,
		ReleaseKeyID: releaseKeyID, ControlKeyID: controlKeyID, DesiredKeyID: desiredKeyID,
	}); err != nil {
		t.Fatal(err)
	}

	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, "--json", "--home", home, "release", "publish", "--plan")
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	plan := decodeCLIEnvelope(t, stdout)
	if !plan.OK || plan.Command != "release.publish.plan" || !reflect.DeepEqual(state.requestsSnapshot(), []string{"POST /v1/admin/releases/plan"}) {
		t.Fatalf("remote plan preflight mismatch: plan=%+v requests=%v", plan, state.requestsSnapshot())
	}

	status, stdout, stderr = invokeInternalLegacyHandlerForTest(t, "--json", "--home", home, "release", "publish")
	if status != exitOK || stderr != "" {
		t.Fatalf("publish status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	result := decodeCLIEnvelope(t, stdout)
	if !result.OK || result.Command != "release.publish" {
		t.Fatalf("publish envelope=%+v", result)
	}
	requests := state.requestsSnapshot()
	if len(requests) != 3 || requests[0] != "POST /v1/admin/releases/plan" || requests[1] != "POST /v1/admin/releases/import" || requests[2] != "GET /v1/releases/current/manifest" {
		t.Fatalf("unexpected remote publish requests: %v", requests)
	}
	if bundle := state.bundleSnapshot(); len(bundle) == 0 || bytes.Contains(bundle, []byte("PRIVATE KEY")) {
		t.Fatalf("remote bundle missing or leaked private key material: bytes=%d", len(bundle))
	}
	var configured operatorServingConfig
	if err := store.ReadJSON("serving/remote.json", &configured); err != nil || configured.ReleaseSet != stage.Signed.Manifest.SetID {
		t.Fatalf("remote checkpoint not updated: set=%s err=%v", configured.ReleaseSet, err)
	}
	var highWater operatorReleaseHighWater
	if err := store.ReadJSON(operatorReleaseHighWaterPath, &highWater); err != nil || highWater.Generation != 71 || highWater.SetID != stage.Signed.Manifest.SetID {
		t.Fatalf("operator high-water not committed: %+v err=%v", highWater, err)
	}
	uploadDirectory := filepath.Join(home, "releases", "upload")
	entries, err := os.ReadDir(uploadDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary release bundle was retained: entries=%v err=%v", entries, err)
	}
}

func TestLoadOperatorServingConfigRejectsSharedTrustRootBindings(t *testing.T) {
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	caPath, _ := store.Path(remoteCAPath)
	if err := store.WriteJSON("serving/remote.json", operatorServingConfig{
		Schema: 1, BaseURL: "https://127.0.0.1:8443", TLSPin: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ReleaseSet:    "sha256:" + strings.Repeat("a", 64),
		ConfiguredAt:  time.Now().UTC(),
		CACertificate: caPath,
		ReleaseKeyID:  strings.Repeat("1", 64),
		DesiredKeyID:  strings.Repeat("1", 64),
		ControlKeyID:  strings.Repeat("2", 64),
	}); err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	if _, _, err := loadOperatorServingConfig(ctx); err == nil || !strings.Contains(err.Error(), "share one Ed25519 root") {
		t.Fatalf("shared trust-root binding was accepted: %v", err)
	}
}

func TestReleasePublishCandidateChecksHighWaterWithoutAdvancingIt(t *testing.T) {
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	current := operatorReleaseHighWater{Schema: 1, Generation: 10, SetID: "sha256:" + strings.Repeat("a", 64)}
	if err := store.WriteJSON(operatorReleaseHighWaterPath, current); err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	if err := verifyOperatorReleaseCandidate(ctx, release.Manifest{Generation: 9, SetID: "sha256:" + strings.Repeat("b", 64)}); err == nil {
		t.Fatal("rollback candidate passed pre-upload high-water check")
	}
	if err := verifyOperatorReleaseCandidate(ctx, release.Manifest{Generation: 10, SetID: "sha256:" + strings.Repeat("b", 64)}); err == nil {
		t.Fatal("equal-generation conflict passed pre-upload high-water check")
	}
	if err := verifyOperatorReleaseCandidate(ctx, release.Manifest{Generation: 11, SetID: "sha256:" + strings.Repeat("c", 64)}); err != nil {
		t.Fatalf("higher candidate failed read-only check: %v", err)
	}
	var after operatorReleaseHighWater
	if err := store.ReadJSON(operatorReleaseHighWaterPath, &after); err != nil || after != current {
		t.Fatalf("pre-upload check advanced high-water: after=%+v err=%v", after, err)
	}
}

type remoteReleaseTestState struct {
	mu       sync.Mutex
	requests []string
	bundle   []byte
}

func (state *remoteReleaseTestState) record(value string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.requests = append(state.requests, value)
}

func (state *remoteReleaseTestState) setBundle(value []byte) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.bundle = append([]byte(nil), value...)
}

func (state *remoteReleaseTestState) requestsSnapshot() []string {
	state.mu.Lock()
	defer state.mu.Unlock()
	return append([]string(nil), state.requests...)
}

func (state *remoteReleaseTestState) bundleSnapshot() []byte {
	state.mu.Lock()
	defer state.mu.Unlock()
	return append([]byte(nil), state.bundle...)
}

func startReleaseRemoteTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte, string) {
	t.Helper()
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
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	return server, certificatePEM, pin
}

func decodeJSONForReleaseTest(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}
