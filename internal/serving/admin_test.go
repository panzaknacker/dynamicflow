package serving

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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

type adminFixture struct {
	base           *servingFixture
	server         *Server
	tls            *httptest.Server
	desiredStore   *DesiredStore
	controlPublic  ed25519.PublicKey
	controlPrivate ed25519.PrivateKey
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	fixture := &adminFixture{base: newServingFixture(t)}
	var err error
	fixture.controlPublic, fixture.controlPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.desiredStore, err = NewDesiredStore(
		filepath.Join(filepath.Dir(fixture.base.releaseRoot), "private", "admin-desired"), fixture.base.desiredPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server, err = New(Config{
		Enrollments: fixture.base.enrollments, Statuses: fixture.base.statuses, Logs: fixture.base.logs,
		ReleaseRoot: fixture.base.releaseRoot, ReleasePublicKey: fixture.base.releasePublic,
		DesiredPublicKey: fixture.base.desiredPublic, DesiredStates: fixture.desiredStore,
		ControlPublicKey: fixture.controlPublic, Bootstrap: []byte("#!/bin/sh\nset -eu\n"),
		Audit: fixture.base.audit, Clock: func() time.Time { return fixture.base.now }, MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.tls = httptest.NewTLSServer(fixture.server.Handler())
	t.Cleanup(fixture.tls.Close)
	return fixture
}

func TestAdminReleasePlanIsAuthenticatedReadOnlyAndDetectsVersionConflict(t *testing.T) {
	fixture := newAdminFixture(t)
	path := "/v1/admin/releases/plan"
	current, _, err := release.Current(fixture.base.releaseRoot, fixture.base.releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	body := canonicalTestJSON(t, current)
	response := fixture.request(t, http.MethodPost, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, body))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("release plan status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var receipt struct {
		Status string `json:"status"`
		SetID  string `json:"set_id"`
	}
	if err := json.Unmarshal([]byte(readResponse(t, response)), &receipt); err != nil || receipt.Status != "allowed" || receipt.SetID != current.Manifest.SetID {
		t.Fatalf("release plan receipt=%+v err=%v", receipt, err)
	}
	currentAfter, _, err := release.Current(fixture.base.releaseRoot, fixture.base.releasePublic)
	if err != nil || currentAfter.Manifest.SetID != current.Manifest.SetID {
		t.Fatalf("read-only plan changed current: set=%s err=%v", currentAfter.Manifest.SetID, err)
	}

	artifact := filepath.Join(t.TempDir(), "component.tar")
	if err := os.WriteFile(artifact, []byte("different bytes for retained v1.0.0"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := release.BuildFromArtifacts(2, []release.ArtifactInput{{
		Component: "ssh", Version: "v1.0.0", Target: "linux-amd64", ArtifactName: "component.tar", SourcePath: artifact,
	}}, []release.Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.SignManifest(candidate, fixture.base.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	body = canonicalTestJSON(t, signed)
	response = fixture.request(t, http.MethodPost, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, body))
	if response.StatusCode != http.StatusConflict || !strings.Contains(readResponse(t, response), `"code":"version_conflict"`) {
		t.Fatalf("version-conflict plan status=%d", response.StatusCode)
	}
}

func TestAdminEnrollmentTLSControlReplayConflictExpiryAndAuditRedaction(t *testing.T) {
	fixture := newAdminFixture(t)
	plain := httptest.NewRequest(http.MethodGet, "http://serving/v1/admin/enrollments", nil)
	plainResponse := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(plainResponse, plain)
	if plainResponse.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain admin HTTP status=%d, want %d", plainResponse.Code, http.StatusUpgradeRequired)
	}

	desiredOne := fixture.desired(t, "vm-02", 1, fixture.base.releaseSet, fixture.base.now, fixture.base.now.Add(time.Hour))
	createOneBody := canonicalTestJSON(t, AdminEnrollmentCreateRequest{Desired: desiredOne, TTLSeconds: 60})
	createPath := "/v1/admin/enrollments"
	validAuthorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, createPath, createOneBody)
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.request(t, http.MethodPost, createPath, createOneBody,
		fixture.controlAuthorization(t, wrongPrivate, http.MethodPost, createPath, createOneBody))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong control key status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	tamperedBody := append(append([]byte(nil), createOneBody...), ' ')
	response = fixture.request(t, http.MethodPost, createPath, tamperedBody, validAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered admin body status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	response = fixture.request(t, http.MethodPost, createPath, createOneBody, validAuthorization)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("admin create status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	createdBody := readResponse(t, response)
	var created AdminEnrollmentCreateResponse
	if err := json.Unmarshal([]byte(createdBody), &created); err != nil {
		t.Fatal(err)
	}
	if created.Instance != "vm-02" || created.Secret == "" || created.EnrollmentID == "" {
		t.Fatalf("unexpected create response: %#v", created)
	}
	response = fixture.request(t, http.MethodPost, createPath, createOneBody, validAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin replay status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	// A control signature for one instance path is not valid for another.
	statusPath := "/v1/admin/instances/vm-02/status"
	statusAuthorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, statusPath, nil)
	response = fixture.request(t, http.MethodGet, "/v1/admin/instances/vm-03/status", nil, statusAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-instance control path status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	// The operator list is request-signed but never returns one-time secrets.
	listAuthorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, createPath, nil)
	response = fixture.request(t, http.MethodGet, createPath, nil, listAuthorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin list status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	listBody := readResponse(t, response)
	if strings.Contains(listBody, created.Secret) || strings.Contains(listBody, "secret_digest") {
		t.Fatalf("admin list leaked secret material: %s", listBody)
	}

	desiredTwo := fixture.desired(t, "vm-02", 2, fixture.base.releaseSet, fixture.base.now, fixture.base.now.Add(time.Hour))
	createTwoBody := canonicalTestJSON(t, AdminEnrollmentCreateRequest{Desired: desiredTwo, TTLSeconds: 60})
	response = fixture.request(t, http.MethodPost, createPath, createTwoBody,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, createPath, createTwoBody))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("active enrollment conflict status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	stillFirst, err := fixture.desiredStore.Get("vm-02")
	if err != nil || stillFirst.State.Generation != 1 {
		t.Fatalf("conflicting enrollment changed desired state: generation=%d err=%v", stillFirst.State.Generation, err)
	}
	fixture.base.now = fixture.base.now.Add(61 * time.Second)
	response = fixture.request(t, http.MethodPost, createPath, createTwoBody,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, createPath, createTwoBody))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create after expiry status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	secondCreatedBody := readResponse(t, response)
	var secondCreated AdminEnrollmentCreateResponse
	if err := json.Unmarshal([]byte(secondCreatedBody), &secondCreated); err != nil {
		t.Fatal(err)
	}
	if secondCreated.Secret == "" || secondCreated.EnrollmentID == created.EnrollmentID {
		t.Fatalf("unexpected replacement enrollment: %#v", secondCreated)
	}

	auditData, err := json.Marshal(fixture.base.audit.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{created.Secret, secondCreated.Secret, created.EnrollmentID, secondCreated.EnrollmentID} {
		if bytes.Contains(auditData, []byte(secret)) {
			t.Fatalf("audit leaked enrollment credential %q: %s", secret, auditData)
		}
	}
}

func TestAdminReleaseImportAuthenticatesStreamReverifiesAndActivatesAtomically(t *testing.T) {
	fixture := newAdminFixture(t)
	artifactPath := filepath.Join(t.TempDir(), "ssh-v2.tar")
	if err := os.WriteFile(artifactPath, []byte("second immutable release artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(2, []release.ArtifactInput{{
		Component: "ssh", Version: "v2.0.0", Target: "linux-amd64", ArtifactName: "ssh-v2.tar", SourcePath: artifactPath,
	}}, []release.Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.SignManifest(manifest, fixture.base.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if _, _, err := release.WriteBundle(&bundle, signed, map[string]string{manifest.Components[0].Artifact: artifactPath}, fixture.base.releasePublic); err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/releases/import"
	authorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, bundle.Bytes())
	tampered := append([]byte(nil), bundle.Bytes()...)
	tampered[len(tampered)-1] ^= 0xff
	response := fixture.releaseImportRequest(t, path, tampered, authorization)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered import status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	current, _, err := release.Current(fixture.base.releaseRoot, fixture.base.releasePublic)
	if err != nil || current.Manifest.Generation != 1 {
		t.Fatalf("tampered import changed active release: generation=%d err=%v", current.Manifest.Generation, err)
	}

	authorization = fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, bundle.Bytes())
	response = fixture.releaseImportRequest(t, path, bundle.Bytes(), authorization)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("valid import status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var receipt struct {
		Status     string `json:"status"`
		SetID      string `json:"set_id"`
		Generation uint64 `json:"generation"`
		Bytes      int64  `json:"bytes"`
	}
	if err := json.Unmarshal([]byte(readResponse(t, response)), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "activated" || receipt.SetID != manifest.SetID || receipt.Generation != 2 || receipt.Bytes != int64(bundle.Len()) {
		t.Fatalf("unexpected release receipt: %#v", receipt)
	}
	current, _, err = release.Current(fixture.base.releaseRoot, fixture.base.releasePublic)
	if err != nil || current.Manifest.SetID != manifest.SetID {
		t.Fatalf("new release was not activated: set=%s err=%v", current.Manifest.SetID, err)
	}

	response = fixture.releaseImportRequest(t, path, bundle.Bytes(), authorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("release import replay status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	events := fixture.base.audit.snapshot()
	verified, activated := false, false
	for _, event := range events {
		if event.Action == "admin_release_import" && event.Outcome == "verified" {
			verified = true
		}
		if event.Action == "admin_release_import" && event.Outcome == "activated" {
			activated = true
		}
	}
	if !verified || !activated {
		t.Fatalf("release import audit evidence missing: %#v", events)
	}
}

func TestConcurrentReleaseImportsActivateExactlyOneSetPerGeneration(t *testing.T) {
	fixture := newAdminFixture(t)
	path := "/v1/admin/releases/import"
	type candidate struct {
		body          []byte
		authorization string
		setID         string
	}
	candidates := make([]candidate, 0, 2)
	for index, contents := range []string{"candidate-alpha\n", "candidate-bravo\n"} {
		artifactPath := filepath.Join(t.TempDir(), fmt.Sprintf("ssh-v2-%d.tar", index))
		if err := os.WriteFile(artifactPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest, err := release.BuildFromArtifacts(2, []release.ArtifactInput{{
			Component: "ssh", Version: "v2.0.0", Target: "linux-amd64",
			ArtifactName: fmt.Sprintf("ssh-v2-%d.tar", index), SourcePath: artifactPath,
		}}, []release.Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := release.SignManifest(manifest, fixture.base.releasePrivate)
		if err != nil {
			t.Fatal(err)
		}
		var bundle bytes.Buffer
		if _, _, err := release.WriteBundle(&bundle, signed, map[string]string{
			manifest.Components[0].Artifact: artifactPath,
		}, fixture.base.releasePublic); err != nil {
			t.Fatal(err)
		}
		body := append([]byte(nil), bundle.Bytes()...)
		candidates = append(candidates, candidate{
			body: body, setID: manifest.SetID,
			authorization: fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, body),
		})
	}
	type result struct {
		status int
		err    error
	}
	results := make(chan result, len(candidates))
	var wait sync.WaitGroup
	for _, input := range candidates {
		input := input
		wait.Add(1)
		go func() {
			defer wait.Done()
			request, err := http.NewRequest(http.MethodPost, fixture.tls.URL+path, bytes.NewReader(input.body))
			if err != nil {
				results <- result{err: err}
				return
			}
			request.Header.Set("Content-Type", release.BundleMediaType)
			request.Header.Set(ControlAuthorizationHeader, input.authorization)
			response, err := fixture.tls.Client().Do(request)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			results <- result{status: response.StatusCode}
		}()
	}
	wait.Wait()
	close(results)
	statuses := map[int]int{}
	for outcome := range results {
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		statuses[outcome.status]++
	}
	if statuses[http.StatusCreated] != 1 || statuses[http.StatusConflict] != 1 || len(statuses) != 2 {
		t.Fatalf("concurrent import statuses=%v", statuses)
	}
	current, _, err := release.Current(fixture.base.releaseRoot, fixture.base.releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	if current.Manifest.Generation != 2 || current.Manifest.SetID != candidates[0].setID && current.Manifest.SetID != candidates[1].setID {
		t.Fatalf("invalid concurrent winner: generation=%d set=%s", current.Manifest.Generation, current.Manifest.SetID)
	}
	entries, err := os.ReadDir(filepath.Join(fixture.base.releaseRoot, ".imports"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("release import left private upload stages: %v", entries)
	}
}

func TestAdminDesiredRequiresIndependentValidSignatureAndMonotonicGeneration(t *testing.T) {
	fixture := newAdminFixture(t)
	initial := fixture.desired(t, "vm-02", 1, fixture.base.releaseSet, fixture.base.now, fixture.base.now.Add(time.Hour))
	if err := fixture.desiredStore.Put(initial, fixture.base.releaseSet, fixture.base.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/instances/vm-02/desired"
	second := fixture.desired(t, "vm-02", 2, fixture.base.releaseSet, fixture.base.now, fixture.base.now.Add(time.Hour))
	secondBody := canonicalTestJSON(t, second)
	secondAuthorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, secondBody)
	response := fixture.request(t, http.MethodPut, path, append(secondBody, ' '), secondAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered PUT body status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	response = fixture.request(t, http.MethodPut, path, secondBody, secondAuthorization)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("desired generation 2 status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	response = fixture.request(t, http.MethodPut, path, secondBody, secondAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("desired PUT replay status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	response = fixture.request(t, http.MethodPut, path, canonicalTestJSON(t, initial),
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, canonicalTestJSON(t, initial)))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("desired rollback status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	// Possession of the control key alone cannot forge desired-state authority.
	forged := second
	forged.State.Profile = "pbp"
	forgedBody := canonicalTestJSON(t, forged)
	response = fixture.request(t, http.MethodPut, path, forgedBody,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, forgedBody))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("forged desired signature status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	wrongRelease := fixture.desired(t, "vm-02", 3, "sha256:"+strings.Repeat("f", 64), fixture.base.now, fixture.base.now.Add(time.Hour))
	wrongReleaseBody := canonicalTestJSON(t, wrongRelease)
	response = fixture.request(t, http.MethodPut, path, wrongReleaseBody,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, wrongReleaseBody))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("wrong release desired status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	wrongPathAuthorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, path, nil)
	response = fixture.request(t, http.MethodGet, "/v1/admin/instances/vm-03/desired", nil, wrongPathAuthorization)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-instance desired GET status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
}

func TestAdminDesiredRejectsProfileTransitionWithoutPartialMutation(t *testing.T) {
	fixture := newAdminFixture(t)
	artifactPath := filepath.Join(t.TempDir(), "ssh-v2.tar")
	if err := os.WriteFile(artifactPath, []byte("profile transition release artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(2, []release.ArtifactInput{{
		Component: "ssh", Version: "v2.0.0", Target: "linux-amd64", ArtifactName: "ssh-v2.tar", SourcePath: artifactPath,
	}}, []release.Profile{
		{Name: "ssh", Components: []string{"ssh"}},
		{Name: "pbp", Components: []string{"ssh"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest, err := release.SignManifest(manifest, fixture.base.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.Publish(
		fixture.base.releaseRoot, signedManifest,
		map[string]string{manifest.Components[0].Artifact: artifactPath}, fixture.base.releasePublic,
	); err != nil {
		t.Fatal(err)
	}

	const instance = "vm-profile"
	initial := signDesiredFixture(
		t, fixture.base.desiredPrivate, instance, "ssh", manifest.SetID, 1,
		fixture.base.now, fixture.base.now.Add(time.Hour), false,
	)
	if err := fixture.desiredStore.Put(initial, manifest.SetID, fixture.base.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	credential, err := fixture.base.enrollments.Create(instance, "ssh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	instancePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instancePEM, err := signing.MarshalPublicPEM(instancePublic)
	if err != nil {
		t.Fatal(err)
	}
	beforeRecord, err := fixture.base.enrollments.Consume(enrollment.ConsumeRequest{
		ID: credential.ID, Secret: credential.Secret, Instance: instance, Profile: "ssh", InstancePublicKeyPEM: instancePEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	transition := signDesiredFixture(
		t, fixture.base.desiredPrivate, instance, "pbp", manifest.SetID, 2,
		fixture.base.now, fixture.base.now.Add(time.Hour), false,
	)
	path := "/v1/admin/instances/" + instance + "/desired"
	body := canonicalTestJSON(t, transition)
	response := fixture.request(t, http.MethodPut, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, body))
	responseBody := readResponse(t, response)
	if response.StatusCode != http.StatusConflict || !strings.Contains(responseBody, `"code":"profile_transition_unsupported"`) {
		t.Fatalf("profile transition status=%d body=%s", response.StatusCode, responseBody)
	}
	stored, err := fixture.desiredStore.Get(instance)
	if err != nil || !reflect.DeepEqual(stored, initial) {
		t.Fatalf("rejected transition changed desired: stored=%#v err=%v", stored, err)
	}
	afterRecord, err := fixture.base.enrollments.FindInstance(instance)
	if err != nil || !reflect.DeepEqual(afterRecord, beforeRecord) {
		t.Fatalf("rejected transition changed enrollment binding: before=%#v after=%#v err=%v", beforeRecord, afterRecord, err)
	}

	// The rejected generation was never committed; a same-profile update at
	// that generation remains valid and proves normal apply is unchanged.
	sameProfile := signDesiredFixture(
		t, fixture.base.desiredPrivate, instance, "ssh", manifest.SetID, 2,
		fixture.base.now, fixture.base.now.Add(time.Hour), false,
	)
	body = canonicalTestJSON(t, sameProfile)
	response = fixture.request(t, http.MethodPut, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPut, path, body))
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("same-profile update status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	stored, err = fixture.desiredStore.Get(instance)
	if err != nil || stored.State.Profile != "ssh" || stored.State.Generation != 2 {
		t.Fatalf("same-profile desired=%#v err=%v", stored, err)
	}
}

func TestAdminConfigurationSeparatesAllTrustKeysAndContainsNoPrivateKey(t *testing.T) {
	fixture := newAdminFixture(t)
	typeOfPrivateKey := reflect.TypeOf(ed25519.PrivateKey{})
	configType := reflect.TypeOf(Config{})
	for index := 0; index < configType.NumField(); index++ {
		if configType.Field(index).Type == typeOfPrivateKey {
			t.Fatalf("serving Config exposes private-key field %s", configType.Field(index).Name)
		}
	}
	baseConfig := Config{
		Enrollments: fixture.base.enrollments, Statuses: fixture.base.statuses, Logs: fixture.base.logs,
		ReleaseRoot: fixture.base.releaseRoot, ReleasePublicKey: fixture.base.releasePublic,
		DesiredPublicKey: fixture.base.desiredPublic, DesiredStates: fixture.desiredStore,
		ControlPublicKey: fixture.controlPublic, Bootstrap: []byte("bootstrap"),
	}
	for name, key := range map[string]ed25519.PublicKey{
		"release": fixture.base.releasePublic,
		"desired": fixture.base.desiredPublic,
	} {
		candidate := baseConfig
		candidate.ControlPublicKey = key
		if _, err := New(candidate); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("control key equals %s key: got %v, want ErrInvalidConfig", name, err)
		}
	}
	withoutControl := baseConfig
	withoutControl.ControlPublicKey = nil
	if _, err := New(withoutControl); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("admin store without control key: got %v, want ErrInvalidConfig", err)
	}
	bothResolvers := baseConfig
	bothResolvers.ResolveDesired = func(_ context.Context, _ enrollment.Record) (enrollment.SignedDesiredState, error) {
		return *fixture.base.desired, nil
	}
	if _, err := New(bothResolvers); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("desired store plus external resolver: got %v, want ErrInvalidConfig", err)
	}
}

func TestAdminEnrollmentResumesDesiredFirstCrashPoint(t *testing.T) {
	fixture := newAdminFixture(t)
	desired := fixture.desired(t, "vm-resume", 1, fixture.base.releaseSet, fixture.base.now, fixture.base.now.Add(time.Hour))
	// This is the safe state left by a crash after DesiredStore.Put but before
	// enrollment.Create. Retrying the exact request must create only the code.
	if err := fixture.desiredStore.Put(desired, fixture.base.releaseSet, fixture.base.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	body := canonicalTestJSON(t, AdminEnrollmentCreateRequest{Desired: desired, TTLSeconds: 300})
	path := "/v1/admin/enrollments"
	response := fixture.request(t, http.MethodPost, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, body))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("resume desired-first state status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
	active, err := fixture.base.enrollments.HasActiveInstance("vm-resume")
	if err != nil || !active {
		t.Fatalf("resumed enrollment active=%v err=%v", active, err)
	}
	stored, err := fixture.desiredStore.Get("vm-resume")
	if err != nil || !reflect.DeepEqual(stored, desired) {
		t.Fatalf("resumed desired=%#v err=%v", stored, err)
	}
}

func TestAdminRejectsSignedProfileAbsentFromCurrentRelease(t *testing.T) {
	fixture := newAdminFixture(t)
	desired := signDesiredFixture(
		t, fixture.base.desiredPrivate, "vm-pbp", "pbp", fixture.base.releaseSet, 1,
		fixture.base.now, fixture.base.now.Add(time.Hour), false,
	)
	body := canonicalTestJSON(t, AdminEnrollmentCreateRequest{Desired: desired, TTLSeconds: 300})
	path := "/v1/admin/enrollments"
	response := fixture.request(t, http.MethodPost, path, body,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodPost, path, body))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown profile create status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	responseBody := readResponse(t, response)
	if !strings.Contains(responseBody, "profile_not_found") {
		t.Fatalf("unknown profile response=%s", responseBody)
	}
	active, err := fixture.base.enrollments.HasActiveInstance("vm-pbp")
	if err != nil || active {
		t.Fatalf("unknown profile created enrollment: active=%v err=%v", active, err)
	}
}

func TestControlReplayRejectedAfterServingRestart(t *testing.T) {
	fixture := newAdminFixture(t)
	path := "/v1/admin/enrollments"
	authorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, path, nil)
	response := fixture.request(t, http.MethodGet, path, nil, authorization)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("first admin list status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)

	reopenedEnrollments, err := enrollment.NewStore(
		filepath.Join(filepath.Dir(fixture.base.releaseRoot), "private", "enrollments.json"),
		enrollment.WithClock(func() time.Time { return fixture.base.now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Config{
		Enrollments: reopenedEnrollments, Statuses: fixture.base.statuses, Logs: fixture.base.logs,
		ReleaseRoot: fixture.base.releaseRoot, ReleasePublicKey: fixture.base.releasePublic,
		DesiredPublicKey: fixture.base.desiredPublic, DesiredStates: fixture.desiredStore,
		ControlPublicKey: fixture.controlPublic, Bootstrap: []byte("#!/bin/sh\nset -eu\n"),
		Audit: fixture.base.audit, Clock: func() time.Time { return fixture.base.now }, MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	restartedTLS := httptest.NewTLSServer(restarted.Handler())
	defer restartedTLS.Close()
	request, err := http.NewRequest(http.MethodGet, restartedTLS.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(ControlAuthorizationHeader, authorization)
	response, err = restartedTLS.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay after restart status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	_ = readResponse(t, response)
}

func (fixture *adminFixture) desired(t *testing.T, instance string, generation uint64, releaseSet string, issuedAt, expiresAt time.Time) enrollment.SignedDesiredState {
	t.Helper()
	return signDesiredFixture(t, fixture.base.desiredPrivate, instance, "ssh", releaseSet, generation, issuedAt, expiresAt, false)
}

func (fixture *adminFixture) controlAuthorization(t *testing.T, privateKey ed25519.PrivateKey, method, path string, body []byte) string {
	t.Helper()
	signed, err := enrollment.NewSignedControlRequest(privateKey, method, path, body, fixture.base.now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeControlAuthorization(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (fixture *adminFixture) request(t *testing.T, method, path string, body []byte, authorization string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, fixture.tls.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set(ControlAuthorizationHeader, authorization)
	}
	response, err := fixture.tls.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (fixture *adminFixture) releaseImportRequest(t *testing.T, path string, body []byte, authorization string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, fixture.tls.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", release.BundleMediaType)
	request.Header.Set(ControlAuthorizationHeader, authorization)
	response, err := fixture.tls.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func canonicalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := signing.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
