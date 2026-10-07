package serving

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInstanceLogEndpointAuthenticationReplayBoundsTimeAndBinding(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.enroll(t)
	path := "/v1/instances/vm-01/logs/pbp"
	valid := testLogBatch("vm-01", "ssh", "pbp", 1, 2)
	for index := range valid.Events {
		valid.Events[index].Timestamp = fixture.now.Unix()
	}
	validBody := canonicalTestJSON(t, valid)

	response := fixture.signedRequest(t, http.MethodPost, path, validBody, "")
	assertHTTPStatus(t, response, http.StatusUnauthorized)
	response = fixture.signedRequest(t, http.MethodPost, "/v1/instances/vm-01/logs/vpn", validBody,
		fixture.authorization(t, http.MethodPost, path, validBody))
	assertHTTPStatus(t, response, http.StatusUnauthorized)

	request, err := http.NewRequest(http.MethodPost, fixture.tls.URL+path, bytes.NewReader(validBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(AuthorizationHeader, fixture.authorization(t, http.MethodPost, path, validBody))
	response, err = fixture.tls.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertHTTPStatus(t, response, http.StatusBadRequest)

	tooLarge := bytes.Repeat([]byte{'x'}, maxLogBody+1)
	response = fixture.signedRequest(t, http.MethodPost, path, tooLarge, "")
	assertHTTPStatus(t, response, http.StatusRequestEntityTooLarge)

	tests := []struct {
		name  string
		batch LogBatch
	}{
		{name: "instance", batch: testLogBatch("vm-02", "ssh", "pbp", 1, 1)},
		{name: "profile", batch: testLogBatch("vm-01", "pbp", "pbp", 1, 1)},
		{name: "component", batch: testLogBatch("vm-01", "ssh", "vpn", 1, 1)},
		{name: "too old", batch: testLogBatch("vm-01", "ssh", "pbp", 1, 1)},
		{name: "future", batch: testLogBatch("vm-01", "ssh", "pbp", 1, 1)},
	}
	tests[0].batch.Events[0].Timestamp = fixture.now.Unix()
	tests[1].batch.Events[0].Timestamp = fixture.now.Unix()
	tests[2].batch.Events[0].Timestamp = fixture.now.Unix()
	tests[3].batch.Events[0].Timestamp = fixture.now.Add(-30*24*time.Hour - time.Second).Unix()
	tests[4].batch.Events[0].Timestamp = fixture.now.Add(fixture.server.maxClockSkew + time.Second).Unix()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := canonicalTestJSON(t, test.batch)
			response := fixture.signedRequest(t, http.MethodPost, path, body,
				fixture.authorization(t, http.MethodPost, path, body))
			assertHTTPStatus(t, response, http.StatusBadRequest)
		})
	}

	// The finite schema intentionally cannot carry raw stderr/messages.
	var withMessage map[string]any
	if err := json.Unmarshal(validBody, &withMessage); err != nil {
		t.Fatal(err)
	}
	withMessage["message"] = "must-not-be-persisted"
	unknownFieldBody := canonicalTestJSON(t, withMessage)
	response = fixture.signedRequest(t, http.MethodPost, path, unknownFieldBody,
		fixture.authorization(t, http.MethodPost, path, unknownFieldBody))
	assertHTTPStatus(t, response, http.StatusBadRequest)

	authorization := fixture.authorization(t, http.MethodPost, path, validBody)
	response = fixture.signedRequest(t, http.MethodPost, path, validBody, authorization)
	assertHTTPStatus(t, response, http.StatusAccepted)
	response = fixture.signedRequest(t, http.MethodPost, path, validBody, authorization)
	assertHTTPStatus(t, response, http.StatusUnauthorized)
	response = fixture.signedRequest(t, http.MethodPost, path, validBody,
		fixture.authorization(t, http.MethodPost, path, validBody))
	assertHTTPStatus(t, response, http.StatusAccepted)

	stored, err := fixture.logs.Get("vm-01", "pbp")
	if err != nil || len(stored.Events) != len(valid.Events) {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	collision := valid
	collision.Events = append([]LogEvent(nil), valid.Events...)
	collision.Events[0].Code = "installer_failed"
	collisionBody := canonicalTestJSON(t, collision)
	response = fixture.signedRequest(t, http.MethodPost, path, collisionBody,
		fixture.authorization(t, http.MethodPost, path, collisionBody))
	if response.StatusCode != http.StatusConflict {
		body := readResponse(t, response)
		t.Fatalf("collision status=%d body=%s", response.StatusCode, body)
	}
	body := readResponse(t, response)
	if !strings.Contains(body, "log_sequence_conflict") {
		t.Fatalf("collision response=%s", body)
	}
}

func TestAdminLogEndpointControlAuthenticationReplayAndListing(t *testing.T) {
	fixture := newAdminFixture(t)
	for _, component := range []string{"vpn", "pbp"} {
		batch := testLogBatch("vm-01", "ssh", component, 1, 1)
		batch.Events[0].Timestamp = fixture.base.now.Unix()
		if err := fixture.base.logs.Put(batch); err != nil {
			t.Fatal(err)
		}
	}
	componentPath := "/v1/admin/instances/vm-01/logs/pbp"
	response := fixture.request(t, http.MethodGet, componentPath, nil, "")
	assertHTTPStatus(t, response, http.StatusUnauthorized)

	authorization := fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, componentPath, nil)
	response = fixture.request(t, http.MethodGet, componentPath, nil, authorization)
	if response.StatusCode != http.StatusOK {
		body := readResponse(t, response)
		t.Fatalf("admin component logs status=%d body=%s", response.StatusCode, body)
	}
	var snapshot LogSnapshot
	if err := json.Unmarshal([]byte(readResponse(t, response)), &snapshot); err != nil ||
		ValidateLogSnapshot(snapshot) != nil || snapshot.Instance != "vm-01" || snapshot.Component != "pbp" {
		t.Fatalf("admin snapshot=%#v err=%v", snapshot, err)
	}
	response = fixture.request(t, http.MethodGet, componentPath, nil, authorization)
	assertHTTPStatus(t, response, http.StatusUnauthorized)

	wrongPath := "/v1/admin/instances/vm-01/logs/vpn"
	response = fixture.request(t, http.MethodGet, wrongPath, nil,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, componentPath, nil))
	assertHTTPStatus(t, response, http.StatusUnauthorized)

	listPath := "/v1/admin/instances/vm-01/logs"
	response = fixture.request(t, http.MethodGet, listPath, nil,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, listPath, nil))
	if response.StatusCode != http.StatusOK {
		body := readResponse(t, response)
		t.Fatalf("admin log list status=%d body=%s", response.StatusCode, body)
	}
	var listed struct {
		Logs []LogSnapshot `json:"logs"`
	}
	if err := json.Unmarshal([]byte(readResponse(t, response)), &listed); err != nil || len(listed.Logs) != 2 ||
		listed.Logs[0].Component != "pbp" || listed.Logs[1].Component != "vpn" {
		t.Fatalf("admin listed=%#v err=%v", listed, err)
	}

	missingPath := "/v1/admin/instances/vm-02/logs/pbp"
	response = fixture.request(t, http.MethodGet, missingPath, nil,
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, missingPath, nil))
	assertHTTPStatus(t, response, http.StatusNotFound)

	response = fixture.request(t, http.MethodGet, componentPath, []byte{'x'},
		fixture.controlAuthorization(t, fixture.controlPrivate, http.MethodGet, componentPath, []byte{'x'}))
	assertHTTPStatus(t, response, http.StatusUnauthorized)
	response = fixture.request(t, http.MethodPost, componentPath, nil, "")
	assertHTTPStatus(t, response, http.StatusMethodNotAllowed)
}

func TestLogEndpointRejectsNonCanonicalAuthorizationBodyBinding(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.enroll(t)
	path := "/v1/instances/vm-01/logs/pbp"
	batch := testLogBatch("vm-01", "ssh", "pbp", 1, 1)
	batch.Events[0].Timestamp = fixture.now.Unix()
	canonical := canonicalTestJSON(t, batch)
	nonCanonical := append([]byte(" "), canonical...)
	response := fixture.signedRequest(t, http.MethodPost, path, nonCanonical,
		fixture.authorization(t, http.MethodPost, path, canonical))
	assertHTTPStatus(t, response, http.StatusUnauthorized)
}

func assertHTTPStatus(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	if response.StatusCode != expected {
		body := readResponse(t, response)
		t.Fatalf("HTTP status=%d, want %d; body=%s", response.StatusCode, expected, body)
	}
	_ = readResponse(t, response)
}
