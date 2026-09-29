package serving

import (
	"net/http"
	"reflect"
	"testing"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/signing"
)

func TestRevokedIdentityCanSubmitOnlyGenerationBoundFailClosedAck(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.enroll(t)

	ack := NormalizeStatus(StatusReport{
		Schema: StatusSchema, Instance: "vm-01", Profile: "ssh",
		DesiredGeneration: 2, AppliedGeneration: 1, ReleaseSet: fixture.releaseSet,
		State: "revoked", Revoked: true, FailClosed: true, ReportedAt: fixture.now.Unix(),
		Components: []ComponentStatus{{Name: "ssh", Version: "v1.0.0", State: "blocked", Code: "revoked"}},
	})
	ackBody, err := signing.CanonicalJSON(ack)
	if err != nil {
		t.Fatal(err)
	}
	statusPath := "/v1/instances/vm-01/status"

	// a revocation-shaped report cannot be pre-positioned before the signed
	// desired state has actually revoked the identity.
	response := fixture.signedRequest(t, http.MethodPost, statusPath, ackBody,
		fixture.authorization(t, http.MethodPost, statusPath, ackBody))
	assertHTTPStatus(t, response, http.StatusConflict)

	revokedState := fixture.desired.State
	revokedState.Generation = 2
	revokedState.Revoked = true
	revokedState.AuthorizedSSHKeys = nil
	revoked, err := enrollment.SignDesiredState(revokedState, fixture.desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.desired = &revoked

	// a normal ready report from a now-revoked identity is rejected even when
	// it is signed with the still-known instance identity.
	normal := ack
	normal.State, normal.Revoked, normal.FailClosed = "ready", false, false
	normal.Components = []ComponentStatus{{Name: "ssh", Version: "v1.0.0", State: "ready"}}
	normalBody, err := signing.CanonicalJSON(normal)
	if err != nil {
		t.Fatal(err)
	}
	response = fixture.signedRequest(t, http.MethodPost, statusPath, normalBody,
		fixture.authorization(t, http.MethodPost, statusPath, normalBody))
	assertHTTPStatus(t, response, http.StatusConflict)

	authorization := fixture.authorization(t, http.MethodPost, statusPath, ackBody)
	response = fixture.signedRequest(t, http.MethodPost, statusPath, ackBody, authorization)
	assertHTTPStatus(t, response, http.StatusAccepted)
	response = fixture.signedRequest(t, http.MethodPost, statusPath, ackBody, authorization)
	assertHTTPStatus(t, response, http.StatusUnauthorized)
	persisted, err := fixture.statuses.Get("vm-01")
	if err != nil || !reflect.DeepEqual(persisted, ack) {
		t.Fatalf("persisted revocation ack=%#v err=%v, want %#v", persisted, err, ack)
	}

	logPath := "/v1/instances/vm-01/logs/ssh"
	ordinary := LogBatch{
		Schema: LogSchema, Instance: "vm-01", Profile: "ssh", Component: "ssh",
		Events: []LogEvent{{Sequence: 1, Timestamp: fixture.now.Unix(), Level: "info", Event: "reconcile_started"}},
	}
	ordinaryBody, err := signing.CanonicalJSON(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	response = fixture.signedRequest(t, http.MethodPost, logPath, ordinaryBody,
		fixture.authorization(t, http.MethodPost, logPath, ordinaryBody))
	assertHTTPStatus(t, response, http.StatusConflict)

	revocationEvent := LogBatch{
		Schema: LogSchema, Instance: "vm-01", Profile: "ssh", Component: "ssh",
		Events: []LogEvent{{
			Sequence: 2, Timestamp: fixture.now.Unix(), Level: "critical",
			Event: "phase_fail_closed", Code: "revoked",
		}},
	}
	logBody, err := signing.CanonicalJSON(revocationEvent)
	if err != nil {
		t.Fatal(err)
	}
	response = fixture.signedRequest(t, http.MethodPost, logPath, logBody,
		fixture.authorization(t, http.MethodPost, logPath, logBody))
	assertHTTPStatus(t, response, http.StatusAccepted)
	snapshot, err := fixture.logs.Get("vm-01", "ssh")
	if err != nil || len(snapshot.Events) != 1 || snapshot.Events[0] != revocationEvent.Events[0] {
		t.Fatalf("persisted revocation log=%#v err=%v", snapshot, err)
	}
}
