package cli

import (
	"context"
	"dynamicflow/internal/instanceclient"
	"encoding/json"
	"strings"
	"testing"

	"dynamicflow/internal/targetapply"
)

func TestInstanceRuntimeHandoffDoesNotReportReadyOrRequireOldBinaryProfileWork(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	client := newFakeRuntimeClient(fixture)
	client.readSecret = true
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	hostKeyReads := 0
	deps.readSSHHostKey = func() (string, error) {
		hostKeyReads++
		return "", nil
	}
	deps.runApply = func(_ context.Context, config targetapply.Config) (targetapply.Result, error) {
		if len(config.Plan.Phases) == 0 || config.Plan.Phases[0].Profile != "flow" {
			t.Fatalf("runtime phase was not first: %#v", config.Plan.Phases)
		}
		for _, state := range []string{"preflight", "applying", "verifying", "complete"} {
			config.Event("flow", state, "")
		}
		return targetapply.Result{PlanID: config.Plan.ID, HandoffRequired: true}, nil
	}

	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" {
		t.Fatalf("handoff status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if hostKeyReads != 0 {
		t.Fatalf("handoff tried to read an SSH host key %d times", hostKeyReads)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var data struct {
		RuntimeHandoff    bool   `json:"runtime_handoff"`
		ProfileApplied    bool   `json:"profile_applied"`
		AppliedGeneration uint64 `json:"applied_generation"`
		PlanID            string `json:"plan_id"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil || !data.RuntimeHandoff || data.ProfileApplied ||
		data.AppliedGeneration != 0 || !strings.HasPrefix(data.PlanID, "sha256:") {
		t.Fatalf("handoff result=%#v err=%v", data, err)
	}
	if len(client.statuses) < 2 {
		t.Fatalf("missing handoff status reports: %#v", client.statuses)
	}
	finalStatus := client.statuses[len(client.statuses)-1]
	if finalStatus.State != "applying" || finalStatus.AppliedGeneration != 0 || finalStatus.SSHHostKey != "" {
		t.Fatalf("handoff falsely reported ready: %#v", finalStatus)
	}
	for _, component := range finalStatus.Components {
		if component.Name == "flow" {
			if component.State != "ready" {
				t.Fatalf("activated flow component state=%q", component.State)
			}
		} else if component.State != "pending" {
			t.Fatalf("old binary advanced profile component: %#v", component)
		}
	}
	for _, batch := range client.logs {
		for _, event := range batch.Events {
			if event.Event == "reconcile_complete" {
				t.Fatalf("handoff emitted completion: %#v", batch)
			}
		}
	}
}
