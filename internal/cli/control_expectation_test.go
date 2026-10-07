package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"dynamicflow/internal/application"
)

func TestControlExpectedSystemCLIRejectsChangedActiveSystem(t *testing.T) {
	fixture := newControlCLIFixture(t)
	callsPath, argvPath := installFakeControlSSH(t, 0, "unexpected-control-expectation-ssh")

	beforePlan := snapshotCLIState(t, fixture.home)
	arguments := append(fixture.bindArguments(true), "--expect-system", fixture.systemID)
	envelope := requireControlExpectationSuccess(t, "control.bind.plan", arguments...)
	var bindPlan application.BindControlPlan
	if err := json.Unmarshal(envelope.Data, &bindPlan); err != nil {
		t.Fatal(err)
	}
	if !bindPlan.Plan || bindPlan.SystemID != fixture.systemID || bindPlan.ControlName != "control-1" || bindPlan.NetworkConnections != 0 {
		t.Fatalf("unexpected bind plan: %+v", bindPlan)
	}
	if !reflect.DeepEqual(beforePlan, snapshotCLIState(t, fixture.home)) {
		t.Fatal("binding plan with the expected active system changed state")
	}

	arguments = append(fixture.bindArguments(false), "--expect-system", bindPlan.SystemID)
	envelope = requireControlExpectationSuccess(t, "control.bind", arguments...)
	var bound application.BindControlResult
	if err := json.Unmarshal(envelope.Data, &bound); err != nil {
		t.Fatal(err)
	}
	if !bound.Created || bound.System.ID != fixture.systemID || bound.Control.Name != "control-1" || bound.NetworkConnections != 0 {
		t.Fatalf("unexpected bind result: %+v", bound)
	}

	beforeCheckPlan := snapshotCLIState(t, fixture.home)
	envelope = requireControlExpectationSuccess(t, "control.check.plan", "--json", "--home", fixture.home,
		"control", "check", "control-1", "--plan", "--expect-system="+fixture.systemID)
	var checkPlan application.CheckControlPlan
	if err := json.Unmarshal(envelope.Data, &checkPlan); err != nil {
		t.Fatal(err)
	}
	if !checkPlan.Plan || checkPlan.SystemID != fixture.systemID || checkPlan.ControlName != "control-1" || checkPlan.NetworkConnections != 1 {
		t.Fatalf("unexpected check plan: %+v", checkPlan)
	}
	if !reflect.DeepEqual(beforeCheckPlan, snapshotCLIState(t, fixture.home)) {
		t.Fatal("check plan with the expected active system changed state")
	}

	envelope = requireControlExpectationSuccess(t, "system.init", "--json", "--home", fixture.home,
		"system", "init", "--name", "second", "--control-name", "control-1")
	var second application.InitSystemResult
	if err := json.Unmarshal(envelope.Data, &second); err != nil {
		t.Fatal(err)
	}
	if second.System.ID == "" || second.System.ID == fixture.systemID {
		t.Fatalf("second system ID = %q", second.System.ID)
	}
	requireControlExpectationSuccess(t, "system.select", "--json", "--home", fixture.home,
		"system", "select", "id:"+second.System.ID)
	arguments = append(fixture.bindArguments(false), "--expect-system", second.System.ID)
	envelope = requireControlExpectationSuccess(t, "control.bind", arguments...)
	if err := json.Unmarshal(envelope.Data, &bound); err != nil {
		t.Fatal(err)
	}
	if !bound.Created || bound.System.ID != second.System.ID || bound.Control.Name != "control-1" {
		t.Fatalf("second system did not bind the same Control name: %+v", bound)
	}
	beforeConflict := snapshotCLIState(t, fixture.home)
	for _, action := range []string{"bind", "check", "install", "apply", "attest"} {
		for _, planOnly := range []bool{true, false} {
			name := action + "/commit"
			if planOnly {
				name = action + "/plan"
			}
			t.Run(name, func(t *testing.T) {
				arguments := append(controlExpectationArguments(fixture, action, planOnly), "--expect-system", fixture.systemID)
				status, stdout, stderr := runControlExpectationCLI(arguments...)
				if status != exitConflict || stdout != "" {
					t.Fatalf("stale expected system: status=%d stdout=%q stderr=%q", status, stdout, stderr)
				}
				envelope := decodeCLIEnvelope(t, stderr)
				if envelope.OK || envelope.Command != "control."+action || envelope.Error == nil ||
					envelope.Error.Code != "system_conflict" || envelope.Error.Next == "" {
					t.Fatalf("unexpected system-conflict envelope: %+v", envelope)
				}
				assertNoControlCLISecret(t, stdout+stderr, fixture)
				if !reflect.DeepEqual(beforeConflict, snapshotCLIState(t, fixture.home)) {
					t.Fatal("rejected expectation changed registry, keys, workflow, audit or other local state")
				}
				assertControlExpectationNoSSH(t, callsPath, argvPath)
			})
		}
	}

	envelope = requireControlExpectationSuccess(t, "control.check.plan", "--json", "--home", fixture.home,
		"control", "check", "control-1", "--plan", "--expect-system", second.System.ID)
	if err := json.Unmarshal(envelope.Data, &checkPlan); err != nil {
		t.Fatal(err)
	}
	if checkPlan.SystemID != second.System.ID || checkPlan.ControlName != "control-1" {
		t.Fatalf("fresh plan did not use the selected system: %+v", checkPlan)
	}
	if !reflect.DeepEqual(beforeConflict, snapshotCLIState(t, fixture.home)) {
		t.Fatal("fresh check plan changed local state")
	}
	assertControlExpectationNoSSH(t, callsPath, argvPath)
}

func TestControlExpectedSystemCLIUsageDoesNotChangeState(t *testing.T) {
	fixture := newControlCLIFixture(t)
	callsPath, argvPath := installFakeControlSSH(t, 0, "unexpected-control-expectation-ssh")
	otherID := "sys-" + strings.Repeat("0", 32)
	if otherID == fixture.systemID {
		otherID = "sys-" + strings.Repeat("1", 32)
	}
	tests := []struct {
		name  string
		flags []string
	}{
		{name: "empty value", flags: []string{"--expect-system", ""}},
		{name: "empty equals value", flags: []string{"--expect-system="}},
		{name: "missing value", flags: []string{"--expect-system"}},
		{name: "system name", flags: []string{"--expect-system", "lab"}},
		{name: "incomplete ID", flags: []string{"--expect-system", "sys-123"}},
		{name: "uppercase ID", flags: []string{"--expect-system", "sys-" + strings.Repeat("A", 32)}},
		{name: "selector instead of ID", flags: []string{"--expect-system", "id:" + fixture.systemID}},
		{name: "duplicate same ID", flags: []string{"--expect-system", fixture.systemID, "--expect-system", fixture.systemID}},
		{name: "duplicate conflicting ID", flags: []string{"--expect-system", fixture.systemID, "--expect-system=" + otherID}},
	}
	before := snapshotCLIState(t, fixture.home)
	for _, action := range []string{"bind", "check", "install", "apply", "attest"} {
		for _, planOnly := range []bool{true, false} {
			name := action + "/commit/"
			if planOnly {
				name = action + "/plan/"
			}
			for _, test := range tests {
				t.Run(name+test.name, func(t *testing.T) {
					arguments := append(controlExpectationArguments(fixture, action, planOnly), test.flags...)
					status, stdout, stderr := runControlExpectationCLI(arguments...)
					if status != exitUsage || stdout != "" {
						t.Fatalf("invalid expectation: status=%d stdout=%q stderr=%q", status, stdout, stderr)
					}
					envelope := decodeCLIEnvelope(t, stderr)
					if envelope.OK || envelope.Command != "control."+action || envelope.Error == nil || envelope.Error.Code != "usage" {
						t.Fatalf("unexpected usage envelope: %+v", envelope)
					}
					assertNoControlCLISecret(t, stdout+stderr, fixture)
					if !reflect.DeepEqual(before, snapshotCLIState(t, fixture.home)) {
						t.Fatal("invalid expected-system option changed local state")
					}
					assertControlExpectationNoSSH(t, callsPath, argvPath)
				})
			}
		}
	}
}

func TestControlExpectedSystemCLIHelpIsStateless(t *testing.T) {
	home := filepath.Join(t.TempDir(), "must-not-exist")
	commands := [][]string{
		{"--help"},
		{"control", "--help"},
		{"control", "bind", "--help"},
		{"control", "check", "--help"},
		{"control", "install", "--help"},
		{"control", "apply", "--help"},
		{"control", "attest", "--help"},
	}
	for _, command := range commands {
		for _, jsonOutput := range []bool{false, true} {
			arguments := []string{"--home", home}
			name := strings.Join(command, " ") + "/human"
			if jsonOutput {
				arguments = append(arguments, "--json")
				name = strings.Join(command, " ") + "/json"
			}
			arguments = append(arguments, command...)
			t.Run(name, func(t *testing.T) {
				status, stdout, stderr := runControlExpectationCLI(arguments...)
				if status != exitOK || stderr != "" || !strings.Contains(stdout, "--expect-system") {
					t.Fatalf("help did not describe the system guard: status=%d stdout=%q stderr=%q", status, stdout, stderr)
				}
				if jsonOutput {
					envelope := decodeCLIEnvelope(t, stdout)
					if !envelope.OK || envelope.Command != "help" || envelope.Error != nil {
						t.Fatalf("unexpected help envelope: %+v", envelope)
					}
				}
				if _, err := os.Lstat(home); !os.IsNotExist(err) {
					t.Fatalf("help opened the operator state: %v", err)
				}
			})
		}
	}
}

func controlExpectationArguments(fixture controlCLIFixture, action string, planOnly bool) []string {
	if action == "bind" {
		return fixture.bindArguments(planOnly)
	}
	arguments := []string{"--json", "--home", fixture.home, "control", action, "control-1"}
	if planOnly {
		arguments = append(arguments, "--plan")
	}
	return arguments
}

func runControlExpectationCLI(arguments ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	status := RunWithIO(arguments, strings.NewReader(""), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func requireControlExpectationSuccess(t *testing.T, command string, arguments ...string) cliEnvelope {
	t.Helper()
	status, stdout, stderr := runControlExpectationCLI(arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("%s: status=%d stdout=%q stderr=%q", command, status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != command || envelope.Error != nil {
		t.Fatalf("%s: unexpected success envelope: %+v", command, envelope)
	}
	return envelope
}

func assertControlExpectationNoSSH(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("local rejection or plan invoked SSH: %v", err)
		}
	}
}
