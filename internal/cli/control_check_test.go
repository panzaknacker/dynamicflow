package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestControlCheckCLIPlanOneAttemptAndIdempotentJSON(t *testing.T) {
	fixture := newControlCLIFixture(t)
	if status, stdout, stderr := invokeCLI(t, fixture.bindArguments(false)...); status != exitOK || stderr != "" {
		t.Fatalf("bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	callsPath, argvPath := installFakeControlSSH(t, 0, "remote-output-must-be-discarded")
	before := snapshotCLIState(t, fixture.home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1", "--plan")
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	planEnvelope := decodeCLIEnvelope(t, stdout)
	if !planEnvelope.OK || planEnvelope.Command != "control.check.plan" {
		t.Fatalf("plan envelope = %+v", planEnvelope)
	}
	var plan struct {
		Plan               bool   `json:"plan"`
		NetworkConnections int    `json:"network_connections"`
		FixedRemoteCommand string `json:"fixed_remote_command"`
		AlreadyVerified    bool   `json:"already_verified"`
		ResumesFailedTask  bool   `json:"resumes_failed_task"`
	}
	if err := json.Unmarshal(planEnvelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.NetworkConnections != 1 || plan.FixedRemoteCommand != "/bin/true" ||
		plan.AlreadyVerified || plan.ResumesFailedTask {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := os.Lstat(callsPath); !os.IsNotExist(err) {
		t.Fatalf("plan invoked SSH: %v", err)
	}
	after := snapshotCLIState(t, fixture.home)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("check --plan changed state:\nbefore=%v\nafter=%v", before, after)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1")
	if status != exitOK || stderr != "" {
		t.Fatalf("check status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "control.check" {
		t.Fatalf("check envelope = %+v", envelope)
	}
	var result struct {
		Verified           bool `json:"verified"`
		AlreadyVerified    bool `json:"already_verified"`
		Reconciled         bool `json:"reconciled"`
		NetworkConnections int  `json:"network_connections"`
		Control            struct {
			Lifecycle string `json:"lifecycle"`
		} `json:"control"`
		Task struct {
			Phase string `json:"phase"`
		} `json:"task"`
		Transport struct {
			Route    string `json:"route"`
			Attempts int    `json:"attempts"`
		} `json:"transport"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.AlreadyVerified || result.Reconciled || result.NetworkConnections != 1 ||
		result.Control.Lifecycle != "connectivity_verified" || result.Task.Phase != "connectivity_verified" ||
		result.Transport.Route != "direct_first_control" || result.Transport.Attempts != 1 {
		t.Fatalf("check result = %+v", result)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)
	if strings.Contains(stdout+stderr, "remote-output-must-be-discarded") {
		t.Fatal("CLI leaked discarded SSH output")
	}
	calls, err := os.ReadFile(callsPath)
	if err != nil || strings.Count(string(calls), "call\n") != 1 {
		t.Fatalf("SSH calls=%q err=%v", calls, err)
	}
	argv, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	arguments := strings.Fields(string(argv))
	if len(arguments) != 6 || arguments[0] != "-F" || arguments[2] != "-S" ||
		arguments[3] != "none" || arguments[4] != "flow-control-control-1" || arguments[5] != "/bin/true" {
		t.Fatalf("SSH argv = %q", argv)
	}
	if strings.Contains(string(argv), fixture.bootstrapPath) {
		t.Fatalf("SSH argv exposed private identity path: %q", argv)
	}

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1")
	if status != exitOK || stderr != "" {
		t.Fatalf("repeat status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Verified || !result.AlreadyVerified || result.NetworkConnections != 0 || result.Transport.Attempts != 0 {
		t.Fatalf("repeat result = %+v", result)
	}
	calls, err = os.ReadFile(callsPath)
	if err != nil || strings.Count(string(calls), "call\n") != 1 {
		t.Fatalf("idempotent check repeated SSH: %q err=%v", calls, err)
	}
}

func TestControlCheckCLIFailureIsSanitizedAndExplicitlyResumable(t *testing.T) {
	fixture := newControlCLIFixture(t)
	if status, stdout, stderr := invokeCLI(t, fixture.bindArguments(false)...); status != exitOK || stderr != "" {
		t.Fatalf("bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	callsPath, _ := installFakeControlSSH(t, 23, "ssh-remote-secret-must-not-leak")
	status, stdout, stderr := invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1")
	if status != exitRemote || stdout != "" {
		t.Fatalf("failure status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.OK || failure.Command != "control.check" || failure.Error == nil ||
		failure.Error.Code != "control_connectivity" || failure.Error.Next == "" ||
		strings.Contains(stderr, "ssh-remote-secret-must-not-leak") {
		t.Fatalf("failure envelope = %+v raw=%q", failure, stderr)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "status")
	if status != exitOK || stderr != "" || !strings.Contains(stdout, `"phase":"failed_safe"`) ||
		!strings.Contains(stdout, `"code":"control_connectivity"`) {
		t.Fatalf("failed-safe status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1", "--plan")
	if status != exitOK || stderr != "" || !strings.Contains(stdout, `"resumes_failed_task":true`) ||
		!strings.Contains(stdout, `"network_connections":1`) {
		t.Fatalf("resume plan=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	calls, err := os.ReadFile(callsPath)
	if err != nil || strings.Count(string(calls), "call\n") != 1 {
		t.Fatalf("resume plan invoked SSH: %q err=%v", calls, err)
	}

	t.Setenv("FLOW_CONTROL_SSH_EXIT", "0")
	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "check", "control-1")
	if status != exitOK || stderr != "" || strings.Contains(stdout, "ssh-remote-secret-must-not-leak") {
		t.Fatalf("resume status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	calls, err = os.ReadFile(callsPath)
	if err != nil || strings.Count(string(calls), "call\n") != 2 {
		t.Fatalf("explicit resume calls: %q err=%v", calls, err)
	}
}

func installFakeControlSSH(t *testing.T, exitCode int, remoteSecret string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	sshPath := filepath.Join(directory, "ssh")
	script := `#!/bin/sh
printf '%s\n' call >> "$FLOW_CONTROL_SSH_CALLS"
printf '%s\n' "$@" > "$FLOW_CONTROL_SSH_ARGV"
printf '%s\n' "$FLOW_CONTROL_REMOTE_SECRET"
printf '%s\n' "$FLOW_CONTROL_REMOTE_SECRET" >&2
exit "${FLOW_CONTROL_SSH_EXIT:-0}"
`
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	callsPath := filepath.Join(t.TempDir(), "calls")
	argvPath := filepath.Join(t.TempDir(), "argv")
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FLOW_CONTROL_SSH_CALLS", callsPath)
	t.Setenv("FLOW_CONTROL_SSH_ARGV", argvPath)
	t.Setenv("FLOW_CONTROL_REMOTE_SECRET", remoteSecret)
	t.Setenv("FLOW_CONTROL_SSH_EXIT", strconv.Itoa(exitCode))
	return callsPath, argvPath
}
