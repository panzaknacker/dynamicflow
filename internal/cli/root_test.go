package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cliEnvelope struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Next    string `json:"next"`
	} `json:"error"`
}

func invokeCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(arguments, &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func decodeCLIEnvelope(t *testing.T, text string) cliEnvelope {
	t.Helper()
	var envelope cliEnvelope
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", text, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("trailing JSON content in %q: %v", text, err)
	}
	return envelope
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(directory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	return root
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestHelpContract(t *testing.T) {
	status, stdout, stderr := invokeCLI(t, "--help")
	if status != exitOK {
		t.Fatalf("help status = %d, stderr = %s", status, stderr)
	}
	if stderr != "" {
		t.Fatalf("help wrote stderr: %q", stderr)
	}
	required := []string{
		"flow init",
		"flow doctor",
		"flow start serving [--plan]",
		"flow status serving",
		"flow logs serving",
		"flow key create --name NAME",
		"flow key rotate --name NAME",
		"flow profile show NAME",
		"flow release build [--rebuild]",
		"flow release verify [PATH]",
		"flow release publish [--remote | --root PATH] [--plan]",
		"flow enroll create --name NAME --profile PROFILE",
		"flow enroll list",
		"flow enroll revoke (--id ID | --name NAME)",
		"flow instance logs NAME [--component COMPONENT]",
		"flow instance apply NAME --profile PROFILE [--plan]",
		"flow instance hostkey pin NAME --public-key-file PATH",
		"flow instance hostkey rotate NAME --public-key-file PATH",
		"flow instance ssh NAME [--gui] [--local-port PORT]",
		"flow instance exec NAME -- COMMAND [ARG...]",
		"flow instance secret reveal NAME --secret vnc",
		"flow instance secret rotate NAME --secret vnc",
		"flow test lab [--inventory .flow/lab.yaml] [--plan]",
		"return control_route_unavailable before\n  operator state, network or child-process access",
		"There is no environment,\n  stored-state or automatic direct fallback.",
		"Global options are recognized anywhere before a literal -- separator.",
		"The one-time enroll create result and explicit instance secret reveal/rotate",
		"Do not\ncapture either result in shell history, CI logs or persistent automation output.",
	}
	for _, contract := range required {
		if !strings.Contains(stdout, contract) {
			t.Errorf("help is missing %q", contract)
		}
	}
}

func TestNoArgsWithoutTTYIsStateFreeAndActionable(t *testing.T) {
	home := filepath.Join(t.TempDir(), "must-not-exist")
	var stdout, stderr bytes.Buffer
	status := RunWithIO([]string{"--home", home}, strings.NewReader(""), &stdout, &stderr)
	if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "tty_required") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("non-TTY no-args opened state: %v", err)
	}
}

func TestNoArgsJSONReturnsDashboardWithoutANSI(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	status := RunWithIO([]string{"--json", "--home", home}, strings.NewReader(""), &stdout, &stderr)
	if status != exitOK || stderr.Len() != 0 || strings.Contains(stdout.String(), "\x1b") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	envelope := decodeCLIEnvelope(t, stdout.String())
	if !envelope.OK || envelope.Command != "dashboard" {
		t.Fatalf("envelope = %+v", envelope)
	}
}

func TestCommandGroupHelpIsAvailableWithoutOperatorState(t *testing.T) {
	for group, required := range map[string]string{
		"init":     "flow init",
		"doctor":   "flow doctor",
		"serving":  "flow serving configure",
		"start":    "flow start serving [--plan]",
		"status":   "flow status serving",
		"logs":     "flow logs serving [--lines N]",
		"key":      "flow key rotate --name NAME",
		"profile":  "flow profile show NAME",
		"release":  "flow release build [--rebuild] [--generation N]",
		"enroll":   "flow enroll create --name NAME --profile PROFILE",
		"instance": "flow instance secret rotate NAME --secret vnc",
		"test":     "flow test lab [--inventory ABSOLUTE-PATH] [--plan]",
	} {
		t.Run(group, func(t *testing.T) {
			status, stdout, stderr := invokeCLI(t, group, "--help")
			if status != exitOK || stderr != "" || !strings.Contains(stdout, required) {
				t.Fatalf("%s --help: status=%d stdout=%q stderr=%q", group, status, stdout, stderr)
			}
			status, alternate, stderr := invokeCLI(t, "help", group)
			if status != exitOK || stderr != "" || alternate != stdout {
				t.Fatalf("help %s differs: status=%d stdout=%q stderr=%q", group, status, alternate, stderr)
			}
		})
	}
}

func TestLeafCommandHelpIsSuccessfulWithoutOperatorState(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		required  string
	}{
		{name: "start serving", arguments: []string{"start", "serving", "--help"}, required: "flow start serving [--plan]"},
		{name: "release publish short", arguments: []string{"release", "publish", "-h"}, required: "flow release publish [--remote | --root ABSOLUTE-PATH] [--plan]"},
		{name: "instance ssh", arguments: []string{"instance", "ssh", "--help"}, required: "flow instance ssh NAME [--gui] [--local-port PORT]"},
		{name: "instance secret reveal short", arguments: []string{"instance", "secret", "reveal", "-h"}, required: "flow instance secret reveal NAME --secret vnc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "unopened-flow-home")
			arguments := append([]string{"--home", home}, test.arguments...)
			status, stdout, stderr := invokeCLI(t, arguments...)
			if status != exitOK || stderr != "" || !strings.Contains(stdout, test.required) {
				t.Fatalf("leaf help: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if _, err := os.Lstat(home); !os.IsNotExist(err) {
				t.Fatalf("leaf help opened operator state %q: %v", home, err)
			}
		})
	}
}

func TestJSONLeafHelpIsStructuredAndStateFree(t *testing.T) {
	home := filepath.Join(t.TempDir(), "unopened-flow-home")
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "publish", "--help")
	if status != exitOK || stderr != "" {
		t.Fatalf("JSON leaf help status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "help" || envelope.Error != nil {
		t.Fatalf("JSON leaf help envelope = %+v", envelope)
	}
	var data struct {
		Topic string `json:"topic"`
		Text  string `json:"text"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Topic != "release.publish" || !strings.Contains(data.Text, "flow release publish") {
		t.Fatalf("JSON leaf help data = %+v", data)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("JSON leaf help opened operator state %q: %v", home, err)
	}
}

func TestLeafHelpDoesNotCaptureUnknownCommandsOrRemoteArguments(t *testing.T) {
	t.Run("unknown leaf", func(t *testing.T) {
		status, stdout, stderr := invokeCLI(t, "--json", "--home", privateTempDir(t), "release", "nope", "--help")
		if status != exitUsage || stdout != "" {
			t.Fatalf("unknown leaf status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Command != "release" || envelope.Error == nil || envelope.Error.Code != "usage" {
			t.Fatalf("unknown leaf envelope = %+v", envelope)
		}
	})

	t.Run("literal exec separator", func(t *testing.T) {
		status, stdout, stderr := invokeCLI(t, "--json", "--home", privateTempDir(t), "instance", "exec", "missing", "--", "--help")
		if status != exitConflict || stdout != "" {
			t.Fatalf("remote help argument status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Command != "instance.exec" || envelope.Error == nil || envelope.Error.Code != controlRouteUnavailableCode {
			t.Fatalf("remote help argument was captured locally: %+v", envelope)
		}
	})
}

func TestJSONHelpIsStructuredAndDoesNotOpenOperatorState(t *testing.T) {
	home := filepath.Join(t.TempDir(), "unopened-flow-home")
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "help", "instance")
	if status != exitOK || stderr != "" {
		t.Fatalf("JSON help status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "help" || envelope.Error != nil {
		t.Fatalf("JSON help envelope = %+v", envelope)
	}
	var data struct {
		Topic string `json:"topic"`
		Text  string `json:"text"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Topic != "instance" || !strings.Contains(data.Text, "flow instance key finalize") {
		t.Fatalf("JSON help data = %+v", data)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("help opened operator state %q: %v", home, err)
	}
}

func TestUnknownHelpTopicIsStructuredAndDoesNotOpenOperatorState(t *testing.T) {
	home := filepath.Join(t.TempDir(), "unopened-flow-home")
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "help", "unknown-topic")
	if status != exitUsage || stdout != "" {
		t.Fatalf("unknown help status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.OK || envelope.Command != "help" || envelope.Error == nil || envelope.Error.Code != "usage" || envelope.Error.Next == "" {
		t.Fatalf("unknown help envelope = %+v", envelope)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("unknown help opened operator state %q: %v", home, err)
	}
}

func TestJSONUsageAndRouteGateFailuresAreSingleStructuredDocuments(t *testing.T) {
	home := privateTempDir(t)
	root := repositoryRoot(t)
	commands := []struct {
		arguments []string
		command   string
	}{
		{[]string{"init", "--unknown-option"}, "init"},
		{[]string{"doctor", "--unknown-option"}, "doctor"},
		{[]string{"key", "list", "--unknown-option"}, "key.list"},
		{[]string{"profile", "list", "--unknown-option"}, "profile.list"},
		{[]string{"release", "verify", "--unknown-option"}, "release.verify"},
		{[]string{"serving", "show", "unexpected"}, "serving.show"},
		{[]string{"start", "serving", "--unknown-option"}, "start.serving"},
		{[]string{"status", "serving", "unexpected"}, "status.serving"},
		{[]string{"logs", "serving", "--lines", "0"}, "logs.serving"},
		{[]string{"enroll", "create"}, "enroll.create"},
		{[]string{"instance", "status"}, "instance.status"},
		{[]string{"instance", "secret", "reveal"}, "instance.secret.reveal"},
		{[]string{"test", "lab", "--unknown-option"}, "test.lab"},
	}
	for _, test := range commands {
		name := strings.Join(test.arguments[:len(test.arguments)-1], "_")
		t.Run(name, func(t *testing.T) {
			arguments := []string{"--json", "--home", home, "--source-root", root}
			arguments = append(arguments, test.arguments...)
			status, stdout, stderr := invokeCLI(t, arguments...)
			wantStatus, wantCode := exitUsage, "usage"
			if operatorActionNeedsControlRoute(test.arguments) {
				wantStatus, wantCode = exitConflict, controlRouteUnavailableCode
			}
			if status != wantStatus || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.OK || envelope.Command != test.command || envelope.Error == nil || envelope.Error.Code != wantCode || envelope.Error.Next == "" {
				t.Fatalf("failure envelope = %+v", envelope)
			}
		})
	}
}

func TestExitCodeContract(t *testing.T) {
	t.Setenv("FLOW_PROFILES_DIR", "")
	home := privateTempDir(t)
	root := repositoryRoot(t)
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"unknown command", []string{"--home", home, "unknown"}, exitUsage},
		{"relative home", []string{"--home", "relative", "init"}, exitUsage},
		{"missing key name", []string{"--home", home, "key", "create"}, exitUsage},
		{"missing profile", []string{"--home", home, "--source-root", root, "profile", "show", "missing"}, exitConfig},
		{"missing release stage", []string{"--home", home, "release", "verify"}, exitConfig},
		{"HTTPS instance lifecycle requires Control route", []string{"--home", home, "instance", "status", "missing"}, exitConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _, _ := invokeCLI(t, test.args...)
			if status != test.want {
				t.Fatalf("status = %d, want %d", status, test.want)
			}
		})
	}
}

func TestJSONSuccessAndFailureUseSingleDocument(t *testing.T) {
	status, stdout, stderr := invokeCLI(t, "--json", "--version")
	if status != exitOK || stderr != "" {
		t.Fatalf("version status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	success := decodeCLIEnvelope(t, stdout)
	if !success.OK || success.Command != "version" || success.Error != nil {
		t.Fatalf("version envelope = %+v", success)
	}

	status, stdout, stderr = invokeCLI(t, "--json", "--home", privateTempDir(t), "unknown")
	if status != exitUsage || stdout != "" {
		t.Fatalf("failure status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.OK || failure.Command != "flow" || failure.Error == nil || failure.Error.Code != "usage" || failure.Error.Next != "Run flow --help." {
		t.Fatalf("failure envelope = %+v", failure)
	}
}

func TestGlobalOptionFailuresHaveStableCommandAndNextAction(t *testing.T) {
	for _, arguments := range [][]string{
		{"--json", "--home"},
		{"--json", "--home", "relative", "doctor"},
		{"--json", "--source-root"},
	} {
		status, stdout, stderr := invokeCLI(t, arguments...)
		if status != exitUsage || stdout != "" {
			t.Fatalf("arguments=%v status=%d stdout=%q stderr=%q", arguments, status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Command != "flow" || envelope.Error == nil || envelope.Error.Code != "usage" || envelope.Error.Next != "Run flow --help." {
			t.Fatalf("arguments=%v envelope=%+v", arguments, envelope)
		}
	}
}
