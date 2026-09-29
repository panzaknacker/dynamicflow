package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"dynamicflow/internal/controlruntime"
)

const (
	controlRuntimeTestSystem  = "sys-0123456789abcdef0123456789abcdef"
	controlRuntimeTestControl = "control-1"
)

type recordingControlRuntimeInstaller struct {
	calls   int
	request controlruntime.InstallRequest
	input   []byte
	result  controlruntime.InstallResult
	err     error
}

func (installer *recordingControlRuntimeInstaller) Install(
	_ context.Context,
	reader io.Reader,
	request controlruntime.InstallRequest,
) (controlruntime.InstallResult, error) {
	installer.calls++
	installer.request = request
	data, err := io.ReadAll(reader)
	if err != nil {
		return controlruntime.InstallResult{}, err
	}
	installer.input = data
	return installer.result, installer.err
}

type countedControlRuntimeReader struct {
	data  *bytes.Reader
	reads int
}

func (reader *countedControlRuntimeReader) Read(buffer []byte) (int, error) {
	reader.reads++
	return reader.data.Read(buffer)
}

func TestControlRuntimeInstallReadsEnvelopeOnlyFromStdinAndEmitsPublicReceipt(t *testing.T) {
	privateMarker := []byte(`{"opaque_envelope":"BEGIN PRIVATE KEY must never be echoed"}`)
	installer := &recordingControlRuntimeInstaller{result: validControlRuntimeResult()}
	status, stdout, stderr := invokeControlRuntime(
		[]string{
			"install",
			"--minimum-generation", "7",
			"--expected-control", controlRuntimeTestControl,
			"--expected-system", controlRuntimeTestSystem,
		},
		bytes.NewReader(privateMarker),
		false,
		installer,
	)
	if status != exitOK || installer.calls != 1 {
		t.Fatalf("status=%d calls=%d stdout=%q stderr=%q", status, installer.calls, stdout, stderr)
	}
	if installer.request != (controlruntime.InstallRequest{
		ExpectedSystemID: controlRuntimeTestSystem, ExpectedControlName: controlRuntimeTestControl, MinimumGeneration: 7,
	}) {
		t.Fatalf("request = %+v", installer.request)
	}
	if !bytes.Equal(installer.input, privateMarker) {
		t.Fatalf("stdin changed: %q", installer.input)
	}
	if strings.Contains(stdout, string(privateMarker)) || strings.Contains(stderr, string(privateMarker)) ||
		strings.Contains(stdout, "PRIVATE KEY") || strings.Contains(stderr, "PRIVATE KEY") {
		t.Fatalf("envelope leaked: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, controlRuntimeTestControl) || !strings.Contains(stdout, controlRuntimeTestSystem) ||
		stderr != "" {
		t.Fatalf("unexpected public output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestControlRuntimeInstallJSONHasExplicitSecretFreeSchema(t *testing.T) {
	secret := "enrollment-secret-that-is-stdin-only"
	installer := &recordingControlRuntimeInstaller{result: validControlRuntimeResult()}
	status, stdout, stderr := invokeControlRuntime(validControlRuntimeArguments(), strings.NewReader(secret), true, installer)
	if status != exitOK || stderr != "" || installer.calls != 1 {
		t.Fatalf("status=%d calls=%d stdout=%q stderr=%q", status, installer.calls, stdout, stderr)
	}
	var envelope struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Data    struct {
			Installed      bool   `json:"installed"`
			SystemID       string `json:"system_id"`
			ControlName    string `json:"control_name"`
			Generation     uint64 `json:"generation"`
			EnvelopeDigest string `json:"envelope_digest"`
			RuntimeDigest  string `json:"runtime_digest"`
			Changed        bool   `json:"changed"`
			RolledBack     bool   `json:"rolled_back"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Command != "control-runtime.install" || !envelope.Data.Installed ||
		envelope.Data.SystemID != controlRuntimeTestSystem || envelope.Data.ControlName != controlRuntimeTestControl ||
		envelope.Data.Generation != 7 || !envelope.Data.Changed || envelope.Data.RolledBack {
		t.Fatalf("JSON receipt = %+v", envelope)
	}
	if strings.Contains(stdout, secret) || strings.Contains(stdout, "private") {
		t.Fatalf("JSON leaked stdin: %s", stdout)
	}

	var generic map[string]any
	if err := json.Unmarshal([]byte(stdout), &generic); err != nil {
		t.Fatal(err)
	}
	data, ok := generic["data"].(map[string]any)
	if !ok || len(data) != 8 {
		t.Fatalf("unexpected public schema: %#v", generic)
	}
}

func TestControlRuntimeInstallRejectsNonCanonicalOrSecretCapableArgvBeforeReading(t *testing.T) {
	invalid := [][]string{
		nil,
		{"unknown"},
		{"install"},
		{"install", "--expected-system=" + controlRuntimeTestSystem, "--expected-control", controlRuntimeTestControl, "--minimum-generation", "7"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-system", controlRuntimeTestSystem, "--minimum-generation", "7"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", controlRuntimeTestControl, "--minimum-generation", "7", "operand"},
		{"install", "--expected-system", "sys-0123456789abcdef0123456789abcdeg", "--expected-control", controlRuntimeTestControl, "--minimum-generation", "7"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", "Control-1", "--minimum-generation", "7"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", "control/../../secret", "--minimum-generation", "7"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", controlRuntimeTestControl, "--minimum-generation", "01"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", controlRuntimeTestControl, "--minimum-generation", "0"},
		{"install", "--expected-system", controlRuntimeTestSystem, "--expected-control", controlRuntimeTestControl, "--minimum-generation", "18446744073709551616"},
	}
	for _, arguments := range invalid {
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			reader := &countedControlRuntimeReader{data: bytes.NewReader([]byte("stdin-secret"))}
			installer := &recordingControlRuntimeInstaller{}
			status, stdout, stderr := invokeControlRuntime(arguments, reader, true, installer)
			if status != exitUsage || installer.calls != 0 || reader.reads != 0 || stdout != "" {
				t.Fatalf("args=%#v status=%d calls=%d reads=%d stdout=%q stderr=%q", arguments, status, installer.calls, reader.reads, stdout, stderr)
			}
			if strings.Contains(stderr, "stdin-secret") || strings.Contains(stderr, "control/../../secret") {
				t.Fatalf("usage output leaked input/argv: %s", stderr)
			}
			assertControlRuntimeErrorCode(t, stderr, "usage")
		})
	}
}

func TestControlRuntimeHelpDoesNotReadInputOrConstructInstaller(t *testing.T) {
	reader := &countedControlRuntimeReader{data: bytes.NewReader([]byte("stdin-secret"))}
	constructed := 0
	var stdout, stderr bytes.Buffer
	out := &emitter{json: true, stdout: &stdout, stderr: &stderr, command: "control-runtime"}
	status := runControlRuntime([]string{"--help"}, reader, out, controlRuntimeDependencies{
		newInstaller: func() controlRuntimeInstaller {
			constructed++
			return &recordingControlRuntimeInstaller{}
		},
	})
	if status != exitOK || reader.reads != 0 || constructed != 0 || stderr.Len() != 0 {
		t.Fatalf("status=%d reads=%d constructors=%d stdout=%q stderr=%q", status, reader.reads, constructed, stdout.String(), stderr.String())
	}
	var value map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value["ok"] != true || value["command"] != "help" || strings.Contains(stdout.String(), "stdin-secret") {
		t.Fatalf("help envelope = %s", stdout.String())
	}
}

func TestControlRuntimeInstallerFailuresAreClassifiedWithoutCauseOrStdin(t *testing.T) {
	tests := []struct {
		name   string
		cause  error
		code   string
		status int
	}{
		{"root", controlruntime.ErrRootRequired, "privilege", exitAuth},
		{"invalid envelope", controlruntime.ErrInvalidEnvelope, "control_envelope_verify", exitVerify},
		{"binding", controlruntime.ErrEnvelopeBinding, "control_envelope_verify", exitVerify},
		{"generation", controlruntime.ErrGenerationConflict, "control_generation_conflict", exitConflict},
		{"busy", controlruntime.ErrInstallBusy, "control_install_busy", exitConflict},
		{"unsafe host", controlruntime.ErrUnsafeHost, "control_host_unsafe", exitVerify},
		{"sshd validation", controlruntime.ErrSSHDValidation, "control_sshd_validation", exitVerify},
		{"sshd reload", controlruntime.ErrSSHDReload, "control_sshd_reload", exitFailure},
		{"rollback", controlruntime.ErrInstallRollback, "control_recovery_required", exitPartial},
		{"cancelled", context.Canceled, "control_install_interrupted", exitPartial},
		{"generic", controlruntime.ErrInstallFailed, "control_install", exitFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret := "attacker-controlled-private-diagnostic"
			installer := &recordingControlRuntimeInstaller{
				result: validControlRuntimeResult(),
				err:    fmt.Errorf("%w: %s", test.cause, secret),
			}
			status, stdout, stderr := invokeControlRuntime(validControlRuntimeArguments(), strings.NewReader("stdin-private-value"), true, installer)
			if status != test.status || stdout != "" || installer.calls != 1 {
				t.Fatalf("status=%d want=%d calls=%d stdout=%q stderr=%q", status, test.status, installer.calls, stdout, stderr)
			}
			if strings.Contains(stderr, secret) || strings.Contains(stderr, "stdin-private-value") {
				t.Fatalf("failure leaked untrusted detail: %s", stderr)
			}
			assertControlRuntimeErrorCode(t, stderr, test.code)
		})
	}
}

func TestControlRuntimeRejectsInvalidSuccessReceiptWithoutLeakingIt(t *testing.T) {
	secret := "private-result-field"
	result := validControlRuntimeResult()
	result.SystemID = secret
	result.RolledBack = true
	installer := &recordingControlRuntimeInstaller{result: result}
	status, stdout, stderr := invokeControlRuntime(validControlRuntimeArguments(), strings.NewReader("input-secret"), true, installer)
	if status != exitVerify || stdout != "" || strings.Contains(stderr, secret) || strings.Contains(stderr, "input-secret") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertControlRuntimeErrorCode(t, stderr, "control_runtime_result")
}

func TestControlRuntimeUnavailableFailsBeforeReadingStdin(t *testing.T) {
	reader := &countedControlRuntimeReader{data: bytes.NewReader([]byte("stdin-secret"))}
	var stdout, stderr bytes.Buffer
	out := &emitter{json: true, stdout: &stdout, stderr: &stderr, command: "control-runtime.install"}
	status := runControlRuntime(validControlRuntimeArguments(), reader, out, controlRuntimeDependencies{})
	if status != exitConfig || reader.reads != 0 || stdout.Len() != 0 || strings.Contains(stderr.String(), "stdin-secret") {
		t.Fatalf("status=%d reads=%d stdout=%q stderr=%q", status, reader.reads, stdout.String(), stderr.String())
	}
	assertControlRuntimeErrorCode(t, stderr.String(), "control_runtime_unavailable")
}

func validControlRuntimeArguments() []string {
	return []string{
		"install",
		"--expected-system", controlRuntimeTestSystem,
		"--expected-control", controlRuntimeTestControl,
		"--minimum-generation", "7",
	}
}

func validControlRuntimeResult() controlruntime.InstallResult {
	return controlruntime.InstallResult{
		SystemID: controlRuntimeTestSystem, ControlName: controlRuntimeTestControl, Generation: 7,
		EnvelopeDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeDigest:  "sha256:" + strings.Repeat("b", 64),
		Changed:        true,
	}
}

func invokeControlRuntime(
	arguments []string,
	stdin io.Reader,
	jsonOutput bool,
	installer controlRuntimeInstaller,
) (int, string, string) {
	var stdout, stderr bytes.Buffer
	command := "control-runtime"
	if len(arguments) > 0 && arguments[0] == "install" {
		command = "control-runtime.install"
	}
	out := &emitter{json: jsonOutput, stdout: &stdout, stderr: &stderr, command: command}
	status := runControlRuntime(arguments, stdin, out, controlRuntimeDependencies{
		newInstaller: func() controlRuntimeInstaller { return installer },
	})
	return status, stdout.String(), stderr.String()
}

func assertControlRuntimeErrorCode(t *testing.T, output, expected string) {
	t.Helper()
	var envelope struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("invalid JSON failure %q: %v", output, err)
	}
	if envelope.OK || envelope.Error.Code != expected {
		t.Fatalf("failure=%+v, want code %q", envelope, expected)
	}
}

func TestParseControlRuntimeInstallArguments(t *testing.T) {
	request, err := parseControlRuntimeInstallArguments([]string{
		"--minimum-generation", "42",
		"--expected-system", controlRuntimeTestSystem,
		"--expected-control", controlRuntimeTestControl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.ExpectedSystemID != controlRuntimeTestSystem || request.ExpectedControlName != controlRuntimeTestControl ||
		request.MinimumGeneration != 42 {
		t.Fatalf("request = %+v", request)
	}
	if _, err := parseControlRuntimeInstallArguments([]string{
		"--expected-system", controlRuntimeTestSystem,
		"--expected-control", controlRuntimeTestControl,
		"--minimum-generation", "-1",
	}); err == nil {
		t.Fatal("negative generation accepted")
	}
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("unreachable sanity guard")
	}
}
