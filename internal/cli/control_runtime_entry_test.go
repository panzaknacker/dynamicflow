package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dynamicflow/internal/controlruntime"
)

func TestControlRuntimeEntryIsIndependentOfOperatorState(t *testing.T) {
	home := filepath.Join(t.TempDir(), "operator-must-not-exist")
	t.Setenv("FLOW_HOME", home)
	t.Setenv("FLOW_PROFILES_DIR", filepath.Join(home, "missing-profiles"))
	t.Setenv("SSH_ORIGINAL_COMMAND", "untrusted-shell-command")
	for _, test := range []struct {
		name string
		args []string
		code int
		text string
	}{
		{"group help", []string{"control-runtime", "--help"}, exitOK, "Control runtime"},
		{"install help", []string{"control-runtime", "install", "--help"}, exitOK, "--expected-system"},
		{"session help", []string{"control-runtime", "session", "--help"}, exitOK, "SSH_ORIGINAL_COMMAND"},
		{"apply help", []string{"control", "apply", "--help"}, exitOK, "flow control apply"},
		{"invalid install", []string{"--json", "control-runtime", "install"}, exitUsage, "control-runtime.install"},
		{"denied session", []string{"control-runtime", "session", "--state-root", controlruntime.DefaultStateRoot}, exitAuth, "Control session denied"},
		{"session alternate root", []string{"control-runtime", "session", "--state-root", home}, exitUsage, "Control session denied"},
		{"install operator home", []string{"control-runtime", "install", "--home", home}, exitUsage, "operator state options"},
		{"session source root", []string{"control-runtime", "session", "--source-root", home}, exitUsage, "operator state options"},
		{"session json", []string{"--json", "control-runtime", "session", "--state-root", controlruntime.DefaultStateRoot}, exitUsage, "fixed attestation protocol"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &countedControlRuntimeReader{data: bytes.NewReader([]byte("stdin-secret"))}
			var stdout, stderr bytes.Buffer
			status := RunWithIO(test.args, reader, &stdout, &stderr)
			output := stdout.String() + stderr.String()
			if status != test.code || !strings.Contains(output, test.text) || reader.reads != 0 || strings.Contains(output, "stdin-secret") {
				t.Fatalf("status=%d reads=%d stdout=%q stderr=%q", status, reader.reads, stdout.String(), stderr.String())
			}
			if _, err := os.Lstat(home); !os.IsNotExist(err) {
				t.Fatalf("runtime accessed operator state: %v", err)
			}
		})
	}
}

func TestControlRuntimeInstallEntryReachesActualInstaller(t *testing.T) {
	home := filepath.Join(t.TempDir(), "operator-must-not-exist")
	t.Setenv("FLOW_HOME", home)
	arguments := append([]string{"--json", "control-runtime"}, validControlRuntimeArguments()...)
	var stdout, stderr bytes.Buffer
	status := RunWithIO(arguments, strings.NewReader("{}"), &stdout, &stderr)
	wantStatus, wantCode := exitAuth, "privilege"
	if os.Geteuid() == 0 {
		// A malformed envelope is rejected before any privileged mutation.
		wantStatus, wantCode = exitVerify, "control_envelope_verify"
	}
	if status != wantStatus || stdout.Len() != 0 {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	envelope := decodeCLIEnvelope(t, stderr.String())
	if envelope.Command != "control-runtime.install" || envelope.Error == nil || envelope.Error.Code != wantCode {
		t.Fatalf("unexpected runtime result: %s", stderr.String())
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("installer created operator state: %v", err)
	}
}

type recordingControlSession struct {
	calls    int
	request  controlruntime.SessionRequest
	response []byte
	err      error
}

func (session *recordingControlSession) Execute(_ context.Context, request controlruntime.SessionRequest) ([]byte, error) {
	session.calls++
	session.request = request
	return session.response, session.err
}

func TestControlSessionAdapterPreservesCanonicalProtocolAndIgnoresStdin(t *testing.T) {
	response := []byte(`{"schema":1,"nonce":"public-nonce"}`)
	session := &recordingControlSession{response: response}
	reader := &countedControlRuntimeReader{data: bytes.NewReader([]byte("stdin-secret"))}
	var stdout, stderr bytes.Buffer
	status := runControlRuntime([]string{"session", "--state-root", controlruntime.DefaultStateRoot}, reader,
		&emitter{stdout: &stdout, stderr: &stderr}, controlRuntimeDependencies{
			newSession:   func() controlRuntimeSession { return session },
			newInstaller: func() controlRuntimeInstaller { t.Fatal("session constructed installer"); return nil },
		})
	if status != exitOK || session.calls != 1 || reader.reads != 0 || stderr.Len() != 0 || !bytes.Equal(stdout.Bytes(), response) {
		t.Fatalf("status=%d calls=%d reads=%d stdout=%q stderr=%q", status, session.calls, reader.reads, stdout.String(), stderr.String())
	}
	if session.request.StateRoot != controlruntime.DefaultStateRoot {
		t.Fatalf("unexpected session root: %+v", session.request)
	}
}

func TestControlSessionRejectsArgumentsBeforeConstruction(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--state-root=" + controlruntime.DefaultStateRoot},
		{"--state-root", "/"}, {"--state-root", controlruntime.DefaultStateRoot + "/"},
		{"--state-root", controlruntime.DefaultStateRoot, "extra-secret"},
		{"--state-root", controlruntime.DefaultStateRoot, "--state-root", controlruntime.DefaultStateRoot},
	} {
		var stdout, stderr bytes.Buffer
		status := runControlRuntime(append([]string{"session"}, args...), strings.NewReader("stdin-secret"),
			&emitter{stdout: &stdout, stderr: &stderr}, controlRuntimeDependencies{
				newSession: func() controlRuntimeSession { t.Fatal("invalid args constructed session"); return nil },
			})
		if status != exitUsage || stdout.Len() != 0 || stderr.String() != controlruntime.ErrSessionDenied.Error()+"\n" {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", args, status, stdout.String(), stderr.String())
		}
	}
}

func TestControlSessionErrorsNeverExposeUnderlyingDetails(t *testing.T) {
	for _, denied := range []bool{true, false} {
		cause, want, code := controlruntime.ErrSessionUnavailable, controlruntime.ErrSessionUnavailable, exitFailure
		if denied {
			cause, want, code = controlruntime.ErrSessionDenied, controlruntime.ErrSessionDenied, exitAuth
		}
		session := &recordingControlSession{response: []byte("unsafe partial response"), err: errors.Join(cause, errors.New("private remote detail"))}
		var stdout, stderr bytes.Buffer
		status := runControlRuntime([]string{"session", "--state-root", controlruntime.DefaultStateRoot}, nil,
			&emitter{stdout: &stdout, stderr: &stderr}, controlRuntimeDependencies{newSession: func() controlRuntimeSession { return session }})
		if status != code || stdout.Len() != 0 || stderr.String() != want.Error()+"\n" {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
		}
	}
}
