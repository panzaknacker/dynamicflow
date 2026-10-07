package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"dynamicflow/internal/workflow"
)

// These subprocesses exercise real signal delivery without signalling the Go
// test process or contacting a host. The fake SSH process is the test binary.
func TestControlSignalCLIHelper(t *testing.T) {
	if os.Getenv("FLOW_SIGNAL_HELPER") != "cli" {
		return
	}
	status := RunWithIO([]string{"--json", "--home", os.Getenv("FLOW_SIGNAL_HOME"), "control", "check", "control-1"}, os.Stdin, os.Stdout, os.Stderr)
	os.Exit(status)
}

func TestControlSignalSSHHelper(t *testing.T) {
	if os.Getenv("FLOW_SIGNAL_HELPER") != "ssh" {
		return
	}
	if err := os.WriteFile(os.Getenv("FLOW_SIGNAL_READY"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(91)
	}
	time.Sleep(2 * time.Minute)
	os.Exit(92)
}

func TestControlCLISignalsWaitForDurableCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(signal.String(), func(t *testing.T) {
			fixture := newControlCLIFixture(t)
			if status, stdout, stderr := invokeCLI(t, fixture.bindArguments(false)...); status != exitOK {
				t.Fatalf("bind: status=%d stdout=%s stderr=%s", status, stdout, stderr)
			}
			directory := t.TempDir()
			ready := filepath.Join(directory, "ready")
			ssh := "#!/bin/sh\nFLOW_SIGNAL_HELPER=ssh exec \"$FLOW_SIGNAL_EXECUTABLE\" -test.run '^TestControlSignalSSHHelper$'\n"
			if err := os.WriteFile(filepath.Join(directory, "ssh"), []byte(ssh), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, executable, "-test.run", "^TestControlSignalCLIHelper$")
			child.Env = append(os.Environ(), "FLOW_SIGNAL_HELPER=cli", "FLOW_SIGNAL_EXECUTABLE="+executable,
				"FLOW_SIGNAL_READY="+ready, "FLOW_SIGNAL_HOME="+fixture.home)
			var stdout, stderr bytes.Buffer
			child.Stdout, child.Stderr = &stdout, &stderr
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			finished := false
			defer func() {
				if finished {
					return
				}
				_ = child.Process.Kill()
				if data, err := os.ReadFile(ready); err == nil {
					if pid, err := strconv.Atoi(string(data)); err == nil {
						if process, err := os.FindProcess(pid); err == nil {
							_ = process.Kill()
						}
					}
				}
			}()
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					_ = child.Wait()
					t.Fatalf("local SSH helper did not start: %v", ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := child.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			err := child.Wait()
			finished = ctx.Err() == nil
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != exitPartial || ctx.Err() != nil {
				t.Fatalf("signal exit=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			envelope := decodeCLIEnvelope(t, stderr.String())
			if envelope.OK || envelope.Command != "control.check" || envelope.Error == nil || envelope.Error.Code != "cancelled" || stdout.Len() != 0 {
				t.Fatalf("unsafe signal result: %+v stderr=%q", envelope, stderr.String())
			}
			assertNoControlCLISecret(t, stdout.String()+stderr.String(), fixture)
			status, statusOutput, statusError := invokeCLI(t, "--json", "--home", fixture.home, "control", "status")
			var state struct {
				Tasks []workflow.Task `json:"tasks"`
			}
			if status != exitOK || json.Unmarshal(decodeCLIEnvelope(t, statusOutput).Data, &state) != nil ||
				len(state.Tasks) != 1 || state.Tasks[0].Phase != workflow.PhaseFailedSafe || state.Tasks[0].ResumePhase != workflow.PhaseHostKeyVerified {
				t.Fatalf("process exited before checkpoint: status=%d state=%+v stderr=%s", status, state, statusError)
			}
		})
	}
}
