package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOperatorRemoteCommandsFailClosedBeforeStateNetworkOrProcess(t *testing.T) {
	var serverCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverCalls.Add(1)
	}))
	t.Cleanup(server.Close)

	temporary := privateTempDir(t)
	home := filepath.Join(temporary, "operator-state-must-not-be-created")
	sentinel := filepath.Join(temporary, "process-must-not-run")
	installRouteGateProcessSentinels(t, sentinel)
	t.Setenv("FLOW_ALLOW_DIRECT", "1")
	t.Setenv("DYNAMICFLOW_ALLOW_DIRECT", "true")
	t.Setenv("FLOW_CONTROL_ROUTE_READY", "1")

	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{"serving configure", "serving.configure", []string{"serving", "configure", "--url", server.URL, "--ca-file", "/tmp/unread-ca.pem", "--tls-pin", "SHA256:blocked"}},
		{"start serving", "start.serving", []string{"start", "serving"}},
		{"start serving plan", "start.serving", []string{"start", "serving", "--plan"}},
		{"status serving", "status.serving", []string{"status", "serving"}},
		{"logs serving", "logs.serving", []string{"logs", "serving", "--lines", "5"}},
		{"enroll create", "enroll.create", []string{"enroll", "create", "--name", "node-1", "--profile", "pbp"}},
		{"enroll list", "enroll.list", []string{"enroll", "list"}},
		{"enroll revoke", "enroll.revoke", []string{"enroll", "revoke", "--id", "blocked"}},
		{"instance status", "instance.status", []string{"instance", "status", "node-1"}},
		{"instance logs", "instance.logs", []string{"instance", "logs", "node-1", "--component", "pbp"}},
		{"instance apply", "instance.apply", []string{"instance", "apply", "node-1", "--profile", "pbp"}},
		{"instance apply plan", "instance.apply", []string{"instance", "apply", "node-1", "--profile", "pbp", "--plan"}},
		{"instance ssh", "instance.ssh", []string{"instance", "ssh", "node-1"}},
		{"instance gui", "instance.ssh", []string{"instance", "ssh", "node-1", "--gui", "--local-port", "5901"}},
		{"instance exec", "instance.exec", []string{"instance", "exec", "node-1", "--", "/bin/true"}},
		{"instance secret reveal", "instance.secret.reveal", []string{"instance", "secret", "reveal", "node-1", "--secret", "vnc"}},
		{"instance secret rotate", "instance.secret.rotate", []string{"instance", "secret", "rotate", "node-1", "--secret", "vnc"}},
		{"instance key finalize", "instance.key.finalize", []string{"instance", "key", "finalize", "node-1"}},
		{"instance key finalize plan", "instance.key.finalize", []string{"instance", "key", "finalize", "node-1", "--plan"}},
		{"instance revoke", "instance.revoke", []string{"instance", "revoke", "node-1"}},
		{"release publish remote", "release.publish", []string{"release", "publish", "--remote"}},
		{"release publish remote plan", "release.publish", []string{"release", "publish", "--remote", "--plan"}},
		{"release publish implicit", "release.publish", []string{"release", "publish"}},
		{"release publish implicit plan", "release.publish", []string{"release", "publish", "--plan"}},
		{"test lab", "test.lab", []string{"test", "lab", "--inventory", "/tmp/lab.yaml"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			beforeCalls := serverCalls.Load()
			arguments := append([]string{"--json", "--home", home}, test.args...)
			status, stdout, stderr := invokeCLI(t, arguments...)
			if status != exitConflict || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			var envelope struct {
				OK      bool   `json:"ok"`
				Command string `json:"command"`
				Error   struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Next    string `json:"next"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stderr), &envelope); err != nil {
				t.Fatalf("decode failure: %v; stderr=%q", err, stderr)
			}
			if envelope.OK || envelope.Command != test.command || envelope.Error.Code != controlRouteUnavailableCode ||
				envelope.Error.Message != controlRouteUnavailableText || envelope.Error.Next != controlRouteUnavailableNext ||
				!strings.Contains(envelope.Error.Next, "Control route") {
				t.Fatalf("unexpected envelope: %+v", envelope)
			}
			if serverCalls.Load() != beforeCalls {
				t.Fatal("blocked command contacted the HTTP server")
			}
			if _, err := os.Lstat(sentinel); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("blocked command executed a process: %v", err)
			}
			if _, err := os.Lstat(home); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("route gate was reached only after opening operator state: %v", err)
			}
		})
	}
}

func TestControlRouteGateAllowsOnlyProvenLocalOrControlSurfaces(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		blocked bool
	}{
		{"system init", []string{"system", "init", "--name", "lab"}, false},
		{"control check", []string{"control", "check", "control-1"}, false},
		{"control install", []string{"control", "install", "control-1"}, false},
		{"dashboard", []string{"dashboard"}, false},
		{"doctor", []string{"doctor"}, false},
		{"key rotate", []string{"key", "rotate", "--name", "operator"}, false},
		{"profile list", []string{"profile", "list"}, false},
		{"release build", []string{"release", "build"}, false},
		{"release verify", []string{"release", "verify"}, false},
		{"explicit local publish", []string{"release", "publish", "--root", "/srv/dynamicflow/releases"}, false},
		{"explicit local publish plan", []string{"release", "publish", "--plan", "--root=/srv/dynamicflow/releases"}, false},
		{"explicit local publish remote false", []string{"release", "publish", "--remote=false", "--root", "/srv/dynamicflow/releases"}, false},
		{"ambiguous publish", []string{"release", "publish"}, true},
		{"relative publish", []string{"release", "publish", "--root", "releases"}, true},
		{"root filesystem publish", []string{"release", "publish", "--root", "/"}, true},
		{"empty publish", []string{"release", "publish", "--root="}, true},
		{"duplicate publish ending empty", []string{"release", "publish", "--root", "/srv/dynamicflow/releases", "--root="}, true},
		{"remote true with root", []string{"release", "publish", "--root", "/srv/dynamicflow/releases", "--remote=true"}, true},
		{"lab plan", []string{"test", "lab", "--plan"}, false},
		{"lab plan true", []string{"test", "lab", "--inventory", "/tmp/lab.yaml", "--plan=true"}, false},
		{"lab plan false", []string{"test", "lab", "--plan=false"}, true},
		{"lab plan behind separator", []string{"test", "lab", "--", "--plan"}, true},
		{"instance list", []string{"instance", "list"}, false},
		{"instance bind", []string{"instance", "bind", "node-1"}, false},
		{"instance hostkey local", []string{"instance", "hostkey", "pin", "node-1"}, false},
		{"serving show", []string{"serving", "show"}, false},
		{"raw serve", []string{"serve", "--config", "/etc/dynamicflow/config.json"}, false},
		{"raw instance runtime", []string{"instance-runtime", "status"}, false},
		{"future raw control runtime", []string{"control-runtime", "session"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := operatorActionNeedsControlRoute(test.args); got != test.blocked {
				t.Fatalf("operatorActionNeedsControlRoute(%q)=%t, want %t", test.args, got, test.blocked)
			}
		})
	}
}

func installRouteGateProcessSentinels(t *testing.T, sentinel string) {
	t.Helper()
	directory := filepath.Join(privateTempDir(t), "bin")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n: >\"$FLOW_ROUTE_GATE_SENTINEL\"\nexit 99\n"
	for _, name := range []string{"ssh", "curl", "journalctl", "systemctl"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	t.Setenv("FLOW_ROUTE_GATE_SENTINEL", sentinel)
}
