package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instances"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

func TestInstanceSSHArgsOffersPreviousOnlyDuringRecordedOverlap(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
	initial, err := keys.Create(context.Background(), sshkeys.Instance, "rotation-test")
	if err != nil {
		t.Fatal(err)
	}
	manager := instances.NewManager(store, keys)
	if _, err := manager.Put(instances.Record{
		Name: "rotation-test", Profile: "ssh", Host: "192.0.2.9", SSHPort: 22,
		SSHUser: "debian", Key: instances.KeyRef{Scope: sshkeys.Instance, Name: "rotation-test"},
		HostKey: initial.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	local := localEnrollment{
		Schema: 1, Name: "rotation-test", Profile: "ssh", State: "issued",
		KeyScope: sshkeys.Instance, KeyName: "rotation-test", KeyGeneration: initial.Generation,
		Desired: enrollment.SignedDesiredState{State: enrollment.DesiredState{Instance: "rotation-test"}},
		Host:    "192.0.2.9", SSHUser: "debian", SSHPort: 22,
	}
	if err := store.WriteJSON(filepath.Join("enrollments", "rotation-test.json"), local); err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	assertSSHIdentityCount(t, ctx, "rotation-test", 1)

	expected, bound, err := boundInstanceKeyRotation(ctx, "rotation-test")
	if err != nil || !bound || expected != initial.Generation {
		t.Fatalf("bound rotation checkpoint = %d/%t, %v", expected, bound, err)
	}
	rotated, err := keys.RotateIfGeneration(context.Background(), sshkeys.Instance, "rotation-test", expected)
	if err != nil {
		t.Fatal(err)
	}
	expected, bound, err = boundInstanceKeyRotation(ctx, "rotation-test")
	if err != nil || !bound || expected != initial.Generation {
		t.Fatalf("second bound checkpoint = %d/%t, %v", expected, bound, err)
	}
	if _, err := keys.RotateIfGeneration(context.Background(), sshkeys.Instance, "rotation-test", expected); !errors.Is(err, sshkeys.ErrGeneration) {
		t.Fatalf("second unacknowledged rotation error = %v", err)
	}
	_, previousPaths, err := keys.Previous(sshkeys.Instance, "rotation-test")
	if err != nil {
		t.Fatal(err)
	}
	// The key was rotated locally but the overlap generation has not yet been
	// published. Both identities are needed to avoid a transient lockout.
	args := assertSSHIdentityCount(t, ctx, "rotation-test", 2)
	if !cliContainsPair(args, "-i", previousPaths.Private) {
		t.Fatal("pre-publication overlap omitted the previous identity")
	}

	// Publishing the overlap records the active generation and keeps the
	// explicit pending bit until the target acknowledgement is observed.
	local.KeyGeneration = rotated.Generation
	local.RotationPending = true
	if err := store.WriteJSON(filepath.Join("enrollments", "rotation-test.json"), local); err != nil {
		t.Fatal(err)
	}
	assertSSHIdentityCount(t, ctx, "rotation-test", 2)

	// Publishing old-key removal clears the overlap. The old private file is
	// retained as local audit/recovery evidence but must no longer enter argv.
	local.RotationPending = false
	if err := store.WriteJSON(filepath.Join("enrollments", "rotation-test.json"), local); err != nil {
		t.Fatal(err)
	}
	args = assertSSHIdentityCount(t, ctx, "rotation-test", 1)
	if cliContainsPair(args, "-i", previousPaths.Private) {
		t.Fatal("completed rotation still offered the previous private identity")
	}

	local.State = "revoked"
	if err := store.WriteJSON(filepath.Join("enrollments", "rotation-test.json"), local); err != nil {
		t.Fatal(err)
	}
	if _, err := instanceSSHArgs(ctx, "rotation-test"); !errors.Is(err, instances.ErrRevoked) {
		t.Fatalf("revoked enrollment SSH error = %v", err)
	}
}

func TestInstanceExecJSONEnvelopeMatchesRemoteExit(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	remoteArgs := []string{"printf", "hello world"}
	wantDigest := sha256.Sum256([]byte(strings.Join(remoteArgs, "\x00")))

	for _, test := range []struct {
		name       string
		remoteExit string
		wantStatus int
		wantOK     bool
	}{
		{name: "success", remoteExit: "0", wantStatus: exitOK, wantOK: true},
		{name: "remote nonzero", remoteExit: "42", wantStatus: 42, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := privateTempDir(t)
			store, err := localstate.Open(home)
			if err != nil {
				t.Fatal(err)
			}
			keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
			identity, err := keys.Create(context.Background(), sshkeys.Instance, "exec-test")
			if err != nil {
				t.Fatal(err)
			}
			manager := instances.NewManager(store, keys)
			if _, err := manager.Put(instances.Record{
				Name: "exec-test", Profile: "ssh", Host: "192.0.2.10", SSHPort: 22,
				SSHUser: "debian", Key: instances.KeyRef{Scope: sshkeys.Instance, Name: "exec-test"},
				HostKey: identity.PublicKey,
			}); err != nil {
				t.Fatal(err)
			}
			local := localEnrollment{
				Schema: 1, Name: "exec-test", Profile: "ssh", State: "issued",
				KeyScope: sshkeys.Instance, KeyName: "exec-test", KeyGeneration: identity.Generation,
				Desired: enrollment.SignedDesiredState{State: enrollment.DesiredState{Instance: "exec-test"}},
				Host:    "192.0.2.10", SSHUser: "debian", SSHPort: 22,
			}
			if err := store.WriteJSON(filepath.Join("enrollments", "exec-test.json"), local); err != nil {
				t.Fatal(err)
			}

			fakeBin := privateTempDir(t)
			fakeSSH := filepath.Join(fakeBin, "ssh")
			fakeScript := "#!/bin/sh\nprintf '%s\\n' 'remote stdout'\nprintf '%s\\n' 'remote stderr' >&2\nexit \"${FLOW_TEST_SSH_EXIT:-1}\"\n"
			if err := os.WriteFile(fakeSSH, []byte(fakeScript), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", fakeBin)
			t.Setenv("FLOW_TEST_SSH_EXIT", test.remoteExit)
			arguments := []string{"--json", "--home", home, "instance", "exec", "exec-test", "--"}
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, append(arguments, remoteArgs...)...)
			if status != test.wantStatus {
				t.Fatalf("status=%d, want %d; stdout=%q stderr=%q", status, test.wantStatus, stdout, stderr)
			}
			document, other := stdout, stderr
			if !test.wantOK {
				document, other = stderr, stdout
			}
			if other != "" {
				t.Fatalf("unexpected second output stream: %q", other)
			}
			envelope := decodeCLIEnvelope(t, document)
			if envelope.OK != test.wantOK || envelope.Command != "instance.exec" {
				t.Fatalf("envelope=%+v", envelope)
			}
			if test.wantOK && envelope.Error != nil {
				t.Fatalf("success has error: %+v", envelope.Error)
			}
			if !test.wantOK && (envelope.Error == nil || envelope.Error.Code != "remote_command" || envelope.Error.Message == "" || envelope.Error.Next == "") {
				t.Fatalf("failure error=%+v", envelope.Error)
			}
			var data map[string]any
			if err := json.Unmarshal(envelope.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data["instance"] != "exec-test" ||
				data["exit_code"] != float64(test.wantStatus) ||
				data["stdout"] != "remote stdout\n" ||
				data["stderr"] != "remote stderr\n" ||
				data["argv_sha256"] != hex.EncodeToString(wantDigest[:]) {
				t.Fatalf("data=%+v", data)
			}
		})
	}
}

func TestExplicitSSHAndExecAuditFailureDoesNotStartProcess(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
	identity, err := keys.Create(context.Background(), sshkeys.Instance, "audit-gate")
	if err != nil {
		t.Fatal(err)
	}
	manager := instances.NewManager(store, keys)
	if _, err := manager.Put(instances.Record{
		Name: "audit-gate", Profile: "ssh", Host: "192.0.2.11", SSHPort: 22,
		SSHUser: "debian", Key: instances.KeyRef{Scope: sshkeys.Instance, Name: "audit-gate"},
		HostKey: identity.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	local := localEnrollment{
		Schema: 1, Name: "audit-gate", Profile: "ssh", State: "issued",
		KeyScope: sshkeys.Instance, KeyName: "audit-gate", KeyGeneration: identity.Generation,
		Desired: enrollment.SignedDesiredState{State: enrollment.DesiredState{Instance: "audit-gate"}},
		Host:    "192.0.2.11", SSHUser: "debian", SSHPort: 22,
	}
	if err := store.WriteJSON(filepath.Join("enrollments", "audit-gate.json"), local); err != nil {
		t.Fatal(err)
	}

	fakeBin := privateTempDir(t)
	sentinel := filepath.Join(privateTempDir(t), "ssh-started")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	script := "#!/bin/sh\n: >\"$FLOW_TEST_SSH_SENTINEL\"\nexit 0\n"
	if err := os.WriteFile(fakeSSH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("FLOW_TEST_SSH_SENTINEL", sentinel)
	if err := os.MkdirAll(filepath.Join(home, "logs", "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{name: "ssh", arguments: []string{"instance", "ssh", "audit-gate"}},
		{name: "exec", arguments: []string{"instance", "exec", "audit-gate", "--", "true"}},
		{name: "secret", arguments: []string{"instance", "secret", "reveal", "audit-gate", "--secret", "vnc"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			arguments := append([]string{"--home", home}, test.arguments...)
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, arguments...)
			if status != exitFailure || stdout != "" || !strings.Contains(stderr, "[audit_unavailable]") {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("SSH process started despite failed pre-action audit: %v", err)
			}
		})
	}
}

func TestInstanceVNCSecretUsesOnlyFixedTargetOneShot(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
	identity, err := keys.Create(context.Background(), sshkeys.Instance, "vnc-fixed")
	if err != nil {
		t.Fatal(err)
	}
	manager := instances.NewManager(store, keys)
	if _, err := manager.Put(instances.Record{
		Name: "vnc-fixed", Profile: "ssh-gui", Host: "192.0.2.12", SSHPort: 22,
		SSHUser: "debian", Key: instances.KeyRef{Scope: sshkeys.Instance, Name: "vnc-fixed"},
		HostKey: identity.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	local := localEnrollment{
		Schema: 1, Name: "vnc-fixed", Profile: "ssh-gui", State: "issued",
		KeyScope: sshkeys.Instance, KeyName: "vnc-fixed", KeyGeneration: identity.Generation,
		Desired: enrollment.SignedDesiredState{State: enrollment.DesiredState{Instance: "vnc-fixed"}},
		Host:    "192.0.2.12", SSHUser: "debian", SSHPort: 22,
	}
	if err := store.WriteJSON(filepath.Join("enrollments", "vnc-fixed.json"), local); err != nil {
		t.Fatal(err)
	}

	fakeBin := privateTempDir(t)
	argvPath := filepath.Join(privateTempDir(t), "argv")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	fakeScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$FLOW_TEST_SSH_ARGV\"\nif [ \"${FLOW_TEST_SSH_FAIL:-0}\" = 1 ]; then printf '%s\\n' \"$FLOW_TEST_REMOTE_SECRET\" >&2; exit 23; fi\nprintf '%s\\n' \"$FLOW_TEST_REMOTE_SECRET\"\n"
	if err := os.WriteFile(fakeSSH, []byte(fakeScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("FLOW_TEST_SSH_ARGV", argvPath)
	t.Setenv("FLOW_TEST_REMOTE_SECRET", "Ab3dE5gH")

	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, "--home", home, "instance", "secret", "rotate", "vnc-fixed", "--secret", "vnc")
	if status != exitOK || stdout != "Ab3dE5gH\n" || !strings.Contains(stderr, "WARNING:") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	argv, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	joined := string(argv)
	for _, required := range []string{"sudo\n-n\n/usr/local/bin/flow\ninstance-runtime\nsecret\nrotate\n--secret\nvnc\n"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("fixed target argv missing %q in %q", required, joined)
		}
	}
	for _, forbidden := range []string{"Ab3dE5gH", "/bin/bash", "cat\n", ".vm-bootstrap-vnc"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("remote argv contains forbidden value %q: %q", forbidden, joined)
		}
	}
	auditBytes, err := os.ReadFile(filepath.Join(home, "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditBytes, []byte("Ab3dE5gH")) {
		t.Fatalf("audit contains credential: %q", auditBytes)
	}

	t.Setenv("FLOW_TEST_REMOTE_SECRET", "Leak1234")
	t.Setenv("FLOW_TEST_SSH_FAIL", "1")
	status, stdout, stderr = invokeInternalLegacyHandlerForTest(t, "--home", home, "instance", "secret", "reveal", "vnc-fixed", "--secret", "vnc")
	if status != exitRemote || strings.Contains(stdout+stderr, "Leak1234") {
		t.Fatalf("failure disclosed remote stderr: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	auditBytes, err = os.ReadFile(filepath.Join(home, "logs", "audit.jsonl"))
	if err != nil || bytes.Contains(auditBytes, []byte("Leak1234")) {
		t.Fatalf("failure audit contains credential: err=%v audit=%q", err, auditBytes)
	}
}

func TestVNCSecretOutputRequiresOneBoundedCanonicalLine(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		valid bool
	}{
		{"canonical", "Ab3dE5gH\n", true},
		{"no newline", "Ab3dE5gH", false},
		{"crlf", "Ab3dE5gH\r\n", false},
		{"second line", "Ab3dE5gH\nOther", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output vncSecretOutput
			if _, err := output.Write([]byte(test.input)); err != nil {
				t.Fatal(err)
			}
			value, valid := output.value()
			if valid != test.valid || test.valid && value != "Ab3dE5gH" {
				t.Fatalf("value=%q valid=%t", value, valid)
			}
		})
	}
}

func TestSSHArgsWithVNCForwardEnablesOnlyFixedLoopbackTunnel(t *testing.T) {
	base := []string{
		"-F", "none",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-p", "22",
		"-l", "admin",
		"203.0.113.10",
	}
	args, err := sshArgsWithVNCForward(base, 5902)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"ClearAllForwardings=no",
		"ExitOnForwardFailure=yes",
		"-L 127.0.0.1:5902:127.0.0.1:5901",
		"ForwardAgent=no",
		"ForwardX11=no",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("GUI SSH args missing %q: %v", want, args)
		}
	}
	if strings.Contains(joined, "ClearAllForwardings=yes") {
		t.Fatalf("GUI SSH args still suppress the tunnel: %v", args)
	}
	ssh, lookupErr := exec.LookPath("ssh")
	if lookupErr != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	output, commandErr := exec.Command(ssh, append([]string{"-G"}, args...)...).CombinedOutput()
	if commandErr != nil {
		t.Fatalf("ssh -G rejected GUI arguments: %v: %s", commandErr, output)
	}
	config := strings.ToLower(string(output))
	if !strings.Contains(config, "clearallforwardings no") ||
		!strings.Contains(config, "localforward [127.0.0.1]:5902 [127.0.0.1]:5901") {
		t.Fatalf("OpenSSH did not resolve the loopback VNC tunnel:\n%s", output)
	}
}

func assertSSHIdentityCount(t *testing.T, ctx *commandContext, name string, want int) []string {
	t.Helper()
	args, err := instanceSSHArgs(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, argument := range args {
		if argument == "-i" {
			count++
		}
	}
	if count != want {
		t.Fatalf("SSH identity count = %d, want %d: %v", count, want, args)
	}
	return args
}

func cliContainsPair(values []string, first, second string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == first && values[index+1] == second {
			return true
		}
	}
	return false
}
