package controlinstalltransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/sshtransport"
)

type installRunner struct {
	mu      sync.Mutex
	calls   int
	argv    []string
	payload []byte
	fail    bool
	secret  string
}

func (runner *installRunner) Run(_ context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	data, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	runner.payload = data
	_, _ = io.WriteString(stdout, strings.Repeat(runner.secret, 9000))
	_, _ = io.WriteString(stderr, strings.Repeat(runner.secret, 9000))
	if runner.fail {
		return errors.New("remote detail: " + runner.secret)
	}
	return nil
}

func (runner *installRunner) snapshot() (int, []string, []byte) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.calls, append([]string(nil), runner.argv...), append([]byte(nil), runner.payload...)
}

func TestInstallFirstControlStreamsVerifiedPayloadOnceWithFixedCommand(t *testing.T) {
	fixture := newInstallFixture(t)
	runner := &installRunner{secret: "discarded-remote-secret"}
	transport := New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now }))
	result, err := transport.InstallFirstControl(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	calls, argv, payload := runner.snapshot()
	if calls != 1 || result.Attempts != 1 || result.Route != "direct_first_control" ||
		result.FirstHopAlias != "control-1" || result.PolicyGeneration != 1 ||
		result.ExecutableBytes != int64(len(fixture.executableBytes)) || result.EnvelopeBytes != len(fixture.envelope) ||
		!result.StdoutTruncated || !result.StderrTruncated || result.StdoutBytes != MaxOutputBytes || result.StderrBytes != MaxOutputBytes {
		t.Fatalf("install result=%+v calls=%d argv=%#v", result, calls, argv)
	}
	wantPayload := append(append([]byte(nil), fixture.executableBytes...), fixture.envelope...)
	if !bytes.Equal(payload, wantPayload) {
		t.Fatalf("payload length=%d, want %d", len(payload), len(wantPayload))
	}
	if len(argv) != 6 || argv[0] != "-F" || argv[2] != "-S" || argv[3] != "none" || argv[4] != "flow-control-control-1" {
		t.Fatalf("managed SSH argv = %#v", argv)
	}
	command := argv[len(argv)-1]
	for _, required := range []string{
		"set -eu", "/usr/bin/sudo -n -- /usr/bin/mktemp -d /var/lib/.dynamicflow-bootstrap.",
		"iflag=fullblock", "/usr/bin/sha256sum -c -", "control-runtime install",
		"--expected-system " + fixture.systemID, "--expected-control control-1", "--minimum-generation 1",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("fixed remote command lacks %q: %s", required, command)
		}
	}
	for _, forbidden := range []string{
		fixture.executablePath, fixture.identityPath, fixture.request.Control.Host,
		fixture.request.Control.HostKey, string(fixture.envelope), runner.secret, "ProxyJump", "ProxyCommand",
	} {
		if strings.Contains(strings.Join(argv, "\n"), forbidden) {
			t.Fatalf("SSH argv leaked forbidden value %q", forbidden)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(fixture.executablePath)) || bytes.Contains(encoded, []byte(fixture.identityPath)) ||
		bytes.Contains(encoded, []byte(runner.secret)) {
		t.Fatalf("result leaked local/remote private data: %s", encoded)
	}
}

func TestInstallFirstControlFailureIsSanitizedAndNeverRetried(t *testing.T) {
	fixture := newInstallFixture(t)
	runner := &installRunner{fail: true, secret: "private-remote-error"}
	transport := New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now }))
	result, err := transport.InstallFirstControl(context.Background(), fixture.request)
	if !errors.Is(err, ErrControlInstall) || strings.Contains(err.Error(), runner.secret) || result.Attempts != 1 {
		t.Fatalf("unsafe failure result=%+v err=%v", result, err)
	}
	if calls, _, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("failed install attempts=%d, want exactly one", calls)
	}
}

func TestInstallFirstControlRejectsChangedExecutableAndEnvelopeBeforeRunner(t *testing.T) {
	fixture := newInstallFixture(t)
	runner := &installRunner{}
	transport := New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now }))
	changed := bytes.Repeat([]byte("Z"), len(fixture.executableBytes))
	if err := os.WriteFile(fixture.executablePath, changed, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.InstallFirstControl(context.Background(), fixture.request); !errors.Is(err, ErrPayloadChanged) {
		t.Fatalf("changed executable error = %v", err)
	}
	if calls, _, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("changed executable reached runner: %d", calls)
	}

	fixture = newInstallFixture(t)
	runner = &installRunner{}
	transport = New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now }))
	fixture.request.Envelope = append([]byte(nil), fixture.request.Envelope...)
	fixture.request.Envelope[len(fixture.request.Envelope)-1] ^= 1
	if _, err := transport.InstallFirstControl(context.Background(), fixture.request); !errors.Is(err, ErrInvalidInstall) {
		t.Fatalf("tampered envelope error = %v", err)
	}
	if calls, _, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("tampered envelope reached runner: %d", calls)
	}
}

func TestNewExecutableRejectsWritableSymlinkAndHardlinkAndCannotSerializePath(t *testing.T) {
	directory := t.TempDir()
	unsafe := filepath.Join(directory, "unsafe-flow")
	if err := os.WriteFile(unsafe, []byte("unsafe"), 0o722); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o722); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExecutable(unsafe); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("world-writable executable error = %v", err)
	}
	if err := os.Chmod(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink-flow")
	if err := os.Symlink(unsafe, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExecutable(symlink); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("symlink executable error = %v", err)
	}
	hardlink := filepath.Join(directory, "hardlink-flow")
	if err := os.Link(unsafe, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExecutable(unsafe); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("hardlinked executable error = %v", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	executable, err := NewExecutable(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(executable); !errors.Is(err, ErrPrivatePathJSON) {
		t.Fatalf("Executable JSON error = %v", err)
	}
}

func TestNewExecutableRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow-fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := NewExecutable(path)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("FIFO was accepted as an executable: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Release a regressed blocking reader before failing the test, so
		// neither a goroutine nor a FIFO descriptor survives the fixture.
		if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatal("opening an executable FIFO waited for a writer")
	}
}

type installFixture struct {
	store           *localstate.Store
	now             time.Time
	systemID        string
	executablePath  string
	executableBytes []byte
	identityPath    string
	envelope        []byte
	request         Request
}

func newInstallFixture(t *testing.T) installFixture {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	identityPath, identityPublic := generateSSHKey(t, keygen, filepath.Join(directory, "bootstrap"), "bootstrap")
	hostPath, hostPublic := generateSSHKey(t, keygen, filepath.Join(directory, "host"), "host")
	defer os.Remove(hostPath)
	defer os.Remove(hostPath + ".pub")
	_, identityFingerprint, err := sshkeys.ValidateEd25519PublicKey(identityPublic)
	if err != nil {
		t.Fatal(err)
	}
	hostNormalized, hostFingerprint, err := sshkeys.ValidateEd25519PublicKey(hostPublic)
	if err != nil {
		t.Fatal(err)
	}
	hostFields := strings.Fields(hostNormalized)
	privateIdentity, err := sshtransport.NewPrivateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := sshtransport.Endpoint{
		Alias: "control-1", Role: sshtransport.RoleControl, Host: "203.0.113.40", Port: 22,
		User: "debian", Identity: privateIdentity, IdentityFingerprint: identityFingerprint,
		HostKey: strings.Join(hostFields[:2], " "), HostKeyFingerprint: hostFingerprint,
	}

	managementPath, managementPublic := generateSSHKey(t, keygen, filepath.Join(directory, "management"), "management")
	defer os.Remove(managementPath)
	defer os.Remove(managementPath + ".pub")
	managementNormalized, managementFingerprint, err := sshkeys.ValidateEd25519PublicKey(managementPublic)
	if err != nil {
		t.Fatal(err)
	}
	managementFields := strings.Fields(managementNormalized)
	now := time.Date(2026, 7, 23, 16, 0, 0, 0, time.UTC)
	systemID := "sys-00000000000000000000000000000000"
	policy := controlpolicy.Policy{
		SchemaVersion: controlpolicy.SchemaVersion, SystemID: systemID, ControlName: "control-1",
		Generation: 1, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		ManagementKeys: []controlpolicy.ManagementKey{{
			Name: "control-1", Generation: 1, State: controlpolicy.KeyActive,
			PublicKey: strings.Join(managementFields[:2], " "), Fingerprint: managementFingerprint,
		}}, Routes: []controlpolicy.Route{},
	}
	_, privateSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := controlpolicy.Sign(policy, privateSigner)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := signing.MarshalPublicPEM(privateSigner.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := controlruntime.NewEnvelope(systemID, "control-1", publicPEM, signed)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := controlruntime.MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(directory, "flow")
	executableBytes := []byte("test-flow-binary-content")
	if err := os.WriteFile(executablePath, executableBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := NewExecutable(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Control: endpoint, Executable: executable, Envelope: envelopeBytes,
		ExpectedSystemID: systemID, ExpectedControlName: "control-1", MinimumGeneration: 1,
	}
	return installFixture{
		store: store, now: now, systemID: systemID, executablePath: executablePath,
		executableBytes: executableBytes, identityPath: identityPath, envelope: envelopeBytes, request: request,
	}
}

func generateSSHKey(t *testing.T, keygen, path, comment string) (string, string) {
	t.Helper()
	command := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate SSH key: %v: %s", err, output)
	}
	public, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return path, string(public)
}
