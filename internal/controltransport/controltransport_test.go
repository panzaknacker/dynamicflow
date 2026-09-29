package controltransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshtransport"
)

type recordingRunner struct {
	mu       sync.Mutex
	calls    int
	argv     []string
	stdin    io.Reader
	deadline time.Time
	run      func(context.Context, io.Writer, io.Writer) error
}

func (runner *recordingRunner) Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.mu.Lock()
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	runner.stdin = stdin
	runner.deadline, _ = ctx.Deadline()
	runner.mu.Unlock()
	if runner.run != nil {
		return runner.run(ctx, stdout, stderr)
	}
	return nil
}

func (runner *recordingRunner) snapshot() (int, []string, io.Reader, time.Time) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.calls, append([]string(nil), runner.argv...), runner.stdin, runner.deadline
}

func TestCheckFirstControlUsesExactSingleFixedInvocation(t *testing.T) {
	fixture := newFixture(t)
	runner := &recordingRunner{}
	started := time.Now()
	result, err := New(fixture.builder, runner).CheckFirstControl(context.Background(), fixture.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	calls, argv, stdin, deadline := runner.snapshot()
	if calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
	if stdin != nil {
		t.Fatalf("runner stdin = %#v, want nil", stdin)
	}
	if len(argv) != 6 || argv[0] != "-F" || argv[2] != "-S" || argv[3] != "none" ||
		argv[4] != "flow-control-control-a" || argv[5] != "/bin/true" {
		t.Fatalf("runner argv = %#v", argv)
	}
	if !filepath.IsAbs(argv[1]) || strings.Contains(strings.Join(argv, "\x00"), fixture.privatePath) {
		t.Fatalf("runner argv contains an unsafe config or private path: %#v", argv)
	}
	remaining := time.Until(deadline)
	if deadline.Before(started.Add(44*time.Second)) || remaining > FirstControlCheckTimeout {
		t.Fatalf("runner deadline = %s, remaining %s", deadline, remaining)
	}
	want := Result{FirstHopAlias: "control-a", Route: "direct_first_control", Attempts: 1}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestCheckFirstControlBoundsAndDiscardsOutput(t *testing.T) {
	fixture := newFixture(t)
	secret := "runner-secret-must-not-leak"
	runner := &recordingRunner{run: func(_ context.Context, stdout, stderr io.Writer) error {
		stdoutPayload := bytes.Repeat([]byte(secret), int(MaxOutputBytes/int64(len(secret)))+100)
		stderrPayload := bytes.Repeat([]byte(fixture.privatePath), int(MaxOutputBytes/int64(len(fixture.privatePath)))+100)
		if written, err := stdout.Write(stdoutPayload); err != nil || written != len(stdoutPayload) {
			return errors.New("stdout writer rejected bounded discard")
		}
		if written, err := stderr.Write(stderrPayload); err != nil || written != len(stderrPayload) {
			return errors.New("stderr writer rejected bounded discard")
		}
		return nil
	}}
	result, err := New(fixture.builder, runner).CheckFirstControl(context.Background(), fixture.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if result.StdoutBytes != MaxOutputBytes || result.StderrBytes != MaxOutputBytes ||
		!result.StdoutTruncated || !result.StderrTruncated {
		t.Fatalf("bounded result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, fixture.privatePath, "stdout", "stderr"} {
		if forbidden == "stdout" || forbidden == "stderr" {
			continue // field names are metadata; only raw contents are forbidden.
		}
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("result JSON leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestCheckFirstControlMasksRunnerAndBuilderErrors(t *testing.T) {
	fixture := newFixture(t)
	secret := "runner-secret " + fixture.privatePath
	runner := &recordingRunner{run: func(context.Context, io.Writer, io.Writer) error {
		return errors.New(secret)
	}}
	result, err := New(fixture.builder, runner).CheckFirstControl(context.Background(), fixture.endpoint)
	if !errors.Is(err, ErrFirstControlCheck) || err.Error() != ErrFirstControlCheck.Error() {
		t.Fatalf("runner error = %q", err)
	}
	if strings.Contains(err.Error(), secret) || result.Attempts != 1 {
		t.Fatalf("runner details leaked: result=%+v error=%q", result, err)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}

	if err := os.Remove(fixture.privatePath); err != nil {
		t.Fatal(err)
	}
	result, err = New(fixture.builder, runner).CheckFirstControl(context.Background(), fixture.endpoint)
	if !errors.Is(err, ErrFirstControlCheck) || err.Error() != ErrFirstControlCheck.Error() || result.Attempts != 0 {
		t.Fatalf("builder failure result=%+v error=%q", result, err)
	}
	if strings.Contains(err.Error(), fixture.privatePath) {
		t.Fatalf("builder error leaked private path: %q", err)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("runner was called after builder failure: %d", calls)
	}
}

func TestCheckFirstControlPropagatesCallerCancellationSafely(t *testing.T) {
	fixture := newFixture(t)
	started := make(chan struct{})
	runner := &recordingRunner{run: func(ctx context.Context, _, _ io.Writer) error {
		close(started)
		<-ctx.Done()
		return errors.New("unsafe backend cancellation: " + fixture.privatePath)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan Result, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, err := New(fixture.builder, runner).CheckFirstControl(ctx, fixture.endpoint)
		resultChannel <- result
		errorChannel <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not start")
	}
	cancel()
	result := <-resultChannel
	err := <-errorChannel
	if !errors.Is(err, ErrFirstControlCheck) || !errors.Is(err, context.Canceled) ||
		err.Error() != ErrFirstControlCheck.Error() {
		t.Fatalf("cancel error = %q", err)
	}
	if strings.Contains(err.Error(), fixture.privatePath) || result.Attempts != 1 {
		t.Fatalf("cancel details leaked: result=%+v error=%q", result, err)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
}

func TestCheckFirstControlRejectsUnavailableTransportWithoutRunner(t *testing.T) {
	runner := &recordingRunner{}
	secret := "secret-alias"
	result, err := New(nil, runner).CheckFirstControl(context.Background(), sshtransport.Endpoint{Alias: secret})
	if !errors.Is(err, ErrFirstControlCheck) || err.Error() != ErrFirstControlCheck.Error() || result.Attempts != 0 {
		t.Fatalf("nil builder result=%+v error=%q", result, err)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatalf("unvalidated endpoint alias leaked into result JSON: %s", encoded)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("runner calls = %d, want 0", calls)
	}
}

type fixture struct {
	builder     *sshtransport.Builder
	endpoint    sshtransport.Endpoint
	privatePath string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	store, err := localstate.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "private-secret-do-not-leak")
	if err := os.WriteFile(privatePath, []byte("opaque-test-private-key\n"), localstate.FileMode); err != nil {
		t.Fatal(err)
	}
	identity, err := sshtransport.NewPrivateIdentity(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	key, hostFingerprint := hostKey(42)
	return fixture{
		builder: sshtransport.NewBuilder(store),
		endpoint: sshtransport.Endpoint{
			Alias: "control-a", Role: sshtransport.RoleControl,
			Host: "203.0.113.40", Port: 22, User: "flow-jump",
			Identity: identity, IdentityFingerprint: fingerprint(41),
			HostKey: key, HostKeyFingerprint: hostFingerprint,
		},
		privatePath: privatePath,
	}
}

func hostKey(seed byte) (string, string) {
	algorithm := []byte("ssh-ed25519")
	key := bytes.Repeat([]byte{seed}, 32)
	blob := appendSSHString(nil, algorithm)
	blob = appendSSHString(blob, key)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	digest := sha256.Sum256(blob)
	return line, "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func appendSSHString(destination, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination = append(destination, size[:]...)
	return append(destination, value...)
}

func fingerprint(seed byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}
