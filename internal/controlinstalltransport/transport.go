// Package controlinstalltransport owns the single-session process boundary
// that installs the first Control runtime through its independently pinned
// bootstrap SSH path. It has no routed-target or arbitrary-command API.
package controlinstalltransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/sshtransport"
)

const (
	InstallTimeout     = 3 * time.Minute
	MaxExecutableBytes = 128 << 20
	MaxOutputBytes     = 64 << 10
)

var (
	ErrInvalidInstall   = errors.New("invalid first-Control installation request")
	ErrUnsafeExecutable = errors.New("unsafe local flow executable")
	ErrControlInstall   = errors.New("first-Control runtime installation failed")
	ErrPrivatePathJSON  = errors.New("local executable paths cannot be serialized as JSON")
	ErrPayloadChanged   = errors.New("local flow executable changed after preparation")
)

// Runner is the injectable SSH process boundary. argv excludes the executable
// name. Install always supplies one bounded payload reader and discard writers.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error
}

type defaultRunner struct{}

func (defaultRunner) Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runSSH(ctx, argv, stdin, stdout, stderr)
}

// Executable is a descriptor-derived binding to the local flow binary. Its
// path is deliberately opaque and cannot be JSON-encoded.
type Executable struct {
	path   string
	device uint64
	inode  uint64
	size   int64
	digest string
}

func (Executable) MarshalJSON() ([]byte, error) { return nil, ErrPrivatePathJSON }

// Size and Digest expose only bounded public integrity metadata. The local
// path remains opaque and is revalidated when the payload is streamed.
func (executable Executable) Size() int64    { return executable.size }
func (executable Executable) Digest() string { return executable.digest }

// NewExecutable validates and hashes a non-writable, owner-local, single-link
// regular file. Install reopens and revalidates the exact inode and digest.
func NewExecutable(path string) (Executable, error) {
	file, metadata, err := openExecutable(path)
	if err != nil {
		return Executable{}, err
	}
	defer file.Close()
	digest, err := digestReader(file, metadata.size)
	if err != nil {
		return Executable{}, ErrUnsafeExecutable
	}
	metadata.digest = digest
	return metadata, nil
}

type Request struct {
	Control             sshtransport.Endpoint
	Executable          Executable
	Envelope            []byte
	ExpectedSystemID    string
	ExpectedControlName string
	MinimumGeneration   uint64
}

// Result exposes only bounded integrity and attempt metadata. Remote output,
// the local executable path and SSH argv are never returned.
type Result struct {
	Route            string `json:"route"`
	FirstHopAlias    string `json:"first_hop_alias"`
	Attempts         int    `json:"attempts"`
	ExecutableBytes  int64  `json:"executable_bytes"`
	ExecutableDigest string `json:"executable_digest"`
	EnvelopeBytes    int    `json:"envelope_bytes"`
	EnvelopeDigest   string `json:"envelope_digest"`
	PolicyGeneration uint64 `json:"policy_generation"`
	StdoutBytes      int64  `json:"stdout_bytes"`
	StderrBytes      int64  `json:"stderr_bytes"`
	StdoutTruncated  bool   `json:"stdout_truncated"`
	StderrTruncated  bool   `json:"stderr_truncated"`
}

type Transport struct {
	builder *sshtransport.Builder
	runner  Runner
	now     func() time.Time
}

type Option func(*Transport)

func WithClock(clock func() time.Time) Option {
	return func(transport *Transport) {
		if clock != nil {
			transport.now = clock
		}
	}
}

func New(builder *sshtransport.Builder, runner Runner, options ...Option) *Transport {
	if runner == nil {
		runner = defaultRunner{}
	}
	transport := &Transport{builder: builder, runner: runner, now: time.Now}
	for _, option := range options {
		if option != nil {
			option(transport)
		}
	}
	return transport
}

// InstallFirstControl performs exactly one pinned SSH process attempt and no
// retry or fallback. The remote command is renderer-owned and contains only
// validated public IDs, decimal lengths and SHA-256 digests. Binary and signed
// envelope bytes are concatenated on stdin, never placed in argv.
func (transport *Transport) InstallFirstControl(ctx context.Context, request Request) (Result, error) {
	result := Result{Route: "direct_first_control"}
	if transport == nil || transport.builder == nil || transport.runner == nil || transport.now == nil || ctx == nil ||
		request.MinimumGeneration == 0 || len(request.Envelope) == 0 || len(request.Envelope) > controlruntime.MaxEnvelopeBytes {
		return result, ErrInvalidInstall
	}
	if err := ctx.Err(); err != nil {
		return result, safeInstallError(err, nil)
	}
	envelope, err := controlruntime.ParseCanonical(request.Envelope)
	if err != nil {
		return result, ErrInvalidInstall
	}
	if err := controlruntime.VerifyEnvelope(
		envelope, transport.now().UTC(), request.ExpectedSystemID, request.ExpectedControlName, request.MinimumGeneration,
	); err != nil {
		return result, ErrInvalidInstall
	}
	if envelope.Policy.Policy.Generation != request.MinimumGeneration {
		return result, ErrInvalidInstall
	}

	executable, metadata, err := reopenExactExecutable(request.Executable)
	if err != nil {
		return result, err
	}
	defer executable.Close()
	envelopeDigest := sha256.Sum256(request.Envelope)
	result.ExecutableBytes = metadata.size
	result.ExecutableDigest = metadata.digest
	result.EnvelopeBytes = len(request.Envelope)
	result.EnvelopeDigest = "sha256:" + hex.EncodeToString(envelopeDigest[:])
	result.PolicyGeneration = envelope.Policy.Policy.Generation

	invocation, err := transport.builder.BuildDirectFirstControl(
		sshtransport.CapabilityFirstControlBootstrap, request.Control,
	)
	if err != nil {
		return result, ErrInvalidInstall
	}
	result.FirstHopAlias = request.Control.Alias
	remoteCommand, err := renderRemoteCommand(request, result)
	if err != nil {
		return result, ErrInvalidInstall
	}
	argv := append(invocation.Arguments(), remoteCommand)
	stdin := io.MultiReader(executable, bytes.NewReader(request.Envelope))
	stdout := boundedOutput{limit: MaxOutputBytes}
	stderr := boundedOutput{limit: MaxOutputBytes}
	operation, cancel := context.WithTimeout(ctx, InstallTimeout)
	defer cancel()
	if err := operation.Err(); err != nil {
		return result, safeInstallError(err, nil)
	}
	result.Attempts = 1
	err = transport.runner.Run(operation, argv, stdin, &stdout, &stderr)
	result.StdoutBytes, result.StderrBytes = stdout.kept, stderr.kept
	result.StdoutTruncated, result.StderrTruncated = stdout.truncated, stderr.truncated
	if err != nil || operation.Err() != nil {
		return result, safeInstallError(operation.Err(), err)
	}
	return result, nil
}

func renderRemoteCommand(request Request, result Result) (string, error) {
	executableHash := strings.TrimPrefix(result.ExecutableDigest, "sha256:")
	envelopeHash := strings.TrimPrefix(result.EnvelopeDigest, "sha256:")
	if len(executableHash) != 64 || len(envelopeHash) != 64 || request.ExpectedSystemID != request.envelopeSystemID() ||
		request.ExpectedControlName != request.envelopeControlName() {
		return "", ErrInvalidInstall
	}
	// The root-owned temporary directory is claimed before stdin is written, so
	// another process using the bootstrap account cannot replace the verified
	// binary between hashing and sudo execution. Every interpolated value has
	// already passed the signed policy's strict identifier grammar.
	return "set -eu\n" +
		"umask 077\n" +
		"export LC_ALL=C\n" +
		"tmp=$(/usr/bin/sudo -n -- /usr/bin/mktemp -d /var/lib/.dynamicflow-bootstrap.XXXXXXXXXXXX)\n" +
		"cleanup() { /usr/bin/sudo -n -- /usr/bin/rm -rf -- \"$tmp\"; }\n" +
		"trap cleanup EXIT HUP INT TERM\n" +
		"/usr/bin/sudo -n -- /usr/bin/dd iflag=fullblock bs=" + strconv.FormatInt(result.ExecutableBytes, 10) + " count=1 of=\"$tmp/flow\" status=none\n" +
		"/usr/bin/sudo -n -- /usr/bin/dd iflag=fullblock bs=" + strconv.Itoa(result.EnvelopeBytes) + " count=1 of=\"$tmp/envelope.json\" status=none\n" +
		"/usr/bin/printf '%s  %s\\n%s  %s\\n' " + executableHash + " \"$tmp/flow\" " + envelopeHash + " \"$tmp/envelope.json\" | /usr/bin/sudo -n -- /usr/bin/sha256sum -c - >/dev/null\n" +
		"/usr/bin/sudo -n -- /usr/bin/chmod 0500 \"$tmp/flow\"\n" +
		"/usr/bin/sudo -n -- /usr/bin/dd if=\"$tmp/envelope.json\" status=none | /usr/bin/sudo -n -- \"$tmp/flow\" control-runtime install --expected-system " + request.ExpectedSystemID + " --expected-control " + request.ExpectedControlName + " --minimum-generation " + strconv.FormatUint(request.MinimumGeneration, 10) + "\n", nil
}

// These accessors intentionally parse the already authenticated envelope and
// are used only to keep renderer interpolation tied to those signed values.
func (request Request) envelopeSystemID() string {
	envelope, err := controlruntime.ParseCanonical(request.Envelope)
	if err != nil {
		return ""
	}
	return envelope.SystemID
}

func (request Request) envelopeControlName() string {
	envelope, err := controlruntime.ParseCanonical(request.Envelope)
	if err != nil {
		return ""
	}
	return envelope.ControlName
}

func openExecutable(path string) (*os.File, Executable, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsRune(path, '\x00') || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return nil, Executable{}, ErrUnsafeExecutable
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, Executable{}, ErrUnsafeExecutable
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, Executable{}, ErrUnsafeExecutable
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, Executable{}, ErrUnsafeExecutable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || (int(stat.Uid) != os.Geteuid() && stat.Uid != 0) ||
		info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > MaxExecutableBytes {
		file.Close()
		return nil, Executable{}, ErrUnsafeExecutable
	}
	linked, err := os.Lstat(path)
	if err != nil {
		file.Close()
		return nil, Executable{}, ErrUnsafeExecutable
	}
	linkedStat, linkedOK := linked.Sys().(*syscall.Stat_t)
	if linked.Mode()&os.ModeSymlink != 0 || !linkedOK || linkedStat.Dev != stat.Dev || linkedStat.Ino != stat.Ino {
		file.Close()
		return nil, Executable{}, ErrUnsafeExecutable
	}
	return file, Executable{path: path, device: uint64(stat.Dev), inode: uint64(stat.Ino), size: info.Size()}, nil
}

func reopenExactExecutable(expected Executable) (*os.File, Executable, error) {
	file, actual, err := openExecutable(expected.path)
	if err != nil {
		return nil, Executable{}, err
	}
	if actual.device != expected.device || actual.inode != expected.inode || actual.size != expected.size {
		file.Close()
		return nil, Executable{}, ErrPayloadChanged
	}
	digest, err := digestReader(file, actual.size)
	if err != nil || digest != expected.digest {
		file.Close()
		return nil, Executable{}, ErrPayloadChanged
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, Executable{}, ErrPayloadChanged
	}
	actual.digest = digest
	return file, actual, nil
}

func digestReader(reader io.Reader, size int64) (string, error) {
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(reader, size+1))
	if err != nil || written != size {
		return "", ErrUnsafeExecutable
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

type boundedOutput struct {
	limit     int64
	kept      int64
	truncated bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	remaining := output.limit - output.kept
	if remaining < 0 {
		remaining = 0
	}
	if int64(len(data)) > remaining {
		output.kept = output.limit
		output.truncated = true
	} else {
		output.kept += int64(len(data))
	}
	return len(data), nil
}

type classifiedInstallError struct{ cause error }

func (classifiedInstallError) Error() string { return ErrControlInstall.Error() }
func (problem classifiedInstallError) Is(target error) bool {
	return target == ErrControlInstall || target == problem.cause
}

func safeInstallError(contextErr, runnerErr error) error {
	switch {
	case errors.Is(contextErr, context.Canceled), errors.Is(runnerErr, context.Canceled):
		return classifiedInstallError{cause: context.Canceled}
	case errors.Is(contextErr, context.DeadlineExceeded), errors.Is(runnerErr, context.DeadlineExceeded):
		return classifiedInstallError{cause: context.DeadlineExceeded}
	default:
		return ErrControlInstall
	}
}
