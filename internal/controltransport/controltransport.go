// package controltransport owns the process boundary for the one-time direct
// connectivity check of the first dynamicflow control node.
package controltransport

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"

	"dynamicflow/internal/sshtransport"
)

const (
	// FirstControlCheckTimeout bounds the single SSH process attempt.
	FirstControlCheckTimeout = 45 * time.Second
	// MaxOutputBytes is the maximum amount reported independently for stdout
	// and stderr. output contents are always discarded.
	MaxOutputBytes int64 = 64 << 10
)

var ErrFirstControlCheck = errors.New("first control connectivity check failed")

// Runner is the injectable SSH process boundary. argv excludes the executable
// name. CheckFirstControl always passes nil stdin and bounded discard writers.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error
}

// DefaultRunner starts the locally installed OpenSSH client without a shell.
type DefaultRunner struct{}

func (DefaultRunner) Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, "ssh", argv...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

// Result contains only safe metadata about one direct first-control check. it
// deliberately excludes endpoint addresses, argv, raw output and key paths.
type Result struct {
	FirstHopAlias   string `json:"first_hop_alias"`
	Route           string `json:"route"`
	Attempts        int    `json:"attempts"`
	StdoutBytes     int64  `json:"stdout_bytes"`
	StderrBytes     int64  `json:"stderr_bytes"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// Transport performs only the direct connectivity check for the first
// control. routed targets and arbitrary commands intentionally have no API in
// this package.
type Transport struct {
	builder *sshtransport.Builder
	runner  Runner
}

// New constructs a Transport. a nil runner selects DefaultRunner.
func New(builder *sshtransport.Builder, runner Runner) *Transport {
	if runner == nil {
		runner = DefaultRunner{}
	}
	return &Transport{builder: builder, runner: runner}
}

// CheckFirstControl makes exactly one bounded SSH attempt using the sole
// direct capability and the fixed remote command /bin/true. it performs no
// retry or fallback. errors never expose builder, runner or remote details.
func (transport *Transport) CheckFirstControl(ctx context.Context, control sshtransport.Endpoint) (Result, error) {
	result := Result{
		Route:    "direct_first_control",
		Attempts: 0,
	}
	if transport == nil || transport.builder == nil || transport.runner == nil || ctx == nil {
		return result, ErrFirstControlCheck
	}

	invocation, err := transport.builder.BuildDirectFirstControl(
		sshtransport.CapabilityFirstControlBootstrap,
		control,
	)
	if err != nil {
		return result, ErrFirstControlCheck
	}
	// the builder has now validated the endpoint's strict public alias grammar.
	result.FirstHopAlias = control.Alias
	argv := append(invocation.Arguments(), "/bin/true")
	stdout := boundedOutput{limit: MaxOutputBytes}
	stderr := boundedOutput{limit: MaxOutputBytes}

	operation, cancel := context.WithTimeout(ctx, FirstControlCheckTimeout)
	defer cancel()
	result.Attempts = 1
	err = transport.runner.Run(operation, argv, nil, &stdout, &stderr)
	result.StdoutBytes, result.StderrBytes = stdout.kept, stderr.kept
	result.StdoutTruncated, result.StderrTruncated = stdout.truncated, stderr.truncated
	if err != nil {
		return result, safeCheckError(operation.Err(), err)
	}
	return result, nil
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
	written := int64(len(data))
	if written > remaining {
		output.kept = output.limit
		output.truncated = true
	} else {
		output.kept += written
	}
	return len(data), nil
}

type classifiedCheckError struct {
	cause error
}

func (classifiedCheckError) Error() string { return ErrFirstControlCheck.Error() }

func (check classifiedCheckError) Is(target error) bool {
	return target == ErrFirstControlCheck || target == check.cause
}

func safeCheckError(contextErr, runnerErr error) error {
	switch {
	case errors.Is(contextErr, context.Canceled), errors.Is(runnerErr, context.Canceled):
		return classifiedCheckError{cause: context.Canceled}
	case errors.Is(contextErr, context.DeadlineExceeded), errors.Is(runnerErr, context.DeadlineExceeded):
		return classifiedCheckError{cause: context.DeadlineExceeded}
	default:
		return ErrFirstControlCheck
	}
}
