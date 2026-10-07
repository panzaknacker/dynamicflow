package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/signing"
)

const controlRuntimeHelpText = `Dynamicflow Control runtime (internal Linux root entry point)

Usage:
  flow control-runtime install --expected-system SYSTEM_ID \
    --expected-control CONTROL_NAME --minimum-generation GENERATION
  flow control-runtime session --state-root /var/lib/dynamicflow/control

The canonical, signed Control installation envelope is read exclusively from
stdin. This command accepts no paths, credentials, private keys, environment
configuration, positional operands, or arbitrary commands. It is invoked by
the fixed, pinned first-Control bootstrap transport.

Session is the installer-owned sshd ForceCommand. It accepts only the fixed
state root and a bounded attestation request from SSH_ORIGINAL_COMMAND, verifies
the unprivileged management identity and signed active policy, and emits one
canonical public JSON response. It never opens operator state or reads stdin.
`

type controlRuntimeInstaller interface {
	Install(context.Context, io.Reader, controlruntime.InstallRequest) (controlruntime.InstallResult, error)
}

type controlRuntimeDependencies struct {
	newInstaller func() controlRuntimeInstaller
	newSession   func() controlRuntimeSession
}

type controlRuntimeSession interface {
	Execute(context.Context, controlruntime.SessionRequest) ([]byte, error)
}

type controlRuntimeInstallOutput struct {
	Installed      bool   `json:"installed"`
	SystemID       string `json:"system_id"`
	ControlName    string `json:"control_name"`
	Generation     uint64 `json:"generation"`
	EnvelopeDigest string `json:"envelope_digest"`
	RuntimeDigest  string `json:"runtime_digest"`
	Changed        bool   `json:"changed"`
	RolledBack     bool   `json:"rolled_back"`
}

func commandControlRuntimeRaw(arguments []string, stdin io.Reader, stdout, stderr io.Writer, jsonOutput bool) int {
	command := "control-runtime"
	if len(arguments) > 0 && (arguments[0] == "install" || arguments[0] == "session") {
		command += "." + arguments[0]
	}
	out := &emitter{json: jsonOutput, stdout: stdout, stderr: stderr, command: command}
	return runControlRuntime(arguments, stdin, out, defaultControlRuntimeDependencies())
}

func defaultControlRuntimeDependencies() controlRuntimeDependencies {
	return controlRuntimeDependencies{
		newInstaller: func() controlRuntimeInstaller {
			return controlruntime.NewInstaller()
		},
		newSession: func() controlRuntimeSession {
			return controlruntime.NewSession()
		},
	}
}

func runControlRuntime(arguments []string, stdin io.Reader, out *emitter, dependencies controlRuntimeDependencies) int {
	if out == nil {
		return exitFailure
	}
	if len(arguments) == 0 {
		return out.fail("usage", "control-runtime requires a fixed install or session operation", "Run flow control-runtime --help.", exitUsage)
	}
	if isRuntimeHelp(arguments[0]) {
		if out.json {
			return out.success("help", map[string]any{"topic": "control-runtime", "text": controlRuntimeHelpText}, "")
		}
		fmt.Fprint(out.stdout, controlRuntimeHelpText)
		return exitOK
	}
	if arguments[0] == "session" {
		return runControlRuntimeSession(arguments[1:], out, dependencies)
	}
	if arguments[0] != "install" {
		return out.fail("usage", "unknown control-runtime operation", "Run flow control-runtime --help.", exitUsage)
	}
	request, err := parseControlRuntimeInstallArguments(arguments[1:])
	if err != nil {
		return out.fail(
			"usage",
			"invalid fixed Control runtime installation binding",
			"Use flow control-runtime install --expected-system SYSTEM_ID --expected-control CONTROL_NAME --minimum-generation GENERATION; provide the signed envelope only on stdin.",
			exitUsage,
		)
	}
	if stdin == nil || dependencies.newInstaller == nil {
		return out.fail(
			"control_runtime_unavailable",
			"Control runtime installation is unavailable",
			"Repair the installed flow binary and retry the fixed pinned bootstrap operation.",
			exitConfig,
		)
	}
	installer := dependencies.newInstaller()
	if installer == nil {
		return out.fail(
			"control_runtime_unavailable",
			"Control runtime installation is unavailable",
			"Repair the installed flow binary and retry the fixed pinned bootstrap operation.",
			exitConfig,
		)
	}
	operation, stop := commandOperationContext()
	defer stop()
	result, err := installer.Install(operation, stdin, request)
	if err != nil {
		return failControlRuntimeInstall(out, err)
	}
	if !validControlRuntimeInstallResult(result, request) {
		return out.fail(
			"control_runtime_result",
			"Control runtime installation returned an invalid public receipt",
			"Treat Control as not ready and recover through the provider console.",
			exitVerify,
		)
	}
	output := controlRuntimeInstallOutput{
		Installed: true, SystemID: result.SystemID, ControlName: result.ControlName,
		Generation: result.Generation, EnvelopeDigest: result.EnvelopeDigest,
		RuntimeDigest: result.RuntimeDigest, Changed: result.Changed, RolledBack: false,
	}
	human := fmt.Sprintf(
		"Control runtime installation verified for %s in %s (generation %d; changed: %t).",
		output.ControlName, output.SystemID, output.Generation, output.Changed,
	)
	return out.success("control-runtime.install", output, human)
}

func runControlRuntimeSession(arguments []string, out *emitter, dependencies controlRuntimeDependencies) int {
	// Deliberately do not use flag parsing: alternate spellings, extra values
	// and global JSON envelopes are not part of the forced-command protocol.
	if out.json || len(arguments) != 2 || arguments[0] != "--state-root" || arguments[1] != controlruntime.DefaultStateRoot {
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionDenied)
		return exitUsage
	}
	if dependencies.newSession == nil {
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionUnavailable)
		return exitConfig
	}
	session := dependencies.newSession()
	if session == nil {
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionUnavailable)
		return exitConfig
	}
	operation, stop := commandOperationContext()
	defer stop()
	response, err := session.Execute(operation, controlruntime.SessionRequest{StateRoot: arguments[1]})
	if err != nil {
		if errors.Is(err, controlruntime.ErrSessionDenied) {
			fmt.Fprintln(out.stderr, controlruntime.ErrSessionDenied)
			return exitAuth
		}
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionUnavailable)
		return exitFailure
	}
	if len(response) == 0 || len(response) > controlruntime.MaxSessionResponseBytes {
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionUnavailable)
		return exitFailure
	}
	if count, err := out.stdout.Write(response); err != nil || count != len(response) {
		fmt.Fprintln(out.stderr, controlruntime.ErrSessionUnavailable)
		return exitFailure
	}
	return exitOK
}

func parseControlRuntimeInstallArguments(arguments []string) (controlruntime.InstallRequest, error) {
	var request controlruntime.InstallRequest
	if len(arguments) != 6 {
		return request, errors.New("invalid argument count")
	}
	seen := make(map[string]struct{}, 3)
	for index := 0; index < len(arguments); index += 2 {
		name, value := arguments[index], arguments[index+1]
		if value == "" || strings.HasPrefix(value, "-") {
			return controlruntime.InstallRequest{}, errors.New("missing public binding value")
		}
		if _, duplicate := seen[name]; duplicate {
			return controlruntime.InstallRequest{}, errors.New("duplicate public binding")
		}
		seen[name] = struct{}{}
		switch name {
		case "--expected-system":
			if !validControlRuntimeSystemID(value) {
				return controlruntime.InstallRequest{}, errors.New("invalid system identifier")
			}
			request.ExpectedSystemID = value
		case "--expected-control":
			if !validControlRuntimeName(value) {
				return controlruntime.InstallRequest{}, errors.New("invalid Control name")
			}
			request.ExpectedControlName = value
		case "--minimum-generation":
			generation, err := strconv.ParseUint(value, 10, 64)
			if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != value {
				return controlruntime.InstallRequest{}, errors.New("invalid minimum generation")
			}
			request.MinimumGeneration = generation
		default:
			return controlruntime.InstallRequest{}, errors.New("unknown public binding")
		}
	}
	if len(seen) != 3 || request.ExpectedSystemID == "" || request.ExpectedControlName == "" || request.MinimumGeneration == 0 {
		return controlruntime.InstallRequest{}, errors.New("incomplete public binding")
	}
	return request, nil
}

func validControlRuntimeSystemID(value string) bool {
	if len(value) != len("sys-")+32 || !strings.HasPrefix(value, "sys-") {
		return false
	}
	for _, character := range value[len("sys-"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validControlRuntimeName(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validControlRuntimeInstallResult(result controlruntime.InstallResult, request controlruntime.InstallRequest) bool {
	return result.SystemID == request.ExpectedSystemID &&
		result.ControlName == request.ExpectedControlName &&
		result.Generation >= request.MinimumGeneration &&
		validControlRuntimeDigest(result.EnvelopeDigest) &&
		validControlRuntimeDigest(result.RuntimeDigest) &&
		!result.RolledBack
}

func validControlRuntimeDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func failControlRuntimeInstall(out *emitter, err error) int {
	switch {
	case errors.Is(err, controlruntime.ErrInstallRollback):
		return out.fail(
			"control_recovery_required",
			"Control runtime rollback could not be proven",
			"Do not retry over SSH; recover and verify the host through the provider console.",
			exitPartial,
		)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return out.fail(
			"control_install_interrupted",
			"Control runtime installation was interrupted",
			"Treat Control as inactive, inspect the host through the provider console if needed, then retry the same fixed operation.",
			exitPartial,
		)
	case errors.Is(err, controlruntime.ErrRootRequired):
		return out.fail(
			"privilege",
			"Control runtime installation requires root",
			"Retry only through the fixed pinned bootstrap operation, which invokes this entry point through non-interactive sudo.",
			exitAuth,
		)
	case errors.Is(err, controlruntime.ErrInvalidEnvelope),
		errors.Is(err, controlruntime.ErrEnvelopeBinding),
		errors.Is(err, controlpolicy.ErrInvalidPolicy),
		errors.Is(err, controlpolicy.ErrPolicyExpired),
		errors.Is(err, controlpolicy.ErrPolicyBinding),
		errors.Is(err, controlpolicy.ErrGeneration),
		errors.Is(err, controlpolicy.ErrNonCanonical),
		errors.Is(err, signing.ErrInvalidKey),
		errors.Is(err, signing.ErrInvalidSignature):
		return out.fail(
			"control_envelope_verify",
			"Control installation envelope verification failed",
			"Generate a fresh canonical signed envelope for this exact system, Control name and generation; do not activate Control.",
			exitVerify,
		)
	case errors.Is(err, controlruntime.ErrGenerationConflict):
		return out.fail(
			"control_generation_conflict",
			"Control runtime policy generation conflicts with installed state",
			"Inspect the installed public generation through provider-console recovery and issue a strictly newer signed policy.",
			exitConflict,
		)
	case errors.Is(err, controlruntime.ErrInstallBusy):
		return out.fail(
			"control_install_busy",
			"Another Control runtime installation is active",
			"Wait for the active transaction to finish, then retry the same fixed operation.",
			exitConflict,
		)
	case errors.Is(err, controlruntime.ErrUnsafeHost):
		return out.fail(
			"control_host_unsafe",
			"Control host state failed safe ownership or path verification",
			"Keep Control inactive and inspect the root-owned runtime state through the provider console.",
			exitVerify,
		)
	case errors.Is(err, controlruntime.ErrSSHDValidation):
		return out.fail(
			"control_sshd_validation",
			"Control SSH policy validation failed",
			"Keep the bootstrap path active, inspect sanitized sshd diagnostics through the provider console, and retry after repair.",
			exitVerify,
		)
	case errors.Is(err, controlruntime.ErrSSHDReload):
		return out.fail(
			"control_sshd_reload",
			"Control SSH policy reload failed and the previous state was restored",
			"Keep Control inactive, inspect the sanitized system journal through the provider console, and retry after repair.",
			exitFailure,
		)
	default:
		return out.fail(
			"control_install",
			"Control runtime installation failed safely",
			"Keep Control inactive, inspect sanitized host logs through the provider console, and retry only after the cause is repaired.",
			exitFailure,
		)
	}
}
