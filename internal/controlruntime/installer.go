package controlruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const (
	DefaultSSHDConfigPath = "/etc/ssh/sshd_config"
	DefaultSSHDDropInPath = "/etc/ssh/sshd_config.d/60-dynamicflow-control.conf"
	rollbackTimeout       = time.Minute
)

var (
	ErrRootRequired       = errors.New("Control runtime installation requires root")
	ErrUnsafeHost         = errors.New("Control runtime host state is unsafe")
	ErrInstallBusy        = errors.New("another Control runtime installation is active")
	ErrInstallFailed      = errors.New("Control runtime installation failed")
	ErrSSHDValidation     = errors.New("Control SSH policy validation failed")
	ErrSSHDReload         = errors.New("Control SSH policy reload failed")
	ErrInstallRollback    = errors.New("Control runtime rollback failed; provider-console recovery is required")
	ErrGenerationConflict = errors.New("Control runtime policy generation conflicts with installed state")
)

// InstallRequest supplies the independently authenticated binding expected by
// the bootstrap transport. System and Control identifiers are never inferred
// from the untrusted envelope itself.
type InstallRequest struct {
	ExpectedSystemID    string `json:"expected_system_id"`
	ExpectedControlName string `json:"expected_control_name"`
	MinimumGeneration   uint64 `json:"minimum_generation"`
}

// PlanPhase is intentionally free of key material, command output and remote
// addresses. It is safe for normal CLI/TUI and JSON output.
type PlanPhase struct {
	Name       string `json:"name"`
	WillChange bool   `json:"will_change"`
	Detail     string `json:"detail"`
}

// InstallPlan describes the verified, fixed-scope mutation without exposing
// the envelope contents or a private local path.
type InstallPlan struct {
	Operation      string      `json:"operation"`
	SystemID       string      `json:"system_id"`
	ControlName    string      `json:"control_name"`
	Generation     uint64      `json:"generation"`
	EnvelopeDigest string      `json:"envelope_digest"`
	RuntimeDigest  string      `json:"runtime_digest"`
	StateRoot      string      `json:"state_root"`
	SSHDConfig     string      `json:"sshd_config"`
	Changed        bool        `json:"changed"`
	Phases         []PlanPhase `json:"phases"`
}

// InstallResult reports only authenticated public metadata and whether a
// failed activation was restored. Raw stderr/stdout never crosses this API.
type InstallResult struct {
	SystemID       string `json:"system_id"`
	ControlName    string `json:"control_name"`
	Generation     uint64 `json:"generation"`
	EnvelopeDigest string `json:"envelope_digest"`
	RuntimeDigest  string `json:"runtime_digest"`
	Changed        bool   `json:"changed"`
	RolledBack     bool   `json:"rolled_back"`
}

type preparedInstall struct {
	envelope InstallEnvelope
	files    RenderedFiles
	digest   string
}

type hostPreflight struct {
	CreateAccount     bool
	LockAccount       bool
	InstallExecutable bool
	ActivateBundle    bool
	InstallDropIn     bool
	CleanupStale      bool
	runtime           executableSnapshot
}

func (state hostPreflight) changed() bool {
	return state.CreateAccount || state.LockAccount || state.InstallExecutable || state.ActivateBundle || state.InstallDropIn || state.CleanupStale
}

type installLock interface {
	Release() error
}

type stagedMutation interface {
	ValidateSSHD(context.Context) error
	Activate() error
	Activated() bool
	Rollback() error
	Commit() error
	Abort() error
}

type installPlatform interface {
	StateRoot() string
	SSHDConfigPath() string
	EffectiveUID() int
	AcquireLock() (installLock, error)
	Preflight(context.Context, preparedInstall, InstallRequest) (hostPreflight, error)
	EnsureManagementAccount(context.Context, hostPreflight) error
	Stage(context.Context, preparedInstall, hostPreflight) (stagedMutation, error)
	ValidateActiveSSHD(context.Context) error
	ReloadSSHD(context.Context) error
	CleanupStaging() error
}

// Installer reconciles the fixed Linux Control runtime. NewInstaller is the
// production constructor; tests use the same orchestration through an injected
// platform so no unit test writes /etc or creates an account.
type Installer struct {
	platform installPlatform
	now      func() time.Time
}

// NewInstaller constructs the production Linux installer using the exact
// running /proc/self/exe as the runtime source.
func NewInstaller() *Installer {
	return NewInstallerWithDependencies(nil, ProcessExecutableSource{})
}

// NewInstallerWithDependencies keeps the command and executable-source
// boundaries injectable without allowing callers to choose destination paths.
// The runner only receives fixed executable paths and argv arrays selected
// inside this package; no shell command strings are built.
func NewInstallerWithDependencies(runner CommandRunner, source ExecutableSource) *Installer {
	return &Installer{platform: newLinuxPlatform(productionLinuxConfig(), runner, source), now: time.Now}
}

// Plan authenticates a bounded canonical envelope and inspects the host. It is
// read-only: it does not create a lock, directory, user or temporary file.
func (installer *Installer) Plan(ctx context.Context, reader io.Reader, request InstallRequest) (InstallPlan, error) {
	prepared, err := installer.prepare(ctx, reader, request)
	if err != nil {
		return InstallPlan{}, err
	}
	state, err := installer.platform.Preflight(ctx, prepared, request)
	if err != nil {
		return InstallPlan{}, safeInstallError(ErrUnsafeHost, err)
	}
	return buildInstallPlan(installer.platform, prepared, state), nil
}

// Install verifies before the first mutation, serializes concurrent attempts,
// repeats preflight under the lock, then activates and reloads transactionally.
// A reload failure restores the previous bundle/drop-in and reloads that old
// configuration. Failure to prove the restoration is surfaced as a mandatory
// provider-console recovery condition.
func (installer *Installer) Install(ctx context.Context, reader io.Reader, request InstallRequest) (InstallResult, error) {
	if installer == nil || installer.platform == nil || installer.now == nil || ctx == nil || reader == nil {
		return InstallResult{}, ErrInstallFailed
	}
	if installer.platform.EffectiveUID() != 0 {
		return InstallResult{}, ErrRootRequired
	}
	prepared, err := installer.prepare(ctx, reader, request)
	if err != nil {
		return InstallResult{}, err
	}
	result := resultFor(prepared)

	lock, err := installer.platform.AcquireLock()
	if err != nil {
		if errors.Is(err, ErrUnsafeHost) {
			return result, safeInstallError(ErrUnsafeHost, err)
		}
		return result, safeInstallError(ErrInstallBusy, err)
	}
	defer lock.Release()

	state, err := installer.platform.Preflight(ctx, prepared, request)
	if err != nil {
		return result, safeInstallError(ErrUnsafeHost, err)
	}
	result.Changed = state.changed()
	result.RuntimeDigest = state.runtime.digest
	if err := installer.platform.EnsureManagementAccount(ctx, state); err != nil {
		return result, safeInstallError(ErrInstallFailed, err)
	}
	if !state.InstallExecutable && !state.ActivateBundle && !state.InstallDropIn {
		// A previous process may have crashed after its final rename but before
		// reloading sshd. Revalidating and reloading an exact configuration is
		// idempotent and closes that otherwise invisible resume gap.
		if err := installer.platform.ValidateActiveSSHD(ctx); err != nil {
			return result, safeInstallError(ErrSSHDValidation, err)
		}
		if err := installer.platform.ReloadSSHD(ctx); err != nil {
			return result, safeInstallError(ErrSSHDReload, err)
		}
		if err := installer.platform.CleanupStaging(); err != nil {
			return result, safeInstallError(ErrInstallFailed, err)
		}
		return result, nil
	}

	transaction, err := installer.platform.Stage(ctx, prepared, state)
	if err != nil {
		return result, safeInstallError(ErrInstallFailed, err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = transaction.Abort()
		}
	}()
	if err := transaction.ValidateSSHD(ctx); err != nil {
		_ = transaction.Abort()
		finished = true
		return result, safeInstallError(ErrSSHDValidation, err)
	}
	if err := transaction.Activate(); err != nil {
		if transaction.Activated() {
			if rollbackErr := installer.restore(ctx, transaction); rollbackErr != nil {
				finished = true
				return result, safeInstallError(ErrInstallRollback, rollbackErr)
			}
			result.RolledBack = true
		} else {
			_ = transaction.Abort()
		}
		finished = true
		return result, safeInstallError(ErrInstallFailed, err)
	}
	if state.ActivateBundle || state.InstallDropIn {
		if activeErr := installer.platform.ValidateActiveSSHD(ctx); activeErr != nil {
			if rollbackErr := installer.restore(ctx, transaction); rollbackErr != nil {
				finished = true
				return result, safeInstallError(ErrInstallRollback, rollbackErr)
			}
			result.RolledBack = true
			finished = true
			return result, safeInstallError(ErrSSHDValidation, activeErr)
		}
		if reloadErr := installer.platform.ReloadSSHD(ctx); reloadErr != nil {
			if rollbackErr := installer.restore(ctx, transaction); rollbackErr != nil {
				finished = true
				return result, safeInstallError(ErrInstallRollback, rollbackErr)
			}
			result.RolledBack = true
			finished = true
			return result, safeInstallError(ErrSSHDReload, reloadErr)
		}
	}
	if err := transaction.Commit(); err != nil {
		// Activation and reload already succeeded. Do not roll a valid policy
		// back solely because removal of a root-owned recovery copy failed.
		finished = true
		return result, safeInstallError(ErrInstallFailed, err)
	}
	if err := installer.platform.CleanupStaging(); err != nil {
		finished = true
		return result, safeInstallError(ErrInstallFailed, err)
	}
	finished = true
	return result, nil
}

func (installer *Installer) restore(ctx context.Context, transaction stagedMutation) error {
	// Once activation changed the host, cancellation must not leave sshd using
	// a different policy from the restored files. Keep recovery independent of
	// the caller's cancellation while bounding its validation and reload work.
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(); err != nil {
		return err
	}
	if err := installer.platform.ValidateActiveSSHD(recovery); err != nil {
		return err
	}
	if err := installer.platform.ReloadSSHD(recovery); err != nil {
		return err
	}
	return transaction.Commit()
}

func (installer *Installer) prepare(ctx context.Context, reader io.Reader, request InstallRequest) (preparedInstall, error) {
	if installer == nil || installer.platform == nil || installer.now == nil || ctx == nil || reader == nil ||
		request.ExpectedSystemID == "" || request.ExpectedControlName == "" {
		return preparedInstall{}, ErrInvalidEnvelope
	}
	if err := ctx.Err(); err != nil {
		return preparedInstall{}, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxEnvelopeBytes+1))
	if contextErr := ctx.Err(); contextErr != nil {
		return preparedInstall{}, contextErr
	}
	if err != nil || len(data) == 0 || len(data) > MaxEnvelopeBytes {
		return preparedInstall{}, ErrInvalidEnvelope
	}
	envelope, err := ParseCanonical(data)
	if err != nil {
		return preparedInstall{}, err
	}
	files, err := Render(
		envelope, installer.now().UTC(), request.ExpectedSystemID, request.ExpectedControlName,
		request.MinimumGeneration, installer.platform.StateRoot(),
	)
	if err != nil {
		return preparedInstall{}, err
	}
	if err := files.ValidateNoPrivateMaterial(); err != nil {
		return preparedInstall{}, err
	}
	digest := sha256.Sum256(files.EnvelopeJSON)
	return preparedInstall{
		envelope: envelope,
		files:    files,
		digest:   "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func buildInstallPlan(platform installPlatform, prepared preparedInstall, state hostPreflight) InstallPlan {
	policy := prepared.envelope.Policy.Policy
	return InstallPlan{
		Operation: "control_runtime_install", SystemID: policy.SystemID, ControlName: policy.ControlName,
		Generation: policy.Generation, EnvelopeDigest: prepared.digest,
		RuntimeDigest: state.runtime.digest,
		StateRoot:     platform.StateRoot(), SSHDConfig: platform.SSHDConfigPath(), Changed: state.changed(),
		Phases: []PlanPhase{
			{Name: "verify_envelope", Detail: "verify canonical signature, binding, validity and generation before mutation"},
			{Name: "management_account", WillChange: state.CreateAccount || state.LockAccount, Detail: "ensure the fixed non-root password-disabled Control account remains public-key accessible"},
			{Name: "install_runtime", WillChange: state.InstallExecutable, Detail: "install the descriptor-pinned running flow image atomically as root-owned mode 0755"},
			{Name: "stage_policy", WillChange: state.ActivateBundle || state.InstallDropIn, Detail: "stage root-owned policy files without following links"},
			{Name: "validate_sshd", WillChange: state.InstallDropIn, Detail: "validate the complete SSH daemon configuration before activation"},
			{Name: "activate", WillChange: state.InstallExecutable || state.ActivateBundle || state.InstallDropIn, Detail: "atomically switch the runtime, signed policy bundle and SSH drop-in"},
			{Name: "reload", WillChange: state.ActivateBundle || state.InstallDropIn, Detail: "validate and reload SSH even when files already match, closing interrupted-activation gaps"},
			{Name: "cleanup_staging", WillChange: state.CleanupStale, Detail: "remove only verified inactive staging entries left by an interrupted attempt"},
		},
	}
}

func resultFor(prepared preparedInstall) InstallResult {
	policy := prepared.envelope.Policy.Policy
	return InstallResult{
		SystemID: policy.SystemID, ControlName: policy.ControlName,
		Generation: policy.Generation, EnvelopeDigest: prepared.digest,
	}
}

type classifiedInstallError struct {
	public error
	cause  error
}

func (problem classifiedInstallError) Error() string { return problem.public.Error() }

func (problem classifiedInstallError) Is(target error) bool {
	return target == problem.public || errors.Is(problem.cause, target)
}

func safeInstallError(public, cause error) error {
	if cause == nil {
		return public
	}
	return classifiedInstallError{public: public, cause: cause}
}
