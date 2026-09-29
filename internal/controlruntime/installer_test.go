package controlruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/signing"
)

func TestInstallerPlanIsVerifiedBoundedAndReadOnly(t *testing.T) {
	envelope := installerEnvelope(t, 3)
	platform := &fakeInstallPlatform{
		euid: 1000, state: hostPreflight{CreateAccount: true, LockAccount: true, ActivateBundle: true, InstallDropIn: true},
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	request := installerRequest(3)
	plan, err := installer.Plan(context.Background(), bytes.NewReader(envelope), request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || plan.Generation != 3 || plan.StateRoot != DefaultStateRoot ||
		plan.SSHDConfig != DefaultSSHDDropInPath || !strings.HasPrefix(plan.EnvelopeDigest, "sha256:") {
		t.Fatalf("plan = %+v", plan)
	}
	if got := strings.Join(platform.calls, ","); got != "preflight" {
		t.Fatalf("plan mutated host: %s", got)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ssh-ed25519", "BEGIN", "PRIVATE", "permitopen", "10.40.0.9"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("plan leaked %q: %s", forbidden, encoded)
		}
	}

	platform.calls = nil
	tooLarge := io.MultiReader(bytes.NewReader(envelope), bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxEnvelopeBytes)))
	if _, err := installer.Plan(context.Background(), tooLarge, request); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("oversized error = %v", err)
	}
	if len(platform.calls) != 0 {
		t.Fatalf("oversized input reached host: %v", platform.calls)
	}

	platform.calls = nil
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)/2] ^= 1
	if _, err := installer.Plan(context.Background(), bytes.NewReader(tampered), request); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	if len(platform.calls) != 0 {
		t.Fatalf("tampered input reached host: %v", platform.calls)
	}
}

func TestInstallerSuccessUsesOneSerializedTransaction(t *testing.T) {
	platform := &fakeInstallPlatform{
		euid: 0, state: hostPreflight{CreateAccount: true, LockAccount: true, ActivateBundle: true, InstallDropIn: true},
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	result, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.RolledBack || result.Generation != 3 || !strings.HasPrefix(result.EnvelopeDigest, "sha256:") {
		t.Fatalf("result = %+v", result)
	}
	want := "lock,preflight,account,stage,validate,activate,validate_active,reload,commit,cleanup,release"
	if got := strings.Join(platform.calls, ","); got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

func TestInstallerRequiresRootBeforeInputOrHostAccess(t *testing.T) {
	platform := &fakeInstallPlatform{euid: 1000}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	reader := &countingReader{reader: bytes.NewReader(installerEnvelope(t, 3))}
	if _, err := installer.Install(context.Background(), reader, installerRequest(3)); !errors.Is(err, ErrRootRequired) {
		t.Fatalf("error = %v", err)
	}
	if reader.reads != 0 || len(platform.calls) != 0 {
		t.Fatalf("non-root touched input/host: reads=%d calls=%v", reader.reads, platform.calls)
	}
}

func TestInstallerValidationFailureNeverActivates(t *testing.T) {
	secret := errors.New("attacker-controlled stderr: super-secret-token")
	platform := &fakeInstallPlatform{
		euid: 0, state: hostPreflight{ActivateBundle: true, InstallDropIn: true}, validateErr: secret,
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	_, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrSSHDValidation) || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("unsafe validation error = %v", err)
	}
	if got := strings.Join(platform.calls, ","); got != "lock,preflight,account,stage,validate,abort,release" {
		t.Fatalf("calls = %s", got)
	}
}

func TestInstallerReloadFailureRestoresAndRevalidatesOldState(t *testing.T) {
	secret := errors.New("reload output contains private path /operator/key")
	platform := &fakeInstallPlatform{
		euid: 0, state: hostPreflight{ActivateBundle: true, InstallDropIn: true}, reloadErrors: []error{secret, nil},
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	result, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrSSHDReload) || strings.Contains(err.Error(), "operator") {
		t.Fatalf("unsafe reload error = %v", err)
	}
	if !result.RolledBack {
		t.Fatalf("result = %+v", result)
	}
	want := "lock,preflight,account,stage,validate,activate,validate_active,reload,rollback,validate_active,reload,commit,release"
	if got := strings.Join(platform.calls, ","); got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

func TestInstallerPostActivationValidationFailureRollsBackBeforeReload(t *testing.T) {
	secret := errors.New("active sshd diagnostic with secret")
	platform := &fakeInstallPlatform{
		euid: 0, state: hostPreflight{ActivateBundle: true, InstallDropIn: true},
		validateActiveErrors: []error{secret, nil},
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	result, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrSSHDValidation) || strings.Contains(err.Error(), "secret") || !result.RolledBack {
		t.Fatalf("post-activation validation result=%+v error=%v", result, err)
	}
	want := "lock,preflight,account,stage,validate,activate,validate_active,rollback,validate_active,reload,commit,release"
	if got := strings.Join(platform.calls, ","); got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

func TestInstallerRollbackFailureRequiresConsoleRecovery(t *testing.T) {
	platform := &fakeInstallPlatform{
		euid: 0, state: hostPreflight{ActivateBundle: true},
		reloadErrors: []error{errors.New("reload failed")}, rollbackErr: errors.New("rollback secret"),
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	_, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrInstallRollback) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("rollback error = %v", err)
	}
	if got := strings.Join(platform.calls, ","); got != "lock,preflight,account,stage,validate,activate,validate_active,reload,rollback,release" {
		t.Fatalf("calls = %s", got)
	}
}

func TestInstallerIdempotentAccountOnlyDoesNotStageOrReload(t *testing.T) {
	platform := &fakeInstallPlatform{euid: 0, state: hostPreflight{LockAccount: true}}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	result, err := installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed {
		t.Fatalf("result = %+v", result)
	}
	if got := strings.Join(platform.calls, ","); got != "lock,preflight,account,validate_active,reload,cleanup,release" {
		t.Fatalf("calls = %s", got)
	}
}

type countingReader struct {
	reader io.Reader
	reads  int
}

func (reader *countingReader) Read(data []byte) (int, error) {
	reader.reads++
	return reader.reader.Read(data)
}

type fakeInstallPlatform struct {
	euid                 int
	state                hostPreflight
	calls                []string
	lockErr              error
	preflightErr         error
	accountErr           error
	stageErr             error
	validateErr          error
	activateErr          error
	reloadErrors         []error
	validateOldErr       error
	validateActiveErrors []error
	rollbackErr          error
	commitErr            error
	cleanupErr           error
}

func (platform *fakeInstallPlatform) StateRoot() string      { return DefaultStateRoot }
func (platform *fakeInstallPlatform) SSHDConfigPath() string { return DefaultSSHDDropInPath }
func (platform *fakeInstallPlatform) EffectiveUID() int      { return platform.euid }

func (platform *fakeInstallPlatform) AcquireLock() (installLock, error) {
	platform.calls = append(platform.calls, "lock")
	if platform.lockErr != nil {
		return nil, platform.lockErr
	}
	return &fakeInstallLock{platform: platform}, nil
}

func (platform *fakeInstallPlatform) Preflight(context.Context, preparedInstall, InstallRequest) (hostPreflight, error) {
	platform.calls = append(platform.calls, "preflight")
	return platform.state, platform.preflightErr
}

func (platform *fakeInstallPlatform) EnsureManagementAccount(context.Context, hostPreflight) error {
	platform.calls = append(platform.calls, "account")
	return platform.accountErr
}

func (platform *fakeInstallPlatform) Stage(context.Context, preparedInstall, hostPreflight) (stagedMutation, error) {
	platform.calls = append(platform.calls, "stage")
	if platform.stageErr != nil {
		return nil, platform.stageErr
	}
	return &fakeStagedMutation{platform: platform}, nil
}

func (platform *fakeInstallPlatform) ValidateActiveSSHD(context.Context) error {
	platform.calls = append(platform.calls, "validate_active")
	if len(platform.validateActiveErrors) > 0 {
		err := platform.validateActiveErrors[0]
		platform.validateActiveErrors = platform.validateActiveErrors[1:]
		return err
	}
	return platform.validateOldErr
}

func (platform *fakeInstallPlatform) ReloadSSHD(context.Context) error {
	platform.calls = append(platform.calls, "reload")
	if len(platform.reloadErrors) == 0 {
		return nil
	}
	err := platform.reloadErrors[0]
	platform.reloadErrors = platform.reloadErrors[1:]
	return err
}

func (platform *fakeInstallPlatform) CleanupStaging() error {
	platform.calls = append(platform.calls, "cleanup")
	return platform.cleanupErr
}

type fakeInstallLock struct{ platform *fakeInstallPlatform }

func (lock *fakeInstallLock) Release() error {
	lock.platform.calls = append(lock.platform.calls, "release")
	return nil
}

type fakeStagedMutation struct {
	platform *fakeInstallPlatform
	active   bool
}

func (mutation *fakeStagedMutation) ValidateSSHD(context.Context) error {
	mutation.platform.calls = append(mutation.platform.calls, "validate")
	return mutation.platform.validateErr
}

func (mutation *fakeStagedMutation) Activate() error {
	mutation.platform.calls = append(mutation.platform.calls, "activate")
	mutation.active = true
	return mutation.platform.activateErr
}

func (mutation *fakeStagedMutation) Activated() bool { return mutation.active }

func (mutation *fakeStagedMutation) Rollback() error {
	mutation.platform.calls = append(mutation.platform.calls, "rollback")
	if mutation.platform.rollbackErr == nil {
		mutation.active = false
	}
	return mutation.platform.rollbackErr
}

func (mutation *fakeStagedMutation) Commit() error {
	mutation.platform.calls = append(mutation.platform.calls, "commit")
	return mutation.platform.commitErr
}

func (mutation *fakeStagedMutation) Abort() error {
	mutation.platform.calls = append(mutation.platform.calls, "abort")
	mutation.active = false
	return nil
}

func installerRequest(generation uint64) InstallRequest {
	return InstallRequest{
		ExpectedSystemID:    "sys-0123456789abcdef0123456789abcdef",
		ExpectedControlName: "control-1", MinimumGeneration: generation,
	}
}

func installerEnvelope(t *testing.T, generation uint64) []byte {
	t.Helper()
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := runtimePolicy(false)
	policy.Generation = generation
	policy.IssuedAt = runtimeTime.Add(-time.Minute)
	policy.ExpiresAt = runtimeTime.Add(24 * time.Hour)
	signed, err := controlpolicy.Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := signing.MarshalPublicPEM(public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(policy.SystemID, policy.ControlName, publicPEM, signed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
