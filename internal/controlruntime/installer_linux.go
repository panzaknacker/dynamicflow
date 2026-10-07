//go:build linux

package controlruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managementShell        = "/bin/sh"
	disabledPasswordMarker = "*NP*"
	lockFileName           = ".install.lock"
	maxCommandBytes        = 16 << 10
	commandTimeout         = 30 * time.Second
	maxRuntimeBytes        = 256 << 20

	getentPath    = "/usr/bin/getent"
	useraddPath   = "/usr/sbin/useradd"
	usermodPath   = "/usr/sbin/usermod"
	sshdPath      = "/usr/sbin/sshd"
	systemctlPath = "/usr/bin/systemctl"
)

var bundleFiles = []managedFile{
	{name: "envelope.json", mode: 0o444},
	{name: "policy.json", mode: 0o444},
	{name: "policy-root.pem", mode: 0o444},
	{name: "authorized_keys", mode: 0o444},
}

// CommandRunner is the sole process boundary used by the privileged installer.
// executable and argv remain separate, stdin is always nil, and all output is
// bounded by the caller. Implementations must not invoke a shell.
type CommandRunner interface {
	Run(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error
}

// ExecutableSource returns a descriptor for the exact runtime image to install.
// The production source is the kernel-owned /proc/self/exe link, so pathname
// replacement cannot change the bytes after this process has started.
type ExecutableSource interface {
	Open() (*os.File, error)
	IsRunningExecutable() bool
}

// ProcessExecutableSource opens the currently running Linux executable.
type ProcessExecutableSource struct{}

func (ProcessExecutableSource) Open() (*os.File, error)   { return os.Open("/proc/self/exe") }
func (ProcessExecutableSource) IsRunningExecutable() bool { return true }

// DefaultCommandRunner invokes one absolute executable without a shell.
type DefaultCommandRunner struct{}

func (DefaultCommandRunner) Run(ctx context.Context, executable string, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, argv...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

type linuxConfig struct {
	anchor       string
	stateRoot    string
	sshdConfig   string
	sshdDropIn   string
	executable   string
	ownerUID     uint32
	ownerGID     uint32
	effectiveUID func() int
}

func productionLinuxConfig() linuxConfig {
	return linuxConfig{
		anchor: "/", stateRoot: DefaultStateRoot,
		sshdConfig: DefaultSSHDConfigPath, sshdDropIn: DefaultSSHDDropInPath,
		executable: DefaultExecutable, ownerUID: 0, ownerGID: 0,
		effectiveUID: os.Geteuid,
	}
}

type linuxPlatform struct {
	config linuxConfig
	runner CommandRunner
	source ExecutableSource
}

func newLinuxPlatform(configuration linuxConfig, runner CommandRunner, sources ...ExecutableSource) *linuxPlatform {
	if runner == nil {
		runner = DefaultCommandRunner{}
	}
	var source ExecutableSource = ProcessExecutableSource{}
	if len(sources) == 1 && sources[0] != nil {
		source = sources[0]
	} else if len(sources) > 1 {
		source = nil
	}
	return &linuxPlatform{config: configuration, runner: runner, source: source}
}

func (platform *linuxPlatform) StateRoot() string      { return platform.config.stateRoot }
func (platform *linuxPlatform) SSHDConfigPath() string { return platform.config.sshdDropIn }

func (platform *linuxPlatform) EffectiveUID() int {
	if platform == nil || platform.config.effectiveUID == nil {
		return -1
	}
	return platform.config.effectiveUID()
}

func (platform *linuxPlatform) AcquireLock() (installLock, error) {
	if err := platform.validateConfiguration(); err != nil {
		return nil, err
	}
	directory, err := openTrustedDirectory(
		platform.config.anchor, platform.config.stateRoot, true,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return nil, err
	}
	file, created, err := openOrCreateManagedFile(directory, lockFileName, 0o600, platform.config.ownerUID, platform.config.ownerGID)
	if err != nil {
		directory.Close()
		return nil, err
	}
	if created {
		if err := directory.Sync(); err != nil {
			file.Close()
			directory.Close()
			return nil, err
		}
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		directory.Close()
		return nil, err
	}
	return &linuxInstallLock{file: file, directory: directory}, nil
}

type linuxInstallLock struct {
	file      *os.File
	directory *os.File
}

func (lock *linuxInstallLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if lock.directory != nil {
		if err := lock.directory.Close(); closeErr == nil {
			closeErr = err
		}
		lock.directory = nil
	}
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func (platform *linuxPlatform) Preflight(ctx context.Context, desired preparedInstall, request InstallRequest) (hostPreflight, error) {
	var state hostPreflight
	if ctx == nil || errIfDone(ctx) != nil {
		return state, context.Canceled
	}
	if err := platform.validateConfiguration(); err != nil {
		return state, err
	}
	runtime, installRuntime, err := platform.inspectRuntime()
	if err != nil {
		return state, err
	}
	state.runtime = runtime
	state.InstallExecutable = installRuntime
	mainConfig, err := readProtectedFile(
		platform.config.anchor, platform.config.sshdConfig,
		platform.config.ownerUID, platform.config.ownerGID, MaxEnvelopeBytes,
	)
	if err != nil {
		return state, err
	}
	if !mainIncludesDropIn(mainConfig, filepath.Dir(platform.config.sshdDropIn)) {
		return state, ErrUnsafeHost
	}

	account, exists, locked, err := platform.managementAccount(ctx)
	if err != nil {
		return state, err
	}
	if !exists {
		state.CreateAccount, state.LockAccount = true, true
	} else {
		if account.name != ManagementUser || account.uid == 0 || account.gid == 0 ||
			account.home != platform.config.stateRoot || account.shell != managementShell {
			return state, ErrUnsafeHost
		}
		state.LockAccount = !locked
	}

	sshdDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.sshdDropIn), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return state, err
	}
	dropIn, dropInErr := readManagedFileAt(sshdDirectory, filepath.Base(platform.config.sshdDropIn), 0o644, platform.config.ownerUID, platform.config.ownerGID, MaxEnvelopeBytes)
	sshdDirectory.Close()
	switch {
	case errors.Is(dropInErr, os.ErrNotExist), errors.Is(dropInErr, syscall.ENOENT):
		state.InstallDropIn = true
	case dropInErr != nil:
		return state, dropInErr
	case bytes.Equal(dropIn, desired.files.SSHDPolicy):
		// Already exact.
	case bytes.HasPrefix(dropIn, []byte("# Managed by Dynamicflow.")):
		state.InstallDropIn = true
	default:
		return state, ErrUnsafeHost
	}
	stale, err := platform.hasExternalStaging()
	if err != nil {
		return state, err
	}
	state.CleanupStale = stale

	root, err := openTrustedDirectory(
		platform.config.anchor, platform.config.stateRoot, false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		state.ActivateBundle = true
		return state, nil
	}
	if err != nil {
		return state, err
	}
	defer root.Close()
	rootStale, err := inspectStateRootEntries(root, platform.config.ownerUID, platform.config.ownerGID)
	if err != nil {
		return state, err
	}
	state.CleanupStale = state.CleanupStale || rootStale
	active, err := openManagedDirectoryAt(root, ActiveBundleName, platform.config.ownerUID, platform.config.ownerGID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		state.ActivateBundle = true
		return state, nil
	}
	if err != nil {
		return state, err
	}
	defer active.Close()
	installed, err := platform.verifyBundle(active, request)
	if err != nil {
		return state, err
	}
	installedCanonical, err := MarshalCanonical(installed)
	if err != nil {
		return state, err
	}
	desiredGeneration := desired.envelope.Policy.Policy.Generation
	installedGeneration := installed.Policy.Policy.Generation
	if installed.ControlPolicyKeyID != desired.envelope.ControlPolicyKeyID || installedGeneration > desiredGeneration {
		return state, ErrGenerationConflict
	}
	if installedGeneration == desiredGeneration {
		if !bytes.Equal(installedCanonical, desired.files.EnvelopeJSON) {
			return state, ErrGenerationConflict
		}
		return state, nil
	}
	state.ActivateBundle = true
	return state, nil
}

func (platform *linuxPlatform) EnsureManagementAccount(ctx context.Context, state hostPreflight) error {
	if state.CreateAccount {
		if err := platform.runDiscard(ctx, useraddPath, []string{
			"--system", "--user-group", "--home-dir", platform.config.stateRoot,
			"--no-create-home", "--shell", managementShell, ManagementUser,
		}); err != nil {
			return err
		}
	}
	if state.CreateAccount || state.LockAccount {
		// A leading '!' from usermod --lock makes the account inaccessible to
		// OpenSSH even for public-key authentication on Linux. OpenSSH's own
		// sshd(8) documentation recommends *NP* for a password-disabled account
		// that must remain available to public-key authentication.
		if err := platform.runDiscard(ctx, usermodPath, []string{"--password", disabledPasswordMarker, ManagementUser}); err != nil {
			return err
		}
	}
	account, exists, locked, err := platform.managementAccount(ctx)
	if err != nil || !exists || !locked || account.name != ManagementUser || account.uid == 0 || account.gid == 0 ||
		account.home != platform.config.stateRoot || account.shell != managementShell {
		if err != nil {
			return err
		}
		return ErrUnsafeHost
	}
	return nil
}

func (platform *linuxPlatform) Stage(ctx context.Context, desired preparedInstall, state hostPreflight) (stagedMutation, error) {
	if ctx == nil || errIfDone(ctx) != nil {
		return nil, context.Canceled
	}
	root, err := openTrustedDirectory(
		platform.config.anchor, platform.config.stateRoot, true,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return nil, err
	}
	sshdDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.sshdDropIn), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		root.Close()
		return nil, err
	}
	transaction := &linuxTransaction{
		platform: platform, root: root, sshdDirectory: sshdDirectory,
		executableNeeded: state.InstallExecutable,
		bundleNeeded:     state.ActivateBundle, dropInNeeded: state.InstallDropIn,
	}
	if state.InstallExecutable {
		transaction.executableDirectory, err = openTrustedDirectory(
			platform.config.anchor, filepath.Dir(platform.config.executable), false,
			platform.config.ownerUID, platform.config.ownerGID,
		)
		if err == nil {
			transaction.executableStage, err = randomManagedName(".flow-pending-")
		}
		if err == nil {
			err = platform.writeExecutable(transaction.executableDirectory, transaction.executableStage, state.runtime)
		}
		if err != nil {
			transaction.Abort()
			return nil, err
		}
	}
	if state.ActivateBundle {
		transaction.bundleStage, err = randomManagedName(".stage-")
		if err == nil {
			err = platform.writeBundle(root, transaction.bundleStage, desired.files)
		}
		if err != nil {
			transaction.Abort()
			return nil, err
		}
	}
	if state.InstallDropIn {
		transaction.dropInStage, err = randomManagedName(".sshd-pending-")
		if err == nil {
			err = writeManagedFileAt(
				sshdDirectory, transaction.dropInStage, desired.files.SSHDPolicy, 0o644,
				platform.config.ownerUID, platform.config.ownerGID,
			)
		}
		if err != nil {
			transaction.Abort()
			return nil, err
		}
		transaction.validationStage, err = randomManagedName(".sshd-validation-")
		if err == nil {
			validation, renderErr := renderSSHDValidationConfig(
				platform.config.sshdConfig,
				filepath.Join(filepath.Dir(platform.config.sshdDropIn), transaction.dropInStage),
			)
			if renderErr != nil {
				err = renderErr
			} else {
				err = writeManagedFileAt(
					sshdDirectory, transaction.validationStage, validation, 0o600,
					platform.config.ownerUID, platform.config.ownerGID,
				)
			}
		}
		if err != nil {
			transaction.Abort()
			return nil, err
		}
	}
	return transaction, nil
}

func (platform *linuxPlatform) ValidateActiveSSHD(ctx context.Context) error {
	return platform.validateSSHD(ctx, platform.config.sshdConfig)
}

func (platform *linuxPlatform) ReloadSSHD(ctx context.Context) error {
	return platform.runDiscard(ctx, systemctlPath, []string{"reload", "ssh.service"})
}

func (platform *linuxPlatform) CleanupStaging() error {
	if err := platform.validateConfiguration(); err != nil {
		return err
	}
	root, err := openTrustedDirectory(
		platform.config.anchor, platform.config.stateRoot, false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err == nil {
		names, listErr := directoryNames(root)
		if listErr != nil {
			root.Close()
			return listErr
		}
		for _, name := range names {
			if validManagedName(name, ".stage-") {
				if removeErr := removeStaleBundleAt(root, name, platform.config.ownerUID, platform.config.ownerGID); removeErr != nil {
					root.Close()
					return removeErr
				}
			}
		}
		if closeErr := root.Close(); closeErr != nil {
			return closeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOENT) {
		return err
	}

	sshdDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.sshdDropIn), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return err
	}
	if err := cleanupStaleFilesAt(sshdDirectory, platform.config.ownerUID, platform.config.ownerGID, map[string][]uint32{
		".sshd-pending-":    {0o600, 0o644},
		".sshd-validation-": {0o600},
	}); err != nil {
		sshdDirectory.Close()
		return err
	}
	if err := sshdDirectory.Close(); err != nil {
		return err
	}

	executableDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.executable), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return err
	}
	if err := cleanupStaleFilesAt(executableDirectory, platform.config.ownerUID, platform.config.ownerGID, map[string][]uint32{
		".flow-pending-": {0o600, 0o755},
	}); err != nil {
		executableDirectory.Close()
		return err
	}
	return executableDirectory.Close()
}

func (platform *linuxPlatform) hasExternalStaging() (bool, error) {
	sshdDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.sshdDropIn), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return false, err
	}
	sshdStale, err := hasStagingName(sshdDirectory, ".sshd-pending-", ".sshd-validation-")
	sshdDirectory.Close()
	if err != nil {
		return false, err
	}
	executableDirectory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.executable), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return false, err
	}
	executableStale, err := hasStagingName(executableDirectory, ".flow-pending-")
	executableDirectory.Close()
	return sshdStale || executableStale, err
}

func (platform *linuxPlatform) validateSSHD(ctx context.Context, configPath string) error {
	if !safeAbsolutePath(configPath) ||
		(configPath != platform.config.sshdConfig && filepath.Dir(configPath) != filepath.Dir(platform.config.sshdDropIn)) {
		return ErrUnsafeHost
	}
	return platform.runDiscard(ctx, sshdPath, []string{"-t", "-f", configPath})
}

func renderSSHDValidationConfig(mainConfig, pendingDropIn string) ([]byte, error) {
	if !safeAbsolutePath(mainConfig) || !safeAbsolutePath(pendingDropIn) || mainConfig == pendingDropIn {
		return nil, ErrUnsafeHost
	}
	return []byte("# Dynamicflow pre-activation validation only.\nInclude " + mainConfig + "\nMatch all\nInclude " + pendingDropIn + "\n"), nil
}

func (platform *linuxPlatform) runDiscard(ctx context.Context, executable string, arguments []string) error {
	if ctx == nil || platform.runner == nil || !safeCommand(executable, arguments) {
		return ErrUnsafeHost
	}
	operation, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	if err := operation.Err(); err != nil {
		return safeInstallError(ErrInstallFailed, err)
	}
	stdout, stderr := &boundedCommandOutput{limit: maxCommandBytes}, &boundedCommandOutput{limit: maxCommandBytes}
	err := platform.runner.Run(operation, executable, append([]string(nil), arguments...), nil, stdout, stderr)
	if contextErr := operation.Err(); contextErr != nil {
		return safeInstallError(ErrInstallFailed, contextErr)
	}
	if err != nil {
		return safeInstallError(ErrInstallFailed, err)
	}
	return nil
}

type accountRecord struct {
	name  string
	uid   uint64
	gid   uint64
	home  string
	shell string
}

func (platform *linuxPlatform) managementAccount(ctx context.Context) (accountRecord, bool, bool, error) {
	var account accountRecord
	output := &boundedCommandOutput{limit: 4096, retain: true}
	stderr := &boundedCommandOutput{limit: maxCommandBytes}
	operation, cancel := context.WithTimeout(ctx, commandTimeout)
	err := platform.runner.Run(operation, getentPath, []string{"passwd", ManagementUser}, nil, output, stderr)
	cancel()
	if err != nil {
		if commandExitCode(err) == 2 {
			return account, false, false, nil
		}
		return account, false, false, safeInstallError(ErrUnsafeHost, err)
	}
	if output.truncated {
		return account, false, false, ErrUnsafeHost
	}
	line := strings.TrimSuffix(string(output.data), "\n")
	if strings.Contains(line, "\n") || strings.ContainsRune(line, '\x00') {
		return account, false, false, ErrUnsafeHost
	}
	fields := strings.Split(line, ":")
	if len(fields) != 7 || fields[0] != ManagementUser {
		return account, false, false, ErrUnsafeHost
	}
	uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
	gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
	if uidErr != nil || gidErr != nil || !safeAbsolutePath(fields[5]) || !safeAbsolutePath(fields[6]) {
		return account, false, false, ErrUnsafeHost
	}
	account = accountRecord{name: fields[0], uid: uid, gid: gid, home: fields[5], shell: fields[6]}

	output = &boundedCommandOutput{limit: 4096, retain: true}
	defer clear(output.data)
	stderr = &boundedCommandOutput{limit: maxCommandBytes}
	operation, cancel = context.WithTimeout(ctx, commandTimeout)
	err = platform.runner.Run(operation, getentPath, []string{"shadow", ManagementUser}, nil, output, stderr)
	cancel()
	if err != nil || output.truncated {
		return account, true, false, safeInstallError(ErrUnsafeHost, err)
	}
	shadowLine := strings.TrimSuffix(string(output.data), "\n")
	if strings.Contains(shadowLine, "\n") || strings.ContainsRune(shadowLine, '\x00') {
		return account, true, false, ErrUnsafeHost
	}
	shadow := strings.Split(shadowLine, ":")
	if len(shadow) < 2 || shadow[0] != ManagementUser {
		return account, true, false, ErrUnsafeHost
	}
	return account, true, shadow[1] == disabledPasswordMarker, nil
}

func (platform *linuxPlatform) verifyBundle(directory *os.File, request InstallRequest) (InstallEnvelope, error) {
	contents := make(map[string][]byte, len(bundleFiles))
	for _, file := range bundleFiles {
		data, err := readManagedFileAt(directory, file.name, file.mode, platform.config.ownerUID, platform.config.ownerGID, MaxEnvelopeBytes)
		if err != nil {
			return InstallEnvelope{}, err
		}
		contents[file.name] = data
	}
	if err := requireExactDirectoryEntries(directory, bundleFiles); err != nil {
		return InstallEnvelope{}, err
	}
	envelope, err := ParseCanonical(contents["envelope.json"])
	if err != nil {
		return InstallEnvelope{}, err
	}
	// Use the signed issuance instant to verify authenticity even when an old
	// policy has expired. This permits a securely signed recovery update while
	// still enforcing the new envelope's current validity in prepare().
	if err := VerifyEnvelope(
		envelope, envelope.Policy.Policy.IssuedAt, request.ExpectedSystemID,
		request.ExpectedControlName, envelope.Policy.Policy.Generation,
	); err != nil {
		return InstallEnvelope{}, err
	}
	rendered, err := Render(
		envelope, envelope.Policy.Policy.IssuedAt, request.ExpectedSystemID,
		request.ExpectedControlName, envelope.Policy.Policy.Generation, platform.config.stateRoot,
	)
	if err != nil || !bytes.Equal(contents["policy.json"], rendered.PolicyJSON) ||
		!bytes.Equal(contents["policy-root.pem"], rendered.PolicyPublicPEM) ||
		!bytes.Equal(contents["authorized_keys"], rendered.AuthorizedKeys) {
		return InstallEnvelope{}, ErrUnsafeHost
	}
	return envelope, nil
}

func (platform *linuxPlatform) writeBundle(root *os.File, name string, files RenderedFiles) error {
	if !validManagedName(name, ".stage-") {
		return ErrUnsafeHost
	}
	if err := syscall.Mkdirat(int(root.Fd()), name, 0o755); err != nil {
		return err
	}
	stageFD, err := syscall.Openat(int(root.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
		return err
	}
	if err := syscall.Fchown(stageFD, int(platform.config.ownerUID), int(platform.config.ownerGID)); err == nil {
		err = syscall.Fchmod(stageFD, 0o755)
	}
	if closeErr := syscall.Close(stageFD); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
		return err
	}
	directory, err := openManagedDirectoryAt(root, name, platform.config.ownerUID, platform.config.ownerGID)
	if err != nil {
		_ = unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR)
		return err
	}
	defer directory.Close()
	entries := []struct {
		managedFile
		data []byte
	}{
		{bundleFiles[0], files.EnvelopeJSON},
		{bundleFiles[1], files.PolicyJSON},
		{bundleFiles[2], files.PolicyPublicPEM},
		{bundleFiles[3], files.AuthorizedKeys},
	}
	for _, entry := range entries {
		if err := writeManagedFileAt(directory, entry.name, entry.data, entry.mode, platform.config.ownerUID, platform.config.ownerGID); err != nil {
			return err
		}
	}
	if err := requireExactDirectoryEntries(directory, bundleFiles); err != nil {
		return err
	}
	return root.Sync()
}

type executableSnapshot struct {
	device   uint64
	inode    uint64
	size     int64
	mode     uint32
	uid      uint32
	gid      uint32
	links    uint64
	modified syscall.Timespec
	changed  syscall.Timespec
	digest   string
}

func (platform *linuxPlatform) inspectRuntime() (executableSnapshot, bool, error) {
	var empty executableSnapshot
	if platform == nil || platform.source == nil {
		return empty, false, ErrUnsafeHost
	}
	source, err := platform.source.Open()
	if err != nil || source == nil {
		if source != nil {
			source.Close()
		}
		return empty, false, ErrUnsafeHost
	}
	snapshot, err := inspectExecutableDescriptor(
		source, platform.source.IsRunningExecutable(), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	closeErr := source.Close()
	if err != nil {
		return empty, false, err
	}
	if closeErr != nil {
		return empty, false, closeErr
	}

	directory, err := openTrustedDirectory(
		platform.config.anchor, filepath.Dir(platform.config.executable), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil {
		return empty, false, err
	}
	defer directory.Close()
	destinationFD, err := syscall.Openat(
		int(directory.Fd()), filepath.Base(platform.config.executable),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0,
	)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return snapshot, true, nil
	}
	if err != nil {
		return empty, false, ErrUnsafeHost
	}
	destination := os.NewFile(uintptr(destinationFD), filepath.Base(platform.config.executable))
	if destination == nil {
		syscall.Close(destinationFD)
		return empty, false, ErrUnsafeHost
	}
	installed, inspectErr := inspectExecutableDescriptor(
		destination, false, true, platform.config.ownerUID, platform.config.ownerGID,
	)
	closeErr = destination.Close()
	if inspectErr != nil {
		return empty, false, inspectErr
	}
	if closeErr != nil {
		return empty, false, closeErr
	}
	return snapshot, snapshot.digest != installed.digest || snapshot.size != installed.size, nil
}

func inspectExecutableDescriptor(file *os.File, running, exactInstalledMode bool, uid, gid uint32) (executableSnapshot, error) {
	var empty executableSnapshot
	if file == nil {
		return empty, ErrUnsafeHost
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &before); err != nil ||
		before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Size < 1 || before.Size > maxRuntimeBytes ||
		before.Mode&0o111 == 0 || before.Mode&0o022 != 0 || before.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 {
		return empty, ErrUnsafeHost
	}
	if exactInstalledMode && before.Mode&0o777 != 0o755 {
		return empty, ErrUnsafeHost
	}
	if !running && (before.Uid != uid || before.Gid != gid || before.Nlink != 1) {
		return empty, ErrUnsafeHost
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return empty, ErrUnsafeHost
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxRuntimeBytes+1))
	if err != nil || written != before.Size {
		return empty, ErrUnsafeHost
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &after); err != nil || !sameStableFile(before, after) {
		return empty, ErrUnsafeHost
	}
	return executableSnapshot{
		device: uint64(before.Dev), inode: before.Ino, size: before.Size,
		mode: before.Mode, uid: before.Uid, gid: before.Gid, links: before.Nlink,
		modified: before.Mtim, changed: before.Ctim,
		digest: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func sameExecutableSnapshot(left, right executableSnapshot) bool {
	return left.device == right.device && left.inode == right.inode && left.size == right.size &&
		left.mode == right.mode && left.uid == right.uid && left.gid == right.gid && left.links == right.links &&
		left.modified == right.modified && left.changed == right.changed && left.digest == right.digest
}

func (platform *linuxPlatform) writeExecutable(directory *os.File, name string, expected executableSnapshot) error {
	if directory == nil || !validManagedName(name, ".flow-pending-") || expected.digest == "" {
		return ErrUnsafeHost
	}
	source, err := platform.source.Open()
	if err != nil || source == nil {
		if source != nil {
			source.Close()
		}
		return ErrUnsafeHost
	}
	defer source.Close()
	actual, err := inspectExecutableDescriptor(
		source, platform.source.IsRunningExecutable(), false,
		platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil || !sameExecutableSnapshot(expected, actual) {
		return ErrUnsafeHost
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return ErrUnsafeHost
	}
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return err
	}
	destination := os.NewFile(uintptr(fd), name)
	if destination == nil {
		syscall.Close(fd)
		return ErrUnsafeHost
	}
	keep := false
	defer func() {
		_ = destination.Close()
		if !keep {
			_ = syscall.Unlinkat(int(directory.Fd()), name)
		}
	}()
	if err := destination.Chown(int(platform.config.ownerUID), int(platform.config.ownerGID)); err != nil {
		return err
	}
	copied, err := io.Copy(destination, io.LimitReader(source, maxRuntimeBytes+1))
	if err != nil || copied != expected.size {
		return ErrUnsafeHost
	}
	var sourceAfter syscall.Stat_t
	if err := syscall.Fstat(int(source.Fd()), &sourceAfter); err != nil ||
		uint64(sourceAfter.Dev) != expected.device || sourceAfter.Ino != expected.inode ||
		sourceAfter.Size != expected.size || sourceAfter.Mode != expected.mode ||
		sourceAfter.Uid != expected.uid || sourceAfter.Gid != expected.gid || sourceAfter.Nlink != expected.links ||
		sourceAfter.Mtim != expected.modified || sourceAfter.Ctim != expected.changed {
		return ErrUnsafeHost
	}
	if err := destination.Chmod(0o755); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	installed, err := inspectExecutableDescriptor(
		destination, false, true, platform.config.ownerUID, platform.config.ownerGID,
	)
	if err != nil || installed.digest != expected.digest || installed.size != expected.size {
		return ErrUnsafeHost
	}
	if err := destination.Close(); err != nil {
		return err
	}
	keep = true
	return directory.Sync()
}

func (platform *linuxPlatform) validateConfiguration() error {
	configuration := platform.config
	if platform == nil || platform.runner == nil || platform.source == nil || configuration.effectiveUID == nil ||
		!safeTrustAnchor(configuration.anchor) || !safeAbsolutePath(configuration.stateRoot) ||
		!safeAbsolutePath(configuration.sshdConfig) || !safeAbsolutePath(configuration.sshdDropIn) ||
		!safeAbsolutePath(configuration.executable) || filepath.Base(configuration.sshdDropIn) == "." ||
		!pathInside(configuration.anchor, configuration.stateRoot) ||
		!pathInside(configuration.anchor, configuration.sshdConfig) ||
		!pathInside(configuration.anchor, configuration.sshdDropIn) ||
		!pathInside(configuration.anchor, configuration.executable) {
		return ErrUnsafeHost
	}
	return nil
}

type linuxTransaction struct {
	platform            *linuxPlatform
	root                *os.File
	sshdDirectory       *os.File
	executableDirectory *os.File
	executableStage     string
	bundleStage         string
	dropInStage         string
	validationStage     string
	executableNeeded    bool
	bundleNeeded        bool
	dropInNeeded        bool
	executableHadOld    bool
	bundleHadOld        bool
	dropInHadOld        bool
	executableActive    bool
	bundleActive        bool
	dropInActive        bool
	closed              bool
}

func (transaction *linuxTransaction) ValidateSSHD(ctx context.Context) error {
	if transaction == nil || transaction.closed {
		return ErrUnsafeHost
	}
	configuration := transaction.platform.config.sshdConfig
	if transaction.dropInNeeded {
		configuration = filepath.Join(filepath.Dir(transaction.platform.config.sshdDropIn), transaction.validationStage)
	}
	return transaction.platform.validateSSHD(ctx, configuration)
}

func (transaction *linuxTransaction) Activate() error {
	if transaction == nil || transaction.closed {
		return ErrUnsafeHost
	}
	if transaction.executableNeeded {
		destination := filepath.Base(transaction.platform.config.executable)
		exists, err := managedExecutableExists(
			transaction.executableDirectory, destination,
			transaction.platform.config.ownerUID, transaction.platform.config.ownerGID,
		)
		if err != nil {
			return err
		}
		transaction.executableHadOld = exists
		if exists {
			err = unix.Renameat2(
				int(transaction.executableDirectory.Fd()), transaction.executableStage,
				int(transaction.executableDirectory.Fd()), destination, unix.RENAME_EXCHANGE,
			)
		} else {
			err = syscall.Renameat(
				int(transaction.executableDirectory.Fd()), transaction.executableStage,
				int(transaction.executableDirectory.Fd()), destination,
			)
		}
		if err != nil {
			return err
		}
		transaction.executableActive = true
		if err := transaction.executableDirectory.Sync(); err != nil {
			return err
		}
	}
	if transaction.bundleNeeded {
		exists, err := managedDirectoryExists(transaction.root, ActiveBundleName, transaction.platform.config.ownerUID, transaction.platform.config.ownerGID)
		if err != nil {
			return err
		}
		transaction.bundleHadOld = exists
		if exists {
			err = unix.Renameat2(int(transaction.root.Fd()), transaction.bundleStage, int(transaction.root.Fd()), ActiveBundleName, unix.RENAME_EXCHANGE)
		} else {
			err = syscall.Renameat(int(transaction.root.Fd()), transaction.bundleStage, int(transaction.root.Fd()), ActiveBundleName)
		}
		if err != nil {
			return err
		}
		transaction.bundleActive = true
		if err := transaction.root.Sync(); err != nil {
			return err
		}
	}
	if transaction.dropInNeeded {
		destination := filepath.Base(transaction.platform.config.sshdDropIn)
		exists, err := managedFileExists(transaction.sshdDirectory, destination, 0o644, transaction.platform.config.ownerUID, transaction.platform.config.ownerGID)
		if err != nil {
			return err
		}
		transaction.dropInHadOld = exists
		if exists {
			err = unix.Renameat2(int(transaction.sshdDirectory.Fd()), transaction.dropInStage, int(transaction.sshdDirectory.Fd()), destination, unix.RENAME_EXCHANGE)
		} else {
			err = syscall.Renameat(int(transaction.sshdDirectory.Fd()), transaction.dropInStage, int(transaction.sshdDirectory.Fd()), destination)
		}
		if err != nil {
			return err
		}
		transaction.dropInActive = true
		if err := transaction.sshdDirectory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func (transaction *linuxTransaction) Activated() bool {
	return transaction != nil && (transaction.executableActive || transaction.bundleActive || transaction.dropInActive)
}

func (transaction *linuxTransaction) Rollback() error {
	if transaction == nil || transaction.closed {
		return ErrUnsafeHost
	}
	if transaction.dropInActive {
		destination := filepath.Base(transaction.platform.config.sshdDropIn)
		var err error
		if transaction.dropInHadOld {
			err = unix.Renameat2(int(transaction.sshdDirectory.Fd()), transaction.dropInStage, int(transaction.sshdDirectory.Fd()), destination, unix.RENAME_EXCHANGE)
		} else {
			err = syscall.Renameat(int(transaction.sshdDirectory.Fd()), destination, int(transaction.sshdDirectory.Fd()), transaction.dropInStage)
		}
		if err != nil {
			return err
		}
		transaction.dropInActive = false
		if err := transaction.sshdDirectory.Sync(); err != nil {
			return err
		}
	}
	if transaction.bundleActive {
		var err error
		if transaction.bundleHadOld {
			err = unix.Renameat2(int(transaction.root.Fd()), transaction.bundleStage, int(transaction.root.Fd()), ActiveBundleName, unix.RENAME_EXCHANGE)
		} else {
			err = syscall.Renameat(int(transaction.root.Fd()), ActiveBundleName, int(transaction.root.Fd()), transaction.bundleStage)
		}
		if err != nil {
			return err
		}
		transaction.bundleActive = false
		if err := transaction.root.Sync(); err != nil {
			return err
		}
	}
	if transaction.executableActive {
		destination := filepath.Base(transaction.platform.config.executable)
		var err error
		if transaction.executableHadOld {
			err = unix.Renameat2(
				int(transaction.executableDirectory.Fd()), transaction.executableStage,
				int(transaction.executableDirectory.Fd()), destination, unix.RENAME_EXCHANGE,
			)
		} else {
			err = syscall.Renameat(
				int(transaction.executableDirectory.Fd()), destination,
				int(transaction.executableDirectory.Fd()), transaction.executableStage,
			)
		}
		if err != nil {
			return err
		}
		transaction.executableActive = false
		if err := transaction.executableDirectory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func (transaction *linuxTransaction) Commit() error {
	if transaction == nil || transaction.closed {
		return nil
	}
	if transaction.executableStage != "" {
		if err := removeExecutableAt(
			transaction.executableDirectory, transaction.executableStage,
			transaction.platform.config.ownerUID, transaction.platform.config.ownerGID,
		); err != nil {
			return err
		}
		transaction.executableStage = ""
	}
	if transaction.bundleStage != "" {
		if err := removeBundleAt(transaction.root, transaction.bundleStage, transaction.platform.config.ownerUID, transaction.platform.config.ownerGID); err != nil {
			return err
		}
		transaction.bundleStage = ""
	}
	if transaction.dropInStage != "" {
		if err := removeManagedFileAt(transaction.sshdDirectory, transaction.dropInStage, 0o644, transaction.platform.config.ownerUID, transaction.platform.config.ownerGID); err != nil {
			return err
		}
		transaction.dropInStage = ""
	}
	if transaction.validationStage != "" {
		if err := removeManagedFileAt(transaction.sshdDirectory, transaction.validationStage, 0o600, transaction.platform.config.ownerUID, transaction.platform.config.ownerGID); err != nil {
			return err
		}
		transaction.validationStage = ""
	}
	return transaction.close()
}

func (transaction *linuxTransaction) Abort() error {
	if transaction == nil || transaction.closed {
		return nil
	}
	if transaction.Activated() {
		if err := transaction.Rollback(); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (transaction *linuxTransaction) close() error {
	transaction.closed = true
	var result error
	if transaction.root != nil {
		result = transaction.root.Close()
		transaction.root = nil
	}
	if transaction.sshdDirectory != nil {
		if err := transaction.sshdDirectory.Close(); result == nil {
			result = err
		}
		transaction.sshdDirectory = nil
	}
	if transaction.executableDirectory != nil {
		if err := transaction.executableDirectory.Close(); result == nil {
			result = err
		}
		transaction.executableDirectory = nil
	}
	return result
}

type managedFile struct {
	name string
	mode uint32
}

func openTrustedDirectory(anchor, target string, create bool, uid, gid uint32) (*os.File, error) {
	if !safeTrustAnchor(anchor) || !safeAbsolutePath(target) || !pathInside(anchor, target) {
		return nil, ErrUnsafeHost
	}
	anchorFD, err := syscall.Open(anchor, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(anchorFD), anchor)
	if current == nil {
		syscall.Close(anchorFD)
		return nil, ErrUnsafeHost
	}
	if err := verifyOpenDirectory(current, uid, gid); err != nil {
		current.Close()
		return nil, err
	}
	relative, err := filepath.Rel(anchor, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		current.Close()
		return nil, ErrUnsafeHost
	}
	if relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if !validPathComponent(component) {
			current.Close()
			return nil, ErrUnsafeHost
		}
		nextFD, openErr := syscall.Openat(int(current.Fd()), component, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if create && (errors.Is(openErr, syscall.ENOENT) || errors.Is(openErr, os.ErrNotExist)) {
			created := false
			if mkdirErr := syscall.Mkdirat(int(current.Fd()), component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				current.Close()
				return nil, mkdirErr
			} else {
				created = mkdirErr == nil
			}
			nextFD, openErr = syscall.Openat(int(current.Fd()), component, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if openErr == nil && created {
				if ownerErr := syscall.Fchown(nextFD, int(uid), int(gid)); ownerErr != nil {
					syscall.Close(nextFD)
					current.Close()
					return nil, ownerErr
				}
				if modeErr := syscall.Fchmod(nextFD, 0o755); modeErr != nil {
					syscall.Close(nextFD)
					current.Close()
					return nil, modeErr
				}
				if syncErr := current.Sync(); syncErr != nil {
					syscall.Close(nextFD)
					current.Close()
					return nil, syncErr
				}
			}
		}
		if openErr != nil {
			current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			syscall.Close(nextFD)
			current.Close()
			return nil, ErrUnsafeHost
		}
		current.Close()
		current = next
		if err := verifyOpenDirectory(current, uid, gid); err != nil {
			current.Close()
			return nil, err
		}
	}
	return current, nil
}

func verifyOpenDirectory(directory *os.File, uid, gid uint32) error {
	if directory == nil {
		return ErrUnsafeHost
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(int(directory.Fd()), &details); err != nil ||
		details.Mode&syscall.S_IFMT != syscall.S_IFDIR || details.Uid != uid || details.Gid != gid ||
		details.Mode&0o022 != 0 || details.Mode&0o111 != 0o111 {
		return ErrUnsafeHost
	}
	return nil
}

func openManagedDirectoryAt(parent *os.File, name string, uid, gid uint32) (*os.File, error) {
	if parent == nil || !validPathComponent(name) {
		return nil, ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		syscall.Close(fd)
		return nil, ErrUnsafeHost
	}
	if err := verifyOpenDirectory(directory, uid, gid); err != nil {
		directory.Close()
		return nil, err
	}
	return directory, nil
}

func managedDirectoryExists(parent *os.File, name string, uid, gid uint32) (bool, error) {
	directory, err := openManagedDirectoryAt(parent, name, uid, gid)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, directory.Close()
}

func writeManagedFileAt(directory *os.File, name string, data []byte, mode uint32, uid, gid uint32) error {
	if directory == nil || !validPathComponent(name) || len(data) == 0 || len(data) > MaxEnvelopeBytes ||
		(mode != 0o444 && mode != 0o600 && mode != 0o644) {
		return ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return ErrUnsafeHost
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = syscall.Unlinkat(int(directory.Fd()), name)
		}
	}()
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := verifyOpenManagedFile(file, data, mode, uid, gid); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return directory.Sync()
}

func openOrCreateManagedFile(directory *os.File, name string, mode uint32, uid, gid uint32) (*os.File, bool, error) {
	if directory == nil || !validPathComponent(name) {
		return nil, false, ErrUnsafeHost
	}
	created := false
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, mode)
	if err == nil {
		created = true
		if chownErr := syscall.Fchown(fd, int(uid), int(gid)); chownErr != nil {
			syscall.Close(fd)
			_ = syscall.Unlinkat(int(directory.Fd()), name)
			return nil, false, chownErr
		}
		if chmodErr := syscall.Fchmod(fd, mode); chmodErr != nil {
			syscall.Close(fd)
			_ = syscall.Unlinkat(int(directory.Fd()), name)
			return nil, false, chmodErr
		}
	} else if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Openat(int(directory.Fd()), name, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, false, ErrUnsafeHost
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != mode || details.Uid != uid || details.Gid != gid || details.Nlink != 1 {
		file.Close()
		return nil, false, ErrUnsafeHost
	}
	return file, created, nil
}

func readManagedFileAt(directory *os.File, name string, mode, uid, gid uint32, limit int64) ([]byte, error) {
	if directory == nil || !validPathComponent(name) || limit < 1 {
		return nil, ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrUnsafeHost
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || !validManagedFileStat(before, mode, uid, gid) || before.Size < 1 || before.Size > limit {
		return nil, ErrUnsafeHost
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size {
		return nil, ErrUnsafeHost
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil || !sameStableFile(before, after) {
		return nil, ErrUnsafeHost
	}
	return data, nil
}

func verifyOpenManagedFile(file *os.File, expected []byte, mode, uid, gid uint32) error {
	if file == nil {
		return ErrUnsafeHost
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &before); err != nil || !validManagedFileStat(before, mode, uid, gid) || before.Size != int64(len(expected)) {
		return ErrUnsafeHost
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrUnsafeHost
	}
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil || !bytes.Equal(actual, expected) {
		return ErrUnsafeHost
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &after); err != nil || !sameStableFile(before, after) {
		return ErrUnsafeHost
	}
	return nil
}

func validManagedFileStat(details syscall.Stat_t, mode, uid, gid uint32) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFREG && details.Mode&0o777 == mode &&
		details.Uid == uid && details.Gid == gid && details.Nlink == 1
}

func sameStableFile(before, after syscall.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size &&
		before.Mode == after.Mode && before.Uid == after.Uid && before.Gid == after.Gid &&
		before.Nlink == after.Nlink && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func managedFileExists(directory *os.File, name string, mode, uid, gid uint32) (bool, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || !validManagedFileStat(details, mode, uid, gid) {
		return false, ErrUnsafeHost
	}
	return true, nil
}

func managedExecutableExists(directory *os.File, name string, uid, gid uint32) (bool, error) {
	if directory == nil || !validPathComponent(name) {
		return false, ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnsafeHost
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return false, ErrUnsafeHost
	}
	_, inspectErr := inspectExecutableDescriptor(file, false, true, uid, gid)
	closeErr := file.Close()
	if inspectErr != nil {
		return false, inspectErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	return true, nil
}

func removeExecutableAt(directory *os.File, name string, uid, gid uint32) error {
	exists, err := managedExecutableExists(directory, name, uid, gid)
	if err != nil || !exists {
		return err
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}

func removeManagedFileAt(directory *os.File, name string, mode, uid, gid uint32) error {
	exists, err := managedFileExists(directory, name, mode, uid, gid)
	if err != nil || !exists {
		return err
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}

func removeBundleAt(root *os.File, name string, uid, gid uint32) error {
	if name == "" {
		return nil
	}
	directory, err := openManagedDirectoryAt(root, name, uid, gid)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := requireExactDirectoryEntries(directory, bundleFiles); err != nil {
		directory.Close()
		return err
	}
	for _, file := range bundleFiles {
		if err := removeManagedFileAt(directory, file.name, file.mode, uid, gid); err != nil {
			directory.Close()
			return err
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return root.Sync()
}

func removeStaleBundleAt(root *os.File, name string, uid, gid uint32) error {
	directory, err := openStaleDirectoryAt(root, name, uid, gid)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := directoryNames(directory)
	if err != nil {
		directory.Close()
		return err
	}
	modes := make(map[string][]uint32, len(bundleFiles))
	for _, file := range bundleFiles {
		modes[file.name] = []uint32{0o600, file.mode}
	}
	for _, entry := range names {
		allowed, ok := modes[entry]
		if !ok {
			directory.Close()
			return ErrUnsafeHost
		}
		if err := removeStaleRegularAt(directory, entry, uid, gid, allowed...); err != nil {
			directory.Close()
			return err
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return root.Sync()
}

func openStaleDirectoryAt(parent *os.File, name string, uid, gid uint32) (*os.File, error) {
	if parent == nil || !validPathComponent(name) {
		return nil, ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		syscall.Close(fd)
		return nil, ErrUnsafeHost
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		details.Uid != uid || details.Gid != gid || details.Mode&0o022 != 0 || details.Mode&0o100 == 0 {
		directory.Close()
		return nil, ErrUnsafeHost
	}
	return directory, nil
}

func removeStaleRegularAt(directory *os.File, name string, uid, gid uint32, modes ...uint32) error {
	if directory == nil || !validPathComponent(name) || len(modes) == 0 {
		return ErrUnsafeHost
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var details syscall.Stat_t
	statErr := syscall.Fstat(fd, &details)
	closeErr := syscall.Close(fd)
	if statErr != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Uid != uid || details.Gid != gid || details.Nlink != 1 {
		return ErrUnsafeHost
	}
	modeOK := false
	for _, mode := range modes {
		if details.Mode&0o777 == mode {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return ErrUnsafeHost
	}
	if closeErr != nil {
		return closeErr
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}

func cleanupStaleFilesAt(directory *os.File, uid, gid uint32, prefixes map[string][]uint32) error {
	names, err := directoryNames(directory)
	if err != nil {
		return err
	}
	for _, name := range names {
		for prefix, modes := range prefixes {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if !validManagedName(name, prefix) {
				return ErrUnsafeHost
			}
			if err := removeStaleRegularAt(directory, name, uid, gid, modes...); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func inspectStateRootEntries(root *os.File, uid, gid uint32) (bool, error) {
	names, err := directoryNames(root)
	if err != nil {
		return false, err
	}
	stale := false
	for _, name := range names {
		switch {
		case name == ActiveBundleName:
		case name == lockFileName:
			exists, verifyErr := managedFileExists(root, name, 0o600, uid, gid)
			if verifyErr != nil || !exists {
				if verifyErr != nil {
					return false, verifyErr
				}
				return false, ErrUnsafeHost
			}
		case strings.HasPrefix(name, ".stage-"):
			if !validManagedName(name, ".stage-") {
				return false, ErrUnsafeHost
			}
			stale = true
		default:
			return false, ErrUnsafeHost
		}
	}
	return stale, nil
}

func hasStagingName(directory *os.File, prefixes ...string) (bool, error) {
	names, err := directoryNames(directory)
	if err != nil {
		return false, err
	}
	found := false
	for _, name := range names {
		for _, prefix := range prefixes {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if !validManagedName(name, prefix) {
				return false, ErrUnsafeHost
			}
			found = true
		}
	}
	return found, nil
}

func directoryNames(directory *os.File) ([]string, error) {
	if directory == nil {
		return nil, ErrUnsafeHost
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return directory.Readdirnames(-1)
}

func requireExactDirectoryEntries(directory *os.File, expected []managedFile) error {
	if directory == nil {
		return ErrUnsafeHost
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, file := range expected {
		wanted[file.name] = struct{}{}
	}
	if len(names) != len(wanted) {
		return ErrUnsafeHost
	}
	for _, name := range names {
		if _, ok := wanted[name]; !ok {
			return ErrUnsafeHost
		}
	}
	return nil
}

func readProtectedFile(anchor, path string, uid, gid uint32, limit int64) ([]byte, error) {
	if limit < 1 {
		return nil, ErrUnsafeHost
	}
	directory, err := openTrustedDirectory(anchor, filepath.Dir(path), false, uid, gid)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(int(directory.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		syscall.Close(fd)
		return nil, ErrUnsafeHost
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Uid != uid || before.Gid != gid || before.Nlink != 1 || before.Mode&0o022 != 0 ||
		before.Size < 1 || before.Size > limit {
		return nil, ErrUnsafeHost
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size {
		return nil, ErrUnsafeHost
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil || !sameStableFile(before, after) {
		return nil, ErrUnsafeHost
	}
	return data, nil
}

func mainIncludesDropIn(configuration []byte, dropInDirectory string) bool {
	if len(configuration) == 0 || !safeAbsolutePath(dropInDirectory) {
		return false
	}
	expected := filepath.Join(dropInDirectory, "*.conf")
	insideMatch := false
	for _, raw := range strings.Split(string(configuration), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		if directive == "match" {
			insideMatch = true
			continue
		}
		if directive != "include" || insideMatch {
			continue
		}
		for _, pattern := range fields[1:] {
			if strings.HasPrefix(pattern, "#") {
				break
			}
			if pattern == expected {
				return true
			}
		}
	}
	return false
}

// The filesystem root is the production trust anchor, but remains forbidden
// as an installation destination. Tests may use an isolated non-root anchor.
func safeTrustAnchor(value string) bool {
	return value == "/" || safeAbsolutePath(value)
}

func pathInside(anchor, target string) bool {
	relative, err := filepath.Rel(anchor, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validPathComponent(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.Contains(value, "/") &&
		!strings.ContainsRune(value, '\x00') && !strings.ContainsAny(value, "\\\r\n")
}

func validManagedName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return err == nil
}

func randomManagedName(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func safeCommand(executable string, arguments []string) bool {
	allowed := executable == getentPath || executable == useraddPath ||
		executable == usermodPath || executable == sshdPath || executable == systemctlPath
	if !allowed || !safeAbsolutePath(executable) {
		return false
	}
	for _, argument := range arguments {
		if argument == "" || strings.ContainsAny(argument, "\x00\r\n") {
			return false
		}
	}
	return true
}

type boundedCommandOutput struct {
	limit     int
	retain    bool
	data      []byte
	seen      int
	truncated bool
}

func (output *boundedCommandOutput) Write(data []byte) (int, error) {
	before := output.seen
	output.seen += len(data)
	remaining := output.limit - before
	if remaining < 0 {
		remaining = 0
	}
	if len(data) > remaining {
		output.truncated = true
	}
	if output.retain && remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		output.data = append(output.data, data[:remaining]...)
	}
	return len(data), nil
}

type exitCoder interface{ ExitCode() int }

func commandExitCode(err error) int {
	var coded exitCoder
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return -1
}

func errIfDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
