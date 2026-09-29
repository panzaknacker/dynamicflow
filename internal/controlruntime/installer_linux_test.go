//go:build linux

package controlruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/signing"
)

func TestLinuxInstallerAtomicIdempotentActivation(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	envelope := fixedInstallerEnvelope(t, public, private, 3, runtimeTime.Add(24*time.Hour))
	plan, err := fixture.installer.Plan(context.Background(), bytes.NewReader(envelope), installerRequest(3))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || !strings.HasPrefix(plan.RuntimeDigest, "sha256:") || !planPhaseChanges(plan, "install_runtime") {
		t.Fatalf("runtime plan = %+v", plan)
	}
	if _, err := os.Lstat(fixture.config.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plan mutated state root: %v", err)
	}
	result, err := fixture.installer.Install(context.Background(), bytes.NewReader(envelope), installerRequest(3))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.RolledBack || result.RuntimeDigest != plan.RuntimeDigest {
		t.Fatalf("result = %+v", result)
	}
	sourceRuntime, err := os.ReadFile(fixture.sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	installedRuntime, err := os.ReadFile(fixture.config.executable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installedRuntime, sourceRuntime) {
		t.Fatal("installed runtime differs from descriptor-pinned source")
	}
	assertManagedFile(t, fixture.config.executable, 0o755, fixture.config.ownerUID, fixture.config.ownerGID)
	active := filepath.Join(fixture.config.stateRoot, ActiveBundleName)
	assertManagedDirectory(t, active, fixture.config.ownerUID, fixture.config.ownerGID)
	for _, file := range bundleFiles {
		assertManagedFile(t, filepath.Join(active, file.name), file.mode, fixture.config.ownerUID, fixture.config.ownerGID)
	}
	assertManagedFile(t, fixture.config.sshdDropIn, 0o644, fixture.config.ownerUID, fixture.config.ownerGID)
	policy, err := os.ReadFile(fixture.config.sshdDropIn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(policy, []byte(fixture.config.stateRoot+"/"+ActiveBundleName+"/authorized_keys")) {
		t.Fatalf("drop-in points outside atomic bundle: %s", policy)
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn))
	for _, call := range fixture.runner.calls {
		if call.executable != sshdPath {
			continue
		}
		if len(call.arguments) != 3 || call.arguments[0] != "-t" || call.arguments[1] != "-f" ||
			strings.Contains(strings.Join(call.arguments, " "), "-o") || strings.Contains(strings.Join(call.arguments, " "), "Include=") {
			t.Fatalf("unsafe sshd validation argv: %+v", call)
		}
	}

	reloads := fixture.runner.countExecutable(systemctlPath)
	second, err := fixture.installer.Install(context.Background(), bytes.NewReader(envelope), installerRequest(3))
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.RolledBack || fixture.runner.countExecutable(systemctlPath) != reloads+1 {
		t.Fatalf("idempotent result=%+v reloads=%d->%d", second, reloads, fixture.runner.countExecutable(systemctlPath))
	}
}

func TestLinuxInstallerReloadFailureAtomicallyRestoresOldGeneration(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope := fixedInstallerEnvelope(t, public, private, 3, runtimeTime.Add(24*time.Hour))
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(oldEnvelope), installerRequest(3)); err != nil {
		t.Fatal(err)
	}
	oldActive, err := os.ReadFile(filepath.Join(fixture.config.stateRoot, ActiveBundleName, "envelope.json"))
	if err != nil {
		t.Fatal(err)
	}

	oldRuntime, err := os.ReadFile(fixture.config.executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.sourcePath, []byte("flow-new-generation-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	newEnvelope := fixedInstallerEnvelope(t, public, private, 4, runtimeTime.Add(48*time.Hour))
	fixture.runner.reloadErrors = []error{errors.New("untrusted stderr /operator/private.pem"), nil}
	result, err := fixture.installer.Install(context.Background(), bytes.NewReader(newEnvelope), installerRequest(3))
	if !errors.Is(err, ErrSSHDReload) || strings.Contains(err.Error(), "private.pem") {
		t.Fatalf("reload error = %v", err)
	}
	if !result.RolledBack {
		t.Fatalf("result = %+v", result)
	}
	restored, err := os.ReadFile(filepath.Join(fixture.config.stateRoot, ActiveBundleName, "envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, oldActive) || !bytes.Equal(restored, oldEnvelope) {
		t.Fatal("old signed generation was not restored exactly")
	}
	restoredRuntime, err := os.ReadFile(fixture.config.executable)
	if err != nil || !bytes.Equal(restoredRuntime, oldRuntime) {
		t.Fatalf("old runtime was not restored exactly: %v", err)
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn))
}

func TestLinuxInstallerSSHDValidationFailureLeavesNoActivePolicy(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	fixture.runner.sshdErrors = []error{errors.New("invalid config with secret output")}
	_, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrSSHDValidation) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("validation error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.config.stateRoot, ActiveBundleName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active policy exists after validation failure: %v", err)
	}
	if _, err := os.Lstat(fixture.config.sshdDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drop-in exists after validation failure: %v", err)
	}
	if _, err := os.Lstat(fixture.config.executable); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime exists after validation failure: %v", err)
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn))
}

func TestLinuxInstallerRetryReloadsAfterCrashFollowingFinalRename(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	envelope := installerEnvelope(t, 3)
	request := installerRequest(3)
	prepared, err := fixture.installer.prepare(context.Background(), bytes.NewReader(envelope), request)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := fixture.platform.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	state, err := fixture.platform.Preflight(context.Background(), prepared, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.platform.EnsureManagementAccount(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.platform.Stage(context.Background(), prepared, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.ValidateSSHD(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := staged.Activate(); err != nil {
		t.Fatal(err)
	}
	// simulate abrupt process death: close descriptors without commit,
	// rollback or reload. the next invocation must not mistake exact files for
	// a completed activation.
	if err := staged.(*linuxTransaction).close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	fixture.runner.calls = nil

	result, err := fixture.installer.Install(context.Background(), bytes.NewReader(envelope), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || fixture.runner.countExecutable(sshdPath) != 1 || fixture.runner.countExecutable(systemctlPath) != 1 {
		t.Fatalf("crash resume result=%+v calls=%+v", result, fixture.runner.calls)
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn), filepath.Dir(fixture.config.executable))
}

func TestLinuxInstallerRejectsSymlinkedStateRootWithoutFollowingIt(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixture.config.stateRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	chmodTree(t, fixture.config.anchor, filepath.Dir(fixture.config.stateRoot), 0o755)
	if err := os.Symlink(outside, fixture.config.stateRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); err == nil {
		t.Fatal("symlinked state root accepted")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "unchanged" {
		t.Fatalf("symlink target changed: %q %v", contents, err)
	}
}

func TestLinuxInstallerRejectsHardlinkedDropInBeforeMutation(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	external := filepath.Join(fixture.config.anchor, "external.conf")
	content := []byte("# Managed by Dynamicflow. attacker collision\n")
	if err := os.WriteFile(external, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, fixture.config.sshdDropIn); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("hardlink error = %v", err)
	}
	actual, err := os.ReadFile(external)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("hardlink target changed: %q %v", actual, err)
	}
	if fixture.runner.countExecutable(sshdPath) != 0 || fixture.runner.countExecutable(systemctlPath) != 0 {
		t.Fatalf("unsafe destination reached sshd/reload: %+v", fixture.runner.calls)
	}
}

func TestLinuxInstallerRequiresGlobalMainConfigDropInInclude(t *testing.T) {
	for _, main := range []string{
		"# no include\nPasswordAuthentication no\n",
		"Match User somebody\n    Include PLACEHOLDER/*.conf\n",
	} {
		fixture := newLinuxInstallerFixture(t)
		main = strings.ReplaceAll(main, "PLACEHOLDER", filepath.Dir(fixture.config.sshdDropIn))
		if err := os.WriteFile(fixture.config.sshdConfig, []byte(main), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
			t.Fatalf("unsafe main config accepted (%q): %v", main, err)
		}
		for _, path := range []string{fixture.config.executable, filepath.Join(fixture.config.stateRoot, ActiveBundleName), fixture.config.sshdDropIn} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe main config activated %s: %v", path, err)
			}
		}
	}
}

func TestLinuxInstallerRejectsSymlinkAndHardlinkRuntimeDestinations(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		fixture := newLinuxInstallerFixture(t)
		external := filepath.Join(fixture.config.anchor, "external-runtime")
		content := []byte("external executable\n")
		if err := os.WriteFile(external, content, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, fixture.config.executable); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
			t.Fatalf("symlink error = %v", err)
		}
		actual, err := os.ReadFile(external)
		if err != nil || !bytes.Equal(actual, content) {
			t.Fatalf("symlink target changed: %q %v", actual, err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		fixture := newLinuxInstallerFixture(t)
		external := filepath.Join(fixture.config.anchor, "external-runtime")
		content := []byte("external executable\n")
		if err := os.WriteFile(external, content, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(external, fixture.config.executable); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
			t.Fatalf("hardlink error = %v", err)
		}
		actual, err := os.ReadFile(external)
		if err != nil || !bytes.Equal(actual, content) {
			t.Fatalf("hardlink target changed: %q %v", actual, err)
		}
	})
}

func TestLinuxInstallerDetectsExecutableSourceSwapBeforeStaging(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	source := &linuxChangingExecutableSource{path: fixture.sourcePath, changeOnOpen: 2}
	fixture.platform.source = source
	_, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if !errors.Is(err, ErrInstallFailed) {
		t.Fatalf("source swap error = %v", err)
	}
	for _, path := range []string{fixture.config.executable, filepath.Join(fixture.config.stateRoot, ActiveBundleName), fixture.config.sshdDropIn} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source swap activated %s: %v", path, err)
		}
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn), filepath.Dir(fixture.config.executable))
}

func TestLinuxInstallerRejectsOversizedExecutableBeforeStaging(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	if err := os.Truncate(fixture.sourcePath, maxRuntimeBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("oversized executable error = %v", err)
	}
	if _, err := os.Lstat(fixture.config.executable); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized runtime activated: %v", err)
	}
}

func TestLinuxInstallerRejectsHardlinkedActiveFileWithoutReplacingIt(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	envelope := installerEnvelope(t, 3)
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(envelope), installerRequest(3)); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(fixture.config.stateRoot, ActiveBundleName, "authorized_keys")
	if err := os.Remove(authorized); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(fixture.config.anchor, "external-keys")
	content := []byte("external must remain unchanged\n")
	if err := os.WriteFile(external, content, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, authorized); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(envelope), installerRequest(3)); !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("hardlinked active file error = %v", err)
	}
	actual, err := os.ReadFile(external)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("external hardlink changed: %q %v", actual, err)
	}
}

func TestLinuxInstallerCreatesOnlyFixedLockedNonRootAccount(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	fixture.runner.accountExists = false
	fixture.runner.accountLocked = false
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3)); err != nil {
		t.Fatal(err)
	}
	wantUseradd := []string{
		"--system", "--user-group", "--home-dir", fixture.config.stateRoot,
		"--no-create-home", "--shell", managementShell, ManagementUser,
	}
	wantPasswordDisable := []string{"--password", disabledPasswordMarker, ManagementUser}
	foundCreate, foundLock := false, false
	for _, call := range fixture.runner.calls {
		if call.stdinWasSet {
			t.Fatalf("command received stdin: %+v", call)
		}
		if call.executable == "/bin/sh" || call.executable == "/bin/bash" {
			t.Fatalf("shell invoked: %+v", call)
		}
		switch call.executable {
		case useraddPath:
			foundCreate = reflect.DeepEqual(call.arguments, wantUseradd)
		case usermodPath:
			foundLock = reflect.DeepEqual(call.arguments, wantPasswordDisable)
		}
		joined := strings.Join(call.arguments, " ")
		if strings.Contains(joined, "PRIVATE") || strings.Contains(joined, "ssh-ed25519") || strings.Contains(joined, "permitopen") {
			t.Fatalf("policy/key material reached argv: %+v", call)
		}
	}
	if !foundCreate || !foundLock || !fixture.runner.accountExists || !fixture.runner.accountLocked {
		t.Fatalf("account create/lock missing: calls=%+v", fixture.runner.calls)
	}
}

func TestLinuxInstallLockRejectsParallelMutationAndRecovers(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	first, err := fixture.platform.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.platform.AcquireLock(); err == nil {
		t.Fatal("parallel lock acquired")
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := fixture.platform.AcquireLock()
	if err != nil {
		t.Fatalf("lock did not recover: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

type linuxInstallerFixture struct {
	config     linuxConfig
	sourcePath string
	runner     *linuxFixtureRunner
	platform   *linuxPlatform
	installer  *Installer
}

func newLinuxInstallerFixture(t *testing.T) linuxInstallerFixture {
	t.Helper()
	anchor := t.TempDir()
	if err := os.Chmod(anchor, 0o755); err != nil {
		t.Fatal(err)
	}
	configuration := linuxConfig{
		anchor:     anchor,
		stateRoot:  filepath.Join(anchor, "var/lib/dynamicflow/control"),
		sshdConfig: filepath.Join(anchor, "etc/ssh/sshd_config"),
		sshdDropIn: filepath.Join(anchor, "etc/ssh/sshd_config.d/60-dynamicflow-control.conf"),
		executable: filepath.Join(anchor, "usr/local/bin/flow"),
		ownerUID:   uint32(os.Geteuid()), ownerGID: uint32(os.Getegid()),
		effectiveUID: func() int { return 0 },
	}
	sourcePath := filepath.Join(anchor, "bootstrap/flow-upload")
	for _, directory := range []string{filepath.Dir(configuration.sshdConfig), filepath.Dir(configuration.sshdDropIn), filepath.Dir(configuration.executable), filepath.Dir(sourcePath)} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		chmodTree(t, anchor, directory, 0o755)
	}
	mainConfig := "# isolated sshd config\nInclude " + filepath.Dir(configuration.sshdDropIn) + "/*.conf\n"
	if err := os.WriteFile(configuration.sshdConfig, []byte(mainConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("flow-test-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &linuxFixtureRunner{
		accountExists: true, accountLocked: true, accountHome: configuration.stateRoot,
		accountUID: 2201, accountGID: 2201,
	}
	platform := newLinuxPlatform(configuration, runner, linuxPathExecutableSource{path: sourcePath})
	return linuxInstallerFixture{
		config: configuration, sourcePath: sourcePath, runner: runner, platform: platform,
		installer: &Installer{platform: platform, now: func() time.Time { return runtimeTime }},
	}
}

type linuxPathExecutableSource struct{ path string }

func (source linuxPathExecutableSource) Open() (*os.File, error) { return os.Open(source.path) }
func (linuxPathExecutableSource) IsRunningExecutable() bool      { return false }

type linuxChangingExecutableSource struct {
	path         string
	opens        int
	changeOnOpen int
}

func (source *linuxChangingExecutableSource) Open() (*os.File, error) {
	source.opens++
	if source.opens == source.changeOnOpen {
		if err := os.WriteFile(source.path, []byte("changed-after-preflight\n"), 0o755); err != nil {
			return nil, err
		}
	}
	return os.Open(source.path)
}

func (*linuxChangingExecutableSource) IsRunningExecutable() bool { return false }

func chmodTree(t *testing.T, anchor, destination string, mode os.FileMode) {
	t.Helper()
	current := anchor
	relative, err := filepath.Rel(anchor, destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		if err := os.Chmod(current, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func assertManagedDirectory(t *testing.T, path string, uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		t.Fatalf("unsafe directory %s: %v %+v", path, err, info)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("unsafe directory owner %s: %+v", path, stat)
	}
}

func assertManagedFile(t *testing.T, path string, mode uint32, uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || uint32(info.Mode().Perm()) != mode {
		t.Fatalf("unsafe file %s: %v %+v", path, err, info)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 {
		t.Fatalf("unsafe file metadata %s: %+v", path, stat)
	}
}

func assertNoStageEntries(t *testing.T, directories ...string) {
	t.Helper()
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".stage-") || strings.HasPrefix(entry.Name(), ".sshd-pending-") ||
				strings.HasPrefix(entry.Name(), ".sshd-validation-") || strings.HasPrefix(entry.Name(), ".flow-pending-") {
				t.Fatalf("staging entry remains: %s", filepath.Join(directory, entry.Name()))
			}
		}
	}
}

func planPhaseChanges(plan InstallPlan, name string) bool {
	for _, phase := range plan.Phases {
		if phase.Name == name {
			return phase.WillChange
		}
	}
	return false
}

type linuxCommandCall struct {
	executable  string
	arguments   []string
	stdinWasSet bool
}

type linuxFixtureRunner struct {
	calls         []linuxCommandCall
	accountExists bool
	accountLocked bool
	accountHome   string
	accountUID    uint64
	accountGID    uint64
	sshdErrors    []error
	reloadErrors  []error
}

func (runner *linuxFixtureRunner) Run(_ context.Context, executable string, arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	runner.calls = append(runner.calls, linuxCommandCall{
		executable: executable, arguments: append([]string(nil), arguments...), stdinWasSet: stdin != nil,
	})
	switch executable {
	case getentPath:
		if !runner.accountExists {
			return linuxTestExitError{code: 2}
		}
		if reflect.DeepEqual(arguments, []string{"passwd", ManagementUser}) {
			_, _ = io.WriteString(stdout, ManagementUser+":x:"+
				strconvFormat(runner.accountUID)+":"+strconvFormat(runner.accountGID)+
				":Dynamicflow Control:"+runner.accountHome+":"+managementShell+"\n")
		} else if reflect.DeepEqual(arguments, []string{"shadow", ManagementUser}) {
			marker := "!unsafe-locked-hash"
			if runner.accountLocked {
				marker = disabledPasswordMarker
			}
			_, _ = io.WriteString(stdout, ManagementUser+":"+marker+":20657:0:99999:7:::\n")
		} else {
			return errors.New("unexpected getent arguments")
		}
	case useraddPath:
		runner.accountExists = true
		runner.accountLocked = true
	case usermodPath:
		runner.accountLocked = true
	case sshdPath:
		if len(runner.sshdErrors) > 0 {
			err := runner.sshdErrors[0]
			runner.sshdErrors = runner.sshdErrors[1:]
			_, _ = io.WriteString(stderr, "discarded sshd diagnostic with sensitive text")
			return err
		}
	case systemctlPath:
		if len(runner.reloadErrors) > 0 {
			err := runner.reloadErrors[0]
			runner.reloadErrors = runner.reloadErrors[1:]
			_, _ = io.WriteString(stderr, "discarded reload diagnostic with sensitive text")
			return err
		}
	default:
		return errors.New("unexpected executable")
	}
	return nil
}

func (runner *linuxFixtureRunner) countExecutable(executable string) int {
	count := 0
	for _, call := range runner.calls {
		if call.executable == executable {
			count++
		}
	}
	return count
}

type linuxTestExitError struct{ code int }

func (problem linuxTestExitError) Error() string { return "command failed" }
func (problem linuxTestExitError) ExitCode() int { return problem.code }

func strconvFormat(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var encoded [20]byte
	position := len(encoded)
	for value > 0 {
		position--
		encoded[position] = digits[value%10]
		value /= 10
	}
	return string(encoded[position:])
}

func fixedInstallerEnvelope(t *testing.T, public ed25519.PublicKey, private ed25519.PrivateKey, generation uint64, expires time.Time) []byte {
	t.Helper()
	policy := runtimePolicy(false)
	policy.Generation = generation
	policy.IssuedAt = runtimeTime.Add(-time.Minute)
	policy.ExpiresAt = expires
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
