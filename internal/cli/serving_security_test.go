package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestServingUnitLimitsWritesToPrivateStateAndReleaseRoot(t *testing.T) {
	stateRoot := "/var/lib/dynamicflow-serving"
	releaseRoot := filepath.Join(stateRoot, "verified-releases")
	unit := servingUnit(
		"/usr/local/bin/flow",
		filepath.Join(stateRoot, "config.json"),
		stateRoot,
		releaseRoot,
		defaultServingServiceUser,
		"991",
	)

	for _, line := range []string{
		"ReadOnlyPaths=" + stateRoot + "\n",
		"ReadWritePaths=" + filepath.Join(stateRoot, "private") + "\n",
		"ReadWritePaths=" + releaseRoot + "\n",
	} {
		if count := strings.Count(unit, line); count != 1 {
			t.Fatalf("systemd unit contains %q %d times, want exactly once:\n%s", line, count, unit)
		}
	}
	if strings.Contains(unit, "ReadWritePaths="+stateRoot+"\n") {
		t.Fatalf("systemd unit makes the complete state root writable:\n%s", unit)
	}
}

func TestServingConvergedModesExposeOnlyPublicVerificationInputs(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{fixture.input.StateRoot, 0o751},
		{fixture.input.ReleaseRoot, 0o755},
		{filepath.Join(fixture.input.ReleaseRoot, "sets"), 0o755},
		{filepath.Join(fixture.input.ReleaseRoot, "history"), 0o755},
		{filepath.Join(fixture.input.StateRoot, "trust"), 0o755},
		{filepath.Join(fixture.input.StateRoot, "trust", "release.public.pem"), 0o644},
		{filepath.Join(fixture.input.StateRoot, "trust", "desired-state.public.pem"), 0o644},
		{filepath.Join(fixture.input.StateRoot, "trust", "control.public.pem"), 0o644},
		{filepath.Join(fixture.input.StateRoot, "tls"), 0o750},
		{filepath.Join(fixture.input.StateRoot, "tls", "serving.key"), 0o640},
		{filepath.Join(fixture.input.StateRoot, "private"), 0o700},
		{filepath.Join(fixture.input.StateRoot, "config.json"), 0o640},
	} {
		info, err := os.Lstat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != item.mode {
			t.Fatalf("mode %s=%04o, want %04o", item.path, info.Mode().Perm(), item.mode)
		}
	}
}

func TestServingInputsRejectSystemdPathInjectionBeforeReconciliation(t *testing.T) {
	validState := "/var/lib/dynamicflow-serving"
	validRelease := validState + "/releases"
	validKeys := []string{"/operator/release.pem", "/operator/desired.pem", "/operator/control.pem"}
	for name, roots := range map[string][2]string{
		"state newline":   {validState + "\nReadWritePaths=/", validRelease},
		"release newline": {validState, validRelease + "\nBindReadWritePaths=/"},
		"state space":     {"/var/lib/dynamic flow", "/var/lib/dynamic flow/releases"},
		"release tab":     {validState, validState + "/release\troot"},
		"unclean state":   {"/var/lib/../lib/dynamicflow-serving", validRelease},
		"unclean release": {validState, validState + "/nested/../releases"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateServingInputs(roots[0], roots[1], "https://serving.example.test:8443", "127.0.0.1:8443", validKeys[0], validKeys[1], validKeys[2], defaultServingServiceUser); err == nil {
				t.Fatalf("unsafe systemd path pair was accepted: %#v", roots)
			}
		})
	}
	if err := validateServingInputs(validState, validRelease, "https://serving.example.test:8443", "127.0.0.1:8443", validKeys[0], validKeys[1], validKeys[2], defaultServingServiceUser); err != nil {
		t.Fatalf("valid serving inputs rejected: %v", err)
	}
}

func TestServingInputsRejectReleaseRootOverlapWithProtectedState(t *testing.T) {
	stateRoot := "/var/lib/dynamicflow-serving"
	validKeys := []string{"/operator/release.pem", "/operator/desired.pem", "/operator/control.pem"}
	for name, releaseRoot := range map[string]string{
		"state root":       stateRoot,
		"private":          filepath.Join(stateRoot, "private"),
		"below private":    filepath.Join(stateRoot, "private", "releases"),
		"trust":            filepath.Join(stateRoot, "trust"),
		"below trust":      filepath.Join(stateRoot, "trust", "releases"),
		"tls":              filepath.Join(stateRoot, "tls"),
		"below tls":        filepath.Join(stateRoot, "tls", "releases"),
		"config collision": filepath.Join(stateRoot, "config.json"),
		"script collision": filepath.Join(stateRoot, "bootstrap.sh", "releases"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateServingInputs(stateRoot, releaseRoot, "https://serving.example.test:8443", "127.0.0.1:8443", validKeys[0], validKeys[1], validKeys[2], defaultServingServiceUser); err == nil {
				t.Fatalf("protected serving state overlap was accepted: %s", releaseRoot)
			}
		})
	}
	for _, releaseRoot := range []string{
		filepath.Join(stateRoot, "releases"),
		filepath.Join(stateRoot, "custom", "verified-releases"),
	} {
		if err := validateServingInputs(stateRoot, releaseRoot, "https://serving.example.test:8443", "127.0.0.1:8443", validKeys[0], validKeys[1], validKeys[2], defaultServingServiceUser); err != nil {
			t.Fatalf("separate release subtree %q rejected: %v", releaseRoot, err)
		}
	}
}

func TestServingReleasePublishLockUsesServiceOwnershipAndRejectsHardlinks(t *testing.T) {
	releaseRoot := filepath.Join(t.TempDir(), "releases")
	if err := os.Mkdir(releaseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	if err := ensureReleasePublishLockOwned(releaseRoot, uid, gid); err != nil {
		t.Fatalf("create protected publication lock: %v", err)
	}
	lockPath := filepath.Join(releaseRoot, ".publish.lock")
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || metadata.Nlink != 1 ||
		int(metadata.Uid) != uid || int(metadata.Gid) != gid || info.Size() != 0 {
		t.Fatalf("unexpected publication lock metadata: mode=%v metadata=%#v size=%d", info.Mode(), metadata, info.Size())
	}
	if err := os.Link(lockPath, filepath.Join(releaseRoot, "lock-alias")); err != nil {
		t.Fatal(err)
	}
	if err := ensureReleasePublishLockOwned(releaseRoot, uid, gid); err == nil {
		t.Fatal("hard-linked publication lock was accepted")
	}
}

func TestServingAtomicWriteRepairsMetadataAndTrueNoopDoesNotMutate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := []byte("canonical serving config\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	changed, err := writeAtomicIfChanged(path, content, 0o640, uid, gid)
	if err != nil || !changed {
		t.Fatalf("metadata repair changed=%t err=%v", changed, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0o640 || int(metadata.Uid) != uid || int(metadata.Gid) != gid || metadata.Nlink != 1 {
		t.Fatalf("metadata was not repaired: mode=%v metadata=%#v", info.Mode(), metadata)
	}
	before := *metadata
	changed, err = writeAtomicIfChanged(path, content, 0o640, uid, gid)
	if err != nil || changed {
		t.Fatalf("converged write changed=%t err=%v", changed, err)
	}
	afterInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	after := afterInfo.Sys().(*syscall.Stat_t)
	if before.Ino != after.Ino || before.Ctim != after.Ctim || before.Mtim != after.Mtim {
		t.Fatalf("true no-op mutated target metadata: before=%#v after=%#v", before, *after)
	}
}

func TestServingAtomicWriteRejectsHardlinkAndSymlinkAncestors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	alias := filepath.Join(root, "config-alias.json")
	content := []byte("protected\n")
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAtomicIfChanged(path, content, 0o640, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("hard-linked serving control file was accepted")
	}
	external := t.TempDir()
	symlinkParent := filepath.Join(t.TempDir(), "redirect")
	if err := os.Symlink(external, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAtomicIfChanged(filepath.Join(symlinkParent, "config.json"), content, 0o640, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("symlinked serving control-file ancestor was accepted")
	}
	if entries, err := os.ReadDir(external); err != nil || len(entries) != 0 {
		t.Fatalf("unsafe write changed external directory: entries=%v err=%v", entries, err)
	}
}

func TestServingAtomicWriteNeverFollowsConcurrentSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "config.json")
	held := filepath.Join(root, ".config-held")
	external := filepath.Join(t.TempDir(), "outside")
	content := []byte("same canonical content\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(external, content, 0o611); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(external, 0o611); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stop:
				_ = os.Remove(target)
				_ = os.Rename(held, target)
				return
			default:
			}
			if os.Rename(target, held) == nil {
				_ = os.Symlink(external, target)
				runtime.Gosched()
				_ = os.Remove(target)
				_ = os.Rename(held, target)
			}
		}
	}()
	for attempt := 0; attempt < 1000; attempt++ {
		_, _ = writeAtomicIfChanged(target, content, 0o640, os.Geteuid(), os.Getegid())
	}
	close(stop)
	wait.Wait()
	info, err := os.Stat(external)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o611 {
		t.Fatalf("descriptor-relative write changed external symlink target to %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(external)
	if err != nil || !strings.EqualFold(string(data), string(content)) {
		t.Fatalf("descriptor-relative write changed external content: %q err=%v", data, err)
	}
}

func TestServingControlMetadataRejectsHardlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serving.crt")
	if err := os.WriteFile(path, []byte("certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".alias"); err != nil {
		t.Fatal(err)
	}
	if err := secureServingControlFile(path, 0o644, os.Getegid()); err == nil {
		t.Fatal("hard-linked control file was accepted for ownership repair")
	}
}

func TestServingDirectoryMetadataNeverFollowsConcurrentSymlink(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	target := filepath.Join(private, "status")
	held := filepath.Join(private, ".status-held")
	external := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(external, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(external, 0o711); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stop:
				_ = os.Remove(target)
				_ = os.Rename(held, target)
				return
			default:
			}
			if os.Rename(target, held) == nil {
				_ = os.Symlink(external, target)
				runtime.Gosched()
				_ = os.Remove(target)
				_ = os.Rename(held, target)
			}
		}
	}()
	for attempt := 0; attempt < 1000; attempt++ {
		_ = ensureAbsoluteDirectoryOwned(target, 0o700, os.Geteuid(), os.Getegid())
	}
	close(stop)
	wait.Wait()
	info, err := os.Stat(external)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o711 {
		t.Fatalf("descriptor traversal changed an external symlink target to %04o", info.Mode().Perm())
	}
}

func TestServingServiceUserIsFixedAndCannotBeRootOrLoginAccount(t *testing.T) {
	if !validServiceUser(defaultServingServiceUser) {
		t.Fatal("dedicated serving account was rejected")
	}
	for _, value := range []string{"root", "admin", "ubuntu", "custom-serving", ""} {
		if validServiceUser(value) {
			t.Fatalf("unsafe serving account accepted: %q", value)
		}
	}
}
