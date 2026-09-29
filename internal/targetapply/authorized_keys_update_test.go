package targetapply

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

func TestAuthorizedKeySetActivatesExactlyAndIdempotently(t *testing.T) {
	directory := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), ".ssh"))
	defer directory.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	oldKeys := authorizedKeyTestKeys(t, 1)
	newKeys := authorizedKeyTestKeys(t, 2)
	oldPayload, _ := canonicalAuthorizedKeys(oldKeys)
	newPayload, _ := canonicalAuthorizedKeys(newKeys)
	writeRuntimeTestFile(t, directory, "authorized_keys", oldPayload, 0o600)

	if err := activateAuthorizedKeySet(directory, newKeys, uid, gid, authorizedKeyUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := readRuntimeTestFile(t, directory, "authorized_keys"); string(got) != string(newPayload) {
		t.Fatalf("authorized_keys=%q, want exact signed set %q", got, newPayload)
	}
	before := statRuntimeTestFile(t, directory, "authorized_keys")
	if before.Mode&0o777 != 0o600 || before.Uid != uid || before.Gid != gid || before.Nlink != 1 {
		t.Fatalf("unsafe authorized_keys metadata: %#v", before)
	}
	if err := activateAuthorizedKeySet(directory, newKeys, uid, gid, authorizedKeyUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	after := statRuntimeTestFile(t, directory, "authorized_keys")
	if before.Ino != after.Ino || before.Mtim != after.Mtim {
		t.Fatalf("idempotent exact-set retry replaced file: before=%#v after=%#v", before, after)
	}

	rotated := authorizedKeyTestKeys(t, 1)
	rotatedPayload, _ := canonicalAuthorizedKeys(rotated)
	if err := activateAuthorizedKeySet(directory, rotated, uid, gid, authorizedKeyUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := readRuntimeTestFile(t, directory, "authorized_keys"); string(got) != string(rotatedPayload) {
		t.Fatalf("rotation retained an unauthorized key: %q", got)
	}
}

func TestAuthorizedKeySetCrashBoundariesResume(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	oldKeys := authorizedKeyTestKeys(t, 1)
	newKeys := authorizedKeyTestKeys(t, 2)
	oldPayload, _ := canonicalAuthorizedKeys(oldKeys)
	newPayload, _ := canonicalAuthorizedKeys(newKeys)
	crash := errors.New("simulated authorized_keys crash")
	for _, test := range []struct {
		name       string
		hooks      authorizedKeyUpdateHooks
		wantActive bool
	}{
		{"before rename", authorizedKeyUpdateHooks{beforeRename: func() error { return crash }}, false},
		{"after rename", authorizedKeyUpdateHooks{afterRename: func() error { return crash }}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), ".ssh"))
			defer directory.Close()
			writeRuntimeTestFile(t, directory, "authorized_keys", oldPayload, 0o600)
			err := activateAuthorizedKeySet(directory, newKeys, uid, gid, test.hooks)
			if !errors.Is(err, crash) {
				t.Fatalf("activation error=%v, want crash", err)
			}
			got := readRuntimeTestFile(t, directory, "authorized_keys")
			active := string(got) == string(newPayload)
			if active != test.wantActive {
				t.Fatalf("new exact set active=%t, want %t; content=%q", active, test.wantActive, got)
			}
			if !active && string(got) != string(oldPayload) {
				t.Fatalf("pre-rename crash exposed a partial set: %q", got)
			}
			if err := activateAuthorizedKeySet(directory, newKeys, uid, gid, authorizedKeyUpdateHooks{}); err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := readRuntimeTestFile(t, directory, "authorized_keys"); string(got) != string(newPayload) {
				t.Fatalf("resume did not activate exact set: %q", got)
			}
		})
	}
}

func TestAuthorizedKeySetVerifyRejectsPostInstallerDrift(t *testing.T) {
	directory := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), ".ssh"))
	defer directory.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	keys := authorizedKeyTestKeys(t, 2)
	payload, _ := canonicalAuthorizedKeys(keys)
	writeRuntimeTestFile(t, directory, "authorized_keys", payload, 0o600)

	if err := verifyAuthorizedKeySet(directory, keys, uid, gid); err != nil {
		t.Fatalf("exact signed set rejected: %v", err)
	}
	if err := syscall.Unlinkat(int(directory.Fd()), "authorized_keys"); err != nil {
		t.Fatal(err)
	}
	drifted, _ := canonicalAuthorizedKeys(keys[:1])
	writeRuntimeTestFile(t, directory, "authorized_keys", drifted, 0o600)
	if err := verifyAuthorizedKeySet(directory, keys, uid, gid); err == nil {
		t.Fatal("post-installer authorized_keys drift was accepted")
	}
}

func TestAuthorizedKeySetRejectsSymlinkAndHardlink(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	keys := authorizedKeyTestKeys(t, 2)

	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".ssh")
		directory := openRuntimeTestDirectory(t, path)
		defer directory.Close()
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sentinel, filepath.Join(path, "authorized_keys")); err != nil {
			t.Fatal(err)
		}
		if err := activateAuthorizedKeySet(directory, keys, uid, gid, authorizedKeyUpdateHooks{}); err == nil {
			t.Fatal("symlinked authorized_keys was accepted")
		}
		if got, _ := os.ReadFile(sentinel); string(got) != "untouched" {
			t.Fatalf("symlink target changed: %q", got)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".ssh")
		directory := openRuntimeTestDirectory(t, path)
		defer directory.Close()
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, []byte("old-set"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(sentinel, filepath.Join(path, "authorized_keys")); err != nil {
			t.Fatal(err)
		}
		if err := activateAuthorizedKeySet(directory, keys, uid, gid, authorizedKeyUpdateHooks{}); err == nil {
			t.Fatal("hardlinked authorized_keys was accepted")
		}
		if got, _ := os.ReadFile(sentinel); string(got) != "old-set" {
			t.Fatalf("hardlink target changed: %q", got)
		}
	})

	t.Run("temporary symlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".ssh")
		directory := openRuntimeTestDirectory(t, path)
		defer directory.Close()
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sentinel, filepath.Join(path, authorizedKeysTemporaryName)); err != nil {
			t.Fatal(err)
		}
		if err := activateAuthorizedKeySet(directory, keys, uid, gid, authorizedKeyUpdateHooks{}); err == nil {
			t.Fatal("symlinked temporary authorized_keys was accepted")
		}
		if got, _ := os.ReadFile(sentinel); string(got) != "untouched" {
			t.Fatalf("temporary symlink target changed: %q", got)
		}
	})
}

func TestAuthorizedKeySetRequiresCanonicalUniqueOrder(t *testing.T) {
	directory := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), ".ssh"))
	defer directory.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	keys := authorizedKeyTestKeys(t, 2)
	for _, test := range []struct {
		name string
		keys []string
	}{
		{"reverse order", []string{keys[1], keys[0]}},
		{"duplicate", []string{keys[0], keys[0]}},
		{"invalid", []string{"ssh-ed25519 invalid"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := activateAuthorizedKeySet(directory, test.keys, uid, gid, authorizedKeyUpdateHooks{}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error=%v, want ErrInvalidConfig", err)
			}
		})
	}
	if _, err := syscall.Openat(int(directory.Fd()), "authorized_keys", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("invalid set created authorized_keys: %v", err)
	}
}

func TestSSHDirectoryFDDefeatsHomePathSwap(t *testing.T) {
	root := t.TempDir()
	homePath := filepath.Join(root, "home")
	home := openRuntimeTestDirectory(t, homePath)
	defer home.Close()
	moved := filepath.Join(root, "home-held-by-fd")
	if err := os.Rename(homePath, moved); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(root, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, homePath); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	sshDirectory, err := openOrCreateSSHDirectory(home, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer sshDirectory.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(int(sshDirectory.Fd()), &details); err != nil || details.Mode&0o777 != 0o700 || details.Uid != uid || details.Gid != gid {
		t.Fatalf("unsafe created .ssh metadata: err=%v stat=%#v", err, details)
	}
	if _, err := os.Lstat(filepath.Join(attacker, ".ssh")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path-swapped home received .ssh: %v", err)
	}
	if info, err := os.Stat(filepath.Join(moved, ".ssh")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("held home did not receive safe .ssh: info=%v err=%v", info, err)
	}
}

func authorizedKeyTestKeys(t *testing.T, count int) []string {
	t.Helper()
	keys := make([]string, 0, count)
	for len(keys) < count {
		candidate := testPlan(t, "ssh").AuthorizedSSHKeys[0]
		duplicate := false
		for _, key := range keys {
			duplicate = duplicate || key == candidate
		}
		if !duplicate {
			keys = append(keys, candidate)
		}
	}
	sort.Strings(keys)
	return keys
}
