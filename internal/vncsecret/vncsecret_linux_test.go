//go:build linux

package vncsecret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

const (
	oldPassword = "OldPass1"
	oldEncoded  = "OLDCRYPT"
	newEncoded  = "NEWCRYPT"
)

type fixture struct {
	cfg    config
	root   string
	home   string
	events []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base, err := os.MkdirTemp(".", ".vncsecret-test-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(abs) })
	root := filepath.Join(abs, "root")
	home := filepath.Join(abs, "home")
	for _, dir := range []string{root, home, filepath.Join(home, ".vnc"), filepath.Join(home, ".config"), filepath.Join(home, ".config", "tigervnc")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureFile(t, filepath.Join(root, managedSecretName), []byte(oldPassword+"\n"))
	writeFixtureFile(t, filepath.Join(home, ".vnc", "passwd"), []byte(oldEncoded))
	writeFixtureFile(t, filepath.Join(home, ".config", "tigervnc", "passwd"), []byte(oldEncoded))
	item := &fixture{root: root, home: home}
	item.cfg = config{
		secretDir: root,
		homeDir:   home,
		rootUID:   os.Getuid(),
		rootGID:   os.Getgid(),
		uid:       os.Getuid(),
		gid:       os.Getgid(),
		random:    bytes.NewReader(make([]byte, 4096)),
		filter: func(password []byte) ([]byte, error) {
			switch string(password) {
			case oldPassword:
				return []byte(oldEncoded), nil
			case "AAAAAAAA":
				return []byte(newEncoded), nil
			default:
				t.Fatalf("unexpected password %q", password)
				return nil, errors.New("unexpected password")
			}
		},
		service: func(action string) error {
			item.events = append(item.events, action)
			return nil
		},
		validate: func(legacy, modern string, expected []byte) error {
			item.events = append(item.events, "validate")
			if legacy != filepath.Join(home, ".vnc") || modern != filepath.Join(home, ".config", "tigervnc") || string(expected) != newEncoded && string(expected) != oldEncoded {
				t.Fatalf("unexpected validation values: %q %q %q", legacy, modern, expected)
			}
			return nil
		},
	}
	return item
}

func TestRevealValidatesFormatModeAndLinks(t *testing.T) {
	item := newFixture(t)
	value, err := reveal(item.cfg)
	if err != nil || string(value) != oldPassword {
		t.Fatalf("reveal=%q err=%v", value, err)
	}
	clear(value)

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *fixture)
	}{
		{"symlink", func(t *testing.T, f *fixture) {
			path := filepath.Join(f.root, managedSecretName)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, f *fixture) {
			if err := os.Link(filepath.Join(f.root, managedSecretName), filepath.Join(f.root, "second")); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode", func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Join(f.root, managedSecretName), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"format", func(t *testing.T, f *fixture) {
			writeFixtureFile(t, filepath.Join(f.root, managedSecretName), []byte("not-valid\n"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newFixture(t)
			test.mutate(t, candidate)
			if value, err := reveal(candidate.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
				t.Fatalf("value=%q err=%v", value, err)
			}
		})
	}
}

func TestRevealRejectsCredentialThatDoesNotMatchRuntimePasswordFiles(t *testing.T) {
	item := newFixture(t)
	writeFixtureFile(t, filepath.Join(item.home, ".config", "tigervnc", "passwd"), []byte("DRIFTED!"))
	if value, err := reveal(item.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestRotateAtomicallyUpdatesAllFilesAndModes(t *testing.T) {
	item := newFixture(t)
	value, err := rotate(item.cfg)
	if err != nil || string(value) != "AAAAAAAA" {
		t.Fatalf("rotate=%q err=%v", value, err)
	}
	if reflect.DeepEqual(item.events, []string{"stop", "restart", "active", "validate"}) == false {
		t.Fatalf("events=%v", item.events)
	}
	assertFixtureFile(t, filepath.Join(item.root, managedSecretName), []byte("AAAAAAAA\n"), os.Getuid(), os.Getgid())
	assertFixtureFile(t, filepath.Join(item.home, ".vnc", "passwd"), []byte(newEncoded), os.Getuid(), os.Getgid())
	assertFixtureFile(t, filepath.Join(item.home, ".config", "tigervnc", "passwd"), []byte(newEncoded), os.Getuid(), os.Getgid())
}

func TestRotateRejectsRuntimeSymlinkHardlinkAndWrongMode(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *fixture)
	}{
		{"symlink directory", func(t *testing.T, f *fixture) {
			path := filepath.Join(f.home, ".vnc")
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink file", func(t *testing.T, f *fixture) {
			if err := os.Link(filepath.Join(f.home, ".vnc", "passwd"), filepath.Join(f.home, ".vnc", "other")); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong file mode", func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Join(f.home, ".vnc", "passwd"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := newFixture(t)
			test.mutate(t, item)
			if value, err := rotate(item.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
				t.Fatalf("value=%q err=%v", value, err)
			}
			if len(item.events) != 0 {
				t.Fatalf("service touched on unsafe preflight: %v", item.events)
			}
		})
	}
}

func TestRotatePartialCommitRollsBackVerifiedBytes(t *testing.T) {
	item := newFixture(t)
	item.cfg.hook = func(phase string) error {
		if phase == "after_replace_0" {
			return errors.New("injected partial failure")
		}
		return nil
	}
	if value, err := rotate(item.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
		t.Fatalf("value=%q err=%v", value, err)
	}
	assertOldFiles(t, item)
	if !reflect.DeepEqual(item.events, []string{"stop", "stop", "restart", "active", "validate"}) {
		t.Fatalf("events=%v", item.events)
	}
}

func TestRotateServiceFailureRollsBackAndRestartsOldCredential(t *testing.T) {
	item := newFixture(t)
	restarts := 0
	item.cfg.service = func(action string) error {
		item.events = append(item.events, action)
		if action == "restart" {
			restarts++
			if restarts == 1 {
				return errors.New("injected restart failure")
			}
		}
		return nil
	}
	item.cfg.validate = func(_, _ string, expected []byte) error {
		item.events = append(item.events, "validate")
		if string(expected) != oldEncoded {
			t.Fatalf("rollback validated wrong bytes: %q", expected)
		}
		return nil
	}
	if value, err := rotate(item.cfg); !errors.Is(err, ErrService) || value != nil {
		t.Fatalf("value=%q err=%v", value, err)
	}
	assertOldFiles(t, item)
	if !reflect.DeepEqual(item.events, []string{"stop", "restart", "stop", "restart", "active", "validate"}) {
		t.Fatalf("events=%v", item.events)
	}
}

func TestRotateDetectsPathSwapAndLeavesServiceStopped(t *testing.T) {
	item := newFixture(t)
	item.cfg.hook = func(phase string) error {
		if phase != "after_commit" {
			return nil
		}
		original := filepath.Join(item.home, ".vnc")
		if err := os.Rename(original, original+".swapped"); err != nil {
			return err
		}
		if err := os.Mkdir(original, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(original, "passwd"), []byte("ATTACKER"), 0o600)
	}
	if value, err := rotate(item.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
		t.Fatalf("value=%q err=%v", value, err)
	}
	assertFixtureFile(t, filepath.Join(item.root, managedSecretName), []byte(oldPassword+"\n"), os.Getuid(), os.Getgid())
	assertFixtureFile(t, filepath.Join(item.home, ".vnc.swapped", "passwd"), []byte(oldEncoded), os.Getuid(), os.Getgid())
	if !reflect.DeepEqual(item.events, []string{"stop", "stop", "stop"}) {
		t.Fatalf("events=%v", item.events)
	}
}

func TestRandomPasswordIsAlphanumericAndDifferent(t *testing.T) {
	value, err := randomPassword(bytes.NewReader(make([]byte, 4096)), []byte("BBBBBBBB"))
	if err != nil || string(value) != "AAAAAAAA" || !validSource(append(append([]byte(nil), value...), '\n')) {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if _, err := randomPassword(bytes.NewReader(nil), []byte(oldPassword)); err == nil {
		t.Fatal("empty entropy unexpectedly succeeded")
	}
}

func TestRevealRejectsConcurrentCredentialOperation(t *testing.T) {
	item := newFixture(t)
	root, err := openAbsoluteDirectory(item.root, os.Getuid(), os.Getgid(), 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	unlock, err := lock(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if value, err := reveal(item.cfg); !errors.Is(err, ErrUnsafeState) || value != nil {
		t.Fatalf("concurrent reveal value=%q err=%v", value, err)
	}
	unlock()
	value, err := reveal(item.cfg)
	if err != nil || string(value) != oldPassword {
		t.Fatalf("reveal after unlock value=%q err=%v", value, err)
	}
}

func assertOldFiles(t *testing.T, item *fixture) {
	t.Helper()
	assertFixtureFile(t, filepath.Join(item.root, managedSecretName), []byte(oldPassword+"\n"), os.Getuid(), os.Getgid())
	assertFixtureFile(t, filepath.Join(item.home, ".vnc", "passwd"), []byte(oldEncoded), os.Getuid(), os.Getgid())
	assertFixtureFile(t, filepath.Join(item.home, ".config", "tigervnc", "passwd"), []byte(oldEncoded), os.Getuid(), os.Getgid())
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFixtureFile(t *testing.T, path string, want []byte, uid, gid int) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s=%q err=%v want=%q", path, got, err, want)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		t.Fatalf("unsafe metadata for %s: uid=%d gid=%d mode=%o nlink=%d", path, stat.Uid, stat.Gid, stat.Mode&0o777, stat.Nlink)
	}
}
