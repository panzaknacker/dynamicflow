package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRejectsSymlinksAndUnsafeManagedParents(t *testing.T) {
	for _, test := range []struct {
		name    string
		changed string
		symlink bool
		wanted  error
	}{
		{name: "final symlink", changed: "first/second/document.json", symlink: true, wanted: ErrSymlink},
		{name: "parent symlink", changed: "first/second", symlink: true, wanted: ErrSymlink},
		{name: "grandparent symlink", changed: "first", symlink: true, wanted: ErrSymlink},
		{name: "unsafe parent", changed: "first/second", wanted: ErrInsecureMode},
		{name: "unsafe grandparent", changed: "first", wanted: ErrInsecureMode},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			store, err := Open(filepath.Join(base, "state"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(store.Root(), "first/second"), DirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Root(), "first/second/document.json"), []byte(`{"private":"state"}`), FileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadFile("first/second/document.json"); err != nil {
				t.Fatalf("valid private chain rejected: %v", err)
			}
			changed := filepath.Join(store.Root(), test.changed)
			if test.symlink {
				outside := filepath.Join(base, "outside")
				if err := os.Rename(changed, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, changed); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Chmod(changed, 0o777); err != nil {
				t.Fatal(err)
			}
			data, err := store.ReadFile("first/second/document.json")
			if !errors.Is(err, test.wanted) || data != nil {
				t.Fatalf("unsafe read returned data=%q err=%v, want %v", data, err, test.wanted)
			}
		})
	}
}

func TestReadFileRejectsRootReplacementAfterOpen(t *testing.T) {
	for _, scenario := range []string{"root symlink", "root directory", "ancestor symlink", "unsafe root", "missing root"} {
		t.Run(scenario, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			store, err := Open(filepath.Join(parent, "state"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Root(), "document.json"), []byte("original"), FileMode); err != nil {
				t.Fatal(err)
			}
			wanted := ErrSymlink
			switch scenario {
			case "root symlink", "root directory", "missing root":
				saved := filepath.Join(base, "original-root")
				if err := os.Rename(store.Root(), saved); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "root symlink":
					if err := os.Symlink(saved, store.Root()); err != nil {
						t.Fatal(err)
					}
				case "root directory":
					if err := os.Mkdir(store.Root(), DirMode); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(store.Root(), "document.json"), []byte("replacement"), FileMode); err != nil {
						t.Fatal(err)
					}
					wanted = ErrInvalidPath
				case "missing root":
					wanted = ErrInvalidPath
				}
			case "ancestor symlink":
				saved := filepath.Join(base, "original-parent")
				if err := os.Rename(parent, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(saved, parent); err != nil {
					t.Fatal(err)
				}
			case "unsafe root":
				if err := os.Chmod(store.Root(), 0o755); err != nil {
					t.Fatal(err)
				}
				wanted = ErrInsecureMode
			}
			data, err := store.ReadFile("document.json")
			if !errors.Is(err, wanted) || data != nil {
				t.Fatalf("changed-root read returned data=%q err=%v, want %v", data, err, wanted)
			}
			if scenario == "missing root" {
				if _, err := os.Lstat(store.Root()); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("read recreated missing root: %v", err)
				}
			}
		})
	}
}

func TestReadFileDoesNotCreateMissingParents(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFile("missing/parent/document.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created missing parent: %v", err)
	}
}

func TestReadFileRejectsFinalFIFOWithoutBlocking(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root(), "document.json")
	if err := syscall.Mkfifo(path, uint32(FileMode.Perm())); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.ReadFile("document.json")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("FIFO error=%v, want invalid path", err)
		}
	case <-time.After(2 * time.Second):
		// Release only this test's reader before reporting a blocking regression.
		if writer, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
			_ = syscall.Close(writer)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("reading a FIFO blocked before file-type validation")
	}
}
