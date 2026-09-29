package localstate

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestAtomicJSONAndPrivateModes(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	type document struct {
		Name string `json:"name"`
	}
	if err := store.WriteJSON("nested/document.json", document{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJSON("nested/document.json", document{Name: "second"}); err != nil {
		t.Fatal(err)
	}
	var got document
	if err := store.ReadJSON("nested/document.json", &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "second" {
		t.Fatalf("got %q, want second", got.Name)
	}
	path, _ := store.Path("nested/document.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != FileMode {
		t.Fatalf("file mode %04o, want %04o", mode, FileMode)
	}
}

func TestRejectsTraversalSymlinkAndBroadPermissions(t *testing.T) {
	base := t.TempDir()
	store, err := Open(filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Path("../escape"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("traversal error = %v", err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link, _ := store.Path("linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureDir("linked/child"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink error = %v", err)
	}

	insecure := filepath.Join(base, "insecure")
	if err := os.Mkdir(insecure, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(insecure); !errors.Is(err, ErrInsecureMode) {
		t.Fatalf("permission error = %v", err)
	}
}

func TestOpenRejectsSymlinkedAncestorWithoutCreatingOutsideState(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(link, "private", "state")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlinked ancestor error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state was created through symlinked ancestor: %v", err)
	}
}

func TestAppendJSONLIsRecordAtomic(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	const records = 24
	var wg sync.WaitGroup
	for i := 0; i < records; i++ {
		wg.Add(1)
		go func(value int) {
			defer wg.Done()
			if err := store.AppendJSONL("audit/events.jsonl", map[string]int{"value": value}); err != nil {
				t.Errorf("append: %v", err)
			}
		}(i)
	}
	wg.Wait()
	path, _ := store.Path("audit/events.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != records {
		t.Fatalf("got %d records, want %d", count, records)
	}
}

func TestWithTryLockFailsFastAndUsesSecureMetadata(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- store.WithLock("locks/release.lock", func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	called := false
	if err := store.WithTryLock("locks/release.lock", func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("try-lock error = %v, want ErrLockBusy", err)
	}
	if called {
		t.Fatal("busy try-lock invoked its protected operation")
	}
	path, _ := store.Path("locks/release.lock")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != FileMode || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		t.Fatalf("unsafe lock metadata: mode=%v stat=%+v", info.Mode(), stat)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := store.WithTryLock("locks/release.lock", func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("try-lock after release: %v", err)
	}
	if !called {
		t.Fatal("available try-lock did not invoke its protected operation")
	}
}

func TestLockRejectsSymlinkHardlinkAndWrongMode(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(t *testing.T, path string)
		wanted error
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, nil, FileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
			wanted: ErrSymlink,
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, nil, FileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, path+".second"); err != nil {
					t.Fatal(err)
				}
			},
			wanted: ErrInvalidPath,
		},
		{
			name: "wrong-mode",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, nil, FileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wanted: ErrInsecureMode,
		},
		{
			name: "fifo",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := syscall.Mkfifo(path, uint32(FileMode.Perm())); err != nil {
					t.Skipf("mkfifo unavailable: %v", err)
				}
			},
			wanted: ErrInvalidPath,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnsureDir("locks"); err != nil {
				t.Fatal(err)
			}
			path, _ := store.Path("locks/release.lock")
			test.setup(t, path)
			called := false
			err = store.WithTryLock("locks/release.lock", func() error {
				called = true
				return nil
			})
			if !errors.Is(err, test.wanted) {
				t.Fatalf("lock error = %v, want %v", err, test.wanted)
			}
			if called {
				t.Fatal("unsafe lock invoked its protected operation")
			}
		})
	}
}
