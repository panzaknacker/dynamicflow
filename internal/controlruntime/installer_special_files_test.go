//go:build linux

package controlruntime

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInstallerFileChecksRejectFIFOsWithoutBlocking(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	for name, check := range map[string]func(*os.File) error{
		"managed file": func(directory *os.File) error {
			_, err := managedFileExists(directory, "unsafe", 0o600, uid, gid)
			return err
		},
		"executable": func(directory *os.File) error {
			_, err := managedExecutableExists(directory, "unsafe", uid, gid)
			return err
		},
		"staging cleanup": func(directory *os.File) error {
			return removeStaleRegularAt(directory, "unsafe", uid, gid, 0o600)
		},
		"existing lock": func(directory *os.File) error {
			file, _, err := openOrCreateManagedFile(directory, "unsafe", 0o600, uid, gid)
			if file != nil {
				file.Close()
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "unsafe")
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			requirePromptFIFORejection(t, path, func() error { return check(directory) })
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatalf("unsafe special file was changed: info=%v err=%v", info, err)
			}
		})
	}
}

func TestLinuxRuntimeInspectionRejectsFIFOWithoutBlocking(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	if err := syscall.Mkfifo(fixture.config.executable, 0o755); err != nil {
		t.Fatal(err)
	}
	requirePromptFIFORejection(t, fixture.config.executable, func() error {
		_, _, err := fixture.platform.inspectRuntime()
		return err
	})
	if len(fixture.runner.calls) != 0 {
		t.Fatal("unsafe runtime reached a host command")
	}
}

func requirePromptFIFORejection(t *testing.T, path string, check func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- check() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafeHost) {
			t.Fatalf("special file was not rejected: %v", err)
		}
	case <-time.After(time.Second):
		// Release the intentionally malformed fixture's own reader on regression,
		// so failure cannot leave the package waiting forever on the FIFO.
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			syscall.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("special-file check could not be unblocked")
		}
		t.Fatal("special-file check blocked before validating its type")
	}
}
