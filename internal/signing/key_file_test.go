package signing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestKeyLoadRejectsParentSymlinkHardlinkAndUnsafePublicMode(t *testing.T) {
	for _, scenario := range []string{"parent symlink", "hardlink", "public mode"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			private, public := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.pem")
			if _, err := GenerateFiles(private, public); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "parent symlink":
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				private, public = filepath.Join(link, "private.pem"), filepath.Join(link, "public.pem")
			case "hardlink":
				for _, path := range []string{private, public} {
					if err := os.Link(path, path+".alias"); err != nil {
						t.Fatal(err)
					}
				}
			case "public mode":
				if err := os.Chmod(public, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadPublicFile(public); !errors.Is(err, ErrUnsafeKeyFile) {
				t.Fatalf("unsafe public key accepted: %v", err)
			}
			if scenario != "public mode" {
				if _, err := LoadPrivateFile(private); !errors.Is(err, ErrUnsafeKeyFile) {
					t.Fatalf("unsafe private key accepted: %v", err)
				}
			}
		})
	}
}

func TestKeyLoadRejectsSpecialAndOversizedFiles(t *testing.T) {
	for _, scenario := range []string{"fifo", "directory", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			var err error
			switch scenario {
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "oversize":
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxKeyFileBytes+1), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPrivateFile(path); !errors.Is(err, ErrUnsafeKeyFile) {
				t.Fatalf("unsafe private key accepted: %v", err)
			}
			if _, err := LoadPublicFile(path); !errors.Is(err, ErrUnsafeKeyFile) {
				t.Fatalf("unsafe public key accepted: %v", err)
			}
		})
	}
}
