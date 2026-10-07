//go:build linux

package controlruntime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestProductionRuntimeAcceptsRootAnchorWithoutAllowingRootDestination(t *testing.T) {
	platform := newLinuxPlatform(productionLinuxConfig(), nil)
	if err := platform.validateConfiguration(); err != nil {
		t.Fatalf("production configuration rejects its own filesystem anchor: %v", err)
	}
	// This exercises the real descriptor walk read-only, without requiring root
	// or creating files under /etc. An isolated test anchor cannot cover it.
	directory, err := openTrustedDirectory("/", "/etc", false, 0, 0)
	if err != nil {
		t.Fatalf("read-only production trust walk: %v", err)
	}
	directory.Close()
	if _, err := readProtectedFile("/", "/etc/passwd", 0, 0, maxLocalPasswdBytes); err != nil {
		t.Fatalf("read-only OS identity source: %v", err)
	}
	for _, anchor := range []string{"", ".", "//", "/etc/..", "/etc/"} {
		if safeTrustAnchor(anchor) {
			t.Fatalf("accepted noncanonical trust anchor %q", anchor)
		}
	}
	platform.config.stateRoot = "/"
	if err := platform.validateConfiguration(); !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("root installation destination accepted: %v", err)
	}
}

func TestManagementIdentityRequiresUniqueLocalAccountAndUID(t *testing.T) {
	valid := "root:x:0:0:root:/root:/bin/sh\n" + ManagementUser + ":x:1001:1001::/nonexistent:/bin/sh\n"
	if name, err := managementUsernameForUID([]byte(valid), 1001); err != nil || name != ManagementUser {
		t.Fatalf("name=%q err=%v", name, err)
	}
	for name, contents := range map[string]string{
		"empty":             "",
		"duplicate name":    valid + ManagementUser + ":x:1001:1001::/nonexistent:/bin/sh\n",
		"duplicate uid":     valid + "impostor:x:1001:1001::/nonexistent:/bin/sh\n",
		"numeric uid alias": valid + "impostor:x:01001:1001::/nonexistent:/bin/sh\n",
		"signed uid alias":  valid + "impostor:x:+1001:1001::/nonexistent:/bin/sh\n",
		"invalid uid":       valid + "impostor:x:invalid:1001::/nonexistent:/bin/sh\n",
		"overflow uid":      valid + "impostor:x:4294967296:1001::/nonexistent:/bin/sh\n",
		"wrong uid":         strings.Replace(valid, ":1001:1001:", ":1002:1001:", 1),
		"leading zero uid":  strings.Replace(valid, ":1001:1001:", ":01001:1001:", 1),
		"malformed":         valid + "broken:entry\n",
	} {
		t.Run(name, func(t *testing.T) {
			if username, err := managementUsernameForUID([]byte(contents), 1001); username != "" || err != ErrSessionDenied {
				t.Fatalf("username=%q err=%v", username, err)
			}
		})
	}
}

func TestActiveEnvelopeReadRejectsUnsafeFilesystemObjects(t *testing.T) {
	for _, mutation := range []string{"none", "symlink-file", "hardlink-file", "writable-file", "directory-file", "fifo-file", "symlink-active", "writable-parent", "outside-anchor"} {
		t.Run(mutation, func(t *testing.T) {
			anchor := t.TempDir()
			if err := os.Chmod(anchor, 0o755); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(anchor, "control")
			active := filepath.Join(root, ActiveBundleName)
			if err := os.MkdirAll(active, 0o755); err != nil {
				t.Fatal(err)
			}
			// Explicitly set modes because test hosts can have a restrictive umask.
			for _, path := range []string{root, active} {
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(active, "envelope.json")
			contents := []byte("bounded-public-fixture")
			if err := os.WriteFile(path, contents, 0o444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o444); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "symlink-file":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink-file":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "writable-file":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory-file", "fifo-file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mutation == "directory-file" {
					if err := os.Mkdir(path, 0o755); err != nil {
						t.Fatal(err)
					}
				} else if err := syscall.Mkfifo(path, 0o444); err != nil {
					t.Fatal(err)
				}
			case "symlink-active":
				if err := os.Rename(active, active+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(active+".original", active); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(root, 0o777); err != nil {
					t.Fatal(err)
				}
			case "outside-anchor":
				root = filepath.Join(anchor, "..", "outside")
			}
			data, err := readActiveEnvelopeAt(anchor, root, uint32(os.Getuid()), uint32(os.Getgid()))
			if mutation == "none" {
				if err != nil || !bytes.Equal(data, contents) {
					t.Fatalf("data=%q err=%v", data, err)
				}
			} else if !errors.Is(err, ErrUnsafeHost) || len(data) != 0 {
				t.Fatalf("unsafe %s returned data=%q err=%v", mutation, data, err)
			}
		})
	}
}
