package targetapply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"dynamicflow/internal/applyplan"
)

func TestRuntimeStageActivateAndIdempotence(t *testing.T) {
	payload := []byte("\x7fELF\x02\x01\x01\x00raw-flow-runtime")
	artifact := runtimeTestArtifact(payload)
	recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
	defer recovery.Close()
	destination := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "bin"))
	defer destination.Close()
	uid := uint32(os.Geteuid())
	fetches := 0
	fetch := func(_ context.Context, got applyplan.Artifact, writer io.Writer) error {
		fetches++
		if got != artifact {
			t.Fatalf("fetched artifact = %#v, want %#v", got, artifact)
		}
		_, err := writer.Write(payload)
		return err
	}

	name, err := stageRuntimeArtifact(context.Background(), recovery, artifact, fetch, uid)
	if err != nil {
		t.Fatal(err)
	}
	if name != hex.EncodeToString(sha256Digest(payload))+".flow" || fetches != 1 {
		t.Fatalf("recovery name=%q fetches=%d", name, fetches)
	}
	if err := verifyNamedRuntimeFile(recovery, name, artifact, runtimeRecoveryMode, uid); err != nil {
		t.Fatalf("recovery verification: %v", err)
	}
	writeRuntimeTestFile(t, destination, "flow", []byte("old-runtime"), runtimeInstalledMode)
	if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := readRuntimeTestFile(t, destination, "flow"); !bytes.Equal(got, payload) {
		t.Fatalf("installed bytes = %q, want raw payload", got)
	}
	before := statRuntimeTestFile(t, destination, "flow")
	if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, fetch, uid); err != nil {
		t.Fatal(err)
	}
	if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	after := statRuntimeTestFile(t, destination, "flow")
	if fetches != 1 || before.Ino != after.Ino || before.Mtim != after.Mtim {
		t.Fatalf("idempotent retry changed runtime: fetches=%d before=%#v after=%#v", fetches, before, after)
	}
	secondPayload := []byte("a-newer-signed-runtime")
	secondArtifact := runtimeTestArtifact(secondPayload)
	secondName, err := stageRuntimeArtifact(context.Background(), recovery, secondArtifact, runtimePayloadFetcher(secondPayload), uid)
	if err != nil {
		t.Fatal(err)
	}
	if secondName == name || verifyNamedRuntimeFile(recovery, name, artifact, runtimeRecoveryMode, uid) != nil ||
		verifyNamedRuntimeFile(recovery, secondName, secondArtifact, runtimeRecoveryMode, uid) != nil {
		t.Fatal("recovery copies were not retained independently per digest")
	}
}

func TestRuntimeActivationCrashBoundariesResumeSafely(t *testing.T) {
	payload := []byte("new-flow-runtime")
	artifact := runtimeTestArtifact(payload)
	crash := errors.New("simulated crash boundary")
	for _, test := range []struct {
		name       string
		hooks      runtimeUpdateHooks
		wantActive bool
	}{
		{"before rename", runtimeUpdateHooks{beforeRename: func() error { return crash }}, false},
		{"after rename", runtimeUpdateHooks{afterRename: func() error { return crash }}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
			defer recovery.Close()
			destination := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "bin"))
			defer destination.Close()
			uid := uint32(os.Geteuid())
			if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(payload), uid); err != nil {
				t.Fatal(err)
			}
			writeRuntimeTestFile(t, destination, "flow", []byte("old-flow-runtime"), runtimeInstalledMode)
			err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, test.hooks)
			if !errors.Is(err, crash) {
				t.Fatalf("activation error = %v, want crash boundary", err)
			}
			active := bytes.Equal(readRuntimeTestFile(t, destination, "flow"), payload)
			if active != test.wantActive {
				t.Fatalf("active after boundary=%t, want %t", active, test.wantActive)
			}
			if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := readRuntimeTestFile(t, destination, "flow"); !bytes.Equal(got, payload) {
				t.Fatalf("resume installed %q", got)
			}
		})
	}
}

func TestRuntimeActivationPreservesInitialExecutableForManualRecovery(t *testing.T) {
	oldPayload := []byte("known-working-initial-flow")
	newPayload := []byte("signed-new-flow")
	artifact := runtimeTestArtifact(newPayload)
	uid := uint32(os.Geteuid())
	recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
	defer recovery.Close()
	destination := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "bin"))
	defer destination.Close()
	writeRuntimeTestFile(t, destination, "flow", oldPayload, runtimeInstalledMode)
	if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(newPayload), uid); err != nil {
		t.Fatal(err)
	}

	if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	oldDigest := sha256.Sum256(oldPayload)
	oldName := hex.EncodeToString(oldDigest[:]) + ".flow"
	if err := verifyNamedRuntimeContent(recovery, oldName, "sha256:"+hex.EncodeToString(oldDigest[:]), int64(len(oldPayload)), runtimeRecoveryMode, uid); err != nil {
		t.Fatalf("initial executable recovery missing or unsafe: %v", err)
	}
	if got := readRuntimeTestFile(t, destination, "flow"); !bytes.Equal(got, newPayload) {
		t.Fatalf("new runtime not activated: %q", got)
	}
	if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
	if err := verifyNamedRuntimeContent(recovery, oldName, "sha256:"+hex.EncodeToString(oldDigest[:]), int64(len(oldPayload)), runtimeRecoveryMode, uid); err != nil {
		t.Fatalf("idempotent activation lost initial recovery: %v", err)
	}
}

func TestRuntimeActivationRejectsSymlinksAndHardlinks(t *testing.T) {
	payload := []byte("verified-flow-runtime")
	artifact := runtimeTestArtifact(payload)
	uid := uint32(os.Geteuid())

	t.Run("destination symlink", func(t *testing.T) {
		recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
		defer recovery.Close()
		destinationPath := filepath.Join(t.TempDir(), "bin")
		destination := openRuntimeTestDirectory(t, destinationPath)
		defer destination.Close()
		if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(payload), uid); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sentinel, filepath.Join(destinationPath, "flow")); err != nil {
			t.Fatal(err)
		}
		if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); !errors.Is(err, ErrArtifactVerification) {
			t.Fatalf("symlink error = %v", err)
		}
		if data, _ := os.ReadFile(sentinel); string(data) != "untouched" {
			t.Fatalf("symlink target changed: %q", data)
		}
	})

	t.Run("destination hardlink", func(t *testing.T) {
		recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
		defer recovery.Close()
		destinationPath := filepath.Join(t.TempDir(), "bin")
		destination := openRuntimeTestDirectory(t, destinationPath)
		defer destination.Close()
		if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(payload), uid); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, []byte("old-flow"), os.FileMode(runtimeInstalledMode)); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(sentinel, filepath.Join(destinationPath, "flow")); err != nil {
			t.Fatal(err)
		}
		if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); !errors.Is(err, ErrArtifactVerification) {
			t.Fatalf("hardlink error = %v", err)
		}
		if data, _ := os.ReadFile(sentinel); string(data) != "old-flow" {
			t.Fatalf("hardlink target changed: %q", data)
		}
	})

	t.Run("recovery symlink", func(t *testing.T) {
		recoveryPath := filepath.Join(t.TempDir(), "recovery")
		recovery := openRuntimeTestDirectory(t, recoveryPath)
		defer recovery.Close()
		name, _ := runtimeRecoveryName(artifact)
		sentinel := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(sentinel, payload, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sentinel, filepath.Join(recoveryPath, name)); err != nil {
			t.Fatal(err)
		}
		fetches := 0
		_, err := stageRuntimeArtifact(context.Background(), recovery, artifact, func(context.Context, applyplan.Artifact, io.Writer) error {
			fetches++
			return nil
		}, uid)
		if !errors.Is(err, ErrArtifactVerification) || fetches != 0 {
			t.Fatalf("recovery symlink error=%v fetches=%d", err, fetches)
		}
	})
}

func TestRuntimeDirectoryFDDefeatsPathSwap(t *testing.T) {
	payload := []byte("verified-runtime")
	artifact := runtimeTestArtifact(payload)
	uid := uint32(os.Geteuid())
	recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
	defer recovery.Close()
	if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(payload), uid); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	original := filepath.Join(root, "bin")
	destination := openRuntimeTestDirectory(t, original)
	defer destination.Close()
	writeRuntimeTestFile(t, destination, "flow", []byte("old-runtime"), runtimeInstalledMode)
	moved := filepath.Join(root, "bin-held-by-fd")
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(root, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attacker, "flow"), []byte("sentinel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, original); err != nil {
		t.Fatal(err)
	}
	if err := activateRuntimeFromDirectories(recovery, destination, artifact, uid, runtimeUpdateHooks{}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(attacker, "flow")); string(data) != "sentinel" {
		t.Fatalf("path-swapped destination changed: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(moved, "flow")); !bytes.Equal(data, payload) {
		t.Fatalf("held directory did not receive runtime: %q", data)
	}
}

func TestRuntimeStageRejectsTamperAndOverflow(t *testing.T) {
	payload := []byte("signed-runtime")
	artifact := runtimeTestArtifact(payload)
	uid := uint32(os.Geteuid())
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{"digest mismatch", []byte("tampered-runtime")},
		{"signed size overflow", append(append([]byte(nil), payload...), '!')},
	} {
		t.Run(test.name, func(t *testing.T) {
			recovery := openRuntimeTestDirectory(t, filepath.Join(t.TempDir(), "recovery"))
			defer recovery.Close()
			if _, err := stageRuntimeArtifact(context.Background(), recovery, artifact, runtimePayloadFetcher(test.payload), uid); !errors.Is(err, ErrArtifactVerification) {
				t.Fatalf("stage error = %v", err)
			}
			name, _ := runtimeRecoveryName(artifact)
			if _, err := syscall.Openat(int(recovery.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0); !errors.Is(err, syscall.ENOENT) {
				t.Fatalf("invalid recovery artifact remained: %v", err)
			}
		})
	}
}

func runtimeTestArtifact(payload []byte) applyplan.Artifact {
	digest := sha256.Sum256(payload)
	return applyplan.Artifact{
		Component: "flow", Version: "v1.2.3", Target: "linux-amd64",
		Path: "flow/v1.2.3/linux-amd64/flow", Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(payload)),
	}
}

func runtimePayloadFetcher(payload []byte) FetchArtifact {
	return func(_ context.Context, _ applyplan.Artifact, writer io.Writer) error {
		_, err := writer.Write(payload)
		return err
	}
}

func sha256Digest(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return digest[:]
}

func openRuntimeTestDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		t.Fatal("open test directory")
	}
	return file
}

func writeRuntimeTestFile(t *testing.T, directory *os.File, name string, payload []byte, mode uint32) {
	t.Helper()
	fd, err := syscall.Openat(int(directory.Fd()), name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := file.Write(payload); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Sync(); err != nil {
		t.Fatal(err)
	}
}

func readRuntimeTestFile(t *testing.T, directory *os.File, name string) []byte {
	t.Helper()
	file, err := openNamedRuntimeFile(directory, name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func statRuntimeTestFile(t *testing.T, directory *os.File, name string) syscall.Stat_t {
	t.Helper()
	file, err := openNamedRuntimeFile(directory, name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &details); err != nil {
		t.Fatal(err)
	}
	return details
}
