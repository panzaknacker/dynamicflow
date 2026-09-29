package targetapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"dynamicflow/internal/applyplan"
)

const (
	runtimeBinaryPath             = "/usr/local/bin/flow"
	maxRuntimeArtifactSize int64  = 256 << 20
	runtimeRecoveryMode    uint32 = 0o700
	runtimeInstalledMode   uint32 = 0o755
)

type runtimeUpdateHooks struct {
	beforeRename func() error
	afterRename  func() error
}

func (r *runner) ensureRuntimeArtifact(ctx context.Context, artifact applyplan.Artifact) (string, error) {
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("%w: runtime update requires root", ErrArtifactVerification)
	}
	// persist the newly created recovery-directory entry before any installed
	// binary can point at bytes whose recovery copy could disappear on reboot.
	parent, err := openTrustedAbsoluteDirectory(filepath.Dir(r.runtimeRecoveryDir), true)
	if err != nil {
		return "", err
	}
	if err := parent.Sync(); err != nil {
		parent.Close()
		return "", err
	}
	if err := parent.Close(); err != nil {
		return "", err
	}
	directory, err := openTrustedAbsoluteDirectory(r.runtimeRecoveryDir, true)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	return stageRuntimeArtifact(ctx, directory, artifact, r.config.FetchArtifact, 0)
}

func (r *runner) activateRuntimeArtifact(ctx context.Context, artifact applyplan.Artifact) error {
	if _, err := r.ensureRuntimeArtifact(ctx, artifact); err != nil {
		return err
	}
	recovery, err := openTrustedAbsoluteDirectory(r.runtimeRecoveryDir, true)
	if err != nil {
		return err
	}
	defer recovery.Close()
	destination, err := openTrustedAbsoluteDirectory(filepath.Dir(runtimeBinaryPath), false)
	if err != nil {
		return err
	}
	defer destination.Close()
	return activateRuntimeFromDirectories(recovery, destination, artifact, 0, runtimeUpdateHooks{})
}

func (r *runner) verifyRuntimeArtifact() error {
	if os.Geteuid() != 0 {
		return ErrArtifactVerification
	}
	phase, err := r.phase("flow")
	if err != nil {
		return err
	}
	destination, err := openTrustedAbsoluteDirectory(filepath.Dir(runtimeBinaryPath), false)
	if err != nil {
		return err
	}
	defer destination.Close()
	return verifyNamedRuntimeFile(destination, filepath.Base(runtimeBinaryPath), phase.Steps[0].Artifact, runtimeInstalledMode, 0)
}

func validateRuntimeArtifact(artifact applyplan.Artifact) error {
	if artifact.Component != "flow" || !digestRE.MatchString(artifact.Digest) ||
		artifact.Size <= 0 || artifact.Size > maxRuntimeArtifactSize ||
		(artifact.Target != "linux-amd64" && artifact.Target != "linux-arm64") ||
		artifact.Path != "flow/"+artifact.Version+"/"+artifact.Target+"/flow" {
		return ErrArtifactVerification
	}
	return nil
}

func runtimeRecoveryName(artifact applyplan.Artifact) (string, error) {
	if err := validateRuntimeArtifact(artifact); err != nil {
		return "", err
	}
	return strings.TrimPrefix(artifact.Digest, "sha256:") + ".flow", nil
}

func stageRuntimeArtifact(ctx context.Context, directory *os.File, artifact applyplan.Artifact, fetch FetchArtifact, expectedUID uint32) (string, error) {
	if ctx == nil || directory == nil || fetch == nil {
		return "", ErrArtifactVerification
	}
	name, err := runtimeRecoveryName(artifact)
	if err != nil {
		return "", err
	}
	if err := verifyNamedRuntimeFile(directory, name, artifact, runtimeRecoveryMode, expectedUID); err == nil {
		return name, nil
	}
	if err := removeInvalidManagedFile(directory, name, expectedUID, runtimeRecoveryMode); err != nil {
		return "", err
	}

	temporaryName := ".flow-download-" + strings.TrimSuffix(name, ".flow")
	if err := verifyNamedRuntimeFile(directory, temporaryName, artifact, runtimeRecoveryMode, expectedUID); err == nil {
		if err := syscall.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
			return "", err
		}
		if err := directory.Sync(); err != nil {
			return "", err
		}
		if err := verifyNamedRuntimeFile(directory, name, artifact, runtimeRecoveryMode, expectedUID); err != nil {
			return "", err
		}
		return name, nil
	}
	if err := removeInvalidManagedFile(directory, temporaryName, expectedUID, 0o600, runtimeRecoveryMode); err != nil {
		return "", err
	}

	fd, err := syscall.Openat(int(directory.Fd()), temporaryName,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	temporary := os.NewFile(uintptr(fd), temporaryName)
	if temporary == nil {
		syscall.Close(fd)
		return "", ErrArtifactVerification
	}
	activated := false
	defer func() {
		_ = temporary.Close()
		if !activated {
			_ = syscall.Unlinkat(int(directory.Fd()), temporaryName)
		}
	}()
	limited := &boundedWriter{writer: temporary, remaining: artifact.Size}
	if err := fetch(ctx, artifact, limited); err != nil || limited.remaining != 0 {
		return "", ErrArtifactVerification
	}
	if err := temporary.Chmod(os.FileMode(runtimeRecoveryMode)); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := verifyOpenRuntimeFile(temporary, artifact, runtimeRecoveryMode, expectedUID); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := syscall.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return "", err
	}
	activated = true
	if err := directory.Sync(); err != nil {
		return "", err
	}
	if err := verifyNamedRuntimeFile(directory, name, artifact, runtimeRecoveryMode, expectedUID); err != nil {
		return "", err
	}
	return name, nil
}

func activateRuntimeFromDirectories(recovery, destination *os.File, artifact applyplan.Artifact, expectedUID uint32, hooks runtimeUpdateHooks) error {
	if recovery == nil || destination == nil {
		return ErrArtifactVerification
	}
	recoveryName, err := runtimeRecoveryName(artifact)
	if err != nil {
		return err
	}
	if err := verifyNamedRuntimeFile(recovery, recoveryName, artifact, runtimeRecoveryMode, expectedUID); err != nil {
		return err
	}
	if err := verifyNamedRuntimeFile(destination, "flow", artifact, runtimeInstalledMode, expectedUID); err == nil {
		return nil
	}
	if err := requireSafeInstalledDestination(destination, "flow", expectedUID); err != nil {
		return err
	}
	if _, err := stageInstalledRuntimeRecovery(recovery, destination, expectedUID); err != nil {
		return err
	}

	temporaryName := ".flow-update-" + strings.TrimSuffix(recoveryName, ".flow")
	prepared := verifyNamedRuntimeFile(destination, temporaryName, artifact, runtimeInstalledMode, expectedUID) == nil
	if !prepared {
		if err := removeInvalidManagedFile(destination, temporaryName, expectedUID, 0o600, runtimeInstalledMode); err != nil {
			return err
		}
		source, err := openNamedRuntimeFile(recovery, recoveryName)
		if err != nil {
			return err
		}
		defer source.Close()
		if err := verifyOpenRuntimeFile(source, artifact, runtimeRecoveryMode, expectedUID); err != nil {
			return err
		}
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return err
		}
		fd, err := syscall.Openat(int(destination.Fd()), temporaryName,
			syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		temporary := os.NewFile(uintptr(fd), temporaryName)
		if temporary == nil {
			syscall.Close(fd)
			return ErrArtifactVerification
		}
		keep := false
		defer func() {
			_ = temporary.Close()
			if !keep {
				_ = syscall.Unlinkat(int(destination.Fd()), temporaryName)
			}
		}()
		written, err := io.Copy(temporary, source)
		if err != nil || written != artifact.Size {
			return ErrArtifactVerification
		}
		if err := temporary.Chmod(os.FileMode(runtimeInstalledMode)); err != nil {
			return err
		}
		if err := temporary.Sync(); err != nil {
			return err
		}
		if err := verifyOpenRuntimeFile(temporary, artifact, runtimeInstalledMode, expectedUID); err != nil {
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		keep = true
	}

	if hooks.beforeRename != nil {
		if err := hooks.beforeRename(); err != nil {
			return err
		}
	}
	if err := syscall.Renameat(int(destination.Fd()), temporaryName, int(destination.Fd()), "flow"); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if hooks.afterRename != nil {
		if err := hooks.afterRename(); err != nil {
			return err
		}
	}
	return verifyNamedRuntimeFile(destination, "flow", artifact, runtimeInstalledMode, expectedUID)
}

// stageInstalledRuntimeRecovery preserves the previously running executable
// before the first atomic replacement. the copy is content-addressed and
// root-only, but deliberately not treated as a signed release artifact and is
// never selected automatically. it exists solely for explicit console
// recovery when the first signed replacement cannot run.
func stageInstalledRuntimeRecovery(recovery, destination *os.File, expectedUID uint32) (string, error) {
	source, err := openNamedRuntimeFile(destination, "flow")
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", ErrArtifactVerification
	}
	defer source.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(int(source.Fd()), &before); err != nil ||
		!validRuntimeStat(before, before.Size, runtimeInstalledMode, expectedUID) ||
		before.Size <= 0 || before.Size > maxRuntimeArtifactSize {
		return "", ErrArtifactVerification
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", ErrArtifactVerification
	}
	hash := sha256.New()
	read, err := io.Copy(hash, source)
	if err != nil || read != before.Size {
		return "", ErrArtifactVerification
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(source.Fd()), &after); err != nil ||
		!validRuntimeStat(after, before.Size, runtimeInstalledMode, expectedUID) ||
		after.Ino != before.Ino || after.Size != before.Size ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return "", ErrArtifactVerification
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	name := digest + ".flow"
	if err := verifyNamedRuntimeContent(recovery, name, "sha256:"+digest, before.Size, runtimeRecoveryMode, expectedUID); err == nil {
		return name, nil
	}
	if exists, safe := managedRuntimeFileState(recovery, name, expectedUID, runtimeRecoveryMode); exists && !safe {
		return "", ErrArtifactVerification
	} else if exists {
		return "", ErrArtifactVerification
	}

	temporaryName := ".flow-previous-" + digest
	if err := removeInvalidManagedFile(recovery, temporaryName, expectedUID, 0o600, runtimeRecoveryMode); err != nil {
		return "", err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", ErrArtifactVerification
	}
	fd, err := syscall.Openat(int(recovery.Fd()), temporaryName,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	temporary := os.NewFile(uintptr(fd), temporaryName)
	if temporary == nil {
		syscall.Close(fd)
		return "", ErrArtifactVerification
	}
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = syscall.Unlinkat(int(recovery.Fd()), temporaryName)
		}
	}()
	written, err := io.Copy(temporary, source)
	if err != nil || written != before.Size {
		return "", ErrArtifactVerification
	}
	if err := temporary.Chmod(os.FileMode(runtimeRecoveryMode)); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := verifyOpenRuntimeContent(temporary, "sha256:"+digest, before.Size, runtimeRecoveryMode, expectedUID); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := syscall.Renameat(int(recovery.Fd()), temporaryName, int(recovery.Fd()), name); err != nil {
		return "", err
	}
	keep = true
	if err := recovery.Sync(); err != nil {
		return "", err
	}
	if err := verifyNamedRuntimeContent(recovery, name, "sha256:"+digest, before.Size, runtimeRecoveryMode, expectedUID); err != nil {
		return "", err
	}
	return name, nil
}

func requireSafeInstalledDestination(directory *os.File, name string, expectedUID uint32) error {
	exists, safe := managedRuntimeFileState(directory, name, expectedUID, runtimeInstalledMode)
	if exists && !safe {
		return fmt.Errorf("%w: unsafe installed flow destination", ErrArtifactVerification)
	}
	return nil
}

func removeInvalidManagedFile(directory *os.File, name string, expectedUID uint32, allowedModes ...uint32) error {
	exists, safe := managedRuntimeFileState(directory, name, expectedUID, allowedModes...)
	if !exists {
		return nil
	}
	if !safe {
		return fmt.Errorf("%w: unsafe managed runtime file %s", ErrArtifactVerification, name)
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}

func managedRuntimeFileState(directory *os.File, name string, expectedUID uint32, allowedModes ...uint32) (bool, bool) {
	file, err := openNamedRuntimeFile(directory, name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return false, false
	}
	if err != nil {
		return true, false
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &details); err != nil ||
		details.Mode&syscall.S_IFMT != syscall.S_IFREG || details.Uid != expectedUID || details.Nlink != 1 {
		return true, false
	}
	mode := details.Mode & 0o777
	for _, allowed := range allowedModes {
		if mode == allowed {
			return true, true
		}
	}
	return true, false
}

func verifyNamedRuntimeFile(directory *os.File, name string, artifact applyplan.Artifact, mode, expectedUID uint32) error {
	file, err := openNamedRuntimeFile(directory, name)
	if err != nil {
		return ErrArtifactVerification
	}
	defer file.Close()
	return verifyOpenRuntimeFile(file, artifact, mode, expectedUID)
}

func openNamedRuntimeFile(directory *os.File, name string) (*os.File, error) {
	if directory == nil || name == "" || name == "." || name == ".." || strings.Contains(name, "/") || strings.ContainsRune(name, '\x00') {
		return nil, ErrArtifactVerification
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrArtifactVerification
	}
	return file, nil
}

func verifyOpenRuntimeFile(file *os.File, artifact applyplan.Artifact, mode, expectedUID uint32) error {
	if file == nil || validateRuntimeArtifact(artifact) != nil {
		return ErrArtifactVerification
	}
	return verifyOpenRuntimeContent(file, artifact.Digest, artifact.Size, mode, expectedUID)
}

func verifyNamedRuntimeContent(directory *os.File, name, digest string, size int64, mode, expectedUID uint32) error {
	file, err := openNamedRuntimeFile(directory, name)
	if err != nil {
		return ErrArtifactVerification
	}
	defer file.Close()
	return verifyOpenRuntimeContent(file, digest, size, mode, expectedUID)
}

func verifyOpenRuntimeContent(file *os.File, digest string, size int64, mode, expectedUID uint32) error {
	if file == nil || !digestRE.MatchString(digest) || size <= 0 || size > maxRuntimeArtifactSize {
		return ErrArtifactVerification
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &before); err != nil || !validRuntimeStat(before, size, mode, expectedUID) {
		return ErrArtifactVerification
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrArtifactVerification
	}
	hash := sha256.New()
	read, err := io.Copy(hash, file)
	if err != nil || read != size {
		return ErrArtifactVerification
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &after); err != nil || !validRuntimeStat(after, size, mode, expectedUID) ||
		after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return ErrArtifactVerification
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrArtifactVerification
	}
	return nil
}

func validRuntimeStat(details syscall.Stat_t, size int64, mode, expectedUID uint32) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFREG && details.Mode&0o777 == mode &&
		details.Uid == expectedUID && details.Nlink == 1 && details.Size == size
}

func openTrustedAbsoluteDirectory(path string, private bool) (*os.File, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrArtifactVerification
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		syscall.Close(fd)
		return nil, ErrArtifactVerification
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			current.Close()
			return nil, ErrArtifactVerification
		}
		nextFD, openErr := syscall.Openat(int(current.Fd()), part,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), part)
		if next == nil {
			syscall.Close(nextFD)
			current.Close()
			return nil, ErrArtifactVerification
		}
		current.Close()
		current = next
		var details syscall.Stat_t
		if err := syscall.Fstat(nextFD, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
			details.Uid != 0 || details.Mode&0o022 != 0 || index == len(parts)-1 && private && details.Mode&0o777 != 0o700 {
			current.Close()
			return nil, ErrArtifactVerification
		}
	}
	return current, nil
}
