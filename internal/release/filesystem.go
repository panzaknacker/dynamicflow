package release

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func makeTreeReadOnly(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return ErrUnsafePath
		}
		return os.Chmod(path, 0o444)
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		// files are read-only; directories retain owner write permission so an
		// explicit release-pruning workflow can remove a whole immutable set.
		// every read still verifies the signed content digest, so replacing a
		// path cannot turn modified bytes into a valid set.
		if err := os.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func removeStage(path string) error {
	_ = filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(current, 0o700)
		}
		return nil
	})
	return os.RemoveAll(path)
}

func canonicalRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: release root must be absolute", ErrUnsafePath)
	}
	clean := filepath.Clean(root)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: refusing filesystem root", ErrUnsafePath)
	}
	if err := checkReleaseRootCreation(clean); err != nil {
		return "", err
	}
	if err := ensureAbsoluteDirectory(clean, 0o755); err != nil {
		return "", err
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: release root is not a real directory", ErrUnsafePath)
	}
	if err := validateOwnedReleaseDirectory(clean); err != nil {
		return "", err
	}
	if err := validateReleasePathAncestors(clean); err != nil {
		return "", err
	}
	return clean, nil
}

func validateReleasePathAncestors(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafePath
	}
	defer func() { _ = syscall.Close(fd) }()
	var parent syscall.Stat_t
	if err := syscall.Fstat(fd, &parent); err != nil || !trustedReleaseAncestor(parent) {
		return fmt.Errorf("%w: filesystem root metadata", ErrUnsafePath)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return fmt.Errorf("%w: release-root ancestor", ErrUnsafePath)
		}
		var child syscall.Stat_t
		if err := syscall.Fstat(next, &child); err != nil || !trustedReleaseAncestor(child) || parent.Mode&0o022 != 0 && parent.Mode&0o1000 == 0 {
			_ = syscall.Close(next)
			return fmt.Errorf("%w: release-root ancestor metadata", ErrUnsafePath)
		}
		if err := syscall.Close(fd); err != nil {
			_ = syscall.Close(next)
			return err
		}
		fd = next
		parent = child
	}
	return nil
}

func trustedReleaseAncestor(details syscall.Stat_t) bool {
	uid := int(details.Uid)
	return details.Mode&syscall.S_IFMT == syscall.S_IFDIR && (uid == 0 || uid == os.Geteuid())
}

func ensureReleaseRootIdentity(path string, expected syscall.Stat_t) error {
	current, err := validatePublishedDirectory(path)
	if err != nil || current.Dev != expected.Dev || current.Ino != expected.Ino || current.Mode != expected.Mode || current.Uid != expected.Uid || current.Gid != expected.Gid {
		return fmt.Errorf("%w: release root changed during publication", ErrUnsafePath)
	}
	return nil
}

func validateOwnedReleaseDirectory(path string) error {
	directory, details, err := openDirectoryNoFollow(path)
	if err != nil {
		return err
	}
	closeErr := directory.Close()
	if closeErr != nil || int(details.Uid) != os.Geteuid() || details.Mode&0o022 != 0 {
		return fmt.Errorf("%w: release directory must be owner-controlled", ErrUnsafePath)
	}
	return nil
}

func infoSyscallStat(info os.FileInfo) (syscall.Stat_t, bool) {
	if info == nil {
		return syscall.Stat_t{}, false
	}
	details, ok := info.Sys().(*syscall.Stat_t)
	if !ok || details == nil {
		return syscall.Stat_t{}, false
	}
	return *details, true
}

func ensureAbsoluteDirectory(path string, mode os.FileMode) error {
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		if err := ensureDirectory(current, mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureDirectory(path string, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrUnsafePath, path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil {
		// concurrent publishers may both observe a missing directory. treat the
		// winner's safe directory as success, but never accept a symlink or file.
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrUnsafePath, path)
		}
	}
	return nil
}

func copyVerified(source, target string, component Component) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	input, _, err := openRegularNoFollow(source)
	if err != nil {
		return fmt.Errorf("%w: unsafe source for %s", err, component.Artifact)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if syncErr := output.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := output.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return copyErr
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if size != component.Size || digest != component.Digest {
		return fmt.Errorf("%w: artifact changed while publishing %s", ErrArtifactTampered, component.Artifact)
	}
	return nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".write-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncTreeDirectories(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func activateCurrent(root, setName string) error {
	current := filepath.Join(root, "current")
	if info, err := os.Lstat(current); err == nil {
		if !singleLinkSymlink(info) {
			return fmt.Errorf("%w: current pointer is not a symlink", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(root, ".current-"+hex.EncodeToString(random))
	if err := os.Symlink(filepath.ToSlash(filepath.Join("sets", setName)), temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, current); err != nil {
		return err
	}
	return syncDirectory(root)
}
