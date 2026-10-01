package release

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"dynamicflow/internal/signing"
)

// Publish verifies, stages and activates a signed set below root. no signing
// private key is needed on the serving node.
func Publish(root string, signed SignedManifest, artifactPaths map[string]string, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	root, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	publishLock, err := lockPublish(filepath.Join(root, ".publish.lock"))
	if err != nil {
		return err
	}
	defer unlockPublish(publishLock)
	rootDirectory, rootIdentity, err := openDirectoryNoFollow(root)
	if err != nil || !secureImmutableDirectory(rootIdentity) {
		if rootDirectory != nil {
			_ = rootDirectory.Close()
		}
		return fmt.Errorf("%w: release root identity", ErrUnsafePath)
	}
	defer rootDirectory.Close()
	setsRoot := filepath.Join(root, "sets")
	if err := ensureDirectory(setsRoot, 0o755); err != nil {
		return err
	}
	if err := validateOwnedReleaseDirectory(setsRoot); err != nil {
		return err
	}
	historyRoot := filepath.Join(root, "history")
	if err := ensureDirectory(historyRoot, 0o755); err != nil {
		return err
	}
	if err := validateOwnedReleaseDirectory(historyRoot); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	retained, retainedFound, versionHistory, err := retainedReleaseHighWater(root, setsRoot, historyRoot, publicKey)
	if err != nil {
		return err
	}
	if retainedFound {
		if signed.Manifest.Generation < retained.Generation ||
			signed.Manifest.Generation == retained.Generation && signed.Manifest.SetID != retained.SetID {
			return fmt.Errorf("%w: retained=%d/%s candidate=%d/%s", ErrReleaseRollback,
				retained.Generation, retained.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
		}
	}
	if err := registerVersionBindings(versionHistory, signed.Manifest); err != nil {
		return err
	}
	currentPath := filepath.Join(root, "current")
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if _, statErr := os.Lstat(currentPath); statErr == nil {
		current, _, currentErr := Current(root, publicKey)
		if currentErr != nil {
			return currentErr
		}
		if signed.Manifest.Generation < current.Manifest.Generation {
			return fmt.Errorf("%w: current=%d candidate=%d", ErrReleaseRollback, current.Manifest.Generation, signed.Manifest.Generation)
		}
		if signed.Manifest.Generation == current.Manifest.Generation {
			if signed.Manifest.SetID != current.Manifest.SetID {
				return fmt.Errorf("%w: generation %d already identifies another set", ErrReleaseRollback, signed.Manifest.Generation)
			}
			if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
				return err
			}
			return syncDirectory(root)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	setName := strings.TrimPrefix(signed.Manifest.SetID, "sha256:")
	if len(setName) != 64 {
		return fmt.Errorf("%w: invalid set name", ErrInvalidManifest)
	}
	destination := filepath.Join(setsRoot, setName)
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil {
		return err
	}
	// a crash can occur after the immutable set rename but before the history
	// tombstone or current-pointer commit. in that state the signed destination
	// is the durable source of truth: verify it in full and finish the two
	// remaining commits without requiring the transient upload files to still
	// exist. never use this path for an absent, mismatched or damaged set.
	if destinationInfo, statErr := os.Lstat(destination); statErr == nil {
		if !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: immutable set destination is unsafe", ErrUnsafePath)
		}
		destinationBefore, identityErr := validatePublishedDirectory(destination)
		if identityErr != nil {
			return identityErr
		}
		existing, _, loadErr := loadPublishedSet(root, setName, publicKey)
		if loadErr != nil {
			return loadErr
		}
		if !reflect.DeepEqual(existing, signed) {
			return fmt.Errorf("%w: immutable set conflicts with existing content", ErrInvalidManifest)
		}
		if err := syncDirectory(setsRoot); err != nil {
			return err
		}
		if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
			return err
		}
		if err := ensureManifestHistoryEntry(historyRoot, signed, publicKey); err != nil {
			return err
		}
		destinationAfter, identityErr := validatePublishedDirectory(destination)
		if identityErr != nil || !stableImmutableMetadata(destinationBefore, destinationAfter) {
			return fmt.Errorf("%w: immutable set changed during resume", ErrUnsafePath)
		}
		if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
			return err
		}
		return activateCurrent(root, setName)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := VerifyArtifacts(signed.Manifest, artifactPaths); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(setsRoot, ".stage-")
	if err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	committed := false
	defer func() {
		if !committed {
			removeStage(stage)
		}
	}()
	if err := writeAtomicFile(filepath.Join(stage, "signed-manifest.json"), envelope, 0o644); err != nil {
		return err
	}
	for _, component := range signed.Manifest.Components {
		source := artifactPaths[component.Artifact]
		target := filepath.Join(stage, "artifacts", filepath.FromSlash(component.Artifact))
		if err := copyVerified(source, target, component); err != nil {
			return err
		}
	}
	if err := makeTreeReadOnly(stage); err != nil {
		return err
	}
	if err := syncTreeDirectories(stage); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		destinationInfo, statErr := os.Lstat(destination)
		if statErr != nil {
			return fmt.Errorf("activate immutable set: %w", err)
		}
		if !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: immutable set destination is unsafe", ErrUnsafePath)
		}
		existing, readErr := readPublishedManifest(filepath.Join(destination, "signed-manifest.json"))
		if readErr != nil || !bytes.Equal(existing, envelope) {
			return fmt.Errorf("%w: immutable set conflicts with existing content", ErrInvalidManifest)
		}
		if verifyErr := verifyPublishedArtifacts(destination, signed.Manifest); verifyErr != nil {
			return verifyErr
		}
		if removeErr := removeStage(stage); removeErr != nil {
			return removeErr
		}
	}
	committed = true
	if err := syncDirectory(setsRoot); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if err := ensureManifestHistoryEntry(historyRoot, signed, publicKey); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	return activateCurrent(root, setName)
}

// CheckPublishPolicy performs the retained-generation and immutable-version
// checks without creating, backfilling or activating anything. it is a
// point-in-time plan preflight; Publish repeats every check while holding the
// publication lock. a genuinely absent root represents an empty destination.
func CheckPublishPolicy(root string, signed SignedManifest, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	rootDirectory, rootExists, err := openOptionalImmutableRoot(root)
	if err != nil {
		return err
	}
	if !rootExists {
		return checkReleaseRootCreation(root)
	}
	if err := validateReleasePathAncestors(filepath.Clean(root)); err != nil {
		_ = rootDirectory.Close()
		return err
	}
	var rootDetails syscall.Stat_t
	if err := syscall.Fstat(int(rootDirectory.Fd()), &rootDetails); err != nil || !ownerCanMutateDirectory(rootDetails) {
		_ = rootDirectory.Close()
		return fmt.Errorf("%w: release root is not owner-writable", ErrUnsafePath)
	}
	if err := rootDirectory.Close(); err != nil {
		return err
	}
	root = filepath.Clean(root)
	if err := checkPublishLockMetadata(filepath.Join(root, ".publish.lock")); err != nil {
		return err
	}
	versionHistory := make(map[string]immutableVersionBinding)
	var retained releaseHighWater
	retainedFound := false
	historyRoot := filepath.Join(root, "history")
	historyDirectory, historyExists, err := openOptionalImmutableRoot(historyRoot)
	if err != nil {
		return err
	}
	if historyExists {
		var details syscall.Stat_t
		if err := syscall.Fstat(int(historyDirectory.Fd()), &details); err != nil || !ownerCanMutateDirectory(details) {
			_ = historyDirectory.Close()
			return fmt.Errorf("%w: manifest-history directory is not owner-writable", ErrUnsafePath)
		}
		if err := historyDirectory.Close(); err != nil {
			return err
		}
		retained, retainedFound, err = scanManifestHistory(historyRoot, publicKey, versionHistory)
		if err != nil {
			return err
		}
	}
	setsRoot := filepath.Join(root, "sets")
	setsDirectory, setsExist, err := openOptionalImmutableRoot(setsRoot)
	if err != nil {
		return err
	}
	if setsExist {
		var details syscall.Stat_t
		if err := syscall.Fstat(int(setsDirectory.Fd()), &details); err != nil || !ownerCanMutateDirectory(details) {
			_ = setsDirectory.Close()
			return fmt.Errorf("%w: sets directory is not owner-writable", ErrUnsafePath)
		}
		if err := setsDirectory.Close(); err != nil {
			return err
		}
		if _, err := scanRetainedSetEntries(root, setsRoot, publicKey, &retained, &retainedFound, versionHistory); err != nil {
			return err
		}
	}
	if retainedFound && (signed.Manifest.Generation < retained.Generation ||
		signed.Manifest.Generation == retained.Generation && signed.Manifest.SetID != retained.SetID) {
		return fmt.Errorf("%w: retained=%d/%s candidate=%d/%s", ErrReleaseRollback,
			retained.Generation, retained.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
	}
	if err := registerVersionBindings(versionHistory, signed.Manifest); err != nil {
		return err
	}
	currentPath := filepath.Join(root, "current")
	if _, statErr := os.Lstat(currentPath); statErr == nil {
		current, _, currentErr := Current(root, publicKey)
		if currentErr != nil {
			return currentErr
		}
		if signed.Manifest.Generation < current.Manifest.Generation ||
			signed.Manifest.Generation == current.Manifest.Generation && signed.Manifest.SetID != current.Manifest.SetID {
			return fmt.Errorf("%w: current=%d/%s candidate=%d/%s", ErrReleaseRollback,
				current.Manifest.Generation, current.Manifest.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return nil
}

func ownerCanMutateDirectory(details syscall.Stat_t) bool {
	return secureImmutableDirectory(details) && details.Mode&0o300 == 0o300
}

func checkReleaseRootCreation(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafePath
	}
	currentPath := string(filepath.Separator)
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
		if errors.Is(openErr, syscall.ENOENT) {
			if parent.Mode&0o022 != 0 && parent.Mode&0o1000 == 0 {
				return fmt.Errorf("%w: writable release-root ancestor lacks sticky protection", ErrUnsafePath)
			}
			if err := syscall.Access(currentPath, 0o3); err != nil {
				return fmt.Errorf("%w: deepest release-root ancestor is not writable", ErrUnsafePath)
			}
			return nil
		}
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
		currentPath = filepath.Join(currentPath, part)
		parent = child
	}
	return nil
}

func checkPublishLockMetadata(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: publish lock metadata", ErrUnsafePath)
	}
	details, ok := info.Sys().(*syscall.Stat_t)
	var parent syscall.Stat_t
	if !ok || details.Nlink != 1 || details.Size != 0 || syscall.Stat(filepath.Dir(path), &parent) != nil || details.Uid != parent.Uid || details.Gid != parent.Gid {
		return fmt.Errorf("%w: publish lock ownership", ErrUnsafePath)
	}
	return nil
}

func lockPublish(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return nil, ErrUnsafePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrUnsafePath
	}
	var stat syscall.Stat_t
	var parent syscall.Stat_t
	if err := syscall.Stat(filepath.Dir(path), &parent); err != nil ||
		syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 ||
		stat.Mode&0o777 != 0o600 || stat.Size != 0 || stat.Uid != parent.Uid || stat.Gid != parent.Gid {
		file.Close()
		return nil, ErrUnsafePath
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func unlockPublish(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
