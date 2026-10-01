package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// VerifyArtifacts verifies direct signed size/digest bindings. artifactPaths is
// keyed by Component.Artifact.
func VerifyArtifacts(manifest Manifest, artifactPaths map[string]string) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	if len(artifactPaths) != len(manifest.Components) {
		return fmt.Errorf("%w: artifact map is incomplete or contains extras", ErrInvalidManifest)
	}
	for _, component := range manifest.Components {
		path, exists := artifactPaths[component.Artifact]
		if !exists {
			return fmt.Errorf("%w: missing %s", ErrInvalidManifest, component.Artifact)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: unsafe artifact %s", ErrUnsafePath, component.Artifact)
		}
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		if digest != component.Digest || size != component.Size {
			return fmt.Errorf("%w: %s", ErrArtifactTampered, component.Artifact)
		}
	}
	return nil
}

// CheckImmutableVersionRoot compares a candidate manifest with any artifacts
// already present below root. a genuinely missing root, directory or final
// artifact is allowed because the version has not been materialized there.
// existing entries are opened descriptor-relatively without following links;
// only owner-controlled, singly-linked regular files may establish a version
// binding. the comparison streams bytes and never loads large artifacts into
// memory.
func CheckImmutableVersionRoot(root string, manifest Manifest) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	rootFile, exists, err := openOptionalImmutableRoot(root)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	defer rootFile.Close()
	for _, component := range manifest.Components {
		digest, size, found, inspectErr := inspectOptionalImmutableArtifact(rootFile, component.Artifact, component.Size)
		if inspectErr != nil {
			return fmt.Errorf("%w: %s", inspectErr, component.Artifact)
		}
		if found && (digest != component.Digest || size != component.Size) {
			return fmt.Errorf("%w: %s", ErrVersionConflict, component.Artifact)
		}
	}
	return nil
}

func openOptionalImmutableRoot(path string) (*os.File, bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, false, fmt.Errorf("%w: immutable version root must be an absolute non-root path", ErrUnsafePath)
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, fmt.Errorf("%w: open immutable version root", ErrUnsafePath)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, false, ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if errors.Is(openErr, syscall.ENOENT) {
			return nil, false, nil
		}
		if openErr != nil {
			return nil, false, fmt.Errorf("%w: immutable version root ancestor", ErrUnsafePath)
		}
		fd = next
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || !secureImmutableDirectory(details) {
		_ = syscall.Close(fd)
		return nil, false, fmt.Errorf("%w: immutable version root metadata", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, false, ErrUnsafePath
	}
	return file, true, nil
}

func inspectOptionalImmutableArtifact(root *os.File, logical string, expectedSize int64) (string, int64, bool, error) {
	if root == nil || !safeRelativeArtifact(logical) || expectedSize <= 0 || expectedSize > MaxBundleBytes {
		return "", 0, false, ErrUnsafePath
	}
	directoryFD, err := syscall.Openat(int(root.Fd()), ".", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, false, ErrUnsafePath
	}
	parts := strings.Split(logical, "/")
	for _, part := range parts[:len(parts)-1] {
		next, openErr := syscall.Openat(directoryFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(directoryFD)
		if errors.Is(openErr, syscall.ENOENT) {
			return "", 0, false, nil
		}
		if openErr != nil {
			return "", 0, false, ErrUnsafePath
		}
		var details syscall.Stat_t
		if statErr := syscall.Fstat(next, &details); statErr != nil || !secureImmutableDirectory(details) {
			_ = syscall.Close(next)
			return "", 0, false, ErrUnsafePath
		}
		directoryFD = next
	}
	defer syscall.Close(directoryFD)
	name := parts[len(parts)-1]
	var directoryBefore syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryBefore); err != nil || !secureImmutableDirectory(directoryBefore) {
		return "", 0, false, ErrUnsafePath
	}
	entries, err := immutableDirectoryEntries(directoryFD)
	if err != nil {
		return "", 0, false, err
	}
	if len(entries) == 0 {
		var directoryAfter syscall.Stat_t
		if err := syscall.Fstat(directoryFD, &directoryAfter); err != nil || !stableImmutableMetadata(directoryBefore, directoryAfter) {
			return "", 0, false, ErrUnsafePath
		}
		return "", 0, false, nil
	}
	if len(entries) != 1 {
		return "", 0, false, ErrUnsafePath
	}
	if entries[0] != name {
		unexpected, openErr := syscall.Openat(directoryFD, entries[0], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return "", 0, false, ErrUnsafePath
		}
		var details syscall.Stat_t
		statErr := syscall.Fstat(unexpected, &details)
		closeErr := syscall.Close(unexpected)
		if statErr != nil || closeErr != nil || !secureImmutableArtifact(details) {
			return "", 0, false, ErrUnsafePath
		}
		return "", 0, false, ErrVersionConflict
	}
	fd, openErr := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		return "", 0, false, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), logical)
	if file == nil {
		_ = syscall.Close(fd)
		return "", 0, false, ErrUnsafePath
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || !secureImmutableArtifact(before) {
		_ = file.Close()
		return "", 0, false, ErrUnsafePath
	}
	if before.Size != expectedSize {
		_ = file.Close()
		return "", 0, false, ErrVersionConflict
	}
	digest, size, hashErr := hashOpenFile(file)
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	closeErr := file.Close()
	if hashErr != nil {
		return "", 0, false, hashErr
	}
	if statErr != nil || closeErr != nil || !stableImmutableMetadata(before, after) {
		return "", 0, false, ErrUnsafePath
	}
	// bind the bytes just inspected back to the directory entry. a rename or
	// replacement during hashing is an unsafe concurrent mutation, not absence.
	reopened, reopenErr := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if reopenErr != nil {
		return "", 0, false, ErrUnsafePath
	}
	var linked syscall.Stat_t
	linkedErr := syscall.Fstat(reopened, &linked)
	reopenCloseErr := syscall.Close(reopened)
	if linkedErr != nil || reopenCloseErr != nil || !stableImmutableMetadata(after, linked) {
		return "", 0, false, ErrUnsafePath
	}
	var directoryAfter syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryAfter); err != nil || !stableImmutableMetadata(directoryBefore, directoryAfter) {
		return "", 0, false, ErrUnsafePath
	}
	return digest, size, true, nil
}

func immutableDirectoryEntries(fd int) ([]string, error) {
	duplicate, err := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	directory := os.NewFile(uintptr(duplicate), "immutable-version-coordinate")
	if directory == nil {
		_ = syscall.Close(duplicate)
		return nil, ErrUnsafePath
	}
	entries, readErr := directory.Readdirnames(2)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 1 {
		return nil, ErrUnsafePath
	}
	for _, entry := range entries {
		if !safeName(entry) {
			return nil, ErrUnsafePath
		}
	}
	return entries, nil
}

func secureImmutableDirectory(details syscall.Stat_t) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFDIR && int(details.Uid) == os.Geteuid() && details.Mode&0o022 == 0
}

func secureImmutableArtifact(details syscall.Stat_t) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFREG && int(details.Uid) == os.Geteuid() && details.Nlink == 1 && details.Mode&0o022 == 0
}

func stableImmutableMetadata(first, second syscall.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Mode == second.Mode &&
		first.Nlink == second.Nlink && first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Size == second.Size && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func hashFile(path string) (string, int64, error) {
	file, _, err := openRegularNoFollow(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	return hashOpenFile(file)
}

// ReadRegularFile reads a bounded single-link regular file through a
// descriptor-relative, no-follow path walk. it is used by the release CLI for
// version and externally supplied staged metadata.
func ReadRegularFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum > MaxBundleBytes {
		return nil, ErrUnsafePath
	}
	file, details, err := openRegularNoFollow(path)
	if err != nil || details.Size < 0 || details.Size > maximum {
		if file != nil {
			file.Close()
		}
		return nil, ErrUnsafePath
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != details.Size || int64(len(data)) > maximum {
		return nil, ErrUnsafePath
	}
	return data, nil
}

// RegularFileSize validates a single-link regular path without reading it.
func RegularFileSize(path string) (int64, error) {
	file, details, err := openRegularNoFollow(path)
	if err != nil {
		return 0, err
	}
	if err := file.Close(); err != nil {
		return 0, err
	}
	return details.Size, nil
}

func hashOpenFile(file *os.File) (string, int64, error) {
	hash := sha256.New()
	detector := &privateKeyDetector{}
	size, err := io.Copy(io.MultiWriter(hash, detector), file)
	if err != nil {
		return "", 0, err
	}
	if detector.found {
		return "", 0, ErrPrivateKey
	}
	if err := inspectCompressedArtifact(file); err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

var privateKeyMarkers = [][]byte{
	privateKeyMarker(""),
	privateKeyMarker("ENCRYPTED "),
	privateKeyMarker("OPENSSH "),
	privateKeyMarker("RSA "),
	privateKeyMarker("EC "),
	privateKeyMarker("DSA "),
}

//go:noinline
func privateKeyMarker(kind string) []byte {
	marker := make([]byte, 0, 32+len(kind))
	marker = append(marker, "-----BEGIN "...)
	marker = append(marker, kind...)
	marker = append(marker, "PRIVATE"...)
	marker = append(marker, byte(32))
	marker = append(marker, "KEY-----"...)
	return marker
}

type privateKeyDetector struct {
	tail  []byte
	found bool
}

func (detector *privateKeyDetector) Write(data []byte) (int, error) {
	original := len(data)
	if detector.found {
		return original, nil
	}
	combined := append(append([]byte(nil), detector.tail...), data...)
	for _, marker := range privateKeyMarkers {
		if bytes.Contains(combined, marker) {
			detector.found = true
			break
		}
	}
	const retained = 64
	if len(combined) > retained {
		detector.tail = append(detector.tail[:0], combined[len(combined)-retained:]...)
	} else {
		detector.tail = append(detector.tail[:0], combined...)
	}
	return original, nil
}

func inspectCompressedArtifact(file *os.File) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var magic [2]byte
	count, err := io.ReadFull(file, magic[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	if count != len(magic) || magic != [2]byte{0x1f, 0x8b} {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("%w: malformed gzip artifact", ErrArtifactTampered)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var expanded int64
	entries := 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: malformed tar artifact", ErrArtifactTampered)
		}
		entries++
		if entries > 100000 || header.Size < 0 || expanded > MaxBundleBytes-header.Size {
			return fmt.Errorf("%w: compressed artifact exceeds inspection bounds", ErrInvalidManifest)
		}
		expanded += header.Size
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		detector := &privateKeyDetector{}
		written, copyErr := io.Copy(detector, archive)
		if copyErr != nil || written != header.Size {
			return fmt.Errorf("%w: truncated tar artifact", ErrArtifactTampered)
		}
		if detector.found {
			return ErrPrivateKey
		}
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, syscall.Stat_t, error) {
	var details syscall.Stat_t
	if path == "" || filepath.Clean(path) == string(filepath.Separator) {
		return nil, details, ErrUnsafePath
	}
	clean := filepath.Clean(path)
	start := "."
	if filepath.IsAbs(clean) {
		start = string(filepath.Separator)
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) == 0 {
		return nil, details, ErrUnsafePath
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, details, ErrUnsafePath
		}
	}
	directoryFD, err := syscall.Open(start, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, details, fmt.Errorf("%w: open artifact root", ErrUnsafePath)
	}
	for _, part := range parts[:len(parts)-1] {
		nextFD, openErr := syscall.Openat(directoryFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(directoryFD)
		if openErr != nil {
			return nil, details, fmt.Errorf("%w: open artifact ancestor", ErrUnsafePath)
		}
		directoryFD = nextFD
	}
	fd, err := syscall.Openat(directoryFD, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	_ = syscall.Close(directoryFD)
	if err != nil {
		return nil, details, fmt.Errorf("%w: open artifact", ErrUnsafePath)
	}
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG || details.Nlink != 1 {
		_ = syscall.Close(fd)
		return nil, details, fmt.Errorf("%w: artifact is not a single-link regular file", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	return file, details, nil
}

func openDirectoryNoFollow(path string) (*os.File, syscall.Stat_t, error) {
	var details syscall.Stat_t
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, details, ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, details, ErrUnsafePath
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, details, ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, details, fmt.Errorf("%w: open directory", ErrUnsafePath)
		}
		fd = next
	}
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	return file, details, nil
}
