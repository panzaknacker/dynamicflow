package reconcile

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxArchiveEntries = 200000
	maxArchiveBytes   = int64(4 << 30)
	maxMemberBytes    = int64(2 << 30)
)

var ErrUnsafeArchive = errors.New("unsafe release archive")

// ExtractTarGz extracts regular files and directories into a private empty
// staging directory. Links, devices, duplicate paths and traversal are denied.
// It returns the single top-level directory required by component releases.
func ExtractTarGz(archivePath, destination string) (string, error) {
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: archive is not a regular file", ErrUnsafeArchive)
	}
	destinationInfo, err := os.Lstat(destination)
	if err != nil || !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 || destinationInfo.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: staging directory must be private and real", ErrUnsafeArchive)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return "", fmt.Errorf("%w: staging directory must be empty", ErrUnsafeArchive)
	}
	input, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return "", fmt.Errorf("%w: invalid gzip stream", ErrUnsafeArchive)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	seen := map[string]bool{}
	topLevels := map[string]bool{}
	var total int64
	count := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", fmt.Errorf("%w: read tar: %v", ErrUnsafeArchive, nextErr)
		}
		count++
		if count > maxArchiveEntries {
			return "", fmt.Errorf("%w: too many members", ErrUnsafeArchive)
		}
		name, err := safeMemberName(header.Name)
		if err != nil {
			return "", err
		}
		if seen[name] {
			return "", fmt.Errorf("%w: duplicate member %s", ErrUnsafeArchive, name)
		}
		seen[name] = true
		topLevels[strings.Split(name, string(filepath.Separator))[0]] = true
		target := filepath.Join(destination, name)
		if !within(destination, target) {
			return "", fmt.Errorf("%w: member escapes staging root", ErrUnsafeArchive)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := ensureSafeDirectory(destination, target); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxMemberBytes || total > maxArchiveBytes-header.Size {
				return "", fmt.Errorf("%w: member size limit exceeded", ErrUnsafeArchive)
			}
			total += header.Size
			if err := ensureSafeDirectory(destination, filepath.Dir(target)); err != nil {
				return "", err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return "", fmt.Errorf("%w: create member: %v", ErrUnsafeArchive, err)
			}
			written, copyErr := io.CopyN(output, reader, header.Size)
			if syncErr := output.Sync(); copyErr == nil {
				copyErr = syncErr
			}
			if closeErr := output.Close(); copyErr == nil {
				copyErr = closeErr
			}
			if copyErr != nil || written != header.Size {
				return "", fmt.Errorf("%w: truncated member", ErrUnsafeArchive)
			}
		default:
			return "", fmt.Errorf("%w: member %s has forbidden type %d", ErrUnsafeArchive, name, header.Typeflag)
		}
	}
	if len(topLevels) != 1 {
		return "", fmt.Errorf("%w: archive needs exactly one top-level directory", ErrUnsafeArchive)
	}
	var top string
	for top = range topLevels {
	}
	root := filepath.Join(destination, top)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: top-level member is not a directory", ErrUnsafeArchive)
	}
	return root, nil
}

func safeMemberName(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("%w: invalid member path", ErrUnsafeArchive)
	}
	clean := filepath.Clean(name)
	clean = strings.TrimSuffix(clean, string(filepath.Separator))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.ToSlash(clean) != strings.TrimSuffix(name, "/") {
		return "", fmt.Errorf("%w: non-canonical member path %q", ErrUnsafeArchive, name)
	}
	return clean, nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func ensureSafeDirectory(root, directory string) error {
	if !within(root, directory) {
		return ErrUnsafeArchive
	}
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." {
		return err
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: unsafe staging directory", ErrUnsafeArchive)
		}
	}
	return nil
}
