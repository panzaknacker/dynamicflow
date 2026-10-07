package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openReadFile opens existing state only. Directory descriptors anchor each
// lookup, so exchanging a checked parent for a symlink cannot redirect a read.
// Root identity is retained as metadata rather than a long-lived descriptor.
func (s *Store) openReadFile(relative string) (*os.File, error) {
	if s == nil || s.rootInfo == nil {
		return nil, ErrInvalidPath
	}
	clean, err := cleanRelative(relative)
	if err != nil {
		return nil, err
	}
	current, err := openExistingReadDirectory(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The root existed when Store was opened. Losing it must not look
			// like an absent record that a caller may safely initialize anew.
			return nil, fmt.Errorf("%w: original state root is unavailable", ErrInvalidPath)
		}
		return nil, err
	}
	defer func() { _ = current.Close() }()
	info, err := current.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateInfo(info, true); err != nil {
		return nil, err
	}
	if !os.SameFile(s.rootInfo, info) {
		return nil, fmt.Errorf("%w: state root was replaced", ErrInvalidPath)
	}
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		fd, err := syscall.Openat(int(current.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, readPathError(err)
		}
		next := os.NewFile(uintptr(fd), part)
		if err := validateOpenFile(next, true); err != nil {
			_ = next.Close()
			return nil, err
		}
		previous := current
		current = next
		if err := previous.Close(); err != nil {
			return nil, err
		}
	}
	fd, err := syscall.Openat(int(current.Fd()), parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, readPathError(err)
	}
	return os.NewFile(uintptr(fd), filepath.Join(s.root, clean)), nil
}

// Ancestors above the managed root need not be private (for example /tmp), but
// none may be a symlink. Once the managed root is reached, openReadFile checks
// its identity and the owner/private-mode invariant of every managed directory.
func openExistingReadDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, ErrInvalidPath
	}
	current, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if current >= 0 {
			_ = syscall.Close(current)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		fd, err := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, readPathError(err)
		}
		previous := current
		current = fd
		if err := syscall.Close(previous); err != nil {
			return nil, err
		}
	}
	file := os.NewFile(uintptr(current), path)
	current = -1
	return file, nil
}

func readPathError(err error) error {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return ErrSymlink
	}
	return err
}
