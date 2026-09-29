// package localstate provides a small, security-focused store for operator-local
// dynamicflow state. all managed directories and files are private to their
// owner, symbolic links are rejected, and replacements are atomic.
package localstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	DirMode      os.FileMode = 0o700
	FileMode     os.FileMode = 0o600
	maxJSONBytes             = 8 << 20
)

var (
	ErrInsecureMode = errors.New("local state has insecure permissions")
	ErrInvalidPath  = errors.New("invalid local state path")
	ErrLockBusy     = errors.New("local state lock is busy")
	ErrNotOwned     = errors.New("local state is not owned by the current user")
	ErrSymlink      = errors.New("symbolic links are not allowed in local state")
)

// Store owns one private directory tree.
type Store struct {
	root string
}

// DefaultRoot returns the XDG state directory used by dynamicflow. FLOW_HOME
// can be used by the CLI to select an explicit state directory.
func DefaultRoot() (string, error) {
	if configured := os.Getenv("FLOW_HOME"); configured != "" {
		return filepath.Abs(configured)
	}
	if configured := os.Getenv("XDG_STATE_HOME"); configured != "" {
		return filepath.Abs(filepath.Join(configured, "dynamicflow"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "dynamicflow"), nil
}

// Open creates or validates a private state root.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: empty root", ErrInvalidPath)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve state root: %w", err)
	}
	if err := ensureAbsolutePrivateRoot(abs); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	if err := validatePath(abs, true); err != nil {
		return nil, fmt.Errorf("validate state root: %w", err)
	}
	return &Store{root: abs}, nil
}

// ensureAbsolutePrivateRoot traverses from an already-open filesystem root.
// no path component may be a symlink, and creation is descriptor-relative so
// an attacker cannot redirect MkdirAll through a swapped ancestor.
func ensureAbsolutePrivateRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return ErrInvalidPath
	}
	rootFD, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	current := rootFD
	defer func() { _ = syscall.Close(current) }()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrInvalidPath
		}
		next, openErr := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(current, part, uint32(DirMode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				return mkdirErr
			}
			next, openErr = syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return ErrSymlink
			}
			return openErr
		}
		if err := syscall.Close(current); err != nil {
			_ = syscall.Close(next)
			return err
		}
		current = next
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(current, &opened); err != nil || opened.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return ErrInvalidPath
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrSymlink
	}
	linked, ok := info.Sys().(*syscall.Stat_t)
	if !ok || linked.Dev != opened.Dev || linked.Ino != opened.Ino {
		return ErrSymlink
	}
	return nil
}

func (s *Store) Root() string { return s.root }

// Path resolves a relative managed path without touching the filesystem.
func (s *Store) Path(relative string) (string, error) {
	clean, err := cleanRelative(relative)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.root, clean)
	rel, err := filepath.Rel(s.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path escapes state root", ErrInvalidPath)
	}
	return path, nil
}

// EnsureDir creates and validates every directory below the state root.
func (s *Store) EnsureDir(relative string) (string, error) {
	clean, err := cleanRelative(relative)
	if err != nil {
		return "", err
	}
	if err := validatePath(s.root, true); err != nil {
		return "", fmt.Errorf("validate state root: %w", err)
	}
	if clean == "." {
		return s.root, nil
	}
	current := s.root
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, DirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create state directory %q: %w", part, err)
		}
		if err := validatePath(current, true); err != nil {
			return "", fmt.Errorf("validate state directory %q: %w", part, err)
		}
	}
	return current, nil
}

// ReadFile reads a private regular file without following a final symlink.
func (s *Store) ReadFile(relative string) ([]byte, error) {
	path, err := s.Path(relative)
	if err != nil {
		return nil, err
	}
	f, err := openNoFollow(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := validateOpenFile(f, false); err != nil {
		return nil, fmt.Errorf("validate %q: %w", relative, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", relative, err)
	}
	if len(data) > maxJSONBytes {
		return nil, fmt.Errorf("read %q: file exceeds %d bytes", relative, maxJSONBytes)
	}
	return data, nil
}

// WriteFile atomically replaces a private regular file.
func (s *Store) WriteFile(relative string, data []byte) error {
	path, err := s.Path(relative)
	if err != nil {
		return err
	}
	dirRel := filepath.Dir(relative)
	dir, err := s.EnsureDir(dirRel)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if err := validateInfo(info, false); err != nil {
			return fmt.Errorf("validate existing %q: %w", relative, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing %q: %w", relative, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(FileMode); err != nil {
		return fmt.Errorf("secure temporary state file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("activate state file: %w", err)
	}
	removeTemp = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

// WriteJSON serializes one value and atomically replaces the destination.
func (s *Store) WriteJSON(relative string, value any) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode %q: %w", relative, err)
	}
	return s.WriteFile(relative, buf.Bytes())
}

// ReadJSON decodes exactly one JSON value and rejects unknown fields.
func (s *Store) ReadJSON(relative string, destination any) error {
	data, err := s.ReadFile(relative)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %q: %w", relative, err)
	}
	if err := requireEOF(decoder); err != nil {
		return fmt.Errorf("decode %q: %w", relative, err)
	}
	return nil
}

// AppendJSONL appends one complete JSON record while holding an advisory lock.
func (s *Store) AppendJSONL(relative string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode JSONL record: %w", err)
	}
	data = append(data, '\n')
	path, err := s.Path(relative)
	if err != nil {
		return err
	}
	if _, err := s.EnsureDir(filepath.Dir(relative)); err != nil {
		return err
	}
	f, err := openNoFollow(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND, uint32(FileMode.Perm()))
	if err != nil {
		return fmt.Errorf("open JSONL file: %w", err)
	}
	defer f.Close()
	if err := validateOpenFile(f, false); err != nil {
		return fmt.Errorf("validate JSONL file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock JSONL file: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck -- best effort on close
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("append JSONL record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync JSONL file: %w", err)
	}
	return nil
}

// WithLock serializes a state mutation with an owner-only advisory lock file.
func (s *Store) WithLock(relative string, fn func() error) error {
	return s.withLock(relative, false, fn)
}

// WithTryLock runs fn while holding an owner-only advisory lock. it fails with
// ErrLockBusy instead of waiting when another process already holds the lock.
func (s *Store) WithTryLock(relative string, fn func() error) error {
	return s.withLock(relative, true, fn)
}

func (s *Store) withLock(relative string, nonBlocking bool, fn func() error) error {
	path, err := s.Path(relative)
	if err != nil {
		return err
	}
	if _, err := s.EnsureDir(filepath.Dir(relative)); err != nil {
		return err
	}
	f, err := openNoFollow(path, syscall.O_RDWR|syscall.O_CREAT, uint32(FileMode.Perm()))
	if err != nil {
		return fmt.Errorf("open state lock: %w", err)
	}
	defer f.Close()
	if err := validateLockFile(path, f); err != nil {
		return fmt.Errorf("validate state lock: %w", err)
	}
	operation := syscall.LOCK_EX
	if nonBlocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), operation); err != nil {
		if nonBlocking && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)) {
			return ErrLockBusy
		}
		return fmt.Errorf("acquire state lock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck -- best effort on close
	if err := validateLockFile(path, f); err != nil {
		return fmt.Errorf("revalidate state lock: %w", err)
	}
	return fn()
}

func validateLockFile(path string, file *os.File) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if err := validateInfo(opened, false); err != nil {
		return err
	}
	if opened.Mode().Perm() != FileMode {
		return fmt.Errorf("%w: lock mode %04o", ErrInsecureMode, opened.Mode().Perm())
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Nlink != 1 {
		return fmt.Errorf("%w: state lock must have exactly one link", ErrInvalidPath)
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if linked.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	linkedStat, ok := linked.Sys().(*syscall.Stat_t)
	if !ok || linkedStat.Dev != openedStat.Dev || linkedStat.Ino != openedStat.Ino {
		return fmt.Errorf("%w: state lock path changed", ErrInvalidPath)
	}
	return nil
}

func cleanRelative(relative string) (string, error) {
	if strings.ContainsRune(relative, '\x00') || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, relative)
	}
	for _, part := range strings.FieldsFunc(filepath.ToSlash(relative), func(r rune) bool { return r == '/' }) {
		if part == ".." {
			return "", fmt.Errorf("%w: parent traversal", ErrInvalidPath)
		}
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: parent traversal", ErrInvalidPath)
	}
	return clean, nil
}

func validatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateInfo(info, directory)
}

func validateInfo(info os.FileInfo, directory bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("%w: expected directory", ErrInvalidPath)
	}
	if !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: expected regular file", ErrInvalidPath)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode %04o", ErrInsecureMode, info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return ErrNotOwned
	}
	return nil
}

func validateOpenFile(file *os.File, directory bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return validateInfo(info, directory)
}

func openNoFollow(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlink
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func syncDir(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	return dir.Sync()
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
