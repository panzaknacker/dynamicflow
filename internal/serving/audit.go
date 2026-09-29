package serving

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"

	"dynamicflow/internal/signing"
)

var auditTokenRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// AuditEvent has no free-form body, URL, enrollment ID, secret, key or error
// text fields. this keeps the audit contract useful without becoming a secret
// exfiltration surface.
type AuditEvent struct {
	Timestamp int64  `json:"timestamp"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	Instance  string `json:"instance,omitempty"`
	Profile   string `json:"profile,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
}

type AuditSink interface {
	Record(AuditEvent) error
}

type AuditFunc func(AuditEvent) error

func (function AuditFunc) Record(event AuditEvent) error { return function(event) }

type FileAuditLog struct {
	path string
	mu   sync.Mutex
}

func NewFileAuditLog(path string) (*FileAuditLog, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrUnsafeState
	}
	if err := secureDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !privateStateFileInfo(info, 0o600, 1<<30) {
			return nil, ErrUnsafeState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &FileAuditLog{path: filepath.Clean(path)}, nil
}

func (log *FileAuditLog) Record(event AuditEvent) error {
	if err := validateAuditEvent(event); err != nil {
		return err
	}
	data, err := signing.CanonicalJSON(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	log.mu.Lock()
	defer log.mu.Unlock()
	fd, err := syscall.Open(log.path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), log.path)
	if file == nil {
		syscall.Close(fd)
		return errors.New("open audit log")
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || stat.Mode&0o077 != 0 {
		return ErrUnsafeState
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func validateAuditEvent(event AuditEvent) error {
	if event.Timestamp <= 0 || !auditTokenRE.MatchString(event.Action) || !auditTokenRE.MatchString(event.Outcome) ||
		(event.Instance != "" && !validStatusName(event.Instance)) || (event.Profile != "" && !validStatusName(event.Profile)) {
		return fmt.Errorf("invalid redacted audit event")
	}
	if event.RemoteIP != "" && net.ParseIP(event.RemoteIP) == nil {
		return fmt.Errorf("invalid redacted audit remote IP")
	}
	return nil
}
