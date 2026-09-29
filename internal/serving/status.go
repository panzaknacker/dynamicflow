package serving

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
)

const StatusSchema = 1

var (
	ErrInvalidStatus = errors.New("invalid instance status")
	ErrUnsafeState   = errors.New("unsafe serving state path")
	statusNameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	statusDigestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type ComponentStatus struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	State   string `json:"state"`
	Code    string `json:"code,omitempty"`
}

// StatusReport deliberately uses finite state and error-code fields instead
// of arbitrary messages, which avoids persisting secrets from stderr.
type StatusReport struct {
	Schema            int               `json:"schema"`
	Instance          string            `json:"instance"`
	Profile           string            `json:"profile"`
	DesiredGeneration uint64            `json:"desired_generation"`
	AppliedGeneration uint64            `json:"applied_generation"`
	ReleaseSet        string            `json:"release_set"`
	State             string            `json:"state"`
	Components        []ComponentStatus `json:"components"`
	Revoked           bool              `json:"revoked,omitempty"`
	FailClosed        bool              `json:"fail_closed,omitempty"`
	SSHHostKey        string            `json:"ssh_host_key,omitempty"`
	ReportedAt        int64             `json:"reported_at"`
}

type StatusStore struct {
	directory string
	mu        sync.RWMutex
}

func NewStatusStore(directory string) (*StatusStore, error) {
	if err := secureDirectory(directory); err != nil {
		return nil, err
	}
	return &StatusStore{directory: filepath.Clean(directory)}, nil
}

func (store *StatusStore) Put(report StatusReport) error {
	if err := ValidateStatus(report); err != nil {
		return err
	}
	if !statusComponentsCanonical(report.Components) {
		return fmt.Errorf("%w: components are not canonical", ErrInvalidStatus)
	}
	data, err := signing.CanonicalJSON(report)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return writeAtomicPrivate(filepath.Join(store.directory, report.Instance+".json"), data)
}

func (store *StatusStore) Get(instance string) (StatusReport, error) {
	if !validStatusName(instance) {
		return StatusReport{}, ErrInvalidStatus
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	path := filepath.Join(store.directory, instance+".json")
	data, err := readPrivateFile(path)
	if err != nil {
		return StatusReport{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report StatusReport
	if err := decoder.Decode(&report); err != nil {
		return StatusReport{}, fmt.Errorf("decode status: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return StatusReport{}, ErrInvalidStatus
	}
	canonical, err := signing.CanonicalJSON(report)
	if err != nil || !bytes.Equal(canonical, data) {
		return StatusReport{}, ErrInvalidStatus
	}
	if err := ValidateStatus(report); err != nil || !statusComponentsCanonical(report.Components) {
		return StatusReport{}, ErrInvalidStatus
	}
	return report, nil
}

func ValidateStatus(report StatusReport) error {
	if report.Schema != StatusSchema || !validStatusName(report.Instance) || !validStatusName(report.Profile) ||
		report.DesiredGeneration == 0 || report.AppliedGeneration > report.DesiredGeneration ||
		!statusDigestRE.MatchString(report.ReleaseSet) || !validOverallState(report.State) || report.ReportedAt <= 0 ||
		len(report.Components) > 128 {
		return ErrInvalidStatus
	}
	if report.Revoked || report.FailClosed || report.State == "revoked" {
		if !IsRevocationAcknowledgement(report) {
			return ErrInvalidStatus
		}
	}
	seen := make(map[string]struct{}, len(report.Components))
	for _, component := range report.Components {
		if !validStatusName(component.Name) || !validStatusToken(component.Version) || !validComponentState(component.State) ||
			(component.Code != "" && !validStatusName(component.Code)) {
			return ErrInvalidStatus
		}
		if _, exists := seen[component.Name]; exists {
			return ErrInvalidStatus
		}
		seen[component.Name] = struct{}{}
	}
	if report.SSHHostKey != "" {
		normalized, _, err := sshkeys.ValidateEd25519PublicKey(report.SSHHostKey)
		fields := strings.Fields(normalized)
		if err != nil || len(fields) < 2 || report.SSHHostKey != strings.Join(fields[:2], " ") {
			return ErrInvalidStatus
		}
	}
	return nil
}

// IsRevocationAcknowledgement recognizes the only status a revoked instance
// identity may submit. it is deliberately exact and contains no free-form
// diagnostics or host key: the identity can acknowledge only that its fixed
// local SSH fail-closed action succeeded.
func IsRevocationAcknowledgement(report StatusReport) bool {
	return report.Revoked && report.FailClosed && report.State == "revoked" && report.SSHHostKey == "" &&
		len(report.Components) == 1 && report.Components[0].Name == "ssh" &&
		validStatusToken(report.Components[0].Version) && report.Components[0].State == "blocked" &&
		report.Components[0].Code == "revoked"
}

func NormalizeStatus(report StatusReport) StatusReport {
	result := report
	result.Components = append([]ComponentStatus(nil), report.Components...)
	sort.Slice(result.Components, func(i, j int) bool { return result.Components[i].Name < result.Components[j].Name })
	return result
}

func statusComponentsCanonical(components []ComponentStatus) bool {
	for index := 1; index < len(components); index++ {
		if components[index-1].Name >= components[index].Name {
			return false
		}
	}
	return true
}

func validOverallState(state string) bool {
	switch state {
	case "pending", "applying", "ready", "degraded", "failed", "blocked", "rolled-back", "revoked":
		return true
	default:
		return false
	}
}

func validComponentState(state string) bool {
	switch state {
	case "pending", "applying", "ready", "failed", "blocked", "rolled-back", "skipped":
		return true
	default:
		return false
	}
}

func validStatusName(value string) bool {
	return value != "." && value != ".." && statusNameRE.MatchString(value)
}

func validStatusToken(value string) bool {
	return value != "" && len(value) <= 64 && !strings.ContainsAny(value, "\r\n\x00/\\") && statusNameRE.MatchString(value)
}

func secureDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: directory must be absolute", ErrUnsafeState)
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return fmt.Errorf("%w: refusing filesystem root", ErrUnsafeState)
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: directory path contains a symlink or non-directory", ErrUnsafeState)
		}
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: state directory must be mode 0700 or stricter", ErrUnsafeState)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: state directory must be owned by the service user", ErrUnsafeState)
	}
	return nil
}

func writeAtomicPrivate(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !privateStateFileInfo(info, 0o600, 1<<20) {
			return ErrUnsafeState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".write-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
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
	return syncStateDirectory(directory)
}

func readPrivateFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrUnsafeState
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !privateStateFileInfo(info, 0o600, 1<<20) {
		return nil, ErrUnsafeState
	}
	if info.Size() > 1<<20 {
		return nil, ErrInvalidStatus
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 || int64(len(data)) != info.Size() {
		return nil, ErrInvalidStatus
	}
	return data, nil
}

func privateStateFileInfo(info os.FileInfo, mode os.FileMode, maxSize int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode ||
		info.Size() < 0 || info.Size() > maxSize {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && int(stat.Uid) == os.Geteuid()
}

func syncStateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
