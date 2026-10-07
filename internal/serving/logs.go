package serving

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"dynamicflow/internal/signing"
)

const (
	LogSchema         = 1
	MaxLogBatchEvents = 256
	// With the finite nine-component allowlist, 1024 maximally sized events
	// per component keep the authenticated aggregate operator response below
	// the client's 2 MiB bound while retaining substantially more than one
	// upload batch.
	MaxRetainedEvents = 1024
	MaxLogComponents  = 32
)

var (
	ErrInvalidLog          = errors.New("invalid sanitized instance log")
	ErrLogSequenceConflict = fmt.Errorf("%w: sequence conflict", ErrInvalidLog)
	ErrLogCapacity         = fmt.Errorf("%w: component capacity reached", ErrInvalidLog)
)

// LogEvent deliberately has no free-form message field. Instances may upload
// only finite event and error-code tokens; raw stderr and secrets remain on the
// target in its protected, locally rotated component log.
type LogEvent struct {
	Sequence  uint64 `json:"sequence"`
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	Code      string `json:"code,omitempty"`
}

type LogBatch struct {
	Schema    int        `json:"schema"`
	Instance  string     `json:"instance"`
	Profile   string     `json:"profile"`
	Component string     `json:"component"`
	Events    []LogEvent `json:"events"`
}

type LogSnapshot struct {
	Schema    int        `json:"schema"`
	Instance  string     `json:"instance"`
	Component string     `json:"component"`
	Events    []LogEvent `json:"events"`
}

type LogStore struct {
	directory string
	mu        sync.RWMutex
}

func NewLogStore(directory string) (*LogStore, error) {
	if err := secureDirectory(directory); err != nil {
		return nil, err
	}
	return &LogStore{directory: filepath.Clean(directory)}, nil
}

func ValidateLogBatch(batch LogBatch) error {
	if batch.Schema != LogSchema || !validStatusName(batch.Instance) ||
		!validStatusName(batch.Profile) || !validLogComponent(batch.Component) ||
		len(batch.Events) == 0 || len(batch.Events) > MaxLogBatchEvents {
		return ErrInvalidLog
	}
	return validateLogEvents(batch.Events)
}

// ValidateLogSnapshot applies the same finite-token contract to data returned
// to an operator. Callers must validate snapshots even though the transport is
// authenticated: a compromised serving node must not be able to inject
// terminal control characters through a human-readable log view.
func ValidateLogSnapshot(snapshot LogSnapshot) error {
	if snapshot.Schema != LogSchema || !validStatusName(snapshot.Instance) ||
		!validLogComponent(snapshot.Component) || len(snapshot.Events) == 0 ||
		len(snapshot.Events) > MaxRetainedEvents {
		return ErrInvalidLog
	}
	return validateLogEvents(snapshot.Events)
}

func validateLogEvents(events []LogEvent) error {
	var previous uint64
	for index, event := range events {
		if event.Sequence == 0 || event.Timestamp <= 0 || !validLogLevel(event.Level) ||
			!validLogEvent(event.Event) || !validLogCode(event.Code) ||
			(index > 0 && event.Sequence <= previous) {
			return ErrInvalidLog
		}
		previous = event.Sequence
	}
	return nil
}

func validLogComponent(component string) bool {
	switch component {
	case "flow", "instance-runtime", "ssh", "ssh-gui", "vpn", "vpn-pbp-de", "pbp", "decepticon", "examstation":
		return true
	default:
		return false
	}
}

func validLogEvent(event string) bool {
	switch event {
	case "reconcile_started", "phase_preflight", "phase_applying", "phase_verifying",
		"phase_complete", "phase_failed", "phase_fail_closed", "reconcile_complete", "reconcile_failed",
		"pbp_launch_started", "pbp_browser_started", "pbp_browser_crashed",
		"pbp_egress_rejected", "pbp_egress_unavailable", "pbp_launch_rejected",
		"pbp_launch_failed", "pbp_cleanup_failed", "pbp_launch_ended":
		return true
	default:
		return false
	}
}

func validLogCode(code string) bool {
	switch code {
	case "", "artifact_verification", "installer_failed", "rollback_failed", "phase_failed", "apply_busy", "revoked",
		"normal_user_close", "vpn_wrong", "vpn_relay_changed", "vpn_unavailable",
		"vpn_control_failure", "signal", "browser_crash", "browser_closed_unexpectedly",
		"browser_cleanup_failed", "startup_error":
		return true
	default:
		return false
	}
}

// IsRevocationLogBatch recognizes the only finite log event accepted after a
// desired-state revocation. The generation-bound status acknowledgement is
// authoritative; this event only makes the local SSH fail-closed transition
// visible in the component log.
func IsRevocationLogBatch(batch LogBatch) bool {
	return batch.Component == "ssh" && len(batch.Events) == 1 &&
		batch.Events[0].Level == "critical" && batch.Events[0].Event == "phase_fail_closed" &&
		batch.Events[0].Code == "revoked"
}

func validLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warning", "error", "critical":
		return true
	default:
		return false
	}
}

func (store *LogStore) Put(batch LogBatch) error {
	if err := ValidateLogBatch(batch); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := lockDesiredFile(filepath.Join(store.directory, ".logs.lock"))
	if err != nil {
		return err
	}
	defer unlockDesiredFile(lock)
	instanceDirectory := filepath.Join(store.directory, batch.Instance)
	if err := secureDirectory(instanceDirectory); err != nil {
		return err
	}
	componentCount, err := validateLogInstanceDirectory(instanceDirectory)
	if err != nil {
		return err
	}
	path := filepath.Join(instanceDirectory, batch.Component+".json")
	snapshot := LogSnapshot{Schema: LogSchema, Instance: batch.Instance, Component: batch.Component}
	data, err := readPrivateFile(path)
	if err == nil {
		if err := decodeCanonicalLogSnapshot(data, &snapshot); err != nil {
			return err
		}
		if snapshot.Instance != batch.Instance || snapshot.Component != batch.Component {
			return ErrInvalidLog
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if componentCount >= MaxLogComponents {
		return ErrLogCapacity
	}
	// Once retention has discarded an event, accepting that sequence again
	// would make collision detection depend on upload timing. Reject batches
	// older than the retained watermark instead of resurrecting them.
	if len(snapshot.Events) == MaxRetainedEvents && batch.Events[0].Sequence < snapshot.Events[0].Sequence {
		return ErrLogSequenceConflict
	}

	bySequence := make(map[uint64]LogEvent, len(snapshot.Events)+len(batch.Events))
	for _, event := range snapshot.Events {
		bySequence[event.Sequence] = event
	}
	for _, event := range batch.Events {
		if existing, present := bySequence[event.Sequence]; present && existing != event {
			return ErrLogSequenceConflict
		}
		bySequence[event.Sequence] = event
	}
	snapshot.Events = snapshot.Events[:0]
	for _, event := range bySequence {
		snapshot.Events = append(snapshot.Events, event)
	}
	sort.Slice(snapshot.Events, func(left, right int) bool {
		return snapshot.Events[left].Sequence < snapshot.Events[right].Sequence
	})
	if len(snapshot.Events) > MaxRetainedEvents {
		snapshot.Events = append([]LogEvent(nil), snapshot.Events[len(snapshot.Events)-MaxRetainedEvents:]...)
	}
	encoded, err := signing.CanonicalJSON(snapshot)
	if err != nil {
		return err
	}
	return writeAtomicPrivate(path, encoded)
}

func (store *LogStore) Get(instance, component string) (LogSnapshot, error) {
	if !validStatusName(instance) || !validLogComponent(component) {
		return LogSnapshot{}, ErrInvalidLog
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	lock, err := lockDesiredFile(filepath.Join(store.directory, ".logs.lock"))
	if err != nil {
		return LogSnapshot{}, err
	}
	defer unlockDesiredFile(lock)
	path := filepath.Join(store.directory, instance, component+".json")
	data, err := readPrivateFile(path)
	if err != nil {
		return LogSnapshot{}, err
	}
	var snapshot LogSnapshot
	if err := decodeCanonicalLogSnapshot(data, &snapshot); err != nil {
		return LogSnapshot{}, err
	}
	if snapshot.Instance != instance || snapshot.Component != component {
		return LogSnapshot{}, ErrInvalidLog
	}
	return snapshot, nil
}

func (store *LogStore) List(instance string) ([]LogSnapshot, error) {
	if !validStatusName(instance) {
		return nil, ErrInvalidLog
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	lock, err := lockDesiredFile(filepath.Join(store.directory, ".logs.lock"))
	if err != nil {
		return nil, err
	}
	defer unlockDesiredFile(lock)
	directory := filepath.Join(store.directory, instance)
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafeState
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, ErrUnsafeState
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxLogComponents {
		return nil, ErrUnsafeState
	}
	result := make([]LogSnapshot, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			return nil, ErrUnsafeState
		}
		component := strings.TrimSuffix(name, ".json")
		if !validLogComponent(component) || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, ErrUnsafeState
		}
		data, err := readPrivateFile(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		var snapshot LogSnapshot
		if err := decodeCanonicalLogSnapshot(data, &snapshot); err != nil || snapshot.Instance != instance || snapshot.Component != component {
			return nil, ErrInvalidLog
		}
		result = append(result, snapshot)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Component < result[right].Component })
	return result, nil
}

func validateLogInstanceDirectory(directory string) (int, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	if len(entries) > MaxLogComponents {
		return 0, ErrUnsafeState
	}
	for _, entry := range entries {
		name := entry.Name()
		component := strings.TrimSuffix(name, ".json")
		info, infoErr := entry.Info()
		if infoErr != nil || !strings.HasSuffix(name, ".json") || !validLogComponent(component) ||
			!privateStateFileInfo(info, 0o600, 1<<20) {
			return 0, ErrUnsafeState
		}
	}
	return len(entries), nil
}

func decodeCanonicalLogSnapshot(data []byte, snapshot *LogSnapshot) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(snapshot); err != nil {
		return fmt.Errorf("decode log snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidLog
	}
	canonical, err := signing.CanonicalJSON(*snapshot)
	if err != nil || !bytes.Equal(canonical, data) || ValidateLogSnapshot(*snapshot) != nil {
		return ErrInvalidLog
	}
	return nil
}
