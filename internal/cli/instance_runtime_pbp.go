package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/serving"
)

const (
	pbpRuntimeUser             = "malwarelab"
	pbpRuntimeHome             = "/home/malwarelab"
	pbpRuntimeLogRelative      = ".local/state/dynamicflow/pbp/logs"
	pbpRuntimeBridgePath       = "reports/pbp-runtime-bridge.json"
	pbpRuntimeBridgeLock       = "reports/pbp-runtime-bridge.lock"
	pbpRuntimeLogMaxBytes      = 4 << 20
	pbpRuntimeLogMaxLineBytes  = 16 << 10
	pbpRuntimeLogMaxFiles      = 8
	pbpRuntimeDirMaxEntries    = 256
	pbpRuntimeMaxLinesPerRun   = 1024
	pbpRuntimeMaxEventsPerRun  = 256
	pbpRuntimeMaxTrackedFiles  = 64
	pbpRuntimeBridgeCheckpoint = 1
)

type pbpRuntimeSource struct {
	home string
	uid  uint32
}

type pbpRuntimeFileCheckpoint struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	Done   bool   `json:"done,omitempty"`
}

type pbpRuntimePending struct {
	File   string           `json:"file"`
	Device uint64           `json:"device"`
	Inode  uint64           `json:"inode"`
	Offset int64            `json:"offset"`
	Event  serving.LogEvent `json:"event"`
}

type pbpRuntimeBridgeState struct {
	Schema    int                                 `json:"schema"`
	HighWater string                              `json:"high_water,omitempty"`
	Files     map[string]pbpRuntimeFileCheckpoint `json:"files"`
	Pending   *pbpRuntimePending                  `json:"pending,omitempty"`
}

type pbpRuntimeLocalRecord struct {
	Event  string `json:"event"`
	Reason string `json:"reason"`
}

type pbpRuntimeOpenFile struct {
	name   string
	file   *os.File
	device uint64
	inode  uint64
	size   int64
}

func reportPBPRuntimeLogs(
	ctx context.Context,
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	now func() time.Time,
) error {
	if config.Profile != "pbp" {
		return nil
	}
	account, err := user.Lookup(pbpRuntimeUser)
	if err != nil || account.Username != pbpRuntimeUser || filepath.Clean(account.HomeDir) != pbpRuntimeHome {
		return errRuntimeConfiguration
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errRuntimeConfiguration
	}
	return reportPBPRuntimeLogsFrom(ctx, config, client, now, pbpRuntimeSource{
		home: pbpRuntimeHome,
		uid:  uint32(uid),
	})
}

func reportPBPRuntimeLogsFrom(
	ctx context.Context,
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	now func() time.Time,
	source pbpRuntimeSource,
) error {
	if ctx == nil || client == nil || now == nil || !filepath.IsAbs(source.home) {
		return errRuntimeConfiguration
	}
	store, err := openInstanceRuntimeStore(config.StateRoot)
	if err != nil {
		return err
	}
	return store.WithLock(pbpRuntimeBridgeLock, func() error {
		state, err := readPBPRuntimeBridgeState(store)
		if err != nil {
			return err
		}
		if state.Pending != nil {
			if err := uploadPBPPending(ctx, config, client, store, &state); err != nil {
				return err
			}
		}
		files, err := openPBPRuntimeLogs(source)
		if err != nil {
			return err
		}
		defer closePBPRuntimeFiles(files)

		lines, emitted := 0, 0
		for _, sourceFile := range files {
			checkpoint, exists := state.Files[sourceFile.name]
			if !exists {
				if state.HighWater != "" && sourceFile.name <= state.HighWater {
					continue
				}
				checkpoint = pbpRuntimeFileCheckpoint{Device: sourceFile.device, Inode: sourceFile.inode}
				state.Files[sourceFile.name] = checkpoint
				prunePBPRuntimeBridgeState(&state)
				checkpoint, exists = state.Files[sourceFile.name]
				if !exists {
					continue
				}
			}
			if checkpoint.Done {
				continue
			}
			if checkpoint.Device != sourceFile.device || checkpoint.Inode != sourceFile.inode {
				checkpoint.Done = true
				state.Files[sourceFile.name] = checkpoint
				continue
			}
			if sourceFile.size < checkpoint.Offset {
				// The launcher never truncates or reuses a runtime log. Refuse the
				// changed identity permanently instead of replaying old offsets.
				checkpoint.Done = true
				state.Files[sourceFile.name] = checkpoint
				continue
			}
			offset := checkpoint.Offset
			reader := bufio.NewReaderSize(
				io.NewSectionReader(sourceFile.file, offset, sourceFile.size-offset),
				pbpRuntimeLogMaxLineBytes+1,
			)
			for offset < sourceFile.size && lines < pbpRuntimeMaxLinesPerRun && emitted < pbpRuntimeMaxEventsPerRun {
				line, consumed, complete, oversized, readErr := readBoundedPBPLine(reader)
				if readErr != nil {
					return readErr
				}
				if !complete {
					break
				}
				lines++
				nextOffset := offset + consumed
				event, selected := normalizePBPRuntimeRecord(line, oversized)
				if selected {
					sequence, err := allocateInstanceRuntimeLogSequence(config.StateRoot, "pbp")
					if err != nil {
						return err
					}
					event.Sequence = sequence
					event.Timestamp = now().UTC().Unix()
					state.Pending = &pbpRuntimePending{
						File: sourceFile.name, Device: sourceFile.device, Inode: sourceFile.inode,
						Offset: nextOffset, Event: event,
					}
					if err := writePBPRuntimeBridgeState(store, state); err != nil {
						return err
					}
					if err := uploadPBPPending(ctx, config, client, store, &state); err != nil {
						return err
					}
					emitted++
				} else {
					checkpoint.Offset = nextOffset
					state.Files[sourceFile.name] = checkpoint
				}
				offset = nextOffset
			}
			if state.Pending == nil {
				checkpoint = state.Files[sourceFile.name]
				if !checkpoint.Done && checkpoint.Device == sourceFile.device && checkpoint.Inode == sourceFile.inode {
					checkpoint.Offset = offset
					state.Files[sourceFile.name] = checkpoint
				}
			}
			prunePBPRuntimeBridgeState(&state)
			if err := writePBPRuntimeBridgeState(store, state); err != nil {
				return err
			}
			if lines >= pbpRuntimeMaxLinesPerRun || emitted >= pbpRuntimeMaxEventsPerRun {
				break
			}
		}
		return nil
	})
}

func readPBPRuntimeBridgeState(store *localstate.Store) (pbpRuntimeBridgeState, error) {
	state := pbpRuntimeBridgeState{Schema: pbpRuntimeBridgeCheckpoint, Files: map[string]pbpRuntimeFileCheckpoint{}}
	if err := store.ReadJSON(pbpRuntimeBridgePath, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, fmt.Errorf("%w: PBP bridge checkpoint", errRuntimeConfiguration)
	}
	if err := validatePBPRuntimeBridgeState(state); err != nil {
		return state, err
	}
	return state, nil
}

func writePBPRuntimeBridgeState(store *localstate.Store, state pbpRuntimeBridgeState) error {
	if err := validatePBPRuntimeBridgeState(state); err != nil {
		return err
	}
	return store.WriteJSON(pbpRuntimeBridgePath, state)
}

func validatePBPRuntimeBridgeState(state pbpRuntimeBridgeState) error {
	if state.Schema != pbpRuntimeBridgeCheckpoint || state.Files == nil ||
		len(state.Files) > pbpRuntimeMaxTrackedFiles || (state.HighWater != "" && !pbpRuntimeLogName(state.HighWater)) {
		return errRuntimeConfiguration
	}
	for name, checkpoint := range state.Files {
		if !pbpRuntimeLogName(name) || checkpoint.Device == 0 || checkpoint.Inode == 0 ||
			checkpoint.Offset < 0 || checkpoint.Offset > pbpRuntimeLogMaxBytes {
			return errRuntimeConfiguration
		}
	}
	if state.Pending != nil {
		pending := state.Pending
		checkpoint, exists := state.Files[pending.File]
		if !exists || checkpoint.Done || pending.Device != checkpoint.Device || pending.Inode != checkpoint.Inode ||
			pending.Offset <= checkpoint.Offset || pending.Offset > pbpRuntimeLogMaxBytes ||
			pending.Event.Sequence == 0 || pending.Event.Timestamp <= 0 ||
			!validNormalizedPBPRuntimeEvent(pending.Event) {
			return errRuntimeConfiguration
		}
	}
	return nil
}

func uploadPBPPending(
	ctx context.Context,
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	store *localstate.Store,
	state *pbpRuntimeBridgeState,
) error {
	pending := state.Pending
	if pending == nil {
		return nil
	}
	if err := client.ReportLogs(ctx, serving.LogBatch{
		Schema: serving.LogSchema, Instance: config.Instance, Profile: config.Profile,
		Component: "pbp", Events: []serving.LogEvent{pending.Event},
	}); err != nil {
		return err
	}
	checkpoint := state.Files[pending.File]
	checkpoint.Offset = pending.Offset
	state.Files[pending.File] = checkpoint
	state.Pending = nil
	return writePBPRuntimeBridgeState(store, *state)
}

func normalizePBPRuntimeRecord(line []byte, oversized bool) (serving.LogEvent, bool) {
	if oversized || len(line) == 0 || len(line) > pbpRuntimeLogMaxLineBytes {
		return serving.LogEvent{}, false
	}
	var projected map[string]json.RawMessage
	if json.Unmarshal(line, &projected) != nil {
		return serving.LogEvent{}, false
	}
	var record pbpRuntimeLocalRecord
	eventRaw, ok := projected["event"]
	if !ok || json.Unmarshal(eventRaw, &record.Event) != nil {
		return serving.LogEvent{}, false
	}
	if reasonRaw, ok := projected["reason"]; ok {
		if json.Unmarshal(reasonRaw, &record.Reason) != nil {
			return serving.LogEvent{}, false
		}
	}
	switch record.Event {
	case "launch.begin":
		return serving.LogEvent{Level: "info", Event: "pbp_launch_started"}, true
	case "browser.context_started":
		return serving.LogEvent{Level: "info", Event: "pbp_browser_started"}, true
	case "browser.page_crashed":
		return serving.LogEvent{Level: "error", Event: "pbp_browser_crashed"}, true
	case "launch.egress_rejected":
		return serving.LogEvent{Level: "critical", Event: "pbp_egress_rejected", Code: "vpn_wrong"}, true
	case "launch.egress_unavailable":
		return serving.LogEvent{Level: "error", Event: "pbp_egress_unavailable", Code: "vpn_unavailable"}, true
	case "launch.rejected":
		return serving.LogEvent{Level: "error", Event: "pbp_launch_rejected", Code: "startup_error"}, true
	case "launch.internal_error":
		return serving.LogEvent{Level: "error", Event: "pbp_launch_failed", Code: "browser_closed_unexpectedly"}, true
	case "profile.cleanup_failed":
		return serving.LogEvent{Level: "critical", Event: "pbp_cleanup_failed", Code: "browser_cleanup_failed"}, true
	case "launch.end":
		if !validPBPLifecycleReason(record.Reason) {
			return serving.LogEvent{}, false
		}
		level := "info"
		if record.Reason != "normal_user_close" && record.Reason != "signal" {
			level = "error"
		}
		return serving.LogEvent{Level: level, Event: "pbp_launch_ended", Code: record.Reason}, true
	default:
		return serving.LogEvent{}, false
	}
}

func validNormalizedPBPRuntimeEvent(event serving.LogEvent) bool {
	if event.Sequence == 0 || event.Timestamp <= 0 {
		return false
	}
	switch event.Event {
	case "pbp_launch_started":
		return event.Level == "info" && event.Code == ""
	case "pbp_browser_started":
		return event.Level == "info" && event.Code == ""
	case "pbp_browser_crashed":
		return event.Level == "error" && event.Code == ""
	case "pbp_egress_rejected":
		return event.Level == "critical" && event.Code == "vpn_wrong"
	case "pbp_egress_unavailable":
		return event.Level == "error" && event.Code == "vpn_unavailable"
	case "pbp_launch_rejected":
		return event.Level == "error" && event.Code == "startup_error"
	case "pbp_launch_failed":
		return event.Level == "error" && event.Code == "browser_closed_unexpectedly"
	case "pbp_cleanup_failed":
		return event.Level == "critical" && event.Code == "browser_cleanup_failed"
	case "pbp_launch_ended":
		return (event.Level == "info" || event.Level == "error") && validPBPLifecycleReason(event.Code)
	default:
		return false
	}
}

func validPBPLifecycleReason(reason string) bool {
	switch reason {
	case "normal_user_close", "vpn_wrong", "vpn_relay_changed", "vpn_unavailable",
		"vpn_control_failure", "signal", "browser_crash", "browser_closed_unexpectedly",
		"browser_cleanup_failed", "startup_error":
		return true
	default:
		return false
	}
}

func readBoundedPBPLine(reader *bufio.Reader) ([]byte, int64, bool, bool, error) {
	var line []byte
	var consumed int64
	oversized := false
	for {
		part, err := reader.ReadSlice('\n')
		consumed += int64(len(part))
		if !oversized && len(line)+len(part) <= pbpRuntimeLogMaxLineBytes {
			line = append(line, part...)
		} else {
			oversized = true
			line = nil
		}
		switch {
		case err == nil:
			return bytes.TrimSuffix(line, []byte{'\n'}), consumed, true, oversized, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil, consumed, false, oversized, nil
		default:
			return nil, consumed, false, oversized, err
		}
	}
}

func openPBPRuntimeLogs(source pbpRuntimeSource) ([]pbpRuntimeOpenFile, error) {
	logDir, err := openPBPRuntimeLogDirectory(source)
	if err != nil {
		return nil, err
	}
	defer logDir.Close()
	names, err := logDir.Readdirnames(pbpRuntimeDirMaxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > pbpRuntimeDirMaxEntries {
		return nil, errRuntimeConfiguration
	}
	sort.Strings(names)
	files := make([]pbpRuntimeOpenFile, 0, pbpRuntimeLogMaxFiles)
	for _, name := range names {
		if !pbpRuntimeLogName(name) {
			continue
		}
		if len(files) == pbpRuntimeLogMaxFiles {
			closePBPRuntimeFiles(files)
			return nil, errRuntimeConfiguration
		}
		fd, openErr := syscall.Openat(
			int(logDir.Fd()), name,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
			0,
		)
		if openErr != nil {
			closePBPRuntimeFiles(files)
			return nil, openErr
		}
		file := os.NewFile(uintptr(fd), name)
		var details syscall.Stat_t
		if err := syscall.Fstat(fd, &details); err != nil ||
			details.Mode&syscall.S_IFMT != syscall.S_IFREG || details.Uid != source.uid ||
			details.Nlink != 1 || details.Mode&0o7777 != 0o600 ||
			details.Size < 0 || details.Size > pbpRuntimeLogMaxBytes {
			file.Close()
			closePBPRuntimeFiles(files)
			return nil, errRuntimeConfiguration
		}
		files = append(files, pbpRuntimeOpenFile{
			name: name, file: file, device: uint64(details.Dev), inode: details.Ino, size: details.Size,
		})
	}
	return files, nil
}

func openPBPRuntimeLogDirectory(source pbpRuntimeSource) (*os.File, error) {
	cleanHome := filepath.Clean(source.home)
	if !filepath.IsAbs(cleanHome) || cleanHome == "/" {
		return nil, errRuntimeConfiguration
	}
	full := filepath.Join(cleanHome, filepath.FromSlash(pbpRuntimeLogRelative))
	parts := strings.Split(strings.TrimPrefix(full, "/"), "/")
	homeParts := strings.Split(strings.TrimPrefix(cleanHome, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for index, part := range parts {
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		if index < len(homeParts)-1 {
			continue
		}
		var details syscall.Stat_t
		if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
			details.Uid != source.uid {
			syscall.Close(fd)
			return nil, errRuntimeConfiguration
		}
		mode := details.Mode & 0o7777
		if index == len(homeParts)-1 {
			if mode != 0o700 && mode != 0o750 {
				syscall.Close(fd)
				return nil, errRuntimeConfiguration
			}
		} else if mode != 0o700 {
			syscall.Close(fd)
			return nil, errRuntimeConfiguration
		}
	}
	return os.NewFile(uintptr(fd), full), nil
}

func closePBPRuntimeFiles(files []pbpRuntimeOpenFile) {
	for _, file := range files {
		_ = file.file.Close()
	}
}

func pbpRuntimeLogName(name string) bool {
	if !strings.HasPrefix(name, "runtime-") || !strings.HasSuffix(name, ".jsonl") {
		return false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(name, "runtime-"), ".jsonl")
	segments := strings.Split(stem, "-")
	if len(segments) != 3 {
		return false
	}
	timestamp, pid, nonce := segments[0], segments[1], segments[2]
	if len(timestamp) != 16 || timestamp[8] != 'T' || timestamp[15] != 'Z' ||
		len(pid) == 0 || len(pid) > 10 || len(nonce) != 8 {
		return false
	}
	for index, char := range timestamp {
		if index == 8 || index == 15 {
			continue
		}
		if char < '0' || char > '9' {
			return false
		}
	}
	for _, char := range pid {
		if char < '0' || char > '9' {
			return false
		}
	}
	for _, char := range nonce {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func prunePBPRuntimeBridgeState(state *pbpRuntimeBridgeState) {
	if len(state.Files) <= pbpRuntimeMaxTrackedFiles {
		return
	}
	names := make([]string, 0, len(state.Files))
	for name := range state.Files {
		if state.Pending == nil || name != state.Pending.File {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for len(state.Files) > pbpRuntimeMaxTrackedFiles && len(names) > 0 {
		name := names[0]
		names = names[1:]
		delete(state.Files, name)
		if name > state.HighWater {
			state.HighWater = name
		}
	}
}
