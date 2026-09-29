package serving

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"dynamicflow/internal/signing"
)

func TestLogContractUsesFiniteAllowlists(t *testing.T) {
	valid := testLogBatch("vm-01", "pbp", "pbp", 1, 1)
	if err := ValidateLogBatch(valid); err != nil {
		t.Fatalf("valid batch: %v", err)
	}
	tokenShapedSecret := strings.Repeat("A", 43)
	for name, mutate := range map[string]func(*LogBatch){
		"component": func(batch *LogBatch) { batch.Component = tokenShapedSecret },
		"event":     func(batch *LogBatch) { batch.Events[0].Event = tokenShapedSecret },
		"code":      func(batch *LogBatch) { batch.Events[0].Code = tokenShapedSecret },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Events = append([]LogEvent(nil), valid.Events...)
			mutate(&candidate)
			if err := ValidateLogBatch(candidate); !errors.Is(err, ErrInvalidLog) {
				t.Fatalf("token outside allowlist accepted: %v", err)
			}
		})
	}
}

func TestLogContractAcceptsOnlyFinitePBPRuntimeVocabulary(t *testing.T) {
	for _, candidate := range []LogEvent{
		{Sequence: 1, Timestamp: 1_800_000_000, Level: "info", Event: "pbp_launch_started"},
		{Sequence: 1, Timestamp: 1_800_000_000, Level: "error", Event: "pbp_browser_crashed"},
		{Sequence: 1, Timestamp: 1_800_000_000, Level: "critical", Event: "pbp_egress_rejected", Code: "vpn_wrong"},
		{Sequence: 1, Timestamp: 1_800_000_000, Level: "error", Event: "pbp_launch_ended", Code: "browser_cleanup_failed"},
	} {
		batch := LogBatch{Schema: LogSchema, Instance: "vm-01", Profile: "pbp", Component: "pbp", Events: []LogEvent{candidate}}
		if err := ValidateLogBatch(batch); err != nil {
			t.Fatalf("finite PBP event rejected: %#v: %v", candidate, err)
		}
	}
	for _, forbidden := range []string{
		"browser crashed at /home/malwarelab/profile",
		"https://secret.example/path",
		"203.0.113.7",
		"token=SUPER-SECRET",
		"--password=secret",
	} {
		batch := LogBatch{
			Schema: LogSchema, Instance: "vm-01", Profile: "pbp", Component: "pbp",
			Events: []LogEvent{{Sequence: 1, Timestamp: 1_800_000_000, Level: "error", Event: forbidden}},
		}
		if err := ValidateLogBatch(batch); !errors.Is(err, ErrInvalidLog) {
			t.Fatalf("free-form PBP value accepted: %q: %v", forbidden, err)
		}
	}
}

func TestRevocationLogBatchIsOneExactFiniteSSHEvent(t *testing.T) {
	batch := LogBatch{
		Schema: LogSchema, Instance: "vm-01", Profile: "pbp", Component: "ssh",
		Events: []LogEvent{{
			Sequence: 1, Timestamp: 1_800_000_000, Level: "critical",
			Event: "phase_fail_closed", Code: "revoked",
		}},
	}
	if err := ValidateLogBatch(batch); err != nil || !IsRevocationLogBatch(batch) {
		t.Fatalf("valid revocation event rejected: %#v err=%v", batch, err)
	}
	for name, mutate := range map[string]func(*LogBatch){
		"component": func(value *LogBatch) { value.Component = "instance-runtime" },
		"level":     func(value *LogBatch) { value.Events[0].Level = "error" },
		"event":     func(value *LogBatch) { value.Events[0].Event = "reconcile_failed" },
		"code":      func(value *LogBatch) { value.Events[0].Code = "phase_failed" },
		"extra": func(value *LogBatch) {
			value.Events = append(value.Events, LogEvent{Sequence: 2, Timestamp: 1_800_000_000, Level: "critical", Event: "phase_fail_closed", Code: "revoked"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := batch
			candidate.Events = append([]LogEvent(nil), batch.Events...)
			mutate(&candidate)
			if IsRevocationLogBatch(candidate) {
				t.Fatalf("non-exact revocation event accepted: %#v", candidate)
			}
		})
	}
}

func TestMaximumAggregateLogResponseFitsOperatorBound(t *testing.T) {
	components := []string{"flow", "instance-runtime", "ssh", "ssh-gui", "vpn", "vpn-pbp-de", "pbp", "decepticon", "examstation"}
	snapshots := make([]LogSnapshot, len(components))
	for componentIndex, component := range components {
		events := make([]LogEvent, MaxRetainedEvents)
		start := uint64(math.MaxUint64 - MaxRetainedEvents + 1)
		for index := range events {
			events[index] = LogEvent{
				Sequence: start + uint64(index), Timestamp: math.MaxInt64, Level: "critical",
				Event: "phase_fail_closed", Code: "artifact_verification",
			}
		}
		snapshots[componentIndex] = LogSnapshot{
			Schema: LogSchema, Instance: strings.Repeat("i", 64), Component: component, Events: events,
		}
		if err := ValidateLogSnapshot(snapshots[componentIndex]); err != nil {
			t.Fatalf("maximal snapshot %s: %v", component, err)
		}
	}
	encoded, err := signing.CanonicalJSON(map[string]any{"logs": snapshots})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 2<<20 {
		t.Fatalf("maximum aggregate log response is %d bytes, must remain below operator 2 MiB bound", len(encoded))
	}
}

func TestLogStoreCanonicalPrivateIdempotentAndCollisionSafe(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private", "logs")
	store, err := NewLogStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	batch := testLogBatch("vm-01", "pbp", "pbp", 1, 3)
	if err := store.Put(batch); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(batch); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}

	snapshot, err := store.Get("vm-01", "pbp")
	if err != nil {
		t.Fatal(err)
	}
	want := LogSnapshot{Schema: LogSchema, Instance: "vm-01", Component: "pbp", Events: batch.Events}
	if !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("snapshot=%#v, want %#v", snapshot, want)
	}
	path := filepath.Join(directory, "vm-01", "pbp.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("log file info=%v err=%v", info, err)
	}
	instanceInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !instanceInfo.IsDir() || instanceInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("instance log directory info=%v err=%v", instanceInfo, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := signing.CanonicalJSON(want)
	if err != nil || !bytes.Equal(data, canonical) {
		t.Fatalf("persisted log is not canonical: err=%v data=%q", err, data)
	}

	collision := testLogBatch("vm-01", "pbp", "pbp", 2, 1)
	collision.Events[0].Code = "installer_failed"
	if err := store.Put(collision); !errors.Is(err, ErrLogSequenceConflict) || !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("sequence collision=%v", err)
	}
	after, err := store.Get("vm-01", "pbp")
	if err != nil || !reflect.DeepEqual(after, want) {
		t.Fatalf("collision changed snapshot=%#v err=%v", after, err)
	}
}

func TestLogStoreRejectsTraversalSymlinksAndTamperedCanonicalState(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(base, "linked-logs")
	if err := os.Symlink(outside, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogStore(linkedRoot); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked store root=%v", err)
	}

	directory := filepath.Join(base, "private", "logs")
	store, err := NewLogStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range []LogBatch{
		testLogBatch("../escape", "pbp", "pbp", 1, 1),
		testLogBatch("vm-01", "../escape", "pbp", 1, 1),
		testLogBatch("vm-01", "pbp", "../escape", 1, 1),
	} {
		if err := store.Put(batch); !errors.Is(err, ErrInvalidLog) {
			t.Fatalf("traversal batch %#v: %v", batch, err)
		}
	}
	if _, err := store.Get("../escape", "pbp"); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("traversal get=%v", err)
	}
	if _, err := store.List("../escape"); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("traversal list=%v", err)
	}

	if err := os.Symlink(outside, filepath.Join(directory, "vm-linked")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(testLogBatch("vm-linked", "pbp", "pbp", 1, 1)); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked instance directory=%v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pbp.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("write escaped through symlink: %v", err)
	}

	batch := testLogBatch("vm-01", "pbp", "pbp", 1, 1)
	if err := store.Put(batch); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "vm-01", "pbp.json")
	outsideFile := filepath.Join(outside, "target.json")
	if err := os.WriteFile(outsideFile, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("vm-01", "pbp"); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked component get=%v", err)
	}
	if err := store.Put(batch); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked component put=%v", err)
	}
	if _, err := store.List("vm-01"); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked component list=%v", err)
	}
	outsideData, err := os.ReadFile(outsideFile)
	if err != nil || string(outsideData) != "unchanged" {
		t.Fatalf("outside file changed=%q err=%v", outsideData, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tampered := LogSnapshot{Schema: LogSchema, Instance: "other-vm", Component: "pbp", Events: batch.Events}
	tamperedData, err := signing.CanonicalJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tamperedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(batch); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("mismatched stored binding=%v", err)
	}

	empty := LogSnapshot{Schema: LogSchema, Instance: "vm-01", Component: "pbp", Events: []LogEvent{}}
	emptyData, err := signing.CanonicalJSON(empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, emptyData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("vm-01", "pbp"); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("empty persisted snapshot=%v", err)
	}
	if err := os.WriteFile(path, append(emptyData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("vm-01", "pbp"); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("noncanonical persisted snapshot=%v", err)
	}

	lockDirectory := filepath.Join(base, "lock-test")
	lockStore, err := NewLogStore(lockDirectory)
	if err != nil {
		t.Fatal(err)
	}
	lockTarget := filepath.Join(outside, "lock-target")
	if err := os.WriteFile(lockTarget, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lockTarget, filepath.Join(lockDirectory, ".logs.lock")); err != nil {
		t.Fatal(err)
	}
	if err := lockStore.Put(testLogBatch("vm-01", "pbp", "pbp", 1, 1)); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlinked lock=%v", err)
	}
	lockData, err := os.ReadFile(lockTarget)
	if err != nil || string(lockData) != "unchanged" {
		t.Fatalf("lock target changed=%q err=%v", lockData, err)
	}
}

func TestLogStoreRetentionWatermarkAndSortedList(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	store, err := NewLogStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	total := MaxRetainedEvents + MaxLogBatchEvents
	for start := 1; start <= total; start += MaxLogBatchEvents {
		count := MaxLogBatchEvents
		if start+count-1 > total {
			count = total - start + 1
		}
		if err := store.Put(testLogBatch("vm-01", "pbp", "pbp", uint64(start), count)); err != nil {
			t.Fatalf("put batch at %d: %v", start, err)
		}
	}
	snapshot, err := store.Get("vm-01", "pbp")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != MaxRetainedEvents || snapshot.Events[0].Sequence != uint64(total-MaxRetainedEvents+1) ||
		snapshot.Events[len(snapshot.Events)-1].Sequence != uint64(total) {
		t.Fatalf("retention=%d first=%d last=%d", len(snapshot.Events), snapshot.Events[0].Sequence, snapshot.Events[len(snapshot.Events)-1].Sequence)
	}
	lastBatch := testLogBatch("vm-01", "pbp", "pbp", uint64(total-MaxLogBatchEvents+1), MaxLogBatchEvents)
	if err := store.Put(lastBatch); err != nil {
		t.Fatalf("idempotent retained retry=%v", err)
	}
	if err := store.Put(testLogBatch("vm-01", "pbp", "pbp", 1, 1)); !errors.Is(err, ErrLogSequenceConflict) {
		t.Fatalf("evicted sequence accepted=%v", err)
	}
	collision := testLogBatch("vm-01", "pbp", "pbp", snapshot.Events[0].Sequence, 1)
	collision.Events[0].Event = "phase_failed"
	if err := store.Put(collision); !errors.Is(err, ErrLogSequenceConflict) {
		t.Fatalf("retained collision=%v", err)
	}
	if err := store.Put(testLogBatch("vm-01", "pbp", "vpn", 1, 1)); err != nil {
		t.Fatal(err)
	}
	listed, err := store.List("vm-01")
	if err != nil || len(listed) != 2 || listed[0].Component != "pbp" || listed[1].Component != "vpn" {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestLogStoreConcurrentUniqueBatches(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	store, err := NewLogStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewLogStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	const workers, eventsPerWorker = 16, 8
	errorsByWorker := make([]error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			start := uint64(worker*eventsPerWorker + 1)
			target := store
			if worker%2 != 0 {
				target = secondStore
			}
			errorsByWorker[worker] = target.Put(testLogBatch("vm-01", "pbp", "pbp", start, eventsPerWorker))
		}(worker)
	}
	wait.Wait()
	for worker, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("worker %d: %v", worker, err)
		}
	}
	snapshot, err := store.Get("vm-01", "pbp")
	if err != nil || len(snapshot.Events) != workers*eventsPerWorker {
		t.Fatalf("concurrent snapshot events=%d err=%v", len(snapshot.Events), err)
	}
	for index, event := range snapshot.Events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event %d sequence=%d", index, event.Sequence)
		}
	}
}

func testLogBatch(instance, profile, component string, start uint64, count int) LogBatch {
	events := make([]LogEvent, count)
	for index := range events {
		sequence := start + uint64(index)
		events[index] = LogEvent{
			Sequence: sequence, Timestamp: 1_800_000_000 + int64(sequence), Level: "info", Event: "phase_applying",
		}
	}
	return LogBatch{Schema: LogSchema, Instance: instance, Profile: profile, Component: component, Events: events}
}
