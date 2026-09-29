package serving

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusStoreAtomicCanonicalAndTamperDetection(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private", "statuses")
	store, err := NewStatusStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	report := NormalizeStatus(StatusReport{
		Schema: StatusSchema, Instance: "vm-01", Profile: "pbp", DesiredGeneration: 3, AppliedGeneration: 2,
		ReleaseSet: "sha256:" + strings.Repeat("a", 64), State: "applying", ReportedAt: 1_800_000_000,
		Components: []ComponentStatus{
			{Name: "vpn", Version: "v1.0.0", State: "ready"},
			{Name: "pbp", Version: "v1.0.0", State: "applying"},
		},
	})
	if err := store.Put(report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "vm-01.json")
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("status mode/type=%v err=%v", info.Mode(), err)
	}
	loaded, err := store.Get("vm-01")
	if err != nil || loaded.Instance != report.Instance || len(loaded.Components) != 2 {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("vm-01"); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("unsafe status mode: got %v, want ErrUnsafeState", err)
	}
}

func TestPrivateStateReadRejectsHardlinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	alias := filepath.Join(root, "alias.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(path); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("hardlinked private state error=%v, want ErrUnsafeState", err)
	}
	if err := writeAtomicPrivate(path, []byte(`{"schema":1}`)); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("hardlinked private state replacement error=%v, want ErrUnsafeState", err)
	}
}

func TestRevocationAcknowledgementIsFiniteExactAndFailClosed(t *testing.T) {
	report := NormalizeStatus(StatusReport{
		Schema: StatusSchema, Instance: "vm-01", Profile: "pbp",
		DesiredGeneration: 9, AppliedGeneration: 8,
		ReleaseSet: "sha256:" + strings.Repeat("a", 64), State: "revoked",
		Revoked: true, FailClosed: true, ReportedAt: 1_800_000_000,
		Components: []ComponentStatus{{Name: "ssh", Version: "v0.2.0", State: "blocked", Code: "revoked"}},
	})
	if err := ValidateStatus(report); err != nil || !IsRevocationAcknowledgement(report) {
		t.Fatalf("valid revocation acknowledgement rejected: %#v err=%v", report, err)
	}

	tests := []struct {
		name   string
		mutate func(*StatusReport)
	}{
		{name: "not flagged revoked", mutate: func(value *StatusReport) { value.Revoked = false }},
		{name: "not fail closed", mutate: func(value *StatusReport) { value.FailClosed = false }},
		{name: "wrong overall state", mutate: func(value *StatusReport) { value.State = "blocked" }},
		{name: "host key attached", mutate: func(value *StatusReport) { value.SSHHostKey = "not-permitted" }},
		{name: "wrong component", mutate: func(value *StatusReport) { value.Components[0].Name = "vpn" }},
		{name: "component not blocked", mutate: func(value *StatusReport) { value.Components[0].State = "ready" }},
		{name: "wrong finite code", mutate: func(value *StatusReport) { value.Components[0].Code = "phase_failed" }},
		{name: "extra component", mutate: func(value *StatusReport) {
			value.Components = append(value.Components, ComponentStatus{Name: "vpn", Version: "v1.0.0", State: "blocked", Code: "revoked"})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := report
			candidate.Components = append([]ComponentStatus(nil), report.Components...)
			test.mutate(&candidate)
			if IsRevocationAcknowledgement(candidate) || ValidateStatus(candidate) == nil {
				t.Fatalf("non-exact revocation acknowledgement accepted: %#v", candidate)
			}
		})
	}
}

func TestFileAuditLogIsPrivateAndRejectsUnredactedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	log, err := NewFileAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{Timestamp: 1_800_000_000, Action: "enroll", Outcome: "accepted", Instance: "vm-01", Profile: "pbp", RemoteIP: "192.0.2.10"}
	if err := log.Record(event); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("audit mode/type=%v err=%v", info.Mode(), err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"action":"enroll"`) || strings.Contains(string(data), "secret") {
		t.Fatalf("unexpected audit data: %s", data)
	}
	if err := log.Record(AuditEvent{Timestamp: 1, Action: "enroll", Outcome: "rejected", Instance: "secret\nvalue"}); err == nil {
		t.Fatal("audit accepted a non-redacted free-form instance value")
	}
}

func TestFileAuditLogRejectsHardlinkedDestination(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "audit")
	path := filepath.Join(directory, "audit.jsonl")
	log, err := NewFileAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Record(AuditEvent{Timestamp: 1, Action: "enroll", Outcome: "started"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".alias"); err != nil {
		t.Fatal(err)
	}
	if err := log.Record(AuditEvent{Timestamp: 2, Action: "enroll", Outcome: "accepted"}); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("hardlinked audit destination: got %v, want ErrUnsafeState", err)
	}
	data, err := os.ReadFile(path + ".alias")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"accepted"`) {
		t.Fatal("audit event was appended through a hardlinked destination")
	}
}
