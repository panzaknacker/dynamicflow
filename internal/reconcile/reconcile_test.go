package reconcile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

type fakeRunner struct {
	failAt       string
	verifyFailAt string
	rollbackErr  error
	calls        []string
}

func (runner *fakeRunner) Preflight(_ context.Context, phase string, _ Plan) error {
	runner.calls = append(runner.calls, "preflight:"+phase)
	return nil
}
func (runner *fakeRunner) Apply(_ context.Context, phase string, _ Plan) error {
	runner.calls = append(runner.calls, "apply:"+phase)
	if phase == runner.failAt {
		return &PhaseError{Code: "installer_failed", Message: "account 1234567890123456 token abcdefghijklmnopqrstuvwxyz", Next: "retry"}
	}
	return nil
}
func (runner *fakeRunner) Verify(_ context.Context, phase string, _ Plan) error {
	runner.calls = append(runner.calls, "verify:"+phase)
	if phase == runner.verifyFailAt {
		return &PhaseError{Code: "policy-drift", Message: "live state no longer satisfies policy", Next: "repair the fixed profile and retry"}
	}
	return nil
}
func (runner *fakeRunner) Rollback(_ context.Context, phase string, _ Plan, _ error) error {
	runner.calls = append(runner.calls, "rollback:"+phase)
	return runner.rollbackErr
}

func testPlan() Plan {
	return Plan{Instance: "vm-one", Profile: "pbp", ReleaseSet: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Generation: 1, Phases: []string{"ssh", "ssh-gui", "vpn-pbp-de", "pbp"}}
}

func TestEngineReverifiesCompletedPhasesAndFailsClosedOnDrift(t *testing.T) {
	runner := &fakeRunner{}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	if _, err := engine.Run(context.Background(), testPlan()); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	runner.verifyFailAt = "vpn-pbp-de"
	runner.rollbackErr = ErrFailClosedEstablished
	journal, err := engine.Run(context.Background(), testPlan())
	if err == nil {
		t.Fatal("completed VPN policy drift was accepted")
	}
	if journal.Phases[2].Status != FailClosed || journal.Phases[2].ErrorCode != "policy-drift" {
		t.Fatalf("drift was not recorded fail-closed: %#v", journal.Phases[2])
	}
	for _, unexpected := range []string{"preflight:ssh", "apply:ssh", "apply:ssh-gui", "apply:vpn-pbp-de", "verify:pbp"} {
		for _, call := range runner.calls {
			if call == unexpected {
				t.Fatalf("unexpected call after completed-state drift check: %s", call)
			}
		}
	}
	want := []string{"verify:ssh", "verify:ssh-gui", "verify:vpn-pbp-de", "rollback:vpn-pbp-de"}
	if strings.Join(runner.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("drift calls = %v, want %v", runner.calls, want)
	}
}

func TestEngineNeverLabelsUnconfirmedRollbackFailClosed(t *testing.T) {
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: "ssh-gui", rollbackErr: errors.New("could not stop listener")}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	journal, err := engine.Run(context.Background(), testPlan())
	if err == nil {
		t.Fatal("apply with unconfirmed rollback unexpectedly succeeded")
	}
	phase := journal.Phases[1]
	if phase.Status != Failed || phase.ErrorCode != "rollback_failed" || strings.Contains(phase.Message, "remains fail-closed") {
		t.Fatalf("unconfirmed rollback was mislabeled: %#v", phase)
	}
	next := testPlan()
	next.Generation = 2
	next.ReleaseSet = "sha256:" + strings.Repeat("c", 64)
	runner.failAt = ""
	runner.rollbackErr = nil
	if _, err := engine.Run(context.Background(), next); err == nil || !strings.Contains(err.Error(), "unconfirmed rollback") {
		t.Fatalf("new plan superseded an unconfirmed rollback: %v", err)
	}
}

func TestEngineResumesAndRedacts(t *testing.T) {
	runner := &fakeRunner{failAt: "ssh-gui"}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	journal, err := engine.Run(context.Background(), testPlan())
	if err == nil || len(journal.Phases) != 4 || journal.Phases[0].Status != Complete || journal.Phases[1].Status != Failed {
		t.Fatalf("unexpected failed journal: %#v, %v", journal, err)
	}
	if journal.Phases[1].Message == "" || journal.Phases[1].Message == "account 1234567890123456 token abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("failure was not redacted: %#v", journal.Phases[1])
	}
	if journal.Phases[1].ErrorCode != "installer_failed" {
		t.Fatalf("safe structured failure code was lost: %#v", journal.Phases[1])
	}
	runner.failAt = ""
	before := len(runner.calls)
	journal, err = engine.Run(context.Background(), testPlan())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range journal.Phases {
		if phase.Status != Complete {
			t.Fatalf("phase did not resume: %#v", phase)
		}
	}
	for _, call := range runner.calls[before:] {
		if call == "apply:ssh" {
			t.Fatal("completed phase was rerun")
		}
	}
}

func TestEngineJournalBindsCompleteCallerPlanID(t *testing.T) {
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: "ssh-gui"}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	first := testPlan()
	first.PlanID = "sha256:" + strings.Repeat("a", 64)
	if _, err := engine.Run(context.Background(), first); err == nil {
		t.Fatal("first plan unexpectedly completed")
	}
	second := first
	second.PlanID = "sha256:" + strings.Repeat("b", 64)
	if _, err := engine.Run(context.Background(), second); err == nil || !strings.Contains(err.Error(), "newer desired generation") {
		t.Fatalf("different complete-plan binding was accepted: %v", err)
	}
}

func TestEngineSupersedesRolledBackFailureWithNewerGenerationAndArchivesEvidence(t *testing.T) {
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: "ssh-gui"}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	failed, err := engine.Run(context.Background(), testPlan())
	if err == nil || failed.Phases[1].Status != Failed {
		t.Fatalf("first generation did not reach a rolled-back failure: %#v %v", failed, err)
	}
	next := testPlan()
	next.Generation = 2
	next.ReleaseSet = "sha256:" + strings.Repeat("b", 64)
	runner.failAt = ""
	completed, err := engine.Run(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range completed.Phases {
		if phase.Status != Complete {
			t.Fatalf("newer plan did not complete: %#v", completed)
		}
	}
	digest := strings.TrimPrefix(failed.PlanDigest, "sha256:")
	archive := filepath.Join(stateDirectory, "history", "00000000000000000001-"+digest[:16]+".json")
	data, err := readJournal(archive)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := signing.CanonicalJSON(failed)
	if err != nil || !bytes.Equal(data, canonical) {
		t.Fatalf("superseded journal evidence changed: %v", err)
	}
}

func TestEngineRejectsImpossibleForgedJournalState(t *testing.T) {
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := testPlan()
	digest, err := planDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	journal := Journal{Schema: journalSchema, PlanDigest: digest, Plan: plan, UpdatedAt: time.Now().Unix()}
	for index, name := range plan.Phases {
		state := PhaseState{Name: name, Status: Pending}
		if index == 0 {
			// a completed phase without an attempt/timestamps could otherwise
			// suppress the fixed SSH phase on resume.
			state.Status = Complete
		}
		journal.Phases = append(journal.Phases, state)
	}
	if err := writeJournal(filepath.Join(stateDirectory, "apply.json"), journal); err != nil {
		t.Fatal(err)
	}
	engine := Engine{StateDirectory: stateDirectory, Runner: &fakeRunner{}}
	if _, err := engine.Run(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "invalid reconciliation journal") {
		t.Fatalf("forged complete state accepted: %v", err)
	}
}

func TestEngineRejectsSymlinkedAndHardlinkedJournal(t *testing.T) {
	for _, link := range []string{"symlink", "hardlink"} {
		t.Run(link, func(t *testing.T) {
			parent := t.TempDir()
			stateDirectory := filepath.Join(parent, "state")
			if err := os.Mkdir(stateDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			plan := testPlan()
			digest, err := planDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			journal := Journal{Schema: journalSchema, PlanDigest: digest, Plan: plan, UpdatedAt: time.Now().Unix()}
			for _, name := range plan.Phases {
				journal.Phases = append(journal.Phases, PhaseState{Name: name, Status: Pending})
			}
			external := filepath.Join(parent, "external.json")
			if err := writeJournal(external, journal); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(stateDirectory, "apply.json")
			if link == "symlink" {
				err = os.Symlink(external, target)
			} else {
				err = os.Link(external, target)
			}
			if err != nil {
				t.Fatal(err)
			}
			engine := Engine{StateDirectory: stateDirectory, Runner: &fakeRunner{}}
			if _, err := engine.Run(context.Background(), plan); err == nil {
				t.Fatal("linked reconciliation journal accepted")
			}
		})
	}
}

func TestReconcileLockRejectsHardlink(t *testing.T) {
	directory := t.TempDir()
	external := filepath.Join(directory, "external")
	if err := os.WriteFile(external, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(directory, "apply.lock")
	if err := os.Link(external, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(lock); err == nil {
		t.Fatal("hardlinked reconciliation lock accepted")
	}
}

type blockingRunner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (runner *blockingRunner) Preflight(_ context.Context, _ string, _ Plan) error {
	runner.once.Do(func() { close(runner.started) })
	<-runner.release
	return nil
}
func (*blockingRunner) Apply(context.Context, string, Plan) error           { return nil }
func (*blockingRunner) Verify(context.Context, string, Plan) error          { return nil }
func (*blockingRunner) Rollback(context.Context, string, Plan, error) error { return nil }

func TestEngineConcurrentRunReturnsBusy(t *testing.T) {
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &blockingRunner{started: make(chan struct{}), release: make(chan struct{})}
	engine := Engine{StateDirectory: stateDirectory, Runner: runner}
	result := make(chan error, 1)
	go func() {
		_, err := engine.Run(context.Background(), testPlan())
		result <- err
	}()
	<-runner.started
	if _, err := engine.Run(context.Background(), testPlan()); !errors.Is(err, ErrBusy) {
		close(runner.release)
		t.Fatalf("concurrent run error = %v", err)
	}
	close(runner.release)
	if err := <-result; err != nil {
		t.Fatalf("first run failed: %v", err)
	}
}

func TestExtractRejectsTraversalAndLinks(t *testing.T) {
	for _, test := range []struct {
		name     string
		header   tar.Header
		contents string
	}{
		{"traversal", tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}, "x"},
		{"symlink", tar.Header{Name: "root/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "bad.tar.gz")
			writeArchive(t, archive, []tar.Header{test.header}, []string{test.contents})
			destination := filepath.Join(t.TempDir(), "stage")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := ExtractTarGz(archive, destination); !errors.Is(err, ErrUnsafeArchive) {
				t.Fatalf("expected unsafe archive, got %v", err)
			}
		})
	}
}

func TestExtractValidSingleRoot(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "good.tar.gz")
	headers := []tar.Header{
		{Name: "tool/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "tool/run", Mode: 0o755, Size: 2, Typeflag: tar.TypeReg},
	}
	writeArchive(t, archive, headers, []string{"", "ok"})
	destination := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ExtractTarGz(archive, destination)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "run")); err != nil || string(data) != "ok" {
		t.Fatalf("wrong extracted file: %q, %v", data, err)
	}
}

func writeArchive(t *testing.T, path string, headers []tar.Header, contents []string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for index := range headers {
		header := headers[index]
		if err := tarWriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if contents[index] != "" {
			if _, err := tarWriter.Write([]byte(contents[index])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
