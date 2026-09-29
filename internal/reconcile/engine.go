// package reconcile executes a fixed declarative profile plan with durable,
// resumable phases. it has no generic command/job facility.
package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/signing"
)

const journalSchema = 1

const maxJournalBytes = int64(8 << 20)

var (
	ErrBusy                  = errors.New("another profile reconciliation is running")
	ErrInvalidPlan           = errors.New("invalid reconciliation plan")
	ErrFailClosedEstablished = errors.New("component fail-closed state was independently confirmed")
	safePhase                = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	safeCode                 = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	safeInstance             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	releaseSet               = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	secretLike               = regexp.MustCompile(`[A-Za-z0-9_=-]{24,}|[0-9]{10,}`)
)

type Plan struct {
	Instance   string `json:"instance"`
	Profile    string `json:"profile"`
	ReleaseSet string `json:"release_set"`
	Generation uint64 `json:"generation"`
	// PlanID binds the durable journal to the complete, independently
	// verified target plan (including authorized keys and artifact digests).
	// generic reconcile users may omit it; target installers must set it.
	PlanID string   `json:"plan_id,omitempty"`
	Phases []string `json:"phases"`
}

type PhaseStatus string

const (
	Pending    PhaseStatus = "pending"
	Preflight  PhaseStatus = "preflight"
	Applying   PhaseStatus = "applying"
	Verifying  PhaseStatus = "verifying"
	Complete   PhaseStatus = "complete"
	Failed     PhaseStatus = "failed"
	FailClosed PhaseStatus = "fail_closed"
)

type PhaseState struct {
	Name       string      `json:"name"`
	Status     PhaseStatus `json:"status"`
	Attempts   int         `json:"attempts"`
	StartedAt  int64       `json:"started_at,omitempty"`
	FinishedAt int64       `json:"finished_at,omitempty"`
	ErrorCode  string      `json:"error_code,omitempty"`
	Message    string      `json:"message,omitempty"`
	Next       string      `json:"next,omitempty"`
}

type Journal struct {
	Schema     int          `json:"schema"`
	PlanDigest string       `json:"plan_digest"`
	Plan       Plan         `json:"plan"`
	Phases     []PhaseState `json:"phases"`
	UpdatedAt  int64        `json:"updated_at"`
}

type PhaseError struct {
	Code    string
	Message string
	Next    string
}

func (failure *PhaseError) Error() string { return failure.Code + ": " + failure.Message }

// Runner is implemented by a fixed allowlist of component/profile executors.
// Rollback must either restore the previous state or establish a documented
// safe fail-closed state. it returns nil only after restoring the prior state,
// ErrFailClosedEstablished after independently confirming a blocked state, and
// any other error when neither result could be confirmed.
type Runner interface {
	Preflight(context.Context, string, Plan) error
	Apply(context.Context, string, Plan) error
	Verify(context.Context, string, Plan) error
	Rollback(context.Context, string, Plan, error) error
}

type Event struct {
	Phase  string `json:"phase"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Engine struct {
	StateDirectory string
	Runner         Runner
	Now            func() time.Time
	Event          func(Event)
}

func (engine *Engine) Run(ctx context.Context, plan Plan) (Journal, error) {
	if err := validatePlan(plan); err != nil {
		return Journal{}, err
	}
	if engine.Runner == nil || !filepath.IsAbs(engine.StateDirectory) || filepath.Clean(engine.StateDirectory) == string(filepath.Separator) {
		return Journal{}, ErrInvalidPlan
	}
	if engine.Now == nil {
		engine.Now = time.Now
	}
	if err := ensurePrivateStateDir(engine.StateDirectory); err != nil {
		return Journal{}, err
	}
	lock, err := acquire(filepath.Join(engine.StateDirectory, "apply.lock"))
	if err != nil {
		return Journal{}, err
	}
	defer releaseLock(lock)
	digest, err := planDigest(plan)
	if err != nil {
		return Journal{}, err
	}
	journalPath := filepath.Join(engine.StateDirectory, "apply.json")
	journal, err := loadOrCreateJournal(journalPath, plan, digest, engine.Now())
	if err != nil {
		return Journal{}, err
	}
	for index := range journal.Phases {
		phase := &journal.Phases[index]
		if phase.Status == Complete {
			// completion is a durable checkpoint, not a permanent assertion that
			// the live host still satisfies the policy. re-verify every completed
			// phase on each reconciliation so configuration drift (notably a
			// disabled VPN lockdown mode) is detected and forced fail-closed.
			phase.Status = Verifying
			phase.ErrorCode, phase.Message, phase.Next = "", "", ""
			if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Verifying), Detail: "drift-check"}); err != nil {
				return journal, err
			}
			if err := engine.Runner.Verify(ctx, phase.Name, plan); err != nil {
				return engine.fail(journalPath, journal, index, err, true)
			}
			phase.Status = Complete
			phase.FinishedAt = engine.Now().UTC().Unix()
			if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Complete), Detail: "current"}); err != nil {
				return journal, err
			}
			continue
		}
		phase.Attempts++
		phase.StartedAt = engine.Now().UTC().Unix()
		phase.FinishedAt = 0
		phase.ErrorCode, phase.Message, phase.Next = "", "", ""
		phase.Status = Preflight
		if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Preflight)}); err != nil {
			return journal, err
		}
		if err := engine.Runner.Preflight(ctx, phase.Name, plan); err != nil {
			return engine.fail(journalPath, journal, index, err, false)
		}
		phase.Status = Applying
		if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Applying)}); err != nil {
			return journal, err
		}
		if err := engine.Runner.Apply(ctx, phase.Name, plan); err != nil {
			return engine.fail(journalPath, journal, index, err, true)
		}
		phase.Status = Verifying
		if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Verifying)}); err != nil {
			return journal, err
		}
		if err := engine.Runner.Verify(ctx, phase.Name, plan); err != nil {
			return engine.fail(journalPath, journal, index, err, true)
		}
		phase.Status = Complete
		phase.FinishedAt = engine.Now().UTC().Unix()
		if err := engine.persist(journalPath, &journal, Event{Phase: phase.Name, Status: string(Complete)}); err != nil {
			return journal, err
		}
	}
	return journal, nil
}

func (engine *Engine) fail(path string, journal Journal, index int, cause error, rollback bool) (Journal, error) {
	phase := &journal.Phases[index]
	failure := classify(cause)
	phase.Status = Failed
	phase.ErrorCode, phase.Message, phase.Next = failure.Code, failure.Message, failure.Next
	phase.FinishedAt = engine.Now().UTC().Unix()
	if rollback {
		rollbackContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := engine.Runner.Rollback(rollbackContext, phase.Name, journal.Plan, cause)
		cancel()
		switch {
		case errors.Is(err, ErrFailClosedEstablished):
			phase.Status = FailClosed
		case err != nil:
			// do not claim fail-closed when the runner could not prove it. this
			// state also blocks superseding the journal with a different plan.
			phase.Status = Failed
			phase.ErrorCode = "rollback_failed"
			phase.Message = "activation failed and rollback or fail-closed state could not be confirmed"
			phase.Next = "isolate the instance through the provider console, inspect sanitized logs, and recover the last verified state"
		}
	}
	if err := engine.persist(path, &journal, Event{Phase: phase.Name, Status: string(phase.Status), Detail: phase.ErrorCode}); err != nil {
		return journal, err
	}
	return journal, cause
}

func (engine *Engine) persist(path string, journal *Journal, event Event) error {
	journal.UpdatedAt = engine.Now().UTC().Unix()
	if err := writeJournal(path, *journal); err != nil {
		return err
	}
	if engine.Event != nil {
		engine.Event(event)
	}
	return nil
}

func validatePlan(plan Plan) error {
	if !safeInstance.MatchString(plan.Instance) || !safePhase.MatchString(plan.Profile) || plan.Generation == 0 ||
		!releaseSet.MatchString(plan.ReleaseSet) ||
		(plan.PlanID != "" && !releaseSet.MatchString(plan.PlanID)) || len(plan.Phases) == 0 {
		return ErrInvalidPlan
	}
	seen := map[string]bool{}
	for _, phase := range plan.Phases {
		if !safePhase.MatchString(phase) || seen[phase] {
			return ErrInvalidPlan
		}
		seen[phase] = true
	}
	return nil
}

func planDigest(plan Plan) (string, error) {
	canonical, err := signing.CanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func loadOrCreateJournal(path string, plan Plan, digest string, now time.Time) (Journal, error) {
	data, err := readJournal(path)
	if err == nil {
		var existing Journal
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&existing); err != nil || existing.Schema != journalSchema {
			return Journal{}, errors.New("invalid reconciliation journal")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return Journal{}, errors.New("invalid reconciliation journal")
		}
		canonical, canonicalErr := signing.CanonicalJSON(existing)
		if canonicalErr != nil || !bytes.Equal(canonical, data) || validatePlan(existing.Plan) != nil {
			return Journal{}, errors.New("invalid reconciliation journal")
		}
		expectedDigest, digestErr := planDigest(existing.Plan)
		if digestErr != nil || expectedDigest != existing.PlanDigest || validateJournal(existing) != nil {
			return Journal{}, errors.New("invalid reconciliation journal")
		}
		if existing.PlanDigest == digest {
			return existing, nil
		}
		if plan.Generation <= existing.Plan.Generation {
			return Journal{}, errors.New("cannot supersede reconciliation without a newer desired generation")
		}
		for _, phase := range existing.Phases {
			switch phase.Status {
			case Complete, Pending, FailClosed:
			case Failed:
				if phase.ErrorCode == "rollback_failed" {
					return Journal{}, errors.New("cannot supersede reconciliation with an unconfirmed rollback state")
				}
			default:
				return Journal{}, errors.New("cannot supersede reconciliation without confirmed rollback or a pending phase")
			}
		}
		if err := archiveSupersededJournal(path, existing); err != nil {
			return Journal{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Journal{}, err
	}
	journal := Journal{Schema: journalSchema, PlanDigest: digest, Plan: plan, UpdatedAt: now.UTC().Unix()}
	for _, name := range plan.Phases {
		journal.Phases = append(journal.Phases, PhaseState{Name: name, Status: Pending})
	}
	if err := writeJournal(path, journal); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func archiveSupersededJournal(path string, journal Journal) error {
	history := filepath.Join(filepath.Dir(path), "history")
	if err := ensurePrivateStateDir(history); err != nil {
		return err
	}
	digest := strings.TrimPrefix(journal.PlanDigest, "sha256:")
	if len(digest) != 64 {
		return errors.New("invalid superseded reconciliation digest")
	}
	archive := filepath.Join(history, fmt.Sprintf("%020d-%s.json", journal.Plan.Generation, digest[:16]))
	if existing, err := readJournal(archive); err == nil {
		canonical, canonicalErr := signing.CanonicalJSON(journal)
		if canonicalErr != nil || !bytes.Equal(existing, canonical) {
			return errors.New("superseded reconciliation archive conflicts with existing evidence")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeJournal(archive, journal)
}

func readJournal(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open reconciliation journal")
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != 0o600 || int(details.Uid) != os.Geteuid() || details.Nlink != 1 ||
		details.Size <= 0 || details.Size > maxJournalBytes {
		return nil, errors.New("invalid reconciliation journal")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil || int64(len(data)) > maxJournalBytes {
		return nil, errors.New("invalid reconciliation journal")
	}
	return data, nil
}

func validateJournal(journal Journal) error {
	if journal.UpdatedAt <= 0 || len(journal.Phases) != len(journal.Plan.Phases) {
		return errors.New("invalid reconciliation journal")
	}
	nonComplete := false
	for index, phase := range journal.Phases {
		if phase.Name != journal.Plan.Phases[index] || phase.Attempts < 0 || phase.StartedAt < 0 || phase.FinishedAt < 0 {
			return errors.New("invalid reconciliation journal")
		}
		switch phase.Status {
		case Complete:
			if nonComplete || phase.Attempts == 0 || phase.StartedAt == 0 || phase.FinishedAt < phase.StartedAt ||
				phase.ErrorCode != "" || phase.Message != "" || phase.Next != "" {
				return errors.New("invalid reconciliation journal")
			}
		case Pending:
			nonComplete = true
			if phase.Attempts != 0 || phase.StartedAt != 0 || phase.FinishedAt != 0 ||
				phase.ErrorCode != "" || phase.Message != "" || phase.Next != "" {
				return errors.New("invalid reconciliation journal")
			}
		case Preflight, Applying, Verifying:
			if nonComplete || phase.Attempts == 0 || phase.StartedAt == 0 || phase.FinishedAt != 0 ||
				phase.ErrorCode != "" || phase.Message != "" || phase.Next != "" {
				return errors.New("invalid reconciliation journal")
			}
			nonComplete = true
		case Failed, FailClosed:
			if nonComplete || phase.Attempts == 0 || phase.StartedAt == 0 || phase.FinishedAt < phase.StartedAt ||
				!safeCode.MatchString(phase.ErrorCode) || !safeJournalText(phase.Message) || !safeJournalText(phase.Next) {
				return errors.New("invalid reconciliation journal")
			}
			nonComplete = true
		default:
			return errors.New("invalid reconciliation journal")
		}
	}
	return nil
}

func safeJournalText(value string) bool {
	return value == "" || len(value) <= 512 && redact(value) == value
}

func classify(err error) PhaseError {
	var explicit *PhaseError
	if errors.As(err, &explicit) {
		return PhaseError{Code: safeToken(explicit.Code, "phase_failed"), Message: redact(explicit.Message), Next: redact(explicit.Next)}
	}
	return PhaseError{Code: "phase_failed", Message: "component phase failed; technical details are in the sanitized component log", Next: "inspect flow instance logs and retry to resume"}
}

func redact(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 32 || character == 127 {
			return ' '
		}
		return character
	}, value)
	value = secretLike.ReplaceAllString(value, "[REDACTED]")
	if len(value) > 512 {
		value = value[:512]
	}
	return strings.TrimSpace(value)
}

func safeToken(value, fallback string) string {
	if safeCode.MatchString(value) {
		return value
	}
	return fallback
}

func ensurePrivateStateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("unsafe reconciliation state directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("unsafe reconciliation state directory")
	}
	return nil
}

func acquire(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return nil, errors.New("unsafe reconciliation lock")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open reconciliation lock")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		int(details.Uid) != os.Geteuid() || details.Nlink != 1 {
		file.Close()
		return nil, errors.New("unsafe reconciliation lock")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return file, nil
}

func releaseLock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func writeJournal(path string, journal Journal) error {
	data, err := signing.CanonicalJSON(journal)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".apply-")
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
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), directory)
	if dir == nil {
		syscall.Close(fd)
		return errors.New("open reconciliation state directory")
	}
	defer dir.Close()
	return dir.Sync()
}
