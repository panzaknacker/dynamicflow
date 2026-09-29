package workflow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"dynamicflow/internal/localstate"
)

type Manager struct {
	store *localstate.Store
	now   func() time.Time
}

type Option func(*Manager)

func WithClock(clock func() time.Time) Option {
	return func(manager *Manager) { manager.now = clock }
}

func NewManager(store *localstate.Store, options ...Option) *Manager {
	manager := &Manager{store: store, now: time.Now}
	for _, option := range options {
		option(manager)
	}
	return manager
}

func (m *Manager) CreateControlBootstrap(systemID, controlName string, key KeyReference) (Task, error) {
	if m == nil || m.store == nil || !token.MatchString(systemID) || !token.MatchString(controlName) {
		return Task{}, ErrInvalidTask
	}
	id := controlTaskID(controlName)
	var result Task
	err := m.store.WithLock(lockRelative(id), func() error {
		existing, err := m.getUnlocked(id)
		if err == nil {
			if existing.SystemID != systemID || existing.Resource.Name != controlName || existing.Key != key {
				return ErrConflict
			}
			result = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := m.now().UTC()
		result = Task{
			SchemaVersion: SchemaVersion,
			ID:            id, SystemID: systemID, Kind: ControlBootstrap,
			Resource: Resource{Type: "control", Name: controlName},
			Revision: 1, Phase: PhaseAwaitingCloudVM, Attempt: 1, Key: key,
			NextAction: ActionCreateCloudVM, CreatedAt: now, UpdatedAt: now,
		}
		if err := Validate(result); err != nil {
			return err
		}
		if err := m.store.AppendJSONL(eventsRelative(id), Event{SchemaVersion: SchemaVersion, TaskID: id, Revision: 1, Phase: result.Phase, Status: "intent", Time: now}); err != nil {
			return fmt.Errorf("write workflow intent: %w", err)
		}
		if err := m.store.WriteJSON(taskRelative(id), result); err != nil {
			return fmt.Errorf("write workflow task: %w", err)
		}
		return m.store.AppendJSONL(eventsRelative(id), Event{SchemaVersion: SchemaVersion, TaskID: id, Revision: 1, Phase: result.Phase, Status: "committed", Time: now})
	})
	return result, err
}

func (m *Manager) Get(id string) (Task, error) {
	if !token.MatchString(id) {
		return Task{}, ErrInvalidTask
	}
	return m.getUnlocked(id)
}

func (m *Manager) List() ([]Task, error) {
	directory, err := m.store.Path("workflows/tasks")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []Task{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]Task, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("%w: unexpected workflow entry", ErrInvalidTask)
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		task, err := m.Get(id)
		if err != nil {
			return nil, err
		}
		result = append(result, task)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (m *Manager) Advance(id string, expectedRevision uint64, phase Phase) (Task, error) {
	return m.transition(id, expectedRevision, phase, nil)
}

func (m *Manager) FailSafe(id string, expectedRevision uint64, code, next string) (Task, error) {
	if !token.MatchString(code) || strings.TrimSpace(next) == "" || len(next) > 512 {
		return Task{}, ErrInvalidTask
	}
	return m.transition(id, expectedRevision, PhaseFailedSafe, &Failure{Code: code, Next: next})
}

func (m *Manager) Resume(id string, expectedRevision uint64) (Task, error) {
	current, err := m.Get(id)
	if err != nil {
		return Task{}, err
	}
	if current.Revision != expectedRevision {
		return Task{}, ErrConflict
	}
	if current.Phase != PhaseFailedSafe {
		return Task{}, ErrInvalidPhase
	}
	return m.transition(id, expectedRevision, current.ResumePhase, nil)
}

func (m *Manager) transition(id string, expectedRevision uint64, phase Phase, failure *Failure) (Task, error) {
	if !token.MatchString(id) || expectedRevision == 0 || !validPhase(phase) {
		return Task{}, ErrInvalidTask
	}
	var result Task
	err := m.store.WithLock(lockRelative(id), func() error {
		current, err := m.getUnlocked(id)
		if err != nil {
			return err
		}
		if current.Revision != expectedRevision {
			return ErrConflict
		}
		if !allowedTransition(current.Phase, phase, current.ResumePhase) {
			return ErrInvalidPhase
		}
		previous := current.Phase
		current.Revision++
		current.Phase = phase
		current.UpdatedAt = m.now().UTC()
		current.Failure = failure
		current.ResumePhase = ""
		if phase == PhaseFailedSafe {
			current.ResumePhase = previous
		} else if previous == PhaseFailedSafe {
			current.Attempt++
		}
		current.NextAction = nextAction(phase)
		if err := Validate(current); err != nil {
			return err
		}
		code := ""
		if failure != nil {
			code = failure.Code
		}
		event := Event{SchemaVersion: SchemaVersion, TaskID: id, Revision: current.Revision, Phase: phase, Status: "intent", Code: code, Time: current.UpdatedAt}
		if err := m.store.AppendJSONL(eventsRelative(id), event); err != nil {
			return fmt.Errorf("write workflow intent: %w", err)
		}
		if err := m.store.WriteJSON(taskRelative(id), current); err != nil {
			return fmt.Errorf("write workflow task: %w", err)
		}
		event.Status = "committed"
		if err := m.store.AppendJSONL(eventsRelative(id), event); err != nil {
			return fmt.Errorf("write workflow completion: %w", err)
		}
		result = current
		return nil
	})
	return result, err
}

func (m *Manager) getUnlocked(id string) (Task, error) {
	var task Task
	if err := m.store.ReadJSON(taskRelative(id), &task); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Task{}, ErrNotFound
		}
		return Task{}, err
	}
	if err := Validate(task); err != nil || task.ID != id {
		if err == nil {
			err = ErrInvalidTask
		}
		return Task{}, err
	}
	return task, nil
}

func taskRelative(id string) string   { return filepath.Join("workflows", "tasks", id+".json") }
func lockRelative(id string) string   { return filepath.Join("workflows", "locks", id+".lock") }
func eventsRelative(id string) string { return filepath.Join("workflows", "events", id+".jsonl") }
