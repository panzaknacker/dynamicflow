package application

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/systemstate"
)

type SelectSystemRequest struct {
	Meta                     RequestMeta `json:"meta"`
	Selector                 string      `json:"selector"`
	ExpectedRegistryRevision uint64      `json:"expected_registry_revision,omitempty"`
}

type SelectSystemPlan struct {
	Plan               bool               `json:"plan"`
	System             systemstate.System `json:"system"`
	PreviousSystemID   string             `json:"previous_system_id"`
	RegistryRevision   uint64             `json:"registry_revision"`
	AlreadyActive      bool               `json:"already_active"`
	Changes            []string           `json:"changes"`
	NetworkConnections int                `json:"network_connections"`
}

type SelectSystemResult struct {
	System             systemstate.System `json:"system"`
	PreviousSystemID   string             `json:"previous_system_id"`
	RegistryRevision   uint64             `json:"registry_revision"`
	Changed            bool               `json:"changed"`
	NetworkConnections int                `json:"network_connections"`
}

// PlanSystemSelect previews only a local operator-context change. System
// readiness, identities and target configuration are not mutated by selection.
func (application *Application) PlanSystemSelect(ctx context.Context, request SelectSystemRequest) (SelectSystemPlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return SelectSystemPlan{}, appError("cancelled", 8, "System selection was cancelled.", "Refresh the system list and retry.", nil)
	}
	if application == nil || application.store == nil || application.systems == nil {
		return SelectSystemPlan{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	registry, err := application.systems.Snapshot()
	if err != nil {
		return SelectSystemPlan{}, appError("system_state", 3, "System state is invalid.", "Recover the private system registry.", err)
	}
	if request.ExpectedRegistryRevision != 0 && request.ExpectedRegistryRevision != registry.Revision {
		return SelectSystemPlan{}, systemSelectionConflict(systemstate.ErrRevisionConflict)
	}
	selector := strings.TrimPrefix(request.Selector, "id:")
	exactID := strings.HasPrefix(request.Selector, "id:")
	var selected *systemstate.System
	for index := range registry.Systems {
		system := &registry.Systems[index]
		if system.ID != selector && (exactID || system.Name != selector) {
			continue
		}
		if selected != nil && selected.ID != system.ID {
			return SelectSystemPlan{}, appError("system_ambiguous", 6, "The selector matches both a system name and a different system ID.", "Prefix the intended system ID with id: to select it unambiguously.", nil)
		}
		selected = system
	}
	if selected == nil {
		return SelectSystemPlan{}, appError("system_not_found", 3, "The requested system does not exist.", "Choose an exact system name or ID from flow dashboard.", systemstate.ErrNotFound)
	}
	if selected.Status == systemstate.StatusRetired {
		return SelectSystemPlan{}, appError("system_retired", 6, "A retired system cannot become the active operator context.", "Select a non-retired system.", systemstate.ErrInvalidTransition)
	}
	plan := SelectSystemPlan{
		Plan: true, System: *selected, PreviousSystemID: registry.ActiveSystemID,
		RegistryRevision: registry.Revision, AlreadyActive: registry.ActiveSystemID == selected.ID,
		Changes: []string{},
	}
	if !plan.AlreadyActive {
		plan.Changes = []string{"select this system for subsequent operator commands", "record the previous and selected system IDs in the local audit"}
	}
	return plan, nil
}

func (application *Application) SelectSystem(ctx context.Context, request SelectSystemRequest, observer Observer) (SelectSystemResult, error) {
	plan, err := application.PlanSystemSelect(ctx, request)
	if err != nil {
		return SelectSystemResult{}, err
	}
	var result SelectSystemResult
	// Existing network operations hold their system's bootstrap lock until the
	// checkpoint is durable. Locking both contexts prevents a mid-flight switch;
	// nonblocking acquisition and registry CAS also prevent selector deadlocks.
	withContextLocks := func(operation func() error) error {
		return application.store.WithTryLock(systemSelectionLock(plan.PreviousSystemID), func() error {
			if plan.PreviousSystemID == plan.System.ID {
				return operation()
			}
			return application.store.WithTryLock(systemSelectionLock(plan.System.ID), operation)
		})
	}
	err = withContextLocks(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Bind the confirmed plan to both its immutable target ID and the exact
		// registry revision. A concurrent rename-like selector or context change
		// cannot silently change the meaning of this operation.
		confirmed, err := application.PlanSystemSelect(ctx, SelectSystemRequest{Selector: "id:" + plan.System.ID, ExpectedRegistryRevision: plan.RegistryRevision})
		if err != nil {
			return err
		}
		if confirmed.System.ID != plan.System.ID || confirmed.PreviousSystemID != plan.PreviousSystemID {
			return systemstate.ErrRevisionConflict
		}
		result = SelectSystemResult{System: plan.System, PreviousSystemID: plan.PreviousSystemID, RegistryRevision: plan.RegistryRevision}
		if plan.AlreadyActive {
			return nil
		}
		notify(observer, "system_selection", "running", "recording the explicit local system-context change")
		fields := map[string]any{"previous_system_id": plan.PreviousSystemID, "system_id": plan.System.ID, "registry_revision": plan.RegistryRevision, "network_connections": 0}
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "system.select", "outcome": "intent", "fields": fields,
		}); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		selected, err := application.systems.SetActive(plan.System.ID, plan.RegistryRevision)
		if err != nil {
			return err
		}
		result.System, result.Changed, result.RegistryRevision = selected, true, plan.RegistryRevision+1
		fields["registry_revision"] = result.RegistryRevision
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "system.select", "outcome": "success", "fields": fields,
		}); err != nil {
			return appError("system_selection_audit", 8, "The active system changed, but its completion audit could not be saved.", "Inspect flow dashboard and repair the private audit log before continuing.", err)
		}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return SelectSystemResult{}, failure
		}
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return SelectSystemResult{}, appError("cancelled", 8, "System selection was cancelled.", "Inspect flow dashboard before retrying.", err)
		case errors.Is(err, localstate.ErrLockBusy), errors.Is(err, systemstate.ErrRevisionConflict):
			return SelectSystemResult{}, systemSelectionConflict(err)
		default:
			return SelectSystemResult{}, appError("system_selection_state", 5, "The active system selection could not be verified or saved.", "Inspect the private registry and audit before retrying.", err)
		}
	}
	notify(observer, "system_selection", "complete", "the selected system is the active local operator context")
	return result, nil
}

func systemSelectionLock(systemID string) string {
	return filepath.Join("systems", systemID, "operations", "control-bootstrap.lock")
}

func systemSelectionConflict(cause error) error {
	return appError("system_conflict", 6, "Another system operation is active or the registry changed.", "Finish the active operation, refresh the system list and confirm the selection again.", cause)
}
