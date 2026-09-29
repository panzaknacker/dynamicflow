package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/controlinstalltransport"
	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/netpolicy"
	"dynamicflow/internal/sshtransport"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

const controlInstallEvidenceSchema = 1

type InstallPreparedControlRequest struct {
	Meta RequestMeta `json:"meta"`
	Name string      `json:"name"`
}

type InstallPreparedControlPlan struct {
	Plan               bool     `json:"plan"`
	SystemID           string   `json:"system_id"`
	ControlName        string   `json:"control_name"`
	CurrentLifecycle   string   `json:"current_lifecycle"`
	CurrentTaskPhase   string   `json:"current_task_phase"`
	Route              string   `json:"route"`
	FixedOperation     string   `json:"fixed_operation"`
	PolicyGeneration   uint64   `json:"policy_generation"`
	EnvelopeDigest     string   `json:"envelope_digest"`
	ExecutableDigest   string   `json:"executable_digest,omitempty"`
	ExecutableBytes    int64    `json:"executable_bytes,omitempty"`
	Changes            []string `json:"changes"`
	NetworkConnections int      `json:"network_connections"`
	ResumesFailedTask  bool     `json:"resumes_failed_task"`
	ReconcilesEvidence bool     `json:"reconciles_evidence"`
	AlreadyInstalled   bool     `json:"already_installed"`
	Retry              string   `json:"retry"`
	Fallback           string   `json:"fallback"`
}

type InstallPreparedControlResult struct {
	Installed          bool                           `json:"installed"`
	AlreadyInstalled   bool                           `json:"already_installed"`
	Reconciled         bool                           `json:"reconciled"`
	SystemID           string                         `json:"system_id"`
	Control            controlnodes.Record            `json:"control"`
	Task               workflow.Task                  `json:"task"`
	EnvelopeDigest     string                         `json:"envelope_digest"`
	ExecutableDigest   string                         `json:"executable_digest"`
	PolicyGeneration   uint64                         `json:"policy_generation"`
	Transport          controlinstalltransport.Result `json:"transport"`
	NetworkConnections int                            `json:"network_connections"`
	AuditLog           string                         `json:"audit_log"`
}

type controlInstallEvidence struct {
	SchemaVersion    int       `json:"schema_version"`
	SystemID         string    `json:"system_id"`
	ControlName      string    `json:"control_name"`
	EnvelopeDigest   string    `json:"envelope_digest"`
	ExecutableDigest string    `json:"executable_digest"`
	ExecutableBytes  int64     `json:"executable_bytes"`
	PolicyGeneration uint64    `json:"policy_generation"`
	Route            string    `json:"route"`
	Attempts         int       `json:"attempts"`
	InstalledAt      time.Time `json:"installed_at"`
}

// PlanPreparedControlInstall validates the exact staged identity, signed
// envelope, bootstrap route and local executable without writing transport
// files or opening a connection.
func (application *Application) PlanPreparedControlInstall(operation context.Context, request InstallPreparedControlRequest) (InstallPreparedControlPlan, error) {
	if err := operation.Err(); err != nil {
		return InstallPreparedControlPlan{}, appError("cancelled", 8, "Control installation plan was cancelled.", "Retry the plan.", err)
	}
	active, store, bindingContext, _, record, err := application.controlInstallContextWithResume(request.Name, true)
	if err != nil {
		return InstallPreparedControlPlan{}, err
	}
	if err := validatePreparedControlApplyCheckpoint(active, record, bindingContext.task); err != nil {
		return InstallPreparedControlPlan{}, err
	}
	prepared, err := application.readPreparedControlEnvelope(store, active, record)
	if err != nil {
		return InstallPreparedControlPlan{}, appError("control_install_envelope", 5, "The signed Control installation envelope is unavailable or invalid.", "Recover the exact prepared envelope before any network operation.", err)
	}
	if err := preparedEnvelopeMatchesRecord(prepared, record); err != nil {
		return InstallPreparedControlPlan{}, appError("control_install_envelope", 5, "The signed envelope differs from staged Control access.", "Recover the exact management identity and envelope; never create a fallback.", err)
	}

	plan := InstallPreparedControlPlan{
		Plan: true, SystemID: active.ID, ControlName: record.Name,
		CurrentLifecycle: string(record.Lifecycle), CurrentTaskPhase: string(bindingContext.task.Phase),
		Route: "direct_first_control", FixedOperation: "control-runtime install",
		PolicyGeneration: prepared.envelope.Policy.Policy.Generation, EnvelopeDigest: prepared.digest,
		Retry: "none", Fallback: "none", Changes: []string{},
	}
	evidence, evidenceErr := readControlInstallEvidence(store, active.ID, record.Name, prepared)
	switch {
	case evidenceErr == nil:
		plan.ExecutableDigest = evidence.ExecutableDigest
		plan.ExecutableBytes = evidence.ExecutableBytes
		plan.AlreadyInstalled = bindingContext.task.Phase == workflow.PhaseAttesting
		plan.ReconcilesEvidence = !plan.AlreadyInstalled
		if plan.ReconcilesEvidence {
			plan.Changes = []string{"reconcile authenticated remote-install evidence with the persistent task"}
		}
		return plan, nil
	case !errors.Is(evidenceErr, os.ErrNotExist):
		return InstallPreparedControlPlan{}, appError("control_install_evidence", 5, "Existing Control installation evidence is invalid.", "Recover the exact evidence before retrying; do not repeat an ambiguous privileged install.", evidenceErr)
	}
	if bootstrapExpired(active, application.now()) {
		return InstallPreparedControlPlan{}, expiredBootstrapError()
	}
	if _, err := authorizeFirstControlNetwork(active.ID, record, netpolicy.ActionControlInstall); err != nil {
		return InstallPreparedControlPlan{}, err
	}
	if _, _, _, err := application.prepareFirstControlEndpoint(store, bindingContext); err != nil {
		return InstallPreparedControlPlan{}, err
	}
	executable, err := controlinstalltransport.NewExecutable(application.executablePath)
	if err != nil {
		return InstallPreparedControlPlan{}, appError("control_executable", 5, "The local flow executable is unsafe or changed.", "Use a regular, non-writable, single-link flow binary and retry the plan.", err)
	}
	plan.ExecutableDigest = executable.Digest()
	plan.ExecutableBytes = executable.Size()
	plan.NetworkConnections = 1
	plan.ResumesFailedTask = bindingContext.task.Phase == workflow.PhaseFailedSafe
	plan.Changes = []string{
		"stream the exact local flow binary and signed envelope through one pinned first-Control SSH session",
		"verify both SHA-256 payloads in a root-owned temporary directory",
		"run the fixed privileged control-runtime installer transaction",
		"persist bounded install evidence and advance to management-access attestation",
	}
	return plan, nil
}

// InstallPreparedControl performs one explicit, pinned and audited bootstrap
// session. it never retries or selects another endpoint. a failed attempt is
// persisted fail-safe and requires another explicit invocation.
func (application *Application) InstallPreparedControl(operation context.Context, request InstallPreparedControlRequest, observer Observer) (InstallPreparedControlResult, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return InstallPreparedControlResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if err := operation.Err(); err != nil {
		return InstallPreparedControlResult{}, appError("cancelled", 8, "Control installation was cancelled.", "Run the same explicit operation to resume.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return InstallPreparedControlResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Prepare the first Control installation.", err)
	}
	var result InstallPreparedControlResult
	operationLock := filepath.Join("systems", active.ID, "operations", "control-bootstrap.lock")
	err = application.store.WithLock(operationLock, func() error {
		current, store, bindingContext, _, record, err := application.controlInstallContextWithResume(request.Name, true)
		if err != nil {
			return err
		}
		if current.ID != active.ID {
			return errors.New("active system changed during Control installation")
		}
		if err := validatePreparedControlApplyCheckpoint(current, record, bindingContext.task); err != nil {
			return err
		}
		prepared, err := application.readPreparedControlEnvelope(store, current, record)
		if err != nil {
			return err
		}
		if err := preparedEnvelopeMatchesRecord(prepared, record); err != nil {
			return err
		}
		task := bindingContext.task
		evidence, evidenceErr := readControlInstallEvidence(store, current.ID, record.Name, prepared)
		if evidenceErr != nil && !errors.Is(evidenceErr, os.ErrNotExist) {
			return fmt.Errorf("invalid Control install evidence: %w", evidenceErr)
		}
		if evidenceErr == nil {
			reconciled := false
			if task.Phase == workflow.PhaseFailedSafe {
				task, err = bindingContext.workflows.Resume(task.ID, task.Revision)
				if err != nil {
					return err
				}
			}
			if task.Phase == workflow.PhaseInstalling {
				task, err = bindingContext.workflows.Advance(task.ID, task.Revision, workflow.PhaseAttesting)
				if err != nil {
					return err
				}
				reconciled = true
			}
			auditLog, _ := application.store.Path("logs/audit.jsonl")
			if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
				"time": application.now().UTC(), "action": "control.install.apply", "outcome": "already_installed",
				"fields": map[string]any{"system_id": current.ID, "control": record.Name, "task_id": task.ID, "envelope_digest": evidence.EnvelopeDigest, "executable_digest": evidence.ExecutableDigest, "network_connections": 0, "reconciled": reconciled},
			}); err != nil {
				return err
			}
			result = installResultFromEvidence(record, task, evidence, true, reconciled, auditLog)
			return nil
		}

		if bootstrapExpired(current, application.now()) {
			return expiredBootstrapError()
		}
		if task.Phase == workflow.PhaseFailedSafe {
			notify(observer, "workflow", "running", "resuming the explicit Control installation fail-safe checkpoint")
			task, err = bindingContext.workflows.Resume(task.ID, task.Revision)
			if err != nil {
				return err
			}
		}
		decision, err := authorizeFirstControlNetwork(current.ID, record, netpolicy.ActionControlInstall)
		if err != nil {
			return err
		}
		_, endpoint, _, err := application.prepareFirstControlEndpoint(store, bindingContext)
		if err != nil {
			return err
		}
		executable, err := controlinstalltransport.NewExecutable(application.executablePath)
		if err != nil {
			return appError("control_executable", 5, "The local flow executable is unsafe or changed.", "Use a regular, non-writable, single-link flow binary and retry.", err)
		}
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.install.apply", "outcome": "intent",
			"fields": map[string]any{
				"system_id": current.ID, "control": record.Name, "task_id": task.ID,
				"network_policy": decision, "route": "direct_first_control", "attempt": task.Attempt,
				"fixed_operation": "control-runtime install", "envelope_digest": prepared.digest,
				"executable_digest": executable.Digest(), "executable_bytes": executable.Size(),
			},
		}); err != nil {
			return err
		}
		notify(observer, "control_install", "running", "streaming one integrity-bound payload through the pinned first-Control route")
		transport := controlinstalltransport.New(
			sshtransport.NewBuilder(store), application.controlRunner,
			controlinstalltransport.WithClock(application.now),
		)
		transportResult, installErr := transport.InstallFirstControl(operation, controlinstalltransport.Request{
			Control: endpoint, Executable: executable, Envelope: prepared.bytes,
			ExpectedSystemID: current.ID, ExpectedControlName: record.Name,
			MinimumGeneration: prepared.envelope.Policy.Policy.Generation,
		})
		if installErr != nil {
			next := "Verify passwordless non-interactive sudo, available /usr/bin core tools and the pinned bootstrap route; then run the explicit install again."
			failed, failErr := bindingContext.workflows.FailSafe(task.ID, task.Revision, "control_install", next)
			if failErr != nil {
				return fmt.Errorf("persist failed Control installation checkpoint: %w", failErr)
			}
			_ = application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
				"time": application.now().UTC(), "action": "control.install.apply", "outcome": "failed_safe",
				"fields": map[string]any{
					"system_id": current.ID, "control": record.Name, "task_id": failed.ID,
					"route": "direct_first_control", "attempts": transportResult.Attempts,
					"stdout_bytes": transportResult.StdoutBytes, "stderr_bytes": transportResult.StderrBytes,
				},
			})
			return appError("control_install", 7, "The pinned first-Control installation failed safely.", next, installErr)
		}
		evidence = controlInstallEvidence{
			SchemaVersion: controlInstallEvidenceSchema, SystemID: current.ID, ControlName: record.Name,
			EnvelopeDigest: transportResult.EnvelopeDigest, ExecutableDigest: transportResult.ExecutableDigest,
			ExecutableBytes: transportResult.ExecutableBytes, PolicyGeneration: transportResult.PolicyGeneration,
			Route: transportResult.Route, Attempts: transportResult.Attempts, InstalledAt: application.now().UTC(),
		}
		if err := validateControlInstallEvidence(evidence, current.ID, record.Name, prepared); err != nil {
			return err
		}
		if err := store.WriteJSON(controlInstallEvidenceRelative(record.Name), evidence); err != nil {
			return fmt.Errorf("persist Control install evidence: %w", err)
		}
		task, err = bindingContext.workflows.Advance(task.ID, task.Revision, workflow.PhaseAttesting)
		if err != nil {
			return err
		}
		auditLog, _ := application.store.Path("logs/audit.jsonl")
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.install.apply", "outcome": "success",
			"fields": map[string]any{
				"system_id": current.ID, "control": record.Name, "task_id": task.ID,
				"route": transportResult.Route, "attempts": transportResult.Attempts,
				"envelope_digest": evidence.EnvelopeDigest, "executable_digest": evidence.ExecutableDigest,
				"stdout_bytes": transportResult.StdoutBytes, "stderr_bytes": transportResult.StderrBytes,
			},
		}); err != nil {
			return err
		}
		result = InstallPreparedControlResult{
			Installed: true, SystemID: current.ID, Control: record, Task: task,
			EnvelopeDigest: evidence.EnvelopeDigest, ExecutableDigest: evidence.ExecutableDigest,
			PolicyGeneration: evidence.PolicyGeneration, Transport: transportResult,
			NetworkConnections: transportResult.Attempts, AuditLog: auditLog,
		}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return InstallPreparedControlResult{}, failure
		}
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return InstallPreparedControlResult{}, appError("cancelled", 8, "Control installation stopped at a fail-safe checkpoint.", "Run the same explicit operation to resume.", err)
		case errors.Is(err, workflow.ErrConflict), errors.Is(err, controlnodes.ErrRevisionConflict):
			return InstallPreparedControlResult{}, appError("control_conflict", 6, "Control installation state changed concurrently.", "Refresh status and retry.", err)
		default:
			return InstallPreparedControlResult{}, appError("control_install", 5, "The prepared Control installation checkpoint is inconsistent or invalid.", "Inspect the private task, envelope and install evidence before retrying.", err)
		}
	}
	notify(observer, "control_install", "complete", "the Control runtime is installed; management-key proof and bootstrap revocation are still required")
	return result, nil
}

func validatePreparedControlApplyCheckpoint(system systemstate.System, record controlnodes.Record, task workflow.Task) error {
	if system.Bootstrap.State != systemstate.BootstrapProvisioning || record.Lifecycle != controlnodes.LifecycleInstalling ||
		record.Access.Phase != controlnodes.AccessStaged {
		return appError("control_install_checkpoint", 6, "Control is not at the staged provisioning checkpoint.", "Prepare the signed route-free installation envelope first.", nil)
	}
	switch task.Phase {
	case workflow.PhaseInstalling, workflow.PhaseAttesting:
		return nil
	case workflow.PhaseFailedSafe:
		if task.ResumePhase == workflow.PhaseInstalling && task.Failure != nil && task.Failure.Code == "control_install" {
			return nil
		}
	}
	return appError("control_install_checkpoint", 6, "The Control task is not at the installation or attestation checkpoint.", "Recover the exact persistent task before any connection.", nil)
}

func readControlInstallEvidence(store interface {
	ReadJSON(string, any) error
}, systemID, controlName string, prepared preparedControlEnvelope) (controlInstallEvidence, error) {
	var evidence controlInstallEvidence
	if err := store.ReadJSON(controlInstallEvidenceRelative(controlName), &evidence); err != nil {
		return controlInstallEvidence{}, err
	}
	if err := validateControlInstallEvidence(evidence, systemID, controlName, prepared); err != nil {
		return controlInstallEvidence{}, err
	}
	return evidence, nil
}

func validateControlInstallEvidence(evidence controlInstallEvidence, systemID, controlName string, prepared preparedControlEnvelope) error {
	if evidence.SchemaVersion != controlInstallEvidenceSchema || evidence.SystemID != systemID || evidence.ControlName != controlName ||
		evidence.EnvelopeDigest != prepared.digest || evidence.PolicyGeneration != prepared.envelope.Policy.Policy.Generation ||
		evidence.ExecutableBytes <= 0 || !validContentDigest(evidence.ExecutableDigest) ||
		evidence.Route != "direct_first_control" || evidence.Attempts != 1 || !validUTCTime(evidence.InstalledAt) {
		return errors.New("invalid Control install evidence")
	}
	return nil
}

func validContentDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func validUTCTime(value time.Time) bool {
	if value.IsZero() || value.Unix() <= 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func installResultFromEvidence(record controlnodes.Record, task workflow.Task, evidence controlInstallEvidence, already, reconciled bool, auditLog string) InstallPreparedControlResult {
	return InstallPreparedControlResult{
		Installed: true, AlreadyInstalled: already, Reconciled: reconciled,
		SystemID: evidence.SystemID, Control: record, Task: task,
		EnvelopeDigest: evidence.EnvelopeDigest, ExecutableDigest: evidence.ExecutableDigest,
		PolicyGeneration: evidence.PolicyGeneration, NetworkConnections: 0, AuditLog: auditLog,
	}
}

func controlInstallEvidenceRelative(name string) string {
	return filepath.Join("control", "install", name, "applied-g1.json")
}
