package application

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controltransport"
	"dynamicflow/internal/instances"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/netpolicy"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/sshtransport"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

// BindControlRequest contains the complete human-confirmed trust boundary for
// the first Control VM. HostPublicKey must come from the named independent
// evidence channel; BindControl never discovers a host key from the network.
type BindControlRequest struct {
	Meta            RequestMeta                  `json:"meta"`
	Name            string                       `json:"name"`
	Host            string                       `json:"host"`
	Port            int                          `json:"port"`
	SSHUser         string                       `json:"ssh_user"`
	OperatingSystem controlnodes.OperatingSystem `json:"operating_system"`
	HostPublicKey   string                       `json:"host_public_key"`
	EvidenceSource  controlnodes.EvidenceSource  `json:"evidence_source"`
}

type BindControlPlan struct {
	Plan                 bool                 `json:"plan"`
	SystemID             string               `json:"system_id"`
	ControlName          string               `json:"control_name"`
	CanonicalHost        string               `json:"canonical_host"`
	Port                 int                  `json:"port"`
	SSHUser              string               `json:"ssh_user"`
	OperatingSystem      string               `json:"operating_system"`
	HostKeyFingerprint   string               `json:"host_key_fingerprint"`
	EvidenceSource       string               `json:"evidence_source"`
	Changes              []string             `json:"changes"`
	NetworkConnections   int                  `json:"network_connections"`
	GeneratesPrivateKeys bool                 `json:"generates_private_keys"`
	Existing             *controlnodes.Record `json:"existing,omitempty"`
}

type BindControlResult struct {
	Created            bool                `json:"created"`
	Resumed            bool                `json:"resumed"`
	System             systemstate.System  `json:"system"`
	Control            controlnodes.Record `json:"control"`
	Task               workflow.Task       `json:"task"`
	TopologyGeneration uint64              `json:"topology_generation"`
	NetworkConnections int                 `json:"network_connections"`
	AuditLog           string              `json:"audit_log"`
}

type ControlStatusResult struct {
	System     systemstate.System    `json:"system"`
	Controls   []controlnodes.Record `json:"controls"`
	Tasks      []workflow.Task       `json:"tasks"`
	Topology   *topology.Topology    `json:"topology,omitempty"`
	ObservedAt time.Time             `json:"observed_at"`
}

type CheckControlRequest struct {
	Meta RequestMeta `json:"meta"`
	Name string      `json:"name"`
}

type CheckControlPlan struct {
	Plan               bool     `json:"plan"`
	SystemID           string   `json:"system_id"`
	ControlName        string   `json:"control_name"`
	CurrentLifecycle   string   `json:"current_lifecycle"`
	CurrentTaskPhase   string   `json:"current_task_phase"`
	Changes            []string `json:"changes"`
	NetworkConnections int      `json:"network_connections"`
	FixedRemoteCommand string   `json:"fixed_remote_command,omitempty"`
	AlreadyVerified    bool     `json:"already_verified"`
	ResumesFailedTask  bool     `json:"resumes_failed_task"`
}

type CheckControlResult struct {
	Verified           bool                    `json:"verified"`
	AlreadyVerified    bool                    `json:"already_verified"`
	Reconciled         bool                    `json:"reconciled"`
	SystemID           string                  `json:"system_id"`
	Control            controlnodes.Record     `json:"control"`
	Task               workflow.Task           `json:"task"`
	Transport          controltransport.Result `json:"transport"`
	NetworkConnections int                     `json:"network_connections"`
	AuditLog           string                  `json:"audit_log"`
}

type controlBindingContext struct {
	system    systemstate.System
	task      workflow.Task
	keys      *sshkeys.Manager
	workflows *workflow.Manager
}

type normalizedControlRequest struct {
	name            string
	host            string
	port            int
	sshUser         string
	operatingSystem controlnodes.OperatingSystem
	hostPublicKey   string
	hostFingerprint string
	evidenceSource  controlnodes.EvidenceSource
}

// PlanControlBind validates all local input and existing trust state without
// opening a socket, creating a lock, or changing local state.
func (application *Application) PlanControlBind(operation context.Context, request BindControlRequest) (BindControlPlan, error) {
	if err := operation.Err(); err != nil {
		return BindControlPlan{}, appError("cancelled", 8, "Control binding plan was cancelled.", "Retry the plan.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return BindControlPlan{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create or select a system before binding Control.", err)
	}
	store, err := application.openSystemStore(active.ID)
	if err != nil {
		return BindControlPlan{}, appError("system_state", 3, "The active system state is unavailable.", "Repair its private owner-local directory.", err)
	}
	context, err := application.loadControlBindingContext(store, active, request.Name, false)
	if err != nil {
		return BindControlPlan{}, err
	}
	normalized, err := normalizeControlRequest(request, context.task.Resource.Name)
	if err != nil {
		return BindControlPlan{}, err
	}
	if normalized.hostFingerprint == context.task.Key.Fingerprint {
		return BindControlPlan{}, appError("control_hostkey", 5, "The SSH host key must be distinct from the operator bootstrap identity.", "Obtain the VM's ssh_host_ed25519_key.pub from the provider console.", nil)
	}
	manager, err := controlnodes.NewManager(application.store, context.keys, controlnodes.WithClock(application.now))
	if err != nil {
		return BindControlPlan{}, appError("control_state", 3, "Control state could not be validated.", "Repair the private system state.", err)
	}
	plan := BindControlPlan{
		Plan: true, SystemID: active.ID, ControlName: normalized.name,
		CanonicalHost: normalized.host, Port: normalized.port, SSHUser: normalized.sshUser,
		OperatingSystem: string(normalized.operatingSystem), HostKeyFingerprint: normalized.hostFingerprint,
		EvidenceSource: string(normalized.evidenceSource), NetworkConnections: 0, GeneratesPrivateKeys: false,
	}
	existing, getErr := manager.Get(active.ID, normalized.name)
	switch {
	case getErr == nil:
		if !bindingMatches(existing, normalized, context.task.Key) {
			return BindControlPlan{}, appError("control_binding_conflict", 6, "The Control VM is already bound to different immutable trust data.", "Create a replacement workflow; do not overwrite a pinned endpoint or host key.", controlnodes.ErrBindingConflict)
		}
		plan.Existing = &existing
		plan.Changes = []string{}
	case errors.Is(getErr, controlnodes.ErrNotFound):
		if bootstrapExpired(active, application.now()) {
			return BindControlPlan{}, expiredBootstrapError()
		}
		plan.Changes = []string{
			"commit the independently verified Control endpoint and Ed25519 host key",
			"persist the initial pinned topology generation",
			"advance the resumable Control task through the host-trust gate",
		}
	default:
		return BindControlPlan{}, appError("control_state", 3, "Existing Control trust state is invalid.", "Repair the pinned metadata before continuing.", getErr)
	}
	return plan, nil
}

// BindControl commits only local, independently verified trust metadata. it
// deliberately performs zero network operations. a crash between checkpoints
// is repaired by replaying the exact same immutable request.
func (application *Application) BindControl(operation context.Context, request BindControlRequest, observer Observer) (BindControlResult, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return BindControlResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if err := operation.Err(); err != nil {
		return BindControlResult{}, appError("cancelled", 8, "Control binding was cancelled.", "Run the same operation to resume.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return BindControlResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create or select a system before binding Control.", err)
	}
	var result BindControlResult
	operationLock := filepath.Join("systems", active.ID, "operations", "control-bootstrap.lock")
	err = application.store.WithLock(operationLock, func() error {
		if err := operation.Err(); err != nil {
			return err
		}
		current, err := application.systems.Active()
		if err != nil || current.ID != active.ID {
			return fmt.Errorf("active system changed during Control binding: %w", err)
		}
		store, err := application.openSystemStore(current.ID)
		if err != nil {
			return err
		}
		bindingContext, err := application.loadControlBindingContext(store, current, request.Name, false)
		if err != nil {
			return err
		}
		normalized, err := normalizeControlRequest(request, bindingContext.task.Resource.Name)
		if err != nil {
			return err
		}
		if normalized.hostFingerprint == bindingContext.task.Key.Fingerprint {
			return appError("control_hostkey", 5, "The SSH host key must be distinct from the operator bootstrap identity.", "Obtain the VM's ssh_host_ed25519_key.pub from the provider console.", nil)
		}
		manager, err := controlnodes.NewManager(application.store, bindingContext.keys, controlnodes.WithClock(application.now))
		if err != nil {
			return err
		}
		existing, getErr := manager.Get(current.ID, normalized.name)
		if errors.Is(getErr, controlnodes.ErrNotFound) && bootstrapExpired(current, application.now()) {
			return expiredBootstrapError()
		}
		if getErr != nil && !errors.Is(getErr, controlnodes.ErrNotFound) {
			return getErr
		}
		if getErr == nil && !bindingMatches(existing, normalized, bindingContext.task.Key) {
			return controlnodes.ErrBindingConflict
		}

		notify(observer, "control_host_trust", "running", "committing the independently verified Ed25519 host key")
		record, created, err := manager.Bind(controlnodes.BindInput{
			SystemID: current.ID, Name: normalized.name, Host: normalized.host, Port: normalized.port,
			SSHUser: normalized.sshUser, OperatingSystem: normalized.operatingSystem,
			BootstrapKey: controlnodes.BootstrapKeyRef{
				Scope: bindingContext.task.Key.Scope, Name: bindingContext.task.Key.Name,
				Generation: bindingContext.task.Key.Generation, Fingerprint: bindingContext.task.Key.Fingerprint,
			},
			HostPublicKey: normalized.hostPublicKey, EvidenceSource: normalized.evidenceSource,
		})
		if err != nil {
			return err
		}
		notify(observer, "topology", "running", "pinning the sole direct first-Control route")
		topologyState, err := reconcileBoundTopology(store, record)
		if err != nil {
			return err
		}
		notify(observer, "workflow", "running", "advancing the persistent task through the host-trust gate")
		task, err := advanceTaskToHostVerified(operation, bindingContext.workflows, bindingContext.task)
		if err != nil {
			return err
		}
		notify(observer, "system", "running", "committing the bound Control identity")
		current, err = application.reconcileHostBoundSystem(current.ID, record)
		if err != nil {
			return err
		}
		auditLog, _ := application.store.Path("logs/audit.jsonl")
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.bind", "outcome": "success",
			"fields": map[string]any{
				"system_id": current.ID, "control": record.Name, "task_id": task.ID,
				"host_fingerprint": record.HostFingerprint, "evidence_source": record.EvidenceSource,
				"created": created, "network_connections": 0,
			},
		}); err != nil {
			return fmt.Errorf("commit Control binding audit: %w", err)
		}
		result = BindControlResult{
			Created: created, Resumed: !created, System: current, Control: record, Task: task,
			TopologyGeneration: topologyState.Generation, NetworkConnections: 0, AuditLog: auditLog,
		}
		return nil
	})
	if err != nil {
		if failure := new(Error); errors.As(err, &failure) {
			return BindControlResult{}, failure
		}
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return BindControlResult{}, appError("cancelled", 8, "Control binding stopped at a resumable checkpoint.", "Repeat the exact same binding operation.", err)
		case errors.Is(err, controlnodes.ErrBindingConflict):
			return BindControlResult{}, appError("control_binding_conflict", 6, "The Control VM is already bound to different immutable trust data.", "Create a replacement workflow; do not overwrite a pinned endpoint or host key.", err)
		case errors.Is(err, controlnodes.ErrBootstrapKeyMismatch):
			return BindControlResult{}, appError("bootstrap_identity", 5, "The Control bootstrap identity no longer matches its workflow.", "Recover the original owner-local key generation; do not create a silent replacement.", err)
		default:
			return BindControlResult{}, appError("control_bind", 3, "Control trust could not be committed safely.", "Inspect the private audit/task state and repeat the exact operation to resume.", err)
		}
	}
	notify(observer, "control_host_trust", "complete", "Control endpoint and host key are pinned; no network connection was made")
	return result, nil
}

type controlCheckMode int

const (
	controlCheckInvalid controlCheckMode = iota
	controlCheckNetwork
	controlCheckResumeNetwork
	controlCheckReconcile
	controlCheckAlreadyVerified
)

// PlanControlCheck proves that all local identities and pins needed by the
// single direct first-Control exception are intact. it creates no managed SSH
// files, starts no process and changes no workflow checkpoint.
func (application *Application) PlanControlCheck(operation context.Context, request CheckControlRequest) (CheckControlPlan, error) {
	if err := operation.Err(); err != nil {
		return CheckControlPlan{}, appError("cancelled", 8, "Control connectivity plan was cancelled.", "Retry the plan.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return CheckControlPlan{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create and bind the first Control VM.", err)
	}
	store, err := application.openSystemStore(active.ID)
	if err != nil {
		return CheckControlPlan{}, appError("system_state", 3, "The active system state is unavailable.", "Repair its private owner-local directory.", err)
	}
	bindingContext, err := application.loadControlBindingContext(store, active, request.Name, true)
	if err != nil {
		return CheckControlPlan{}, err
	}
	record, _, err := application.loadControlRecord(bindingContext)
	if err != nil {
		return CheckControlPlan{}, err
	}
	mode, err := classifyControlCheck(record, bindingContext.task)
	if err != nil {
		return CheckControlPlan{}, err
	}
	plan := CheckControlPlan{
		Plan: true, SystemID: active.ID, ControlName: record.Name,
		CurrentLifecycle: string(record.Lifecycle), CurrentTaskPhase: string(bindingContext.task.Phase),
		Changes: []string{}, NetworkConnections: 0,
	}
	switch mode {
	case controlCheckNetwork:
		if bootstrapExpired(active, application.now()) {
			return CheckControlPlan{}, expiredBootstrapError()
		}
		if _, err := authorizeFirstControlNetwork(active.ID, record, netpolicy.ActionFirstControlCheck); err != nil {
			return CheckControlPlan{}, err
		}
		if _, _, _, err := application.prepareFirstControlEndpoint(store, bindingContext); err != nil {
			return CheckControlPlan{}, err
		}
		plan.Changes = []string{
			"write content-addressed owner-only OpenSSH transport files",
			"make exactly one pinned direct SSH attempt to the first Control VM",
			"run the fixed remote command /bin/true and commit connectivity evidence",
		}
		plan.NetworkConnections = 1
		plan.FixedRemoteCommand = "/bin/true"
	case controlCheckResumeNetwork:
		if bootstrapExpired(active, application.now()) {
			return CheckControlPlan{}, expiredBootstrapError()
		}
		if _, err := authorizeFirstControlNetwork(active.ID, record, netpolicy.ActionFirstControlCheck); err != nil {
			return CheckControlPlan{}, err
		}
		if _, _, _, err := application.prepareFirstControlEndpoint(store, bindingContext); err != nil {
			return CheckControlPlan{}, err
		}
		plan.ResumesFailedTask = true
		plan.Changes = []string{
			"resume the recorded connectivity fail-safe checkpoint",
			"make exactly one pinned direct SSH attempt to the first Control VM",
			"run the fixed remote command /bin/true and commit connectivity evidence",
		}
		plan.NetworkConnections = 1
		plan.FixedRemoteCommand = "/bin/true"
	case controlCheckReconcile:
		plan.Changes = []string{"reconcile the persistent task with already committed connectivity evidence"}
	case controlCheckAlreadyVerified:
		plan.AlreadyVerified = true
	}
	return plan, nil
}

// CheckControl performs the only operator-local direct network connection
// permitted by the Control-first architecture. it is one pinned SSH attempt,
// one fixed /bin/true command, no shell, no retry and no fallback.
func (application *Application) CheckControl(operation context.Context, request CheckControlRequest, observer Observer) (CheckControlResult, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return CheckControlResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if err := operation.Err(); err != nil {
		return CheckControlResult{}, appError("cancelled", 8, "Control connectivity check was cancelled.", "Run the same explicit check to resume.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return CheckControlResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create and bind the first Control VM.", err)
	}
	var result CheckControlResult
	operationLock := filepath.Join("systems", active.ID, "operations", "control-bootstrap.lock")
	err = application.store.WithLock(operationLock, func() error {
		current, err := application.systems.Active()
		if err != nil || current.ID != active.ID {
			return fmt.Errorf("active system changed during Control check: %w", err)
		}
		store, err := application.openSystemStore(current.ID)
		if err != nil {
			return err
		}
		bindingContext, err := application.loadControlBindingContext(store, current, request.Name, true)
		if err != nil {
			return err
		}
		record, manager, err := application.loadControlRecord(bindingContext)
		if err != nil {
			return err
		}
		mode, err := classifyControlCheck(record, bindingContext.task)
		if err != nil {
			return err
		}
		task := bindingContext.task
		if mode == controlCheckResumeNetwork {
			notify(observer, "workflow", "running", "resuming the explicit connectivity fail-safe checkpoint")
			task, err = bindingContext.workflows.Resume(task.ID, task.Revision)
			if err != nil {
				return err
			}
			mode = controlCheckNetwork
		}
		auditLog, _ := application.store.Path("logs/audit.jsonl")
		if mode == controlCheckAlreadyVerified || mode == controlCheckReconcile {
			if mode == controlCheckReconcile {
				notify(observer, "workflow", "running", "reconciling committed connectivity evidence")
				task, err = bindingContext.workflows.Advance(task.ID, task.Revision, workflow.PhaseConnectivityOK)
				if err != nil {
					return err
				}
			}
			if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
				"time": application.now().UTC(), "action": "control.check", "outcome": "already_verified",
				"fields": map[string]any{"system_id": current.ID, "control": record.Name, "task_id": task.ID, "network_connections": 0, "reconciled": mode == controlCheckReconcile},
			}); err != nil {
				return fmt.Errorf("commit Control reconciliation audit: %w", err)
			}
			result = CheckControlResult{
				Verified: true, AlreadyVerified: mode == controlCheckAlreadyVerified, Reconciled: mode == controlCheckReconcile,
				SystemID: current.ID, Control: record, Task: task, NetworkConnections: 0, AuditLog: auditLog,
			}
			return nil
		}
		if mode != controlCheckNetwork {
			return fmt.Errorf("invalid Control connectivity mode")
		}
		if bootstrapExpired(current, application.now()) {
			return expiredBootstrapError()
		}
		decision, err := authorizeFirstControlNetwork(current.ID, record, netpolicy.ActionFirstControlCheck)
		if err != nil {
			return err
		}
		_, endpoint, endpointManager, err := application.prepareFirstControlEndpoint(store, bindingContext)
		if err != nil {
			return err
		}
		manager = endpointManager
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.check", "outcome": "intent",
			"fields": map[string]any{"system_id": current.ID, "control": record.Name, "task_id": task.ID, "route": "direct_first_control", "fixed_command": "/bin/true", "attempt": task.Attempt, "network_policy": decision},
		}); err != nil {
			return fmt.Errorf("commit Control connectivity intent: %w", err)
		}
		notify(observer, "control_connectivity", "running", "opening one pinned direct first-Control SSH connection")
		transport := controltransport.New(sshtransport.NewBuilder(store), application.controlRunner)
		transportResult, checkErr := transport.CheckFirstControl(operation, endpoint)
		if checkErr != nil {
			next := "Verify the provider-console host key, endpoint, cloud firewall and authorized bootstrap public key; then run the explicit check again."
			failed, failErr := bindingContext.workflows.FailSafe(task.ID, task.Revision, "control_connectivity", next)
			if failErr != nil {
				return fmt.Errorf("persist failed Control connectivity checkpoint: %w", failErr)
			}
			_ = application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
				"time": application.now().UTC(), "action": "control.check", "outcome": "failed_safe",
				"fields": map[string]any{
					"system_id": current.ID, "control": record.Name, "task_id": failed.ID,
					"route": "direct_first_control", "attempts": transportResult.Attempts,
					"stdout_bytes": transportResult.StdoutBytes, "stderr_bytes": transportResult.StderrBytes,
				},
			})
			return appError("control_connectivity", 7, "The pinned first-Control connectivity check failed safely.", next, checkErr)
		}
		notify(observer, "control_connectivity", "running", "committing connectivity evidence before advancing the task")
		record, err = manager.Transition(current.ID, record.Name, record.Revision, controlnodes.LifecycleConnectivityVerified)
		if err != nil {
			return err
		}
		task, err = bindingContext.workflows.Advance(task.ID, task.Revision, workflow.PhaseConnectivityOK)
		if err != nil {
			return err
		}
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.check", "outcome": "success",
			"fields": map[string]any{
				"system_id": current.ID, "control": record.Name, "task_id": task.ID,
				"route": transportResult.Route, "attempts": transportResult.Attempts,
				"stdout_bytes": transportResult.StdoutBytes, "stderr_bytes": transportResult.StderrBytes,
			},
		}); err != nil {
			return fmt.Errorf("commit Control connectivity audit: %w", err)
		}
		result = CheckControlResult{
			Verified: true, SystemID: current.ID, Control: record, Task: task,
			Transport: transportResult, NetworkConnections: transportResult.Attempts, AuditLog: auditLog,
		}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return CheckControlResult{}, failure
		}
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return CheckControlResult{}, appError("cancelled", 8, "The Control connectivity check stopped at a fail-safe checkpoint.", "Run the same explicit check to resume.", err)
		case errors.Is(err, controlnodes.ErrRevisionConflict), errors.Is(err, workflow.ErrConflict):
			return CheckControlResult{}, appError("control_conflict", 6, "Control connectivity state changed concurrently.", "Refresh status and retry the explicit check.", err)
		default:
			return CheckControlResult{}, appError("control_check", 5, "The first-Control connectivity gate is inconsistent or invalid.", "Inspect Control status, pins and the persistent task before retrying.", err)
		}
	}
	notify(observer, "control_connectivity", "complete", "the pinned first-Control SSH path is verified")
	return result, nil
}

func (application *Application) ControlStatus(operation context.Context) (ControlStatusResult, error) {
	if err := operation.Err(); err != nil {
		return ControlStatusResult{}, appError("cancelled", 8, "Control status refresh was cancelled.", "Retry the refresh.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return ControlStatusResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create or select a system first.", err)
	}
	store, err := application.openSystemStore(active.ID)
	if err != nil {
		return ControlStatusResult{}, appError("system_state", 3, "The active system state is unavailable.", "Repair its private owner-local directory.", err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now), sshkeys.WithControlScope())
	manager, err := controlnodes.NewManager(application.store, keys, controlnodes.WithClock(application.now))
	if err != nil {
		return ControlStatusResult{}, appError("control_state", 3, "Control state is invalid.", "Repair the private Control registry.", err)
	}
	controls, err := manager.List(active.ID)
	if err != nil {
		return ControlStatusResult{}, appError("control_state", 3, "Control state is invalid.", "Repair the private Control registry.", err)
	}
	tasks, err := workflow.NewManager(store, workflow.WithClock(application.now)).List()
	if err != nil {
		return ControlStatusResult{}, appError("workflow_state", 3, "Control workflow state is invalid.", "Repair the affected persistent task.", err)
	}
	var topologyResult *topology.Topology
	document, topologyErr := topology.NewStore(store).Load()
	if topologyErr == nil {
		topologyResult = &document
	} else if !errors.Is(topologyErr, topology.ErrNotFound) {
		return ControlStatusResult{}, appError("topology_state", 3, "The Control topology is invalid.", "Repair the pinned topology before any connection.", topologyErr)
	}
	return ControlStatusResult{System: active, Controls: controls, Tasks: tasks, Topology: topologyResult, ObservedAt: application.now().UTC()}, nil
}

func (application *Application) loadControlBindingContext(store *localstate.Store, active systemstate.System, requestedName string, allowConnectivityResume bool) (controlBindingContext, error) {
	if store == nil || active.ID == "" {
		return controlBindingContext{}, appError("system_state", 3, "The active system state is unavailable.", "Repair its owner-local directory.", nil)
	}
	switch active.Bootstrap.State {
	case systemstate.BootstrapKeyPrepared, systemstate.BootstrapHostBound,
		systemstate.BootstrapProvisioning, systemstate.BootstrapControlActive:
	default:
		return controlBindingContext{}, appError("control_gate", 6, "The active system is not at a bindable Control bootstrap checkpoint.", "Resume or recover its existing Control workflow.", nil)
	}
	workflows := workflow.NewManager(store, workflow.WithClock(application.now))
	tasks, err := workflows.List()
	if err != nil {
		return controlBindingContext{}, appError("workflow_state", 3, "Control workflow state is invalid.", "Recover the persistent bootstrap task before continuing.", err)
	}
	var selected *workflow.Task
	for index := range tasks {
		task := &tasks[index]
		if task.Kind != workflow.ControlBootstrap || task.SystemID != active.ID {
			continue
		}
		if requestedName != "" && task.Resource.Name != requestedName {
			continue
		}
		if selected != nil {
			return controlBindingContext{}, appError("workflow_state", 3, "More than one first-Control bootstrap task matches the active system.", "Repair the conflicting private task state.", nil)
		}
		selected = task
	}
	if selected == nil {
		return controlBindingContext{}, appError("control_task", 3, "The first-Control bootstrap task is missing.", "Run flow system init with the original system and Control names to resume.", workflow.ErrNotFound)
	}
	if selected.Phase == workflow.PhaseFailedSafe && !allowConnectivityResume {
		next := "Recover the fail-safe task before binding Control."
		if selected.Failure != nil && strings.TrimSpace(selected.Failure.Next) != "" {
			next = selected.Failure.Next
		}
		return controlBindingContext{}, appError("control_failed_safe", 6, "The first-Control task is in a fail-closed state.", next, nil)
	}
	if selected.Phase == workflow.PhaseRevoked {
		return controlBindingContext{}, appError("control_revoked", 4, "The first-Control bootstrap was revoked.", "Start an explicit replacement workflow.", nil)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now), sshkeys.WithControlScope())
	key, _, err := keys.Active(selected.Key.Scope, selected.Key.Name)
	if err != nil || key.Generation != selected.Key.Generation || key.Fingerprint != selected.Key.Fingerprint ||
		key.Fingerprint != active.Bootstrap.BootstrapKeyFingerprint {
		return controlBindingContext{}, appError("bootstrap_identity", 5, "The owner-local Control bootstrap identity does not match system and task state.", "Recover the original key generation; never create a silent replacement.", err)
	}
	return controlBindingContext{system: active, task: *selected, keys: keys, workflows: workflows}, nil
}

func normalizeControlRequest(request BindControlRequest, expectedName string) (normalizedControlRequest, error) {
	name := request.Name
	if name == "" {
		name = expectedName
	}
	if name != expectedName {
		return normalizedControlRequest{}, appError("control_name", 6, "The Control name does not match the immutable bootstrap task.", "Use the Control name printed by flow system init.", nil)
	}
	port := request.Port
	if port == 0 {
		port = 22
	}
	host, err := instances.ValidateEndpoint(request.Host, request.SSHUser, port)
	if err != nil || request.SSHUser == "root" {
		return normalizedControlRequest{}, appError("control_endpoint", 2, "The Control SSH endpoint is unsafe or invalid.", "Use a canonical IP/hostname, port 1-65535 and a non-root SSH user.", err)
	}
	switch request.OperatingSystem {
	case controlnodes.OSDebian13, controlnodes.OSUbuntu2404:
	default:
		return normalizedControlRequest{}, appError("control_os", 2, "The Control operating system is unsupported.", "Use debian-13 or ubuntu-24.04 on amd64.", nil)
	}
	switch request.EvidenceSource {
	case controlnodes.EvidenceProviderConsole, controlnodes.EvidenceProviderAttestation:
	default:
		return normalizedControlRequest{}, appError("control_evidence", 2, "The SSH host key lacks an independent evidence source.", "Use provider-console or provider-attestation; network observation is not trusted.", nil)
	}
	normalizedKey, fingerprint, err := sshkeys.ValidateEd25519PublicKey(request.HostPublicKey)
	if err != nil {
		return normalizedControlRequest{}, appError("control_hostkey", 5, "The supplied Control host key is not a valid Ed25519 public key.", "Obtain the complete ssh_host_ed25519_key.pub through the independent provider channel.", err)
	}
	fields := strings.Fields(normalizedKey)
	if len(fields) < 2 {
		return normalizedControlRequest{}, appError("control_hostkey", 5, "The supplied Control host key is invalid.", "Use the single-line Ed25519 host public key.", nil)
	}
	// drop any untrusted comment before persistence or display. the key type and
	// base64 body are the complete cryptographic host identity.
	canonicalKey := strings.Join(fields[:2], " ")
	return normalizedControlRequest{
		name: name, host: host, port: port, sshUser: request.SSHUser,
		operatingSystem: request.OperatingSystem, hostPublicKey: canonicalKey,
		hostFingerprint: fingerprint, evidenceSource: request.EvidenceSource,
	}, nil
}

func bindingMatches(record controlnodes.Record, request normalizedControlRequest, key workflow.KeyReference) bool {
	return record.SystemID != "" && record.Name == request.name && record.Host == request.host &&
		record.Port == request.port && record.SSHUser == request.sshUser &&
		record.OperatingSystem == request.operatingSystem && record.HostPublicKey == request.hostPublicKey &&
		record.HostFingerprint == request.hostFingerprint && record.EvidenceSource == request.evidenceSource &&
		record.BootstrapKey == (controlnodes.BootstrapKeyRef{
			Scope: key.Scope, Name: key.Name, Generation: key.Generation, Fingerprint: key.Fingerprint,
		})
}

func (application *Application) prepareFirstControlEndpoint(store *localstate.Store, bindingContext controlBindingContext) (controlnodes.Record, sshtransport.Endpoint, *controlnodes.Manager, error) {
	record, manager, err := application.loadControlRecord(bindingContext)
	if err != nil {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, err
	}
	document, err := topology.NewStore(store).Load()
	if err != nil || document.Control == nil {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, appError("topology_state", 3, "The first-Control topology is missing or invalid.", "Repeat the exact Control binding to restore its safe checkpoint.", err)
	}
	expected := topology.Control{
		Name: record.Name, Host: record.Host, SSHPort: record.Port, SSHUser: record.SSHUser,
		Trust: topology.TrustPinned, HostKeyFingerprint: record.HostFingerprint,
	}
	if *document.Control != expected || document.ControlReady {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, appError("topology_state", 5, "The direct first-Control route is not the expected pinned pre-activation route.", "Do not use a direct fallback; inspect the topology and Control lifecycle.", topology.ErrRouteBinding)
	}
	material, err := manager.AccessMaterial(bindingContext.system.ID, record.Name)
	if err != nil {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, appError("bootstrap_identity", 5, "The owner-local bootstrap identity or pinned known_hosts file is invalid.", "Recover the exact key generation and host pin before connecting.", err)
	}
	identity, err := sshtransport.NewPrivateIdentity(material.IdentityPath)
	if err != nil {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, appError("bootstrap_identity", 5, "The owner-local bootstrap private key is not a safe 0600 identity.", "Repair its ownership, mode and single-link regular-file invariant.", err)
	}
	fields := strings.Fields(record.HostPublicKey)
	if len(fields) < 2 {
		return controlnodes.Record{}, sshtransport.Endpoint{}, nil, appError("control_hostkey", 5, "The pinned Control host key is invalid.", "Recover it from the independent evidence source.", nil)
	}
	endpoint := sshtransport.Endpoint{
		Alias: record.Name, Role: sshtransport.RoleControl, Host: record.Host, Port: record.Port,
		User: material.SSHUser, Identity: identity, IdentityFingerprint: material.Identity.Fingerprint,
		HostKey: strings.Join(fields[:2], " "), HostKeyFingerprint: record.HostFingerprint,
	}
	return record, endpoint, manager, nil
}

func (application *Application) loadControlRecord(bindingContext controlBindingContext) (controlnodes.Record, *controlnodes.Manager, error) {
	manager, err := controlnodes.NewManager(application.store, bindingContext.keys, controlnodes.WithClock(application.now))
	if err != nil {
		return controlnodes.Record{}, nil, appError("control_state", 3, "Control state could not be validated.", "Repair the private Control registry.", err)
	}
	record, err := manager.Get(bindingContext.system.ID, bindingContext.task.Resource.Name)
	if err != nil {
		return controlnodes.Record{}, nil, appError("control_binding", 3, "The first Control VM is not safely bound.", "Bind its endpoint and independently verified Ed25519 host key first.", err)
	}
	return record, manager, nil
}

func authorizeFirstControlNetwork(systemID string, record controlnodes.Record, action netpolicy.Action) (netpolicy.Decision, error) {
	decision, err := netpolicy.Decide(netpolicy.Input{
		SystemID: systemID, Source: netpolicy.ActorOperator, Destination: netpolicy.ActorControl,
		Action: action, Bootstrap: netpolicy.BootstrapControlPending, ControlReady: false,
		ControlRevoked: record.Lifecycle == controlnodes.LifecycleRevoked,
		Control: netpolicy.ControlBinding{
			ID: record.Name, SelectedFingerprint: record.HostFingerprint, PinnedFingerprint: record.HostFingerprint,
		},
		Target:    netpolicy.TargetBinding{ID: record.Name, PinnedFingerprint: record.HostFingerprint},
		Authority: netpolicy.Authority{Human: true},
	})
	if err != nil || !decision.Allowed() || decision.Mode() != netpolicy.ModeDirectFirstControl {
		return netpolicy.Decision{}, appError("network_policy", 6, "The Control-first network policy denied the direct bootstrap path.", "Inspect the selected Control identity, host pin and bootstrap checkpoint; no fallback is permitted.", err)
	}
	return decision, nil
}

func classifyControlCheck(record controlnodes.Record, task workflow.Task) (controlCheckMode, error) {
	if task.Phase == workflow.PhaseFailedSafe {
		if record.Lifecycle == controlnodes.LifecycleBound && task.ResumePhase == workflow.PhaseHostKeyVerified &&
			task.Failure != nil && task.Failure.Code == "control_connectivity" {
			return controlCheckResumeNetwork, nil
		}
		return controlCheckInvalid, appError("control_failed_safe", 6, "The Control task has a different fail-safe checkpoint.", "Recover the recorded task failure before attempting connectivity.", nil)
	}
	if task.Phase == workflow.PhaseRevoked || record.Lifecycle == controlnodes.LifecycleRevoked {
		return controlCheckInvalid, appError("control_revoked", 4, "The Control bootstrap or node has been revoked.", "Start an explicit replacement workflow.", nil)
	}
	switch record.Lifecycle {
	case controlnodes.LifecycleBound:
		if task.Phase == workflow.PhaseHostKeyVerified {
			return controlCheckNetwork, nil
		}
	case controlnodes.LifecycleConnectivityVerified:
		if task.Phase == workflow.PhaseHostKeyVerified {
			return controlCheckReconcile, nil
		}
		if taskAtOrAfterConnectivity(task.Phase) {
			return controlCheckAlreadyVerified, nil
		}
	case controlnodes.LifecycleInstalling, controlnodes.LifecycleReady:
		if taskAtOrAfterConnectivity(task.Phase) {
			return controlCheckAlreadyVerified, nil
		}
	}
	return controlCheckInvalid, appError("control_checkpoint", 6, "Control lifecycle and persistent task checkpoints disagree.", "Refresh status and resume the earlier incomplete phase; do not open a direct fallback.", nil)
}

func taskAtOrAfterConnectivity(phase workflow.Phase) bool {
	switch phase {
	case workflow.PhaseConnectivityOK, workflow.PhaseInstalling, workflow.PhaseAttesting, workflow.PhaseReady:
		return true
	default:
		return false
	}
}

func bootstrapExpired(system systemstate.System, now time.Time) bool {
	return system.Bootstrap.ExpiresAt == nil || !now.UTC().Before(system.Bootstrap.ExpiresAt.UTC())
}

func expiredBootstrapError() *Error {
	return appError("bootstrap_expired", 4, "The first-Control bootstrap identity has expired before host binding.", "Rotate it explicitly and replace the cloud-authorized public key before any connection.", nil)
}

func reconcileBoundTopology(store *localstate.Store, record controlnodes.Record) (topology.Topology, error) {
	topologies := topology.NewStore(store)
	expectedControl := topology.Control{
		Name: record.Name, Host: record.Host, SSHPort: record.Port, SSHUser: record.SSHUser,
		Trust: topology.TrustPinned, HostKeyFingerprint: record.HostFingerprint,
	}
	document, err := topologies.Load()
	if errors.Is(err, topology.ErrNotFound) {
		document = topology.Topology{
			Schema: topology.SchemaVersion, Generation: 1, ControlReady: false,
			Control: &expectedControl, Targets: []topology.Target{}, Routes: []topology.Route{},
		}
		if err := topologies.Save(document); err != nil {
			return topology.Topology{}, err
		}
		return document, nil
	}
	if err != nil {
		return topology.Topology{}, err
	}
	if document.Control == nil || *document.Control != expectedControl {
		return topology.Topology{}, fmt.Errorf("%w: persisted Control differs from immutable binding", topology.ErrRouteBinding)
	}
	if document.ControlReady && record.Lifecycle != controlnodes.LifecycleReady {
		return topology.Topology{}, fmt.Errorf("%w: topology says ready before the Control lifecycle", topology.ErrInvalidTopology)
	}
	return document, nil
}

func advanceTaskToHostVerified(operation context.Context, workflows *workflow.Manager, task workflow.Task) (workflow.Task, error) {
	for {
		if err := operation.Err(); err != nil {
			return workflow.Task{}, err
		}
		var next workflow.Phase
		switch task.Phase {
		case workflow.PhasePrepared:
			next = workflow.PhaseAwaitingCloudVM
		case workflow.PhaseAwaitingCloudVM:
			next = workflow.PhaseAwaitingEndpoint
		case workflow.PhaseAwaitingEndpoint:
			next = workflow.PhaseAwaitingOOBHostKey
		case workflow.PhaseAwaitingOOBHostKey:
			next = workflow.PhaseHostKeyVerified
		case workflow.PhaseHostKeyVerified, workflow.PhaseConnectivityOK, workflow.PhaseInstalling,
			workflow.PhaseAttesting, workflow.PhaseReady:
			return task, nil
		case workflow.PhaseFailedSafe:
			return workflow.Task{}, appError("control_failed_safe", 6, "The first-Control task is in a fail-closed state.", "Recover its recorded failure before continuing.", nil)
		case workflow.PhaseRevoked:
			return workflow.Task{}, appError("control_revoked", 4, "The first-Control bootstrap was revoked.", "Start an explicit replacement workflow.", nil)
		default:
			return workflow.Task{}, workflow.ErrInvalidPhase
		}
		updated, err := workflows.Advance(task.ID, task.Revision, next)
		if err != nil {
			return workflow.Task{}, err
		}
		task = updated
	}
}

func (application *Application) reconcileHostBoundSystem(systemID string, record controlnodes.Record) (systemstate.System, error) {
	current, err := application.systems.Get(systemID)
	if err != nil {
		return systemstate.System{}, err
	}
	if current.Bootstrap.BootstrapKeyFingerprint != record.BootstrapKey.Fingerprint || current.Bootstrap.ExpiresAt == nil {
		return systemstate.System{}, fmt.Errorf("bootstrap metadata differs from bound Control")
	}
	switch current.Bootstrap.State {
	case systemstate.BootstrapKeyPrepared:
		return application.systems.Update(current.ID, current.Revision, func(candidate *systemstate.System) error {
			candidate.Bootstrap.State = systemstate.BootstrapHostBound
			candidate.Bootstrap.ControlNodeID = record.Name
			candidate.Bootstrap.HostKeyFingerprint = record.HostFingerprint
			return nil
		})
	case systemstate.BootstrapHostBound, systemstate.BootstrapProvisioning, systemstate.BootstrapControlActive:
		if current.Bootstrap.ControlNodeID != record.Name || current.Bootstrap.HostKeyFingerprint != record.HostFingerprint {
			return systemstate.System{}, fmt.Errorf("system Control binding differs from pinned Control")
		}
		return current, nil
	default:
		return systemstate.System{}, fmt.Errorf("system is not at a host-binding checkpoint")
	}
}
