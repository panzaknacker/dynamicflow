// Package application is the single policy and operation boundary shared by
// Dynamicflow's TUI, human CLI and JSON adapters.
package application

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controltransport"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

const defaultBootstrapLifetime = 2 * time.Hour

type Surface string

const (
	SurfaceCLI Surface = "cli"
	SurfaceTUI Surface = "tui"
)

type RequestMeta struct {
	Surface          Surface `json:"surface"`
	CorrelationID    string  `json:"correlation_id,omitempty"`
	ExpectedSystemID string  `json:"expected_system_id,omitempty"`
}

type Event struct {
	Phase  string `json:"phase"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Observer interface {
	OnEvent(Event)
}

type ObserverFunc func(Event)

func (function ObserverFunc) OnEvent(event Event) { function(event) }

type Error struct {
	Code     string `json:"code"`
	ExitCode int    `json:"-"`
	SafeText string `json:"message"`
	Next     string `json:"next"`
	Cause    error  `json:"-"`
}

func (failure *Error) Error() string {
	if failure == nil {
		return ""
	}
	return failure.SafeText
}

func (failure *Error) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

type Config struct {
	Store          *localstate.Store
	Clock          func() time.Time
	Random         io.Reader
	SSHKeygen      string
	ControlRunner  controltransport.Runner
	ExecutablePath string
}

type Application struct {
	store          *localstate.Store
	systems        *systemstate.Store
	now            func() time.Time
	sshKeygen      string
	controlRunner  controltransport.Runner
	executablePath string
}

func Open(config Config) (*Application, error) {
	if config.Store == nil {
		return nil, errors.New("application requires private local state")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	systems, err := systemstate.New(config.Store, systemstate.WithClock(clock), systemstate.WithRandomReader(random))
	if err != nil {
		return nil, err
	}
	keygen := config.SSHKeygen
	if keygen == "" {
		keygen = "ssh-keygen"
	}
	executablePath := config.ExecutablePath
	if executablePath == "" {
		executablePath, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve flow executable: %w", err)
		}
	}
	return &Application{
		store: config.Store, systems: systems, now: clock, sshKeygen: keygen,
		controlRunner: config.ControlRunner, executablePath: executablePath,
	}, nil
}

type InitSystemRequest struct {
	Meta        RequestMeta `json:"meta"`
	Name        string      `json:"name"`
	ControlName string      `json:"control_name"`
}

type InitSystemPlan struct {
	Plan                 bool     `json:"plan"`
	Name                 string   `json:"name"`
	ControlName          string   `json:"control_name"`
	ExistingSystemID     string   `json:"existing_system_id,omitempty"`
	Changes              []string `json:"changes"`
	NetworkConnections   int      `json:"network_connections"`
	GeneratesPrivateKeys bool     `json:"generates_private_keys"`
	DisplaysPublicOnly   bool     `json:"displays_public_only"`
	RequiresOOBHostKey   bool     `json:"requires_oob_hostkey"`
}

func (application *Application) PlanSystemInit(request InitSystemRequest) (InitSystemPlan, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return InitSystemPlan{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if request.ControlName == "" {
		request.ControlName = "control-1"
	}
	if !controlnodes.ValidName(request.ControlName) {
		return InitSystemPlan{}, invalidInitialControlName()
	}
	plan := InitSystemPlan{
		Plan: true, Name: request.Name, ControlName: request.ControlName, NetworkConnections: 0,
		DisplaysPublicOnly: true, RequiresOOBHostKey: true,
	}
	existing, err := application.systems.GetByName(request.Name)
	switch {
	case err == nil:
		if existing.Bootstrap.State != systemstate.BootstrapNotStarted && existing.Bootstrap.State != systemstate.BootstrapKeyPrepared {
			return InitSystemPlan{}, appError("system_bootstrap_advanced", 6, "The existing system has advanced beyond local initialization.", "Use flow system select and flow control status to resume its recorded Control workflow.", nil)
		}
		plan.ExistingSystemID = existing.ID
		if existing.Bootstrap.State == systemstate.BootstrapNotStarted {
			plan.Changes = []string{"ensure five separated offline trust roots", "create unique first-Control bootstrap identity", "persist resumable bootstrap task"}
			plan.GeneratesPrivateKeys = true
			store, openErr := application.openSystemStore(existing.ID)
			if openErr != nil && (existing.Trust.Generation > 0 || !errors.Is(openErr, os.ErrNotExist)) {
				return InitSystemPlan{}, appError("system_state", 5, "The existing initialization directory is unsafe.", "Recover the original private system directory.", openErr)
			}
			if openErr == nil {
				tasks, err := workflow.NewManager(store, workflow.WithClock(application.now)).List()
				if err != nil {
					return InitSystemPlan{}, appError("bootstrap_identity", 5, "The existing initialization journal is invalid.", "Recover its original task before resuming.", err)
				}
				if len(tasks) > 0 {
					if err := application.readInitialIdentity(existing, store, request); err != nil {
						return InitSystemPlan{}, err
					}
					plan.GeneratesPrivateKeys = false
					plan.Changes = []string{"verify existing trust roots and bootstrap task", "commit the incomplete system initialization checkpoint"}
				} else {
					keyStarted, err := bootstrapKeyStarted(store)
					if err != nil {
						return InitSystemPlan{}, err
					}
					if keyStarted || existing.Trust.Generation > 0 {
						if _, err := loadInitialTrust(existing, store); err != nil {
							return InitSystemPlan{}, err
						}
						keys := sshkeys.NewManager(store)
						if _, _, err := keys.Active(sshkeys.Bootstrap, request.ControlName); err == nil {
							plan.GeneratesPrivateKeys = false
							plan.Changes = []string{"verify existing trust roots and bootstrap identity", "persist resumable bootstrap task", "commit the incomplete system initialization checkpoint"}
						} else if !errors.Is(err, sshkeys.ErrNotFound) {
							return InitSystemPlan{}, appError("bootstrap_identity", 5, "The original first-Control bootstrap identity is unavailable.", "Recover its original private key and generation before resuming.", err)
						}
					}
				}
			}
		} else {
			store, err := application.openSystemStore(existing.ID)
			if err != nil {
				return InitSystemPlan{}, appError("system_state", 5, "The committed system directory is unavailable.", "Recover the original system state before resuming initialization.", err)
			}
			if err := application.readInitialIdentity(existing, store, request); err != nil {
				return InitSystemPlan{}, err
			}
			plan.Changes = []string{"verify existing trust roots", "reuse the bound bootstrap identity and task"}
		}
	case errors.Is(err, systemstate.ErrNotFound):
		plan.Changes = []string{"create provider-independent system registry entry", "create five separated offline trust roots", "create unique first-Control bootstrap identity", "persist resumable bootstrap task"}
		plan.GeneratesPrivateKeys = true
	default:
		return InitSystemPlan{}, appError("system_invalid", 3, "The system name or registry is invalid.", "Use a unique name containing letters, digits, dot, underscore or hyphen.", err)
	}
	return plan, nil
}

type CloudRequirements struct {
	Role                 string   `json:"role"`
	PublicKey            string   `json:"public_key"`
	PublicKeyFingerprint string   `json:"public_key_fingerprint"`
	SupportedOS          []string `json:"supported_os"`
	MinimumVCPU          int      `json:"minimum_vcpu"`
	MinimumRAMMiB        int      `json:"minimum_ram_mib"`
	MinimumDiskGiB       int      `json:"minimum_disk_gib"`
	RequiredInput        []string `json:"required_input"`
	TrustWarning         string   `json:"trust_warning"`
}

type InitSystemResult struct {
	Created      bool                 `json:"created"`
	Resumed      bool                 `json:"resumed"`
	System       systemstate.System   `json:"system"`
	Trust        operatortrust.Bundle `json:"trust"`
	Task         workflow.Task        `json:"task"`
	Cloud        CloudRequirements    `json:"cloud"`
	AuditLog     string               `json:"audit_log"`
	KeyExpiresAt time.Time            `json:"bootstrap_key_expires_at"`
	KeyExpired   bool                 `json:"bootstrap_key_expired"`
}

func (application *Application) InitSystem(operation context.Context, request InitSystemRequest, observer Observer) (InitSystemResult, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return InitSystemResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if operation == nil {
		return InitSystemResult{}, appError("cancelled", 8, "System initialization was cancelled.", "Run the same command to resume.", nil)
	}
	if err := operation.Err(); err != nil {
		return InitSystemResult{}, appError("cancelled", 8, "System initialization was cancelled.", "Run the same command to resume.", err)
	}
	if request.ControlName == "" {
		request.ControlName = "control-1"
	}
	if !controlnodes.ValidName(request.ControlName) {
		return InitSystemResult{}, invalidInitialControlName()
	}
	notify(observer, "system", "running", "creating or resuming private system state")
	system, created, err := application.systems.CreateOrGet(request.Name)
	if err != nil {
		return InitSystemResult{}, appError("system_invalid", 3, "The system name or registry is invalid.", "Use a unique name containing letters, digits, dot, underscore or hyphen.", err)
	}
	var result InitSystemResult
	result.Created = created
	err = application.store.WithLock(filepath.Join("systems", system.ID, "initialize.lock"), func() error {
		if err := operation.Err(); err != nil {
			return err
		}
		current, err := application.systems.Get(system.ID)
		if err != nil {
			return err
		}
		if current.Bootstrap.State != systemstate.BootstrapNotStarted && current.Bootstrap.State != systemstate.BootstrapKeyPrepared {
			return appError("system_bootstrap_advanced", 6, "The existing system has advanced beyond local initialization.", "Use flow system select and flow control status to resume its recorded Control workflow.", nil)
		}
		var systemStore *localstate.Store
		if current.Trust.Generation > 0 || current.Bootstrap.BootstrapKeyFingerprint != "" {
			systemStore, err = application.openSystemStore(current.ID)
		} else {
			systemStore, err = application.ensureSystemStore(current.ID)
		}
		if err != nil {
			return err
		}
		notify(observer, "trust", "running", "verifying five separated offline trust roots")
		trust, key, task, err := application.prepareInitialIdentity(operation, current, systemStore, request, observer)
		if err != nil {
			return err
		}
		expiresAt := key.CreatedAt.Add(defaultBootstrapLifetime)
		expectedTrust := initialTrustMetadata(trust, current.Trust.Generation)
		expectedBootstrap := systemstate.BootstrapMetadata{
			State:                   systemstate.BootstrapKeyPrepared,
			BootstrapKeyFingerprint: key.Fingerprint,
			ExpiresAt:               &expiresAt,
		}
		if current.Trust != expectedTrust || !equalBootstrap(current.Bootstrap, expectedBootstrap) {
			if current.Bootstrap.State != systemstate.BootstrapNotStarted && current.Bootstrap.State != systemstate.BootstrapKeyPrepared {
				return errors.New("system bootstrap has advanced and cannot be reinitialized")
			}
			current, err = application.systems.Update(current.ID, current.Revision, func(candidate *systemstate.System) error {
				candidate.Trust = expectedTrust
				candidate.Bootstrap = expectedBootstrap
				return nil
			})
			if err != nil {
				return err
			}
		}
		auditLog, _ := application.store.Path("logs/audit.jsonl")
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "system.init", "outcome": "success",
			"fields": map[string]any{"system_id": current.ID, "control": request.ControlName, "task_id": task.ID, "resumed": !created},
		}); err != nil {
			return fmt.Errorf("commit system initialization audit: %w", err)
		}
		result = InitSystemResult{
			Created: created, Resumed: !created, System: current, Trust: trust, Task: task,
			Cloud: CloudRequirements{
				Role: "control", PublicKey: key.PublicKey, PublicKeyFingerprint: key.Fingerprint,
				SupportedOS: []string{"Debian 13 amd64", "Ubuntu 24.04 LTS amd64"},
				MinimumVCPU: 2, MinimumRAMMiB: 4096, MinimumDiskGiB: 40,
				RequiredInput: []string{"reachable IP or hostname", "non-root SSH user", "operating system", "Ed25519 host public key from the provider console"},
				TrustWarning:  "The injected public key authenticates the operator to the VM; it does not authenticate the VM. Confirm its Ed25519 host key independently before connectivity checks.",
			},
			AuditLog: auditLog, KeyExpiresAt: expiresAt, KeyExpired: !application.now().UTC().Before(expiresAt),
		}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return InitSystemResult{}, failure
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return InitSystemResult{}, appError("cancelled", 8, "System initialization stopped at a resumable checkpoint.", "Run the same command to resume; do not generate another bootstrap key.", err)
		}
		return InitSystemResult{}, appError("system_init", 3, "System initialization could not commit a safe checkpoint.", "Inspect the private audit log and run the same command to resume.", err)
	}
	notify(observer, "system", "complete", "offline trust and first-control bootstrap are ready")
	return result, nil
}

func equalBootstrap(left, right systemstate.BootstrapMetadata) bool {
	if left.State != right.State || left.ControlNodeID != right.ControlNodeID ||
		left.BootstrapKeyFingerprint != right.BootstrapKeyFingerprint || left.HostKeyFingerprint != right.HostKeyFingerprint ||
		left.BootstrapKeyRevoked != right.BootstrapKeyRevoked || left.FailureCode != right.FailureCode {
		return false
	}
	if left.ExpiresAt == nil || right.ExpiresAt == nil {
		return left.ExpiresAt == nil && right.ExpiresAt == nil
	}
	return left.ExpiresAt.Equal(*right.ExpiresAt)
}

func (application *Application) ensureSystemStore(id string) (*localstate.Store, error) {
	directory, err := application.store.EnsureDir(filepath.Join("systems", id))
	if err != nil {
		return nil, err
	}
	return localstate.Open(directory)
}

func (application *Application) openSystemStore(id string) (*localstate.Store, error) {
	directory, err := application.store.Path(filepath.Join("systems", id))
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != localstate.DirMode {
		return nil, localstate.ErrInvalidPath
	}
	return localstate.Open(directory)
}

func notify(observer Observer, phase, status, detail string) {
	if observer != nil {
		observer.OnEvent(Event{Phase: phase, Status: status, Detail: detail})
	}
}

func appError(code string, exitCode int, text, next string, cause error) *Error {
	return &Error{Code: code, ExitCode: exitCode, SafeText: text, Next: next, Cause: cause}
}

func AsError(err error) *Error {
	var failure *Error
	if errors.As(err, &failure) {
		return failure
	}
	return appError("internal", 1, "Dynamicflow encountered an internal error.", "Inspect the private log and retry.", err)
}

type Capability struct {
	Action  string `json:"action"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type DashboardSnapshot struct {
	RegistryRevision uint64                `json:"registry_revision"`
	ActiveSystemID   string                `json:"active_system_id,omitempty"`
	Systems          []systemstate.System  `json:"systems"`
	Controls         []controlnodes.Record `json:"controls"`
	Tasks            []workflow.Task       `json:"tasks"`
	Topology         *topology.Topology    `json:"topology,omitempty"`
	Bootstrap        *BootstrapGuide       `json:"bootstrap,omitempty"`
	Capabilities     []Capability          `json:"capabilities"`
	ObservedAt       time.Time             `json:"observed_at"`
}

type BootstrapGuide struct {
	SystemID             string         `json:"system_id"`
	ControlName          string         `json:"control_name"`
	TaskID               string         `json:"task_id"`
	Phase                workflow.Phase `json:"phase"`
	PublicKey            string         `json:"public_key"`
	PublicKeyFingerprint string         `json:"public_key_fingerprint"`
	ExpiresAt            time.Time      `json:"expires_at"`
	Expired              bool           `json:"expired"`
	HostTrustRequired    bool           `json:"host_trust_required"`
}

func (application *Application) Dashboard(operation context.Context) (DashboardSnapshot, error) {
	if operation == nil || operation.Err() != nil {
		return DashboardSnapshot{}, appError("cancelled", 8, "Dashboard refresh was cancelled.", "Retry the refresh.", nil)
	}
	registry, err := application.systems.Snapshot()
	if err != nil {
		return DashboardSnapshot{}, appError("system_state", 3, "System state is invalid.", "Recover the private registry before continuing.", err)
	}
	snapshot := DashboardSnapshot{
		RegistryRevision: registry.Revision, ActiveSystemID: registry.ActiveSystemID,
		Systems: registry.Systems, Controls: []controlnodes.Record{}, Tasks: []workflow.Task{}, ObservedAt: application.now().UTC(),
	}
	if registry.ActiveSystemID != "" {
		// Use the selection and metadata from this exact registry snapshot. A
		// second Active() read can observe a concurrent switch and mix one
		// system's tasks/keys with another system's Control and expiry.
		var active systemstate.System
		for _, candidate := range registry.Systems {
			if candidate.ID == registry.ActiveSystemID {
				active = candidate
				break
			}
		}
		store, err := application.openSystemStore(registry.ActiveSystemID)
		if errors.Is(err, os.ErrNotExist) && active.Trust.Generation == 0 && active.Bootstrap.State == systemstate.BootstrapNotStarted {
			snapshot.Capabilities = dashboardCapabilities(snapshot)
			return snapshot, nil
		}
		if err != nil {
			return DashboardSnapshot{}, appError("system_state", 3, "The active system directory is unavailable.", "Repair its owner and mode.", err)
		}
		snapshot.Tasks, err = workflow.NewManager(store, workflow.WithClock(application.now)).List()
		if err != nil {
			return DashboardSnapshot{}, appError("workflow_state", 3, "Workflow state is invalid.", "Recover the affected task before continuing.", err)
		}
		keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now), sshkeys.WithControlScope())
		controls, managerErr := controlnodes.NewManager(application.store, keys, controlnodes.WithClock(application.now))
		if managerErr != nil {
			return DashboardSnapshot{}, appError("control_state", 3, "Control state is invalid.", "Repair the private Control registry.", managerErr)
		}
		snapshot.Controls, err = controls.List(active.ID)
		if err != nil {
			return DashboardSnapshot{}, appError("control_state", 3, "Control state is invalid.", "Repair the private Control registry.", err)
		}
		document, topologyErr := topology.NewStore(store).Load()
		if topologyErr == nil {
			snapshot.Topology = &document
		} else if !errors.Is(topologyErr, topology.ErrNotFound) {
			return DashboardSnapshot{}, appError("topology_state", 3, "The system topology is invalid.", "Repair its pinned routes before continuing.", topologyErr)
		}
		for _, task := range snapshot.Tasks {
			if task.SystemID != active.ID {
				return DashboardSnapshot{}, appError("workflow_state", 5, "A workflow belongs to a different system.", "Recover the task's original system binding.", nil)
			}
			if task.Kind != workflow.ControlBootstrap || task.Phase == workflow.PhaseReady || task.Phase == workflow.PhaseRevoked {
				continue
			}
			key, keyErr := keys.Get(task.Key.Scope, task.Key.Name)
			if keyErr != nil || key.Name != task.Resource.Name || key.Generation != task.Key.Generation || key.Fingerprint != task.Key.Fingerprint {
				return DashboardSnapshot{}, appError("bootstrap_identity", 5, "The persisted Control bootstrap identity does not match its task.", "Do not generate a replacement; recover the owner-local key generation and task binding.", keyErr)
			}
			if active.Bootstrap.State == systemstate.BootstrapNotStarted && task.Phase == workflow.PhaseAwaitingCloudVM {
				// The journal commits before the registry's final initialization
				// checkpoint. Resume is valid, but this snapshot cannot yet offer
				// a committed bootstrap identity or cloud handoff.
				continue
			}
			if active.Bootstrap.BootstrapKeyFingerprint != key.Fingerprint || active.Bootstrap.ExpiresAt == nil {
				return DashboardSnapshot{}, appError("bootstrap_identity", 5, "The bootstrap identity differs from the system registry.", "Recover the original system binding before continuing.", nil)
			}
			snapshot.Bootstrap = &BootstrapGuide{
				SystemID: active.ID, ControlName: task.Resource.Name, TaskID: task.ID, Phase: task.Phase,
				PublicKey: key.PublicKey, PublicKeyFingerprint: key.Fingerprint, ExpiresAt: *active.Bootstrap.ExpiresAt,
				Expired: !snapshot.ObservedAt.Before(*active.Bootstrap.ExpiresAt), HostTrustRequired: active.Bootstrap.HostKeyFingerprint == "",
			}
			break
		}
	}
	snapshot.Capabilities = dashboardCapabilities(snapshot)
	return snapshot, nil
}

func dashboardCapabilities(snapshot DashboardSnapshot) []Capability {
	return append(capabilities(snapshot.Systems, snapshot.ActiveSystemID), controlInstallCapability(snapshot),
		controlRemoteCapability(snapshot, "control.apply"), controlRemoteCapability(snapshot, "control.attest"))
}

func controlRemoteCapability(snapshot DashboardSnapshot, action string) Capability {
	capability := Capability{Action: action, Reason: "control_install_required"}
	if action != "control.apply" && action != "control.attest" {
		return capability
	}
	provisioning := false
	for _, system := range snapshot.Systems {
		if system.ID == snapshot.ActiveSystemID {
			provisioning = system.Bootstrap.State == systemstate.BootstrapProvisioning
		}
	}
	if !provisioning || snapshot.Topology == nil || snapshot.Topology.Control == nil || snapshot.Topology.ControlReady {
		return capability
	}
	var control *controlnodes.Record
	for index := range snapshot.Controls {
		candidate := &snapshot.Controls[index]
		if candidate.SystemID != snapshot.ActiveSystemID || candidate.Lifecycle == controlnodes.LifecycleRevoked {
			continue
		}
		if control != nil {
			capability.Reason = "control_ambiguous"
			return capability
		}
		control = candidate
	}
	if control == nil || control.Lifecycle != controlnodes.LifecycleInstalling || control.Access.Phase != controlnodes.AccessStaged {
		return capability
	}
	expected := topology.Control{Name: control.Name, Host: control.Host, SSHPort: control.Port, SSHUser: control.SSHUser,
		Trust: topology.TrustPinned, HostKeyFingerprint: control.HostFingerprint}
	if *snapshot.Topology.Control != expected {
		capability.Reason = "topology_inconsistent"
		return capability
	}
	var task *workflow.Task
	for index := range snapshot.Tasks {
		candidate := &snapshot.Tasks[index]
		if candidate.SystemID != snapshot.ActiveSystemID || candidate.Kind != workflow.ControlBootstrap || candidate.Resource.Name != control.Name {
			continue
		}
		if task != nil {
			capability.Reason = "workflow_ambiguous"
			return capability
		}
		task = candidate
	}
	if task == nil {
		capability.Reason = "workflow_required"
		return capability
	}
	phase := task.Phase
	if phase == workflow.PhaseFailedSafe {
		code := "control_install"
		if action == "control.attest" {
			code = "control_attestation"
		}
		if task.Failure == nil || task.Failure.Code != code {
			capability.Reason = "failed_safe"
			return capability
		}
		phase = task.ResumePhase
	}
	if action == "control.apply" && phase == workflow.PhaseInstalling || action == "control.attest" && phase == workflow.PhaseAttesting {
		capability.Allowed, capability.Reason = true, ""
	}
	return capability
}

func controlInstallCapability(snapshot DashboardSnapshot) Capability {
	capability := Capability{Action: "control.install", Reason: "system_required"}
	if snapshot.ActiveSystemID == "" {
		return capability
	}
	var control *controlnodes.Record
	for index := range snapshot.Controls {
		candidate := &snapshot.Controls[index]
		if candidate.SystemID != snapshot.ActiveSystemID || candidate.Lifecycle == controlnodes.LifecycleRevoked {
			continue
		}
		if control != nil {
			capability.Reason = "control_ambiguous"
			return capability
		}
		control = candidate
	}
	if control == nil {
		capability.Reason = "control_required"
		return capability
	}
	var task *workflow.Task
	for index := range snapshot.Tasks {
		candidate := &snapshot.Tasks[index]
		if candidate.Kind == workflow.ControlBootstrap && candidate.SystemID == snapshot.ActiveSystemID && candidate.Resource.Name == control.Name {
			task = candidate
			break
		}
	}
	if task == nil {
		capability.Reason = "workflow_required"
		return capability
	}
	if task.Phase == workflow.PhaseFailedSafe {
		capability.Reason = "failed_safe"
		return capability
	}
	if control.Lifecycle == controlnodes.LifecycleConnectivityVerified && task.Phase == workflow.PhaseConnectivityOK &&
		control.Access.Phase == controlnodes.AccessBootstrap {
		capability.Allowed = true
		capability.Reason = ""
		return capability
	}
	if (control.Lifecycle == controlnodes.LifecycleConnectivityVerified || control.Lifecycle == controlnodes.LifecycleInstalling) &&
		(task.Phase == workflow.PhaseConnectivityOK || task.Phase == workflow.PhaseInstalling) &&
		(control.Access.Phase == controlnodes.AccessBootstrap || control.Access.Phase == controlnodes.AccessStaged) {
		capability.Allowed = true
		capability.Reason = ""
		return capability
	}
	switch control.Lifecycle {
	case controlnodes.LifecycleBound:
		capability.Reason = "connectivity_required"
	case controlnodes.LifecycleReady:
		capability.Reason = "control_already_ready"
	default:
		capability.Reason = "checkpoint_inconsistent"
	}
	return capability
}

func capabilities(systems []systemstate.System, activeID string) []Capability {
	result := []Capability{{Action: "system.init", Allowed: true}}
	var active *systemstate.System
	for index := range systems {
		if systems[index].ID == activeID {
			active = &systems[index]
			break
		}
	}
	if active == nil {
		return append(result,
			Capability{Action: "control.bind", Allowed: false, Reason: "system_required"},
			Capability{Action: "control.check", Allowed: false, Reason: "system_required"},
			Capability{Action: "serving.create", Allowed: false, Reason: "control_required"},
			Capability{Action: "instance.create", Allowed: false, Reason: "control_required"},
		)
	}
	controlReady := active.Bootstrap.State == systemstate.BootstrapControlActive && active.Status == systemstate.StatusActive
	bindAllowed := active.Bootstrap.State == systemstate.BootstrapKeyPrepared
	bindReason := ""
	if !bindAllowed {
		bindReason = "control_already_bound"
	}
	checkAllowed := active.Bootstrap.State == systemstate.BootstrapHostBound
	checkReason := ""
	if !checkAllowed {
		if active.Bootstrap.State == systemstate.BootstrapKeyPrepared {
			checkReason = "hostkey_required"
		} else {
			checkReason = "connectivity_already_verified"
		}
	}
	result = append(result,
		Capability{Action: "control.bind", Allowed: bindAllowed, Reason: bindReason},
		Capability{Action: "control.check", Allowed: checkAllowed, Reason: checkReason},
	)
	reason := ""
	if !controlReady {
		reason = "control_required"
	}
	result = append(result,
		Capability{Action: "serving.create", Allowed: controlReady, Reason: reason},
		Capability{Action: "instance.create", Allowed: controlReady, Reason: reason},
		Capability{Action: "instance.ssh", Allowed: controlReady, Reason: reason},
	)
	return result
}

func IsStateAbsent(err error) bool { return errors.Is(err, os.ErrNotExist) }
