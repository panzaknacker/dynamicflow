// package application is the single policy and operation boundary shared by
// dynamicflow's TUI, human CLI and JSON adapters.
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
	Surface       Surface `json:"surface"`
	CorrelationID string  `json:"correlation_id,omitempty"`
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
	if request.ControlName == "" {
		request.ControlName = "control-1"
	}
	plan := InitSystemPlan{
		Plan: true, Name: request.Name, ControlName: request.ControlName, NetworkConnections: 0,
		DisplaysPublicOnly: true, RequiresOOBHostKey: true,
	}
	existing, err := application.systems.GetByName(request.Name)
	switch {
	case err == nil:
		plan.ExistingSystemID = existing.ID
		if existing.Bootstrap.State == systemstate.BootstrapNotStarted {
			plan.Changes = []string{"ensure five separated offline trust roots", "create unique first-Control bootstrap identity", "persist resumable bootstrap task"}
			plan.GeneratesPrivateKeys = true
		} else {
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
	if err := operation.Err(); err != nil {
		return InitSystemResult{}, appError("cancelled", 8, "System initialization was cancelled.", "Run the same command to resume.", err)
	}
	if request.ControlName == "" {
		request.ControlName = "control-1"
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
		systemStore, err := application.ensureSystemStore(current.ID)
		if err != nil {
			return err
		}
		notify(observer, "trust", "running", "verifying five separated offline trust roots")
		trust, err := operatortrust.Ensure(systemStore)
		if err != nil {
			return fmt.Errorf("ensure system trust: %w", err)
		}
		if err := operatortrust.Validate(trust); err != nil {
			return err
		}
		notify(observer, "bootstrap_key", "running", "creating or reopening the unique first-control identity")
		keys := sshkeys.NewManager(systemStore, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now))
		key, keyErr := keys.Create(operation, sshkeys.Bootstrap, request.ControlName)
		if errors.Is(keyErr, sshkeys.ErrAlreadyExists) {
			key, keyErr = keys.Get(sshkeys.Bootstrap, request.ControlName)
		}
		if keyErr != nil {
			return fmt.Errorf("ensure control bootstrap identity: %w", keyErr)
		}
		expiresAt := key.CreatedAt.Add(defaultBootstrapLifetime)
		workflows := workflow.NewManager(systemStore, workflow.WithClock(application.now))
		task, err := workflows.CreateControlBootstrap(current.ID, request.ControlName, workflow.KeyReference{
			Scope: key.Scope, Name: key.Name, Generation: key.Generation, Fingerprint: key.Fingerprint,
		})
		if err != nil {
			return fmt.Errorf("ensure control bootstrap workflow: %w", err)
		}
		expectedTrust := systemstate.TrustMetadata{
			Generation: 1, SystemRootKeyID: trust.SystemRoot, ReleaseKeyID: trust.Release,
			DesiredStateKeyID: trust.DesiredState, ServingAdminKeyID: trust.ServingAdmin,
			ControlPolicyKeyID: trust.ControlPolicy,
		}
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
	if err := operation.Err(); err != nil {
		return DashboardSnapshot{}, appError("cancelled", 8, "Dashboard refresh was cancelled.", "Retry the refresh.", err)
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
		store, err := application.openSystemStore(registry.ActiveSystemID)
		if errors.Is(err, os.ErrNotExist) {
			snapshot.Capabilities = append(capabilities(registry.Systems, registry.ActiveSystemID), controlInstallCapability(snapshot))
			return snapshot, nil
		}
		if err != nil {
			return DashboardSnapshot{}, appError("system_state", 3, "The active system directory is unavailable.", "Repair its owner and mode.", err)
		}
		snapshot.Tasks, err = workflow.NewManager(store, workflow.WithClock(application.now)).List()
		if err != nil {
			return DashboardSnapshot{}, appError("workflow_state", 3, "Workflow state is invalid.", "Recover the affected task before continuing.", err)
		}
		active, activeErr := application.systems.Active()
		if activeErr != nil {
			return DashboardSnapshot{}, appError("system_state", 3, "The active system binding is invalid.", "Recover the private registry.", activeErr)
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
			if task.Kind != workflow.ControlBootstrap || task.Phase == workflow.PhaseReady || task.Phase == workflow.PhaseRevoked {
				continue
			}
			key, keyErr := keys.Get(task.Key.Scope, task.Key.Name)
			if keyErr != nil || key.Generation != task.Key.Generation || key.Fingerprint != task.Key.Fingerprint || active.Bootstrap.ExpiresAt == nil {
				return DashboardSnapshot{}, appError("bootstrap_identity", 5, "The persisted Control bootstrap identity does not match its task.", "Do not generate a replacement; recover the owner-local key generation and task binding.", keyErr)
			}
			snapshot.Bootstrap = &BootstrapGuide{
				SystemID: active.ID, ControlName: task.Resource.Name, TaskID: task.ID, Phase: task.Phase,
				PublicKey: key.PublicKey, PublicKeyFingerprint: key.Fingerprint, ExpiresAt: *active.Bootstrap.ExpiresAt,
				Expired: !application.now().UTC().Before(*active.Bootstrap.ExpiresAt), HostTrustRequired: active.Bootstrap.HostKeyFingerprint == "",
			}
			break
		}
	}
	snapshot.Capabilities = append(capabilities(registry.Systems, registry.ActiveSystemID), controlInstallCapability(snapshot))
	return snapshot, nil
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
