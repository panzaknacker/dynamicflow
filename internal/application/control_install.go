package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

const initialControlPolicyLifetime = 30 * 24 * time.Hour

// PrepareControlInstallRequest selects the already pinned first Control. The
// preparation operation is local-only: it creates the long-lived owner-local
// management identity and a signed, route-free installation envelope.
type PrepareControlInstallRequest struct {
	Meta RequestMeta `json:"meta"`
	Name string      `json:"name"`
}

// PrepareControlInstallPlan is deliberately public-only. A missing management
// identity is reported as a future local key-generation change; the plan never
// creates that identity or an installation envelope.
type PrepareControlInstallPlan struct {
	Plan                 bool     `json:"plan"`
	SystemID             string   `json:"system_id"`
	ControlName          string   `json:"control_name"`
	CurrentLifecycle     string   `json:"current_lifecycle"`
	CurrentTaskPhase     string   `json:"current_task_phase"`
	ManagementUser       string   `json:"management_user"`
	PolicyGeneration     uint64   `json:"policy_generation"`
	RouteCount           int      `json:"route_count"`
	Changes              []string `json:"changes"`
	NetworkConnections   int      `json:"network_connections"`
	GeneratesPrivateKeys bool     `json:"generates_private_keys"`
	AlreadyPrepared      bool     `json:"already_prepared"`
}

// PrepareControlInstallResult contains only public management-key metadata and
// content digests. Private paths and envelope bytes stay behind the operation
// boundary used later by the fixed remote installer.
type PrepareControlInstallResult struct {
	Prepared            bool                      `json:"prepared"`
	Resumed             bool                      `json:"resumed"`
	System              systemstate.System        `json:"system"`
	Control             controlnodes.Record       `json:"control"`
	Task                workflow.Task             `json:"task"`
	ManagementIdentity  controlnodes.AccessKeyRef `json:"management_identity"`
	ManagementPublicKey string                    `json:"management_public_key"`
	ManagementUser      string                    `json:"management_user"`
	PolicyGeneration    uint64                    `json:"policy_generation"`
	PolicyKeyID         string                    `json:"policy_key_id"`
	EnvelopeDigest      string                    `json:"envelope_digest"`
	NetworkConnections  int                       `json:"network_connections"`
	AuditLog            string                    `json:"audit_log"`
}

type preparedControlEnvelope struct {
	envelope controlruntime.InstallEnvelope
	bytes    []byte
	digest   string
	key      sshkeys.Record
}

// PlanControlInstall validates the local bootstrap, policy root and any
// existing checkpoint without generating a key, signing or opening a socket.
func (application *Application) PlanControlInstall(operation context.Context, request PrepareControlInstallRequest) (PrepareControlInstallPlan, error) {
	if err := operation.Err(); err != nil {
		return PrepareControlInstallPlan{}, appError("cancelled", 8, "Control installation planning was cancelled.", "Retry the local plan.", err)
	}
	if err := application.checkSystemExpectation(request.Meta); err != nil {
		return PrepareControlInstallPlan{}, err
	}
	active, store, bindingContext, _, record, err := application.controlInstallContext(request.Name)
	if err != nil {
		return PrepareControlInstallPlan{}, err
	}
	if err := validateSystemExpectation(request.Meta, active.ID); err != nil {
		return PrepareControlInstallPlan{}, err
	}
	if err := validateControlInstallCheckpoint(record, bindingContext.task); err != nil {
		return PrepareControlInstallPlan{}, err
	}
	if bootstrapExpired(active, application.now()) {
		return PrepareControlInstallPlan{}, expiredBootstrapError()
	}

	plan := PrepareControlInstallPlan{
		Plan: true, SystemID: active.ID, ControlName: record.Name,
		CurrentLifecycle: string(record.Lifecycle), CurrentTaskPhase: string(bindingContext.task.Phase),
		ManagementUser: controlnodes.ManagementAccessUser, PolicyGeneration: 1,
		RouteCount: 0, NetworkConnections: 0,
	}
	prepared, readErr := application.readPreparedControlEnvelope(store, active, record)
	switch {
	case readErr == nil:
		if err := preparedEnvelopeMatchesRecord(prepared, record); err != nil {
			return PrepareControlInstallPlan{}, err
		}
		plan.AlreadyPrepared = record.Access.Phase == controlnodes.AccessStaged &&
			record.Lifecycle == controlnodes.LifecycleInstalling &&
			bindingContext.task.Phase == workflow.PhaseInstalling
		if !plan.AlreadyPrepared {
			plan.Changes = controlInstallReconciliationChanges(record, bindingContext.task)
		}
	case errors.Is(readErr, os.ErrNotExist):
		key, keyErr := bindingContext.keys.Get(sshkeys.Control, record.Name)
		switch {
		case keyErr == nil:
			if key.Status != sshkeys.ActiveStatus {
				return PrepareControlInstallPlan{}, appError("control_management_identity", 5, "The staged Control management identity is not active.", "Recover or explicitly replace the owner-local management identity.", sshkeys.ErrRevoked)
			}
		case errors.Is(keyErr, sshkeys.ErrNotFound):
			plan.GeneratesPrivateKeys = true
		default:
			return PrepareControlInstallPlan{}, appError("control_management_identity", 5, "The owner-local Control management identity is invalid.", "Repair the private system key store before continuing.", keyErr)
		}
		if record.Access.Phase != controlnodes.AccessBootstrap {
			return PrepareControlInstallPlan{}, appError("control_install_checkpoint", 6, "Control access is staged but its signed installation envelope is missing.", "Recover the exact envelope; never silently authorize a replacement identity.", os.ErrNotExist)
		}
		plan.Changes = []string{
			"create or reuse the separate owner-local Control management identity",
			"sign and persist a generation-1 route-free Control policy envelope",
			"stage management access while retaining the bootstrap identity",
			"advance Control, workflow and system to the resumable installing checkpoint",
		}
	default:
		return PrepareControlInstallPlan{}, appError("control_install_envelope", 5, "The prepared Control installation envelope is invalid.", "Recover its exact canonical signed bytes before continuing.", readErr)
	}
	return plan, nil
}

// PrepareControlInstall commits the public signed input needed by the later
// fixed remote installer. It deliberately performs zero network operations.
func (application *Application) PrepareControlInstall(operation context.Context, request PrepareControlInstallRequest, observer Observer) (PrepareControlInstallResult, error) {
	if application == nil || application.store == nil || application.systems == nil {
		return PrepareControlInstallResult{}, appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	if err := operation.Err(); err != nil {
		return PrepareControlInstallResult{}, appError("cancelled", 8, "Control installation preparation was cancelled.", "Run the same operation to resume.", err)
	}
	active, err := application.systems.Active()
	if err != nil {
		return PrepareControlInstallResult{}, appError("system_required", 3, "No active Dynamicflow system is available.", "Create, bind and verify the first Control VM.", err)
	}
	if err := validateSystemExpectation(request.Meta, active.ID); err != nil {
		return PrepareControlInstallResult{}, err
	}

	var result PrepareControlInstallResult
	operationLock := filepath.Join("systems", active.ID, "operations", "control-bootstrap.lock")
	err = application.store.WithLock(operationLock, func() error {
		if err := operation.Err(); err != nil {
			return err
		}
		current, store, bindingContext, manager, record, err := application.controlInstallContext(request.Name)
		if err != nil {
			return err
		}
		if current.ID != active.ID {
			return errors.New("active system changed during Control installation preparation")
		}
		if err := validateControlInstallCheckpoint(record, bindingContext.task); err != nil {
			return err
		}
		if bootstrapExpired(current, application.now()) {
			return expiredBootstrapError()
		}

		notify(observer, "control_management_key", "running", "creating or reopening the separate owner-local Control management identity")
		key, keyCreated, err := ensureControlManagementKey(operation, bindingContext.keys, record.Name)
		if err != nil {
			return err
		}
		prepared, envelopeCreated, err := application.ensurePreparedControlEnvelope(store, current, record, key)
		if err != nil {
			return err
		}
		if err := preparedEnvelopeMatchesRecord(prepared, record); err != nil && record.Access.Phase != controlnodes.AccessBootstrap {
			return err
		}

		notify(observer, "control_policy", "running", "staging the signed route-free management policy")
		reference := controlnodes.AccessKeyRef{
			Scope: key.Scope, Name: key.Name, Generation: key.Generation, Fingerprint: key.Fingerprint,
		}
		record, staged, err := manager.Stage(current.ID, record.Name, record.Revision, reference, controlnodes.ManagementAccessUser)
		if err != nil {
			return err
		}
		if record.Lifecycle == controlnodes.LifecycleConnectivityVerified {
			record, err = manager.Transition(current.ID, record.Name, record.Revision, controlnodes.LifecycleInstalling)
			if err != nil {
				return err
			}
		}
		task := bindingContext.task
		if task.Phase == workflow.PhaseConnectivityOK {
			task, err = bindingContext.workflows.Advance(task.ID, task.Revision, workflow.PhaseInstalling)
			if err != nil {
				return err
			}
		}
		current, err = application.reconcileControlProvisioningSystem(current, record)
		if err != nil {
			return err
		}
		auditLog, _ := application.store.Path("logs/audit.jsonl")
		if err := application.store.AppendJSONL("logs/audit.jsonl", map[string]any{
			"time": application.now().UTC(), "action": "control.install.prepare", "outcome": "success",
			"fields": map[string]any{
				"system_id": current.ID, "control": record.Name, "task_id": task.ID,
				"management_fingerprint": key.Fingerprint, "management_generation": key.Generation,
				"policy_generation": prepared.envelope.Policy.Policy.Generation,
				"policy_key_id":     prepared.envelope.ControlPolicyKeyID, "envelope_digest": prepared.digest,
				"key_created": keyCreated, "envelope_created": envelopeCreated, "staged": staged,
				"routes": 0, "network_connections": 0,
			},
		}); err != nil {
			return fmt.Errorf("commit Control installation preparation audit: %w", err)
		}
		result = PrepareControlInstallResult{
			Prepared: true, Resumed: !(keyCreated || envelopeCreated || staged),
			System: current, Control: record, Task: task, ManagementIdentity: reference,
			ManagementPublicKey: canonicalSSHPublicKey(key.PublicKey), ManagementUser: controlnodes.ManagementAccessUser,
			PolicyGeneration: prepared.envelope.Policy.Policy.Generation,
			PolicyKeyID:      prepared.envelope.ControlPolicyKeyID, EnvelopeDigest: prepared.digest,
			NetworkConnections: 0, AuditLog: auditLog,
		}
		return nil
	})
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			return PrepareControlInstallResult{}, failure
		}
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return PrepareControlInstallResult{}, appError("cancelled", 8, "Control installation preparation stopped at a resumable checkpoint.", "Run the same operation to resume.", err)
		case errors.Is(err, controlnodes.ErrRevisionConflict), errors.Is(err, workflow.ErrConflict):
			return PrepareControlInstallResult{}, appError("control_conflict", 6, "Control installation state changed concurrently.", "Refresh status and retry the local preparation.", err)
		default:
			return PrepareControlInstallResult{}, appError("control_install_prepare", 5, "The signed Control installation checkpoint could not be prepared safely.", "Inspect private task/audit state and repeat the operation without replacing keys.", err)
		}
	}
	notify(observer, "control_policy", "complete", "the route-free signed Control installation envelope is ready; no network connection was made")
	return result, nil
}

func (application *Application) controlInstallContext(name string) (systemstate.System, *localstate.Store, controlBindingContext, *controlnodes.Manager, controlnodes.Record, error) {
	return application.controlInstallContextWithResume(name, false)
}

func (application *Application) controlInstallContextWithResume(name string, allowFailedSafe bool) (systemstate.System, *localstate.Store, controlBindingContext, *controlnodes.Manager, controlnodes.Record, error) {
	active, err := application.systems.Active()
	if err != nil {
		return systemstate.System{}, nil, controlBindingContext{}, nil, controlnodes.Record{},
			appError("system_required", 3, "No active Dynamicflow system is available.", "Create, bind and verify the first Control VM.", err)
	}
	store, err := application.openSystemStore(active.ID)
	if err != nil {
		return systemstate.System{}, nil, controlBindingContext{}, nil, controlnodes.Record{},
			appError("system_state", 3, "The active system state is unavailable.", "Repair its private owner-local directory.", err)
	}
	bindingContext, err := application.loadControlBindingContext(store, active, name, allowFailedSafe)
	if err != nil {
		return systemstate.System{}, nil, controlBindingContext{}, nil, controlnodes.Record{}, err
	}
	record, manager, err := application.loadControlRecord(bindingContext)
	if err != nil {
		return systemstate.System{}, nil, controlBindingContext{}, nil, controlnodes.Record{}, err
	}
	return active, store, bindingContext, manager, record, nil
}

func validateControlInstallCheckpoint(record controlnodes.Record, task workflow.Task) error {
	if record.Lifecycle == controlnodes.LifecycleRevoked || task.Phase == workflow.PhaseRevoked {
		return appError("control_revoked", 4, "The first Control bootstrap or node is revoked.", "Start an explicit replacement workflow.", nil)
	}
	if task.Phase == workflow.PhaseFailedSafe {
		next := "Recover the recorded fail-safe checkpoint before preparing installation."
		if task.Failure != nil && task.Failure.Next != "" {
			next = task.Failure.Next
		}
		return appError("control_failed_safe", 6, "The first-Control task is in a fail-closed state.", next, nil)
	}
	valid := false
	switch record.Lifecycle {
	case controlnodes.LifecycleConnectivityVerified:
		valid = task.Phase == workflow.PhaseConnectivityOK &&
			(record.Access.Phase == controlnodes.AccessBootstrap || record.Access.Phase == controlnodes.AccessStaged)
	case controlnodes.LifecycleInstalling:
		valid = (task.Phase == workflow.PhaseConnectivityOK || task.Phase == workflow.PhaseInstalling) &&
			record.Access.Phase == controlnodes.AccessStaged
	}
	if !valid {
		return appError("control_install_checkpoint", 6, "Control lifecycle, access identity and persistent task are not at a safe installation checkpoint.", "Finish the earlier trust gate or recover the exact recorded checkpoint; do not open a fallback.", nil)
	}
	return nil
}

func ensureControlManagementKey(operation context.Context, keys *sshkeys.Manager, name string) (sshkeys.Record, bool, error) {
	key, err := keys.Create(operation, sshkeys.Control, name)
	created := err == nil
	if errors.Is(err, sshkeys.ErrAlreadyExists) {
		key, err = keys.Get(sshkeys.Control, name)
	}
	if err != nil {
		return sshkeys.Record{}, false, fmt.Errorf("ensure owner-local Control management identity: %w", err)
	}
	if key.Status != sshkeys.ActiveStatus || key.Scope != sshkeys.Control || key.Name != name {
		return sshkeys.Record{}, false, errors.New("Control management identity is not active")
	}
	return key, created, nil
}

func (application *Application) ensurePreparedControlEnvelope(store *localstate.Store, system systemstate.System, record controlnodes.Record, key sshkeys.Record) (preparedControlEnvelope, bool, error) {
	prepared, err := application.readPreparedControlEnvelope(store, system, record)
	if err == nil {
		if err := preparedEnvelopeMatchesKey(prepared, key); err != nil {
			return preparedControlEnvelope{}, false, err
		}
		return prepared, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return preparedControlEnvelope{}, false, err
	}
	if record.Access.Phase != controlnodes.AccessBootstrap {
		return preparedControlEnvelope{}, false, errors.New("staged Control access has no recoverable signed envelope")
	}
	issuedAt := application.now().UTC().Truncate(time.Second)
	policy := controlpolicy.Policy{
		SchemaVersion: controlpolicy.SchemaVersion, SystemID: system.ID, ControlName: record.Name,
		Generation: 1, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(initialControlPolicyLifetime),
		ManagementKeys: []controlpolicy.ManagementKey{{
			Name: key.Name, Generation: key.Generation, State: controlpolicy.KeyActive,
			PublicKey: canonicalSSHPublicKey(key.PublicKey), Fingerprint: key.Fingerprint,
		}},
		Routes: []controlpolicy.Route{},
	}
	policy = controlpolicy.SortCanonical(policy)
	signed, err := operatortrust.SignControlPolicy(store, policy)
	if err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("sign initial Control policy: %w", err)
	}
	publicPEM, keyID, err := operatortrust.ControlPolicyPublic(store)
	if err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("load Control-policy public root: %w", err)
	}
	if keyID != system.Trust.ControlPolicyKeyID {
		return preparedControlEnvelope{}, false, errors.New("Control-policy root differs from system trust metadata")
	}
	envelope, err := controlruntime.NewEnvelope(system.ID, record.Name, publicPEM, signed)
	if err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("construct Control installation envelope: %w", err)
	}
	encoded, err := controlruntime.MarshalCanonical(envelope)
	if err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("encode Control installation envelope: %w", err)
	}
	rendered, err := controlruntime.Render(envelope, issuedAt, system.ID, record.Name, 1, controlruntime.DefaultStateRoot)
	if err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("verify Control installation envelope: %w", err)
	}
	if err := rendered.ValidateNoPrivateMaterial(); err != nil {
		return preparedControlEnvelope{}, false, err
	}
	if err := store.WriteFile(controlEnvelopeRelative(record.Name), encoded); err != nil {
		return preparedControlEnvelope{}, false, fmt.Errorf("persist Control installation envelope: %w", err)
	}
	return preparedControlEnvelope{envelope: envelope, bytes: encoded, digest: contentDigest(encoded), key: key}, true, nil
}

func (application *Application) readPreparedControlEnvelope(store *localstate.Store, system systemstate.System, record controlnodes.Record) (preparedControlEnvelope, error) {
	encoded, err := store.ReadFile(controlEnvelopeRelative(record.Name))
	if err != nil {
		return preparedControlEnvelope{}, err
	}
	envelope, err := controlruntime.ParseCanonical(encoded)
	if err != nil {
		return preparedControlEnvelope{}, err
	}
	if err := controlruntime.VerifyEnvelope(envelope, application.now().UTC().Truncate(time.Second), system.ID, record.Name, 1); err != nil {
		return preparedControlEnvelope{}, err
	}
	if envelope.ControlPolicyKeyID != system.Trust.ControlPolicyKeyID {
		return preparedControlEnvelope{}, errors.New("Control installation envelope uses a different policy root")
	}
	if len(envelope.Policy.Policy.ManagementKeys) != 1 {
		return preparedControlEnvelope{}, errors.New("initial Control installation policy must contain exactly one management key")
	}
	policyKey := envelope.Policy.Policy.ManagementKeys[0]
	key, err := sshkeysRecordFromPolicy(policyKey)
	if err != nil {
		return preparedControlEnvelope{}, err
	}
	return preparedControlEnvelope{
		envelope: envelope, bytes: append([]byte(nil), encoded...), digest: contentDigest(encoded), key: key,
	}, nil
}

func sshkeysRecordFromPolicy(key controlpolicy.ManagementKey) (sshkeys.Record, error) {
	if key.State != controlpolicy.KeyActive {
		return sshkeys.Record{}, errors.New("initial Control management key is not active in policy")
	}
	normalized, fingerprint, err := sshkeys.ValidateEd25519PublicKey(key.PublicKey)
	if err != nil || fingerprint != key.Fingerprint || canonicalSSHPublicKey(normalized) != key.PublicKey {
		return sshkeys.Record{}, errors.New("invalid Control management key in policy")
	}
	return sshkeys.Record{
		Scope: sshkeys.Control, Name: key.Name, Generation: key.Generation,
		Status: sshkeys.ActiveStatus, PublicKey: key.PublicKey, Fingerprint: key.Fingerprint,
	}, nil
}

func preparedEnvelopeMatchesKey(prepared preparedControlEnvelope, key sshkeys.Record) error {
	if prepared.key.Scope != key.Scope || prepared.key.Name != key.Name ||
		prepared.key.Generation != key.Generation || prepared.key.Fingerprint != key.Fingerprint ||
		prepared.key.PublicKey != canonicalSSHPublicKey(key.PublicKey) {
		return errors.New("prepared Control envelope does not match the exact owner-local management identity")
	}
	return nil
}

func preparedEnvelopeMatchesRecord(prepared preparedControlEnvelope, record controlnodes.Record) error {
	if record.Access.Phase == controlnodes.AccessBootstrap {
		return nil
	}
	if record.Access.Phase != controlnodes.AccessStaged ||
		record.Access.Pending.Scope != prepared.key.Scope || record.Access.Pending.Name != prepared.key.Name ||
		record.Access.Pending.Generation != prepared.key.Generation || record.Access.Pending.Fingerprint != prepared.key.Fingerprint ||
		record.Access.PendingAccessUser != controlnodes.ManagementAccessUser {
		return errors.New("prepared Control envelope differs from staged management access")
	}
	return nil
}

func controlInstallReconciliationChanges(record controlnodes.Record, task workflow.Task) []string {
	changes := []string{}
	if record.Access.Phase == controlnodes.AccessBootstrap {
		changes = append(changes, "stage the already prepared management identity while retaining bootstrap access")
	}
	if record.Lifecycle == controlnodes.LifecycleConnectivityVerified {
		changes = append(changes, "advance the Control lifecycle to installing")
	}
	if task.Phase == workflow.PhaseConnectivityOK {
		changes = append(changes, "advance the persistent task to installing")
	}
	return changes
}

func (application *Application) reconcileControlProvisioningSystem(system systemstate.System, record controlnodes.Record) (systemstate.System, error) {
	if system.Bootstrap.ControlNodeID != record.Name || system.Bootstrap.HostKeyFingerprint != record.HostFingerprint ||
		system.Bootstrap.BootstrapKeyFingerprint != record.BootstrapKey.Fingerprint {
		return systemstate.System{}, errors.New("system bootstrap binding differs from the Control installation checkpoint")
	}
	switch system.Bootstrap.State {
	case systemstate.BootstrapHostBound:
		return application.systems.Update(system.ID, system.Revision, func(candidate *systemstate.System) error {
			candidate.Bootstrap.State = systemstate.BootstrapProvisioning
			return nil
		})
	case systemstate.BootstrapProvisioning:
		return system, nil
	default:
		return systemstate.System{}, errors.New("system is not at a Control provisioning checkpoint")
	}
}

func canonicalSSHPublicKey(value string) string {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return ""
	}
	return strings.Join(fields[:2], " ")
}

func contentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func controlEnvelopeRelative(name string) string {
	return filepath.Join("control", "install", name, "envelope-g1.json")
}
