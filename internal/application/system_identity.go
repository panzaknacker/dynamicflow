package application

import (
	"context"
	"errors"
	"fmt"
	"os"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

// prepareInitialIdentity recovers only an uncommitted initialization. Once a
// role or bootstrap identity is committed, missing files are data loss, never
// permission to silently generate a replacement trust root or SSH identity.
func (application *Application) prepareInitialIdentity(ctx context.Context, system systemstate.System, store *localstate.Store, request InitSystemRequest, observer Observer) (operatortrust.Bundle, sshkeys.Record, workflow.Task, error) {
	return application.initialIdentity(ctx, system, store, request, observer, true)
}

// readInitialIdentity runs the same binding checks for a committed bootstrap
// plan, with all creation paths explicitly disabled.
func (application *Application) readInitialIdentity(system systemstate.System, store *localstate.Store, request InitSystemRequest) error {
	_, _, _, err := application.initialIdentity(context.Background(), system, store, request, nil, false)
	return err
}

func (application *Application) initialIdentity(ctx context.Context, system systemstate.System, store *localstate.Store, request InitSystemRequest, observer Observer, allowCreate bool) (operatortrust.Bundle, sshkeys.Record, workflow.Task, error) {
	fail := func(err error) (operatortrust.Bundle, sshkeys.Record, workflow.Task, error) {
		return operatortrust.Bundle{}, sshkeys.Record{}, workflow.Task{}, err
	}
	workflows := workflow.NewManager(store, workflow.WithClock(application.now))
	tasks, err := workflows.List()
	if err != nil {
		return fail(err)
	}
	var existing *workflow.Task
	for index := range tasks {
		task := &tasks[index]
		if task.Kind != workflow.ControlBootstrap {
			continue
		}
		if task.SystemID != system.ID || existing != nil {
			return fail(appError("bootstrap_identity", 5, "The first-Control bootstrap journal has inconsistent system bindings.", "Recover the original task before initializing again.", nil))
		}
		if task.Resource.Name != request.ControlName {
			return fail(appError("control_name", 6, "The existing first-Control task has a different immutable Control name.", "Reuse the original Control name; initialization does not rename or replace identities.", nil))
		}
		existing = task
	}
	committedBootstrap := system.Bootstrap.BootstrapKeyFingerprint != ""
	if committedBootstrap && system.Trust.Generation == 0 {
		return fail(appError("system_trust", 5, "The committed bootstrap has no signing-root binding.", "Recover the complete original system registry; initialization does not recreate missing trust bindings.", nil))
	}
	if committedBootstrap && existing == nil {
		return fail(appError("bootstrap_identity", 5, "The committed bootstrap task is missing.", "Restore the original owner-local journal before continuing.", nil))
	}
	var trust operatortrust.Bundle
	keyStarted, err := bootstrapKeyStarted(store)
	if err != nil {
		return fail(err)
	}
	// The bootstrap namespace is first created after committing trust. This
	// also covers interruption during key generation, before a task exists.
	if system.Trust.Generation > 0 || existing != nil || keyStarted || !allowCreate {
		trust, err = loadInitialTrust(system, store)
	} else {
		trust, err = operatortrust.Ensure(store)
	}
	if err != nil || operatortrust.Validate(trust) != nil {
		return fail(appError("system_trust", 5, "The existing system trust roots cannot be verified.", "Restore the exact committed trust material; initialization never replaces it.", err))
	}
	notify(observer, "bootstrap_key", "running", "creating or reopening the unique first-control identity")
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now))
	var key sshkeys.Record
	if committedBootstrap || existing != nil || !allowCreate {
		key, _, err = keys.Active(sshkeys.Bootstrap, request.ControlName)
	} else {
		key, err = keys.Create(ctx, sshkeys.Bootstrap, request.ControlName)
		if errors.Is(err, sshkeys.ErrAlreadyExists) {
			key, _, err = keys.Active(sshkeys.Bootstrap, request.ControlName)
		}
	}
	if err != nil {
		return fail(appError("bootstrap_identity", 5, "The original first-Control bootstrap identity is unavailable.", "Recover its original private key and generation; no replacement was created.", err))
	}
	reference := workflow.KeyReference{Scope: key.Scope, Name: key.Name, Generation: key.Generation, Fingerprint: key.Fingerprint}
	if existing != nil && existing.Key != reference {
		return fail(appError("bootstrap_identity", 5, "The first-Control key does not match its immutable task reference.", "Recover the original key generation and bootstrap journal.", nil))
	}
	if committedBootstrap && (key.Fingerprint != system.Bootstrap.BootstrapKeyFingerprint || system.Bootstrap.ExpiresAt == nil ||
		!system.Bootstrap.ExpiresAt.Equal(key.CreatedAt.Add(defaultBootstrapLifetime))) {
		return fail(appError("bootstrap_identity", 5, "The bootstrap identity or expiry differs from the committed system binding.", "Restore the original bootstrap metadata; initialization does not extend its lifetime.", nil))
	}
	if existing != nil {
		return trust, key, *existing, nil
	}
	if !allowCreate {
		return fail(appError("bootstrap_identity", 5, "The existing bootstrap journal is unavailable.", "Recover the original bootstrap task before resuming initialization.", nil))
	}
	task, err := workflows.CreateControlBootstrap(system.ID, request.ControlName, reference)
	if err != nil {
		return fail(fmt.Errorf("ensure control bootstrap workflow: %w", err))
	}
	return trust, key, task, nil
}

// Even an empty bootstrap namespace or a key-generation lock proves that
// initialization passed the trust commit. Presence only tightens recovery;
// Load and the key manager still validate the actual files without repair.
func bootstrapKeyStarted(store *localstate.Store) (bool, error) {
	path, err := store.Path("keys/bootstrap")
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, appError("bootstrap_identity", 5, "The bootstrap identity checkpoint cannot be inspected.", "Recover its original private directory before resuming.", err)
	}
	return true, nil
}

func loadInitialTrust(system systemstate.System, store *localstate.Store) (operatortrust.Bundle, error) {
	trust, err := operatortrust.Load(store)
	if err != nil {
		return operatortrust.Bundle{}, appError("system_trust", 5, "The existing system trust roots cannot be verified.", "Restore the exact committed trust material; initialization never replaces it.", err)
	}
	if system.Trust.Generation > 0 && system.Trust != initialTrustMetadata(trust, system.Trust.Generation) {
		return operatortrust.Bundle{}, appError("system_trust", 5, "The committed signing identities differ from the system registry.", "Recover the matching system trust bundle before continuing.", nil)
	}
	return trust, nil
}

func initialTrustMetadata(bundle operatortrust.Bundle, generation uint64) systemstate.TrustMetadata {
	if generation == 0 {
		generation = 1
	}
	return systemstate.TrustMetadata{
		Generation: generation, SystemRootKeyID: bundle.SystemRoot, ReleaseKeyID: bundle.Release,
		DesiredStateKeyID: bundle.DesiredState, ServingAdminKeyID: bundle.ServingAdmin,
		ControlPolicyKeyID: bundle.ControlPolicy,
	}
}

func invalidInitialControlName() error {
	return appError("control_name", 2, "The first-Control name cannot be used by the Control policy and SSH protocol.", "Use 1-63 lowercase letters, digits or hyphens, starting with a letter.", nil)
}
