package application

import (
	"context"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshtransport"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

func (application *Application) diagnoseControlCheckpoint(ctx context.Context, result *DiagnosticsResult, system systemstate.System, store *localstate.Store, task workflow.Task, controls []controlnodes.Record, manager *controlnodes.Manager, document topology.Topology, hasTopology bool) {
	phase := task.Phase
	if phase == workflow.PhaseFailedSafe {
		phase = task.ResumePhase
	}
	if task.Phase == workflow.PhaseRevoked || system.Bootstrap.State == systemstate.BootstrapRevoked || system.Bootstrap.State == systemstate.BootstrapFailed {
		result.add("control:checkpoint", DiagnosticFailed, "The Control bootstrap is revoked or requires explicit recovery.", "Recover or replace the recorded Control bootstrap explicitly.")
		return
	}
	if len(controls) == 0 && system.Bootstrap.State == systemstate.BootstrapKeyPrepared && !hasTopology && diagnosticPreBindingPhase(phase) {
		application.diagnoseBootstrapExpiry(result, system)
		result.add("control:checkpoint", DiagnosticPending, "The Control VM and independent host-key binding are still pending.", "Create the VM with the existing bootstrap public key, then run flow control bind.")
		return
	}
	if len(controls) != 1 {
		result.add("control:binding", DiagnosticFailed, "The first-Control record is missing or ambiguous.", "Recover the original Control record without selecting an alternate endpoint.")
		return
	}
	record := controls[0]
	expectedKey := controlnodes.BootstrapKeyRef{Scope: task.Key.Scope, Name: task.Key.Name, Generation: task.Key.Generation, Fingerprint: task.Key.Fingerprint}
	if record.SystemID != system.ID || record.Name != task.Resource.Name || record.BootstrapKey != expectedKey || record.Lifecycle == controlnodes.LifecycleRevoked {
		result.add("control:binding", DiagnosticFailed, "Control and task do not share the exact bootstrap identity and resource.", "Recover the original Control name and bootstrap generation.")
		return
	}
	expectedTopology := topology.Control{Name: record.Name, Host: record.Host, SSHPort: record.Port, SSHUser: record.SSHUser, Trust: topology.TrustPinned, HostKeyFingerprint: record.HostFingerprint}
	if hasTopology && (document.Control == nil || *document.Control != expectedTopology) {
		result.add("topology:binding", DiagnosticFailed, "Topology differs from the independently pinned Control endpoint.", "Recover the original endpoint and host key before connecting.")
		return
	}
	// A crash may leave a bound record before the final system/task checkpoint.
	// Repeating the exact explicit binding reconciles it without a new identity.
	if system.Bootstrap.State == systemstate.BootstrapKeyPrepared && record.Lifecycle == controlnodes.LifecycleBound &&
		record.Access.Phase == controlnodes.AccessBootstrap && !document.ControlReady && (diagnosticPreBindingPhase(phase) || phase == workflow.PhaseHostKeyVerified) {
		application.diagnoseBootstrapExpiry(result, system)
		result.add("control:checkpoint", DiagnosticPending, "The existing Control binding needs its final local checkpoint.", "Repeat flow control bind with the exact original endpoint and independently confirmed host key.")
		return
	}
	if system.Bootstrap.ControlNodeID != record.Name || system.Bootstrap.HostKeyFingerprint != record.HostFingerprint || !hasTopology {
		result.add("control:binding", DiagnosticFailed, "System, Control and topology do not share the same committed host binding.", "Recover the original system, Control and topology checkpoints.")
		return
	}
	result.add("control:binding", DiagnosticOK, "System, task, Control and topology agree on the exact pinned endpoint.", "")
	if phase == workflow.PhaseReady || record.Lifecycle == controlnodes.LifecycleReady || document.ControlReady || system.Bootstrap.State == systemstate.BootstrapControlActive {
		application.diagnoseReadyControl(result, system, store, task, record, manager, document)
		return
	}
	var err error
	next, detail := "", ""
	switch phase {
	case workflow.PhaseHostKeyVerified:
		// A committed connectivity record can make check a local reconciliation,
		// but installation still needs this bootstrap identity afterwards.
		application.diagnoseBootstrapExpiry(result, system)
		_, err = application.PlanControlCheck(ctx, CheckControlRequest{Name: record.Name})
		next, detail = "Run flow control check with the recorded Control name.", "Pinned connectivity verification or its local reconciliation is pending."
	case workflow.PhaseConnectivityOK:
		_, err = application.PlanControlInstall(ctx, PrepareControlInstallRequest{Name: record.Name})
		next, detail = "Run flow control install with the recorded Control name.", "Local installation preparation or its checkpoint is pending."
	case workflow.PhaseInstalling:
		_, err = application.PlanPreparedControlInstall(ctx, InstallPreparedControlRequest{Name: record.Name})
		next, detail = "Run flow control apply with the recorded Control name after reviewing --plan.", "Control installation or its local reconciliation is pending."
	case workflow.PhaseAttesting:
		_, err = application.PlanControlAttest(ctx, AttestControlRequest{Name: record.Name})
		next, detail = "Use flow control attest for a fresh proof; bootstrap revocation and activation remain pending.", "Management proof, verified bootstrap revocation and Control activation are not all committed."
	default:
		result.add("control:checkpoint", DiagnosticFailed, "Control lifecycle and task phase disagree.", "Recover the earlier incomplete checkpoint before continuing.")
		return
	}
	if err != nil {
		failure := AsError(err)
		result.add("control:checkpoint", DiagnosticFailed, failure.SafeText, "Inspect the corresponding Control --plan command and recover its recorded trust gate.")
		result.Checks[len(result.Checks)-1].Code = failure.Code
		return
	}
	result.add("control:checkpoint", DiagnosticPending, detail, next)
}

func (application *Application) diagnoseBootstrapExpiry(result *DiagnosticsResult, system systemstate.System) {
	if bootstrapExpired(system, application.now()) {
		result.add("bootstrap:validity", DiagnosticFailed, "The bootstrap identity expired before its required network steps completed.", "Recover the existing bootstrap workflow explicitly; do not extend or replace trust silently.")
	} else {
		result.add("bootstrap:validity", DiagnosticOK, "The bootstrap identity remains within its allowed validity period.", "")
	}
}

func (application *Application) diagnoseReadyControl(result *DiagnosticsResult, system systemstate.System, store *localstate.Store, task workflow.Task, record controlnodes.Record, manager *controlnodes.Manager, document topology.Topology) {
	if task.Phase != workflow.PhaseReady || record.Lifecycle != controlnodes.LifecycleReady || record.Access.Phase != controlnodes.AccessManagement ||
		!document.ControlReady || system.Bootstrap.State != systemstate.BootstrapControlActive || !system.Bootstrap.BootstrapKeyRevoked {
		result.add("control:readiness", DiagnosticFailed, "Control-ready assertions disagree with committed access and bootstrap revocation.", "Recover the exact activation checkpoint; readiness cannot be inferred from connectivity.")
		return
	}
	material, err := manager.AccessMaterial(system.ID, record.Name)
	if err == nil {
		_, err = sshtransport.NewPrivateIdentity(material.IdentityPath)
	}
	if err != nil {
		result.add("control:readiness", DiagnosticFailed, "The active management identity or exact bootstrap revocation is invalid.", "Recover the committed management identity and revocation evidence.")
		return
	}
	prepared, err := application.readPreparedControlEnvelope(store, system, record)
	if err != nil || prepared.key.Scope != material.Identity.Scope || prepared.key.Name != material.Identity.Name ||
		prepared.key.Generation != material.Identity.Generation || prepared.key.Fingerprint != material.Identity.Fingerprint {
		result.add("control:readiness", DiagnosticFailed, "The active signed Control policy is invalid, expired or bound to another identity.", "Recover or renew the exact signed policy through the authorized Control workflow.")
		return
	}
	installed, err := readControlInstallEvidence(store, system.ID, record.Name, prepared)
	if err != nil {
		result.add("control:readiness", DiagnosticFailed, "The exact Control installation receipt is missing or inconsistent.", "Recover the original installation evidence before trusting the activation checkpoint.")
		return
	}
	var proof ControlProofEvidence
	if err := store.ReadJSON(controlProofRelative(record.Name), &proof); err != nil ||
		proof.SchemaVersion != 1 || proof.SystemID != system.ID || proof.ControlName != record.Name ||
		proof.ManagementFingerprint != material.Identity.Fingerprint || proof.ManagementGeneration != material.Identity.Generation ||
		proof.HostKeyFingerprint != record.HostFingerprint || proof.PolicyGeneration != installed.PolicyGeneration ||
		proof.EnvelopeDigest != prepared.digest || proof.ExecutableDigest != installed.ExecutableDigest ||
		!validUTCTime(proof.VerifiedAt) || !validUTCTime(proof.RemoteObservedAt) {
		result.add("control:readiness", DiagnosticFailed, "The exact Control management proof is missing or inconsistent.", "Recover the original authenticated management proof before trusting the activation checkpoint.")
		return
	}
	result.ControlReady = true
	result.add("control:readiness", DiagnosticOK, "Local Control-ready, management-access and bootstrap-revocation checkpoints agree; remote availability was not checked.", "")
}

func diagnosticPreBindingPhase(phase workflow.Phase) bool {
	switch phase {
	case workflow.PhasePrepared, workflow.PhaseAwaitingCloudVM, workflow.PhaseAwaitingEndpoint, workflow.PhaseAwaitingOOBHostKey:
		return true
	default:
		return false
	}
}
