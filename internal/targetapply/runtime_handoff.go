package targetapply

import (
	"context"
	"path/filepath"

	"dynamicflow/internal/applyplan"
	"dynamicflow/internal/reconcile"
)

// prepareRuntimeHandoff replaces only the fixed flow executable. When bytes
// changed it deliberately returns before reconcile can run any profile phase
// or advance the apply checkpoint. The next timer invocation starts the new
// /usr/local/bin/flow and resumes the content-bound plan idempotently.
func (r *runner) prepareRuntimeHandoff(ctx context.Context) (bool, error) {
	phase, err := r.phase("flow")
	if err != nil {
		return false, err
	}
	artifact := phase.Steps[0].Artifact
	required, err := runtimeUpdateRequired(artifact)
	if err != nil {
		r.runtimeEvent("flow", "failed", "phase_failed")
		return false, &reconcile.PhaseError{Code: "runtime_activation_failed", Message: "the installed flow destination is unsafe", Next: "inspect /usr/local/bin ownership, modes, symlinks and hardlinks before retrying"}
	}
	if !required {
		return false, nil
	}

	r.runtimeEvent("flow", "preflight", "")
	if _, err := r.ensureRuntimeArtifact(ctx, artifact); err != nil {
		r.runtimeEvent("flow", "failed", "artifact_verification")
		return false, &reconcile.PhaseError{Code: "runtime_artifact_verification", Message: "the signed flow runtime could not be verified", Next: "check serving release health and retry; the installed runtime was not changed"}
	}
	r.runtimeEvent("flow", "applying", "")
	if err := r.activateRuntimeArtifact(ctx, artifact); err != nil {
		r.runtimeEvent("flow", "failed", "phase_failed")
		return false, &reconcile.PhaseError{Code: "runtime_activation_failed", Message: "the verified flow runtime could not be activated atomically", Next: "retry; use the digest-named root-only recovery copy for console recovery"}
	}
	r.runtimeEvent("flow", "verifying", "")
	if err := r.verifyRuntimeArtifact(); err != nil {
		r.runtimeEvent("flow", "failed", "phase_failed")
		return false, &reconcile.PhaseError{Code: "runtime_activation_failed", Message: "the activated flow runtime did not pass post-rename verification", Next: "recover from the digest-named root-only copy and inspect filesystem integrity"}
	}
	r.runtimeEvent("flow", "complete", "handoff")
	return true, nil
}

func runtimeUpdateRequired(artifact applyplan.Artifact) (bool, error) {
	if err := validateRuntimeArtifact(artifact); err != nil {
		return false, err
	}
	destination, err := openTrustedAbsoluteDirectory(filepath.Dir(runtimeBinaryPath), false)
	if err != nil {
		return false, err
	}
	defer destination.Close()
	if err := verifyNamedRuntimeFile(destination, filepath.Base(runtimeBinaryPath), artifact, runtimeInstalledMode, 0); err == nil {
		return false, nil
	}
	if err := requireSafeInstalledDestination(destination, filepath.Base(runtimeBinaryPath), 0); err != nil {
		return false, err
	}
	return true, nil
}

func (r *runner) runtimeEvent(phase, state, detail string) {
	if r.config.Event != nil {
		r.config.Event(phase, state, detail)
	}
}
