package application

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/operatortrust"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/sshtransport"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/topology"
	"dynamicflow/internal/workflow"
)

type DiagnosticStatus string

const (
	DiagnosticOK      DiagnosticStatus = "ok"
	DiagnosticPending DiagnosticStatus = "pending"
	DiagnosticFailed  DiagnosticStatus = "failed"
)

// DiagnosticCheck describes local integrity or an expected incomplete step.
// Pending steps do not fail local health and never imply Control readiness.
type DiagnosticCheck struct {
	Name   string           `json:"name"`
	Status DiagnosticStatus `json:"status"`
	OK     bool             `json:"ok"`
	Code   string           `json:"code,omitempty"`
	Detail string           `json:"detail"`
	Next   string           `json:"next,omitempty"`
}

type DiagnosticsResult struct {
	Scope              string            `json:"scope"`
	SystemID           string            `json:"system_id,omitempty"`
	Healthy            bool              `json:"healthy"`
	ControlReady       bool              `json:"control_ready"`
	NetworkConnections int               `json:"network_connections"`
	Checks             []DiagnosticCheck `json:"checks"`
	ObservedAt         time.Time         `json:"observed_at"`
}

// DiagnoseLocal is the shared read-only entry point, including invalid registry
// diagnostics when corruption prevents constructing an Application. A scope of
// "operator" means that no system is registered; adapters may then inspect the
// legacy operator layout. Invalid registries always retain scope "system".
func DiagnoseLocal(ctx context.Context, configuration Config) (DiagnosticsResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return DiagnosticsResult{}, diagnosticsCancelled()
	}
	app, err := Open(configuration)
	if err != nil {
		now := time.Now
		if configuration.Clock != nil {
			now = configuration.Clock
		}
		result := newDiagnosticsResult(now())
		result.add("system:registry", DiagnosticFailed, "System registry or private application state is invalid.", "Recover the existing private registry; do not initialize replacement trust roots.")
		return result, nil
	}
	return app.Diagnose(ctx)
}

// Diagnose inspects existing local state and executable availability. It never
// executes a process, creates keys, writes a journal or contacts an endpoint.
// A healthy result states local consistency only, not remote availability.
func (application *Application) Diagnose(ctx context.Context) (DiagnosticsResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return DiagnosticsResult{}, diagnosticsCancelled()
	}
	if application == nil || application.store == nil || application.systems == nil || application.now == nil {
		return DiagnosticsResult{}, appError("application_unavailable", 3, "Private application state is unavailable.", "Recover the private state directory.", nil)
	}
	result := newDiagnosticsResult(application.now())
	registry, err := application.systems.Snapshot()
	if err != nil {
		result.add("system:registry", DiagnosticFailed, "The system registry is invalid.", "Recover the existing registry before continuing.")
		return result, nil
	}
	if len(registry.Systems) == 0 {
		result.Scope = "operator"
		result.add("system:registry", DiagnosticPending, "No Dynamicflow system is registered.", "Use flow system init to begin a Control-first system.")
		return result, nil
	}
	var active systemstate.System
	for _, system := range registry.Systems {
		if system.ID == registry.ActiveSystemID {
			active = system
			break
		}
	}
	result.SystemID = active.ID
	result.add("system:registry", DiagnosticOK, "The active system registry is valid.", "")
	for _, tool := range []struct{ name, executable string }{{"ssh", "ssh"}, {"ssh-keygen", application.sshKeygen}} {
		if _, err := exec.LookPath(tool.executable); err != nil {
			result.add("tool:"+tool.name, DiagnosticFailed, "Required local executable is unavailable.", "Install the OpenSSH client tools or repair PATH.")
		} else {
			result.add("tool:"+tool.name, DiagnosticOK, "Required local executable is available; it was not run.", "")
		}
	}
	store, err := application.openSystemStore(active.ID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && active.Trust.Generation == 0 && active.Bootstrap.State == systemstate.BootstrapNotStarted {
			result.add("system:initialization", DiagnosticPending, "Local system initialization has not committed yet.", "Resume flow system init with the original system and Control names.")
		} else {
			result.add("system:directory", DiagnosticFailed, "The existing system directory is missing or unsafe.", "Recover the original private system directory and its ownership.")
		}
		return result, nil
	}
	if active.Trust.Generation == 0 && active.Bootstrap.State == systemstate.BootstrapNotStarted {
		// Trust can commit before the final system checkpoint. Missing roots at
		// this stage are expected; an existing committed bundle must be sound.
		var committed operatortrust.Bundle
		if err := store.ReadJSON("keys/signing/trust.json", &committed); !errors.Is(err, os.ErrNotExist) {
			if _, err := operatortrust.Load(store); err != nil {
				result.add("trust:roots", DiagnosticFailed, "An already committed signing bundle is incomplete or invalid.", "Recover its original key pairs before resuming initialization.")
			} else {
				result.add("trust:roots", DiagnosticOK, "The five committed signing pairs are valid; their final system checkpoint is pending.", "")
			}
		}
		result.add("system:initialization", DiagnosticPending, "Local trust and bootstrap initialization are not committed yet.", "Resume flow system init with the original system and Control names.")
		return result, nil
	}
	bundle, trustErr := operatortrust.Load(store)
	if trustErr != nil {
		result.add("trust:roots", DiagnosticFailed, "The five committed signing roots could not be verified.", "Restore the original complete key pairs and trust bundle; diagnostics never generate replacements.")
	} else {
		result.add("trust:roots", DiagnosticOK, "System-root, release, desired-state, serving-admin and control-policy key pairs are valid and distinct.", "")
		if !diagnosticTrustMatches(bundle, active.Trust) {
			result.add("trust:binding", DiagnosticFailed, "Signing roots differ from the system's committed trust identities.", "Recover the exact original trust bundle and registry binding.")
		} else {
			result.add("trust:binding", DiagnosticOK, "All five signing roots match the active system.", "")
		}
	}
	tasks, err := workflow.NewManager(store, workflow.WithClock(application.now)).List()
	if err != nil || len(tasks) != 1 || tasks[0].SystemID != active.ID || tasks[0].Kind != workflow.ControlBootstrap {
		result.add("workflow:task", DiagnosticFailed, "The first-Control bootstrap task is missing, invalid or ambiguous.", "Recover the original task and its system binding.")
		return result, nil
	}
	task := tasks[0]
	result.add("workflow:task", DiagnosticOK, "One valid first-Control bootstrap task belongs to the active system.", "")
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(application.sshKeygen), sshkeys.WithClock(application.now), sshkeys.WithControlScope())
	key, keyPaths, keyErr := keys.Current(task.Key.Scope, task.Key.Name)
	if keyErr == nil {
		_, keyErr = sshtransport.NewPrivateIdentity(keyPaths.Private)
	}
	wantedStatus := sshkeys.ActiveStatus
	if active.Bootstrap.BootstrapKeyRevoked {
		wantedStatus = sshkeys.RevokedStatus
	}
	if keyErr != nil || key.Scope != task.Key.Scope || key.Name != task.Key.Name || key.Generation != task.Key.Generation ||
		key.Fingerprint != task.Key.Fingerprint || key.Fingerprint != active.Bootstrap.BootstrapKeyFingerprint || key.Status != wantedStatus {
		result.add("bootstrap:identity", DiagnosticFailed, "Bootstrap identity does not match its exact task, system and revocation state.", "Recover the original bootstrap generation; do not generate a replacement.")
		return result, nil
	}
	result.add("bootstrap:identity", DiagnosticOK, "Bootstrap public metadata matches its task and system; the private file passes local safety checks. SSH authentication was not attempted.", "")
	manager, err := controlnodes.NewManager(application.store, keys, controlnodes.WithClock(application.now))
	if err != nil {
		result.add("control:registry", DiagnosticFailed, "Control registry is unavailable.", "Recover the private Control registry.")
		return result, nil
	}
	controls, err := manager.List(active.ID)
	if err != nil {
		result.add("control:registry", DiagnosticFailed, "Control records or their independently pinned host keys are invalid.", "Recover the original Control record and host pin.")
		return result, nil
	}
	document, topologyErr := topology.NewStore(store).Load()
	if topologyErr != nil && !errors.Is(topologyErr, topology.ErrNotFound) {
		result.add("topology:binding", DiagnosticFailed, "The local Control topology is invalid.", "Recover the exact pinned topology before connecting.")
		return result, nil
	}
	application.diagnoseControlCheckpoint(ctx, &result, active, store, task, controls, manager, document, topologyErr == nil)
	if ctx.Err() != nil {
		return DiagnosticsResult{}, diagnosticsCancelled()
	}
	latest, err := application.systems.Snapshot()
	if err != nil || latest.Revision != registry.Revision || latest.ActiveSystemID != registry.ActiveSystemID {
		result.add("system:snapshot", DiagnosticFailed, "System state changed during diagnostics.", "Run flow doctor again after the active operation completes.")
	}
	if !result.Healthy {
		result.ControlReady = false
	}
	return result, nil
}

func newDiagnosticsResult(now time.Time) DiagnosticsResult {
	return DiagnosticsResult{Scope: "system", Healthy: true, Checks: []DiagnosticCheck{}, ObservedAt: now.UTC()}
}

func (result *DiagnosticsResult) add(name string, status DiagnosticStatus, detail, next string) {
	result.Checks = append(result.Checks, DiagnosticCheck{Name: name, Status: status, OK: status != DiagnosticFailed, Detail: detail, Next: next})
	if status == DiagnosticFailed {
		result.Healthy = false
	}
}

func diagnosticTrustMatches(bundle operatortrust.Bundle, trust systemstate.TrustMetadata) bool {
	return trust.Generation > 0 && bundle.SystemRoot == trust.SystemRootKeyID && bundle.Release == trust.ReleaseKeyID &&
		bundle.DesiredState == trust.DesiredStateKeyID && bundle.ServingAdmin == trust.ServingAdminKeyID && bundle.ControlPolicy == trust.ControlPolicyKeyID
}

func diagnosticsCancelled() *Error {
	return appError("cancelled", 8, "Local diagnostics were cancelled.", "Run flow doctor again.", nil)
}
