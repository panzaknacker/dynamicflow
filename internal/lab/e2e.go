package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	MinimumSoakSeconds = 30 * 60
	NormalCloseCycles  = 5
)

type Action string

const (
	ActionPreflight        Action = "preflight"
	ActionServingProbe     Action = "serving-probe"
	ActionServingReconcile Action = "serving-reconcile"
	ActionServingRestart   Action = "serving-restart"
	ActionRuntimeProbe     Action = "runtime-probe"
	ActionEnrollmentProbe  Action = "enrollment-evidence-probe"
	ActionRecoveryProbe    Action = "recovery-evidence-probe"
	ActionApplyConcurrency Action = "apply-concurrency-probe"
	ActionReboot           Action = "reboot"
	ActionReachable        Action = "reachable"
	ActionVNCProbe         Action = "vnc-loopback-probe"
	ActionPBPProbe         Action = "pbp-vpn-probe"
	ActionPBPIdentity      Action = "pbp-identity-probe"
	ActionPBPSoakStart     Action = "pbp-soak-start"
	ActionPBPSoakPoll      Action = "pbp-soak-poll"
	ActionPBPSoakResult    Action = "pbp-soak-result"
	ActionPBPForensics     Action = "pbp-forensics"
)

var fixedActions = map[Action]struct{}{
	ActionPreflight: {}, ActionServingProbe: {}, ActionServingReconcile: {}, ActionServingRestart: {},
	ActionRuntimeProbe: {}, ActionEnrollmentProbe: {}, ActionRecoveryProbe: {},
	ActionApplyConcurrency: {}, ActionReboot: {}, ActionReachable: {},
	ActionVNCProbe: {}, ActionPBPProbe: {}, ActionPBPIdentity: {}, ActionPBPSoakStart: {},
	ActionPBPSoakPoll: {}, ActionPBPSoakResult: {}, ActionPBPForensics: {},
}

func IsFixedAction(action Action) bool {
	_, ok := fixedActions[action]
	return ok
}

func IsMutatingAction(action Action) bool {
	switch action {
	case ActionServingReconcile, ActionServingRestart, ActionApplyConcurrency, ActionReboot, ActionPBPSoakStart, ActionPBPSoakResult:
		return true
	default:
		return false
	}
}

type RemoteState string

const (
	RemoteReady    RemoteState = "ready"
	RemoteRunning  RemoteState = "running"
	RemoteComplete RemoteState = "complete"
)

type RemoteResult struct {
	State RemoteState
	Data  []byte
}

type RemoteExecutor interface {
	Run(context.Context, Host, Action) (RemoteResult, error)
}

type ControlPlane interface {
	RotateSSHKey(context.Context, Host) (uint64, error)
	RotateVNCSecret(context.Context, Host) error
	RevokeInstance(context.Context, Host) (uint64, error)
}

type Progress struct {
	Phase  string
	Host   string
	Status string
}

type PhaseResult struct {
	Name       string    `json:"name"`
	Host       string    `json:"host,omitempty"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Evidence   string    `json:"evidence,omitempty"`
}

type Report struct {
	Schema                  int                   `json:"schema"`
	Test                    string                `json:"test"`
	Status                  string                `json:"status"`
	StartedAt               time.Time             `json:"started_at"`
	FinishedAt              time.Time             `json:"finished_at"`
	MinimumSoakSeconds      int                   `json:"minimum_soak_seconds"`
	NormalCloseCycles       int                   `json:"normal_close_cycles"`
	VPNFailureArmed         bool                  `json:"vpn_failure_armed"`
	QualifyingPBPPass       bool                  `json:"qualifying_pbp_pass"`
	QualificationMatrix     []QualificationStep   `json:"qualification_matrix"`
	Phases                  []PhaseResult         `json:"phases"`
	FailureCode             string                `json:"failure_code,omitempty"`
	FailurePhase            string                `json:"failure_phase,omitempty"`
	FailureNextAction       string                `json:"failure_next_action,omitempty"`
	PBPResultSHA256         string                `json:"pbp_result_sha256,omitempty"`
	PBPResultRemoteBytes    int                   `json:"pbp_result_remote_bytes,omitempty"`
	PBPForensics            *PBPForensicsEvidence `json:"pbp_forensics,omitempty"`
	PBPForensicsSHA256      string                `json:"pbp_forensics_sha256,omitempty"`
	PBPForensicsRemoteBytes int                   `json:"pbp_forensics_remote_bytes,omitempty"`
}

type RunError struct {
	Code    string
	Phase   string
	Message string
	Next    string
	Blocked bool
}

func (err *RunError) Error() string {
	if err.Phase == "" {
		return err.Message
	}
	return err.Phase + ": " + err.Message
}

type Runner struct {
	ValidateBinding func(Host) error
	Remote          RemoteExecutor
	Control         ControlPlane
	Now             func() time.Time
	Sleep           func(context.Context, time.Duration) error
	Progress        func(Progress)
	RebootTimeout   time.Duration
	SoakTimeout     time.Duration
	PollInterval    time.Duration
}

func (runner Runner) Run(ctx context.Context, inventory Inventory) (Report, []byte, error) {
	now := runner.Now
	if now == nil {
		now = time.Now
	}
	report := Report{
		Schema: 1, Test: "dynamicflow-four-vm-e2e", Status: "RUNNING",
		StartedAt: now().UTC(), MinimumSoakSeconds: MinimumSoakSeconds,
		NormalCloseCycles: NormalCloseCycles, VPNFailureArmed: true,
		QualificationMatrix: QualificationMatrix(),
	}
	var pbpResult []byte
	fail := func(runErr *RunError) (Report, []byte, error) {
		if runErr.Blocked {
			report.Status = "BLOCKED"
		} else {
			report.Status = "FAIL"
		}
		report.FailureCode = runErr.Code
		report.FailurePhase = runErr.Phase
		report.FailureNextAction = runErr.Next
		report.FinishedAt = now().UTC()
		return report, append([]byte(nil), pbpResult...), runErr
	}

	roleHosts, validationErr := validateE2EInventory(inventory)
	if validationErr != nil {
		return fail(validationErr)
	}
	if runner.ValidateBinding == nil || runner.Remote == nil || runner.Control == nil {
		return fail(blocked("local-preflight", "lab_runner_unavailable", "the bounded lab runner is not configured", "Run the repository-built flow binary from the initialized operator state."))
	}
	// resolve every local identity and pinned host key before the first network
	// connection or mutation. a later host must never turn an earlier host into
	// a partially executed lab.
	for _, role := range requiredRoles() {
		if err := runner.ValidateBinding(roleHosts[role]); err != nil {
			return fail(blocked("local-preflight", "lab_instance_unpinned", fmt.Sprintf("%s lacks a complete local endpoint, key, host-pin, profile, or control-plane binding", roleHosts[role].Name), "Run flow instance bind, verify the Ed25519 key through the provider console, then flow instance hostkey pin; enrollment and recovery roles also require dedicated per-instance keys and matching live enrollment state."))
		}
	}

	runRemote := func(phase string, host Host, action Action, evidence string) *RunError {
		if IsMutatingAction(action) && !host.Disposable {
			return blocked(phase, "lab_not_disposable", "the fixed mutating action is not authorized for "+host.Name, "Set disposable: true only after explicitly authorizing this rebuildable lab host.")
		}
		if !IsFixedAction(action) {
			return failed(phase, "lab_action_invalid", "the runner selected a non-fixed remote action", "Stop and inspect the local flow binary.")
		}
		started := now().UTC()
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
		result, err := runner.Remote.Run(ctx, host, action)
		finished := now().UTC()
		if err != nil {
			report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "FAIL", StartedAt: started, FinishedAt: finished})
			runner.emit(Progress{Phase: phase, Host: host.Name, Status: "failed"})
			return failed(phase, "lab_remote_action", fmt.Sprintf("fixed action %s failed on %s", action, host.Name), nextForAction(action, host.Name))
		}
		if result.State != RemoteReady && action != ActionPBPSoakStart && action != ActionPBPSoakPoll && action != ActionPBPSoakResult {
			return failed(phase, "lab_remote_protocol", "remote action returned an invalid finite state", nextForAction(action, host.Name))
		}
		report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: finished, Evidence: evidence})
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
		return nil
	}

	for _, role := range requiredRoles() {
		host := roleHosts[role]
		if runErr := runRemote("preflight-"+role, host, ActionPreflight, "fixed SSH preflight through pinned host key"); runErr != nil {
			return fail(runErr)
		}
	}
	servingHost := roleHosts["serving"]
	if runErr := runRemote("serving-https-and-no-ssh", servingHost, ActionServingProbe, "verified HTTPS health; no serving ssh/scp child or port-22 socket"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("serving-flow-reconcile-idempotent", servingHost, ActionServingReconcile, "flow start serving plan was a complete no-op; two real reconciles remained no-op and preserved the service process"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("serving-restart-stability", servingHost, ActionServingRestart, "restart became healthy; repeated systemd start preserved the same process"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.rebootAndResume(ctx, &report, servingHost, "serving-reboot-resume", ActionServingProbe, "pinned SSH returned; serving HTTPS health and no-outbound-SSH invariant resumed", now); runErr != nil {
		return fail(runErr)
	}

	for _, role := range []string{"enrollment", "pbp", "recovery-negative"} {
		host := roleHosts[role]
		if runErr := runRemote("runtime-timer-"+role, host, ActionRuntimeProbe, "signed runtime ready; persistent pull timer enabled and active"); runErr != nil {
			return fail(runErr)
		}
	}

	enrollmentHost := roleHosts["enrollment"]
	if runErr := runRemote("enrollment-public-key-only", enrollmentHost, ActionEnrollmentProbe, "fresh outbound-HTTPS enrollment retained no credential fields and installed one public Ed25519 SSH key"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.runControlPhase(ctx, &report, "ssh-key-rotation", enrollmentHost, "rotate", now); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("runtime-after-key-rotation", enrollmentHost, ActionRuntimeProbe, "rotation overlap and removal generations acknowledged over HTTPS"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.rebootAndResume(ctx, &report, enrollmentHost, "enrollment-reboot-resume", ActionRuntimeProbe, "pinned SSH returned; signed runtime and persistent timer resumed", now); runErr != nil {
		return fail(runErr)
	}

	recoveryHost := roleHosts["recovery-negative"]
	if runErr := runRemote("recovery-evidence", recoveryHost, ActionRecoveryProbe, "attested tamper/interruption/upgrade run left two verification failures, a resumed complete journal, empty staging and protected runtime recovery copies"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("parallel-apply-lock-and-resume", recoveryHost, ActionApplyConcurrency, "a contender received apply_busy while the production lock was held; a fixed reconcile then completed after release"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.rebootAndResume(ctx, &report, recoveryHost, "recovery-reboot-resume", ActionRuntimeProbe, "pinned SSH returned; completed apply checkpoint and persistent runtime resumed", now); runErr != nil {
		return fail(runErr)
	}

	pbpHost := roleHosts["pbp"]
	if runErr := runRemote("vnc-loopback", pbpHost, ActionVNCProbe, "VNC :5901 is loopback-only and clipboard is disabled"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.runVNCSecretRotation(ctx, &report, pbpHost, now); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("pbp-vpn-preflight", pbpHost, ActionPBPProbe, "PBP v0.1.9, stable persona, DE egress, Shadowsocks 443, lockdown and auto-connect verified"); runErr != nil {
		return fail(runErr)
	}
	identityBefore, runErr := runner.capturePBPIdentity(ctx, &report, pbpHost, "pbp-identity-before-reboot", now)
	if runErr != nil {
		return fail(runErr)
	}
	if runErr := runner.rebootAndResume(ctx, &report, pbpHost, "pbp-reboot-resume", ActionRuntimeProbe, "pinned SSH returned; signed runtime and persistent timer resumed", now); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("vnc-loopback-after-reboot", pbpHost, ActionVNCProbe, "VNC :5901 remained loopback-only and clipboard remained disabled after reboot"); runErr != nil {
		return fail(runErr)
	}
	if runErr := runRemote("pbp-vpn-after-reboot", pbpHost, ActionPBPProbe, "PBP policy and German Mullvad egress recovered after reboot"); runErr != nil {
		return fail(runErr)
	}
	identityAfter, runErr := runner.capturePBPIdentity(ctx, &report, pbpHost, "pbp-identity-after-reboot", now)
	if runErr != nil {
		return fail(runErr)
	}
	if !bytes.Equal(identityBefore, identityAfter) {
		return fail(failed("pbp-identity-after-reboot", "pbp_persona_changed", "the protected persona identity changed across the PBP VM reboot", "Stop PBP; recover the persona and matching profile from a consistent snapshot instead of generating a replacement."))
	}
	pbpResult, runErr = runner.runPBPSoak(ctx, &report, pbpHost, now)
	if runErr != nil {
		return fail(runErr)
	}

	if runErr := runner.runControlPhase(ctx, &report, "signed-revocation", recoveryHost, "revoke", now); runErr != nil {
		return fail(runErr)
	}

	report.Status = "PASS"
	report.QualifyingPBPPass = true
	report.FinishedAt = now().UTC()
	return report, pbpResult, nil
}

func (runner Runner) runVNCSecretRotation(ctx context.Context, report *Report, host Host, now func() time.Time) *RunError {
	phase := "vnc-secret-rotation"
	if !host.Disposable {
		return blocked(phase, "lab_not_disposable", "the VNC credential rotation is not authorized for "+host.Name, "Set disposable: true only for the explicitly rebuildable PBP host.")
	}
	started := now().UTC()
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	if err := runner.Control.RotateVNCSecret(ctx, host); err != nil {
		report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "FAIL", StartedAt: started, FinishedAt: now().UTC()})
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "failed"})
		return failed(phase, "lab_vnc_secret_rotation", "the fixed flow VNC credential rotation did not complete", "Inspect the SSH/GUI service through the provider console; the credential was suppressed from lab evidence.")
	}
	report.Phases = append(report.Phases, PhaseResult{
		Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: now().UTC(),
		Evidence: "flow instance secret rotate completed through pinned SSH; credential output was suppressed",
	})
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
	return nil
}

func (runner Runner) capturePBPIdentity(ctx context.Context, report *Report, host Host, phase string, now func() time.Time) ([]byte, *RunError) {
	started := now().UTC()
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	result, err := runner.Remote.Run(ctx, host, ActionPBPIdentity)
	if err != nil || result.State != RemoteReady || len(result.Data) != sha256.Size {
		report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "FAIL", StartedAt: started, FinishedAt: now().UTC()})
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "failed"})
		return nil, failed(phase, "pbp_identity_probe", "the fixed protected persona identity probe failed", "Inspect persona ownership, mode and schema through the provider console; do not replace it.")
	}
	report.Phases = append(report.Phases, PhaseResult{
		Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: now().UTC(),
		Evidence: "protected persona inode, size, digest and stable fields were captured without portable identity values",
	})
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
	return append([]byte(nil), result.Data...), nil
}

func (runner Runner) runControlPhase(ctx context.Context, report *Report, phase string, host Host, operation string, now func() time.Time) *RunError {
	if !host.Disposable {
		return blocked(phase, "lab_not_disposable", "the bounded control mutation is not authorized for "+host.Name, "Set disposable: true only for an explicitly rebuildable lab host.")
	}
	started := now().UTC()
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	var generation uint64
	var err error
	switch operation {
	case "rotate":
		generation, err = runner.Control.RotateSSHKey(ctx, host)
	case "revoke":
		generation, err = runner.Control.RevokeInstance(ctx, host)
	default:
		return failed(phase, "lab_control_invalid", "unknown bounded control-plane operation", "Stop and inspect the local flow binary.")
	}
	finished := now().UTC()
	if err != nil || generation == 0 {
		report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "FAIL", StartedAt: started, FinishedAt: finished})
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "failed"})
		next := "Inspect serving and the target's outbound HTTPS status; no SSH fallback is permitted."
		if operation == "revoke" {
			next = "Use the provider console to confirm target fail-closed state; do not treat local SSH disablement alone as a remote acknowledgement."
		}
		return failed(phase, "lab_control_ack", "signed "+operation+" did not receive a complete target HTTPS acknowledgement", next)
	}
	report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: finished, Evidence: fmt.Sprintf("signed desired generation %d acknowledged", generation)})
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
	return nil
}

func (runner Runner) rebootAndResume(ctx context.Context, report *Report, host Host, phase string, readiness Action, evidence string, now func() time.Time) *RunError {
	if !host.Disposable || !IsFixedAction(readiness) || IsMutatingAction(readiness) {
		return blocked(phase, "lab_reboot_gate", "the fixed reboot readiness gate is not authorized", "Use only the documented disposable host and fixed readiness probe.")
	}
	started := now().UTC()
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	if _, err := runner.Remote.Run(ctx, host, ActionReboot); err != nil {
		return failed(phase, "lab_reboot_request", "the fixed reboot request was not acknowledged", "Use the provider console to inspect the host, then rerun the lab.")
	}
	timeout := runner.RebootTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	interval := runner.PollInterval
	if interval <= 0 {
		interval = 20 * time.Second
	}
	deadline := now().Add(timeout)
	attempt := 0
	for now().Before(deadline) {
		attempt++
		if err := runner.sleep(ctx, interval); err != nil {
			return failed(phase, "lab_interrupted", "waiting for reboot was interrupted", "Rerun the lab; completed phases are recorded in its result.")
		}
		if result, err := runner.Remote.Run(ctx, host, ActionReachable); err == nil && result.State == RemoteReady {
			if status, statusErr := runner.Remote.Run(ctx, host, readiness); statusErr == nil && status.State == RemoteReady {
				report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: now().UTC(), Evidence: evidence})
				runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
				return nil
			}
		}
		if attempt%3 == 0 {
			runner.emit(Progress{Phase: phase, Host: host.Name, Status: "waiting"})
		}
	}
	return failed(phase, "lab_reboot_timeout", "host did not return with ready runtime and timer before the bounded deadline", "Use the provider console and flow instance logs; do not change the pinned host key automatically.")
}

func (runner Runner) runPBPSoak(ctx context.Context, report *Report, host Host, now func() time.Time) ([]byte, *RunError) {
	phase := "pbp-qualifying-soak"
	if !host.Disposable {
		return nil, blocked(phase, "lab_not_disposable", "the qualifying VPN fault injection is not authorized", "Set disposable: true only for the explicitly rebuildable PBP host.")
	}
	phaseStarted := now().UTC()
	timeout := runner.SoakTimeout
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}
	if timeout < time.Duration(MinimumSoakSeconds)*time.Second {
		return nil, failed(phase, "pbp_soak_policy", "configured wait bound is shorter than the qualifying soak minimum", "Use an unmodified flow binary with a wait bound of at least 1800 seconds.")
	}
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	start, err := runner.Remote.Run(ctx, host, ActionPBPSoakStart)
	if err != nil || start.State != RemoteRunning {
		return nil, failed(phase, "pbp_soak_start", "the fixed malwarelab soak service did not start", "Open the pinned VNC tunnel, ensure the malwarelab XFCE session is active, and inspect sanitized PBP logs.")
	}
	// keep this value in its original location so a real time.Time retains its
	// monotonic component. Remote timestamps are evidence, but they must not be
	// able to make the local runner accept a run early.
	localStarted := now()
	interval := runner.PollInterval
	if interval <= 0 {
		interval = 20 * time.Second
	}
	deadline := localStarted.Add(timeout)
	completed := false
	var localCompleted time.Time
	polls := 0
	for now().Before(deadline) {
		polls++
		if err := runner.sleep(ctx, interval); err != nil {
			return nil, failed(phase, "lab_interrupted", "PBP soak wait was interrupted", "The remote bounded service may still be running; inspect it through the explicit lab workflow.")
		}
		poll, pollErr := runner.Remote.Run(ctx, host, ActionPBPSoakPoll)
		if pollErr != nil {
			// the explicitly armed fail-closed phase can temporarily remove the
			// management route. only the overall deadline may turn this into PASS/FAIL.
			if polls%3 == 0 {
				runner.emit(Progress{Phase: phase, Host: host.Name, Status: "waiting (VPN fail-closed may temporarily remove SSH)"})
			}
			continue
		}
		switch poll.State {
		case RemoteRunning:
			if polls%3 == 0 {
				runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running (wall-clock soak)"})
			}
			continue
		case RemoteComplete:
			completed = true
			localCompleted = now()
		default:
			return nil, failed(phase, "pbp_soak_protocol", "soak poll returned an invalid finite state", "Inspect the bounded transient service and its journal.")
		}
		break
	}
	if !completed {
		return nil, failed(phase, "pbp_soak_timeout", "qualifying soak did not complete before the 60-minute bound", "Use the provider console if Mullvad recovery failed; inspect the secure remote result and PBP logs.")
	}
	forensicsErr := runner.runPBPForensics(ctx, report, host, now)
	result, err := runner.Remote.Run(ctx, host, ActionPBPSoakResult)
	if err != nil || result.State != RemoteComplete {
		return nil, failed(phase, "pbp_soak_result", "the secure remote soak result could not be read", "Inspect the fixed malwarelab test-results directory through the provider console.")
	}
	resultData := append([]byte(nil), result.Data...)
	report.PBPResultRemoteBytes = len(resultData)
	resultDigest := sha256.Sum256(resultData)
	report.PBPResultSHA256 = fmt.Sprintf("sha256:%x", resultDigest)
	localElapsed := localCompleted.Sub(localStarted)
	if localElapsed < time.Duration(MinimumSoakSeconds)*time.Second {
		return resultData, failed(phase, "pbp_soak_local_duration", "the remote service completed before the local runner observed at least 1800 seconds after start acknowledgement", "Treat PBP as unqualified; inspect the preserved remote result, verify the remote service and clocks, then repeat the full 30-minute run.")
	}
	evidence, err := ValidateQualifyingSoak(resultData)
	if err != nil {
		return resultData, failed(phase, "pbp_soak_not_qualifying", err.Error(), "Treat PBP as unqualified; inspect the preserved secure result and sanitized logs, repair the cause, then repeat the full 30-minute run.")
	}
	evidence += fmt.Sprintf("; local runner observed %ds after start acknowledgement", int(localElapsed/time.Second))
	report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "PASS", StartedAt: phaseStarted, FinishedAt: now().UTC(), Evidence: evidence})
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
	if forensicsErr != nil {
		return resultData, forensicsErr
	}
	return resultData, nil
}

func (runner Runner) runPBPForensics(ctx context.Context, report *Report, host Host, now func() time.Time) *RunError {
	phase := "pbp-forensics"
	started := now().UTC()
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "running"})
	result, err := runner.Remote.Run(ctx, host, ActionPBPForensics)
	finished := now().UTC()
	failForensics := func(code, message, next string) *RunError {
		report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "FAIL", StartedAt: started, FinishedAt: finished})
		runner.emit(Progress{Phase: phase, Host: host.Name, Status: "failed"})
		return failed(phase, code, message, next)
	}
	if err != nil || result.State != RemoteComplete {
		return failForensics("pbp_forensics_remote", "the fixed bounded PBP forensics action did not return evidence", "Inspect the preserved soak result and use the provider console; do not replace this phase with a free-form command.")
	}
	evidence, validationErr := ValidatePBPForensics(result.Data)
	if validationErr != nil {
		return failForensics("pbp_forensics_invalid", validationErr.Error(), "Treat PBP as unqualified; preserve the soak result, repair the evidence source, then repeat the full qualifying soak and fixed forensics phase.")
	}
	digest := sha256.Sum256(result.Data)
	report.PBPForensics = &evidence
	report.PBPForensicsSHA256 = fmt.Sprintf("sha256:%x", digest)
	report.PBPForensicsRemoteBytes = len(result.Data)
	report.Phases = append(report.Phases, PhaseResult{Name: phase, Host: host.Name, Status: "PASS", StartedAt: started, FinishedAt: finished, Evidence: "canonical bounded forensics validated: session, loopback VNC, profile locks, persona, runtime events, kernel/coredump metadata, and unit states"})
	runner.emit(Progress{Phase: phase, Host: host.Name, Status: "passed"})
	return nil
}

func (runner Runner) emit(progress Progress) {
	if runner.Progress != nil {
		runner.Progress(progress)
	}
}

func (runner Runner) sleep(ctx context.Context, duration time.Duration) error {
	if runner.Sleep != nil {
		return runner.Sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func requiredRoles() []string {
	return []string{"serving", "enrollment", "pbp", "recovery-negative"}
}

func validateE2EInventory(inventory Inventory) (map[string]Host, *RunError) {
	if inventory.Version != 2 {
		return nil, blocked("local-preflight", "lab_inventory_version", "lab qualification requires inventory version 2", "Regenerate the private inventory from the current runbook.")
	}
	if len(inventory.Hosts) != len(requiredRoles()) {
		return nil, blocked("local-preflight", "lab_roles", fmt.Sprintf("lab requires exactly four hosts, found %d", len(inventory.Hosts)), "Keep exactly one host for each documented role.")
	}
	allowed := map[string]bool{}
	for _, role := range requiredRoles() {
		allowed[role] = true
	}
	result := make(map[string]Host, len(inventory.Hosts))
	nonDisposable := []string{}
	for _, host := range inventory.Hosts {
		if !allowed[host.Role] || result[host.Role].Name != "" {
			return nil, blocked("local-preflight", "lab_roles", "lab roles are missing, duplicated, or unsupported", "Keep exactly one serving, enrollment, pbp, and recovery-negative role.")
		}
		result[host.Role] = host
		if !host.Disposable {
			nonDisposable = append(nonDisposable, host.Name)
		}
	}
	if len(result) != len(requiredRoles()) {
		return nil, blocked("local-preflight", "lab_roles", "lab roles are incomplete", "Keep exactly one serving, enrollment, pbp, and recovery-negative role.")
	}
	if len(nonDisposable) != 0 {
		sort.Strings(nonDisposable)
		return nil, blocked("local-preflight", "lab_not_disposable", "mutation is not authorized for: "+strings.Join(nonDisposable, ", "), "Set disposable: true only after explicitly authorizing rebuildable lab hosts.")
	}
	unconfirmed := []string{}
	missing := []string{}
	for _, role := range requiredRoles() {
		host := result[role]
		if !host.HostKeyVerifiedOutOfBand {
			unconfirmed = append(unconfirmed, host.Name)
		}
		if gates := MissingAttestations(host); len(gates) != 0 {
			missing = append(missing, host.Name+":"+strings.Join(gates, ","))
		}
	}
	if len(unconfirmed) != 0 {
		return nil, blocked("local-preflight", "lab_hostkey_unconfirmed", "out-of-band Ed25519 host-key confirmation is missing for: "+strings.Join(unconfirmed, ", "), "Verify every fingerprint through the provider console, then set host_key_verified_out_of_band: true.")
	}
	if len(missing) != 0 {
		return nil, blocked("local-preflight", "lab_attestations_missing", "required external qualification attestations are missing: "+strings.Join(missing, "; "), "Complete the role-bound console tests and add only the exact attested_gates tokens documented in the runbook.")
	}
	return result, nil
}

func blocked(phase, code, message, next string) *RunError {
	return &RunError{Code: code, Phase: phase, Message: message, Next: next, Blocked: true}
}

func failed(phase, code, message, next string) *RunError {
	return &RunError{Code: code, Phase: phase, Message: message, Next: next}
}

func nextForAction(action Action, host string) string {
	switch action {
	case ActionServingProbe, ActionServingReconcile, ActionServingRestart:
		return "Inspect dynamicflow-serving.service and its sanitized journal on " + host + "."
	case ActionRuntimeProbe, ActionEnrollmentProbe:
		return "Run flow instance status/logs and inspect the protected target runtime state on " + host + "."
	case ActionRecoveryProbe, ActionApplyConcurrency:
		return "Inspect the protected apply journal, verification events, runtime recovery copies and fixed reconcile unit on " + host + "."
	case ActionVNCProbe:
		return "Keep port 5901 closed publicly; inspect TigerVNC/XFCE through the pinned SSH tunnel on " + host + "."
	case ActionPBPProbe, ActionPBPIdentity, ActionPBPSoakStart, ActionPBPSoakPoll, ActionPBPSoakResult, ActionPBPForensics:
		return "Inspect Mullvad, the malwarelab VNC session, and sanitized PBP logs on " + host + "."
	default:
		return "Use the provider console and pinned flow instance access to inspect " + host + "."
	}
}

type soakResult struct {
	Schema        int                    `json:"schema"`
	Test          string                 `json:"test"`
	StartedAt     string                 `json:"started_at"`
	FinishedAt    string                 `json:"finished_at"`
	Status        string                 `json:"status"`
	Configuration soakConfiguration      `json:"configuration"`
	Phases        []soakPhase            `json:"phases"`
	Summary       map[string]interface{} `json:"summary"`
}

type soakConfiguration struct {
	DurationSeconds        int  `json:"duration_seconds"`
	MinimumDurationSeconds int  `json:"minimum_duration_seconds"`
	NormalCycles           int  `json:"normal_cycles"`
	VPNFailureArmed        bool `json:"vpn_failure_armed"`
	QualifyingDuration     bool `json:"qualifying_duration"`
}

type soakPhase struct {
	Name       string                 `json:"name"`
	Status     string                 `json:"status"`
	StartedAt  string                 `json:"started_at"`
	FinishedAt string                 `json:"finished_at"`
	Detail     string                 `json:"detail"`
	Metrics    map[string]interface{} `json:"metrics"`
}

func ValidateQualifyingSoak(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return "", errors.New("PBP result is empty or exceeds the 1 MiB bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var result soakResult
	if err := decoder.Decode(&result); err != nil {
		return "", errors.New("PBP result is not the strict schema")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("PBP result has trailing content")
	}
	if result.Schema != 1 || result.Test != "pbp-real-vm-soak" || result.Status != "PASS" ||
		result.Configuration.DurationSeconds < MinimumSoakSeconds ||
		result.Configuration.MinimumDurationSeconds != MinimumSoakSeconds ||
		result.Configuration.NormalCycles < 3 || result.Configuration.NormalCycles != NormalCloseCycles ||
		!result.Configuration.VPNFailureArmed || !result.Configuration.QualifyingDuration {
		return "", errors.New("PBP result does not contain the fixed qualifying configuration")
	}
	started, startErr := time.Parse(time.RFC3339, result.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339, result.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Sub(started) < time.Duration(MinimumSoakSeconds)*time.Second {
		return "", errors.New("PBP result does not prove at least 1800 wall-clock seconds")
	}
	required := requiredSoakPhaseNames()
	if len(result.Phases) != len(required) {
		return "", errors.New("PBP result does not contain the exact required phase set")
	}
	phases := make(map[string]soakPhase, len(result.Phases))
	phaseTimes := make(map[string][2]time.Time, len(result.Phases))
	previousFinished := started
	for index, phase := range result.Phases {
		if phase.Name != required[index] || phase.Status != "PASS" || phase.Detail != "real-VM assertions passed" {
			return "", errors.New("PBP result phases are missing, reordered, duplicated, or non-PASS")
		}
		phaseStarted, phaseStartErr := time.Parse(time.RFC3339, phase.StartedAt)
		phaseFinished, phaseFinishErr := time.Parse(time.RFC3339, phase.FinishedAt)
		if phaseStartErr != nil || phaseFinishErr != nil {
			return "", fmt.Errorf("PBP result phase %s has invalid timestamps", phase.Name)
		}
		if phaseStarted.Before(started) || phaseFinished.Before(phaseStarted) ||
			phaseStarted.Before(previousFinished) || phaseFinished.After(finished) {
			return "", fmt.Errorf("PBP result phase %s is outside the ordered result timeline", phase.Name)
		}
		phases[phase.Name] = phase
		phaseTimes[phase.Name] = [2]time.Time{phaseStarted, phaseFinished}
		previousFinished = phaseFinished
	}
	soakTimes := phaseTimes["thirty_minute_soak"]
	if soakTimes[1].Sub(soakTimes[0]) < time.Duration(MinimumSoakSeconds)*time.Second {
		return "", errors.New("PBP soak phase timestamps do not prove at least 1800 wall-clock seconds")
	}
	unexpectedExit := metricInt(phases["unexpected_browser_process_exit"], "launcher_exit_code")
	vpnExit := metricInt(phases["vpn_real_disconnect_fail_closed"], "launcher_exit_code")
	retainedLogs := metricInt(phases["log_rotation_redaction"], "retained_logs")
	if !metricBool(phases["preflight"], "pinned_release") ||
		!metricBool(phases["preflight"], "egress_verified") ||
		!metricBool(phases["thirty_minute_soak"], "minimum_30_minutes") ||
		metricInt(phases["thirty_minute_soak"], "wall_clock_seconds") < MinimumSoakSeconds ||
		!metricBool(phases["thirty_minute_soak"], "visible_lock_dialog") ||
		metricInt(phases["thirty_minute_soak"], "egress_checks") <= 0 ||
		metricInt(phases["thirty_minute_soak"], "transient_egress_checks") < 0 ||
		!metricBool(phases["unexpected_browser_process_exit"], "browser_sigkill") ||
		!metricBool(phases["unexpected_browser_process_exit"], "visible_dialog") ||
		(unexpectedExit != 21 && unexpectedExit != 23) ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "real_disconnect") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "offline_signal") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "visible_dialog") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "transient_retry_observed") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "bounded_backoff_observed") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "real_relay_switch") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "egress_identity_changed") ||
		!metricBool(phases["vpn_real_disconnect_fail_closed"], "restart_after_relay_switch") ||
		metricInt(phases["vpn_real_disconnect_fail_closed"], "retry_window_seconds") < 25 || vpnExit != 22 ||
		!metricBool(phases["log_rotation_redaction"], "retention_bounded") ||
		!metricBool(phases["log_rotation_redaction"], "redaction_checked") ||
		metricInt(phases["log_rotation_redaction"], "distinct_logs_observed") < NormalCloseCycles+4 ||
		retainedLogs <= 0 || retainedLogs > 8 ||
		!mapBool(result.Summary, "qualifying_real_vm_pass") || !mapBool(result.Summary, "no_secrets_recorded") ||
		mapInt(result.Summary, "egress_checks") <= 0 ||
		mapInt(result.Summary, "distinct_logs_observed") < NormalCloseCycles+4 {
		return "", errors.New("PBP result is missing pinned-release, egress, crash, visible-error, retry, fail-closed, or bounded-redacted-log evidence")
	}
	for cycle := 1; cycle <= NormalCloseCycles; cycle++ {
		phase := phases[fmt.Sprintf("normal_close_restart_%d", cycle)]
		if metricInt(phase, "cycle") != cycle || !metricBool(phase, "normal_exit") || !metricBool(phase, "lock_reacquired") {
			return "", errors.New("PBP result does not prove all close/restart lock cycles")
		}
	}
	if containsSensitiveResult(result) {
		return "", errors.New("PBP result contains a prohibited secret-like field")
	}
	return fmt.Sprintf("real PASS: %ds minimum, %d close cycles, SIGKILL/visible errors, armed VPN fail-closed and changed Mullvad egress", MinimumSoakSeconds, NormalCloseCycles), nil
}

func metricBool(phase soakPhase, key string) bool { return mapBool(phase.Metrics, key) }

func mapBool(values map[string]interface{}, key string) bool {
	value, ok := values[key].(bool)
	return ok && value
}

func metricInt(phase soakPhase, key string) int { return mapInt(phase.Metrics, key) }

func mapInt(values map[string]interface{}, key string) int {
	value, ok := values[key].(json.Number)
	if !ok {
		return -1
	}
	number, err := value.Int64()
	if err != nil || number < 0 || number > 1<<31-1 {
		return -1
	}
	return int(number)
}

func containsSensitiveResult(result soakResult) bool {
	prohibited := map[string]bool{"ip": true, "address": true, "url": true, "persona": true, "password": true, "secret": true, "token": true, "account": true}
	var walk func(interface{}) bool
	walk = func(value interface{}) bool {
		switch typed := value.(type) {
		case map[string]interface{}:
			for key, nested := range typed {
				if prohibited[strings.ToLower(key)] || walk(nested) {
					return true
				}
			}
		case []interface{}:
			for _, nested := range typed {
				if walk(nested) {
					return true
				}
			}
		case string:
			lower := strings.ToLower(typed)
			return strings.Contains(lower, "http://") || strings.Contains(lower, "https://") ||
				strings.Contains(lower, "password=") || strings.Contains(lower, "secret=") || strings.Contains(lower, "token=")
		}
		return false
	}
	for _, phase := range result.Phases {
		if walk(phase.Metrics) {
			return true
		}
	}
	return walk(result.Summary)
}

func requiredSoakPhaseNames() []string {
	names := make([]string, 0, NormalCloseCycles+5)
	names = append(names, "preflight")
	for cycle := 1; cycle <= NormalCloseCycles; cycle++ {
		names = append(names, fmt.Sprintf("normal_close_restart_%d", cycle))
	}
	return append(names, "thirty_minute_soak", "unexpected_browser_process_exit", "vpn_real_disconnect_fail_closed", "log_rotation_redaction")
}
