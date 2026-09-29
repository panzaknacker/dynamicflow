package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instances"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
)

var lifecycleInstanceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func instanceHTTPSLifecycle(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow instance <status|logs|apply> NAME")
	}
	switch args[0] {
	case "status":
		return instanceStatusHTTPS(ctx, args[1:])
	case "apply":
		return instanceApplyHTTPS(ctx, args[1:])
	case "logs":
		return instanceLogsHTTPS(ctx, args[1:])
	default:
		return usage(ctx, "unknown HTTPS instance lifecycle command")
	}
}

func instanceStatusHTTPS(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("instance status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) {
		return usage(ctx, "usage: flow instance status NAME")
	}
	name := flags.Arg(0)
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var report serving.StatusReport
	err = remote.controlJSON(operation, http.MethodGet, "/v1/admin/instances/"+name+"/status", nil, &report, http.StatusOK)
	if err != nil {
		var remoteErr *operatorHTTPError
		if errors.As(err, &remoteErr) && remoteErr.Status == http.StatusNotFound && remoteErr.Code == "status_not_found" {
			var desired enrollment.SignedDesiredState
			if desiredErr := remote.controlJSON(operation, http.MethodGet, "/v1/admin/instances/"+name+"/desired", nil, &desired, http.StatusOK); desiredErr != nil {
				return ctx.out.fail("status", safeRemoteError(desiredErr), "Verify the enrollment name and serving state.", exitRemote)
			}
			data := map[string]any{"instance": name, "state": "pending", "reported": false, "desired": desired.State}
			return ctx.out.success("instance.status", data, fmt.Sprintf("%s: pending; no signed status report has arrived yet (desired generation %d)", name, desired.State.Generation))
		}
		return ctx.out.fail("status", safeRemoteError(err), "Check serving status and the instance's outbound HTTPS path.", exitRemote)
	}
	if report.Instance != name {
		return ctx.out.fail("verification", "status instance binding mismatch", "Do not trust the report; inspect serving state.", exitVerify)
	}
	sshPinned := false
	sshHostKeyFingerprint := ""
	if report.SSHHostKey != "" {
		_, fingerprint, keyErr := sshkeys.ValidateEd25519PublicKey(report.SSHHostKey)
		if keyErr != nil {
			return ctx.out.fail("ssh_host_key", "status contained an invalid Ed25519 host key", "Do not trust the report; inspect serving and target state.", exitVerify)
		}
		sshHostKeyFingerprint = fingerprint
		pinned, pinErr := instanceManager(ctx).Get(name)
		switch {
		case pinErr == nil:
			if pinned.HostKey != report.SSHHostKey {
				return ctx.out.fail("ssh_host_key", instances.ErrHostKeyChanged.Error(), "Do not use SSH; verify the new key through the provider console and use the explicit hostkey rotate command.", exitVerify)
			}
			sshPinned = true
		case errors.Is(pinErr, instances.ErrNotFound):
			// a serving node verifies the target request, but a compromised
			// serving node can still fabricate its stored status response.
			// initial SSH trust therefore requires an independent provider-
			// console key and the explicit hostkey pin command.
		default:
			return ctx.out.fail("ssh_host_key", pinErr.Error(), "Repair local pinned-host metadata before using SSH.", exitConfig)
		}
	}
	stale := time.Now().UTC().Unix()-report.ReportedAt > 15*60
	data := map[string]any{
		"report": report, "stale": stale, "ssh_host_key_pinned": sshPinned,
		"reported_ssh_host_key_fingerprint": sshHostKeyFingerprint,
	}
	human := fmt.Sprintf("%s: %s; applied=%d desired=%d; reported=%s", name, report.State, report.AppliedGeneration, report.DesiredGeneration, time.Unix(report.ReportedAt, 0).UTC().Format(time.RFC3339))
	if stale {
		human += " (STALE)"
	}
	if report.SSHHostKey != "" && !sshPinned {
		human += "\nSSH remains blocked: verify the Ed25519 host key through the provider console, then run flow instance hostkey pin."
	}
	return ctx.out.success("instance.status", data, human)
}

func instanceBind(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("instance bind", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	host := flags.String("host", "", "reachable SSH host or address")
	sshUser := flags.String("ssh-user", "", "existing non-root SSH administrator")
	sshPort := flags.Int("ssh-port", 22, "SSH port")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) || *host == "" || *sshUser == "" {
		return usage(ctx, "usage: flow instance bind NAME --host HOST --ssh-user USER [--ssh-port 22]")
	}
	normalized, err := instances.ValidateEndpoint(*host, *sshUser, *sshPort)
	if err != nil {
		return ctx.out.fail("ssh_endpoint", err.Error(), "Provide a reachable host, non-root administrator and port 1..65535.", exitConfig)
	}
	local, err := loadLocalEnrollment(ctx, flags.Arg(0))
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Create the enrollment on this operator first.", exitConfig)
	}
	if local.State == "revoked" {
		return ctx.out.fail("revoked", "instance is locally revoked", "Create a new instance rather than rebinding revoked trust.", exitConflict)
	}
	manager := instanceManager(ctx)
	pinned, pinnedErr := manager.Get(local.Name)
	if pinnedErr != nil && !errors.Is(pinnedErr, instances.ErrNotFound) {
		return ctx.out.fail("ssh_host_key", pinnedErr.Error(), "Repair local pinned-host metadata before rebinding its destination.", exitConfig)
	}
	local.Host, local.SSHUser, local.SSHPort = normalized, *sshUser, *sshPort
	local.UpdatedAt = time.Now().UTC()
	if err := saveLocalEnrollment(ctx, local); err != nil {
		return ctx.out.fail("state", err.Error(), "Repair local state permissions.", exitConfig)
	}
	hostKeyPinned := pinnedErr == nil
	if hostKeyPinned {
		if _, err := manager.Put(instances.Record{
			Name: local.Name, Profile: local.Profile, Host: normalized, SSHPort: *sshPort,
			SSHUser: *sshUser, Key: pinned.Key, HostKey: pinned.HostKey,
		}); err != nil {
			return ctx.out.fail("state_partial", "endpoint was stored but pinned known_hosts could not be rebound", "Retry the same explicit bind after repairing local instance metadata.", exitPartial)
		}
	}
	audit(ctx, "instance.bind", "success", map[string]any{
		"instance": local.Name, "host": normalized, "ssh_user": *sshUser,
		"ssh_port": *sshPort, "host_key_pinned": hostKeyPinned,
	})
	human := "Stored the SSH endpoint without contacting it. Verify the Ed25519 host key through the provider console, then run flow instance hostkey pin."
	if hostKeyPinned {
		human = "Rebound the SSH endpoint without contacting it; the existing explicitly pinned Ed25519 host key was retained."
	}
	return ctx.out.success("instance.bind", map[string]any{
		"instance": local.Name, "host": normalized, "ssh_user": *sshUser, "ssh_port": *sshPort,
		"host_key_pinned": hostKeyPinned, "network_connection": false,
	}, human)
}

func instanceApplyHTTPS(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("instance apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "target profile")
	plan := flags.Bool("plan", false, "preview without publishing desired state")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) || *profile == "" {
		return usage(ctx, "usage: flow instance apply NAME --profile PROFILE [--plan]")
	}
	name := flags.Arg(0)
	local, err := loadLocalEnrollment(ctx, name)
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Create the enrollment on this operator or restore its public metadata.", exitConfig)
	}
	if local.State == "revoked" {
		return ctx.out.fail("revoked", "instance is locally revoked", "Create a new instance identity rather than silently reusing revoked trust.", exitConflict)
	}
	if *profile != local.Profile {
		return ctx.out.fail(
			"profile_transition_unsupported",
			fmt.Sprintf("instance is bound to profile %s; publishing %s would strand the current target runtime", local.Profile, *profile),
			"Enroll a new instance with the target profile; signed in-place profile transitions are not enabled yet.",
			exitConflict,
		)
	}
	registry, err := loadProfiles(ctx)
	if err != nil {
		return ctx.out.fail("profile", err.Error(), "Repair the profile graph.", exitConfig)
	}
	resolved, err := registry.Resolve(*profile)
	if err != nil {
		return ctx.out.fail("profile", err.Error(), "Choose a profile shown by flow profile list.", exitConfig)
	}
	requested, _ := registry.Get(*profile)
	if !requested.Installable {
		return ctx.out.fail("profile_unavailable", "profile is declarative-only and has no fixed target executor", "Choose an installable profile.", exitConfig)
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	current, desired, err := fetchAndVerifyOperatorState(ctx, remote, operation, name)
	if err != nil {
		return ctx.out.fail("verification", err.Error(), "Do not apply until release and desired-state signatures verify.", exitVerify)
	}
	if !releaseHasProfile(current.Manifest, *profile) {
		return ctx.out.fail("profile", "profile is not present in the active signed release", "Publish a release containing the profile.", exitVerify)
	}
	manager := sshkeys.NewManager(ctx.store)
	activeKey, err := manager.Get(local.KeyScope, local.KeyName)
	if err != nil || activeKey.Status != sshkeys.ActiveStatus {
		return ctx.out.fail("ssh_key", fmt.Sprintf("active key unavailable: %v", err), "Restore or rotate the local SSH key explicitly.", exitAuth)
	}
	keys := []string{activeKey.PublicKey}
	rotationPending := local.RotationPending
	rotationStarted := false
	switch {
	case activeKey.Generation < local.KeyGeneration:
		return ctx.out.fail("ssh_key", "active SSH key generation is below the local instance checkpoint", "Repair local key metadata before publishing desired state.", exitConflict)
	case activeKey.Generation > local.KeyGeneration:
		if activeKey.Generation-local.KeyGeneration != 1 || local.RotationPending {
			return ctx.out.fail("ssh_key", "more than one unfinalized SSH key generation would create a lockout window", "Do not publish; recover the immediately previous instance key checkpoint.", exitConflict)
		}
		rotationStarted = true
		keys = canonicalSSHKeys(append(append([]string{}, desired.State.AuthorizedSSHKeys...), activeKey.PublicKey))
		rotationPending = true
	case rotationPending:
		keys = append([]string(nil), desired.State.AuthorizedSSHKeys...)
		if len(keys) < 2 || !containsString(keys, activeKey.PublicKey) {
			return ctx.out.fail("rotation_pending", "signed overlap state is inconsistent with the active key", "Do not remove any key; repair local signed rotation metadata.", exitConflict)
		}
	}
	now := time.Now().UTC()
	nextState := enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: name, Profile: *profile,
		Generation: desired.State.Generation + 1, ReleaseSet: current.Manifest.SetID,
		AuthorizedSSHKeys: keys, IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	desiredPrivate, _, err := loadDesiredSigner(ctx, remote)
	if err != nil {
		return ctx.out.fail("desired_signing", err.Error(), "Restore the desired-state signing key.", exitAuth)
	}
	next, err := enrollment.SignDesiredState(nextState, desiredPrivate)
	if err != nil {
		return ctx.out.fail("desired_signing", err.Error(), "Validate profile and SSH public key metadata.", exitVerify)
	}
	data := map[string]any{
		"plan": *plan, "instance": name, "profile": *profile, "generation": next.State.Generation,
		"release_set": next.State.ReleaseSet, "resolved_profiles": resolved, "authorized_key_count": len(keys),
		"rotation_overlap": rotationPending, "rotation_started": rotationStarted, "operation": "signed-desired-state-over-https",
	}
	if *plan {
		return ctx.out.success("instance.apply.plan", data, fmt.Sprintf("PLAN: publish signed desired generation %d for %s; profile graph: %v", next.State.Generation, name, resolved))
	}
	if err := audit(ctx, "instance.apply", "started", map[string]any{"instance": name, "profile": *profile, "generation": next.State.Generation}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; desired state was not published", "Repair the private audit log and retry.", exitFailure)
	}
	if err := remote.controlJSON(operation, http.MethodPut, "/v1/admin/instances/"+name+"/desired", next, nil, http.StatusAccepted); err != nil {
		return ctx.out.fail("apply", safeRemoteError(err), "No SSH fallback was attempted; inspect serving and retry the same signed generation.", exitRemote)
	}
	local.Profile, local.Desired, local.KeyGeneration, local.RotationPending = *profile, next, activeKey.Generation, rotationPending
	local.UpdatedAt = time.Now().UTC()
	if err := saveLocalEnrollment(ctx, local); err != nil {
		return ctx.out.fail("state", err.Error(), "Desired state is published; recover local public metadata from serving before another apply.", exitPartial)
	}
	audit(ctx, "instance.apply", "success", map[string]any{"instance": name, "profile": *profile, "generation": next.State.Generation, "release_set": next.State.ReleaseSet})
	return ctx.out.success("instance.apply", data, fmt.Sprintf("Published desired generation %d for %s; the instance will reconcile over outbound HTTPS.", next.State.Generation, name))
}

func instanceKeyHTTPS(ctx *commandContext, args []string) int {
	if len(args) == 0 || args[0] != "finalize" {
		return usage(ctx, "usage: flow instance key finalize NAME [--plan]")
	}
	flags := flag.NewFlagSet("instance key finalize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.Bool("plan", false, "preview the pinned-SSH proof and signed removal")
	if err := parseInterspersed(flags, args[1:]); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) {
		return usage(ctx, "usage: flow instance key finalize NAME [--plan]")
	}
	name := flags.Arg(0)
	local, err := loadLocalEnrollment(ctx, name)
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Restore the local enrollment checkpoint.", exitConfig)
	}
	if local.State == "revoked" || !local.RotationPending {
		return ctx.out.fail("rotation_state", "instance has no live SSH overlap to finalize", "Rotate and publish exactly one new instance key first.", exitConflict)
	}
	keyManager := sshkeys.NewManager(ctx.store)
	active, err := keyManager.Get(local.KeyScope, local.KeyName)
	if err != nil || active.Status != sshkeys.ActiveStatus || active.Generation != local.KeyGeneration {
		return ctx.out.fail("ssh_key", "active SSH key does not match the published overlap checkpoint", "Repair the local instance key checkpoint without publishing removal.", exitConflict)
	}
	instanceRecord, err := instanceManager(ctx).Get(name)
	if err != nil || instanceRecord.Key.Scope != local.KeyScope || instanceRecord.Key.Name != local.KeyName {
		return ctx.out.fail("ssh_key", "pinned instance identity differs from enrollment metadata", "Repair local pinned instance metadata.", exitConfig)
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	fetchContext, fetchCancel := context.WithTimeout(context.Background(), 30*time.Second)
	current, desired, err := fetchAndVerifyOperatorState(ctx, remote, fetchContext, name)
	fetchCancel()
	if err != nil {
		return ctx.out.fail("verification", err.Error(), "Do not finalize until signed release and overlap state verify.", exitVerify)
	}
	if len(desired.State.AuthorizedSSHKeys) < 2 || !containsString(desired.State.AuthorizedSSHKeys, active.PublicKey) {
		return ctx.out.fail("rotation_state", "remote signed desired state is not the expected overlap", "Keep the old key and repair the signed overlap.", exitConflict)
	}
	data := map[string]any{
		"plan": *plan, "instance": name, "active_key_generation": active.Generation,
		"current_desired_generation": desired.State.Generation,
		"next_desired_generation":    desired.State.Generation + 1,
		"proof":                      "explicit-pinned-ssh-active-key-only",
	}
	if *plan {
		return ctx.out.success("instance.key.finalize.plan", data, "PLAN: prove the active key over pinned SSH, then publish removal of the previous key.")
	}
	sshArguments, err := instanceManager(ctx).SSHArgs(name)
	if err != nil {
		return ctx.out.fail("ssh", err.Error(), "Repair the active identity and pinned known_hosts entry.", exitConfig)
	}
	sshArguments = append(sshArguments, "/bin/true")
	proofContext, proofCancel := context.WithTimeout(context.Background(), 45*time.Second)
	command := exec.CommandContext(proofContext, "ssh", sshArguments...)
	command.Stdin = nil
	var proofOutput bytes.Buffer
	command.Stdout = &limitedWriter{writer: &proofOutput, remaining: 1 << 20}
	command.Stderr = &limitedWriter{writer: &proofOutput, remaining: 1 << 20}
	if err := audit(ctx, "instance.key.finalize", "proof_started", map[string]any{"instance": name, "generation": active.Generation}); err != nil {
		proofCancel()
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; SSH proof was not started", "Repair the private audit log and retry.", exitFailure)
	}
	proofErr := command.Run()
	proofCancel()
	if proofErr != nil {
		audit(ctx, "instance.key.finalize", "proof_failed", map[string]any{"instance": name, "generation": active.Generation})
		return ctx.out.fail("ssh_key_proof", "the active key was not accepted over the pinned SSH host identity", "Wait for outbound HTTPS reconciliation, then retry this explicit finalization.", exitRemote)
	}
	now := time.Now().UTC()
	nextState := enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: name, Profile: local.Profile,
		Generation: desired.State.Generation + 1, ReleaseSet: current.Manifest.SetID,
		AuthorizedSSHKeys: []string{active.PublicKey}, IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
	}
	private, _, err := loadDesiredSigner(ctx, remote)
	if err != nil {
		return ctx.out.fail("desired_signing", err.Error(), "Restore the desired-state signing key.", exitAuth)
	}
	next, err := enrollment.SignDesiredState(nextState, private)
	if err != nil {
		return ctx.out.fail("desired_signing", err.Error(), "Repair signed rotation metadata.", exitVerify)
	}
	publishContext, publishCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = remote.controlJSON(publishContext, http.MethodPut, "/v1/admin/instances/"+name+"/desired", next, nil, http.StatusAccepted)
	publishCancel()
	if err != nil {
		return ctx.out.fail("rotation_publish", safeRemoteError(err), "The previous key remains authorized; retry finalization without rotating again.", exitRemote)
	}
	local.Desired, local.RotationPending, local.UpdatedAt = next, false, time.Now().UTC()
	if err := saveLocalEnrollment(ctx, local); err != nil {
		return ctx.out.fail("state", "old-key removal was published but the local checkpoint was not committed", "Recover the signed desired state from serving before another key operation.", exitPartial)
	}
	audit(ctx, "instance.key.finalize", "success", map[string]any{"instance": name, "generation": active.Generation, "desired_generation": next.State.Generation})
	data["published"] = true
	return ctx.out.success("instance.key.finalize", data, fmt.Sprintf("Proved key generation %d over pinned SSH and published old-key removal.", active.Generation))
}

func instanceRevokeHTTPS(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("instance revoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) {
		return usage(ctx, "usage: flow instance revoke NAME")
	}
	name := flags.Arg(0)
	local, err := loadLocalEnrollment(ctx, name)
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Restore local enrollment metadata before revocation.", exitConfig)
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	current, desired, err := fetchAndVerifyOperatorState(ctx, remote, operation, name)
	if err != nil {
		return ctx.out.fail("verification", err.Error(), "Verify serving trust before revocation.", exitVerify)
	}
	if !desired.State.Revoked {
		now := time.Now().UTC()
		revokedState := enrollment.DesiredState{
			Schema: enrollment.DesiredStateSchema, Instance: name, Profile: desired.State.Profile,
			Generation: desired.State.Generation + 1, ReleaseSet: current.Manifest.SetID, Revoked: true,
			AuthorizedSSHKeys: nil, IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
		}
		private, _, signerErr := loadDesiredSigner(ctx, remote)
		if signerErr != nil {
			return ctx.out.fail("desired_signing", signerErr.Error(), "Restore the desired-state signing key.", exitAuth)
		}
		revoked, signerErr := enrollment.SignDesiredState(revokedState, private)
		if signerErr != nil {
			return ctx.out.fail("desired_signing", signerErr.Error(), "Inspect desired-state metadata.", exitVerify)
		}
		if err := audit(ctx, "instance.revoke", "started", map[string]any{"instance": name, "generation": revoked.State.Generation}); err != nil {
			return ctx.out.fail("audit_unavailable", "local audit event could not be committed; revocation was not published", "Repair the private audit log and retry.", exitFailure)
		}
		if err := remote.controlJSON(operation, http.MethodPut, "/v1/admin/instances/"+name+"/desired", revoked, nil, http.StatusAccepted); err != nil {
			return ctx.out.fail("revoke", safeRemoteError(err), "No local SSH trust was changed; fix serving connectivity and retry.", exitRemote)
		}
		local.Desired = revoked
	}
	local.State, local.UpdatedAt = "revoked", time.Now().UTC()
	if err := saveLocalEnrollment(ctx, local); err != nil {
		return ctx.out.fail("state", err.Error(), "Revocation is published; manually quarantine local SSH metadata.", exitPartial)
	}
	if local.KeyScope == sshkeys.Instance {
		_, _ = sshkeys.NewManager(ctx.store).Revoke(local.KeyScope, local.KeyName)
	}
	if _, getErr := instanceManager(ctx).Get(name); getErr == nil {
		_, _ = instanceManager(ctx).Revoke(name)
	}
	audit(ctx, "instance.revoke", "success", map[string]any{"instance": name, "generation": local.Desired.State.Generation})
	return ctx.out.success("instance.revoke", map[string]any{
		"instance": name, "desired_generation": local.Desired.State.Generation, "local_ssh_disabled": true, "remote_acknowledged": false,
	}, "Published fail-closed revocation for "+name+" and disabled its local SSH identity. Wait for status acknowledgement before considering the target remediated.")
}

func instanceLogsHTTPS(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("instance logs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	component := flags.String("component", "", "component name")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || !validLifecycleName(flags.Arg(0)) || (*component != "" && !validLifecycleName(*component)) {
		return usage(ctx, "usage: flow instance logs NAME [--component COMPONENT]")
	}
	name := flags.Arg(0)
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var snapshots []serving.LogSnapshot
	if *component != "" {
		var snapshot serving.LogSnapshot
		err = remote.controlJSON(operation, http.MethodGet, "/v1/admin/instances/"+name+"/logs/"+*component, nil, &snapshot, http.StatusOK)
		if err == nil {
			snapshots = []serving.LogSnapshot{snapshot}
		}
	} else {
		var response struct {
			Logs []serving.LogSnapshot `json:"logs"`
		}
		err = remote.controlJSON(operation, http.MethodGet, "/v1/admin/instances/"+name+"/logs", nil, &response, http.StatusOK)
		snapshots = response.Logs
	}
	if err != nil {
		var remoteErr *operatorHTTPError
		if errors.As(err, &remoteErr) && remoteErr.Status == http.StatusNotFound && remoteErr.Code == "logs_not_found" {
			return ctx.out.success("instance.logs", map[string]any{"instance": name, "logs": []serving.LogSnapshot{}}, name+": no sanitized component logs have been reported yet")
		}
		return ctx.out.fail("logs", safeRemoteError(err), "Check serving status and the instance's outbound HTTPS reconciliation.", exitRemote)
	}
	seenComponents := make(map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		_, duplicate := seenComponents[snapshot.Component]
		if serving.ValidateLogSnapshot(snapshot) != nil || snapshot.Instance != name ||
			(*component != "" && snapshot.Component != *component) || duplicate {
			return ctx.out.fail("verification", "serving returned a log snapshot with the wrong binding", "Do not trust the response; inspect serving state.", exitVerify)
		}
		seenComponents[snapshot.Component] = struct{}{}
	}
	data := map[string]any{"instance": name, "logs": snapshots, "sanitized": true}
	if ctx.out.json {
		return ctx.out.success("instance.logs", data, "")
	}
	for _, snapshot := range snapshots {
		fmt.Fprintf(ctx.out.stdout, "[%s]\n", snapshot.Component)
		for _, event := range snapshot.Events {
			code := ""
			if event.Code != "" {
				code = " code=" + event.Code
			}
			fmt.Fprintf(ctx.out.stdout, "%s %-8s %s%s seq=%d\n", time.Unix(event.Timestamp, 0).UTC().Format(time.RFC3339), event.Level, event.Event, code, event.Sequence)
		}
	}
	if len(snapshots) == 0 {
		fmt.Fprintf(ctx.out.stdout, "%s: no sanitized component logs have been reported yet\n", name)
	}
	return exitOK
}

func fetchAndVerifyOperatorState(ctx *commandContext, remote *remoteServing, operation context.Context, name string) (release.SignedManifest, enrollment.SignedDesiredState, error) {
	local, err := loadLocalEnrollment(ctx, name)
	if err != nil {
		return release.SignedManifest{}, enrollment.SignedDesiredState{}, err
	}
	var manifest release.SignedManifest
	if err := remote.publicJSON(operation, http.MethodGet, "/v1/releases/current/manifest", &manifest); err != nil {
		return manifest, enrollment.SignedDesiredState{}, err
	}
	releasePublicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
	releasePublic, err := signing.LoadPublicFile(releasePublicPath)
	if err != nil || release.VerifyManifest(manifest, releasePublic) != nil {
		return manifest, enrollment.SignedDesiredState{}, errors.New("active release signature failed")
	}
	if err := acceptOperatorReleaseHighWater(ctx, manifest.Manifest); err != nil {
		return manifest, enrollment.SignedDesiredState{}, err
	}
	var desired enrollment.SignedDesiredState
	if err := remote.controlJSON(operation, http.MethodGet, "/v1/admin/instances/"+name+"/desired", nil, &desired, http.StatusOK); err != nil {
		return manifest, desired, err
	}
	_, desiredPublic, err := loadDesiredSigner(ctx, remote)
	if err != nil {
		return manifest, desired, err
	}
	minimum := local.Desired.State.Generation
	if minimum == 0 {
		minimum = 1
	}
	if err := enrollment.VerifyDesiredStateForRenewal(desired, desiredPublic, enrollment.DesiredExpectation{
		Instance: name, Profile: local.Profile,
		MinGeneration: minimum, Now: time.Now().UTC(), MaxClockSkew: 5 * time.Minute,
	}); err != nil {
		return manifest, desired, err
	}
	if local.Desired.State.Generation == desired.State.Generation {
		localCanonical, localErr := signing.CanonicalJSON(local.Desired)
		remoteCanonical, remoteErr := signing.CanonicalJSON(desired)
		if localErr != nil || remoteErr != nil || !bytes.Equal(localCanonical, remoteCanonical) {
			return manifest, desired, errors.New("desired-state generation conflicts with the local signed checkpoint")
		}
	}
	return manifest, desired, nil
}

func loadDesiredSigner(ctx *commandContext, remote *remoteServing) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privatePath, _ := ctx.store.Path("keys/signing/desired-state.private.pem")
	publicPath, _ := ctx.store.Path("keys/signing/desired-state.public.pem")
	private, public, err := loadSigningPair(privatePath, publicPath)
	if err != nil {
		return nil, nil, err
	}
	identifier, _ := signing.KeyID(public)
	if identifier != remote.config.DesiredKeyID {
		return nil, nil, errors.New("desired-state signer differs from pinned serving trust")
	}
	return private, public, nil
}

func loadLocalEnrollment(ctx *commandContext, name string) (localEnrollment, error) {
	var local localEnrollment
	if !validLifecycleName(name) {
		return local, errors.New("invalid instance name")
	}
	if err := ctx.store.ReadJSON(filepath.Join("enrollments", name+".json"), &local); err != nil {
		return local, err
	}
	if local.Schema != 1 || local.Name != name || local.Profile == "" || local.KeyName == "" || local.KeyGeneration == 0 ||
		(local.State != "draft" && local.State != "issued" && local.State != "revoked") || local.Desired.State.Instance != name {
		return local, errors.New("invalid local enrollment metadata")
	}
	return local, nil
}

func saveLocalEnrollment(ctx *commandContext, local localEnrollment) error {
	if !validLifecycleName(local.Name) {
		return errors.New("invalid instance name")
	}
	return ctx.store.WriteJSON(filepath.Join("enrollments", local.Name+".json"), local)
}

func canonicalSSHKeys(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validLifecycleName(value string) bool {
	return value != "." && value != ".." && lifecycleInstanceName.MatchString(value)
}
