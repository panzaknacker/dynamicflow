package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/instances"
	"dynamicflow/internal/lab"
	"dynamicflow/internal/sshkeys"
)

type labScenario struct {
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Tests []string `json:"tests"`
}

func commandTest(ctx *commandContext, args []string) int {
	if len(args) == 0 || args[0] != "lab" {
		return usage(ctx, "usage: flow test lab [--inventory ABSOLUTE-PATH] [--plan]")
	}
	flags := newCommandFlagSet(ctx, "test lab")
	inventoryPath := flags.String("inventory", "", "private lab inventory")
	plan := flags.Bool("plan", false, "show the E2E plan without changing hosts")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow test lab [--inventory ABSOLUTE-PATH] [--plan]")
	}
	if *inventoryPath == "" {
		if ctx.sourceRoot == "" {
			return ctx.out.fail("config", "source root is required for the default lab inventory", "Pass --inventory with an absolute mode-0600 path.", exitConfig)
		}
		*inventoryPath = filepath.Join(ctx.sourceRoot, ".flow", "lab.yaml")
	}
	if !filepath.IsAbs(*inventoryPath) {
		return usage(ctx, "--inventory must be an absolute path")
	}
	inventory, err := lab.Load(*inventoryPath)
	if err != nil {
		return ctx.out.fail("lab_inventory", err.Error(), "Provide the version-2 private inventory fields, out-of-band host-key confirmation, and only the role-bound attestations documented in the lab runbook.", exitConfig)
	}
	scenarios := []labScenario{
		{Name: "serving", Role: "serving", Tests: []string{"HTTPS verified-release health", "service restart and VM reboot", "no outbound SSH"}},
		{Name: "enrollment", Role: "enrollment", Tests: []string{"attested fresh enrollment/replay/expiry", "public-key-only target", "signed key rotation", "reboot resume"}},
		{Name: "pbp", Role: "pbp", Tests: []string{"ssh-gui dependencies", "Mullvad DE/Shadowsocks 443/lockdown", "30-minute soak", "five close/restart cycles", "VPN fail-closed and relay recovery"}},
		{Name: "recovery", Role: "recovery-negative", Tests: []string{"attested signature/digest rejection", "interrupted apply evidence", "runtime handoff evidence", "parallel lock/resume", "reboot and revocation"}},
	}
	roleHosts := map[string][]string{}
	nonDisposable := []string{}
	unconfirmed := []string{}
	missingAttestations := map[string][]string{}
	for _, host := range inventory.Hosts {
		roleHosts[host.Role] = append(roleHosts[host.Role], host.Name)
		if !host.Disposable {
			nonDisposable = append(nonDisposable, host.Name)
		}
		if !host.HostKeyVerifiedOutOfBand {
			unconfirmed = append(unconfirmed, host.Name)
		}
		if missing := lab.MissingAttestations(host); len(missing) != 0 {
			missingAttestations[host.Name] = missing
		}
	}
	for index := range scenarios {
		hosts := roleHosts[scenarios[index].Role]
		if len(hosts) != 1 {
			return ctx.out.fail("lab_roles", fmt.Sprintf("role %s needs exactly one host, found %d", scenarios[index].Role, len(hosts)), "Update only the role field in the private inventory.", exitConfig)
		}
	}
	if len(inventory.Hosts) != len(scenarios) || len(roleHosts) != len(scenarios) {
		return ctx.out.fail("lab_roles", fmt.Sprintf("lab needs exactly four hosts and four roles, found %d hosts and %d roles", len(inventory.Hosts), len(roleHosts)), "Keep exactly one serving, enrollment, pbp, and recovery-negative host.", exitConfig)
	}
	sort.Strings(nonDisposable)
	sort.Strings(unconfirmed)
	type planHost struct {
		Name                 string `json:"name"`
		Role                 string `json:"role"`
		Address              string `json:"address"`
		SSHUser              string `json:"ssh_user"`
		OS                   string `json:"os"`
		Disposable           bool   `json:"disposable"`
		HostKeyConfirmed     bool   `json:"host_key_verified_out_of_band"`
		AttestationsComplete bool   `json:"attestations_complete"`
		Pinned               bool   `json:"pinned"`
	}
	planHosts := make([]planHost, 0, len(inventory.Hosts))
	unpinned := []string{}
	manager := instanceManager(ctx)
	for _, host := range inventory.Hosts {
		pinned := validateLabBinding(ctx, manager, host) == nil
		planHosts = append(planHosts, planHost{Name: host.Name, Role: host.Role, Address: host.Address, SSHUser: host.SSHUser, OS: host.OS, Disposable: host.Disposable, HostKeyConfirmed: host.HostKeyVerifiedOutOfBand, AttestationsComplete: len(lab.MissingAttestations(host)) == 0, Pinned: pinned})
		if !pinned {
			unpinned = append(unpinned, host.Name)
		}
	}
	sort.Strings(unpinned)
	data := map[string]any{"inventory": *inventoryPath, "hosts": planHosts, "scenarios": scenarios, "qualification_matrix": lab.QualificationMatrix(), "plan": true, "blocked_non_disposable": nonDisposable, "blocked_hostkey_unconfirmed": unconfirmed, "blocked_attestations": missingAttestations, "blocked_unpinned": unpinned}
	if *plan {
		lines := []string{"Four-VM E2E plan:"}
		for _, scenario := range scenarios {
			lines = append(lines, fmt.Sprintf("- %s (%s): %s", scenario.Name, strings.Join(roleHosts[scenario.Role], ","), strings.Join(scenario.Tests, ", ")))
		}
		if len(nonDisposable) != 0 {
			lines = append(lines, "Mutation blocked until explicitly disposable: "+strings.Join(nonDisposable, ", "))
		}
		if len(unconfirmed) != 0 {
			lines = append(lines, "Execution blocked until each Ed25519 fingerprint is confirmed out-of-band: "+strings.Join(unconfirmed, ", "))
		}
		if len(missingAttestations) != 0 {
			lines = append(lines, fmt.Sprintf("Execution blocked by %d host qualification-attestation set(s).", len(missingAttestations)))
		}
		if len(unpinned) != 0 {
			lines = append(lines, "Execution blocked until the confirmed Ed25519 host key matches pinned flow state: "+strings.Join(unpinned, ", "))
		}
		return ctx.out.success("test.lab.plan", data, strings.Join(lines, "\n"))
	}
	if len(nonDisposable) != 0 {
		_ = audit(ctx, "test.lab", "blocked", map[string]any{"non_disposable": nonDisposable})
		return ctx.out.fail("lab_not_disposable", "destructive E2E phases are not authorized for: "+strings.Join(nonDisposable, ", "), "Set disposable: true only for hosts that may be rebuilt; flow performed no host mutation.", exitConflict)
	}
	if len(unconfirmed) != 0 {
		_ = audit(ctx, "test.lab", "blocked", map[string]any{"hostkey_unconfirmed": len(unconfirmed)})
		return ctx.out.fail("lab_hostkey_unconfirmed", "out-of-band Ed25519 host-key confirmation is missing for: "+strings.Join(unconfirmed, ", "), "Verify each fingerprint through the provider console; flow performed no SSH connection.", exitConflict)
	}
	if len(missingAttestations) != 0 {
		_ = audit(ctx, "test.lab", "blocked", map[string]any{"hosts_missing_attestations": len(missingAttestations)})
		return ctx.out.fail("lab_attestations_missing", "one or more role-bound qualification attestations are missing", "Complete the documented external gates and add only their exact tokens; flow performed no SSH connection.", exitConflict)
	}
	if len(unpinned) != 0 {
		_ = audit(ctx, "test.lab", "blocked", map[string]any{"unpinned": unpinned})
		return ctx.out.fail("lab_instance_unpinned", "confirmed inventory host keys do not have complete matching flow bindings: "+strings.Join(unpinned, ", "), "Bind the exact endpoint and pin the provider-console-verified Ed25519 key; flow performed no SSH connection.", exitConflict)
	}
	return runLabE2E(ctx, inventory, scenarios)
}

func runLabE2E(ctx *commandContext, inventory lab.Inventory, scenarios []labScenario) int {
	_ = scenarios
	harness, err := loadLabHarness(ctx.sourceRoot)
	if err != nil {
		return ctx.out.fail("lab_harness", err.Error(), "Run from the Dynamicflow source tree containing the qualifying PBP harness.", exitConfig)
	}
	manager := instanceManager(ctx)
	executor := &labSSHExecutor{
		sshArgs: func(name string) ([]string, error) { return instanceSSHArgs(ctx, name) }, harness: harness,
		audit: func(action, outcome string, fields map[string]any) error {
			return audit(ctx, action, outcome, fields)
		},
	}
	control := &labControlPlane{ctx: ctx, timeout: 15 * time.Minute, interval: 15 * time.Second}
	operation, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runner := lab.Runner{
		ValidateBinding: func(host lab.Host) error { return validateLabBinding(ctx, manager, host) },
		Remote:          executor, Control: control,
		Progress: func(progress lab.Progress) {
			detail := progress.Host
			if detail != "" {
				detail += " (fixed audited action)"
			}
			ctx.out.phase(progress.Phase, progress.Status, detail)
		},
		RebootTimeout: 10 * time.Minute, SoakTimeout: 60 * time.Minute, PollInterval: 20 * time.Second,
	}
	if err := audit(ctx, "test.lab", "started", map[string]any{"hosts": len(inventory.Hosts), "minimum_soak_seconds": lab.MinimumSoakSeconds, "normal_cycles": lab.NormalCloseCycles}); err != nil {
		return ctx.out.fail("lab_audit_unavailable", "the mandatory lab start audit could not be persisted", "Repair private FLOW_HOME permissions; flow performed no SSH connection or mutation.", exitPartial)
	}
	report, pbpResult, runErr := runner.Run(operation, inventory)
	if len(pbpResult) != 0 {
		digest := sha256.Sum256(pbpResult)
		report.PBPResultSHA256 = "sha256:" + hex.EncodeToString(digest[:])
	}
	reportPath, pbpPath, writeErr := writeLabEvidence(ctx, report, pbpResult)
	if writeErr != nil {
		audit(ctx, "test.lab", "evidence-failure", map[string]any{"status": report.Status})
		return ctx.out.fail("lab_evidence", writeErr.Error(), "Repair the private FLOW_HOME permissions before repeating any E2E mutation.", exitPartial)
	}
	if runErr != nil {
		var typed *lab.RunError
		code, message, next, status := "lab_failed", "four-VM E2E failed", "Inspect the private result and the named phase.", exitRemote
		if errors.As(runErr, &typed) {
			code, message, next = typed.Code, typed.Error(), typed.Next
			if typed.Blocked {
				status = exitConflict
			}
		}
		next += " Result: " + reportPath
		audit(ctx, "test.lab", strings.ToLower(report.Status), map[string]any{"failure_code": code, "failure_phase": report.FailurePhase, "result": reportPath})
		return ctx.out.fail(code, message, next, status)
	}
	audit(ctx, "test.lab", "success", map[string]any{"result": reportPath, "pbp_result": pbpPath, "qualifying_soak": true})
	data := map[string]any{"report": report, "result_path": reportPath, "pbp_result_path": pbpPath}
	human := fmt.Sprintf("Four-VM E2E PASS. Result: %s\nQualifying PBP evidence: %s", reportPath, pbpPath)
	return ctx.out.success("test.lab", data, human)
}

func validateLabBinding(ctx *commandContext, manager *instances.Manager, host lab.Host) error {
	if ctx == nil || manager == nil {
		return errors.New("instance manager is unavailable")
	}
	record, err := manager.Get(host.Name)
	if err != nil || record.Status != instances.ActiveStatus || record.HostKey == "" || record.HostKeyFingerprint == "" {
		return errors.New("active pinned instance record is unavailable")
	}
	if !host.HostKeyVerifiedOutOfBand || host.HostKeyFingerprint == "" {
		return errors.New("inventory host key lacks explicit out-of-band confirmation")
	}
	normalizedHostKey, fingerprint, hostKeyErr := sshkeys.ValidateEd25519PublicKey(record.HostKey)
	if hostKeyErr != nil || normalizedHostKey != record.HostKey || fingerprint != record.HostKeyFingerprint || fingerprint != host.HostKeyFingerprint {
		return errors.New("pinned Ed25519 host key differs from the out-of-band inventory fingerprint")
	}
	if record.SSHUser != host.SSHUser || record.SSHPort != 22 || (record.Host != host.Address && (host.IPv6 == "" || record.Host != host.IPv6)) {
		return errors.New("instance endpoint differs from the private lab inventory")
	}
	if host.Role == "pbp" && record.Profile != "pbp" {
		return errors.New("PBP role is not bound to the pbp profile")
	}
	if host.Role == "enrollment" || host.Role == "recovery-negative" {
		if record.Key.Scope != sshkeys.Instance || record.Key.Name != host.Name {
			return errors.New("mutable lab target requires a dedicated per-instance key")
		}
		local, localErr := loadLocalEnrollment(ctx, host.Name)
		if localErr != nil || local.State == "revoked" || local.Profile != record.Profile ||
			local.KeyScope != record.Key.Scope || local.KeyName != record.Key.Name {
			return errors.New("mutable lab target lacks matching live enrollment metadata")
		}
		registry, registryErr := loadProfiles(ctx)
		if registryErr != nil {
			return errors.New("profile registry is unavailable")
		}
		if _, resolveErr := registry.Resolve(local.Profile); resolveErr != nil {
			return errors.New("mutable lab profile is not resolvable")
		}
		remote, remoteErr := loadRemoteServing(ctx)
		if remoteErr != nil {
			return errors.New("pinned serving control plane is unavailable")
		}
		if _, _, signerErr := loadDesiredSigner(ctx, remote); signerErr != nil {
			return errors.New("desired-state signer is unavailable or mismatched")
		}
	}
	if _, err := instanceSSHArgs(ctx, host.Name); err != nil {
		return errors.New("hardened SSH identity is unavailable")
	}
	return nil
}

func writeLabEvidence(ctx *commandContext, report lab.Report, pbpResult []byte) (string, string, error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", errors.New("could not allocate an evidence identifier")
	}
	stamp := report.StartedAt.UTC().Format("20060102T150405Z")
	base := stamp + "-" + hex.EncodeToString(nonce[:])
	reportRelative := filepath.Join("lab", "results", base+"-report.json")
	pbpRelative := ""
	if len(pbpResult) != 0 {
		pbpRelative = filepath.Join("lab", "results", base+"-pbp.json")
		if err := ctx.store.WriteFile(pbpRelative, pbpResult); err != nil {
			return "", "", fmt.Errorf("store validated PBP evidence: %w", err)
		}
	}
	if err := ctx.store.WriteJSON(reportRelative, report); err != nil {
		return "", "", fmt.Errorf("store lab report: %w", err)
	}
	reportPath, _ := ctx.store.Path(reportRelative)
	pbpPath := ""
	if pbpRelative != "" {
		pbpPath, _ = ctx.store.Path(pbpRelative)
	}
	return reportPath, pbpPath, nil
}
