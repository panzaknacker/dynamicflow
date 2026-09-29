package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/lab"
)

func writeLabInventory(t *testing.T, disposable bool) (string, string) {
	t.Helper()
	directory := privateTempDir(t)
	identity := filepath.Join(directory, "bootstrap-identity")
	if err := os.WriteFile(identity, []byte("private path sentinel only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := []struct{ name, role, address, user, os string }{
		{"serve-01", "serving", "192.0.2.10", "admin", "Debian 13"},
		{"enroll-01", "enrollment", "192.0.2.11", "admin", "Debian 13"},
		{"pbp-01", "pbp", "192.0.2.12", "admin", "Debian 13"},
		{"recover-01", "recovery-negative", "192.0.2.13", "ubuntu", "Ubuntu 24.04"},
	}
	var inventory strings.Builder
	inventory.WriteString("version: 2\nhosts:\n")
	for _, host := range hosts {
		inventory.WriteString("  - name: " + host.name + "\n")
		inventory.WriteString("    role: " + host.role + "\n")
		inventory.WriteString("    address: " + host.address + "\n")
		inventory.WriteString("    ssh_user: " + host.user + "\n")
		inventory.WriteString("    os: " + host.os + "\n")
		inventory.WriteString("    identity_file: " + identity + "\n")
		inventory.WriteString("    host_key_fingerprint: SHA256:" + strings.Repeat("A", 43) + "\n")
		inventory.WriteString("    host_key_verified_out_of_band: true\n")
		switch host.role {
		case "enrollment":
			inventory.WriteString("    attested_gates: fresh-enrollment-outbound-https,enrollment-replay-rejected,enrollment-expiry-rejected\n")
		case "recovery-negative":
			inventory.WriteString("    attested_gates: signature-tamper-rejected,digest-tamper-rejected,apply-interruption-injected,runtime-upgrade-published\n")
		}
		inventory.WriteString("    disposable: ")
		if disposable {
			inventory.WriteString("true\n")
		} else {
			inventory.WriteString("false\n")
		}
	}
	path := filepath.Join(directory, "lab.yaml")
	if err := os.WriteFile(path, []byte(inventory.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, identity
}

func TestLabPlanDoesNotExposePrivateIdentityPath(t *testing.T) {
	inventory, identity := writeLabInventory(t, false)
	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t),
		"test", "lab", "--inventory", inventory, "--plan",
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if strings.Contains(stdout, identity) || strings.Contains(stdout, "identity_file") || strings.Contains(stdout, "known_hosts_file") || strings.Contains(stdout, "host_key_fingerprint") || strings.Contains(stdout, "SHA256:") {
		t.Fatalf("plan exposed bootstrap trust paths: %s", stdout)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "test.lab.plan" {
		t.Fatalf("envelope = %+v", envelope)
	}
}

func TestLabPlanAcceptsExplicitPendingGatesWithoutUnlockingExecution(t *testing.T) {
	inventory, identity := writeLabInventory(t, false)
	data, err := os.ReadFile(inventory)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "attested_gates:") {
			continue
		}
		lines = append(lines, strings.ReplaceAll(line, "host_key_verified_out_of_band: true", "host_key_verified_out_of_band: false"))
	}
	if err := os.WriteFile(inventory, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := invokeCLI(t, "--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t), "test", "lab", "--inventory", inventory, "--plan")
	if status != exitOK || stderr != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if !strings.Contains(stdout, "blocked_hostkey_unconfirmed") || !strings.Contains(stdout, "blocked_attestations") || !strings.Contains(stdout, "qualification_matrix") {
		t.Fatalf("pending blockers or matrix missing: %s", stdout)
	}
	if strings.Contains(stdout, identity) || strings.Contains(stdout, "SHA256:") {
		t.Fatalf("pending plan exposed trust path or fingerprint: %s", stdout)
	}
}

func TestLabNonDisposableAndUnpinnedBlockBeforeSSH(t *testing.T) {
	fakeBin := privateTempDir(t)
	sentinel := filepath.Join(t.TempDir(), "ssh-called")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\n: >\"$LAB_SSH_SENTINEL\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	t.Setenv("LAB_SSH_SENTINEL", sentinel)
	for _, test := range []struct {
		name       string
		disposable bool
		code       string
	}{
		{"non-disposable", false, "lab_not_disposable"},
		{"unpinned", true, "lab_instance_unpinned"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventory, identity := writeLabInventory(t, test.disposable)
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
				"--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t),
				"test", "lab", "--inventory", inventory,
			)
			if status != exitConflict || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.Error == nil || envelope.Error.Code != test.code {
				t.Fatalf("envelope = %+v", envelope)
			}
			if strings.Contains(stderr, identity) || strings.Contains(stderr, "private path sentinel") {
				t.Fatalf("blocker exposed private identity material: %s", stderr)
			}
			if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("SSH ran before prerequisites: %v", err)
			}
		})
	}
}

func TestRemoteLabActionsAreFixedAndSoakCannotBeDowngraded(t *testing.T) {
	harness := []byte("#!/usr/bin/python3\nprint('bounded')\n")
	actions := []lab.Action{
		lab.ActionPreflight, lab.ActionServingProbe, lab.ActionServingReconcile, lab.ActionServingRestart,
		lab.ActionRuntimeProbe, lab.ActionEnrollmentProbe, lab.ActionRecoveryProbe,
		lab.ActionApplyConcurrency, lab.ActionReboot, lab.ActionReachable,
		lab.ActionVNCProbe, lab.ActionPBPProbe, lab.ActionPBPIdentity, lab.ActionPBPSoakStart,
		lab.ActionPBPSoakPoll, lab.ActionPBPForensics, lab.ActionPBPSoakResult,
	}
	for _, action := range actions {
		spec, err := buildLabRemoteSpec(action, harness)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if strings.Join(spec.argv, " ") != "sudo -n /bin/bash -s" {
			t.Fatalf("%s argv = %v", action, spec.argv)
		}
		payload := string(spec.stdin)
		for _, forbidden := range []string{"ssh-keyscan", "scp ", "sudoers", "young.pem", "allow-short-nonqualifying"} {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("%s contains forbidden %q", action, forbidden)
			}
		}
		if bash, lookupErr := exec.LookPath("bash"); lookupErr == nil {
			check := exec.Command(bash, "-n")
			check.Stdin = strings.NewReader(payload)
			if output, checkErr := check.CombinedOutput(); checkErr != nil {
				t.Fatalf("%s is not valid Bash: %v: %s", action, checkErr, output)
			}
		}
	}
	start, err := buildLabRemoteSpec(lab.ActionPBPSoakStart, harness)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(start.stdin)
	for _, required := range []string{
		"--duration-seconds 1800", "--normal-cycles 5", "--exercise-vpn-failure", "--disposable-network-test",
		"socket.SO_PEERCRED", "peer_uid != uid", "state = \"disconnect\"", "state = \"connect\"", "mullvad(\"connect\")",
		"baseline_egress = wait_egress()", "connect_different_egress()", "current != baseline_egress",
	} {
		if !strings.Contains(payload, required) {
			t.Fatalf("soak action is missing %q", required)
		}
	}
	transition := strings.Index(payload, "state = \"connect\"\n                succeeded = mullvad(action)")
	recovery := strings.Index(payload, "if state == \"connect\":\n        for _recovery_attempt in range(3):")
	if transition < 0 || recovery < 0 || recovery <= transition {
		t.Fatal("VPN helper no longer restores after an attempted/partial disconnect")
	}
	if _, err := buildLabRemoteSpec(lab.Action("operator-command"), harness); err == nil {
		t.Fatal("arbitrary action was accepted")
	}
}

func TestEmbeddedRootVPNHelperIsValidPython(t *testing.T) {
	start, err := buildLabRemoteSpec(lab.ActionPBPSoakStart, []byte("#!/usr/bin/python3\n"))
	if err != nil {
		t.Fatal(err)
	}
	payload := string(start.stdin)
	const begin = "cat >\"$helper_stage\" <<'DYNAMICFLOW_VPN_HELPER_9B18A7C2'\n"
	const end = "\nDYNAMICFLOW_VPN_HELPER_9B18A7C2\n"
	startAt := strings.Index(payload, begin)
	if startAt < 0 {
		t.Fatal("helper heredoc start missing")
	}
	startAt += len(begin)
	endAt := strings.Index(payload[startAt:], end)
	if endAt < 0 {
		t.Fatal("helper heredoc end missing")
	}
	helper := payload[startAt : startAt+endAt]
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(t.TempDir(), "vpn-trigger.py")
	if err := os.WriteFile(path, []byte(helper), 0o600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command(python, "-m", "py_compile", path)
	check.Env = append(os.Environ(), "PYTHONPYCACHEPREFIX="+t.TempDir())
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("embedded helper is not valid Python: %v: %s", err, output)
	}
}

func TestRepositoryHarnessContainsBoundedTriggerContract(t *testing.T) {
	harness, err := loadLabHarness(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(harness) {
		t.Fatal("Python harness was unexpectedly treated as JSON")
	}
	for _, required := range []string{
		"DYNAMICFLOW_LAB_VPN_TRIGGER",
		"socket.AF_UNIX",
		"MINIMUM_SOAK_SECONDS = 30 * 60",
		`metrics["real_relay_switch"] = True`,
		`metrics["egress_identity_changed"] = True`,
		`metrics["restart_after_relay_switch"] = True`,
	} {
		if !strings.Contains(string(harness), required) {
			t.Fatalf("harness missing %q", required)
		}
	}
}

func TestLabRemoteStartAuditFailureDoesNotStartSSH(t *testing.T) {
	fakeBin := privateTempDir(t)
	sentinel := filepath.Join(t.TempDir(), "ssh-called")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf \"%s\n\" started >\"$LAB_SSH_SENTINEL\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	t.Setenv("LAB_SSH_SENTINEL", sentinel)
	withoutAudit := &labSSHExecutor{sshArgs: func(string) ([]string, error) { return []string{"pinned-target"}, nil }}
	if _, err := withoutAudit.Run(context.Background(), lab.Host{Name: "pbp-01"}, lab.ActionPreflight); err == nil {
		t.Fatal("remote action without mandatory audit was accepted")
	}
	if _, statErr := os.Lstat(sentinel); !os.IsNotExist(statErr) {
		t.Fatalf("SSH process started without mandatory audit: %v", statErr)
	}
	audits := 0
	executor := &labSSHExecutor{
		sshArgs: func(string) ([]string, error) { return []string{"pinned-target"}, nil },
		audit: func(action, outcome string, fields map[string]any) error {
			audits++
			if action != "test.lab.remote" || outcome != "started" || fields["instance"] != "pbp-01" {
				t.Fatalf("unexpected audit: %s %s %+v", action, outcome, fields)
			}
			return errors.New("durable audit unavailable")
		},
	}
	_, err := executor.Run(context.Background(), lab.Host{Name: "pbp-01"}, lab.ActionPreflight)
	if err == nil || !strings.Contains(err.Error(), "audit") || audits != 1 {
		t.Fatalf("error=%v audits=%d", err, audits)
	}
	if _, statErr := os.Lstat(sentinel); !os.IsNotExist(statErr) {
		t.Fatalf("SSH process started despite failed start audit: %v", statErr)
	}
}

func TestLabRemoteOutcomeAuditIsBestEffort(t *testing.T) {
	fakeBin := privateTempDir(t)
	fakeSSH := filepath.Join(fakeBin, "ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf \"%s\n\" preflight-ok\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	outcomes := []string{}
	executor := &labSSHExecutor{
		sshArgs: func(string) ([]string, error) { return []string{"pinned-target"}, nil },
		audit: func(_ string, outcome string, _ map[string]any) error {
			outcomes = append(outcomes, outcome)
			if outcome == "started" {
				return nil
			}
			return errors.New("outcome audit unavailable")
		},
	}
	result, err := executor.Run(context.Background(), lab.Host{Name: "pbp-01"}, lab.ActionPreflight)
	if err != nil || result.State != lab.RemoteReady {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if strings.Join(outcomes, ",") != "started,success" {
		t.Fatalf("audit outcomes = %v", outcomes)
	}
}

func TestPBPForensicsRemoteActionIsFixedReadOnlyAndBounded(t *testing.T) {
	spec, err := buildLabRemoteSpec(lab.ActionPBPForensics, []byte("unused"))
	if err != nil {
		t.Fatal(err)
	}
	if spec.timeout != 6*time.Minute || strings.Join(spec.argv, " ") != "sudo -n /bin/bash -s" {
		t.Fatalf("forensics spec = %+v", spec)
	}
	payload := string(spec.stdin)
	for _, required := range []string{
		"/run/dynamicflow-lab-pbp-soak-started", "journalctl", "coredumpctl", "--since", "--lines=4097", "\"-n\", \"1025\"", "sort_keys=True",
		".local/share/toolkit-pbp/profile", "browser.lock", "sport = :5901", "COREDUMP_UID", "\"uid\"", "\"exe\"",
		"runtime.stderr", "launch.end", "launch.lifecycle_complete", "browser.context_started",
		"browser.context_closed", "browser.page_opened", "browser.page_closed", "browser.page_crashed",
		"playwright.dispatch_failed", "sha256", "available", "dynamicflow-lab-pbp-soak.service",
	} {
		if !strings.Contains(payload, required) {
			t.Fatalf("forensics action is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"rm -f", "systemctl reset-failed", "systemctl start", "systemctl stop", "systemctl restart",
		"curl ", "https://", "subprocess.Popen", "os.kill(",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("forensics action contains mutating or network operation %q", forbidden)
		}
	}
	result, err := parseLabRemoteOutput(lab.ActionPBPForensics, []byte("{}\n"))
	if err != nil || result.State != lab.RemoteComplete || string(result.Data) != "{}\n" {
		t.Fatalf("forensics parse result=%+v error=%v", result, err)
	}
	if _, err := parseLabRemoteOutput(lab.ActionPBPForensics, nil); err == nil {
		t.Fatal("empty forensics output was accepted")
	}
	if _, err := parseLabRemoteOutput(lab.ActionPBPForensics, make([]byte, maxLabOutputBytes+1)); err == nil {
		t.Fatal("oversized forensics output was accepted")
	}
}

func TestEmbeddedPBPForensicsCollectorIsValidPython(t *testing.T) {
	const begin = "/usr/bin/python3 - \"$marker\" <<'DYNAMICFLOW_PBP_FORENSICS_65EAF219'\n"
	const end = "\nDYNAMICFLOW_PBP_FORENSICS_65EAF219\n"
	startAt := strings.Index(labPBPForensicsScript, begin)
	if startAt < 0 {
		t.Fatal("forensics heredoc start missing")
	}
	startAt += len(begin)
	endAt := strings.Index(labPBPForensicsScript[startAt:], end)
	if endAt < 0 {
		t.Fatal("forensics heredoc end missing")
	}
	collector := labPBPForensicsScript[startAt : startAt+endAt]
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(t.TempDir(), "pbp-forensics.py")
	if err := os.WriteFile(path, []byte(collector), 0o600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command(python, "-m", "py_compile", path)
	check.Env = append(os.Environ(), "PYTHONPYCACHEPREFIX="+t.TempDir())
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("embedded forensics collector is not valid Python: %v: %s", err, output)
	}
}

func TestLabQualificationGatesBlockBeforeSSH(t *testing.T) {
	fakeBin := privateTempDir(t)
	sentinel := filepath.Join(t.TempDir(), "ssh-called")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf called >\"$LAB_SSH_SENTINEL\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	t.Setenv("LAB_SSH_SENTINEL", sentinel)
	tests := []struct {
		name   string
		mutate func(string) string
		code   string
	}{
		{
			name: "unconfirmed host key",
			mutate: func(value string) string {
				return strings.Replace(value, "host_key_verified_out_of_band: true", "host_key_verified_out_of_band: false", 1)
			},
			code: "lab_hostkey_unconfirmed",
		},
		{
			name: "missing replay attestation",
			mutate: func(value string) string {
				return strings.Replace(value, ",enrollment-replay-rejected", "", 1)
			},
			code: "lab_attestations_missing",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory, _ := writeLabInventory(t, true)
			data, err := os.ReadFile(inventory)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(inventory, []byte(test.mutate(string(data))), 0o600); err != nil {
				t.Fatal(err)
			}
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, "--json", "--home", privateTempDir(t), "--source-root", repositoryRoot(t), "test", "lab", "--inventory", inventory)
			if status != exitConflict || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.Error == nil || envelope.Error.Code != test.code {
				t.Fatalf("envelope = %+v", envelope)
			}
			if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("SSH ran before qualification gate: %v", err)
			}
		})
	}
}

func TestQualificationRemoteProbesAreFixedAndEvidenceBound(t *testing.T) {
	tests := []struct {
		action   lab.Action
		required []string
		forbid   []string
	}{
		{
			action:   lab.ActionServingReconcile,
			required: []string{"start serving --plan", `data.get("state") == "noop"`, "start serving)", `data.get("changed") is False`, "MainPID", "serving-reconcile-ok"},
			forbid:   []string{"--public-url", "ssh-keyscan", "scp ", "rm -"},
		},
		{
			action:   lab.ActionEnrollmentProbe,
			required: []string{"runtime-config.json", "set(value) != expected", "authorized_keys", "len(lines) != 1", "ssh-ed25519", "O_NOFOLLOW", "id_ed25519"},
			forbid:   []string{"curl ", "journalctl", "rm -", "systemctl restart"},
		},
		{
			action:   lab.ActionRecoveryProbe,
			required: []string{"checkpoint.json", "apply.json", "attempts", ">= 2", "runtime-recovery", "hash_regular", "verification_count", "--lines=4097", "flock -n"},
			forbid:   []string{"rm -", "systemctl restart", "systemctl reboot", "curl "},
		},
		{
			action:   lab.ActionApplyConcurrency,
			required: []string{"targetapply.lock", "flock -n 9", "instance-runtime reconcile --state-root", "apply_busy", "contender_status", "profile_applied", "flock -n 8"},
			forbid:   []string{"$@", "eval ", "bash -c", "sh -c", "rm -", "systemctl restart"},
		},
		{
			action:   lab.ActionPBPIdentity,
			required: []string{"pbp-persona.json", "O_NOFOLLOW", "st_ino", "st_size", "sha256(raw)", "firefox_user_prefs", "pbp-identity:"},
			forbid:   []string{"persona_id\")", "rm -", "systemctl", "curl "},
		},
	}
	for _, test := range tests {
		spec, err := buildLabRemoteSpec(test.action, []byte("unused"))
		if err != nil {
			t.Fatalf("%s: %v", test.action, err)
		}
		if strings.Join(spec.argv, " ") != "sudo -n /bin/bash -s" {
			t.Fatalf("%s argv = %v", test.action, spec.argv)
		}
		payload := string(spec.stdin)
		for _, required := range test.required {
			if !strings.Contains(payload, required) {
				t.Fatalf("%s missing %q", test.action, required)
			}
		}
		for _, forbidden := range test.forbid {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("%s contains %q", test.action, forbidden)
			}
		}
	}
}

func TestQualificationEmbeddedPythonIsValid(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	tests := []struct {
		name, payload, begin, end string
	}{
		{"enrollment-config", labEnrollmentProbeScript, "<<DYNAMICFLOW_LAB_ENROLLMENT_CONFIG_3A57C119\n", "\nDYNAMICFLOW_LAB_ENROLLMENT_CONFIG_3A57C119\n"},
		{"authorized-key", labEnrollmentProbeScript, "<<DYNAMICFLOW_LAB_AUTHORIZED_KEY_4E6210AF\n", "\nDYNAMICFLOW_LAB_AUTHORIZED_KEY_4E6210AF\n"},
		{"recovery-evidence", labRecoveryProbeScript, "<<DYNAMICFLOW_LAB_RECOVERY_EVIDENCE_63B209D4\n", "\nDYNAMICFLOW_LAB_RECOVERY_EVIDENCE_63B209D4\n"},
		{"pbp-identity", labPBPIdentityScript, "<<'DYNAMICFLOW_LAB_PBP_IDENTITY_74BA20E1'\n", "\nDYNAMICFLOW_LAB_PBP_IDENTITY_74BA20E1\n"},
	}
	compile := func(name, source string) {
		path := filepath.Join(t.TempDir(), name+".py")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		check := exec.Command(python, "-m", "py_compile", path)
		check.Env = append(os.Environ(), "PYTHONPYCACHEPREFIX="+t.TempDir())
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("%s Python is invalid: %v: %s", name, err, output)
		}
	}
	for _, test := range tests {
		start := strings.Index(test.payload, test.begin)
		if start < 0 {
			t.Fatalf("%s begin missing", test.name)
		}
		start += len(test.begin)
		end := strings.Index(test.payload[start:], test.end)
		if end < 0 {
			t.Fatalf("%s end missing", test.name)
		}
		compile(test.name, test.payload[start:start+end])
	}
}
