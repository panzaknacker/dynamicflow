package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type recordedAction struct {
	host   string
	action Action
}

type fakeRemote struct {
	actions       []recordedAction
	result        []byte
	forensics     []byte
	polls         int
	completeAfter int
	identityCalls int
	identityDrift bool
}

func (remote *fakeRemote) Run(_ context.Context, host Host, action Action) (RemoteResult, error) {
	remote.actions = append(remote.actions, recordedAction{host: host.Name, action: action})
	switch action {
	case ActionPBPSoakStart:
		return RemoteResult{State: RemoteRunning}, nil
	case ActionPBPSoakPoll:
		remote.polls++
		completeAfter := remote.completeAfter
		if completeAfter <= 0 {
			completeAfter = 2
		}
		if remote.polls < completeAfter {
			return RemoteResult{State: RemoteRunning}, nil
		}
		return RemoteResult{State: RemoteComplete}, nil
	case ActionPBPSoakResult:
		return RemoteResult{State: RemoteComplete, Data: remote.result}, nil
	case ActionPBPForensics:
		return RemoteResult{State: RemoteComplete, Data: remote.forensics}, nil
	case ActionPBPIdentity:
		remote.identityCalls++
		value := byte(0x42)
		if remote.identityDrift && remote.identityCalls > 1 {
			value = 0x43
		}
		return RemoteResult{State: RemoteReady, Data: bytes.Repeat([]byte{value}, sha256.Size)}, nil
	default:
		return RemoteResult{State: RemoteReady}, nil
	}
}

type fakeControl struct {
	operations []string
}

func (control *fakeControl) RotateSSHKey(_ context.Context, host Host) (uint64, error) {
	control.operations = append(control.operations, "rotate:"+host.Name)
	return 2, nil
}

func (control *fakeControl) RotateVNCSecret(_ context.Context, host Host) error {
	control.operations = append(control.operations, "vnc-rotate:"+host.Name)
	return nil
}

func (control *fakeControl) RevokeInstance(_ context.Context, host Host) (uint64, error) {
	control.operations = append(control.operations, "revoke:"+host.Name)
	return 3, nil
}

func testInventory(disposable bool) Inventory {
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	return Inventory{Version: 2, Hosts: []Host{
		{Name: "serve-01", Role: "serving", Address: "192.0.2.10", SSHUser: "admin", Disposable: disposable, HostKeyFingerprint: fingerprint, HostKeyVerifiedOutOfBand: true},
		{Name: "enroll-01", Role: "enrollment", Address: "192.0.2.11", SSHUser: "admin", Disposable: disposable, HostKeyFingerprint: fingerprint, HostKeyVerifiedOutOfBand: true, AttestedGates: RequiredAttestations("enrollment")},
		{Name: "pbp-01", Role: "pbp", Address: "192.0.2.12", SSHUser: "admin", Disposable: disposable, HostKeyFingerprint: fingerprint, HostKeyVerifiedOutOfBand: true},
		{Name: "recover-01", Role: "recovery-negative", Address: "192.0.2.13", SSHUser: "admin", Disposable: disposable, HostKeyFingerprint: fingerprint, HostKeyVerifiedOutOfBand: true, AttestedGates: RequiredAttestations("recovery-negative")},
	}}
}

func qualifyingResult(t *testing.T) []byte {
	t.Helper()
	base := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	stamp := func(offset int) string { return base.Add(time.Duration(offset) * time.Second).Format(time.RFC3339) }
	phases := []map[string]interface{}{
		{"name": "preflight", "status": "PASS", "started_at": stamp(0), "finished_at": stamp(1), "detail": "real-VM assertions passed", "metrics": map[string]interface{}{"pinned_release": true, "egress_verified": true}},
	}
	cursor := 2
	for cycle := 1; cycle <= NormalCloseCycles; cycle++ {
		phases = append(phases, map[string]interface{}{
			"name": fmt.Sprintf("normal_close_restart_%d", cycle), "status": "PASS",
			"started_at": stamp(cursor), "finished_at": stamp(cursor + 2),
			"detail": "real-VM assertions passed", "metrics": map[string]interface{}{"cycle": cycle, "normal_exit": true, "lock_reacquired": true},
		})
		cursor += 3
	}
	phases = append(phases,
		map[string]interface{}{"name": "thirty_minute_soak", "status": "PASS", "started_at": stamp(cursor), "finished_at": stamp(cursor + MinimumSoakSeconds), "detail": "real-VM assertions passed", "metrics": map[string]interface{}{"minimum_30_minutes": true, "wall_clock_seconds": MinimumSoakSeconds, "visible_lock_dialog": true, "egress_checks": 7, "transient_egress_checks": 0}},
		map[string]interface{}{"name": "unexpected_browser_process_exit", "status": "PASS", "started_at": stamp(cursor + 1801), "finished_at": stamp(cursor + 1808), "detail": "real-VM assertions passed", "metrics": map[string]interface{}{"browser_sigkill": true, "visible_dialog": true, "launcher_exit_code": 21}},
		map[string]interface{}{"name": "vpn_real_disconnect_fail_closed", "status": "PASS", "started_at": stamp(cursor + 1809), "finished_at": stamp(cursor + 1839), "detail": "real-VM assertions passed", "metrics": map[string]interface{}{"real_disconnect": true, "offline_signal": true, "visible_dialog": true, "launcher_exit_code": 22, "transient_retry_observed": true, "bounded_backoff_observed": true, "real_relay_switch": true, "egress_identity_changed": true, "restart_after_relay_switch": true, "retry_window_seconds": 30}},
		map[string]interface{}{"name": "log_rotation_redaction", "status": "PASS", "started_at": stamp(cursor + 1840), "finished_at": stamp(cursor + 1841), "detail": "real-VM assertions passed", "metrics": map[string]interface{}{"distinct_logs_observed": 9, "retained_logs": 8, "retention_bounded": true, "redaction_checked": true}},
	)
	value := map[string]interface{}{
		"schema": 1, "test": "pbp-real-vm-soak", "started_at": stamp(0),
		"finished_at": stamp(cursor + 1841), "status": "PASS",
		"configuration": map[string]interface{}{
			"duration_seconds": 1800, "minimum_duration_seconds": 1800, "normal_cycles": NormalCloseCycles,
			"vpn_failure_armed": true, "qualifying_duration": true,
		},
		"phases": phases,
		"summary": map[string]interface{}{
			"qualifying_real_vm_pass": true, "egress_checks": 7, "distinct_logs_observed": 9, "no_secrets_recorded": true,
		},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func qualifyingForensics(t *testing.T) []byte {
	t.Helper()
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	available := func() map[string]interface{} {
		return map[string]interface{}{"available": true, "count": 0, "sha256": digestA}
	}
	unavailable := func() map[string]interface{} {
		return map[string]interface{}{"available": false, "count": nil, "sha256": nil}
	}
	metadata := func() map[string]interface{} {
		return map[string]interface{}{"inode": 4242, "sha256": digestA, "size": 4096}
	}
	unit := func(active, sub, result string) map[string]interface{} {
		return map[string]interface{}{"active_state": active, "load_state": "loaded", "result": result, "sub_state": sub}
	}
	value := map[string]interface{}{
		"apparmor_denied": available(),
		"collected_at":    "2026-07-23T00:31:00Z",
		"coredumps":       unavailable(),
		"desktop": map[string]interface{}{
			"display_bound": true, "vnc_loopback_5901": true, "vnc_public_5901": false,
			"vnc_unit_active": true, "xauthority_bound": true, "xfce_active": true,
		},
		"kernel_killed":   available(),
		"kernel_oom":      available(),
		"kernel_segfault": available(),
		"persona": map[string]interface{}{
			"baseline": metadata(), "current": metadata(), "unchanged": true,
		},
		"profile": map[string]interface{}{
			"app_lock_free": true, "app_lock_present": true, "native_lock_count": 0, "profile_process_count": 0,
		},
		"runtime_logs": map[string]interface{}{
			"count": 2,
			"events": map[string]interface{}{
				"browser_context_closed":            2,
				"browser_context_started":           2,
				"browser_page_closed":               2,
				"browser_page_crashed":              1,
				"browser_page_opened":               2,
				"launch_end":                        2,
				"launch_lifecycle_complete":         2,
				"playwright_dispatch_failed":        0,
				"runtime_stderr":                    1,
				"runtime_stderr_capture_error":      0,
				"runtime_stderr_capture_incomplete": 0,
			},
			"sha256": []string{digestA, digestB},
		},
		"schema":     1,
		"started_at": "2026-07-23T00:00:00Z",
		"status":     "captured",
		"systemd_units": map[string]interface{}{
			"dynamicflow-lab-pbp-soak.service":        unit("inactive", "dead", "success"),
			"dynamicflow-lab-pbp-vpn-trigger.service": unit("inactive", "dead", "success"),
			"mullvad-daemon.service":                  unit("active", "running", "success"),
			"tigervncserver@:1.service":               unit("active", "running", "success"),
		},
		"test": "pbp-forensics",
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
func mutateQualifyingForensics(t *testing.T, mutate func(map[string]interface{})) []byte {
	t.Helper()
	var value map[string]interface{}
	if err := json.Unmarshal(qualifyingForensics(t), &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	changed, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(changed, byte(10))
}

func mutateQualifyingResult(t *testing.T, mutate func(map[string]interface{})) []byte {
	t.Helper()
	var value map[string]interface{}
	if err := json.Unmarshal(qualifyingResult(t), &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	changed, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestRunnerRefusesNonDisposableBeforeAnyBindingOrRemoteAction(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t)}
	control := &fakeControl{}
	bindings := 0
	runner := Runner{
		ValidateBinding: func(Host) error { bindings++; return nil }, Remote: remote, Control: control,
	}
	report, result, err := runner.Run(context.Background(), testInventory(false))
	var runErr *RunError
	if !errors.As(err, &runErr) || !runErr.Blocked || runErr.Code != "lab_not_disposable" {
		t.Fatalf("error = %#v", err)
	}
	if report.Status != "BLOCKED" || result != nil || bindings != 0 || len(remote.actions) != 0 || len(control.operations) != 0 {
		t.Fatalf("mutation occurred: report=%+v bindings=%d actions=%v control=%v", report, bindings, remote.actions, control.operations)
	}
}

func TestRunnerResolvesEveryPinnedBindingBeforeNetwork(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t)}
	control := &fakeControl{}
	bindings := []string{}
	runner := Runner{
		ValidateBinding: func(host Host) error {
			bindings = append(bindings, host.Name)
			if host.Role == "pbp" {
				return errors.New("unpinned")
			}
			return nil
		}, Remote: remote, Control: control,
	}
	report, _, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || !runErr.Blocked || runErr.Code != "lab_instance_unpinned" {
		t.Fatalf("error = %#v", err)
	}
	if report.Status != "BLOCKED" || len(remote.actions) != 0 || len(control.operations) != 0 {
		t.Fatalf("network/control action occurred: %+v %+v", remote.actions, control.operations)
	}
	if strings.Join(bindings, ",") != "serve-01,enroll-01,pbp-01" {
		t.Fatalf("binding order = %v", bindings)
	}
}

func TestRunnerUsesOnlyFixedActionsAndQualifyingPolicy(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t), forensics: qualifyingForensics(t), completeAfter: 90}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: 20 * time.Second, RebootTimeout: time.Minute, SoakTimeout: 60 * time.Minute,
	}
	report, result, err := runner.Run(context.Background(), testInventory(true))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "PASS" || !report.QualifyingPBPPass || report.MinimumSoakSeconds != 1800 || report.NormalCloseCycles != 5 || !report.VPNFailureArmed {
		t.Fatalf("report = %+v", report)
	}
	if report.PBPForensics == nil || report.PBPForensicsRemoteBytes != len(remote.forensics) || !strings.HasPrefix(report.PBPForensicsSHA256, "sha256:") {
		t.Fatalf("mandatory forensics missing from report: %+v", report)
	}
	if !strings.HasPrefix(report.PBPResultSHA256, "sha256:") {
		t.Fatalf("soak result digest missing: %+v", report)
	}
	if string(result) != string(remote.result) {
		t.Fatal("validated remote result was not returned unchanged")
	}
	forensicsIndex, resultIndex := -1, -1
	for index, action := range remote.actions {
		if !IsFixedAction(action.action) {
			t.Fatalf("non-fixed action: %+v", action)
		}
		if action.action == ActionPBPForensics {
			forensicsIndex = index
		}
		if action.action == ActionPBPSoakResult {
			resultIndex = index
		}
	}
	if forensicsIndex < 0 || resultIndex != forensicsIndex+1 {
		t.Fatalf("forensics/result order = %d/%d actions=%+v", forensicsIndex, resultIndex, remote.actions)
	}
	withoutPolls := []string{}
	for _, action := range remote.actions {
		if action.action != ActionPBPSoakPoll {
			withoutPolls = append(withoutPolls, action.host+":"+string(action.action))
		}
	}
	wantActions := []string{
		"serve-01:preflight", "enroll-01:preflight", "pbp-01:preflight", "recover-01:preflight",
		"serve-01:serving-probe", "serve-01:serving-reconcile", "serve-01:serving-restart", "serve-01:reboot", "serve-01:reachable", "serve-01:serving-probe",
		"enroll-01:runtime-probe", "pbp-01:runtime-probe", "recover-01:runtime-probe",
		"enroll-01:enrollment-evidence-probe", "enroll-01:runtime-probe", "enroll-01:reboot", "enroll-01:reachable", "enroll-01:runtime-probe",
		"recover-01:recovery-evidence-probe", "recover-01:apply-concurrency-probe", "recover-01:reboot", "recover-01:reachable", "recover-01:runtime-probe",
		"pbp-01:vnc-loopback-probe", "pbp-01:pbp-vpn-probe", "pbp-01:pbp-identity-probe",
		"pbp-01:reboot", "pbp-01:reachable", "pbp-01:runtime-probe", "pbp-01:vnc-loopback-probe",
		"pbp-01:pbp-vpn-probe", "pbp-01:pbp-identity-probe", "pbp-01:pbp-soak-start",
		"pbp-01:pbp-forensics", "pbp-01:pbp-soak-result",
	}
	if strings.Join(withoutPolls, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("fixed action sequence differs:\n got %v\nwant %v", withoutPolls, wantActions)
	}
	if len(report.QualificationMatrix) != len(QualificationMatrix()) {
		t.Fatalf("report qualification matrix missing: %+v", report.QualificationMatrix)
	}
	if got := strings.Join(control.operations, ","); got != "rotate:enroll-01,vnc-rotate:pbp-01,revoke:recover-01" {
		t.Fatalf("control operations = %s", got)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "young.pem") || strings.Contains(string(encoded), "ssh -") {
		t.Fatalf("report exposed command/key material: %s", encoded)
	}
}

func TestRunnerRejectsRemoteCompletionBeforeLocallyObservedMinimum(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t), forensics: qualifyingForensics(t), completeAfter: 1}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: 20 * time.Second, RebootTimeout: time.Minute, SoakTimeout: 60 * time.Minute,
	}
	report, evidence, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Code != "pbp_soak_local_duration" || report.Status != "FAIL" {
		t.Fatalf("report=%+v error=%#v", report, err)
	}
	if string(evidence) != string(remote.result) || report.PBPResultRemoteBytes != len(remote.result) || report.QualifyingPBPPass {
		t.Fatalf("remote evidence was not preserved on early completion: report=%+v bytes=%d", report, len(evidence))
	}
}

func TestRunnerRejectsPBPIdentityDriftAcrossRebootBeforeSoak(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t), forensics: qualifyingForensics(t), identityDrift: true}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: time.Second, RebootTimeout: time.Minute, SoakTimeout: 60 * time.Minute,
	}
	report, evidence, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Code != "pbp_persona_changed" || report.Status != "FAIL" || len(evidence) != 0 {
		t.Fatalf("report=%+v evidence=%d error=%#v", report, len(evidence), err)
	}
	for _, action := range remote.actions {
		if action.action == ActionPBPSoakStart {
			t.Fatal("persona drift started the PBP soak")
		}
	}
	if got := strings.Join(control.operations, ","); got != "rotate:enroll-01,vnc-rotate:pbp-01" {
		t.Fatalf("unexpected control operations after persona drift: %s", got)
	}
}

func TestRunnerPreservesRemoteEvidenceOnValidationFailure(t *testing.T) {
	invalid := mutateQualifyingResult(t, func(value map[string]interface{}) {
		phases := value["phases"].([]interface{})
		phases[1].(map[string]interface{})["metrics"].(map[string]interface{})["cycle"] = 2
	})
	remote := &fakeRemote{result: invalid, forensics: qualifyingForensics(t), completeAfter: 90}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: 20 * time.Second, RebootTimeout: time.Minute, SoakTimeout: 60 * time.Minute,
	}
	report, evidence, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Code != "pbp_soak_not_qualifying" || report.Status != "FAIL" {
		t.Fatalf("report=%+v error=%#v", report, err)
	}
	if string(evidence) != string(invalid) || report.PBPResultRemoteBytes != len(invalid) || report.QualifyingPBPPass {
		t.Fatalf("invalid remote evidence was not preserved: report=%+v bytes=%d", report, len(evidence))
	}
}

func TestRunnerNeverStartsSoakWithShortLocalWaitPolicy(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t)}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: time.Second, RebootTimeout: time.Minute, SoakTimeout: 1799 * time.Second,
	}
	report, _, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Code != "pbp_soak_policy" || report.Status != "FAIL" {
		t.Fatalf("report=%+v error=%#v", report, err)
	}
	for _, action := range remote.actions {
		if action.action == ActionPBPSoakStart {
			t.Fatal("short local wait policy started the remote soak")
		}
	}
}

func TestQualifyingSoakCannotBeShortenedOrDisarmed(t *testing.T) {
	base := qualifyingResult(t)
	var value map[string]interface{}
	if err := json.Unmarshal(base, &value); err != nil {
		t.Fatal(err)
	}
	configuration := value["configuration"].(map[string]interface{})
	tests := []struct {
		name   string
		mutate func()
	}{
		{"short duration", func() { configuration["duration_seconds"] = float64(1799) }},
		{"too few cycles", func() { configuration["normal_cycles"] = float64(3) }},
		{"vpn disarmed", func() { configuration["vpn_failure_armed"] = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := json.Unmarshal(base, &value); err != nil {
				t.Fatal(err)
			}
			configuration = value["configuration"].(map[string]interface{})
			test.mutate()
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateQualifyingSoak(changed); err == nil {
				t.Fatal("non-qualifying result was accepted")
			}
		})
	}
}

func TestQualifyingSoakRejectsIncoherentPhaseEvidence(t *testing.T) {
	if _, err := ValidateQualifyingSoak(qualifyingResult(t)); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"reordered phases", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[1], phases[2] = phases[2], phases[1]
		}},
		{"overlapping phases", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[2].(map[string]interface{})["started_at"] = phases[1].(map[string]interface{})["started_at"]
		}},
		{"wrong cycle number", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[1].(map[string]interface{})["metrics"].(map[string]interface{})["cycle"] = 2
		}},
		{"missing preflight evidence", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			delete(phases[0].(map[string]interface{})["metrics"].(map[string]interface{}), "pinned_release")
		}},
		{"unbounded log retention", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[len(phases)-1].(map[string]interface{})["metrics"].(map[string]interface{})["retained_logs"] = 9
		}},
		{"missing real relay switch", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[len(phases)-2].(map[string]interface{})["metrics"].(map[string]interface{})["real_relay_switch"] = false
		}},
		{"missing changed egress", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[len(phases)-2].(map[string]interface{})["metrics"].(map[string]interface{})["egress_identity_changed"] = false
		}},
		{"missing restart after relay switch", func(value map[string]interface{}) {
			phases := value["phases"].([]interface{})
			phases[len(phases)-2].(map[string]interface{})["metrics"].(map[string]interface{})["restart_after_relay_switch"] = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := mutateQualifyingResult(t, test.mutate)
			if _, err := ValidateQualifyingSoak(changed); err == nil {
				t.Fatal("incoherent phase evidence was accepted")
			}
		})
	}
}

func TestQualifyingSoakRejectsSecretLikeEvidence(t *testing.T) {
	var value map[string]interface{}
	if err := json.Unmarshal(qualifyingResult(t), &value); err != nil {
		t.Fatal(err)
	}
	value["summary"].(map[string]interface{})["token"] = "do-not-store"
	changed, _ := json.Marshal(value)
	if _, err := ValidateQualifyingSoak(changed); err == nil {
		t.Fatal("secret-like result was accepted")
	}
}

func TestPBPForensicsValidatorAcceptsCanonicalBoundedEvidenceAndFinalStates(t *testing.T) {
	valid := qualifyingForensics(t)
	evidence, err := ValidatePBPForensics(valid)
	if err != nil {
		t.Fatalf("valid canonical evidence rejected: %v", err)
	}
	if evidence.Test != "pbp-forensics" || evidence.Persona.Baseline != evidence.Persona.Current {
		t.Fatalf("validated evidence = %+v", evidence)
	}
	failedTransient := mutateQualifyingForensics(t, func(value map[string]interface{}) {
		units := value["systemd_units"].(map[string]interface{})
		soak := units["dynamicflow-lab-pbp-soak.service"].(map[string]interface{})
		soak["active_state"] = "failed"
		soak["sub_state"] = "failed"
		soak["result"] = "exit-code"
		units["mullvad-daemon.service"].(map[string]interface{})["result"] = "none"
	})
	if _, err := ValidatePBPForensics(failedTransient); err != nil {
		t.Fatalf("explicit failed/inactive state evidence rejected: %v", err)
	}
}

func TestPBPForensicsValidatorRejectsManipulationAndSchemaDrift(t *testing.T) {
	tests := []struct {
		name string
		data func() []byte
	}{
		{"missing newline", func() []byte {
			valid := qualifyingForensics(t)
			return valid[:len(valid)-1]
		}},
		{"noncanonical whitespace", func() []byte { return append([]byte(" "), qualifyingForensics(t)...) }},
		{"trailing JSON", func() []byte { return append(qualifyingForensics(t), []byte("{}\n")...) }},
		{"duplicate key", func() []byte {
			return []byte(strings.Replace(string(qualifyingForensics(t)), `"schema":1`, `"schema":1,"schema":1`, 1))
		}},
		{"over size bound", func() []byte { return make([]byte, MaximumForensicsBytes+1) }},
		{"unknown root field", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) { value["operator"] = "secret" })
		}},
		{"missing required availability", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				delete(value["coredumps"].(map[string]interface{}), "available")
			})
		}},
		{"wrong schema", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) { value["schema"] = 2 })
		}},
		{"persona changed", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["persona"].(map[string]interface{})["current"].(map[string]interface{})["inode"] = 4243
			})
		}},
		{"public VNC", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["desktop"].(map[string]interface{})["vnc_public_5901"] = true
			})
		}},
		{"profile still running", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["profile"].(map[string]interface{})["profile_process_count"] = 1
			})
		}},
		{"unavailable source fabricates count", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["coredumps"].(map[string]interface{})["count"] = 0
			})
		}},
		{"inconsistent kernel availability", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["kernel_oom"] = map[string]interface{}{"available": false, "count": nil, "sha256": nil}
			})
		}},
		{"missing browser lifecycle", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				events := value["runtime_logs"].(map[string]interface{})["events"].(map[string]interface{})
				events["browser_context_closed"] = 0
			})
		}},
		{"VNC unit inactive", func() []byte {
			return mutateQualifyingForensics(t, func(value map[string]interface{}) {
				value["systemd_units"].(map[string]interface{})["tigervncserver@:1.service"].(map[string]interface{})["active_state"] = "inactive"
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidatePBPForensics(test.data()); err == nil {
				t.Fatal("manipulated forensics evidence was accepted")
			}
		})
	}
}

func TestRunnerFailsClosedWhenMandatoryForensicsIsMissingButPreservesSoakResult(t *testing.T) {
	remote := &fakeRemote{result: qualifyingResult(t), completeAfter: 90}
	control := &fakeControl{}
	clock := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	runner := Runner{
		ValidateBinding: func(Host) error { return nil }, Remote: remote, Control: control,
		Now:          func() time.Time { return clock },
		Sleep:        func(_ context.Context, duration time.Duration) error { clock = clock.Add(duration); return nil },
		PollInterval: 20 * time.Second, RebootTimeout: time.Minute, SoakTimeout: 60 * time.Minute,
	}
	report, result, err := runner.Run(context.Background(), testInventory(true))
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Code != "pbp_forensics_invalid" || report.Status != "FAIL" {
		t.Fatalf("report=%+v error=%#v", report, err)
	}
	if report.PBPForensics != nil || report.QualifyingPBPPass || string(result) != string(remote.result) {
		t.Fatalf("missing mandatory forensics was not fail-closed: report=%+v result-bytes=%d", report, len(result))
	}
	forensicsIndex, resultIndex := -1, -1
	for index, action := range remote.actions {
		if action.action == ActionPBPForensics {
			forensicsIndex = index
		}
		if action.action == ActionPBPSoakResult {
			resultIndex = index
		}
	}
	if forensicsIndex < 0 || resultIndex != forensicsIndex+1 {
		t.Fatalf("forensics did not precede result cleanup: %d/%d", forensicsIndex, resultIndex)
	}
}

func TestRunnerRefusesUnconfirmedHostKeyAndMissingAttestationsBeforeBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Inventory)
		code   string
	}{
		{
			name: "host key confirmation",
			mutate: func(inventory *Inventory) {
				inventory.Hosts[2].HostKeyVerifiedOutOfBand = false
			},
			code: "lab_hostkey_unconfirmed",
		},
		{
			name: "role attestation",
			mutate: func(inventory *Inventory) {
				inventory.Hosts[1].AttestedGates = inventory.Hosts[1].AttestedGates[:2]
			},
			code: "lab_attestations_missing",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := testInventory(true)
			test.mutate(&inventory)
			remote := &fakeRemote{result: qualifyingResult(t)}
			control := &fakeControl{}
			bindings := 0
			runner := Runner{
				ValidateBinding: func(Host) error { bindings++; return nil },
				Remote:          remote,
				Control:         control,
			}
			report, _, err := runner.Run(context.Background(), inventory)
			var runErr *RunError
			if !errors.As(err, &runErr) || !runErr.Blocked || runErr.Code != test.code || report.Status != "BLOCKED" {
				t.Fatalf("report=%+v error=%#v", report, err)
			}
			if bindings != 0 || len(remote.actions) != 0 || len(control.operations) != 0 {
				t.Fatalf("network-capable operation before gate: bindings=%d remote=%v control=%v", bindings, remote.actions, control.operations)
			}
		})
	}
}

func TestQualificationMatrixIsCompleteOrderedAndClosed(t *testing.T) {
	matrix := QualificationMatrix()
	if len(matrix) < 20 {
		t.Fatalf("qualification matrix is unexpectedly small: %d", len(matrix))
	}
	seen := map[string]bool{}
	soak := -1
	for index, step := range matrix {
		if step.Sequence != index+1 || step.Name == "" || step.Role == "" || step.Kind == "" || seen[step.Name] {
			t.Fatalf("invalid matrix step %d: %+v", index, step)
		}
		seen[step.Name] = true
		for _, action := range step.Actions {
			if !IsFixedAction(action) {
				t.Fatalf("matrix contains non-fixed action %q", action)
			}
		}
		if step.Name == "pbp-qualifying-soak" {
			soak = index
			joined := make([]string, len(step.Actions))
			for actionIndex := range step.Actions {
				joined[actionIndex] = string(step.Actions[actionIndex])
			}
			if strings.Join(joined, ",") != "pbp-soak-start,pbp-soak-poll,pbp-forensics,pbp-soak-result" {
				t.Fatalf("soak action order = %v", step.Actions)
			}
		}
	}
	if soak < 0 || !seen["serving-flow-reconcile-idempotent"] || !seen["serving-reboot-resume"] ||
		!seen["enrollment-public-key-only"] || !seen["recovery-evidence"] ||
		!seen["parallel-apply-lock-and-resume"] || !seen["vnc-secret-rotation"] ||
		!seen["pbp-reboot-resume"] || !seen["signed-revocation"] {
		t.Fatalf("matrix misses a mandatory phase: %+v", matrix)
	}
	for _, role := range []string{"enrollment", "recovery-negative"} {
		host := Host{Role: role, AttestedGates: RequiredAttestations(role)}
		if missing := MissingAttestations(host); len(missing) != 0 {
			t.Fatalf("complete %s gates reported missing: %v", role, missing)
		}
		host.AttestedGates = host.AttestedGates[:len(host.AttestedGates)-1]
		if len(MissingAttestations(host)) != 1 {
			t.Fatalf("missing %s gate was not detected", role)
		}
	}
}

func TestMutatingActionsAreExplicitlyClassified(t *testing.T) {
	for _, action := range []Action{ActionServingReconcile, ActionServingRestart, ActionApplyConcurrency, ActionReboot, ActionPBPSoakStart, ActionPBPSoakResult} {
		if !IsMutatingAction(action) {
			t.Fatalf("mutating action %q was not gated", action)
		}
	}
	for _, action := range []Action{ActionPreflight, ActionServingProbe, ActionRuntimeProbe, ActionEnrollmentProbe, ActionRecoveryProbe, ActionReachable, ActionVNCProbe, ActionPBPProbe, ActionPBPIdentity, ActionPBPSoakPoll, ActionPBPForensics} {
		if IsMutatingAction(action) {
			t.Fatalf("read-only action %q was classified mutating", action)
		}
	}
}
