package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/application"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/systemstate"
)

func TestSystemSelectCLIJSONPlanCommitAndHumanRoundTrip(t *testing.T) {
	home, first, second := selectionCLIFixture(t)
	before := snapshotCLIState(t, home)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "select", "--plan", second.System.Name)
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	var plan application.SelectSystemPlan
	if err := json.Unmarshal(envelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Command != "system.select.plan" || !plan.Plan || plan.AlreadyActive ||
		plan.System.ID != second.System.ID || plan.PreviousSystemID != first.System.ID || plan.NetworkConnections != 0 {
		t.Fatalf("unexpected selection plan: envelope=%+v data=%+v", envelope, plan)
	}
	if !reflect.DeepEqual(before, snapshotCLIState(t, home)) {
		t.Fatal("CLI selection plan changed private state")
	}

	status, stdout, stderr = invokeCLI(t, "system", "select", second.System.Name, "--home", home,
		"--expect-revision", strconv.FormatUint(plan.RegistryRevision, 10), "--json")
	if status != exitOK || stderr != "" {
		t.Fatalf("commit status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope = decodeCLIEnvelope(t, stdout)
	var result application.SelectSystemResult
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Command != "system.select" || !result.Changed || result.System.ID != second.System.ID ||
		result.PreviousSystemID != first.System.ID || result.RegistryRevision != plan.RegistryRevision+1 || result.NetworkConnections != 0 {
		t.Fatalf("unexpected selection result: envelope=%+v data=%+v", envelope, result)
	}
	if strings.Contains(stdout, "PRIVATE KEY") || strings.Contains(stdout, filepath.Join(home, "systems")) {
		t.Fatal("selection output exposed private material or paths")
	}
	status, dashboardOut, stderr := invokeCLI(t, "--home", home, "--json", "dashboard")
	if status != exitOK || stderr != "" {
		t.Fatalf("dashboard status=%d stderr=%q", status, stderr)
	}
	var dashboard application.DashboardSnapshot
	if err := json.Unmarshal(decodeCLIEnvelope(t, dashboardOut).Data, &dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard.ActiveSystemID != second.System.ID || dashboard.Bootstrap == nil || dashboard.Bootstrap.PublicKey != second.Cloud.PublicKey {
		t.Fatal("subsequent dashboard did not use the explicitly selected system")
	}
	beforeNoop := snapshotCLIState(t, home)
	status, stdout, stderr = invokeCLI(t, "--home", home, "--json", "system", "select", "id:"+second.System.ID)
	if status != exitOK || stderr != "" {
		t.Fatalf("idempotent explicit-ID selection status=%d stderr=%q", status, stderr)
	}
	if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.RegistryRevision != dashboard.RegistryRevision || !reflect.DeepEqual(beforeNoop, snapshotCLIState(t, home)) {
		t.Fatal("idempotent CLI selection changed revision, audit or identity state")
	}

	status, stdout, stderr = invokeCLI(t, "--home", home, "system", "select", first.System.ID, "--plan")
	if status != exitOK || stderr != "" || !strings.Contains(stdout, "PLAN select system alpha (") || !strings.Contains(stdout, "Network connections: 0") {
		t.Fatalf("human plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	status, stdout, stderr = invokeCLI(t, "--home", home, "system", "select", first.System.ID)
	if status != exitOK || !strings.Contains(stdout, "Active system: alpha ("+first.System.ID+")") ||
		!strings.Contains(stdout, "Changed: true") || !strings.Contains(stdout, "Network connections: 0") ||
		!strings.Contains(stderr, "[system_selection] complete") {
		t.Fatalf("human selection status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func TestSystemSelectCLIStaleRevisionIsStructuredAndReadOnly(t *testing.T) {
	home, _, second := selectionCLIFixture(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	systems, err := systemstate.New(store)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := systems.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := systems.CreateOrGet("concurrently-created"); err != nil {
		t.Fatal(err)
	}
	before := snapshotCLIState(t, home)
	for _, planOnly := range []bool{false, true} {
		arguments := []string{"--json", "--home", home, "system", "select", second.System.Name,
			"--expect-revision", strconv.FormatUint(registry.Revision, 10)}
		if planOnly {
			arguments = append(arguments, "--plan")
		}
		status, stdout, stderr := invokeCLI(t, arguments...)
		if status != exitConflict || stdout != "" {
			t.Fatalf("stale selection status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Command != "system.select" || envelope.Error == nil || envelope.Error.Code != "system_conflict" {
			t.Fatalf("stale selection envelope=%+v", envelope)
		}
		if !reflect.DeepEqual(before, snapshotCLIState(t, home)) {
			t.Fatal("stale CLI selection changed state")
		}
	}
}

func TestSystemSelectCLIBusyTargetReturnsConflictWithoutNetwork(t *testing.T) {
	home, first, second := selectionCLIFixture(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.System.ID, second.System.ID} {
		if err := store.WithLock(filepath.Join("systems", id, "operations", "control-bootstrap.lock"), func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	held, unlock, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- store.WithLock(filepath.Join("systems", second.System.ID, "operations", "control-bootstrap.lock"), func() error {
			close(held)
			<-unlock
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-done:
		t.Fatalf("hold target operation lock: %v", err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			close(unlock)
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	defer release()
	type output struct {
		status         int
		stdout, stderr string
	}
	completed := make(chan output, 1)
	go func() {
		status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "select", second.System.Name)
		completed <- output{status, stdout, stderr}
	}()
	select {
	case result := <-completed:
		if result.status != exitConflict || result.stdout != "" {
			t.Fatalf("busy selection status=%d stdout=%q stderr=%q", result.status, result.stdout, result.stderr)
		}
		envelope := decodeCLIEnvelope(t, result.stderr)
		if envelope.Error == nil || envelope.Error.Code != "system_conflict" || envelope.Command != "system.select" {
			t.Fatalf("busy selection envelope=%+v", envelope)
		}
	case <-time.After(2 * time.Second):
		release()
		<-completed
		t.Fatal("CLI waited for a busy target instead of returning conflict")
	}
}

func TestSystemSelectCLIHelpIsStateFreeAndDescribesRevisionAndExactID(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(strconv.FormatBool(jsonOutput), func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "must-not-exist")
			arguments := []string{"--home", home, "system", "select", "--help"}
			if jsonOutput {
				arguments = append(arguments, "--json")
			}
			status, stdout, stderr := invokeCLI(t, arguments...)
			if status != exitOK || stderr != "" {
				t.Fatalf("help status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			text := stdout
			if jsonOutput {
				envelope := decodeCLIEnvelope(t, stdout)
				var help struct {
					Topic string `json:"topic"`
					Text  string `json:"text"`
				}
				if err := json.Unmarshal(envelope.Data, &help); err != nil {
					t.Fatal(err)
				}
				if !envelope.OK || envelope.Command != "help" || help.Topic != "system.select" {
					t.Fatalf("help envelope=%+v data=%+v", envelope, help)
				}
				text = help.Text
			}
			for _, required := range []string{"flow system select NAME_OR_ID", "--plan", "--expect-revision N", "id:", "local active context"} {
				if !strings.Contains(text, required) {
					t.Fatalf("selection help omits %q", required)
				}
			}
			if _, err := os.Lstat(home); !os.IsNotExist(err) {
				t.Fatalf("selection help opened operator state: %v", err)
			}
		})
	}
}

func TestSystemSelectCLIInvalidFlagsAndMissingSystemRemainStructured(t *testing.T) {
	home := privateTempDir(t)
	for _, test := range []struct {
		args []string
		exit int
		code string
	}{
		{nil, exitUsage, "usage"},
		{[]string{"alpha", "extra"}, exitUsage, "usage"},
		{[]string{"alpha", "--unknown"}, exitUsage, "usage"},
		{[]string{"alpha", "--expect-revision", "-1"}, exitUsage, "usage"},
		{[]string{"alpha", "--expect-revision", "invalid"}, exitUsage, "usage"},
		{[]string{"alpha", "--plan=invalid"}, exitUsage, "usage"},
		{[]string{"missing"}, exitConfig, "system_not_found"},
		{[]string{"missing", "--plan"}, exitConfig, "system_not_found"},
	} {
		arguments := append([]string{"--json", "--home", home, "system", "select"}, test.args...)
		status, stdout, stderr := invokeCLI(t, arguments...)
		if status != test.exit || stdout != "" {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", test.args, status, stdout, stderr)
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.OK || envelope.Command != "system.select" || envelope.Error == nil || envelope.Error.Code != test.code {
			t.Fatalf("args=%v envelope=%+v", test.args, envelope)
		}
	}
}

func selectionCLIFixture(t *testing.T) (string, application.InitSystemResult, application.InitSystemResult) {
	t.Helper()
	home := privateTempDir(t)
	results := make([]application.InitSystemResult, 0, 2)
	for _, name := range []string{"alpha", "beta"} {
		status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "init", "--name", name)
		if status != exitOK || stderr != "" {
			t.Fatalf("initialize %s status=%d stderr=%q", name, status, stderr)
		}
		var result application.InitSystemResult
		if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &result); err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	sentinel := filepath.Join(t.TempDir(), "unexpected-network-process")
	installRouteGateProcessSentinels(t, sentinel)
	t.Cleanup(func() {
		if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
			t.Errorf("system selection invoked a network-capable process: %v", err)
		}
	})
	return home, results[0], results[1]
}
