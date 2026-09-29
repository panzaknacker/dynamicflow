package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type controlCLIFixture struct {
	home             string
	systemID         string
	hostPublicPath   string
	hostPrivatePath  string
	hostPrivateBytes []byte
	bootstrapPath    string
	bootstrapBytes   []byte
}

func TestControlBindPlanCommitAndStatusJSONContracts(t *testing.T) {
	fixture := newControlCLIFixture(t)
	before := snapshotCLIState(t, fixture.home)
	arguments := fixture.bindArguments(true)
	status, stdout, stderr := invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	planEnvelope := decodeCLIEnvelope(t, stdout)
	if !planEnvelope.OK || planEnvelope.Command != "control.bind.plan" {
		t.Fatalf("plan envelope = %+v", planEnvelope)
	}
	var plan struct {
		Plan                 bool     `json:"plan"`
		SystemID             string   `json:"system_id"`
		ControlName          string   `json:"control_name"`
		CanonicalHost        string   `json:"canonical_host"`
		Port                 int      `json:"port"`
		HostKeyFingerprint   string   `json:"host_key_fingerprint"`
		Changes              []string `json:"changes"`
		NetworkConnections   int      `json:"network_connections"`
		GeneratesPrivateKeys bool     `json:"generates_private_keys"`
	}
	if err := json.Unmarshal(planEnvelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.Plan || plan.SystemID != fixture.systemID || plan.ControlName != "control-1" ||
		plan.CanonicalHost != "control.example.test" || plan.Port != 22 ||
		plan.HostKeyFingerprint == "" || len(plan.Changes) != 3 ||
		plan.NetworkConnections != 0 || plan.GeneratesPrivateKeys {
		t.Fatalf("plan = %+v", plan)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)
	after := snapshotCLIState(t, fixture.home)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("--plan changed local state:\nbefore=%v\nafter=%v", before, after)
	}
	if _, err := os.Lstat(filepath.Join(fixture.home, "systems", fixture.systemID, "control-nodes")); !os.IsNotExist(err) {
		t.Fatalf("--plan created Control state: %v", err)
	}

	arguments = fixture.bindArguments(false)
	status, stdout, stderr = invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	bindEnvelope := decodeCLIEnvelope(t, stdout)
	if !bindEnvelope.OK || bindEnvelope.Command != "control.bind" {
		t.Fatalf("bind envelope = %+v", bindEnvelope)
	}
	var bound struct {
		Created bool `json:"created"`
		Resumed bool `json:"resumed"`
		Control struct {
			Name            string `json:"name"`
			Host            string `json:"host"`
			HostFingerprint string `json:"host_fingerprint"`
			Lifecycle       string `json:"lifecycle"`
		} `json:"control"`
		Task struct {
			Phase string `json:"phase"`
		} `json:"task"`
		NetworkConnections int `json:"network_connections"`
	}
	if err := json.Unmarshal(bindEnvelope.Data, &bound); err != nil {
		t.Fatal(err)
	}
	if !bound.Created || bound.Resumed || bound.Control.Name != "control-1" ||
		bound.Control.Host != "control.example.test" || bound.Control.HostFingerprint != plan.HostKeyFingerprint ||
		bound.Control.Lifecycle != "bound" || bound.Task.Phase != "hostkey_verified" || bound.NetworkConnections != 0 {
		t.Fatalf("bound result = %+v", bound)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	status, stdout, stderr = invokeCLI(t, "--json", "--home", fixture.home, "control", "status")
	if status != exitOK || stderr != "" {
		t.Fatalf("status status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	statusEnvelope := decodeCLIEnvelope(t, stdout)
	if !statusEnvelope.OK || statusEnvelope.Command != "control.status" {
		t.Fatalf("status envelope = %+v", statusEnvelope)
	}
	var statusData struct {
		Controls []struct {
			Name      string `json:"name"`
			Lifecycle string `json:"lifecycle"`
		} `json:"controls"`
		Topology *struct {
			Generation   uint64 `json:"generation"`
			ControlReady bool   `json:"control_ready"`
		} `json:"topology"`
	}
	if err := json.Unmarshal(statusEnvelope.Data, &statusData); err != nil {
		t.Fatal(err)
	}
	if len(statusData.Controls) != 1 || statusData.Controls[0].Name != "control-1" ||
		statusData.Controls[0].Lifecycle != "bound" || statusData.Topology == nil ||
		statusData.Topology.Generation != 1 || statusData.Topology.ControlReady {
		t.Fatalf("status data = %+v", statusData)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	committed := snapshotCLIState(t, fixture.home)
	status, stdout, stderr = invokeCLI(t, fixture.bindArguments(true)...)
	if status != exitOK || stderr != "" || decodeCLIEnvelope(t, stdout).Command != "control.bind.plan" {
		t.Fatalf("repeat plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if current := snapshotCLIState(t, fixture.home); !reflect.DeepEqual(current, committed) {
		t.Fatalf("repeat --plan changed committed state:\nbefore=%v\nafter=%v", committed, current)
	}
}

func TestControlHumanContractsContainTrustFactsButNoKeyPaths(t *testing.T) {
	fixture := newControlCLIFixture(t)
	arguments := fixture.bindArguments(true)
	arguments = withoutJSON(arguments)
	status, stdout, stderr := invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" || !strings.Contains(stdout, "PLAN Control control-1") ||
		!strings.Contains(stdout, "Network connections: 0") || !strings.Contains(stdout, "Host-key fingerprint: SHA256:") {
		t.Fatalf("human plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	arguments = withoutJSON(fixture.bindArguments(false))
	status, stdout, stderr = invokeCLI(t, arguments...)
	if status != exitOK || !strings.Contains(stdout, "Control control-1 binding created") ||
		!strings.Contains(stdout, "Lifecycle: bound") || !strings.Contains(stdout, "Network connections: 0") ||
		strings.Contains(stderr, "ERROR") {
		t.Fatalf("human bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)

	status, stdout, stderr = invokeCLI(t, "--home", fixture.home, "control", "status")
	if status != exitOK || stderr != "" || !strings.Contains(stdout, "Control status for system lab") ||
		!strings.Contains(stdout, "hostkey SHA256:") || !strings.Contains(stdout, "Topology: generation 1") {
		t.Fatalf("human status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)
}

func TestControlCLIUsageEvidenceAndConflictExitCodes(t *testing.T) {
	fixture := newControlCLIFixture(t)
	tests := []struct {
		name    string
		args    []string
		want    int
		command string
		code    string
	}{
		{name: "missing flags", args: []string{"--json", "--home", fixture.home, "control", "bind", "control-1"}, want: exitUsage, command: "control.bind", code: "usage"},
		{name: "relative hostkey", args: []string{"--json", "--home", fixture.home, "control", "bind", "control-1", "--host", "control.example.test", "--ssh-user", "debian", "--os", "debian-13", "--hostkey-file", "relative.pub", "--evidence", "provider-console"}, want: exitUsage, command: "control.bind", code: "usage"},
		{name: "unsupported os", args: replaceControlArgument(fixture.bindArguments(true), "--os", "debian-12"), want: exitUsage, command: "control.bind", code: "control_os"},
		{name: "network evidence", args: replaceControlArgument(fixture.bindArguments(true), "--evidence", "ssh-keyscan"), want: exitUsage, command: "control.bind", code: "control_evidence"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, stdout, stderr := invokeCLI(t, test.args...)
			if status != test.want || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.OK || envelope.Command != test.command || envelope.Error == nil || envelope.Error.Code != test.code || envelope.Error.Next == "" {
				t.Fatalf("failure envelope = %+v", envelope)
			}
			assertNoControlCLISecret(t, stdout+stderr, fixture)
		})
	}

	symlink := filepath.Join(t.TempDir(), "hostkey-link.pub")
	if err := os.Symlink(fixture.hostPublicPath, symlink); err != nil {
		t.Fatal(err)
	}
	symlinkArgs := replaceControlArgument(fixture.bindArguments(true), "--hostkey-file", symlink)
	status, stdout, stderr := invokeCLI(t, symlinkArgs...)
	if status != exitConfig || stdout != "" {
		t.Fatalf("symlink status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.Command != "control.bind" || failure.Error == nil || failure.Error.Code != "control_hostkey_file" {
		t.Fatalf("symlink failure = %+v", failure)
	}

	if status, stdout, stderr := invokeCLI(t, fixture.bindArguments(false)...); status != exitOK || stderr != "" {
		t.Fatalf("initial bind status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	conflictArgs := replaceControlArgument(fixture.bindArguments(false), "--host", "203.0.113.99")
	status, stdout, stderr = invokeCLI(t, conflictArgs...)
	if status != exitConflict || stdout != "" {
		t.Fatalf("conflict status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure = decodeCLIEnvelope(t, stderr)
	if failure.Command != "control.bind" || failure.Error == nil || failure.Error.Code != "control_binding_conflict" {
		t.Fatalf("conflict failure = %+v", failure)
	}
	assertNoControlCLISecret(t, stdout+stderr, fixture)
}

func TestControlHelpDispatchLeafHelpAndRequestedCommandIDAreStable(t *testing.T) {
	home := filepath.Join(t.TempDir(), "must-not-exist")
	for _, args := range [][]string{
		{"--home", home, "control", "--help"},
		{"--home", home, "help", "control"},
		{"--home", home, "control", "bind", "--help"},
		{"--home", home, "control", "check", "--help"},
		{"--home", home, "control", "install", "--help"},
		{"--home", home, "control", "status", "-h"},
	} {
		status, stdout, stderr := invokeCLI(t, args...)
		if status != exitOK || stderr != "" || !strings.Contains(stdout, "flow control bind NAME") ||
			!strings.Contains(stdout, "flow control check NAME [--plan]") ||
			!strings.Contains(stdout, "flow control install NAME [--plan]") || !strings.Contains(stdout, "flow control status") {
			t.Fatalf("help args=%v status=%d stdout=%q stderr=%q", args, status, stdout, stderr)
		}
		if _, err := os.Lstat(home); !os.IsNotExist(err) {
			t.Fatalf("help opened operator state: %v", err)
		}
	}
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "control", "bind", "--help")
	if status != exitOK || stderr != "" {
		t.Fatalf("JSON help status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var help struct {
		Topic string `json:"topic"`
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if err := json.Unmarshal(envelope.Data, &help); err != nil || envelope.Command != "help" || help.Topic != "control.bind" {
		t.Fatalf("JSON help = %+v topic=%+v", envelope, help)
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"control"}, "control"},
		{[]string{"control", "bind", "operator-provided-name", "--host", "secret.example"}, "control.bind"},
		{[]string{"control", "check", "operator-provided-name"}, "control.check"},
		{[]string{"control", "install", "operator-provided-name"}, "control.install"},
		{[]string{"control", "status"}, "control.status"},
	} {
		if got := requestedCommandID(test.args); got != test.want {
			t.Fatalf("requestedCommandID(%v)=%q, want %q", test.args, got, test.want)
		}
	}
}

func newControlCLIFixture(t *testing.T) controlCLIFixture {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	home := privateTempDir(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "system", "init", "--name", "lab", "--control-name", "control-1")
	if status != exitOK || stderr != "" {
		t.Fatalf("initialize fixture status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var initialized struct {
		System struct {
			ID string `json:"id"`
		} `json:"system"`
	}
	if err := json.Unmarshal(decodeCLIEnvelope(t, stdout).Data, &initialized); err != nil {
		t.Fatal(err)
	}
	hostBase := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")
	command := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "cli-control-test", "-f", hostBase)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate host key: %v: %s", err, output)
	}
	hostPrivate, err := os.ReadFile(hostBase)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := filepath.Join(home, "systems", initialized.System.ID, "keys", "bootstrap", "control-1", "generations", "000001", "id_ed25519")
	bootstrap, err := os.ReadFile(bootstrapPath)
	if err != nil {
		t.Fatal(err)
	}
	return controlCLIFixture{
		home: home, systemID: initialized.System.ID, hostPublicPath: hostBase + ".pub",
		hostPrivatePath: hostBase, hostPrivateBytes: hostPrivate,
		bootstrapPath: bootstrapPath, bootstrapBytes: bootstrap,
	}
}

func (fixture controlCLIFixture) bindArguments(plan bool) []string {
	arguments := []string{
		"--json", "--home", fixture.home, "control", "bind", "control-1",
		"--host", "Control.Example.TEST", "--ssh-user", "debian", "--os", "debian-13",
		"--hostkey-file", fixture.hostPublicPath, "--evidence", "provider-console",
	}
	if plan {
		arguments = append(arguments, "--plan")
	}
	return arguments
}

func assertNoControlCLISecret(t *testing.T, output string, fixture controlCLIFixture) {
	t.Helper()
	for _, forbidden := range []string{
		fixture.hostPublicPath, fixture.hostPrivatePath, fixture.bootstrapPath,
		string(fixture.hostPrivateBytes), string(fixture.bootstrapBytes), "PRIVATE KEY",
	} {
		if forbidden != "" && strings.Contains(output, forbidden) {
			t.Fatalf("Control CLI output leaked private key material or an input/key path: %q", forbidden)
		}
	}
}

func withoutJSON(arguments []string) []string {
	result := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument != "--json" {
			result = append(result, argument)
		}
	}
	return result
}

func replaceControlArgument(arguments []string, option, value string) []string {
	result := append([]string(nil), arguments...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == option {
			result[index+1] = value
			return result
		}
	}
	return result
}

func snapshotCLIState(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative] = "dir:" + info.Mode().String()
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		result[relative] = fmt.Sprintf("file:%s:%x", info.Mode().String(), digest)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReadBoundedPublicKeyFileRejectsSymlinksEmptyAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.pub")
	if err := os.WriteFile(valid, []byte("ssh-ed25519 public\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readBoundedPublicKeyFile(valid)
	if err != nil || !bytes.Equal(data, []byte("ssh-ed25519 public\n")) {
		t.Fatalf("valid read = %q, err=%v", data, err)
	}
	empty := filepath.Join(directory, "empty.pub")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "large.pub")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, int(maxHostPublicKeyFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.pub")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{empty, oversized, symlink, filepath.Join(directory, "missing.pub")} {
		if _, err := readBoundedPublicKeyFile(path); !errors.Is(err, errPublicKeyFileUnsafe) {
			t.Errorf("path %s error = %v", path, err)
		}
	}
}
