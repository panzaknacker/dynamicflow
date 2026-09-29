package tui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/workflow"
)

func tuiApplication(t *testing.T) *application.Application {
	return newTUIFixture(t, nil).app
}

type tuiFixture struct {
	app    *application.Application
	runner *tuiControlRunner
	home   string
}

type tuiControlRunner struct {
	mutex sync.Mutex
	calls int
	argv  []string
}

func (runner *tuiControlRunner) Run(_ context.Context, argv []string, stdin io.Reader, _, _ io.Writer) error {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.calls++
	runner.argv = append([]string(nil), argv...)
	if stdin != nil {
		return errors.New("unexpected SSH stdin")
	}
	return nil
}

func (runner *tuiControlRunner) snapshot() (int, []string) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return runner.calls, append([]string(nil), runner.argv...)
}

func newTUIFixture(t *testing.T, runner *tuiControlRunner) tuiFixture {
	t.Helper()
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	config := application.Config{
		Store: store, Clock: func() time.Time { return time.Date(2026, 7, 23, 15, 0, 0, 0, time.UTC) },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x61}, 128)), SSHKeygen: keygen,
	}
	if runner != nil {
		config.ControlRunner = runner
	}
	app, err := application.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	return tuiFixture{app: app, runner: runner, home: store.Root()}
}

func tuiHostPublicKey(seed byte) string {
	blob := make([]byte, 0, 4+len("ssh-ed25519")+4+32)
	blob = appendSSHTestString(blob, []byte("ssh-ed25519"))
	key := make([]byte, 32)
	for index := range key {
		key[index] = seed + byte(index)
	}
	blob = appendSSHTestString(blob, key)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " provider-console-host"
}

func appendSSHTestString(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func tuiBindRequest() application.BindControlRequest {
	return application.BindControlRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "control-1",
		Host: "203.0.113.40", Port: 22, SSHUser: "debian", OperatingSystem: controlnodes.OSDebian13,
		HostPublicKey: tuiHostPublicKey(0x21), EvidenceSource: controlnodes.EvidenceProviderConsole,
	}
}

func tuiText(value string) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: 'x', Text: value})
}

func tuiSpecial(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: code})
}

func updateTUI(t *testing.T, ui model, message tea.Msg) (model, tea.Cmd) {
	t.Helper()
	updated, command := ui.Update(message)
	result, ok := updated.(model)
	if !ok {
		t.Fatalf("updated model has type %T", updated)
	}
	return result, command
}

func TestFreshDashboardAndWizardNavigation(t *testing.T) {
	app := tuiApplication(t)
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	if view := ui.View(); !strings.Contains(view.Content, "NEW CONTROL PLANE") || strings.Contains(view.Content, "\x1b") {
		t.Fatalf("fresh view = %q", view.Content)
	}
	updated, _ := ui.Update(tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	ui = updated.(model)
	for _, character := range "lab-system" {
		updated, _ = ui.Update(tea.KeyPressMsg(tea.Key{Code: character, Text: string(character)}))
		ui = updated.(model)
	}
	if ui.name != "lab-system" || !strings.Contains(ui.View().Content, "No provider API") {
		t.Fatalf("wizard model=%+v view=%q", ui, ui.View().Content)
	}
}

func TestInitCommandAndRestartShowSamePublicKey(t *testing.T) {
	app := tuiApplication(t)
	message := initSystemCommand(context.Background(), app, "lab")()
	initialized := message.(initSystemMsg)
	if initialized.err != nil || initialized.result.Cloud.PublicKey == "" {
		t.Fatalf("init message = %+v", initialized)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	view := ui.View().Content
	if snapshot.Bootstrap == nil || snapshot.Bootstrap.PublicKey != initialized.result.Cloud.PublicKey ||
		!strings.Contains(view, initialized.result.Cloud.PublicKey) || !strings.Contains(view, "TRUST GATE") {
		t.Fatalf("restart lost public guide: bootstrap=%+v view=%q", snapshot.Bootstrap, view)
	}
	if strings.Contains(view, "PRIVATE KEY") || strings.Contains(view, "id_ed25519") {
		t.Fatal("TUI leaked private key material or path")
	}
}

func TestResizeAndRemoteTextRemainBounded(t *testing.T) {
	app := tuiApplication(t)
	snapshot, _ := app.Dashboard(context.Background())
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	updated, _ := ui.Update(tea.WindowSizeMsg{Width: 72, Height: 18})
	ui = updated.(model)
	ui.error = "remote\x1b]52;c;ZXhmaWw=\a\u202Eevil"
	view := ui.View().Content
	if strings.Contains(view, "\x1b") || strings.ContainsRune(view, '\u202e') || !strings.Contains(view, "�") {
		t.Fatalf("unsafe terminal text survived: %q", view)
	}
}

func TestNotReadyStatusIsNeverRenderedAsReady(t *testing.T) {
	ui := model{color: true}
	status := ui.status("NOT READY")
	if strings.Contains(status, green) || !strings.Contains(status, yellow) {
		t.Fatalf("NOT READY used a ready visual state: %q", status)
	}
}

func TestControlBindWizardPlansThenCommitsWithoutNetwork(t *testing.T) {
	runner := &tuiControlRunner{}
	fixture := newTUIFixture(t, runner)
	if _, err := fixture.app.InitSystem(context.Background(), application.InitSystemRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "bind-wizard", ControlName: "control-1",
	}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), fixture.app, snapshot, []string{"NO_COLOR=1"})
	if view := ui.View().Content; !strings.Contains(view, "b bind control") || !strings.Contains(view, "Press b") {
		t.Fatalf("bind action is not discoverable: %q", view)
	}

	ui, _ = updateTUI(t, ui, tuiText("b"))
	if ui.screen != screenControlBind || ui.bindForm.Name != "control-1" || ui.bindForm.Port != "22" {
		t.Fatalf("initial bind form = %+v screen=%v", ui.bindForm, ui.screen)
	}
	ui, _ = updateTUI(t, ui, tuiText("203.0.113.40"))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, tuiText("ubuntu"))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyRight))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyRight))
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	hostKey := tuiHostPublicKey(0x31)
	ui, _ = updateTUI(t, ui, tuiText(hostKey))

	var planCommand tea.Cmd
	ui, planCommand = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if planCommand == nil || !ui.busy {
		t.Fatal("final bind field did not request an explicit local plan")
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("bind preflight opened a network process: %d", calls)
	}
	ui, _ = updateTUI(t, ui, planCommand())
	if ui.screen != screenControlBindConfirm || ui.bindPlan == nil || ui.bindPlan.NetworkConnections != 0 ||
		ui.bindPlan.GeneratesPrivateKeys || ui.bindPlan.OperatingSystem != string(controlnodes.OSUbuntu2404) ||
		ui.bindPlan.EvidenceSource != string(controlnodes.EvidenceProviderAttestation) {
		t.Fatalf("bind confirmation plan = %+v screen=%v", ui.bindPlan, ui.screen)
	}
	if view := ui.View().Content; !strings.Contains(view, "Network connections   0") ||
		!strings.Contains(view, ui.bindPlan.HostKeyFingerprint) {
		t.Fatalf("binding plan is not visibly complete: %q", view)
	}

	// printable pasted text that spells a control key must never authorize a
	// trust commit. only an actual enter key event may do that.
	ui, planCommand = updateTUI(t, ui, tuiText("enter"))
	if ui.screen != screenControlBindConfirm || planCommand != nil {
		t.Fatal("pasted text authorized the binding")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEscape))
	if ui.screen != screenControlBind || ui.bindForm.HostPublicKey != hostKey {
		t.Fatal("Esc did not preserve the resumable binding form")
	}
	ui, planCommand = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, planCommand())

	var bindCommand tea.Cmd
	ui, bindCommand = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if bindCommand == nil {
		t.Fatal("explicit confirmation did not call the Application binding")
	}
	bindMessage := bindCommand()
	bound := bindMessage.(controlBindMsg)
	if bound.err != nil || bound.result.NetworkConnections != 0 || string(bound.result.Task.Phase) != "hostkey_verified" {
		t.Fatalf("bind result = %+v err=%v", bound.result, bound.err)
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("binding opened a network process: %d", calls)
	}
	var refresh tea.Cmd
	ui, refresh = updateTUI(t, ui, bindMessage)
	if refresh == nil {
		t.Fatal("successful bind did not refresh the dashboard")
	}
	ui, _ = updateTUI(t, ui, refresh())
	if ui.screen != screenDashboard || !capabilityAllowed(ui.snapshot, "control.check") || len(ui.snapshot.Controls) != 1 ||
		!strings.Contains(ui.View().Content, "c check control") {
		t.Fatalf("bound dashboard = %+v view=%q", ui.snapshot, ui.View().Content)
	}
}

func TestControlCheckConfirmationUsesOnePinnedFixedCommandAndRestartsCleanly(t *testing.T) {
	runner := &tuiControlRunner{}
	fixture := newTUIFixture(t, runner)
	if _, err := fixture.app.InitSystem(context.Background(), application.InitSystemRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "check-wizard", ControlName: "control-1",
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.BindControl(context.Background(), tuiBindRequest(), nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// constructing a fresh model represents a TUI process restart. the durable
	// Application state must put it back at the host-key verified gate.
	ui := newModel(context.Background(), fixture.app, snapshot, []string{"NO_COLOR=1"})
	if snapshot.Bootstrap == nil || string(snapshot.Bootstrap.Phase) != "hostkey_verified" ||
		!strings.Contains(ui.View().Content, "c check control") {
		t.Fatalf("restart did not restore the Control check gate: %+v", snapshot.Bootstrap)
	}

	var planCommand tea.Cmd
	ui, planCommand = updateTUI(t, ui, tuiText("c"))
	if planCommand == nil || !ui.busy {
		t.Fatal("c did not request an Application connectivity plan")
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("planning opened SSH: %d", calls)
	}
	ui, _ = updateTUI(t, ui, planCommand())
	if ui.screen != screenControlCheckConfirm || ui.checkPlan == nil || ui.checkPlan.NetworkConnections != 1 ||
		ui.checkPlan.FixedRemoteCommand != "/bin/true" {
		t.Fatalf("check plan = %+v screen=%v", ui.checkPlan, ui.screen)
	}
	view := ui.View().Content
	for _, expected := range []string{
		"Network connections  1", "Remote command       /bin/true", "Attempts             exactly one",
		"Retry                none", "Fallback             none", "pinned Ed25519 host key",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("check confirmation lacks %q: %q", expected, view)
		}
	}

	ui, planCommand = updateTUI(t, ui, tuiText("enter"))
	if ui.screen != screenControlCheckConfirm || planCommand != nil {
		t.Fatal("pasted text authorized the network connection")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEscape))
	if ui.screen != screenDashboard {
		t.Fatal("Esc did not return to durable dashboard state")
	}
	ui, planCommand = updateTUI(t, ui, tuiText("c"))
	ui, _ = updateTUI(t, ui, planCommand())

	var checkCommand tea.Cmd
	ui, checkCommand = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if checkCommand == nil {
		t.Fatal("explicit Enter did not call the Application connectivity operation")
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("SSH happened before executing the confirmed command: %d", calls)
	}
	checkMessage := checkCommand()
	checked := checkMessage.(controlCheckMsg)
	if checked.err != nil || checked.result.NetworkConnections != 1 || checked.result.Transport.Attempts != 1 ||
		checked.result.Transport.Route != "direct_first_control" {
		t.Fatalf("check result = %+v err=%v", checked.result, checked.err)
	}
	calls, argv := runner.snapshot()
	if calls != 1 || len(argv) == 0 || argv[len(argv)-1] != "/bin/true" {
		t.Fatalf("runner calls=%d argv=%#v", calls, argv)
	}
	var refresh tea.Cmd
	ui, refresh = updateTUI(t, ui, checkMessage)
	ui, _ = updateTUI(t, ui, refresh())
	if ui.screen != screenDashboard || controlCheckAvailable(ui.snapshot) ||
		len(ui.snapshot.Controls) != 1 || string(ui.snapshot.Controls[0].Lifecycle) != "connectivity_verified" {
		t.Fatalf("verified dashboard = %+v", ui.snapshot)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("dashboard refresh retried or fell back: %d", calls)
	}
}

func TestControlInstallPreparationPlansCommitsAndResumesWithoutNetwork(t *testing.T) {
	runner := &tuiControlRunner{}
	fixture := newTUIFixture(t, runner)
	initialized, err := fixture.app.InitSystem(context.Background(), application.InitSystemRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "install-wizard", ControlName: "control-1",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.BindControl(context.Background(), tuiBindRequest(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.CheckControl(context.Background(), application.CheckControlRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "control-1",
	}, nil); err != nil {
		t.Fatal(err)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("connectivity setup calls = %d, want 1", calls)
	}
	snapshot, err := fixture.app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), fixture.app, snapshot, []string{"NO_COLOR=1"})
	if !controlInstallAvailable(snapshot) || !capabilityAllowed(snapshot, "control.install") ||
		!strings.Contains(ui.View().Content, "i prepare control install") ||
		!strings.Contains(ui.View().Content, "does not install the remote VM") {
		t.Fatalf("local install action is not discoverable: capabilities=%+v view=%q", snapshot.Capabilities, ui.View().Content)
	}
	inconsistent := snapshot
	inconsistent.Controls = append([]controlnodes.Record(nil), snapshot.Controls...)
	inconsistent.Controls[0].Lifecycle = controlnodes.LifecycleReady
	if controlInstallAvailable(inconsistent) {
		t.Fatal("a stale allowed capability bypassed the concrete Control lifecycle gate")
	}
	inconsistent = snapshot
	inconsistent.Tasks = append([]workflow.Task(nil), snapshot.Tasks...)
	for index := range inconsistent.Tasks {
		if inconsistent.Tasks[index].Kind == workflow.ControlBootstrap {
			inconsistent.Tasks[index].Phase = workflow.PhaseReady
		}
	}
	if controlInstallAvailable(inconsistent) {
		t.Fatal("a stale allowed capability bypassed the concrete workflow gate")
	}

	var planCommand tea.Cmd
	ui, planCommand = updateTUI(t, ui, tuiText("i"))
	if planCommand == nil || !ui.busy {
		t.Fatal("i did not request the Application install plan")
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("planning opened a network process: %d", calls)
	}
	ui, _ = updateTUI(t, ui, planCommand())
	if ui.screen != screenControlInstallConfirm || ui.installPlan == nil ||
		ui.installPlan.NetworkConnections != 0 || ui.installPlan.RouteCount != 0 ||
		!ui.installPlan.GeneratesPrivateKeys || ui.installPlan.AlreadyPrepared {
		t.Fatalf("local install plan = %+v screen=%v", ui.installPlan, ui.screen)
	}
	for _, expected := range []string{
		"Routes authorized    0 (route-free)", "Network connections  0",
		"NO REMOTE INSTALLATION", "CONTROL WILL REMAIN NOT READY",
	} {
		if !strings.Contains(ui.View().Content, expected) {
			t.Fatalf("install confirmation lacks %q: %q", expected, ui.View().Content)
		}
	}

	// printable paste must never authorize the local identity/policy commit.
	ui, planCommand = updateTUI(t, ui, tuiText("enter"))
	if ui.screen != screenControlInstallConfirm || planCommand != nil {
		t.Fatal("pasted text authorized local Control installation preparation")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEscape))
	if ui.screen != screenDashboard || ui.installPlan != nil {
		t.Fatal("Esc did not return to the durable dashboard gate")
	}
	ui, planCommand = updateTUI(t, ui, tuiText("i"))
	ui, _ = updateTUI(t, ui, planCommand())

	var installCommand tea.Cmd
	ui, installCommand = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if installCommand == nil || !ui.busy {
		t.Fatal("explicit Enter did not call the Application preparation operation")
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("network process ran before executing local preparation: %d", calls)
	}
	installMessage := installCommand()
	prepared := installMessage.(controlInstallMsg)
	if prepared.err != nil || !prepared.result.Prepared || prepared.result.Resumed ||
		prepared.result.NetworkConnections != 0 || prepared.result.ManagementPublicKey == "" ||
		string(prepared.result.Control.Lifecycle) != "installing" || string(prepared.result.Task.Phase) != "installing" {
		t.Fatalf("local install result = %+v err=%v", prepared.result, prepared.err)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("local preparation opened a network process: %d", calls)
	}
	ui, _ = updateTUI(t, ui, installMessage)
	if ui.screen != screenControlInstallPrepared || ui.installDone == nil {
		t.Fatalf("prepared receipt screen=%v receipt=%+v", ui.screen, ui.installDone)
	}
	view := ui.View().Content
	for _, expected := range []string{
		"LOCAL CONTROL INSTALLATION CHECKPOINT PREPARED", "CONTROL NOT READY",
		"REMOTE INSTALLATION PENDING", prepared.result.ManagementPublicKey,
		"Routes authorized    0 (route-free)", "Network connections  0",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("prepared receipt lacks %q: %q", expected, view)
		}
	}
	privatePath := filepath.Join(fixture.home, "systems", initialized.System.ID, "keys", "control", "control-1", "generations", "000001", "id_ed25519")
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(fixture.home, "systems", initialized.System.ID, "control", "install", "control-1", "envelope-g1.json")
	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		fixture.home, privatePath, envelopePath, filepath.Join(fixture.home, "logs", "audit.jsonl"),
		string(privateBytes), string(envelopeBytes), "OPENSSH PRIVATE KEY", "id_ed25519",
	} {
		if forbidden != "" && strings.Contains(view, forbidden) {
			t.Fatalf("TUI leaked a private/checkpoint value %q", forbidden)
		}
	}

	// a printable paste on the receipt cannot navigate. a real esc refreshes
	// durable state, and a fresh TUI process exposes the resumable checkpoint.
	ui, planCommand = updateTUI(t, ui, tuiText("esc"))
	if ui.screen != screenControlInstallPrepared || planCommand != nil {
		t.Fatal("pasted text navigated away from the prepared receipt")
	}
	var refresh tea.Cmd
	ui, refresh = updateTUI(t, ui, tuiSpecial(tea.KeyEscape))
	if refresh == nil || ui.screen != screenDashboard || !ui.busy {
		t.Fatal("real Esc did not begin a durable dashboard refresh")
	}
	ui, _ = updateTUI(t, ui, refresh())
	if ui.busy || !controlInstallAvailable(ui.snapshot) || ui.snapshot.Topology == nil || ui.snapshot.Topology.ControlReady ||
		len(ui.snapshot.Controls) != 1 || string(ui.snapshot.Controls[0].Lifecycle) != "installing" {
		t.Fatalf("prepared dashboard incorrectly claims readiness: %+v", ui.snapshot)
	}

	restarted := newModel(context.Background(), fixture.app, ui.snapshot, []string{"NO_COLOR=1"})
	restarted, planCommand = updateTUI(t, restarted, tuiText("i"))
	restarted, _ = updateTUI(t, restarted, planCommand())
	if restarted.installPlan == nil || !restarted.installPlan.AlreadyPrepared || restarted.installPlan.GeneratesPrivateKeys {
		t.Fatalf("restart did not restore the exact prepared checkpoint: %+v", restarted.installPlan)
	}
	restarted, installCommand = updateTUI(t, restarted, tuiSpecial(tea.KeyEnter))
	installMessage = installCommand()
	resumed := installMessage.(controlInstallMsg)
	if resumed.err != nil || !resumed.result.Resumed || resumed.result.ManagementPublicKey != prepared.result.ManagementPublicKey ||
		resumed.result.EnvelopeDigest != prepared.result.EnvelopeDigest {
		t.Fatalf("resumed preparation changed public identity/checkpoint: %+v err=%v", resumed.result, resumed.err)
	}
	if calls, _ := runner.snapshot(); calls != 1 {
		t.Fatalf("resume retried connectivity or opened another network process: %d", calls)
	}
}

func TestControlInputAndErrorsAreBoundedSingleLineAndTerminalSafe(t *testing.T) {
	app := tuiApplication(t)
	if _, err := app.InitSystem(context.Background(), application.InitSystemRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: "safe-input", ControlName: "control-1",
	}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tuiText("b"))

	ui, _ = updateTUI(t, ui, tuiText("203.0.113.8\x1b]52;c;ZXhmaWw=\a\u202Eevil\nnext"))
	if ui.bindForm.Host != "" || ui.screen != screenControlBind {
		t.Fatalf("unsafe paste changed form or navigation: %+v", ui.bindForm)
	}
	ui, _ = updateTUI(t, ui, tuiText("esc"))
	if ui.screen != screenControlBind || ui.bindForm.Host != "esc" {
		t.Fatal("printable pasted text was interpreted as the Esc control key")
	}
	ui.bindForm.Host = ""
	ui, _ = updateTUI(t, ui, tuiText(strings.Repeat("a", 300)))
	if len([]rune(ui.bindForm.Host)) != 253 {
		t.Fatalf("host input was not bounded: %d", len([]rune(ui.bindForm.Host)))
	}
	ui.bindForm.Host = "safe\x1b]8;;https://example.invalid\aevil\u202E"
	ui.error = safeError("remote\x1b]52;c;ZXhmaWw=\a", "retry\u202Ehidden")
	view := ui.View().Content
	if strings.Contains(view, "\x1b") || strings.ContainsRune(view, '\u202e') || !strings.Contains(view, "Next:") {
		t.Fatalf("unsafe form/error text survived rendering: %q", view)
	}
}
