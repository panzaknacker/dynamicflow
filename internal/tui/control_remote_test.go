package tui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
)

type tuiRemoteRunner struct {
	calls    int
	binary   []byte
	envelope []byte
	now      time.Time
}

func tuiEnvelopeDigest(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }

func (runner *tuiRemoteRunner) Run(_ context.Context, argv []string, stdin io.Reader, stdout, _ io.Writer) error {
	runner.calls++
	command := argv[len(argv)-1]
	if command == "/bin/true" {
		return nil
	}
	if strings.Contains(command, "control-runtime install") {
		payload, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(payload, runner.binary) {
			return errors.New("unexpected runtime payload")
		}
		runner.envelope = bytes.Clone(payload[len(runner.binary):])
		_, err = controlruntime.ParseCanonical(runner.envelope)
		return err
	}
	fields := strings.Split(command, " ")
	if len(fields) != 5 || fields[0] != controlruntime.AttestationCommandV1 || stdin != nil {
		return errors.New("unexpected management session")
	}
	generation, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return err
	}
	// The TUI uses the actual Application and transport; only the remote process
	// boundary is substituted. Policy verification itself is covered by the
	// Application-to-Session integration tests.
	response, err := signing.CanonicalJSON(controlruntime.SessionResponse{Schema: 1, System: fields[1], Control: fields[2], Generation: generation,
		EnvelopeSHA256: tuiEnvelopeDigest(runner.envelope), Nonce: fields[4], ObservedAt: runner.now})
	if err != nil {
		return err
	}
	_, err = stdout.Write(response)
	return err
}

func TestControlRemoteKeyboardFlowPlansConfirmsAndReturnsVerifiedReceipt(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tuiRemoteRunner{binary: []byte("tui-test-runtime"), now: time.Now().UTC().Truncate(time.Second)}
	executable := filepath.Join(t.TempDir(), "flow")
	if err := os.WriteFile(executable, runner.binary, 0o700); err != nil {
		t.Fatal(err)
	}
	app, err := application.Open(application.Config{Store: store, Clock: func() time.Time { return runner.now }, ControlRunner: runner, ExecutablePath: executable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.InitSystem(context.Background(), application.InitSystemRequest{Name: "terminal-lab"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), tuiBindRequest(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CheckControl(context.Background(), application.CheckControlRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareControlInstall(context.Background(), application.PrepareControlInstallRequest{Name: "control-1"}, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	if !capabilityAllowed(snapshot, "control.apply") || capabilityAllowed(snapshot, "control.attest") || !strings.Contains(ui.View().Content, "p install control") {
		t.Fatalf("installation is not the next action: %s", ui.View().Content)
	}
	ui, command := updateTUI(t, ui, tuiText("p"))
	if !ui.busy || command == nil || runner.calls != 1 {
		t.Fatal("installation planning started a connection or was unavailable")
	}
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenControlApplyConfirm || ui.applyPlan == nil || runner.calls != 1 {
		t.Fatal("plan did not reach confirmation without network")
	}
	ui, command = updateTUI(t, ui, tuiText("enter"))
	if command != nil || ui.busy {
		t.Fatal("pasted Enter text authorized a remote operation")
	}
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if command == nil || !ui.busy {
		t.Fatal("explicit Enter did not start installation")
	}
	ui, duplicate := updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if duplicate != nil {
		t.Fatal("busy installation allowed duplicate submission")
	}
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenControlApplyDone || ui.applyDone == nil || runner.calls != 2 || !strings.Contains(ui.View().Content, "NOT READY") {
		t.Fatalf("installation receipt: %s", ui.View().Content)
	}
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, command())
	if !capabilityAllowed(ui.snapshot, "control.attest") || capabilityAllowed(ui.snapshot, "control.apply") {
		t.Fatal("post-install dashboard did not advance to attestation")
	}
	ui, command = updateTUI(t, ui, tuiText("a"))
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenControlAttestConfirm || ui.attestPlan == nil || runner.calls != 2 {
		t.Fatal("attestation plan opened a connection")
	}
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenControlAttestDone || ui.attestDone == nil || runner.calls != 3 || !strings.Contains(ui.View().Content, "Control management access verified") || !strings.Contains(ui.View().Content, "NOT READY") {
		t.Fatalf("attestation receipt: %s", ui.View().Content)
	}
	for _, forbidden := range []string{store.Root(), executable, "id_ed25519", "PRIVATE KEY"} {
		if strings.Contains(ui.View().Content, forbidden) {
			t.Fatalf("TUI receipt leaked %q", forbidden)
		}
	}
}

func TestRemoteControlFailureKeepsPlanAndAllowsRetryOrBack(t *testing.T) {
	for _, screen := range []screen{screenControlApplyConfirm, screenControlAttestConfirm} {
		ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
		ui.screen, ui.busy = screen, true
		ui.applyPlan = &application.InstallPreparedControlPlan{ControlName: "control-1"}
		ui.attestPlan = &application.AttestControlPlan{ControlName: "control-1"}
		failure := &application.Error{SafeText: "Remote operation failed.", Next: "Repair the pinned route and retry."}
		var message tea.Msg = controlApplyMsg{err: failure}
		if screen == screenControlAttestConfirm {
			message = controlAttestMsg{err: failure}
		}
		ui, _ = updateTUI(t, ui, message)
		if ui.screen != screen || ui.busy || ui.error == "" || !strings.Contains(ui.View().Content, "Repair the pinned route") {
			t.Fatal("remote failure lost its plan or recovery action")
		}
		ui, command := updateTUI(t, ui, tuiSpecial(tea.KeyEsc))
		if ui.screen != screenDashboard || !ui.busy || command == nil || ui.applyPlan != nil || ui.attestPlan != nil {
			t.Fatal("Escape did not return to a fresh dashboard")
		}
	}
}
