package tui

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/workflow"
)

func interruptKey() tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})
}

func assertQuitCommand(t *testing.T, command tea.Cmd) {
	t.Helper()
	if command == nil {
		t.Fatal("completed cancellation did not request exit")
	}
	if message := command(); !isQuitMessage(message) {
		t.Fatalf("exit command returned %T", message)
	}
}

func isQuitMessage(message tea.Msg) bool {
	_, ok := message.(tea.QuitMsg)
	return ok
}

func TestCancellationWaitsForEveryServiceResult(t *testing.T) {
	results := []tea.Msg{
		initSystemMsg{}, dashboardMsg{}, controlBindPlanMsg{}, controlBindMsg{},
		controlCheckPlanMsg{}, controlCheckMsg{}, controlInstallPlanMsg{}, controlInstallMsg{},
		controlApplyPlanMsg{}, controlApplyMsg{}, controlAttestPlanMsg{}, controlAttestMsg{},
		systemSelectPlanMsg{}, systemSelectMsg{},
	}
	for _, result := range results {
		ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
		operation := ui.beginOperation("Checking Control")
		ui, quit := updateTUI(t, ui, interruptKey())
		if quit != nil || !ui.busy || !ui.quitPending || !errors.Is(operation.Err(), context.Canceled) {
			t.Fatalf("Ctrl+C did not request cancellation and retain the busy model for %T", result)
		}
		ui, quit = updateTUI(t, ui, interruptKey())
		if quit != nil || !strings.Contains(ui.View().Content, "waiting for safe checkpoint") {
			t.Fatal("repeated Ctrl+C skipped the safe-completion wait")
		}
		ui, quit = updateTUI(t, ui, tuiSpecial(tea.KeyF1))
		if !ui.help || quit != nil {
			t.Fatal("help became inaccessible while cancelling")
		}
		ui, quit = updateTUI(t, ui, result)
		if ui.busy || ui.operationCancel != nil {
			t.Fatalf("result %T did not finish the operation lifecycle", result)
		}
		assertQuitCommand(t, quit)
	}
}

func TestContextAndFrameworkSignalsUseTheSafeCancellationPath(t *testing.T) {
	for _, message := range []tea.Msg{tea.InterruptMsg{}, tea.QuitMsg{}} {
		ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
		operation := ui.beginOperation("Installing Control")
		filtered := shutdownFilter(ui, message)
		if _, ok := filtered.(quitRequestMsg); !ok {
			t.Fatalf("framework signal %T bypasses the application drain", message)
		}
		ui, quit := updateTUI(t, ui, filtered)
		if quit != nil || !ui.busy || !ui.quitPending || operation.Err() == nil {
			t.Fatal("framework signal released the terminal before completion")
		}
		ui, quit = updateTUI(t, ui, controlApplyMsg{err: context.Canceled})
		if !isQuitMessage(shutdownFilter(ui, quit())) {
			t.Fatal("completed service could not release the terminal")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ui := newModel(ctx, nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
	operation := ui.beginOperation("Checking Control")
	watch := ui.Init()
	if watch == nil {
		t.Fatal("cancellable caller context has no model watcher")
	}
	cancel()
	ui, quit := updateTUI(t, ui, watch())
	if quit != nil || !ui.quitPending || operation.Err() == nil {
		t.Fatal("caller cancellation bypassed the command-completion wait")
	}
	ui, quit = updateTUI(t, ui, controlCheckMsg{err: context.Canceled})
	assertQuitCommand(t, quit)
	if ui.busy {
		t.Fatal("completed context cancellation remains busy")
	}
}

func TestBubbleTeaInterruptDrainsBeforeReturning(t *testing.T) {
	ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1", "TERM=dumb"})
	operation := ui.beginOperation("Checking Control")
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	program := tea.NewProgram(ui, tea.WithInput(input), tea.WithOutput(io.Discard),
		tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutRenderer(),
		tea.WithoutSignalHandler(), tea.WithFilter(shutdownFilter))
	t.Cleanup(program.Kill)
	type outcome struct {
		model tea.Model
		err   error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := program.Run()
		completed <- outcome{model: result, err: err}
	}()
	program.Send(tea.InterruptMsg{})
	select {
	case <-operation.Done():
	case result := <-completed:
		t.Fatalf("Bubble Tea quit instead of cancelling the command: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("Bubble Tea did not route the interrupt to the model")
	}
	program.Send(tea.QuitMsg{})
	select {
	case result := <-completed:
		t.Fatalf("a second framework quit skipped the completion wait: %v", result.err)
	default:
	}
	program.Send(controlCheckMsg{err: context.Canceled})
	select {
	case result := <-completed:
		if result.err != nil || result.model.(model).busy || !result.model.(model).quitPending {
			t.Fatalf("unexpected drained program state: model=%+v err=%v", result.model, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bubble Tea did not exit after command completion")
	}
}

func TestProgressBelongsToTheCurrentOperationAndRemainsTerminalSafe(t *testing.T) {
	ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
	messages := make(chan tea.Msg, 1)
	ui.send = func(message tea.Msg) { messages <- message }
	ctx := ui.beginOperation("Preparing local Control installation")
	observer := operationObserver(ctx)
	if observer == nil {
		t.Fatal("running service has no progress observer")
	}
	observer.OnEvent(application.Event{Phase: "control_policy\x1b]52;c;ZXhmaWw=\a", Status: "running\u202E", Detail: "public checkpoint"})
	message := <-messages
	ui, _ = updateTUI(t, ui, message)
	if view := ui.View().Content; !strings.Contains(view, "control_policy") || strings.Contains(view, "\x1b") || strings.ContainsRune(view, '\u202e') {
		t.Fatalf("progress is absent or terminal-unsafe: %q", view)
	}
	ui.finishOperation()
	if ctx.Err() == nil {
		t.Fatal("completed operation context was not released")
	}
	ui.beginOperation("Refreshing dashboard")
	defer ui.finishOperation()
	ui, _ = updateTUI(t, ui, message)
	if ui.progress.Phase != "" || strings.Contains(ui.View().Content, "control_policy") {
		t.Fatal("late progress from an earlier operation replaced the current status")
	}
}

type cancellingControlRunner struct {
	started   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (runner *cancellingControlRunner) Run(ctx context.Context, _ []string, _ io.Reader, _, _ io.Writer) error {
	close(runner.started)
	<-ctx.Done()
	close(runner.cancelled)
	<-runner.release
	return ctx.Err()
}

func TestControlCancellationQuitsOnlyAfterFailSafeStateIsPersisted(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &cancellingControlRunner{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
	app, err := application.Open(application.Config{Store: store, ControlRunner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.InitSystem(context.Background(), application.InitSystemRequest{Name: "cancel-terminal"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(context.Background(), tuiBindRequest(), nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	ui, command := updateTUI(t, ui, tuiText("c"))
	if command == nil {
		t.Fatal("connectivity plan is unavailable")
	}
	ui, _ = updateTUI(t, ui, command())
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if command == nil {
		t.Fatal("confirmed connectivity check is unavailable")
	}
	completed := make(chan tea.Msg, 1)
	go func() { completed <- command() }()
	released := false
	t.Cleanup(func() {
		if ui.operationCancel != nil {
			ui.operationCancel()
		}
		if !released {
			close(runner.release)
		}
	})
	select {
	case <-runner.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake pinned runner did not start")
	}
	ui, quit := updateTUI(t, ui, interruptKey())
	if quit != nil || !ui.quitPending {
		t.Fatal("Ctrl+C quit before the runner completed")
	}
	select {
	case <-runner.cancelled:
	case <-time.After(time.Second):
		t.Fatal("Ctrl+C did not cancel the service context")
	}
	select {
	case <-completed:
		t.Fatal("service returned while its runner was still draining")
	default:
	}
	close(runner.release)
	released = true
	var result tea.Msg
	select {
	case result = <-completed:
	case <-time.After(2 * time.Minute):
		t.Fatal("cancelled service did not finish persisting its fail-safe state")
	}
	checked, ok := result.(controlCheckMsg)
	if !ok || checked.err == nil || application.AsError(checked.err).ExitCode != 8 {
		t.Fatalf("cancelled service result = %#v", result)
	}
	// The result may allow exit only after a fresh reader sees the durable
	// failed-safe checkpoint and its exact explicit resume phase.
	saved, err := app.Dashboard(context.Background())
	if err != nil || len(saved.Tasks) != 1 || saved.Tasks[0].Phase != workflow.PhaseFailedSafe || saved.Tasks[0].ResumePhase != workflow.PhaseHostKeyVerified {
		t.Fatalf("durable cancellation state = %+v, err=%v", saved.Tasks, err)
	}
	ui, quit = updateTUI(t, ui, result)
	if ui.busy {
		t.Fatal("persisted cancellation did not release busy state")
	}
	assertQuitCommand(t, quit)
}
