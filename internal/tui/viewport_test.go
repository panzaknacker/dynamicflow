package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"dynamicflow/internal/application"
	"dynamicflow/internal/systemstate"
	"dynamicflow/internal/workflow"
)

func manyRecordsSnapshot() application.DashboardSnapshot {
	return recordsSnapshot(100)
}

func recordsSnapshot(count int) application.DashboardSnapshot {
	snapshot := application.DashboardSnapshot{ActiveSystemID: "sys-00000000000000000000000000000001"}
	for index := 1; index <= count; index++ {
		snapshot.Systems = append(snapshot.Systems, systemstate.System{
			ID: fmt.Sprintf("sys-%032x", index), Name: fmt.Sprintf("system-%03d", index),
			Status:    systemstate.StatusInitializing,
			Bootstrap: systemstate.BootstrapMetadata{State: systemstate.BootstrapKeyPrepared},
		})
		snapshot.Tasks = append(snapshot.Tasks, workflow.Task{
			ID: fmt.Sprintf("task-%03d", index), SystemID: snapshot.ActiveSystemID,
			Phase: workflow.PhaseAwaitingCloudVM, Attempt: 1, Revision: uint64(index),
		})
	}
	return snapshot
}

func TestMaximumRegistryRemainsNavigable(t *testing.T) {
	// systemstate's public registry limit is 4096 systems. No state files or
	// private identities are needed to exercise that real presentation bound.
	snapshot := recordsSnapshot(4096)
	snapshot.Tasks = nil
	ui := newModel(context.Background(), nil, snapshot, []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 40, Height: 12})
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnd))
	assertViewFits(t, ui)
	if !strings.Contains(ui.View().Content, "system-4096") {
		t.Fatal("the registry capacity's final system is not keyboard-reachable")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyHome))
	if ui.scroll != 0 {
		t.Fatal("Home could not return from the maximum registry size")
	}
}

func assertViewFits(t *testing.T, ui model) {
	t.Helper()
	view := ui.View().Content
	if ui.width <= 0 || ui.height <= 0 {
		if view != "" {
			t.Fatalf("zero-size terminal has content: %q", view)
		}
		return
	}
	lines := strings.Split(view, "\n")
	if len(lines) > ui.height {
		t.Fatalf("view has %d lines in a %d-line terminal", len(lines), ui.height)
	}
	for index, line := range lines {
		if width := ansi.StringWidth(line); width > ui.width {
			t.Fatalf("line %d has %d cells in a %d-column terminal: %q", index, width, ui.width, line)
		}
	}
}

func TestViewportReachesEveryRecordAndPinsFooter(t *testing.T) {
	ui := newModel(context.Background(), nil, manyRecordsSnapshot(), []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 40, Height: 12})
	var visited strings.Builder
	for pages := 0; ; pages++ {
		assertViewFits(t, ui)
		view := ui.View().Content
		lines := strings.Split(view, "\n")
		if !strings.Contains(lines[len(lines)-2], "? help") || !strings.Contains(lines[len(lines)-1], "PgUp/PgDn") {
			t.Fatalf("pinned navigation disappeared: %q", view)
		}
		visited.WriteString(view)
		previous := ui.scroll
		ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyPgDown))
		if ui.scroll == previous {
			break
		}
		if pages > 200 {
			t.Fatal("page navigation did not reach a stable final page")
		}
	}
	for index := 1; index <= 100; index++ {
		for _, name := range []string{fmt.Sprintf("system-%03d", index), fmt.Sprintf("task-%03d", index)} {
			if !strings.Contains(visited.String(), name) {
				t.Fatalf("record %s cannot be reached by keyboard", name)
			}
		}
	}
	last := ui.scroll
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyHome))
	if ui.scroll != 0 {
		t.Fatal("Home did not reach the first page")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnd))
	if ui.scroll != last || !strings.Contains(ui.View().Content, "task-100") {
		t.Fatal("End did not reach the last record")
	}
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 100, Height: 35})
	assertViewFits(t, ui)
	body, _, _ := ui.viewportSize()
	if ui.scroll > len(ui.bodyLines())-body {
		t.Fatal("resize left the viewport below its content")
	}
}

func TestViewportWrapsWholePublicKeysAndUnicodeWithoutTruncation(t *testing.T) {
	publicKey := tuiHostPublicKey(0x21) + " " + strings.Repeat("unbroken-public-comment", 8)
	ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
	ui.screen = screenControlInstallPrepared
	ui.installDone = &controlInstallReceipt{ControlName: "control-1", ManagementPublicKey: publicKey}
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 32, Height: 10})
	// Collect one newly exposed body line per Down key, just as a reader can.
	var body strings.Builder
	height, header, _ := ui.viewportSize()
	for steps := 0; ; steps++ {
		assertViewFits(t, ui)
		lines := strings.Split(ui.View().Content, "\n")[header : header+height]
		if steps == 0 {
			body.WriteString(strings.Join(lines, ""))
		} else {
			body.WriteString(lines[len(lines)-1])
		}
		previous := ui.scroll
		ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyDown))
		if ui.scroll == previous {
			break
		}
		if steps > 200 {
			t.Fatal("could not reach the end of the public-key receipt")
		}
	}
	if !strings.Contains(body.String(), publicKey) || strings.Contains(body.String(), "…") {
		t.Fatalf("public key was truncated or altered while wrapping: %q", body.String())
	}
	for _, colored := range []bool{false, true} {
		ui.color = colored
		value := ui.style(bold+cyan, "界🙂 e\u0301 "+strings.Repeat("A", 64))
		wrapped := wrapLine(value, 7)
		if got := ansi.Strip(strings.Join(wrapped, "")); got != ansi.Strip(value) {
			t.Fatalf("Unicode graphemes changed while wrapping: %q", got)
		}
		for _, line := range wrapped {
			if ansi.StringWidth(line) > 7 {
				t.Fatalf("Unicode line overflows: %q", line)
			}
		}
	}
}

func TestHelpPreservesFormAndScrollAndDoesNotAuthorizeCommands(t *testing.T) {
	ui := newModel(context.Background(), nil, manyRecordsSnapshot(), []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 40, Height: 12})
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnd))
	previous := ui.scroll
	ui, command := updateTUI(t, ui, tuiText("?"))
	if !ui.help || command != nil || !strings.Contains(ui.View().Content, "Keyboard help") {
		t.Fatal("advertised ? help did not open")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnd))
	if ui.helpScroll == 0 || !strings.Contains(ui.View().Content, "automatically retry") {
		t.Fatal("the help's final cancellation instructions cannot be reached")
	}
	ui, command = updateTUI(t, ui, tuiText("n"))
	if !ui.help || ui.screen != screenDashboard || command != nil {
		t.Fatal("help allowed an underlying action")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEsc))
	if ui.help || ui.scroll != previous {
		t.Fatal("closing help lost the dashboard reading position")
	}
	ui.screen = screenControlBind
	ui.bindForm = newControlBindForm("control-1")
	ui.bindForm.Host = "203.0.113.40"
	ui.bindForm.Field = bindSSHUser
	form := ui.bindForm
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyF1))
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if ui.bindForm != form || command != nil || !ui.help {
		t.Fatal("help altered or submitted the binding form")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyF1))
	if ui.bindForm != form || ui.help {
		t.Fatal("F1 did not restore the original form focus and input")
	}
}

func TestNarrowFormKeepsKeyboardFocusAndErrorRecoveryVisible(t *testing.T) {
	ui := newModel(context.Background(), nil, application.DashboardSnapshot{
		Bootstrap:    &application.BootstrapGuide{ControlName: "control-1"},
		Capabilities: []application.Capability{{Action: "control.bind", Allowed: true}},
	}, []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 40, Height: 10})
	ui, _ = updateTUI(t, ui, tuiText("b"))
	for index := 0; index < int(bindFieldCount)*2; index++ {
		assertViewFits(t, ui)
		if !strings.Contains(ui.View().Content, "> ") || !strings.Contains(ui.View().Content, "Editing: "+bindFieldLabel(ui.bindForm.Field)) {
			t.Fatalf("field %v has no visible keyboard focus: %q", ui.bindForm.Field, ui.View().Content)
		}
		ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyTab))
	}
	ui.bindForm.Field = bindHostPublicKey
	ui, _ = updateTUI(t, ui, tuiText(tuiHostPublicKey(0x31)+strings.Repeat("Z", 180)))
	if !strings.Contains(ui.View().Content, "▌") || !strings.Contains(ui.View().Content, "Editing: Host public key") {
		t.Fatal("typing a long public key hid the caret or focused-field label")
	}
	form := ui.bindForm
	ui, _ = updateTUI(t, ui, controlBindPlanMsg{err: &application.Error{
		SafeText: "The Control trust input is invalid.", Next: "Correct the public host key and submit the plan again.",
	}})
	if ui.bindForm != form || !strings.Contains(ui.View().Content, "ERROR") || !strings.Contains(ui.View().Content, "Correct the public host key") {
		t.Fatalf("form error hid recovery or lost input: %q", ui.View().Content)
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyHome))
	ui, _ = updateTUI(t, ui, tuiText("pgdown"))
	if !strings.HasSuffix(ui.bindForm.HostPublicKey, "pgdown") || !strings.Contains(ui.View().Content, "▌") {
		t.Fatal("pasted navigation words were interpreted as control keys")
	}
}

func TestBracketedPasteOnlyEditsTheCurrentInputField(t *testing.T) {
	ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
	for _, shortcut := range []string{"n", "q", "?", "ctrl+c", "enter"} {
		updated, command := updateTUI(t, ui, tea.PasteMsg{Content: shortcut})
		if command != nil || updated.screen != screenDashboard || updated.help {
			t.Fatalf("bracketed paste %q triggered a dashboard action", shortcut)
		}
	}
	ui, _ = updateTUI(t, ui, tuiText("n"))
	ui, command := updateTUI(t, ui, tea.PasteMsg{Content: "lab-system"})
	if command != nil || ui.name != "lab-system" {
		t.Fatal("bracketed paste did not populate the system-name input")
	}
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: "\nenter\x1b[31m"})
	if ui.name != "lab-system" || ui.busy {
		t.Fatal("unsafe bracketed paste changed or submitted the system name")
	}
	ui.screen = screenControlBind
	ui.bindForm = newControlBindForm("control-1")
	ui.bindForm.Field = bindHostPublicKey
	publicKey := tuiHostPublicKey(0x31)
	ui, command = updateTUI(t, ui, tea.PasteMsg{Content: publicKey})
	if command != nil || ui.bindForm.HostPublicKey != publicKey {
		t.Fatal("bracketed paste lost or altered the complete public host key")
	}
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: "\x1b]52;c;ZXhmaWw=\a\nenter"})
	if ui.bindForm.HostPublicKey != publicKey || ui.busy {
		t.Fatal("unsafe bracketed paste altered trust material or submitted the form")
	}
	for _, screen := range []screen{screenControlBindConfirm, screenControlCheckConfirm, screenControlInstallConfirm, screenControlApplyConfirm, screenControlAttestConfirm} {
		ui.screen = screen
		for _, text := range []string{"enter", "\r", "esc", "\x1b"} {
			ui, command = updateTUI(t, ui, tea.PasteMsg{Content: text})
			if command != nil || ui.busy || ui.screen != screen {
				t.Fatalf("bracketed paste %q authorized or left confirmation %v", text, screen)
			}
		}
	}
}

func TestViewsRespectTinyAndColoredTerminalBounds(t *testing.T) {
	for _, size := range [][2]int{{0, 0}, {1, 1}, {2, 3}, {20, 6}, {32, 10}, {40, 12}, {80, 24}, {200, 60}} {
		for _, colored := range []bool{false, true} {
			ui := newModel(context.Background(), nil, manyRecordsSnapshot(), nil)
			ui.color = colored
			ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			for screen := screenDashboard; screen <= screenSystemSelectConfirm; screen++ {
				ui.screen = screen
				ui.error = "remote\x1b]52;c;ZXhmaWw=\a\u202Eerror " + strings.Repeat("界", 70)
				assertViewFits(t, ui)
				if plain := ansi.Strip(ui.View().Content); strings.ContainsRune(plain, '\u202e') || strings.Contains(plain, "\x1b") {
					t.Fatalf("untrusted terminal control survived: %q", plain)
				}
			}
			ui.help = true
			assertViewFits(t, ui)
		}
	}
}
