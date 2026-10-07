package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"dynamicflow/internal/application"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/systemstate"
)

func TestSystemFilterKeepsTheTypedTailAndCaretVisible(t *testing.T) {
	for _, query := range []string{strings.Repeat("long-name-", 8) + "tail", strings.Repeat("界", 40) + "終"} {
		ui := newModel(context.Background(), nil, manyRecordsSnapshot(), []string{"NO_COLOR=1"})
		ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 32, Height: 10})
		ui, _ = updateTUI(t, ui, tuiText("s"))
		ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: query})
		lines := strings.Split(ui.View().Content, "\n")
		footer := lines[len(lines)-1]
		runes := []rune(query)
		if ui.systemQuery != query || !strings.HasSuffix(footer, string(runes[len(runes)-1])+"▌") || ansi.StringWidth(footer) > 32 {
			t.Fatalf("long filter lost its visible input tail/caret: %q", footer)
		}
		ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyBackspace))
		lines = strings.Split(ui.View().Content, "\n")
		if !strings.HasSuffix(lines[len(lines)-1], string(runes[len(runes)-2])+"▌") {
			t.Fatalf("filter edit did not expose the new tail: %q", lines[len(lines)-1])
		}
	}
}

func TestSystemChooserFiltersNavigatesAndPreservesVisibleSelection(t *testing.T) {
	ui := newModel(context.Background(), nil, manyRecordsSnapshot(), []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tea.WindowSizeMsg{Width: 40, Height: 12})
	ui, command := updateTUI(t, ui, tuiText("s"))
	if command != nil || ui.screen != screenSystemSelect || !strings.Contains(ui.View().Content, "> system-001") {
		t.Fatal("s did not open the active-system chooser")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEnd))
	assertViewFits(t, ui)
	if ui.systemSelection != 99 || !strings.Contains(ui.View().Content, "> system-100") {
		t.Fatalf("End did not expose the final choice: %q", ui.View().Content)
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyHome))
	if ui.systemSelection != 0 || !strings.Contains(ui.View().Content, "> system-001") {
		t.Fatal("Home did not restore the first choice")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyPgDown))
	if ui.systemSelection == 0 {
		t.Fatal("PageDown did not advance the selected choice")
	}
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: "SyStEm-042"})
	if len(ui.filteredSystems()) != 1 || ui.filteredSystems()[0].Name != "system-042" ||
		!strings.Contains(ui.View().Content, "> system-042") || !strings.Contains(ui.View().Content, "Filter: SyStEm-042▌") {
		t.Fatalf("case-insensitive pasted filter is not visible or exact: %q", ui.View().Content)
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyF1))
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if command != nil || !ui.help {
		t.Fatal("help submitted an underlying system choice")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEsc))
	if ui.systemQuery != "SyStEm-042" || ui.systemSelection != 0 {
		t.Fatal("closing help lost the selected filtered system")
	}
	ui, _ = updateTUI(t, ui, tea.KeyPressMsg(tea.Key{Code: 'u', Mod: tea.ModCtrl}))
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: "no matching system"})
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if command != nil || ui.busy || !strings.Contains(ui.View().Content, "No matching systems") {
		t.Fatal("empty filter results have no safe recovery state")
	}
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: "\x1b]52;c;ZXhmaWw=\a\n"})
	if ui.systemQuery != "no matching system" {
		t.Fatal("unsafe paste altered the system filter")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEsc))
	if ui.screen != screenDashboard || ui.systemQuery != "" {
		t.Fatal("Esc did not leave the chooser without a mutation")
	}
}

func TestNewlyInitializedInactiveSystemIsOfferedForExplicitSelection(t *testing.T) {
	snapshot := recordsSnapshot(2)
	ui := newModel(context.Background(), nil, snapshot, []string{"NO_COLOR=1"})
	ui.screen, ui.busy = screenNewSystem, true
	created := snapshot.Systems[1]
	ui, refresh := updateTUI(t, ui, initSystemMsg{result: application.InitSystemResult{System: created, Created: true}})
	if refresh == nil || ui.selectAfterRefresh != created.ID || !ui.busy {
		t.Fatal("new inactive system did not request a durable snapshot before selection")
	}
	ui, command := updateTUI(t, ui, dashboardMsg{snapshot: snapshot})
	if command != nil || ui.busy || ui.screen != screenSystemSelect || ui.systemSelection != 1 ||
		ui.snapshot.ActiveSystemID != snapshot.Systems[0].ID {
		t.Fatal("new system was silently activated or not offered for explicit selection")
	}
	if !strings.Contains(ui.View().Content, "> "+created.Name) {
		t.Fatal("newly initialized system is not the visible selected choice")
	}
}

func TestSystemSelectionPlansConfirmsExactIDAndRejectsStaleRevision(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := systemstate.New(store)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := registry.CreateOrGet("operator-a")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := registry.CreateOrGet("operator-b")
	if err != nil {
		t.Fatal(err)
	}
	// A legal system name may look like another system's ID. The TUI must
	// resolve its selected row with the Application's explicit id: selector.
	if _, _, err := registry.CreateOrGet(second.ID); err != nil {
		t.Fatal(err)
	}
	runner := &tuiControlRunner{}
	app, err := application.Open(application.Config{Store: store, ControlRunner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ui := newModel(context.Background(), app, snapshot, []string{"NO_COLOR=1"})
	ui, _ = updateTUI(t, ui, tuiText("s"))
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: second.Name})
	ui, command := updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	if command == nil || !ui.busy {
		t.Fatal("Enter did not request an Application selection plan")
	}
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenSystemSelectConfirm || ui.systemSelectPlan == nil ||
		ui.systemSelectPlan.System.ID != second.ID || ui.systemSelectPlan.RegistryRevision != snapshot.RegistryRevision ||
		!strings.Contains(ui.View().Content, second.ID) {
		t.Fatalf("selection confirmation lost the exact system/revision: %q", ui.View().Content)
	}
	unchanged, err := registry.Snapshot()
	if err != nil || unchanged.ActiveSystemID != first.ID || unchanged.Revision != snapshot.RegistryRevision {
		t.Fatal("selection planning mutated the registry")
	}
	ui, command = updateTUI(t, ui, tea.PasteMsg{Content: "enter"})
	if command != nil || ui.busy {
		t.Fatal("pasted Enter authorized a system switch")
	}
	// Even stale presentation query text cannot redirect the frozen plan.
	ui.systemQuery = first.Name
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	message := command()
	selected := message.(systemSelectMsg)
	if selected.err != nil || !selected.result.Changed || selected.result.System.ID != second.ID || selected.result.NetworkConnections != 0 {
		t.Fatalf("confirmed selection = %+v, err=%v", selected.result, selected.err)
	}
	ui, command = updateTUI(t, ui, message)
	ui, _ = updateTUI(t, ui, command())
	if ui.screen != screenDashboard || ui.snapshot.ActiveSystemID != second.ID || ui.busy {
		t.Fatal("successful selection did not refresh the selected system's dashboard")
	}

	ui, _ = updateTUI(t, ui, tuiText("s"))
	ui, _ = updateTUI(t, ui, tea.PasteMsg{Content: first.Name})
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, command())
	if _, _, err := registry.CreateOrGet("operator-c"); err != nil {
		t.Fatal(err)
	}
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	message = command()
	conflict := message.(systemSelectMsg)
	if conflict.err == nil || application.AsError(conflict.err).Code != "system_conflict" {
		t.Fatalf("stale confirmation bypassed revision binding: %v", conflict.err)
	}
	ui, _ = updateTUI(t, ui, message)
	if ui.screen != screenSystemSelectConfirm || ui.systemSelectPlan == nil || ui.error == "" {
		t.Fatal("stale-plan failure lost its visible target or recovery path")
	}
	saved, err := registry.Snapshot()
	if err != nil || saved.ActiveSystemID != second.ID {
		t.Fatal("stale confirmation changed the active system")
	}
	ui, _ = updateTUI(t, ui, tuiSpecial(tea.KeyEsc))
	ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
	ui, _ = updateTUI(t, ui, command())
	if ui.systemSelectPlan.RegistryRevision != saved.Revision {
		t.Fatal("returning to selection did not obtain a fresh authoritative plan")
	}
	if calls, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("local system selection opened %d network processes", calls)
	}
}
