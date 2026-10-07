package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/safeview"
	"dynamicflow/internal/systemstate"
)

type systemSelectPlanMsg struct {
	plan application.SelectSystemPlan
	err  error
}

type systemSelectMsg struct {
	result application.SelectSystemResult
	err    error
}

func (model *model) openSystemSelect(target string) {
	model.screen, model.error = screenSystemSelect, ""
	model.systemQuery = ""
	model.systemSelection = 0
	model.systemSelectPlan = nil
	for index, system := range model.snapshot.Systems {
		if system.ID == target {
			model.systemSelection = index
			break
		}
	}
}

func (model model) filteredSystems() []systemstate.System {
	query := strings.ToLower(model.systemQuery)
	if query == "" {
		return model.snapshot.Systems
	}
	var result []systemstate.System
	for _, system := range model.snapshot.Systems {
		if strings.Contains(strings.ToLower(system.Name), query) || strings.Contains(strings.ToLower(system.ID), query) {
			result = append(result, system)
		}
	}
	return result
}

func (model model) updateSystemSelect(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if model.screen == screenSystemSelectConfirm {
		if key.Text != "" {
			return model, nil
		}
		switch key.String() {
		case "esc":
			model.systemSelectPlan = nil
			model.screen, model.error = screenSystemSelect, ""
		case "enter":
			if model.systemSelectPlan != nil {
				// Freeze the plan's immutable identity and registry revision.
				// Never re-resolve a mutable query or name at confirmation time.
				request := application.SelectSystemRequest{Meta: application.RequestMeta{Surface: application.SurfaceTUI},
					Selector: "id:" + model.systemSelectPlan.System.ID, ExpectedRegistryRevision: model.systemSelectPlan.RegistryRevision}
				ctx := model.beginOperation("Selecting active system")
				return model, selectSystemCommand(ctx, model.app, request)
			}
		}
		return model, nil
	}
	if key.Text != "" {
		query := appendBoundedSafe(model.systemQuery, key.Text, 128, nil)
		if query != model.systemQuery {
			model.systemQuery, model.systemSelection, model.error = query, 0, ""
		}
		return model, nil
	}
	count := len(model.filteredSystems())
	body, _, _ := model.viewportSize()
	switch key.String() {
	case "esc":
		model.screen, model.error, model.systemQuery = screenDashboard, "", ""
	case "backspace", "ctrl+h":
		model.systemQuery = dropLastRune(model.systemQuery)
		model.systemSelection, model.error = 0, ""
	case "ctrl+u":
		model.systemQuery, model.systemSelection, model.error = "", 0, ""
	case "down", "tab":
		model.systemSelection++
	case "up", "shift+tab":
		model.systemSelection--
	case "pgdown":
		model.systemSelection += max(1, body/3)
	case "pgup":
		model.systemSelection -= max(1, body/3)
	case "home":
		model.systemSelection = 0
	case "end":
		model.systemSelection = count - 1
	case "enter":
		if count != 0 && model.systemSelection >= 0 && model.systemSelection < count {
			selected := model.filteredSystems()[model.systemSelection]
			ctx := model.beginOperation("Planning active-system selection")
			return model, planSystemSelectCommand(ctx, model.app, selected.ID)
		}
	}
	model.systemSelection = max(0, min(model.systemSelection, count-1))
	return model, nil
}

func planSystemSelectCommand(ctx context.Context, app *application.Application, id string) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanSystemSelect(ctx, application.SelectSystemRequest{Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Selector: "id:" + id})
		return systemSelectPlanMsg{plan: plan, err: err}
	}
}

func selectSystemCommand(ctx context.Context, app *application.Application, request application.SelectSystemRequest) tea.Cmd {
	return func() tea.Msg {
		result, err := app.SelectSystem(ctx, request, operationObserver(ctx))
		return systemSelectMsg{result: result, err: err}
	}
}

func (model model) renderSystemSelect() []string {
	filtered := model.filteredSystems()
	lines := []string{
		model.style(bold+cyan, "Select active system"), "",
		"The active system determines which Control tasks and actions are shown.",
		"Type a name or ID to filter. Ctrl+U clears the filter.",
		fmt.Sprintf("%d matching systems · Enter previews the local change", len(filtered)), "",
	}
	if len(filtered) == 0 {
		return append(lines, "No matching systems. Edit the filter or press Ctrl+U to show all systems.")
	}
	for index, system := range filtered {
		marker := "  "
		if index == model.systemSelection {
			marker = model.style(cyan+bold, "> ")
		}
		active := ""
		if system.ID == model.snapshot.ActiveSystemID {
			active = " (active)"
		}
		// One logical entry keeps keyboard focus and its exact immutable ID
		// together when wrapping on a small terminal.
		lines = append(lines, marker+safeview.Text(system.Name, 64)+active+"\n    "+safeview.Text(system.ID, 64)+
			"\n    "+safeview.Text(string(system.Status), 64)+" · Control "+safeview.Text(string(system.Bootstrap.State), 64))
	}
	return lines
}

func (model model) renderSystemSelectConfirm() []string {
	plan := model.systemSelectPlan
	if plan == nil {
		return []string{"No system-selection plan. Press Esc to choose a system."}
	}
	lines := []string{
		model.style(bold+cyan, "Confirm active system"), "",
		"  System name        " + safeview.Text(plan.System.Name, 64),
		"  System ID          " + safeview.Text(plan.System.ID, 64),
		"  Previous system    " + safeview.Text(plan.PreviousSystemID, 64),
		fmt.Sprintf("  Registry revision  %d", plan.RegistryRevision),
		fmt.Sprintf("  Network connections %d", plan.NetworkConnections), "",
		"Enter makes this system the target of subsequent Control actions.",
		"The recorded registry revision must still match when you confirm.", "",
	}
	if plan.AlreadyActive {
		lines = append(lines, "This system is already active. No selection change is needed.")
	}
	for _, change := range plan.Changes {
		lines = append(lines, "  • "+safeview.Text(change, 1024))
	}
	return lines
}
