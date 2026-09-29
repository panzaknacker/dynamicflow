package tui

import (
	"context"
	"regexp"
	"strings"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
)

type screen int

const (
	screenDashboard screen = iota
	screenNewSystem
	screenControlBind
	screenControlBindConfirm
	screenControlCheckConfirm
	screenControlInstallConfirm
	screenControlInstallPrepared
)

var systemCharacter = regexp.MustCompile(`^[A-Za-z0-9._-]$`)

type model struct {
	ctx      context.Context
	app      *application.Application
	snapshot application.DashboardSnapshot
	screen   screen
	width    int
	height   int
	name     string
	busy     bool
	error    string
	color    bool

	bindForm    controlBindForm
	bindRequest application.BindControlRequest
	bindPlan    *application.BindControlPlan
	checkPlan   *application.CheckControlPlan
	installPlan *application.PrepareControlInstallPlan
	installDone *controlInstallReceipt
}

type initSystemMsg struct {
	result application.InitSystemResult
	err    error
}

type dashboardMsg struct {
	snapshot application.DashboardSnapshot
	err      error
}

func newModel(ctx context.Context, app *application.Application, snapshot application.DashboardSnapshot, environment []string) model {
	color := true
	for _, value := range environment {
		if value == "NO_COLOR" || strings.HasPrefix(value, "NO_COLOR=") || value == "TERM=dumb" {
			color = false
		}
	}
	return model{ctx: ctx, app: app, snapshot: snapshot, width: 100, height: 30, color: color}
}

func (model model) Init() tea.Cmd { return nil }

func (model model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = typed.Width, typed.Height
		return model, nil
	case tea.InterruptMsg:
		return model, tea.Quit
	case initSystemMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.screen = screenDashboard
		model.error = ""
		return model, refreshCommand(model.ctx, model.app)
	case dashboardMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.snapshot = typed.snapshot
		model.error = ""
		return model, nil
	case controlBindPlanMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.bindRequest = typed.request
		model.bindPlan = &typed.plan
		model.screen = screenControlBindConfirm
		model.error = ""
		return model, nil
	case controlBindMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.screen = screenDashboard
		model.bindForm = controlBindForm{}
		model.bindRequest = application.BindControlRequest{}
		model.bindPlan = nil
		model.error = ""
		model.busy = true
		return model, refreshCommand(model.ctx, model.app)
	case controlCheckPlanMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.checkPlan = &typed.plan
		model.screen = screenControlCheckConfirm
		model.error = ""
		return model, nil
	case controlCheckMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.screen = screenDashboard
		model.checkPlan = nil
		model.error = ""
		model.busy = true
		return model, refreshCommand(model.ctx, model.app)
	case controlInstallPlanMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.installPlan = &typed.plan
		model.installDone = nil
		model.screen = screenControlInstallConfirm
		model.error = ""
		return model, nil
	case controlInstallMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.installPlan = nil
		model.installDone = newControlInstallReceipt(typed.result)
		model.screen = screenControlInstallPrepared
		model.error = ""
		return model, nil
	case tea.KeyPressMsg:
		key := typed.String()
		if key == "ctrl+c" || (key == "q" && model.screen == screenDashboard && !model.busy) {
			return model, tea.Quit
		}
		if model.busy {
			return model, nil
		}
		if model.screen == screenDashboard {
			switch key {
			case "n":
				model.screen, model.name, model.error = screenNewSystem, "", ""
			case "r":
				model.busy = true
				return model, refreshCommand(model.ctx, model.app)
			case "b":
				if capabilityAllowed(model.snapshot, "control.bind") && model.snapshot.Bootstrap != nil {
					model.bindForm = newControlBindForm(model.snapshot.Bootstrap.ControlName)
					model.bindRequest = application.BindControlRequest{}
					model.bindPlan = nil
					model.screen = screenControlBind
					model.error = ""
				}
			case "c":
				if controlCheckAvailable(model.snapshot) {
					name := guidedControlName(model.snapshot)
					if name != "" {
						model.busy = true
						model.error = ""
						return model, planControlCheckCommand(model.ctx, model.app, name)
					}
				}
			case "i":
				if controlInstallAvailable(model.snapshot) {
					name := guidedControlName(model.snapshot)
					if name != "" {
						model.busy = true
						model.error = ""
						return model, planControlInstallCommand(model.ctx, model.app, name)
					}
				}
			}
			return model, nil
		}
		if model.screen == screenControlBind {
			return model.updateControlBind(typed)
		}
		if model.screen == screenControlBindConfirm {
			if typed.Text != "" {
				return model, nil
			}
			switch key {
			case "esc":
				model.screen = screenControlBind
				model.bindPlan = nil
				model.error = ""
			case "enter":
				model.busy = true
				model.error = ""
				return model, bindControlCommand(model.ctx, model.app, model.bindRequest)
			}
			return model, nil
		}
		if model.screen == screenControlCheckConfirm {
			if typed.Text != "" {
				return model, nil
			}
			switch key {
			case "esc":
				model.screen = screenDashboard
				model.checkPlan = nil
				model.error = ""
			case "enter":
				if model.checkPlan == nil {
					return model, nil
				}
				model.busy = true
				model.error = ""
				return model, checkControlCommand(model.ctx, model.app, model.checkPlan.ControlName)
			}
			return model, nil
		}
		if model.screen == screenControlInstallConfirm {
			if typed.Text != "" {
				return model, nil
			}
			switch key {
			case "esc":
				model.screen = screenDashboard
				model.installPlan = nil
				model.error = ""
			case "enter":
				if model.installPlan == nil {
					return model, nil
				}
				model.busy = true
				model.error = ""
				return model, prepareControlInstallCommand(model.ctx, model.app, model.installPlan.ControlName)
			}
			return model, nil
		}
		if model.screen == screenControlInstallPrepared {
			if typed.Text != "" {
				return model, nil
			}
			if key == "esc" || key == "enter" {
				model.screen = screenDashboard
				model.installDone = nil
				model.error = ""
				model.busy = true
				return model, refreshCommand(model.ctx, model.app)
			}
			return model, nil
		}
		if typed.Text != "" {
			for _, character := range typed.Text {
				value := string(character)
				if len([]rune(model.name)) < 64 && systemCharacter.MatchString(value) {
					model.name += value
				}
			}
			return model, nil
		}
		switch key {
		case "esc":
			model.screen, model.name, model.error = screenDashboard, "", ""
		case "backspace", "ctrl+h":
			runes := []rune(model.name)
			if len(runes) > 0 {
				model.name = string(runes[:len(runes)-1])
			}
		case "enter":
			if len(model.name) == 0 {
				model.error = "Enter a system name."
				return model, nil
			}
			model.busy, model.error = true, ""
			return model, initSystemCommand(model.ctx, model.app, model.name)
		}
	}
	return model, nil
}

func (model model) updateControlBind(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Text != "" {
		model.bindForm.append(key.Text)
		return model, nil
	}
	switch key.String() {
	case "esc":
		model.screen = screenDashboard
		model.bindForm = controlBindForm{}
		model.bindRequest = application.BindControlRequest{}
		model.bindPlan = nil
		model.error = ""
	case "tab", "down":
		model.bindForm.move(1)
	case "shift+tab", "up":
		model.bindForm.move(-1)
	case "left":
		model.bindForm.choose(-1)
	case "right":
		model.bindForm.choose(1)
	case "backspace", "ctrl+h":
		model.bindForm.backspace()
	case "enter":
		if model.bindForm.Field != bindHostPublicKey {
			model.bindForm.move(1)
			return model, nil
		}
		model.busy = true
		model.error = ""
		return model, planControlBindCommand(model.ctx, model.app, model.bindForm.request())
	}
	return model, nil
}

func (model *model) setError(err error) {
	failure := application.AsError(err)
	model.error = safeError(failure.SafeText, failure.Next)
}

func (model model) View() tea.View {
	view := tea.NewView(model.render())
	view.AltScreen = true
	view.MouseMode = tea.MouseModeNone
	view.ReportFocus = false
	view.WindowTitle = ""
	return view
}

func initSystemCommand(ctx context.Context, app *application.Application, name string) tea.Cmd {
	return func() tea.Msg {
		result, err := app.InitSystem(ctx, application.InitSystemRequest{
			Meta: application.RequestMeta{Surface: application.SurfaceTUI}, Name: name, ControlName: "control-1",
		}, nil)
		return initSystemMsg{result: result, err: err}
	}
}

func refreshCommand(ctx context.Context, app *application.Application) tea.Cmd {
	return func() tea.Msg {
		snapshot, err := app.Dashboard(ctx)
		return dashboardMsg{snapshot: snapshot, err: err}
	}
}
