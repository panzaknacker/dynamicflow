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
	screenControlApplyConfirm
	screenControlApplyDone
	screenControlAttestConfirm
	screenControlAttestDone
	screenSystemSelect
	screenSystemSelectConfirm
)

var systemCharacter = regexp.MustCompile(`^[A-Za-z0-9._-]$`)

type model struct {
	ctx        context.Context
	app        *application.Application
	snapshot   application.DashboardSnapshot
	screen     screen
	width      int
	height     int
	name       string
	busy       bool
	error      string
	color      bool
	scroll     int
	help       bool
	helpScroll int

	operationCancel context.CancelFunc
	operationID     uint64
	operationLabel  string
	progress        application.Event
	quitPending     bool
	send            func(tea.Msg)

	bindForm    controlBindForm
	bindRequest application.BindControlRequest
	bindPlan    *application.BindControlPlan
	checkPlan   *application.CheckControlPlan
	installPlan *application.PrepareControlInstallPlan
	installDone *controlInstallReceipt
	applyPlan   *application.InstallPreparedControlPlan
	applyDone   *controlApplyReceipt
	attestPlan  *application.AttestControlPlan
	attestDone  *application.ControlProofEvidence

	systemQuery        string
	systemSelection    int
	systemSelectPlan   *application.SelectSystemPlan
	selectAfterRefresh string
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

func (model model) Init() tea.Cmd {
	if model.ctx.Done() == nil {
		return nil
	}
	return func() tea.Msg {
		<-model.ctx.Done()
		return quitRequestMsg{}
	}
}

func (current model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if operationFinished(message) {
		current.finishOperation()
		if current.quitPending {
			return current, tea.Quit
		}
	}
	switch typed := message.(type) {
	case quitRequestMsg, tea.InterruptMsg:
		return current.requestQuit()
	case operationProgressMsg:
		if current.busy && typed.id == current.operationID {
			current.progress = typed.event
		}
		return current, nil
	case tea.PasteMsg:
		if current.busy || current.help || !current.textInputScreen() {
			return current, nil
		}
		// Bubble Tea's bracketed-paste event is text input only. Never route
		// pasted shortcut names through navigation or confirmation handling.
		message = tea.KeyPressMsg(tea.Key{Text: typed.Content})
	case tea.KeyPressMsg:
		if typed.Text == "" && typed.String() == "ctrl+c" {
			return current.requestQuit()
		}
		if typed.String() == "f1" && typed.Text == "" || typed.String() == "?" &&
			(current.help || !current.textInputScreen()) {
			current.help = !current.help
			current.helpScroll = 0
			return current, nil
		}
		if current.help && typed.Text == "" && typed.String() == "esc" {
			current.help = false
			return current, nil
		}
		if current.scrollKey(typed) {
			return current, nil
		}
		if current.help {
			return current, nil
		}
	}
	previousScreen, previousField, previousError := current.screen, current.bindForm.Field, current.error
	previousName, previousForm := current.name, current.bindForm
	previousQuery, previousSelection := current.systemQuery, current.systemSelection
	updated, command := current.update(message)
	result := updated.(model)
	if result.screen != previousScreen || result.error != previousError {
		result.scroll = 0
	}
	if result.screen != previousScreen || result.bindForm.Field != previousField ||
		result.name != previousName || result.bindForm != previousForm ||
		result.systemQuery != previousQuery || result.systemSelection != previousSelection {
		result.revealInput(result.screen == previousScreen && result.bindForm.Field == previousField)
	}
	if _, resized := message.(tea.WindowSizeMsg); resized && result.error == "" {
		result.revealInput(false)
	}
	result.clampScroll()
	return result, command
}

func (model model) update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = typed.Width, typed.Height
		return model, nil
	case initSystemMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.screen = screenDashboard
		model.error = ""
		if model.snapshot.ActiveSystemID != "" && typed.result.System.ID != model.snapshot.ActiveSystemID {
			model.selectAfterRefresh = typed.result.System.ID
		}
		ctx := model.beginOperation("Refreshing dashboard")
		return model, refreshCommand(ctx, model.app)
	case dashboardMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.snapshot = typed.snapshot
		model.error = ""
		if target := model.selectAfterRefresh; target != "" {
			model.selectAfterRefresh = ""
			if target != model.snapshot.ActiveSystemID {
				model.openSystemSelect(target)
			}
		}
		return model, nil
	case systemSelectPlanMsg:
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.systemSelectPlan = &typed.plan
		model.screen, model.error = screenSystemSelectConfirm, ""
		return model, nil
	case systemSelectMsg:
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.systemSelectPlan = nil
		model.systemQuery = ""
		model.screen = screenDashboard
		ctx := model.beginOperation("Refreshing selected system")
		return model, refreshCommand(ctx, model.app)
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
		ctx := model.beginOperation("Refreshing dashboard")
		return model, refreshCommand(ctx, model.app)
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
		ctx := model.beginOperation("Refreshing dashboard")
		return model, refreshCommand(ctx, model.app)
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
	case controlApplyPlanMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.applyPlan = &typed.plan
		model.applyDone = nil
		model.screen, model.error = screenControlApplyConfirm, ""
		return model, nil
	case controlApplyMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.applyPlan = nil
		model.applyDone = &controlApplyReceipt{SystemID: typed.result.SystemID, ControlName: typed.result.Control.Name, EnvelopeDigest: typed.result.EnvelopeDigest,
			ExecutableDigest: typed.result.ExecutableDigest, PolicyGeneration: typed.result.PolicyGeneration,
			NetworkConnections: typed.result.NetworkConnections, AlreadyInstalled: typed.result.AlreadyInstalled}
		model.screen, model.error = screenControlApplyDone, ""
		return model, nil
	case controlAttestPlanMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.attestPlan = &typed.plan
		model.attestDone = nil
		model.screen, model.error = screenControlAttestConfirm, ""
		return model, nil
	case controlAttestMsg:
		model.busy = false
		if typed.err != nil {
			model.setError(typed.err)
			return model, nil
		}
		model.attestPlan = nil
		evidence := typed.result.Evidence
		model.attestDone = &evidence
		model.screen, model.error = screenControlAttestDone, ""
		return model, nil
	case tea.KeyPressMsg:
		key := typed.String()
		if key == "q" && model.screen == screenDashboard && !model.busy {
			return model, tea.Quit
		}
		if model.busy {
			return model, nil
		}
		if model.screen == screenDashboard {
			switch key {
			case "n":
				model.screen, model.name, model.error = screenNewSystem, "", ""
			case "s":
				if len(model.snapshot.Systems) != 0 {
					model.openSystemSelect(model.snapshot.ActiveSystemID)
				}
			case "r":
				ctx := model.beginOperation("Refreshing dashboard")
				return model, refreshCommand(ctx, model.app)
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
						ctx := model.beginOperation("Planning Control connectivity check")
						return model, planControlCheckCommand(ctx, model.app, model.snapshot.ActiveSystemID, name)
					}
				}
			case "i":
				if controlInstallAvailable(model.snapshot) {
					name := guidedControlName(model.snapshot)
					if name != "" {
						model.busy = true
						model.error = ""
						ctx := model.beginOperation("Planning local Control preparation")
						return model, planControlInstallCommand(ctx, model.app, model.snapshot.ActiveSystemID, name)
					}
				}
			case "p":
				if capabilityAllowed(model.snapshot, "control.apply") {
					model.busy, model.error = true, ""
					ctx := model.beginOperation("Planning Control runtime installation")
					return model, planControlApplyCommand(ctx, model.app, model.snapshot.ActiveSystemID, guidedControlName(model.snapshot))
				}
			case "a":
				if capabilityAllowed(model.snapshot, "control.attest") {
					model.busy, model.error = true, ""
					ctx := model.beginOperation("Planning management-access verification")
					return model, planControlAttestCommand(ctx, model.app, model.snapshot.ActiveSystemID, guidedControlName(model.snapshot))
				}
			}
			return model, nil
		}
		if model.screen == screenSystemSelect || model.screen == screenSystemSelectConfirm {
			return model.updateSystemSelect(typed)
		}
		if model.screen == screenControlApplyConfirm || model.screen == screenControlAttestConfirm ||
			model.screen == screenControlApplyDone || model.screen == screenControlAttestDone {
			return model.updateControlRemote(typed)
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
				if model.bindPlan == nil || model.bindPlan.SystemID == "" {
					return model, nil
				}
				model.busy = true
				model.error = ""
				request := model.bindRequest
				request.Meta = controlRequestMeta(model.bindPlan.SystemID)
				ctx := model.beginOperation("Committing Control trust")
				return model, bindControlCommand(ctx, model.app, request)
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
				if model.checkPlan == nil || model.checkPlan.SystemID == "" {
					return model, nil
				}
				model.busy = true
				model.error = ""
				ctx := model.beginOperation("Checking pinned Control connectivity")
				return model, checkControlCommand(ctx, model.app, model.checkPlan.SystemID, model.checkPlan.ControlName)
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
				if model.installPlan == nil || model.installPlan.SystemID == "" {
					return model, nil
				}
				model.busy = true
				model.error = ""
				ctx := model.beginOperation("Preparing local Control installation")
				return model, prepareControlInstallCommand(ctx, model.app, model.installPlan.SystemID, model.installPlan.ControlName)
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
				ctx := model.beginOperation("Refreshing dashboard")
				return model, refreshCommand(ctx, model.app)
			}
			return model, nil
		}
		if typed.Text != "" {
			model.name = appendBoundedSafe(model.name, typed.Text, 64, func(character rune) bool {
				return systemCharacter.MatchString(string(character))
			})
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
			ctx := model.beginOperation("Creating or resuming system")
			return model, initSystemCommand(ctx, model.app, model.name)
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
		request := model.bindForm.request()
		request.Meta = controlRequestMeta(model.snapshot.ActiveSystemID)
		ctx := model.beginOperation("Planning local Control trust")
		return model, planControlBindCommand(ctx, model.app, request)
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
		}, operationObserver(ctx))
		return initSystemMsg{result: result, err: err}
	}
}

func refreshCommand(ctx context.Context, app *application.Application) tea.Cmd {
	return func() tea.Msg {
		snapshot, err := app.Dashboard(ctx)
		return dashboardMsg{snapshot: snapshot, err: err}
	}
}
