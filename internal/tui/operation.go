package tui

import (
	"context"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/safeview"
)

type quitRequestMsg struct{}

type operationProgressMsg struct {
	id    uint64
	event application.Event
}

type observerContextKey struct{}

func (model *model) beginOperation(label string) context.Context {
	ctx, cancel := context.WithCancel(model.ctx)
	model.operationCancel = cancel
	model.operationID++
	model.operationLabel = label
	model.progress = application.Event{}
	model.busy, model.error = true, ""
	if model.send != nil {
		id, send := model.operationID, model.send
		observer := application.ObserverFunc(func(event application.Event) {
			// Application events are public presentation data; never forward a
			// result, error cause, filesystem path or transport output here.
			event.Phase = safeview.Text(event.Phase, 64)
			event.Status = safeview.Text(event.Status, 32)
			event.Detail = safeview.Text(event.Detail, 256)
			send(operationProgressMsg{id: id, event: event})
		})
		ctx = context.WithValue(ctx, observerContextKey{}, observer)
	}
	return ctx
}

func operationObserver(ctx context.Context) application.Observer {
	observer, _ := ctx.Value(observerContextKey{}).(application.Observer)
	return observer
}

func (model *model) finishOperation() {
	if model.operationCancel != nil {
		model.operationCancel()
		model.operationCancel = nil
	}
	model.busy = false
	model.operationLabel = ""
	model.progress = application.Event{}
}

func (model model) requestQuit() (tea.Model, tea.Cmd) {
	if !model.busy {
		return model, tea.Quit
	}
	model.quitPending = true
	if model.operationCancel != nil {
		model.operationCancel()
	}
	// A service may still be persisting its fail-safe checkpoint. Its result
	// message, rather than cancellation alone, releases the terminal.
	return model, nil
}

func operationFinished(message tea.Msg) bool {
	switch message.(type) {
	case initSystemMsg, dashboardMsg, controlBindPlanMsg, controlBindMsg,
		controlCheckPlanMsg, controlCheckMsg, controlInstallPlanMsg, controlInstallMsg,
		controlApplyPlanMsg, controlApplyMsg, controlAttestPlanMsg, controlAttestMsg,
		systemSelectPlanMsg, systemSelectMsg:
		return true
	default:
		return false
	}
}

func shutdownFilter(current tea.Model, message tea.Msg) tea.Msg {
	switch message.(type) {
	case tea.InterruptMsg:
		return quitRequestMsg{}
	case tea.QuitMsg:
		if model, ok := current.(model); ok && model.busy {
			return quitRequestMsg{}
		}
	}
	return message
}
