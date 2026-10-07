package tui

import (
	"context"
	"fmt"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/safeview"
)

type controlApplyPlanMsg struct {
	plan application.InstallPreparedControlPlan
	err  error
}
type controlApplyMsg struct {
	result application.InstallPreparedControlResult
	err    error
}
type controlAttestPlanMsg struct {
	plan application.AttestControlPlan
	err  error
}
type controlAttestMsg struct {
	result application.AttestControlResult
	err    error
}

type controlApplyReceipt struct {
	SystemID                                      string
	ControlName, EnvelopeDigest, ExecutableDigest string
	PolicyGeneration                              uint64
	NetworkConnections                            int
	AlreadyInstalled                              bool
}

func planControlApplyCommand(ctx context.Context, app *application.Application, systemID, name string) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanPreparedControlInstall(ctx, application.InstallPreparedControlRequest{Meta: controlRequestMeta(systemID), Name: name})
		return controlApplyPlanMsg{plan: plan, err: err}
	}
}

func applyControlCommand(ctx context.Context, app *application.Application, systemID, name string) tea.Cmd {
	return func() tea.Msg {
		result, err := app.InstallPreparedControl(ctx, application.InstallPreparedControlRequest{Meta: controlRequestMeta(systemID), Name: name}, operationObserver(ctx))
		return controlApplyMsg{result: result, err: err}
	}
}

func planControlAttestCommand(ctx context.Context, app *application.Application, systemID, name string) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanControlAttest(ctx, application.AttestControlRequest{Meta: controlRequestMeta(systemID), Name: name})
		return controlAttestPlanMsg{plan: plan, err: err}
	}
}

func attestControlCommand(ctx context.Context, app *application.Application, systemID, name string) tea.Cmd {
	return func() tea.Msg {
		result, err := app.AttestControl(ctx, application.AttestControlRequest{Meta: controlRequestMeta(systemID), Name: name}, operationObserver(ctx))
		return controlAttestMsg{result: result, err: err}
	}
}

func (model model) updateControlRemote(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if key.Text != "" {
		return model, nil
	}
	if key.String() == "esc" || (key.String() == "enter" && (model.screen == screenControlApplyDone || model.screen == screenControlAttestDone)) {
		model.screen, model.error, model.busy = screenDashboard, "", true
		model.applyPlan, model.applyDone, model.attestPlan, model.attestDone = nil, nil, nil, nil
		ctx := model.beginOperation("Refreshing dashboard")
		return model, refreshCommand(ctx, model.app)
	}
	if key.String() != "enter" {
		return model, nil
	}
	if model.screen == screenControlApplyConfirm && model.applyPlan != nil && model.applyPlan.SystemID != "" {
		model.busy, model.error = true, ""
		ctx := model.beginOperation("Installing Control runtime")
		return model, applyControlCommand(ctx, model.app, model.applyPlan.SystemID, model.applyPlan.ControlName)
	}
	if model.screen == screenControlAttestConfirm && model.attestPlan != nil && model.attestPlan.SystemID != "" {
		model.busy, model.error = true, ""
		ctx := model.beginOperation("Verifying Control management access")
		return model, attestControlCommand(ctx, model.app, model.attestPlan.SystemID, model.attestPlan.ControlName)
	}
	return model, nil
}

func (model model) renderControlRemote(width int) []string {
	lines := []string{""}
	switch model.screen {
	case screenControlApplyConfirm:
		plan := model.applyPlan
		if plan == nil {
			return []string{"No installation plan is available. Press Esc to refresh."}
		}
		lines = append(lines, model.style(bold+cyan, "Install Control runtime"), "",
			"  System              "+safeview.Text(plan.SystemID, 64),
			"  Control             "+safeview.Text(plan.ControlName, 64),
			"  Route               pinned first-Control bootstrap",
			"  Runtime digest      "+safeview.Text(plan.ExecutableDigest, 80),
			fmt.Sprintf("  Runtime size        %d bytes", plan.ExecutableBytes),
			"  Policy digest       "+safeview.Text(plan.EnvelopeDigest, 80),
			fmt.Sprintf("  Policy generation   %d", plan.PolicyGeneration),
			fmt.Sprintf("  Connections         %d", plan.NetworkConnections), "")
		for _, change := range plan.Changes {
			lines = append(lines, "  • "+safeview.Text(change, 1024))
		}
		lines = append(lines, "", "The installation changes the remote VM and requires passwordless sudo.",
			"Management-key verification and bootstrap revocation follow separately.",
			model.style(yellow, "Control remains not ready until those gates are complete."))
	case screenControlApplyDone:
		receipt := model.applyDone
		if receipt == nil {
			return []string{"No installation receipt is available. Press Esc to refresh."}
		}
		lines = append(lines, model.style(bold, "Control runtime installed"), "",
			"  System              "+safeview.Text(receipt.SystemID, 64),
			"  Control             "+safeview.Text(receipt.ControlName, 64),
			"  Runtime digest      "+safeview.Text(receipt.ExecutableDigest, 80),
			"  Policy digest       "+safeview.Text(receipt.EnvelopeDigest, 80),
			fmt.Sprintf("  Connections         %d", receipt.NetworkConnections), "",
			model.status("NOT READY"), "",
			"Refresh the dashboard and press a to verify management access.")
	case screenControlAttestConfirm:
		plan := model.attestPlan
		if plan == nil {
			return []string{"No management-attestation plan is available. Press Esc to refresh."}
		}
		lines = append(lines, model.style(bold+cyan, "Verify Control management access"), "",
			"  System              "+safeview.Text(plan.SystemID, 64),
			"  Control             "+safeview.Text(plan.ControlName, 64),
			"  Management key      "+safeview.Text(plan.ManagementFingerprint, 96),
			"  Pinned host key     "+safeview.Text(plan.HostKeyFingerprint, 96),
			"  Installed policy    "+safeview.Text(plan.EnvelopeDigest, 80),
			fmt.Sprintf("  Policy generation   %d", plan.PolicyGeneration), "",
			"One connection must answer a fresh challenge using the exact installed policy.",
			"The staged management key is used exclusively. There is no automatic retry.", "",
			model.style(yellow, "Bootstrap revocation and Control activation remain separate steps."))
	case screenControlAttestDone:
		proof := model.attestDone
		if proof == nil {
			return []string{"No management proof is available. Press Esc to refresh."}
		}
		lines = append(lines, model.style(bold, "Control management access verified"), "",
			"  System              "+safeview.Text(proof.SystemID, 64),
			"  Control             "+safeview.Text(proof.ControlName, 64),
			"  Management key      "+safeview.Text(proof.ManagementFingerprint, 96),
			"  Installed policy    "+safeview.Text(proof.EnvelopeDigest, 80),
			"  Verified at         "+proof.VerifiedAt.Format("2006-01-02 15:04:05Z"), "",
			model.status("NOT READY"), "",
			"The proof is saved in private system state.",
			"Bootstrap revocation must still be verified before activating Control.")
	}
	return lines
}
