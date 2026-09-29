package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

const controlApplyUsage = "usage: flow control apply NAME [--plan]"

type controlApplyPlanOutput struct {
	Plan               bool     `json:"plan"`
	SystemID           string   `json:"system_id"`
	ControlName        string   `json:"control_name"`
	CurrentLifecycle   string   `json:"current_lifecycle"`
	CurrentTaskPhase   string   `json:"current_task_phase"`
	Route              string   `json:"route"`
	FixedOperation     string   `json:"fixed_operation"`
	PolicyGeneration   uint64   `json:"policy_generation"`
	EnvelopeDigest     string   `json:"envelope_digest"`
	ExecutableDigest   string   `json:"executable_digest,omitempty"`
	ExecutableBytes    int64    `json:"executable_bytes,omitempty"`
	Changes            []string `json:"changes"`
	NetworkConnections int      `json:"network_connections"`
	ResumesFailedTask  bool     `json:"resumes_failed_task"`
	ReconcilesEvidence bool     `json:"reconciles_evidence"`
	AlreadyInstalled   bool     `json:"already_installed"`
	Retry              string   `json:"retry"`
	Fallback           string   `json:"fallback"`
	ControlReady       bool     `json:"control_ready"`
}

type controlApplyOutput struct {
	Installed           bool   `json:"installed"`
	AlreadyInstalled    bool   `json:"already_installed"`
	Reconciled          bool   `json:"reconciled"`
	SystemID            string `json:"system_id"`
	ControlName         string `json:"control_name"`
	ControlLifecycle    string `json:"control_lifecycle"`
	AccessPhase         string `json:"access_phase"`
	TaskID              string `json:"task_id"`
	TaskPhase           string `json:"task_phase"`
	EnvelopeDigest      string `json:"envelope_digest"`
	ExecutableDigest    string `json:"executable_digest"`
	PolicyGeneration    uint64 `json:"policy_generation"`
	Route               string `json:"route,omitempty"`
	Attempts            int    `json:"attempts"`
	ExecutableBytes     int64  `json:"executable_bytes,omitempty"`
	NetworkConnections  int    `json:"network_connections"`
	ManagementKeyProven bool   `json:"management_key_proven"`
	BootstrapRevoked    bool   `json:"bootstrap_revoked"`
	ControlReady        bool   `json:"control_ready"`
}

func controlApply(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "control apply")
	planOnly := flags.Bool("plan", false, "preview the one-session pinned remote installation")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 {
		return usage(ctx, controlApplyUsage)
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.InstallPreparedControlRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceCLI}, Name: flags.Arg(0),
	}
	if *planOnly {
		plan, err := app.PlanPreparedControlInstall(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		output := controlApplyPlanOutput{
			Plan: plan.Plan, SystemID: plan.SystemID, ControlName: plan.ControlName,
			CurrentLifecycle: plan.CurrentLifecycle, CurrentTaskPhase: plan.CurrentTaskPhase,
			Route: plan.Route, FixedOperation: plan.FixedOperation, PolicyGeneration: plan.PolicyGeneration,
			EnvelopeDigest: plan.EnvelopeDigest, ExecutableDigest: plan.ExecutableDigest,
			ExecutableBytes: plan.ExecutableBytes, Changes: append([]string(nil), plan.Changes...),
			NetworkConnections: plan.NetworkConnections, ResumesFailedTask: plan.ResumesFailedTask,
			ReconcilesEvidence: plan.ReconcilesEvidence, AlreadyInstalled: plan.AlreadyInstalled,
			Retry: plan.Retry, Fallback: plan.Fallback, ControlReady: false,
		}
		changes := strings.Join(output.Changes, "; ")
		if changes == "" {
			changes = "none (authenticated installation evidence already matches)"
		}
		human := fmt.Sprintf(
			"PLAN pinned Control runtime apply for %s in system %s\n"+
				"Lifecycle: %s; task: %s\nRoute: %s; fixed operation: %s\n"+
				"Policy generation: %d; envelope: %s\nExecutable: %s (%d bytes)\n"+
				"Changes: %s\nNetwork connections: %d; retry: %s; fallback: %s\n"+
				"Management key proven: no\nBootstrap revoked: no\nControl ready: no",
			output.ControlName, output.SystemID, output.CurrentLifecycle, output.CurrentTaskPhase,
			output.Route, output.FixedOperation, output.PolicyGeneration, output.EnvelopeDigest,
			output.ExecutableDigest, output.ExecutableBytes, changes, output.NetworkConnections,
			output.Retry, output.Fallback,
		)
		return ctx.out.success("control.apply.plan", output, human)
	}
	observer := application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	})
	result, err := app.InstallPreparedControl(context.Background(), request, observer)
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	output := controlApplyOutput{
		Installed: result.Installed, AlreadyInstalled: result.AlreadyInstalled, Reconciled: result.Reconciled,
		SystemID: result.SystemID, ControlName: result.Control.Name,
		ControlLifecycle: string(result.Control.Lifecycle), AccessPhase: string(result.Control.Access.Phase),
		TaskID: result.Task.ID, TaskPhase: string(result.Task.Phase),
		EnvelopeDigest: result.EnvelopeDigest, ExecutableDigest: result.ExecutableDigest,
		PolicyGeneration: result.PolicyGeneration, Route: result.Transport.Route,
		Attempts: result.Transport.Attempts, ExecutableBytes: result.Transport.ExecutableBytes,
		NetworkConnections:  result.NetworkConnections,
		ManagementKeyProven: false, BootstrapRevoked: false, ControlReady: false,
	}
	mode := "installed"
	if output.AlreadyInstalled {
		mode = "already installed"
	}
	if output.Reconciled {
		mode = "reconciled from authenticated evidence"
	}
	human := fmt.Sprintf(
		"Control runtime %s on %s.\nLifecycle: %s; access: %s; task: %s\n"+
			"Policy generation: %d; envelope: %s\nExecutable: %s\n"+
			"Route: %s; attempts: %d; network connections: %d\n"+
			"MANAGEMENT KEY PROVEN: NO\nBOOTSTRAP REVOKED: NO\nCONTROL READY: NO\n"+
			"Next: prove the staged management identity, revoke bootstrap remotely and locally, then activate Control.",
		mode, output.ControlName, output.ControlLifecycle, output.AccessPhase, output.TaskPhase,
		output.PolicyGeneration, output.EnvelopeDigest, output.ExecutableDigest,
		output.Route, output.Attempts, output.NetworkConnections,
	)
	return ctx.out.success("control.apply", output, human)
}
