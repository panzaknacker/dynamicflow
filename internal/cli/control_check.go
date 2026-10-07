package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

const controlCheckUsage = "usage: flow control check NAME [--plan] [--expect-system SYS_ID]"

func controlCheck(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "control check")
	meta := registerControlSystemExpectation(flags)
	plan := flags.Bool("plan", false, "preview the one fixed pinned connectivity attempt without opening a socket")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 {
		return usage(ctx, controlCheckUsage)
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.CheckControlRequest{
		Meta: *meta, Name: flags.Arg(0),
	}
	if *plan {
		result, err := app.PlanControlCheck(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		changes := strings.Join(result.Changes, "; ")
		if changes == "" {
			changes = "none (connectivity evidence is already committed)"
		}
		human := fmt.Sprintf("PLAN first-Control connectivity for %s in system %s\nLifecycle: %s; task: %s\nChanges: %s\nNetwork connections: %d\nAlready verified: %t\nResumes failed task: %t",
			result.ControlName, result.SystemID, result.CurrentLifecycle, result.CurrentTaskPhase,
			changes, result.NetworkConnections, result.AlreadyVerified, result.ResumesFailedTask)
		if result.FixedRemoteCommand != "" {
			human += "\nFixed remote command: " + result.FixedRemoteCommand + "\nRetry/fallback: none"
		}
		return ctx.out.success("control.check.plan", result, human)
	}
	observer := application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	})
	operation, stop := commandOperationContext()
	defer stop()
	result, err := app.CheckControl(operation, request, observer)
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	mode := "verified by one pinned direct attempt"
	if result.AlreadyVerified {
		mode = "already verified; no network connection made"
	} else if result.Reconciled {
		mode = "reconciled from committed evidence; no network connection made"
	}
	human := fmt.Sprintf("Control %s connectivity %s.\nLifecycle: %s\nTask: %s (%s)\nRoute: %s\nAttempts this invocation: %d\nNetwork connections: %d\nRaw remote output: discarded",
		result.Control.Name, mode, result.Control.Lifecycle, result.Task.ID, result.Task.Phase,
		result.Transport.Route, result.Transport.Attempts, result.NetworkConnections)
	return ctx.out.success("control.check", result, human)
}
