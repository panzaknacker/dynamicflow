package cli

import (
	"context"
	"fmt"

	"dynamicflow/internal/application"
)

func systemSelect(ctx *commandContext, arguments []string) int {
	flags := newCommandFlagSet(ctx, "system select")
	planOnly := flags.Bool("plan", false, "preview the local active-system change")
	expected := flags.Uint64("expect-revision", 0, "require the displayed registry revision")
	if err := parseInterspersed(flags, arguments); err != nil || flags.NArg() != 1 {
		return usage(ctx, "usage: flow system select NAME_OR_ID [--plan] [--expect-revision N]")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", "The private system registry is unavailable.", "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.SelectSystemRequest{Meta: application.RequestMeta{Surface: application.SurfaceCLI}, Selector: flags.Arg(0), ExpectedRegistryRevision: *expected}
	if *planOnly {
		plan, err := app.PlanSystemSelect(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		human := fmt.Sprintf("PLAN select system %s (%s)\nPrevious active system: %s\nRegistry revision: %d\nAlready active: %t\nNetwork connections: 0", plan.System.Name, plan.System.ID, plan.PreviousSystemID, plan.RegistryRevision, plan.AlreadyActive)
		return ctx.out.success("system.select.plan", plan, human)
	}
	operation, stop := commandOperationContext()
	defer stop()
	result, err := app.SelectSystem(operation, request, application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	}))
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	human := fmt.Sprintf("Active system: %s (%s)\nChanged: %t\nRegistry revision: %d\nNetwork connections: 0\nSubsequent operator commands use this system.", result.System.Name, result.System.ID, result.Changed, result.RegistryRevision)
	return ctx.out.success("system.select", result, human)
}
