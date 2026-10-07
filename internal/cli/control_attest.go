package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

func controlAttest(ctx *commandContext, arguments []string) int {
	flags := newCommandFlagSet(ctx, "control attest")
	meta := registerControlSystemExpectation(flags)
	planOnly := flags.Bool("plan", false, "preview the pinned management-key challenge without mutation or network access")
	if err := parseInterspersed(flags, arguments); err != nil || flags.NArg() != 1 {
		return usage(ctx, "usage: flow control attest NAME [--plan] [--expect-system SYS_ID]")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", "The private application state is unavailable.", "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.AttestControlRequest{Meta: *meta, Name: flags.Arg(0)}
	if *planOnly {
		plan, err := app.PlanControlAttest(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		human := fmt.Sprintf("PLAN management attestation for Control %s in system %s\nRoute: %s\nManagement key: %s\nHost key: %s\nPolicy generation: %d; envelope: %s\nChanges: %s\nNetwork connections on apply: %d; retry: none; fallback: none\nControl ready: no",
			plan.ControlName, plan.SystemID, plan.Route, plan.ManagementFingerprint, plan.HostKeyFingerprint,
			plan.PolicyGeneration, plan.EnvelopeDigest, strings.Join(plan.Changes, "; "), plan.NetworkConnections)
		return ctx.out.success("control.attest.plan", plan, human)
	}
	operation, stop := commandOperationContext()
	defer stop()
	result, err := app.AttestControl(operation, request, application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	}))
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	human := fmt.Sprintf("Management access verified for Control %s.\nManagement key: %s\nPolicy generation: %d; envelope: %s\nRoute: %s; network connections: %d\nBootstrap revoked: no\nControl ready: no\nNext: complete verified bootstrap revocation before activating Control.",
		result.Evidence.ControlName, result.Evidence.ManagementFingerprint, result.Evidence.PolicyGeneration,
		result.Evidence.EnvelopeDigest, result.Transport.Route, result.NetworkConnections)
	return ctx.out.success("control.attest", result, human)
}
