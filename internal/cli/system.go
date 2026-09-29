package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

func openApplication(ctx *commandContext) (*application.Application, error) {
	return application.Open(application.Config{Store: ctx.store})
}

func commandSystem(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow system <init|status>")
	}
	switch args[0] {
	case "init":
		return systemInit(ctx, args[1:])
	case "status":
		return systemStatus(ctx, args[1:])
	default:
		return usage(ctx, "unknown system command: "+args[0])
	}
}

func systemInit(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "system init")
	name := flags.String("name", "", "provider-independent system name")
	controlName := flags.String("control-name", "control-1", "first control node name")
	plan := flags.Bool("plan", false, "preview local trust/bootstrap changes without applying them")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(*name) == "" {
		return usage(ctx, "usage: flow system init --name NAME [--control-name NAME]")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	if *plan {
		result, err := app.PlanSystemInit(application.InitSystemRequest{Meta: application.RequestMeta{Surface: application.SurfaceCLI}, Name: *name, ControlName: *controlName})
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		return ctx.out.success("system.init.plan", result, fmt.Sprintf("PLAN: %s\nNetwork connections: 0\nPrivate keys generated now: %t\nOOB hostkey required: true", strings.Join(result.Changes, "; "), result.GeneratesPrivateKeys))
	}
	observer := application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	})
	result, err := app.InitSystem(context.Background(), application.InitSystemRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceCLI}, Name: *name, ControlName: *controlName,
	}, observer)
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	message := fmt.Sprintf(`System %s (%s) is ready for the first Control VM.

Paste this public key into the cloud VM:
%s

Public-key fingerprint: %s
Bootstrap task: %s (%s)
Bootstrap key expires: %s

Before any connection, obtain the VM's full Ed25519 SSH host public key through
the provider console or an authenticated provider attestation. The injected
public key does not authenticate the VM.

Private key material remains only in the owner-local Dynamicflow state.
Audit log: %s`, result.System.Name, result.System.ID, result.Cloud.PublicKey,
		result.Cloud.PublicKeyFingerprint, result.Task.ID, result.Task.Phase,
		result.KeyExpiresAt.Format("2006-01-02T15:04:05Z"), result.AuditLog)
	return ctx.out.success("system.init", result, message)
}

func systemStatus(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "system status")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow system status")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	if snapshot.ActiveSystemID == "" {
		return ctx.out.fail("system_required", "no Dynamicflow system exists", "Run flow system init --name NAME.", exitConfig)
	}
	for _, system := range snapshot.Systems {
		if system.ID != snapshot.ActiveSystemID {
			continue
		}
		data := map[string]any{"system": system, "tasks": snapshot.Tasks, "capabilities": snapshot.Capabilities, "observed_at": snapshot.ObservedAt}
		human := fmt.Sprintf("System: %s (%s)\nState: %s\nControl bootstrap: %s\nRevision: %d\nTasks: %d",
			system.Name, system.ID, system.Status, system.Bootstrap.State, system.Revision, len(snapshot.Tasks))
		return ctx.out.success("system.status", data, human)
	}
	return ctx.out.fail("system_state", "active system is missing from the registry", "Recover the private system registry.", exitConfig)
}

func commandDashboard(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "dashboard")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow dashboard")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	snapshot, err := app.Dashboard(context.Background())
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	if ctx.out.json {
		return ctx.out.success("dashboard", snapshot, "")
	}
	if len(snapshot.Systems) == 0 {
		return ctx.out.success("dashboard", snapshot, "No Dynamicflow system exists. Run flow system init --name NAME.")
	}
	lines := []string{fmt.Sprintf("Systems: %d  Active: %s  Tasks: %d", len(snapshot.Systems), snapshot.ActiveSystemID, len(snapshot.Tasks))}
	for _, system := range snapshot.Systems {
		marker := " "
		if system.ID == snapshot.ActiveSystemID {
			marker = "*"
		}
		lines = append(lines, fmt.Sprintf("%s %-20s %-12s control=%s", marker, system.Name, system.Status, system.Bootstrap.State))
	}
	return ctx.out.success("dashboard", snapshot, strings.Join(lines, "\n"))
}

func emitApplicationError(ctx *commandContext, err error) int {
	failure := application.AsError(err)
	status := failure.ExitCode
	if status < exitFailure || status > exitPartial {
		status = exitFailure
	}
	return ctx.out.fail(failure.Code, failure.SafeText, failure.Next, status)
}
