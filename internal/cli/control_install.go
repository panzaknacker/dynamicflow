package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

const controlInstallUsage = "usage: flow control install NAME [--plan]"

// controlInstallPlanOutput is a presentation boundary, not an alias for the
// application result. keeping it explicit prevents future private checkpoint
// paths or envelope bytes from silently becoming part of the CLI contract.
type controlInstallPlanOutput struct {
	Plan                        bool     `json:"plan"`
	SystemID                    string   `json:"system_id"`
	ControlName                 string   `json:"control_name"`
	CurrentLifecycle            string   `json:"current_lifecycle"`
	CurrentTaskPhase            string   `json:"current_task_phase"`
	ManagementUser              string   `json:"management_user"`
	PolicyGeneration            uint64   `json:"policy_generation"`
	RouteCount                  int      `json:"route_count"`
	Changes                     []string `json:"changes"`
	NetworkConnections          int      `json:"network_connections"`
	GeneratesPrivateKeys        bool     `json:"generates_private_keys"`
	AlreadyPrepared             bool     `json:"already_prepared"`
	RouteFree                   bool     `json:"route_free"`
	RemoteInstallationPerformed bool     `json:"remote_installation_performed"`
	ControlReady                bool     `json:"control_ready"`
}

// controlInstallOutput deliberately contains the one public management key
// which the operator must be able to inspect. it excludes AuditLog, local key
// paths, canonical envelope bytes and every private-key field.
type controlInstallOutput struct {
	Prepared                    bool   `json:"prepared"`
	Resumed                     bool   `json:"resumed"`
	SystemID                    string `json:"system_id"`
	ControlName                 string `json:"control_name"`
	ControlLifecycle            string `json:"control_lifecycle"`
	AccessPhase                 string `json:"access_phase"`
	TaskID                      string `json:"task_id"`
	TaskPhase                   string `json:"task_phase"`
	ManagementScope             string `json:"management_scope"`
	ManagementName              string `json:"management_name"`
	ManagementGeneration        uint64 `json:"management_generation"`
	ManagementFingerprint       string `json:"management_fingerprint"`
	ManagementPublicKey         string `json:"management_public_key"`
	ManagementUser              string `json:"management_user"`
	PolicyGeneration            uint64 `json:"policy_generation"`
	PolicyKeyID                 string `json:"policy_key_id"`
	EnvelopeDigest              string `json:"envelope_digest"`
	RouteCount                  int    `json:"route_count"`
	NetworkConnections          int    `json:"network_connections"`
	RouteFree                   bool   `json:"route_free"`
	RemoteInstallationPerformed bool   `json:"remote_installation_performed"`
	ControlReady                bool   `json:"control_ready"`
}

func controlInstall(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "control install")
	planOnly := flags.Bool("plan", false, "preview the local route-free preparation without mutation")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 {
		return usage(ctx, controlInstallUsage)
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.PrepareControlInstallRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceCLI},
		Name: flags.Arg(0),
	}
	if *planOnly {
		plan, err := app.PlanControlInstall(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		output := controlInstallPlanOutput{
			Plan: plan.Plan, SystemID: plan.SystemID, ControlName: plan.ControlName,
			CurrentLifecycle: plan.CurrentLifecycle, CurrentTaskPhase: plan.CurrentTaskPhase,
			ManagementUser: plan.ManagementUser, PolicyGeneration: plan.PolicyGeneration,
			RouteCount: plan.RouteCount, Changes: append([]string(nil), plan.Changes...),
			NetworkConnections: plan.NetworkConnections, GeneratesPrivateKeys: plan.GeneratesPrivateKeys,
			AlreadyPrepared: plan.AlreadyPrepared, RouteFree: plan.RouteCount == 0,
			RemoteInstallationPerformed: false, ControlReady: false,
		}
		changes := strings.Join(output.Changes, "; ")
		if changes == "" {
			changes = "none (the exact local preparation checkpoint already exists)"
		}
		human := fmt.Sprintf(
			"PLAN local Control installation preparation for %s in system %s\n"+
				"Lifecycle: %s; task: %s\nManagement user: %s\nPolicy generation: %d\n"+
				"Routes authorized: %d (route-free)\nChanges: %s\nNetwork connections: %d\n"+
				"Owner-local private key generated on commit: %t\n"+
				"Remote installation performed: no\nControl ready: no",
			output.ControlName, output.SystemID, output.CurrentLifecycle, output.CurrentTaskPhase,
			output.ManagementUser, output.PolicyGeneration, output.RouteCount, changes,
			output.NetworkConnections, output.GeneratesPrivateKeys,
		)
		return ctx.out.success("control.install.plan", output, human)
	}

	observer := application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	})
	result, err := app.PrepareControlInstall(context.Background(), request, observer)
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	output := controlInstallOutput{
		Prepared: result.Prepared, Resumed: result.Resumed,
		SystemID: result.System.ID, ControlName: result.Control.Name,
		ControlLifecycle: string(result.Control.Lifecycle), AccessPhase: string(result.Control.Access.Phase),
		TaskID: result.Task.ID, TaskPhase: string(result.Task.Phase),
		ManagementScope: string(result.ManagementIdentity.Scope), ManagementName: result.ManagementIdentity.Name,
		ManagementGeneration:  result.ManagementIdentity.Generation,
		ManagementFingerprint: result.ManagementIdentity.Fingerprint,
		ManagementPublicKey:   result.ManagementPublicKey, ManagementUser: result.ManagementUser,
		PolicyGeneration: result.PolicyGeneration, PolicyKeyID: result.PolicyKeyID,
		EnvelopeDigest: result.EnvelopeDigest, RouteCount: 0,
		NetworkConnections: result.NetworkConnections, RouteFree: true,
		RemoteInstallationPerformed: false, ControlReady: false,
	}
	mode := "created"
	if output.Resumed {
		mode = "resumed"
	}
	human := fmt.Sprintf(
		"Local Control installation preparation %s for %s.\n"+
			"Lifecycle checkpoint: %s; access: %s; task: %s\n"+
			"Management user: %s\nManagement public key:\n%s\n"+
			"Management fingerprint: %s; generation: %d\n"+
			"Signed policy: generation %d, key %s\nEnvelope digest: %s\n"+
			"Routes authorized: %d (route-free)\nNetwork connections: %d\n"+
			"REMOTE INSTALLATION PERFORMED: NO\nCONTROL READY: NO\n"+
			"Next: run the separate fixed, pinned remote installation step when it is available.",
		mode, output.ControlName, output.ControlLifecycle, output.AccessPhase, output.TaskPhase,
		output.ManagementUser, output.ManagementPublicKey, output.ManagementFingerprint,
		output.ManagementGeneration, output.PolicyGeneration, output.PolicyKeyID,
		output.EnvelopeDigest, output.RouteCount, output.NetworkConnections,
	)
	return ctx.out.success("control.install", output, human)
}
