package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"dynamicflow/internal/application"
	"dynamicflow/internal/controlnodes"
)

const controlBindUsage = "usage: flow control bind NAME --host HOST --ssh-user USER --os debian-13|ubuntu-24.04 --hostkey-file ABS --evidence provider-console|provider-attestation [--ssh-port PORT] [--plan]"

func commandControl(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow control <bind|check|install|apply|status>")
	}
	switch args[0] {
	case "bind":
		return controlBind(ctx, args[1:])
	case "check":
		return controlCheck(ctx, args[1:])
	case "install":
		return controlInstall(ctx, args[1:])
	case "apply":
		return controlApply(ctx, args[1:])
	case "status":
		return controlStatus(ctx, args[1:])
	default:
		return usage(ctx, "unknown control command: "+args[0])
	}
}

func controlBind(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "control bind")
	host := flags.String("host", "", "operator-reachable Control hostname or IP")
	sshUser := flags.String("ssh-user", "", "non-root SSH user")
	operatingSystem := flags.String("os", "", "Control base operating system")
	hostKeyFile := flags.String("hostkey-file", "", "absolute path to independently verified Ed25519 host public key")
	evidence := flags.String("evidence", "", "out-of-band host-key evidence source")
	sshPort := flags.Int("ssh-port", 22, "SSH port")
	plan := flags.Bool("plan", false, "validate and preview the local binding without mutation")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 ||
		strings.TrimSpace(*host) == "" || strings.TrimSpace(*sshUser) == "" ||
		strings.TrimSpace(*operatingSystem) == "" || strings.TrimSpace(*hostKeyFile) == "" ||
		strings.TrimSpace(*evidence) == "" {
		return usage(ctx, controlBindUsage)
	}
	if !filepath.IsAbs(*hostKeyFile) {
		return usage(ctx, "--hostkey-file must be an absolute path\n"+controlBindUsage)
	}
	publicKey, err := readBoundedPublicKeyFile(*hostKeyFile)
	switch {
	case errors.Is(err, errPublicKeyFileUnsafe):
		return ctx.out.fail("control_hostkey_file", "the Control host-key file must be a small regular non-symlink file", "Export ssh_host_ed25519_key.pub through the provider console or provider attestation.", exitConfig)
	case errors.Is(err, errPublicKeyFileChanged):
		return ctx.out.fail("control_hostkey_file", "the Control host-key file changed while it was opened", "Repeat with a stable local regular file.", exitConflict)
	case err != nil:
		return ctx.out.fail("control_hostkey_file", "the Control host-key file could not be read safely", "Check the local public-key file and retry.", exitConfig)
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	request := application.BindControlRequest{
		Meta: application.RequestMeta{Surface: application.SurfaceCLI}, Name: flags.Arg(0),
		Host: *host, Port: *sshPort, SSHUser: *sshUser,
		OperatingSystem: controlnodes.OperatingSystem(*operatingSystem), HostPublicKey: string(publicKey),
		EvidenceSource: controlnodes.EvidenceSource(*evidence),
	}
	if *plan {
		result, err := app.PlanControlBind(context.Background(), request)
		if err != nil {
			return emitApplicationError(ctx, err)
		}
		changes := strings.Join(result.Changes, "; ")
		if changes == "" {
			changes = "none (the immutable binding already matches)"
		}
		human := fmt.Sprintf("PLAN Control %s for system %s\nEndpoint: %s port %d as %s\nOS: %s\nHost-key fingerprint: %s\nEvidence: %s\nChanges: %s\nNetwork connections: %d\nPrivate keys generated: %t",
			result.ControlName, result.SystemID, result.CanonicalHost, result.Port, result.SSHUser,
			result.OperatingSystem, result.HostKeyFingerprint, result.EvidenceSource, changes,
			result.NetworkConnections, result.GeneratesPrivateKeys)
		return ctx.out.success("control.bind.plan", result, human)
	}
	observer := application.ObserverFunc(func(event application.Event) {
		ctx.out.phase(event.Phase, event.Status, event.Detail)
	})
	result, err := app.BindControl(context.Background(), request, observer)
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	mode := "created"
	if result.Resumed {
		mode = "resumed"
	}
	human := fmt.Sprintf("Control %s binding %s for system %s.\nEndpoint: %s port %d as %s\nOS: %s\nLifecycle: %s\nHost-key fingerprint: %s\nEvidence: %s\nTask: %s (%s)\nTopology generation: %d\nNetwork connections: %d",
		result.Control.Name, mode, result.System.ID, result.Control.Host, result.Control.Port,
		result.Control.SSHUser, result.Control.OperatingSystem, result.Control.Lifecycle,
		result.Control.HostFingerprint, result.Control.EvidenceSource, result.Task.ID,
		result.Task.Phase, result.TopologyGeneration, result.NetworkConnections)
	return ctx.out.success("control.bind", result, human)
}

func controlStatus(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "control status")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow control status")
	}
	app, err := openApplication(ctx)
	if err != nil {
		return ctx.out.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
	}
	result, err := app.ControlStatus(context.Background())
	if err != nil {
		return emitApplicationError(ctx, err)
	}
	lines := []string{
		fmt.Sprintf("Control status for system %s (%s)", result.System.Name, result.System.ID),
		fmt.Sprintf("System state: %s; bootstrap: %s", result.System.Status, result.System.Bootstrap.State),
		fmt.Sprintf("Controls: %d; tasks: %d", len(result.Controls), len(result.Tasks)),
	}
	for _, control := range result.Controls {
		lines = append(lines, fmt.Sprintf("- %s: %s port %d as %s; %s; hostkey %s; evidence %s",
			control.Name, control.Host, control.Port, control.SSHUser, control.Lifecycle,
			control.HostFingerprint, control.EvidenceSource))
	}
	for _, task := range result.Tasks {
		lines = append(lines, fmt.Sprintf("- task %s: %s (next: %s)", task.ID, task.Phase, task.NextAction))
	}
	if result.Topology == nil {
		lines = append(lines, "Topology: not bound")
	} else {
		lines = append(lines, fmt.Sprintf("Topology: generation %d; Control ready: %t", result.Topology.Generation, result.Topology.ControlReady))
	}
	return ctx.out.success("control.status", result, strings.Join(lines, "\n"))
}
