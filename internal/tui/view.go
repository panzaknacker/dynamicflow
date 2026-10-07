package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"dynamicflow/internal/safeview"
)

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	cyan    = "\x1b[38;5;45m"
	green   = "\x1b[38;5;84m"
	yellow  = "\x1b[38;5;220m"
	red     = "\x1b[38;5;203m"
	magenta = "\x1b[38;5;213m"
)

func (model model) render() string {
	if model.width <= 0 || model.height <= 0 {
		return ""
	}
	width := model.contentWidth()
	body := model.bodyLines()
	bodyHeight, headerHeight, footerHeight := model.viewportSize()
	offset := min(model.scrollOffset(), max(0, len(body)-bodyHeight))
	end := min(len(body), offset+bodyHeight)
	lines := make([]string, 0, model.height)
	if headerHeight != 0 {
		title := model.style(bold, "DYNAMICFLOW")
		if width >= 60 {
			title += "  " + model.style(dim, "CONTROL-FIRST LIFECYCLE PLATFORM")
		}
		lines = append(lines, ansi.Truncate(title, width, ""))
	}
	lines = append(lines, body[offset:end]...)
	for len(lines) < headerHeight+bodyHeight {
		lines = append(lines, "")
	}
	footer := model.actionFooter()
	if model.help {
		footer = "Esc/F1/? return   PgUp/PgDn scroll"
	}
	if model.busy {
		footer = "Ctrl+C cancel/quit   F1 help"
		if model.quitPending {
			footer = "Cancelling; waiting for safe checkpoint"
		}
	}
	if footerHeight > 0 {
		lines = append(lines, model.style(dim, ansi.Truncate(footer, width, "…")))
	}
	if footerHeight > 1 {
		position := fmt.Sprintf("%d-%d/%d", min(offset+1, len(body)), end, len(body))
		navigation := "PgUp/PgDn scroll   Home/End   " + position
		if width < 45 {
			navigation = "PgUp/PgDn " + position
		}
		if model.screen == screenControlBind && !model.help {
			navigation = "Editing: " + bindFieldLabel(model.bindForm.Field) + "   PgUp/PgDn scroll"
		}
		if model.screen == screenSystemSelect && !model.help {
			navigation = model.systemFilterLine(width)
		}
		if model.busy {
			navigation = model.operationLabel
			if model.progress.Phase != "" {
				navigation = safeview.Text(model.progress.Phase, 64) + ": " + safeview.Text(model.progress.Status, 32)
			}
		}
		lines = append(lines, model.style(dim, ansi.Truncate(navigation, width, "…")))
	}
	return strings.Join(lines, "\n")
}

func (model model) systemFilterLine(width int) string {
	label := "Filter: "
	if width < 9 {
		label = "/"
	}
	if width < 2 {
		label = ""
	}
	value := safeview.Text(model.systemQuery, 128)
	available := max(0, width-ansi.StringWidth(label)-1)
	if available == 0 {
		value = ""
	} else if cells := ansi.StringWidth(value); cells > available {
		// Editing happens at the end of the query. Keep that tail and its
		// caret visible instead of truncating the active input off-screen.
		value = ansi.TruncateLeft(value, cells-available+1, "…")
	}
	return label + value + "▌"
}

func (model model) contentLines() []string {
	if model.help {
		return model.renderHelp()
	}
	width := model.contentWidth()
	var lines []string
	if model.error != "" {
		lines = append(lines, model.style(red+bold, "ERROR")+"  "+safeview.Text(model.error, 1024), "")
	}
	switch model.screen {
	case screenSystemSelect:
		lines = append(lines, model.renderSystemSelect()...)
	case screenSystemSelectConfirm:
		lines = append(lines, model.renderSystemSelectConfirm()...)
	case screenNewSystem:
		lines = append(lines, model.renderNewSystem(width)...)
	case screenControlBind:
		lines = append(lines, model.renderControlBind(width)...)
	case screenControlBindConfirm:
		lines = append(lines, model.renderControlBindConfirm(width)...)
	case screenControlCheckConfirm:
		lines = append(lines, model.renderControlCheckConfirm(width)...)
	case screenControlInstallConfirm:
		lines = append(lines, model.renderControlInstallConfirm(width)...)
	case screenControlInstallPrepared:
		lines = append(lines, model.renderControlInstallPrepared(width)...)
	case screenControlApplyConfirm, screenControlApplyDone, screenControlAttestConfirm, screenControlAttestDone:
		lines = append(lines, model.renderControlRemote(width)...)
	default:
		lines = append(lines, model.renderDashboard(width)...)
	}
	return lines
}

func (model model) actionFooter() string {
	footer := model.dashboardFooter()
	switch model.screen {
	case screenSystemSelect:
		footer = "F1 help   ↑/↓ select   Enter plan   Esc dashboard"
	case screenSystemSelectConfirm:
		footer = "Enter select active system   Esc choose again   F1 help"
	case screenNewSystem:
		footer = "Enter create/resume   Esc cancel   F1 help"
	case screenControlBind:
		footer = "F1 help   Tab/↑/↓ field   ←/→ choice   Enter next/plan   Esc dashboard"
	case screenControlBindConfirm:
		footer = "Enter commit local trust   Esc edit   F1 help"
	case screenControlCheckConfirm:
		footer = "Enter make the one pinned check   Esc dashboard   F1 help"
	case screenControlInstallConfirm:
		footer = "Enter commit local preparation   Esc dashboard   F1 help"
	case screenControlInstallPrepared:
		footer = "Enter/Esc refresh dashboard   F1 help"
	case screenControlApplyConfirm:
		footer = "Enter install Control runtime   Esc dashboard   F1 help"
	case screenControlAttestConfirm:
		footer = "Enter verify management access   Esc dashboard   F1 help"
	case screenControlApplyDone, screenControlAttestDone:
		footer = "Enter/Esc refresh dashboard   F1 help"
	}
	if model.width < 60 {
		switch model.screen {
		case screenSystemSelect:
			footer = "F1 help  ↑/↓ select  Enter plan"
		case screenSystemSelectConfirm:
			footer = "F1 help  Enter select  Esc back"
		case screenDashboard:
			footer = "? help   n new   q quit"
		case screenNewSystem:
			footer = "F1 help  Enter create  Esc back"
		case screenControlBind:
			footer = "F1 help  Tab field  Enter next"
		case screenControlBindConfirm, screenControlCheckConfirm, screenControlInstallConfirm,
			screenControlApplyConfirm, screenControlAttestConfirm:
			footer = "F1 help  Enter confirm  Esc back"
		default:
			footer = "F1 help  Enter/Esc dashboard"
		}
	}
	return footer
}

func (model model) dashboardFooter() string {
	parts := []string{"? help", "n new system"}
	if len(model.snapshot.Systems) != 0 {
		parts = append(parts, "s select system")
	}
	if capabilityAllowed(model.snapshot, "control.bind") {
		parts = append(parts, "b bind control")
	}
	if controlCheckAvailable(model.snapshot) {
		parts = append(parts, "c check control")
	}
	if controlInstallAvailable(model.snapshot) && !capabilityAllowed(model.snapshot, "control.apply") {
		parts = append(parts, "i prepare control install")
	}
	if capabilityAllowed(model.snapshot, "control.apply") {
		parts = append(parts, "p install control")
	}
	if capabilityAllowed(model.snapshot, "control.attest") {
		parts = append(parts, "a verify management")
	}
	parts = append(parts, "r refresh", "q quit")
	return strings.Join(parts, "   ")
}

func (model model) renderDashboard(width int) []string {
	lines := []string{}
	if len(model.snapshot.Systems) == 0 {
		lines = append(lines,
			"",
			model.style(bold, "NEW CONTROL PLANE"),
			"",
			"No Dynamicflow system exists on this operator workstation.",
			"Press "+model.style(cyan+bold, "n")+" to create a provider-independent system.",
			"",
			model.style(dim, "Flow will create offline trust roots and one unique first-Control public key."),
			model.style(dim, "No network connection is made during this step."),
		)
		return lines
	}

	activeName, activeStatus, controlStatus := "unknown", "UNKNOWN", "NOT READY"
	for _, system := range model.snapshot.Systems {
		if system.ID == model.snapshot.ActiveSystemID {
			activeName = safeview.Text(system.Name, 64)
			activeStatus = strings.ToUpper(string(system.Status))
			controlStatus = strings.ToUpper(string(system.Bootstrap.State))
		}
	}
	lines = append(lines,
		"",
		fmt.Sprintf("SYSTEM  %s  %s", model.style(bold, activeName), model.status(activeStatus)),
		fmt.Sprintf("CONTROL %s     SERVING %s     INSTANCES %s", model.status(controlStatus), model.status("BLOCKED"), model.status("BLOCKED")),
		model.style(dim, fmt.Sprintf("Snapshot %s · registry revision %d · local source", model.snapshot.ObservedAt.Format("15:04:05Z"), model.snapshot.RegistryRevision)),
		"",
		model.style(bold+magenta, "SYSTEMS"),
	)
	for _, system := range model.snapshot.Systems {
		marker := " "
		if system.ID == model.snapshot.ActiveSystemID {
			marker = "●"
		}
		lines = append(lines, fmt.Sprintf(" %s %-22s %-13s control=%s", marker, safeview.Text(system.Name, 64), safeview.Text(string(system.Status), 64), safeview.Text(string(system.Bootstrap.State), 64)))
	}
	if len(model.snapshot.Controls) > 0 {
		lines = append(lines, "", model.style(bold+magenta, "CONTROLS"))
		for _, control := range model.snapshot.Controls {
			lines = append(lines, fmt.Sprintf("  %-20s %-24s host-key=%s",
				safeview.Text(control.Name, 64), safeview.Text(string(control.Lifecycle), 64), safeview.Text(control.HostFingerprint, 96)))
		}
	}
	lines = append(lines, "", model.style(bold+magenta, "TASKS"))
	if len(model.snapshot.Tasks) == 0 {
		lines = append(lines, "  No active tasks")
	}
	for _, task := range model.snapshot.Tasks {
		lines = append(lines, fmt.Sprintf("  %-36s %-24s attempt=%d rev=%d", safeview.Text(task.ID, 128), safeview.Text(string(task.Phase), 64), task.Attempt, task.Revision))
	}
	if model.snapshot.Bootstrap != nil && capabilityAllowed(model.snapshot, "control.bind") {
		guide := model.snapshot.Bootstrap
		state := "VALID"
		if guide.Expired {
			state = "EXPIRED — explicit rotation required"
		}
		lines = append(lines,
			"",
			model.style(bold+cyan, "NEXT HUMAN GATE · CREATE FIRST CONTROL VM"),
			"  1. Create a fresh VM at any provider (Debian 13 or Ubuntu 24.04).",
			"  2. Paste this public key into the provider's SSH-key field:",
			"",
			"  "+safeview.Text(guide.PublicKey, 4096),
			"",
			"  Fingerprint  "+safeview.Text(guide.PublicKeyFingerprint, 128),
			"  Valid until  "+guide.ExpiresAt.Format("2006-01-02 15:04:05Z")+"  "+model.status(state),
			"",
			model.style(yellow, "  TRUST GATE: obtain the VM's full Ed25519 host public key independently"),
			model.style(yellow, "  from the provider console or attestation before Flow opens a socket."),
			"",
			"  Press "+model.style(cyan+bold, "b")+" to enter and locally verify the immutable Control binding.",
		)
	}
	if controlCheckAvailable(model.snapshot) {
		guide := model.snapshot.Bootstrap
		lines = append(lines,
			"",
			model.style(bold+cyan, "NEXT HUMAN GATE · VERIFY FIRST CONTROL CONNECTIVITY"),
			"  Control       "+safeview.Text(guide.ControlName, 64),
			"  Task phase    "+safeview.Text(string(guide.Phase), 64),
			"",
			model.style(yellow, "  This is the sole direct first-Control exception."),
			"  Press "+model.style(cyan+bold, "c")+" to inspect its pinned one-attempt plan before any socket is opened.",
		)
	}
	if controlInstallAvailable(model.snapshot) && !capabilityAllowed(model.snapshot, "control.apply") {
		name := guidedControlName(model.snapshot)
		lines = append(lines,
			"",
			model.style(bold+cyan, "NEXT LOCAL GATE · PREPARE CONTROL INSTALLATION"),
			"  Control       "+safeview.Text(name, 64),
			"",
			model.style(yellow, "  This creates a signed route-free local checkpoint with zero network connections."),
			model.style(yellow, "  It does not install the remote VM and does not mark Control ready."),
			"  Press "+model.style(cyan+bold, "i")+" to inspect the local plan before committing it.",
		)
	}
	if capabilityAllowed(model.snapshot, "control.apply") {
		lines = append(lines, "", model.style(bold+cyan, "INSTALL CONTROL RUNTIME"),
			"  The signed local preparation is complete.",
			"  Press "+model.style(cyan+bold, "p")+" to preview installation on the pinned Control VM.",
			"  The plan shows the exact runtime and policy before you authorize one connection.")
	}
	if capabilityAllowed(model.snapshot, "control.attest") {
		lines = append(lines, "", model.style(bold+cyan, "VERIFY CONTROL MANAGEMENT ACCESS"),
			"  The runtime is installed. Control activation still requires verified access and bootstrap revocation.",
			"  Press "+model.style(cyan+bold, "a")+" to preview a fresh check with the staged management key.")
	}
	return lines
}

func (model model) renderControlBind(width int) []string {
	form := model.bindForm
	phase := "AWAITING TRUST INPUT"
	if model.busy {
		phase = "LOCAL PREFLIGHT"
	}
	lines := []string{
		"",
		model.style(bold+cyan, "CONTROL BIND · PHASE 2/4"),
		model.status(phase),
		"",
		"Record the endpoint and independently authenticated host identity.",
		model.style(dim, "Planning is local-only: it opens no socket, creates no key and changes no state."),
		"",
		"  Name (immutable from bootstrap)  " + model.style(bold, safeview.Text(form.Name, 64)),
		model.bindFieldLine(bindHost, "Host", form.Host),
		model.bindFieldLine(bindPort, "Port", form.Port),
		model.bindFieldLine(bindSSHUser, "Non-root SSH user", form.SSHUser),
		model.bindChoiceLine(bindOperatingSystem, "Operating system", operatingSystemLabels(), form.OperatingSystemIndex),
		model.bindChoiceLine(bindEvidence, "Host-key evidence", evidenceLabels(), form.EvidenceIndex),
		model.bindFieldLine(bindHostPublicKey, "Full Ed25519 host public key", form.HostPublicKey),
		"",
		model.style(yellow, "Host-key evidence must come from the provider console or provider attestation."),
		model.style(dim, "A network-observed host key is never accepted as trust evidence."),
	}
	return lines
}

func operatingSystemLabels() []string {
	labels := make([]string, len(bindOperatingSystems))
	for index, value := range bindOperatingSystems {
		labels[index] = string(value)
	}
	return labels
}

func evidenceLabels() []string {
	labels := make([]string, len(bindEvidenceSources))
	for index, value := range bindEvidenceSources {
		labels[index] = string(value)
	}
	return labels
}

func (model model) bindFieldLine(field bindField, label, value string) string {
	marker := " "
	if model.bindForm.Field == field {
		marker = model.style(cyan+bold, ">")
	}
	if value == "" {
		value = model.style(dim, "<required>")
	} else {
		value = model.style(bold, safeview.Text(value, 4096))
	}
	if model.bindForm.Field == field {
		value += "▌"
	}
	if model.width < 70 {
		return " " + marker + " " + label + "\n    " + value
	}
	return fmt.Sprintf(" %s %-31s %s", marker, label, value)
}

func (model model) bindChoiceLine(field bindField, label string, values []string, selected int) string {
	marker := " "
	if model.bindForm.Field == field {
		marker = model.style(cyan+bold, ">")
	}
	choices := make([]string, len(values))
	for index, value := range values {
		prefix := "○"
		if index == selected {
			prefix = "●"
		}
		choices[index] = prefix + " " + safeview.Text(value, 64)
	}
	if model.width < 70 {
		return " " + marker + " " + label + "\n    " + strings.Join(choices, "   ")
	}
	return fmt.Sprintf(" %s %-31s %s", marker, label, strings.Join(choices, "   "))
}

func (model model) renderControlBindConfirm(width int) []string {
	if model.bindPlan == nil {
		return []string{"", model.style(red+bold, "No current Control binding plan. Press Esc to return.")}
	}
	plan := model.bindPlan
	lines := []string{
		"",
		model.style(bold+cyan, "CONFIRM CONTROL TRUST · LOCAL COMMIT"),
		model.status("AWAITING CONFIRMATION"),
		"",
		"  System              " + safeview.Text(plan.SystemID, 64),
		"  Control             " + safeview.Text(plan.ControlName, 64),
		"  Endpoint            " + safeview.Text(fmt.Sprintf("%s:%d", plan.CanonicalHost, plan.Port), 320),
		"  Non-root SSH user   " + safeview.Text(plan.SSHUser, 64),
		"  Operating system    " + safeview.Text(plan.OperatingSystem, 64),
		"  Host-key evidence   " + safeview.Text(plan.EvidenceSource, 64),
		"  Host fingerprint    " + safeview.Text(plan.HostKeyFingerprint, 128),
		"",
		fmt.Sprintf("  Network connections   %d", plan.NetworkConnections),
		fmt.Sprintf("  Generates private key  %t", plan.GeneratesPrivateKeys),
		"",
		model.style(bold, "Local changes:"),
	}
	if len(plan.Changes) == 0 {
		lines = append(lines, "  No changes; the exact immutable binding is already committed.")
	}
	for _, change := range plan.Changes {
		lines = append(lines, "  • "+safeview.Text(change, 1024))
	}
	lines = append(lines,
		"",
		model.style(yellow, "Enter commits exactly this independently verified trust data; it still opens no socket."),
	)
	return lines
}

func (model model) renderControlCheckConfirm(width int) []string {
	if model.checkPlan == nil {
		return []string{"", model.style(red+bold, "No current Control connectivity plan. Press Esc to return.")}
	}
	plan := model.checkPlan
	lines := []string{
		"",
		model.style(bold+cyan, "CONFIRM FIRST CONTROL CONNECTIVITY · PHASE 3/4"),
		model.status("AWAITING CONFIRMATION"),
		"",
		"  System               " + safeview.Text(plan.SystemID, 64),
		"  Control              " + safeview.Text(plan.ControlName, 64),
		"  Current lifecycle    " + safeview.Text(plan.CurrentLifecycle, 64),
		"  Current task phase   " + safeview.Text(plan.CurrentTaskPhase, 64),
		"",
		model.style(bold, "Bounded transport contract:"),
		fmt.Sprintf("  Network connections  %d", plan.NetworkConnections),
		"  Route                direct, first Control only, pinned Ed25519 host key",
		"  Remote command       " + safeview.Text(plan.FixedRemoteCommand, 64),
		"  Attempts             exactly one",
		"  Retry                none",
		"  Fallback             none",
		"  Forwarding           none",
		"",
		model.style(bold, "Application plan:"),
	}
	for _, change := range plan.Changes {
		lines = append(lines, "  • "+safeview.Text(change, 1024))
	}
	lines = append(lines,
		"",
		model.style(yellow, "Enter authorizes this one visible pinned connection. Failure remains explicit and resumable."),
	)
	return lines
}

func (model model) renderControlInstallConfirm(width int) []string {
	if model.installPlan == nil {
		return []string{"", model.style(red+bold, "No current local Control installation plan. Press Esc to return.")}
	}
	plan := model.installPlan
	lines := []string{
		"",
		model.style(bold+cyan, "CONFIRM LOCAL CONTROL INSTALLATION PREPARATION"),
		model.status("AWAITING CONFIRMATION"),
		"",
		"  System               " + safeview.Text(plan.SystemID, 64),
		"  Control              " + safeview.Text(plan.ControlName, 64),
		"  Current lifecycle    " + safeview.Text(plan.CurrentLifecycle, 64),
		"  Current task phase   " + safeview.Text(plan.CurrentTaskPhase, 64),
		"  Management user      " + safeview.Text(plan.ManagementUser, 64),
		fmt.Sprintf("  Policy generation    %d", plan.PolicyGeneration),
		fmt.Sprintf("  Routes authorized    %d (route-free)", plan.RouteCount),
		fmt.Sprintf("  Network connections  %d", plan.NetworkConnections),
		fmt.Sprintf("  Generates local key  %t", plan.GeneratesPrivateKeys),
		fmt.Sprintf("  Already prepared     %t", plan.AlreadyPrepared),
		"",
		model.style(bold, "Local changes:"),
	}
	if len(plan.Changes) == 0 {
		lines = append(lines, "  No changes; the exact signed local checkpoint already exists.")
	}
	for _, change := range plan.Changes {
		lines = append(lines, "  • "+safeview.Text(change, 1024))
	}
	lines = append(lines,
		"",
		model.style(yellow, "Enter commits only the owner-local key and signed route-free checkpoint."),
		model.style(red+bold, "NO REMOTE INSTALLATION · CONTROL WILL REMAIN NOT READY"),
	)
	return lines
}

func (model model) renderControlInstallPrepared(width int) []string {
	if model.installDone == nil {
		return []string{"", model.style(red+bold, "No local Control installation receipt. Press Esc to refresh.")}
	}
	receipt := model.installDone
	mode := "CREATED"
	if receipt.Resumed {
		mode = "RESUMED"
	}
	return []string{
		"",
		model.style(bold+cyan, "LOCAL CONTROL INSTALLATION CHECKPOINT PREPARED"),
		model.status(mode),
		model.style(red+bold, "[CONTROL NOT READY · REMOTE INSTALLATION PENDING]"),
		"",
		"  System               " + safeview.Text(receipt.SystemID, 64),
		"  Control              " + safeview.Text(receipt.ControlName, 64),
		"  Lifecycle checkpoint " + safeview.Text(receipt.ControlLifecycle, 64),
		"  Access phase         " + safeview.Text(receipt.AccessPhase, 64),
		"  Task phase           " + safeview.Text(receipt.TaskPhase, 64),
		"  Management user      " + safeview.Text(receipt.ManagementUser, 64),
		"",
		model.style(bold, "Public management key (safe to inspect/copy):"),
		"  " + safeview.Text(receipt.ManagementPublicKey, 4096),
		"  Fingerprint          " + safeview.Text(receipt.ManagementFingerprint, 128),
		fmt.Sprintf("  Key generation       %d", receipt.ManagementGeneration),
		fmt.Sprintf("  Policy generation    %d", receipt.PolicyGeneration),
		"  Policy key ID        " + safeview.Text(receipt.PolicyKeyID, 128),
		"  Envelope digest      " + safeview.Text(receipt.EnvelopeDigest, 128),
		"",
		fmt.Sprintf("  Routes authorized    %d (route-free)", 0),
		fmt.Sprintf("  Network connections  %d", receipt.NetworkConnections),
		"",
		model.style(yellow, "The signed envelope remains owner-local for the later fixed, pinned remote installer; it is not displayed here."),
	}
}

func (model model) renderNewSystem(width int) []string {
	phase := "AWAITING INPUT"
	if model.busy {
		phase = "COMMITTING"
	}
	return []string{
		"",
		model.style(bold+cyan, "NEW SYSTEM · PHASE 1/4"),
		model.status(phase),
		"",
		"Choose a local provider-independent system name.",
		model.style(dim, "Allowed: letters, digits, dot, underscore and hyphen; maximum 64 characters."),
		"",
		"  Name  " + model.style(bold, safeview.Text(model.name, 64)+"▌"),
		"",
		model.style(bold, "The committed operation will:"),
		"  [1] create or resume private system state",
		"  [2] verify five separated offline Ed25519 trust roots",
		"  [3] create exactly one owner-local 0600 Control bootstrap key",
		"  [4] persist an awaiting-cloud-VM task for safe restart/resume",
		"",
		model.style(dim, "No provider API, SSH connection, serving connection or target connection occurs in this phase."),
	}
}

func (model model) status(value string) string {
	upper := strings.ToUpper(value)
	style := yellow
	switch {
	case strings.Contains(upper, "FAIL"), strings.Contains(upper, "EXPIRED"), strings.Contains(upper, "REVOKED"):
		style = red
	case strings.Contains(upper, "NOT READY"), strings.Contains(upper, "BLOCKED"),
		strings.Contains(upper, "AWAITING"), strings.Contains(upper, "PREPARED"), strings.Contains(upper, "PENDING"):
		style = yellow
	case strings.Contains(upper, "READY"), strings.Contains(upper, "ACTIVE"), upper == "VALID":
		style = green
	}
	return model.style(style+bold, "["+safeview.Text(upper, 64)+"]")
}

func (model model) style(code, value string) string {
	if !model.color {
		return value
	}
	return code + value + reset
}
