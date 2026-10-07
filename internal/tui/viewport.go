package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func (model model) contentWidth() int { return max(1, min(model.width, 150)) }

func (model model) viewportSize() (body, header, footer int) {
	height := max(0, model.height)
	if height >= 4 {
		header = 1
	}
	footer = min(2, max(0, height-1-header))
	body = height - header - footer
	return
}

func (model model) bodyLines() []string {
	var lines []string
	for _, line := range model.contentLines() {
		lines = append(lines, wrapLine(line, model.contentWidth())...)
	}
	return lines
}

// Every slice remains a self-contained ANSI line, so scrolling into a styled
// paragraph cannot inherit a previous screen's color. Hard wrapping preserves
// every byte of a public key; no width-based truncation enters the data area.
func wrapLine(value string, width int) []string {
	var lines []string
	for _, logicalLine := range strings.Split(value, "\n") {
		offset := 0
		for _, wrapped := range strings.Split(ansi.Hardwrap(logicalLine, width, true), "\n") {
			cells := ansi.StringWidth(wrapped)
			if cells == 0 {
				lines = append(lines, "")
				continue
			}
			line := ansi.Cut(logicalLine, offset, offset+cells)
			lines = append(lines, ansi.Truncate(line, width, ""))
			offset += cells
		}
	}
	return lines
}

func (model model) scrollOffset() int {
	if model.help {
		return model.helpScroll
	}
	return model.scroll
}

func (model *model) setScroll(offset int) {
	if model.help {
		model.helpScroll = offset
	} else {
		model.scroll = offset
	}
	model.clampScroll()
}

func (model *model) clampScroll() {
	body, _, _ := model.viewportSize()
	limit := max(0, len(model.bodyLines())-body)
	if model.help {
		model.helpScroll = max(0, min(model.helpScroll, limit))
	} else {
		model.scroll = max(0, min(model.scroll, limit))
	}
}

func (model *model) scrollKey(key tea.KeyPressMsg) bool {
	if key.Text != "" {
		return false
	}
	if !model.help && model.screen == screenSystemSelect {
		return false
	}
	body, _, _ := model.viewportSize()
	offset := model.scrollOffset()
	switch key.String() {
	case "pgup":
		offset -= max(1, body-1)
	case "pgdown":
		offset += max(1, body-1)
	case "home":
		offset = 0
	case "end":
		offset = len(model.bodyLines())
	case "up", "down":
		if !model.help && (model.screen == screenControlBind || model.screen == screenNewSystem) {
			return false
		}
		if key.String() == "up" {
			offset--
		} else {
			offset++
		}
	default:
		return false
	}
	model.setScroll(offset)
	return true
}

func (model *model) revealInput(editing bool) {
	if model.help || !model.textInputScreen() {
		return
	}
	body, _, _ := model.viewportSize()
	if body <= 0 {
		return
	}
	start := 0
	for _, line := range model.contentLines() {
		wrapped := wrapLine(line, model.contentWidth())
		plain := strings.TrimLeft(ansi.Strip(line), " ")
		focused := strings.HasPrefix(plain, "> ")
		if model.screen == screenNewSystem {
			focused = strings.HasPrefix(plain, "Name  ")
		}
		if focused {
			end := start + len(wrapped)
			if editing && end > model.scroll+body {
				model.scroll = end - body
			} else if start < model.scroll || start >= model.scroll+body {
				model.scroll = start
			} else if end > model.scroll+body && len(wrapped) <= body {
				model.scroll = end - body
			}
			return
		}
		start += len(wrapped)
	}
}

func (model model) textInputScreen() bool {
	return model.screen == screenControlBind || model.screen == screenNewSystem || model.screen == screenSystemSelect
}

func bindFieldLabel(field bindField) string {
	switch field {
	case bindHost:
		return "Host"
	case bindPort:
		return "Port"
	case bindSSHUser:
		return "SSH user"
	case bindOperatingSystem:
		return "Operating system"
	case bindEvidence:
		return "Host-key evidence"
	case bindHostPublicKey:
		return "Host public key"
	default:
		return "Control binding"
	}
}

func (model model) renderHelp() []string {
	lines := []string{
		model.style(bold, "Keyboard help"), "",
		"F1 opens help from every screen. Esc or F1 returns without changing your input.",
		"? opens help outside text fields.", "",
		model.style(bold, "Read the entire page"),
		"PgUp / PgDn   Previous / next page",
		"Home / End    First / last line",
		"Up / Down     Scroll one line outside forms",
		"Long values, public keys and plans wrap without horizontal scrolling.", "",
		model.style(bold, "Dashboard"),
		"n   Create or resume a local system",
		"s   Find and select the active system",
		"r   Refresh durable system state",
		"q   Quit while idle",
	}
	for _, action := range []struct {
		allowed bool
		text    string
	}{
		{capabilityAllowed(model.snapshot, "control.bind"), "b   Bind the first Control endpoint and host key"},
		{controlCheckAvailable(model.snapshot), "c   Plan the pinned Control connectivity check"},
		{controlInstallAvailable(model.snapshot), "i   Plan local Control installation preparation"},
		{capabilityAllowed(model.snapshot, "control.apply"), "p   Plan remote Control runtime installation"},
		{capabilityAllowed(model.snapshot, "control.attest"), "a   Plan Control management-access verification"},
	} {
		if action.allowed {
			lines = append(lines, action.text)
		}
	}
	lines = append(lines, "", model.style(bold, "Forms and confirmation"),
		"Tab / Shift+Tab or Up / Down selects a binding field.",
		"Left / Right changes the operating system or evidence choice.",
		"Enter advances a field, previews a plan, or confirms the visible plan.",
		"Esc returns to the preceding screen. Form errors preserve your input.",
		"Pasted words such as enter or esc never confirm a plan.", "",
		model.style(bold, "Selecting systems"),
		"Type a system name or ID to filter. Ctrl+U clears the filter.",
		"Up / Down or Tab / Shift+Tab chooses a system; Home / End selects the first / last.",
		"PgUp / PgDn moves through choices. Enter previews the exact system and registry revision.",
		"Only a second Enter on that confirmation changes the active system.", "",
		model.style(bold, "Running operations"),
		"Ctrl+C cancels the current operation and requests exit.",
		"Flow waits for the service to finish saving its safe checkpoint before quitting.",
		"Repeated Ctrl+C does not skip that wait. Help and scrolling remain available.",
		"A later start reads the saved state; it does not automatically retry a connection.")
	return lines
}
