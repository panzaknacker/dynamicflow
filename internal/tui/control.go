package tui

import (
	"context"
	"strconv"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/controlnodes"
	"dynamicflow/internal/safeview"
	"dynamicflow/internal/workflow"
)

type bindField int

const (
	bindHost bindField = iota
	bindPort
	bindSSHUser
	bindOperatingSystem
	bindEvidence
	bindHostPublicKey
	bindFieldCount
)

var (
	bindOperatingSystems = []controlnodes.OperatingSystem{
		controlnodes.OSDebian13,
		controlnodes.OSUbuntu2404,
	}
	bindEvidenceSources = []controlnodes.EvidenceSource{
		controlnodes.EvidenceProviderConsole,
		controlnodes.EvidenceProviderAttestation,
	}
)

type controlBindForm struct {
	Name                 string
	Host                 string
	Port                 string
	SSHUser              string
	OperatingSystemIndex int
	EvidenceIndex        int
	HostPublicKey        string
	Field                bindField
}

func newControlBindForm(name string) controlBindForm {
	return controlBindForm{Name: name, Port: "22"}
}

func (form controlBindForm) request() application.BindControlRequest {
	port, err := strconv.Atoi(form.Port)
	if err != nil {
		// parsing belongs to this presentation adapter. the Application remains
		// authoritative for whether the resulting request is acceptable.
		port = -1
	}
	return application.BindControlRequest{
		Meta:            application.RequestMeta{Surface: application.SurfaceTUI},
		Name:            form.Name,
		Host:            form.Host,
		Port:            port,
		SSHUser:         form.SSHUser,
		OperatingSystem: bindOperatingSystems[form.OperatingSystemIndex],
		HostPublicKey:   form.HostPublicKey,
		EvidenceSource:  bindEvidenceSources[form.EvidenceIndex],
	}
}

func (form *controlBindForm) move(delta int) {
	next := int(form.Field) + delta
	if next < 0 {
		next = int(bindFieldCount) - 1
	}
	if next >= int(bindFieldCount) {
		next = 0
	}
	form.Field = bindField(next)
}

func (form *controlBindForm) choose(delta int) {
	switch form.Field {
	case bindOperatingSystem:
		form.OperatingSystemIndex = cycle(form.OperatingSystemIndex, len(bindOperatingSystems), delta)
	case bindEvidence:
		form.EvidenceIndex = cycle(form.EvidenceIndex, len(bindEvidenceSources), delta)
	}
}

func cycle(current, length, delta int) int {
	next := current + delta
	for next < 0 {
		next += length
	}
	return next % length
}

func (form *controlBindForm) append(text string) {
	switch form.Field {
	case bindHost:
		form.Host = appendBoundedSafe(form.Host, text, 253, nil)
	case bindPort:
		form.Port = appendBoundedSafe(form.Port, text, 5, func(character rune) bool {
			return character >= '0' && character <= '9'
		})
	case bindSSHUser:
		form.SSHUser = appendBoundedSafe(form.SSHUser, text, 32, nil)
	case bindHostPublicKey:
		form.HostPublicKey = appendBoundedSafe(form.HostPublicKey, text, 4096, nil)
	}
}

func (form *controlBindForm) backspace() {
	switch form.Field {
	case bindHost:
		form.Host = dropLastRune(form.Host)
	case bindPort:
		form.Port = dropLastRune(form.Port)
	case bindSSHUser:
		form.SSHUser = dropLastRune(form.SSHUser)
	case bindHostPublicKey:
		form.HostPublicKey = dropLastRune(form.HostPublicKey)
	}
}

func appendBoundedSafe(current, text string, maximum int, accept func(rune) bool) string {
	if text == "" || maximum <= 0 || !utf8.ValidString(text) {
		return current
	}
	count := utf8.RuneCountInString(text)
	if count == 0 || safeview.Text(text, count) != text {
		// reject the complete paste when it contains terminal controls, newlines,
		// bidi controls or invalid text. never silently alter trust material.
		return current
	}
	currentRunes := []rune(current)
	if len(currentRunes) >= maximum {
		return current
	}
	if accept != nil {
		for _, character := range text {
			if !accept(character) {
				return current
			}
		}
	}
	available := maximum - len(currentRunes)
	for _, character := range text {
		if available == 0 {
			break
		}
		currentRunes = append(currentRunes, character)
		available--
	}
	return string(currentRunes)
}

func dropLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}

func capabilityAllowed(snapshot application.DashboardSnapshot, action string) bool {
	for _, capability := range snapshot.Capabilities {
		if capability.Action == action {
			return capability.Allowed
		}
	}
	return false
}

func controlCheckAvailable(snapshot application.DashboardSnapshot) bool {
	if !capabilityAllowed(snapshot, "control.check") || snapshot.Bootstrap == nil {
		return false
	}
	if snapshot.Bootstrap.Phase == workflow.PhaseHostKeyVerified {
		return true
	}
	if snapshot.Bootstrap.Phase != workflow.PhaseFailedSafe {
		return false
	}
	for _, task := range snapshot.Tasks {
		if task.ID == snapshot.Bootstrap.TaskID && task.ResumePhase == workflow.PhaseHostKeyVerified {
			return true
		}
	}
	return false
}

func controlInstallAvailable(snapshot application.DashboardSnapshot) bool {
	if !capabilityAllowed(snapshot, "control.install") {
		return false
	}
	name := guidedControlName(snapshot)
	if name == "" {
		return false
	}
	var controlFound bool
	for _, control := range snapshot.Controls {
		if control.SystemID != snapshot.ActiveSystemID || control.Name != name {
			continue
		}
		if controlFound {
			return false
		}
		controlFound = (control.Lifecycle == controlnodes.LifecycleConnectivityVerified ||
			control.Lifecycle == controlnodes.LifecycleInstalling) &&
			(control.Access.Phase == controlnodes.AccessBootstrap || control.Access.Phase == controlnodes.AccessStaged)
	}
	if !controlFound {
		return false
	}
	for _, task := range snapshot.Tasks {
		if task.Kind == workflow.ControlBootstrap && task.SystemID == snapshot.ActiveSystemID && task.Resource.Name == name {
			return task.Phase == workflow.PhaseConnectivityOK || task.Phase == workflow.PhaseInstalling
		}
	}
	return false
}

func guidedControlName(snapshot application.DashboardSnapshot) string {
	if snapshot.Bootstrap != nil {
		return snapshot.Bootstrap.ControlName
	}
	for _, control := range snapshot.Controls {
		return control.Name
	}
	return ""
}

func safeError(text, next string) string {
	text = safeview.Text(text, 512)
	next = safeview.Text(next, 512)
	if next == "" {
		return text
	}
	return text + " Next: " + next
}

type controlBindPlanMsg struct {
	request application.BindControlRequest
	plan    application.BindControlPlan
	err     error
}

type controlBindMsg struct {
	result application.BindControlResult
	err    error
}

type controlCheckPlanMsg struct {
	plan application.CheckControlPlan
	err  error
}

type controlCheckMsg struct {
	result application.CheckControlResult
	err    error
}

type controlInstallPlanMsg struct {
	plan application.PrepareControlInstallPlan
	err  error
}

type controlInstallMsg struct {
	result application.PrepareControlInstallResult
	err    error
}

// controlInstallReceipt is the TUI presentation boundary. it intentionally
// drops the Application audit path and never carries private identity paths or
// canonical envelope bytes.
type controlInstallReceipt struct {
	ControlName           string
	ControlLifecycle      string
	AccessPhase           string
	TaskPhase             string
	ManagementUser        string
	ManagementPublicKey   string
	ManagementFingerprint string
	ManagementGeneration  uint64
	PolicyGeneration      uint64
	PolicyKeyID           string
	EnvelopeDigest        string
	NetworkConnections    int
	Resumed               bool
}

func newControlInstallReceipt(result application.PrepareControlInstallResult) *controlInstallReceipt {
	return &controlInstallReceipt{
		ControlName: result.Control.Name, ControlLifecycle: string(result.Control.Lifecycle),
		AccessPhase: string(result.Control.Access.Phase), TaskPhase: string(result.Task.Phase),
		ManagementUser: result.ManagementUser, ManagementPublicKey: result.ManagementPublicKey,
		ManagementFingerprint: result.ManagementIdentity.Fingerprint,
		ManagementGeneration:  result.ManagementIdentity.Generation,
		PolicyGeneration:      result.PolicyGeneration, PolicyKeyID: result.PolicyKeyID,
		EnvelopeDigest: result.EnvelopeDigest, NetworkConnections: result.NetworkConnections,
		Resumed: result.Resumed,
	}
}

func planControlBindCommand(ctx context.Context, app *application.Application, request application.BindControlRequest) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanControlBind(ctx, request)
		return controlBindPlanMsg{request: request, plan: plan, err: err}
	}
}

func bindControlCommand(ctx context.Context, app *application.Application, request application.BindControlRequest) tea.Cmd {
	return func() tea.Msg {
		result, err := app.BindControl(ctx, request, nil)
		return controlBindMsg{result: result, err: err}
	}
}

func planControlCheckCommand(ctx context.Context, app *application.Application, name string) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanControlCheck(ctx, application.CheckControlRequest{
			Meta: application.RequestMeta{Surface: application.SurfaceTUI},
			Name: name,
		})
		return controlCheckPlanMsg{plan: plan, err: err}
	}
}

func checkControlCommand(ctx context.Context, app *application.Application, name string) tea.Cmd {
	return func() tea.Msg {
		result, err := app.CheckControl(ctx, application.CheckControlRequest{
			Meta: application.RequestMeta{Surface: application.SurfaceTUI},
			Name: name,
		}, nil)
		return controlCheckMsg{result: result, err: err}
	}
}

func planControlInstallCommand(ctx context.Context, app *application.Application, name string) tea.Cmd {
	return func() tea.Msg {
		plan, err := app.PlanControlInstall(ctx, application.PrepareControlInstallRequest{
			Meta: application.RequestMeta{Surface: application.SurfaceTUI},
			Name: name,
		})
		return controlInstallPlanMsg{plan: plan, err: err}
	}
}

func prepareControlInstallCommand(ctx context.Context, app *application.Application, name string) tea.Cmd {
	return func() tea.Msg {
		result, err := app.PrepareControlInstall(ctx, application.PrepareControlInstallRequest{
			Meta: application.RequestMeta{Surface: application.SurfaceTUI},
			Name: name,
		}, nil)
		return controlInstallMsg{result: result, err: err}
	}
}
