// package netpolicy makes fail-closed transport decisions for dynamicflow's
// operator and managed-node network paths. it selects a mode but never opens a
// connection, resolves a host, executes a command, or performs a fallback.
package netpolicy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const SchemaVersion = 1

var (
	ErrInvalidInput          = errors.New("invalid network-policy input")
	ErrUnsafePublicID        = errors.New("unsafe public identifier")
	ErrInvalidFingerprint    = errors.New("invalid Ed25519 fingerprint")
	ErrInconsistentBootstrap = errors.New("inconsistent bootstrap state")
)

var (
	systemIDRE = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	nodeIDRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// Actor is one side of a policy-evaluated network path.
type Actor string

const (
	ActorOperator        Actor = "operator"
	ActorControl         Actor = "control"
	ActorServing         Actor = "serving"
	ActorInstance        Actor = "instance"
	ActorProviderConsole Actor = "provider-console"
)

// Action is the complete set of network-relevant operator and node actions.
type Action string

const (
	ActionFirstControlCheck  Action = "first_control_check"
	ActionControlInstall     Action = "control_install"
	ActionServingBootstrap   Action = "serving_bootstrap"
	ActionInstanceBootstrap  Action = "instance_bootstrap"
	ActionDesiredStateUpdate Action = "desired_state_update"
	ActionSSH                Action = "ssh"
	ActionExec               Action = "exec"
	ActionVNC                Action = "vnc"
	ActionStatus             Action = "status"
	ActionReleasePull        Action = "release_pull"
	ActionRecovery           Action = "recovery"
)

// Mode is the sole transport class selected by a Decision. ModeDenied is the
// zero-trust outcome and is never replaced by a fallback.
type Mode string

const (
	ModeDirectFirstControl Mode = "direct_first_control"
	ModeViaControl         Mode = "via_control"
	ModeOutboundHTTPSPull  Mode = "outbound_https_pull"
	ModeProviderConsole    Mode = "provider_console"
	ModeDenied             Mode = "denied"
)

// BootstrapState binds a request to the monotonic system bootstrap phase.
type BootstrapState string

const (
	BootstrapUninitialized  BootstrapState = "uninitialized"
	BootstrapControlPending BootstrapState = "control_pending"
	BootstrapManaged        BootstrapState = "managed"
)

// Reason is a stable, non-secret audit explanation for a decision.
type Reason string

const (
	ReasonAllowFirstControl         Reason = "allow_first_control"
	ReasonAllowViaControl           Reason = "allow_via_control"
	ReasonAllowOutboundHTTPSPull    Reason = "allow_outbound_https_pull"
	ReasonAllowProviderRecovery     Reason = "allow_provider_recovery"
	ReasonInvalidInput              Reason = "invalid_input"
	ReasonActionNotAllowed          Reason = "action_not_allowed"
	ReasonControlNotReady           Reason = "control_not_ready"
	ReasonControlRevoked            Reason = "control_revoked"
	ReasonHumanAuthorityRequired    Reason = "human_authority_required"
	ReasonRecoveryAuthorityRequired Reason = "recovery_authority_required"
	ReasonProviderConsoleRequired   Reason = "provider_console_required"
	ReasonServingToInstanceDenied   Reason = "serving_to_instance_denied"
	ReasonControlPinMissing         Reason = "control_pin_missing"
	ReasonControlPinMismatch        Reason = "control_pin_mismatch"
	ReasonTargetPinMissing          Reason = "target_pin_missing"
	ReasonTargetPinMismatch         Reason = "target_pin_mismatch"
	ReasonRouteBindingMissing       Reason = "route_binding_missing"
	ReasonRouteBindingMismatch      Reason = "route_binding_mismatch"
	ReasonTargetBindingMismatch     Reason = "target_binding_mismatch"
	ReasonUnexpectedRouteBinding    Reason = "unexpected_route_binding"
	ReasonVNCLoopbackRequired       Reason = "vnc_loopback_required"
)

// Authority records explicit user presence and the separate elevation needed
// for provider-console recovery. Recovery without human authority is invalid.
type Authority struct {
	Human    bool
	Recovery bool
}

// ControlBinding binds the selected control to its operator-pinned identity.
// RouteFingerprint is required only when the final target is not the control.
type ControlBinding struct {
	ID                  string
	SelectedFingerprint string
	PinnedFingerprint   string
	RouteFingerprint    string
}

// TargetBinding binds the public target ID and, for routed SSH paths, its
// independently pinned identity to the route document.
type TargetBinding struct {
	ID                string
	PinnedFingerprint string
	RouteFingerprint  string
}

// VNCMetadata intentionally contains no address. LoopbackOnly affirms that a
// separately validated transport uses loopback at both ends of the VNC tunnel.
type VNCMetadata struct {
	LoopbackOnly bool
}

// Input is a public-metadata-only snapshot evaluated as one indivisible policy
// request. it has no fields for hosts, private paths, secrets, or commands.
type Input struct {
	SystemID       string
	Source         Actor
	Destination    Actor
	Action         Action
	Bootstrap      BootstrapState
	ControlReady   bool
	ControlRevoked bool
	Control        ControlBinding
	Target         TargetBinding
	Authority      Authority
	VNC            VNCMetadata
}

// Decision is immutable outside this package. use Allowed, Mode, and Reason
// for enforcement; MarshalJSON exposes only bounded public audit metadata.
type Decision struct {
	schema                     int
	allowed                    bool
	systemID                   string
	source                     Actor
	destination                Actor
	action                     Action
	mode                       Mode
	controlID                  string
	targetID                   string
	selectedControlFingerprint string
	pinnedControlFingerprint   string
	routeControlFingerprint    string
	pinnedTargetFingerprint    string
	routeTargetFingerprint     string
	vncLoopbackOnly            bool
	reason                     Reason
}

// Allowed reports whether the exact input is authorized. a zero or malformed
// Decision always reports false.
func (decision Decision) Allowed() bool {
	return validDecision(decision) && decision.allowed
}

// Mode returns the only authorized transport mode, or ModeDenied for any
// denied, zero, or malformed Decision.
func (decision Decision) Mode() Mode {
	if !validDecision(decision) || !decision.allowed {
		return ModeDenied
	}
	return decision.mode
}

// Reason returns the stable audit reason, or ReasonInvalidInput for a zero or
// malformed Decision.
func (decision Decision) Reason() Reason {
	if !validDecision(decision) {
		return ReasonInvalidInput
	}
	return decision.reason
}

// MarshalJSON emits a fixed public audit surface. invalid Decision values are
// sanitized to an anonymous denied decision instead of echoing bad data.
func (decision Decision) MarshalJSON() ([]byte, error) {
	if !validDecision(decision) {
		decision = invalidDecision()
	}
	type publicDecision struct {
		Schema                     int    `json:"schema"`
		Allowed                    bool   `json:"allowed"`
		SystemID                   string `json:"system_id,omitempty"`
		Source                     Actor  `json:"source,omitempty"`
		Destination                Actor  `json:"destination,omitempty"`
		Action                     Action `json:"action,omitempty"`
		Mode                       Mode   `json:"mode"`
		ControlID                  string `json:"control_id,omitempty"`
		TargetID                   string `json:"target_id,omitempty"`
		SelectedControlFingerprint string `json:"selected_control_fingerprint,omitempty"`
		PinnedControlFingerprint   string `json:"pinned_control_fingerprint,omitempty"`
		RouteControlFingerprint    string `json:"route_control_fingerprint,omitempty"`
		PinnedTargetFingerprint    string `json:"pinned_target_fingerprint,omitempty"`
		RouteTargetFingerprint     string `json:"route_target_fingerprint,omitempty"`
		VNCLoopbackOnly            bool   `json:"vnc_loopback_only,omitempty"`
		Reason                     Reason `json:"reason"`
	}
	return json.Marshal(publicDecision{
		Schema: decision.schema, Allowed: decision.allowed,
		SystemID: decision.systemID, Source: decision.source,
		Destination: decision.destination, Action: decision.action,
		Mode: decision.mode, ControlID: decision.controlID,
		TargetID:                   decision.targetID,
		SelectedControlFingerprint: decision.selectedControlFingerprint,
		PinnedControlFingerprint:   decision.pinnedControlFingerprint,
		RouteControlFingerprint:    decision.routeControlFingerprint,
		PinnedTargetFingerprint:    decision.pinnedTargetFingerprint,
		RouteTargetFingerprint:     decision.routeTargetFingerprint,
		VNCLoopbackOnly:            decision.vncLoopbackOnly, Reason: decision.reason,
	})
}

// Decide validates one complete request and returns exactly one mode. invalid
// input returns a denied decision as well as an error, so ignoring the error
// cannot accidentally authorize a path.
func Decide(input Input) (Decision, error) {
	if err := validateInput(input); err != nil {
		return invalidDecision(), err
	}
	decision := decisionFor(input)

	// this absolute invariant is evaluated before every other policy branch.
	if input.Source == ActorServing && input.Destination == ActorInstance {
		return deny(decision, ReasonServingToInstanceDenied), nil
	}
	if input.Action == ActionRecovery || input.Source == ActorProviderConsole {
		return decideRecovery(input, decision), nil
	}

	switch input.Source {
	case ActorOperator:
		return decideOperator(input, decision), nil
	case ActorInstance:
		return decideInstancePull(input, decision), nil
	default:
		return deny(decision, ReasonActionNotAllowed), nil
	}
}

func decideRecovery(input Input, decision Decision) Decision {
	if input.Source != ActorProviderConsole {
		return deny(decision, ReasonProviderConsoleRequired)
	}
	if input.Action != ActionRecovery || !recoveryDestination(input.Destination) {
		return deny(decision, ReasonActionNotAllowed)
	}
	if !input.Authority.Human {
		return deny(decision, ReasonHumanAuthorityRequired)
	}
	if !input.Authority.Recovery {
		return deny(decision, ReasonRecoveryAuthorityRequired)
	}
	if input.Target.ID == "" {
		return deny(decision, ReasonTargetBindingMismatch)
	}
	return allow(decision, ModeProviderConsole, ReasonAllowProviderRecovery)
}

func decideOperator(input Input, decision Decision) Decision {
	if input.ControlRevoked {
		return deny(decision, ReasonControlRevoked)
	}
	if !input.ControlReady {
		if input.Bootstrap != BootstrapControlPending || input.Destination != ActorControl ||
			(input.Action != ActionFirstControlCheck && input.Action != ActionControlInstall) {
			return deny(decision, ReasonControlNotReady)
		}
		if !input.Authority.Human {
			return deny(decision, ReasonHumanAuthorityRequired)
		}
		if reason := controlDestinationBinding(input); reason != "" {
			return deny(decision, reason)
		}
		return allow(decision, ModeDirectFirstControl, ReasonAllowFirstControl)
	}

	if !operatorActionAllowed(input.Destination, input.Action) {
		return deny(decision, ReasonActionNotAllowed)
	}
	if operatorActionRequiresHuman(input.Action) && !input.Authority.Human {
		return deny(decision, ReasonHumanAuthorityRequired)
	}
	if input.Action == ActionVNC && !input.VNC.LoopbackOnly {
		return deny(decision, ReasonVNCLoopbackRequired)
	}

	var reason Reason
	if input.Destination == ActorControl {
		reason = controlDestinationBinding(input)
	} else {
		reason = routedTargetBinding(input)
	}
	if reason != "" {
		return deny(decision, reason)
	}
	return allow(decision, ModeViaControl, ReasonAllowViaControl)
}

func decideInstancePull(input Input, decision Decision) Decision {
	if !input.ControlReady || input.Bootstrap != BootstrapManaged {
		return deny(decision, ReasonControlNotReady)
	}
	if input.Destination != ActorServing || input.Target.ID == "" {
		return deny(decision, ReasonActionNotAllowed)
	}
	switch input.Action {
	case ActionInstanceBootstrap, ActionDesiredStateUpdate, ActionStatus, ActionReleasePull:
		return allow(decision, ModeOutboundHTTPSPull, ReasonAllowOutboundHTTPSPull)
	default:
		return deny(decision, ReasonActionNotAllowed)
	}
}

func controlDestinationBinding(input Input) Reason {
	if input.Control.ID == "" || input.Target.ID == "" {
		return ReasonRouteBindingMissing
	}
	if input.Target.ID != input.Control.ID {
		return ReasonTargetBindingMismatch
	}
	if input.Control.SelectedFingerprint == "" || input.Control.PinnedFingerprint == "" {
		return ReasonControlPinMissing
	}
	if input.Target.PinnedFingerprint == "" {
		return ReasonTargetPinMissing
	}
	if input.Control.SelectedFingerprint != input.Control.PinnedFingerprint {
		return ReasonControlPinMismatch
	}
	if input.Target.PinnedFingerprint != input.Control.PinnedFingerprint {
		return ReasonTargetPinMismatch
	}
	if input.Control.RouteFingerprint != "" || input.Target.RouteFingerprint != "" {
		return ReasonUnexpectedRouteBinding
	}
	return ""
}

func routedTargetBinding(input Input) Reason {
	if input.Control.ID == "" || input.Target.ID == "" {
		return ReasonRouteBindingMissing
	}
	if input.Control.ID == input.Target.ID {
		return ReasonTargetBindingMismatch
	}
	if input.Control.SelectedFingerprint == "" || input.Control.PinnedFingerprint == "" {
		return ReasonControlPinMissing
	}
	if input.Control.SelectedFingerprint != input.Control.PinnedFingerprint {
		return ReasonControlPinMismatch
	}
	if input.Control.RouteFingerprint == "" || input.Target.RouteFingerprint == "" {
		return ReasonRouteBindingMissing
	}
	if input.Control.RouteFingerprint != input.Control.PinnedFingerprint {
		return ReasonRouteBindingMismatch
	}
	if input.Target.PinnedFingerprint == "" {
		return ReasonTargetPinMissing
	}
	if input.Target.RouteFingerprint != input.Target.PinnedFingerprint {
		return ReasonTargetPinMismatch
	}
	return ""
}

func operatorActionAllowed(destination Actor, action Action) bool {
	switch destination {
	case ActorControl:
		return action == ActionControlInstall || action == ActionSSH || action == ActionExec || action == ActionStatus
	case ActorServing:
		return action == ActionServingBootstrap || action == ActionDesiredStateUpdate ||
			action == ActionSSH || action == ActionExec || action == ActionStatus
	case ActorInstance:
		return action == ActionSSH || action == ActionExec || action == ActionVNC || action == ActionStatus
	default:
		return false
	}
}

func operatorActionRequiresHuman(action Action) bool {
	return action != ActionStatus
}

func recoveryDestination(actor Actor) bool {
	return actor == ActorControl || actor == ActorServing || actor == ActorInstance
}

func validateInput(input Input) error {
	if !systemIDRE.MatchString(input.SystemID) {
		return fmt.Errorf("%w: %w: system ID", ErrInvalidInput, ErrUnsafePublicID)
	}
	if !validActor(input.Source) || !validActor(input.Destination) || !validAction(input.Action) ||
		!validBootstrap(input.Bootstrap) {
		return ErrInvalidInput
	}
	for _, item := range []string{input.Control.ID, input.Target.ID} {
		if item != "" && !nodeIDRE.MatchString(item) {
			return fmt.Errorf("%w: %w: node ID", ErrInvalidInput, ErrUnsafePublicID)
		}
	}
	for _, fingerprint := range []string{
		input.Control.SelectedFingerprint,
		input.Control.PinnedFingerprint,
		input.Control.RouteFingerprint,
		input.Target.PinnedFingerprint,
		input.Target.RouteFingerprint,
	} {
		if fingerprint != "" && !validFingerprint(fingerprint) {
			return fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidFingerprint)
		}
	}
	if input.ControlReady != (input.Bootstrap == BootstrapManaged) {
		return fmt.Errorf("%w: %w", ErrInvalidInput, ErrInconsistentBootstrap)
	}
	if input.Authority.Recovery && !input.Authority.Human {
		return fmt.Errorf("%w: recovery authority requires human authority", ErrInvalidInput)
	}
	if input.Authority.Recovery && input.Action != ActionRecovery {
		return fmt.Errorf("%w: recovery authority on a non-recovery action", ErrInvalidInput)
	}
	if input.VNC.LoopbackOnly && input.Action != ActionVNC {
		return fmt.Errorf("%w: VNC metadata on a non-VNC action", ErrInvalidInput)
	}
	return nil
}

func validActor(actor Actor) bool {
	switch actor {
	case ActorOperator, ActorControl, ActorServing, ActorInstance, ActorProviderConsole:
		return true
	default:
		return false
	}
}

func validAction(action Action) bool {
	switch action {
	case ActionFirstControlCheck, ActionControlInstall, ActionServingBootstrap,
		ActionInstanceBootstrap, ActionDesiredStateUpdate, ActionSSH, ActionExec,
		ActionVNC, ActionStatus, ActionReleasePull, ActionRecovery:
		return true
	default:
		return false
	}
}

func validBootstrap(state BootstrapState) bool {
	switch state {
	case BootstrapUninitialized, BootstrapControlPending, BootstrapManaged:
		return true
	default:
		return false
	}
}

func validMode(mode Mode) bool {
	switch mode {
	case ModeDirectFirstControl, ModeViaControl, ModeOutboundHTTPSPull, ModeProviderConsole, ModeDenied:
		return true
	default:
		return false
	}
}

func validFingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32 && value == prefix+base64.RawStdEncoding.EncodeToString(decoded)
}

func decisionFor(input Input) Decision {
	return Decision{
		schema: SchemaVersion, systemID: input.SystemID,
		source: input.Source, destination: input.Destination, action: input.Action,
		mode: ModeDenied, controlID: input.Control.ID, targetID: input.Target.ID,
		selectedControlFingerprint: input.Control.SelectedFingerprint,
		pinnedControlFingerprint:   input.Control.PinnedFingerprint,
		routeControlFingerprint:    input.Control.RouteFingerprint,
		pinnedTargetFingerprint:    input.Target.PinnedFingerprint,
		routeTargetFingerprint:     input.Target.RouteFingerprint,
		vncLoopbackOnly:            input.VNC.LoopbackOnly, reason: ReasonActionNotAllowed,
	}
}

func invalidDecision() Decision {
	return Decision{schema: SchemaVersion, mode: ModeDenied, reason: ReasonInvalidInput}
}

func allow(decision Decision, mode Mode, reason Reason) Decision {
	decision.allowed = true
	decision.mode = mode
	decision.reason = reason
	return decision
}

func deny(decision Decision, reason Reason) Decision {
	decision.allowed = false
	decision.mode = ModeDenied
	decision.reason = reason
	return decision
}

func validDecision(decision Decision) bool {
	if decision.schema != SchemaVersion || !validMode(decision.mode) || !validReason(decision.reason) {
		return false
	}
	if decision.allowed == (decision.mode == ModeDenied) {
		return false
	}
	if decision.allowed && !allowedReasonForMode(decision.mode, decision.reason) {
		return false
	}
	if !decision.allowed && decision.reason != ReasonInvalidInput && isAllowReason(decision.reason) {
		return false
	}
	if decision.systemID != "" && !systemIDRE.MatchString(decision.systemID) {
		return false
	}
	if decision.source != "" && !validActor(decision.source) ||
		decision.destination != "" && !validActor(decision.destination) ||
		decision.action != "" && !validAction(decision.action) {
		return false
	}
	for _, item := range []string{decision.controlID, decision.targetID} {
		if item != "" && !nodeIDRE.MatchString(item) {
			return false
		}
	}
	for _, fingerprint := range []string{
		decision.selectedControlFingerprint, decision.pinnedControlFingerprint,
		decision.routeControlFingerprint, decision.pinnedTargetFingerprint,
		decision.routeTargetFingerprint,
	} {
		if fingerprint != "" && !validFingerprint(fingerprint) {
			return false
		}
	}
	return true
}

func validReason(reason Reason) bool {
	switch reason {
	case ReasonAllowFirstControl, ReasonAllowViaControl, ReasonAllowOutboundHTTPSPull,
		ReasonAllowProviderRecovery, ReasonInvalidInput, ReasonActionNotAllowed,
		ReasonControlNotReady, ReasonControlRevoked, ReasonHumanAuthorityRequired,
		ReasonRecoveryAuthorityRequired, ReasonProviderConsoleRequired,
		ReasonServingToInstanceDenied, ReasonControlPinMissing, ReasonControlPinMismatch,
		ReasonTargetPinMissing, ReasonTargetPinMismatch, ReasonRouteBindingMissing,
		ReasonRouteBindingMismatch, ReasonTargetBindingMismatch,
		ReasonUnexpectedRouteBinding, ReasonVNCLoopbackRequired:
		return true
	default:
		return false
	}
}

func allowedReasonForMode(mode Mode, reason Reason) bool {
	switch mode {
	case ModeDirectFirstControl:
		return reason == ReasonAllowFirstControl
	case ModeViaControl:
		return reason == ReasonAllowViaControl
	case ModeOutboundHTTPSPull:
		return reason == ReasonAllowOutboundHTTPSPull
	case ModeProviderConsole:
		return reason == ReasonAllowProviderRecovery
	default:
		return false
	}
}

func isAllowReason(reason Reason) bool {
	return reason == ReasonAllowFirstControl || reason == ReasonAllowViaControl ||
		reason == ReasonAllowOutboundHTTPSPull || reason == ReasonAllowProviderRecovery
}
