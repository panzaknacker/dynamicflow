package netpolicy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	controlFingerprint = testFingerprint(1)
	targetFingerprint  = testFingerprint(2)
	otherFingerprint   = testFingerprint(3)
)

func TestAllowedPolicyMatrix(t *testing.T) {
	assertAllowed(t, validDirectInput(ActionControlAttest), ModeDirectControlProof, ReasonAllowControlProof)
	for _, action := range []Action{ActionFirstControlCheck, ActionControlInstall} {
		t.Run("direct-"+string(action), func(t *testing.T) {
			assertAllowed(t, validDirectInput(action), ModeDirectFirstControl, ReasonAllowFirstControl)
		})
	}

	operatorMatrix := map[Actor][]Action{
		ActorControl:  {ActionControlInstall, ActionSSH, ActionExec, ActionStatus},
		ActorServing:  {ActionServingBootstrap, ActionDesiredStateUpdate, ActionSSH, ActionExec, ActionStatus},
		ActorInstance: {ActionSSH, ActionExec, ActionVNC, ActionStatus},
	}
	for destination, actions := range operatorMatrix {
		for _, action := range actions {
			t.Run("managed-"+string(destination)+"-"+string(action), func(t *testing.T) {
				assertAllowed(t, validManagedOperatorInput(destination, action), ModeViaControl, ReasonAllowViaControl)
			})
		}
	}

	for _, action := range []Action{
		ActionInstanceBootstrap, ActionDesiredStateUpdate, ActionStatus, ActionReleasePull,
	} {
		t.Run("pull-"+string(action), func(t *testing.T) {
			assertAllowed(t, validPullInput(action), ModeOutboundHTTPSPull, ReasonAllowOutboundHTTPSPull)
		})
	}

	for _, destination := range []Actor{ActorControl, ActorServing, ActorInstance} {
		t.Run("recovery-"+string(destination), func(t *testing.T) {
			input := validRecoveryInput(destination)
			input.ControlRevoked = true
			assertAllowed(t, input, ModeProviderConsole, ReasonAllowProviderRecovery)
		})
	}
}

func TestCompleteManagedActorActionMatrixHasNoUnexpectedAllow(t *testing.T) {
	for _, source := range allActors() {
		for _, destination := range allActors() {
			for _, action := range allActions() {
				name := string(source) + "-to-" + string(destination) + "-" + string(action)
				t.Run(name, func(t *testing.T) {
					input := validManagedOperatorInput(destination, action)
					input.Source = source
					if action == ActionRecovery {
						input.Authority.Recovery = source == ActorProviderConsole
					}
					decision, err := Decide(input)
					if err != nil {
						t.Fatalf("Decide(): %v", err)
					}
					wantAllowed, wantMode := expectedManagedDecision(source, destination, action)
					if decision.Allowed() != wantAllowed || decision.Mode() != wantMode {
						t.Fatalf("decision = allowed:%v mode:%q reason:%q, want allowed:%v mode:%q",
							decision.Allowed(), decision.Mode(), decision.Reason(), wantAllowed, wantMode)
					}
				})
			}
		}
	}
}

func TestDirectFirstControlHasNoOtherActionTargetOrFallback(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Input)
		reason Reason
	}{
		{
			name: "ready-does-not-fall-forward",
			mutate: func(input *Input) {
				input.Bootstrap = BootstrapManaged
				input.ControlReady = true
			},
			reason: ReasonActionNotAllowed,
		},
		{
			name: "uninitialized",
			mutate: func(input *Input) {
				input.Bootstrap = BootstrapUninitialized
			},
			reason: ReasonControlNotReady,
		},
		{
			name: "ssh",
			mutate: func(input *Input) {
				input.Action = ActionSSH
			},
			reason: ReasonControlNotReady,
		},
		{
			name: "instance-target",
			mutate: func(input *Input) {
				input.Destination = ActorInstance
				input.Target.ID = "instance-01"
			},
			reason: ReasonControlNotReady,
		},
		{
			name: "human-authority",
			mutate: func(input *Input) {
				input.Authority.Human = false
			},
			reason: ReasonHumanAuthorityRequired,
		},
		{
			name: "revoked",
			mutate: func(input *Input) {
				input.ControlRevoked = true
			},
			reason: ReasonControlRevoked,
		},
		{
			name: "different-control-target",
			mutate: func(input *Input) {
				input.Target.ID = "other-control"
			},
			reason: ReasonTargetBindingMismatch,
		},
		{
			name: "selected-pin-missing",
			mutate: func(input *Input) {
				input.Control.SelectedFingerprint = ""
			},
			reason: ReasonControlPinMissing,
		},
		{
			name: "pinned-control-missing",
			mutate: func(input *Input) {
				input.Control.PinnedFingerprint = ""
			},
			reason: ReasonControlPinMissing,
		},
		{
			name: "target-pin-missing",
			mutate: func(input *Input) {
				input.Target.PinnedFingerprint = ""
			},
			reason: ReasonTargetPinMissing,
		},
		{
			name: "selected-pin-mismatch",
			mutate: func(input *Input) {
				input.Control.SelectedFingerprint = otherFingerprint
			},
			reason: ReasonControlPinMismatch,
		},
		{
			name: "target-pin-mismatch",
			mutate: func(input *Input) {
				input.Target.PinnedFingerprint = otherFingerprint
			},
			reason: ReasonTargetPinMismatch,
		},
		{
			name: "route-metadata-never-imported",
			mutate: func(input *Input) {
				input.Control.RouteFingerprint = controlFingerprint
			},
			reason: ReasonUnexpectedRouteBinding,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validDirectInput(ActionFirstControlCheck)
			test.mutate(&input)
			assertDenied(t, input, test.reason)
		})
	}
}

func TestManagedRoutesRequireReadyUnrevokedExactPins(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Input)
		reason Reason
	}{
		{
			name: "control-not-ready",
			mutate: func(input *Input) {
				input.Bootstrap = BootstrapControlPending
				input.ControlReady = false
			},
			reason: ReasonControlNotReady,
		},
		{
			name: "control-revoked",
			mutate: func(input *Input) {
				input.ControlRevoked = true
			},
			reason: ReasonControlRevoked,
		},
		{
			name: "control-id-missing",
			mutate: func(input *Input) {
				input.Control.ID = ""
			},
			reason: ReasonRouteBindingMissing,
		},
		{
			name: "target-id-missing",
			mutate: func(input *Input) {
				input.Target.ID = ""
			},
			reason: ReasonRouteBindingMissing,
		},
		{
			name: "same-endpoint",
			mutate: func(input *Input) {
				input.Target.ID = input.Control.ID
			},
			reason: ReasonTargetBindingMismatch,
		},
		{
			name: "selected-pin-missing",
			mutate: func(input *Input) {
				input.Control.SelectedFingerprint = ""
			},
			reason: ReasonControlPinMissing,
		},
		{
			name: "selected-pin-mismatch",
			mutate: func(input *Input) {
				input.Control.SelectedFingerprint = otherFingerprint
			},
			reason: ReasonControlPinMismatch,
		},
		{
			name: "route-control-missing",
			mutate: func(input *Input) {
				input.Control.RouteFingerprint = ""
			},
			reason: ReasonRouteBindingMissing,
		},
		{
			name: "route-control-mismatch",
			mutate: func(input *Input) {
				input.Control.RouteFingerprint = otherFingerprint
			},
			reason: ReasonRouteBindingMismatch,
		},
		{
			name: "target-pin-missing",
			mutate: func(input *Input) {
				input.Target.PinnedFingerprint = ""
			},
			reason: ReasonTargetPinMissing,
		},
		{
			name: "route-target-missing",
			mutate: func(input *Input) {
				input.Target.RouteFingerprint = ""
			},
			reason: ReasonRouteBindingMissing,
		},
		{
			name: "route-target-mismatch",
			mutate: func(input *Input) {
				input.Target.RouteFingerprint = otherFingerprint
			},
			reason: ReasonTargetPinMismatch,
		},
		{
			name: "exec-needs-human",
			mutate: func(input *Input) {
				input.Authority.Human = false
			},
			reason: ReasonHumanAuthorityRequired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validManagedOperatorInput(ActorInstance, ActionExec)
			test.mutate(&input)
			assertDenied(t, input, test.reason)
		})
	}
}

func TestOperatorManagedActionRestrictionsAndVNC(t *testing.T) {
	for _, test := range []struct {
		name        string
		destination Actor
		action      Action
		mutate      func(*Input)
		reason      Reason
	}{
		{name: "instance-bootstrap-is-pull-only", destination: ActorInstance, action: ActionInstanceBootstrap, reason: ReasonActionNotAllowed},
		{name: "release-pull-is-not-operator", destination: ActorServing, action: ActionReleasePull, reason: ReasonActionNotAllowed},
		{name: "first-check-closes-after-ready", destination: ActorControl, action: ActionFirstControlCheck, reason: ReasonActionNotAllowed},
		{name: "vnc-serving", destination: ActorServing, action: ActionVNC, reason: ReasonActionNotAllowed},
		{
			name: "vnc-missing-loopback", destination: ActorInstance, action: ActionVNC,
			mutate: func(input *Input) { input.VNC.LoopbackOnly = false }, reason: ReasonVNCLoopbackRequired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validManagedOperatorInput(test.destination, test.action)
			if test.mutate != nil {
				test.mutate(&input)
			}
			assertDenied(t, input, test.reason)
		})
	}

	status := validManagedOperatorInput(ActorInstance, ActionStatus)
	status.Authority.Human = false
	assertAllowed(t, status, ModeViaControl, ReasonAllowViaControl)

	vnc := validManagedOperatorInput(ActorInstance, ActionVNC)
	decision, err := Decide(vnc)
	if err != nil {
		t.Fatalf("Decide(VNC): %v", err)
	}
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(VNC): %v", err)
	}
	if !bytes.Contains(data, []byte(`"vnc_loopback_only":true`)) {
		t.Fatalf("VNC decision lacks loopback-only metadata: %s", data)
	}
}

func TestSSHExecAndVNCAlwaysRequireExplicitHumanAuthority(t *testing.T) {
	for _, action := range []Action{ActionSSH, ActionExec, ActionVNC} {
		t.Run(string(action), func(t *testing.T) {
			input := validManagedOperatorInput(ActorInstance, action)
			input.Authority.Human = false
			assertDenied(t, input, ReasonHumanAuthorityRequired)
		})
	}
}

func TestServingNeverInitiatesInstancePath(t *testing.T) {
	for _, action := range allActions() {
		t.Run(string(action), func(t *testing.T) {
			input := validManagedOperatorInput(ActorInstance, ActionStatus)
			input.Source = ActorServing
			input.Action = action
			input.Authority = Authority{}
			input.VNC = VNCMetadata{}
			assertDenied(t, input, ReasonServingToInstanceDenied)
		})
	}
}

func TestInstanceNormalPathsAreOutboundHTTPSOnly(t *testing.T) {
	input := validPullInput(ActionReleasePull)
	input.ControlRevoked = true
	input.Control.SelectedFingerprint = otherFingerprint
	input.Control.RouteFingerprint = otherFingerprint
	assertAllowed(t, input, ModeOutboundHTTPSPull, ReasonAllowOutboundHTTPSPull)

	for _, test := range []struct {
		name   string
		mutate func(*Input)
	}{
		{
			name: "ssh",
			mutate: func(input *Input) {
				input.Action = ActionSSH
			},
		},
		{
			name: "wrong-destination",
			mutate: func(input *Input) {
				input.Destination = ActorInstance
			},
		},
		{
			name: "before-managed",
			mutate: func(input *Input) {
				input.Bootstrap = BootstrapControlPending
				input.ControlReady = false
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPullInput(ActionStatus)
			test.mutate(&candidate)
			decision, err := Decide(candidate)
			if err != nil {
				t.Fatalf("Decide(): %v", err)
			}
			if decision.Allowed() || decision.Mode() != ModeDenied {
				t.Fatalf("unexpected fallback: allowed=%v mode=%q", decision.Allowed(), decision.Mode())
			}
		})
	}
}

func TestProviderRecoveryRequiresBothExplicitAuthorities(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Input)
		reason Reason
	}{
		{
			name: "wrong-source",
			mutate: func(input *Input) {
				input.Source = ActorOperator
			},
			reason: ReasonProviderConsoleRequired,
		},
		{
			name: "human-missing",
			mutate: func(input *Input) {
				input.Authority = Authority{}
			},
			reason: ReasonHumanAuthorityRequired,
		},
		{
			name: "recovery-missing",
			mutate: func(input *Input) {
				input.Authority.Recovery = false
			},
			reason: ReasonRecoveryAuthorityRequired,
		},
		{
			name: "wrong-destination",
			mutate: func(input *Input) {
				input.Destination = ActorOperator
			},
			reason: ReasonActionNotAllowed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validRecoveryInput(ActorInstance)
			test.mutate(&input)
			assertDenied(t, input, test.reason)
		})
	}

	uninitialized := validRecoveryInput(ActorControl)
	uninitialized.Bootstrap = BootstrapUninitialized
	uninitialized.ControlReady = false
	uninitialized.Control = ControlBinding{}
	assertAllowed(t, uninitialized, ModeProviderConsole, ReasonAllowProviderRecovery)
}

func TestStrictInputValidationReturnsDeniedDecision(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Input)
		cause  error
	}{
		{
			name: "system-path",
			mutate: func(input *Input) {
				input.SystemID = "/home/operator/.ssh/id_ed25519"
			},
			cause: ErrUnsafePublicID,
		},
		{
			name: "unknown-source",
			mutate: func(input *Input) {
				input.Source = Actor("root-shell")
			},
			cause: ErrInvalidInput,
		},
		{
			name: "unknown-destination",
			mutate: func(input *Input) {
				input.Destination = Actor("internet")
			},
			cause: ErrInvalidInput,
		},
		{
			name: "unknown-action",
			mutate: func(input *Input) {
				input.Action = Action("run-command")
			},
			cause: ErrInvalidInput,
		},
		{
			name: "unknown-bootstrap",
			mutate: func(input *Input) {
				input.Bootstrap = BootstrapState("legacy")
			},
			cause: ErrInvalidInput,
		},
		{
			name: "ready-state-mismatch",
			mutate: func(input *Input) {
				input.ControlReady = false
			},
			cause: ErrInconsistentBootstrap,
		},
		{
			name: "unsafe-control-id",
			mutate: func(input *Input) {
				input.Control.ID = "../../control"
			},
			cause: ErrUnsafePublicID,
		},
		{
			name: "unsafe-target-id",
			mutate: func(input *Input) {
				input.Target.ID = "target.example"
			},
			cause: ErrUnsafePublicID,
		},
		{
			name: "fingerprint-format",
			mutate: func(input *Input) {
				input.Target.RouteFingerprint = "SHA256:not-canonical"
			},
			cause: ErrInvalidFingerprint,
		},
		{
			name: "recovery-without-human",
			mutate: func(input *Input) {
				input.Action = ActionRecovery
				input.Authority = Authority{Recovery: true}
			},
			cause: ErrInvalidInput,
		},
		{
			name: "recovery-on-normal-action",
			mutate: func(input *Input) {
				input.Authority.Recovery = true
			},
			cause: ErrInvalidInput,
		},
		{
			name: "vnc-metadata-on-exec",
			mutate: func(input *Input) {
				input.VNC.LoopbackOnly = true
			},
			cause: ErrInvalidInput,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validManagedOperatorInput(ActorInstance, ActionExec)
			test.mutate(&input)
			decision, err := Decide(input)
			if !errors.Is(err, ErrInvalidInput) || !errors.Is(err, test.cause) {
				t.Fatalf("Decide() error = %v, want ErrInvalidInput and %v", err, test.cause)
			}
			if decision.Allowed() || decision.Mode() != ModeDenied || decision.Reason() != ReasonInvalidInput {
				t.Fatalf("invalid input did not fail closed: allowed=%v mode=%q reason=%q", decision.Allowed(), decision.Mode(), decision.Reason())
			}
		})
	}
}

func TestDecisionJSONIsFixedPublicAuditSurface(t *testing.T) {
	decision, err := Decide(validManagedOperatorInput(ActorInstance, ActionVNC))
	if err != nil {
		t.Fatalf("Decide(): %v", err)
	}
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	assertJSONKeyAllowlist(t, data)
	for _, forbidden := range []string{"host", "private", "path", "command", "secret", "authority"} {
		if bytes.Contains(bytes.ToLower(data), []byte(`"`+forbidden+`"`)) {
			t.Fatalf("decision JSON exposes forbidden field %q: %s", forbidden, data)
		}
	}

	unsafe := validManagedOperatorInput(ActorInstance, ActionExec)
	unsafe.SystemID = "/home/operator/.ssh/id_ed25519"
	denied, err := Decide(unsafe)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsafe Decide() error = %v", err)
	}
	data, err = json.Marshal(denied)
	if err != nil {
		t.Fatalf("Marshal(denied): %v", err)
	}
	if bytes.Contains(data, []byte(unsafe.SystemID)) {
		t.Fatalf("invalid input was echoed: %s", data)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("Unmarshal(denied): %v", err)
	}
	if len(object) != 4 || object["mode"] != string(ModeDenied) || object["reason"] != string(ReasonInvalidInput) {
		t.Fatalf("invalid decision JSON = %#v", object)
	}
}

func TestZeroDecisionFailsClosedAndSerializesAnonymously(t *testing.T) {
	var decision Decision
	if decision.Allowed() || decision.Mode() != ModeDenied || decision.Reason() != ReasonInvalidInput {
		t.Fatalf("zero decision is not fail-closed")
	}
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(zero): %v", err)
	}
	if string(data) != `{"schema":1,"allowed":false,"mode":"denied","reason":"invalid_input"}` {
		t.Fatalf("zero JSON = %s", data)
	}
}

func TestDecideIsSafeForConcurrentUse(t *testing.T) {
	input := validManagedOperatorInput(ActorInstance, ActionExec)
	want, err := Decide(input)
	if err != nil {
		t.Fatalf("initial Decide(): %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("initial Marshal(): %v", err)
	}

	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, decideErr := Decide(input)
			if decideErr != nil {
				t.Errorf("Decide(): %v", decideErr)
				return
			}
			gotJSON, marshalErr := json.Marshal(got)
			if marshalErr != nil {
				t.Errorf("Marshal(): %v", marshalErr)
				return
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Errorf("concurrent decision differs: %s != %s", gotJSON, wantJSON)
			}
		}()
	}
	wait.Wait()
}

func FuzzDecideFailClosed(f *testing.F) {
	seed := validManagedOperatorInput(ActorInstance, ActionExec)
	f.Add(
		seed.SystemID, string(seed.Source), string(seed.Destination), string(seed.Action), string(seed.Bootstrap),
		seed.Control.ID, seed.Target.ID, seed.Control.SelectedFingerprint, seed.Control.PinnedFingerprint,
		seed.Control.RouteFingerprint, seed.Target.PinnedFingerprint, seed.Target.RouteFingerprint,
		seed.ControlReady, seed.ControlRevoked, seed.Authority.Human, seed.Authority.Recovery, seed.VNC.LoopbackOnly,
	)
	f.Add("/tmp/key", "serving", "instance", "exec", "managed", "control-01", "instance-01", "bad", "", "", "", "", true, false, false, false, false)

	f.Fuzz(func(t *testing.T, systemID, source, destination, action, bootstrap, controlID, targetID,
		selectedControl, pinnedControl, routeControl, pinnedTarget, routeTarget string,
		ready, revoked, human, recovery, loopback bool,
	) {
		input := Input{
			SystemID: systemID, Source: Actor(source), Destination: Actor(destination), Action: Action(action),
			Bootstrap: BootstrapState(bootstrap), ControlReady: ready, ControlRevoked: revoked,
			Control:   ControlBinding{ID: controlID, SelectedFingerprint: selectedControl, PinnedFingerprint: pinnedControl, RouteFingerprint: routeControl},
			Target:    TargetBinding{ID: targetID, PinnedFingerprint: pinnedTarget, RouteFingerprint: routeTarget},
			Authority: Authority{Human: human, Recovery: recovery}, VNC: VNCMetadata{LoopbackOnly: loopback},
		}
		decision, err := Decide(input)
		if err != nil {
			if decision.Allowed() || decision.Mode() != ModeDenied || decision.Reason() != ReasonInvalidInput {
				t.Fatalf("invalid fuzz input escaped closed state")
			}
		} else if decision.Allowed() {
			assertAllowedInvariant(t, input, decision)
		} else if decision.Mode() != ModeDenied {
			t.Fatalf("denied fuzz input selected %q", decision.Mode())
		}
		data, marshalErr := json.Marshal(decision)
		if marshalErr != nil {
			t.Fatalf("Marshal(): %v", marshalErr)
		}
		assertJSONKeyAllowlist(t, data)
	})
}

func FuzzInvalidDecisionJSONIsAnonymous(f *testing.F) {
	f.Add("/home/operator/.ssh/id_ed25519", "../../control", "target.example", "SHA256:bad")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, systemID, controlID, targetID, fingerprint string) {
		input := validManagedOperatorInput(ActorInstance, ActionExec)
		input.SystemID = systemID
		input.Control.ID = controlID
		input.Target.ID = targetID
		input.Target.RouteFingerprint = fingerprint
		decision, err := Decide(input)
		data, marshalErr := json.Marshal(decision)
		if marshalErr != nil {
			t.Fatalf("Marshal(): %v", marshalErr)
		}
		assertJSONKeyAllowlist(t, data)
		if err == nil {
			return
		}
		var object map[string]any
		if unmarshalErr := json.Unmarshal(data, &object); unmarshalErr != nil {
			t.Fatalf("Unmarshal(): %v", unmarshalErr)
		}
		if len(object) != 4 || object["mode"] != string(ModeDenied) || object["reason"] != string(ReasonInvalidInput) {
			t.Fatalf("invalid input was not anonymized: %#v", object)
		}
	})
}

func validDirectInput(action Action) Input {
	return Input{
		SystemID:     "sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:       ActorOperator,
		Destination:  ActorControl,
		Action:       action,
		Bootstrap:    BootstrapControlPending,
		ControlReady: false,
		Control: ControlBinding{
			ID: "control-01", SelectedFingerprint: controlFingerprint,
			PinnedFingerprint: controlFingerprint,
		},
		Target:    TargetBinding{ID: "control-01", PinnedFingerprint: controlFingerprint},
		Authority: Authority{Human: true},
	}
}

func validManagedOperatorInput(destination Actor, action Action) Input {
	targetID := "instance-01"
	if destination == ActorServing {
		targetID = "serving-01"
	}
	input := Input{
		SystemID:     "sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:       ActorOperator,
		Destination:  destination,
		Action:       action,
		Bootstrap:    BootstrapManaged,
		ControlReady: true,
		Control: ControlBinding{
			ID: "control-01", SelectedFingerprint: controlFingerprint,
			PinnedFingerprint: controlFingerprint, RouteFingerprint: controlFingerprint,
		},
		Target: TargetBinding{
			ID: targetID, PinnedFingerprint: targetFingerprint, RouteFingerprint: targetFingerprint,
		},
		Authority: Authority{Human: true},
	}
	if destination == ActorControl {
		input.Control.RouteFingerprint = ""
		input.Target = TargetBinding{ID: "control-01", PinnedFingerprint: controlFingerprint}
	}
	if action == ActionVNC {
		input.VNC.LoopbackOnly = true
	}
	return input
}

func validPullInput(action Action) Input {
	return Input{
		SystemID:     "sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:       ActorInstance,
		Destination:  ActorServing,
		Action:       action,
		Bootstrap:    BootstrapManaged,
		ControlReady: true,
		Control:      ControlBinding{ID: "control-01"},
		Target:       TargetBinding{ID: "serving-01"},
	}
}

func validRecoveryInput(destination Actor) Input {
	targetID := "instance-01"
	if destination == ActorControl {
		targetID = "control-01"
	} else if destination == ActorServing {
		targetID = "serving-01"
	}
	return Input{
		SystemID:       "sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:         ActorProviderConsole,
		Destination:    destination,
		Action:         ActionRecovery,
		Bootstrap:      BootstrapManaged,
		ControlReady:   true,
		ControlRevoked: true,
		Control:        ControlBinding{ID: "control-01"},
		Target:         TargetBinding{ID: targetID},
		Authority:      Authority{Human: true, Recovery: true},
	}
}

func assertAllowed(t *testing.T, input Input, mode Mode, reason Reason) {
	t.Helper()
	decision, err := Decide(input)
	if err != nil {
		t.Fatalf("Decide(): %v", err)
	}
	if !decision.Allowed() || decision.Mode() != mode || decision.Reason() != reason {
		t.Fatalf("decision = allowed:%v mode:%q reason:%q, want true %q %q", decision.Allowed(), decision.Mode(), decision.Reason(), mode, reason)
	}
	assertAllowedInvariant(t, input, decision)
}

func assertDenied(t *testing.T, input Input, reason Reason) {
	t.Helper()
	decision, err := Decide(input)
	if err != nil {
		t.Fatalf("Decide(): %v", err)
	}
	if decision.Allowed() || decision.Mode() != ModeDenied || decision.Reason() != reason {
		t.Fatalf("decision = allowed:%v mode:%q reason:%q, want false denied %q", decision.Allowed(), decision.Mode(), decision.Reason(), reason)
	}
}

func assertAllowedInvariant(t *testing.T, input Input, decision Decision) {
	t.Helper()
	switch decision.Mode() {
	case ModeDirectControlProof:
		if input.Source != ActorOperator || input.Destination != ActorControl || input.ControlReady || input.ControlRevoked ||
			input.Bootstrap != BootstrapControlPending || !input.Authority.Human || input.Action != ActionControlAttest || controlDestinationBinding(input) != "" {
			t.Fatalf("pending Control proof invariant violated by %#v", input)
		}
	case ModeDirectFirstControl:
		if input.Source != ActorOperator || input.Destination != ActorControl || input.ControlReady || input.ControlRevoked ||
			input.Bootstrap != BootstrapControlPending || !input.Authority.Human ||
			(input.Action != ActionFirstControlCheck && input.Action != ActionControlInstall) ||
			controlDestinationBinding(input) != "" {
			t.Fatalf("direct invariant violated by %#v", input)
		}
	case ModeViaControl:
		if input.Source != ActorOperator || !input.ControlReady || input.ControlRevoked || input.Bootstrap != BootstrapManaged ||
			!operatorActionAllowed(input.Destination, input.Action) ||
			operatorActionRequiresHuman(input.Action) && !input.Authority.Human ||
			input.Action == ActionVNC && !input.VNC.LoopbackOnly {
			t.Fatalf("via-control invariant violated by %#v", input)
		}
		if input.Destination == ActorControl && controlDestinationBinding(input) != "" {
			t.Fatalf("managed control binding violated")
		}
		if input.Destination != ActorControl && routedTargetBinding(input) != "" {
			t.Fatalf("managed target binding violated")
		}
	case ModeOutboundHTTPSPull:
		if input.Source != ActorInstance || input.Destination != ActorServing || !input.ControlReady || input.Bootstrap != BootstrapManaged ||
			(input.Action != ActionInstanceBootstrap && input.Action != ActionDesiredStateUpdate && input.Action != ActionStatus && input.Action != ActionReleasePull) {
			t.Fatalf("outbound-pull invariant violated by %#v", input)
		}
	case ModeProviderConsole:
		if input.Source != ActorProviderConsole || input.Action != ActionRecovery || !recoveryDestination(input.Destination) ||
			!input.Authority.Human || !input.Authority.Recovery {
			t.Fatalf("provider-console invariant violated by %#v", input)
		}
	default:
		t.Fatalf("allowed decision selected invalid mode %q", decision.Mode())
	}
}

func assertJSONKeyAllowlist(t *testing.T, data []byte) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("Unmarshal decision JSON: %v; data=%s", err, data)
	}
	allowed := map[string]bool{
		"schema": true, "allowed": true, "system_id": true, "source": true,
		"destination": true, "action": true, "mode": true, "control_id": true,
		"target_id": true, "selected_control_fingerprint": true,
		"pinned_control_fingerprint": true, "route_control_fingerprint": true,
		"pinned_target_fingerprint": true, "route_target_fingerprint": true,
		"vnc_loopback_only": true, "reason": true,
	}
	for key := range object {
		if !allowed[key] {
			t.Fatalf("unexpected decision JSON key %q in %s", key, data)
		}
	}
}

func allActions() []Action {
	return []Action{
		ActionFirstControlCheck, ActionControlInstall, ActionControlAttest, ActionServingBootstrap,
		ActionInstanceBootstrap, ActionDesiredStateUpdate, ActionSSH, ActionExec,
		ActionVNC, ActionStatus, ActionReleasePull, ActionRecovery,
	}
}

func allActors() []Actor {
	return []Actor{ActorOperator, ActorControl, ActorServing, ActorInstance, ActorProviderConsole}
}

func expectedManagedDecision(source, destination Actor, action Action) (bool, Mode) {
	if source == ActorServing && destination == ActorInstance {
		return false, ModeDenied
	}
	if source == ActorProviderConsole {
		if action == ActionRecovery && recoveryDestination(destination) {
			return true, ModeProviderConsole
		}
		return false, ModeDenied
	}
	if action == ActionRecovery {
		return false, ModeDenied
	}
	if source == ActorOperator && operatorActionAllowed(destination, action) {
		return true, ModeViaControl
	}
	if source == ActorInstance && destination == ActorServing {
		switch action {
		case ActionInstanceBootstrap, ActionDesiredStateUpdate, ActionStatus, ActionReleasePull:
			return true, ModeOutboundHTTPSPull
		}
	}
	return false, ModeDenied
}

func testFingerprint(fill byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestInputContainsNoHostPathOrCommandSurface(t *testing.T) {
	for _, structure := range []any{Input{}, ControlBinding{}, TargetBinding{}, Authority{}, VNCMetadata{}} {
		typeOfStructure := reflect.TypeOf(structure)
		for index := 0; index < typeOfStructure.NumField(); index++ {
			name := strings.ToLower(typeOfStructure.Field(index).Name)
			for _, forbidden := range []string{"host", "path", "command", "private", "secret"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s unexpectedly exposes %q field %q", typeOfStructure.Name(), forbidden, name)
				}
			}
		}
	}
}
