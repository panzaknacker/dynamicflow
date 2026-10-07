package netpolicy

import "testing"

func TestPendingControlAttestationIsExclusiveAndFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"ready":                 func(input *Input) { input.ControlReady = true; input.Bootstrap = BootstrapManaged },
		"uninitialized":         func(input *Input) { input.Bootstrap = BootstrapUninitialized },
		"no explicit authority": func(input *Input) { input.Authority.Human = false },
		"revoked":               func(input *Input) { input.ControlRevoked = true },
		"other node":            func(input *Input) { input.Target.ID = "other-control" },
		"other pin":             func(input *Input) { input.Target.PinnedFingerprint = otherFingerprint },
		"unpinned":              func(input *Input) { input.Control.PinnedFingerprint = "" },
		"instance":              func(input *Input) { input.Destination = ActorInstance },
		"serving":               func(input *Input) { input.Destination = ActorServing },
		"remote initiator":      func(input *Input) { input.Source = ActorControl },
		"unexpected route":      func(input *Input) { input.Control.RouteFingerprint = input.Control.PinnedFingerprint },
	} {
		t.Run(name, func(t *testing.T) {
			input := validDirectInput(ActionControlAttest)
			mutate(&input)
			decision, err := Decide(input)
			if err != nil || decision.Allowed() || decision.Mode() != ModeDenied {
				t.Fatalf("unsafe attestation decision=%+v err=%v", decision, err)
			}
		})
	}
}
