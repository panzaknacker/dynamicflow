package lab

// Qualification attestations are narrow declarations about tests that cannot
// be recreated safely without receiving an enrollment secret or publishing
// deliberately invalid release material. Reports never label them automated.
const (
	GateFreshEnrollmentOutboundHTTPS = "fresh-enrollment-outbound-https"
	GateEnrollmentReplayRejected     = "enrollment-replay-rejected"
	GateEnrollmentExpiryRejected     = "enrollment-expiry-rejected"
	GateSignatureTamperRejected      = "signature-tamper-rejected"
	GateDigestTamperRejected         = "digest-tamper-rejected"
	GateApplyInterruptionInjected    = "apply-interruption-injected"
	GateRuntimeUpgradePublished      = "runtime-upgrade-published"
)

var roleAttestations = map[string][]string{
	"serving": nil,
	"enrollment": {
		GateFreshEnrollmentOutboundHTTPS,
		GateEnrollmentReplayRejected,
		GateEnrollmentExpiryRejected,
	},
	"pbp": nil,
	"recovery-negative": {
		GateSignatureTamperRejected,
		GateDigestTamperRejected,
		GateApplyInterruptionInjected,
		GateRuntimeUpgradePublished,
	},
}

// RequiredAttestations returns a fresh copy of the fixed role-bound list.
func RequiredAttestations(role string) []string {
	values, ok := roleAttestations[role]
	if !ok {
		return nil
	}
	return append([]string(nil), values...)
}

// MissingAttestations returns the required declarations that are absent.
func MissingAttestations(host Host) []string {
	present := make(map[string]bool, len(host.AttestedGates))
	for _, value := range host.AttestedGates {
		present[value] = true
	}
	var missing []string
	for _, value := range RequiredAttestations(host.Role) {
		if !present[value] {
			missing = append(missing, value)
		}
	}
	return missing
}

// QualificationStep is the public machine-readable contract for the fixed
// four-VM run. Actions come only from the closed RemoteExecutor allowlist.
type QualificationStep struct {
	Sequence    int      `json:"sequence"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Kind        string   `json:"kind"`
	Mutating    bool     `json:"mutating"`
	Attestation string   `json:"attestation,omitempty"`
	Actions     []Action `json:"actions,omitempty"`
}

// QualificationMatrix returns the smallest fixed sequence used by Runner.
func QualificationMatrix() []QualificationStep {
	steps := []QualificationStep{
		{Name: "inventory-disposable-and-hostkey", Role: "all", Kind: "inventory-gate"},
		{Name: "fresh-enrollment", Role: "enrollment", Kind: "operator-attested", Mutating: true, Attestation: GateFreshEnrollmentOutboundHTTPS},
		{Name: "enrollment-replay", Role: "enrollment", Kind: "operator-attested", Mutating: true, Attestation: GateEnrollmentReplayRejected},
		{Name: "enrollment-expiry", Role: "enrollment", Kind: "operator-attested", Mutating: true, Attestation: GateEnrollmentExpiryRejected},
		{Name: "signature-tamper", Role: "recovery-negative", Kind: "operator-attested", Mutating: true, Attestation: GateSignatureTamperRejected},
		{Name: "digest-tamper", Role: "recovery-negative", Kind: "operator-attested", Mutating: true, Attestation: GateDigestTamperRejected},
		{Name: "apply-interruption", Role: "recovery-negative", Kind: "operator-attested", Mutating: true, Attestation: GateApplyInterruptionInjected},
		{Name: "runtime-upgrade", Role: "recovery-negative", Kind: "operator-attested", Mutating: true, Attestation: GateRuntimeUpgradePublished},
	}
	for _, role := range requiredRoles() {
		steps = append(steps, QualificationStep{Name: "preflight-" + role, Role: role, Kind: "fixed-remote", Actions: []Action{ActionPreflight}})
	}
	steps = append(steps,
		QualificationStep{Name: "serving-https-and-no-ssh", Role: "serving", Kind: "fixed-remote", Actions: []Action{ActionServingProbe}},
		QualificationStep{Name: "serving-flow-reconcile-idempotent", Role: "serving", Kind: "fixed-remote", Mutating: true, Actions: []Action{ActionServingReconcile}},
		QualificationStep{Name: "serving-restart-stability", Role: "serving", Kind: "fixed-remote", Mutating: true, Actions: []Action{ActionServingRestart}},
		QualificationStep{Name: "serving-reboot-resume", Role: "serving", Kind: "bounded-composite", Mutating: true, Actions: []Action{ActionReboot, ActionReachable, ActionServingProbe}},
	)
	for _, role := range []string{"enrollment", "pbp", "recovery-negative"} {
		steps = append(steps, QualificationStep{Name: "runtime-timer-" + role, Role: role, Kind: "fixed-remote", Actions: []Action{ActionRuntimeProbe}})
	}
	steps = append(steps,
		QualificationStep{Name: "enrollment-public-key-only", Role: "enrollment", Kind: "fixed-remote", Actions: []Action{ActionEnrollmentProbe}},
		QualificationStep{Name: "ssh-key-rotation", Role: "enrollment", Kind: "bounded-control", Mutating: true},
		QualificationStep{Name: "runtime-after-key-rotation", Role: "enrollment", Kind: "fixed-remote", Actions: []Action{ActionRuntimeProbe}},
		QualificationStep{Name: "enrollment-reboot-resume", Role: "enrollment", Kind: "bounded-composite", Mutating: true, Actions: []Action{ActionReboot, ActionReachable, ActionRuntimeProbe}},
		QualificationStep{Name: "recovery-evidence", Role: "recovery-negative", Kind: "fixed-remote", Actions: []Action{ActionRecoveryProbe}},
		QualificationStep{Name: "parallel-apply-lock-and-resume", Role: "recovery-negative", Kind: "fixed-remote", Mutating: true, Actions: []Action{ActionApplyConcurrency}},
		QualificationStep{Name: "recovery-reboot-resume", Role: "recovery-negative", Kind: "bounded-composite", Mutating: true, Actions: []Action{ActionReboot, ActionReachable, ActionRuntimeProbe}},
		QualificationStep{Name: "vnc-loopback", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionVNCProbe}},
		QualificationStep{Name: "vnc-secret-rotation", Role: "pbp", Kind: "bounded-control", Mutating: true},
		QualificationStep{Name: "pbp-vpn-preflight", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionPBPProbe}},
		QualificationStep{Name: "pbp-identity-before-reboot", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionPBPIdentity}},
		QualificationStep{Name: "pbp-reboot-resume", Role: "pbp", Kind: "bounded-composite", Mutating: true, Actions: []Action{ActionReboot, ActionReachable, ActionRuntimeProbe}},
		QualificationStep{Name: "vnc-loopback-after-reboot", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionVNCProbe}},
		QualificationStep{Name: "pbp-vpn-after-reboot", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionPBPProbe}},
		QualificationStep{Name: "pbp-identity-after-reboot", Role: "pbp", Kind: "fixed-remote", Actions: []Action{ActionPBPIdentity}},
		QualificationStep{Name: "pbp-qualifying-soak", Role: "pbp", Kind: "bounded-composite", Mutating: true, Actions: []Action{ActionPBPSoakStart, ActionPBPSoakPoll, ActionPBPForensics, ActionPBPSoakResult}},
		QualificationStep{Name: "signed-revocation", Role: "recovery-negative", Kind: "bounded-control", Mutating: true},
	)
	for index := range steps {
		steps[index].Sequence = index + 1
		steps[index].Actions = append([]Action(nil), steps[index].Actions...)
	}
	return steps
}
