package controlpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

var policyTime = time.Date(2026, 7, 23, 16, 0, 0, 0, time.UTC)

func TestSignedPolicyCanonicalRoundTripAndForcedAllowlist(t *testing.T) {
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy()
	signed, err := Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, public, policyTime.Add(time.Minute), policy.SystemID, policy.ControlName, 7); err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalCanonical(signed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCanonical(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalCanonical(parsed)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatalf("canonical round trip changed bytes: %v\n%s\n%s", err, encoded, reencoded)
	}
	if err := Verify(parsed, public, policyTime.Add(time.Hour), policy.SystemID, policy.ControlName, 7); err != nil {
		t.Fatal(err)
	}

	authorized, err := RenderAuthorizedKeys(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(authorized)
	if strings.Count(text, "\n") != 2 || strings.Count(text, `restrict,command="`+ForcedSession+`",port-forwarding`) != 2 ||
		strings.Count(text, `permitopen="10.20.0.8:22"`) != 2 ||
		strings.Count(text, `permitopen="[2001:db8::20]:8443"`) != 2 ||
		strings.Contains(text, "PRIVATE") || strings.Contains(text, "ProxyCommand") || strings.Contains(text, "ssh-rsa") {
		t.Fatalf("authorized_keys = %q", text)
	}
	for _, key := range policy.ManagementKeys {
		if !strings.Contains(text, key.PublicKey) {
			t.Fatalf("authorized set omitted key: %s", key.Name)
		}
	}
	if strings.Contains(string(encoded), ForcedSession) {
		t.Fatal("signed policy unexpectedly carries a command string")
	}
}

func TestPolicyWithNoRoutesCannotForward(t *testing.T) {
	policy := validPolicy()
	policy.Routes = []Route{}
	policy.ManagementKeys = policy.ManagementKeys[:1]
	authorized, err := RenderAuthorizedKeys(policy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(authorized)
	if strings.Contains(text, "port-forwarding") || strings.Contains(text, "permitopen") ||
		!strings.HasPrefix(text, `restrict,command="`+ForcedSession+`"`) {
		t.Fatalf("route-free authorized_keys is not fail-closed: %q", text)
	}
}

func TestPolicySignatureBindingTimeAndGenerationFailClosed(t *testing.T) {
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy()
	signed, err := Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		now        time.Time
		systemID   string
		control    string
		generation uint64
		want       error
	}{
		{name: "before issue", now: policy.IssuedAt.Add(-time.Second), systemID: policy.SystemID, control: policy.ControlName, generation: 7, want: ErrPolicyExpired},
		{name: "at expiry", now: policy.ExpiresAt, systemID: policy.SystemID, control: policy.ControlName, generation: 7, want: ErrPolicyExpired},
		{name: "wrong system", now: policyTime, systemID: "sys-ffffffffffffffffffffffffffffffff", control: policy.ControlName, generation: 7, want: ErrPolicyBinding},
		{name: "wrong control", now: policyTime, systemID: policy.SystemID, control: "control-2", generation: 7, want: ErrPolicyBinding},
		{name: "rollback", now: policyTime, systemID: policy.SystemID, control: policy.ControlName, generation: 8, want: ErrGeneration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Verify(signed, public, test.now, test.systemID, test.control, test.generation); !errors.Is(err, test.want) {
				t.Fatalf("Verify error = %v, want %v", err, test.want)
			}
		})
	}

	tampered := signed
	tampered.Policy.Routes[0].Host = "10.20.0.9"
	if err := Verify(tampered, public, policyTime, policy.SystemID, policy.ControlName, 7); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("tampered policy error = %v", err)
	}
	otherPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, otherPublic, policyTime, policy.SystemID, policy.ControlName, 7); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("wrong signer error = %v", err)
	}
}

func TestValidateRejectsUnsafeOrNonCanonicalPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "schema", mutate: func(policy *Policy) { policy.SchemaVersion++ }},
		{name: "system", mutate: func(policy *Policy) { policy.SystemID = "../system" }},
		{name: "control", mutate: func(policy *Policy) { policy.ControlName = "Control One" }},
		{name: "generation", mutate: func(policy *Policy) { policy.Generation = 0 }},
		{name: "fractional time", mutate: func(policy *Policy) { policy.IssuedAt = policy.IssuedAt.Add(time.Nanosecond) }},
		{name: "long lifetime", mutate: func(policy *Policy) { policy.ExpiresAt = policy.IssuedAt.Add(MaxPolicyLifetime + time.Second) }},
		{name: "no key", mutate: func(policy *Policy) { policy.ManagementKeys = nil }},
		{name: "two active", mutate: func(policy *Policy) { policy.ManagementKeys[1].State = KeyActive }},
		{name: "two pending", mutate: func(policy *Policy) { policy.ManagementKeys[0].State = KeyPending }},
		{name: "shared key", mutate: func(policy *Policy) {
			policy.ManagementKeys[1].PublicKey = policy.ManagementKeys[0].PublicKey
			policy.ManagementKeys[1].Fingerprint = policy.ManagementKeys[0].Fingerprint
		}},
		{name: "key comment", mutate: func(policy *Policy) { policy.ManagementKeys[0].PublicKey += " attacker-comment" }},
		{name: "unsorted keys", mutate: func(policy *Policy) {
			policy.ManagementKeys[0], policy.ManagementKeys[1] = policy.ManagementKeys[1], policy.ManagementKeys[0]
		}},
		{name: "route target injection", mutate: func(policy *Policy) { policy.Routes[0].Target = "../../root" }},
		{name: "host injection", mutate: func(policy *Policy) { policy.Routes[0].Host = "host\nProxyCommand=x" }},
		{name: "noncanonical IP", mutate: func(policy *Policy) { policy.Routes[0].Host = "010.020.000.008" }},
		{name: "duplicate address", mutate: func(policy *Policy) {
			policy.Routes[1].Host = policy.Routes[0].Host
			policy.Routes[1].Port = policy.Routes[0].Port
		}},
		{name: "unsorted routes", mutate: func(policy *Policy) { policy.Routes[0], policy.Routes[1] = policy.Routes[1], policy.Routes[0] }},
		{name: "ssh without host pin", mutate: func(policy *Policy) { policy.Routes[0].HostKeyFingerprint = "" }},
		{name: "ssh with TLS pin", mutate: func(policy *Policy) { policy.Routes[0].TLSPin = testFingerprint(90) }},
		{name: "https without TLS pin", mutate: func(policy *Policy) { policy.Routes[1].TLSPin = "" }},
		{name: "https with host pin", mutate: func(policy *Policy) { policy.Routes[1].HostKeyFingerprint = testFingerprint(91) }},
		{name: "wrong action kind", mutate: func(policy *Policy) { policy.Routes[1].Actions = []Action{ActionSSH} }},
		{name: "duplicate action", mutate: func(policy *Policy) { policy.Routes[0].Actions = []Action{ActionSSH, ActionSSH} }},
		{name: "unsorted actions", mutate: func(policy *Policy) { policy.Routes[0].Actions = []Action{ActionVNC, ActionExec} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			if err := Validate(policy); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Validate error = %v", err)
			}
			if rendered, err := RenderAuthorizedKeys(policy); err == nil || len(rendered) != 0 {
				t.Fatalf("invalid policy rendered: %q, %v", rendered, err)
			}
		})
	}
}

func TestCanonicalParserRejectsUnknownWhitespaceAndTrailingData(t *testing.T) {
	_, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(validPolicy(), private)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := MarshalCanonical(signed)
	if err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCanonical(pretty); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("pretty JSON error = %v", err)
	}
	unknown := bytes.Replace(canonical, []byte(`"policy":{`), []byte(`"unknown":1,"policy":{`), 1)
	if _, err := ParseCanonical(unknown); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown field error = %v", err)
	}
	if _, err := ParseCanonical(append(canonical, []byte("{}")...)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("trailing JSON error = %v", err)
	}
	if _, err := ParseCanonical(bytes.Repeat([]byte{'x'}, MaxCanonicalBytes+1)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized JSON error = %v", err)
	}
}

func TestSortCanonicalDoesNotMutateCaller(t *testing.T) {
	policy := validPolicy()
	policy.ManagementKeys[0], policy.ManagementKeys[1] = policy.ManagementKeys[1], policy.ManagementKeys[0]
	policy.Routes[0], policy.Routes[1] = policy.Routes[1], policy.Routes[0]
	policy.Routes[1].Actions = []Action{ActionVNC, ActionExec, ActionSSH}
	originalFirstKey := policy.ManagementKeys[0].Name
	originalFirstRoute := policy.Routes[0].Target
	sorted := SortCanonical(policy)
	if err := Validate(sorted); err != nil {
		t.Fatal(err)
	}
	if policy.ManagementKeys[0].Name != originalFirstKey || policy.Routes[0].Target != originalFirstRoute {
		t.Fatal("SortCanonical mutated caller slices")
	}
}

func FuzzParseCanonicalNeverPanics(fuzz *testing.F) {
	fuzz.Add([]byte(`{}`))
	fuzz.Add([]byte(`{"policy":null,"signature":null}`))
	fuzz.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCanonical(data)
	})
}

func validPolicy() Policy {
	activeKey, activeFingerprint := testPublicKey(11)
	pendingKey, pendingFingerprint := testPublicKey(12)
	return Policy{
		SchemaVersion: SchemaVersion,
		SystemID:      "sys-0123456789abcdef0123456789abcdef",
		ControlName:   "control-1",
		Generation:    7,
		IssuedAt:      policyTime.Add(-time.Minute),
		ExpiresAt:     policyTime.Add(24 * time.Hour),
		ManagementKeys: []ManagementKey{
			{Name: "control-1", Generation: 1, State: KeyActive, PublicKey: activeKey, Fingerprint: activeFingerprint},
			{Name: "control-2", Generation: 2, State: KeyPending, PublicKey: pendingKey, Fingerprint: pendingFingerprint},
		},
		Routes: []Route{
			{
				Target: "pbp-1", Kind: RouteSSH, Host: "10.20.0.8", Port: 22,
				HostKeyFingerprint: testFingerprint(31), Actions: []Action{ActionExec, ActionSSH, ActionVNC},
			},
			{
				Target: "serving-1", Kind: RouteHTTPS, Host: "2001:db8::20", Port: 8443,
				TLSPin: testFingerprint(32), Actions: []Action{ActionServingAdmin},
			},
		},
	}
}

func testPublicKey(seed byte) (string, string) {
	algorithm := []byte("ssh-ed25519")
	blob := appendSSHField(nil, algorithm)
	blob = appendSSHField(blob, bytes.Repeat([]byte{seed}, 32))
	digest := sha256.Sum256(blob)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
		"SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func appendSSHField(destination, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination = append(destination, size[:]...)
	return append(destination, value...)
}

func testFingerprint(seed byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}
