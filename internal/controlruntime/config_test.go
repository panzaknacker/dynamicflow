package controlruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/signing"
)

var runtimeTime = time.Date(2026, 7, 23, 18, 0, 0, 0, time.UTC)

func TestEnvelopeRoundTripVerifyAndRenderHardenedFiles(t *testing.T) {
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := runtimePolicy(true)
	signed, err := controlpolicy.Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := signing.MarshalPublicPEM(public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(policy.SystemID, policy.ControlName, publicPEM, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(envelope, runtimeTime, policy.SystemID, policy.ControlName, 3); err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCanonical(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalCanonical(parsed)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatalf("canonical envelope changed: %v", err)
	}
	files, err := Render(parsed, runtimeTime, policy.SystemID, policy.ControlName, 3, DefaultStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.ValidateNoPrivateMaterial(); err != nil {
		t.Fatal(err)
	}
	sshd := string(files.SSHDPolicy)
	for _, required := range []string{
		"Match User " + ManagementUser,
		"AuthenticationMethods publickey",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"AuthorizedKeysFile " + DefaultStateRoot + "/" + ActiveBundleName + "/authorized_keys",
		"ForceCommand " + controlpolicy.ForcedSession,
		"PermitTTY no", "X11Forwarding no", "AllowAgentForwarding no",
		"AllowTcpForwarding local", "GatewayPorts no", "PermitTunnel no",
		"PermitUserEnvironment no", "PermitUserRC no",
	} {
		if strings.Count(sshd, required) != 1 {
			t.Fatalf("sshd policy missing/duplicates %q:\n%s", required, sshd)
		}
	}
	for _, forbidden := range []string{"PermitRootLogin yes", "PasswordAuthentication yes", "AllowAgentForwarding yes", "AllowTcpForwarding yes", "PermitOpen any", "ProxyCommand"} {
		if strings.Contains(sshd, forbidden) {
			t.Fatalf("sshd policy contains %q:\n%s", forbidden, sshd)
		}
	}
	authorized := string(files.AuthorizedKeys)
	if !strings.Contains(authorized, `restrict,command="`+controlpolicy.ForcedSession+`",port-forwarding`) ||
		!strings.Contains(authorized, `permitopen="10.40.0.9:22"`) || strings.Count(authorized, "\n") != 1 {
		t.Fatalf("authorized_keys = %q", authorized)
	}
	if !bytes.Equal(files.PolicyPublicPEM, publicPEM) || !bytes.Equal(files.EnvelopeJSON, encoded) {
		t.Fatal("rendered trust/envelope bytes differ from verified input")
	}
}

func TestRouteFreeEnvelopeLeavesForwardingDisabledAtAuthorizedKey(t *testing.T) {
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := runtimePolicy(false)
	signed, err := controlpolicy.Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, _ := signing.MarshalPublicPEM(public)
	envelope, err := NewEnvelope(policy.SystemID, policy.ControlName, publicPEM, signed)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Render(envelope, runtimeTime, policy.SystemID, policy.ControlName, 1, DefaultStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files.AuthorizedKeys), "port-forwarding") || strings.Contains(string(files.AuthorizedKeys), "permitopen") {
		t.Fatalf("route-free policy allows forwarding: %q", files.AuthorizedKeys)
	}
}

func TestEnvelopeTamperBindingTimeGenerationAndPathFailClosed(t *testing.T) {
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	policy := runtimePolicy(true)
	signed, err := controlpolicy.Sign(policy, private)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, _ := signing.MarshalPublicPEM(public)
	envelope, err := NewEnvelope(policy.SystemID, policy.ControlName, publicPEM, signed)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		now     time.Time
		system  string
		control string
		minimum uint64
		want    error
	}{
		{name: "wrong system", now: runtimeTime, system: "sys-ffffffffffffffffffffffffffffffff", control: policy.ControlName, minimum: 3, want: ErrEnvelopeBinding},
		{name: "wrong control", now: runtimeTime, system: policy.SystemID, control: "control-2", minimum: 3, want: ErrEnvelopeBinding},
		{name: "expired", now: policy.ExpiresAt, system: policy.SystemID, control: policy.ControlName, minimum: 3, want: controlpolicy.ErrPolicyExpired},
		{name: "rollback", now: runtimeTime, system: policy.SystemID, control: policy.ControlName, minimum: 4, want: controlpolicy.ErrGeneration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyEnvelope(envelope, test.now, test.system, test.control, test.minimum); !errors.Is(err, test.want) {
				t.Fatalf("VerifyEnvelope error = %v, want %v", err, test.want)
			}
		})
	}
	tampered := envelope
	tampered.Policy.Policy.Routes[0].Host = "10.40.0.10"
	if err := VerifyEnvelope(tampered, runtimeTime, policy.SystemID, policy.ControlName, 3); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("tampered policy error = %v", err)
	}
	otherPublic, _, _ := signing.Generate()
	otherPEM, _ := signing.MarshalPublicPEM(otherPublic)
	tampered = envelope
	tampered.ControlPolicyPublicPEM = string(otherPEM)
	if err := VerifyEnvelope(tampered, runtimeTime, policy.SystemID, policy.ControlName, 3); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("rebound root error = %v", err)
	}
	for _, path := range []string{"relative", "/", "/var/lib/flow state", "/var/lib/flow\nMatch User root", `/var/lib/flow"bad`} {
		if files, err := Render(envelope, runtimeTime, policy.SystemID, policy.ControlName, 3, path); !errors.Is(err, ErrInvalidEnvelope) || !reflect.DeepEqual(files, RenderedFiles{}) {
			t.Fatalf("unsafe path %q rendered: %+v %v", path, files, err)
		}
	}
}

func TestEnvelopeParserRejectsUnknownNoncanonicalAndPrivateMarkers(t *testing.T) {
	public, private, _ := signing.Generate()
	policy := runtimePolicy(false)
	signed, _ := controlpolicy.Sign(policy, private)
	publicPEM, _ := signing.MarshalPublicPEM(public)
	envelope, _ := NewEnvelope(policy.SystemID, policy.ControlName, publicPEM, signed)
	canonical, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(envelope, "", "  ")
	unknown := bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"extra":1,"schema_version":1`), 1)
	for _, data := range [][]byte{pretty, unknown, append(canonical, []byte("{}")...), bytes.Repeat([]byte{'x'}, MaxEnvelopeBytes+1)} {
		if _, err := ParseCanonical(data); err == nil {
			t.Fatalf("unsafe/noncanonical envelope accepted: %.80q", data)
		}
	}
	files, err := Render(envelope, runtimeTime, policy.SystemID, policy.ControlName, 1, DefaultStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	privateMarker := "\n-----BEGIN OPENSSH " + "PRIVATE KEY-----"
	files.PolicyJSON = append(files.PolicyJSON, []byte(privateMarker)...)
	if err := files.ValidateNoPrivateMaterial(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("private marker error = %v", err)
	}
}

func runtimePolicy(withRoute bool) controlpolicy.Policy {
	publicKey, fingerprint := runtimeSSHKey(51)
	policy := controlpolicy.Policy{
		SchemaVersion: controlpolicy.SchemaVersion,
		SystemID:      "sys-0123456789abcdef0123456789abcdef",
		ControlName:   "control-1", Generation: 3,
		IssuedAt: runtimeTime.Add(-time.Minute), ExpiresAt: runtimeTime.Add(24 * time.Hour),
		ManagementKeys: []controlpolicy.ManagementKey{{
			Name: "control-1", Generation: 1, State: controlpolicy.KeyActive,
			PublicKey: publicKey, Fingerprint: fingerprint,
		}},
		Routes: []controlpolicy.Route{},
	}
	if withRoute {
		policy.Routes = []controlpolicy.Route{{
			Target: "instance-1", Kind: controlpolicy.RouteSSH, Host: "10.40.0.9", Port: 22,
			HostKeyFingerprint: runtimeFingerprint(71), Actions: []controlpolicy.Action{controlpolicy.ActionSSH},
		}}
	}
	return policy
}

func runtimeSSHKey(seed byte) (string, string) {
	algorithm := []byte("ssh-ed25519")
	blob := runtimeAppendSSHField(nil, algorithm)
	blob = runtimeAppendSSHField(blob, bytes.Repeat([]byte{seed}, 32))
	digest := sha256.Sum256(blob)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob),
		"SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func runtimeAppendSSHField(destination, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination = append(destination, size[:]...)
	return append(destination, value...)
}

func runtimeFingerprint(seed byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}
