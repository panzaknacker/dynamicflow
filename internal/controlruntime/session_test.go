package controlruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

type sessionFixture struct {
	session  *Session
	env      map[string]string
	identity SessionIdentity
	envelope []byte
	readErr  error
	reads    int
	now      time.Time
	command  string
	root     string
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	data := installerEnvelope(t, 3)
	envelope, err := ParseCanonical(data)
	if err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf("%s %s %s 3 %s", AttestationCommandV1, envelope.SystemID, envelope.ControlName, strings.Repeat("a", 64))
	fixture := &sessionFixture{
		env:      map[string]string{"SSH_ORIGINAL_COMMAND": command, "SSH_CONNECTION": "192.0.2.10 45678 192.0.2.20 22"},
		identity: SessionIdentity{Username: ManagementUser, UID: 1001, EffectiveUID: 1001},
		envelope: data, now: runtimeTime, command: command, root: DefaultStateRoot,
	}
	fixture.session, err = NewSessionWithDependencies(SessionConfig{StateRoot: fixture.root}, SessionDependencies{
		LookupEnvironment: func(name string) (string, bool) { value, ok := fixture.env[name]; return value, ok },
		CurrentIdentity:   func() (SessionIdentity, error) { return fixture.identity, nil },
		ReadActiveEnvelope: func(root string) ([]byte, error) {
			fixture.reads++
			if root != fixture.root {
				t.Fatalf("unbound state root %q", root)
			}
			return fixture.envelope, fixture.readErr
		},
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *sessionFixture) execute() ([]byte, error) {
	return fixture.session.Execute(context.Background(), SessionRequest{StateRoot: fixture.root})
}

func TestSessionAttestsExactSignedPolicyWithChallengeAndCanonicalPublicResponse(t *testing.T) {
	fixture := newSessionFixture(t)
	fixture.now = fixture.now.Add(123 * time.Millisecond)
	data, err := fixture.execute()
	if err != nil || fixture.reads != 1 {
		t.Fatalf("reads=%d err=%v", fixture.reads, err)
	}
	var response SessionResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	canonical, err := signing.CanonicalJSON(response)
	digest := sha256.Sum256(fixture.envelope)
	policy, _ := ParseCanonical(fixture.envelope)
	if err != nil || !bytes.Equal(data, canonical) || response.Schema != SessionResponseSchema ||
		response.System != policy.SystemID || response.Control != policy.ControlName || response.Generation != 3 ||
		response.EnvelopeSHA256 != "sha256:"+hex.EncodeToString(digest[:]) || response.Nonce != strings.Repeat("a", 64) ||
		!response.ObservedAt.Equal(runtimeTime) || len(data) > MaxSessionResponseBytes {
		t.Fatalf("response=%s err=%v", data, err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 7 {
		t.Fatalf("unexpected public schema: %s", data)
	}
	for _, forbidden := range []string{"ssh-ed25519", "PUBLIC KEY", "192.0.2.", fixture.root, "SSH_CONNECTION"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("response contains %q: %s", forbidden, data)
		}
	}
}

func TestSessionRejectsUntrustedSSHContextBeforeReadingState(t *testing.T) {
	fixture := newSessionFixture(t)
	for name, change := range map[string]func(*sessionFixture){
		"missing command":         func(f *sessionFixture) { delete(f.env, "SSH_ORIGINAL_COMMAND") },
		"shell":                   func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = "sh -c id" },
		"command newline":         func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] += "\n" },
		"command whitespace":      func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = " " + f.command },
		"injection":               func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] += ";id" },
		"extra argument":          func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] += " extra" },
		"leading zero generation": func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = strings.Replace(f.command, " 3 ", " 03 ", 1) },
		"short nonce":             func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = f.command[:len(f.command)-1] },
		"long command":            func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = strings.Repeat("a", MaxSessionCommandBytes+1) },
		"missing connection":      func(f *sessionFixture) { delete(f.env, "SSH_CONNECTION") },
		"hostname peer":           func(f *sessionFixture) { f.env["SSH_CONNECTION"] = "client.example 45678 192.0.2.20 22" },
		"unspecified peer":        func(f *sessionFixture) { f.env["SSH_CONNECTION"] = "0.0.0.0 45678 192.0.2.20 22" },
		"zero port":               func(f *sessionFixture) { f.env["SSH_CONNECTION"] = "192.0.2.10 0 192.0.2.20 22" },
		"overflow port":           func(f *sessionFixture) { f.env["SSH_CONNECTION"] = "192.0.2.10 65536 192.0.2.20 22" },
		"noncanonical port":       func(f *sessionFixture) { f.env["SSH_CONNECTION"] = "192.0.2.10 45678 192.0.2.20 022" },
		"root identity":           func(f *sessionFixture) { f.identity.UID = 0; f.identity.EffectiveUID = 0 },
		"setuid identity":         func(f *sessionFixture) { f.identity.EffectiveUID++ },
		"other user":              func(f *sessionFixture) { f.identity.Username = "bootstrap" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSessionFixture(t)
			change(f)
			data, err := f.execute()
			if !errors.Is(err, ErrSessionDenied) || len(data) != 0 || f.reads != 0 {
				t.Fatalf("data=%q err=%v reads=%d", data, err, f.reads)
			}
		})
	}
	if data, err := fixture.session.Execute(context.Background(), SessionRequest{StateRoot: "/tmp/untrusted"}); !errors.Is(err, ErrSessionDenied) || len(data) != 0 || fixture.reads != 0 {
		t.Fatalf("unbound root response=%q err=%v reads=%d", data, err, fixture.reads)
	}
}

func TestSessionRejectsUnauthenticAndMismatchedPolicyWithoutDisclosingCause(t *testing.T) {
	for name, change := range map[string]func(*sessionFixture){
		"read failure": func(f *sessionFixture) { f.readErr = errors.New("sensitive underlying path") },
		"empty":        func(f *sessionFixture) { f.envelope = nil },
		"oversized":    func(f *sessionFixture) { f.envelope = bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1) },
		"noncanonical": func(f *sessionFixture) { f.envelope = append(f.envelope, '\n') },
		"tampered signature": func(f *sessionFixture) {
			f.envelope = bytes.ReplaceAll(f.envelope, []byte(`"generation":3`), []byte(`"generation":4`))
		},
		"wrong generation": func(f *sessionFixture) { f.env["SSH_ORIGINAL_COMMAND"] = strings.Replace(f.command, " 3 ", " 2 ", 1) },
		"wrong system": func(f *sessionFixture) {
			fields := strings.Split(f.command, " ")
			fields[1] = "sys-" + strings.Repeat("f", 32)
			f.env["SSH_ORIGINAL_COMMAND"] = strings.Join(fields, " ")
		},
		"wrong control": func(f *sessionFixture) {
			fields := strings.Split(f.command, " ")
			fields[2] = "other-control"
			f.env["SSH_ORIGINAL_COMMAND"] = strings.Join(fields, " ")
		},
		"expired": func(f *sessionFixture) {
			envelope, _ := ParseCanonical(f.envelope)
			f.now = envelope.Policy.Policy.ExpiresAt
		},
		"future": func(f *sessionFixture) {
			envelope, _ := ParseCanonical(f.envelope)
			f.now = envelope.Policy.Policy.IssuedAt.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSessionFixture(t)
			change(fixture)
			data, err := fixture.execute()
			if err != ErrSessionUnavailable || len(data) != 0 || fixture.reads != 1 {
				t.Fatalf("data=%q err=%v reads=%d", data, err, fixture.reads)
			}
		})
	}
}

func TestSessionCancellationNeverReturnsPartialAttestation(t *testing.T) {
	for _, cancelDuringRead := range []bool{false, true} {
		fixture := newSessionFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cancelDuringRead {
			fixture.session.dependencies.ReadActiveEnvelope = func(string) ([]byte, error) { cancel(); return fixture.envelope, nil }
		} else {
			cancel()
		}
		data, err := fixture.session.Execute(ctx, SessionRequest{StateRoot: fixture.root})
		if err != ErrSessionUnavailable || len(data) != 0 {
			t.Fatalf("cancelDuringRead=%t data=%q err=%v", cancelDuringRead, data, err)
		}
	}
}
