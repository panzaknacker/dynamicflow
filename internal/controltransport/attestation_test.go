package controltransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshtransport"
)

var attestTime = time.Date(2026, 9, 24, 15, 0, 0, 0, time.UTC)

func attestationRequest(fixture fixture) AttestationRequest {
	endpoint := fixture.endpoint
	endpoint.User = sshtransport.ReadyControlUser
	return AttestationRequest{
		Pending: sshtransport.PendingControlProof{Control: endpoint, ControlHostKeyFingerprint: endpoint.HostKeyFingerprint,
			BootstrapIdentityFingerprint: fingerprint(1), Phase: sshtransport.PhasePendingManagementProof},
		SystemID: "sys-" + strings.Repeat("a", 32), ControlName: endpoint.Alias, Generation: 3,
		EnvelopeDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func responseForAttestation(request AttestationRequest, nonce string) controlruntime.SessionResponse {
	return controlruntime.SessionResponse{Schema: controlruntime.SessionResponseSchema, System: request.SystemID,
		Control: request.ControlName, Generation: request.Generation, EnvelopeSHA256: request.EnvelopeDigest,
		Nonce: nonce, ObservedAt: attestTime}
}

func TestPendingAttestationUsesManagementKeyAndFreshBoundedProtocol(t *testing.T) {
	fixture := newFixture(t)
	request := attestationRequest(fixture)
	runner := &recordingRunner{}
	var nonces []string
	runner.run = func(_ context.Context, stdout, stderr io.Writer) error {
		_, argv, stdin, deadline := runner.snapshot()
		if stdin != nil || deadline.IsZero() || argv[4] != "flow-control-control-a" {
			t.Fatalf("unexpected SSH session: argv=%v stdin=%v deadline=%v", argv, stdin, deadline)
		}
		config, err := os.ReadFile(argv[1])
		if err != nil {
			return err
		}
		for _, required := range []string{"User dynamicflow-control", "ClearAllForwardings yes", "ForwardAgent no", "StrictHostKeyChecking yes"} {
			if !strings.Contains(string(config), required) {
				t.Fatalf("missing %q in managed SSH config", required)
			}
		}
		fields := strings.Split(argv[len(argv)-1], " ")
		if len(fields) != 5 || fields[0] != controlruntime.AttestationCommandV1 || fields[1] != request.SystemID || fields[2] != request.ControlName || fields[3] != "3" || len(fields[4]) != 64 {
			t.Fatalf("unexpected command: %v", fields)
		}
		nonces = append(nonces, fields[4])
		data, err := signing.CanonicalJSON(responseForAttestation(request, fields[4]))
		if err != nil {
			return err
		}
		_, _ = stderr.Write([]byte("untrusted remote diagnostic"))
		_, err = stdout.Write(data)
		return err
	}
	transport := New(fixture.builder, runner, WithClock(func() time.Time { return attestTime }))
	for range 2 {
		result, err := transport.AttestPendingControl(context.Background(), request)
		if err != nil || !result.Verified || result.Attempts != 1 || result.Route != "direct_pending_control" || result.Response == nil {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		encoded, _ := json.Marshal(result)
		if bytes.Contains(encoded, []byte(fixture.privatePath)) || bytes.Contains(encoded, []byte("untrusted remote diagnostic")) {
			t.Fatalf("proof leaked private path or stderr: %s", encoded)
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("challenge was reused: %v", nonces)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 2 {
		t.Fatalf("unexpected automatic retry: %d calls", calls)
	}
}

func TestPendingAttestationRejectsExitZeroWithoutExactFreshResponse(t *testing.T) {
	for _, failure := range []string{"empty", "wrong-nonce", "wrong-system", "wrong-control", "wrong-generation", "wrong-envelope", "expired", "future", "subsecond", "unknown-field", "duplicate-field", "pretty-json", "trailing", "oversize", "runner-error"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newFixture(t)
			request := attestationRequest(fixture)
			nonce := strings.Repeat("00", 32)
			runner := &recordingRunner{run: func(_ context.Context, stdout, stderr io.Writer) error {
				response := responseForAttestation(request, nonce)
				switch failure {
				case "wrong-nonce":
					response.Nonce = strings.Repeat("a", 64)
				case "wrong-system":
					response.System = "sys-" + strings.Repeat("f", 32)
				case "wrong-control":
					response.Control = "other-control"
				case "wrong-generation":
					response.Generation++
				case "wrong-envelope":
					response.EnvelopeSHA256 = "sha256:" + strings.Repeat("c", 64)
				case "expired":
					response.ObservedAt = attestTime.Add(-AttestationClockSkew - time.Second)
				case "future":
					response.ObservedAt = attestTime.Add(AttestationClockSkew + time.Second)
				case "subsecond":
					response.ObservedAt = attestTime.Add(time.Nanosecond)
				}
				data, _ := signing.CanonicalJSON(response)
				switch failure {
				case "empty":
					data = nil
				case "unknown-field":
					data = append([]byte(`{"private":"remote-secret",`), data[1:]...)
				case "duplicate-field":
					data = append([]byte(`{"schema":1,`), data[1:]...)
				case "pretty-json":
					data, _ = json.MarshalIndent(response, "", "  ")
				case "trailing":
					data = append(data, '\n')
				case "oversize":
					data = append(data, bytes.Repeat([]byte("x"), controlruntime.MaxSessionResponseBytes)...)
				}
				_, _ = stdout.Write(data)
				_, _ = stderr.Write(bytes.Repeat([]byte("remote-secret"), int(MaxOutputBytes)))
				if failure == "runner-error" {
					return errors.New("remote-secret")
				}
				return nil
			}}
			result, err := New(fixture.builder, runner, WithClock(func() time.Time { return attestTime }), WithRandomReader(bytes.NewReader(make([]byte, 32)))).AttestPendingControl(context.Background(), request)
			if !errors.Is(err, ErrControlAttestation) || err.Error() != ErrControlAttestation.Error() || result.Verified || result.Response != nil || result.Attempts != 1 || !result.StderrTruncated {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if calls, _, _, _ := runner.snapshot(); calls != 1 {
				t.Fatalf("failure retried: %d", calls)
			}
		})
	}
}

func TestPendingAttestationRejectsUnsafeRequestBeforeProcess(t *testing.T) {
	fixture := newFixture(t)
	for name, change := range map[string]func(*AttestationRequest){
		"wrong name":      func(r *AttestationRequest) { r.ControlName = "other-control" },
		"bad system":      func(r *AttestationRequest) { r.SystemID = "sys-bad;id" },
		"bad digest":      func(r *AttestationRequest) { r.EnvelopeDigest = "sha256:bad" },
		"zero generation": func(r *AttestationRequest) { r.Generation = 0 },
		"bootstrap reused": func(r *AttestationRequest) {
			r.Pending.BootstrapIdentityFingerprint = r.Pending.Control.IdentityFingerprint
		},
		"bootstrap user":      func(r *AttestationRequest) { r.Pending.Control.User = "bootstrap" },
		"no staged assertion": func(r *AttestationRequest) { r.Pending.Phase = "" },
		"wrong host pin":      func(r *AttestationRequest) { r.Pending.ControlHostKeyFingerprint = fingerprint(9) },
	} {
		t.Run(name, func(t *testing.T) {
			request := attestationRequest(fixture)
			change(&request)
			runner := &recordingRunner{}
			result, err := New(fixture.builder, runner).AttestPendingControl(context.Background(), request)
			if !errors.Is(err, ErrControlAttestation) || result.Attempts != 0 || result.Verified {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if calls, _, _, _ := runner.snapshot(); calls != 0 {
				t.Fatalf("unsafe request started %d processes", calls)
			}
		})
	}
}

func TestPendingAttestationCancellationAndEntropyFailureAreNetworkFree(t *testing.T) {
	fixture := newFixture(t)
	runner := &recordingRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := New(fixture.builder, runner).AttestPendingControl(ctx, attestationRequest(fixture))
	if !errors.Is(err, context.Canceled) || result.Attempts != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	result, err = New(fixture.builder, runner, WithRandomReader(strings.NewReader("short"))).AttestPendingControl(context.Background(), attestationRequest(fixture))
	if !errors.Is(err, ErrControlAttestation) || result.Attempts != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if calls, _, _, _ := runner.snapshot(); calls != 0 {
		t.Fatalf("invalid preflight started %d processes", calls)
	}
}
