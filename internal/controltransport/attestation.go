package controltransport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dynamicflow/internal/controlruntime"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshtransport"
)

const AttestationClockSkew = time.Minute

var (
	ErrControlAttestation = errors.New("Control management attestation failed")
	attestationSystemRE   = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)
	attestationControlRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	attestationDigestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// AttestationRequest binds a proof to the exact staged management identity,
// independently pinned host, signed policy generation and installed envelope.
// A successful SSH exit alone never constitutes a successful attestation.
type AttestationRequest struct {
	Pending        sshtransport.PendingControlProof
	SystemID       string
	ControlName    string
	Generation     uint64
	EnvelopeDigest string
}

type AttestationResult struct {
	Verified        bool                            `json:"verified"`
	Route           string                          `json:"route"`
	FirstHopAlias   string                          `json:"first_hop_alias,omitempty"`
	Attempts        int                             `json:"attempts"`
	Response        *controlruntime.SessionResponse `json:"response,omitempty"`
	StdoutBytes     int64                           `json:"stdout_bytes"`
	StderrBytes     int64                           `json:"stderr_bytes"`
	StdoutTruncated bool                            `json:"stdout_truncated"`
	StderrTruncated bool                            `json:"stderr_truncated"`
}

// AttestPendingControl authenticates exactly once with the staged management
// key. The fixed remote ForceCommand must answer a fresh 256-bit challenge
// using the exact installed signed envelope. There is no bootstrap fallback,
// forwarding, stdin payload, arbitrary command or implicit retry.
func (transport *Transport) AttestPendingControl(ctx context.Context, request AttestationRequest) (AttestationResult, error) {
	result := AttestationResult{Route: "direct_pending_control"}
	if transport == nil || transport.builder == nil || transport.runner == nil || transport.now == nil || transport.random == nil || ctx == nil ||
		!attestationSystemRE.MatchString(request.SystemID) || !attestationControlRE.MatchString(request.ControlName) ||
		request.ControlName != request.Pending.Control.Alias || request.Generation == 0 || !attestationDigestRE.MatchString(request.EnvelopeDigest) {
		return result, ErrControlAttestation
	}
	if err := ctx.Err(); err != nil {
		return result, attestationError{cause: err}
	}
	var entropy [32]byte
	if _, err := io.ReadFull(transport.random, entropy[:]); err != nil {
		return result, ErrControlAttestation
	}
	nonce := hex.EncodeToString(entropy[:])
	invocation, err := transport.builder.BuildDirectPendingControlProof(sshtransport.CapabilityPendingControlProof, request.Pending)
	if err != nil {
		return result, ErrControlAttestation
	}
	result.FirstHopAlias = request.Pending.Control.Alias
	command := strings.Join([]string{controlruntime.AttestationCommandV1, request.SystemID, request.ControlName, strconv.FormatUint(request.Generation, 10), nonce}, " ")
	stdout := attestationOutput{}
	stderr := boundedOutput{limit: MaxOutputBytes}
	operation, cancel := context.WithTimeout(ctx, FirstControlCheckTimeout)
	defer cancel()
	started := transport.now().UTC()
	if err := operation.Err(); err != nil {
		return result, attestationError{cause: err}
	}
	result.Attempts = 1
	err = transport.runner.Run(operation, append(invocation.Arguments(), command), nil, &stdout, &stderr)
	finished := transport.now().UTC()
	result.StdoutBytes, result.StdoutTruncated = int64(len(stdout.data)), stdout.truncated
	result.StderrBytes, result.StderrTruncated = stderr.kept, stderr.truncated
	if operation.Err() != nil {
		return result, attestationError{cause: operation.Err()}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result, attestationError{cause: err}
		}
		return result, ErrControlAttestation
	}
	if stdout.truncated || finished.Before(started) {
		return result, ErrControlAttestation
	}
	response, err := verifyAttestationResponse(stdout.data, request, nonce, started, finished)
	if err != nil {
		return result, ErrControlAttestation
	}
	result.Verified = true
	result.Response = &response
	return result, nil
}

func verifyAttestationResponse(data []byte, request AttestationRequest, nonce string, started, finished time.Time) (controlruntime.SessionResponse, error) {
	var response controlruntime.SessionResponse
	if len(data) == 0 || len(data) > controlruntime.MaxSessionResponseBytes {
		return response, ErrControlAttestation
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return controlruntime.SessionResponse{}, ErrControlAttestation
	}
	canonical, err := signing.CanonicalJSON(response)
	_, offset := response.ObservedAt.Zone()
	if err != nil || !bytes.Equal(canonical, data) || response.Schema != controlruntime.SessionResponseSchema ||
		response.System != request.SystemID || response.Control != request.ControlName || response.Generation != request.Generation ||
		response.EnvelopeSHA256 != request.EnvelopeDigest || response.Nonce != nonce ||
		response.ObservedAt.IsZero() || response.ObservedAt.Unix() <= 0 || response.ObservedAt.Nanosecond() != 0 || offset != 0 ||
		response.ObservedAt.Before(started.Add(-AttestationClockSkew)) || response.ObservedAt.After(finished.Add(AttestationClockSkew)) {
		return controlruntime.SessionResponse{}, ErrControlAttestation
	}
	return response, nil
}

type attestationOutput struct {
	data      []byte
	truncated bool
}

func (output *attestationOutput) Write(data []byte) (int, error) {
	remaining := controlruntime.MaxSessionResponseBytes - len(output.data)
	keep := len(data)
	if keep > remaining {
		keep = remaining
		output.truncated = true
	}
	output.data = append(output.data, data[:keep]...)
	return len(data), nil
}

type attestationError struct{ cause error }

func (attestationError) Error() string { return ErrControlAttestation.Error() }

func (failure attestationError) Is(target error) bool {
	return target == ErrControlAttestation || errors.Is(failure.cause, target)
}
