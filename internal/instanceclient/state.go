package instanceclient

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

const (
	stateSchema = 1
	statePath   = "client-state.json"
)

var ErrInvalidState = errors.New("invalid instance client state")

// State contains only public binding and signed desired-state data. enrollment
// credentials and private identity material can never be serialized into it.
type State struct {
	Schema            int                            `json:"schema"`
	Instance          string                         `json:"instance"`
	Profile           string                         `json:"profile"`
	IdentityKeyID     string                         `json:"identity_key_id"`
	Enrolled          bool                           `json:"enrolled"`
	ReleaseGeneration uint64                         `json:"release_generation,omitempty"`
	ReleaseSet        string                         `json:"release_set,omitempty"`
	Desired           *enrollment.SignedDesiredState `json:"desired,omitempty"`
	UpdatedAt         int64                          `json:"updated_at"`
}

func loadOrCreateState(store *localstate.Store, instance, profile, keyID string, now time.Time, desiredKey ed25519.PublicKey) (State, error) {
	var state State
	if err := store.ReadJSON(statePath, &state); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return State{}, err
		}
		state = State{
			Schema: stateSchema, Instance: instance, Profile: profile,
			IdentityKeyID: keyID, UpdatedAt: now.UTC().Unix(),
		}
		if err := store.WriteJSON(statePath, state); err != nil {
			return State{}, err
		}
		return state, nil
	}
	if state.Schema != stateSchema || state.Instance != instance || state.Profile != profile || state.IdentityKeyID != keyID || state.UpdatedAt <= 0 {
		return State{}, ErrInvalidState
	}
	if state.Enrolled != (state.Desired != nil) ||
		state.Enrolled != (state.ReleaseGeneration != 0) || state.Enrolled != (state.ReleaseSet != "") {
		return State{}, ErrInvalidState
	}
	if state.Desired != nil {
		if len(desiredKey) != ed25519.PublicKeySize || state.ReleaseSet != state.Desired.State.ReleaseSet {
			return State{}, ErrInvalidState
		}
		issuedAt := time.Unix(state.Desired.State.IssuedAt, 0).UTC()
		if err := enrollment.VerifyDesiredState(*state.Desired, desiredKey, enrollment.DesiredExpectation{
			Instance: instance, Profile: profile, ReleaseSet: state.Desired.State.ReleaseSet,
			MinGeneration: state.Desired.State.Generation, Now: issuedAt,
		}); err != nil {
			return State{}, fmt.Errorf("%w: persisted desired state: %v", ErrInvalidState, err)
		}
	}
	return cloneState(state), nil
}

func (client *Client) acceptDesiredLocked(signed enrollment.SignedDesiredState, manifest release.SignedManifest) error {
	if client.state.ReleaseGeneration > manifest.Manifest.Generation ||
		(client.state.ReleaseGeneration == manifest.Manifest.Generation && client.state.ReleaseGeneration != 0 && client.state.ReleaseSet != manifest.Manifest.SetID) {
		return fmt.Errorf("%w: release-manifest rollback or generation conflict", ErrInvalidState)
	}
	minimum := uint64(1)
	if client.state.Desired != nil {
		minimum = client.state.Desired.State.Generation
	}
	if err := enrollment.VerifyDesiredState(signed, client.desiredPublicKey, enrollment.DesiredExpectation{
		Instance: client.instance, Profile: client.profile, ReleaseSet: manifest.Manifest.SetID,
		MinGeneration: minimum, Now: client.now().UTC(), MaxClockSkew: client.maxClockSkew,
	}); err != nil {
		return err
	}
	profileFound := false
	for _, profile := range manifest.Manifest.Profiles {
		if profile.Name == client.profile {
			profileFound = true
			break
		}
	}
	if !profileFound {
		return enrollment.ErrBinding
	}
	if client.state.Desired != nil && client.state.Desired.State.Generation == signed.State.Generation {
		existing, err := signing.CanonicalJSON(*client.state.Desired)
		if err != nil {
			return err
		}
		incoming, err := signing.CanonicalJSON(signed)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, incoming) {
			return fmt.Errorf("%w: desired-state generation has different content", ErrInvalidState)
		}
	}
	accepted := cloneSignedDesired(signed)
	next := State{
		Schema: stateSchema, Instance: client.instance, Profile: client.profile,
		IdentityKeyID: client.identity.keyID, Enrolled: true,
		ReleaseGeneration: manifest.Manifest.Generation, ReleaseSet: manifest.Manifest.SetID,
		Desired: &accepted, UpdatedAt: client.now().UTC().Unix(),
	}
	if err := client.store.WriteJSON(statePath, next); err != nil {
		return err
	}
	client.state = cloneState(next)
	return nil
}

func cloneState(state State) State {
	result := state
	if state.Desired != nil {
		desired := cloneSignedDesired(*state.Desired)
		result.Desired = &desired
	}
	return result
}

func cloneSignedDesired(input enrollment.SignedDesiredState) enrollment.SignedDesiredState {
	result := input
	result.State.AuthorizedSSHKeys = append([]string(nil), input.State.AuthorizedSSHKeys...)
	result.Signature.Value = append([]byte(nil), input.Signature.Value...)
	return result
}
