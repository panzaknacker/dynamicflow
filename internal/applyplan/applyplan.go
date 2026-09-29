// package applyplan derives an immutable target installation plan exclusively
// from independently verified release and desired-state metadata.

// it deliberately does not download artifacts or execute installers. callers
// can therefore persist and display the plan before handing its phases to the
// fixed reconciliation engine.
package applyplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/profiles"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

const (
	SchemaVersion       = 2
	defaultMaxClockSkew = 5 * time.Minute
)

var (
	ErrInvalidInput      = errors.New("invalid apply-plan input")
	ErrRevoked           = errors.New("instance desired state is revoked")
	ErrRollback          = errors.New("apply-plan rollback refused")
	ErrProfileMismatch   = errors.New("release profile does not match the local declaration")
	ErrMissingArtifact   = errors.New("required release artifact is missing")
	ErrAmbiguousArtifact = errors.New("required release artifact is ambiguous")
	ErrRevokedArtifact   = errors.New("required release artifact is revoked")
	ErrUnsupportedTarget = errors.New("unsupported target architecture")

	instanceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	digestRE       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Checkpoint is the last successfully accepted state on this instance. it
// prevents a correctly signed older release or desired-state document from
// producing an installation plan. DesiredStateID also rejects different
// content reissued with an already accepted desired generation.
type Checkpoint struct {
	ReleaseGeneration uint64 `json:"release_generation,omitempty"`
	ReleaseSet        string `json:"release_set,omitempty"`
	DesiredGeneration uint64 `json:"desired_generation,omitempty"`
	DesiredStateID    string `json:"desired_state_id,omitempty"`
}

// Options binds a plan to the immutable local instance configuration and the
// target architecture. GOARCH accepts only architectures for which flow
// currently publishes target binaries and PBP artifacts.
type Options struct {
	Instance     string
	Profile      string
	GOARCH       string
	Now          time.Time
	MaxClockSkew time.Duration
	Checkpoint   Checkpoint
}

// Artifact is a direct copy of the security-relevant component binding from
// the verified release manifest.
type Artifact struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Target    string `json:"target"`
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Step is one fixed component action within a declarative profile phase.
// its ID is stable across repeated planning of the same profile graph.
type Step struct {
	ID       string   `json:"id"`
	Artifact Artifact `json:"artifact"`
}

// Phase retains the verified dependency edges in addition to its
// dependency-first position in Plan.Phases.
type Phase struct {
	ID        string   `json:"id"`
	Profile   string   `json:"profile"`
	DependsOn []string `json:"depends_on,omitempty"`
	Steps     []Step   `json:"steps"`
}

// Plan is deterministic for a given pair of signed documents, registry,
// checkpoint and GOARCH. ID covers every other plan field.
type Plan struct {
	Schema            int      `json:"schema"`
	ID                string   `json:"id"`
	Instance          string   `json:"instance"`
	Profile           string   `json:"profile"`
	Target            string   `json:"target"`
	ReleaseSet        string   `json:"release_set"`
	ReleaseGeneration uint64   `json:"release_generation"`
	DesiredGeneration uint64   `json:"desired_generation"`
	DesiredStateID    string   `json:"desired_state_id"`
	AuthorizedSSHKeys []string `json:"authorized_ssh_keys"`
	Phases            []Phase  `json:"phases"`
}

// Build verifies both trust domains and derives a dependency-first plan. a
// returned plan contains only metadata that was covered by the release or
// desired-state signature and checked against the local profile registry.
func Build(
	registry *profiles.Registry,
	signedRelease release.SignedManifest,
	releasePublicKey ed25519.PublicKey,
	signedDesired enrollment.SignedDesiredState,
	desiredPublicKey ed25519.PublicKey,
	options Options,
) (Plan, error) {
	if err := validateOptions(registry, releasePublicKey, desiredPublicKey, options); err != nil {
		return Plan{}, err
	}
	if err := release.VerifyManifest(signedRelease, releasePublicKey); err != nil {
		return Plan{}, fmt.Errorf("verify current release: %w", err)
	}
	if err := checkReleaseCheckpoint(signedRelease.Manifest, options.Checkpoint); err != nil {
		return Plan{}, err
	}

	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := options.MaxClockSkew
	if skew == 0 {
		skew = defaultMaxClockSkew
	}
	minimumDesired := options.Checkpoint.DesiredGeneration
	if minimumDesired == 0 {
		minimumDesired = 1
	}
	if err := enrollment.VerifyDesiredState(signedDesired, desiredPublicKey, enrollment.DesiredExpectation{
		Instance: options.Instance, Profile: options.Profile,
		ReleaseSet: signedRelease.Manifest.SetID, MinGeneration: minimumDesired,
		Now: now.UTC(), MaxClockSkew: skew,
	}); err != nil {
		return Plan{}, fmt.Errorf("verify desired state: %w", err)
	}
	if signedDesired.State.Revoked {
		return Plan{}, ErrRevoked
	}
	desiredStateID, err := desiredStateID(signedDesired.State)
	if err != nil {
		return Plan{}, err
	}
	if options.Checkpoint.DesiredGeneration != 0 &&
		signedDesired.State.Generation == options.Checkpoint.DesiredGeneration &&
		desiredStateID != options.Checkpoint.DesiredStateID {
		return Plan{}, fmt.Errorf("%w: desired-state generation %d has different content", ErrRollback, signedDesired.State.Generation)
	}

	resolved, err := registry.Resolve(options.Profile)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve profile: %w", err)
	}
	manifestProfiles := make(map[string]release.Profile, len(signedRelease.Manifest.Profiles))
	for _, profile := range signedRelease.Manifest.Profiles {
		manifestProfiles[profile.Name] = profile
	}
	for _, profile := range resolved {
		manifestProfile, exists := manifestProfiles[profile.Name]
		if !exists || !sameSet(profile.DependsOn, manifestProfile.DependsOn) || !sameSet(profile.Components, manifestProfile.Components) {
			return Plan{}, fmt.Errorf("%w: %s", ErrProfileMismatch, profile.Name)
		}
	}
	if options.Profile == "pbp" {
		if err := validatePBPClosure(resolved); err != nil {
			return Plan{}, err
		}
	}

	target := "linux-" + options.GOARCH
	plan := Plan{
		Schema: SchemaVersion, Instance: options.Instance, Profile: options.Profile,
		Target: target, ReleaseSet: signedRelease.Manifest.SetID,
		ReleaseGeneration: signedRelease.Manifest.Generation,
		DesiredGeneration: signedDesired.State.Generation,
		DesiredStateID:    desiredStateID,
		AuthorizedSSHKeys: append([]string(nil), signedDesired.State.AuthorizedSSHKeys...),
		Phases:            make([]Phase, 0, len(resolved)+1),
	}
	runtimeArtifact, err := selectRuntimeArtifact(signedRelease.Manifest, target)
	if err != nil {
		return Plan{}, err
	}
	plan.Phases = append(plan.Phases, Phase{
		ID:      "phase/flow",
		Profile: "flow",
		Steps: []Step{{
			ID: "phase/flow/component/flow",
			Artifact: Artifact{
				Component: runtimeArtifact.Name, Version: runtimeArtifact.Version,
				Target: runtimeArtifact.Target, Path: runtimeArtifact.Artifact,
				Digest: runtimeArtifact.Digest, Size: runtimeArtifact.Size,
			},
		}},
	})
	phaseIDs := map[string]struct{}{"phase/flow": {}}
	stepIDs := map[string]struct{}{"phase/flow/component/flow": {}}
	for _, declaration := range resolved {
		phaseID := "phase/" + declaration.Name
		if _, duplicate := phaseIDs[phaseID]; duplicate {
			return Plan{}, fmt.Errorf("%w: duplicate phase ID %s", ErrInvalidInput, phaseID)
		}
		phaseIDs[phaseID] = struct{}{}
		dependencies := append([]string(nil), declaration.DependsOn...)
		sort.Strings(dependencies)
		for index := range dependencies {
			dependencies[index] = "phase/" + dependencies[index]
		}
		if len(dependencies) == 0 {
			dependencies = []string{"phase/flow"}
		}
		componentNames := append([]string(nil), declaration.Components...)
		sort.Strings(componentNames)
		phase := Phase{ID: phaseID, Profile: declaration.Name, DependsOn: dependencies, Steps: make([]Step, 0, len(componentNames))}
		for _, componentName := range componentNames {
			selected, err := selectArtifact(signedRelease.Manifest, componentName, target)
			if err != nil {
				return Plan{}, err
			}
			stepID := phaseID + "/component/" + componentName
			if _, duplicate := stepIDs[stepID]; duplicate {
				return Plan{}, fmt.Errorf("%w: duplicate step ID %s", ErrInvalidInput, stepID)
			}
			stepIDs[stepID] = struct{}{}
			phase.Steps = append(phase.Steps, Step{ID: stepID, Artifact: Artifact{
				Component: selected.Name, Version: selected.Version, Target: selected.Target,
				Path: selected.Artifact, Digest: selected.Digest, Size: selected.Size,
			}})
		}
		plan.Phases = append(plan.Phases, phase)
	}
	id, err := planID(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.ID = id
	return plan, nil
}

// selectRuntimeArtifact intentionally differs from selectArtifact: the binary
// that replaces /usr/local/bin/flow must be built for the exact runtime target.
// a target-independent ("any") artifact is never a valid executable update.
func selectRuntimeArtifact(manifest release.Manifest, target string) (release.Component, error) {
	candidates := make([]release.Component, 0, 2)
	for _, component := range manifest.Components {
		if component.Name == "flow" && component.Target == target {
			candidates = append(candidates, component)
		}
	}
	switch len(candidates) {
	case 0:
		return release.Component{}, fmt.Errorf("%w: flow for %s", ErrMissingArtifact, target)
	case 1:
	default:
		return release.Component{}, fmt.Errorf("%w: flow has %d candidates for %s", ErrAmbiguousArtifact, len(candidates), target)
	}
	selected := candidates[0]
	if selected.Artifact != "flow/"+selected.Version+"/"+target+"/flow" {
		return release.Component{}, fmt.Errorf("%w: flow has an invalid runtime artifact path", ErrMissingArtifact)
	}
	for _, revocation := range manifest.Revocations {
		if revocation.Component == selected.Name && revocation.Version == selected.Version {
			return release.Component{}, fmt.Errorf("%w: %s %s", ErrRevokedArtifact, selected.Name, selected.Version)
		}
	}
	return selected, nil
}

func validateOptions(registry *profiles.Registry, releaseKey, desiredKey ed25519.PublicKey, options Options) error {
	if registry == nil || !instanceNameRE.MatchString(options.Instance) || options.Instance == "." || options.Instance == ".." ||
		options.Profile == "" || len(releaseKey) != ed25519.PublicKeySize || len(desiredKey) != ed25519.PublicKeySize ||
		bytes.Equal(releaseKey, desiredKey) || options.MaxClockSkew < 0 {
		return ErrInvalidInput
	}
	if options.GOARCH != "amd64" && options.GOARCH != "arm64" {
		return fmt.Errorf("%w: linux-%s", ErrUnsupportedTarget, options.GOARCH)
	}
	checkpoint := options.Checkpoint
	if (checkpoint.ReleaseGeneration == 0) != (checkpoint.ReleaseSet == "") ||
		(checkpoint.ReleaseSet != "" && !digestRE.MatchString(checkpoint.ReleaseSet)) ||
		(checkpoint.DesiredGeneration == 0) != (checkpoint.DesiredStateID == "") ||
		(checkpoint.DesiredStateID != "" && !digestRE.MatchString(checkpoint.DesiredStateID)) {
		return fmt.Errorf("%w: malformed checkpoint", ErrInvalidInput)
	}
	return nil
}

func checkReleaseCheckpoint(manifest release.Manifest, checkpoint Checkpoint) error {
	if manifest.Generation < checkpoint.ReleaseGeneration {
		return fmt.Errorf("%w: release generation %d is older than %d", ErrRollback, manifest.Generation, checkpoint.ReleaseGeneration)
	}
	if checkpoint.ReleaseGeneration != 0 && manifest.Generation == checkpoint.ReleaseGeneration && manifest.SetID != checkpoint.ReleaseSet {
		return fmt.Errorf("%w: release generation %d identifies another set", ErrRollback, manifest.Generation)
	}
	return nil
}

func validatePBPClosure(resolved []profiles.Profile) error {
	wantNames := []string{"ssh", "ssh-gui", "vpn-pbp-de", "pbp"}
	wantDependencies := [][]string{nil, {"ssh"}, {"ssh-gui"}, {"vpn-pbp-de"}}
	wantComponents := [][]string{{"ssh"}, {"ssh"}, {"vpn"}, {"pbp"}}
	if len(resolved) != len(wantNames) {
		return fmt.Errorf("%w: pbp dependency closure is not exact", ErrProfileMismatch)
	}
	for index, profile := range resolved {
		if profile.Name != wantNames[index] ||
			!sameSet(profile.DependsOn, wantDependencies[index]) ||
			!sameSet(profile.Components, wantComponents[index]) || profile.Name == "vpn" {
			return fmt.Errorf("%w: pbp phase %d must be %s", ErrProfileMismatch, index, wantNames[index])
		}
	}
	return nil
}

func selectArtifact(manifest release.Manifest, componentName, target string) (release.Component, error) {
	candidates := make([]release.Component, 0, 2)
	for _, component := range manifest.Components {
		if component.Name == componentName && (component.Target == target || component.Target == "any") {
			candidates = append(candidates, component)
		}
	}
	switch len(candidates) {
	case 0:
		return release.Component{}, fmt.Errorf("%w: %s for %s", ErrMissingArtifact, componentName, target)
	case 1:
		// continue below so the explicit revocation defense remains in place
		// even if release.validate is relaxed in a future schema.
	default:
		return release.Component{}, fmt.Errorf("%w: %s has %d candidates for %s/any", ErrAmbiguousArtifact, componentName, len(candidates), target)
	}
	selected := candidates[0]
	for _, revocation := range manifest.Revocations {
		if revocation.Component == selected.Name && revocation.Version == selected.Version {
			return release.Component{}, fmt.Errorf("%w: %s %s", ErrRevokedArtifact, selected.Name, selected.Version)
		}
	}
	return selected, nil
}

func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func planID(plan Plan) (string, error) {
	copy := plan
	copy.ID = ""
	canonical, err := signing.CanonicalJSON(copy)
	if err != nil {
		return "", fmt.Errorf("canonicalize apply plan: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func desiredStateID(state enrollment.DesiredState) (string, error) {
	canonical, err := signing.CanonicalJSON(state)
	if err != nil {
		return "", fmt.Errorf("canonicalize desired state: %w", err)
	}
	hash := sha256.New()
	hash.Write([]byte("dynamicflow/desired-state-id/v1\x00"))
	hash.Write(canonical)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
