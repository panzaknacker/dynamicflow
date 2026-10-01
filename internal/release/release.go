// package release builds, signs, verifies and atomically activates immutable
// dynamicflow release sets.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"dynamicflow/internal/signing"
)

const (
	SchemaVersion            = 1
	SignatureDomain          = "dynamicflow/release-manifest/v1"
	MaxManifestEnvelopeBytes = 4 << 20
	MaxBundleBytes           = int64(16 << 30)
	MaxComponents            = 256
	MaxProfiles              = 128
	MaxRevocations           = 1024
	maxNameBytes             = 128
	maxArtifactPathBytes     = 512
)

var (
	ErrInvalidManifest  = errors.New("invalid release manifest")
	ErrArtifactTampered = errors.New("release artifact digest or size mismatch")
	ErrPrivateKey       = errors.New("release artifact contains private key material")
	ErrUnsafePath       = errors.New("unsafe release path")
	ErrVersionConflict  = errors.New("immutable artifact version conflict")
	ErrReleaseRollback  = errors.New("release generation rollback refused")
)

var (
	safeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	versionRE  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Component struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Target   string `json:"target"`
	Artifact string `json:"artifact"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
}

type Profile struct {
	Name       string   `json:"name"`
	DependsOn  []string `json:"depends_on,omitempty"`
	Components []string `json:"components"`
}

type Revocation struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
}

type Manifest struct {
	Schema      int          `json:"schema"`
	Generation  uint64       `json:"generation"`
	SetID       string       `json:"set_id"`
	Components  []Component  `json:"components"`
	Profiles    []Profile    `json:"profiles"`
	Revocations []Revocation `json:"revocations,omitempty"`
}

type SignedManifest struct {
	Manifest  Manifest          `json:"manifest"`
	Signature signing.Signature `json:"signature"`
}

// ArtifactInput binds a source file to the immutable logical artifact name
// that appears in the signed manifest.
type ArtifactInput struct {
	Component    string
	Version      string
	Target       string
	ArtifactName string
	SourcePath   string
}

// BuildFromArtifacts hashes the exact source bytes and returns a normalized,
// content-addressed manifest. source paths never enter the manifest.
func BuildFromArtifacts(generation uint64, artifacts []ArtifactInput, profiles []Profile, revocations []Revocation) (Manifest, error) {
	manifest := Manifest{
		Schema:      SchemaVersion,
		Generation:  generation,
		Profiles:    cloneProfiles(profiles),
		Revocations: append([]Revocation(nil), revocations...),
	}
	for _, artifact := range artifacts {
		name := artifact.ArtifactName
		if name == "" {
			name = filepath.Base(artifact.SourcePath)
		}
		if !safeName(artifact.Component) || !safeVersion(artifact.Version) || !safeName(artifact.Target) || !safeName(name) {
			return Manifest{}, fmt.Errorf("%w: invalid artifact identity", ErrInvalidManifest)
		}
		info, err := os.Lstat(artifact.SourcePath)
		if err != nil {
			return Manifest{}, fmt.Errorf("inspect artifact %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
			return Manifest{}, fmt.Errorf("%w: artifact source must be a non-empty regular file", ErrUnsafePath)
		}
		digest, size, err := hashFile(artifact.SourcePath)
		if err != nil {
			return Manifest{}, err
		}
		logical := filepath.ToSlash(filepath.Join(artifact.Component, artifact.Version, artifact.Target, name))
		manifest.Components = append(manifest.Components, Component{
			Name: artifact.Component, Version: artifact.Version, Target: artifact.Target,
			Artifact: logical, Digest: digest, Size: size,
		})
	}
	manifest = normalize(manifest)
	setID, err := ComputeSetID(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.SetID = setID
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func safeName(value string) bool {
	return len(value) > 0 && len(value) <= maxNameBytes && value != "." && value != ".." && safeNameRE.MatchString(value)
}

func safeVersion(value string) bool {
	return len(value) <= maxNameBytes && versionRE.MatchString(value)
}

func safeReason(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func normalize(manifest Manifest) Manifest {
	result := manifest
	result.Components = append([]Component(nil), manifest.Components...)
	sort.Slice(result.Components, func(i, j int) bool {
		a, b := result.Components[i], result.Components[j]
		return strings.Join([]string{a.Name, a.Version, a.Target, a.Artifact}, "\x00") <
			strings.Join([]string{b.Name, b.Version, b.Target, b.Artifact}, "\x00")
	})
	result.Profiles = cloneProfiles(manifest.Profiles)
	for index := range result.Profiles {
		sort.Strings(result.Profiles[index].DependsOn)
		sort.Strings(result.Profiles[index].Components)
	}
	sort.Slice(result.Profiles, func(i, j int) bool { return result.Profiles[i].Name < result.Profiles[j].Name })
	result.Revocations = append([]Revocation(nil), manifest.Revocations...)
	sort.Slice(result.Revocations, func(i, j int) bool {
		a, b := result.Revocations[i], result.Revocations[j]
		return strings.Join([]string{a.Component, a.Version, a.Reason}, "\x00") <
			strings.Join([]string{b.Component, b.Version, b.Reason}, "\x00")
	})
	return result
}

func cloneProfiles(profiles []Profile) []Profile {
	result := make([]Profile, len(profiles))
	for index, profile := range profiles {
		result[index] = profile
		result[index].DependsOn = append([]string(nil), profile.DependsOn...)
		result[index].Components = append([]string(nil), profile.Components...)
	}
	return result
}

// ComputeSetID covers every security-relevant manifest field except SetID
// itself, avoiding a self-referential digest.
func ComputeSetID(manifest Manifest) (string, error) {
	copy := normalize(manifest)
	copy.SetID = ""
	canonical, err := signing.CanonicalJSON(copy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func Validate(manifest Manifest) error {
	if manifest.Schema != SchemaVersion || manifest.Generation == 0 || len(manifest.Components) == 0 || len(manifest.Components) > MaxComponents ||
		len(manifest.Profiles) == 0 || len(manifest.Profiles) > MaxProfiles || len(manifest.Revocations) > MaxRevocations {
		return fmt.Errorf("%w: missing schema, generation, components or profiles", ErrInvalidManifest)
	}
	if !reflect.DeepEqual(manifest, normalize(manifest)) {
		return fmt.Errorf("%w: manifest arrays are not canonical", ErrInvalidManifest)
	}
	expectedID, err := ComputeSetID(manifest)
	if err != nil || manifest.SetID != expectedID {
		return fmt.Errorf("%w: set identifier mismatch", ErrInvalidManifest)
	}
	componentNames := make(map[string]struct{})
	componentKeys := make(map[string]struct{})
	activeVersions := make(map[string]map[string]struct{})
	componentTargets := make(map[string]map[string]struct{})
	var totalArtifactBytes int64
	for _, component := range manifest.Components {
		if !safeName(component.Name) || !safeVersion(component.Version) || !safeName(component.Target) ||
			!digestRE.MatchString(component.Digest) || component.Size <= 0 || component.Size > MaxBundleBytes || !safeRelativeArtifact(component.Artifact) {
			return fmt.Errorf("%w: invalid component field", ErrInvalidManifest)
		}
		if totalArtifactBytes > MaxBundleBytes-component.Size {
			return fmt.Errorf("%w: total artifact size exceeds release bound", ErrInvalidManifest)
		}
		totalArtifactBytes += component.Size
		expectedPrefix := filepath.ToSlash(filepath.Join(component.Name, component.Version, component.Target)) + "/"
		if !strings.HasPrefix(component.Artifact, expectedPrefix) {
			return fmt.Errorf("%w: artifact is not directly bound to component/version/target", ErrInvalidManifest)
		}
		key := component.Name + "\x00" + component.Version + "\x00" + component.Target
		if _, exists := componentKeys[key]; exists {
			return fmt.Errorf("%w: duplicate component target", ErrInvalidManifest)
		}
		componentKeys[key] = struct{}{}
		componentNames[component.Name] = struct{}{}
		if componentTargets[component.Name] == nil {
			componentTargets[component.Name] = make(map[string]struct{})
		}
		componentTargets[component.Name][component.Target] = struct{}{}
		if activeVersions[component.Name] == nil {
			activeVersions[component.Name] = make(map[string]struct{})
		}
		activeVersions[component.Name][component.Version] = struct{}{}
	}
	for name, versions := range activeVersions {
		if len(versions) != 1 {
			return fmt.Errorf("%w: component %q uses different versions across targets", ErrInvalidManifest, name)
		}
		if _, hasAny := componentTargets[name]["any"]; hasAny && len(componentTargets[name]) != 1 {
			return fmt.Errorf("%w: component %q mixes target any with exact targets", ErrInvalidManifest, name)
		}
	}
	profileNames := make(map[string]struct{})
	for _, profile := range manifest.Profiles {
		if !safeName(profile.Name) || len(profile.Components) == 0 || len(profile.Components) > MaxComponents || len(profile.DependsOn) > MaxProfiles {
			return fmt.Errorf("%w: invalid profile", ErrInvalidManifest)
		}
		if _, exists := profileNames[profile.Name]; exists {
			return fmt.Errorf("%w: duplicate profile", ErrInvalidManifest)
		}
		profileNames[profile.Name] = struct{}{}
		seenComponents := make(map[string]struct{}, len(profile.Components))
		for _, component := range profile.Components {
			if _, exists := componentNames[component]; !exists {
				return fmt.Errorf("%w: profile references unknown component %q", ErrInvalidManifest, component)
			}
			if _, exists := seenComponents[component]; exists {
				return fmt.Errorf("%w: profile repeats component %q", ErrInvalidManifest, component)
			}
			seenComponents[component] = struct{}{}
		}
	}
	for _, profile := range manifest.Profiles {
		seenDependencies := make(map[string]struct{}, len(profile.DependsOn))
		for _, dependency := range profile.DependsOn {
			if dependency == profile.Name {
				return fmt.Errorf("%w: profile depends on itself", ErrInvalidManifest)
			}
			if _, exists := profileNames[dependency]; !exists {
				return fmt.Errorf("%w: profile references unknown dependency %q", ErrInvalidManifest, dependency)
			}
			if _, exists := seenDependencies[dependency]; exists {
				return fmt.Errorf("%w: profile repeats dependency %q", ErrInvalidManifest, dependency)
			}
			seenDependencies[dependency] = struct{}{}
		}
	}
	if err := validateProfileDAG(manifest.Profiles); err != nil {
		return err
	}
	revocations := make(map[string]struct{})
	for _, revocation := range manifest.Revocations {
		if !safeName(revocation.Component) || !safeVersion(revocation.Version) || !safeReason(revocation.Reason) {
			return fmt.Errorf("%w: invalid revocation", ErrInvalidManifest)
		}
		key := revocation.Component + "\x00" + revocation.Version
		if _, exists := revocations[key]; exists {
			return fmt.Errorf("%w: duplicate revocation", ErrInvalidManifest)
		}
		revocations[key] = struct{}{}
		if versions := activeVersions[revocation.Component]; versions != nil {
			if _, active := versions[revocation.Version]; active {
				return fmt.Errorf("%w: active component is revoked", ErrInvalidManifest)
			}
		}
	}
	return nil
}

func validateProfileDAG(profiles []Profile) error {
	edges := make(map[string][]string, len(profiles))
	for _, profile := range profiles {
		edges[profile.Name] = profile.DependsOn
	}
	state := make(map[string]uint8, len(profiles))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("%w: profile dependency cycle", ErrInvalidManifest)
		case 2:
			return nil
		}
		state[name] = 1
		for _, dependency := range edges[name] {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range edges {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

func safeRelativeArtifact(path string) bool {
	if path == "" || len(path) > maxArtifactPathBytes || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || filepath.ToSlash(filepath.Clean(path)) != path {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !safeName(part) {
			return false
		}
	}
	return true
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey) (SignedManifest, error) {
	if err := Validate(manifest); err != nil {
		return SignedManifest{}, err
	}
	signature, err := signing.SignCanonical(privateKey, SignatureDomain, manifest)
	if err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Manifest: manifest, Signature: signature}, nil
}

func VerifyManifest(signed SignedManifest, publicKey ed25519.PublicKey) error {
	if err := Validate(signed.Manifest); err != nil {
		return err
	}
	if err := signing.VerifyCanonical(publicKey, SignatureDomain, signed.Manifest, signed.Signature); err != nil {
		return fmt.Errorf("verify release manifest: %w", err)
	}
	return nil
}
