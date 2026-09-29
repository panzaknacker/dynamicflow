// package release builds, signs, verifies and atomically activates immutable
// dynamicflow release sets.
package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
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

// VerifyArtifacts verifies direct signed size/digest bindings. artifactPaths is
// keyed by Component.Artifact.
func VerifyArtifacts(manifest Manifest, artifactPaths map[string]string) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	if len(artifactPaths) != len(manifest.Components) {
		return fmt.Errorf("%w: artifact map is incomplete or contains extras", ErrInvalidManifest)
	}
	for _, component := range manifest.Components {
		path, exists := artifactPaths[component.Artifact]
		if !exists {
			return fmt.Errorf("%w: missing %s", ErrInvalidManifest, component.Artifact)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: unsafe artifact %s", ErrUnsafePath, component.Artifact)
		}
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		if digest != component.Digest || size != component.Size {
			return fmt.Errorf("%w: %s", ErrArtifactTampered, component.Artifact)
		}
	}
	return nil
}

// CheckVersionHistory prevents a logical component/version/target coordinate
// from being rebound to another artifact name or another byte sequence. The
// previous manifest must already have been authenticated by the caller.
func CheckVersionHistory(previous, candidate Manifest) error {
	if err := Validate(previous); err != nil {
		return err
	}
	if err := Validate(candidate); err != nil {
		return err
	}
	coordinates := make(map[string]Component, len(previous.Components))
	for _, component := range previous.Components {
		key := strings.Join([]string{component.Name, component.Version, component.Target}, "\x00")
		coordinates[key] = component
	}
	for _, component := range candidate.Components {
		key := strings.Join([]string{component.Name, component.Version, component.Target}, "\x00")
		prior, exists := coordinates[key]
		if !exists {
			continue
		}
		if prior.Artifact != component.Artifact || prior.Digest != component.Digest || prior.Size != component.Size {
			return fmt.Errorf("%w: %s/%s/%s", ErrVersionConflict, component.Name, component.Version, component.Target)
		}
	}
	return nil
}

// CheckGenerationHistory prevents signing a rollback or assigning one
// generation to two different release sets. an exact fixed-generation rebuild
// is allowed because its content-addressed set ID is identical.
func CheckGenerationHistory(previous, candidate Manifest) error {
	if err := Validate(previous); err != nil {
		return err
	}
	if err := Validate(candidate); err != nil {
		return err
	}
	if candidate.Generation < previous.Generation {
		return fmt.Errorf("%w: previous=%d/%s candidate=%d/%s", ErrReleaseRollback,
			previous.Generation, previous.SetID, candidate.Generation, candidate.SetID)
	}
	if candidate.Generation == previous.Generation && candidate.SetID != previous.SetID {
		return fmt.Errorf("%w: generation %d already identifies %s", ErrReleaseRollback,
			candidate.Generation, previous.SetID)
	}
	return nil
}

// CheckImmutableVersionRoot compares a candidate manifest with any artifacts
// already present below root. a genuinely missing root, directory or final
// artifact is allowed because the version has not been materialized there.
// existing entries are opened descriptor-relatively without following links;
// only owner-controlled, singly-linked regular files may establish a version
// binding. the comparison streams bytes and never loads large artifacts into
// memory.
func CheckImmutableVersionRoot(root string, manifest Manifest) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	rootFile, exists, err := openOptionalImmutableRoot(root)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	defer rootFile.Close()
	for _, component := range manifest.Components {
		digest, size, found, inspectErr := inspectOptionalImmutableArtifact(rootFile, component.Artifact, component.Size)
		if inspectErr != nil {
			return fmt.Errorf("%w: %s", inspectErr, component.Artifact)
		}
		if found && (digest != component.Digest || size != component.Size) {
			return fmt.Errorf("%w: %s", ErrVersionConflict, component.Artifact)
		}
	}
	return nil
}

func openOptionalImmutableRoot(path string) (*os.File, bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, false, fmt.Errorf("%w: immutable version root must be an absolute non-root path", ErrUnsafePath)
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, fmt.Errorf("%w: open immutable version root", ErrUnsafePath)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, false, ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if errors.Is(openErr, syscall.ENOENT) {
			return nil, false, nil
		}
		if openErr != nil {
			return nil, false, fmt.Errorf("%w: immutable version root ancestor", ErrUnsafePath)
		}
		fd = next
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || !secureImmutableDirectory(details) {
		_ = syscall.Close(fd)
		return nil, false, fmt.Errorf("%w: immutable version root metadata", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, false, ErrUnsafePath
	}
	return file, true, nil
}

func inspectOptionalImmutableArtifact(root *os.File, logical string, expectedSize int64) (string, int64, bool, error) {
	if root == nil || !safeRelativeArtifact(logical) || expectedSize <= 0 || expectedSize > MaxBundleBytes {
		return "", 0, false, ErrUnsafePath
	}
	directoryFD, err := syscall.Openat(int(root.Fd()), ".", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, false, ErrUnsafePath
	}
	parts := strings.Split(logical, "/")
	for _, part := range parts[:len(parts)-1] {
		next, openErr := syscall.Openat(directoryFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(directoryFD)
		if errors.Is(openErr, syscall.ENOENT) {
			return "", 0, false, nil
		}
		if openErr != nil {
			return "", 0, false, ErrUnsafePath
		}
		var details syscall.Stat_t
		if statErr := syscall.Fstat(next, &details); statErr != nil || !secureImmutableDirectory(details) {
			_ = syscall.Close(next)
			return "", 0, false, ErrUnsafePath
		}
		directoryFD = next
	}
	defer syscall.Close(directoryFD)
	name := parts[len(parts)-1]
	var directoryBefore syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryBefore); err != nil || !secureImmutableDirectory(directoryBefore) {
		return "", 0, false, ErrUnsafePath
	}
	entries, err := immutableDirectoryEntries(directoryFD)
	if err != nil {
		return "", 0, false, err
	}
	if len(entries) == 0 {
		var directoryAfter syscall.Stat_t
		if err := syscall.Fstat(directoryFD, &directoryAfter); err != nil || !stableImmutableMetadata(directoryBefore, directoryAfter) {
			return "", 0, false, ErrUnsafePath
		}
		return "", 0, false, nil
	}
	if len(entries) != 1 {
		return "", 0, false, ErrUnsafePath
	}
	if entries[0] != name {
		unexpected, openErr := syscall.Openat(directoryFD, entries[0], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return "", 0, false, ErrUnsafePath
		}
		var details syscall.Stat_t
		statErr := syscall.Fstat(unexpected, &details)
		closeErr := syscall.Close(unexpected)
		if statErr != nil || closeErr != nil || !secureImmutableArtifact(details) {
			return "", 0, false, ErrUnsafePath
		}
		return "", 0, false, ErrVersionConflict
	}
	fd, openErr := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		return "", 0, false, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), logical)
	if file == nil {
		_ = syscall.Close(fd)
		return "", 0, false, ErrUnsafePath
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || !secureImmutableArtifact(before) {
		_ = file.Close()
		return "", 0, false, ErrUnsafePath
	}
	if before.Size != expectedSize {
		_ = file.Close()
		return "", 0, false, ErrVersionConflict
	}
	digest, size, hashErr := hashOpenFile(file)
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	closeErr := file.Close()
	if hashErr != nil {
		return "", 0, false, hashErr
	}
	if statErr != nil || closeErr != nil || !stableImmutableMetadata(before, after) {
		return "", 0, false, ErrUnsafePath
	}
	// bind the bytes just inspected back to the directory entry. a rename or
	// replacement during hashing is an unsafe concurrent mutation, not absence.
	reopened, reopenErr := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if reopenErr != nil {
		return "", 0, false, ErrUnsafePath
	}
	var linked syscall.Stat_t
	linkedErr := syscall.Fstat(reopened, &linked)
	reopenCloseErr := syscall.Close(reopened)
	if linkedErr != nil || reopenCloseErr != nil || !stableImmutableMetadata(after, linked) {
		return "", 0, false, ErrUnsafePath
	}
	var directoryAfter syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryAfter); err != nil || !stableImmutableMetadata(directoryBefore, directoryAfter) {
		return "", 0, false, ErrUnsafePath
	}
	return digest, size, true, nil
}

func immutableDirectoryEntries(fd int) ([]string, error) {
	duplicate, err := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	directory := os.NewFile(uintptr(duplicate), "immutable-version-coordinate")
	if directory == nil {
		_ = syscall.Close(duplicate)
		return nil, ErrUnsafePath
	}
	entries, readErr := directory.Readdirnames(2)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 1 {
		return nil, ErrUnsafePath
	}
	for _, entry := range entries {
		if !safeName(entry) {
			return nil, ErrUnsafePath
		}
	}
	return entries, nil
}

func secureImmutableDirectory(details syscall.Stat_t) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFDIR && int(details.Uid) == os.Geteuid() && details.Mode&0o022 == 0
}

func secureImmutableArtifact(details syscall.Stat_t) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFREG && int(details.Uid) == os.Geteuid() && details.Nlink == 1 && details.Mode&0o022 == 0
}

func stableImmutableMetadata(first, second syscall.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Mode == second.Mode &&
		first.Nlink == second.Nlink && first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Size == second.Size && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func hashFile(path string) (string, int64, error) {
	file, _, err := openRegularNoFollow(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	return hashOpenFile(file)
}

// ReadRegularFile reads a bounded single-link regular file through a
// descriptor-relative, no-follow path walk. it is used by the release CLI for
// version and externally supplied staged metadata.
func ReadRegularFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum > MaxBundleBytes {
		return nil, ErrUnsafePath
	}
	file, details, err := openRegularNoFollow(path)
	if err != nil || details.Size < 0 || details.Size > maximum {
		if file != nil {
			file.Close()
		}
		return nil, ErrUnsafePath
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != details.Size || int64(len(data)) > maximum {
		return nil, ErrUnsafePath
	}
	return data, nil
}

// RegularFileSize validates a single-link regular path without reading it.
func RegularFileSize(path string) (int64, error) {
	file, details, err := openRegularNoFollow(path)
	if err != nil {
		return 0, err
	}
	if err := file.Close(); err != nil {
		return 0, err
	}
	return details.Size, nil
}

func hashOpenFile(file *os.File) (string, int64, error) {
	hash := sha256.New()
	detector := &privateKeyDetector{}
	size, err := io.Copy(io.MultiWriter(hash, detector), file)
	if err != nil {
		return "", 0, err
	}
	if detector.found {
		return "", 0, ErrPrivateKey
	}
	if err := inspectCompressedArtifact(file); err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

var privateKeyMarkers = [][]byte{
	privateKeyMarker(""),
	privateKeyMarker("ENCRYPTED "),
	privateKeyMarker("OPENSSH "),
	privateKeyMarker("RSA "),
	privateKeyMarker("EC "),
	privateKeyMarker("DSA "),
}

//go:noinline
func privateKeyMarker(kind string) []byte {
	marker := make([]byte, 0, 32+len(kind))
	marker = append(marker, "-----BEGIN "...)
	marker = append(marker, kind...)
	marker = append(marker, "PRIVATE"...)
	marker = append(marker, byte(32))
	marker = append(marker, "KEY-----"...)
	return marker
}

type privateKeyDetector struct {
	tail  []byte
	found bool
}

func (detector *privateKeyDetector) Write(data []byte) (int, error) {
	original := len(data)
	if detector.found {
		return original, nil
	}
	combined := append(append([]byte(nil), detector.tail...), data...)
	for _, marker := range privateKeyMarkers {
		if bytes.Contains(combined, marker) {
			detector.found = true
			break
		}
	}
	const retained = 64
	if len(combined) > retained {
		detector.tail = append(detector.tail[:0], combined[len(combined)-retained:]...)
	} else {
		detector.tail = append(detector.tail[:0], combined...)
	}
	return original, nil
}

func inspectCompressedArtifact(file *os.File) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var magic [2]byte
	count, err := io.ReadFull(file, magic[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	if count != len(magic) || magic != [2]byte{0x1f, 0x8b} {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("%w: malformed gzip artifact", ErrArtifactTampered)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var expanded int64
	entries := 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: malformed tar artifact", ErrArtifactTampered)
		}
		entries++
		if entries > 100000 || header.Size < 0 || expanded > MaxBundleBytes-header.Size {
			return fmt.Errorf("%w: compressed artifact exceeds inspection bounds", ErrInvalidManifest)
		}
		expanded += header.Size
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		detector := &privateKeyDetector{}
		written, copyErr := io.Copy(detector, archive)
		if copyErr != nil || written != header.Size {
			return fmt.Errorf("%w: truncated tar artifact", ErrArtifactTampered)
		}
		if detector.found {
			return ErrPrivateKey
		}
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, syscall.Stat_t, error) {
	var details syscall.Stat_t
	if path == "" || filepath.Clean(path) == string(filepath.Separator) {
		return nil, details, ErrUnsafePath
	}
	clean := filepath.Clean(path)
	start := "."
	if filepath.IsAbs(clean) {
		start = string(filepath.Separator)
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) == 0 {
		return nil, details, ErrUnsafePath
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, details, ErrUnsafePath
		}
	}
	directoryFD, err := syscall.Open(start, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, details, fmt.Errorf("%w: open artifact root", ErrUnsafePath)
	}
	for _, part := range parts[:len(parts)-1] {
		nextFD, openErr := syscall.Openat(directoryFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(directoryFD)
		if openErr != nil {
			return nil, details, fmt.Errorf("%w: open artifact ancestor", ErrUnsafePath)
		}
		directoryFD = nextFD
	}
	fd, err := syscall.Openat(directoryFD, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	_ = syscall.Close(directoryFD)
	if err != nil {
		return nil, details, fmt.Errorf("%w: open artifact", ErrUnsafePath)
	}
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG || details.Nlink != 1 {
		_ = syscall.Close(fd)
		return nil, details, fmt.Errorf("%w: artifact is not a single-link regular file", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	return file, details, nil
}

func openDirectoryNoFollow(path string) (*os.File, syscall.Stat_t, error) {
	var details syscall.Stat_t
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, details, ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, details, ErrUnsafePath
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = syscall.Close(fd)
			return nil, details, ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, details, fmt.Errorf("%w: open directory", ErrUnsafePath)
		}
		fd = next
	}
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, details, ErrUnsafePath
	}
	return file, details, nil
}

// Publish verifies, stages and activates a signed set below root. no signing
// private key is needed on the serving node.
func Publish(root string, signed SignedManifest, artifactPaths map[string]string, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	root, err := canonicalRoot(root)
	if err != nil {
		return err
	}
	publishLock, err := lockPublish(filepath.Join(root, ".publish.lock"))
	if err != nil {
		return err
	}
	defer unlockPublish(publishLock)
	rootDirectory, rootIdentity, err := openDirectoryNoFollow(root)
	if err != nil || !secureImmutableDirectory(rootIdentity) {
		if rootDirectory != nil {
			_ = rootDirectory.Close()
		}
		return fmt.Errorf("%w: release root identity", ErrUnsafePath)
	}
	defer rootDirectory.Close()
	setsRoot := filepath.Join(root, "sets")
	if err := ensureDirectory(setsRoot, 0o755); err != nil {
		return err
	}
	if err := validateOwnedReleaseDirectory(setsRoot); err != nil {
		return err
	}
	historyRoot := filepath.Join(root, "history")
	if err := ensureDirectory(historyRoot, 0o755); err != nil {
		return err
	}
	if err := validateOwnedReleaseDirectory(historyRoot); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	retained, retainedFound, versionHistory, err := retainedReleaseHighWater(root, setsRoot, historyRoot, publicKey)
	if err != nil {
		return err
	}
	if retainedFound {
		if signed.Manifest.Generation < retained.Generation ||
			signed.Manifest.Generation == retained.Generation && signed.Manifest.SetID != retained.SetID {
			return fmt.Errorf("%w: retained=%d/%s candidate=%d/%s", ErrReleaseRollback,
				retained.Generation, retained.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
		}
	}
	if err := registerVersionBindings(versionHistory, signed.Manifest); err != nil {
		return err
	}
	currentPath := filepath.Join(root, "current")
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if _, statErr := os.Lstat(currentPath); statErr == nil {
		current, _, currentErr := Current(root, publicKey)
		if currentErr != nil {
			return currentErr
		}
		if signed.Manifest.Generation < current.Manifest.Generation {
			return fmt.Errorf("%w: current=%d candidate=%d", ErrReleaseRollback, current.Manifest.Generation, signed.Manifest.Generation)
		}
		if signed.Manifest.Generation == current.Manifest.Generation {
			if signed.Manifest.SetID != current.Manifest.SetID {
				return fmt.Errorf("%w: generation %d already identifies another set", ErrReleaseRollback, signed.Manifest.Generation)
			}
			if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
				return err
			}
			return syncDirectory(root)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	setName := strings.TrimPrefix(signed.Manifest.SetID, "sha256:")
	if len(setName) != 64 {
		return fmt.Errorf("%w: invalid set name", ErrInvalidManifest)
	}
	destination := filepath.Join(setsRoot, setName)
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil {
		return err
	}
	// a crash can occur after the immutable set rename but before the history
	// tombstone or current-pointer commit. in that state the signed destination
	// is the durable source of truth: verify it in full and finish the two
	// remaining commits without requiring the transient upload files to still
	// exist. never use this path for an absent, mismatched or damaged set.
	if destinationInfo, statErr := os.Lstat(destination); statErr == nil {
		if !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: immutable set destination is unsafe", ErrUnsafePath)
		}
		destinationBefore, identityErr := validatePublishedDirectory(destination)
		if identityErr != nil {
			return identityErr
		}
		existing, _, loadErr := loadPublishedSet(root, setName, publicKey)
		if loadErr != nil {
			return loadErr
		}
		if !reflect.DeepEqual(existing, signed) {
			return fmt.Errorf("%w: immutable set conflicts with existing content", ErrInvalidManifest)
		}
		if err := syncDirectory(setsRoot); err != nil {
			return err
		}
		if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
			return err
		}
		if err := ensureManifestHistoryEntry(historyRoot, signed, publicKey); err != nil {
			return err
		}
		destinationAfter, identityErr := validatePublishedDirectory(destination)
		if identityErr != nil || !stableImmutableMetadata(destinationBefore, destinationAfter) {
			return fmt.Errorf("%w: immutable set changed during resume", ErrUnsafePath)
		}
		if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
			return err
		}
		return activateCurrent(root, setName)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := VerifyArtifacts(signed.Manifest, artifactPaths); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(setsRoot, ".stage-")
	if err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	committed := false
	defer func() {
		if !committed {
			removeStage(stage)
		}
	}()
	if err := writeAtomicFile(filepath.Join(stage, "signed-manifest.json"), envelope, 0o644); err != nil {
		return err
	}
	for _, component := range signed.Manifest.Components {
		source := artifactPaths[component.Artifact]
		target := filepath.Join(stage, "artifacts", filepath.FromSlash(component.Artifact))
		if err := copyVerified(source, target, component); err != nil {
			return err
		}
	}
	if err := makeTreeReadOnly(stage); err != nil {
		return err
	}
	if err := syncTreeDirectories(stage); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		destinationInfo, statErr := os.Lstat(destination)
		if statErr != nil {
			return fmt.Errorf("activate immutable set: %w", err)
		}
		if !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: immutable set destination is unsafe", ErrUnsafePath)
		}
		existing, readErr := readPublishedManifest(filepath.Join(destination, "signed-manifest.json"))
		if readErr != nil || !bytes.Equal(existing, envelope) {
			return fmt.Errorf("%w: immutable set conflicts with existing content", ErrInvalidManifest)
		}
		if verifyErr := verifyPublishedArtifacts(destination, signed.Manifest); verifyErr != nil {
			return verifyErr
		}
		if removeErr := removeStage(stage); removeErr != nil {
			return removeErr
		}
	}
	committed = true
	if err := syncDirectory(setsRoot); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	if err := ensureManifestHistoryEntry(historyRoot, signed, publicKey); err != nil {
		return err
	}
	if err := ensureReleaseRootIdentity(root, rootIdentity); err != nil {
		return err
	}
	return activateCurrent(root, setName)
}

// CheckPublishPolicy performs the retained-generation and immutable-version
// checks without creating, backfilling or activating anything. it is a
// point-in-time plan preflight; Publish repeats every check while holding the
// publication lock. a genuinely absent root represents an empty destination.
func CheckPublishPolicy(root string, signed SignedManifest, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	rootDirectory, rootExists, err := openOptionalImmutableRoot(root)
	if err != nil {
		return err
	}
	if !rootExists {
		return checkReleaseRootCreation(root)
	}
	if err := validateReleasePathAncestors(filepath.Clean(root)); err != nil {
		_ = rootDirectory.Close()
		return err
	}
	var rootDetails syscall.Stat_t
	if err := syscall.Fstat(int(rootDirectory.Fd()), &rootDetails); err != nil || !ownerCanMutateDirectory(rootDetails) {
		_ = rootDirectory.Close()
		return fmt.Errorf("%w: release root is not owner-writable", ErrUnsafePath)
	}
	if err := rootDirectory.Close(); err != nil {
		return err
	}
	root = filepath.Clean(root)
	if err := checkPublishLockMetadata(filepath.Join(root, ".publish.lock")); err != nil {
		return err
	}
	versionHistory := make(map[string]immutableVersionBinding)
	var retained releaseHighWater
	retainedFound := false
	historyRoot := filepath.Join(root, "history")
	historyDirectory, historyExists, err := openOptionalImmutableRoot(historyRoot)
	if err != nil {
		return err
	}
	if historyExists {
		var details syscall.Stat_t
		if err := syscall.Fstat(int(historyDirectory.Fd()), &details); err != nil || !ownerCanMutateDirectory(details) {
			_ = historyDirectory.Close()
			return fmt.Errorf("%w: manifest-history directory is not owner-writable", ErrUnsafePath)
		}
		if err := historyDirectory.Close(); err != nil {
			return err
		}
		retained, retainedFound, err = scanManifestHistory(historyRoot, publicKey, versionHistory)
		if err != nil {
			return err
		}
	}
	setsRoot := filepath.Join(root, "sets")
	setsDirectory, setsExist, err := openOptionalImmutableRoot(setsRoot)
	if err != nil {
		return err
	}
	if setsExist {
		var details syscall.Stat_t
		if err := syscall.Fstat(int(setsDirectory.Fd()), &details); err != nil || !ownerCanMutateDirectory(details) {
			_ = setsDirectory.Close()
			return fmt.Errorf("%w: sets directory is not owner-writable", ErrUnsafePath)
		}
		if err := setsDirectory.Close(); err != nil {
			return err
		}
		if _, err := scanRetainedSetEntries(root, setsRoot, publicKey, &retained, &retainedFound, versionHistory); err != nil {
			return err
		}
	}
	if retainedFound && (signed.Manifest.Generation < retained.Generation ||
		signed.Manifest.Generation == retained.Generation && signed.Manifest.SetID != retained.SetID) {
		return fmt.Errorf("%w: retained=%d/%s candidate=%d/%s", ErrReleaseRollback,
			retained.Generation, retained.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
	}
	if err := registerVersionBindings(versionHistory, signed.Manifest); err != nil {
		return err
	}
	currentPath := filepath.Join(root, "current")
	if _, statErr := os.Lstat(currentPath); statErr == nil {
		current, _, currentErr := Current(root, publicKey)
		if currentErr != nil {
			return currentErr
		}
		if signed.Manifest.Generation < current.Manifest.Generation ||
			signed.Manifest.Generation == current.Manifest.Generation && signed.Manifest.SetID != current.Manifest.SetID {
			return fmt.Errorf("%w: current=%d/%s candidate=%d/%s", ErrReleaseRollback,
				current.Manifest.Generation, current.Manifest.SetID, signed.Manifest.Generation, signed.Manifest.SetID)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return nil
}

func ownerCanMutateDirectory(details syscall.Stat_t) bool {
	return secureImmutableDirectory(details) && details.Mode&0o300 == 0o300
}

func checkReleaseRootCreation(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafePath
	}
	currentPath := string(filepath.Separator)
	defer func() { _ = syscall.Close(fd) }()
	var parent syscall.Stat_t
	if err := syscall.Fstat(fd, &parent); err != nil || !trustedReleaseAncestor(parent) {
		return fmt.Errorf("%w: filesystem root metadata", ErrUnsafePath)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if parent.Mode&0o022 != 0 && parent.Mode&0o1000 == 0 {
				return fmt.Errorf("%w: writable release-root ancestor lacks sticky protection", ErrUnsafePath)
			}
			if err := syscall.Access(currentPath, 0o3); err != nil {
				return fmt.Errorf("%w: deepest release-root ancestor is not writable", ErrUnsafePath)
			}
			return nil
		}
		if openErr != nil {
			return fmt.Errorf("%w: release-root ancestor", ErrUnsafePath)
		}
		var child syscall.Stat_t
		if err := syscall.Fstat(next, &child); err != nil || !trustedReleaseAncestor(child) || parent.Mode&0o022 != 0 && parent.Mode&0o1000 == 0 {
			_ = syscall.Close(next)
			return fmt.Errorf("%w: release-root ancestor metadata", ErrUnsafePath)
		}
		if err := syscall.Close(fd); err != nil {
			_ = syscall.Close(next)
			return err
		}
		fd = next
		currentPath = filepath.Join(currentPath, part)
		parent = child
	}
	return nil
}

func checkPublishLockMetadata(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: publish lock metadata", ErrUnsafePath)
	}
	details, ok := info.Sys().(*syscall.Stat_t)
	var parent syscall.Stat_t
	if !ok || details.Nlink != 1 || details.Size != 0 || syscall.Stat(filepath.Dir(path), &parent) != nil || details.Uid != parent.Uid || details.Gid != parent.Gid {
		return fmt.Errorf("%w: publish lock ownership", ErrUnsafePath)
	}
	return nil
}

type releaseHighWater struct {
	Generation uint64
	SetID      string
}

type immutableVersionBinding struct {
	Artifact string
	Digest   string
	Size     int64
	SetID    string
}

func registerVersionBindings(history map[string]immutableVersionBinding, manifest Manifest) error {
	for _, component := range manifest.Components {
		key := strings.Join([]string{component.Name, component.Version, component.Target}, "\x00")
		binding := immutableVersionBinding{
			Artifact: component.Artifact,
			Digest:   component.Digest,
			Size:     component.Size,
			SetID:    manifest.SetID,
		}
		if previous, exists := history[key]; exists {
			if previous.Artifact != binding.Artifact || previous.Digest != binding.Digest || previous.Size != binding.Size {
				return fmt.Errorf("%w: %s/%s/%s (retained %s, candidate %s)",
					ErrVersionConflict, component.Name, component.Version, component.Target, previous.SetID, manifest.SetID)
			}
			continue
		}
		history[key] = binding
	}
	return nil
}

func acceptReleaseHighWater(result *releaseHighWater, found *bool, manifest Manifest) error {
	candidate := releaseHighWater{Generation: manifest.Generation, SetID: manifest.SetID}
	switch {
	case !*found || candidate.Generation > result.Generation:
		*result, *found = candidate, true
	case candidate.Generation == result.Generation && candidate.SetID != result.SetID:
		return fmt.Errorf("%w: retained generation %d identifies multiple sets", ErrReleaseRollback, candidate.Generation)
	}
	return nil
}

func retainedReleaseHighWater(root, setsRoot, historyRoot string, publicKey ed25519.PublicKey) (releaseHighWater, bool, map[string]immutableVersionBinding, error) {
	versionHistory := make(map[string]immutableVersionBinding)
	result, found, err := scanManifestHistory(historyRoot, publicKey, versionHistory)
	if err != nil {
		return releaseHighWater{}, false, nil, err
	}
	verifiedSets, err := scanRetainedSetEntries(root, setsRoot, publicKey, &result, &found, versionHistory)
	if err != nil {
		return releaseHighWater{}, false, nil, err
	}
	// backfill only after the complete retained catalog has passed every
	// signature, artifact, generation and version-binding check. a conflicting
	// legacy root must not partially commit whichever set happened to sort first.
	for _, signed := range verifiedSets {
		if err := ensureManifestHistoryEntry(historyRoot, signed, publicKey); err != nil {
			return releaseHighWater{}, false, nil, err
		}
	}
	return result, found, versionHistory, nil
}

func scanRetainedSetEntries(root, setsRoot string, publicKey ed25519.PublicKey, result *releaseHighWater, found *bool, versionHistory map[string]immutableVersionBinding) ([]SignedManifest, error) {
	entries, err := os.ReadDir(setsRoot)
	if err != nil {
		return nil, err
	}
	verifiedSets := make([]SignedManifest, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".stage-") {
			continue
		}
		if !validPublishedSetName(name) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: unexpected retained set entry", ErrUnsafePath)
		}
		signed, _, err := loadPublishedSet(root, name, publicKey)
		if err != nil {
			return nil, err
		}
		if err := acceptReleaseHighWater(result, found, signed.Manifest); err != nil {
			return nil, err
		}
		if err := registerVersionBindings(versionHistory, signed.Manifest); err != nil {
			return nil, err
		}
		verifiedSets = append(verifiedSets, signed)
	}
	return verifiedSets, nil
}

func scanManifestHistory(historyRoot string, publicKey ed25519.PublicKey, versions map[string]immutableVersionBinding) (releaseHighWater, bool, error) {
	entries, err := os.ReadDir(historyRoot)
	if err != nil {
		return releaseHighWater{}, false, err
	}
	var result releaseHighWater
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".stage-") {
			continue
		}
		if !validPublishedSetName(name) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return releaseHighWater{}, false, fmt.Errorf("%w: unexpected manifest-history entry", ErrUnsafePath)
		}
		signed, err := loadManifestHistoryEntry(historyRoot, name, publicKey)
		if err != nil {
			return releaseHighWater{}, false, err
		}
		if err := acceptReleaseHighWater(&result, &found, signed.Manifest); err != nil {
			return releaseHighWater{}, false, err
		}
		if err := registerVersionBindings(versions, signed.Manifest); err != nil {
			return releaseHighWater{}, false, err
		}
	}
	return result, found, nil
}

func ensureManifestHistoryEntry(historyRoot string, signed SignedManifest, publicKey ed25519.PublicKey) error {
	if err := VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	setName := strings.TrimPrefix(signed.Manifest.SetID, "sha256:")
	if !validPublishedSetName(setName) || signed.Manifest.SetID != "sha256:"+setName {
		return ErrInvalidManifest
	}
	destination := filepath.Join(historyRoot, setName)
	if _, err := os.Lstat(destination); err == nil {
		existing, loadErr := loadManifestHistoryEntry(historyRoot, setName, publicKey)
		if loadErr != nil {
			return loadErr
		}
		if !reflect.DeepEqual(existing, signed) {
			return fmt.Errorf("%w: manifest-history set conflict", ErrInvalidManifest)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(historyRoot, ".stage-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = removeStage(stage)
		}
	}()
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := writeAtomicFile(filepath.Join(stage, "signed-manifest.json"), envelope, 0o444); err != nil {
		return err
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, loadErr := loadManifestHistoryEntry(historyRoot, setName, publicKey)
		if loadErr != nil || !reflect.DeepEqual(existing, signed) {
			return fmt.Errorf("%w: manifest-history set conflict", ErrInvalidManifest)
		}
		if err := removeStage(stage); err != nil {
			return err
		}
	}
	committed = true
	return syncDirectory(historyRoot)
}

func loadManifestHistoryEntry(historyRoot, setName string, publicKey ed25519.PublicKey) (SignedManifest, error) {
	entryPath := filepath.Join(historyRoot, setName)
	info, err := os.Lstat(entryPath)
	details, metadataOK := infoSyscallStat(info)
	if err != nil || !metadataOK || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 || int(details.Uid) != os.Geteuid() {
		return SignedManifest{}, fmt.Errorf("%w: manifest-history directory", ErrUnsafePath)
	}
	entries, err := os.ReadDir(entryPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "signed-manifest.json" || !entries[0].Type().IsRegular() {
		return SignedManifest{}, fmt.Errorf("%w: manifest-history contents", ErrUnsafePath)
	}
	data, err := readPublishedManifest(filepath.Join(entryPath, "signed-manifest.json"))
	if err != nil {
		return SignedManifest{}, err
	}
	var signed SignedManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedManifest{}, fmt.Errorf("decode manifest history: %w", err)
	}
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil || !bytes.Equal(canonical, data) {
		return SignedManifest{}, fmt.Errorf("%w: manifest history is not canonical", ErrInvalidManifest)
	}
	if err := VerifyManifest(signed, publicKey); err != nil {
		return SignedManifest{}, err
	}
	if strings.TrimPrefix(signed.Manifest.SetID, "sha256:") != setName {
		return SignedManifest{}, fmt.Errorf("%w: manifest-history directory/set ID mismatch", ErrInvalidManifest)
	}
	return signed, nil
}

func lockPublish(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return nil, ErrUnsafePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrUnsafePath
	}
	var stat syscall.Stat_t
	var parent syscall.Stat_t
	if err := syscall.Stat(filepath.Dir(path), &parent); err != nil ||
		syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 ||
		stat.Mode&0o777 != 0o600 || stat.Size != 0 || stat.Uid != parent.Uid || stat.Gid != parent.Gid {
		file.Close()
		return nil, ErrUnsafePath
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func unlockPublish(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func makeTreeReadOnly(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return ErrUnsafePath
		}
		return os.Chmod(path, 0o444)
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		// files are read-only; directories retain owner write permission so an
		// explicit release-pruning workflow can remove a whole immutable set.
		// every read still verifies the signed content digest, so replacing a
		// path cannot turn modified bytes into a valid set.
		if err := os.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func removeStage(path string) error {
	_ = filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(current, 0o700)
		}
		return nil
	})
	return os.RemoveAll(path)
}

func canonicalRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: release root must be absolute", ErrUnsafePath)
	}
	clean := filepath.Clean(root)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: refusing filesystem root", ErrUnsafePath)
	}
	if err := checkReleaseRootCreation(clean); err != nil {
		return "", err
	}
	if err := ensureAbsoluteDirectory(clean, 0o755); err != nil {
		return "", err
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: release root is not a real directory", ErrUnsafePath)
	}
	if err := validateOwnedReleaseDirectory(clean); err != nil {
		return "", err
	}
	if err := validateReleasePathAncestors(clean); err != nil {
		return "", err
	}
	return clean, nil
}

func validateReleasePathAncestors(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafePath
	}
	defer func() { _ = syscall.Close(fd) }()
	var parent syscall.Stat_t
	if err := syscall.Fstat(fd, &parent); err != nil || !trustedReleaseAncestor(parent) {
		return fmt.Errorf("%w: filesystem root metadata", ErrUnsafePath)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrUnsafePath
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return fmt.Errorf("%w: release-root ancestor", ErrUnsafePath)
		}
		var child syscall.Stat_t
		if err := syscall.Fstat(next, &child); err != nil || !trustedReleaseAncestor(child) || parent.Mode&0o022 != 0 && parent.Mode&0o1000 == 0 {
			_ = syscall.Close(next)
			return fmt.Errorf("%w: release-root ancestor metadata", ErrUnsafePath)
		}
		if err := syscall.Close(fd); err != nil {
			_ = syscall.Close(next)
			return err
		}
		fd = next
		parent = child
	}
	return nil
}

func trustedReleaseAncestor(details syscall.Stat_t) bool {
	uid := int(details.Uid)
	return details.Mode&syscall.S_IFMT == syscall.S_IFDIR && (uid == 0 || uid == os.Geteuid())
}

func ensureReleaseRootIdentity(path string, expected syscall.Stat_t) error {
	current, err := validatePublishedDirectory(path)
	if err != nil || current.Dev != expected.Dev || current.Ino != expected.Ino || current.Mode != expected.Mode || current.Uid != expected.Uid || current.Gid != expected.Gid {
		return fmt.Errorf("%w: release root changed during publication", ErrUnsafePath)
	}
	return nil
}

func validateOwnedReleaseDirectory(path string) error {
	directory, details, err := openDirectoryNoFollow(path)
	if err != nil {
		return err
	}
	closeErr := directory.Close()
	if closeErr != nil || int(details.Uid) != os.Geteuid() || details.Mode&0o022 != 0 {
		return fmt.Errorf("%w: release directory must be owner-controlled", ErrUnsafePath)
	}
	return nil
}

func infoSyscallStat(info os.FileInfo) (syscall.Stat_t, bool) {
	if info == nil {
		return syscall.Stat_t{}, false
	}
	details, ok := info.Sys().(*syscall.Stat_t)
	if !ok || details == nil {
		return syscall.Stat_t{}, false
	}
	return *details, true
}

func ensureAbsoluteDirectory(path string, mode os.FileMode) error {
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		if err := ensureDirectory(current, mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureDirectory(path string, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrUnsafePath, path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil {
		// concurrent publishers may both observe a missing directory. treat the
		// winner's safe directory as success, but never accept a symlink or file.
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrUnsafePath, path)
		}
	}
	return nil
}

func copyVerified(source, target string, component Component) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	input, _, err := openRegularNoFollow(source)
	if err != nil {
		return fmt.Errorf("%w: unsafe source for %s", err, component.Artifact)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if syncErr := output.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := output.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return copyErr
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if size != component.Size || digest != component.Digest {
		return fmt.Errorf("%w: artifact changed while publishing %s", ErrArtifactTampered, component.Artifact)
	}
	return nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".write-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncTreeDirectories(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func activateCurrent(root, setName string) error {
	current := filepath.Join(root, "current")
	if info, err := os.Lstat(current); err == nil {
		if !singleLinkSymlink(info) {
			return fmt.Errorf("%w: current pointer is not a symlink", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(root, ".current-"+hex.EncodeToString(random))
	if err := os.Symlink(filepath.ToSlash(filepath.Join("sets", setName)), temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, current); err != nil {
		return err
	}
	return syncDirectory(root)
}

// Current loads and verifies the signed current manifest and every immutable
// artifact beneath the current pointer.
func Current(root string, publicKey ed25519.PublicKey) (SignedManifest, string, error) {
	root, err := existingRoot(root)
	if err != nil {
		return SignedManifest{}, "", err
	}
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if err != nil || !singleLinkSymlink(info) {
		return SignedManifest{}, "", fmt.Errorf("%w: missing or unsafe current pointer", ErrUnsafePath)
	}
	target, err := os.Readlink(current)
	if err != nil {
		return SignedManifest{}, "", err
	}
	if filepath.IsAbs(target) || filepath.ToSlash(filepath.Clean(target)) != target || !strings.HasPrefix(target, "sets/") {
		return SignedManifest{}, "", fmt.Errorf("%w: invalid current target", ErrUnsafePath)
	}
	setName := strings.TrimPrefix(target, "sets/")
	if !validPublishedSetName(setName) || target != "sets/"+setName {
		return SignedManifest{}, "", fmt.Errorf("%w: invalid current set name", ErrUnsafePath)
	}
	return loadPublishedSet(root, setName, publicKey)
}

func singleLinkSymlink(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	details, ok := info.Sys().(*syscall.Stat_t)
	return ok && details.Nlink == 1
}

// OpenSet loads and verifies one immutable published release by its signed set
// ID. it deliberately does not consult the mutable current pointer: an
// already-issued desired state remains installable while a newer release is
// activated for subsequent rollouts.
func OpenSet(root, setID string, publicKey ed25519.PublicKey) (SignedManifest, string, error) {
	root, err := existingRoot(root)
	if err != nil {
		return SignedManifest{}, "", err
	}
	if !strings.HasPrefix(setID, "sha256:") {
		return SignedManifest{}, "", fmt.Errorf("%w: invalid release set ID", ErrUnsafePath)
	}
	setName := strings.TrimPrefix(setID, "sha256:")
	if !validPublishedSetName(setName) || setID != "sha256:"+setName {
		return SignedManifest{}, "", fmt.Errorf("%w: invalid release set ID", ErrUnsafePath)
	}
	return loadPublishedSet(root, setName, publicKey)
}

func validPublishedSetName(setName string) bool {
	decoded, err := hex.DecodeString(setName)
	return err == nil && len(decoded) == sha256.Size && len(setName) == 64 && setName == strings.ToLower(setName)
}

func loadPublishedSet(root, setName string, publicKey ed25519.PublicKey) (SignedManifest, string, error) {
	setPath := filepath.Join(root, "sets", setName)
	if _, err := validatePublishedDirectory(filepath.Join(root, "sets")); err != nil {
		return SignedManifest{}, "", fmt.Errorf("%w: immutable sets directory", ErrUnsafePath)
	}
	if _, err := validatePublishedDirectory(setPath); err != nil {
		return SignedManifest{}, "", fmt.Errorf("%w: immutable set directory", ErrUnsafePath)
	}
	manifestPath := filepath.Join(setPath, "signed-manifest.json")
	data, err := readPublishedManifest(manifestPath)
	if err != nil {
		return SignedManifest{}, "", err
	}
	var signed SignedManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedManifest{}, "", fmt.Errorf("decode signed manifest: %w", err)
	}
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil || !bytes.Equal(canonical, data) {
		return SignedManifest{}, "", fmt.Errorf("%w: signed manifest file is not canonical", ErrInvalidManifest)
	}
	if err := VerifyManifest(signed, publicKey); err != nil {
		return SignedManifest{}, "", err
	}
	if strings.TrimPrefix(signed.Manifest.SetID, "sha256:") != setName {
		return SignedManifest{}, "", fmt.Errorf("%w: immutable directory/set ID mismatch", ErrInvalidManifest)
	}
	if err := validatePublishedArtifactDirectories(setPath, signed.Manifest); err != nil {
		return SignedManifest{}, "", err
	}
	if err := verifyPublishedArtifacts(setPath, signed.Manifest); err != nil {
		return SignedManifest{}, "", err
	}
	return signed, setPath, nil
}

func readPublishedManifest(path string) ([]byte, error) {
	file, details, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("%w: signed manifest is unsafe", ErrUnsafePath)
	}
	defer file.Close()
	if details.Mode&0o777 != 0o444 || int(details.Uid) != os.Geteuid() || details.Size <= 0 || details.Size > MaxManifestEnvelopeBytes {
		return nil, fmt.Errorf("%w: signed manifest metadata is unsafe", ErrUnsafePath)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxManifestEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != details.Size || len(data) > MaxManifestEnvelopeBytes {
		return nil, fmt.Errorf("%w: signed manifest changed while reading", ErrUnsafePath)
	}
	return data, nil
}

func existingRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: release root must be absolute", ErrUnsafePath)
	}
	clean := filepath.Clean(root)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: refusing filesystem root", ErrUnsafePath)
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: release root path is missing or unsafe", ErrUnsafePath)
		}
	}
	if _, err := validatePublishedDirectory(clean); err != nil {
		return "", err
	}
	if err := validateReleasePathAncestors(clean); err != nil {
		return "", err
	}
	return clean, nil
}

func validatePublishedDirectory(path string) (syscall.Stat_t, error) {
	directory, details, err := openDirectoryNoFollow(path)
	if err != nil {
		return syscall.Stat_t{}, err
	}
	closeErr := directory.Close()
	if closeErr != nil || !secureImmutableDirectory(details) {
		return syscall.Stat_t{}, fmt.Errorf("%w: published directory must be owner-controlled", ErrUnsafePath)
	}
	return details, nil
}

func validatePublishedArtifactDirectories(setPath string, manifest Manifest) error {
	artifactsRoot := filepath.Join(setPath, "artifacts")
	if _, err := validatePublishedDirectory(artifactsRoot); err != nil {
		return fmt.Errorf("%w: published artifacts directory", ErrUnsafePath)
	}
	seen := make(map[string]struct{})
	for _, component := range manifest.Components {
		parts := strings.Split(component.Artifact, "/")
		current := artifactsRoot
		for _, part := range parts[:len(parts)-1] {
			current = filepath.Join(current, part)
			if _, exists := seen[current]; exists {
				continue
			}
			if _, err := validatePublishedDirectory(current); err != nil {
				return fmt.Errorf("%w: published artifact ancestor %s", ErrUnsafePath, component.Artifact)
			}
			seen[current] = struct{}{}
		}
	}
	return nil
}

func verifyPublishedArtifacts(setPath string, manifest Manifest) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	for _, component := range manifest.Components {
		path := filepath.Join(setPath, "artifacts", filepath.FromSlash(component.Artifact))
		file, details, err := openRegularNoFollow(path)
		if err != nil {
			return fmt.Errorf("%w: published artifact %s", ErrUnsafePath, component.Artifact)
		}
		if details.Mode&0o777 != 0o444 {
			file.Close()
			return fmt.Errorf("%w: published artifact metadata %s", ErrUnsafePath, component.Artifact)
		}
		if int(details.Uid) != os.Geteuid() {
			file.Close()
			return fmt.Errorf("%w: published artifact owner %s", ErrUnsafePath, component.Artifact)
		}
		if details.Size != component.Size {
			file.Close()
			return fmt.Errorf("%w: published artifact size %s", ErrArtifactTampered, component.Artifact)
		}
		digest, size, hashErr := hashOpenFile(file)
		closeErr := file.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		if size != component.Size || digest != component.Digest {
			return fmt.Errorf("%w: %s", ErrArtifactTampered, component.Artifact)
		}
	}
	return nil
}
