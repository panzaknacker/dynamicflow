package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"dynamicflow/internal/signing"
)

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
