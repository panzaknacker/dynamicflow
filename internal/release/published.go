package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"dynamicflow/internal/signing"
)

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
