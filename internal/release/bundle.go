package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"dynamicflow/internal/signing"
)

// BundleMediaType identifies the deterministic streaming release transport.
// the bundle is deliberately not an archive: paths come exclusively from the
// verified manifest and artifact bytes follow in canonical manifest order.
const BundleMediaType = "application/vnd.dynamicflow.release-bundle"

var bundleMagic = []byte("DYNAMICFLOW-RS1\n")

// BundleSize returns the exact wire size without reading artifact bytes.
func BundleSize(signed SignedManifest) (int64, error) {
	if err := Validate(signed.Manifest); err != nil {
		return 0, err
	}
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil || len(envelope) == 0 || len(envelope) > MaxManifestEnvelopeBytes {
		return 0, fmt.Errorf("%w: invalid bundle manifest", ErrInvalidManifest)
	}
	size := int64(len(bundleMagic) + 4 + len(envelope))
	for _, component := range signed.Manifest.Components {
		if component.Size <= 0 || size > int64(^uint64(0)>>1)-component.Size {
			return 0, fmt.Errorf("%w: bundle size overflow", ErrInvalidManifest)
		}
		size += component.Size
		if size > MaxBundleBytes {
			return 0, fmt.Errorf("%w: bundle exceeds maximum size", ErrInvalidManifest)
		}
	}
	return size, nil
}

// WriteBundle verifies and streams a deterministic signed release bundle. the
// returned digest authenticates the exact HTTP body used by remote publish.
func WriteBundle(destination io.Writer, signed SignedManifest, artifactPaths map[string]string, publicKey ed25519.PublicKey) (int64, string, error) {
	if destination == nil || len(artifactPaths) != len(signed.Manifest.Components) {
		return 0, "", fmt.Errorf("%w: invalid bundle destination or artifact map", ErrInvalidManifest)
	}
	if err := VerifyManifest(signed, publicKey); err != nil {
		return 0, "", err
	}
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil || len(envelope) == 0 || len(envelope) > MaxManifestEnvelopeBytes {
		return 0, "", fmt.Errorf("%w: invalid bundle manifest", ErrInvalidManifest)
	}
	hash := sha256.New()
	counter := &countingWriter{writer: io.MultiWriter(destination, hash)}
	if err := writeBundleBytes(counter, bundleMagic); err != nil {
		return counter.count, "", err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(envelope)))
	if err := writeBundleBytes(counter, length[:]); err != nil {
		return counter.count, "", err
	}
	if err := writeBundleBytes(counter, envelope); err != nil {
		return counter.count, "", err
	}
	for _, component := range signed.Manifest.Components {
		path, exists := artifactPaths[component.Artifact]
		if !exists {
			return counter.count, "", fmt.Errorf("%w: missing %s", ErrInvalidManifest, component.Artifact)
		}
		file, err := openBundleSource(path, component.Size)
		if err != nil {
			return counter.count, "", err
		}
		if err := inspectCompressedArtifact(file); err != nil {
			file.Close()
			return counter.count, "", err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return counter.count, "", err
		}
		directDetector := &privateKeyDetector{}
		artifactHash := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(counter, artifactHash, directDetector), file, component.Size)
		var extra [1]byte
		extraCount, extraErr := file.Read(extra[:])
		closeErr := file.Close()
		if copyErr != nil || written != component.Size || extraCount != 0 || !errors.Is(extraErr, io.EOF) {
			return counter.count, "", fmt.Errorf("%w: artifact changed while bundling %s", ErrArtifactTampered, component.Artifact)
		}
		if directDetector.found {
			return counter.count, "", ErrPrivateKey
		}
		if closeErr != nil {
			return counter.count, "", closeErr
		}
		digest := "sha256:" + hex.EncodeToString(artifactHash.Sum(nil))
		if digest != component.Digest {
			return counter.count, "", fmt.Errorf("%w: %s", ErrArtifactTampered, component.Artifact)
		}
	}
	expectedSize, err := BundleSize(signed)
	if err != nil || counter.count != expectedSize {
		return counter.count, "", fmt.Errorf("%w: bundle size mismatch", ErrInvalidManifest)
	}
	return counter.count, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// ReadBundle streams one bundle into a fresh private staging directory. it
// returns only verified regular-file paths suitable for publish.
func ReadBundle(source io.Reader, stagingDirectory string, publicKey ed25519.PublicKey) (SignedManifest, map[string]string, int64, string, error) {
	var signed SignedManifest
	if source == nil || !filepath.IsAbs(stagingDirectory) {
		return signed, nil, 0, "", fmt.Errorf("%w: invalid bundle source or staging path", ErrUnsafePath)
	}
	staging, stagingDetails, err := openDirectoryNoFollow(stagingDirectory)
	if err != nil || stagingDetails.Mode&0o777 != 0o700 || int(stagingDetails.Uid) != os.Geteuid() {
		if staging != nil {
			staging.Close()
		}
		return signed, nil, 0, "", fmt.Errorf("%w: staging directory is not private", ErrUnsafePath)
	}
	defer staging.Close()
	hash := sha256.New()
	counter := &countingReader{reader: io.TeeReader(source, hash)}
	magic := make([]byte, len(bundleMagic))
	if _, err := io.ReadFull(counter, magic); err != nil || !bytes.Equal(magic, bundleMagic) {
		return signed, nil, counter.count, "", fmt.Errorf("%w: invalid bundle magic", ErrInvalidManifest)
	}
	var length [4]byte
	if _, err := io.ReadFull(counter, length[:]); err != nil {
		return signed, nil, counter.count, "", fmt.Errorf("%w: truncated bundle manifest", ErrInvalidManifest)
	}
	manifestLength := int(binary.BigEndian.Uint32(length[:]))
	if manifestLength <= 0 || manifestLength > MaxManifestEnvelopeBytes {
		return signed, nil, counter.count, "", fmt.Errorf("%w: invalid bundle manifest length", ErrInvalidManifest)
	}
	envelope := make([]byte, manifestLength)
	if _, err := io.ReadFull(counter, envelope); err != nil {
		return signed, nil, counter.count, "", fmt.Errorf("%w: truncated bundle manifest", ErrInvalidManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: invalid signed bundle manifest", ErrInvalidManifest)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: trailing manifest data", ErrInvalidManifest)
	}
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil || !bytes.Equal(canonical, envelope) || VerifyManifest(signed, publicKey) != nil {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: bundle manifest verification failed", ErrInvalidManifest)
	}
	if _, err := BundleSize(signed); err != nil {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: invalid bundle bounds", ErrInvalidManifest)
	}
	paths := make(map[string]string, len(signed.Manifest.Components))
	for _, component := range signed.Manifest.Components {
		target, err := createBundleTarget(int(staging.Fd()), stagingDirectory, stagingDetails, component.Artifact)
		if err != nil {
			return SignedManifest{}, nil, counter.count, "", err
		}
		artifactHash := sha256.New()
		directDetector := &privateKeyDetector{}
		written, copyErr := io.CopyN(io.MultiWriter(target, artifactHash, directDetector), counter, component.Size)
		if copyErr == nil && directDetector.found {
			copyErr = ErrPrivateKey
		}
		if syncErr := target.Sync(); copyErr == nil {
			copyErr = syncErr
		}
		if copyErr == nil {
			copyErr = inspectCompressedArtifact(target)
		}
		if closeErr := target.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if errors.Is(copyErr, ErrPrivateKey) {
			return SignedManifest{}, nil, counter.count, "", ErrPrivateKey
		}
		if copyErr != nil || written != component.Size {
			return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: truncated artifact %s", ErrArtifactTampered, component.Artifact)
		}
		digest := "sha256:" + hex.EncodeToString(artifactHash.Sum(nil))
		if digest != component.Digest {
			return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: %s", ErrArtifactTampered, component.Artifact)
		}
		paths[component.Artifact] = filepath.Join(stagingDirectory, "artifacts", filepath.FromSlash(component.Artifact))
	}
	var extra [1]byte
	if count, err := counter.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: trailing bundle bytes", ErrInvalidManifest)
	}
	expectedSize, err := BundleSize(signed)
	if err != nil || counter.count != expectedSize {
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: bundle size mismatch", ErrInvalidManifest)
	}
	canonicalStage, canonicalDetails, err := openDirectoryNoFollow(stagingDirectory)
	if err != nil || canonicalDetails.Dev != stagingDetails.Dev || canonicalDetails.Ino != stagingDetails.Ino ||
		canonicalDetails.Mode&0o777 != 0o700 || canonicalDetails.Uid != stagingDetails.Uid || canonicalDetails.Gid != stagingDetails.Gid {
		if canonicalStage != nil {
			canonicalStage.Close()
		}
		return SignedManifest{}, nil, counter.count, "", fmt.Errorf("%w: staging directory changed during import", ErrUnsafePath)
	}
	canonicalStage.Close()
	if err := VerifyArtifacts(signed.Manifest, paths); err != nil {
		return SignedManifest{}, nil, counter.count, "", err
	}
	return signed, paths, counter.count, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

type countingWriter struct {
	writer io.Writer
	count  int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.count += int64(written)
	return written, err
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (reader *countingReader) Read(data []byte) (int, error) {
	read, err := reader.reader.Read(data)
	reader.count += int64(read)
	return read, err
}

func writeBundleBytes(writer io.Writer, data []byte) error {
	_, err := io.Copy(writer, bytes.NewReader(data))
	return err
}

func openBundleSource(path string, expectedSize int64) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: bundle source path must be absolute", ErrUnsafePath)
	}
	file, details, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open bundle source", ErrUnsafePath)
	}
	if details.Size != expectedSize {
		file.Close()
		return nil, fmt.Errorf("%w: unsafe bundle source", ErrUnsafePath)
	}
	return file, nil
}

func createBundleTarget(rootFD int, root string, rootDetails syscall.Stat_t, logical string) (*os.File, error) {
	currentFD, err := ensureBundleDirectoryAt(rootFD, "artifacts", rootDetails)
	if err != nil {
		return nil, err
	}
	current := filepath.Join(root, "artifacts")
	parts := bytes.Split([]byte(logical), []byte{'/'})
	for _, raw := range parts[:len(parts)-1] {
		nextFD, openErr := ensureBundleDirectoryAt(currentFD, string(raw), rootDetails)
		_ = syscall.Close(currentFD)
		if openErr != nil {
			return nil, openErr
		}
		currentFD = nextFD
		current = filepath.Join(current, string(raw))
	}
	name := string(parts[len(parts)-1])
	target := filepath.Join(current, name)
	fd, err := syscall.Openat(currentFD, name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	_ = syscall.Close(currentFD)
	if err != nil {
		return nil, fmt.Errorf("%w: create bundle target", ErrUnsafePath)
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG || details.Nlink != 1 ||
		details.Mode&0o777 != 0o600 || details.Uid != rootDetails.Uid || details.Gid != rootDetails.Gid {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: unsafe bundle target", ErrUnsafePath)
	}
	file := os.NewFile(uintptr(fd), target)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafePath
	}
	return file, nil
}

func ensureBundleDirectoryAt(parentFD int, name string, root syscall.Stat_t) (int, error) {
	if !safeName(name) {
		return -1, fmt.Errorf("%w: invalid bundle directory", ErrUnsafePath)
	}
	if err := syscall.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, err
	}
	fd, err := syscall.Openat(parentFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: open bundle directory", ErrUnsafePath)
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		details.Mode&0o777 != 0o700 || details.Uid != root.Uid || details.Gid != root.Gid {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("%w: unsafe bundle directory", ErrUnsafePath)
	}
	return fd, nil
}
