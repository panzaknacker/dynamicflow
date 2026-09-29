package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"dynamicflow/internal/signing"
)

func TestReleaseBundleDeterministicRoundTripAndTamperRejection(t *testing.T) {
	signed, paths, public := bundleFixture(t)
	var first, second bytes.Buffer
	firstSize, firstDigest, err := WriteBundle(&first, signed, paths, public)
	if err != nil {
		t.Fatal(err)
	}
	secondSize, secondDigest, err := WriteBundle(&second, signed, paths, public)
	if err != nil {
		t.Fatal(err)
	}
	if firstSize != secondSize || firstDigest != secondDigest || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("identical inputs did not produce an identical release bundle")
	}
	expectedSize, err := BundleSize(signed)
	if err != nil || expectedSize != firstSize {
		t.Fatalf("BundleSize=%d err=%v, wrote %d", expectedSize, err, firstSize)
	}
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	decoded, decodedPaths, decodedSize, decodedDigest, err := ReadBundle(bytes.NewReader(first.Bytes()), stage, public)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Manifest.SetID != signed.Manifest.SetID || decodedSize != firstSize || decodedDigest != firstDigest || len(decodedPaths) != len(paths) {
		t.Fatalf("unexpected round trip: set=%s size=%d digest=%s paths=%d", decoded.Manifest.SetID, decodedSize, decodedDigest, len(decodedPaths))
	}
	if err := VerifyArtifacts(decoded.Manifest, decodedPaths); err != nil {
		t.Fatalf("extracted artifact verification: %v", err)
	}

	tampered := append([]byte(nil), first.Bytes()...)
	tampered[len(tampered)-1] ^= 0xff
	tamperedStage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(tamperedStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ReadBundle(bytes.NewReader(tampered), tamperedStage, public); err == nil {
		t.Fatal("tampered artifact was accepted")
	}

	trailing := append(append([]byte(nil), first.Bytes()...), 0)
	trailingStage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(trailingStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ReadBundle(bytes.NewReader(trailing), trailingStage, public); err == nil {
		t.Fatal("trailing bundle data was accepted")
	}
}

func TestReleaseBundleRejectsSymlinkSourceAndWrongKey(t *testing.T) {
	signed, paths, public := bundleFixture(t)
	for logical, path := range paths {
		link := filepath.Join(t.TempDir(), "artifact-link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		unsafe := make(map[string]string, len(paths))
		for name, source := range paths {
			unsafe[name] = source
		}
		unsafe[logical] = link
		if _, _, err := WriteBundle(&bytes.Buffer{}, signed, unsafe, public); err == nil {
			t.Fatal("symlinked artifact source was accepted")
		}
		break
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteBundle(&bytes.Buffer{}, signed, paths, wrongPublic); err == nil {
		t.Fatal("manifest signed by another key was accepted")
	}
}

func TestReleaseBundleRejectsHardlinkAndSymlinkAncestorSource(t *testing.T) {
	signed, paths, public := bundleFixture(t)
	for logical, path := range paths {
		hardlink := filepath.Join(filepath.Dir(path), "hardlink")
		if err := os.Link(path, hardlink); err != nil {
			t.Fatal(err)
		}
		if _, _, err := WriteBundle(&bytes.Buffer{}, signed, paths, public); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("hardlinked source: got %v, want ErrUnsafePath", err)
		}
		if err := os.Remove(hardlink); err != nil {
			t.Fatal(err)
		}
		realDirectory := filepath.Dir(path)
		linkedDirectory := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		unsafe := make(map[string]string, len(paths))
		for name, source := range paths {
			unsafe[name] = source
		}
		unsafe[logical] = filepath.Join(linkedDirectory, filepath.Base(path))
		if _, _, err := WriteBundle(&bytes.Buffer{}, signed, unsafe, public); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("symlink ancestor source: got %v, want ErrUnsafePath", err)
		}
		break
	}
}

func TestReleaseBundleRejectsPrepositionedTargetSymlink(t *testing.T) {
	signed, paths, public := bundleFixture(t)
	var bundle bytes.Buffer
	if _, _, err := WriteBundle(&bundle, signed, paths, public); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(stage, "artifacts")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ReadBundle(bytes.NewReader(bundle.Bytes()), stage, public); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("prepositioned target symlink: got %v, want ErrUnsafePath", err)
	}
}

func TestReleaseArtifactsExcludePlainAndCompressedPrivateKeys(t *testing.T) {
	for _, test := range []struct {
		name string
		data func(*testing.T) []byte
	}{
		{"plain", func(t *testing.T) []byte { return []byte("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nsecret\n") }},
		{"tar-gzip", privateKeyArchive},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact.tar.gz")
			if err := os.WriteFile(path, test.data(t), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := BuildFromArtifacts(1, []ArtifactInput{{
				Component: "ssh", Version: "v1.2.3", Target: "any", ArtifactName: "ssh.tar.gz", SourcePath: path,
			}}, []Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
			if !errors.Is(err, ErrPrivateKey) {
				t.Fatalf("private-key artifact: got %v, want ErrPrivateKey", err)
			}
		})
	}
}

func TestReadBundleRejectsPrivateKeyEvenWithValidReleaseSignature(t *testing.T) {
	privateMaterial := []byte("-----BEGIN " + "PRIVATE KEY-----\nsecret\n")
	digest := sha256.Sum256(privateMaterial)
	manifest := normalize(Manifest{
		Schema: SchemaVersion, Generation: 1,
		Components: []Component{{
			Name: "ssh", Version: "v1.2.3", Target: "any", Artifact: "ssh/v1.2.3/any/ssh.tar.gz",
			Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(privateMaterial)),
		}},
		Profiles: []Profile{{Name: "ssh", Components: []string{"ssh"}}},
	})
	manifest.SetID, _ = ComputeSetID(manifest)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifest(manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signing.CanonicalJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	body.Write(bundleMagic)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(envelope)))
	body.Write(length[:])
	body.Write(envelope)
	body.Write(privateMaterial)
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ReadBundle(bytes.NewReader(body.Bytes()), stage, public); !errors.Is(err, ErrPrivateKey) {
		t.Fatalf("validly signed private-key bundle: got %v, want ErrPrivateKey", err)
	}
}

func privateKeyArchive(t *testing.T) []byte {
	t.Helper()
	var result bytes.Buffer
	compressed := gzip.NewWriter(&result)
	archive := tar.NewWriter(compressed)
	data := []byte("-----BEGIN " + "PRIVATE KEY-----\nsecret\n")
	if err := archive.WriteHeader(&tar.Header{Name: "keys/operator.pem", Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func bundleFixture(t *testing.T) (SignedManifest, map[string]string, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	first := filepath.Join(root, "one.bin")
	second := filepath.Join(root, "two.bin")
	if err := os.WriteFile(first, []byte("first immutable artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, bytes.Repeat([]byte{0x42}, 4097), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildFromArtifacts(9, []ArtifactInput{
		{Component: "flow", Version: "v1.2.3", Target: "linux-amd64", ArtifactName: "flow", SourcePath: first},
		{Component: "ssh", Version: "v1.2.3", Target: "any", ArtifactName: "ssh.tar.gz", SourcePath: second},
	}, []Profile{{Name: "ssh", Components: []string{"ssh"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifest(manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, component := range signed.Manifest.Components {
		switch component.Name {
		case "flow":
			paths[component.Artifact] = first
		case "ssh":
			paths[component.Artifact] = second
		}
	}
	return signed, paths, public
}
