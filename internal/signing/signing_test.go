package signing

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateFilesPKCS8AndModes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "operator.pem")
	publicPath := filepath.Join(directory, "operator.pub.pem")
	generatedPublic, err := GenerateFiles(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := privateInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("private mode = %o, want 600", got)
	}
	publicInfo, err := os.Stat(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := publicInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("public mode = %o, want 644", got)
	}
	privateKey, err := LoadPrivateFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := LoadPublicFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !generatedPublic.Equal(loadedPublic) || !privateKey.Public().(ed25519.PublicKey).Equal(loadedPublic) {
		t.Fatal("generated, private-derived and loaded public keys differ")
	}
	if _, err := GenerateFiles(privatePath, filepath.Join(directory, "second.pub")); err == nil {
		t.Fatal("existing private key was overwritten")
	}
}

func TestPrivateFileRejectsModeAndSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "operator.pem")
	publicPath := filepath.Join(directory, "operator.pub.pem")
	if _, err := GenerateFiles(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFile(privatePath); !errors.Is(err, ErrUnsafeKeyFile) {
		t.Fatalf("mode error = %v, want ErrUnsafeKeyFile", err)
	}
	link := filepath.Join(directory, "link.pem")
	if err := os.Symlink(privatePath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFile(link); !errors.Is(err, ErrUnsafeKeyFile) {
		t.Fatalf("symlink error = %v, want ErrUnsafeKeyFile", err)
	}
}

func TestGenerateFilesRejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()
	realDirectory := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	_, err := GenerateFiles(filepath.Join(link, "operator.pem"), filepath.Join(link, "operator.pub.pem"))
	if !errors.Is(err, ErrUnsafeKeyFile) {
		t.Fatalf("symlinked key directory: got %v, want ErrUnsafeKeyFile", err)
	}
}

func TestCanonicalSignatureBindsDomainAndValue(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	valueA := map[string]any{"z": 2, "a": []string{"one", "two"}}
	valueB := map[string]any{"a": []string{"one", "two"}, "z": 2}
	signature, err := SignCanonical(privateKey, "test/value", valueA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonical(publicKey, "test/value", valueB, signature); err != nil {
		t.Fatalf("equivalent canonical value did not verify: %v", err)
	}
	if err := VerifyCanonical(publicKey, "test/other", valueB, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-domain error = %v", err)
	}
	valueB["z"] = 3
	if err := VerifyCanonical(publicKey, "test/value", valueB, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tamper error = %v", err)
	}
	otherPublic, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonical(otherPublic, "test/value", valueA, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-key error = %v", err)
	}
}

func TestCanonicalJSONRejectsFloatingPoint(t *testing.T) {
	t.Parallel()
	if _, err := CanonicalJSON(map[string]any{"fraction": 1.5}); err == nil {
		t.Fatal("floating point value was accepted")
	}
}
