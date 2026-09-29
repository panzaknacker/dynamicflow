package tlsutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndValidatePair(t *testing.T) {
	directory := t.TempDir()
	cert := filepath.Join(directory, "serving.crt")
	key := filepath.Join(directory, "serving.key")
	fingerprint, err := GenerateSelfSigned(cert, key, []string{"127.0.0.1", "serving.internal"}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
	if err := ValidatePair(cert, key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v, %v", info, err)
	}
	if _, err := GenerateSelfSigned(cert, key, []string{"127.0.0.1"}, time.Now()); err == nil {
		t.Fatal("existing identity was overwritten")
	}
}
