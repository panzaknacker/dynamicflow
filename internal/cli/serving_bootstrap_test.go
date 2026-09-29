package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/release"
	"dynamicflow/internal/tlsutil"
)

func TestServingBootstrapBindsAdminUserOnlyFromLocalSUDOUser(t *testing.T) {
	directory := privateTempDir(t)
	certPath := filepath.Join(directory, "serving.crt")
	keyPath := filepath.Join(directory, "serving.key")
	if _, err := tlsutil.GenerateSelfSigned(certPath, keyPath, []string{"127.0.0.1"}, time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	releaseKeyPath := filepath.Join(directory, "release.public.pem")
	desiredKeyPath := filepath.Join(directory, "desired.public.pem")
	for _, path := range []string{releaseKeyPath, desiredKeyPath} {
		if err := os.WriteFile(path, []byte("public-test-trust\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := release.SignedManifest{Manifest: release.Manifest{Components: []release.Component{
		{Name: "flow", Version: "v0.2.0", Target: "linux-amd64", Artifact: "flow/v0.2.0/linux-amd64/flow", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1},
		{Name: "flow", Version: "v0.2.0", Target: "linux-arm64", Artifact: "flow/v0.2.0/linux-arm64/flow", Digest: "sha256:" + strings.Repeat("b", 64), Size: 1},
	}}}
	script, err := buildBootstrap("https://serving.example.test:8443", manifest, certPath, releaseKeyPath, desiredKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"admin_user=${SUDO_USER:-}",
		"''|root|malwarelab",
		"--admin-user \"$admin_user\"",
		"instance-runtime enroll",
		"run_enrollment </dev/tty",
		"cleanup\ntrap - EXIT HUP INT TERM",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("bootstrap missing %q", required)
		}
	}
	for _, forbidden := range []string{"--secret", "--enrollment-id", "DYNAMICFLOW_ADMIN_USER"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("bootstrap contains forbidden argument source %q", forbidden)
		}
	}
	check := exec.Command("sh", "-n")
	check.Stdin = bytes.NewReader(script)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap shell syntax: %v: %s", err, output)
	}
	scriptPath := filepath.Join(directory, "bootstrap.sh")
	if err := os.WriteFile(scriptPath, script, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := exec.Command("env", "-i", "PATH=/usr/bin:/bin", "sh", scriptPath)
	output, err := missing.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "Run bootstrap through sudo") {
		t.Fatalf("direct-root bootstrap did not require a local admin user: err=%v output=%q", err, output)
	}
}
