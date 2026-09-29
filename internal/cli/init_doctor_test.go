package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitIsIdempotentAndPreservesTrustRoots(t *testing.T) {
	home := privateTempDir(t)
	arguments := []string{"--json", "--home", home, "--source-root", repositoryRoot(t), "init"}
	status, stdout, stderr := invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("first init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	firstEnvelope := decodeCLIEnvelope(t, stdout)
	var first initResult
	if err := json.Unmarshal(firstEnvelope.Data, &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Created) != 4 || len(first.Existing) != 0 {
		t.Fatalf("first init result = %+v", first)
	}

	privatePaths := []string{
		filepath.Join(home, "keys", "signing", "release.private.pem"),
		filepath.Join(home, "keys", "signing", "desired-state.private.pem"),
		filepath.Join(home, "keys", "signing", "control.private.pem"),
	}
	privateBefore := make(map[string][]byte, len(privatePaths))
	for _, path := range privatePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		privateBefore[path] = data
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("private signing key mode = %04o", info.Mode().Perm())
		}
	}

	status, stdout, stderr = invokeCLI(t, arguments...)
	if status != exitOK || stderr != "" {
		t.Fatalf("second init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	secondEnvelope := decodeCLIEnvelope(t, stdout)
	var second initResult
	if err := json.Unmarshal(secondEnvelope.Data, &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Created) != 0 || len(second.Existing) != 4 {
		t.Fatalf("second init result = %+v", second)
	}
	if first.ReleaseSignerID != second.ReleaseSignerID || first.DesiredSignerID != second.DesiredSignerID || first.ControlKeyID != second.ControlKeyID {
		t.Fatal("idempotent init replaced a trust root")
	}
	for path, before := range privateBefore {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("idempotent init changed %s", path)
		}
	}
	audit, err := os.ReadFile(filepath.Join(home, "logs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(string(audit)), "\n") + 1; lines != 2 {
		t.Fatalf("audit has %d records, want 2", lines)
	}
}

func TestDoctorReportsMissingTrustRootsAsJSON(t *testing.T) {
	home := privateTempDir(t)
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "--source-root", repositoryRoot(t), "doctor")
	if status != exitConfig || stdout != "" {
		t.Fatalf("doctor status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.Error == nil || envelope.Error.Code != "doctor_failed" || envelope.Error.Next == "" {
		t.Fatalf("doctor failure = %+v", envelope)
	}
	if envelope.Command != "doctor" || len(envelope.Data) == 0 {
		t.Fatalf("doctor failure omitted structured diagnostics: %+v", envelope)
	}
	var result struct {
		Healthy bool          `json:"healthy"`
		Checks  []doctorCheck `json:"checks"`
		Home    string        `json:"home"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Healthy || result.Home != home || len(result.Checks) == 0 {
		t.Fatalf("doctor failure diagnostics = %+v", result)
	}
	failures := 0
	for _, check := range result.Checks {
		if !check.OK {
			failures++
		}
	}
	if failures == 0 {
		t.Fatal("doctor failure contained no failed check")
	}
}

func TestDoctorPassesAfterInit(t *testing.T) {
	for _, tool := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is unavailable", tool)
		}
	}
	home := privateTempDir(t)
	root := repositoryRoot(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", root, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "--source-root", root, "doctor")
	if status != exitOK || stderr != "" {
		t.Fatalf("doctor status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "doctor" {
		t.Fatalf("doctor envelope = %+v", envelope)
	}
	var result struct {
		Healthy bool          `json:"healthy"`
		Checks  []doctorCheck `json:"checks"`
	}
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Healthy || len(result.Checks) < 5 {
		t.Fatalf("doctor result = %+v", result)
	}
	names := make(map[string]bool, len(result.Checks))
	for _, check := range result.Checks {
		names[check.Name] = check.OK
	}
	for _, required := range []string{
		"tool:ssh", "tool:ssh-keygen", "signing:release.public.pem",
		"signing:desired-state.public.pem", "profiles",
		"signing:control.public.pem", "signing:key-separation",
	} {
		if !names[required] {
			t.Errorf("doctor did not pass required check %q", required)
		}
	}
}

func TestInitAndDoctorRejectSharedSigningRootsWithoutReplacingThem(t *testing.T) {
	home := privateTempDir(t)
	root := repositoryRoot(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", root, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}

	releasePrivate := filepath.Join(home, "keys", "signing", "release.private.pem")
	releasePublic := filepath.Join(home, "keys", "signing", "release.public.pem")
	desiredPrivate := filepath.Join(home, "keys", "signing", "desired-state.private.pem")
	desiredPublic := filepath.Join(home, "keys", "signing", "desired-state.public.pem")
	for _, item := range []struct {
		source string
		target string
		mode   os.FileMode
	}{
		{releasePrivate, desiredPrivate, 0o600},
		{releasePublic, desiredPublic, 0o644},
	} {
		data, err := os.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.target, data, item.mode); err != nil {
			t.Fatal(err)
		}
	}
	sharedPrivateBefore, err := os.ReadFile(desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}

	status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "--source-root", root, "init")
	if status != exitVerify || stdout != "" {
		t.Fatalf("shared-root init status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.Error == nil || envelope.Error.Code != "verify" || !strings.Contains(envelope.Error.Message, "share one Ed25519 root") {
		t.Fatalf("shared-root init error = %+v", envelope.Error)
	}
	sharedPrivateAfter, err := os.ReadFile(desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedPrivateBefore, sharedPrivateAfter) {
		t.Fatal("failed init replaced an existing shared signing root")
	}

	status, stdout, stderr = invokeCLI(t, "--home", home, "--source-root", root, "doctor")
	if status != exitConfig || stderr != "" {
		t.Fatalf("shared-root doctor status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if !strings.Contains(stdout, "FAIL  signing:key-separation") || !strings.Contains(stdout, "share one Ed25519 root") {
		t.Fatalf("doctor did not expose signing-root collision: %q", stdout)
	}
}
