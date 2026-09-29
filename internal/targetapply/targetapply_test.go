package targetapply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/applyplan"
	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/profiles"
	"dynamicflow/internal/reconcile"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

func testPlan(t *testing.T, profileName string) applyplan.Plan {
	t.Helper()
	registry, err := profiles.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("targetapply supports only amd64/arm64")
	}
	components := []release.ArtifactInput{}
	for _, definition := range []struct{ name, target string }{
		{"flow", "linux-" + runtime.GOARCH},
		{"ssh", "any"}, {"vpn", "any"}, {"pbp", "linux-" + runtime.GOARCH},
		{"decepticon", "any"}, {"examstation", "any"},
	} {
		artifactName := definition.name + ".tar.gz"
		mode := os.FileMode(0o600)
		if definition.name == "flow" {
			artifactName = "flow"
			mode = 0o755
		}
		path := filepath.Join(directory, definition.name+"-"+definition.target)
		if err := os.WriteFile(path, []byte(definition.name+definition.target), mode); err != nil {
			t.Fatal(err)
		}
		components = append(components, release.ArtifactInput{Component: definition.name, Version: "v1.0.0", Target: definition.target, ArtifactName: artifactName, SourcePath: path})
	}
	declarations := registry.List(true)
	manifestProfiles := make([]release.Profile, 0, len(declarations))
	for _, declaration := range declarations {
		manifestProfiles = append(manifestProfiles, release.Profile{Name: declaration.Name, DependsOn: declaration.DependsOn, Components: declaration.Components})
	}
	manifest, err := release.BuildFromArtifacts(1, components, manifestProfiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate, _ := ed25519.GenerateKey(rand.Reader)
	desiredPublic, desiredPrivate, _ := ed25519.GenerateKey(rand.Reader)
	sshPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	sshBlob := make([]byte, 4+len("ssh-ed25519")+4+len(sshPublic))
	binary.BigEndian.PutUint32(sshBlob[0:4], uint32(len("ssh-ed25519")))
	copy(sshBlob[4:], "ssh-ed25519")
	offset := 4 + len("ssh-ed25519")
	binary.BigEndian.PutUint32(sshBlob[offset:offset+4], uint32(len(sshPublic)))
	copy(sshBlob[offset+4:], sshPublic)
	sshLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(sshBlob) + " dynamicflow-test"
	signedRelease, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desired, err := enrollment.SignDesiredState(enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: "pbp-01", Profile: profileName,
		Generation: 1, ReleaseSet: manifest.SetID,
		AuthorizedSSHKeys: []string{sshLine},
		IssuedAt:          now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, desiredPrivate)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := applyplan.Build(registry, signedRelease, releasePublic, desired, desiredPublic, applyplan.Options{
		Instance: "pbp-01", Profile: profileName, GOARCH: runtime.GOARCH, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func clonePlan(t *testing.T, plan applyplan.Plan) applyplan.Plan {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var result applyplan.Plan
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func recomputePlanID(t *testing.T, plan *applyplan.Plan) {
	t.Helper()
	plan.ID = ""
	canonical, err := signing.CanonicalJSON(*plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	plan.ID = "sha256:" + hex.EncodeToString(digest[:])
}

func TestValidatePBPMullvadPolicy(t *testing.T) {
	goodStatus := []byte(`{"state":"connected","details":{"endpoint":{"obfuscation":{"Single":{"obfuscation_type":"Shadowsocks","endpoint":{"address":"203.0.113.8:443"}}}}}}`)
	if err := validateMullvadStatus(goodStatus, true); err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string][]byte{
		"disconnected":    []byte(`{"state":"disconnected"}`),
		"wrong transport": []byte(`{"state":"connected","details":{"endpoint":{"obfuscation":{"Single":{"obfuscation_type":"UDP-over-TCP","endpoint":{"address":"203.0.113.8:443"}}}}}}`),
		"wrong port":      []byte(`{"state":"connected","details":{"endpoint":{"obfuscation":{"Single":{"obfuscation_type":"Shadowsocks","endpoint":{"address":"203.0.113.8:80"}}}}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMullvadStatus(status, true); !errors.Is(err, errDefinitiveVPNPolicy) {
				t.Fatalf("status policy error = %v", err)
			}
		})
	}
	settings := []byte("mode: shadowsocks\nshadowsocks settings: port 443\n")
	if err := validatePBPTransportSettings(settings, []byte("Auto-connect: on\n"), []byte("Lockdown mode: on\n")); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][3][]byte{
		"mode":     {[]byte("mode: automatic\nshadowsocks settings: port 443\n"), []byte("on\n"), []byte("on\n")},
		"port":     {[]byte("mode: shadowsocks\nshadowsocks settings: port 80\n"), []byte("on\n"), []byte("on\n")},
		"auto":     {settings, []byte("off\n"), []byte("on\n")},
		"lockdown": {settings, []byte("on\n"), []byte("off\n")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePBPTransportSettings(values[0], values[1], values[2]); !errors.Is(err, errDefinitiveVPNPolicy) {
				t.Fatalf("transport policy error = %v", err)
			}
		})
	}
	if err := validateMullvadEgress([]byte(`{"mullvad_exit_ip":true,"country":"Germany","ip":"185.65.134.1"}`), true); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{
		[]byte(`{"mullvad_exit_ip":false,"country":"Germany","ip":"185.65.134.1"}`),
		[]byte(`{"mullvad_exit_ip":true,"country":"Sweden","ip":"185.65.134.1"}`),
		[]byte(`{"mullvad_exit_ip":true,"country":"Germany","ip":"127.0.0.1"}`),
	} {
		if err := validateMullvadEgress(payload, true); !errors.Is(err, errDefinitiveVPNPolicy) {
			t.Fatalf("egress policy error = %v", err)
		}
	}
	if err := validateMullvadEgress([]byte(`not-json`), true); err == nil || errors.Is(err, errDefinitiveVPNPolicy) {
		t.Fatalf("malformed response must remain retryable: %v", err)
	}
	for _, enabled := range [][]byte{[]byte("on\n"), []byte("Lockdown mode: on\n")} {
		if !mullvadSettingOn(enabled) {
			t.Fatalf("enabled Mullvad setting rejected: %q", enabled)
		}
	}
	for _, disabled := range [][]byte{[]byte("off\n"), []byte("Lockdown mode: off\n"), []byte("connection unavailable\n")} {
		if mullvadSettingOn(disabled) {
			t.Fatalf("disabled or ambiguous Mullvad setting accepted: %q", disabled)
		}
	}
}

func TestRequiredVPNRevocationRejectsMissingMullvad(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-mullvad")
	if err := ensureVPNFailClosedWithBinary(context.Background(), missing, false); err != nil {
		t.Fatalf("non-VPN profile unexpectedly required Mullvad: %v", err)
	}
	if err := ensureVPNFailClosedWithBinary(context.Background(), missing, true); err == nil ||
		!strings.Contains(err.Error(), "cannot be confirmed") {
		t.Fatalf("VPN profile accepted missing Mullvad: %v", err)
	}
}

func TestVPNFailClosedRequiresConfirmedDisconnectAndStableSettings(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mullvad")
	good := `#!/bin/sh
case "$*" in
  "auto-connect set off"|"lockdown-mode set on"|"disconnect --wait") exit 0 ;;
  "auto-connect get") printf '%s\n' 'Auto-connect: off' ;;
  "lockdown-mode get") printf '%s\n' 'Lockdown mode: on' ;;
  "status --json") printf '%s\n' '{"state":"disconnected","details":{"reason":"user"}}' ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(binary, []byte(good), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureVPNFailClosedWithBinary(context.Background(), binary, true); err != nil {
		t.Fatalf("confirmed disconnected fail-closed state rejected: %v", err)
	}
	connected := strings.Replace(good, `"state":"disconnected"`, `"state":"connected"`, 1)
	if err := os.WriteFile(binary, []byte(connected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureVPNFailClosedWithBinary(context.Background(), binary, true); err == nil {
		t.Fatal("connected Mullvad state was mislabeled fail-closed")
	}
	disconnectFailed := strings.Replace(good, `"disconnect --wait") exit 0`, `"disconnect --wait") exit 1`, 1)
	if err := os.WriteFile(binary, []byte(disconnectFailed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureVPNFailClosedWithBinary(context.Background(), binary, true); err == nil {
		t.Fatal("failed Mullvad disconnect was mislabeled fail-closed")
	}
}

func TestValidatePlanAcceptsOnlyUntamperedFixedClosures(t *testing.T) {
	for _, name := range []string{"ssh", "ssh-gui", "vpn", "pbp"} {
		plan := testPlan(t, name)
		if err := validatePlan(plan); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		mutated := plan
		mutated.AuthorizedSSHKeys = []string{"ssh-ed25519 changed"}
		if err := validatePlan(mutated); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("tampered %s plan error = %v", name, err)
		}
	}
	unsupported := testPlan(t, "ssh")
	unsupported.Profile = "examstation"
	if err := validatePlan(unsupported); !errors.Is(err, ErrInvalidConfig) && !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatalf("unsupported plan error = %v", err)
	}
}

func TestValidatePlanRejectsRehashedInvalidClosureTargetAndArtifactBindings(t *testing.T) {
	base := testPlan(t, "pbp")
	tests := []struct {
		name   string
		mutate func(*applyplan.Plan)
	}{
		{"dependency", func(plan *applyplan.Plan) { plan.Phases[1].DependsOn = nil }},
		{"phase order", func(plan *applyplan.Plan) { plan.Phases[1], plan.Phases[2] = plan.Phases[2], plan.Phases[1] }},
		{"flow removed", func(plan *applyplan.Plan) { plan.Phases = append([]applyplan.Phase(nil), plan.Phases[1:]...) }},
		{"flow moved", func(plan *applyplan.Plan) { plan.Phases[0], plan.Phases[1] = plan.Phases[1], plan.Phases[0] }},
		{"flow duplicated", func(plan *applyplan.Plan) {
			plan.Phases = append(plan.Phases, plan.Phases[0])
		}},
		{"flow target any", func(plan *applyplan.Plan) {
			plan.Phases[0].Steps[0].Artifact.Target = "any"
			plan.Phases[0].Steps[0].Artifact.Path = "flow/v1.0.0/any/flow"
		}},
		{"flow packaged as archive", func(plan *applyplan.Plan) {
			plan.Phases[0].Steps[0].Artifact.Path = "flow/v1.0.0/" + plan.Target + "/flow.tar.gz"
		}},
		{"flow size limit", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Size = maxRuntimeArtifactSize + 1 }},
		{"runtime target", func(plan *applyplan.Plan) { plan.Target = "linux-not-this-host" }},
		{"artifact target", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Target = "linux-not-this-host" }},
		{"artifact traversal", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Path = "../ssh.tar.gz" }},
		{"artifact component path", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Path = "vpn/v1.0.0/any/ssh.tar.gz" }},
		{"artifact version", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Version = "latest" }},
		{"artifact size", func(plan *applyplan.Plan) { plan.Phases[0].Steps[0].Artifact.Size = maxArtifactSize + 1 }},
		{"duplicate key", func(plan *applyplan.Plan) {
			plan.AuthorizedSSHKeys = append(plan.AuthorizedSSHKeys, plan.AuthorizedSSHKeys[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := clonePlan(t, base)
			test.mutate(&mutated)
			recomputePlanID(t, &mutated)
			if err := validatePlan(mutated); err == nil {
				t.Fatal("invalid but self-consistent plan was accepted")
			}
		})
	}
}

func TestRejectRollbackBeforeAnyInstallerWork(t *testing.T) {
	plan := testPlan(t, "ssh")
	base := Checkpoint{
		ReleaseGeneration: plan.ReleaseGeneration, ReleaseSet: plan.ReleaseSet,
		DesiredGeneration: plan.DesiredGeneration, DesiredStateID: plan.DesiredStateID,
	}
	if err := rejectRollback(base, plan); err != nil {
		t.Fatalf("same checkpoint refused: %v", err)
	}
	olderDesired := plan
	base.DesiredGeneration++
	if err := rejectRollback(base, olderDesired); !errors.Is(err, applyplan.ErrRollback) {
		t.Fatalf("older desired error = %v", err)
	}
	base.DesiredGeneration = plan.DesiredGeneration
	base.DesiredStateID = "sha256:" + strings.Repeat("f", 64)
	if err := rejectRollback(base, plan); !errors.Is(err, applyplan.ErrRollback) {
		t.Fatalf("same-generation substitution error = %v", err)
	}
	base.DesiredStateID = plan.DesiredStateID
	base.ReleaseGeneration++
	if err := rejectRollback(base, plan); !errors.Is(err, applyplan.ErrRollback) {
		t.Fatalf("older signed release error = %v", err)
	}
	base.ReleaseGeneration = plan.ReleaseGeneration
	base.ReleaseSet = "sha256:" + strings.Repeat("e", 64)
	if err := rejectRollback(base, plan); !errors.Is(err, applyplan.ErrRollback) {
		t.Fatalf("same-generation release substitution error = %v", err)
	}
}

func TestEnsureArtifactStreamsVerifiesCachesAndRejectsOverflow(t *testing.T) {
	payload := []byte("signed immutable artifact")
	digest := sha256.Sum256(payload)
	artifact := applyplan.Artifact{Component: "ssh", Version: "v1.0.0", Target: "any", Path: "ssh/v1.0.0/any/ssh.tar.gz", Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(payload))}
	directory := t.TempDir()
	calls := 0
	r := &runner{config: Config{FetchArtifact: func(_ context.Context, _ applyplan.Artifact, destination io.Writer) error {
		calls++
		_, err := destination.Write(payload)
		return err
	}}, artifactsDir: directory}
	first, err := r.ensureArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.ensureArtifact(context.Background(), artifact)
	if err != nil || first != second || calls != 1 {
		t.Fatalf("cache result %q %q calls=%d err=%v", first, second, calls, err)
	}

	overflowDirectory := t.TempDir()
	r.artifactsDir = overflowDirectory
	r.config.FetchArtifact = func(_ context.Context, _ applyplan.Artifact, destination io.Writer) error {
		_, err := destination.Write(append(payload, 'x'))
		return err
	}
	if _, err := r.ensureArtifact(context.Background(), artifact); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("overflow error = %v", err)
	}
	entries, _ := os.ReadDir(overflowDirectory)
	if len(entries) != 0 {
		t.Fatalf("failed download left files: %v", entries)
	}
}

func TestEnsureArtifactRejectsUnsafeExistingCachePath(t *testing.T) {
	payload := []byte("x")
	digest := sha256.Sum256(payload)
	artifact := applyplan.Artifact{Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: 1}
	directory := t.TempDir()
	path := filepath.Join(directory, stringsTrimDigest(artifact.Digest)+".tar.gz")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	r := &runner{config: Config{FetchArtifact: func(_ context.Context, _ applyplan.Artifact, destination io.Writer) error {
		_, err := destination.Write(payload)
		return err
	}}, artifactsDir: directory}
	if _, err := r.ensureArtifact(context.Background(), artifact); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("unsafe cache error = %v", err)
	}
}

func TestArtifactCacheReplacesHardlinkWithoutWritingThroughIt(t *testing.T) {
	payload := []byte("immutable")
	digest := sha256.Sum256(payload)
	artifact := applyplan.Artifact{Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(payload))}
	directory := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(directory, stringsTrimDigest(artifact.Digest)+".tar.gz")
	if err := os.Link(external, cache); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(cache, artifact); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("hardlinked cache verified: %v", err)
	}
	r := &runner{config: Config{FetchArtifact: func(_ context.Context, _ applyplan.Artifact, destination io.Writer) error {
		_, err := destination.Write(payload)
		return err
	}}, artifactsDir: directory}
	path, err := r.ensureArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	stat, ok := fileStat(info)
	if err != nil || !ok || stat.Nlink != 1 {
		t.Fatalf("replacement cache is not independent: %#v %v", stat, err)
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != string(payload) {
		t.Fatalf("external hardlink target changed: %q %v", data, err)
	}
}

func stringsTrimDigest(value string) string { return value[len("sha256:"):] }

func TestBoundedWritersStopAtSignedAndLogLimits(t *testing.T) {
	var output bytes.Buffer
	writer := &boundedWriter{writer: &output, remaining: 3}
	if _, err := writer.Write([]byte("four")); !errors.Is(err, ErrArtifactVerification) || output.Len() != 0 {
		t.Fatalf("artifact bound output=%q err=%v", output.String(), err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	logWriter := &sanitizedLogWriter{file: logFile, remaining: 3}
	if count, err := logWriter.Write([]byte("four")); err != nil || count != 4 {
		t.Fatalf("buffered log count=%d err=%v", count, err)
	}
	if err := logWriter.Flush(); err == nil {
		t.Fatal("log limit was not enforced at flush")
	}
}

func TestSanitizedLogWriterRedactsAcrossWritesAndDropsOversizedLines(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	writer := &sanitizedLogWriter{file: logFile, remaining: 1 << 20}
	for _, fragment := range []string{"account 12345678", "90123456 token abcdefghijkl", "mnopqrstuvwxyz\x00\n"} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), maxLogLine+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := logFile.Sync(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "1234567890123456") || strings.Contains(text, "abcdefghijklmnopqrstuvwxyz") ||
		!strings.Contains(text, "[REDACTED]") || !strings.Contains(text, "[output line exceeded safe limit]") {
		t.Fatalf("unexpected sanitized log: %q", text)
	}
}

func TestProtectedLogStartsCleanAndRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ssh.log")
	legacySecret := "1234567890123456"
	if err := os.WriteFile(path, []byte(legacySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openProtectedLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || len(data) != 0 {
		t.Fatalf("legacy output survived cleaned log open: %q %v", data, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("outside", path); err != nil {
		t.Fatal(err)
	}
	if _, err := openProtectedLog(path); err == nil {
		t.Fatal("symlink log accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte(legacySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, path); err != nil {
		t.Fatal(err)
	}
	if _, err := openProtectedLog(path); err == nil {
		t.Fatal("hardlinked log accepted")
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != legacySecret {
		t.Fatalf("hardlinked file was truncated before validation: %q %v", data, err)
	}
}

func TestCleanupManagedStagingRemovesOnlyManagedEntries(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, ".authorized-key-stale")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, ".pbp-stale"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupManagedStaging(directory); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("managed staging remains: %v %v", entries, err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("cleanup followed symlink: %q %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "operator-data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupManagedStaging(directory); err == nil {
		t.Fatal("unrecognized staging entry was silently removed")
	}
}

func TestTargetApplyLockRejectsConcurrentRunAndSymlink(t *testing.T) {
	directory := t.TempDir()
	lockPath := filepath.Join(directory, "targetapply.lock")
	first, err := acquireTargetApplyLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseTargetApplyLock(first)
	if _, err := acquireTargetApplyLock(lockPath); !errors.Is(err, reconcile.ErrBusy) {
		t.Fatalf("second lock error = %v", err)
	}
	releaseTargetApplyLock(first)
	first = nil
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireTargetApplyLock(lockPath); err == nil {
		t.Fatal("symlink lock accepted")
	}
}

func TestAuthorizedKeysAtomicRevocationAndExactRead(t *testing.T) {
	sshDirectory := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	authorized := filepath.Join(sshDirectory, "authorized_keys")
	if err := os.WriteFile(authorized, []byte("ssh-ed25519 test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readAuthorizedKeys(authorized, uid, gid); err != nil || string(data) != "ssh-ed25519 test\n" {
		t.Fatalf("exact read = %q, %v", data, err)
	}
	external := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(external, []byte("do not truncate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(authorized); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, authorized); err != nil {
		t.Fatal(err)
	}
	if err := replaceAuthorizedKeysWithEmpty(sshDirectory, uid, gid); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != "do not truncate" {
		t.Fatalf("revocation followed symlink: %q %v", data, err)
	}
	info, err := os.Lstat(authorized)
	stat, ok := fileStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || info.Size() != 0 {
		t.Fatalf("revoked authorized_keys unsafe: %#v %#v %v", info, stat, err)
	}
	entries, err := os.ReadDir(sshDirectory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "authorized_keys" {
		t.Fatalf("revocation left temp files: %v %v", entries, err)
	}
}

func TestReadAuthorizedKeysRejectsHardlinkAndDirectorySymlink(t *testing.T) {
	uid, gid := os.Geteuid(), os.Getegid()
	sshDirectory := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(sshDirectory, "authorized_keys")
	if err := os.WriteFile(authorized, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(authorized, filepath.Join(sshDirectory, "copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorizedKeys(authorized, uid, gid); err == nil {
		t.Fatal("hardlinked authorized_keys accepted")
	}
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Symlink(real, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorizedKeys(filepath.Join(symlink, "authorized_keys"), uid, gid); err == nil {
		t.Fatal("symlinked SSH directory accepted")
	}
}

func TestPersonaReaderRejectsSymlinkAndPinsValidRootFile(t *testing.T) {
	identity := map[string]any{
		"schema":                   json.Number("2"),
		"browser_version":          "150.0.2-beta.25",
		"browser_major":            json.Number("150"),
		"camoufox_package_version": "0.6.0",
		"os":                       "windows",
		"locale":                   "de-DE",
		"timezone":                 "Europe/Berlin",
		"preset":                   map[string]any{"label": "Größe 😀"},
		"config":                   map[string]any{"seed": json.Number("1234")},
		"firefox_user_prefs":       map[string]any{"webgl.force-enabled": true},
	}
	canonical, err := canonicalPersonaJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	persona := hex.EncodeToString(digest[:])
	identity["persona_id"] = persona
	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(t.TempDir(), "persona.json")
	if err := os.WriteFile(valid, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if actual, err := readPersonaIDAt(valid); err != nil || actual != persona {
			t.Fatalf("valid persona = %q, %v", actual, err)
		}
		tampered := bytes.Replace(payload, []byte(`"seed":1234`), []byte(`"seed":1235`), 1)
		if bytes.Equal(tampered, payload) {
			t.Fatal("test persona did not contain the expected seed")
		}
		if err := os.WriteFile(valid, tampered, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPersonaIDAt(valid); err == nil {
			t.Fatal("persona with an unchanged ID and modified identity was accepted")
		}
		identity["unexpected"] = true
		identity["persona_id"] = persona
		unexpected, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(valid, unexpected, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPersonaIDAt(valid); err == nil {
			t.Fatal("persona with an unexpected identity field was accepted")
		}
	}
	symlink := filepath.Join(t.TempDir(), "persona.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPersonaIDAt(symlink); err == nil {
		t.Fatal("symlink persona accepted")
	}
}

func TestCanonicalPersonaJSONMatchesPythonIdentityEncoding(t *testing.T) {
	actual, err := canonicalPersonaJSON(map[string]any{
		"text": "Größe 😀",
		"n":    json.Number("1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"n":1,"text":"Gr\u00f6\u00dfe \ud83d\ude00"}`
	if string(actual) != expected {
		t.Fatalf("canonical persona JSON = %q, want %q", actual, expected)
	}
}

func TestFixedRuntimeContracts(t *testing.T) {
	if vncSecretPath != "/root/.vm-bootstrap-vnc-malwarelab" {
		t.Fatalf("wrong VNC secret path %q", vncSecretPath)
	}
	r := &runner{}
	if got := r.networkModeArguments(); len(got) != 1 || got[0] != "--outbound-https-enrollment" {
		t.Fatalf("outbound mode = %v", got)
	}
	r.config.SSHConnection = "198.51.100.3 40000 203.0.113.9 22"
	if got := r.networkModeArguments(); len(got) != 0 {
		t.Fatalf("direct SSH mode added args: %v", got)
	}
}

func TestSSHConnectionValidation(t *testing.T) {
	for _, valid := range []string{"", "198.51.100.3 43122 203.0.113.9 22"} {
		if err := validateSSHConnection(valid); err != nil {
			t.Fatalf("valid %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"a b c", "host.example 4 server.example 22", "2001:db8::1 4 2001:db8::2 22", "1.2.3.4 0 5.6.7.8 22", "1.2.3.4 2 5.6.7.8 99999"} {
		if err := validateSSHConnection(invalid); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid %q: %v", invalid, err)
		}
	}
}

func TestEffectiveSSHPolicyRejectsAuthenticationAndForwardingDrift(t *testing.T) {
	common := strings.Join([]string{
		"pubkeyauthentication yes",
		"authenticationmethods publickey",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"permitemptypasswords no",
		"permitrootlogin no",
		"strictmodes yes",
		"x11forwarding no",
		"allowagentforwarding no",
		"disableforwarding no",
		"allowstreamlocalforwarding no",
		"gatewayports no",
		"permittunnel no",
		"permituserrc no",
		"permituserenvironment no",
		"hostbasedauthentication no",
		"ignorerhosts yes",
		"authorizedkeysfile .ssh/authorized_keys",
	}, "\n") + "\n"
	closed := common + "allowtcpforwarding no\npermitopen none\n"
	if err := verifySSHEffectivePolicy([]byte(closed), sshAccessClosed); err != nil {
		t.Fatalf("fixed baseline policy rejected: %v", err)
	}
	gui := common + "allowtcpforwarding local\npermitopen 127.0.0.1:5901\ndenyusers malwarelab\n"
	if err := verifySSHEffectivePolicy([]byte(gui), sshAccessGUI); err != nil {
		t.Fatalf("fixed GUI policy rejected: %v", err)
	}
	for name, policy := range map[string]string{
		"password":         strings.Replace(closed, "passwordauthentication no", "passwordauthentication yes", 1),
		"auth methods":     strings.Replace(closed, "authenticationmethods publickey", "authenticationmethods any", 1),
		"agent forwarding": strings.Replace(closed, "allowagentforwarding no", "allowagentforwarding yes", 1),
		"baseline tunnel":  strings.Replace(closed, "allowtcpforwarding no", "allowtcpforwarding yes", 1),
		"managed keys":     strings.Replace(closed, ".ssh/authorized_keys", ".ssh/other_keys", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifySSHEffectivePolicy([]byte(policy), sshAccessClosed); err == nil {
				t.Fatal("drifted SSH policy was accepted")
			}
		})
	}
	for name, policy := range map[string]string{
		"public destination": strings.Replace(gui, "127.0.0.1:5901", "0.0.0.0:5901", 1),
		"direct GUI login":   strings.Replace(gui, "denyusers malwarelab\n", "", 1),
		"remote forwarding":  strings.Replace(gui, "allowtcpforwarding local", "allowtcpforwarding yes", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifySSHEffectivePolicy([]byte(policy), sshAccessGUI); err == nil {
				t.Fatal("drifted SSH GUI policy was accepted")
			}
		})
	}
	duplicate := closed + "passwordauthentication no\n"
	if err := verifySSHEffectivePolicy([]byte(duplicate), sshAccessClosed); err == nil {
		t.Fatal("ambiguous duplicate effective directive was accepted")
	}
}

func TestManagedVNCAccountAndRuntimePolicyRejectDrift(t *testing.T) {
	uid := 1200
	marker := []byte("malwarelab:1200\n")
	if err := validateManagedVNCAccountEvidence(uid, marker, []byte("malwarelab L 2026-01-01\n"), []byte("malwarelab audio video\n")); err != nil {
		t.Fatalf("valid managed account evidence rejected: %v", err)
	}
	for name, values := range map[string]struct {
		marker, status, groups []byte
	}{
		"identity": {[]byte("malwarelab:1201\n"), []byte("malwarelab L\n"), []byte("malwarelab\n")},
		"password": {marker, []byte("malwarelab P\n"), []byte("malwarelab\n")},
		"group":    {marker, []byte("malwarelab L\n"), []byte("malwarelab docker\n")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateManagedVNCAccountEvidence(uid, values.marker, values.status, values.groups); err == nil {
				t.Fatal("unsafe managed account evidence was accepted")
			}
		})
	}
	policy := map[string]string{
		"SecurityTypes": "VncAuth", "rfbport": "5901", "AllowOverride": "desktop,AcceptPointerEvents",
		"localhost": "yes", "AlwaysShared": "no", "NeverShared": "yes",
		"AcceptCutText": "no", "SendCutText": "no", "SendPrimary": "no", "SetPrimary": "no",
	}
	if err := validateVNCRuntimePolicy(policy); err != nil {
		t.Fatalf("valid VNC runtime policy rejected: %v", err)
	}
	for _, field := range []string{"localhost", "AcceptCutText", "SendCutText", "SendPrimary", "SetPrimary"} {
		mutated := make(map[string]string, len(policy))
		for key, value := range policy {
			mutated[key] = value
		}
		mutated[field] = "yes"
		if field == "localhost" {
			mutated[field] = "no"
		}
		if err := validateVNCRuntimePolicy(mutated); err == nil {
			t.Fatalf("VNC runtime drift %s was accepted", field)
		}
	}
}

func TestVNCFailClosedStopsUnitAndRequiresClosedPort(t *testing.T) {
	directory := t.TempDir()
	systemctl := filepath.Join(directory, "systemctl")
	ss := filepath.Join(directory, "ss")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\ncase \"$1\" in disable) exit 0;; is-active|is-enabled) exit 1;; *) exit 2;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ss, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := disableVNCFailClosedWithBinaries(context.Background(), systemctl, ss); err != nil {
		t.Fatalf("confirmed closed VNC state rejected: %v", err)
	}
	if err := os.WriteFile(ss, []byte("#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 32 0.0.0.0:5901 0.0.0.0:*'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := disableVNCFailClosedWithBinaries(context.Background(), systemctl, ss); err == nil {
		t.Fatal("VNC fail-closed accepted a remaining public listener")
	}
}
