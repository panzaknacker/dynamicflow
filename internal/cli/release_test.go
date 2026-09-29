package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dynamicflow/internal/localstate"
)

func TestReleaseBuildIsReproducibleForFixedGenerationAndInputs(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	build := func() ([]byte, []byte, stagedRelease) {
		t.Helper()
		status, stdout, stderr := invokeCLI(t,
			"--json", "--home", home, "--source-root", source,
			"release", "build", "--generation", "4242",
		)
		if status != exitOK || stderr != "" {
			t.Fatalf("release build status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
		manifest, err := os.ReadFile(filepath.Join(home, "releases", "signed-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var stage stagedRelease
		data, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &stage); err != nil {
			t.Fatal(err)
		}
		return manifest, data, stage
	}

	firstManifest, firstStageBytes, firstStage := build()
	secondManifest, secondStageBytes, secondStage := build()
	if !bytes.Equal(firstManifest, secondManifest) {
		t.Fatal("fixed-generation signed manifest changed across identical builds")
	}
	if firstStage.Signed.Manifest.SetID != secondStage.Signed.Manifest.SetID {
		t.Fatalf("fixed-generation set ID changed: %s != %s", firstStage.Signed.Manifest.SetID, secondStage.Signed.Manifest.SetID)
	}
	if !bytes.Equal(firstStage.Signed.Signature.Value, secondStage.Signed.Signature.Value) {
		t.Fatal("deterministic Ed25519 signature changed across identical builds")
	}
	if !bytes.Equal(firstStageBytes, secondStageBytes) {
		t.Fatal("fixed-generation staged release metadata changed across identical builds")
	}
}

func TestReleaseBuildRejectsChangedBytesForStagedVersionBeforeSigning(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--generation", "31",
	); status != exitOK || stderr != "" || stdout == "" {
		t.Fatalf("initial build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stagePath := filepath.Join(home, "releases", "staged.json")
	manifestPath := filepath.Join(home, "releases", "signed-manifest.json")
	stageBefore, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	changedSource := []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Print(\"changed flow bytes\") }\n")
	if err := os.WriteFile(filepath.Join(source, "cmd", "flow", "main.go"), changedSource, 0o600); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--generation", "32",
	)
	if status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"version_conflict"`) {
		t.Fatalf("collision build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.Error == nil || failure.Error.Next == "" {
		t.Fatalf("collision response = %+v", failure)
	}
	stageAfter, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestAfter, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stageBefore, stageAfter) || !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("rejected version collision changed staged or signed manifest metadata")
	}
}

func TestReleaseBuildRebuildRejectsImmutableRootCollisionBeforeStateMutation(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--generation", "31",
	); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("initial build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}

	snapshotState := func() map[string][]byte {
		t.Helper()
		relatives := []string{
			"releases/staged.json",
			"releases/signed-manifest.json",
			operatorManifestCatalogPath,
		}
		entries, err := os.ReadDir(filepath.Join(home, operatorManifestHistoryDir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			relatives = append(relatives, filepath.Join(operatorManifestHistoryDir, entry.Name()))
		}
		snapshot := make(map[string][]byte, len(relatives))
		for _, relative := range relatives {
			data, err := os.ReadFile(filepath.Join(home, relative))
			if err != nil {
				t.Fatalf("snapshot %s: %v", relative, err)
			}
			snapshot[relative] = data
		}
		return snapshot
	}
	stateBefore := snapshotState()

	for _, component := range []string{"ssh", "vpn", "pbp", "decepticon", "examstation"} {
		writeFixtureFile(t, filepath.Join(source, component, "VERSION"), []byte("v1.2.4\n"))
	}
	immutableSSH := filepath.Join(source, "serving", "releases", "ssh", "v1.2.4", "any", "ssh.tar.gz")
	writeFixtureFile(t, immutableSSH, []byte("immutable:ssh:v1.2.4\n"))

	builders := map[string]string{
		filepath.Join("ssh", "make-toolkit-release.sh"): `#!/bin/sh
set -eu
printf '%s\n' 'rebuilt:ssh:v1.2.4' > "${TOOLKIT_DIST_DIR}/ssh.tar.gz"
`,
		filepath.Join("vpn", "make-release.sh"): `#!/bin/sh
set -eu
printf '%s\n' 'rebuilt:vpn:v1.2.4' > "${TOOLKIT_DIST_DIR}/vpn.tar.gz"
`,
		filepath.Join("pbp", "make-release.sh"): `#!/bin/sh
set -eu
mkdir -p "${TOOLKIT_DIST_DIR}/linux-${1}"
printf '%s\n' "rebuilt:pbp:linux-${1}:v1.2.4" > "${TOOLKIT_DIST_DIR}/linux-${1}/pbp.tar.gz"
`,
		filepath.Join("decepticon", "make-release.sh"): `#!/bin/sh
set -eu
printf '%s\n' 'rebuilt:decepticon:v1.2.4' > "${TOOLKIT_DIST_DIR}/decepticon.tar.gz"
`,
		filepath.Join("examstation", "make-release.sh"): `#!/bin/sh
set -eu
printf '%s\n' 'rebuilt:examstation:v1.2.4' > "${TOOLKIT_DIST_DIR}/examstation.tar.gz"
`,
	}
	for relative, script := range builders {
		path := filepath.Join(source, relative)
		writeFixtureFile(t, path, []byte(script))
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--rebuild", "--generation", "32",
	)
	if status != exitVerify || stdout != "" {
		t.Fatalf("immutable rebuild collision status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	failure := decodeCLIEnvelope(t, stderr)
	if failure.Error == nil || failure.Error.Code != "version_conflict" ||
		!strings.Contains(failure.Error.Message, "ssh/v1.2.4/any/ssh.tar.gz") {
		t.Fatalf("immutable rebuild collision response = %+v", failure)
	}
	rebuiltSSH, err := os.ReadFile(filepath.Join(home, "releases", "build-inputs", "ssh", "ssh.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	immutableBytes, err := os.ReadFile(immutableSSH)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rebuiltSSH, immutableBytes) {
		t.Fatal("fake rebuild did not produce bytes different from the immutable coordinate")
	}

	stateAfter := snapshotState()
	if len(stateAfter) != len(stateBefore) {
		t.Fatalf("rejected rebuild changed operator release state files: before=%d after=%d", len(stateBefore), len(stateAfter))
	}
	for relative, before := range stateBefore {
		after, exists := stateAfter[relative]
		if !exists || !bytes.Equal(before, after) {
			t.Fatalf("rejected rebuild changed signed operator state %s", relative)
		}
	}
}

func TestReleaseBuildRejectsRebindingVersionOlderThanCurrentStage(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	build := func(generation string) (int, string, string) {
		t.Helper()
		return invokeCLI(t, "--json", "--home", home, "--source-root", source, "release", "build", "--generation", generation)
	}
	if status, stdout, stderr := build("41"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("first build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	writeFixtureFile(t, filepath.Join(source, "ssh", "VERSION"), []byte("v1.2.4\n"))
	writeFixtureFile(t, filepath.Join(source, "serving", "releases", "ssh", "v1.2.4", "any", "ssh.tar.gz"), []byte("fixture:ssh:v1.2.4\n"))
	if status, stdout, stderr := build("42"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("second build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stagePath := filepath.Join(home, "releases", "staged.json")
	stageBefore, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(source, "ssh", "VERSION"), []byte("v1.2.3\n"))
	writeFixtureFile(t, filepath.Join(source, "serving", "releases", "ssh", "v1.2.3", "any", "ssh.tar.gz"), []byte("rebound historical ssh bytes\n"))
	status, stdout, stderr := build("43")
	if status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"version_conflict"`) {
		t.Fatalf("historical collision status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stageAfter, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stageBefore, stageAfter) {
		t.Fatal("historical version collision changed current staged release")
	}
	historyEntries, err := os.ReadDir(filepath.Join(home, operatorManifestHistoryDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(historyEntries) != 2 {
		t.Fatalf("operator manifest history entries=%d, want 2 authentic builds", len(historyEntries))
	}
}

func TestReleaseBuildEnforcesOperatorGenerationHighWaterBeforeSigning(t *testing.T) {
	for _, test := range []struct {
		name       string
		generation string
		mutate     bool
	}{
		{name: "lower", generation: "99"},
		{name: "equal-different-set", generation: "100", mutate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := privateTempDir(t)
			source := makeReleaseSourceFixture(t)
			if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
				t.Fatalf("init status=%d: %s", status, stderr)
			}
			if status, stdout, stderr := invokeCLI(t,
				"--json", "--home", home, "--source-root", source,
				"release", "build", "--generation", "100",
			); status != exitOK || stdout == "" || stderr != "" {
				t.Fatalf("initial build status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			stagePath := filepath.Join(home, "releases", "staged.json")
			manifestPath := filepath.Join(home, "releases", "signed-manifest.json")
			stageBefore, err := os.ReadFile(stagePath)
			if err != nil {
				t.Fatal(err)
			}
			manifestBefore, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.mutate {
				writeFixtureFile(t, filepath.Join(source, "ssh", "VERSION"), []byte("v1.2.4\n"))
				writeFixtureFile(t, filepath.Join(source, "serving", "releases", "ssh", "v1.2.4", "any", "ssh.tar.gz"), []byte("fixture:ssh:v1.2.4\n"))
			}
			status, stdout, stderr := invokeCLI(t,
				"--json", "--home", home, "--source-root", source,
				"release", "build", "--generation", test.generation,
			)
			if status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"release_rollback"`) {
				t.Fatalf("rollback build status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			stageAfter, err := os.ReadFile(stagePath)
			if err != nil {
				t.Fatal(err)
			}
			manifestAfter, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stageBefore, stageAfter) || !bytes.Equal(manifestBefore, manifestAfter) {
				t.Fatal("rejected generation changed staged or signed manifest metadata")
			}
			entries, err := os.ReadDir(filepath.Join(home, operatorManifestHistoryDir))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("operator manifest history entries=%d, want 1", len(entries))
			}
		})
	}
}

func TestReleaseStateMismatchFailsClosedAndBuildRecovers(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	build := func(generation string) {
		t.Helper()
		if status, stdout, stderr := invokeCLI(t,
			"--json", "--home", home, "--source-root", source,
			"release", "build", "--generation", generation,
		); status != exitOK || stdout == "" || stderr != "" {
			t.Fatalf("build %s status=%d stdout=%q stderr=%q", generation, status, stdout, stderr)
		}
	}
	build("100")
	firstStage, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(source, "ssh", "VERSION"), []byte("v1.2.4\n"))
	writeFixtureFile(t, filepath.Join(source, "serving", "releases", "ssh", "v1.2.4", "any", "ssh.tar.gz"), []byte("fixture:ssh:v1.2.4\n"))
	build("101")
	writeFixtureFile(t, filepath.Join(home, "releases", "staged.json"), firstStage)

	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "verify"); status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"release_state"`) {
		t.Fatalf("mismatched verify status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	publishRoot := filepath.Join(t.TempDir(), "publish")
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "publish", "--root", publishRoot); status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"release_state"`) {
		t.Fatalf("mismatched publish status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if _, err := os.Lstat(publishRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched state touched publish root: %v", err)
	}

	build("102")
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "verify"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("recovered verify status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func TestOperatorManifestCheckpointDetectsHistoryDeletion(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	build := func(generation string) (int, string, string) {
		t.Helper()
		return invokeCLI(t, "--json", "--home", home, "--source-root", source, "release", "build", "--generation", generation)
	}
	if status, stdout, stderr := build("100"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("first build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var firstStage stagedRelease
	firstStageBytes, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil || json.Unmarshal(firstStageBytes, &firstStage) != nil {
		t.Fatalf("read first stage: %v", err)
	}
	firstHistory := filepath.Join(home, operatorManifestHistoryDir, strings.TrimPrefix(firstStage.Signed.Manifest.SetID, "sha256:")+".json")
	firstHistoryBytes, err := os.ReadFile(firstHistory)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(source, "ssh", "VERSION"), []byte("v1.2.4\n"))
	writeFixtureFile(t, filepath.Join(source, "serving", "releases", "ssh", "v1.2.4", "any", "ssh.tar.gz"), []byte("fixture:ssh:v1.2.4\n"))
	if status, stdout, stderr := build("101"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("second build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stageBefore, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	exportBefore, err := os.ReadFile(filepath.Join(home, "releases", "signed-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(home, operatorManifestCatalogPath)
	checkpointInfo, err := os.Lstat(checkpointPath)
	if err != nil || !checkpointInfo.Mode().IsRegular() || checkpointInfo.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint metadata=%v err=%v", checkpointInfo, err)
	}
	if err := os.Remove(firstHistory); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := build("102")
	if status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"version_policy"`) || !strings.Contains(stderr, "deletion detected") {
		t.Fatalf("deleted history status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stageAfter, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	exportAfter, err := os.ReadFile(filepath.Join(home, "releases", "signed-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stageBefore, stageAfter) || !bytes.Equal(exportBefore, exportAfter) {
		t.Fatal("history deletion changed publishable operator state")
	}
	writeFixtureFile(t, firstHistory, firstHistoryBytes)
	if status, stdout, stderr := build("102"); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("restored history build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stageBefore, err = os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	exportBefore, err = os.ReadFile(filepath.Join(home, "releases", "signed-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(checkpointPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstHistory); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr = build("103")
	if status != exitVerify || stdout != "" || !strings.Contains(stderr, `"code":"version_policy"`) || !strings.Contains(stderr, "checkpoint is missing") {
		t.Fatalf("thinned uncheckpointed history status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	stageAfter, err = os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	exportAfter, err = os.ReadFile(filepath.Join(home, "releases", "signed-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stageBefore, stageAfter) || !bytes.Equal(exportBefore, exportAfter) {
		t.Fatal("checkpoint plus partial-history deletion changed publishable operator state")
	}
}

func TestLocalReleasePublishResumesCommittedSetWithoutSources(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--generation", "100",
	); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	root := filepath.Join(t.TempDir(), "release-root")
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "publish", "--root", root); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("initial publish status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	var stage stagedRelease
	stageBytes, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stageBytes, &stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "history")); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range stage.ArtifactPaths {
		if err := os.Remove(artifact); err != nil {
			t.Fatalf("remove transient artifact: %v", err)
		}
	}
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "publish", "--root", root, "--plan"); status != exitOK || !strings.Contains(stdout, `"resume_committed_set":true`) || stderr != "" {
		t.Fatalf("source-less resume plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "publish", "--root", root); status != exitOK || stdout == "" || stderr != "" {
		t.Fatalf("source-less resume status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(root, "history", strings.TrimPrefix(stage.Signed.Manifest.SetID, "sha256:"), "signed-manifest.json")); err != nil {
		t.Fatalf("resume did not restore history: %v", err)
	}
	currentTarget, err := os.Readlink(filepath.Join(root, "current"))
	wantTarget := filepath.ToSlash(filepath.Join("sets", strings.TrimPrefix(stage.Signed.Manifest.SetID, "sha256:")))
	if err != nil || currentTarget != wantTarget {
		t.Fatalf("resume current target=%q err=%v, want %q", currentTarget, err, wantTarget)
	}
}

func TestReleaseVerifyRejectsUnsafeOrNonCanonicalExternalStage(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "release", "build", "--generation", "17"); status != exitOK {
		t.Fatalf("build status=%d: %s", status, stderr)
	}
	stage, err := os.ReadFile(filepath.Join(home, "releases", "staged.json"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("trailing data", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "stage.json")
		writeFixtureFile(t, path, append(append([]byte(nil), stage...), []byte("{}")...))
		status, stdout, stderr := invokeCLI(t, "--home", home, "release", "verify", path)
		if status != exitConfig || stdout != "" || stderr == "" {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		directory := privateTempDir(t)
		path := filepath.Join(directory, "stage.json")
		writeFixtureFile(t, path, stage)
		if err := os.Link(path, filepath.Join(directory, "stage.second.json")); err != nil {
			t.Fatal(err)
		}
		status, stdout, stderr := invokeCLI(t, "--home", home, "release", "verify", path)
		if status != exitConfig || stdout != "" || stderr == "" {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
	})

	t.Run("symlink ancestor", func(t *testing.T) {
		real := privateTempDir(t)
		path := filepath.Join(real, "stage.json")
		writeFixtureFile(t, path, stage)
		link := filepath.Join(privateTempDir(t), "linked")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		status, stdout, stderr := invokeCLI(t, "--home", home, "release", "verify", filepath.Join(link, "stage.json"))
		if status != exitConfig || stdout != "" || stderr == "" {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
	})
}

func TestReleaseBuilderEnvironmentExcludesAmbientSecretsAndIsStable(t *testing.T) {
	t.Setenv("DYNAMICFLOW_TEST_AMBIENT_SECRET", "must-not-reach-builder")
	t.Setenv("GOFLAGS", "-mod=vendor")
	t.Setenv("GOENV", "/tmp/operator-go-env")
	t.Setenv("GOWORK", "/tmp/operator-go.work")
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOPROXY", "https://operator-proxy.invalid")
	t.Setenv("GOSUMDB", "sum.operator.invalid")
	t.Setenv("GIT_CONFIG_GLOBAL", "/tmp/operator-gitconfig")
	first := environmentWith(map[string]string{"GOOS": "linux", "GOARCH": "amd64"})
	second := environmentWith(map[string]string{"GOARCH": "amd64", "GOOS": "linux"})
	if !bytes.Equal([]byte(strings.Join(first, "\x00")), []byte(strings.Join(second, "\x00"))) {
		t.Fatalf("builder environment order is unstable: %v != %v", first, second)
	}
	joined := strings.Join(first, "\n")
	for _, forbidden := range []string{
		"DYNAMICFLOW_TEST_AMBIENT_SECRET", "must-not-reach-builder",
		"/tmp/operator-go-env", "/tmp/operator-go.work", "https://operator-proxy.invalid",
		"sum.operator.invalid", "/tmp/operator-gitconfig",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("builder environment contains %q: %v", forbidden, first)
		}
	}
	for _, required := range []string{
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=vendor", "GOOS=linux", "GOPROXY=off", "GOSUMDB=off",
		"GOTOOLCHAIN=local", "GOWORK=off", "LANG=C", "LC_ALL=C", "TZ=UTC",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("builder environment missing %q: %v", required, first)
		}
	}
}

func TestReleaseBuildLogRejectsSymlinksHardlinksAndInsecureModes(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "sentinel")
				if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, path+".second"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "insecure-mode",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := privateTempDir(t)
			path := filepath.Join(directory, "release-build.log")
			test.setup(t, path)
			if file, err := openReleaseBuildLog(path, true); err == nil {
				_ = file.Close()
				t.Fatal("unsafe release build log was accepted")
			}
		})
	}

	directory := privateTempDir(t)
	path := filepath.Join(directory, "release-build.log")
	file, err := openReleaseBuildLog(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = openReleaseBuildLog(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("second\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\n" {
		t.Fatalf("secure append log = %q", data)
	}
}

func TestReleaseOperationsFailFastOnSharedOperatorLock(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	if status, _, stderr := invokeCLI(t,
		"--home", home, "--source-root", source,
		"release", "build", "--generation", "23",
	); status != exitOK {
		t.Fatalf("initial release build status=%d: %s", status, stderr)
	}
	stagePath := filepath.Join(home, "releases", "staged.json")
	stageBefore, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	releaseLock := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- store.WithLock(operatorReleaseLock, func() error {
			close(locked)
			<-releaseLock
			return nil
		})
	}()
	<-locked

	commands := [][]string{
		{"--json", "--home", home, "--source-root", source, "release", "build", "--rebuild", "--generation", "24"},
		{"--json", "--home", home, "release", "verify"},
		{"--json", "--home", home, "release", "publish", "--root", filepath.Join(t.TempDir(), "publish"), "--plan"},
	}
	for _, command := range commands {
		status, stdout, stderr := invokeCLI(t, command...)
		if status != exitConflict || stdout != "" || !strings.Contains(stderr, `"code":"release_busy"`) {
			t.Fatalf("busy command %v: status=%d stdout=%q stderr=%q", command, status, stdout, stderr)
		}
	}
	stageAfter, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stageBefore, stageAfter) {
		t.Fatal("busy release build changed staged metadata")
	}
	close(releaseLock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "verify"); status != exitOK || stderr != "" || stdout == "" {
		t.Fatalf("verify after lock release: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func TestReleaseOperationsRejectUnsafeOperatorLockMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "sentinel")
				if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, path+".second"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-mode",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := privateTempDir(t)
			store, err := localstate.Open(home)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnsureDir("releases"); err != nil {
				t.Fatal(err)
			}
			lockPath, _ := store.Path(operatorReleaseLock)
			test.setup(t, lockPath)
			status, stdout, stderr := invokeCLI(t, "--json", "--home", home, "release", "verify")
			if status != exitConfig || stdout != "" || !strings.Contains(stderr, `"code":"release_lock"`) {
				t.Fatalf("unsafe lock: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
		})
	}
}

func TestReleasePlanAndArtifactTamper(t *testing.T) {
	home := privateTempDir(t)
	source := makeReleaseSourceFixture(t)
	if status, _, stderr := invokeCLI(t, "--home", home, "--source-root", source, "init"); status != exitOK {
		t.Fatalf("init status=%d: %s", status, stderr)
	}
	status, stdout, stderr := invokeCLI(t,
		"--json", "--home", home, "--source-root", source,
		"release", "build", "--generation", "42",
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("release build status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "release.build" {
		t.Fatalf("release build envelope = %+v", envelope)
	}

	var stage stagedRelease
	stagePath := filepath.Join(home, "releases", "staged.json")
	data, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &stage); err != nil {
		t.Fatal(err)
	}
	if stage.Signed.Manifest.Generation != 42 || len(stage.Signed.Manifest.Components) != 8 {
		t.Fatalf("staged manifest = %+v", stage.Signed.Manifest)
	}
	if len(stage.Signed.Manifest.Revocations) != 1 ||
		stage.Signed.Manifest.Revocations[0].Component != "ssh" ||
		stage.Signed.Manifest.Revocations[0].Version != "v0.1.5" {
		t.Fatalf("historical SSH revocation missing: %+v", stage.Signed.Manifest.Revocations)
	}

	publishRoot := filepath.Join(t.TempDir(), "serving-releases")
	status, stdout, stderr = invokeCLI(t,
		"--json", "--home", home, "release", "publish",
		"--root", publishRoot, "--plan",
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("publish plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	plan := decodeCLIEnvelope(t, stdout)
	if plan.Command != "release.publish.plan" {
		t.Fatalf("publish plan envelope = %+v", plan)
	}
	if _, err := os.Lstat(publishRoot); !os.IsNotExist(err) {
		t.Fatalf("plan created publish root: %v", err)
	}

	var tamperedPath string
	for logical, path := range stage.ArtifactPaths {
		if logical != "" {
			tamperedPath = path
			break
		}
	}
	if tamperedPath == "" {
		t.Fatal("stage has no artifact paths")
	}
	if err := os.WriteFile(tamperedPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, verifyOutput, verifyError := invokeCLI(t, "--json", "--home", home, "release", "verify")
	if status != exitVerify || verifyOutput != "" {
		t.Fatalf("tamper verify status=%d stdout=%q stderr=%q", status, verifyOutput, verifyError)
	}
	failure := decodeCLIEnvelope(t, verifyError)
	if failure.Error == nil || failure.Error.Code != "verification" || failure.Error.Next == "" {
		t.Fatalf("tamper response = %+v", failure)
	}
}

func makeReleaseSourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "go.mod"), []byte("module dynamicflow-release-fixture\n\ngo 1.23\n"))
	writeFixtureFile(t, filepath.Join(root, "cmd", "flow", "main.go"), []byte("package main\n\nfunc main() {}\n"))
	for _, component := range []string{"ssh", "vpn", "pbp", "decepticon", "examstation"} {
		writeFixtureFile(t, filepath.Join(root, component, "VERSION"), []byte("v1.2.3\n"))
	}
	artifacts := []struct {
		component string
		target    string
		name      string
	}{
		{"ssh", "any", "ssh.tar.gz"},
		{"vpn", "any", "vpn.tar.gz"},
		{"pbp", "linux-amd64", "pbp.tar.gz"},
		{"pbp", "linux-arm64", "pbp.tar.gz"},
		{"decepticon", "any", "decepticon.tar.gz"},
		{"examstation", "any", "examstation.tar.gz"},
	}
	for _, artifact := range artifacts {
		path := filepath.Join(root, "serving", "releases", artifact.component, "v1.2.3", artifact.target, artifact.name)
		writeFixtureFile(t, path, []byte("fixture:"+artifact.component+":"+artifact.target+"\n"))
	}
	sourceProfiles := filepath.Join(repositoryRoot(t), "profiles")
	entries, err := os.ReadDir(sourceProfiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sourceProfiles, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(root, "profiles", entry.Name()), data)
	}
	return root
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
