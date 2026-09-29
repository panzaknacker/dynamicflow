package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

var releaseVersion = regexp.MustCompile(`^v[0-9]+[.][0-9]+[.][0-9]+(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?$`)

type stagedRelease struct {
	Schema        int                    `json:"schema"`
	Signed        release.SignedManifest `json:"signed"`
	ArtifactPaths map[string]string      `json:"artifact_paths"`
	BuildLog      string                 `json:"build_log,omitempty"`
}

const operatorReleaseLock = "releases/operation.lock"
const operatorManifestHistoryDir = "releases/manifest-history"
const operatorManifestCatalogPath = "releases/manifest-history.index.json"

type operatorManifestCatalog struct {
	Schema            int      `json:"schema"`
	SetIDs            []string `json:"set_ids"`
	HighestGeneration uint64   `json:"highest_generation"`
}

var operatorManifestHistoryName = regexp.MustCompile(`^[0-9a-f]{64}[.]json$`)

func withOperatorReleaseLock(ctx *commandContext, operation func() int) int {
	status := exitFailure
	err := ctx.store.WithTryLock(operatorReleaseLock, func() error {
		status = operation()
		return nil
	})
	if errors.Is(err, localstate.ErrLockBusy) {
		return ctx.out.fail(
			"release_busy",
			"another release build, verification or publication is already using the operator release state",
			"Wait for the active release operation to finish, then retry.",
			exitConflict,
		)
	}
	if err != nil {
		return ctx.out.fail(
			"release_lock",
			err.Error(),
			"Repair the owner-only 0600 release lock and private operator-state permissions.",
			exitConfig,
		)
	}
	return status
}

func commandRelease(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow release <build|verify|publish>")
	}
	switch args[0] {
	case "build":
		return releaseBuild(ctx, args[1:])
	case "verify":
		return releaseVerify(ctx, args[1:])
	case "publish":
		return releasePublish(ctx, args[1:])
	default:
		return usage(ctx, "unknown release command: "+args[0])
	}
}

func releaseBuild(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "release build")
	rebuild := flags.Bool("rebuild", false, "rebuild canonical artifacts before signing")
	generationText := flags.String("generation", "", "explicit positive generation for reproducibility")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow release build [--rebuild] [--generation N]")
	}
	return withOperatorReleaseLock(ctx, func() int {
		if ctx.sourceRoot == "" {
			return ctx.out.fail("config", "source root not found", "Run inside the repository or pass --source-root.", exitConfig)
		}
		generation := uint64(time.Now().UTC().Unix())
		if *generationText != "" {
			parsed, err := strconv.ParseUint(*generationText, 10, 64)
			if err != nil || parsed == 0 {
				return usage(ctx, "--generation must be a positive integer")
			}
			generation = parsed
		}
		ctx.out.phase("preflight", "running", "validating profiles and signing key")
		registry, err := loadProfiles(ctx)
		if err != nil {
			return ctx.out.fail("profile", err.Error(), "Repair the declarative profile graph.", exitConfig)
		}
		privatePath, _ := ctx.store.Path("keys/signing/release.private.pem")
		publicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
		privateKey, publicKey, err := loadSigningPair(privatePath, publicPath)
		if err != nil {
			return ctx.out.fail("signing", err.Error(), "Run flow init or restore the release signing key.", exitAuth)
		}
		defer clearRuntimeBytes(privateKey)
		var previousManifest *release.Manifest
		previousStage, stageErr := loadStage(ctx, "")
		switch {
		case stageErr == nil:
			if err := requireOperatorHistoryForExistingStage(ctx); err != nil {
				return ctx.out.fail("version_policy", err.Error(), "Restore the private manifest-history checkpoint and entries before building.", exitVerify)
			}
			if err := release.VerifyManifest(previousStage.Signed, publicKey); err != nil {
				return ctx.out.fail("version_policy", "existing staged release is not authentic: "+err.Error(), "Restore the last authentic staged release before building.", exitVerify)
			}
			if err := retainOperatorManifest(ctx, previousStage.Signed, publicKey); err != nil {
				return ctx.out.fail("version_policy", "could not retain the authentic staged release history: "+err.Error(), "Repair the private operator manifest history before building.", exitVerify)
			}
			manifestCopy := previousStage.Signed.Manifest
			previousManifest = &manifestCopy
		case !errors.Is(stageErr, os.ErrNotExist):
			return ctx.out.fail("version_policy", "existing staged release is unsafe: "+stageErr.Error(), "Repair the private staged release before building.", exitVerify)
		}
		manifestHistory, err := loadOperatorManifestHistory(ctx, publicKey)
		if err != nil {
			return ctx.out.fail("version_policy", "operator manifest history is unsafe: "+err.Error(), "Restore the authentic private manifest history before building.", exitVerify)
		}
		if *generationText == "" {
			for _, previous := range manifestHistory {
				if previous.Generation >= generation {
					if previous.Generation == ^uint64(0) {
						return ctx.out.fail("generation_exhausted", "operator release generation is exhausted", "Rotate to a versioned release schema before signing another release.", exitVerify)
					}
					generation = previous.Generation + 1
				}
			}
		}
		buildRoot, err := ctx.store.EnsureDir("releases/build-inputs")
		if err != nil {
			return ctx.out.fail("config", err.Error(), "Repair local state permissions.", exitConfig)
		}
		logPath, _ := ctx.store.Path("logs/release-build.log")
		if *rebuild {
			ctx.out.phase("artifacts", "running", "reproducibly rebuilding SSH, VPN, PBP, Decepticon, Examstation and flow")
			if err := rebuildArtifacts(ctx, buildRoot, logPath); err != nil {
				audit(ctx, "release.build", "failure", map[string]any{"phase": "artifacts", "error": err.Error(), "log": logPath})
				return ctx.out.fail("build", err.Error(), "Inspect "+logPath+"; no release was signed.", exitFailure)
			}
		}
		inputs, err := discoverArtifacts(ctx, buildRoot, *rebuild, logPath)
		if err != nil {
			return ctx.out.fail("build", err.Error(), "Use --rebuild or restore the immutable component artifact.", exitConfig)
		}
		declarations := registry.List(true)
		manifestProfiles := make([]release.Profile, 0, len(declarations))
		for _, profile := range declarations {
			manifestProfiles = append(manifestProfiles, release.Profile{Name: profile.Name, DependsOn: profile.DependsOn, Components: profile.Components})
		}
		revocations := []release.Revocation{{
			Component: "ssh", Version: "v0.1.5",
			Reason: "revoked: historical release embedded an unauthorized fixed public key",
		}}
		ctx.out.phase("manifest", "running", "hashing direct artifact bindings")
		manifest, err := release.BuildFromArtifacts(generation, inputs, manifestProfiles, revocations)
		if err != nil {
			return ctx.out.fail("manifest", err.Error(), "Fix artifact/profile metadata; nothing was signed.", exitVerify)
		}
		ctx.out.phase("version-policy", "running", "checking immutable component/version bindings before signing")
		if previousManifest != nil {
			err = release.CheckVersionHistory(*previousManifest, manifest)
		}
		for _, previous := range manifestHistory {
			if err != nil {
				break
			}
			err = release.CheckVersionHistory(previous, manifest)
			if err == nil {
				err = release.CheckGenerationHistory(previous, manifest)
			}
		}
		if err == nil {
			err = release.CheckImmutableVersionRoot(filepath.Join(ctx.sourceRoot, "serving", "releases"), manifest)
		}
		if err != nil {
			audit(ctx, "release.build", "failure", map[string]any{"phase": "version-policy", "error": err.Error()})
			if errors.Is(err, release.ErrVersionConflict) {
				return ctx.out.fail("version_conflict", err.Error(), "Bump the affected component VERSION; the existing version-to-bytes binding is immutable.", exitVerify)
			}
			if errors.Is(err, release.ErrReleaseRollback) {
				return ctx.out.fail("release_rollback", err.Error(), "Use a generation above the private operator history high-water mark; nothing was signed.", exitVerify)
			}
			return ctx.out.fail("version_policy", err.Error(), "Repair ownership, modes or path metadata in the immutable release root; nothing was signed.", exitVerify)
		}
		ctx.out.phase("version-policy", "complete", "all existing bindings match")
		signed, err := release.SignManifest(manifest, privateKey)
		if err != nil {
			return ctx.out.fail("signing", err.Error(), "Check the release signing key.", exitAuth)
		}
		if err := retainOperatorManifest(ctx, signed, publicKey); err != nil {
			return ctx.out.fail("version_policy", "could not persist immutable manifest history: "+err.Error(), "Repair private operator state; staged metadata was not changed.", exitVerify)
		}
		if _, err := loadOperatorManifestHistory(ctx, publicKey); err != nil {
			return ctx.out.fail("version_policy", "could not checkpoint immutable manifest history: "+err.Error(), "Repair private operator state; staged metadata was not changed.", exitVerify)
		}
		paths := make(map[string]string, len(inputs))
		for _, component := range signed.Manifest.Components {
			for _, input := range inputs {
				if component.Name == input.Component && component.Version == input.Version && component.Target == input.Target {
					paths[component.Artifact] = input.SourcePath
				}
			}
		}
		stage := stagedRelease{Schema: 1, Signed: signed, ArtifactPaths: paths, BuildLog: logPath}
		canonical, err := signing.CanonicalJSON(signed)
		if err != nil || ctx.store.WriteFile("releases/signed-manifest.json", canonical) != nil {
			return ctx.out.fail("config", "could not persist canonical signed manifest", "Repair local state permissions; the publishable stage was not changed.", exitConfig)
		}
		// staged.json is the final operator-side commit marker. verify and publish
		// also require the canonical export above to match it exactly, so an
		// interruption between these two atomic writes fails closed instead of
		// exposing a partially committed candidate.
		if err := ctx.store.WriteJSON("releases/staged.json", stage); err != nil {
			return ctx.out.fail("config", err.Error(), "Repair local state permissions; release state will remain blocked until a successful rebuild.", exitConfig)
		}
		manifestPath, _ := ctx.store.Path("releases/signed-manifest.json")
		audit(ctx, "release.build", "success", map[string]any{"set_id": manifest.SetID, "generation": manifest.Generation, "components": len(manifest.Components)})
		ctx.out.phase("manifest", "complete", manifest.SetID)
		data := map[string]any{"set_id": manifest.SetID, "generation": manifest.Generation, "manifest": manifestPath, "artifacts": manifest.Components, "build_log": logPath}
		return ctx.out.success("release.build", data, fmt.Sprintf("Signed release %s\nManifest: %s\nBuild log: %s", manifest.SetID, manifestPath, logPath))
	})
}

func retainOperatorManifest(ctx *commandContext, signed release.SignedManifest, publicKey ed25519.PublicKey) error {
	if ctx == nil || ctx.store == nil {
		return errors.New("operator state is unavailable")
	}
	if err := release.VerifyManifest(signed, publicKey); err != nil {
		return err
	}
	setName := strings.TrimPrefix(signed.Manifest.SetID, "sha256:")
	if len(setName) != 64 || !operatorManifestHistoryName.MatchString(setName+".json") {
		return errors.New("invalid release set identifier")
	}
	relative := filepath.ToSlash(filepath.Join(operatorManifestHistoryDir, setName+".json"))
	canonical, err := signing.CanonicalJSON(signed)
	if err != nil {
		return err
	}
	existing, readErr := ctx.store.ReadFile(relative)
	switch {
	case readErr == nil:
		if !bytes.Equal(existing, canonical) {
			return errors.New("content-addressed operator manifest history conflicts")
		}
		return nil
	case !errors.Is(readErr, os.ErrNotExist):
		return readErr
	default:
		return ctx.store.WriteFile(relative, canonical)
	}
}

func loadOperatorManifestHistory(ctx *commandContext, publicKey ed25519.PublicKey) ([]release.Manifest, error) {
	if ctx == nil || ctx.store == nil {
		return nil, errors.New("operator state is unavailable")
	}
	var checkpoint operatorManifestCatalog
	checkpointFound := false
	if err := ctx.store.ReadJSON(operatorManifestCatalogPath, &checkpoint); err == nil {
		checkpointFound = true
		if checkpoint.Schema != 1 || !sort.StringsAreSorted(checkpoint.SetIDs) {
			return nil, errors.New("operator manifest-history checkpoint is invalid")
		}
		for index, setID := range checkpoint.SetIDs {
			if len(setID) != 71 || !strings.HasPrefix(setID, "sha256:") || !operatorManifestHistoryName.MatchString(strings.TrimPrefix(setID, "sha256:")+".json") || index > 0 && checkpoint.SetIDs[index-1] == setID {
				return nil, errors.New("operator manifest-history checkpoint contains an invalid set ID")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if checkpointFound {
		historyPath, err := ctx.store.Path(operatorManifestHistoryDir)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(historyPath); errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("operator manifest-history deletion detected: checkpointed directory is missing")
		} else if err != nil {
			return nil, err
		}
	}
	directory, err := ctx.store.EnsureDir(operatorManifestHistoryDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if !checkpointFound && len(entries) != 0 {
		return nil, errors.New("uncheckpointed operator manifest history requires an explicit audited migration")
	}
	manifests := make([]release.Manifest, 0, len(entries))
	generations := make(map[uint64]string, len(entries))
	setIDs := make(map[string]uint64, len(entries))
	for _, entry := range entries {
		if !operatorManifestHistoryName.MatchString(entry.Name()) || !entry.Type().IsRegular() || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("unexpected operator manifest-history entry")
		}
		relative := filepath.ToSlash(filepath.Join(operatorManifestHistoryDir, entry.Name()))
		data, err := ctx.store.ReadFile(relative)
		if err != nil {
			return nil, err
		}
		var signed release.SignedManifest
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&signed); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("operator manifest history contains trailing data")
		}
		canonical, err := signing.CanonicalJSON(signed)
		if err != nil || !bytes.Equal(canonical, data) {
			return nil, errors.New("operator manifest history is not canonical")
		}
		if err := release.VerifyManifest(signed, publicKey); err != nil {
			return nil, err
		}
		if strings.TrimPrefix(signed.Manifest.SetID, "sha256:")+".json" != entry.Name() {
			return nil, errors.New("operator manifest history filename is not content-addressed")
		}
		if setID, exists := generations[signed.Manifest.Generation]; exists && setID != signed.Manifest.SetID {
			return nil, fmt.Errorf("%w: operator history generation %d identifies multiple sets", release.ErrReleaseRollback, signed.Manifest.Generation)
		}
		generations[signed.Manifest.Generation] = signed.Manifest.SetID
		setIDs[signed.Manifest.SetID] = signed.Manifest.Generation
		for _, previous := range manifests {
			if err := release.CheckVersionHistory(previous, signed.Manifest); err != nil {
				return nil, err
			}
		}
		manifests = append(manifests, signed.Manifest)
	}
	if checkpointFound {
		var checkpointHigh uint64
		for _, setID := range checkpoint.SetIDs {
			generation, exists := setIDs[setID]
			if !exists {
				return nil, fmt.Errorf("operator manifest-history deletion detected: checkpointed set %s is missing", setID)
			}
			if generation > checkpointHigh {
				checkpointHigh = generation
			}
		}
		if checkpoint.HighestGeneration != checkpointHigh {
			return nil, errors.New("operator manifest-history checkpoint high-water is inconsistent")
		}
	}
	catalog := operatorManifestCatalog{Schema: 1, SetIDs: make([]string, 0, len(setIDs))}
	for setID, generation := range setIDs {
		catalog.SetIDs = append(catalog.SetIDs, setID)
		if generation > catalog.HighestGeneration {
			catalog.HighestGeneration = generation
		}
	}
	sort.Strings(catalog.SetIDs)
	if !checkpointFound || !reflect.DeepEqual(checkpoint, catalog) {
		if err := ctx.store.WriteJSON(operatorManifestCatalogPath, catalog); err != nil {
			return nil, err
		}
	}
	return manifests, nil
}

func requireOperatorHistoryForExistingStage(ctx *commandContext) error {
	if ctx == nil || ctx.store == nil {
		return errors.New("operator state is unavailable")
	}
	if _, err := ctx.store.ReadFile(operatorManifestCatalogPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return errors.New("operator manifest-history checkpoint is missing for an existing stage")
}

func verifyOperatorManifestCatalogCandidate(history []release.Manifest, candidate release.Manifest) error {
	found := false
	for _, previous := range history {
		if err := release.CheckVersionHistory(previous, candidate); err != nil {
			return err
		}
		if err := release.CheckGenerationHistory(previous, candidate); err != nil {
			return err
		}
		if previous.SetID == candidate.SetID {
			if !reflect.DeepEqual(previous, candidate) {
				return errors.New("operator manifest-history candidate differs from its content-addressed entry")
			}
			found = true
		}
	}
	if !found {
		return errors.New("staged release is missing from the operator manifest-history checkpoint")
	}
	return nil
}

func rebuildArtifacts(ctx *commandContext, buildRoot, logPath string) error {
	log, err := openReleaseBuildLog(logPath, true)
	if err != nil {
		return err
	}
	if err := log.Close(); err != nil {
		return err
	}
	versions := map[string]string{}
	for _, component := range []string{"ssh", "vpn", "pbp", "decepticon", "examstation"} {
		version, err := readVersion(filepath.Join(ctx.sourceRoot, component, "VERSION"))
		if err != nil {
			return err
		}
		versions[component] = version
	}
	commands := []struct {
		phase string
		path  string
		args  []string
		dist  string
		env   map[string]string
	}{
		{"ssh", filepath.Join(ctx.sourceRoot, "ssh", "make-toolkit-release.sh"), []string{versions["ssh"]}, filepath.Join(buildRoot, "ssh"), nil},
		{"vpn", filepath.Join(ctx.sourceRoot, "vpn", "make-release.sh"), []string{versions["vpn"]}, filepath.Join(buildRoot, "vpn"), nil},
		{"pbp-amd64", filepath.Join(ctx.sourceRoot, "pbp", "make-release.sh"), []string{"amd64", versions["pbp"]}, filepath.Join(buildRoot, "pbp"), nil},
		{"pbp-arm64", filepath.Join(ctx.sourceRoot, "pbp", "make-release.sh"), []string{"arm64", versions["pbp"]}, filepath.Join(buildRoot, "pbp"), nil},
		// the user's current working tree is the explicit source of truth. the
		// decepticon builder records source_dirty=true in BUILD_INFO while still
		// producing deterministic bytes from that exact tree.
		{"decepticon", filepath.Join(ctx.sourceRoot, "decepticon", "make-release.sh"), []string{versions["decepticon"]}, filepath.Join(buildRoot, "decepticon"), map[string]string{"DECEPTICON_ALLOW_DIRTY": "1"}},
		{"examstation", filepath.Join(ctx.sourceRoot, "examstation", "make-release.sh"), []string{versions["examstation"]}, filepath.Join(buildRoot, "examstation"), nil},
	}
	for _, item := range commands {
		ctx.out.phase("artifact:"+item.phase, "running", filepath.Base(item.path))
		if err := runBuilderWithEnvironment(item.path, item.args, item.dist, logPath, item.env); err != nil {
			return fmt.Errorf("%s builder: %w", item.phase, err)
		}
		ctx.out.phase("artifact:"+item.phase, "complete", "")
	}
	return nil
}

func buildFlowArtifacts(ctx *commandContext, buildRoot, logPath string) error {
	for _, architecture := range []string{"amd64", "arm64"} {
		directory := filepath.Join(buildRoot, "flow", "linux-"+architecture)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		output := filepath.Join(directory, "flow")
		operation, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		command := exec.CommandContext(operation, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, "./cmd/flow")
		command.Dir = ctx.sourceRoot
		command.Env = environmentWith(map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": architecture})
		log, err := openReleaseBuildLog(logPath, false)
		if err != nil {
			cancel()
			return err
		}
		command.Stdout, command.Stderr = log, log
		err = command.Run()
		cancel()
		if err == nil {
			err = validateReleaseBuildLog(logPath, log)
		}
		if err == nil {
			err = log.Sync()
		}
		if closeErr := log.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("flow linux-%s build: %w", architecture, err)
		}
		if err := os.Chmod(output, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func environmentWith(values map[string]string) []string {
	allowed := map[string]string{
		"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
		"GOENV": "off", "GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOSUMDB": "off",
		"GOTOOLCHAIN": "local", "GOWORK": "off",
		"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PYTHONHASHSEED": "0",
	}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOPATH"} {
		if value, exists := os.LookupEnv(name); exists {
			allowed[name] = value
		}
	}
	for name, value := range values {
		allowed[name] = value
	}
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+allowed[name])
	}
	return result
}

func runBuilder(path string, arguments []string, dist, logPath string) error {
	return runBuilderWithEnvironment(path, arguments, dist, logPath, nil)
}

func runBuilderWithEnvironment(path string, arguments []string, dist, logPath string, extraEnvironment map[string]string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe builder path: %s", path)
	}
	if err := os.MkdirAll(dist, 0o700); err != nil {
		return err
	}
	log, err := openReleaseBuildLog(logPath, false)
	if err != nil {
		return err
	}
	defer log.Close()
	operation, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	command := exec.CommandContext(operation, path, arguments...)
	environment := map[string]string{"TOOLKIT_DIST_DIR": dist, "PYTHONDONTWRITEBYTECODE": "1"}
	for name, value := range extraEnvironment {
		environment[name] = value
	}
	command.Env = environmentWith(environment)
	command.Stdout = log
	command.Stderr = log
	if err := command.Run(); err != nil {
		return err
	}
	if err := validateReleaseBuildLog(logPath, log); err != nil {
		return err
	}
	return log.Sync()
}

// openReleaseBuildLog never follows the final path and validates both the
// opened descriptor and its directory entry before a builder can write. this
// keeps an attacker-controlled symlink or hardlink in private operator state
// from redirecting build output or truncating another file.
func openReleaseBuildLog(path string, truncate bool) (*os.File, error) {
	flags := os.O_WRONLY | os.O_APPEND | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	file, err := os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open release build log safely: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, fmt.Errorf("secure release build log: %w", err)
		}
	}
	if err := validateReleaseBuildLog(path, file); err != nil {
		return nil, err
	}
	if truncate {
		if err := file.Truncate(0); err != nil {
			return nil, fmt.Errorf("truncate release build log safely: %w", err)
		}
		if _, err := file.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("rewind release build log: %w", err)
		}
		if err := file.Sync(); err != nil {
			return nil, fmt.Errorf("sync release build log: %w", err)
		}
	}
	closeOnError = false
	return file, nil
}

func validateReleaseBuildLog(path string, file *os.File) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect release build log: %w", err)
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		int(openedStat.Uid) != os.Geteuid() || openedStat.Nlink != 1 {
		return errors.New("release build log is not an owner-only singly-linked regular file")
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect release build log path: %w", err)
	}
	linkedStat, ok := linked.Sys().(*syscall.Stat_t)
	if !ok || linked.Mode()&os.ModeSymlink != 0 || linkedStat.Dev != openedStat.Dev || linkedStat.Ino != openedStat.Ino {
		return errors.New("release build log path changed during use")
	}
	return nil
}

func discoverArtifacts(ctx *commandContext, buildRoot string, rebuilt bool, logPath string) ([]release.ArtifactInput, error) {
	versions := map[string]string{}
	for _, component := range []string{"ssh", "vpn", "pbp", "decepticon", "examstation"} {
		version, err := readVersion(filepath.Join(ctx.sourceRoot, component, "VERSION"))
		if err != nil {
			return nil, err
		}
		versions[component] = version
	}
	ctx.out.phase("artifact:flow", "running", "building static amd64/arm64 bootstrap binaries")
	if err := buildFlowArtifacts(ctx, buildRoot, logPath); err != nil {
		return nil, err
	}
	ctx.out.phase("artifact:flow", "complete", "")
	versions["flow"] = "v" + strings.TrimPrefix(Version, "v")
	existing := filepath.Join(ctx.sourceRoot, "serving", "releases")
	pathFor := func(component, target, file string) string {
		if rebuilt {
			switch component {
			case "pbp":
				return filepath.Join(buildRoot, component, target, file)
			default:
				return filepath.Join(buildRoot, component, file)
			}
		}
		return filepath.Join(existing, component, versions[component], target, file)
	}
	// examstation was historically outside the aggregate release. build its
	// exact current artifact on demand instead of silently selecting an older one.
	examPath := pathFor("examstation", "any", "examstation.tar.gz")
	if !rebuilt && !regularFile(examPath) {
		ctx.out.phase("artifact:examstation", "running", "building missing current artifact")
		if err := runBuilder(filepath.Join(ctx.sourceRoot, "examstation", "make-release.sh"), []string{versions["examstation"]}, filepath.Join(buildRoot, "examstation"), logPath); err != nil {
			return nil, fmt.Errorf("examstation builder: %w", err)
		}
		examPath = filepath.Join(buildRoot, "examstation", "examstation.tar.gz")
	}
	inputs := []release.ArtifactInput{
		{Component: "flow", Version: versions["flow"], Target: "linux-amd64", ArtifactName: "flow", SourcePath: filepath.Join(buildRoot, "flow", "linux-amd64", "flow")},
		{Component: "flow", Version: versions["flow"], Target: "linux-arm64", ArtifactName: "flow", SourcePath: filepath.Join(buildRoot, "flow", "linux-arm64", "flow")},
		{Component: "ssh", Version: versions["ssh"], Target: "any", ArtifactName: "ssh.tar.gz", SourcePath: pathFor("ssh", "any", "ssh.tar.gz")},
		{Component: "vpn", Version: versions["vpn"], Target: "any", ArtifactName: "vpn.tar.gz", SourcePath: pathFor("vpn", "any", "vpn.tar.gz")},
		{Component: "pbp", Version: versions["pbp"], Target: "linux-amd64", ArtifactName: "pbp.tar.gz", SourcePath: pathFor("pbp", "linux-amd64", "pbp.tar.gz")},
		{Component: "pbp", Version: versions["pbp"], Target: "linux-arm64", ArtifactName: "pbp.tar.gz", SourcePath: pathFor("pbp", "linux-arm64", "pbp.tar.gz")},
		{Component: "decepticon", Version: versions["decepticon"], Target: "any", ArtifactName: "decepticon.tar.gz", SourcePath: pathFor("decepticon", "any", "decepticon.tar.gz")},
		{Component: "examstation", Version: versions["examstation"], Target: "any", ArtifactName: "examstation.tar.gz", SourcePath: examPath},
	}
	for _, input := range inputs {
		if !regularFile(input.SourcePath) {
			return nil, fmt.Errorf("missing immutable %s artifact: %s", input.Component, input.SourcePath)
		}
	}
	return inputs, nil
}

func readVersion(path string) (string, error) {
	data, err := release.ReadRegularFile(path, 256)
	if err != nil {
		return "", fmt.Errorf("unsafe version file: %s", path)
	}
	version := strings.TrimSpace(string(data))
	if !releaseVersion.MatchString(version) {
		return "", fmt.Errorf("invalid version in %s", path)
	}
	return version, nil
}

func regularFile(path string) bool {
	size, err := release.RegularFileSize(path)
	return err == nil && size > 0
}

func loadStage(ctx *commandContext, path string) (stagedRelease, error) {
	var stage stagedRelease
	if path == "" {
		if err := ctx.store.ReadJSON("releases/staged.json", &stage); err != nil {
			return stage, err
		}
	} else {
		if !filepath.IsAbs(path) {
			return stage, errors.New("release stage path must be absolute")
		}
		data, err := release.ReadRegularFile(path, 16<<20)
		if err != nil {
			return stage, errors.New("release stage path is unsafe")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stage); err != nil {
			return stage, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return stage, errors.New("release stage contains trailing data")
		}
	}
	if stage.Schema != 1 {
		return stage, errors.New("unsupported staged release schema")
	}
	return stage, nil
}

func verifyDefaultStageExport(ctx *commandContext, stage stagedRelease) error {
	if ctx == nil || ctx.store == nil {
		return errors.New("operator release state is unavailable")
	}
	exported, err := ctx.store.ReadFile("releases/signed-manifest.json")
	if err != nil {
		return fmt.Errorf("read canonical signed manifest: %w", err)
	}
	canonical, err := signing.CanonicalJSON(stage.Signed)
	if err != nil {
		return err
	}
	if !bytes.Equal(exported, canonical) {
		return errors.New("staged release and canonical signed manifest do not match")
	}
	return nil
}

func releaseVerify(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "release verify")
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		return usage(ctx, "usage: flow release verify [ABSOLUTE-STAGE-PATH]")
	}
	path := ""
	if flags.NArg() == 1 {
		path = flags.Arg(0)
	}
	return withOperatorReleaseLock(ctx, func() int {
		stage, err := loadStage(ctx, path)
		if err != nil {
			return ctx.out.fail("release", err.Error(), "Build a release or provide its private staged metadata path.", exitConfig)
		}
		if path == "" {
			if err := verifyDefaultStageExport(ctx, stage); err != nil {
				return ctx.out.fail("release_state", err.Error(), "Run flow release build to reconcile the interrupted operator release commit.", exitVerify)
			}
		}
		publicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
		publicKey, err := signing.LoadPublicFile(publicPath)
		if err == nil {
			err = release.VerifyManifest(stage.Signed, publicKey)
		}
		if err == nil {
			err = release.VerifyArtifacts(stage.Signed.Manifest, stage.ArtifactPaths)
		}
		if err != nil {
			audit(ctx, "release.verify", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "error": err.Error()})
			return ctx.out.fail("verification", err.Error(), "Do not publish; rebuild from trusted sources.", exitVerify)
		}
		if path == "" {
			if err := requireOperatorHistoryForExistingStage(ctx); err != nil {
				return ctx.out.fail("version_policy", err.Error(), "Restore the private manifest-history checkpoint before trusting this stage.", exitVerify)
			}
			history, err := loadOperatorManifestHistory(ctx, publicKey)
			if err == nil {
				err = verifyOperatorManifestCatalogCandidate(history, stage.Signed.Manifest)
			}
			if err != nil {
				return ctx.out.fail("version_policy", err.Error(), "Restore the authentic private manifest history; do not publish this stage.", exitVerify)
			}
		}
		audit(ctx, "release.verify", "success", map[string]any{"set_id": stage.Signed.Manifest.SetID})
		return ctx.out.success("release.verify", map[string]any{"verified": true, "set_id": stage.Signed.Manifest.SetID, "components": len(stage.Signed.Manifest.Components)}, "Verified release "+stage.Signed.Manifest.SetID)
	})
}

func releasePublish(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "release publish")
	root := flags.String("root", "", "absolute serving release root")
	forceRemote := flags.Bool("remote", false, "publish to the configured pinned serving node")
	plan := flags.Bool("plan", false, "show changes without writing")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow release publish [--remote | --root ABSOLUTE-PATH] [--plan]")
	}
	if *forceRemote && *root != "" {
		return usage(ctx, "--remote and --root are mutually exclusive")
	}
	return withOperatorReleaseLock(ctx, func() int {
		var remote *remoteServing
		useRemote := false
		if *forceRemote || *root == "" {
			_, configuredErr := ctx.store.ReadFile("serving/remote.json")
			switch {
			case configuredErr == nil:
				var err error
				remote, err = loadRemoteServing(ctx)
				if err != nil {
					return ctx.out.fail("serving", err.Error(), "Repair or repeat flow serving configure; no release was published.", exitConfig)
				}
				useRemote = true
			case *forceRemote:
				return ctx.out.fail("serving", "no pinned remote serving configuration is available", "Run flow serving configure first.", exitConfig)
			case !errors.Is(configuredErr, os.ErrNotExist):
				return ctx.out.fail("serving", configuredErr.Error(), "Repair the private serving configuration.", exitConfig)
			}
		}
		if !useRemote {
			if *root == "" {
				*root, _ = ctx.store.Path("serving/releases")
			}
			if !filepath.IsAbs(*root) || filepath.Clean(*root) == string(filepath.Separator) {
				return usage(ctx, "--root must be an absolute non-root path")
			}
		}
		stage, err := loadStage(ctx, "")
		if err != nil {
			return ctx.out.fail("release", err.Error(), "Run flow release build first.", exitConfig)
		}
		if err := verifyDefaultStageExport(ctx, stage); err != nil {
			return ctx.out.fail("release_state", err.Error(), "Run flow release build to reconcile the interrupted operator release commit; no publish was attempted.", exitVerify)
		}
		componentNames := make([]string, 0, len(stage.Signed.Manifest.Components))
		for _, component := range stage.Signed.Manifest.Components {
			componentNames = append(componentNames, component.Name+":"+component.Version+":"+component.Target)
		}
		sort.Strings(componentNames)
		publicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
		publicKey, err := signing.LoadPublicFile(publicPath)
		if err == nil {
			err = release.VerifyManifest(stage.Signed, publicKey)
		}
		if err == nil && useRemote {
			err = release.VerifyArtifacts(stage.Signed.Manifest, stage.ArtifactPaths)
		}
		if err != nil {
			return ctx.out.fail("verification", err.Error(), "Do not publish; rebuild from trusted sources.", exitVerify)
		}
		if err := requireOperatorHistoryForExistingStage(ctx); err != nil {
			return ctx.out.fail("version_policy", err.Error(), "Restore the private manifest-history checkpoint; no publish was attempted.", exitVerify)
		}
		history, err := loadOperatorManifestHistory(ctx, publicKey)
		if err == nil {
			err = verifyOperatorManifestCatalogCandidate(history, stage.Signed.Manifest)
		}
		if err != nil {
			code := "version_policy"
			next := "Restore the authentic private manifest history; no publish was attempted."
			if errors.Is(err, release.ErrReleaseRollback) {
				code = "release_rollback"
				next = "Build or restore the release at the private operator history high-water mark."
			} else if errors.Is(err, release.ErrVersionConflict) {
				code = "version_conflict"
				next = "Restore the immutable version binding or bump the affected component VERSION."
			}
			return ctx.out.fail(code, err.Error(), next, exitVerify)
		}
		if useRemote {
			if err := verifyOperatorReleaseCandidate(ctx, stage.Signed.Manifest); err != nil {
				return ctx.out.fail("release_rollback", err.Error(), "Build a release above the pinned high-water mark; no upload was attempted.", exitVerify)
			}
		}
		destination := *root
		operation := "verify-copy-atomic-pointer-switch"
		bundleBytes := int64(0)
		if useRemote {
			destination = remote.config.BaseURL
			operation = "signed-stream-upload-server-reverify-atomic-pointer-switch"
			bundleBytes, err = release.BundleSize(stage.Signed)
			if err != nil {
				return ctx.out.fail("release", err.Error(), "Rebuild the staged release.", exitVerify)
			}
		}
		data := map[string]any{"plan": *plan, "set_id": stage.Signed.Manifest.SetID, "destination": destination, "components": componentNames, "operation": operation}
		if useRemote {
			data["bundle_bytes"] = bundleBytes
		} else {
			data["root"] = *root
		}
		if *plan {
			if useRemote {
				operation, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var response struct {
					Status     string `json:"status"`
					SetID      string `json:"set_id"`
					Generation uint64 `json:"generation"`
				}
				if err := remote.controlJSON(operation, http.MethodPost, "/v1/admin/releases/plan", stage.Signed, &response, http.StatusOK); err != nil {
					return ctx.out.fail("publish_plan", safeRemoteError(err), "Resolve the remote retained-history or generation conflict before uploading.", exitVerify)
				}
				if response.Status != "allowed" || response.SetID != stage.Signed.Manifest.SetID || response.Generation != stage.Signed.Manifest.Generation {
					return ctx.out.fail("publish_plan", "serving returned an invalid release-plan receipt", "Do not upload; inspect serving audit and release history.", exitVerify)
				}
			} else {
				if err := release.CheckPublishPolicy(*root, stage.Signed, publicKey); err != nil {
					return ctx.out.fail("publish_plan", err.Error(), "Resolve the retained-history, path or generation conflict before publishing.", exitVerify)
				}
				committed := false
				if existing, _, openErr := release.OpenSet(*root, stage.Signed.Manifest.SetID, publicKey); openErr == nil {
					if !reflect.DeepEqual(existing, stage.Signed) {
						return ctx.out.fail("publish_plan", "committed release set does not match the staged candidate", "Do not publish; inspect the immutable release root.", exitVerify)
					}
					committed = true
				} else if verifyErr := release.VerifyArtifacts(stage.Signed.Manifest, stage.ArtifactPaths); verifyErr != nil {
					return ctx.out.fail("publish_plan", verifyErr.Error(), "Restore the staged artifacts or retain the complete committed set before publishing.", exitVerify)
				}
				data["resume_committed_set"] = committed
			}
			data["policy_preflight"] = "allowed"
			return ctx.out.success("release.publish.plan", data, fmt.Sprintf("PLAN: verify and atomically activate %s at %s\nComponents: %s", stage.Signed.Manifest.SetID, destination, strings.Join(componentNames, ", ")))
		}
		if err := audit(ctx, "release.publish", "started", map[string]any{"set_id": stage.Signed.Manifest.SetID, "destination": destination}); err != nil {
			return ctx.out.fail("audit_unavailable", "local audit event could not be committed; release was not published", "Repair the private audit log and retry.", exitFailure)
		}
		ctx.out.phase("verify", "running", stage.Signed.Manifest.SetID)
		if useRemote {
			return releasePublishRemote(ctx, remote, stage, publicKey, data)
		}
		err = release.Publish(*root, stage.Signed, stage.ArtifactPaths, publicKey)
		if err != nil {
			audit(ctx, "release.publish", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "error": err.Error()})
			return ctx.out.fail("publish", err.Error(), "The previous current pointer remains active; inspect serving release state.", exitVerify)
		}
		if err := audit(ctx, "release.publish", "success", map[string]any{"set_id": stage.Signed.Manifest.SetID, "root": *root}); err != nil {
			return ctx.out.fail("audit_unavailable", "release activated but audit completion could not be committed", "Treat the release as active; repair the audit log before further lifecycle changes.", exitPartial)
		}
		return ctx.out.success("release.publish", data, fmt.Sprintf("Published and atomically activated %s\nRoot: %s", stage.Signed.Manifest.SetID, *root))
	})
}

func releasePublishRemote(ctx *commandContext, remote *remoteServing, stage stagedRelease, publicKey []byte, data map[string]any) int {
	temporaryRoot, err := ctx.store.EnsureDir("releases/upload")
	if err != nil {
		return ctx.out.fail("state", err.Error(), "Repair private operator-state permissions.", exitConfig)
	}
	bundle, err := os.CreateTemp(temporaryRoot, ".release-bundle-")
	if err != nil {
		return ctx.out.fail("state", err.Error(), "Free local disk space and retry.", exitFailure)
	}
	bundlePath := bundle.Name()
	defer os.Remove(bundlePath)
	defer bundle.Close()
	if err := bundle.Chmod(0o600); err != nil {
		return ctx.out.fail("state", err.Error(), "Repair private operator-state permissions.", exitFailure)
	}
	ctx.out.phase("bundle", "running", "streaming canonical verified release bundle")
	size, digest, err := release.WriteBundle(bundle, stage.Signed, stage.ArtifactPaths, publicKey)
	if err == nil {
		err = bundle.Sync()
	}
	if err != nil {
		audit(ctx, "release.publish", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "phase": "bundle"})
		return ctx.out.fail("bundle", err.Error(), "Staged inputs changed or local disk is unavailable; rebuild and retry.", exitVerify)
	}
	ctx.out.phase("upload", "running", fmt.Sprintf("uploading %d verified bytes over pinned HTTPS", size))
	operation, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	var response struct {
		Status     string `json:"status"`
		SetID      string `json:"set_id"`
		Generation uint64 `json:"generation"`
		Bytes      int64  `json:"bytes"`
	}
	if err := remote.controlReleaseBundle(operation, bundle, size, digest, &response); err != nil {
		audit(ctx, "release.publish", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "phase": "upload"})
		return ctx.out.fail("publish", safeRemoteError(err), "The previous remote release remains active unless serving reported activation; inspect serving health and retry idempotently.", exitRemote)
	}
	if response.Status != "activated" || response.SetID != stage.Signed.Manifest.SetID || response.Generation != stage.Signed.Manifest.Generation || response.Bytes != size {
		audit(ctx, "release.publish", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "phase": "receipt"})
		return ctx.out.fail("verification", "serving returned an invalid release activation receipt", "Do not issue desired state; inspect serving audit and health.", exitVerify)
	}
	var current release.SignedManifest
	if err := remote.publicJSON(operation, http.MethodGet, "/v1/releases/current/manifest", &current); err != nil ||
		release.VerifyManifest(current, publicKey) != nil || current.Manifest.SetID != stage.Signed.Manifest.SetID {
		audit(ctx, "release.publish", "failure", map[string]any{"set_id": stage.Signed.Manifest.SetID, "phase": "activation_proof"})
		return ctx.out.fail("verification", "serving did not prove the activated signed release", "Do not issue desired state; inspect serving health and retry verification.", exitVerify)
	}
	if err := acceptOperatorReleaseHighWater(ctx, current.Manifest); err != nil {
		return ctx.out.fail("release_rollback", err.Error(), "Do not trust this serving node; restore a release at or above the operator high-water mark.", exitVerify)
	}
	remote.config.ReleaseSet = current.Manifest.SetID
	remote.config.ConfiguredAt = time.Now().UTC()
	if err := ctx.store.WriteJSON("serving/remote.json", remote.config); err != nil {
		return ctx.out.fail("state", "remote release activated but local serving checkpoint could not be committed", "Repair private state and repeat flow serving configure before lifecycle changes.", exitFailure)
	}
	if err := audit(ctx, "release.publish", "success", map[string]any{"set_id": current.Manifest.SetID, "destination": remote.config.BaseURL}); err != nil {
		return ctx.out.fail("audit_unavailable", "remote release activated but audit completion could not be committed", "Treat the release as active; repair the private audit log before further lifecycle changes.", exitPartial)
	}
	return ctx.out.success("release.publish", data, fmt.Sprintf("Published and atomically activated %s\nServing: %s", current.Manifest.SetID, remote.config.BaseURL))
}

func verifyOperatorReleaseCandidate(ctx *commandContext, manifest release.Manifest) error {
	if ctx == nil || ctx.store == nil || manifest.Generation == 0 || !remoteReleaseSetID.MatchString(manifest.SetID) {
		return errors.New("invalid release high-water candidate")
	}
	return ctx.store.WithLock("serving/release-high-water.lock", func() error {
		var current operatorReleaseHighWater
		err := ctx.store.ReadJSON(operatorReleaseHighWaterPath, &current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Schema != 1 || current.Generation == 0 || !remoteReleaseSetID.MatchString(current.SetID) {
			return errors.New("invalid operator release high-water state")
		}
		if manifest.Generation < current.Generation {
			return fmt.Errorf("signed release generation %d is below pinned generation %d", manifest.Generation, current.Generation)
		}
		if manifest.Generation == current.Generation && manifest.SetID != current.SetID {
			return errors.New("signed release generation conflicts with the pinned set")
		}
		return nil
	})
}
