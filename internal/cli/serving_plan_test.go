package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/tlsutil"
)

type servingPlanTestFixture struct {
	ctx         *commandContext
	home        string
	input       servingPlanInput
	environment servingPlanEnvironment
	privatePEM  []byte
}

func TestInternalServingPlanCreatesNothing(t *testing.T) {
	fixture := newServingPlanTestFixture(t, false)
	beforeState := snapshotServingPlanTree(t, fixture.input.StateRoot)
	beforeHome := snapshotServingPlanTree(t, fixture.home)

	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
		"--json", "--home", fixture.home, "start", "serving", "--plan",
		"--state-root", fixture.input.StateRoot,
		"--release-root", fixture.input.ReleaseRoot,
		"--public-url", fixture.input.PublicURL,
		"--listen", fixture.input.Listen,
		"--release-public-key", fixture.input.ReleaseKeySource,
		"--desired-public-key", fixture.input.DesiredKeySource,
		"--control-public-key", fixture.input.ControlKeySource,
	)
	if status != exitOK || stderr != "" {
		t.Fatalf("plan status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stdout)
	if !envelope.OK || envelope.Command != "start.serving.plan" {
		t.Fatalf("unexpected plan envelope: %+v", envelope)
	}
	var plan servingReconcilePlan
	if err := json.Unmarshal(envelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.State != "changes" || !plan.Changed || plan.Unsafe {
		t.Fatalf("first-run plan=%+v", plan)
	}
	if after := snapshotServingPlanTree(t, fixture.input.StateRoot); !reflect.DeepEqual(after, beforeState) {
		t.Fatalf("plan mutated serving state\nbefore=%v\nafter=%v", beforeState, after)
	}
	if after := snapshotServingPlanTree(t, fixture.home); !reflect.DeepEqual(after, beforeHome) {
		t.Fatalf("plan mutated operator state\nbefore=%v\nafter=%v", beforeHome, after)
	}
	for _, path := range []string{
		filepath.Join(fixture.input.StateRoot, "trust"), filepath.Join(fixture.input.StateRoot, "tls"),
		filepath.Join(fixture.input.StateRoot, "private"), filepath.Join(fixture.home, "serving", "local.json"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("plan created %s: %v", path, err)
		}
	}
}

func TestServingPlanNoopForEquivalentStateAndIsDeterministic(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	first, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != "noop" || first.Changed || first.Unsafe || !first.Complete || !first.Applicable || first.Summary.Changes != 0 {
		t.Fatalf("equivalent state did not produce no-op: %+v", first)
	}
	if !servingReconcilePlanIsNoop(first) {
		t.Fatalf("equivalent state was not eligible for mutation-free start: %+v", first)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("plan JSON is not deterministic\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, bytes.TrimSpace(fixture.privatePEM)) || strings.Contains(string(firstJSON), "PRIVATE KEY") {
		t.Fatal("plan JSON exposed TLS private key material")
	}
	human := formatServingPlan(first)
	if !strings.HasPrefix(human, "PLAN state=noop changed=false unsafe=false complete=true\n") ||
		!strings.Contains(human, "[NOOP] config.runtime action=none") ||
		!strings.Contains(human, "Summary: noop=") || strings.Contains(human, "PRIVATE KEY") {
		t.Fatalf("human plan is incomplete or unsafe: %q", human)
	}
	for index := 1; index < len(first.Items); index++ {
		if first.Items[index-1].ID >= first.Items[index].ID {
			t.Fatalf("plan items are not canonically ordered: %q then %q", first.Items[index-1].ID, first.Items[index].ID)
		}
	}
}

func TestServingPlanDetectsConfigDriftAndPlansRestart(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	configPath := filepath.Join(fixture.input.StateRoot, "config.json")
	if err := os.WriteFile(configPath, []byte("{\"schema\":99}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "changes" || !plan.Changed || plan.Unsafe {
		t.Fatalf("drift plan=%+v", plan)
	}
	if servingReconcilePlanIsNoop(plan) {
		t.Fatal("drifted state was incorrectly eligible for mutation-free start")
	}
	assertServingPlanItem(t, plan, "config.runtime", "change", "update")
	assertServingPlanItem(t, plan, "service.runtime", "change", "restart")
}

func TestServingPlanDetectsUnitDriftAndPlansRestart(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	if err := os.WriteFile(fixture.environment.UnitPath, []byte("[Service]\nExecStart=/bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if servingReconcilePlanIsNoop(plan) {
		t.Fatal("drifted unit was incorrectly eligible for mutation-free start")
	}
	assertServingPlanItem(t, plan, "service.unit", "change", "update")
	assertServingPlanItem(t, plan, "service.runtime", "change", "restart")
}

func TestServingPlanDetectsStaleLoadedSystemdDefinition(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	fixture.environment.ServiceState = func(string) servingPlanServiceState {
		return servingPlanServiceState{
			Available: true, Enabled: true, Active: true, Loaded: true,
			FragmentPath: fixture.environment.UnitPath, NeedsReload: true,
		}
	}
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if servingReconcilePlanIsNoop(plan) {
		t.Fatal("stale loaded unit was incorrectly eligible for mutation-free start")
	}
	assertServingPlanItem(t, plan, "service.definition", "change", "daemon_reload")
	assertServingPlanItem(t, plan, "service.runtime", "change", "restart")
}

func TestServingPlanMakesReferenceReconcileServiceImpactExplicit(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	fixture.input.ExistingReference.Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	assertServingPlanItem(t, plan, "operator.reference", "change", "update")
	assertServingPlanItem(t, plan, "service.runtime", "change", "restart")
}

func TestServingPlanTreatsNonRootAccountLockCheckAsUnknown(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	fixture.environment.LookupAccount = func(string) (servingPlanAccount, bool, error) {
		return servingPlanAccount{UID: fixture.environment.RootUID, GID: fixture.environment.RootGID}, true, os.ErrPermission
	}
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unsafe || !plan.Applicable || plan.Complete || plan.State != "incomplete" {
		t.Fatalf("protected account state must be incomplete but applicable: %+v", plan)
	}
	assertServingPlanItem(t, plan, "account.service", "unknown", "verify_on_apply")
}

func TestServingDeferredExistingFileIsUnknownNotFalsePositiveChange(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "bootstrap.sh")
	writeServingPlanFile(t, path, []byte("existing\n"), 0o640)
	item := planServingDeferredFile("bootstrap.script", path, "generate_after_tls", "verified bootstrap")
	if item.Status != "unknown" || item.Action != "verify_on_apply" {
		t.Fatalf("deferred existing file must be unknown, got %+v", item)
	}
}

func TestServingPlanRejectsUnsafeSymlinkWithoutFollowingIt(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	trustPath := filepath.Join(fixture.input.StateRoot, "trust")
	heldPath := filepath.Join(fixture.input.StateRoot, "trust-held")
	if err := os.Rename(trustPath, heldPath); err != nil {
		t.Fatal(err)
	}
	outside := privateTempDir(t)
	marker := filepath.Join(outside, "must-not-change")
	if err := os.WriteFile(marker, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, trustPath); err != nil {
		t.Fatal(err)
	}
	before := snapshotServingPlanTree(t, outside)

	var stdout, stderr bytes.Buffer
	fixture.ctx.out = &emitter{json: true, stdout: &stdout, stderr: &stderr}
	status := commandServingPlan(fixture.ctx, fixture.input, fixture.environment)
	if status != exitConfig || stdout.Len() != 0 {
		t.Fatalf("unsafe plan status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	envelope := decodeCLIEnvelope(t, stderr.String())
	if envelope.Error == nil || envelope.Error.Code != "unsafe_state" || envelope.Command != "start.serving.plan" {
		t.Fatalf("unsafe plan envelope=%+v", envelope)
	}
	var plan servingReconcilePlan
	if err := json.Unmarshal(envelope.Data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.State != "unsafe" || !plan.Unsafe || plan.Applicable {
		t.Fatalf("unsafe symlink plan=%+v", plan)
	}
	assertServingPlanItem(t, plan, "directory.trust", "unsafe", "manual_repair")
	assertServingPlanItem(t, plan, "trust.release", "unsafe", "manual_repair")
	if after := snapshotServingPlanTree(t, outside); !reflect.DeepEqual(after, before) {
		t.Fatalf("plan followed or changed symlink target\nbefore=%v\nafter=%v", before, after)
	}
}

func TestServingPlanTreatsExpectedPermissionBoundaryAsUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can traverse mode-000 test directories")
	}
	fixture := newServingPlanTestFixture(t, true)
	privatePath := filepath.Join(fixture.input.StateRoot, "private")
	if err := os.Chmod(privatePath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(privatePath, 0o700) })

	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unsafe || !plan.Applicable || plan.Complete {
		t.Fatalf("protected serving state must be incomplete but applicable, got %+v", plan)
	}
	assertServingPlanItem(t, plan, "directory.private.desired", "unknown", "verify_on_apply")
	assertServingPlanItem(t, plan, "directory.private.logs", "unknown", "verify_on_apply")
}

func TestServingPlanRejectsUnsafeHardlink(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	path := filepath.Join(fixture.input.StateRoot, "trust", "release.public.pem")
	link := filepath.Join(fixture.input.StateRoot, "trust", "release.public.held")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}

	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unsafe || plan.Applicable {
		t.Fatalf("hard-linked managed file must block apply: %+v", plan)
	}
	assertServingPlanItem(t, plan, "trust.release", "unsafe", "manual_repair")
}

func TestServingPlanRejectsHardlinkedPublicKeySource(t *testing.T) {
	fixture := newServingPlanTestFixture(t, true)
	link := filepath.Join(filepath.Dir(fixture.input.ReleaseKeySource), "release.public.link.pem")
	if err := os.Link(fixture.input.ReleaseKeySource, link); err != nil {
		t.Fatal(err)
	}
	plan, err := buildServingReconcilePlan(fixture.ctx, fixture.input, fixture.environment)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unsafe || plan.Applicable || servingReconcilePlanIsNoop(plan) {
		t.Fatalf("hard-linked key source must block no-op and apply: %+v", plan)
	}
	assertServingPlanItem(t, plan, "source.release_key", "unsafe", "choose_safe_source")
}

func newServingPlanTestFixture(t *testing.T, equivalent bool) servingPlanTestFixture {
	t.Helper()
	home := privateTempDir(t)
	store, err := localstate.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(privateTempDir(t), "serving")
	if err := os.Mkdir(stateRoot, 0o751); err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate := generateServingPlanKey(t)
	desiredPublic, _ := generateServingPlanKey(t)
	controlPublic, _ := generateServingPlanKey(t)
	releaseRoot := filepath.Join(stateRoot, "releases")
	current := publishServingPlanRelease(t, releaseRoot, releasePublic, releasePrivate)
	sources := privateTempDir(t)
	releaseSource := writeServingPlanPublicKey(t, sources, "release.public.pem", releasePublic)
	desiredSource := writeServingPlanPublicKey(t, sources, "desired.public.pem", desiredPublic)
	controlSource := writeServingPlanPublicKey(t, sources, "control.public.pem", controlPublic)
	executable := filepath.Join(privateTempDir(t), "flow")
	unitPath := filepath.Join(privateTempDir(t), servingServiceName)
	uid, gid := os.Geteuid(), os.Getegid()
	fixture := servingPlanTestFixture{
		ctx:  &commandContext{store: store, out: &emitter{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}},
		home: home,
		input: servingPlanInput{
			StateRoot: stateRoot, ReleaseRoot: releaseRoot, Listen: "127.0.0.1:8443", PublicURL: "https://serving.example.test:8443",
			ReleaseKeySource: releaseSource, DesiredKeySource: desiredSource, ControlKeySource: controlSource,
			ServiceUser: defaultServingServiceUser, ReleasePublic: releasePublic, DesiredPublic: desiredPublic,
			ControlPublic: controlPublic, Current: current,
		},
		environment: servingPlanEnvironment{
			UnitPath: unitPath, ExecutablePath: executable, RootUID: uid, RootGID: gid,
			LookupAccount: func(string) (servingPlanAccount, bool, error) {
				return servingPlanAccount{UID: uid, GID: gid}, true, nil
			},
			ServiceState: func(string) servingPlanServiceState {
				return servingPlanServiceState{Available: true, Enabled: true, Active: true, Loaded: true, FragmentPath: unitPath}
			},
		},
	}
	if equivalent {
		populateEquivalentServingPlanState(t, &fixture)
	}
	return fixture
}

func populateEquivalentServingPlanState(t *testing.T, fixture *servingPlanTestFixture) {
	t.Helper()
	uid, gid := fixture.environment.RootUID, fixture.environment.RootGID
	paths := []struct {
		path string
		mode os.FileMode
	}{
		{fixture.input.StateRoot, 0o751}, {fixture.input.ReleaseRoot, 0o755},
		{filepath.Join(fixture.input.ReleaseRoot, "sets"), 0o755}, {filepath.Join(fixture.input.ReleaseRoot, "history"), 0o755},
		{filepath.Join(fixture.input.ReleaseRoot, ".imports"), 0o700},
		{filepath.Join(fixture.input.StateRoot, "trust"), 0o755}, {filepath.Join(fixture.input.StateRoot, "tls"), 0o750},
		{filepath.Join(fixture.input.StateRoot, "private"), 0o700}, {filepath.Join(fixture.input.StateRoot, "private", "desired"), 0o700},
		{filepath.Join(fixture.input.StateRoot, "private", "status"), 0o700}, {filepath.Join(fixture.input.StateRoot, "private", "logs"), 0o700},
	}
	for _, item := range paths {
		if err := os.MkdirAll(item.path, item.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(item.path, item.mode); err != nil {
			t.Fatal(err)
		}
	}
	trust := filepath.Join(fixture.input.StateRoot, "trust")
	for _, item := range []struct {
		name string
		key  ed25519.PublicKey
	}{
		{"release.public.pem", fixture.input.ReleasePublic},
		{"desired-state.public.pem", fixture.input.DesiredPublic},
		{"control.public.pem", fixture.input.ControlPublic},
	} {
		data, err := signing.MarshalPublicPEM(item.key)
		if err != nil {
			t.Fatal(err)
		}
		writeServingPlanFile(t, filepath.Join(trust, item.name), data, 0o644)
	}
	tlsCert := filepath.Join(fixture.input.StateRoot, "tls", "serving.crt")
	tlsKey := filepath.Join(fixture.input.StateRoot, "tls", "serving.key")
	fingerprint, err := tlsutil.GenerateSelfSigned(tlsCert, tlsKey, []string{"serving.example.test"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tlsKey, 0o640); err != nil {
		t.Fatal(err)
	}
	fixture.privatePEM, err = os.ReadFile(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	config := desiredServingConfig(fixture.input.StateRoot, fixture.input.ReleaseRoot, fixture.input.Listen, fixture.input.PublicURL)
	configData, err := signing.CanonicalJSON(config)
	if err != nil {
		t.Fatal(err)
	}
	writeServingPlanFile(t, filepath.Join(fixture.input.StateRoot, "config.json"), configData, 0o640)
	bootstrap, err := buildBootstrap(fixture.input.PublicURL, fixture.input.Current, tlsCert,
		filepath.Join(trust, "release.public.pem"), filepath.Join(trust, "desired-state.public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	writeServingPlanFile(t, filepath.Join(fixture.input.StateRoot, "bootstrap.sh"), bootstrap, 0o640)
	writeServingPlanFile(t, fixture.environment.ExecutablePath, []byte("fixture flow executable\n"), 0o755)
	unit := servingUnit(fixture.environment.ExecutablePath, filepath.Join(fixture.input.StateRoot, "config.json"), fixture.input.StateRoot,
		fixture.input.ReleaseRoot, fixture.input.ServiceUser, fmt.Sprintf("%d", gid))
	writeServingPlanFile(t, fixture.environment.UnitPath, []byte(unit), 0o644)
	fixture.input.ExistingReference = localServingReference{
		Schema: localServingReferenceSchema, ConfigPath: filepath.Join(fixture.input.StateRoot, "config.json"), StateRoot: fixture.input.StateRoot,
		ReleaseRoot: fixture.input.ReleaseRoot, ReleasePublicKeySource: fixture.input.ReleaseKeySource,
		DesiredPublicKeySource: fixture.input.DesiredKeySource, ControlPublicKeySource: fixture.input.ControlKeySource,
		ServiceUser: fixture.input.ServiceUser, PublicURL: fixture.input.PublicURL, Listen: fixture.input.Listen, Fingerprint: fingerprint,
	}
	fixture.input.ReferenceExists = true
	_ = uid
}

func publishServingPlanRelease(t *testing.T, root string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) release.SignedManifest {
	t.Helper()
	artifacts := privateTempDir(t)
	amd64 := filepath.Join(artifacts, "flow-amd64")
	arm64 := filepath.Join(artifacts, "flow-arm64")
	writeServingPlanFile(t, amd64, []byte("flow linux-amd64\n"), 0o600)
	writeServingPlanFile(t, arm64, []byte("flow linux-arm64\n"), 0o600)
	manifest, err := release.BuildFromArtifacts(1, []release.ArtifactInput{
		{Component: "flow", Version: "v0.2.0", Target: "linux-amd64", ArtifactName: "flow", SourcePath: amd64},
		{Component: "flow", Version: "v0.2.0", Target: "linux-arm64", ArtifactName: "flow", SourcePath: arm64},
	}, []release.Profile{{Name: "bootstrap", Components: []string{"flow"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{
		manifest.Components[0].Artifact: amd64,
		manifest.Components[1].Artifact: arm64,
	}
	if manifest.Components[0].Target == "linux-arm64" {
		paths[manifest.Components[0].Artifact], paths[manifest.Components[1].Artifact] = arm64, amd64
	}
	if err := release.Publish(root, signed, paths, publicKey); err != nil {
		t.Fatal(err)
	}
	return signed
}

func generateServingPlanKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func writeServingPlanPublicKey(t *testing.T, directory, name string, publicKey ed25519.PublicKey) string {
	t.Helper()
	data, err := signing.MarshalPublicPEM(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	writeServingPlanFile(t, path, data, 0o600)
	return path
}

func writeServingPlanFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertServingPlanItem(t *testing.T, plan servingReconcilePlan, id, status, action string) {
	t.Helper()
	for _, item := range plan.Items {
		if item.ID == id {
			if item.Status != status || item.Action != action {
				t.Fatalf("item %s=%+v, want status=%s action=%s", id, item, status, action)
			}
			return
		}
	}
	t.Fatalf("plan has no item %q", id)
}

func snapshotServingPlanTree(t *testing.T, root string) []string {
	t.Helper()
	var result []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		record := fmt.Sprintf("%s|%s", filepath.ToSlash(relative), info.Mode())
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			record += "|link=" + target
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			record += "|sha256=" + hex.EncodeToString(digest[:])
		}
		result = append(result, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(result)
	return result
}
