package applyplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/profiles"
	"dynamicflow/internal/release"
	"dynamicflow/internal/signing"
)

type planFixture struct {
	registry       *profiles.Registry
	releasePublic  ed25519.PublicKey
	releasePrivate ed25519.PrivateKey
	desiredPublic  ed25519.PublicKey
	desiredPrivate ed25519.PrivateKey
	signedRelease  release.SignedManifest
	signedDesired  enrollment.SignedDesiredState
	options        Options
}

func TestBuildPBPPlanIsExactDeterministicAndArchitectureBound(t *testing.T) {
	fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
	plan, err := fixture.build()
	if err != nil {
		t.Fatal(err)
	}
	wantPhases := []string{"flow", "ssh", "ssh-gui", "vpn-pbp-de", "pbp"}
	if plan.Schema != SchemaVersion || plan.Instance != "pbp-01" || plan.Profile != "pbp" ||
		plan.Target != "linux-amd64" || plan.ReleaseSet != fixture.signedRelease.Manifest.SetID ||
		plan.ReleaseGeneration != 10 || plan.DesiredGeneration != 7 || !digestRE.MatchString(plan.ID) ||
		!digestRE.MatchString(plan.DesiredStateID) {
		t.Fatalf("unexpected plan header: %#v", plan)
	}
	if len(plan.AuthorizedSSHKeys) != 1 {
		t.Fatalf("authorized keys missing from verified plan: %#v", plan.AuthorizedSSHKeys)
	}
	if len(plan.Phases) != len(wantPhases) {
		t.Fatalf("phases = %#v, want %v", plan.Phases, wantPhases)
	}
	for index, phase := range plan.Phases {
		if phase.Profile != wantPhases[index] || phase.ID != "phase/"+wantPhases[index] || len(phase.Steps) != 1 {
			t.Fatalf("phase %d = %#v", index, phase)
		}
		if phase.Steps[0].ID != phase.ID+"/component/"+phase.Steps[0].Artifact.Component {
			t.Fatalf("unstable step ID: %#v", phase.Steps[0])
		}
		if phase.Profile == "vpn" {
			t.Fatal("normal vpn profile entered the PBP plan")
		}
	}
	runtimePhase := plan.Phases[0]
	if runtimePhase.Profile != "flow" || len(runtimePhase.DependsOn) != 0 ||
		runtimePhase.Steps[0].Artifact.Path != "flow/v1.0.0/linux-amd64/flow" {
		t.Fatalf("runtime phase is not exact and raw: %#v", runtimePhase)
	}
	if !reflect.DeepEqual(plan.Phases[1].DependsOn, []string{"phase/flow"}) {
		t.Fatalf("ssh is not gated by runtime activation: %#v", plan.Phases[1])
	}
	if got := plan.Phases[3].Steps[0].Artifact.Component; got != "vpn" {
		t.Fatalf("PBP-specific VPN phase selected component %q", got)
	}
	if got := plan.Phases[4].Steps[0].Artifact.Target; got != "linux-amd64" {
		t.Fatalf("PBP target = %q", got)
	}

	again, err := fixture.build()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, again) {
		t.Fatalf("same verified inputs produced different plans:\n%#v\n%#v", plan, again)
	}

	arm := newPBPFixture(t, "arm64", defaultArtifactInputs(t, true, false))
	armPlan, err := arm.build()
	if err != nil {
		t.Fatal(err)
	}
	if got := armPlan.Phases[4].Steps[0].Artifact.Target; got != "linux-arm64" {
		t.Fatalf("arm64 PBP target = %q", got)
	}
	if armPlan.ID == plan.ID {
		t.Fatal("architecture change did not change the content-addressed plan ID")
	}
}

func TestRuntimeArtifactDigestChangesPlanID(t *testing.T) {
	fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
	plan, err := fixture.build()
	if err != nil {
		t.Fatal(err)
	}
	changed := cloneFixture(fixture)
	for index := range changed.signedRelease.Manifest.Components {
		component := &changed.signedRelease.Manifest.Components[index]
		if component.Name == "flow" && component.Target == "linux-amd64" {
			component.Digest = "sha256:" + strings.Repeat("b", 64)
		}
	}
	changed.resignReleaseAndDesired(t)
	changedPlan, err := changed.build()
	if err != nil {
		t.Fatal(err)
	}
	if changedPlan.ID == plan.ID {
		t.Fatal("changed signed runtime digest did not change the plan ID")
	}
}

func TestProductionPBPRegistryBuildsOnlyTheExactPBPChain(t *testing.T) {
	registry, err := profiles.LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := defaultArtifactInputs(t, true, false)
	inputs = append(inputs,
		artifactInput(t, "decepticon", "v1.0.0", "any"),
		artifactInput(t, "examstation", "v1.0.0", "any"),
	)
	fixture := newFixture(t, "amd64", registry, inputs)
	plan, err := fixture.build()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"flow", "ssh", "ssh-gui", "vpn-pbp-de", "pbp"}
	got := make([]string, 0, len(plan.Phases))
	for _, phase := range plan.Phases {
		got = append(got, phase.Profile)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("production PBP phases = %v, want %v", got, want)
	}
}

func TestBuildRejectsUntrustedExpiredRevokedAndMisbindingDesiredState(t *testing.T) {
	base := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
	otherReleasePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	otherDesiredPublic, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		edit func(*planFixture)
		want error
	}{
		{
			name: "wrong release trust root",
			edit: func(f *planFixture) { f.releasePublic = otherReleasePublic },
			want: signing.ErrInvalidSignature,
		},
		{
			name: "tampered signed release",
			edit: func(f *planFixture) { f.signedRelease.Manifest.Generation++ },
			want: release.ErrInvalidManifest,
		},
		{
			name: "wrong desired trust root",
			edit: func(f *planFixture) { f.desiredPublic = otherDesiredPublic },
			want: signing.ErrInvalidSignature,
		},
		{
			name: "tampered desired profile",
			edit: func(f *planFixture) { f.signedDesired.State.Profile = "ssh" },
			want: signing.ErrInvalidSignature,
		},
		{
			name: "wrong expected instance",
			edit: func(f *planFixture) { f.options.Instance = "pbp-02" },
			want: enrollment.ErrBinding,
		},
		{
			name: "wrong expected profile",
			edit: func(f *planFixture) { f.options.Profile = "ssh" },
			want: enrollment.ErrBinding,
		},
		{
			name: "expired desired state",
			edit: func(f *planFixture) { f.options.Now = f.options.Now.Add(2 * time.Hour) },
			want: enrollment.ErrExpired,
		},
		{
			name: "desired generation rollback",
			edit: func(f *planFixture) {
				f.options.Checkpoint.DesiredGeneration = 8
				f.options.Checkpoint.DesiredStateID, _ = desiredStateID(f.signedDesired.State)
			},
			want: enrollment.ErrInvalidDesiredState,
		},
		{
			name: "same desired generation different content",
			edit: func(f *planFixture) {
				f.options.Checkpoint.DesiredGeneration = f.signedDesired.State.Generation
				f.options.Checkpoint.DesiredStateID, _ = desiredStateID(f.signedDesired.State)
				state := f.signedDesired.State
				state.AuthorizedSSHKeys = []string{openSSHKey(t)}
				f.signedDesired = mustSignDesired(t, state, f.desiredPrivate)
			},
			want: ErrRollback,
		},
		{
			name: "release generation rollback",
			edit: func(f *planFixture) {
				f.options.Checkpoint.ReleaseGeneration = 11
				f.options.Checkpoint.ReleaseSet = f.signedRelease.Manifest.SetID
			},
			want: ErrRollback,
		},
		{
			name: "same release generation different set",
			edit: func(f *planFixture) {
				f.options.Checkpoint.ReleaseGeneration = 10
				f.options.Checkpoint.ReleaseSet = "sha256:" + strings.Repeat("f", 64)
			},
			want: ErrRollback,
		},
		{
			name: "revoked desired state",
			edit: func(f *planFixture) {
				state := f.signedDesired.State
				state.Revoked = true
				state.AuthorizedSSHKeys = nil
				f.signedDesired = mustSignDesired(t, state, f.desiredPrivate)
			},
			want: ErrRevoked,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneFixture(base)
			test.edit(&fixture)
			_, err := fixture.build()
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildRejectsInvalidConfigurationAndTarget(t *testing.T) {
	base := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
	tests := []struct {
		name string
		edit func(*planFixture)
		want error
	}{
		{"nil registry", func(f *planFixture) { f.registry = nil }, ErrInvalidInput},
		{"empty instance", func(f *planFixture) { f.options.Instance = "" }, ErrInvalidInput},
		{"path instance", func(f *planFixture) { f.options.Instance = ".." }, ErrInvalidInput},
		{"unsupported arch", func(f *planFixture) { f.options.GOARCH = "386" }, ErrUnsupportedTarget},
		{"negative skew", func(f *planFixture) { f.options.MaxClockSkew = -time.Second }, ErrInvalidInput},
		{"same trust key", func(f *planFixture) { f.desiredPublic = f.releasePublic }, ErrInvalidInput},
		{"partial checkpoint", func(f *planFixture) { f.options.Checkpoint.ReleaseGeneration = 1 }, ErrInvalidInput},
		{"partial desired checkpoint", func(f *planFixture) { f.options.Checkpoint.DesiredGeneration = 1 }, ErrInvalidInput},
		{"malformed checkpoint", func(f *planFixture) {
			f.options.Checkpoint.ReleaseGeneration = 1
			f.options.Checkpoint.ReleaseSet = "not-a-digest"
		}, ErrInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneFixture(base)
			test.edit(&fixture)
			_, err := fixture.build()
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildRejectsProfileDriftAndNonExactPBPGraph(t *testing.T) {
	t.Run("signed manifest differs from local declaration", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
		for index := range fixture.signedRelease.Manifest.Profiles {
			if fixture.signedRelease.Manifest.Profiles[index].Name == "ssh-gui" {
				fixture.signedRelease.Manifest.Profiles[index].Components = []string{"vpn"}
			}
		}
		fixture.resignReleaseAndDesired(t)
		if _, err := fixture.build(); !errors.Is(err, ErrProfileMismatch) {
			t.Fatalf("got %v, want ErrProfileMismatch", err)
		}
	})

	t.Run("pbp cannot use normal vpn profile", func(t *testing.T) {
		declarations := []profiles.Profile{
			{SchemaVersion: profiles.SchemaVersion, Name: "ssh", Description: "ssh", Components: []string{"ssh"}},
			{SchemaVersion: profiles.SchemaVersion, Name: "vpn", Description: "normal vpn", DependsOn: []string{"ssh"}, Components: []string{"vpn"}},
			{SchemaVersion: profiles.SchemaVersion, Name: "pbp", Description: "bad pbp", DependsOn: []string{"vpn"}, Components: []string{"pbp"}},
		}
		registry, err := profiles.NewRegistry(declarations)
		if err != nil {
			t.Fatal(err)
		}
		fixture := newFixture(t, "amd64", registry, defaultArtifactInputs(t, true, false))
		if _, err := fixture.build(); !errors.Is(err, ErrProfileMismatch) {
			t.Fatalf("got %v, want ErrProfileMismatch", err)
		}
	})

	t.Run("same order with different dependency edges", func(t *testing.T) {
		declarations := []profiles.Profile{
			{SchemaVersion: profiles.SchemaVersion, Name: "ssh", Description: "ssh", Components: []string{"ssh"}},
			{SchemaVersion: profiles.SchemaVersion, Name: "ssh-gui", Description: "gui", Components: []string{"ssh"}},
			{SchemaVersion: profiles.SchemaVersion, Name: "vpn-pbp-de", Description: "PBP VPN", DependsOn: []string{"ssh", "ssh-gui"}, Components: []string{"vpn"}},
			{SchemaVersion: profiles.SchemaVersion, Name: "pbp", Description: "PBP", DependsOn: []string{"vpn-pbp-de"}, Components: []string{"pbp"}},
		}
		registry, err := profiles.NewRegistry(declarations)
		if err != nil {
			t.Fatal(err)
		}
		fixture := newFixture(t, "amd64", registry, defaultArtifactInputs(t, true, false))
		if _, err := fixture.build(); !errors.Is(err, ErrProfileMismatch) {
			t.Fatalf("got %v, want ErrProfileMismatch", err)
		}
	})

	t.Run("required profile absent from signed release", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
		filtered := fixture.signedRelease.Manifest.Profiles[:0]
		for _, profile := range fixture.signedRelease.Manifest.Profiles {
			if profile.Name != "pbp" {
				filtered = append(filtered, profile)
			}
		}
		fixture.signedRelease.Manifest.Profiles = filtered
		fixture.resignReleaseAndDesired(t)
		if _, err := fixture.build(); !errors.Is(err, ErrProfileMismatch) {
			t.Fatalf("got %v, want ErrProfileMismatch", err)
		}
	})
}

func TestSelectRuntimeArtifactRequiresExactRawUniqueBinding(t *testing.T) {
	component := func(version, target, path string) release.Component {
		return release.Component{
			Name: "flow", Version: version, Target: target, Artifact: path,
			Digest: "sha256:" + strings.Repeat("a", 64), Size: 1,
		}
	}
	exact := component("v1.0.0", "linux-amd64", "flow/v1.0.0/linux-amd64/flow")
	tests := []struct {
		name     string
		manifest release.Manifest
		want     error
	}{
		{"missing", release.Manifest{}, ErrMissingArtifact},
		{"target any", release.Manifest{Components: []release.Component{component("v1.0.0", "any", "flow/v1.0.0/any/flow")}}, ErrMissingArtifact},
		{"ambiguous", release.Manifest{Components: []release.Component{
			exact,
			component("v2.0.0", "linux-amd64", "flow/v2.0.0/linux-amd64/flow"),
		}}, ErrAmbiguousArtifact},
		{"wrong raw path", release.Manifest{Components: []release.Component{component("v1.0.0", "linux-amd64", "flow/v1.0.0/linux-amd64/flow.tar.gz")}}, ErrMissingArtifact},
		{"revoked", release.Manifest{
			Components:  []release.Component{exact},
			Revocations: []release.Revocation{{Component: "flow", Version: "v1.0.0", Reason: "incident"}},
		}, ErrRevokedArtifact},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := selectRuntimeArtifact(test.manifest, "linux-amd64"); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestBuildRejectsMissingAmbiguousDuplicateAndRevokedArtifacts(t *testing.T) {
	withoutRuntime := func() []release.ArtifactInput {
		inputs := defaultArtifactInputs(t, true, false)
		filtered := make([]release.ArtifactInput, 0, len(inputs)-1)
		for _, input := range inputs {
			if input.Component == "flow" && input.Target == "linux-amd64" {
				continue
			}
			filtered = append(filtered, input)
		}
		return filtered
	}
	t.Run("missing exact flow runtime", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", withoutRuntime())
		if _, err := fixture.build(); !errors.Is(err, ErrMissingArtifact) {
			t.Fatalf("got %v, want ErrMissingArtifact", err)
		}
	})

	t.Run("target-independent and exact flow runtimes are rejected by manifest", func(t *testing.T) {
		inputs := withoutRuntime()
		inputs = append(inputs, flowArtifactInput(t, "v1.0.0", "any"))
		if err := pbpManifestBuildError(t, inputs); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want ErrInvalidManifest", err)
		}
	})

	t.Run("two exact flow runtimes are rejected by manifest", func(t *testing.T) {
		inputs := defaultArtifactInputs(t, true, false)
		inputs = append(inputs, flowArtifactInput(t, "v2.0.0", "linux-amd64"))
		if err := pbpManifestBuildError(t, inputs); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want ErrInvalidManifest", err)
		}
	})

	t.Run("missing architecture artifact", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, false, false))
		if _, err := fixture.build(); !errors.Is(err, ErrMissingArtifact) {
			t.Fatalf("got %v, want ErrMissingArtifact", err)
		}
	})

	t.Run("architecture and any candidates are rejected by manifest", func(t *testing.T) {
		if err := pbpManifestBuildError(t, defaultArtifactInputs(t, true, true)); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want ErrInvalidManifest", err)
		}
	})

	t.Run("two applicable versions are rejected by manifest", func(t *testing.T) {
		inputs := defaultArtifactInputs(t, true, false)
		inputs = append(inputs, artifactInput(t, "pbp", "v2.0.0", "linux-amd64"))
		if err := pbpManifestBuildError(t, inputs); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want ErrInvalidManifest", err)
		}
	})

	t.Run("duplicate manifest binding", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
		component := fixture.signedRelease.Manifest.Components[0]
		fixture.signedRelease.Manifest.Components = append(fixture.signedRelease.Manifest.Components, component)
		sortComponents(fixture.signedRelease.Manifest.Components)
		fixture.signedRelease.Manifest.SetID = mustSetID(t, fixture.signedRelease.Manifest)
		fixture.signedRelease.Signature = mustRawReleaseSignature(t, fixture.signedRelease.Manifest, fixture.releasePrivate)
		if _, err := fixture.build(); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want ErrInvalidManifest", err)
		}
	})

	t.Run("active revoked version", func(t *testing.T) {
		fixture := newPBPFixture(t, "amd64", defaultArtifactInputs(t, true, false))
		selected := fixture.signedRelease.Manifest.Components[0]
		fixture.signedRelease.Manifest.Revocations = []release.Revocation{{
			Component: selected.Name, Version: selected.Version, Reason: "security incident",
		}}
		fixture.signedRelease.Manifest.SetID = mustSetID(t, fixture.signedRelease.Manifest)
		fixture.signedRelease.Signature = mustRawReleaseSignature(t, fixture.signedRelease.Manifest, fixture.releasePrivate)
		if _, err := fixture.build(); !errors.Is(err, release.ErrInvalidManifest) {
			t.Fatalf("got %v, want signed active revocation to fail closed", err)
		}
	})

	t.Run("selected artifact revocation defense", func(t *testing.T) {
		component := release.Component{
			Name: "pbp", Version: "v1.0.0", Target: "linux-amd64",
			Artifact: "pbp/v1.0.0/linux-amd64/pbp.tar.gz",
			Digest:   "sha256:" + strings.Repeat("a", 64), Size: 1,
		}
		manifest := release.Manifest{
			Components:  []release.Component{component},
			Revocations: []release.Revocation{{Component: "pbp", Version: "v1.0.0", Reason: "incident"}},
		}
		if _, err := selectArtifact(manifest, "pbp", "linux-amd64"); !errors.Is(err, ErrRevokedArtifact) {
			t.Fatalf("got %v, want ErrRevokedArtifact", err)
		}
	})
}

func (fixture planFixture) build() (Plan, error) {
	return Build(
		fixture.registry, fixture.signedRelease, fixture.releasePublic,
		fixture.signedDesired, fixture.desiredPublic, fixture.options,
	)
}

func (fixture *planFixture) resignReleaseAndDesired(t *testing.T) {
	t.Helper()
	fixture.signedRelease.Manifest.SetID = mustSetID(t, fixture.signedRelease.Manifest)
	signed, err := release.SignManifest(fixture.signedRelease.Manifest, fixture.releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture.signedRelease = signed
	state := fixture.signedDesired.State
	state.ReleaseSet = signed.Manifest.SetID
	fixture.signedDesired = mustSignDesired(t, state, fixture.desiredPrivate)
}

func cloneFixture(input planFixture) planFixture {
	result := input
	result.releasePublic = append(ed25519.PublicKey(nil), input.releasePublic...)
	result.desiredPublic = append(ed25519.PublicKey(nil), input.desiredPublic...)
	result.signedRelease.Manifest.Components = append([]release.Component(nil), input.signedRelease.Manifest.Components...)
	result.signedRelease.Manifest.Profiles = append([]release.Profile(nil), input.signedRelease.Manifest.Profiles...)
	result.signedRelease.Manifest.Revocations = append([]release.Revocation(nil), input.signedRelease.Manifest.Revocations...)
	result.signedRelease.Signature.Value = append([]byte(nil), input.signedRelease.Signature.Value...)
	result.signedDesired.State.AuthorizedSSHKeys = append([]string(nil), input.signedDesired.State.AuthorizedSSHKeys...)
	result.signedDesired.Signature.Value = append([]byte(nil), input.signedDesired.Signature.Value...)
	return result
}

func newPBPFixture(t *testing.T, architecture string, artifacts []release.ArtifactInput) planFixture {
	t.Helper()
	registry, err := profiles.NewRegistry(pbpDeclarations())
	if err != nil {
		t.Fatal(err)
	}
	return newFixture(t, architecture, registry, artifacts)
}

func pbpManifestBuildError(t *testing.T, artifacts []release.ArtifactInput) error {
	t.Helper()
	registry, err := profiles.NewRegistry(pbpDeclarations())
	if err != nil {
		t.Fatal(err)
	}
	manifestProfiles := make([]release.Profile, 0)
	for _, profile := range registry.List(true) {
		manifestProfiles = append(manifestProfiles, release.Profile{
			Name: profile.Name, DependsOn: profile.DependsOn, Components: profile.Components,
		})
	}
	_, err = release.BuildFromArtifacts(10, artifacts, manifestProfiles, nil)
	return err
}

func newFixture(t *testing.T, architecture string, registry *profiles.Registry, artifacts []release.ArtifactInput) planFixture {
	t.Helper()
	manifestProfiles := make([]release.Profile, 0)
	for _, profile := range registry.List(true) {
		manifestProfiles = append(manifestProfiles, release.Profile{
			Name: profile.Name, DependsOn: profile.DependsOn, Components: profile.Components,
		})
	}
	manifest, err := release.BuildFromArtifacts(10, artifacts, manifestProfiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, desiredPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedRelease, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	desired := mustSignDesired(t, enrollment.DesiredState{
		Schema: enrollment.DesiredStateSchema, Instance: "pbp-01", Profile: "pbp", Generation: 7,
		ReleaseSet: manifest.SetID, AuthorizedSSHKeys: []string{openSSHKey(t)},
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, desiredPrivate)
	return planFixture{
		registry: registry, releasePublic: releasePublic, releasePrivate: releasePrivate,
		desiredPublic: desiredPublic, desiredPrivate: desiredPrivate,
		signedRelease: signedRelease, signedDesired: desired,
		options: Options{Instance: "pbp-01", Profile: "pbp", GOARCH: architecture, Now: now, MaxClockSkew: time.Minute},
	}
}

func pbpDeclarations() []profiles.Profile {
	return []profiles.Profile{
		{SchemaVersion: profiles.SchemaVersion, Name: "ssh", Description: "ssh", Components: []string{"ssh"}},
		{SchemaVersion: profiles.SchemaVersion, Name: "ssh-gui", Description: "gui", DependsOn: []string{"ssh"}, Components: []string{"ssh"}},
		{SchemaVersion: profiles.SchemaVersion, Name: "vpn-pbp-de", Description: "PBP VPN", Internal: true, DependsOn: []string{"ssh-gui"}, Components: []string{"vpn"}},
		{SchemaVersion: profiles.SchemaVersion, Name: "pbp", Description: "PBP", DependsOn: []string{"vpn-pbp-de"}, Components: []string{"pbp"}},
		{SchemaVersion: profiles.SchemaVersion, Name: "vpn", Description: "normal VPN", DependsOn: []string{"ssh"}, Components: []string{"vpn"}},
	}
}

func defaultArtifactInputs(t *testing.T, includeAMD64, includeAnyPBP bool) []release.ArtifactInput {
	t.Helper()
	inputs := []release.ArtifactInput{
		flowArtifactInput(t, "v1.0.0", "linux-amd64"),
		flowArtifactInput(t, "v1.0.0", "linux-arm64"),
		artifactInput(t, "ssh", "v1.0.0", "any"),
		artifactInput(t, "vpn", "v1.0.0", "any"),
		artifactInput(t, "pbp", "v1.0.0", "linux-arm64"),
	}
	if includeAMD64 {
		inputs = append(inputs, artifactInput(t, "pbp", "v1.0.0", "linux-amd64"))
	}
	if includeAnyPBP {
		inputs = append(inputs, artifactInput(t, "pbp", "v1.0.0", "any"))
	}
	return inputs
}

func artifactInput(t *testing.T, component, version, target string) release.ArtifactInput {
	t.Helper()
	directory := t.TempDir()
	name := component + ".tar.gz"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(component+"\x00"+version+"\x00"+target), 0o600); err != nil {
		t.Fatal(err)
	}
	return release.ArtifactInput{
		Component: component, Version: version, Target: target,
		ArtifactName: name, SourcePath: path,
	}
}

func flowArtifactInput(t *testing.T, version, target string) release.ArtifactInput {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "flow")
	if err := os.WriteFile(path, []byte("flow\x00"+version+"\x00"+target), 0o755); err != nil {
		t.Fatal(err)
	}
	return release.ArtifactInput{
		Component: "flow", Version: version, Target: target,
		ArtifactName: "flow", SourcePath: path,
	}
}

func mustSignDesired(t *testing.T, state enrollment.DesiredState, privateKey ed25519.PrivateKey) enrollment.SignedDesiredState {
	t.Helper()
	signed, err := enrollment.SignDesiredState(state, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func openSSHKey(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 0, 4+len("ssh-ed25519")+4+len(publicKey))
	appendString := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		blob = append(blob, size[:]...)
		blob = append(blob, value...)
	}
	appendString([]byte("ssh-ed25519"))
	appendString(publicKey)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " apply-plan-test"
}

func mustSetID(t *testing.T, manifest release.Manifest) string {
	t.Helper()
	id, err := release.ComputeSetID(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustRawReleaseSignature(t *testing.T, manifest release.Manifest, privateKey ed25519.PrivateKey) signing.Signature {
	t.Helper()
	signature, err := signing.SignCanonical(privateKey, release.SignatureDomain, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func sortComponents(components []release.Component) {
	sort.Slice(components, func(i, j int) bool {
		a, b := components[i], components[j]
		return strings.Join([]string{a.Name, a.Version, a.Target, a.Artifact}, "\x00") <
			strings.Join([]string{b.Name, b.Version, b.Target, b.Artifact}, "\x00")
	})
}
