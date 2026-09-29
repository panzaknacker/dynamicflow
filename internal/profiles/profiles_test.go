package profiles

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRepositoryPBPDependencyChain(t *testing.T) {
	registry, err := LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve("pbp")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(resolved))
	for i, profile := range resolved {
		got[i] = profile.Name
	}
	want := []string{"ssh", "ssh-gui", "vpn-pbp-de", "pbp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PBP closure = %v, want %v", got, want)
	}
	for _, name := range got {
		if name == "vpn" {
			t.Fatal("normal Firefox VPN profile leaked into PBP closure")
		}
	}
	internal, ok := registry.Get("vpn-pbp-de")
	if !ok || !internal.Internal {
		t.Fatal("vpn-pbp-de must exist as an internal profile")
	}
}

func TestRepositoryComponentsMatchReleaseArtifacts(t *testing.T) {
	registry, err := LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"ssh":         {"ssh"},
		"ssh-gui":     {"ssh"},
		"vpn":         {"vpn"},
		"vpn-pbp-de":  {"vpn"},
		"pbp":         {"pbp"},
		"decepticon":  {"vpn", "decepticon"},
		"examstation": {"examstation"},
	}
	for name, expected := range want {
		profile, ok := registry.Get(name)
		if !ok {
			t.Errorf("missing profile %q", name)
			continue
		}
		if !reflect.DeepEqual(profile.Components, expected) {
			t.Errorf("%s components = %v, want %v", name, profile.Components, expected)
		}
	}
}

func TestResolveRejectsConflictingProfiles(t *testing.T) {
	registry, err := LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Resolve("pbp", "examstation")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestRegistryRejectsCyclesAndUnknownDependencies(t *testing.T) {
	base := func(name string, dependencies ...string) Profile {
		return Profile{SchemaVersion: 1, Name: name, Description: name, DependsOn: dependencies, Components: []string{name + "-component"}}
	}
	if _, err := NewRegistry([]Profile{base("one", "two")}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("unknown dependency error = %v", err)
	}
	if _, err := NewRegistry([]Profile{base("one", "two"), base("two", "one")}); !errors.Is(err, ErrCycle) {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestListHidesInternalProfiles(t *testing.T) {
	registry, err := LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range registry.List(false) {
		if profile.Name == "vpn-pbp-de" {
			t.Fatal("internal profile appeared in normal listing")
		}
	}
}

func TestBuiltinMatchesRepository(t *testing.T) {
	repository, err := LoadDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := builtin.List(true), repository.List(true); !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled target policy differs from repository profiles\ngot:  %#v\nwant: %#v", got, want)
	}
}
