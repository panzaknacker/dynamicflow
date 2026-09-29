// package profiles loads and resolves dynamicflow's declarative profile graph.
package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const SchemaVersion = 1

var (
	ErrConflict       = errors.New("profile conflict")
	ErrCycle          = errors.New("profile dependency cycle")
	ErrInvalidProfile = errors.New("invalid profile")
	ErrNotFound       = errors.New("profile not found")
	profileName       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// Profile is one installable profile or an internal dependency profile.
type Profile struct {
	SchemaVersion int      `json:"schema_version"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Internal      bool     `json:"internal,omitempty"`
	Installable   bool     `json:"installable"`
	DependsOn     []string `json:"depends_on,omitempty"`
	ConflictsWith []string `json:"conflicts_with,omitempty"`
	Components    []string `json:"components"`
}

// ConflictError identifies the incompatible pair in a requested closure.
type ConflictError struct {
	First  string
	Second string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%v: %s conflicts with %s", ErrConflict, e.First, e.Second)
}

func (e *ConflictError) Unwrap() error { return ErrConflict }

// Registry is an immutable, validated collection of profiles.
type Registry struct {
	profiles map[string]Profile
}

// LoadDir loads all non-symlink *.json profile declarations in a directory.
func LoadDir(directory string) (*Registry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read profiles directory: %w", err)
	}
	loaded := make([]Profile, 0, len(entries))
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%w: %s must be a regular non-symlink file", ErrInvalidProfile, entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open profile %s: %w", entry.Name(), err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read profile %s: %w", entry.Name(), readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close profile %s: %w", entry.Name(), closeErr)
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("%w: %s exceeds 1 MiB", ErrInvalidProfile, entry.Name())
		}
		var profile Profile
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&profile); err != nil {
			return nil, fmt.Errorf("decode profile %s: %w", entry.Name(), err)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, fmt.Errorf("decode profile %s: %w", entry.Name(), err)
		}
		if profile.Name != strings.TrimSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("%w: profile name %q does not match file %q", ErrInvalidProfile, profile.Name, entry.Name())
		}
		loaded = append(loaded, profile)
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("%w: no JSON profiles in %s", ErrInvalidProfile, directory)
	}
	return NewRegistry(loaded)
}

// NewRegistry validates and copies profiles into an immutable registry.
func NewRegistry(input []Profile) (*Registry, error) {
	registry := &Registry{profiles: make(map[string]Profile, len(input))}
	for _, original := range input {
		profile := clone(original)
		if err := validateProfile(profile); err != nil {
			return nil, err
		}
		if _, exists := registry.profiles[profile.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate profile %q", ErrInvalidProfile, profile.Name)
		}
		registry.profiles[profile.Name] = profile
	}
	for _, profile := range registry.profiles {
		for _, dependency := range profile.DependsOn {
			if _, exists := registry.profiles[dependency]; !exists {
				return nil, fmt.Errorf("%w: %s depends on unknown profile %s", ErrInvalidProfile, profile.Name, dependency)
			}
		}
		for _, conflict := range profile.ConflictsWith {
			if _, exists := registry.profiles[conflict]; !exists {
				return nil, fmt.Errorf("%w: %s conflicts with unknown profile %s", ErrInvalidProfile, profile.Name, conflict)
			}
		}
	}
	if err := registry.validateAcyclic(); err != nil {
		return nil, err
	}
	return registry, nil
}

// Get returns a detached copy of one profile.
func (r *Registry) Get(name string) (Profile, bool) {
	profile, ok := r.profiles[name]
	return clone(profile), ok
}

// List returns profiles sorted by name. Internal dependency profiles are
// hidden unless includeInternal is true.
func (r *Registry) List(includeInternal bool) []Profile {
	result := make([]Profile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		if profile.Internal && !includeInternal {
			continue
		}
		result = append(result, clone(profile))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// Resolve returns a dependency-first topological ordering for all requested
// profiles. it rejects conflicts anywhere in the complete dependency closure.
func (r *Registry) Resolve(names ...string) ([]Profile, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: no profile requested", ErrNotFound)
	}
	state := make(map[string]uint8, len(r.profiles))
	ordered := make([]Profile, 0, len(r.profiles))
	var visit func(string, []string) error
	visit = func(name string, stack []string) error {
		profile, exists := r.profiles[name]
		if !exists {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		switch state[name] {
		case 1:
			return fmt.Errorf("%w: %s", ErrCycle, strings.Join(append(stack, name), " -> "))
		case 2:
			return nil
		}
		state[name] = 1
		for _, dependency := range profile.DependsOn {
			if err := visit(dependency, append(stack, name)); err != nil {
				return err
			}
		}
		state[name] = 2
		ordered = append(ordered, clone(profile))
		return nil
	}
	for _, name := range names {
		if err := visit(name, nil); err != nil {
			return nil, err
		}
	}
	selected := make(map[string]struct{}, len(ordered))
	for _, profile := range ordered {
		selected[profile.Name] = struct{}{}
	}
	for _, profile := range ordered {
		for _, conflict := range profile.ConflictsWith {
			if _, exists := selected[conflict]; exists {
				return nil, &ConflictError{First: profile.Name, Second: conflict}
			}
		}
	}
	return ordered, nil
}

func (r *Registry) validateAcyclic() error {
	state := make(map[string]uint8, len(r.profiles))
	var visit func(string, []string) error
	visit = func(name string, stack []string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("%w: %s", ErrCycle, strings.Join(append(stack, name), " -> "))
		case 2:
			return nil
		}
		state[name] = 1
		for _, dependency := range r.profiles[name].DependsOn {
			if err := visit(dependency, append(stack, name)); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range r.profiles {
		if err := visit(name, nil); err != nil {
			return err
		}
	}
	return nil
}

func validateProfile(profile Profile) error {
	if profile.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: %s has schema version %d, want %d", ErrInvalidProfile, profile.Name, profile.SchemaVersion, SchemaVersion)
	}
	if !profileName.MatchString(profile.Name) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidProfile, profile.Name)
	}
	if strings.TrimSpace(profile.Description) == "" {
		return fmt.Errorf("%w: %s has no description", ErrInvalidProfile, profile.Name)
	}
	if len(profile.Components) == 0 {
		return fmt.Errorf("%w: %s has no components", ErrInvalidProfile, profile.Name)
	}
	for field, values := range map[string][]string{
		"dependency": profile.DependsOn,
		"conflict":   profile.ConflictsWith,
		"component":  profile.Components,
	} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if !profileName.MatchString(value) {
				return fmt.Errorf("%w: %s has invalid %s %q", ErrInvalidProfile, profile.Name, field, value)
			}
			if value == profile.Name && field != "component" {
				return fmt.Errorf("%w: %s references itself as %s", ErrInvalidProfile, profile.Name, field)
			}
			if _, duplicate := seen[value]; duplicate {
				return fmt.Errorf("%w: %s repeats %s %q", ErrInvalidProfile, profile.Name, field, value)
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

func clone(profile Profile) Profile {
	profile.DependsOn = append([]string(nil), profile.DependsOn...)
	profile.ConflictsWith = append([]string(nil), profile.ConflictsWith...)
	profile.Components = append([]string(nil), profile.Components...)
	return profile
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
