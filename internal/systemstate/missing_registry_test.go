package systemstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"dynamicflow/internal/localstate"
)

func TestMissingRegistryWithExistingSystemDataNeverBecomesEmpty(t *testing.T) {
	state := openTestLocalState(t)
	store, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	system, _, err := store.CreateOrGet("existing")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.WriteFile(filepath.Join("systems", system.ID, "identity-evidence"), []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state.Root(), registryPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(state); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("reopen accepted orphaned systems: %v", err)
	}
	if _, err := store.Snapshot(); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("live store accepted lost registry: %v", err)
	}
	if _, created, err := store.CreateOrGet("replacement"); !errors.Is(err, ErrInvalidStore) || created {
		t.Fatalf("lost registry created replacement: created=%t err=%v", created, err)
	}
	if _, err := os.Lstat(filepath.Join(state.Root(), registryPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lost registry was rewritten: %v", err)
	}
}

func TestMissingRegistryAllowsOnlySecureInitializationArtifacts(t *testing.T) {
	for _, scenario := range []string{"absent", "empty", "lock", "interrupted registry", "symlink lock", "unexpected file", "unsafe temporary mode", "hardlink temporary", "symlink temporary", "oversized temporary", "temporary with system data"} {
		t.Run(scenario, func(t *testing.T) {
			state := openTestLocalState(t)
			if scenario != "absent" {
				if _, err := state.EnsureDir("systems"); err != nil {
					t.Fatal(err)
				}
			}
			var temporaryPath string
			switch scenario {
			case "lock":
				if err := state.WithLock(registryLock, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			case "symlink lock":
				if err := os.Symlink("missing", filepath.Join(state.Root(), registryLock)); err != nil {
					t.Fatal(err)
				}
			case "unexpected file":
				if err := os.WriteFile(filepath.Join(state.Root(), "systems", "lost-registry.backup"), []byte("existing"), localstate.FileMode); err != nil {
					t.Fatal(err)
				}
			case "interrupted registry", "unsafe temporary mode", "hardlink temporary", "symlink temporary", "oversized temporary", "temporary with system data":
				temporary, err := os.CreateTemp(filepath.Join(state.Root(), "systems"), ".registry.json.tmp-")
				if err != nil {
					t.Fatal(err)
				}
				temporaryPath = temporary.Name()
				if _, err := temporary.WriteString(`{"schema":`); err != nil {
					t.Fatal(err)
				}
				if err := temporary.Close(); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "unsafe temporary mode":
					err = os.Chmod(temporaryPath, 0o644)
				case "hardlink temporary":
					err = os.Link(temporaryPath, filepath.Join(state.Root(), "other-link"))
				case "symlink temporary":
					if err = os.Remove(temporaryPath); err == nil {
						err = os.Symlink("missing", temporaryPath)
					}
				case "oversized temporary":
					err = os.Truncate(temporaryPath, (8<<20)+1)
				case "temporary with system data":
					_, err = state.EnsureDir("systems/sys-00112233445566778899aabbccddeeff")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := New(state)
			allowed := scenario == "absent" || scenario == "empty" || scenario == "lock" || scenario == "interrupted registry"
			if !allowed {
				if !errors.Is(err, ErrInvalidStore) {
					t.Fatalf("unsafe missing registry accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, created, err := store.CreateOrGet("fresh"); err != nil || !created {
				t.Fatalf("fresh initialization failed: created=%t err=%v", created, err)
			}
			if temporaryPath != "" {
				if contents, err := os.ReadFile(temporaryPath); err != nil || string(contents) != `{"schema":` {
					t.Fatalf("uncommitted temporary was adopted or removed: %v", err)
				}
			}
		})
	}
}
