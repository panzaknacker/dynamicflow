package systemstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
)

var testNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

func TestCreateOrGetMultipleSystemsIsIdempotentPrivateAndDeterministic(t *testing.T) {
	state := openTestLocalState(t)
	entropy := append(bytes.Repeat([]byte{0x11}, systemIDSize), bytes.Repeat([]byte{0x22}, systemIDSize)...)
	store, err := New(state, WithClock(func() time.Time { return testNow }), WithRandomReader(bytes.NewReader(entropy)))
	if err != nil {
		t.Fatal(err)
	}

	zeta, created, err := store.CreateOrGet("zeta")
	if err != nil || !created {
		t.Fatalf("create zeta: created=%t err=%v", created, err)
	}
	if zeta.ID != "sys-"+strings.Repeat("11", systemIDSize) || zeta.Schema != SystemSchema || zeta.Revision != 1 ||
		zeta.Status != StatusInitializing || zeta.Bootstrap.State != BootstrapNotStarted ||
		!zeta.CreatedAt.Equal(testNow) || !zeta.UpdatedAt.Equal(testNow) {
		t.Fatalf("unexpected first system: %+v", zeta)
	}
	alpha, created, err := store.CreateOrGet("alpha")
	if err != nil || !created {
		t.Fatalf("create alpha: created=%t err=%v", created, err)
	}
	if alpha.ID != "sys-"+strings.Repeat("22", systemIDSize) {
		t.Fatalf("alpha ID = %q", alpha.ID)
	}

	// the entropy reader is now exhausted. an idempotent lookup must not read it
	// or advance registry/system revisions.
	again, created, err := store.CreateOrGet("alpha")
	if err != nil || created || again != alpha {
		t.Fatalf("idempotent create: got=%+v created=%t err=%v", again, created, err)
	}
	registry, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if registry.Schema != RegistrySchema || registry.Revision != 2 || registry.ActiveSystemID != zeta.ID || len(registry.Systems) != 2 ||
		registry.Systems[0].Name != "alpha" || registry.Systems[1].Name != "zeta" {
		t.Fatalf("registry = %+v", registry)
	}
	active, err := store.Active()
	if err != nil || active.ID != zeta.ID {
		t.Fatalf("active = %+v, err=%v", active, err)
	}

	assertMode(t, state, "systems", localstate.DirMode, true)
	assertMode(t, state, registryPath, localstate.FileMode, false)
	assertMode(t, state, registryLock, localstate.FileMode, false)
	data, err := state.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private_path", `"secret"`, "bearer_token"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("registry exposed forbidden field %q: %s", forbidden, data)
		}
	}
	if _, _, err := store.CreateOrGet("unsafe name"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid name error = %v", err)
	}
}

func TestRevisionCheckedUpdateValidatesMetadataAndImmutableFields(t *testing.T) {
	state := openTestLocalState(t)
	now := testNow
	store, err := New(state,
		WithClock(func() time.Time { return now }),
		WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x31}, systemIDSize))),
	)
	if err != nil {
		t.Fatal(err)
	}
	system, _, err := store.CreateOrGet("primary")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	expires := testNow.Add(15 * time.Minute)
	updated, err := store.Update(system.ID, 1, func(candidate *System) error {
		candidate.Status = StatusActive
		candidate.Trust = validTrust(1)
		candidate.Bootstrap = BootstrapMetadata{
			State: BootstrapControlActive, ControlNodeID: "control-01",
			BootstrapKeyFingerprint: testFingerprint(1), HostKeyFingerprint: testFingerprint(2),
			ExpiresAt: &expires, BootstrapKeyRevoked: true,
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Status != StatusActive || !updated.UpdatedAt.Equal(now) || updated.Trust.Generation != 1 {
		t.Fatalf("updated = %+v", updated)
	}
	registry, err := store.Snapshot()
	if err != nil || registry.Revision != 2 {
		t.Fatalf("registry revision = %d, err=%v", registry.Revision, err)
	}

	called := false
	if _, err := store.Update(system.ID, 1, func(*System) error { called = true; return nil }); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	if called {
		t.Fatal("stale update invoked callback")
	}

	immutable := []struct {
		name   string
		mutate func(*System)
	}{
		{"schema", func(value *System) { value.Schema++ }},
		{"id", func(value *System) { value.ID = "sys-" + strings.Repeat("f", 32) }},
		{"name", func(value *System) { value.Name = "renamed" }},
		{"revision", func(value *System) { value.Revision++ }},
		{"created", func(value *System) { value.CreatedAt = value.CreatedAt.Add(time.Second) }},
		{"updated", func(value *System) { value.UpdatedAt = value.UpdatedAt.Add(time.Second) }},
	}
	for _, test := range immutable {
		t.Run("immutable-"+test.name, func(t *testing.T) {
			_, updateErr := store.Update(system.ID, 2, func(candidate *System) error {
				test.mutate(candidate)
				return nil
			})
			if !errors.Is(updateErr, ErrImmutableField) {
				t.Fatalf("error = %v", updateErr)
			}
		})
	}

	sentinel := errors.New("callback stopped")
	if _, err := store.Update(system.ID, 2, func(candidate *System) error {
		candidate.Status = StatusDegraded
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("callback error = %v", err)
	}
	current, err := store.Get(system.ID)
	if err != nil || current.Revision != 2 || current.Status != StatusActive {
		t.Fatalf("callback failure changed state: %+v err=%v", current, err)
	}

	if _, err := store.Update(system.ID, 2, func(candidate *System) error {
		candidate.Bootstrap.ControlNodeID = "/tmp/private-key"
		return nil
	}); !errors.Is(err, ErrInvalidSystem) {
		t.Fatalf("unsafe metadata error = %v", err)
	}
	if _, err := store.Update(system.ID, 2, func(candidate *System) error {
		candidate.Status = StatusInitializing
		return nil
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("backward status error = %v", err)
	}

	now = testNow
	if _, err := store.Update(system.ID, 2, func(candidate *System) error {
		candidate.Status = StatusDegraded
		return nil
	}); !errors.Is(err, ErrInvalidClock) {
		t.Fatalf("backward clock error = %v", err)
	}
	now = testNow.Add(2 * time.Minute)
	degraded, err := store.Update(system.ID, 2, func(candidate *System) error {
		candidate.Status = StatusDegraded
		return nil
	})
	if err != nil || degraded.Revision != 3 || degraded.Status != StatusDegraded {
		t.Fatalf("degraded = %+v err=%v", degraded, err)
	}
}

func TestActiveSelectionIsRevisionCheckedAndRetirementIsSafe(t *testing.T) {
	state := openTestLocalState(t)
	entropy := append(bytes.Repeat([]byte{0x41}, systemIDSize), bytes.Repeat([]byte{0x42}, systemIDSize)...)
	store, err := New(state, WithClock(func() time.Time { return testNow }), WithRandomReader(bytes.NewReader(entropy)))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := store.CreateOrGet("first")
	second, _, _ := store.CreateOrGet("second")
	selected, err := store.SetActive(second.ID, 2)
	if err != nil || selected.ID != second.ID {
		t.Fatalf("set active: %+v err=%v", selected, err)
	}
	registry, _ := store.Snapshot()
	if registry.Revision != 3 || registry.ActiveSystemID != second.ID {
		t.Fatalf("registry = %+v", registry)
	}
	if _, err := store.SetActive(first.ID, 2); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale active selection error = %v", err)
	}
	if _, err := store.SetActive(second.ID, 3); err != nil {
		t.Fatalf("idempotent selection: %v", err)
	}
	registry, _ = store.Snapshot()
	if registry.Revision != 3 {
		t.Fatalf("idempotent selection advanced revision to %d", registry.Revision)
	}

	retired, err := store.Update(first.ID, 1, func(candidate *System) error {
		candidate.Status = StatusRetired
		return nil
	})
	if err != nil || retired.Status != StatusRetired {
		t.Fatalf("retire inactive: %+v err=%v", retired, err)
	}
	registry, _ = store.Snapshot()
	if _, err := store.SetActive(first.ID, registry.Revision); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("select retired error = %v", err)
	}
	if _, err := store.Update(second.ID, 1, func(candidate *System) error {
		candidate.Status = StatusRetired
		return nil
	}); !errors.Is(err, ErrActiveSystem) {
		t.Fatalf("retire active error = %v", err)
	}
}

func TestActiveStatusRequiresCompleteDistinctTrustAndControlProof(t *testing.T) {
	state := openTestLocalState(t)
	store, err := New(state,
		WithClock(func() time.Time { return testNow }),
		WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x51}, systemIDSize))),
	)
	if err != nil {
		t.Fatal(err)
	}
	system, _, _ := store.CreateOrGet("proof")
	if _, err := store.Update(system.ID, 1, func(candidate *System) error {
		candidate.Status = StatusActive
		return nil
	}); !errors.Is(err, ErrInvalidSystem) {
		t.Fatalf("active without proof error = %v", err)
	}
	if _, err := store.Update(system.ID, 1, func(candidate *System) error {
		candidate.Trust = validTrust(1)
		candidate.Trust.ControlPolicyKeyID = candidate.Trust.ServingAdminKeyID
		return nil
	}); !errors.Is(err, ErrInvalidSystem) {
		t.Fatalf("shared trust role error = %v", err)
	}
	if _, err := store.Update(system.ID, 1, func(candidate *System) error {
		candidate.Trust.Generation = 1
		candidate.Trust.ReleaseKeyID = testKeyID("release")
		return nil
	}); !errors.Is(err, ErrInvalidSystem) {
		t.Fatalf("partial trust error = %v", err)
	}
}

func TestCorruptAndUnknownSchemasFailClosedWithoutOverwrite(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Registry) any
	}{
		{"unknown-registry-schema", func(registry Registry) any { registry.Schema = 99; return registry }},
		{"unknown-system-schema", func(registry Registry) any { registry.Systems[0].Schema = 99; return registry }},
		{"missing-active", func(registry Registry) any { registry.ActiveSystemID = ""; return registry }},
		{"missing-active-record", func(registry Registry) any {
			registry.ActiveSystemID = "sys-" + strings.Repeat("f", 32)
			return registry
		}},
		{"zero-registry-revision", func(registry Registry) any { registry.Revision = 0; return registry }},
		{"zero-system-revision", func(registry Registry) any { registry.Systems[0].Revision = 0; return registry }},
		{"unknown-status", func(registry Registry) any { registry.Systems[0].Status = "unknown"; return registry }},
		{"active-system-retired", func(registry Registry) any { registry.Systems[0].Status = StatusRetired; return registry }},
		{"unsafe-bootstrap-node", func(registry Registry) any {
			registry.Systems[0].Bootstrap = BootstrapMetadata{State: BootstrapFailed, ControlNodeID: "../../escape", BootstrapKeyFingerprint: testFingerprint(1), ExpiresAt: timePointer(testNow.Add(time.Hour)), FailureCode: "failed"}
			return registry
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openTestLocalState(t)
			store, err := New(state,
				WithClock(func() time.Time { return testNow }),
				WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x61}, systemIDSize))),
			)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = store.CreateOrGet("corrupt")
			if err != nil {
				t.Fatal(err)
			}
			registry, _ := store.Snapshot()
			if err := state.WriteJSON(registryPath, test.mutate(registry)); err != nil {
				t.Fatal(err)
			}
			before, _ := state.ReadFile(registryPath)
			if _, err := New(state); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("New error = %v", err)
			}
			if _, _, err := store.CreateOrGet("replacement"); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("CreateOrGet error = %v", err)
			}
			after, _ := state.ReadFile(registryPath)
			if !bytes.Equal(before, after) {
				t.Fatal("corrupt registry was overwritten")
			}
		})
	}

	t.Run("malformed-json", func(t *testing.T) {
		state := openTestLocalState(t)
		if err := state.WriteFile(registryPath, []byte("{\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := New(state); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("malformed error = %v", err)
		}
	})
	t.Run("unknown-json-field", func(t *testing.T) {
		state := openTestLocalState(t)
		data := `{"schema":1,"revision":1,"active_system_id":"sys-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","systems":[],"future":true}`
		if err := state.WriteFile(registryPath, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if _, err := New(state); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("unknown field error = %v", err)
		}
	})
	t.Run("duplicate-name-and-id", func(t *testing.T) {
		state := openTestLocalState(t)
		entropy := append(bytes.Repeat([]byte{0x71}, systemIDSize), bytes.Repeat([]byte{0x72}, systemIDSize)...)
		store, _ := New(state, WithClock(func() time.Time { return testNow }), WithRandomReader(bytes.NewReader(entropy)))
		first, _, _ := store.CreateOrGet("first")
		_, _, _ = store.CreateOrGet("second")
		registry, _ := store.Snapshot()
		registry.Systems[1].ID = first.ID
		registry.Systems[1].Name = first.Name
		if err := state.WriteJSON(registryPath, registry); err != nil {
			t.Fatal(err)
		}
		if _, err := New(state); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("duplicate error = %v", err)
		}
	})
}

func TestConcurrentCreateOrGetAllocatesExactlyOneSystem(t *testing.T) {
	state := openTestLocalState(t)
	store, err := New(state,
		WithClock(func() time.Time { return testNow }),
		WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x81}, systemIDSize))),
	)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	var created atomic.Int64
	ids := make(chan string, workers)
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			system, wasCreated, createErr := store.CreateOrGet("shared")
			if createErr != nil {
				errorsSeen <- createErr
				return
			}
			if wasCreated {
				created.Add(1)
			}
			ids <- system.ID
		}()
	}
	wait.Wait()
	close(errorsSeen)
	close(ids)
	for err := range errorsSeen {
		t.Errorf("concurrent create: %v", err)
	}
	if created.Load() != 1 {
		t.Fatalf("created count = %d", created.Load())
	}
	wanted := "sys-" + strings.Repeat("81", systemIDSize)
	count := 0
	for id := range ids {
		count++
		if id != wanted {
			t.Errorf("ID = %q, want %q", id, wanted)
		}
	}
	if count != workers {
		t.Fatalf("result count = %d", count)
	}
	registry, err := store.Snapshot()
	if err != nil || registry.Revision != 1 || len(registry.Systems) != 1 {
		t.Fatalf("registry after concurrency = %+v err=%v", registry, err)
	}
}

func TestConcurrentRevisionCASHasExactlyOneWinner(t *testing.T) {
	state := openTestLocalState(t)
	store, err := New(state,
		WithClock(func() time.Time { return testNow }),
		WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0x91}, systemIDSize))),
	)
	if err != nil {
		t.Fatal(err)
	}
	system, _, _ := store.CreateOrGet("cas")
	const workers = 48
	var successes atomic.Int64
	var conflicts atomic.Int64
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, updateErr := store.Update(system.ID, 1, func(candidate *System) error {
				candidate.Status = StatusDegraded
				return nil
			})
			switch {
			case updateErr == nil:
				successes.Add(1)
			case errors.Is(updateErr, ErrRevisionConflict):
				conflicts.Add(1)
			default:
				errorsSeen <- updateErr
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("CAS update: %v", err)
	}
	if successes.Load() != 1 || conflicts.Load() != workers-1 {
		t.Fatalf("successes=%d conflicts=%d", successes.Load(), conflicts.Load())
	}
	current, err := store.Get(system.ID)
	if err != nil || current.Revision != 2 || current.Status != StatusDegraded {
		t.Fatalf("current = %+v err=%v", current, err)
	}
	registry, _ := store.Snapshot()
	if registry.Revision != 2 {
		t.Fatalf("registry revision = %d", registry.Revision)
	}
}

func TestConcurrentCreateAcrossIndependentStoreObjectsUsesOneRegistryLock(t *testing.T) {
	state := openTestLocalState(t)
	const workers = 24
	stores := make([]*Store, workers)
	for index := range stores {
		store, err := New(state,
			WithClock(func() time.Time { return testNow }),
			WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{byte(index + 1)}, systemIDSize))),
		)
		if err != nil {
			t.Fatal(err)
		}
		stores[index] = store
	}
	start := make(chan struct{})
	ids := make(chan string, workers)
	errorsSeen := make(chan error, workers)
	var created atomic.Int64
	var wait sync.WaitGroup
	for _, store := range stores {
		wait.Add(1)
		go func(store *Store) {
			defer wait.Done()
			<-start
			system, wasCreated, err := store.CreateOrGet("cross-store")
			if err != nil {
				errorsSeen <- err
				return
			}
			if wasCreated {
				created.Add(1)
			}
			ids <- system.ID
		}(store)
	}
	close(start)
	wait.Wait()
	close(ids)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("cross-store create: %v", err)
	}
	if created.Load() != 1 {
		t.Fatalf("created count = %d", created.Load())
	}
	wanted := ""
	count := 0
	for id := range ids {
		count++
		if wanted == "" {
			wanted = id
		}
		if id != wanted {
			t.Errorf("inconsistent IDs: got %q, want %q", id, wanted)
		}
	}
	if count != workers {
		t.Fatalf("result count = %d", count)
	}
	registry, err := stores[0].Snapshot()
	if err != nil || registry.Revision != 1 || len(registry.Systems) != 1 || registry.Systems[0].ID != wanted {
		t.Fatalf("registry = %+v err=%v", registry, err)
	}
}

func TestEntropyCollisionAndInvalidClockDoNotCommit(t *testing.T) {
	t.Run("collision", func(t *testing.T) {
		state := openTestLocalState(t)
		store, err := New(state,
			WithClock(func() time.Time { return testNow }),
			WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0xa1}, systemIDSize*9))),
		)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _ = store.CreateOrGet("first")
		if _, _, err := store.CreateOrGet("second"); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("collision error = %v", err)
		}
		registry, _ := store.Snapshot()
		if registry.Revision != 1 || len(registry.Systems) != 1 {
			t.Fatalf("collision committed state: %+v", registry)
		}
	})
	t.Run("clock", func(t *testing.T) {
		state := openTestLocalState(t)
		store, err := New(state,
			WithClock(func() time.Time { return time.Time{} }),
			WithRandomReader(bytes.NewReader(bytes.Repeat([]byte{0xb1}, systemIDSize))),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.CreateOrGet("clock"); !errors.Is(err, ErrInvalidClock) {
			t.Fatalf("clock error = %v", err)
		}
		registry, err := store.Snapshot()
		if err != nil || registry.Revision != 0 || len(registry.Systems) != 0 {
			t.Fatalf("invalid clock committed state: %+v err=%v", registry, err)
		}
	})
}

func openTestLocalState(t *testing.T) *localstate.Store {
	t.Helper()
	state, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func validTrust(generation uint64) TrustMetadata {
	return TrustMetadata{
		Generation: generation, SystemRootKeyID: testKeyID("root"), ReleaseKeyID: testKeyID("release"),
		DesiredStateKeyID: testKeyID("desired"), ServingAdminKeyID: testKeyID("admin"),
		ControlPolicyKeyID: testKeyID("policy"),
	}
}

func testKeyID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func testFingerprint(value byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func timePointer(value time.Time) *time.Time { return &value }

func assertMode(t *testing.T, state *localstate.Store, relative string, wanted os.FileMode, directory bool) {
	t.Helper()
	path, err := state.Path(relative)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || info.Mode().Perm() != wanted {
		t.Fatalf("%s metadata: mode=%v directory=%t, want mode=%04o directory=%t", relative, info.Mode(), info.IsDir(), wanted, directory)
	}
}
