package topology

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"dynamicflow/internal/localstate"
)

func TestValidateAcceptsPinnedDirectBootstrapBeforeControlReady(t *testing.T) {
	document := validDirectTopology()
	if err := Validate(document); err != nil {
		t.Fatalf("valid direct bootstrap topology: %v", err)
	}
}

func TestValidateAcceptsFingerprintBoundRoutesEndingAtControl(t *testing.T) {
	document := validRoutedTopology()
	if err := Validate(document); err != nil {
		t.Fatalf("valid routed topology: %v", err)
	}
}

func TestValidateRejectsInvalidControlTrustAndEndpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Topology)
		want   error
	}{
		{
			name: "missing",
			mutate: func(document *Topology) {
				document.Control = nil
			},
			want: ErrMissingControl,
		},
		{
			name: "unpinned",
			mutate: func(document *Topology) {
				document.Control.Trust = TrustUnpinned
				document.Control.HostKeyFingerprint = ""
			},
			want: ErrControlUnpinned,
		},
		{
			name: "revoked",
			mutate: func(document *Topology) {
				document.Control.Trust = TrustRevoked
			},
			want: ErrControlRevoked,
		},
		{
			name: "bad fingerprint",
			mutate: func(document *Topology) {
				document.Control.HostKeyFingerprint = "SHA256:not-canonical"
			},
			want: ErrInvalidFingerprint,
		},
		{
			name: "root user",
			mutate: func(document *Topology) {
				document.Control.SSHUser = "root"
			},
			want: ErrInvalidTopology,
		},
		{
			name: "zero port",
			mutate: func(document *Topology) {
				document.Control.SSHPort = 0
			},
			want: ErrInvalidTopology,
		},
		{
			name: "unsafe host",
			mutate: func(document *Topology) {
				document.Control.Host = "-oProxyCommand=evil"
			},
			want: ErrUnsafeHost,
		},
		{
			name: "noncanonical host",
			mutate: func(document *Topology) {
				document.Control.Host = "Control.Example"
			},
			want: ErrUnsafeHost,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := validRoutedTopology()
			test.mutate(&document)
			if err := Validate(document); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRejectsUnsafeHostForms(t *testing.T) {
	for index, host := range []string{
		"",
		" host.example",
		"host.example ",
		"host name",
		"host/child",
		`host\child`,
		"user@host",
		"fe80::1%eth0",
		"[2001:db8::1]",
		"-host",
		"host.",
		"UPPER.example",
		"0.0.0.0",
		"::",
		"ff02::1",
		"a..b",
		"a_b",
		strings.Repeat("a", 64) + ".example",
	} {
		t.Run("case-"+strconv.Itoa(index), func(t *testing.T) {
			document := validDirectTopology()
			document.Targets[0].DirectHost = host
			if err := Validate(document); !errors.Is(err, ErrUnsafeHost) {
				t.Fatalf("host %q error = %v, want ErrUnsafeHost", host, err)
			}
		})
	}
}

func TestValidateRejectsInvalidTargets(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Topology)
		want   error
	}{
		{
			name: "unpinned",
			mutate: func(document *Topology) {
				document.Targets[0].Trust = TrustUnpinned
			},
			want: ErrTargetUnpinned,
		},
		{
			name: "revoked",
			mutate: func(document *Topology) {
				document.Targets[0].Trust = TrustRevoked
			},
			want: ErrTargetRevoked,
		},
		{
			name: "bad fingerprint",
			mutate: func(document *Topology) {
				document.Targets[0].HostKeyFingerprint = "MD5:bad"
			},
			want: ErrInvalidFingerprint,
		},
		{
			name: "root user",
			mutate: func(document *Topology) {
				document.Targets[0].SSHUser = "root"
			},
			want: ErrInvalidTopology,
		},
		{
			name: "invalid access",
			mutate: func(document *Topology) {
				document.Targets[0].Access = AccessMode("proxy-command")
			},
			want: ErrInvalidTopology,
		},
		{
			name: "direct after ready",
			mutate: func(document *Topology) {
				document.Targets[0].Access = AccessDirect
				document.Targets[0].DirectHost = "198.51.100.20"
			},
			want: ErrDirectAfterControlReady,
		},
		{
			name: "control with direct host",
			mutate: func(document *Topology) {
				document.Targets[0].DirectHost = "198.51.100.20"
			},
			want: ErrInvalidRoute,
		},
		{
			name: "duplicate name",
			mutate: func(document *Topology) {
				document.Targets[1].Name = document.Targets[0].Name
			},
			want: ErrInvalidTopology,
		},
		{
			name: "control name collision",
			mutate: func(document *Topology) {
				document.Targets[0].Name = document.Control.Name
			},
			want: ErrInvalidTopology,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := validRoutedTopology()
			test.mutate(&document)
			if err := Validate(document); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidRoutes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Topology)
		want   error
	}{
		{
			name: "missing route",
			mutate: func(document *Topology) {
				document.Routes = document.Routes[1:]
			},
			want: ErrInvalidRoute,
		},
		{
			name: "orphan route",
			mutate: func(document *Topology) {
				document.Routes[0].Target = "missing-target"
			},
			want: ErrInvalidRoute,
		},
		{
			name: "duplicate route",
			mutate: func(document *Topology) {
				document.Routes[1] = document.Routes[0]
			},
			want: ErrInvalidRoute,
		},
		{
			name: "self jump",
			mutate: func(document *Topology) {
				document.Routes[0].Via = document.Routes[0].Target
			},
			want: ErrSelfJump,
		},
		{
			name: "cycle",
			mutate: func(document *Topology) {
				document.Routes[0].Via = "target-b"
				document.Routes[1].Via = "target-a"
			},
			want: ErrCycle,
		},
		{
			name: "unknown jump",
			mutate: func(document *Topology) {
				document.Routes[0].Via = "unknown"
			},
			want: ErrInvalidRoute,
		},
		{
			name: "bad jump syntax",
			mutate: func(document *Topology) {
				document.Routes[0].Via = "../control"
			},
			want: ErrInvalidRoute,
		},
		{
			name: "duplicate management address",
			mutate: func(document *Topology) {
				document.Routes[1].ManagementAddress = document.Routes[0].ManagementAddress
			},
			want: ErrDuplicateManagementAddress,
		},
		{
			name: "unsafe management address",
			mutate: func(document *Topology) {
				document.Routes[0].ManagementAddress = "10.20.0.2 -o ProxyCommand=evil"
			},
			want: ErrUnsafeHost,
		},
		{
			name: "control fingerprint mismatch",
			mutate: func(document *Topology) {
				document.Routes[0].ControlFingerprint = fingerprint(9)
			},
			want: ErrRouteBinding,
		},
		{
			name: "target fingerprint mismatch",
			mutate: func(document *Topology) {
				document.Routes[0].TargetFingerprint = fingerprint(9)
			},
			want: ErrRouteBinding,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := validRoutedTopology()
			test.mutate(&document)
			if err := Validate(document); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRejectsControlRouteBeforeReadyAndRouteOnDirectTarget(t *testing.T) {
	document := validRoutedTopology()
	document.ControlReady = false
	if err := Validate(document); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("control route before ready error = %v, want ErrInvalidRoute", err)
	}

	document = validDirectTopology()
	document.Routes = []Route{{
		Target: "target-a", Via: document.Control.Name, ManagementAddress: "10.20.0.2",
		ControlFingerprint: document.Control.HostKeyFingerprint,
		TargetFingerprint:  document.Targets[0].HostKeyFingerprint,
	}}
	if err := Validate(document); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("route on direct target error = %v, want ErrInvalidRoute", err)
	}
}

func TestRouteBindingsMustMoveAtomicallyWithHostKeyPins(t *testing.T) {
	document := validRoutedTopology()
	document.Control.HostKeyFingerprint = fingerprint(7)
	if err := Validate(document); !errors.Is(err, ErrRouteBinding) {
		t.Fatalf("stale control route binding error = %v, want ErrRouteBinding", err)
	}
	for index := range document.Routes {
		document.Routes[index].ControlFingerprint = document.Control.HostKeyFingerprint
	}
	if err := Validate(document); err != nil {
		t.Fatalf("atomically updated control route binding: %v", err)
	}

	document.Targets[0].HostKeyFingerprint = fingerprint(8)
	if err := Validate(document); !errors.Is(err, ErrRouteBinding) {
		t.Fatalf("stale target route binding error = %v, want ErrRouteBinding", err)
	}
	document.Routes[0].TargetFingerprint = document.Targets[0].HostKeyFingerprint
	if err := Validate(document); err != nil {
		t.Fatalf("atomically updated target route binding: %v", err)
	}
}

func TestStorePersistsPrivateValidatedCanonicalState(t *testing.T) {
	local := openTestStore(t)
	store := NewStore(local)
	if _, err := store.Load(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("initial Load() error = %v, want ErrNotFound", err)
	}

	document := validRoutedTopology()
	document.Targets[0], document.Targets[1] = document.Targets[1], document.Targets[0]
	document.Routes[0], document.Routes[1] = document.Routes[1], document.Routes[0]
	if err := store.Save(document); err != nil {
		t.Fatalf("Save(): %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if got.Targets[0].Name != "target-a" || got.Routes[0].Target != "target-a" {
		t.Fatalf("stored topology is not canonical: %#v", got)
	}
	path, err := local.Path(stateRelative)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != localstate.FileMode ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		t.Fatalf("unsafe topology state metadata: mode=%v stat=%+v", info.Mode(), stat)
	}
}

func TestStoreIsIdempotentAndEnforcesExactGenerationAdvance(t *testing.T) {
	local := openTestStore(t)
	store := NewStore(local)
	first := validRoutedTopology()
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	path, _ := local.Path(stateRelative)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(first); err != nil {
		t.Fatalf("idempotent Save(): %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent Save rewrote topology bytes")
	}

	changed := validRoutedTopology()
	changed.Routes[0].ManagementAddress = "10.20.0.20"
	if err := store.Save(changed); !errors.Is(err, ErrGeneration) {
		t.Fatalf("same-generation changed Save() error = %v, want ErrGeneration", err)
	}
	changed.Generation = 3
	if err := store.Save(changed); !errors.Is(err, ErrGeneration) {
		t.Fatalf("skipped-generation Save() error = %v, want ErrGeneration", err)
	}
	changed.Generation = 2
	if err := store.Save(changed); err != nil {
		t.Fatalf("next-generation Save(): %v", err)
	}
}

func TestStoreRejectsControlReadyRollbackEvenWithValidDirectDocument(t *testing.T) {
	store := NewStore(openTestStore(t))
	if err := store.Save(validRoutedTopology()); err != nil {
		t.Fatal(err)
	}
	rollback := validDirectTopology()
	rollback.Generation = 2
	if err := Validate(rollback); err != nil {
		t.Fatalf("rollback fixture must be independently schema-valid: %v", err)
	}
	if err := store.Save(rollback); !errors.Is(err, ErrControlReadyRollback) {
		t.Fatalf("rollback Save() error = %v, want ErrControlReadyRollback", err)
	}
}

func TestStoreRejectsInvalidFirstGenerationWithoutWritingState(t *testing.T) {
	local := openTestStore(t)
	store := NewStore(local)
	document := validRoutedTopology()
	document.Generation = 2
	if err := store.Save(document); !errors.Is(err, ErrGeneration) {
		t.Fatalf("first generation error = %v, want ErrGeneration", err)
	}
	path, _ := local.Path(stateRelative)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid first generation wrote state: %v", err)
	}

	document.Generation = 1
	document.Control.Trust = TrustRevoked
	if err := store.Save(document); !errors.Is(err, ErrControlRevoked) {
		t.Fatalf("invalid control error = %v, want ErrControlRevoked", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid topology wrote state: %v", err)
	}
}

func TestStoreRejectsUnknownFieldsAndInvalidPersistedBinding(t *testing.T) {
	local := openTestStore(t)
	store := NewStore(local)
	if err := store.Save(validRoutedTopology()); err != nil {
		t.Fatal(err)
	}
	data, err := local.ReadFile(stateRelative)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1)
	if err := local.WriteFile(stateRelative, data); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field Load() error = %v", err)
	}

	corrupt := validRoutedTopology()
	corrupt.Routes[0].TargetFingerprint = fingerprint(99)
	if err := local.WriteJSON(stateRelative, corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrRouteBinding) {
		t.Fatalf("invalid persisted binding Load() error = %v, want ErrRouteBinding", err)
	}
}

func TestStoreSerializesConflictingConcurrentGeneration(t *testing.T) {
	store := NewStore(openTestStore(t))
	if err := store.Save(validRoutedTopology()); err != nil {
		t.Fatal(err)
	}
	left := validRoutedTopology()
	left.Generation = 2
	left.Routes[0].ManagementAddress = "10.20.0.20"
	right := validRoutedTopology()
	right.Generation = 2
	right.Routes[0].ManagementAddress = "10.20.0.21"

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, document := range []Topology{left, right} {
		document := document
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- store.Save(document)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrGeneration):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent Save() error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent saves: successes=%d conflicts=%d", successes, conflicts)
	}
	got, err := store.Load()
	if err != nil || got.Generation != 2 {
		t.Fatalf("persisted concurrent topology = %#v, err=%v", got, err)
	}
}

func TestStoreRejectsNilLocalState(t *testing.T) {
	var nilStore *Store
	if err := nilStore.Save(validRoutedTopology()); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("nil Store.Save() error = %v", err)
	}
	if _, err := nilStore.Load(); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("nil Store.Load() error = %v", err)
	}
	store := NewStore(nil)
	if err := store.Save(validRoutedTopology()); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("nil local Save() error = %v", err)
	}
}

func TestStoreRejectsSymlinkedTopologyDirectory(t *testing.T) {
	local := openTestStore(t)
	outside := t.TempDir()
	path, err := local.Path("topology")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(local).Save(validRoutedTopology()); !errors.Is(err, localstate.ErrSymlink) {
		t.Fatalf("symlinked topology Save() error = %v, want ErrSymlink", err)
	}
}

func validDirectTopology() Topology {
	return Topology{
		Schema:       SchemaVersion,
		Generation:   1,
		ControlReady: false,
		Control: &Control{
			Name: "control", Host: "control.example", SSHPort: 22, SSHUser: "flow-jump",
			Trust: TrustPinned, HostKeyFingerprint: fingerprint(1),
		},
		Targets: []Target{{
			Name: "target-a", Access: AccessDirect, DirectHost: "198.51.100.20",
			SSHPort: 22, SSHUser: "admin", Trust: TrustPinned,
			HostKeyFingerprint: fingerprint(2),
		}},
		Routes: []Route{},
	}
}

func validRoutedTopology() Topology {
	controlFingerprint := fingerprint(1)
	targetAFingerprint := fingerprint(2)
	targetBFingerprint := fingerprint(3)
	return Topology{
		Schema:       SchemaVersion,
		Generation:   1,
		ControlReady: true,
		Control: &Control{
			Name: "control", Host: "203.0.113.10", SSHPort: 22, SSHUser: "flow-jump",
			Trust: TrustPinned, HostKeyFingerprint: controlFingerprint,
		},
		Targets: []Target{
			{
				Name: "target-a", Access: AccessControl, SSHPort: 22, SSHUser: "admin",
				Trust: TrustPinned, HostKeyFingerprint: targetAFingerprint,
			},
			{
				Name: "target-b", Access: AccessControl, SSHPort: 2222, SSHUser: "ubuntu",
				Trust: TrustPinned, HostKeyFingerprint: targetBFingerprint,
			},
		},
		Routes: []Route{
			{
				Target: "target-a", Via: "control", ManagementAddress: "10.20.0.2",
				ControlFingerprint: controlFingerprint, TargetFingerprint: targetAFingerprint,
			},
			{
				Target: "target-b", Via: "target-a", ManagementAddress: "2001:db8::3",
				ControlFingerprint: controlFingerprint, TargetFingerprint: targetBFingerprint,
			},
		},
	}
}

func fingerprint(seed byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func openTestStore(t *testing.T) *localstate.Store {
	t.Helper()
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
