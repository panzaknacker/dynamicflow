package operatortrust

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dynamicflow/internal/localstate"
)

func TestLoadVerifiesAllCommittedRootsWithoutMutation(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := Ensure(store)
	if err != nil {
		t.Fatal(err)
	}
	before := trustTreeSnapshot(t, store.Root())
	got, err := Load(store)
	if err != nil || got != want {
		t.Fatalf("load=%+v err=%v", got, err)
	}
	if got, err := Ensure(store); err != nil || got != want {
		t.Fatalf("ensure existing trust=%+v err=%v", got, err)
	}
	if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("reading or ensuring committed trust rewrote state")
	}
	lockPath, _ := store.Path("keys/signing/.trust.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	before = trustTreeSnapshot(t, store.Root())
	if got, err := Ensure(store); err != nil || got != want {
		t.Fatalf("ensure without creation lock=%+v err=%v", got, err)
	}
	if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("ensuring committed trust recreated an initialization lock")
	}
	for _, item := range roles {
		t.Run(item.name, func(t *testing.T) {
			privatePath, _ := store.Path(filepath.Join("keys/signing", item.base+".private.pem"))
			private, err := os.ReadFile(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			if err := os.WriteFile(privatePath, []byte("invalid private key"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := trustTreeSnapshot(t, store.Root())
			if _, err := Load(store); err == nil {
				t.Fatal("invalid role key accepted")
			}
			if _, err := Ensure(store); err == nil {
				t.Fatal("committed invalid role key accepted")
			}
			if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
				t.Fatal("invalid role key was repaired or trust rewritten")
			}
			if err := os.WriteFile(privatePath, private, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Both files remain individually valid Ed25519 keys, so this exercises the
	// actual pair binding rather than malformed PEM or bundle validation alone.
	releasePublicPath, _ := store.Path("keys/signing/release.public.pem")
	otherPublicPath, _ := store.Path("keys/signing/desired-state.public.pem")
	otherPublic, err := os.ReadFile(otherPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePublicPath, otherPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	before = trustTreeSnapshot(t, store.Root())
	if _, err := Load(store); err == nil {
		t.Fatal("mismatched but valid private/public pair accepted by Load")
	}
	if _, err := Ensure(store); err == nil {
		t.Fatal("mismatched but valid private/public pair accepted by Ensure")
	}
	if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("mismatched private/public pair was repaired")
	}
}

func TestEnsureNeverRegeneratesMissingCommittedPair(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(store); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"release.private.pem", "release.public.pem"} {
		path, _ := store.Path(filepath.Join("keys/signing", name))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	before := trustTreeSnapshot(t, store.Root())
	if _, err := Ensure(store); err == nil {
		t.Fatal("deleted committed pair was regenerated")
	}
	if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("missing trust pair changed existing state")
	}
}

func TestLoadAndEnsureRejectInvalidCommittedBundleWithoutRepair(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := Ensure(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"malformed", "wrong-id", "duplicate-role"} {
		t.Run(mutation, func(t *testing.T) {
			bundle := want
			switch mutation {
			case "malformed":
				err = store.WriteFile("keys/signing/trust.json", []byte("not JSON"))
			case "wrong-id":
				bundle.Release = "an-uncommitted-root"
				err = store.WriteJSON("keys/signing/trust.json", bundle)
			case "duplicate-role":
				bundle.Release = bundle.SystemRoot
				err = store.WriteJSON("keys/signing/trust.json", bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := trustTreeSnapshot(t, store.Root())
			if _, err := Load(store); err == nil {
				t.Fatal("invalid trust bundle accepted by Load")
			}
			if _, err := Ensure(store); err == nil {
				t.Fatal("invalid trust bundle accepted by Ensure")
			}
			if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
				t.Fatal("invalid committed bundle was rewritten")
			}
		})
	}
}

func TestLoadMissingBundleDoesNotInitializeTrust(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "system"))
	if err != nil {
		t.Fatal(err)
	}
	before := trustTreeSnapshot(t, store.Root())
	if _, err := Load(store); err == nil {
		t.Fatal("missing trust bundle accepted")
	}
	if after := trustTreeSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("Load created trust state")
	}
}

func trustTreeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		value := fmt.Sprintf("%v:%d", info.Mode(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(data))
			clear(data)
		}
		result[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
