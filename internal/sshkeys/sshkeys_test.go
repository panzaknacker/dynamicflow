package sshkeys

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
)

func TestCreateRotateListAndRevoke(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	manager := NewManager(store, WithSSHKeygen(keygen), WithClock(func() time.Time { return clock }))

	created, err := manager.Create(context.Background(), Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	if created.Generation != 1 || created.Status != ActiveStatus || !strings.HasPrefix(created.Fingerprint, "SHA256:") {
		t.Fatalf("unexpected record: %+v", created)
	}
	if _, err := manager.Create(context.Background(), Operator, "operator-one"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate create error = %v", err)
	}
	_, paths, err := manager.Active(Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(paths.Private)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key mode = %04o", mode)
	}
	privateData, err := os.ReadFile(paths.Private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), string(privateData)) || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("private key material appeared in public metadata")
	}

	clock = clock.Add(time.Hour)
	rotated, err := manager.Rotate(context.Background(), Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Generation != 2 || rotated.Fingerprint == created.Fingerprint || rotated.PreviousFingerprint != created.Fingerprint {
		t.Fatalf("unexpected rotation: %+v", rotated)
	}
	previous, previousPaths, err := manager.Previous(Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedPaths, err := manager.Active(Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	if previous.Generation != created.Generation || previous.Fingerprint != created.Fingerprint ||
		previousPaths.Private != paths.Private || previousPaths.Private == rotatedPaths.Private {
		t.Fatalf("previous generation = %+v paths=%+v", previous, previousPaths)
	}
	records, err := manager.List(Operator)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Generation != 2 {
		t.Fatalf("list = %+v", records)
	}
	if _, err := manager.RotateIfGeneration(context.Background(), Operator, "operator-one", 1); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale guarded rotation error = %v", err)
	}
	guarded, err := manager.RotateIfGeneration(context.Background(), Operator, "operator-one", 2)
	if err != nil || guarded.Generation != 3 {
		t.Fatalf("guarded rotation = %+v, %v", guarded, err)
	}
	revoked, err := manager.Revoke(Operator, "operator-one")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != RevokedStatus || revoked.RevokedAt == nil {
		t.Fatalf("revoke = %+v", revoked)
	}
	if _, _, err := manager.Active(Operator, "operator-one"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("active revoked key error = %v", err)
	}
	if _, _, err := manager.Previous(Operator, "operator-one"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("previous revoked key error = %v", err)
	}
	if _, err := manager.Rotate(context.Background(), Operator, "operator-one"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("rotate revoked key error = %v", err)
	}
}

func TestRejectsUnsafeNames(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(store)
	for _, name := range []string{"", "../escape", "name/child", "-option"} {
		if _, err := manager.Create(context.Background(), Instance, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q error = %v", name, err)
		}
	}
}

func TestBootstrapIdentityIsPrivateAndStable(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(store, WithSSHKeygen(keygen))
	record, err := manager.Create(context.Background(), Bootstrap, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Scope != Bootstrap || record.PublicKey == "" || record.Fingerprint == "" {
		t.Fatalf("bootstrap record = %+v", record)
	}
	active, paths, err := manager.Active(Bootstrap, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if active.Fingerprint != record.Fingerprint {
		t.Fatalf("bootstrap fingerprint changed: %q != %q", active.Fingerprint, record.Fingerprint)
	}
	privateInfo, err := os.Lstat(paths.Private)
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 || !privateInfo.Mode().IsRegular() {
		t.Fatalf("bootstrap private key mode = %v", privateInfo.Mode())
	}
}

func TestControlScopeRequiresExplicitInternalCapability(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	ordinary := NewManager(store, WithSSHKeygen(keygen))
	if _, err := ordinary.Create(context.Background(), Control, "control-1"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ordinary manager created internal Control identity: %v", err)
	}
	if _, err := ordinary.List(Control); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ordinary manager listed internal Control identities: %v", err)
	}

	internal := NewManager(store, WithSSHKeygen(keygen), WithControlScope())
	created, err := internal.Create(context.Background(), Control, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if created.Scope != Control || created.Generation != 1 || created.Status != ActiveStatus {
		t.Fatalf("Control identity = %+v", created)
	}
	active, paths, err := internal.Active(Control, "control-1")
	if err != nil || active != created || paths.Private == "" || paths.Public == "" {
		t.Fatalf("active Control identity = %+v paths=%+v err=%v", active, paths, err)
	}
	encoded, err := json.Marshal(paths)
	if err != nil {
		t.Fatal(err)
	}
	var exposed map[string]string
	if err := json.Unmarshal(encoded, &exposed); err != nil {
		t.Fatal(err)
	}
	if len(exposed) != 1 || exposed["public"] != paths.Public || exposed["private"] != "" ||
		strings.Contains(string(encoded), `"Private"`) {
		t.Fatalf("Control paths JSON leaked private identity path: %s", encoded)
	}
	if _, err := ordinary.Get(Control, "control-1"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ordinary manager reopened internal Control identity: %v", err)
	}
}
