package instances

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

func TestPinnedInstanceAndHardenedSSHArgs(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
	identity, err := keys.Create(context.Background(), sshkeys.Instance, "pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	manager := NewManager(store, keys, WithClock(func() time.Time { return now }))
	created, err := manager.Put(Record{
		Name:    "pbp-01",
		Profile: "pbp",
		Host:    "203.0.113.10",
		SSHUser: "debian",
		Key:     KeyRef{Scope: sshkeys.Instance, Name: "pbp-01"},
		HostKey: identity.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.SSHPort != 22 || created.HostKeyFingerprint != identity.Fingerprint || created.Status != ActiveStatus {
		t.Fatalf("created instance = %+v", created)
	}
	knownHosts, err := store.Path(filepath.Join("instances", "pbp-01", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode = %04o", info.Mode().Perm())
	}
	args, err := manager.SSHArgs("pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=" + knownHosts,
		"IdentitiesOnly=yes",
		"IdentityAgent=none",
		"PasswordAuthentication=no",
		"ForwardAgent=no",
		"ForwardX11=no",
		"ClearAllForwardings=yes",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("SSH args missing %q: %v", required, args)
		}
	}
	_, keyPaths, err := keys.Active(sshkeys.Instance, "pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	if !containsPair(args, "-i", keyPaths.Private) || !reflect.DeepEqual(args[len(args)-3:], []string{"-l", "debian", "203.0.113.10"}) {
		t.Fatalf("SSH identity/destination args = %v", args)
	}
	if ssh, err := exec.LookPath("ssh"); err == nil {
		configArgs := append([]string{"-G"}, args...)
		if output, err := exec.Command(ssh, configArgs...).CombinedOutput(); err != nil {
			t.Fatalf("OpenSSH rejected generated arguments: %v: %s", err, output)
		}
	}

	rotatedIdentity, err := keys.Rotate(context.Background(), sshkeys.Instance, "pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	currentOnlyArgs, err := manager.SSHArgs("pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	if identityCountInArgs(currentOnlyArgs) != 1 {
		t.Fatalf("default SSH args retained a stale private generation: %v", currentOnlyArgs)
	}
	overlapArgs, err := manager.SSHArgsWithPrevious("pbp-01")
	if err != nil {
		t.Fatal(err)
	}
	identityCount := identityCountInArgs(overlapArgs)
	if identityCount != 2 {
		t.Fatalf("rotated SSH overlap identity count = %d, args=%v", identityCount, overlapArgs)
	}
	changed := created
	changed.HostKey = rotatedIdentity.PublicKey
	if _, err := manager.Put(changed); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("implicit host key change error = %v", err)
	}
	now = now.Add(time.Hour)
	rotatedHost, err := manager.RotateHostKey("pbp-01", rotatedIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedHost.PreviousHostKeyFingerprint != identity.Fingerprint || rotatedHost.HostKeyFingerprint != rotatedIdentity.Fingerprint {
		t.Fatalf("host key rotation = %+v", rotatedHost)
	}
	records, err := manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "pbp-01" {
		t.Fatalf("instances = %+v", records)
	}
	if _, err := manager.Revoke("pbp-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SSHArgs("pbp-01"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("SSH revoked instance error = %v", err)
	}
}

func TestRejectsUnsafeInstanceInputs(t *testing.T) {
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(store, sshkeys.NewManager(store))
	for _, name := range []string{"", "../escape", "-option", "parent/child"} {
		if _, err := manager.Get(name); !errors.Is(err, ErrInvalidInstance) {
			t.Errorf("name %q error = %v", name, err)
		}
	}
}

func containsPair(values []string, first, second string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == first && values[index+1] == second {
			return true
		}
	}
	return false
}

func identityCountInArgs(values []string) int {
	count := 0
	for _, value := range values {
		if value == "-i" {
			count++
		}
	}
	return count
}
