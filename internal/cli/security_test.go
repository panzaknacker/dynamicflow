package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"dynamicflow/internal/instances"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

func TestNormalLifecycleCommandsNeverExecuteSSH(t *testing.T) {
	home := privateTempDir(t)
	fakeBin := privateTempDir(t)
	sentinel := filepath.Join(t.TempDir(), "ssh-was-executed")
	fakeSSH := filepath.Join(fakeBin, "ssh")
	script := "#!/bin/sh\n: >\"$FLOW_SSH_SENTINEL\"\nexit 99\n"
	if err := os.WriteFile(fakeSSH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	revokeName := "missing"
	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		store, err := localstate.Open(home)
		if err != nil {
			t.Fatal(err)
		}
		keys := sshkeys.NewManager(store, sshkeys.WithSSHKeygen(keygen))
		identity, err := keys.Create(context.Background(), sshkeys.Instance, "lifecycle")
		if err != nil {
			t.Fatal(err)
		}
		manager := instances.NewManager(store, keys)
		if _, err := manager.Put(instances.Record{
			Name: "lifecycle", Profile: "ssh", Host: "203.0.113.20", SSHUser: "debian",
			Key:     instances.KeyRef{Scope: sshkeys.Instance, Name: "lifecycle"},
			HostKey: identity.PublicKey,
		}); err != nil {
			t.Fatal(err)
		}
		revokeName = "lifecycle"
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("FLOW_SSH_SENTINEL", sentinel)

	commands := [][]string{
		{"--home", home, "status", "serving"},
		{"--home", home, "logs", "serving"},
		{"--home", home, "instance", "status", "missing"},
		{"--home", home, "instance", "logs", "missing", "--component", "pbp"},
		{"--home", home, "instance", "apply", "missing", "--profile", "pbp"},
		{"--home", home, "instance", "revoke", revokeName},
	}
	for _, arguments := range commands {
		invokeCLI(t, arguments...)
		if _, err := os.Lstat(sentinel); err == nil {
			t.Fatalf("normal lifecycle command executed ssh: %v", arguments)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}
