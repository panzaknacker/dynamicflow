//go:build linux

package controlruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

type cancelReloadRunner struct {
	delegate        *linuxFixtureRunner
	cancel          context.CancelFunc
	cancelled       bool
	recoveryReloads int
}

func (runner *cancelReloadRunner) Run(ctx context.Context, executable string, arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := runner.delegate.Run(ctx, executable, arguments, stdin, stdout, stderr)
	if executable == systemctlPath {
		if !runner.cancelled {
			runner.cancelled = true
			runner.cancel()
			// CommandContext commonly returns an ExitError after cancellation;
			// the platform must retain the operation's actual cancellation cause.
			return errors.New("signal: killed")
		}
		if _, bounded := ctx.Deadline(); !bounded {
			return errors.New("recovery reload has no deadline")
		}
		runner.recoveryReloads++
	}
	return err
}

func TestLinuxInstallerCancellationRestoresExactOldStateAndReloads(t *testing.T) {
	fixture := newLinuxInstallerFixture(t)
	public, private, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope := fixedInstallerEnvelope(t, public, private, 3, runtimeTime.Add(24*time.Hour))
	if _, err := fixture.installer.Install(context.Background(), bytes.NewReader(oldEnvelope), installerRequest(3)); err != nil {
		t.Fatal(err)
	}
	oldRuntime, err := os.ReadFile(fixture.config.executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.sourcePath, []byte("new-runtime-to-rollback\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &cancelReloadRunner{delegate: fixture.runner, cancel: cancel}
	fixture.platform.runner = runner
	newEnvelope := fixedInstallerEnvelope(t, public, private, 4, runtimeTime.Add(48*time.Hour))
	result, err := fixture.installer.Install(ctx, bytes.NewReader(newEnvelope), installerRequest(3))
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrInstallRollback) || !result.RolledBack || runner.recoveryReloads != 1 {
		t.Fatalf("cancelled activation did not recover safely: result=%+v error=%v recovery reloads=%d", result, err, runner.recoveryReloads)
	}
	restoredEnvelope, err := os.ReadFile(filepath.Join(fixture.config.stateRoot, ActiveBundleName, "envelope.json"))
	if err != nil || !bytes.Equal(restoredEnvelope, oldEnvelope) {
		t.Fatalf("old signed policy was not restored: %v", err)
	}
	restoredRuntime, err := os.ReadFile(fixture.config.executable)
	if err != nil || !bytes.Equal(restoredRuntime, oldRuntime) {
		t.Fatalf("old runtime was not restored: %v", err)
	}
	assertNoStageEntries(t, fixture.config.stateRoot, filepath.Dir(fixture.config.sshdDropIn), filepath.Dir(fixture.config.executable))
}
