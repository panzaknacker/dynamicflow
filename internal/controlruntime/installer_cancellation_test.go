package controlruntime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type recoveryContextKey struct{}

type cancellationInstallPlatform struct {
	*fakeInstallPlatform
	cancel   context.CancelFunc
	reloads  int
	recovery context.Context
}

func (platform *cancellationInstallPlatform) ReloadSSHD(ctx context.Context) error {
	platform.reloads++
	if platform.reloads == 1 {
		platform.cancel()
	}
	return ctx.Err()
}

func (platform *cancellationInstallPlatform) ValidateActiveSSHD(ctx context.Context) error {
	if platform.reloads == 1 {
		platform.recovery = ctx
	}
	return ctx.Err()
}

func TestInstallerCancellationRestoresAndReloadsThroughBoundedRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), recoveryContextKey{}, "operation"))
	defer cancel()
	platform := &cancellationInstallPlatform{
		fakeInstallPlatform: &fakeInstallPlatform{euid: 0, state: hostPreflight{ActivateBundle: true, InstallDropIn: true}},
		cancel:              cancel,
	}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	started := time.Now()
	result, err := installer.Install(ctx, bytes.NewReader(installerEnvelope(t, 3)), installerRequest(3))
	if errors.Is(err, ErrInstallRollback) || !errors.Is(err, context.Canceled) || !result.RolledBack || platform.reloads != 2 {
		t.Fatalf("cancellation did not restore and reload old configuration: result=%+v err=%v reloads=%d", result, err, platform.reloads)
	}
	if platform.recovery == nil || platform.recovery.Value(recoveryContextKey{}) != "operation" {
		t.Fatal("recovery lost operation context")
	}
	deadline, bounded := platform.recovery.Deadline()
	if !bounded || deadline.Before(started) || deadline.After(time.Now().Add(rollbackTimeout)) {
		t.Fatalf("recovery has no bounded deadline: %v %t", deadline, bounded)
	}
	if platform.recovery.Err() != context.Canceled {
		t.Fatal("recovery context resources were not released")
	}
	if got := strings.Join(platform.calls, ","); got != "lock,preflight,account,stage,validate,activate,rollback,commit,release" {
		t.Fatalf("cancellation did not finish durable rollback: %s", got)
	}
}

func TestInstallerCancelledBeforeInputDoesNotReadOrMutate(t *testing.T) {
	platform := &fakeInstallPlatform{euid: 0}
	installer := &Installer{platform: platform, now: func() time.Time { return runtimeTime }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &countingReader{reader: strings.NewReader("unread input")}
	_, err := installer.Install(ctx, reader, installerRequest(3))
	if !errors.Is(err, context.Canceled) || reader.reads != 0 || len(platform.calls) != 0 {
		t.Fatalf("canceled install consumed input or touched host: err=%v reads=%d calls=%v", err, reader.reads, platform.calls)
	}
}

func TestInstallerSafeErrorsRetainNestedCancellationWithoutDetail(t *testing.T) {
	err := safeInstallError(ErrSSHDReload, safeInstallError(ErrInstallFailed, context.Canceled))
	if !errors.Is(err, ErrSSHDReload) || !errors.Is(err, ErrInstallFailed) || !errors.Is(err, context.Canceled) || err.Error() != ErrSSHDReload.Error() {
		t.Fatalf("nested cancellation classification lost: %v", err)
	}
}
