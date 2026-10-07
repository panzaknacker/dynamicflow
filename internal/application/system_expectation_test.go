package application

import (
	"context"
	"crypto/rand"
	"reflect"
	"testing"

	"dynamicflow/internal/systemstate"
)

func TestConfirmedControlActionsRejectChangedActiveSystem(t *testing.T) {
	app, store, expectedSystemID, runner := installedControlAttestFixture(t)
	// The original one-system fixture uses deterministic identical entropy;
	// selection needs a separate genuine system identity for this regression.
	systems, err := systemstate.New(store, systemstate.WithClock(app.now), systemstate.WithRandomReader(rand.Reader))
	if err != nil {
		t.Fatal(err)
	}
	app.systems = systems
	other, err := app.InitSystem(context.Background(), InitSystemRequest{Name: "other", ControlName: "control-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.SelectSystem(context.Background(), SelectSystemRequest{Selector: "id:" + other.System.ID}, nil); err != nil {
		t.Fatal(err)
	}
	meta := RequestMeta{Surface: SurfaceTUI, ExpectedSystemID: expectedSystemID}
	bind := testControlBindRequest(t)
	bind.Meta = meta
	ctx := context.Background()
	before := identityFileSnapshot(t, store.Root())
	for name, action := range map[string]func() error{
		"bind plan": func() error { _, err := app.PlanControlBind(ctx, bind); return err },
		"bind":      func() error { _, err := app.BindControl(ctx, bind, nil); return err },
		"check plan": func() error {
			_, err := app.PlanControlCheck(ctx, CheckControlRequest{Meta: meta, Name: "control-1"})
			return err
		},
		"check": func() error {
			_, err := app.CheckControl(ctx, CheckControlRequest{Meta: meta, Name: "control-1"}, nil)
			return err
		},
		"prepare plan": func() error {
			_, err := app.PlanControlInstall(ctx, PrepareControlInstallRequest{Meta: meta, Name: "control-1"})
			return err
		},
		"prepare": func() error {
			_, err := app.PrepareControlInstall(ctx, PrepareControlInstallRequest{Meta: meta, Name: "control-1"}, nil)
			return err
		},
		"apply plan": func() error {
			_, err := app.PlanPreparedControlInstall(ctx, InstallPreparedControlRequest{Meta: meta, Name: "control-1"})
			return err
		},
		"apply": func() error {
			_, err := app.InstallPreparedControl(ctx, InstallPreparedControlRequest{Meta: meta, Name: "control-1"}, nil)
			return err
		},
		"attest plan": func() error {
			_, err := app.PlanControlAttest(ctx, AttestControlRequest{Meta: meta, Name: "control-1"})
			return err
		},
		"attest": func() error {
			_, err := app.AttestControl(ctx, AttestControlRequest{Meta: meta, Name: "control-1"}, nil)
			return err
		},
	} {
		if failure := AsError(action()); failure.Code != "system_conflict" || failure.ExitCode != 6 {
			t.Errorf("%s ran against a different active system: %+v", name, failure)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("stale confirmations opened %d connections", runner.calls)
	}
	if after := identityFileSnapshot(t, store.Root()); !reflect.DeepEqual(before, after) {
		t.Fatal("stale confirmations changed local state")
	}
}
