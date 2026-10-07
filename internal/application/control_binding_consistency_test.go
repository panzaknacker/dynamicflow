package application

import (
	"context"
	"testing"

	"dynamicflow/internal/systemstate"
)

func TestControlOperationsRejectContradictoryRegistryBindingBeforeNetwork(t *testing.T) {
	for _, field := range []string{"control name", "host pin"} {
		t.Run(field, func(t *testing.T) {
			app, _, systemID, runner := installedControlAttestFixture(t)
			system, err := app.systems.Get(systemID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = app.systems.Update(system.ID, system.Revision, func(candidate *systemstate.System) error {
				if field == "control name" {
					candidate.Bootstrap.ControlNodeID = "other-control"
				} else {
					candidate.Bootstrap.HostKeyFingerprint = candidate.Bootstrap.BootstrapKeyFingerprint
				}
				return nil
			})
			if err != nil {
				t.Fatalf("create schema-valid contradictory registry: %v", err)
			}
			ctx := context.Background()
			for name, operation := range map[string]func() error{
				"check plan": func() error { _, err := app.PlanControlCheck(ctx, CheckControlRequest{Name: "control-1"}); return err },
				"check":      func() error { _, err := app.CheckControl(ctx, CheckControlRequest{Name: "control-1"}, nil); return err },
				"apply plan": func() error {
					_, err := app.PlanPreparedControlInstall(ctx, InstallPreparedControlRequest{Name: "control-1"})
					return err
				},
				"apply": func() error {
					_, err := app.InstallPreparedControl(ctx, InstallPreparedControlRequest{Name: "control-1"}, nil)
					return err
				},
				"attest plan": func() error {
					_, err := app.PlanControlAttest(ctx, AttestControlRequest{Name: "control-1"})
					return err
				},
				"attest": func() error {
					_, err := app.AttestControl(ctx, AttestControlRequest{Name: "control-1"}, nil)
					return err
				},
			} {
				if failure := AsError(operation()); failure.Code != "control_binding" || failure.ExitCode != 5 {
					t.Errorf("%s accepted contradictory binding: %+v", name, failure)
				}
			}
			if runner.calls != 0 {
				t.Fatalf("contradictory registry opened %d connections", runner.calls)
			}
		})
	}
}
