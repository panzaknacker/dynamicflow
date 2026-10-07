package tui

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
	"dynamicflow/internal/localstate"
)

func tuiOperationError(t *testing.T, message tea.Msg) error {
	t.Helper()
	switch typed := message.(type) {
	case controlBindPlanMsg:
		return typed.err
	case controlBindMsg:
		return typed.err
	case controlCheckPlanMsg:
		return typed.err
	case controlCheckMsg:
		return typed.err
	case controlInstallPlanMsg:
		return typed.err
	case controlInstallMsg:
		return typed.err
	case controlApplyPlanMsg:
		return typed.err
	case controlApplyMsg:
		return typed.err
	case controlAttestPlanMsg:
		return typed.err
	case controlAttestMsg:
		return typed.err
	default:
		t.Fatalf("unexpected Control operation message %T", message)
		return nil
	}
}

func systemFileDigests(t *testing.T, root string) map[string][sha256.Size]byte {
	t.Helper()
	files := map[string][sha256.Size]byte{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestControlPlansAndConfirmationsCannotFollowAnotherActiveSystem(t *testing.T) {
	ctx := context.Background()
	store, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tuiRemoteRunner{binary: []byte("system-bound-tui-runtime"), now: time.Now().UTC().Truncate(time.Second)}
	executable := filepath.Join(t.TempDir(), "flow")
	if err := os.WriteFile(executable, runner.binary, 0o700); err != nil {
		t.Fatal(err)
	}
	app, err := application.Open(application.Config{Store: store, ControlRunner: runner, ExecutablePath: executable, Clock: func() time.Time { return runner.now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.InitSystem(ctx, application.InitSystemRequest{Name: "system-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := map[string]application.DashboardSnapshot{}
	saveSnapshot := func(stage string) {
		t.Helper()
		snapshot, err := app.Dashboard(ctx)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[stage] = snapshot
	}
	request := tuiBindRequest()
	saveSnapshot("bind")
	bindPlan, err := app.PlanControlBind(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(ctx, request, nil); err != nil {
		t.Fatal(err)
	}
	saveSnapshot("check")
	checkPlan, err := app.PlanControlCheck(ctx, application.CheckControlRequest{Name: request.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.CheckControl(ctx, application.CheckControlRequest{Name: request.Name}, nil); err != nil {
		t.Fatal(err)
	}
	saveSnapshot("prepare")
	installPlan, err := app.PlanControlInstall(ctx, application.PrepareControlInstallRequest{Name: request.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareControlInstall(ctx, application.PrepareControlInstallRequest{Name: request.Name}, nil); err != nil {
		t.Fatal(err)
	}
	saveSnapshot("apply")
	applyPlan, err := app.PlanPreparedControlInstall(ctx, application.InstallPreparedControlRequest{Name: request.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.InstallPreparedControl(ctx, application.InstallPreparedControlRequest{Name: request.Name}, nil); err != nil {
		t.Fatal(err)
	}
	saveSnapshot("attest")
	attestPlan, err := app.PlanControlAttest(ctx, application.AttestControlRequest{Name: request.Name})
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.InitSystem(ctx, application.InitSystemRequest{Name: "system-b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.SelectSystem(ctx, application.SelectSystemRequest{Selector: "id:" + second.System.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BindControl(ctx, request, nil); err != nil {
		t.Fatal(err)
	}
	current, err := app.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeCalls := runner.calls
	secondRoot := filepath.Join(store.Root(), "systems", second.System.ID)
	beforeFiles := systemFileDigests(t, secondRoot)

	for _, stage := range []struct {
		name   string
		key    string
		screen screen
	}{
		{"bind", "b", screenControlBindConfirm},
		{"check", "c", screenControlCheckConfirm},
		{"prepare", "i", screenControlInstallConfirm},
		{"apply", "p", screenControlApplyConfirm},
		{"attest", "a", screenControlAttestConfirm},
	} {
		t.Run(stage.name, func(t *testing.T) {
			// An old dashboard must not silently plan for the newly active B.
			ui := newModel(ctx, app, snapshots[stage.name], []string{"NO_COLOR=1"})
			ui, command := updateTUI(t, ui, tuiText(stage.key))
			if stage.name == "bind" {
				ui.bindForm.Host, ui.bindForm.Port, ui.bindForm.SSHUser = request.Host, "22", request.SSHUser
				ui.bindForm.HostPublicKey, ui.bindForm.Field = request.HostPublicKey, bindHostPublicKey
				ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
			}
			if command == nil {
				t.Fatal("stale dashboard did not reach the guarded Application planner")
			}
			planResult := command()
			if err := tuiOperationError(t, planResult); err == nil || application.AsError(err).Code != "system_conflict" {
				t.Fatalf("stale dashboard planned against another system: %v", err)
			}
			ui, _ = updateTUI(t, ui, planResult)

			// A refreshed snapshot cannot retarget an already confirmed A plan.
			ui = newModel(ctx, app, current, []string{"NO_COLOR=1"})
			ui.screen = stage.screen
			ui.bindPlan, ui.checkPlan, ui.installPlan, ui.applyPlan, ui.attestPlan = &bindPlan, &checkPlan, &installPlan, &applyPlan, &attestPlan
			ui.bindRequest = request
			ui.bindRequest.Meta = controlRequestMeta(second.System.ID)
			if !strings.Contains(ui.View().Content, first.System.ID) {
				t.Fatal("confirmation did not display the immutable system from its plan")
			}
			ui, command = updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
			if command == nil {
				t.Fatal("confirmation did not reach the guarded Application operation")
			}
			result := command()
			if err := tuiOperationError(t, result); err == nil || application.AsError(err).Code != "system_conflict" {
				t.Fatalf("confirmed A plan was redirected to B: %v", err)
			}
			ui, _ = updateTUI(t, ui, result)
			if ui.busy || ui.error == "" || ui.screen != stage.screen {
				t.Fatal("system conflict lost its confirmation or recovery state")
			}
		})
	}
	if runner.calls != beforeCalls {
		t.Fatal("stale plans opened a connection to another system")
	}
	if !reflect.DeepEqual(beforeFiles, systemFileDigests(t, secondRoot)) {
		t.Fatal("stale plans created or changed state or key material in the other system")
	}
	ui := newModel(ctx, app, current, []string{"NO_COLOR=1"})
	ui, command := updateTUI(t, ui, tuiText("c"))
	ui, _ = updateTUI(t, ui, command())
	if ui.checkPlan == nil || ui.checkPlan.SystemID != second.System.ID || ui.checkPlan.SystemID == first.System.ID || ui.error != "" {
		t.Fatal("an explicitly refreshed B dashboard could not produce its own plan")
	}
}

func TestControlConfirmationRequiresASystemBoundPlan(t *testing.T) {
	for _, screen := range []screen{screenControlBindConfirm, screenControlCheckConfirm, screenControlInstallConfirm, screenControlApplyConfirm, screenControlAttestConfirm} {
		ui := newModel(context.Background(), nil, application.DashboardSnapshot{}, []string{"NO_COLOR=1"})
		ui.screen = screen
		ui.bindPlan = &application.BindControlPlan{ControlName: "control-1"}
		ui.checkPlan = &application.CheckControlPlan{ControlName: "control-1"}
		ui.installPlan = &application.PrepareControlInstallPlan{ControlName: "control-1"}
		ui.applyPlan = &application.InstallPreparedControlPlan{ControlName: "control-1"}
		ui.attestPlan = &application.AttestControlPlan{ControlName: "control-1"}
		ui, command := updateTUI(t, ui, tuiSpecial(tea.KeyEnter))
		if command != nil || ui.busy {
			t.Fatalf("confirmation %v submitted a plan without a system identity", screen)
		}
	}
}
