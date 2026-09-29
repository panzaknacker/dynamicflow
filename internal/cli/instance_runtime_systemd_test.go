package cli

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"dynamicflow/internal/instanceclient"
	"dynamicflow/internal/instanceunit"
)

func TestInstanceRuntimeEnrollInstallsTimerBeforeCredentialOrNetwork(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	installed := false
	installCalls := 0
	client := newFakeRuntimeClient(fixture)
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) {
		// the secret is deliberately lazy: client trust is constructed after
		// the three public/binding fields and before the fourth field is read.
		if !installed || input.index != 3 {
			t.Fatalf("network client created before timer/input ordering: installed=%v input=%d", installed, input.index)
		}
		return client, nil
	})
	baseOpen := deps.openInput
	deps.openInput = func(reader io.Reader) (instanceRuntimeInput, error) {
		if !installed || input.index != 0 {
			t.Fatalf("credential input opened before timer: installed=%v input=%d", installed, input.index)
		}
		return baseOpen(reader)
	}
	deps.installTimer = func(stateRoot string) (bool, error) {
		installCalls++
		if stateRoot != fixture.stateRoot || input.index != 0 {
			t.Fatalf("timer not bound before input: root=%q input=%d", stateRoot, input.index)
		}
		installed = true
		return true, nil
	}

	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" || installCalls != 1 {
		t.Fatalf("enroll status=%d installs=%d stdout=%q stderr=%q", status, installCalls, stdout, stderr)
	}
}

func TestInstanceRuntimeTimerFailureConsumesNoCredentialOrState(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	input := &fakeRuntimeInput{fields: [][]byte{
		[]byte(fixture.instance), []byte(fixture.profile), []byte(fixture.id), []byte(fixture.secret),
	}}
	clientCreated := false
	deps := fixture.dependencies(input, func(instanceclient.Config) (instanceRuntimeClient, error) {
		clientCreated = true
		return nil, errors.New("must not create client")
	})
	deps.installTimer = func(stateRoot string) (bool, error) {
		if stateRoot != fixture.stateRoot {
			t.Fatalf("wrong state root: %q", stateRoot)
		}
		return false, errors.New("systemd deliberately unavailable")
	}

	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitConfig || stdout != "" || clientCreated || len(input.calls) != 0 {
		t.Fatalf("failure status=%d client=%v input=%v stdout=%q stderr=%q", status, clientCreated, input.calls, stdout, stderr)
	}
	if _, err := os.Lstat(fixture.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime state was created before timer preflight: %v", err)
	}
	if !strings.Contains(stderr, "reconcile_service") {
		t.Fatalf("timer failure was not categorized: %q", stderr)
	}
	assertRuntimeOutputDoesNotContain(t, stdout+stderr, fixture.id, fixture.secret)
}

func TestExistingEnrollmentRepairsTimerBeforeDesiredFetch(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	persistRuntimeFixtureConfig(t, fixture)
	installed := false
	client := newFakeRuntimeClient(fixture)
	deps := fixture.dependencies(nil, func(instanceclient.Config) (instanceRuntimeClient, error) {
		if !installed {
			t.Fatal("client created before existing enrollment repaired the timer")
		}
		return client, nil
	})
	deps.installTimer = func(stateRoot string) (bool, error) {
		if stateRoot != fixture.stateRoot {
			t.Fatalf("wrong state root: %q", stateRoot)
		}
		installed = true
		return false, nil
	}

	status, stdout, stderr := invokeInstanceRuntime(t, fixture.enrollArguments(), deps)
	if status != exitOK || stderr != "" || !installed || client.fetchCalls != 1 || client.enrollCalls != 0 {
		t.Fatalf("recovery status=%d installed=%v fetch=%d enroll=%d stdout=%q stderr=%q", status, installed, client.fetchCalls, client.enrollCalls, stdout, stderr)
	}
}

func TestInstanceRuntimeProductionTimerNamesAreNotOperatorControlled(t *testing.T) {
	if instanceunit.ServiceName != "dynamicflow-instance-reconcile.service" ||
		instanceunit.TimerName != "dynamicflow-instance-reconcile.timer" ||
		instanceunit.DefaultStateRoot != defaultInstanceRuntimeRoot {
		t.Fatalf("runtime/systemd constants diverged: service=%q timer=%q roots=%q/%q",
			instanceunit.ServiceName, instanceunit.TimerName, instanceunit.DefaultStateRoot, defaultInstanceRuntimeRoot)
	}
}
