package controlinstalltransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/sshtransport"
)

type cancelInstallRunner struct {
	cancel context.CancelFunc
	calls  int
}

func (runner *cancelInstallRunner) Run(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	runner.calls++
	runner.cancel()
	return nil
}

func TestInstallCancellationBeforeAndDuringProcess(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before", false: "during"}[before], func(t *testing.T) {
			fixture := newInstallFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if before {
				cancel()
			}
			runner := &cancelInstallRunner{cancel: cancel}
			transport := New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now }))
			result, err := transport.InstallFirstControl(ctx, fixture.request)
			wantAttempts := 1
			if before {
				wantAttempts = 0
			}
			if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrControlInstall) || result.Attempts != wantAttempts || runner.calls != wantAttempts {
				t.Fatalf("cancelled install: result=%+v calls=%d err=%v", result, runner.calls, err)
			}
		})
	}
}

func TestInstallDoesNotExposeUnvalidatedAlias(t *testing.T) {
	fixture := newInstallFixture(t)
	fixture.request.Control.Alias = "private-invalid-alias\n"
	runner := &installRunner{}
	result, err := New(sshtransport.NewBuilder(fixture.store), runner, WithClock(func() time.Time { return fixture.now })).InstallFirstControl(context.Background(), fixture.request)
	encoded, marshalErr := json.Marshal(result)
	if err == nil || marshalErr != nil || strings.Contains(string(encoded), "private-invalid-alias") || result.Attempts != 0 {
		t.Fatalf("invalid alias leaked: result=%s err=%v", encoded, err)
	}
}
