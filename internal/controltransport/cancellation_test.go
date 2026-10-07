package controltransport

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCheckCancelledBeforeStartMakesNoAttempt(t *testing.T) {
	fixture := newFixture(t)
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			cancel()
		}
		runner := &recordingRunner{}
		result, err := New(fixture.builder, runner).CheckFirstControl(ctx, fixture.endpoint)
		cancel()
		calls, _, _, _ := runner.snapshot()
		if !errors.Is(err, want) || !errors.Is(err, ErrFirstControlCheck) || calls != 0 || result.Attempts != 0 {
			t.Fatalf("cancelled request: result=%+v calls=%d err=%v", result, calls, err)
		}
	}
}

func TestCheckCancellationWinsOverSuccessfulRunnerExit(t *testing.T) {
	fixture := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &recordingRunner{run: func(context.Context, io.Writer, io.Writer) error {
		cancel()
		return nil
	}}
	result, err := New(fixture.builder, runner).CheckFirstControl(ctx, fixture.endpoint)
	if !errors.Is(err, context.Canceled) || result.Attempts != 1 {
		t.Fatalf("cancelled process was accepted: result=%+v err=%v", result, err)
	}
}
