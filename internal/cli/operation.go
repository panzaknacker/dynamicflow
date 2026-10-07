package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// commandOperationContext keeps signal handling alive until the application
// finishes its durable checkpoint. Cancelling the SSH process must not terminate
// the CLI before that checkpoint and its public result have been recorded.
func commandOperationContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}
