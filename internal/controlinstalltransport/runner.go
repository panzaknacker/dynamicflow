package controlinstalltransport

import (
	"context"
	"io"
	"os/exec"
)

func runSSH(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, "ssh", argv...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}
