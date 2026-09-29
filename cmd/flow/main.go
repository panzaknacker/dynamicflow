package main

import (
	"os"

	"dynamicflow/internal/cli"
)

func main() {
	os.Exit(cli.RunWithIO(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
