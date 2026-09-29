//go:build !linux

package cli

import (
	"os"
)

func runtimeFDIsTerminal(_ *os.File) bool { return false }

func runtimeReadHiddenLine(_ *os.File, _ int) ([]byte, error) {
	return nil, errRuntimeConfiguration
}

func readRootOwnedRuntimePublicFile(_ string, _ int64) ([]byte, error) {
	return nil, errRuntimeConfiguration
}
