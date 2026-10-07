package cli

import (
	"errors"
	"io"
	"os"
)

const maxHostPublicKeyFileBytes = int64(4 << 10)

var (
	errPublicKeyFileUnsafe  = errors.New("public key file is unsafe")
	errPublicKeyFileChanged = errors.New("public key file changed while opening")
	errPublicKeyFileRead    = errors.New("public key file could not be read")
)

// readBoundedPublicKeyFile reads a small public key without accepting a
// symlink or a path that changed identity between inspection and opening. It
// returns bytes only after the opened descriptor has been matched back to the
// original regular file.
func readBoundedPublicKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maxHostPublicKeyFileBytes {
		return nil, errPublicKeyFileUnsafe
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errPublicKeyFileRead
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() ||
		openedInfo.Size() < 1 || openedInfo.Size() > maxHostPublicKeyFileBytes {
		return nil, errPublicKeyFileChanged
	}
	publicKey, err := io.ReadAll(io.LimitReader(file, maxHostPublicKeyFileBytes+1))
	if err != nil || len(publicKey) == 0 || int64(len(publicKey)) > maxHostPublicKeyFileBytes {
		return nil, errPublicKeyFileRead
	}
	return publicKey, nil
}
