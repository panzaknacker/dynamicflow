package instanceclient

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
)

const (
	identityPrivatePath = "identity/instance.private.pem"
	identityPublicPath  = "identity/instance.public.pem"
	identityLockPath    = "identity/.lock"
)

var ErrIdentityConflict = errors.New("instance identity is incomplete or inconsistent")

type identity struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	publicPEM  []byte
	keyID      string
}

func ensureIdentity(store *localstate.Store, allowGenerate bool) (identity, error) {
	var result identity
	err := store.WithLock(identityLockPath, func() error {
		privatePath, err := store.Path(identityPrivatePath)
		if err != nil {
			return err
		}
		publicPath, err := store.Path(identityPublicPath)
		if err != nil {
			return err
		}
		privateExists, err := regularPathExists(privatePath)
		if err != nil {
			return err
		}
		publicExists, err := regularPathExists(publicPath)
		if err != nil {
			return err
		}
		if !privateExists && publicExists {
			return ErrIdentityConflict
		}
		if !privateExists {
			if !allowGenerate {
				return ErrIdentityConflict
			}
			if _, err := signing.GenerateFiles(privatePath, publicPath); err != nil {
				return fmt.Errorf("generate instance identity: %w", err)
			}
		} else if !publicExists {
			// GenerateFiles writes the private key first. if the process died in
			// that narrow window, recover the public half from the same private
			// identity instead of replacing the persona.
			if err := recoverPublicIdentity(privatePath, publicPath); err != nil {
				return err
			}
		}
		if err := hardenPublicIdentity(publicPath); err != nil {
			return err
		}
		privateKey, err := signing.LoadPrivateFile(privatePath)
		if err != nil {
			return fmt.Errorf("load instance private identity: %w", err)
		}
		defer clearBytes(privateKey)
		publicKey, err := signing.LoadPublicFile(publicPath)
		if err != nil {
			return fmt.Errorf("load instance public identity: %w", err)
		}
		derived := privateKey.Public().(ed25519.PublicKey)
		if !derived.Equal(publicKey) {
			return ErrIdentityConflict
		}
		publicPEM, err := signing.MarshalPublicPEM(publicKey)
		if err != nil {
			return err
		}
		keyID, err := signing.KeyID(publicKey)
		if err != nil {
			return err
		}
		result = identity{
			privateKey: append(ed25519.PrivateKey(nil), privateKey...),
			publicKey:  append(ed25519.PublicKey(nil), publicKey...),
			publicPEM:  append([]byte(nil), publicPEM...),
			keyID:      keyID,
		}
		return nil
	})
	return result, err
}

func recoverPublicIdentity(privatePath, publicPath string) error {
	privateKey, err := signing.LoadPrivateFile(privatePath)
	if err != nil {
		return fmt.Errorf("recover instance public identity: %w", err)
	}
	defer clearBytes(privateKey)
	publicPEM, err := signing.MarshalPublicPEM(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	defer clearBytes(publicPEM)
	file, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, localstate.FileMode)
	if err != nil {
		return fmt.Errorf("recover instance public identity: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(publicPath)
		}
	}()
	if err := file.Chmod(localstate.FileMode); err != nil {
		return err
	}
	if _, err := file.Write(publicPEM); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(filepath.Dir(publicPath))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}

func regularPathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, ErrIdentityConflict
	}
	return true, nil
}

func hardenPublicIdentity(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open instance public identity: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return ErrIdentityConflict
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || int(stat.Uid) != os.Geteuid() {
		return ErrIdentityConflict
	}
	if err := syscall.Fchmod(fd, uint32(localstate.FileMode.Perm())); err != nil {
		return fmt.Errorf("secure instance public identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync instance public identity: %w", err)
	}
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != localstate.FileMode {
		return ErrIdentityConflict
	}
	return nil
}
