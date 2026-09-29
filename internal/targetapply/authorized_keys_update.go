package targetapply

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const authorizedKeysTemporaryName = ".authorized_keys.dynamicflow-new"

type authorizedKeyUpdateHooks struct {
	beforeRename func() error
	afterRename  func() error
}

func (r *runner) activateAuthorizedSSHKeys() error {
	account, err := user.Lookup(r.config.AdminUser)
	if err != nil {
		return ErrInvalidConfig
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid < 1000 || gid < 0 {
		return ErrInvalidConfig
	}
	home, err := openTrustedUserHome(account.HomeDir, uint32(uid))
	if err != nil {
		return err
	}
	defer home.Close()
	sshDirectory, err := openOrCreateSSHDirectory(home, uint32(uid), uint32(gid))
	if err != nil {
		return err
	}
	defer sshDirectory.Close()
	return activateAuthorizedKeySet(sshDirectory, r.config.Plan.AuthorizedSSHKeys, uint32(uid), uint32(gid), authorizedKeyUpdateHooks{})
}

func (r *runner) verifyAuthorizedSSHKeys() error {
	account, err := user.Lookup(r.config.AdminUser)
	if err != nil {
		return ErrInvalidConfig
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid < 1000 || gid < 0 {
		return ErrInvalidConfig
	}
	home, err := openTrustedUserHome(account.HomeDir, uint32(uid))
	if err != nil {
		return err
	}
	defer home.Close()
	sshDirectory, err := openExistingSSHDirectory(home, uint32(uid), uint32(gid))
	if err != nil {
		return err
	}
	defer sshDirectory.Close()
	return verifyAuthorizedKeySet(sshDirectory, r.config.Plan.AuthorizedSSHKeys, uint32(uid), uint32(gid))
}

func canonicalAuthorizedKeys(keys []string) ([]byte, error) {
	if len(keys) == 0 || len(keys) > 32 {
		return nil, ErrInvalidConfig
	}
	for index, key := range keys {
		if !validOpenSSHEd25519(key) || index > 0 && keys[index-1] >= key {
			return nil, ErrInvalidConfig
		}
	}
	payload := []byte(strings.Join(keys, "\n") + "\n")
	if int64(len(payload)) > maxAuthorizedKeys {
		return nil, ErrInvalidConfig
	}
	return payload, nil
}

func activateAuthorizedKeySet(directory *os.File, keys []string, uid, gid uint32, hooks authorizedKeyUpdateHooks) error {
	if directory == nil {
		return ErrInvalidConfig
	}
	payload, err := canonicalAuthorizedKeys(keys)
	if err != nil {
		return err
	}
	if err := verifyAuthorizedKeyFile(directory, "authorized_keys", payload, uid, gid); err == nil {
		return nil
	}
	if exists, safe := managedAuthorizedKeyFileState(directory, "authorized_keys", uid, gid, false); exists && !safe {
		return errors.New("unsafe authorized_keys destination")
	}

	prepared := verifyAuthorizedKeyFile(directory, authorizedKeysTemporaryName, payload, uid, gid) == nil
	if !prepared {
		exists, safe := managedAuthorizedKeyFileState(directory, authorizedKeysTemporaryName, uid, gid, true)
		if exists && !safe {
			return errors.New("unsafe authorized_keys temporary file")
		}
		if exists {
			if err := syscall.Unlinkat(int(directory.Fd()), authorizedKeysTemporaryName); err != nil {
				return err
			}
			if err := directory.Sync(); err != nil {
				return err
			}
		}
		fd, err := syscall.Openat(int(directory.Fd()), authorizedKeysTemporaryName,
			syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		temporary := os.NewFile(uintptr(fd), authorizedKeysTemporaryName)
		if temporary == nil {
			syscall.Close(fd)
			return errors.New("create authorized_keys temporary file")
		}
		keep := false
		defer func() {
			_ = temporary.Close()
			if !keep {
				_ = syscall.Unlinkat(int(directory.Fd()), authorizedKeysTemporaryName)
			}
		}()
		if err := temporary.Chown(int(uid), int(gid)); err != nil {
			return err
		}
		if err := temporary.Chmod(0o600); err != nil {
			return err
		}
		if _, err := temporary.Write(payload); err != nil {
			return err
		}
		if err := temporary.Sync(); err != nil {
			return err
		}
		if err := verifyOpenAuthorizedKeyFile(temporary, payload, uid, gid); err != nil {
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		keep = true
	}

	if hooks.beforeRename != nil {
		if err := hooks.beforeRename(); err != nil {
			return err
		}
	}
	if err := syscall.Renameat(int(directory.Fd()), authorizedKeysTemporaryName, int(directory.Fd()), "authorized_keys"); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if hooks.afterRename != nil {
		if err := hooks.afterRename(); err != nil {
			return err
		}
	}
	return verifyAuthorizedKeyFile(directory, "authorized_keys", payload, uid, gid)
}

func verifyAuthorizedKeySet(directory *os.File, keys []string, uid, gid uint32) error {
	if directory == nil {
		return ErrInvalidConfig
	}
	payload, err := canonicalAuthorizedKeys(keys)
	if err != nil {
		return err
	}
	return verifyAuthorizedKeyFile(directory, "authorized_keys", payload, uid, gid)
}

func verifyAuthorizedKeyFile(directory *os.File, name string, payload []byte, uid, gid uint32) error {
	file, err := openNamedAuthorizedKeyFile(directory, name)
	if err != nil {
		return errors.New("unsafe authorized_keys")
	}
	defer file.Close()
	return verifyOpenAuthorizedKeyFile(file, payload, uid, gid)
}

func verifyOpenAuthorizedKeyFile(file *os.File, payload []byte, uid, gid uint32) error {
	if file == nil || len(payload) == 0 || int64(len(payload)) > maxAuthorizedKeys {
		return errors.New("unsafe authorized_keys")
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &before); err != nil || !validAuthorizedKeyStat(before, int64(len(payload)), uid, gid) {
		return errors.New("unsafe authorized_keys")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("unsafe authorized_keys")
	}
	actual, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeys+1))
	if err != nil || string(actual) != string(payload) {
		return errors.New("authorized_keys differs from signed desired state")
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &after); err != nil || !validAuthorizedKeyStat(after, int64(len(payload)), uid, gid) ||
		after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return errors.New("unsafe authorized_keys")
	}
	return nil
}

func validAuthorizedKeyStat(details syscall.Stat_t, size int64, uid, gid uint32) bool {
	return details.Mode&syscall.S_IFMT == syscall.S_IFREG && details.Mode&0o777 == 0o600 &&
		details.Uid == uid && details.Gid == gid && details.Nlink == 1 && details.Size == size
}

func managedAuthorizedKeyFileState(directory *os.File, name string, uid, gid uint32, allowRootTemporary bool) (bool, bool) {
	file, err := openNamedAuthorizedKeyFile(directory, name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return false, false
	}
	if err != nil {
		return true, false
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != 0o600 || details.Nlink != 1 {
		return true, false
	}
	if details.Uid == uid && details.Gid == gid {
		return true, true
	}
	return true, allowRootTemporary && details.Uid == 0
}

func openNamedAuthorizedKeyFile(directory *os.File, name string) (*os.File, error) {
	if directory == nil || name == "" || name == "." || name == ".." || strings.Contains(name, "/") || strings.ContainsRune(name, '\x00') {
		return nil, ErrInvalidConfig
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, ErrInvalidConfig
	}
	return file, nil
}

func openTrustedUserHome(path string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("unsafe admin home")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		syscall.Close(fd)
		return nil, errors.New("open admin home")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			current.Close()
			return nil, errors.New("unsafe admin home")
		}
		nextFD, openErr := syscall.Openat(int(current.Fd()), part,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), part)
		if next == nil {
			syscall.Close(nextFD)
			current.Close()
			return nil, errors.New("open admin home")
		}
		current.Close()
		current = next
		var details syscall.Stat_t
		if err := syscall.Fstat(nextFD, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			current.Close()
			return nil, errors.New("unsafe admin home")
		}
		ownerOK := details.Uid == 0
		if index == len(parts)-1 {
			ownerOK = details.Uid == uid
		}
		if details.Mode&0o022 != 0 || !ownerOK {
			current.Close()
			return nil, errors.New("unsafe admin home")
		}
	}
	return current, nil
}

func openOrCreateSSHDirectory(home *os.File, uid, gid uint32) (*os.File, error) {
	if home == nil {
		return nil, errors.New("unsafe admin home")
	}
	created := false
	fd, err := syscall.Openat(int(home.Fd()), ".ssh", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		mkdirErr := syscall.Mkdirat(int(home.Fd()), ".ssh", 0o700)
		if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
			return nil, mkdirErr
		}
		created = mkdirErr == nil
		fd, err = syscall.Openat(int(home.Fd()), ".ssh", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, errors.New("unsafe .ssh directory")
	}
	directory := os.NewFile(uintptr(fd), ".ssh")
	if directory == nil {
		syscall.Close(fd)
		return nil, errors.New("open .ssh directory")
	}
	if created {
		if err := directory.Chown(int(uid), int(gid)); err != nil {
			directory.Close()
			return nil, err
		}
		if err := directory.Chmod(0o700); err != nil {
			directory.Close()
			return nil, err
		}
		if err := directory.Sync(); err != nil {
			directory.Close()
			return nil, err
		}
		if err := home.Sync(); err != nil {
			directory.Close()
			return nil, err
		}
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		details.Mode&0o777 != 0o700 || details.Uid != uid || details.Gid != gid {
		directory.Close()
		return nil, fmt.Errorf("unsafe .ssh directory")
	}
	return directory, nil
}

func openExistingSSHDirectory(home *os.File, uid, gid uint32) (*os.File, error) {
	if home == nil {
		return nil, errors.New("unsafe admin home")
	}
	fd, err := syscall.Openat(int(home.Fd()), ".ssh", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("unsafe .ssh directory")
	}
	directory := os.NewFile(uintptr(fd), ".ssh")
	if directory == nil {
		syscall.Close(fd)
		return nil, errors.New("open .ssh directory")
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		details.Mode&0o777 != 0o700 || details.Uid != uid || details.Gid != gid {
		directory.Close()
		return nil, errors.New("unsafe .ssh directory")
	}
	return directory, nil
}
