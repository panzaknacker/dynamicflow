//go:build linux

// package vncsecret implements the fixed, root-only VNC credential one-shot.
// it deliberately has no general command execution or caller-supplied paths.
package vncsecret

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	managedUser       = "malwarelab"
	managedHome       = "/home/malwarelab"
	managedSecretDir  = "/root"
	managedSecretName = ".vm-bootstrap-vnc-malwarelab"
	managedUnit       = "tigervncserver@:1.service"
	passwordBytes     = 8
	maxSecretBytes    = 16
	maxCommandOutput  = 4096
)

var (
	ErrUnsafeState = errors.New("unsafe VNC credential state")
	ErrService     = errors.New("VNC service validation failed")
	ErrUnsupported = errors.New("VNC credential operation is unsupported")
)

type config struct {
	secretDir string
	homeDir   string
	rootUID   int
	rootGID   int
	uid       int
	gid       int
	random    io.Reader
	filter    func([]byte) ([]byte, error)
	service   func(string) error
	validate  func(string, string, []byte) error
	hook      func(string) error
}

type directory struct {
	fd   int
	path string
	stat syscall.Stat_t
}

type managedFile struct {
	dir  *directory
	name string
	uid  int
	gid  int
	data []byte
}

// Reveal returns the root-owned source credential after validating every path
// component and file invariant. the caller must deliberately expose it.
func Reveal() ([]byte, error) {
	cfg, err := productionConfig()
	if err != nil {
		return nil, err
	}
	return reveal(cfg)
}

// Rotate replaces the root source and both TigerVNC password files, validates
// the fixed service, and restores verified old bytes on any post-stop failure.
func Rotate() ([]byte, error) {
	cfg, err := productionConfig()
	if err != nil {
		return nil, err
	}
	return rotate(cfg)
}

func productionConfig() (config, error) {
	account, err := user.Lookup(managedUser)
	if err != nil || account.HomeDir != managedHome {
		return config{}, ErrUnsafeState
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return config{}, ErrUnsafeState
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return config{}, ErrUnsafeState
	}
	return config{
		secretDir: managedSecretDir,
		homeDir:   managedHome,
		rootUID:   0,
		rootGID:   0,
		uid:       uid,
		gid:       gid,
		random:    rand.Reader,
		filter:    runPasswordFilter,
		service:   runServiceAction,
		validate:  validateRuntime,
	}, nil
}

func reveal(cfg config) ([]byte, error) {
	root, err := openAbsoluteDirectory(cfg.secretDir, cfg.rootUID, cfg.rootGID, 0o700, true)
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer root.close()
	unlock, err := lock(root, cfg.rootUID, cfg.rootGID)
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer unlock()
	value, err := readFileAt(root.fd, managedSecretName, cfg.rootUID, cfg.rootGID, 0o600, maxSecretBytes)
	if err != nil || !validSource(value) {
		clear(value)
		return nil, ErrUnsafeState
	}
	password := append([]byte(nil), value[:passwordBytes]...)
	clear(value)
	home, legacyDir, modernDir, err := openRuntimeDirectories(cfg)
	if err != nil {
		clear(password)
		return nil, ErrUnsafeState
	}
	defer home.close()
	defer legacyDir.close()
	defer modernDir.close()
	if err := verifyDirectories(cfg, home, legacyDir, modernDir); err != nil {
		clear(password)
		return nil, ErrUnsafeState
	}
	encoded, err := cfg.filter(password)
	if err != nil || len(encoded) != passwordBytes {
		clear(encoded)
		clear(password)
		return nil, ErrUnsafeState
	}
	defer clear(encoded)
	legacy, legacyErr := readFileAt(legacyDir.fd, "passwd", cfg.uid, cfg.gid, 0o600, passwordBytes)
	modern, modernErr := readFileAt(modernDir.fd, "passwd", cfg.uid, cfg.gid, 0o600, passwordBytes)
	defer clear(legacy)
	defer clear(modern)
	if legacyErr != nil || modernErr != nil || !bytes.Equal(legacy, encoded) || !bytes.Equal(modern, encoded) {
		clear(password)
		return nil, ErrUnsafeState
	}
	return password, nil
}

func rotate(cfg config) (password []byte, resultErr error) {
	root, err := openAbsoluteDirectory(cfg.secretDir, cfg.rootUID, cfg.rootGID, 0o700, true)
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer root.close()
	unlock, err := lock(root, cfg.rootUID, cfg.rootGID)
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer unlock()
	home, legacyDir, modernDir, err := openRuntimeDirectories(cfg)
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer home.close()
	defer legacyDir.close()
	defer modernDir.close()

	oldSource, err := readFileAt(root.fd, managedSecretName, cfg.rootUID, cfg.rootGID, 0o600, maxSecretBytes)
	if err != nil || !validSource(oldSource) {
		clear(oldSource)
		return nil, ErrUnsafeState
	}
	defer clear(oldSource)
	oldLegacy, err := readFileAt(legacyDir.fd, "passwd", cfg.uid, cfg.gid, 0o600, passwordBytes)
	if err != nil || len(oldLegacy) != passwordBytes {
		clear(oldLegacy)
		return nil, ErrUnsafeState
	}
	defer clear(oldLegacy)
	oldModern, err := readFileAt(modernDir.fd, "passwd", cfg.uid, cfg.gid, 0o600, passwordBytes)
	if err != nil || !bytes.Equal(oldLegacy, oldModern) {
		clear(oldModern)
		return nil, ErrUnsafeState
	}
	defer clear(oldModern)
	if err := verifyDirectories(cfg, home, legacyDir, modernDir); err != nil {
		return nil, ErrUnsafeState
	}

	password, err = randomPassword(cfg.random, oldSource[:passwordBytes])
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer func() {
		if resultErr != nil {
			clear(password)
			password = nil
		}
	}()
	encoded, err := cfg.filter(password)
	if err != nil || len(encoded) != passwordBytes {
		clear(encoded)
		return nil, ErrUnsafeState
	}
	defer clear(encoded)

	files := []managedFile{
		{dir: root, name: managedSecretName, uid: cfg.rootUID, gid: cfg.rootGID, data: append(append([]byte(nil), password...), '\n')},
		{dir: legacyDir, name: "passwd", uid: cfg.uid, gid: cfg.gid, data: encoded},
		{dir: modernDir, name: "passwd", uid: cfg.uid, gid: cfg.gid, data: encoded},
	}
	for index := range files {
		defer clear(files[index].data)
	}
	oldFiles := []managedFile{
		{dir: root, name: managedSecretName, uid: cfg.rootUID, gid: cfg.rootGID, data: oldSource},
		{dir: legacyDir, name: "passwd", uid: cfg.uid, gid: cfg.gid, data: oldLegacy},
		{dir: modernDir, name: "passwd", uid: cfg.uid, gid: cfg.gid, data: oldModern},
	}

	if err := cfg.service("stop"); err != nil {
		return nil, ErrService
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = cfg.service("stop")
		rollbackOK := replaceAll(oldFiles, nil) == nil && verifyDirectories(cfg, home, legacyDir, modernDir) == nil
		if rollbackOK {
			rollbackOK = cfg.service("restart") == nil && cfg.service("active") == nil && cfg.validate(legacyDir.path, modernDir.path, oldLegacy) == nil
		}
		if !rollbackOK {
			_ = cfg.service("stop")
		}
	}()
	if err := callHook(cfg, "before_commit"); err != nil {
		return nil, ErrUnsafeState
	}
	if err := replaceAll(files, func(index int) error { return callHook(cfg, fmt.Sprintf("after_replace_%d", index)) }); err != nil {
		return nil, ErrUnsafeState
	}
	if err := callHook(cfg, "after_commit"); err != nil {
		return nil, ErrUnsafeState
	}
	if err := verifyDirectories(cfg, home, legacyDir, modernDir); err != nil {
		return nil, ErrUnsafeState
	}
	if err := verifyFiles(files); err != nil {
		return nil, ErrUnsafeState
	}
	if err := cfg.service("restart"); err != nil {
		return nil, ErrService
	}
	if err := cfg.service("active"); err != nil {
		return nil, ErrService
	}
	if err := cfg.validate(legacyDir.path, modernDir.path, encoded); err != nil {
		return nil, ErrService
	}
	if err := verifyDirectories(cfg, home, legacyDir, modernDir); err != nil {
		return nil, ErrUnsafeState
	}
	if err := verifyFiles(files); err != nil {
		return nil, ErrUnsafeState
	}
	committed = true
	return password, nil
}

func openRuntimeDirectories(cfg config) (*directory, *directory, *directory, error) {
	home, err := openAbsoluteDirectory(cfg.homeDir, cfg.uid, cfg.gid, 0, false)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*directory, *directory, *directory, error) {
		home.close()
		return nil, nil, nil, err
	}
	legacy, err := openChildDirectory(home, ".vnc", cfg.uid, cfg.gid, 0o700, true)
	if err != nil {
		return fail(err)
	}
	configDir, err := openChildDirectory(home, ".config", cfg.uid, cfg.gid, 0, false)
	if err != nil {
		legacy.close()
		return fail(err)
	}
	modern, err := openChildDirectory(configDir, "tigervnc", cfg.uid, cfg.gid, 0o700, true)
	configDir.close()
	if err != nil {
		legacy.close()
		return fail(err)
	}
	return home, legacy, modern, nil
}

func openAbsoluteDirectory(path string, finalUID, finalGID int, finalMode uint32, exact bool) (*directory, error) {
	clean := filepath.Clean(path)
	if clean == "/" || !filepath.IsAbs(clean) || clean != path {
		return nil, ErrUnsafeState
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := &directory{fd: fd, path: "/"}
	components := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for index, component := range components {
		final := index == len(components)-1
		var next *directory
		var openErr error
		if final {
			next, openErr = openChildDirectory(current, component, finalUID, finalGID, finalMode, exact)
		} else {
			next, openErr = openIntermediateDirectory(current, component, finalUID, finalGID)
		}
		current.close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	return current, nil
}

func openIntermediateDirectory(parent *directory, name string, finalUID, finalGID int) (*directory, error) {
	if !validName(name) {
		return nil, ErrUnsafeState
	}
	fd, err := syscall.Openat(parent.fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	ownerOK := stat.Uid == 0 && stat.Gid == 0 || int(stat.Uid) == finalUID && int(stat.Gid) == finalGID
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || !ownerOK || stat.Mode&0o022 != 0 {
		syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	return &directory{fd: fd, path: filepath.Join(parent.path, name), stat: stat}, nil
}

func openChildDirectory(parent *directory, name string, uid, gid int, mode uint32, exact bool) (*directory, error) {
	if !validName(name) {
		return nil, ErrUnsafeState
	}
	fd, err := syscall.Openat(parent.fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(stat.Uid) != uid || int(stat.Gid) != gid || stat.Mode&0o022 != 0 || exact && stat.Mode&0o777 != mode {
		syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	return &directory{fd: fd, path: filepath.Join(parent.path, name), stat: stat}, nil
}

func (directory *directory) close() {
	if directory != nil && directory.fd >= 0 {
		_ = syscall.Close(directory.fd)
		directory.fd = -1
	}
}

func verifyDirectories(cfg config, expected ...*directory) error {
	paths := []struct {
		path  string
		uid   int
		gid   int
		mode  uint32
		exact bool
	}{
		{cfg.homeDir, cfg.uid, cfg.gid, 0, false},
		{filepath.Join(cfg.homeDir, ".vnc"), cfg.uid, cfg.gid, 0o700, true},
		{filepath.Join(cfg.homeDir, ".config", "tigervnc"), cfg.uid, cfg.gid, 0o700, true},
	}
	if len(expected) != len(paths) {
		return ErrUnsafeState
	}
	for index, item := range paths {
		actual, err := openAbsoluteDirectory(item.path, item.uid, item.gid, item.mode, item.exact)
		if err != nil {
			return err
		}
		same := actual.stat.Dev == expected[index].stat.Dev && actual.stat.Ino == expected[index].stat.Ino
		actual.close()
		if !same {
			return ErrUnsafeState
		}
	}
	return nil
}

func readFileAt(dirfd int, name string, uid, gid int, mode uint32, maximum int) ([]byte, error) {
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || int(stat.Uid) != uid || int(stat.Gid) != gid || stat.Mode&0o777 != mode || stat.Size < 0 || stat.Size > int64(maximum) {
		return nil, ErrUnsafeState
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(data) > maximum || int64(len(data)) != stat.Size {
		clear(data)
		return nil, ErrUnsafeState
	}
	return data, nil
}

func replaceAll(files []managedFile, after func(int) error) error {
	for index := range files {
		if err := replaceFile(files[index]); err != nil {
			return err
		}
		if after != nil {
			if err := after(index); err != nil {
				return err
			}
		}
	}
	return nil
}

func replaceFile(file managedFile) error {
	if !validName(file.name) || len(file.data) == 0 || len(file.data) > maxSecretBytes {
		return ErrUnsafeState
	}
	temporary, fd, err := createTemporary(file.dir, file.uid, file.gid)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = syscall.Close(fd)
		if !committed {
			_ = syscall.Unlinkat(file.dir.fd, temporary)
		}
	}()
	writer := os.NewFile(uintptr(fd), temporary)
	if err := writeFull(writer, file.data); err != nil {
		return err
	}
	if err := syscall.Fsync(fd); err != nil {
		return err
	}
	if err := syscall.Renameat(file.dir.fd, temporary, file.dir.fd, file.name); err != nil {
		return err
	}
	committed = true
	return syscall.Fsync(file.dir.fd)
}

func createTemporary(dir *directory, uid, gid int) (string, int, error) {
	for attempt := 0; attempt < 32; attempt++ {
		randomName := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, randomName); err != nil {
			return "", -1, err
		}
		name := fmt.Sprintf(".flow-vnc-%x.tmp", randomName)
		fd, err := syscall.Openat(dir.fd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, syscall.EEXIST) {
			continue
		}
		if err != nil {
			return "", -1, err
		}
		if err := syscall.Fchown(fd, uid, gid); err != nil {
			syscall.Close(fd)
			_ = syscall.Unlinkat(dir.fd, name)
			return "", -1, err
		}
		if err := syscall.Fchmod(fd, 0o600); err != nil {
			syscall.Close(fd)
			_ = syscall.Unlinkat(dir.fd, name)
			return "", -1, err
		}
		return name, fd, nil
	}
	return "", -1, ErrUnsafeState
}

func verifyFiles(files []managedFile) error {
	for _, file := range files {
		actual, err := readFileAt(file.dir.fd, file.name, file.uid, file.gid, 0o600, maxSecretBytes)
		if err != nil || !bytes.Equal(actual, file.data) {
			clear(actual)
			return ErrUnsafeState
		}
		clear(actual)
	}
	return nil
}

func lock(root *directory, uid, gid int) (func(), error) {
	fd, err := syscall.Openat(root.fd, ".dynamicflow-vnc-secret.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || int(stat.Uid) != uid || int(stat.Gid) != gid || stat.Mode&0o777 != 0o600 {
		syscall.Close(fd)
		return nil, ErrUnsafeState
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}, nil
}

func randomPassword(source io.Reader, old []byte) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	if source == nil {
		return nil, ErrUnsafeState
	}
	for attempt := 0; attempt < 128; attempt++ {
		result := make([]byte, passwordBytes)
		for index := range result {
			for {
				var candidate [1]byte
				if _, err := io.ReadFull(source, candidate[:]); err != nil {
					clear(result)
					return nil, err
				}
				if int(candidate[0]) >= 248 {
					continue
				}
				result[index] = alphabet[int(candidate[0])%len(alphabet)]
				break
			}
		}
		if !bytes.Equal(result, old) {
			return result, nil
		}
		clear(result)
	}
	return nil, ErrUnsafeState
}

func runPasswordFilter(password []byte) ([]byte, error) {
	var binary *os.File
	var label string
	for _, candidate := range []string{"/usr/bin/tigervncpasswd", "/usr/bin/vncpasswd"} {
		file, err := openTrustedExecutable(candidate)
		if err == nil {
			binary, label = file, candidate
			break
		}
	}
	if binary == nil {
		return nil, ErrUnsupported
	}
	defer binary.Close()
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	command := exec.Command("/proc/self/fd/3", "-f")
	command.Args[0] = label
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		clear(stdout.data)
		clear(stderr.data)
		return nil, ErrUnsupported
	}
	clear(stderr.data)
	return stdout.take(), nil
}

func runServiceAction(action string) error {
	var args []string
	switch action {
	case "stop", "restart":
		args = []string{action, managedUnit}
	case "active":
		args = []string{"is-active", "--quiet", managedUnit}
	default:
		return ErrUnsupported
	}
	return runTrusted("/usr/bin/systemctl", args, nil, nil)
}

func validateRuntime(legacyDir, modernDir string, expected []byte) error {
	passwordFile, err := runtimeConfigValue("PasswordFile")
	if err != nil || passwordFile != filepath.Join(legacyDir, "passwd") && passwordFile != filepath.Join(modernDir, "passwd") {
		return ErrService
	}
	securityTypes, err := runtimeConfigValue("SecurityTypes")
	if err != nil || securityTypes != "VncAuth" {
		return ErrService
	}
	localhost, err := runtimeConfigValue("localhost")
	if err != nil || localhost != "1" && !strings.EqualFold(localhost, "true") && !strings.EqualFold(localhost, "yes") && !strings.EqualFold(localhost, "on") {
		return ErrService
	}
	port, err := runtimeConfigValue("rfbport")
	if err != nil || port != "5901" {
		return ErrService
	}
	if err := validateListeners(); err != nil {
		return err
	}
	// the caller verifies both descriptor-held files against expected bytes
	// before and after this runtime check; never pass the credential to a child.
	if len(expected) != passwordBytes {
		return ErrService
	}
	return nil
}

func runtimeConfigValue(parameter string) (string, error) {
	if parameter != "PasswordFile" && parameter != "SecurityTypes" && parameter != "localhost" && parameter != "rfbport" {
		return "", ErrService
	}
	var stdout limitedBuffer
	environment := []string{"DISPLAY=:1", "XAUTHORITY=/home/malwarelab/.Xauthority", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	err := runTrusted("/usr/sbin/runuser", []string{"-u", managedUser, "--", "/usr/bin/tigervncconfig", "-get", parameter}, environment, &stdout)
	if err != nil {
		return "", ErrService
	}
	value := strings.TrimSpace(string(stdout.data))
	clear(stdout.data)
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrService
	}
	return value, nil
}

func validateListeners() error {
	foundIPv4 := false
	for _, item := range []struct {
		path      string
		loopback  string
		requireV4 bool
	}{
		{"/proc/net/tcp", "0100007F", true},
		{"/proc/net/tcp6", "00000000000000000000000001000000", false},
	} {
		file, err := os.Open(item.path)
		if err != nil {
			return ErrService
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 1<<20))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 || parts[1] != "170D" {
				continue
			}
			if parts[0] != item.loopback {
				file.Close()
				return ErrService
			}
			if item.requireV4 {
				foundIPv4 = true
			}
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return ErrService
		}
	}
	if !foundIPv4 {
		return ErrService
	}
	return nil
}

func runTrusted(path string, args, environment []string, stdout io.Writer) error {
	binary, err := openTrustedExecutable(path)
	if err != nil {
		return ErrUnsupported
	}
	defer binary.Close()
	command := exec.Command("/proc/self/fd/3", args...)
	command.Args[0] = path
	command.ExtraFiles = []*os.File{binary}
	if environment == nil {
		environment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	}
	command.Env = environment
	command.Stdout = stdout
	var stderr limitedBuffer
	command.Stderr = &stderr
	err = command.Run()
	clear(stderr.data)
	return err
}

func openTrustedExecutable(path string) (*os.File, error) {
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(clean) {
		return nil, ErrUnsupported
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 {
		file.Close()
		return nil, ErrUnsupported
	}
	return file, nil
}

func validSource(data []byte) bool {
	if len(data) != passwordBytes+1 || data[passwordBytes] != '\n' {
		return false
	}
	for _, value := range data[:passwordBytes] {
		if value < '0' || value > '9' && value < 'A' || value > 'Z' && value < 'a' || value > 'z' {
			return false
		}
	}
	return true
}

func validName(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsRune(value, 0)
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func callHook(cfg config, phase string) error {
	if cfg.hook == nil {
		return nil
	}
	return cfg.hook(phase)
}

func clear(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

type limitedBuffer struct{ data []byte }

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if len(buffer.data)+len(data) > maxCommandOutput {
		return 0, ErrUnsupported
	}
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func (buffer *limitedBuffer) take() []byte {
	result := buffer.data
	buffer.data = nil
	return result
}
