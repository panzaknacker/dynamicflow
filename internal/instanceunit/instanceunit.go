// package instanceunit installs the narrow, pull-only target reconciliation
// systemd service.  the service has no generic command or job input: its sole
// entry point fetches and applies the instance's signed desired state over the
// already pinned outbound HTTPS client.
package instanceunit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	ServiceName       = "dynamicflow-instance-reconcile.service"
	TimerName         = "dynamicflow-instance-reconcile.timer"
	DefaultExecutable = "/usr/local/bin/flow"
	DefaultStateRoot  = "/var/lib/dynamicflow/instance"
	defaultUnitDir    = "/etc/systemd/system"
)

var errUnsafeConfiguration = errors.New("unsafe instance reconcile unit configuration")

type systemctlRunner func(...string) error
type executableVerifier func(string) error

type installer struct {
	executable string
	stateRoot  string
	unitDir    string
	run        systemctlRunner
	verify     executableVerifier
}

// Install reconciles and enables the fixed root one-shot timer. StateRoot is
// accepted for isolated tests and recovery layouts, but must be a safe absolute
// path. the production bootstrap always supplies DefaultStateRoot.
func Install(stateRoot string) (bool, error) {
	return (installer{
		executable: DefaultExecutable,
		stateRoot:  stateRoot,
		unitDir:    defaultUnitDir,
		run:        runSystemctl,
		verify:     verifyRootExecutable,
	}).install()
}

func (configuration installer) install() (bool, error) {
	if configuration.run == nil || configuration.verify == nil ||
		!safeUnitArgument(configuration.executable, true) ||
		!safeUnitArgument(configuration.stateRoot, false) ||
		!safeUnitArgument(configuration.unitDir, false) {
		return false, errUnsafeConfiguration
	}
	if err := configuration.verify(configuration.executable); err != nil {
		return false, err
	}
	if err := validateDirectoryPath(configuration.unitDir); err != nil {
		return false, err
	}
	unitDirectoryInfo, err := os.Lstat(configuration.unitDir)
	if err != nil || unitDirectoryInfo.Mode().Perm()&0o022 != 0 {
		return false, errors.New("systemd unit directory must not be group or world writable")
	}
	unitDirectoryStat, ok := unitDirectoryInfo.Sys().(*syscall.Stat_t)
	if !ok || int(unitDirectoryStat.Uid) != os.Geteuid() {
		return false, errors.New("systemd unit directory must be owned by the installer")
	}
	for _, name := range []string{ServiceName, TimerName} {
		if err := validateUnitTarget(filepath.Join(configuration.unitDir, name)); err != nil {
			return false, err
		}
	}

	service, err := renderService(configuration.executable, configuration.stateRoot)
	if err != nil {
		return false, err
	}
	timer := renderTimer()
	changedService, err := writeAtomicIfChanged(
		filepath.Join(configuration.unitDir, ServiceName), []byte(service), 0o644,
	)
	if err != nil {
		return false, fmt.Errorf("install instance reconcile service: %w", err)
	}
	changedTimer, err := writeAtomicIfChanged(
		filepath.Join(configuration.unitDir, TimerName), []byte(timer), 0o644,
	)
	if err != nil {
		return false, fmt.Errorf("install instance reconcile timer: %w", err)
	}
	changed := changedService || changedTimer
	if changed {
		if err := configuration.run("daemon-reload"); err != nil {
			return changed, err
		}
	}
	// always reconcile enablement. this repairs a disabled timer without
	// rewriting either unit and is safe on repeated enroll recovery runs.
	if err := configuration.run("enable", "--now", TimerName); err != nil {
		return changed, err
	}
	return changed, nil
}

func renderService(executable, stateRoot string) (string, error) {
	if !safeUnitArgument(executable, true) || !safeUnitArgument(stateRoot, false) {
		return "", errUnsafeConfiguration
	}
	return `[Unit]
Description=Dynamicflow signed desired-state reconciliation
Wants=network-online.target
After=network-online.target
ConditionPathExists=` + filepath.Join(stateRoot, "runtime-config.json") + `
StartLimitIntervalSec=15min
StartLimitBurst=4

[Service]
Type=oneshot
ExecStart=` + executable + ` instance-runtime reconcile --state-root ` + stateRoot + `
TimeoutStartSec=45min
UMask=0077
PrivateTmp=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dynamicflow-instance
`, nil
}

func renderTimer() string {
	return `[Unit]
Description=Periodic Dynamicflow signed desired-state reconciliation

[Timer]
Unit=` + ServiceName + `
OnCalendar=*:0/5
Persistent=true
AccuracySec=15s
RandomizedDelaySec=45s

[Install]
WantedBy=timers.target
`
}

func safeUnitArgument(value string, executable bool) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" ||
		strings.ContainsAny(value, " \t\r\n\x00\\") {
		return false
	}
	if executable && strings.HasSuffix(value, "/") {
		return false
	}
	return true
}

func verifyRootExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("flow target executable must be a protected regular executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("flow target executable must be owned by root")
	}
	return nil
}

func validateDirectoryPath(path string) error {
	if !safeUnitArgument(path, false) {
		return errUnsafeConfiguration
	}
	current := "/"
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("systemd unit directory path is missing or unsafe")
		}
	}
	return nil
}

func validateUnitTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing systemd unit target is unsafe")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 || int(metadata.Uid) != os.Geteuid() {
		return errors.New("existing systemd unit target has unsafe ownership or links")
	}
	return nil
}

func writeAtomicIfChanged(path string, content []byte, mode os.FileMode) (bool, error) {
	if len(content) == 0 || mode.Perm() != mode || mode.Perm()&0o022 != 0 {
		return false, errUnsafeConfiguration
	}
	if err := validateDirectoryPath(filepath.Dir(path)); err != nil {
		return false, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("existing systemd unit target is unsafe")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return false, readErr
		}
		if bytes.Equal(existing, content) {
			if err := os.Chown(path, os.Geteuid(), os.Getegid()); err != nil {
				return false, err
			}
			if err := os.Chmod(path, mode); err != nil {
				return false, err
			}
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".dynamicflow-unit-")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeWithError := func(operationErr error) (bool, error) {
		if closeErr := temporary.Close(); operationErr == nil {
			operationErr = closeErr
		}
		return false, operationErr
	}
	if err := temporary.Chmod(mode); err != nil {
		return closeWithError(err)
	}
	if err := temporary.Chown(os.Geteuid(), os.Getegid()); err != nil {
		return closeWithError(err)
	}
	if _, err := temporary.Write(content); err != nil {
		return closeWithError(err)
	}
	if err := temporary.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return false, err
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil {
		return false, syncErr
	}
	return true, closeErr
}

func runSystemctl(arguments ...string) error {
	allowed := (len(arguments) == 1 && arguments[0] == "daemon-reload") ||
		(len(arguments) == 3 && arguments[0] == "enable" && arguments[1] == "--now" && arguments[2] == TimerName)
	if !allowed {
		return errUnsafeConfiguration
	}
	command := exec.Command("/usr/bin/systemctl", arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("systemctl %s failed: %w", arguments[0], err)
	}
	return nil
}
