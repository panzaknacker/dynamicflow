package instanceunit

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProductionUnitContractIsFixedPullOnlyAndInstallerCompatible(t *testing.T) {
	service, err := renderService(DefaultExecutable, DefaultStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"Type=oneshot",
		"Wants=network-online.target",
		"After=network-online.target",
		"ConditionPathExists=/var/lib/dynamicflow/instance/runtime-config.json",
		"ExecStart=/usr/local/bin/flow instance-runtime reconcile --state-root /var/lib/dynamicflow/instance",
		"TimeoutStartSec=45min",
		"UMask=0077",
		"PrivateTmp=true",
		"ProtectClock=true",
		"ProtectHostname=true",
		"ProtectKernelLogs=true",
		"LockPersonality=true",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	}
	for _, contract := range required {
		if !strings.Contains(service, contract) {
			t.Fatalf("service is missing %q:\n%s", contract, service)
		}
	}
	// The fixed reconciler may mutate /etc, /opt, /home, /var and package
	// state, manipulate nftables/sysctls, and start Mullvad/VNC units. These
	// otherwise-useful directives would silently break a valid signed profile.
	forbidden := []string{
		"ProtectSystem=", "ProtectHome=", "PrivateNetwork=", "PrivateDevices=",
		"ProtectKernelTunables=", "ProtectKernelModules=", "CapabilityBoundingSet=",
		"MemoryDenyWriteExecute=", "RestrictSUIDSGID=", "ReadWritePaths=",
		"NoNewPrivileges=", "Restart=", "Environment=", "EnvironmentFile=",
		" ssh ", " scp ", "curl ", "--server", "--secret", "enroll create", "instance exec",
	}
	for _, contract := range forbidden {
		if strings.Contains(service, contract) {
			t.Fatalf("service contains forbidden contract %q:\n%s", contract, service)
		}
	}
}

func TestTimerIsPersistentAndBoundedlyJittered(t *testing.T) {
	timer := renderTimer()
	for _, contract := range []string{
		"Unit=" + ServiceName,
		"OnCalendar=*:0/5",
		"Persistent=true",
		"AccuracySec=15s",
		"RandomizedDelaySec=45s",
		"WantedBy=timers.target",
	} {
		if !strings.Contains(timer, contract) {
			t.Fatalf("timer is missing %q:\n%s", contract, timer)
		}
	}
	for _, forbidden := range []string{"OnBootSec=", "OnStartupSec=", "ExecStart=", "Environment=", "ssh", "secret"} {
		if strings.Contains(timer, forbidden) {
			t.Fatalf("timer contains forbidden setting %q", forbidden)
		}
	}
}

func TestRenderedUnitsPassSystemdAnalyzeWhenAvailable(t *testing.T) {
	analyzer, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not installed")
	}
	service, err := renderService("/bin/true", DefaultStateRoot)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	servicePath := filepath.Join(directory, ServiceName)
	timerPath := filepath.Join(directory, TimerName)
	if err := os.WriteFile(servicePath, []byte(service), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(timerPath, []byte(renderTimer()), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(analyzer, "verify", servicePath, timerPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("systemd unit verification: %v\n%s", err, output)
	}
}

func TestInstallerIsAtomicIdempotentAndRepairsEnablement(t *testing.T) {
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "units")
	if err := os.Mkdir(unitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "flow")
	if err := os.WriteFile(executable, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	var calls [][]string
	configuration := installer{
		executable: executable, stateRoot: stateRoot, unitDir: unitDirectory,
		verify: func(path string) error {
			if path != executable {
				return errors.New("wrong executable")
			}
			return nil
		},
		run: func(arguments ...string) error {
			calls = append(calls, append([]string(nil), arguments...))
			return nil
		},
	}
	changed, err := configuration.install()
	if err != nil || !changed {
		t.Fatalf("initial install changed=%v err=%v", changed, err)
	}
	wantFirst := [][]string{{"daemon-reload"}, {"enable", "--now", TimerName}}
	if !reflect.DeepEqual(calls, wantFirst) {
		t.Fatalf("initial systemctl calls=%v want=%v", calls, wantFirst)
	}
	for _, name := range []string{ServiceName, TimerName} {
		path := filepath.Join(unitDirectory, name)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatalf("unsafe installed unit %s: info=%v err=%v", name, info, statErr)
		}
	}

	calls = nil
	changed, err = configuration.install()
	if err != nil || changed {
		t.Fatalf("idempotent install changed=%v err=%v", changed, err)
	}
	wantSecond := [][]string{{"enable", "--now", TimerName}}
	if !reflect.DeepEqual(calls, wantSecond) {
		t.Fatalf("idempotent systemctl calls=%v want=%v", calls, wantSecond)
	}

	servicePath := filepath.Join(unitDirectory, ServiceName)
	if err := os.Chmod(servicePath, 0o600); err != nil {
		t.Fatal(err)
	}
	calls = nil
	changed, err = configuration.install()
	if err != nil || changed {
		t.Fatalf("permission repair changed=%v err=%v", changed, err)
	}
	info, err := os.Stat(servicePath)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("unit permissions were not repaired: info=%v err=%v", info, err)
	}
}

func TestInstallerRejectsUnsafeTargetsBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "units")
	if err := os.Mkdir(unitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "flow")
	if err := os.WriteFile(executable, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(unitDirectory, TimerName)); err != nil {
		t.Fatal(err)
	}
	run := false
	configuration := installer{
		executable: executable, stateRoot: filepath.Join(root, "state"), unitDir: unitDirectory,
		verify: func(string) error { return nil },
		run: func(...string) error {
			run = true
			return nil
		},
	}
	if changed, err := configuration.install(); err == nil || changed || run {
		t.Fatalf("unsafe target accepted: changed=%v run=%v err=%v", changed, run, err)
	}
	if _, err := os.Lstat(filepath.Join(unitDirectory, ServiceName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service was partially installed before unsafe timer rejection: %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "do-not-touch" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}
}

func TestInstallerRejectsWritableOrForeignUnitDirectory(t *testing.T) {
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "units")
	if err := os.Mkdir(unitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := installer{
		executable: filepath.Join(root, "flow"), stateRoot: filepath.Join(root, "state"), unitDir: unitDirectory,
		verify: func(string) error { return nil }, run: func(...string) error { return nil },
	}
	if err := os.Chmod(unitDirectory, 0o770); err != nil {
		t.Fatal(err)
	}
	if changed, err := configuration.install(); err == nil || changed {
		t.Fatalf("group-writable unit directory accepted: changed=%v err=%v", changed, err)
	}
}

func TestInstallerRejectsHardlinkedUnitBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "units")
	if err := os.Mkdir(unitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "flow")
	if err := os.WriteFile(executable, []byte("test executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sentinel, filepath.Join(unitDirectory, TimerName)); err != nil {
		t.Fatal(err)
	}
	run := false
	configuration := installer{
		executable: executable, stateRoot: filepath.Join(root, "state"), unitDir: unitDirectory,
		verify: func(string) error { return nil },
		run: func(...string) error {
			run = true
			return nil
		},
	}
	if changed, err := configuration.install(); err == nil || changed || run {
		t.Fatalf("hardlinked target accepted: changed=%v run=%v err=%v", changed, run, err)
	}
	if _, err := os.Lstat(filepath.Join(unitDirectory, ServiceName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service was partially installed before hardlink rejection: %v", err)
	}
	info, err := os.Stat(sentinel)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("hardlink target metadata changed: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "do-not-touch" {
		t.Fatalf("hardlink target changed: data=%q err=%v", data, err)
	}
}

func TestRendererAndSystemctlRejectInjectionOrGenericCommands(t *testing.T) {
	unsafe := []string{
		"relative", "/", "/var/lib/dynamic flow", "/var/lib/dynamicflow\nExecStart=/bin/sh", "/tmp/a\\b",
	}
	for _, value := range unsafe {
		if _, err := renderService(DefaultExecutable, value); err == nil {
			t.Fatalf("unsafe state root accepted: %q", value)
		}
	}
	if _, err := renderService("/usr/local/bin/flow --json", DefaultStateRoot); err == nil {
		t.Fatal("executable argument injection accepted")
	}
	for _, arguments := range [][]string{
		{"start", "ssh.service"}, {"enable", "--now", "attacker.timer"}, {"daemon-reload", "extra"},
	} {
		if err := runSystemctl(arguments...); !errors.Is(err, errUnsafeConfiguration) {
			t.Fatalf("generic systemctl command was not rejected: %v err=%v", arguments, err)
		}
	}
}

func TestSystemctlFailureDoesNotExposeCommandOutput(t *testing.T) {
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "units")
	if err := os.Mkdir(unitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := installer{
		executable: filepath.Join(root, "flow"), stateRoot: filepath.Join(root, "state"), unitDir: unitDirectory,
		verify: func(string) error { return nil },
		run: func(arguments ...string) error {
			return errors.New("bounded systemctl failure")
		},
	}
	changed, err := configuration.install()
	if !changed || err == nil || !strings.Contains(err.Error(), "bounded systemctl failure") {
		t.Fatalf("systemctl failure not surfaced safely: changed=%v err=%v", changed, err)
	}
}
