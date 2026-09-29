package sshtransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"dynamicflow/internal/localstate"
)

func TestBuildRoutedTargetWritesSeparatedPinnedManagedTransport(t *testing.T) {
	fixture := newFixture(t)
	invocation, err := fixture.builder.BuildRoutedTarget(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	arguments := invocation.Arguments()
	if len(arguments) != 5 || arguments[0] != "-F" || arguments[2] != "-S" ||
		arguments[3] != "none" || arguments[4] != "flow-target-target-a" {
		t.Fatalf("managed arguments = %#v", arguments)
	}
	arguments[0] = "-o"
	if invocation.Arguments()[0] != "-F" {
		t.Fatal("Arguments returned mutable invocation state")
	}
	arguments = invocation.Arguments()
	configPath := arguments[1]
	knownHostsPath := filepath.Join(filepath.Dir(configPath), "known_hosts")
	assertPrivateManagedFile(t, configPath)
	assertPrivateManagedFile(t, knownHostsPath)

	config := readFile(t, configPath)
	for _, required := range []string{
		"Host flow-control-control",
		"HostName 203.0.113.10",
		"IdentityFile \"" + fixture.controlIdentity.path + "\"",
		"HostKeyAlias flow-control-control",
		"Host flow-target-target-a",
		"HostName 10.20.0.2",
		"IdentityFile \"" + fixture.targetIdentity.path + "\"",
		"HostKeyAlias flow-target-target-a",
		"ProxyJump flow-control-control",
		"BatchMode yes",
		"IdentitiesOnly yes",
		"IdentityAgent none",
		"StrictHostKeyChecking yes",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"ForwardAgent no",
		"ForwardX11 no",
		"UpdateHostKeys no",
		"VerifyHostKeyDNS no",
		"ControlMaster no",
		"ControlPath none",
		"PermitLocalCommand no",
		"CanonicalizeHostname no",
		"ClearAllForwardings yes",
		"UserKnownHostsFile \"" + knownHostsPath + "\"",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("managed config missing %q:\n%s", required, config)
		}
	}
	if strings.Contains(strings.ToLower(config), "proxycommand") {
		t.Fatalf("managed config contains ProxyCommand:\n%s", config)
	}
	if count := strings.Count(config, "ProxyJump flow-control-control"); count != 1 {
		t.Fatalf("target ProxyJump count = %d, want 1:\n%s", count, config)
	}

	knownHosts := readFile(t, knownHostsPath)
	if knownHosts != "flow-control-control "+fixture.route.Control.HostKey+"\n"+
		"flow-target-target-a "+fixture.route.Target.HostKey+"\n" {
		t.Fatalf("managed known_hosts = %q", knownHosts)
	}
	if strings.Contains(knownHosts, fixture.route.Control.Host) ||
		strings.Contains(knownHosts, fixture.route.Target.Host) {
		t.Fatalf("known_hosts is bound to network addresses instead of logical aliases: %q", knownHosts)
	}

	second, err := fixture.builder.BuildRoutedTarget(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(arguments, second.Arguments()) {
		t.Fatalf("idempotent invocation changed: %v -> %v", arguments, second.Arguments())
	}
}

func TestBuildDirectFirstControlRequiresExactCapability(t *testing.T) {
	fixture := newFixture(t)
	for _, capability := range []Capability{"", "first-control-bootstrap", "routed_target"} {
		if invocation, err := fixture.builder.BuildDirectFirstControl(capability, fixture.route.Control); !errors.Is(err, ErrCapabilityRequired) || len(invocation.Arguments()) != 0 {
			t.Fatalf("capability %q invocation=%v err=%v", capability, invocation.Arguments(), err)
		}
	}
	invocation, err := fixture.builder.BuildDirectFirstControl(CapabilityFirstControlBootstrap, fixture.route.Control)
	if err != nil {
		t.Fatal(err)
	}
	arguments := invocation.Arguments()
	if len(arguments) != 5 || arguments[4] != "flow-control-control" {
		t.Fatalf("direct first-control arguments = %#v", arguments)
	}
	config := readFile(t, arguments[1])
	if strings.Count(config, "\nHost ") != 0 || strings.Count(config, "Host flow-control-control") != 1 ||
		strings.Contains(config, "flow-target-") || !strings.Contains(config, "ProxyJump none") ||
		strings.Contains(strings.ToLower(config), "proxycommand") {
		t.Fatalf("direct control config gained another destination or fallback:\n%s", config)
	}
	if _, exists := reflect.TypeOf(fixture.builder).MethodByName("BuildDirectTarget"); exists {
		t.Fatal("Builder exposes forbidden BuildDirectTarget fallback")
	}
}

func TestBuildDirectPendingControlProofUsesOnlyPinnedStagedIdentity(t *testing.T) {
	fixture := newFixture(t)
	pending := newPendingControlProof(t, fixture)
	for _, capability := range []PendingControlProofCapability{0, 1, 0xffff} {
		if invocation, err := fixture.builder.BuildDirectPendingControlProof(capability, pending); !errors.Is(err, ErrPendingControlCapabilityRequired) || len(invocation.Arguments()) != 0 {
			t.Fatalf("capability %d invocation=%v err=%v", capability, invocation.Arguments(), err)
		}
	}

	invocation, err := fixture.builder.BuildDirectPendingControlProof(CapabilityPendingControlProof, pending)
	if err != nil {
		t.Fatal(err)
	}
	arguments := invocation.Arguments()
	if len(arguments) != 5 || arguments[0] != "-F" || arguments[2] != "-S" ||
		arguments[3] != "none" || arguments[4] != "flow-control-control" {
		t.Fatalf("pending-control arguments = %#v", arguments)
	}
	configPath := arguments[1]
	if !strings.Contains(filepath.ToSlash(configPath), "/sshtransport/pending-control-proof/control/") {
		t.Fatalf("pending proof did not use its isolated namespace: %q", configPath)
	}
	knownHostsPath := filepath.Join(filepath.Dir(configPath), "known_hosts")
	assertPrivateManagedFile(t, configPath)
	assertPrivateManagedFile(t, knownHostsPath)

	config := readFile(t, configPath)
	for _, required := range []string{
		"Host flow-control-control",
		"HostName 203.0.113.10",
		"User " + ReadyControlUser,
		"IdentityFile \"" + pending.Control.Identity.path + "\"",
		"HostKeyAlias flow-control-control",
		"UserKnownHostsFile \"" + knownHostsPath + "\"",
		"StrictHostKeyChecking yes",
		"ClearAllForwardings yes",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("pending-control config missing %q:\n%s", required, config)
		}
	}
	lowerConfig := strings.ToLower(config)
	if strings.Contains(config, fixture.controlIdentity.path) ||
		strings.Contains(config, "flow-target-") ||
		strings.Contains(lowerConfig, "proxyjump") ||
		strings.Contains(lowerConfig, "proxycommand") ||
		strings.Contains(lowerConfig, "localforward") ||
		strings.Contains(lowerConfig, "remoteforward") ||
		strings.Contains(lowerConfig, "dynamicforward") ||
		strings.Contains(lowerConfig, "remotecommand") ||
		strings.Contains(config, "    LocalCommand ") ||
		strings.Count(config, "Host flow-control-control") != 1 {
		t.Fatalf("pending-control config gained a command, forwarding, route, or bootstrap material:\n%s", config)
	}
	if knownHosts := readFile(t, knownHostsPath); knownHosts !=
		"flow-control-control "+pending.Control.HostKey+"\n" {
		t.Fatalf("pending-control known_hosts = %q", knownHosts)
	}

	second, err := fixture.builder.BuildDirectPendingControlProof(CapabilityPendingControlProof, pending)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(arguments, second.Arguments()) {
		t.Fatalf("idempotent pending-control invocation changed: %v -> %v", arguments, second.Arguments())
	}
}

func TestPendingControlProofRejectsReadyStateUserKeyAndStalePin(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*PendingControlProof)
		want   error
	}{
		{"zero phase", func(pending *PendingControlProof) { pending.Phase = "" }, ErrPendingControlState},
		{"ready phase", func(pending *PendingControlProof) { pending.Phase = "ready" }, ErrPendingControlState},
		{"bootstrap user", func(pending *PendingControlProof) { pending.Control.User = "flow-jump" }, ErrManagementIdentity},
		{"root user", func(pending *PendingControlProof) { pending.Control.User = "root" }, ErrUnsafeEndpoint},
		{"target role", func(pending *PendingControlProof) { pending.Control.Role = RoleTarget }, ErrUnsafeEndpoint},
		{"bootstrap key reused", func(pending *PendingControlProof) {
			pending.BootstrapIdentityFingerprint = pending.Control.IdentityFingerprint
		}, ErrManagementIdentity},
		{"invalid bootstrap fingerprint", func(pending *PendingControlProof) {
			pending.BootstrapIdentityFingerprint = "SHA256:bad"
		}, ErrManagementIdentity},
		{"stale bound host key", func(pending *PendingControlProof) {
			pending.ControlHostKeyFingerprint = fingerprint(99)
		}, ErrHostKeyBinding},
		{"stale endpoint host key", func(pending *PendingControlProof) {
			pending.Control.HostKeyFingerprint = fingerprint(98)
		}, ErrHostKeyBinding},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			pending := newPendingControlProof(t, fixture)
			test.mutate(&pending)
			if invocation, err := fixture.builder.BuildDirectPendingControlProof(CapabilityPendingControlProof, pending); !errors.Is(err, test.want) || len(invocation.Arguments()) != 0 {
				t.Fatalf("invocation=%v error=%v, want %v", invocation.Arguments(), err, test.want)
			}
		})
	}
}

func TestBuildDirectReadyControlUsesOnlyPinnedManagementIdentity(t *testing.T) {
	fixture := newFixture(t)
	ready := newReadyControl(t, fixture)
	for _, capability := range []ReadyControlCapability{0, 2, 255} {
		if invocation, err := fixture.builder.BuildDirectReadyControl(capability, ready); !errors.Is(err, ErrReadyControlCapabilityRequired) || len(invocation.Arguments()) != 0 {
			t.Fatalf("capability %d invocation=%v err=%v", capability, invocation.Arguments(), err)
		}
	}

	invocation, err := fixture.builder.BuildDirectReadyControl(CapabilityVerifiedReadyControl, ready)
	if err != nil {
		t.Fatal(err)
	}
	arguments := invocation.Arguments()
	if len(arguments) != 5 || arguments[0] != "-F" || arguments[2] != "-S" ||
		arguments[3] != "none" || arguments[4] != "flow-control-control" {
		t.Fatalf("ready-control arguments = %#v", arguments)
	}
	configPath := arguments[1]
	knownHostsPath := filepath.Join(filepath.Dir(configPath), "known_hosts")
	assertPrivateManagedFile(t, configPath)
	assertPrivateManagedFile(t, knownHostsPath)

	config := readFile(t, configPath)
	for _, required := range []string{
		"Host flow-control-control",
		"HostName 203.0.113.10",
		"User " + ReadyControlUser,
		"IdentityFile \"" + ready.Control.Identity.path + "\"",
		"HostKeyAlias flow-control-control",
		"UserKnownHostsFile \"" + knownHostsPath + "\"",
		"GlobalKnownHostsFile /dev/null",
		"BatchMode yes",
		"IdentitiesOnly yes",
		"IdentityAgent none",
		"StrictHostKeyChecking yes",
		"HostKeyAlgorithms ssh-ed25519",
		"PubkeyAcceptedAlgorithms ssh-ed25519",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"ForwardAgent no",
		"ForwardX11 no",
		"ClearAllForwardings yes",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("ready-control config missing %q:\n%s", required, config)
		}
	}
	if strings.Contains(config, fixture.controlIdentity.path) ||
		strings.Contains(config, "flow-target-") ||
		strings.Contains(strings.ToLower(config), "proxyjump") ||
		strings.Contains(strings.ToLower(config), "proxycommand") ||
		strings.Count(config, "Host flow-control-control") != 1 {
		t.Fatalf("ready-control config gained bootstrap/target/fallback material:\n%s", config)
	}
	if knownHosts := readFile(t, knownHostsPath); knownHosts !=
		"flow-control-control "+ready.Control.HostKey+"\n" {
		t.Fatalf("ready-control known_hosts = %q", knownHosts)
	}

	second, err := fixture.builder.BuildDirectReadyControl(CapabilityVerifiedReadyControl, ready)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(arguments, second.Arguments()) {
		t.Fatalf("idempotent ready-control invocation changed: %v -> %v", arguments, second.Arguments())
	}
}

func TestReadyControlRejectsBootstrapUserKeyAndStalePin(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ReadyControl)
		want   error
	}{
		{"bootstrap user", func(ready *ReadyControl) { ready.Control.User = "flow-jump" }, ErrManagementIdentity},
		{"root user", func(ready *ReadyControl) { ready.Control.User = "root" }, ErrUnsafeEndpoint},
		{"target role", func(ready *ReadyControl) { ready.Control.Role = RoleTarget }, ErrUnsafeEndpoint},
		{"bootstrap key reused", func(ready *ReadyControl) {
			ready.BootstrapIdentityFingerprint = ready.Control.IdentityFingerprint
		}, ErrManagementIdentity},
		{"invalid bootstrap fingerprint", func(ready *ReadyControl) {
			ready.BootstrapIdentityFingerprint = "SHA256:bad"
		}, ErrManagementIdentity},
		{"stale bound host key", func(ready *ReadyControl) {
			ready.ControlHostKeyFingerprint = fingerprint(99)
		}, ErrHostKeyBinding},
		{"stale endpoint host key", func(ready *ReadyControl) {
			ready.Control.HostKeyFingerprint = fingerprint(98)
		}, ErrHostKeyBinding},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			ready := newReadyControl(t, fixture)
			test.mutate(&ready)
			if invocation, err := fixture.builder.BuildDirectReadyControl(CapabilityVerifiedReadyControl, ready); !errors.Is(err, test.want) || len(invocation.Arguments()) != 0 {
				t.Fatalf("invocation=%v error=%v, want %v", invocation.Arguments(), err, test.want)
			}
		})
	}
}

func TestControlCapabilitiesAndBindingsAreDifferentAPITypes(t *testing.T) {
	builderType := reflect.TypeOf((*Builder)(nil))
	bootstrap, exists := builderType.MethodByName("BuildDirectFirstControl")
	if !exists {
		t.Fatal("missing bootstrap transport")
	}
	pending, exists := builderType.MethodByName("BuildDirectPendingControlProof")
	if !exists {
		t.Fatal("missing pending-control proof transport")
	}
	ready, exists := builderType.MethodByName("BuildDirectReadyControl")
	if !exists {
		t.Fatal("missing ready-control transport")
	}
	capabilityTypes := []reflect.Type{bootstrap.Type.In(1), pending.Type.In(1), ready.Type.In(1)}
	for left := range capabilityTypes {
		for right := left + 1; right < len(capabilityTypes); right++ {
			if capabilityTypes[left] == capabilityTypes[right] || capabilityTypes[left].AssignableTo(capabilityTypes[right]) || capabilityTypes[right].AssignableTo(capabilityTypes[left]) {
				t.Fatalf("Control capabilities are assignment-compatible: %v and %v", capabilityTypes[left], capabilityTypes[right])
			}
		}
	}
	bindingTypes := []reflect.Type{bootstrap.Type.In(2), pending.Type.In(2), ready.Type.In(2)}
	for left := range bindingTypes {
		for right := left + 1; right < len(bindingTypes); right++ {
			if bindingTypes[left] == bindingTypes[right] || bindingTypes[left].AssignableTo(bindingTypes[right]) || bindingTypes[right].AssignableTo(bindingTypes[left]) {
				t.Fatalf("Control bindings are assignment-compatible: %v and %v", bindingTypes[left], bindingTypes[right])
			}
		}
	}
	allowedDirect := map[string]bool{
		"BuildDirectFirstControl":        true,
		"BuildDirectPendingControlProof": true,
		"BuildDirectReadyControl":        true,
	}
	for index := 0; index < builderType.NumMethod(); index++ {
		method := builderType.Method(index)
		if strings.HasPrefix(method.Name, "BuildDirect") && !allowedDirect[method.Name] {
			t.Fatalf("Builder exposes forbidden direct-target surface %s", method.Name)
		}
	}
}

func TestRouteRequiresExactHostKeyBindings(t *testing.T) {
	fixture := newFixture(t)
	for _, mutate := range []func(*Route){
		func(route *Route) { route.ControlHostKeyFingerprint = fingerprint(90) },
		func(route *Route) { route.TargetHostKeyFingerprint = fingerprint(91) },
		func(route *Route) { route.Control.HostKeyFingerprint = fingerprint(92) },
		func(route *Route) { route.Target.HostKeyFingerprint = fingerprint(93) },
	} {
		route := fixture.route
		mutate(&route)
		if invocation, err := fixture.builder.BuildRoutedTarget(route); !errors.Is(err, ErrHostKeyBinding) || len(invocation.Arguments()) != 0 {
			t.Fatalf("stale binding invocation=%v err=%v", invocation.Arguments(), err)
		}
	}
}

func TestRoutedEndpointsAndKeysMustBeDistinct(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Route)
	}{
		{"alias", func(route *Route) { route.Target.Alias = route.Control.Alias }},
		{"endpoint", func(route *Route) {
			route.Target.Host, route.Target.Port = route.Control.Host, route.Control.Port
		}},
		{"identity path", func(route *Route) { route.Target.Identity = route.Control.Identity }},
		{"identity fingerprint", func(route *Route) {
			route.Target.IdentityFingerprint = route.Control.IdentityFingerprint
		}},
		{"host key", func(route *Route) {
			route.Target.HostKey = route.Control.HostKey
			route.Target.HostKeyFingerprint = route.Control.HostKeyFingerprint
			route.TargetHostKeyFingerprint = route.Control.HostKeyFingerprint
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			route := fixture.route
			test.mutate(&route)
			if _, err := fixture.builder.BuildRoutedTarget(route); !errors.Is(err, ErrDistinctRouteRequired) {
				t.Fatalf("BuildRoutedTarget() error = %v, want ErrDistinctRouteRequired", err)
			}
		})
	}
}

func TestEndpointValidationRejectsMalformedInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Endpoint)
		want   error
	}{
		{"empty alias", func(endpoint *Endpoint) { endpoint.Alias = "" }, ErrUnsafeEndpoint},
		{"option alias", func(endpoint *Endpoint) { endpoint.Alias = "-o-proxy" }, ErrUnsafeEndpoint},
		{"path alias", func(endpoint *Endpoint) { endpoint.Alias = "../target" }, ErrUnsafeEndpoint},
		{"target role", func(endpoint *Endpoint) { endpoint.Role = RoleTarget }, ErrUnsafeEndpoint},
		{"unknown role", func(endpoint *Endpoint) { endpoint.Role = EndpointRole("jump") }, ErrUnsafeEndpoint},
		{"empty host", func(endpoint *Endpoint) { endpoint.Host = "" }, ErrUnsafeEndpoint},
		{"option host", func(endpoint *Endpoint) { endpoint.Host = "-oProxyCommand=evil" }, ErrUnsafeEndpoint},
		{"space host", func(endpoint *Endpoint) { endpoint.Host = "host name" }, ErrUnsafeEndpoint},
		{"bracket host", func(endpoint *Endpoint) { endpoint.Host = "[2001:db8::1]" }, ErrUnsafeEndpoint},
		{"uppercase host", func(endpoint *Endpoint) { endpoint.Host = "Target.Example" }, ErrUnsafeEndpoint},
		{"ambiguous numeric host", func(endpoint *Endpoint) { endpoint.Host = "010.020.030.040" }, ErrUnsafeEndpoint},
		{"zero port", func(endpoint *Endpoint) { endpoint.Port = 0 }, ErrUnsafeEndpoint},
		{"large port", func(endpoint *Endpoint) { endpoint.Port = 65536 }, ErrUnsafeEndpoint},
		{"root", func(endpoint *Endpoint) { endpoint.User = "root" }, ErrUnsafeEndpoint},
		{"unsafe user", func(endpoint *Endpoint) { endpoint.User = "admin -o" }, ErrUnsafeEndpoint},
		{"zero identity", func(endpoint *Endpoint) { endpoint.Identity = PrivateIdentity{} }, ErrUnsafeIdentity},
		{"bad identity fingerprint", func(endpoint *Endpoint) {
			endpoint.IdentityFingerprint = "SHA256:bad"
		}, ErrUnsafeIdentity},
		{"bad host key", func(endpoint *Endpoint) { endpoint.HostKey = "ssh-rsa bad" }, ErrUnsafeEndpoint},
		{"host key comment", func(endpoint *Endpoint) { endpoint.HostKey += " comment" }, ErrHostKeyBinding},
		{"bad host fingerprint", func(endpoint *Endpoint) {
			endpoint.HostKeyFingerprint = "SHA256:bad"
		}, ErrHostKeyBinding},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			endpoint := fixture.route.Control
			test.mutate(&endpoint)
			if _, err := fixture.builder.BuildDirectFirstControl(CapabilityFirstControlBootstrap, endpoint); !errors.Is(err, test.want) {
				t.Fatalf("BuildDirectFirstControl() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPrivateIdentityValidationAndBuildTimeRevalidation(t *testing.T) {
	base := t.TempDir()
	valid := filepath.Join(base, "valid")
	writePrivateFile(t, valid)
	if _, err := NewPrivateIdentity(valid); err != nil {
		t.Fatalf("valid identity: %v", err)
	}
	for index, test := range []struct {
		path  string
		setup func(string)
	}{
		{"relative", func(string) {}},
		{filepath.Join(base, "space key"), func(path string) { writePrivateFile(t, path) }},
		{filepath.Join(base, "percent%key"), func(path string) { writePrivateFile(t, path) }},
		{filepath.Join(base, "broad"), func(path string) {
			if err := os.WriteFile(path, []byte("key"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{filepath.Join(base, "directory"), func(path string) {
			if err := os.Mkdir(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{filepath.Join(base, "symlink"), func(path string) {
			if err := os.Symlink(valid, path); err != nil {
				t.Fatal(err)
			}
		}},
		{filepath.Join(base, "hardlink"), func(path string) {
			if err := os.Link(valid, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run("case-"+strconv.Itoa(index), func(t *testing.T) {
			test.setup(test.path)
			if _, err := NewPrivateIdentity(test.path); !errors.Is(err, ErrUnsafeIdentity) {
				t.Fatalf("NewPrivateIdentity(%q) error = %v", test.path, err)
			}
		})
	}

	fixture := newFixture(t)
	if err := os.Chmod(fixture.controlIdentity.path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.builder.BuildDirectFirstControl(CapabilityFirstControlBootstrap, fixture.route.Control); !errors.Is(err, ErrUnsafeIdentity) {
		t.Fatalf("build-time identity revalidation error = %v, want ErrUnsafeIdentity", err)
	}
}

func TestPrivateIdentityPathsNeverSerializeToJSON(t *testing.T) {
	fixture := newFixture(t)
	data, err := json.Marshal(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.controlIdentity.path, fixture.targetIdentity.path} {
		if bytes.Contains(data, []byte(path)) {
			t.Fatalf("route JSON leaked private path %q: %s", path, data)
		}
	}
	if _, err := json.Marshal(fixture.controlIdentity); !errors.Is(err, ErrPrivatePathJSON) {
		t.Fatalf("PrivateIdentity JSON error = %v, want ErrPrivatePathJSON", err)
	}
	ready := newReadyControl(t, fixture)
	data, err = json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.controlIdentity.path, ready.Control.Identity.path} {
		if bytes.Contains(data, []byte(path)) {
			t.Fatalf("ready-control JSON leaked private path %q: %s", path, data)
		}
	}
	pending := newPendingControlProof(t, fixture)
	data, err = json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.controlIdentity.path, pending.Control.Identity.path} {
		if bytes.Contains(data, []byte(path)) {
			t.Fatalf("pending-control JSON leaked private path %q: %s", path, data)
		}
	}
}

func TestManagedConfigRejectsSymlinkReplacement(t *testing.T) {
	fixture := newFixture(t)
	invocation, err := fixture.builder.BuildRoutedTarget(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	configPath := invocation.Arguments()[1]
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	writePrivateFile(t, outside)
	if err := os.Symlink(outside, configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.builder.BuildRoutedTarget(fixture.route); !errors.Is(err, localstate.ErrSymlink) {
		t.Fatalf("symlink replacement error = %v, want ErrSymlink", err)
	}
}

func TestManagedConfigRejectsOpenSSHTokenExpansionInStatePath(t *testing.T) {
	fixture := newFixture(t)
	local, err := localstate.Open(filepath.Join(t.TempDir(), "state%h"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBuilder(local).BuildRoutedTarget(fixture.route); !errors.Is(err, ErrInvalidTransport) {
		t.Fatalf("token-expanding state path error = %v, want ErrInvalidTransport", err)
	}
}

func TestWithVNCForwardOnlyAddsFixedFinalTargetLoopback(t *testing.T) {
	fixture := newFixture(t)
	routed, err := fixture.builder.BuildRoutedTarget(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	gui, err := WithVNCForward(routed, 5902)
	if err != nil {
		t.Fatal(err)
	}
	arguments := gui.Arguments()
	joined := strings.Join(arguments, "\x00")
	for _, wanted := range []string{
		"ClearAllForwardings=no",
		"ExitOnForwardFailure=yes",
		"127.0.0.1:5902:127.0.0.1:5901",
	} {
		if !strings.Contains(joined, wanted) {
			t.Fatalf("GUI arguments missing %q: %#v", wanted, arguments)
		}
	}
	if arguments[len(arguments)-1] != "flow-target-target-a" ||
		strings.Contains(joined, "0.0.0.0") || strings.Contains(joined, "-R") ||
		strings.Contains(joined, "-D") {
		t.Fatalf("GUI forward escaped final target loopback: %#v", arguments)
	}
	if _, err := WithVNCForward(gui, 5903); !errors.Is(err, ErrVNCForward) {
		t.Fatalf("second VNC forward error = %v", err)
	}
	if _, err := WithVNCForward(routed, 0); !errors.Is(err, ErrVNCForward) {
		t.Fatalf("invalid VNC port error = %v", err)
	}
	direct, err := fixture.builder.BuildDirectFirstControl(CapabilityFirstControlBootstrap, fixture.route.Control)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithVNCForward(direct, 5902); !errors.Is(err, ErrVNCForward) {
		t.Fatalf("direct-control VNC error = %v", err)
	}
	pending, err := fixture.builder.BuildDirectPendingControlProof(CapabilityPendingControlProof, newPendingControlProof(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithVNCForward(pending, 5902); !errors.Is(err, ErrVNCForward) {
		t.Fatalf("pending-control VNC error = %v", err)
	}
	ready, err := fixture.builder.BuildDirectReadyControl(CapabilityVerifiedReadyControl, newReadyControl(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithVNCForward(ready, 5902); !errors.Is(err, ErrVNCForward) {
		t.Fatalf("ready-control VNC error = %v", err)
	}
}

func TestOpenSSHResolvesSeparatedRouteAndVNCWhenAvailable(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	fixture := newFixture(t)
	invocation, err := fixture.builder.BuildRoutedTarget(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	targetConfig := sshConfig(t, ssh, invocation.Arguments())
	assertConfigValue(t, targetConfig, "hostname", fixture.route.Target.Host)
	assertConfigValue(t, targetConfig, "user", fixture.route.Target.User)
	assertConfigValue(t, targetConfig, "port", strconv.Itoa(fixture.route.Target.Port))
	assertConfigValue(t, targetConfig, "proxyjump", "flow-control-control")
	assertConfigValue(t, targetConfig, "identityfile", fixture.targetIdentity.path)
	if countConfigKey(targetConfig, "identityfile") != 1 {
		t.Fatalf("target has more than one configured identity:\n%s", targetConfig)
	}
	for _, expected := range []string{
		"batchmode yes",
		"identitiesonly yes",
		"identityagent none",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"forwardagent no",
		"forwardx11 no",
		"permitlocalcommand no",
	} {
		if !strings.Contains(targetConfig, expected) {
			t.Errorf("target ssh -G missing %q:\n%s", expected, targetConfig)
		}
	}
	configPath := invocation.Arguments()[1]
	controlConfig := sshConfig(t, ssh, []string{"-F", configPath, "-S", "none", "flow-control-control"})
	assertConfigValue(t, controlConfig, "hostname", fixture.route.Control.Host)
	assertConfigValue(t, controlConfig, "identityfile", fixture.controlIdentity.path)
	if countConfigKey(controlConfig, "identityfile") != 1 {
		t.Fatalf("control has more than one configured identity:\n%s", controlConfig)
	}
	if strings.Contains(controlConfig, strings.ToLower(fixture.targetIdentity.path)) {
		t.Fatalf("control config offers target identity:\n%s", controlConfig)
	}
	if strings.Contains(targetConfig, strings.ToLower(fixture.controlIdentity.path)) {
		t.Fatalf("target config offers control identity:\n%s", targetConfig)
	}

	gui, err := WithVNCForward(invocation, 5902)
	if err != nil {
		t.Fatal(err)
	}
	guiConfig := sshConfig(t, ssh, gui.Arguments())
	if !strings.Contains(guiConfig, "clearallforwardings no") ||
		!strings.Contains(guiConfig, "localforward [127.0.0.1]:5902 [127.0.0.1]:5901") {
		t.Fatalf("ssh -G did not retain fixed VNC forward:\n%s", guiConfig)
	}
}

func TestOpenSSHResolvesPendingControlProofWithoutJumpForwardOrBootstrapKeyWhenAvailable(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	fixture := newFixture(t)
	pending := newPendingControlProof(t, fixture)
	invocation, err := fixture.builder.BuildDirectPendingControlProof(CapabilityPendingControlProof, pending)
	if err != nil {
		t.Fatal(err)
	}
	config := sshConfig(t, ssh, invocation.Arguments())
	assertConfigValue(t, config, "hostname", pending.Control.Host)
	assertConfigValue(t, config, "user", ReadyControlUser)
	assertConfigValue(t, config, "port", strconv.Itoa(pending.Control.Port))
	assertConfigValue(t, config, "identityfile", pending.Control.Identity.path)
	if countConfigKey(config, "identityfile") != 1 {
		t.Fatalf("pending Control has more than one configured identity:\n%s", config)
	}
	if strings.Contains(config, strings.ToLower(fixture.controlIdentity.path)) ||
		strings.Contains(config, "proxyjump flow-") ||
		strings.Contains(config, "proxycommand ") ||
		strings.Contains(config, "localforward ") ||
		strings.Contains(config, "remoteforward ") ||
		strings.Contains(config, "dynamicforward ") ||
		strings.Contains(config, "remotecommand ") {
		t.Fatalf("pending Control resolved a bootstrap key, command, forwarding, or proxy route:\n%s", config)
	}
	for _, expected := range []string{
		"batchmode yes",
		"identitiesonly yes",
		"identityagent none",
		"stricthostkeychecking true",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"forwardagent no",
		"forwardx11 no",
		"clearallforwardings yes",
		"permitlocalcommand no",
	} {
		if !strings.Contains(config, expected) {
			t.Errorf("pending Control ssh -G missing %q:\n%s", expected, config)
		}
	}
}

func TestOpenSSHResolvesReadyControlWithoutJumpOrBootstrapKeyWhenAvailable(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	fixture := newFixture(t)
	ready := newReadyControl(t, fixture)
	invocation, err := fixture.builder.BuildDirectReadyControl(CapabilityVerifiedReadyControl, ready)
	if err != nil {
		t.Fatal(err)
	}
	config := sshConfig(t, ssh, invocation.Arguments())
	assertConfigValue(t, config, "hostname", ready.Control.Host)
	assertConfigValue(t, config, "user", ReadyControlUser)
	assertConfigValue(t, config, "port", strconv.Itoa(ready.Control.Port))
	assertConfigValue(t, config, "identityfile", ready.Control.Identity.path)
	if countConfigKey(config, "identityfile") != 1 {
		t.Fatalf("ready Control has more than one configured identity:\n%s", config)
	}
	if strings.Contains(config, strings.ToLower(fixture.controlIdentity.path)) ||
		strings.Contains(config, "proxyjump flow-") ||
		strings.Contains(config, "proxycommand ") {
		t.Fatalf("ready Control resolved a bootstrap key or proxy route:\n%s", config)
	}
	for _, expected := range []string{
		"batchmode yes",
		"identitiesonly yes",
		"identityagent none",
		"stricthostkeychecking true",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"forwardagent no",
		"forwardx11 no",
		"clearallforwardings yes",
		"permitlocalcommand no",
	} {
		if !strings.Contains(config, expected) {
			t.Errorf("ready Control ssh -G missing %q:\n%s", expected, config)
		}
	}
}

func TestSafeCanonicalIPv6EndpointsAreAccepted(t *testing.T) {
	fixture := newFixture(t)
	fixture.route.Control.Host = "2001:db8::1"
	fixture.route.Target.Host = "fd00::2"
	if _, err := fixture.builder.BuildRoutedTarget(fixture.route); err != nil {
		t.Fatalf("canonical IPv6 route: %v", err)
	}
}

type testFixture struct {
	local           *localstate.Store
	builder         *Builder
	controlIdentity PrivateIdentity
	targetIdentity  PrivateIdentity
	route           Route
}

func newFixture(t *testing.T) testFixture {
	t.Helper()
	root := t.TempDir()
	local, err := localstate.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(root, "control-key")
	targetPath := filepath.Join(root, "target-key")
	writePrivateFile(t, controlPath)
	writePrivateFile(t, targetPath)
	controlIdentity, err := NewPrivateIdentity(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := NewPrivateIdentity(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	controlKey, controlHostFingerprint := hostKey(1)
	targetKey, targetHostFingerprint := hostKey(2)
	control := Endpoint{
		Alias: "control", Role: RoleControl, Host: "203.0.113.10", Port: 22, User: "flow-jump",
		Identity: controlIdentity, IdentityFingerprint: fingerprint(11),
		HostKey: controlKey, HostKeyFingerprint: controlHostFingerprint,
	}
	target := Endpoint{
		Alias: "target-a", Role: RoleTarget, Host: "10.20.0.2", Port: 22, User: "admin",
		Identity: targetIdentity, IdentityFingerprint: fingerprint(12),
		HostKey: targetKey, HostKeyFingerprint: targetHostFingerprint,
	}
	return testFixture{
		local: local, builder: NewBuilder(local),
		controlIdentity: controlIdentity, targetIdentity: targetIdentity,
		route: Route{
			Control: control, Target: target,
			ControlHostKeyFingerprint: controlHostFingerprint,
			TargetHostKeyFingerprint:  targetHostFingerprint,
		},
	}
}

func newReadyControl(t *testing.T, fixture testFixture) ReadyControl {
	t.Helper()
	managementPath := filepath.Join(filepath.Dir(fixture.controlIdentity.path), "control-management-key")
	writePrivateFile(t, managementPath)
	managementIdentity, err := NewPrivateIdentity(managementPath)
	if err != nil {
		t.Fatal(err)
	}
	control := fixture.route.Control
	control.User = ReadyControlUser
	control.Identity = managementIdentity
	control.IdentityFingerprint = fingerprint(13)
	return ReadyControl{
		Control: control, ControlHostKeyFingerprint: control.HostKeyFingerprint,
		BootstrapIdentityFingerprint: fixture.route.Control.IdentityFingerprint,
	}
}

func newPendingControlProof(t *testing.T, fixture testFixture) PendingControlProof {
	t.Helper()
	ready := newReadyControl(t, fixture)
	return PendingControlProof{
		Control:                      ready.Control,
		ControlHostKeyFingerprint:    ready.ControlHostKeyFingerprint,
		BootstrapIdentityFingerprint: ready.BootstrapIdentityFingerprint,
		Phase:                        PhasePendingManagementProof,
	}
}

func hostKey(seed byte) (string, string) {
	algorithm := []byte("ssh-ed25519")
	key := bytes.Repeat([]byte{seed}, 32)
	blob := appendSSHString(nil, algorithm)
	blob = appendSSHString(blob, key)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	digest := sha256.Sum256(blob)
	return line, "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func appendSSHString(destination, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	destination = append(destination, size[:]...)
	return append(destination, value...)
}

func fingerprint(seed byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func writePrivateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test-private-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateManagedFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != localstate.FileMode ||
		stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		t.Fatalf("unsafe managed file %s: mode=%v stat=%+v", path, info.Mode(), stat)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sshConfig(t *testing.T, ssh string, arguments []string) string {
	t.Helper()
	output, err := exec.Command(ssh, append([]string{"-G"}, arguments...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G rejected managed transport: %v: %s", err, output)
	}
	return strings.ToLower(string(output))
}

func assertConfigValue(t *testing.T, config, key, value string) {
	t.Helper()
	wanted := strings.ToLower(key + " " + value)
	for _, line := range strings.Split(config, "\n") {
		if strings.TrimSpace(line) == wanted {
			return
		}
	}
	t.Fatalf("ssh -G missing %q:\n%s", wanted, config)
}

func countConfigKey(config, key string) int {
	count := 0
	prefix := strings.ToLower(key) + " "
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			count++
		}
	}
	return count
}
