// package lab reads the deliberately small, gitignored lab inventory format.
// it is intentionally not a general YAML parser: accepting only the documented
// scalar schema keeps host, user and key-path interpretation unambiguous.
package lab

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var safeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type Inventory struct {
	Version int
	Hosts   []Host
}

type Host struct {
	Name                     string
	Role                     string
	Address                  string
	IPv6                     string
	SSHUser                  string
	OS                       string
	IdentityFile             string
	Disposable               bool
	HostKeyFingerprint       string
	HostKeyVerifiedOutOfBand bool
	AttestedGates            []string
}

func Load(path string) (Inventory, error) {
	before, err := os.Lstat(path)
	if err != nil || !privateFileMetadata(before) {
		return Inventory{}, fmt.Errorf("lab inventory must be a regular owner-only mode-0600 file: %s", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Inventory{}, fmt.Errorf("open private lab inventory: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		syscall.Close(fd)
		return Inventory{}, fmt.Errorf("open private lab inventory")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !privateFileMetadata(opened) {
		return Inventory{}, fmt.Errorf("lab inventory changed while opening")
	}
	result := Inventory{}
	var current *Host
	var currentKeys map[string]bool
	versionSeen := false
	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "hosts:" {
			continue
		}
		if strings.ContainsAny(trimmed, "&*!|>{}[]`") {
			return Inventory{}, fmt.Errorf("unsupported YAML feature on line %d", lineNo)
		}
		if strings.HasPrefix(trimmed, "- name:") {
			if current != nil {
				result.Hosts = append(result.Hosts, *current)
			}
			current = &Host{Name: scalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:")))}
			currentKeys = map[string]bool{"name": true}
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return Inventory{}, fmt.Errorf("invalid inventory syntax on line %d", lineNo)
		}
		value = scalar(strings.TrimSpace(value))
		if current == nil {
			if key != "version" {
				return Inventory{}, fmt.Errorf("unexpected top-level key %q", key)
			}
			if versionSeen {
				return Inventory{}, fmt.Errorf("duplicate inventory version on line %d", lineNo)
			}
			versionSeen = true
			result.Version, err = strconv.Atoi(value)
			if err != nil {
				return Inventory{}, fmt.Errorf("invalid inventory version")
			}
			continue
		}
		if currentKeys[key] {
			return Inventory{}, fmt.Errorf("duplicate host key %q on line %d", key, lineNo)
		}
		currentKeys[key] = true
		switch key {
		case "role":
			current.Role = value
		case "address":
			current.Address = value
		case "ipv6":
			current.IPv6 = value
		case "ssh_user":
			current.SSHUser = value
		case "os":
			current.OS = value
		case "identity_file":
			current.IdentityFile = value
		case "host_key_fingerprint":
			current.HostKeyFingerprint = value
		case "host_key_verified_out_of_band":
			current.HostKeyVerifiedOutOfBand, err = strconv.ParseBool(value)
			if err != nil {
				return Inventory{}, fmt.Errorf("invalid host-key confirmation on line %d", lineNo)
			}
		case "attested_gates":
			current.AttestedGates, err = parseAttestedGates(value)
			if err != nil {
				return Inventory{}, fmt.Errorf("invalid attested gates on line %d: %w", lineNo, err)
			}
		case "disposable":
			current.Disposable, err = strconv.ParseBool(value)
			if err != nil {
				return Inventory{}, fmt.Errorf("invalid disposable value on line %d", lineNo)
			}
		case "known_hosts_file":
			return Inventory{}, fmt.Errorf("known_hosts_file was removed in inventory version 2 on line %d; use host_key_fingerprint plus explicit out-of-band confirmation", lineNo)
		default:
			return Inventory{}, fmt.Errorf("unknown host key %q on line %d", key, lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return Inventory{}, err
	}
	if current != nil {
		result.Hosts = append(result.Hosts, *current)
	}
	if result.Version != 2 {
		return Inventory{}, fmt.Errorf("unsupported lab inventory version %d", result.Version)
	}
	seen := map[string]bool{}
	for i := range result.Hosts {
		if err := validateHost(&result.Hosts[i]); err != nil {
			return Inventory{}, fmt.Errorf("host %d: %w", i+1, err)
		}
		if seen[result.Hosts[i].Name] {
			return Inventory{}, fmt.Errorf("duplicate host %q", result.Hosts[i].Name)
		}
		seen[result.Hosts[i].Name] = true
	}
	if len(result.Hosts) == 0 {
		return Inventory{}, fmt.Errorf("lab inventory contains no hosts")
	}
	return result, nil
}

func scalar(value string) string {
	if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
		return value[1 : len(value)-1]
	}
	return value
}

func validateHost(host *Host) error {
	if !safeName.MatchString(host.Name) || !safeName.MatchString(host.Role) || !safeName.MatchString(host.SSHUser) {
		return fmt.Errorf("name, role and ssh_user must use safe lowercase identifiers")
	}
	allowedGates, knownRole := roleAttestations[host.Role]
	if !knownRole {
		return fmt.Errorf("unsupported lab role %q", host.Role)
	}
	if host.OS == "" || len(host.OS) > 128 || strings.IndexFunc(host.OS, func(value rune) bool { return value < 32 || value == 127 }) >= 0 {
		return fmt.Errorf("os must be a bounded printable value")
	}
	if net.ParseIP(host.Address) == nil {
		return fmt.Errorf("address is not an IP literal")
	}
	if host.IPv6 != "" && net.ParseIP(host.IPv6) == nil {
		return fmt.Errorf("ipv6 is invalid")
	}
	if !filepath.IsAbs(host.IdentityFile) || filepath.Clean(host.IdentityFile) != host.IdentityFile {
		return fmt.Errorf("identity_file must be an absolute normalized path")
	}
	identity, err := os.Lstat(host.IdentityFile)
	if err != nil {
		return fmt.Errorf("identity_file: %w", err)
	}
	if !privateFileMetadata(identity) {
		return fmt.Errorf("identity_file must be a regular owner-only mode-0600 file")
	}
	if !validHostKeyFingerprint(host.HostKeyFingerprint) {
		return fmt.Errorf("host_key_fingerprint must be a canonical Ed25519 SHA256 fingerprint")
	}
	allowed := make(map[string]bool, len(allowedGates))
	for _, gate := range allowedGates {
		allowed[gate] = true
	}
	for _, gate := range host.AttestedGates {
		if !allowed[gate] {
			return fmt.Errorf("attested gate %q is not valid for role %s", gate, host.Role)
		}
	}
	return nil
}

func parseAttestedGates(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	known := map[string]bool{}
	for _, gates := range roleAttestations {
		for _, gate := range gates {
			known[gate] = true
		}
	}
	seen := map[string]bool{}
	values := strings.Split(value, ",")
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
		if !known[values[index]] || seen[values[index]] {
			return nil, fmt.Errorf("unknown or duplicate gate %q", values[index])
		}
		seen[values[index]] = true
	}
	return values, nil
}

func validHostKeyFingerprint(value string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(digest) == 32 && value == prefix+base64.RawStdEncoding.EncodeToString(digest)
}

func privateFileMetadata(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return false
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(metadata.Uid) == os.Geteuid() && metadata.Nlink == 1
}
