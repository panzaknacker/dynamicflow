package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"dynamicflow/internal/instances"
	"dynamicflow/internal/sshkeys"
)

func instanceManager(ctx *commandContext) *instances.Manager {
	keys := sshkeys.NewManager(ctx.store)
	return instances.NewManager(ctx.store, keys)
}

// instanceSSHArgs binds use of the previous private generation to the
// operator's local desired-state rotation checkpoint. the low-level instance
// manager defaults to the active key only, so stale private generations can
// never be offered merely because they remain in the audit-preserving key
// store.
func instanceSSHArgs(ctx *commandContext, name string) ([]string, error) {
	manager := instanceManager(ctx)
	record, err := manager.Get(name)
	if err != nil {
		return nil, err
	}
	local, err := loadLocalEnrollment(ctx, name)
	if err != nil {
		return nil, errors.New("live local enrollment metadata is required for SSH")
	}
	if local.State == "revoked" {
		return nil, instances.ErrRevoked
	}
	if local.KeyScope != record.Key.Scope || local.KeyName != record.Key.Name {
		return nil, errors.New("instance SSH identity differs from enrollment metadata")
	}
	active, err := sshkeys.NewManager(ctx.store).Get(local.KeyScope, local.KeyName)
	if err != nil || active.Status != sshkeys.ActiveStatus {
		return nil, errors.New("active instance SSH identity is unavailable")
	}
	switch {
	case active.Generation < local.KeyGeneration:
		return nil, errors.New("active SSH generation is older than enrollment metadata")
	case active.Generation > local.KeyGeneration:
		if active.Generation-local.KeyGeneration != 1 {
			return nil, errors.New("multiple unacknowledged SSH rotations are not safe")
		}
		if local.RotationPending {
			return nil, errors.New("SSH rotation metadata is inconsistent")
		}
		return manager.SSHArgsWithPrevious(name)
	case local.RotationPending:
		return manager.SSHArgsWithPrevious(name)
	default:
		return manager.SSHArgs(name)
	}
}

func commandInstance(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow instance <list|status|logs|apply|bind|hostkey|key|ssh|exec|revoke|secret>")
	}
	switch args[0] {
	case "list":
		return instanceList(ctx, args[1:])
	case "ssh":
		return instanceSSH(ctx, args[1:])
	case "exec":
		return instanceExec(ctx, args[1:])
	case "bind":
		return instanceBind(ctx, args[1:])
	case "hostkey":
		return instanceHostKey(ctx, args[1:])
	case "key":
		return instanceKeyHTTPS(ctx, args[1:])
	case "revoke":
		return instanceRevoke(ctx, args[1:])
	case "secret":
		return instanceSecret(ctx, args[1:])
	case "status", "logs", "apply":
		return instanceHTTPSLifecycle(ctx, args)
	default:
		return usage(ctx, "unknown instance command: "+args[0])
	}
}

func instanceHostKey(ctx *commandContext, args []string) int {
	if len(args) == 0 || (args[0] != "pin" && args[0] != "rotate") {
		return usage(ctx, "usage: flow instance hostkey <pin|rotate> NAME --public-key-file PATH")
	}
	action := args[0]
	flags := newCommandFlagSet(ctx, "instance hostkey "+action)
	publicKeyFile := flags.String("public-key-file", "", "Ed25519 host public key obtained through an authenticated console")
	if err := parseInterspersed(flags, args[1:]); err != nil || flags.NArg() != 1 || *publicKeyFile == "" {
		return usage(ctx, "usage: flow instance hostkey "+action+" NAME --public-key-file PATH")
	}
	name := flags.Arg(0)
	if !validLifecycleName(name) {
		return usage(ctx, "usage: flow instance hostkey "+action+" NAME --public-key-file PATH")
	}

	publicKey, err := readBoundedPublicKeyFile(*publicKeyFile)
	if errors.Is(err, errPublicKeyFileUnsafe) {
		return ctx.out.fail("ssh_host_key", "public host-key file must be a small regular non-symlink file", "Export /etc/ssh/ssh_host_ed25519_key.pub through the provider console and verify its fingerprint out of band.", exitConfig)
	}
	if errors.Is(err, errPublicKeyFileChanged) {
		return ctx.out.fail("ssh_host_key", "public host-key file changed while it was opened", "Repeat with a stable local regular file.", exitConflict)
	}
	if err != nil {
		return ctx.out.fail("ssh_host_key", "could not read a bounded public host key", "Use the single-line Ed25519 host public key only.", exitConfig)
	}
	manager := instanceManager(ctx)
	before, getErr := manager.Get(name)
	var updated instances.Record
	switch action {
	case "pin":
		if getErr != nil && !errors.Is(getErr, instances.ErrNotFound) {
			return ctx.out.fail("ssh_host_key", getErr.Error(), "Repair local instance metadata before changing trust.", exitConfig)
		}
		local, localErr := loadLocalEnrollment(ctx, name)
		if localErr != nil || local.State == "revoked" || local.Host == "" || local.SSHUser == "" || local.SSHPort == 0 {
			return ctx.out.fail("ssh_host_key", "initial host-key pin requires a live local enrollment with a bound SSH endpoint", "Run flow instance bind, then obtain the Ed25519 host public key from the authenticated provider console.", exitConfig)
		}
		updated, err = manager.Put(instances.Record{
			Name: name, Profile: local.Profile, Host: local.Host, SSHPort: local.SSHPort,
			SSHUser: local.SSHUser, Key: instances.KeyRef{Scope: local.KeyScope, Name: local.KeyName},
			HostKey: string(publicKey),
		})
	case "rotate":
		if getErr != nil {
			return ctx.out.fail("ssh_host_key", getErr.Error(), "Pin the initial provider-console-verified host key first.", exitConfig)
		}
		updated, err = manager.RotateHostKey(name, string(publicKey))
	}
	if err != nil {
		audit(ctx, "instance.hostkey."+action, "failure", map[string]any{"instance": name})
		return ctx.out.fail("ssh_host_key", err.Error(), "Verify the Ed25519 key through an authenticated provider console; never use ssh-keyscan as the trust anchor.", exitVerify)
	}
	oldFingerprint := ""
	if getErr == nil {
		oldFingerprint = before.HostKeyFingerprint
	}
	changed := oldFingerprint != updated.HostKeyFingerprint
	audit(ctx, "instance.hostkey."+action, "success", map[string]any{
		"instance": name, "old_fingerprint": oldFingerprint,
		"new_fingerprint": updated.HostKeyFingerprint, "changed": changed,
	})
	data := map[string]any{
		"instance": name, "old_fingerprint": oldFingerprint,
		"new_fingerprint": updated.HostKeyFingerprint, "changed": changed, "network_connection": false,
	}
	human := fmt.Sprintf("Pinned Ed25519 host key for %s: %s (no network connection)", name, updated.HostKeyFingerprint)
	if oldFingerprint != "" {
		human = fmt.Sprintf("Pinned Ed25519 host key for %s: %s -> %s (no network connection)", name, oldFingerprint, updated.HostKeyFingerprint)
	}
	return ctx.out.success("instance.hostkey."+action, data, human)
}

func instanceList(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "instance list")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow instance list")
	}
	records, err := instanceManager(ctx).List()
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Repair instance metadata or create an enrollment.", exitConfig)
	}
	type item struct {
		Name            string        `json:"name"`
		Profile         string        `json:"profile"`
		State           string        `json:"state"`
		Host            string        `json:"host,omitempty"`
		SSHPort         int           `json:"ssh_port,omitempty"`
		SSHUser         string        `json:"ssh_user,omitempty"`
		HostKeyPinned   bool          `json:"host_key_pinned"`
		HostFingerprint string        `json:"host_key_fingerprint,omitempty"`
		SSHKeyScope     sshkeys.Scope `json:"ssh_key_scope"`
		SSHKeyName      string        `json:"ssh_key_name"`
	}
	byName := make(map[string]item, len(records))
	for _, record := range records {
		byName[record.Name] = item{
			Name: record.Name, Profile: record.Profile, State: string(record.Status), Host: record.Host,
			SSHPort: record.SSHPort, SSHUser: record.SSHUser, HostKeyPinned: true,
			HostFingerprint: record.HostKeyFingerprint, SSHKeyScope: record.Key.Scope, SSHKeyName: record.Key.Name,
		}
	}
	localEnrollments, err := listLocalEnrollments(ctx)
	if err != nil {
		return ctx.out.fail("instance", err.Error(), "Repair local enrollment metadata.", exitConfig)
	}
	for _, local := range localEnrollments {
		if _, exists := byName[local.Name]; exists {
			continue
		}
		state := "pending"
		if local.State == "revoked" {
			state = "revoked"
		}
		byName[local.Name] = item{
			Name: local.Name, Profile: local.Profile, State: state, Host: local.Host,
			SSHPort: local.SSHPort, SSHUser: local.SSHUser, HostKeyPinned: false,
			SSHKeyScope: local.KeyScope, SSHKeyName: local.KeyName,
		}
	}
	items := make([]item, 0, len(byName))
	for _, value := range byName {
		items = append(items, value)
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Name < items[right].Name })
	if !ctx.out.json {
		for _, record := range items {
			endpoint := "unbound"
			if record.Host != "" {
				endpoint = fmt.Sprintf("%s@%s:%d", record.SSHUser, record.Host, record.SSHPort)
			}
			fingerprint := "pending"
			if record.HostKeyPinned {
				fingerprint = record.HostFingerprint
			}
			fmt.Fprintf(ctx.out.stdout, "%-20s %-12s %-8s %-32s hostkey=%s\n", record.Name, record.Profile, record.State, endpoint, fingerprint)
		}
		return exitOK
	}
	return ctx.out.success("instance.list", items, "")
}

func listLocalEnrollments(ctx *commandContext) ([]localEnrollment, error) {
	directory, err := ctx.store.Path("enrollments")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []localEnrollment{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]localEnrollment, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			return nil, errors.New("unexpected entry in local enrollment directory")
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		local, err := loadLocalEnrollment(ctx, name)
		if err != nil {
			return nil, err
		}
		result = append(result, local)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func instanceSSH(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "instance ssh")
	gui := flags.Bool("gui", false, "forward only local VNC through SSH")
	localPort := flags.Int("local-port", 5901, "local VNC port with --gui")
	if err := parseInterspersed(flags, args); err != nil || flags.NArg() != 1 || *localPort < 1024 || *localPort > 65535 {
		return usage(ctx, "usage: flow instance ssh NAME [--gui] [--local-port 5901]")
	}
	localPortSet := false
	flags.Visit(func(option *flag.Flag) { localPortSet = localPortSet || option.Name == "local-port" })
	if localPortSet && !*gui {
		return usage(ctx, "--local-port requires --gui")
	}
	if ctx.out.json {
		return ctx.out.fail("usage", "interactive SSH cannot share stdout with --json", "Use flow instance status --json or omit --json.", exitUsage)
	}
	name := flags.Arg(0)
	sshArgs, err := instanceSSHArgs(ctx, name)
	if err != nil {
		return ctx.out.fail("ssh", err.Error(), "Verify local key and pinned hostkey metadata.", exitConfig)
	}
	if *gui {
		sshArgs, err = sshArgsWithVNCForward(sshArgs, *localPort)
		if err != nil {
			return ctx.out.fail("ssh", err.Error(), "Regenerate the managed instance SSH configuration.", exitConfig)
		}
	}
	if err := audit(ctx, "instance.ssh", "started", map[string]any{"instance": name, "gui": *gui, "local_port": *localPort}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; SSH was not started", "Repair the private audit log and retry.", exitFailure)
	}
	command := exec.Command("ssh", sshArgs...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, ctx.out.stdout, ctx.out.stderr
	err = command.Run()
	if err != nil {
		audit(ctx, "instance.ssh", "failure", map[string]any{"instance": name, "error": exitDescription(err)})
		return exitCode(err, exitRemote)
	}
	audit(ctx, "instance.ssh", "success", map[string]any{"instance": name})
	return exitOK
}

func sshArgsWithVNCForward(arguments []string, localPort int) ([]string, error) {
	if localPort < 1 || localPort > 65535 || len(arguments) == 0 {
		return nil, errors.New("invalid managed VNC forwarding arguments")
	}
	args := append([]string(nil), arguments...)
	replaced := 0
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-o" && args[index+1] == "ClearAllForwardings=yes" {
			args[index+1] = "ClearAllForwardings=no"
			replaced++
			index++
		}
	}
	if replaced != 1 {
		return nil, errors.New("managed SSH forwarding policy is missing or ambiguous")
	}
	forward := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:5901", localPort)
	destination := args[len(args)-1]
	args = append(args[:len(args)-1],
		"-o", "ExitOnForwardFailure=yes",
		"-L", forward,
		destination,
	)
	return args, nil
}

func instanceExec(ctx *commandContext, args []string) int {
	separator := -1
	for index, argument := range args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator != 1 || separator+1 >= len(args) {
		return usage(ctx, "usage: flow instance exec NAME -- COMMAND [ARG...]")
	}
	name := args[0]
	remoteCommand := append([]string(nil), args[separator+1:]...)
	for _, argument := range remoteCommand {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return usage(ctx, "remote command arguments must not contain NUL or newlines")
		}
	}
	sshArgs, err := instanceSSHArgs(ctx, name)
	if err != nil {
		return ctx.out.fail("ssh", err.Error(), "Verify local key and pinned hostkey metadata.", exitConfig)
	}
	sshArgs = append(sshArgs, remoteCommand...)
	digest := sha256.Sum256([]byte(strings.Join(remoteCommand, "\x00")))
	auditFields := map[string]any{"instance": name, "argv_sha256": hex.EncodeToString(digest[:]), "argc": len(remoteCommand)}
	if err := audit(ctx, "instance.exec", "started", auditFields); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; remote command was not started", "Repair the private audit log and retry.", exitFailure)
	}
	command := exec.Command("ssh", sshArgs...)
	command.Stdin = os.Stdin
	if !ctx.out.json {
		command.Stdout, command.Stderr = ctx.out.stdout, ctx.out.stderr
		err = command.Run()
	} else {
		var stdout, stderr bytes.Buffer
		command.Stdout = &limitedWriter{writer: &stdout, remaining: 8 << 20}
		command.Stderr = &limitedWriter{writer: &stderr, remaining: 8 << 20}
		err = command.Run()
		status := exitOK
		if err != nil {
			status = exitCode(err, exitRemote)
		}
		data := map[string]any{"instance": name, "exit_code": status, "stdout": stdout.String(), "stderr": stderr.String(), "argv_sha256": auditFields["argv_sha256"]}
		if err != nil {
			audit(ctx, "instance.exec", "failure", auditFields)
			return ctx.out.failData(
				"instance.exec", data, "remote_command", "explicit remote command failed with "+exitDescription(err),
				"Inspect the captured stderr and local audit log; the command was not retried.", status,
			)
		}
		audit(ctx, "instance.exec", "success", auditFields)
		return ctx.out.success("instance.exec", data, "")
	}
	if err != nil {
		audit(ctx, "instance.exec", "failure", auditFields)
		return exitCode(err, exitRemote)
	}
	audit(ctx, "instance.exec", "success", auditFields)
	return exitOK
}

type limitedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *limitedWriter) Write(data []byte) (int, error) {
	original := len(data)
	if writer.remaining <= 0 {
		return original, nil
	}
	if int64(len(data)) > writer.remaining {
		data = data[:writer.remaining]
	}
	_, err := writer.writer.Write(data)
	writer.remaining -= int64(len(data))
	return original, err
}

func instanceRevoke(ctx *commandContext, args []string) int {
	return instanceRevokeHTTPS(ctx, args)
}

func instanceSecret(ctx *commandContext, args []string) int {
	if len(args) == 0 || (args[0] != "reveal" && args[0] != "rotate") {
		return usage(ctx, "usage: flow instance secret <reveal|rotate> NAME --secret vnc")
	}
	action := args[0]
	flags := newCommandFlagSet(ctx, "instance secret "+action)
	secret := flags.String("secret", "", "secret name")
	if err := parseInterspersed(flags, args[1:]); err != nil || flags.NArg() != 1 || *secret != "vnc" {
		return usage(ctx, "usage: flow instance secret "+action+" NAME --secret vnc")
	}
	name := flags.Arg(0)
	sshArgs, err := instanceSSHArgs(ctx, name)
	if err != nil {
		return ctx.out.fail("ssh", err.Error(), "Verify local key and pinned hostkey metadata.", exitConfig)
	}
	if err := audit(ctx, "instance.secret."+action, "started", map[string]any{"instance": name, "secret": "vnc"}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; secret access was not started", "Repair the private audit log and retry.", exitFailure)
	}
	// the remote argv is intentionally fixed and contains neither the
	// credential nor a caller-controlled command. the target binary performs
	// all filesystem and service work in its root-only one-shot.
	sshArgs = append(sshArgs, "sudo", "-n", "/usr/local/bin/flow", "instance-runtime", "secret", action, "--secret", "vnc")
	command := exec.Command("ssh", sshArgs...)
	var stdout vncSecretOutput
	command.Stdout, command.Stderr = &stdout, io.Discard
	if err := command.Run(); err != nil {
		audit(ctx, "instance.secret."+action, "failure", map[string]any{"instance": name, "secret": "vnc"})
		return ctx.out.fail("remote", "the fixed target VNC credential operation failed", "Check the SSH/GUI profile and remote service status; target details contain no credential.", exitRemote)
	}
	value, validOutput := stdout.value()
	if !validOutput || len(value) != 8 || strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) >= 0 {
		audit(ctx, "instance.secret."+action, "failure", map[string]any{"instance": name, "secret": "vnc"})
		return ctx.out.fail("secret", "remote VNC secret did not pass format validation", "Inspect the remote SSH/GUI installation.", exitVerify)
	}
	if err := audit(ctx, "instance.secret."+action, "success", map[string]any{"instance": name, "secret": "vnc"}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit completion could not be committed; the credential was not displayed", "Repair the private audit log and retry the explicit operation.", exitFailure)
	}
	warning := "VNC credentials are sensitive. This deliberate reveal is recorded in the local audit log."
	if !ctx.out.json {
		fmt.Fprintln(ctx.out.stderr, "WARNING: "+warning)
	}
	data := map[string]any{"instance": name, "secret": "vnc", "value": value, "rotated": action == "rotate", "warning": warning}
	return ctx.out.success("instance.secret."+action, data, value)
}

type vncSecretOutput struct {
	data     [9]byte
	written  int
	overflow bool
}

func (output *vncSecretOutput) Write(data []byte) (int, error) {
	original := len(data)
	remaining := len(output.data) - output.written
	if len(data) > remaining {
		output.overflow = true
		data = data[:max(remaining, 0)]
	}
	output.written += copy(output.data[output.written:], data)
	return original, nil
}

func (output *vncSecretOutput) value() (string, bool) {
	if output.overflow || output.written != len(output.data) || output.data[8] != '\n' {
		return "", false
	}
	return string(output.data[:8]), true
}

func exitCode(err error, fallback int) int {
	var exitErr *exec.ExitError
	if err != nil && strings.Contains(fmt.Sprintf("%T", err), "ExitError") {
		if code := commandExitCode(err); code >= 0 {
			return code
		}
	}
	_ = exitErr
	return fallback
}

func commandExitCode(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func exitDescription(err error) string {
	if code := commandExitCode(err); code >= 0 {
		return "exit=" + strconv.Itoa(code)
	}
	return "execution_failed"
}
