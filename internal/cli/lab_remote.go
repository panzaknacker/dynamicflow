package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/lab"
)

const (
	maxLabHarnessBytes = int64(512 << 10)
	maxLabOutputBytes  = int64(1 << 20)
	labHarnessMarker   = "DYNAMICFLOW_PBP_HARNESS_7D3A6E0B"
)

type labSSHExecutor struct {
	sshArgs func(string) ([]string, error)
	harness []byte
	audit   func(action, outcome string, fields map[string]any) error
}

type labRemoteSpec struct {
	argv    []string
	stdin   []byte
	timeout time.Duration
}

func (executor *labSSHExecutor) Run(ctx context.Context, host lab.Host, action lab.Action) (lab.RemoteResult, error) {
	if executor == nil || executor.sshArgs == nil || executor.audit == nil || !lab.IsFixedAction(action) {
		return lab.RemoteResult{}, errors.New("invalid fixed lab action")
	}
	sshArgs, err := executor.sshArgs(host.Name)
	if err != nil {
		return lab.RemoteResult{}, errors.New("pinned SSH binding is unavailable")
	}
	spec, err := buildLabRemoteSpec(action, executor.harness)
	if err != nil {
		return lab.RemoteResult{}, err
	}
	sshArgs = append(sshArgs, spec.argv...)
	operation := ctx
	cancel := func() {}
	if spec.timeout > 0 {
		operation, cancel = context.WithTimeout(ctx, spec.timeout)
	}
	defer cancel()
	digest := sha256.Sum256(append(append([]byte(strings.Join(spec.argv, "\x00")), 0), spec.stdin...))
	fields := map[string]any{"instance": host.Name, "action": action, "fixed_payload_sha256": hex.EncodeToString(digest[:])}
	if err := executor.audit("test.lab.remote", "started", fields); err != nil {
		return lab.RemoteResult{}, errors.New("could not persist fixed remote action start audit")
	}
	command := exec.CommandContext(operation, "ssh", sshArgs...)
	if len(spec.stdin) != 0 {
		command.Stdin = bytes.NewReader(spec.stdin)
	} else {
		command.Stdin = nil
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: maxLabOutputBytes + 1}
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 64 << 10}
	err = command.Run()
	if err != nil {
		// systemctl may close the SSH transport immediately after it accepted
		// the fixed reboot request. The pre-close acknowledgement is the only
		// error-path output accepted by this action; readiness is checked later.
		if action == lab.ActionReboot && strings.TrimSpace(stdout.String()) == "reboot-requested" {
			fields["transport_closed_after_ack"] = true
			_ = executor.audit("test.lab.remote", "success", fields)
			return lab.RemoteResult{State: lab.RemoteReady}, nil
		}
		fields["exit"] = exitDescription(err)
		stderrDigest := sha256.Sum256(stderr.Bytes())
		fields["stderr_sha256"] = hex.EncodeToString(stderrDigest[:])
		_ = executor.audit("test.lab.remote", "failure", fields)
		return lab.RemoteResult{}, fmt.Errorf("fixed action %s failed (%s)", action, exitDescription(err))
	}
	if int64(stdout.Len()) > maxLabOutputBytes {
		_ = executor.audit("test.lab.remote", "invalid-output", fields)
		return lab.RemoteResult{}, errors.New("remote lab output exceeded bound")
	}
	result, err := parseLabRemoteOutput(action, stdout.Bytes())
	if err != nil {
		_ = executor.audit("test.lab.remote", "invalid-output", fields)
		return lab.RemoteResult{}, err
	}
	_ = executor.audit("test.lab.remote", "success", fields)
	return result, nil
}

func buildLabRemoteSpec(action lab.Action, harness []byte) (labRemoteSpec, error) {
	quick := 2 * time.Minute
	script := ""
	switch action {
	case lab.ActionPreflight:
		script = labPreflightScript
	case lab.ActionServingProbe:
		script = labServingProbeScript
	case lab.ActionServingReconcile:
		script = labServingReconcileScript
		quick = 4 * time.Minute
	case lab.ActionServingRestart:
		script = labServingRestartScript
	case lab.ActionRuntimeProbe:
		script = labRuntimeProbeScript
	case lab.ActionEnrollmentProbe:
		script = labEnrollmentProbeScript
	case lab.ActionRecoveryProbe:
		script = labRecoveryProbeScript
		quick = 4 * time.Minute
	case lab.ActionApplyConcurrency:
		script = labApplyConcurrencyScript
		quick = 20 * time.Minute
	case lab.ActionReboot:
		script = labRebootScript
		quick = 45 * time.Second
	case lab.ActionReachable:
		script = labReachableScript
		quick = 30 * time.Second
	case lab.ActionVNCProbe:
		script = labVNCProbeScript
	case lab.ActionPBPProbe:
		script = labPBPProbeScript
	case lab.ActionPBPIdentity:
		script = labPBPIdentityScript
	case lab.ActionPBPSoakStart:
		if len(harness) == 0 || int64(len(harness)) > maxLabHarnessBytes || bytes.Contains(harness, []byte(labHarnessMarker)) {
			return labRemoteSpec{}, errors.New("invalid bounded PBP harness")
		}
		var payload bytes.Buffer
		payload.WriteString(labPBPSoakStartPrefix)
		payload.WriteString("cat >\"$harness_stage\" <<'")
		payload.WriteString(labHarnessMarker)
		payload.WriteString("'\n")
		payload.Write(harness)
		if len(harness) == 0 || harness[len(harness)-1] != '\n' {
			payload.WriteByte('\n')
		}
		payload.WriteString(labHarnessMarker)
		payload.WriteByte('\n')
		payload.WriteString(labPBPSoakStartSuffix)
		return labRemoteSpec{argv: []string{"sudo", "-n", "/bin/bash", "-s"}, stdin: payload.Bytes(), timeout: quick}, nil
	case lab.ActionPBPSoakPoll:
		script = labPBPSoakPollScript
		quick = 45 * time.Second
	case lab.ActionPBPForensics:
		script = labPBPForensicsScript
		quick = 6 * time.Minute
	case lab.ActionPBPSoakResult:
		script = labPBPSoakResultScript
		quick = 4 * time.Minute
	default:
		return labRemoteSpec{}, errors.New("unsupported lab action")
	}
	return labRemoteSpec{argv: []string{"sudo", "-n", "/bin/bash", "-s"}, stdin: []byte(script), timeout: quick}, nil
}

func parseLabRemoteOutput(action lab.Action, output []byte) (lab.RemoteResult, error) {
	if len(output) > int(maxLabOutputBytes) {
		return lab.RemoteResult{}, errors.New("remote lab output exceeded bound")
	}
	trimmed := strings.TrimSpace(string(output))
	expected := map[lab.Action]string{
		lab.ActionPreflight: "preflight-ok", lab.ActionServingProbe: "serving-ok",
		lab.ActionServingReconcile: "serving-reconcile-ok",
		lab.ActionServingRestart:   "serving-restart-ok", lab.ActionRuntimeProbe: "runtime-ok",
		lab.ActionEnrollmentProbe: "enrollment-evidence-ok", lab.ActionRecoveryProbe: "recovery-evidence-ok",
		lab.ActionApplyConcurrency: "apply-concurrency-ok",
		lab.ActionReboot:           "reboot-requested", lab.ActionReachable: "reachable-ok",
		lab.ActionVNCProbe: "vnc-loopback-ok", lab.ActionPBPProbe: "pbp-vpn-ok",
		lab.ActionPBPSoakStart: "soak-started",
	}
	if value, ok := expected[action]; ok {
		state := lab.RemoteReady
		if action == lab.ActionPBPSoakStart {
			state = lab.RemoteRunning
		}
		if trimmed != value {
			return lab.RemoteResult{}, errors.New("remote fixed action returned unexpected output")
		}
		return lab.RemoteResult{State: state}, nil
	}
	if action == lab.ActionPBPIdentity {
		const prefix = "pbp-identity:"
		if !strings.HasPrefix(trimmed, prefix) || len(trimmed) != len(prefix)+64 {
			return lab.RemoteResult{}, errors.New("invalid PBP identity probe result")
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(trimmed, prefix))
		if err != nil || len(digest) != sha256.Size {
			return lab.RemoteResult{}, errors.New("invalid PBP identity probe digest")
		}
		return lab.RemoteResult{State: lab.RemoteReady, Data: digest}, nil
	}
	if action == lab.ActionPBPSoakPoll {
		switch trimmed {
		case "soak-running":
			return lab.RemoteResult{State: lab.RemoteRunning}, nil
		case "soak-complete":
			return lab.RemoteResult{State: lab.RemoteComplete}, nil
		default:
			return lab.RemoteResult{}, errors.New("invalid soak poll result")
		}
	}
	if action == lab.ActionPBPForensics {
		if len(output) == 0 {
			return lab.RemoteResult{}, errors.New("empty PBP forensics result")
		}
		return lab.RemoteResult{State: lab.RemoteComplete, Data: append([]byte(nil), output...)}, nil
	}
	if action == lab.ActionPBPSoakResult {
		if len(output) == 0 {
			return lab.RemoteResult{}, errors.New("empty soak result")
		}
		return lab.RemoteResult{State: lab.RemoteComplete, Data: append([]byte(nil), output...)}, nil
	}
	return lab.RemoteResult{}, errors.New("unexpected remote action output")
}

func loadLabHarness(sourceRoot string) ([]byte, error) {
	if sourceRoot == "" || !filepath.IsAbs(sourceRoot) {
		return nil, errors.New("source root is required for the real PBP harness")
	}
	path := filepath.Join(sourceRoot, "pbp", "tests", "pbp-vm-soak.py")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxLabHarnessBytes {
		return nil, errors.New("PBP harness must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not open PBP harness")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return nil, errors.New("PBP harness changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLabHarnessBytes+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maxLabHarnessBytes {
		return nil, errors.New("could not read bounded PBP harness")
	}
	required := []string{
		"MINIMUM_SOAK_SECONDS = 30 * 60", "--exercise-vpn-failure", "--disposable-network-test",
		"signal.SIGKILL", "windowclose", "DYNAMICFLOW_LAB_VPN_TRIGGER",
		`metrics["real_relay_switch"] = True`, `metrics["egress_identity_changed"] = True`,
		`metrics["restart_after_relay_switch"] = True`,
	}
	for _, contract := range required {
		if !bytes.Contains(data, []byte(contract)) {
			return nil, fmt.Errorf("PBP harness is missing qualifying contract %q", contract)
		}
	}
	if bytes.Contains(data, []byte(labHarnessMarker)) || bytes.Contains(data, []byte("PRIVATE KEY-----")) {
		return nil, errors.New("PBP harness contains prohibited marker material")
	}
	return data, nil
}

const labPreflightScript = `set -Eeuo pipefail
set +x
umask 077
[ "$(id -u)" -ne 0 ]
sudo -n true
[ -x /usr/local/bin/flow ] && [ ! -L /usr/local/bin/flow ]
[ "$(stat -c '%u' /usr/local/bin/flow)" = 0 ]
mode="$(stat -c '%a' /usr/local/bin/flow)"
(( (8#$mode & 0022) == 0 ))
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] && [ ! -L /etc/ssh/ssh_host_ed25519_key.pub ]
printf '%s\n' preflight-ok
`

const labServingHelpers = `config=/var/lib/dynamicflow-serving/config.json
service=dynamicflow-serving.service
[ -f "$config" ] && [ ! -L "$config" ]
[ "$(stat -c '%u:%a' "$config")" = '0:640' ]
systemctl is-enabled --quiet "$service"
systemctl is-active --quiet "$service"
pid="$(systemctl show --property MainPID --value "$service")"
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
public_url="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1], encoding="utf-8")); u=c.get("public_url", ""); assert isinstance(u,str) and u.startswith("https://") and "?" not in u and "#" not in u; print(u.rstrip("/"))' "$config")"
health="$(curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --cacert /var/lib/dynamicflow-serving/tls/serving.crt "$public_url/v1/health")"
printf '%s' "$health" | python3 -c 'import json,re,sys; v=json.load(sys.stdin); assert v.get("status")=="ok" and re.fullmatch(r"sha256:[0-9a-f]{64}",v.get("release_set","")); assert all(re.fullmatch(r"[0-9a-f]{64}",v.get(k,"")) for k in ("release_key_id","desired_key_id","control_key_id"))'
python3 - "$pid" <<'PY'
import os, pathlib, socket, sys
root=int(sys.argv[1]); pending=[root]; seen=set(); inodes=set()
while pending:
    pid=pending.pop()
    if pid in seen: continue
    seen.add(pid)
    try:
        exe=pathlib.Path(f"/proc/{pid}/exe").resolve().name
        if exe in {"ssh","scp","sftp"}: raise SystemExit(20)
        for fd in pathlib.Path(f"/proc/{pid}/fd").iterdir():
            try: link=os.readlink(fd)
            except OSError: continue
            if link.startswith("socket:[") and link.endswith("]"): inodes.add(link[8:-1])
        children=pathlib.Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        pending.extend(int(value) for value in children)
    except FileNotFoundError:
        continue
for table in ("/proc/net/tcp","/proc/net/tcp6"):
    try: lines=pathlib.Path(table).read_text().splitlines()[1:]
    except OSError: continue
    for line in lines:
        fields=line.split()
        if len(fields)>9 and fields[9] in inodes and fields[3]=="01":
            remote_port=int(fields[2].rsplit(":",1)[1],16)
            if remote_port==22: raise SystemExit(21)
PY
`

const labServingProbeScript = `set -Eeuo pipefail
set +x
umask 077
` + labServingHelpers + `
printf '%s\n' serving-ok
`

const labServingReconcileScript = `set -Eeuo pipefail
set +x
umask 077
flow=/usr/local/bin/flow
home=/var/lib/dynamicflow-serving-operator
service=dynamicflow-serving.service
[ -x "$flow" ] && [ ! -L "$flow" ]
[ -d "$home" ] && [ ! -L "$home" ]
systemctl is-active --quiet "$service"
before="$(systemctl show --property MainPID --value "$service")"
plan="$("$flow" --json --home "$home" start serving --plan)"
printf '%s' "$plan" | /usr/bin/python3 -c '
import json, sys
value = json.load(sys.stdin)
data = value.get("data", {})
assert value.get("ok") is True
assert value.get("command") == "start.serving.plan"
assert data.get("plan") is True and data.get("state") == "noop"
assert data.get("changed") is False and data.get("unsafe") is False
assert data.get("complete") is True and data.get("applicable") is True
'
unset plan
for attempt in 1 2; do
  result="$("$flow" --json --home "$home" start serving)"
  printf '%s' "$result" | /usr/bin/python3 -c '
import json, sys
value = json.load(sys.stdin)
data = value.get("data", {})
assert value.get("ok") is True
assert value.get("command") == "start.serving"
assert data.get("changed") is False and data.get("active") is True
'
  unset result
  systemctl is-active --quiet "$service"
  [ "$(systemctl show --property MainPID --value "$service")" = "$before" ]
done
` + labServingHelpers + `
printf '%s\n' serving-reconcile-ok
`

const labServingRestartScript = `set -Eeuo pipefail
set +x
umask 077
service=dynamicflow-serving.service
systemctl is-active --quiet "$service"
before="$(systemctl show --property MainPID --value "$service")"
systemctl restart "$service"
systemctl is-active --quiet "$service"
after="$(systemctl show --property MainPID --value "$service")"
[[ "$before" =~ ^[1-9][0-9]*$ && "$after" =~ ^[1-9][0-9]*$ && "$before" != "$after" ]]
` + labServingHelpers + `
stable="$(systemctl show --property MainPID --value "$service")"
systemctl start "$service"
systemctl is-active --quiet "$service"
[ "$(systemctl show --property MainPID --value "$service")" = "$stable" ]
printf '%s\n' serving-restart-ok
`

const labRuntimeProbeScript = `set -Eeuo pipefail
set +x
umask 077
service=dynamicflow-instance-reconcile.service
timer=dynamicflow-instance-reconcile.timer
systemctl is-enabled --quiet "$timer"
systemctl is-active --quiet "$timer"
systemctl cat "$service" | grep -Fqx 'ExecStart=/usr/local/bin/flow instance-runtime reconcile --state-root /var/lib/dynamicflow/instance'
status="$(/usr/local/bin/flow --json instance-runtime status --state-root /var/lib/dynamicflow/instance)"
printf '%s' "$status" | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v.get("ok") is True and v.get("command")=="instance-runtime.status"; d=v.get("data",{}); assert d.get("enrolled") is True and d.get("revoked") is False and d.get("profile_applied") is True and d.get("applied_generation")==d.get("desired_generation")'
printf '%s\n' runtime-ok
`

const labEnrollmentProbeScript = `set -Eeuo pipefail
set +x
umask 077
root=/var/lib/dynamicflow/instance
config="$root/runtime-config.json"
[ -f "$config" ] && [ ! -L "$config" ]
[ "$(stat -c "%u:%a:%h" "$config")" = "0:600:1" ]
admin="$(/usr/bin/python3 - "$config" <<DYNAMICFLOW_LAB_ENROLLMENT_CONFIG_3A57C119
import json
import os
import re
import stat
import sys

def unique(pairs):
    value = {}
    for key, nested in pairs:
        if key in value:
            raise SystemExit(31)
        value[key] = nested
    return value

path = sys.argv[1]
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags)
try:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1 or details.st_size < 1 or details.st_size > 65536:
        raise SystemExit(32)
    raw = os.read(fd, details.st_size + 1)
finally:
    os.close(fd)
value = json.loads(raw, object_pairs_hook=unique)
expected = {"schema", "server", "tls_ca", "tls_pin", "release_public_key", "desired_public_key", "state_root", "instance", "profile", "admin_user", "identity_key_id", "request_timeout", "enrolled_at"}
if set(value) != expected or value.get("schema") != 2 or value.get("state_root") != "/var/lib/dynamicflow/instance":
    raise SystemExit(33)
admin = value.get("admin_user")
if not isinstance(admin, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", admin) or admin in {"root", "malwarelab"}:
    raise SystemExit(34)
print(admin)
DYNAMICFLOW_LAB_ENROLLMENT_CONFIG_3A57C119
)"
[ -n "$admin" ]
uid="$(id -u "$admin")"
home="$(getent passwd "$admin" | cut -d: -f6)"
[ "$home" = "/home/$admin" ]
ssh_dir="$home/.ssh"
authorized="$ssh_dir/authorized_keys"
[ -d "$ssh_dir" ] && [ ! -L "$ssh_dir" ]
[ "$(stat -c "%u:%a:%h" "$ssh_dir")" = "$uid:700:1" ]
[ -f "$authorized" ] && [ ! -L "$authorized" ]
[ "$(stat -c "%u:%a:%h" "$authorized")" = "$uid:600:1" ]
/usr/bin/python3 - "$authorized" "$uid" <<DYNAMICFLOW_LAB_AUTHORIZED_KEY_4E6210AF
import base64
import os
import stat
import struct
import sys

path, expected_uid = sys.argv[1], int(sys.argv[2])
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags)
try:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != expected_uid or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1 or details.st_size < 1 or details.st_size > 8192:
        raise SystemExit(36)
    raw = os.read(fd, details.st_size + 1)
finally:
    os.close(fd)
lines = [line for line in raw.decode("ascii").splitlines() if line.strip()]
if len(lines) != 1:
    raise SystemExit(37)
fields = lines[0].split()
if len(fields) not in (2, 3) or fields[0] != "ssh-ed25519":
    raise SystemExit(38)
blob = base64.b64decode(fields[1], validate=True)
def take(value):
    if len(value) < 4:
        raise SystemExit(39)
    size = struct.unpack(">I", value[:4])[0]
    if size > len(value) - 4:
        raise SystemExit(39)
    return value[4:4 + size], value[4 + size:]
algorithm, rest = take(blob)
key, rest = take(rest)
if algorithm != b"ssh-ed25519" or len(key) != 32 or rest:
    raise SystemExit(39)
DYNAMICFLOW_LAB_AUTHORIZED_KEY_4E6210AF
for name in id_ed25519 id_ed25519_sk id_ecdsa id_ecdsa_sk id_rsa identity.pem; do
  [ ! -e "$ssh_dir/$name" ] && [ ! -L "$ssh_dir/$name" ]
done
printf "%s\n" enrollment-evidence-ok
`

const labRecoveryProbeScript = `set -Eeuo pipefail
set +x
umask 077
export LC_ALL=C
root=/var/lib/dynamicflow/instance
apply="$root/apply"
checkpoint="$apply/checkpoint.json"
journal="$apply/apply.json"
history="$apply/history"
staging="$apply/staging"
recovery="$apply/runtime-recovery"
for file in "$checkpoint" "$journal"; do
  [ -f "$file" ] && [ ! -L "$file" ]
  [ "$(stat -c "%u:%a:%h" "$file")" = "0:600:1" ]
done
for directory in "$apply" "$staging" "$recovery"; do
  [ -d "$directory" ] && [ ! -L "$directory" ]
  [ "$(stat -c "%u:%a" "$directory")" = "0:700" ]
done
/usr/bin/python3 - "$checkpoint" "$journal" "$history" "$staging" "$recovery" /usr/local/bin/flow <<DYNAMICFLOW_LAB_RECOVERY_EVIDENCE_63B209D4
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

checkpoint_path, journal_path, history_path, staging_path, recovery_path, flow_path = map(pathlib.Path, sys.argv[1:])
digest_re = re.compile(r"^sha256:[0-9a-f]{64}$")
history_re = re.compile(r"^[0-9]{20}-[0-9a-f]{16}[.]json$")
recovery_re = re.compile(r"^[0-9a-f]{64}[.]flow$")

def unique(pairs):
    value = {}
    for key, nested in pairs:
        if key in value:
            raise RuntimeError("duplicate JSON key")
        value[key] = nested
    return value

def open_regular(path, mode, maximum):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or stat.S_IMODE(details.st_mode) != mode or details.st_nlink != 1 or details.st_size < 1 or details.st_size > maximum:
        os.close(fd)
        raise RuntimeError("unsafe bounded evidence")
    return fd, details

def read_json(path):
    fd, details = open_regular(path, 0o600, 1048576)
    try:
        chunks = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(fd, min(131072, remaining))
            if not chunk:
                raise RuntimeError("short evidence read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (details.st_ino, details.st_size, details.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError("evidence changed while reading")
    finally:
        os.close(fd)
    return json.loads(b"".join(chunks), object_pairs_hook=unique)

def hash_regular(path, mode):
    fd, details = open_regular(path, mode, 268435456)
    digest = hashlib.sha256()
    try:
        remaining = details.st_size
        while remaining:
            chunk = os.read(fd, min(131072, remaining))
            if not chunk:
                raise RuntimeError("short runtime read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (details.st_ino, details.st_size, details.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError("runtime changed while reading")
    finally:
        os.close(fd)
    return digest.hexdigest()

def valid_complete_journal(value):
    if value.get("schema") != 1 or not digest_re.fullmatch(value.get("plan_digest", "")):
        return False
    plan = value.get("plan")
    phases = value.get("phases")
    if not isinstance(plan, dict) or not isinstance(plan.get("generation"), int) or plan["generation"] < 1 or not isinstance(phases, list) or not phases:
        return False
    names = plan.get("phases")
    if not isinstance(names, list) or len(names) != len(phases):
        return False
    for index, phase in enumerate(phases):
        if not isinstance(phase, dict) or phase.get("name") != names[index] or phase.get("status") != "complete" or not isinstance(phase.get("attempts"), int) or phase["attempts"] < 1:
            return False
    return True

checkpoint = read_json(checkpoint_path)
current = read_json(journal_path)
if checkpoint.get("schema") != 1 or not valid_complete_journal(current):
    raise SystemExit(40)
if checkpoint.get("desired_generation") != current.get("plan", {}).get("generation"):
    raise SystemExit(41)
interrupted_resume = any(phase.get("attempts", 0) >= 2 for phase in current["phases"])
if history_path.exists():
    details = history_path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or stat.S_IMODE(details.st_mode) != 0o700:
        raise SystemExit(42)
    entries = sorted(history_path.iterdir())
    if len(entries) > 128:
        raise SystemExit(43)
    for entry in entries:
        if not history_re.fullmatch(entry.name):
            raise SystemExit(44)
        previous = read_json(entry)
        if not valid_complete_journal(previous):
            raise SystemExit(45)
        interrupted_resume = interrupted_resume or any(phase.get("attempts", 0) >= 2 for phase in previous["phases"])
if not interrupted_resume:
    raise SystemExit(46)
if any(staging_path.iterdir()):
    raise SystemExit(47)
entries = sorted(recovery_path.iterdir())
if len(entries) < 2 or len(entries) > 64:
    raise SystemExit(48)
seen = set()
for entry in entries:
    if not recovery_re.fullmatch(entry.name) or hash_regular(entry, 0o700) + ".flow" != entry.name:
        raise SystemExit(49)
    seen.add(entry.name)
if hash_regular(flow_path, 0o755) + ".flow" not in seen:
    raise SystemExit(50)
DYNAMICFLOW_LAB_RECOVERY_EVIDENCE_63B209D4
[ -f "$apply/targetapply.lock" ] && [ ! -L "$apply/targetapply.lock" ]
[ "$(stat -c "%u:%a:%h" "$apply/targetapply.lock")" = "0:600:1" ]
exec 8<>"$apply/targetapply.lock"
flock -n 8
flock -u 8
exec 8>&-
[ -f "$apply/apply.lock" ] && [ ! -L "$apply/apply.lock" ]
[ "$(stat -c "%u:%a:%h" "$apply/apply.lock")" = "0:600:1" ]
exec 9<>"$apply/apply.lock"
flock -n 9
flock -u 9
exec 9>&-
journal_data="$(journalctl --unit dynamicflow-instance-reconcile.service --no-pager --output=cat --lines=4097)"
line_count="$(printf "%s\n" "$journal_data" | awk "END {print NR}")"
[ "$line_count" -le 4096 ]
verification_count="$(printf "%s\n" "$journal_data" | grep -Ec "ERROR \[verification\]:|\"code\":\"verification\"" || true)"
unset journal_data
[ "$verification_count" -ge 2 ]
printf "%s\n" recovery-evidence-ok
`

const labApplyConcurrencyScript = `set -Eeuo pipefail
set +x
umask 077
root=/var/lib/dynamicflow/instance
lock="$root/apply/targetapply.lock"
[ -f "$lock" ] && [ ! -L "$lock" ]
[ "$(stat -c "%u:%a:%h" "$lock")" = "0:600:1" ]
! systemctl is-active --quiet dynamicflow-instance-reconcile.service
exec 9<>"$lock"
flock -n 9
set +e
contender="$(/usr/local/bin/flow --json instance-runtime reconcile --state-root "$root" 2>&1)"
contender_status=$?
set -e
[ "$contender_status" -eq 6 ]
printf "%s" "$contender" | /usr/bin/python3 -c "
import json, sys
def unique(pairs):
    value = {}
    for key, nested in pairs:
        if key in value: raise SystemExit(61)
        value[key] = nested
    return value
value = json.load(sys.stdin, object_pairs_hook=unique)
assert value.get(\"ok\") is False
assert value.get(\"command\") == \"instance-runtime.reconcile\"
assert value.get(\"error\", {}).get(\"code\") == \"apply_busy\"
"
flock -u 9
exec 9>&-
resume="$(/usr/local/bin/flow --json instance-runtime reconcile --state-root "$root")"
printf "%s" "$resume" | /usr/bin/python3 -c "
import json, sys
def unique(pairs):
    value = {}
    for key, nested in pairs:
        if key in value: raise SystemExit(62)
        value[key] = nested
    return value
value = json.load(sys.stdin, object_pairs_hook=unique)
data = value.get(\"data\", {})
assert value.get(\"ok\") is True
assert value.get(\"command\") == \"instance-runtime.reconcile\"
assert data.get(\"profile_applied\") is True
assert data.get(\"applied_generation\") == data.get(\"desired_generation\")
"
exec 8<>"$lock"
flock -n 8
flock -u 8
exec 8>&-
printf "%s\n" apply-concurrency-ok
`

const labRebootScript = `set -Eeuo pipefail
set +x
umask 077
systemctl reboot --no-wall --no-block
printf '%s\n' reboot-requested
`

const labReachableScript = `set -Eeuo pipefail
set +x
systemctl is-system-running --wait >/dev/null 2>&1 || [ "$(systemctl is-system-running)" = degraded ]
printf '%s\n' reachable-ok
`

const labVNCProbeScript = `set -Eeuo pipefail
set +x
umask 077
systemctl is-active --quiet 'tigervncserver@:1.service'
listeners="$(ss -H -ltn 'sport = :5901')"
printf '%s\n' "$listeners" | awk '
  $4 == "127.0.0.1:5901" {v4=1; next}
  $4 == "[::1]:5901" || $4 == "::1:5901" {next}
  NF {bad=1}
  END {exit !(v4 && !bad)}'
uid="$(id -u malwarelab)"
[ -f /home/malwarelab/.Xauthority ] && [ ! -L /home/malwarelab/.Xauthority ]
[ "$(stat -c '%u:%a' /home/malwarelab/.Xauthority)" = "$uid:600" ]
for setting in AcceptCutText SendCutText SendPrimary SetPrimary; do
  value="$(runuser -u malwarelab -- env DISPLAY=:1 XAUTHORITY=/home/malwarelab/.Xauthority tigervncconfig -get "$setting")"
  case "${value,,}" in 0|off|no|false) ;; *) exit 30;; esac
done
session="$(pgrep -o -u malwarelab -x xfce4-session)"
tr '\0' '\n' <"/proc/$session/environ" | grep -Fqx 'DISPLAY=:1'
tr '\0' '\n' <"/proc/$session/environ" | grep -Fqx 'XAUTHORITY=/home/malwarelab/.Xauthority'
printf '%s\n' vnc-loopback-ok
`

const labPBPProbeScript = `set -Eeuo pipefail
set +x
umask 077
[ -x /usr/local/bin/pbp-browser ] && [ ! -L /usr/local/bin/pbp-browser ]
current="$(readlink -f /opt/toolkit/pbp/current)"
case "$current" in /opt/toolkit/pbp/releases/*) ;; *) exit 40;; esac
[ "$(tr -d '\r\n' <"$current/VERSION")" = v0.1.9 ]
[ -f /etc/toolkit/pbp-persona.json ] && [ ! -L /etc/toolkit/pbp-persona.json ]
[ "$(stat -c '%u:%a' /etc/toolkit/pbp-persona.json)" = '0:644' ]
auto="$(timeout --foreground 20s /usr/bin/mullvad auto-connect get)"
lockdown="$(timeout --foreground 20s /usr/bin/mullvad lockdown-mode get)"
grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$auto"
grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$lockdown"
settings="$(timeout --foreground 20s /usr/bin/mullvad anti-censorship get)"
grep -Fxq 'mode: shadowsocks' <<<"$settings"
grep -Fxq 'shadowsocks settings: port 443' <<<"$settings"
status="$(timeout --foreground 20s /usr/bin/mullvad status --json)"
printf '%s' "$status" | jq -e '.state == "connected" and .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks" and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))' >/dev/null
egress="$(runuser -u malwarelab -- env HOME=/home/malwarelab curl -4 --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 https://am.i.mullvad.net/json)"
printf '%s' "$egress" | jq -e '.mullvad_exit_ip == true and .country == "Germany"' >/dev/null
if runuser -u malwarelab -- test -r /var/run/mullvad-vpn; then exit 41; fi
printf '%s\n' pbp-vpn-ok
`

const labPBPIdentityScript = `set -Eeuo pipefail
set +x
umask 077
/usr/bin/python3 - <<'DYNAMICFLOW_LAB_PBP_IDENTITY_74BA20E1'
import hashlib
import json
import os
import stat

path = "/etc/toolkit/pbp-persona.json"
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1 or before.st_size < 1 or before.st_size > 1048576:
        raise SystemExit(70)
    raw = os.read(fd, before.st_size + 1)
    after = os.fstat(fd)
finally:
    os.close(fd)
if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
    raise SystemExit(71)
value = json.loads(raw)
keys = ("persona_id", "browser_version", "browser_major", "camoufox_package_version", "os", "locale", "timezone", "preset", "config", "firefox_user_prefs")
if value.get("schema") != 2 or set(keys) - set(value):
    raise SystemExit(72)
stable = json.dumps({key: value[key] for key in keys}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
record = b"\0".join((
    str(before.st_dev).encode("ascii"),
    str(before.st_ino).encode("ascii"),
    str(before.st_size).encode("ascii"),
    hashlib.sha256(raw).hexdigest().encode("ascii"),
    hashlib.sha256(stable).hexdigest().encode("ascii"),
))
print("pbp-identity:" + hashlib.sha256(record).hexdigest())
DYNAMICFLOW_LAB_PBP_IDENTITY_74BA20E1
`

const labPBPSoakStartPrefix = `set -Eeuo pipefail
set +x
umask 077
harness_stage=/run/dynamicflow-lab-pbp-soak.py
started_stage=/run/dynamicflow-lab-pbp-soak-started.stage
helper_stage=/run/dynamicflow-lab-pbp-vpn-trigger.py
pointer=/run/dynamicflow-lab-pbp-result
socket_path=/run/dynamicflow-lab-pbp-vpn.sock
started_marker=/run/dynamicflow-lab-pbp-soak-started
soak_unit=dynamicflow-lab-pbp-soak.service
helper_unit=dynamicflow-lab-pbp-vpn-trigger.service
for unit in "$soak_unit" "$helper_unit"; do
  if systemctl is-active --quiet "$unit"; then exit 50; fi
done
for path in "$harness_stage" "$helper_stage" "$pointer" "$socket_path" "$started_marker" "$started_stage"; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    [ ! -L "$path" ] || exit 51
    owner="$(stat -c '%u' "$path")"
    [ "$owner" = 0 ] || exit 51
    rm -f -- "$path"
  fi
done
cat >"$helper_stage" <<'DYNAMICFLOW_VPN_HELPER_9B18A7C2'
#!/usr/bin/python3
import ipaddress, json, os, pathlib, pwd, signal, socket, struct, subprocess, time
SOCKET = "/run/dynamicflow-lab-pbp-vpn.sock"
SOAK_UNIT = "dynamicflow-lab-pbp-soak.service"
STARTED_MARKER = pathlib.Path("/run/dynamicflow-lab-pbp-soak-started")
uid = pwd.getpwnam("malwarelab").pw_uid
gid = pwd.getpwnam("malwarelab").pw_gid
deadline = time.monotonic() + 3900
state = "disconnect"
interrupted = False
seen_soak = False
def stop(_signum, _frame):
    global interrupted
    interrupted = True
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
def mullvad(action):
    completed = subprocess.run(
        ["/usr/bin/timeout", "--foreground", "180s", "/usr/bin/mullvad", action, "--wait"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin"}, check=False, timeout=190,
    )
    return completed.returncode == 0
def egress_identity():
    completed = subprocess.run(
        [
            "/usr/sbin/runuser", "-u", "malwarelab", "--",
            "/usr/bin/env", "HOME=/home/malwarelab",
            "/usr/bin/curl", "-4", "--disable", "--fail", "--silent",
            "--show-error", "--location", "--proto", "=https",
            "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "10",
            "--max-time", "30", "https://am.i.mullvad.net/json",
        ],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, check=False, timeout=40,
    )
    if completed.returncode != 0 or len(completed.stdout) > 131072:
        return None
    try:
        value = json.loads(completed.stdout)
        address = ipaddress.ip_address(value.get("ip", ""))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if value.get("mullvad_exit_ip") is not True or value.get("country") != "Germany" or address.version != 4 or not address.is_global:
        return None
    return str(address)
def wait_egress():
    for _attempt in range(12):
        value = egress_identity()
        if value is not None:
            return value
        time.sleep(3)
    return None
baseline_egress = None
def connect_different_egress():
    for attempt in range(4):
        if attempt and not mullvad("disconnect"):
            continue
        if not mullvad("connect"):
            continue
        current = wait_egress()
        if current is not None and current != baseline_egress:
            return True
    return False
def soak_active():
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", SOAK_UNIT],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin"}, check=False, timeout=10,
    )
    return result.returncode == 0
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(SOCKET)
    os.chown(SOCKET, 0, gid)
    os.chmod(SOCKET, 0o620)
    server.listen(1)
    server.settimeout(1.0)
    baseline_egress = wait_egress()
    if baseline_egress is None:
        raise SystemExit(3)
    while not interrupted and time.monotonic() < deadline:
        active = soak_active()
        seen_soak = seen_soak or active or STARTED_MARKER.is_file()
        if seen_soak and not active:
            break
        try:
            connection, _ = server.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(5.0)
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
            chunks = []
            total = 0
            try:
                while True:
                    chunk = connection.recv(33 - total)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 32:
                        break
            except (OSError, socket.timeout):
                continue
            payload = b"".join(chunks)
            if peer_uid != uid or payload not in (b"disconnect\n", b"connect\n"):
                connection.sendall(b"DENIED\n")
                continue
            action = payload[:-1].decode("ascii")
            if action != state:
                connection.sendall(b"DENIED\n")
                continue
            if action == "disconnect":
                state = "connect"
                succeeded = mullvad(action)
            else:
                succeeded = connect_different_egress()
            if not succeeded:
                connection.sendall(b"FAILED\n")
                continue
            if action == "connect":
                state = "done"
            connection.sendall(b"OK\n")
            if action == "connect":
                break
finally:
    if state == "connect":
        for _recovery_attempt in range(3):
            if mullvad("connect"):
                break
            time.sleep(2)
    server.close()
    try: os.unlink(SOCKET)
    except FileNotFoundError: pass
raise SystemExit(0 if state == "done" else 2)
DYNAMICFLOW_VPN_HELPER_9B18A7C2
`

const labPBPSoakStartSuffix = `chmod 0755 "$harness_stage" "$helper_stage"
chown root:root "$harness_stage" "$helper_stage"
uid="$(id -u malwarelab)"
gid="$(id -g malwarelab)"
session="$(pgrep -o -u malwarelab -x xfce4-session)"
environment="$(tr '\0' '\n' <"/proc/$session/environ")"
grep -Fqx 'DISPLAY=:1' <<<"$environment"
grep -Fqx 'XAUTHORITY=/home/malwarelab/.Xauthority' <<<"$environment"
grep -Fqx "XDG_RUNTIME_DIR=/run/user/$uid" <<<"$environment"
grep -Fqx "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" <<<"$environment"
[ -S "/run/user/$uid/bus" ]
result_dir=/home/malwarelab/.local/state/dynamicflow/pbp/test-results
install -d -o malwarelab -g "$gid" -m 0700 "$result_dir"
result="$result_dir/lab-qualifying-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
case "$result" in "$result_dir"/lab-qualifying-[0-9]*.json) ;; *) exit 52;; esac
printf '%s\n' "$result" >"$pointer"
chmod 0600 "$pointer"
/usr/bin/python3 - /etc/toolkit/pbp-persona.json "$started_stage" <<'DYNAMICFLOW_PBP_START_MARKER_42A6C19E'
import datetime
import hashlib
import json
import os
import stat
import sys

source, marker = sys.argv[1:]
read_flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    read_flags |= os.O_NOFOLLOW
source_fd = os.open(source, read_flags)
try:
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_size < 1
        or before.st_size > 2 * 1024 * 1024
    ):
        raise SystemExit(72)
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
        chunk = os.read(source_fd, min(131072, remaining))
        if not chunk:
            raise SystemExit(73)
        digest.update(chunk)
        remaining -= len(chunk)
    after = os.fstat(source_fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise SystemExit(74)
finally:
    os.close(source_fd)
payload = {
    "persona": {
        "inode": before.st_ino,
        "sha256": "sha256:" + digest.hexdigest(),
        "size": before.st_size,
    },
    "schema": 1,
    "started_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
encoded = (json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    write_flags |= os.O_NOFOLLOW
marker_fd = os.open(marker, write_flags, 0o600)
try:
    os.fchmod(marker_fd, 0o600)
    view = memoryview(encoded)
    while view:
        view = view[os.write(marker_fd, view):]
    os.fsync(marker_fd)
    details = os.fstat(marker_fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or stat.S_IMODE(details.st_mode) != 0o600:
        raise SystemExit(75)
finally:
    os.close(marker_fd)
DYNAMICFLOW_PBP_START_MARKER_42A6C19E
systemctl reset-failed "$soak_unit" "$helper_unit" >/dev/null 2>&1 || true
systemd-run --quiet --unit="$helper_unit" --property=Type=exec --property=RuntimeMaxSec=65min --property=TimeoutStopSec=200s --property=NoNewPrivileges=true /usr/bin/python3 "$helper_stage"
start_cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ]; then
    systemctl stop "$helper_unit" >/dev/null 2>&1 || true
    rm -f -- "$harness_stage" "$helper_stage" "$pointer" "$started_marker" "$started_stage"
  fi
  exit "$status"
}
trap start_cleanup EXIT
trap 'exit 70' HUP INT TERM
for _ in $(seq 1 100); do [ -S "$socket_path" ] && break; sleep 0.1; done
[ -S "$socket_path" ] && [ "$(stat -c '%u:%a' "$socket_path")" = "0:620" ]
systemd-run --quiet --unit="$soak_unit" --uid=malwarelab --gid="$gid" --working-directory=/home/malwarelab --property=Type=exec --property=RuntimeMaxSec=60min --property=TimeoutStopSec=30s --property=KillMode=mixed --property=NoNewPrivileges=true --setenv=HOME=/home/malwarelab --setenv=USER=malwarelab --setenv=LOGNAME=malwarelab --setenv=PATH=/usr/local/bin:/usr/bin:/bin --setenv=DISPLAY=:1 --setenv=XAUTHORITY=/home/malwarelab/.Xauthority --setenv="XDG_RUNTIME_DIR=/run/user/$uid" --setenv="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" --setenv=DYNAMICFLOW_LAB_VPN_TRIGGER=/run/dynamicflow-lab-pbp-vpn.sock /usr/bin/python3 "$harness_stage" --duration-seconds 1800 --normal-cycles 5 --exercise-vpn-failure --disposable-network-test --result "$result"
mv -T -- "$started_stage" "$started_marker"
[ -f "$started_marker" ] && [ ! -L "$started_marker" ]
[ "$(stat -c '%u:%a' "$started_marker")" = '0:600' ]
[ "$(stat -c '%s' "$started_marker")" -le 1024 ]
systemctl is-active --quiet "$soak_unit"
trap - EXIT HUP INT TERM
printf '%s\n' soak-started
`

const labPBPSoakPollScript = `set -Eeuo pipefail
set +x
unit=dynamicflow-lab-pbp-soak.service
load="$(systemctl show --property LoadState --value "$unit")"
[ "$load" = loaded ]
active="$(systemctl show --property ActiveState --value "$unit")"
case "$active" in
  active|activating|deactivating) printf '%s\n' soak-running ;;
  inactive|failed) printf '%s\n' soak-complete ;;
  *) exit 60 ;;
esac
`

const labPBPForensicsScript = `set -Eeuo pipefail
set +x
umask 077
export LC_ALL=C
marker=/run/dynamicflow-lab-pbp-soak-started
helper=dynamicflow-lab-pbp-vpn-trigger.service
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%u:%a' "$marker")" = '0:600' ]
[ "$(stat -c '%s' "$marker")" -le 1024 ]
for _ in $(seq 1 180); do
  helper_state="$(systemctl show --property ActiveState --value "$helper")"
  case "$helper_state" in
    inactive|failed) break ;;
    active|activating|deactivating) sleep 1 ;;
    *) exit 80 ;;
  esac
done
helper_state="$(systemctl show --property ActiveState --value "$helper")"
case "$helper_state" in inactive|failed) ;; *) exit 80 ;; esac
/usr/bin/python3 - "$marker" <<'DYNAMICFLOW_PBP_FORENSICS_65EAF219'
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys

MARKER = pathlib.Path(sys.argv[1])
PERSONA = pathlib.Path("/etc/toolkit/pbp-persona.json")
HOME = pathlib.Path("/home/malwarelab")
PROFILE = HOME / ".local/share/toolkit-pbp/profile"
APP_LOCK = HOME / ".local/share/toolkit-pbp/browser.lock"
LOG_ROOT = HOME / ".local/state/dynamicflow/pbp/logs"
LOG_RE = re.compile(r"^runtime-[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}[.]jsonl$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
STATE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
uid = pwd.getpwnam("malwarelab").pw_uid


def reject_duplicates(pairs):
    value = {}
    for key, nested in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = nested
    return value


def read_regular(path, owner, mode, maximum):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise RuntimeError("unsafe bounded file")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(131072, remaining))
            if not chunk:
                raise RuntimeError("short bounded file")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError("file changed while collecting metadata")
        return before, b"".join(chunks)
    finally:
        os.close(descriptor)


def metadata(path, owner, mode, maximum):
    details, raw = read_regular(path, owner, mode, maximum)
    return {
        "inode": details.st_ino,
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size": details.st_size,
    }


def fixed_command(argv, maximum, timeout):
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > maximum:
        raise RuntimeError("bounded fixed probe failed")
    return completed.stdout


def fixed_coredump_command(argv, maximum, timeout):
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        timeout=timeout,
        check=False,
    )
    if len(completed.stdout) > maximum or len(completed.stderr) > 4096:
        raise RuntimeError("bounded coredump probe failed")
    if completed.returncode == 0 and not completed.stderr:
        return completed.stdout
    no_results = completed.stderr.strip() in (b"No coredumps found", b"No coredumps found.")
    if completed.returncode == 1 and not completed.stdout and no_results:
        return b""
    raise RuntimeError("bounded coredump probe failed")


def digest_lines(lines):
    raw = b"".join(line + b"\n" for line in lines)
    return {"available": True, "count": len(lines), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}


marker_details, marker_raw = read_regular(MARKER, 0, 0o600, 1024)
marker = json.loads(marker_raw, object_pairs_hook=reject_duplicates)
if set(marker) != {"persona", "schema", "started_at"} or marker.get("schema") != 1:
    raise RuntimeError("invalid secure start marker")
if not isinstance(marker["persona"], dict) or set(marker["persona"]) != {"inode", "sha256", "size"}:
    raise RuntimeError("invalid marker persona metadata")
if not isinstance(marker["started_at"], str) or not UTC_RE.fullmatch(marker["started_at"]):
    raise RuntimeError("invalid marker UTC time")
baseline = marker["persona"]
if (
    not isinstance(baseline["inode"], int)
    or baseline["inode"] <= 0
    or not isinstance(baseline["size"], int)
    or baseline["size"] <= 0
    or baseline["size"] > 2 * 1024 * 1024
    or not isinstance(baseline["sha256"], str)
    or not DIGEST_RE.fullmatch(baseline["sha256"])
):
    raise RuntimeError("invalid marker metadata values")
current_persona = metadata(PERSONA, 0, 0o644, 2 * 1024 * 1024)

profile_process_count = 0
xfce_sessions = []
profile_text = str(PROFILE)
options = ("-profile", "--profile", "--user-data-dir")
for entry in list(pathlib.Path("/proc").iterdir())[:65536]:
    if not entry.name.isdigit():
        continue
    try:
        if entry.stat().st_uid != uid:
            continue
        comm = (entry / "comm").read_text(encoding="ascii").strip()
        raw_argv = (entry / "cmdline").read_bytes()
        if len(raw_argv) > 131072:
            raise RuntimeError("oversized process arguments")
        argv = [part.decode("utf-8", "replace") for part in raw_argv.rstrip(b"\0").split(b"\0") if part]
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
    if comm == "xfce4-session":
        xfce_sessions.append(entry)
    uses_profile = False
    for index, argument in enumerate(argv):
        if argument in options and index + 1 < len(argv) and os.path.normpath(argv[index + 1]) == profile_text:
            uses_profile = True
        if any(argument.startswith(option + "=") and os.path.normpath(argument.split("=", 1)[1]) == profile_text for option in options):
            uses_profile = True
    if uses_profile:
        profile_process_count += 1

xfce_active = len(xfce_sessions) == 1
display_bound = False
xauthority_bound = False
if xfce_active:
    environment = (xfce_sessions[0] / "environ").read_bytes()
    if len(environment) > 131072:
        raise RuntimeError("oversized XFCE environment")
    values = set(environment.rstrip(b"\0").split(b"\0"))
    display_bound = b"DISPLAY=:1" in values
    xauthority_bound = b"XAUTHORITY=/home/malwarelab/.Xauthority" in values

listener_raw = fixed_command(["/usr/bin/ss", "-H", "-ltn", "sport = :5901"], 1 << 20, 15)
loopback_5901 = False
public_5901 = False
for raw_line in listener_raw.splitlines():
    fields = raw_line.decode("ascii", "strict").split()
    if len(fields) < 4:
        raise RuntimeError("invalid listener record")
    local = fields[3]
    if local.startswith("["):
        host, separator, port = local[1:].partition("]:")
    else:
        host, separator, port = local.rpartition(":")
    if not separator or port != "5901":
        raise RuntimeError("unexpected listener")
    if host in ("127.0.0.1", "::1"):
        loopback_5901 = True
    else:
        public_5901 = True

app_lock_present = False
app_lock_free = False
try:
    lock_details = APP_LOCK.lstat()
except FileNotFoundError:
    pass
else:
    if not stat.S_ISREG(lock_details.st_mode) or lock_details.st_uid != uid or stat.S_IMODE(lock_details.st_mode) != 0o600:
        raise RuntimeError("unsafe app lock")
    lock_flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(APP_LOCK, lock_flags)
    try:
        opened = os.fstat(lock_fd)
        if (opened.st_dev, opened.st_ino) != (lock_details.st_dev, lock_details.st_ino):
            raise RuntimeError("app lock changed")
        app_lock_present = True
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            app_lock_free = False
        else:
            app_lock_free = True
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)
native_lock_count = sum(1 for name in ("lock", ".parentlock", "parent.lock") if (PROFILE / name).exists() or (PROFILE / name).is_symlink())

log_root_details = LOG_ROOT.lstat()
if not stat.S_ISDIR(log_root_details.st_mode) or log_root_details.st_uid != uid or stat.S_IMODE(log_root_details.st_mode) != 0o700:
    raise RuntimeError("unsafe runtime log directory")
log_entries = sorted(LOG_ROOT.iterdir(), key=lambda path: path.name)
if not 1 <= len(log_entries) <= 8:
    raise RuntimeError("runtime log retention bound failed")
# Fixed names emitted by launch-pbp.py. Context and page records are the
# Playwright/browser lifecycle mapping; stderr records capture browser output.
event_names = (
    "runtime.stderr",
    "runtime.stderr_capture_error",
    "runtime.stderr_capture_incomplete",
    "launch.end",
    "launch.lifecycle_complete",
    "browser.context_started",
    "browser.context_closed",
    "browser.page_opened",
    "browser.page_closed",
    "browser.page_crashed",
    "playwright.dispatch_failed",
)
event_counts = {name: 0 for name in event_names}
log_digests = []
for path in log_entries:
    if not LOG_RE.fullmatch(path.name):
        raise RuntimeError("unexpected runtime log entry")
    _details, raw_log = read_regular(path, uid, 0o600, 4 * 1024 * 1024)
    log_digests.append("sha256:" + hashlib.sha256(raw_log).hexdigest())
    for line in raw_log.splitlines():
        if len(line) > 65536:
            raise RuntimeError("oversized runtime event")
        record = json.loads(line, object_pairs_hook=reject_duplicates)
        event = record.get("event")
        if event in event_counts:
            event_counts[event] += 1

journal_path = pathlib.Path("/usr/bin/journalctl")
if journal_path.is_file() and os.access(journal_path, os.X_OK):
    kernel_raw = fixed_command([
        str(journal_path), "--boot=0", "--dmesg", "--no-pager", "--quiet",
        "--since", marker["started_at"], "--lines=4097", "--output=cat",
    ], 8 << 20, 30)
    kernel_lines = kernel_raw.splitlines()
    if len(kernel_lines) >= 4097:
        raise RuntimeError("kernel journal evidence exceeds entry bound")
    apparmor = [line for line in kernel_lines if b"apparmor" in line.lower() and b"denied" in line.lower()]
    oom = [line for line in kernel_lines if any(token in line.lower() for token in (b"out of memory", b"oom-kill", b"oom_reaper"))]
    segfault = [line for line in kernel_lines if any(token in line.lower() for token in (b"segfault", b"general protection fault"))]
    killed = [line for line in kernel_lines if any(token in line.lower() for token in (b"killed process", b"code=killed", b"signal 9"))]
    apparmor_evidence = digest_lines(apparmor)
    oom_evidence = digest_lines(oom)
    segfault_evidence = digest_lines(segfault)
    killed_evidence = digest_lines(killed)
else:
    unavailable = {"available": False, "count": None, "sha256": None}
    apparmor_evidence = dict(unavailable)
    oom_evidence = dict(unavailable)
    segfault_evidence = dict(unavailable)
    killed_evidence = dict(unavailable)

coredump_path = pathlib.Path("/usr/bin/coredumpctl")
if coredump_path.is_file() and os.access(coredump_path, os.X_OK):
    coredump_raw = fixed_coredump_command([
        str(coredump_path), "--no-pager", "--json=short",
        "--since", marker["started_at"], "-n", "1025", "list",
    ], 8 << 20, 30)
    if not coredump_raw:
        coredump_records = []
    else:
        try:
            decoded_coredumps = json.loads(coredump_raw, object_pairs_hook=reject_duplicates)
        except json.JSONDecodeError:
            coredump_records = [
                json.loads(line, object_pairs_hook=reject_duplicates)
                for line in coredump_raw.splitlines() if line
            ]
        else:
            coredump_records = decoded_coredumps if isinstance(decoded_coredumps, list) else [decoded_coredumps]
    if len(coredump_records) >= 1025 or not all(isinstance(record, dict) for record in coredump_records):
        raise RuntimeError("coredump metadata exceeds entry bound or has invalid shape")
    selected = []
    for record in coredump_records:
        record_uid = next((str(record[key]) for key in ("_UID", "COREDUMP_UID", "UID", "uid") if key in record), "")
        searchable = " ".join(str(record.get(key, "")) for key in (
            "COREDUMP_COMM", "COREDUMP_EXE", "COREDUMP_UNIT", "COREDUMP_USER_UNIT", "COREDUMP_CMDLINE",
            "Executable", "Command", "CommandLine", "Unit", "UserUnit", "exe", "comm",
        )).lower()
        if record_uid == str(uid) or "camoufox" in searchable or "toolkit-pbp" in searchable:
            selected.append(json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii"))
    coredump_evidence = digest_lines(selected)
else:
    coredump_evidence = {"available": False, "count": None, "sha256": None}


def unit_state(name):
    raw = fixed_command([
        "/usr/bin/systemctl", "show", "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=Result", name,
    ], 16384, 15)
    values = {}
    for line in raw.decode("ascii", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in ("LoadState", "ActiveState", "SubState", "Result") or key in values:
            raise RuntimeError("invalid unit state")
        values[key] = value or "none"
    if set(values) != {"LoadState", "ActiveState", "SubState", "Result"} or not all(STATE_RE.fullmatch(value) for value in values.values()):
        raise RuntimeError("unsafe unit state")
    return {
        "active_state": values["ActiveState"],
        "load_state": values["LoadState"],
        "result": values["Result"],
        "sub_state": values["SubState"],
    }


units = {
    "dynamicflow-lab-pbp-soak.service": unit_state("dynamicflow-lab-pbp-soak.service"),
    "dynamicflow-lab-pbp-vpn-trigger.service": unit_state("dynamicflow-lab-pbp-vpn-trigger.service"),
    "mullvad-daemon.service": unit_state("mullvad-daemon.service"),
    "tigervncserver@:1.service": unit_state("tigervncserver@:1.service"),
}
output = {
    "apparmor_denied": apparmor_evidence,
    "collected_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "coredumps": coredump_evidence,
    "desktop": {
        "display_bound": display_bound,
        "vnc_loopback_5901": loopback_5901,
        "vnc_public_5901": public_5901,
        "vnc_unit_active": units["tigervncserver@:1.service"]["active_state"] == "active",
        "xauthority_bound": xauthority_bound,
        "xfce_active": xfce_active,
    },
    "kernel_killed": killed_evidence,
    "kernel_oom": oom_evidence,
    "kernel_segfault": segfault_evidence,
    "persona": {
        "baseline": baseline,
        "current": current_persona,
        "unchanged": baseline == current_persona,
    },
    "profile": {
        "app_lock_free": app_lock_free,
        "app_lock_present": app_lock_present,
        "native_lock_count": native_lock_count,
        "profile_process_count": profile_process_count,
    },
    "runtime_logs": {
        "count": len(log_entries),
        "events": {
            "browser_context_closed": event_counts["browser.context_closed"],
            "browser_context_started": event_counts["browser.context_started"],
            "browser_page_closed": event_counts["browser.page_closed"],
            "browser_page_crashed": event_counts["browser.page_crashed"],
            "browser_page_opened": event_counts["browser.page_opened"],
            "launch_end": event_counts["launch.end"],
            "launch_lifecycle_complete": event_counts["launch.lifecycle_complete"],
            "playwright_dispatch_failed": event_counts["playwright.dispatch_failed"],
            "runtime_stderr": event_counts["runtime.stderr"],
            "runtime_stderr_capture_error": event_counts["runtime.stderr_capture_error"],
            "runtime_stderr_capture_incomplete": event_counts["runtime.stderr_capture_incomplete"],
        },
        "sha256": sorted(log_digests),
    },
    "schema": 1,
    "started_at": marker["started_at"],
    "status": "captured",
    "systemd_units": units,
    "test": "pbp-forensics",
}
encoded = (json.dumps(output, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
if len(encoded) > 1 << 20:
    raise RuntimeError("forensics output exceeds 1 MiB")
sys.stdout.buffer.write(encoded)
sys.stdout.buffer.flush()
DYNAMICFLOW_PBP_FORENSICS_65EAF219
`
const labPBPSoakResultScript = `set -Eeuo pipefail
set +x
umask 077
unit=dynamicflow-lab-pbp-soak.service
helper=dynamicflow-lab-pbp-vpn-trigger.service
pointer=/run/dynamicflow-lab-pbp-result
[ "$(systemctl show --property ActiveState --value "$unit")" != active ]
for _ in $(seq 1 180); do
  systemctl is-active --quiet "$helper" || break
  sleep 1
done
systemctl is-active --quiet "$helper" && exit 61
[ -f "$pointer" ] && [ ! -L "$pointer" ] && [ "$(stat -c '%u:%a' "$pointer")" = '0:600' ] && [ "$(stat -c '%s' "$pointer")" -le 512 ]
result="$(tr -d '\r\n' <"$pointer")"
case "$result" in /home/malwarelab/.local/state/dynamicflow/pbp/test-results/lab-qualifying-[0-9]*.json) ;; *) exit 62;; esac
[ -f "$result" ] && [ ! -L "$result" ]
[ "$(stat -c '%u:%a' "$result")" = "$(id -u malwarelab):600" ]
size="$(stat -c '%s' "$result")"
(( size > 0 && size <= 1048576 ))
cat -- "$result"
rm -f -- /run/dynamicflow-lab-pbp-soak.py /run/dynamicflow-lab-pbp-vpn-trigger.py /run/dynamicflow-lab-pbp-soak-started "$pointer"
systemctl reset-failed "$unit" "$helper" >/dev/null 2>&1 || true
`

func labExitStatus(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return 124
	}
	return -1
}
