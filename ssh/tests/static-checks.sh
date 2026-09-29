#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP="$ROOT_DIR/vm-bootstrap.sh"
CONNECT="$ROOT_DIR/connect-gui.sh"
TOOLKIT_WRAPPER="$ROOT_DIR/bootstrap-ssh.sh"
TOOLKIT_BUILDER="$ROOT_DIR/make-toolkit-release.sh"
FLOW_INSTANCE="$ROOT_DIR/../internal/cli/instance.go"
FLOW_RUNTIME="$ROOT_DIR/../internal/cli/instance_runtime.go"
FLOW_VNC_SECRET="$ROOT_DIR/../internal/vncsecret/vncsecret_linux.go"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

bash -n "$BOOTSTRAP"
bash -n "$CONNECT"
bash -n "$TOOLKIT_WRAPPER"
bash -n "$TOOLKIT_BUILDER"

"$BOOTSTRAP" --help >/dev/null
"$CONNECT" --help >/dev/null

grep -Fq 'AuthenticationMethods publickey' "$BOOTSTRAP"
grep -Fq 'PasswordAuthentication no' "$BOOTSTRAP"
grep -Fq 'KbdInteractiveAuthentication no' "$BOOTSTRAP"
grep -Fq 'PermitRootLogin no' "$BOOTSTRAP"
grep -Fq 'AllowTcpForwarding local' "$BOOTSTRAP"
# this intentionally checks a literal source line.
# shellcheck disable=SC2016
grep -Fq 'PermitOpen 127.0.0.1:$VNC_PORT' "$BOOTSTRAP"
grep -Fq 'localhost' "$BOOTSTRAP"
grep -Fq 'acceptcuttext=0' "$BOOTSTRAP"
grep -Fq 'sendcuttext=0' "$BOOTSTRAP"
grep -Fq 'noclipboard' "$BOOTSTRAP"
grep -Fq 'acceptsetdesktopsize=0' "$BOOTSTRAP"
# this intentionally checks the packaged perl mandatory-policy spelling too.
# shellcheck disable=SC2016
grep -Fq '$AcceptSetDesktopSize = "no";' "$BOOTSTRAP"
grep -Fq -- '--confirm-key-tested' "$BOOTSTRAP"
grep -Fq -- '--accept-lockout-risk' "$BOOTSTRAP"
grep -Fq -- '--append-unrestricted-key' "$BOOTSTRAP"
grep -Fq 'cleanup_sshd_transaction' "$BOOTSTRAP"
grep -Fq 'assert_single_effective_token' "$BOOTSTRAP"
grep -Fq 'assert_vnc_runtime_policy' "$BOOTSTRAP"
# this intentionally checks a literal source line.
# shellcheck disable=SC2016
grep -Fq 'DenyUsers $GUI_USER' "$BOOTSTRAP"
grep -Fq 'wait_for_live_sshd_policy' "$BOOTSTRAP"
grep -Fq 'probe_live_sshd_authentication' "$BOOTSTRAP"
grep -Fq 'validate_vnc_system_config' "$BOOTSTRAP"
grep -Fq 'write_vnc_mandatory_policy' "$BOOTSTRAP"
grep -Fq 'stop_disable_vnc_service' "$BOOTSTRAP"
grep -Fq 'cleanup_vnc_transaction' "$BOOTSTRAP"
grep -Fq "trap 'cleanup_vnc_transaction' EXIT" "$BOOTSTRAP"
grep -Fq 'vnc_port_listeners' "$BOOTSTRAP"
grep -Fq "vnc_runtime_bool 'AlwaysShared'" "$BOOTSTRAP"
grep -Fq "vnc_runtime_bool 'AcceptSetDesktopSize'" "$BOOTSTRAP"
grep -Fq 'xdotool getdisplaygeometry' "$BOOTSTRAP"
grep -Fq '1|on|yes|true)' "$BOOTSTRAP"
grep -Fq '0|off|no|false)' "$BOOTSTRAP"
grep -Fq -- '-nolisten tcp' "$BOOTSTRAP"
grep -Fq 'preflight_key_only_ssh_server' "$BOOTSTRAP"
grep -Fq 'Refusing pre-existing, unmanaged GUI account' "$BOOTSTRAP"
grep -Fq "vnc_runtime_value 'PasswordFile'" "$BOOTSTRAP"
# this intentionally checks a literal source line.
# shellcheck disable=SC2016
grep -Fq 'runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"' "$BOOTSTRAP"
grep -Fq 'XFCE session, window manager, panel, and desktop are responsive.' "$BOOTSTRAP"
grep -Fq 'XAUTHORITY="$HOME/.Xauthority"' "$BOOTSTRAP"
grep -Fq 'export XAUTHORITY' "$BOOTSTRAP"
grep -Fq "PATH='/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'" "$BOOTSTRAP"
grep -Fq 'assert_firefox_snap_xauthority_bridge' "$BOOTSTRAP"
grep -Fq '  assert_firefox_snap_xauthority_bridge || return 1' "$BOOTSTRAP"
grep -Fq 'Firefox:          not installed and not downloaded' "$BOOTSTRAP"
grep -Fq '"/usr/local/bin/flow", "instance-runtime", "secret", action, "--secret", "vnc"' "$FLOW_INSTANCE"
grep -Fq 'commandInstanceRuntimeSecret' "$FLOW_RUNTIME"
grep -Fq 'syscall.O_NOFOLLOW' "$FLOW_VNC_SECRET"
grep -Fq 'syscall.Renameat' "$FLOW_VNC_SECRET"
grep -Fq 'syscall.Fsync(file.dir.fd)' "$FLOW_VNC_SECRET"
grep -Fq 'cfg.service("active")' "$FLOW_VNC_SECRET"
if grep -Fq 'vncRotateScript' "$FLOW_INSTANCE"; then
    printf 'Operator CLI still embeds the legacy VNC root shell script.\n' >&2
    exit 1
fi

awk '
  /XAUTHORITY="\$HOME[/][.]Xauthority"/ { source = NR }
  /mirror_tmp="\$\(mktemp "\$common_dir[/][.]Xauthority[.]XXXXXXXX"\)"/ { staged = NR }
  /chmod 0600 "\$mirror_tmp"/ { protected = NR }
  /mv -fT -- "\$mirror_tmp" "\$destination"/ { activated = NR }
  /exec startxfce4/ { direct_exec = NR }
  /exec dbus-launch --exit-with-session startxfce4/ { dbus_exec = NR }
  END {
    exit !(source > 0 && staged > source && protected > staged &&
           activated > protected && direct_exec > activated &&
           dbus_exec > direct_exec)
  }
' "$BOOTSTRAP" || {
    printf 'Firefox Snap Xauthority activation is missing or incorrectly ordered.\n' >&2
    exit 1
}

install_gui_block="$TEST_TMP/install-gui-packages"
awk '
  /^install_gui_packages\(\)/ { capture = 1 }
  capture { print }
  capture && /^}/ { exit }
' "$BOOTSTRAP" >"$install_gui_block"
grep -Eq '^[[:space:]]+xdotool([[:space:]\\]|$)' "$install_gui_block" || {
    printf 'GUI package installation is missing xdotool required by runtime geometry validation.\n' >&2
    exit 1
}
if grep -Eq '(^|[[:space:]\\])firefox(-esr)?([[:space:]\\]|$)' "$install_gui_block"; then
    printf 'GUI package installation unexpectedly contains Firefox.\n' >&2
    exit 1
fi
if grep -Eiq 'snap[[:space:]]+(install|download)[[:space:]]+firefox|https?://[^[:space:]]*firefox' "$BOOTSTRAP"; then
    printf 'Bootstrap unexpectedly installs or downloads Firefox.\n' >&2
    exit 1
fi
if grep -Eq '(^|[[:space:]])xhost([[:space:]]|$)' "$BOOTSTRAP"; then
    printf 'Bootstrap unexpectedly weakens X11 access with xhost.\n' >&2
    exit 1
fi

xstartup="$TEST_TMP/xstartup"
awk '
  !capture && index($0, "EOF_XSTARTUP") { capture = 1; next }
  capture && $0 == "EOF_XSTARTUP" { exit }
  capture { print }
' "$BOOTSTRAP" >"$xstartup"
[ -s "$xstartup" ] || {
    printf 'Could not extract the generated VNC xstartup script.\n' >&2
    exit 1
}
sh -n "$xstartup"

xstartup_bin="$TEST_TMP/xstartup-bin"
xstartup_log="$TEST_TMP/xstartup.log"
xstartup_test="$TEST_TMP/xstartup.test"
mkdir -p "$xstartup_bin"
cat >"$xstartup_bin/dbus-launch" <<'EOF_DBUS_STUB'
#!/bin/sh
set -eu
{
  printf 'XAUTHORITY=%s\n' "$XAUTHORITY"
  printf 'PATH=%s\n' "$PATH"
  for argument in "$@"; do
    printf 'ARG=%s\n' "$argument"
  done
} >"$XSTARTUP_LOG"
EOF_DBUS_STUB
chmod 0755 "$xstartup_bin/dbus-launch"
sed "s#^PATH='#PATH='$xstartup_bin:#" "$xstartup" \
    >"$xstartup_test"
sh -n "$xstartup_test"

run_xstartup_fixture() {
    local fixture_home="$1"
    local fixture_log="$2"

    env -i \
        HOME="$fixture_home" \
        XDG_RUNTIME_DIR="$fixture_home/.missing-runtime" \
        XSTARTUP_LOG="$fixture_log" \
        /bin/sh "$xstartup_test"
}

xstartup_home="$TEST_TMP/xstartup-home"
mkdir -m 0700 "$xstartup_home"
printf '\001cookie-v1\000tail\n' >"$xstartup_home/.Xauthority"
chmod 0600 "$xstartup_home/.Xauthority"
run_xstartup_fixture "$xstartup_home" "$xstartup_log"

xauthority_mirror="$xstartup_home/snap/firefox/common/.Xauthority"
cmp -s "$xstartup_home/.Xauthority" "$xauthority_mirror"
[ "$(stat -c '%a' "$xauthority_mirror")" = '600' ]
for bridge_dir in \
    "$xstartup_home/snap" \
    "$xstartup_home/snap/firefox" \
    "$xstartup_home/snap/firefox/common"; do
    [ -d "$bridge_dir" ] && [ ! -L "$bridge_dir" ]
    [ "$(stat -c '%a' "$bridge_dir")" = '700' ]
done
[ -z "$(find "$xstartup_home/snap/firefox/common" -maxdepth 1 \
    -name '.Xauthority.*' -print -quit)" ]
printf '%s\n' \
    "XAUTHORITY=$xstartup_home/.Xauthority" \
    "PATH=$xstartup_bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin" \
    'ARG=--exit-with-session' \
    'ARG=startxfce4' >"$TEST_TMP/xstartup.expected"
cmp -s "$TEST_TMP/xstartup.expected" "$xstartup_log"

printf '\002cookie-v2\000changed\n' >"$xstartup_home/.Xauthority"
chmod 0600 "$xstartup_home/.Xauthority"
run_xstartup_fixture "$xstartup_home" "$xstartup_log"
cmp -s "$xstartup_home/.Xauthority" "$xauthority_mirror"

unsafe_home="$TEST_TMP/xstartup-unsafe-destination"
sentinel="$TEST_TMP/xauthority-sentinel"
unsafe_log="$TEST_TMP/xstartup-unsafe.log"
mkdir -m 0700 -p "$unsafe_home/snap/firefox/common"
chmod 0700 "$unsafe_home/snap" "$unsafe_home/snap/firefox" \
    "$unsafe_home/snap/firefox/common"
printf 'unsafe-cookie\n' >"$unsafe_home/.Xauthority"
chmod 0600 "$unsafe_home/.Xauthority"
printf 'must-not-change\n' >"$sentinel"
ln -s "$sentinel" "$unsafe_home/snap/firefox/common/.Xauthority"
if run_xstartup_fixture "$unsafe_home" "$unsafe_log" \
    >"$TEST_TMP/xstartup-unsafe.stdout" 2>"$TEST_TMP/xstartup-unsafe.stderr"; then
    printf 'xstartup unexpectedly accepted a symlinked Firefox Xauthority.\n' >&2
    exit 1
fi
grep -Fq 'Unsafe Firefox Xauthority destination' "$TEST_TMP/xstartup-unsafe.stderr"
[ ! -e "$unsafe_log" ]
[ "$(cat "$sentinel")" = 'must-not-change' ]

unsafe_parent_home="$TEST_TMP/xstartup-unsafe-parent"
unsafe_parent_target="$TEST_TMP/xstartup-unsafe-parent-target"
unsafe_parent_log="$TEST_TMP/xstartup-unsafe-parent.log"
mkdir -m 0700 "$unsafe_parent_home" "$unsafe_parent_target"
printf 'unsafe-parent-cookie\n' >"$unsafe_parent_home/.Xauthority"
chmod 0600 "$unsafe_parent_home/.Xauthority"
ln -s "$unsafe_parent_target" "$unsafe_parent_home/snap"
if run_xstartup_fixture "$unsafe_parent_home" "$unsafe_parent_log" \
    >"$TEST_TMP/xstartup-unsafe-parent.stdout" \
    2>"$TEST_TMP/xstartup-unsafe-parent.stderr"; then
    printf 'xstartup unexpectedly accepted a symlinked Firefox Snap directory.\n' >&2
    exit 1
fi
grep -Fq 'Unsafe Firefox Snap directory' "$TEST_TMP/xstartup-unsafe-parent.stderr"
[ ! -e "$unsafe_parent_log" ]
[ -z "$(find "$unsafe_parent_target" -mindepth 1 -print -quit)" ]

awk '
  /VNC_TX_ACTIVE=1/ { armed = NR }
  /systemctl restart "\$unit"/ { restarted = NR }
  /if assert_gui_session_ready/ { validated = NR }
  /VNC_TX_ACTIVE=0/ { committed = NR }
  END {
    exit !(armed > 0 && restarted > armed && validated > restarted &&
           committed > validated)
  }
' "$BOOTSTRAP" || {
    printf 'VNC validation transaction is not ordered fail-closed.\n' >&2
    exit 1
}

grep -Fq -- '-F none' "$CONNECT"
grep -Fq -- '-S none' "$CONNECT"
grep -Fq 'PasswordAuthentication=no' "$CONNECT"
grep -Fq 'KbdInteractiveAuthentication=no' "$CONNECT"
grep -Fq 'IdentitiesOnly=yes' "$CONNECT"
grep -Fq 'IdentityAgent=none' "$CONNECT"
grep -Fq 'StrictHostKeyChecking=yes' "$CONNECT"
grep -Fq 'GlobalKnownHostsFile=none' "$CONNECT"
grep -Fq 'ConnectTimeout=12' "$CONNECT"
grep -Fq 'ConnectionAttempts=1' "$CONNECT"
grep -Fq 'UpdateHostKeys=no' "$CONNECT"
grep -Fq 'ServerAliveInterval=15' "$CONNECT"
grep -Fq 'ServerAliveCountMax=3' "$CONNECT"
grep -Fq 'TCPKeepAlive=no' "$CONNECT"
grep -Fq "PATH='/usr/bin:/bin'" "$CONNECT"
grep -Fq "SSH_BIN='/usr/bin/ssh'" "$CONNECT"

expected_version_regex='^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$'
actual_version_regex="$(sed -n "s/^readonly VERSION_REGEX='\\(.*\\)'$/\\1/p" "$TOOLKIT_BUILDER")"
[ "$actual_version_regex" = "$expected_version_regex" ] || {
    printf 'Toolkit version validation does not match the serving interface: %s\n' \
        "$TOOLKIT_BUILDER" >&2
    exit 1
}

if "$CONNECT" --ssh-port 0 example.invalid >/dev/null 2>&1; then
    printf 'connect-gui.sh unexpectedly accepted TCP port 0.\n' >&2
    exit 1
fi
missing_identity="$TEST_TMP/missing-identity"
if VM_SSH_IDENTITY_DEFAULT="$missing_identity" \
    "$CONNECT" example.invalid >/dev/null 2>&1; then
    printf 'connect-gui.sh unexpectedly accepted missing trust/key inputs.\n' >&2
    exit 1
fi
touch "$TEST_TMP/identity" "$TEST_TMP/known_hosts"
if "$CONNECT" --identity "$TEST_TMP/identity" example.invalid >/dev/null 2>&1; then
    printf 'connect-gui.sh unexpectedly accepted a missing known_hosts file.\n' >&2
    exit 1
fi
if VM_SSH_IDENTITY_DEFAULT="$missing_identity" \
    "$CONNECT" --known-hosts "$TEST_TMP/known_hosts" example.invalid >/dev/null 2>&1; then
    printf 'connect-gui.sh unexpectedly accepted a missing identity file.\n' >&2
    exit 1
fi

connect_test_bin="$TEST_TMP/connect-bin"
connect_test_marker="$TEST_TMP/connect-ssh-called"
mkdir -m 0700 "$connect_test_bin"
cat >"$connect_test_bin/ssh" <<'EOF_FAKE_SSH'
#!/usr/bin/env sh
set -eu
: >"$CONNECT_SSH_MARKER"
EOF_FAKE_SSH
chmod 0700 "$connect_test_bin/ssh"
connect_test="$TEST_TMP/connect-gui-test"
sed "s#^SSH_BIN='/usr/bin/ssh'\$#SSH_BIN='$connect_test_bin/ssh'#" \
    "$CONNECT" >"$connect_test"
chmod 0700 "$connect_test"

encrypted_identity="$TEST_TMP/encrypted-identity"
/usr/bin/ssh-keygen -q -t ed25519 -N 'test-passphrase' -f "$encrypted_identity"
chmod 0600 "$encrypted_identity"
printf 'example.invalid %s\n' "$(cat "$encrypted_identity.pub")" \
    >"$TEST_TMP/safe-known-hosts"
chmod 0644 "$TEST_TMP/safe-known-hosts"
if ! CONNECT_SSH_MARKER="$connect_test_marker" \
    "$connect_test" --identity "$encrypted_identity" \
    --known-hosts "$TEST_TMP/safe-known-hosts" example.invalid >/dev/null 2>&1; then
    printf 'connect-gui.sh rejected a structurally valid encrypted private key.\n' >&2
    exit 1
fi
[ -f "$connect_test_marker" ] || {
    printf 'connect-gui.sh did not reach ssh with a validated encrypted key.\n' >&2
    exit 1
}

assert_connect_rejects_files() {
    local description="$1" identity="$2" known_hosts="$3"
    rm -f "$connect_test_marker"
    if CONNECT_SSH_MARKER="$connect_test_marker" \
        "$connect_test" --identity "$identity" --known-hosts "$known_hosts" \
        example.invalid >/dev/null 2>&1; then
        printf 'connect-gui.sh accepted %s.\n' "$description" >&2
        exit 1
    fi
    [ ! -e "$connect_test_marker" ] || {
        printf 'connect-gui.sh reached ssh with %s.\n' "$description" >&2
        exit 1
    }
}

printf '%s\n' 'not a private key' >"$TEST_TMP/invalid-identity"
chmod 0600 "$TEST_TMP/invalid-identity"
assert_connect_rejects_files 'a structurally invalid private key' \
    "$TEST_TMP/invalid-identity" "$TEST_TMP/safe-known-hosts"

cp "$encrypted_identity" "$TEST_TMP/open-identity"
chmod 0644 "$TEST_TMP/open-identity"
assert_connect_rejects_files 'a group/other-accessible private key' \
    "$TEST_TMP/open-identity" "$TEST_TMP/safe-known-hosts"

ln -s "$encrypted_identity" "$TEST_TMP/symlink-identity"
assert_connect_rejects_files 'a symlinked private key' \
    "$TEST_TMP/symlink-identity" "$TEST_TMP/safe-known-hosts"

cp "$TEST_TMP/safe-known-hosts" "$TEST_TMP/writable-known-hosts"
chmod 0666 "$TEST_TMP/writable-known-hosts"
assert_connect_rejects_files 'a group/world-writable known_hosts file' \
    "$encrypted_identity" "$TEST_TMP/writable-known-hosts"

ln -s "$TEST_TMP/safe-known-hosts" "$TEST_TMP/symlink-known-hosts"
assert_connect_rejects_files 'a symlinked known_hosts file' \
    "$encrypted_identity" "$TEST_TMP/symlink-known-hosts"

cp "$TEST_TMP/safe-known-hosts" "$TEST_TMP/known_hosts_%h"
chmod 0644 "$TEST_TMP/known_hosts_%h"
assert_connect_rejects_files 'an OpenSSH-tokenized known_hosts path' \
    "$encrypted_identity" "$TEST_TMP/known_hosts_%h"

cp "$encrypted_identity" "$TEST_TMP/identity_%h"
chmod 0600 "$TEST_TMP/identity_%h"
assert_connect_rejects_files 'an OpenSSH-tokenized identity path' \
    "$TEST_TMP/identity_%h" "$TEST_TMP/safe-known-hosts"

mkdir -m 0777 "$TEST_TMP/writable-parent"
cp "$encrypted_identity" "$TEST_TMP/writable-parent/identity"
chmod 0600 "$TEST_TMP/writable-parent/identity"
assert_connect_rejects_files 'a private key below a writable ancestor' \
    "$TEST_TMP/writable-parent/identity" "$TEST_TMP/safe-known-hosts"

if grep -Eq "MANAGED_PUBLIC_KEY='ssh-|AAAAC3NzaC1lZDI1NTE5AAAA" "$BOOTSTRAP"; then
    printf 'A fixed SSH public key is still embedded in vm-bootstrap.sh.\n' >&2
    exit 1
fi
grep -Fq -- '--public-key-file FILE' "$BOOTSTRAP"
grep -Fq 'No public key selected.' "$BOOTSTRAP"
grep -Fq 'SSH public-key selection' "$TOOLKIT_WRAPPER"
grep -Fq 'Paste a public key' "$TOOLKIT_WRAPPER"
grep -Fq 'VM_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic' "$CONNECT"
grep -Fq 'select_private_key' "$CONNECT"

for accepted_version in v0.1.0 v12.34.56-rc.1; do
    [[ "$accepted_version" =~ $expected_version_regex ]] || {
        printf 'Expected Toolkit version was rejected: %s\n' "$accepted_version" >&2
        exit 1
    }
done
for rejected_version in v1.2 v1.2.3+meta v1.2.3- v1.2.3_rc v1.2.3foo; do
    if [[ "$rejected_version" =~ $expected_version_regex ]]; then
        printf 'Unsafe/incompatible Toolkit version was accepted: %s\n' "$rejected_version" >&2
        exit 1
    fi
done

printf 'Static checks passed.\n'
