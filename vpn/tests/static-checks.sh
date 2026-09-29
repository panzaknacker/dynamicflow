#!/usr/bin/env bash
set -Eeuo pipefail

report_failure() {
    local status=$?
    local line="$1"
    printf 'TEST ERROR: static-checks.sh failed at line %s (exit %s).\n' \
        "$line" "$status" >&2
    exit "$status"
}
trap 'report_failure "$LINENO"' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
tmpdir="$(mktemp -d)"
cleanup() { rm -rf -- "$tmpdir"; }
trap cleanup EXIT HUP INT TERM

for script in bootstrap-vpn.sh make-release.sh \
    tests/prompt-login-harness.sh tests/render-config-harness.sh \
    tests/static-checks.sh; do
    bash -n "$ROOT_DIR/$script"
done
PYTHONPYCACHEPREFIX="$tmpdir/pycache" \
    python3 -m py_compile "$ROOT_DIR/tests/pty-account.py"

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck \
        "$ROOT_DIR/bootstrap-vpn.sh" \
        "$ROOT_DIR/make-release.sh" \
        "$ROOT_DIR/tests/prompt-login-harness.sh" \
        "$ROOT_DIR/tests/render-config-harness.sh" \
        "$ROOT_DIR/tests/static-checks.sh"
fi

grep -Fq "MULLVAD_KEY_FINGERPRINT='A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd anti-censorship set shadowsocks --port 443' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd anti-censorship set mode shadowsocks' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "mullvad_cmd tunnel set allowed-ips '0.0.0.0/0'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd tunnel set ipv6 off' "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq 'mullvad_cmd tunnel set ipv6 on' "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq 'verify_mullvad_egress 6' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "IPV6_SYSCTL_FILE='/etc/sysctl.d/99-toolkit-vpn-ipv6.conf'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'net.ipv6.conf.all.disable_ipv6 = 1' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'net.ipv6.conf.default.disable_ipv6 = 1' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'net.ipv6.conf.all.accept_ra = 0' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'net.ipv6.conf.default.accept_ra = 0' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'ip -6 route show exact ::/0 proto ra' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'ip -6 route del default proto ra' "$ROOT_DIR/bootstrap-vpn.sh"
if grep -Fq 'ip -6 route flush' "$ROOT_DIR/bootstrap-vpn.sh"; then
    printf 'TEST ERROR: dump-based IPv6 route flush returned to the bootstrap\n' >&2
    exit 1
fi
grep -Fq 'has_usable_ipv6_default_route <<<"$ipv6_default_routes"' \
    "$ROOT_DIR/bootstrap-vpn.sh"
ipv6_delete_line="$(
    awk '/ip -6 route del default proto ra/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
ipv6_check_line="$(
    awk '/ipv6_default_routes=.*ip -6 route show default/ { print NR; exit }' \
        "$ROOT_DIR/bootstrap-vpn.sh"
)"
[[ -n "$ipv6_delete_line" && -n "$ipv6_check_line" &&
    "$ipv6_delete_line" -lt "$ipv6_check_line" ]] || {
    printf 'TEST ERROR: IPv6 RA routes are not deleted before the strict route check\n' >&2
    exit 1
}
grep -Fq "[[ \"\$ssh_family\" == '4' || \"\$ssh_family\" == 'https' ]]" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd split-tunnel clear' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'timeout --foreground 120s /usr/bin/mullvad connect --wait' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'exec sudo -n -- "$SCRIPT_PATH" --root-stage' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd relay set location "$location"' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq '.mullvad_exit_ip == true and .country == "Germany"' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'any|de)' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'configure_mullvad_network "$location"' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'connect_and_lock_mullvad "$admin_user" "$location" "$install_firefox"' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq -- '--skip-firefox)' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq -- '--return-after-install)' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq -- '--outbound-https-enrollment)' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'must run from a provider console, not SSH' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'An interactive terminal is required for the Mullvad account prompt.' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'OUTBOUND_HTTPS_ENROLLMENT=1' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad lockdown-mode set on' "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq 'mullvad_cmd relay set location any' "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq 'sudo -v' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd lockdown-mode set on' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'mullvad_cmd auto-connect set on' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'firefox_package=' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "FIREFOX_POLICY='/etc/firefox/policies/policies.json'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "SSH_BYPASS_TABLE='toolkit_mullvad_ssh'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "SSH_BOOT_SERVICE='toolkit-mullvad-ssh-bypass.service'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'After=local-fs.target nftables.service mullvad-early-boot-blocking.service' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'Before=ssh.service sshd.service' "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'systemctl enable --now "$SSH_BOOT_SERVICE"' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq \
    'tcp dport $SSH_PORTS ct state new,established counter ct mark set 0x00000f41 meta mark set 0x6d6f6c65;' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq \
    'ct mark 0x00000f41 tcp sport $SSH_PORTS ct state established counter meta mark set 0x6d6f6c65;' \
    "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq \
    'tcp sport $SSH_PORTS counter ct mark set 0x00000f41' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'dpkg-statoverride --update --add root "$MULLVAD_GROUP" 0750' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'sudo|wheel|docker|lxd|lxd-admin|incus|incus-admin|libvirt|disk|kvm' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'runuser -u malwarelab -- test -w /var/run/docker.sock' \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq "xdg_data_dirs='/var/lib/snapd/desktop:/usr/local/share:/usr/share'" \
    "$ROOT_DIR/bootstrap-vpn.sh"
grep -Fq 'timeout --kill-after=10s 60s /usr/bin/snap run firefox' \
    "$ROOT_DIR/bootstrap-vpn.sh"
! grep -Fq 'rollback_management_dropin' "$ROOT_DIR/bootstrap-vpn.sh"
[[ "$(grep -Fc '/usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect set off' \
    "$ROOT_DIR/bootstrap-vpn.sh")" -eq 3 ]]
[[ "$(grep -Fc '/usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set off' \
    "$ROOT_DIR/bootstrap-vpn.sh")" -eq 2 ]]
safe_state_line="$(
    awk '/^  secure_preexisting_mullvad$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
base_package_line="$(
    awk '/^  install_base_packages "\$PLATFORM_ID" "\$install_firefox"$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
ssh_bypass_line="$(
    awk '/^  install_ssh_bypass$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
mullvad_package_line="$(
    awk '/^  install_mullvad "\$PLATFORM_ARCH"$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
connect_call_line="$(
    awk '/^  connect_and_lock_mullvad "\$admin_user" "\$location" "\$install_firefox"$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh"
)"
[[ -n "$safe_state_line" && -n "$base_package_line" &&
    "$safe_state_line" -lt "$base_package_line" ]] || {
    printf 'TEST ERROR: pre-existing Mullvad is not secured before package changes\n' >&2
    exit 1
}
[[ -n "$ssh_bypass_line" && -n "$mullvad_package_line" &&
    "$ssh_bypass_line" -lt "$mullvad_package_line" &&
    "$mullvad_package_line" -lt "$connect_call_line" ]] || {
    printf 'TEST ERROR: SSH bypass is not persistent before Mullvad install/connect\n' >&2
    exit 1
}

arm_line="$(awk '/^  arm_rollback_watchdog$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
connect_line="$(awk '/timeout --foreground 120s \/usr\/bin\/mullvad connect --wait/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
lockdown_line="$(awk '/^  mullvad_cmd lockdown-mode set on/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
auto_line="$(awk '/^  mullvad_cmd auto-connect set on/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
disarm_line="$(awk '/^  disarm_rollback_watchdog$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
flow_line="$(awk '/^[[:space:]]+verify_bidirectional_ssh_flow$/ { print NR; exit }' "$ROOT_DIR/bootstrap-vpn.sh")"
post_disarm_state_line="$(
    awk -v start="$disarm_line" \
        'NR > start && /^  verify_final_mullvad_state$/ { print NR; exit }' \
        "$ROOT_DIR/bootstrap-vpn.sh"
)"
[[ "$arm_line" -lt "$connect_line" && "$connect_line" -lt "$lockdown_line" &&
    "$lockdown_line" -lt "$auto_line" && "$auto_line" -lt "$flow_line" &&
    "$flow_line" -lt "$disarm_line" &&
    "$disarm_line" -lt "$post_disarm_state_line" ]] || {
    printf 'TEST ERROR: unsafe Mullvad connect/watchdog/lockdown ordering\n' >&2
    exit 1
}

TOOLKIT_VPN_BOOTSTRAP="$ROOT_DIR/bootstrap-vpn.sh" \
    TOOLKIT_VPN_TEST_TMP="$tmpdir" \
    bash "$ROOT_DIR/tests/render-config-harness.sh"

account='1234567890123456'
args_log="$tmpdir/args.log"
stdin_log="$tmpdir/stdin.log"
prompt_output="$(
    TOOLKIT_VPN_TEST_ACCOUNT="$account" \
        TOOLKIT_VPN_TEST_ARGS_LOG="$args_log" \
        TOOLKIT_VPN_TEST_STDIN_LOG="$stdin_log" \
        TOOLKIT_VPN_BOOTSTRAP="$ROOT_DIR/bootstrap-vpn.sh" \
        python3 "$ROOT_DIR/tests/pty-account.py" \
        bash "$ROOT_DIR/tests/prompt-login-harness.sh" 2>&1
)"
[[ "$prompt_output" == *'Mullvad-Accountnummer:'* ]]
[[ "$prompt_output" != *"$account"* ]] || {
    printf 'TEST ERROR: account number was echoed by the prompt\n' >&2
    exit 1
}
[[ "$(cat "$stdin_log")" == "$account" ]]
expected_args=$'argc=2\narg=account\narg=login'
[[ "$(cat "$args_log")" == "$expected_args" ]]
! grep -Fq "$account" "$args_log"

retry_args_log="$tmpdir/retry-args.log"
retry_stdin_log="$tmpdir/retry-stdin.log"
retry_output="$(
    TOOLKIT_VPN_TEST_ACCOUNTS="paste-artefact,$account" \
        TOOLKIT_VPN_TEST_ARGS_LOG="$retry_args_log" \
        TOOLKIT_VPN_TEST_STDIN_LOG="$retry_stdin_log" \
        TOOLKIT_VPN_BOOTSTRAP="$ROOT_DIR/bootstrap-vpn.sh" \
        python3 "$ROOT_DIR/tests/pty-account.py" \
        bash "$ROOT_DIR/tests/prompt-login-harness.sh" 2>&1
)"
[[ "$retry_output" != *'paste-artefact'* && "$retry_output" != *"$account"* ]]
[[ "$(grep -o 'Mullvad-Accountnummer:' <<<"$retry_output" | wc -l)" -eq 2 ]]
[[ "$(cat "$retry_stdin_log")" == "$account" ]]
[[ "$(cat "$retry_args_log")" == "$expected_args" ]]

failure_args_log="$tmpdir/failure-args.log"
failure_stdin_log="$tmpdir/failure-stdin.log"
failure_state="$tmpdir/failure-state.log"
if failure_output="$(
    TOOLKIT_VPN_TEST_ACCOUNTS="$account,$account,$account" \
        TOOLKIT_VPN_TEST_ARGS_LOG="$failure_args_log" \
        TOOLKIT_VPN_TEST_STDIN_LOG="$failure_stdin_log" \
        TOOLKIT_VPN_TEST_FAILURE_STATE="$failure_state" \
        TOOLKIT_VPN_TEST_LOGIN_FAILURES=3 \
        TOOLKIT_VPN_BOOTSTRAP="$ROOT_DIR/bootstrap-vpn.sh" \
        python3 "$ROOT_DIR/tests/pty-account.py" \
        bash "$ROOT_DIR/tests/prompt-login-harness.sh" 2>&1
)"; then
    printf 'TEST ERROR: three rejected Mullvad logins unexpectedly succeeded\n' >&2
    exit 1
fi
[[ "$failure_output" != *"$account"* ]]
[[ "$failure_output" == *'Mullvad login failed after three attempts.'* ]]
[[ "$(wc -l <"$failure_state")" -eq 3 ]]
! grep -Fq "$account" "$failure_args_log"

dist_one="$tmpdir/dist-one"
dist_two="$tmpdir/dist-two"
mkdir -p "$dist_one" "$dist_two"
TOOLKIT_DIST_DIR="$dist_one" "$ROOT_DIR/make-release.sh" >/dev/null
TOOLKIT_DIST_DIR="$dist_two" "$ROOT_DIR/make-release.sh" >/dev/null
cmp -s "$dist_one/vpn.tar.gz" "$dist_two/vpn.tar.gz"

expected_entries=$'toolkit-vpn\ntoolkit-vpn/README.md\ntoolkit-vpn/SHA256SUMS\ntoolkit-vpn/VERSION\ntoolkit-vpn/bootstrap-vpn.sh'
actual_entries="$(tar -tzf "$dist_one/vpn.tar.gz" | sed 's#/$##' | awk 'NF' | sort)"
[[ "$actual_entries" == "$expected_entries" ]]
if tar -tvzf "$dist_one/vpn.tar.gz" | awk '$1 !~ /^[d-]/ { bad = 1 } END { exit bad ? 0 : 1 }'; then
    printf 'TEST ERROR: archive contains a link or unsupported entry\n' >&2
    exit 1
fi

extract_dir="$tmpdir/extract"
mkdir "$extract_dir"
(
    umask 000
    tar -xzf "$dist_one/vpn.tar.gz" -C "$extract_dir"
)
(
    cd "$extract_dir/toolkit-vpn"
    sha256sum -c SHA256SUMS >/dev/null
)
[[ "$(stat -c '%a' "$extract_dir/toolkit-vpn/bootstrap-vpn.sh")" == 755 ]]
for file in README.md SHA256SUMS VERSION; do
    [[ "$(stat -c '%a' "$extract_dir/toolkit-vpn/$file")" == 644 ]]
done

printf 'VPN static checks passed.\n'
