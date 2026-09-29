#!/usr/bin/env bash
set -Eeuo pipefail
set +x

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
export LC_ALL=C
umask 077
ulimit -c 0 >/dev/null 2>&1 || true

readonly GUI_USER='malwarelab'
readonly GUI_MARKER='/var/lib/vm-bootstrap/gui-user-malwarelab'
readonly MULLVAD_CHECK_URL='https://am.i.mullvad.net/json'
readonly INSTALL_ROOT='/opt/toolkit/pbp'
readonly PERSONA_FILE='/etc/toolkit/pbp-persona.json'
readonly WRAPPER='/usr/local/bin/pbp-browser'
readonly DESKTOP_FILE='/usr/local/share/applications/toolkit-pbp.desktop'
readonly FIREFOX_POLICY='/etc/firefox/policies/policies.json'
readonly APPARMOR_PROFILE='/etc/apparmor.d/toolkit-pbp'
readonly LOG_FILE='/var/log/toolkit-pbp-bootstrap.log'
readonly VPN_POLICY_HELPER='/usr/local/libexec/dynamicflow-pbp-vpn-verify'
readonly VPN_POLICY_SUDOERS='/etc/sudoers.d/dynamicflow-pbp-vpn-policy'
readonly EGRESS_GUARD_HELPER='/usr/local/libexec/dynamicflow-pbp-egress-guard-load'
readonly EGRESS_GUARD_SERVICE_FILE='/etc/systemd/system/dynamicflow-pbp-egress-guard.service'
readonly EGRESS_GUARD_SERVICE='dynamicflow-pbp-egress-guard.service'
readonly EGRESS_GUARD_TABLE='toolkit_pbp_guard'
readonly DOWNLOAD_BACKING='/var/lib/toolkit/pbp/downloads'
readonly DISPOSABLE_TEST_MARKER_NAME='DISPOSABLE-TEST-GATE.json'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
TMP_DIR=''
STAGE_DIR=''
GUI_HOME=''
GUI_UID=''
PLATFORM_ID=''
PLATFORM_ARCH=''
PYTHON_TAG=''
RELEASE=''
TARGET_RELEASE=''
BROWSER_RELEASE_STATUS='security release gate passed'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '\n[toolkit-pbp] %s\n' "$*" >&2
}

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
        rm -rf -- "$STAGE_DIR"
    fi
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
    exit "$status"
}

verify_bundle() {
    [[ -f "$SCRIPT_DIR/SHA256SUMS" && ! -L "$SCRIPT_DIR/SHA256SUMS" ]] ||
        die 'Missing or unsafe internal SHA256SUMS.'
    (cd "$SCRIPT_DIR" && sha256sum -c --quiet SHA256SUMS) ||
        die 'Internal Toolkit PBP bundle checksum verification failed.'
}

validate_disposable_test_marker() {
    local marker="$SCRIPT_DIR/$DISPOSABLE_TEST_MARKER_NAME"

    [[ -f "$marker" && ! -L "$marker" ]] ||
        die "Unsafe disposable-test marker: $marker"
    command -v python3 >/dev/null 2>&1 ||
        die 'python3 is required to validate the disposable-test marker.'
    python3 - "$marker" "$SCRIPT_DIR/browser-assets.lock" \
        "$SCRIPT_DIR/browser-security-policy.json" <<'PY_MARKER' ||
import hashlib
import json
import pathlib
import sys

marker_path, lock_path, policy_path = map(pathlib.Path, sys.argv[1:])
try:
    raw = marker_path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("marker too large")
    marker = json.loads(raw)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
    raise SystemExit(1)
if not isinstance(marker, dict):
    raise SystemExit(1)
if (
    type(marker.get("schema")) is not int
    or marker["schema"] != 1
    or marker.get("mode") != "disposable-test"
    or marker.get("result") != "TEST-ONLY"
):
    raise SystemExit(1)
checks = marker.get("checks")
if not isinstance(checks, list):
    raise SystemExit(1)
expected = {
    "policy-current",
    "review-disposition",
    "exact-release-provenance",
    "exact-wrapper-provenance",
    "gecko-security-baseline",
}
allowed_failures = {"review-disposition", "gecko-security-baseline"}
values = {}
for check in checks:
    if (
        not isinstance(check, dict)
        or set(check) != {"name", "passed", "detail"}
        or not isinstance(check.get("name"), str)
        or type(check.get("passed")) is not bool
        or not isinstance(check.get("detail"), str)
        or check["name"] in values
    ):
        raise SystemExit(1)
    values[check["name"]] = check["passed"]
if set(values) != expected:
    raise SystemExit(1)
if {name for name, passed in values.items() if not passed} != allowed_failures:
    raise SystemExit(1)
for name, path in (("lock_sha256", lock_path), ("policy_sha256", policy_path)):
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise SystemExit(1)
    if marker.get(name) != digest:
        raise SystemExit(1)
PY_MARKER
        die 'The disposable-test marker is malformed or not bound to this browser policy.'
    python3 "$SCRIPT_DIR/browser-maintenance.py" disposable-test \
        --lock "$SCRIPT_DIR/browser-assets.lock" \
        --policy "$SCRIPT_DIR/browser-security-policy.json" >/dev/null ||
        die 'The disposable-test browser gate is no longer current or has additional failures.'
}

validate_bundle_mode() {
    local accepted="$1"
    local marker="$SCRIPT_DIR/$DISPOSABLE_TEST_MARKER_NAME"

    [[ "$accepted" == '0' || "$accepted" == '1' ]] ||
        die 'Internal error: invalid disposable-test acceptance state.'
    if [[ -e "$marker" || -L "$marker" ]]; then
        validate_disposable_test_marker
        [[ "$accepted" == '1' ]] || die \
            'This TEST-ONLY browser bundle requires --accept-disposable-test-browser.'
        BROWSER_RELEASE_STATUS='TEST-ONLY: security baseline knowingly not met'
        log 'TEST-ONLY browser accepted: this disposable VM does not use a security-approved Camoufox release.'
    else
        [[ "$accepted" == '0' ]] || die \
            '--accept-disposable-test-browser is valid only for a marked TEST-ONLY bundle.'
        BROWSER_RELEASE_STATUS='security release gate passed'
    fi
}

valid_admin_user() {
    local user="$1" uid
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ && "$user" != 'root' && "$user" != "$GUI_USER" ]] ||
        return 1
    getent passwd "$user" >/dev/null || return 1
    uid="$(id -u "$user")"
    [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]]
}

valid_persona_class() {
    [[ "${1:-}" == 'basic' || "${1:-}" == 'performance' ||
        "${1:-}" == 'workstation' ]]
}

choose_persona_class() {
    local answer

    if [[ ! -t 0 || ! -t 2 ]]; then
        log 'Keine interaktive Konsole erkannt; Persona-Klasse basic wird verwendet.'
        printf '%s\n' 'basic'
        return 0
    fi
    cat >&2 <<'EOF_PERSONA_CHOICE'

[toolkit-pbp] Persona-Klasse für diese disposable VM:
  1) basic       – 4 CPU-Threads, Intel HD 400, 1600x900
  2) performance – 8 CPU-Threads, NVIDIA GTX 980, 1600x900
  3) workstation – 12 CPU-Threads, Intel HD, 1600x900

Die Auswahl bleibt zusammen mit dem Browserprofil innerhalb dieser VM stabil.
Ein späterer Klassenwechsel erfordert eine frische disposable VM.
EOF_PERSONA_CHOICE
    while true; do
        IFS= read -r -p 'Auswahl [1]: ' answer ||
            die 'Die Persona-Auswahl wurde abgebrochen.'
        case "${answer:-1}" in
        1 | basic)
            printf '%s\n' 'basic'
            return 0
            ;;
        2 | performance)
            printf '%s\n' 'performance'
            return 0
            ;;
        3 | workstation)
            printf '%s\n' 'workstation'
            return 0
            ;;
        *) printf 'Bitte 1, 2 oder 3 wählen.\n' >&2 ;;
        esac
    done
}

user_stage() {
    local admin_user outbound_https_enrollment=0 persona_class=''
    local accept_disposable_test=0

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
        --outbound-https-enrollment)
            ((outbound_https_enrollment == 0)) ||
                die '--outbound-https-enrollment was specified more than once.'
            outbound_https_enrollment=1
            shift
            ;;
        --persona-class)
            [[ "$#" -ge 2 && -z "$persona_class" ]] ||
                die '--persona-class requires one value and may be specified only once.'
            persona_class="$2"
            valid_persona_class "$persona_class" ||
                die 'Persona class must be basic, performance, or workstation.'
            shift 2
            ;;
        --accept-disposable-test-browser)
            ((accept_disposable_test == 0)) ||
                die '--accept-disposable-test-browser was specified more than once.'
            accept_disposable_test=1
            shift
            ;;
        *)
            die 'Supported options are --persona-class CLASS, --outbound-https-enrollment and --accept-disposable-test-browser.'
            ;;
        esac
    done
    validate_bundle_mode "$accept_disposable_test"
    [[ "$(id -u)" -ne 0 ]] ||
        die 'Run PBP as the normal SSH administrator, not through sudo.'
    admin_user="$(id -un)"
    valid_admin_user "$admin_user" ||
        die 'PBP must run as a normal sudo-capable SSH administrator.'
    command -v sudo >/dev/null 2>&1 || die 'sudo is required.'
    [[ -x "$SCRIPT_DIR/toolkit-vpn-stage" && ! -L "$SCRIPT_DIR/toolkit-vpn-stage" ]] ||
        die 'The embedded Toolkit VPN stage is missing or unsafe.'
    if [[ -z "$persona_class" ]]; then
        persona_class="$(choose_persona_class)"
    fi
    valid_persona_class "$persona_class" || die 'Invalid selected persona class.'

    log 'Zuerst wird Mullvad auf Deutschland und Shadowsocks Port 443 festgelegt.'
    if [[ "$outbound_https_enrollment" == '1' ]]; then
        "$SCRIPT_DIR/toolkit-vpn-stage" \
            --location de --skip-firefox --return-after-install \
            --outbound-https-enrollment
    else
        "$SCRIPT_DIR/toolkit-vpn-stage" \
            --location de --skip-firefox --return-after-install
    fi

    log 'Der deutsche Mullvad-Ausgang steht; jetzt folgt die PBP-Browser-Runtime.'
    exec sudo -n -- "$SCRIPT_PATH" --root-stage "$admin_user" "$persona_class" \
        "$accept_disposable_test"
}

prepare_log() {
    if [[ -e "$LOG_FILE" || -L "$LOG_FILE" ]]; then
        [[ -f "$LOG_FILE" && ! -L "$LOG_FILE" && "$(stat -c '%u' "$LOG_FILE")" == '0' ]] ||
            die "Unsafe log path: $LOG_FILE"
    else
        : >"$LOG_FILE"
    fi
    : >"$LOG_FILE"
    chown root:root "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
}

run_logged() {
    local description="$1" status
    shift
    log "$description"
    if "$@" >>"$LOG_FILE" 2>&1; then
        return 0
    else
        status=$?
    fi
    printf 'The command failed; last log lines from %s:\n' "$LOG_FILE" >&2
    tail -n 30 "$LOG_FILE" >&2 || true
    die "$description failed with exit code $status."
}

lock_value() {
    local key="$1" file="$2"
    awk -v key="$key" '
    $1 == key { count += 1; value = $2 }
    END { if (count == 1 && value != "") print value; else exit 1 }
  ' "$file"
}

validate_platform() {
    local major architecture python_version

    [[ -r /etc/os-release && -d /run/systemd/system ]] ||
        die 'PBP requires a running Debian/Ubuntu systemd VM.'
    for command in apt-cache apt-get awk cmp curl dpkg env find findmnt getent id \
        install ip jq mktemp mountpoint mv nft pgrep python3 runuser sha256sum stat \
        systemctl systemd-escape timeout visudo xdg-mime; do
        command -v "$command" >/dev/null 2>&1 || die "Missing required command: $command"
    done
    # shellcheck disable=SC1091
    source /etc/os-release
    major="${VERSION_ID%%.*}"
    [[ "$major" =~ ^[0-9]+$ ]] || die "Unsupported OS version: ${VERSION_ID:-unknown}"
    case "${ID:-}" in
    debian) ((major >= 12)) || die 'PBP requires Debian 12 or newer.' ;;
    ubuntu) ((major >= 24)) || die 'PBP requires Ubuntu 24.04 or newer.' ;;
    *) die 'PBP supports Debian 12+ and Ubuntu 24.04+ only.' ;;
    esac
    PLATFORM_ID="$ID"

    architecture="$(dpkg --print-architecture)"
    case "$architecture" in
    amd64 | arm64) ;;
    *) die "Unsupported PBP architecture: $architecture" ;;
    esac
    PLATFORM_ARCH="$architecture"
    [[ "$(tr -d '[:space:]' <"$SCRIPT_DIR/ARCH")" == "$PLATFORM_ARCH" ]] ||
        die 'This PBP artifact was built for a different architecture.'

    python_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')"
    case "$python_version" in
    311 | 312 | 313) PYTHON_TAG="cp${python_version}" ;;
    *) die "Unsupported system Python for PBP: $python_version" ;;
    esac
    [[ -f "$SCRIPT_DIR/python/${PYTHON_TAG}.tar.gz" &&
        ! -L "$SCRIPT_DIR/python/${PYTHON_TAG}.tar.gz" ]] ||
        die "The PBP artifact has no runtime for ${PYTHON_TAG}."

    RELEASE="$(tr -d '[:space:]' <"$SCRIPT_DIR/VERSION")"
    [[ "$RELEASE" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] ||
        die "Invalid PBP release: $RELEASE"
    TARGET_RELEASE="$INSTALL_ROOT/releases/$RELEASE"
}

validate_gui_user() {
    local marker expected_marker actual_marker password_status group
    local -a groups=()

    getent passwd "$GUI_USER" >/dev/null ||
        die 'Run ssh-gui-hardening before PBP; the malwarelab GUI user is missing.'
    GUI_UID="$(id -u "$GUI_USER")"
    GUI_HOME="$(getent passwd "$GUI_USER" | awk -F: '{print $6}')"
    [[ "$GUI_UID" =~ ^[0-9]+$ && "$GUI_UID" -ge 1000 ]] ||
        die 'malwarelab is not a normal GUI user.'
    [[ "$GUI_HOME" == /* && -d "$GUI_HOME" && ! -L "$GUI_HOME" ]] ||
        die 'malwarelab has an unsafe home directory.'
    [[ "$(stat -c '%u' "$GUI_HOME")" == "$GUI_UID" ]] ||
        die 'malwarelab home has the wrong owner.'

    marker="$GUI_MARKER"
    [[ -f "$marker" && ! -L "$marker" &&
        "$(stat -c '%u:%a' "$marker")" == '0:600' ]] ||
        die 'malwarelab is not the GUI-bootstrap-managed disposable account.'
    expected_marker="${GUI_USER}:${GUI_UID}"
    actual_marker="$(tr -d '\r\n' <"$marker")"
    [[ "$actual_marker" == "$expected_marker" ]] ||
        die 'malwarelab identity no longer matches its GUI marker.'
    password_status="$(passwd --status "$GUI_USER" | awk '{print $2}')"
    [[ "$password_status" == 'L' ]] || die 'malwarelab password must remain locked.'

    IFS=' ' read -r -a groups <<<"$(id -nG "$GUI_USER")"
    for group in "${groups[@]}"; do
        case "$group" in
        sudo | wheel | docker | lxd | lxd-admin | incus | incus-admin | libvirt | disk | kvm)
            die "malwarelab belongs to the privileged $group group."
            ;;
        esac
    done
    if pgrep -u "$GUI_USER" -f '(^|/)(camoufox-bin|firefox|firefox-esr)([[:space:]]|$)' \
        >/dev/null 2>&1; then
        die 'Close every browser window in VNC before installing PBP.'
    fi
}

verify_mullvad_transport() {
    local status_json auto_state lockdown_state settings check_file

    command -v mullvad >/dev/null 2>&1 || die 'Mullvad CLI is not installed.'
    status_json="$(timeout --foreground 20s mullvad status --json)" ||
        die 'Could not read Mullvad connection status.'
    jq -e '
    .state == "connected"
    and .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"
    and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))
  ' <<<"$status_json" >/dev/null ||
        die 'PBP requires an active Mullvad Shadowsocks connection on port 443.'

    settings="$(timeout --foreground 20s mullvad anti-censorship get)" ||
        die 'Could not read Mullvad anti-censorship settings.'
    grep -Fxq 'mode: shadowsocks' <<<"$settings" ||
        die 'Mullvad Shadowsocks mode is not retained.'
    grep -Fxq 'shadowsocks settings: port 443' <<<"$settings" ||
        die 'Mullvad Shadowsocks port is not 443.'
    auto_state="$(timeout --foreground 20s mullvad auto-connect get)" ||
        die 'Could not read Mullvad auto-connect.'
    lockdown_state="$(timeout --foreground 20s mullvad lockdown-mode get)" ||
        die 'Could not read Mullvad lockdown mode.'
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$auto_state" ||
        die 'Mullvad auto-connect is not enabled.'
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$lockdown_state" ||
        die 'Mullvad lockdown mode is not enabled.'

    check_file="$TMP_DIR/mullvad-germany.json"
    run_logged 'Der tatsächliche Mullvad-Ausgang in Deutschland wird erneut geprüft.' \
        curl -4 --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 --retry 2 --retry-delay 1 \
        --output "$check_file" "$MULLVAD_CHECK_URL"
    jq -e '
    .mullvad_exit_ip == true
    and .country == "Germany"
    and (.ip | type == "string" and test("^[0-9]+([.][0-9]+){3}$"))
  ' "$check_file" >/dev/null ||
        die 'The active Mullvad exit is not in Germany.'
}

safe_root_directory() {
    local path="$1" mode
    [[ -d "$path" && ! -L "$path" && "$(stat -c '%u' "$path")" == '0' ]] || return 1
    mode="$(stat -c '%a' "$path")"
    (((8#$mode & 0022) == 0))
}

install_egress_guard() {
    local helper_tmp service_tmp

    safe_root_directory /usr/local || die 'Unsafe /usr/local directory.'
    if [[ ! -e /usr/local/libexec && ! -L /usr/local/libexec ]]; then
        install -d -o root -g root -m 0755 /usr/local/libexec
    fi
    safe_root_directory /usr/local/libexec || die 'Unsafe /usr/local/libexec directory.'
    safe_root_directory /etc/systemd/system || die 'Unsafe systemd unit directory.'

    helper_tmp="$(mktemp /usr/local/libexec/.dynamicflow-pbp-egress-guard-load.XXXXXXXX)"
    cat >"$helper_tmp" <<'EOF_EGRESS_GUARD'
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH LC_ALL=C
umask 077

readonly TABLE='toolkit_pbp_guard'
readonly CHECK_URL='https://am.i.mullvad.net/json'
RUNTIME_DIR=''

guard_error() { printf 'PBP egress guard: %s\n' "$*" >&2; exit 1; }
cleanup_guard() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$RUNTIME_DIR" && -d "$RUNTIME_DIR" ]]; then
    rm -rf -- "$RUNTIME_DIR"
  fi
  exit "$status"
}

render_rules() {
  local uid="$1" interface="${2:-}"
  printf '%s\n' \
    "table inet ${TABLE} {" \
    '  chain output {' \
    '    type filter hook output priority 200; policy accept;' \
    "    meta skuid ${uid} oifname \"lo\" udp dport 53 counter accept comment \"dynamicflow-pbp-loopback-dns-udp\"" \
    "    meta skuid ${uid} oifname \"lo\" tcp dport 53 counter accept comment \"dynamicflow-pbp-loopback-dns-tcp\"" \
    "    meta skuid ${uid} oifname \"lo\" ct state established,related counter accept comment \"dynamicflow-pbp-loopback-replies\""
  if [[ -n "$interface" ]]; then
    printf '%s\n' \
      "    meta skuid ${uid} oifname \"${interface}\" counter accept comment \"dynamicflow-pbp-mullvad\""
  fi
  printf '%s\n' \
    "    meta skuid ${uid} counter reject with icmpx type admin-prohibited comment \"dynamicflow-pbp-deny\"" \
    '  }' \
    '}'
}

apply_rules() {
  local uid="$1" interface="${2:-}" transaction="$RUNTIME_DIR/guard.nft"
  : >"$transaction" || return 1
  if /usr/sbin/nft list table inet "$TABLE" >/dev/null 2>&1; then
    printf 'delete table inet %s\n' "$TABLE" >>"$transaction" || return 1
  fi
  render_rules "$uid" "$interface" >>"$transaction" || return 1
  /usr/sbin/nft --check --file "$transaction" || return 1
  /usr/sbin/nft --file "$transaction"
}

discover_mullvad_interface() {
  local status_json interface

  status_json="$(
    /usr/bin/timeout --foreground 20s /usr/bin/mullvad status --json 2>/dev/null
  )" || return 1
  interface="$(/usr/bin/jq -er '
    select(
      .state == "connected"
      and .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"
      and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))
    )
    | .details.endpoint.tunnel_interface
    | select(type == "string")
  ' <<<"$status_json")" || return 1
  [[ "$interface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || return 1
  /usr/bin/ip -j -d link show dev "$interface" | /usr/bin/jq -e '
    length == 1
    and .[0].linkinfo.info_kind? == "wireguard"
    and (.[0].flags | index("UP"))
  ' >/dev/null || return 1
  /usr/bin/ip -j -4 address show dev "$interface" | /usr/bin/jq -e '
    any(.[].addr_info[]?; .family == "inet" and .scope == "global")
  ' >/dev/null || return 1
  printf '%s\n' "$interface"
}

verify_browser_egress() {
  local response

  response="$(
    /usr/sbin/runuser -u malwarelab -- /usr/bin/curl -4 --disable \
      --fail --silent --show-error --location --max-filesize 131072 \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 8 --max-time 20 "$CHECK_URL"
  )" || return 1
  [[ "${#response}" -le 131072 ]] || return 1
  /usr/bin/jq -e '
    .mullvad_exit_ip == true
    and .country == "Germany"
    and (.ip | type == "string" and test("^[0-9]+([.][0-9]+){3}$"))
  ' <<<"$response" >/dev/null || return 1
  response=''
}

activate_and_verify_guard() {
  local uid="$1"

  interface="$(discover_mullvad_interface)" || return 1
  apply_rules "$uid" "$interface" || return 1
  verify_browser_egress
}

[[ "$(id -u)" == '0' && "$#" == '0' ]] \
  || guard_error 'must run as root without arguments'
for binary in /usr/bin/curl /usr/bin/id /usr/bin/ip /usr/bin/jq \
  /usr/bin/mktemp /usr/bin/mullvad /usr/bin/rm /usr/bin/stat /usr/bin/timeout \
  /usr/sbin/nft /usr/sbin/runuser; do
  [[ -f "$binary" && ! -L "$binary" && "$(stat -c '%u' "$binary")" == '0' ]] \
    || guard_error "unsafe required binary: $binary"
  mode="$(stat -c '%a' "$binary")"
  (( (8#$mode & 0022) == 0 )) || guard_error "writable required binary: $binary"
done

uid="$(/usr/bin/id -u malwarelab)" || guard_error 'malwarelab is missing'
[[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]] \
  || guard_error 'malwarelab has an invalid uid'
RUNTIME_DIR="$(/usr/bin/mktemp -d /run/dynamicflow-pbp-egress.XXXXXXXX)"
trap cleanup_guard EXIT HUP INT TERM
interface=''

# Deny this UID before any discovery, probe, or repair. A broken route therefore
# cannot fall back to the provider interface while Mullvad is being recovered.
apply_rules "$uid" || guard_error 'could not apply the deny-first guard'
if ! activate_and_verify_guard "$uid"; then
  printf '%s\n' \
    'PBP egress guard: Mullvad reports connected but browser routing is unhealthy; reconnecting once.' >&2
  /usr/bin/timeout --foreground 45s /usr/bin/mullvad disconnect --wait \
    >/dev/null 2>&1 || guard_error 'could not disconnect unhealthy Mullvad routing'
  /usr/bin/timeout --foreground 120s /usr/bin/mullvad connect --wait \
    >/dev/null 2>&1 || guard_error 'could not reconnect Mullvad'
  activate_and_verify_guard "$uid" \
    || guard_error 'browser routing is still unhealthy after one Mullvad reconnect'
fi
/usr/sbin/nft list table inet "$TABLE" >/dev/null \
  || guard_error 'the final PBP egress guard is not active'
EOF_EGRESS_GUARD
    chown root:root "$helper_tmp"
    chmod 0755 "$helper_tmp"
    mv -fT -- "$helper_tmp" "$EGRESS_GUARD_HELPER"

    service_tmp="$(mktemp /etc/systemd/system/.dynamicflow-pbp-egress-guard.XXXXXXXX)"
    cat >"$service_tmp" <<EOF_EGRESS_SERVICE
[Unit]
Description=Dynamicflow PBP browser-UID egress guard
Wants=mullvad-daemon.service
After=local-fs.target mullvad-daemon.service
Before=tigervncserver@:1.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=$EGRESS_GUARD_HELPER
RemainAfterExit=yes
Restart=on-failure
RestartSec=3s
TimeoutStartSec=45s
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETUID
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF_EGRESS_SERVICE
    chown root:root "$service_tmp"
    chmod 0644 "$service_tmp"
    mv -fT -- "$service_tmp" "$EGRESS_GUARD_SERVICE_FILE"
    systemctl daemon-reload
    run_logged 'Der unabhängige PBP-UID-Kill-Switch wird geladen und aktiviert.' \
        systemctl enable --now "$EGRESS_GUARD_SERVICE"
    systemctl is-enabled --quiet "$EGRESS_GUARD_SERVICE" ||
        die 'The PBP egress guard service is not enabled.'
    systemctl is-active --quiet "$EGRESS_GUARD_SERVICE" ||
        die 'The PBP egress guard service is not active.'
    /usr/sbin/nft list table inet "$EGRESS_GUARD_TABLE" >/dev/null ||
        die 'The PBP egress guard nftables table is missing.'
}

install_vpn_policy_gate() {
    local helper_tmp sudoers_tmp

    safe_root_directory /usr/local || die 'Unsafe /usr/local directory.'
    if [[ ! -e /usr/local/libexec && ! -L /usr/local/libexec ]]; then
        install -d -o root -g root -m 0755 /usr/local/libexec
    fi
    safe_root_directory /usr/local/libexec || die 'Unsafe /usr/local/libexec directory.'
    safe_root_directory /etc || die 'Unsafe /etc directory.'
    safe_root_directory /etc/sudoers.d || die 'Unsafe /etc/sudoers.d directory.'

    helper_tmp="$(mktemp /usr/local/libexec/.dynamicflow-pbp-vpn-verify.XXXXXXXX)"
    cat >"$helper_tmp" <<'EOF_POLICY_HELPER'
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH LC_ALL=C
umask 077

policy_failure() { exit 20; }
transient_failure() { exit 21; }

[[ "$(id -u)" == '0' && "$#" == '0' ]] || policy_failure
for binary in /usr/bin/findmnt /usr/bin/getent /usr/bin/grep /usr/bin/id \
  /usr/bin/ip /usr/bin/jq /usr/bin/mullvad /usr/bin/printf /usr/bin/stat \
  /usr/bin/timeout /usr/sbin/nft; do
  [[ -f "$binary" && ! -L "$binary" && "$(stat -c '%u' "$binary")" == '0' ]] \
    || transient_failure
  mode="$(stat -c '%a' "$binary")"
  (( (8#$mode & 0022) == 0 )) || transient_failure
done

status_json="$(/usr/bin/timeout --foreground 20s /usr/bin/mullvad status --json)" \
  || transient_failure
connection_state="$(/usr/bin/jq -er '.state | strings' <<<"$status_json")" \
  || transient_failure
# A disconnected/connecting daemon is a bounded-retry outage, not proof that
# the retained Germany/Shadowsocks/lockdown policy is wrong. Connected with a
# different transport, on the other hand, is a definitive policy violation.
[[ "$connection_state" == 'connected' ]] || transient_failure
/usr/bin/jq -e '
  .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"
  and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))
' <<<"$status_json" >/dev/null || policy_failure
settings="$(/usr/bin/timeout --foreground 20s /usr/bin/mullvad anti-censorship get)" \
  || transient_failure
/usr/bin/grep -Fxq 'mode: shadowsocks' <<<"$settings" || policy_failure
/usr/bin/grep -Fxq 'shadowsocks settings: port 443' <<<"$settings" || policy_failure
auto_state="$(/usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect get)" \
  || transient_failure
lockdown_state="$(/usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode get)" \
  || transient_failure
/usr/bin/grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$auto_state" \
  || policy_failure
/usr/bin/grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$lockdown_state" \
  || policy_failure

gui_uid="$(/usr/bin/id -u malwarelab)" || policy_failure
[[ "$gui_uid" =~ ^[0-9]+$ && "$gui_uid" -ge 1000 ]] || policy_failure
interface="$(
  /usr/bin/ip -j -d link show | /usr/bin/jq -er '
    [.[]
      | select((.ifname | type) == "string")
      | select(.ifname | test("^wg[0-9]+-mullvad$"))
      | select(.linkinfo.info_kind? == "wireguard")
      | select(.flags | index("UP"))
      | .ifname]
    | unique
    | if length == 1 then .[0] else error("expected one Mullvad interface") end
  '
)" || transient_failure
[[ "$interface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || policy_failure
/usr/bin/ip -j -4 address show dev "$interface" | /usr/bin/jq -e '
  any(.[].addr_info[]?; .family == "inet" and .scope == "global")
' >/dev/null || transient_failure
guard_json="$(/usr/sbin/nft -j -n list table inet toolkit_pbp_guard)" \
  || policy_failure
/usr/bin/jq -e --argjson uid "$gui_uid" --arg interface "$interface" '
  def has_match($rule; $key; $value):
    any($rule.expr[]?;
      ((.match? | type) == "object")
      and .match.op == "=="
      and .match.left.meta.key? == $key
      and .match.right == $value);
  def has_verdict($rule; $name):
    any($rule.expr[]?; has($name));
  def has_counter($rule):
    any($rule.expr[]?; has("counter"));
  def has_dport($rule; $protocol; $port):
    any($rule.expr[]?;
      .match.left.payload.protocol? == $protocol
      and .match.left.payload.field? == "dport"
      and .match.op == "=="
      and .match.right == $port);
  [.nftables[] | .chain?
    | select(.family == "inet" and .table == "toolkit_pbp_guard")]
    as $chains
  | [.nftables[] | .rule?
      | select(.family == "inet" and .table == "toolkit_pbp_guard"
        and .chain == "output")]
    as $rules
  | ($chains | length) == 1
  and $chains[0].name == "output"
  and $chains[0].type == "filter"
  and $chains[0].hook == "output"
  and $chains[0].prio == 200
  and $chains[0].policy == "accept"
  and ($rules | map(.comment)) == [
    "dynamicflow-pbp-loopback-dns-udp",
    "dynamicflow-pbp-loopback-dns-tcp",
    "dynamicflow-pbp-loopback-replies",
    "dynamicflow-pbp-mullvad",
    "dynamicflow-pbp-deny"
  ]
  and ($rules[0] as $rule
    | ($rule.expr | length) == 5
    and has_match($rule; "skuid"; $uid)
    and has_match($rule; "oifname"; "lo")
    and has_dport($rule; "udp"; 53)
    and has_counter($rule)
    and has_verdict($rule; "accept"))
  and ($rules[1] as $rule
    | ($rule.expr | length) == 5
    and has_match($rule; "skuid"; $uid)
    and has_match($rule; "oifname"; "lo")
    and has_dport($rule; "tcp"; 53)
    and has_counter($rule)
    and has_verdict($rule; "accept"))
  and ($rules[2] as $rule
    | ($rule.expr | length) == 5
    and has_match($rule; "skuid"; $uid)
    and has_match($rule; "oifname"; "lo")
    and any($rule.expr[]?;
      .match.op? == "in"
      and .match.left.ct.key? == "state"
      and .match.right == [2, 4])
    and has_counter($rule)
    and has_verdict($rule; "accept"))
  and ($rules[3] as $rule
    | ($rule.expr | length) == 4
    and has_match($rule; "skuid"; $uid)
    and has_match($rule; "oifname"; $interface)
    and has_counter($rule)
    and has_verdict($rule; "accept"))
  and ($rules[4] as $rule
    | ($rule.expr | length) == 3
    and has_match($rule; "skuid"; $uid)
    and (all($rule.expr[]?; .match.left.meta.key? != "oifname"))
    and has_counter($rule)
    and has_verdict($rule; "reject"))
' <<<"$guard_json" >/dev/null || policy_failure

passwd_entry="$(/usr/bin/getent passwd malwarelab)" || policy_failure
IFS=: read -r account _ passwd_uid _ _ gui_home _ <<<"$passwd_entry"
[[ "$account" == 'malwarelab' && "$passwd_uid" == "$gui_uid" \
    && "$gui_home" =~ ^/[A-Za-z0-9._/-]+$ ]] || policy_failure
download_target="$gui_home/Downloads"
download_backing='/var/lib/toolkit/pbp/downloads'
[[ -d "$download_target" && ! -L "$download_target" \
    && -d "$download_backing" && ! -L "$download_backing" ]] \
  || policy_failure
[[ "$(/usr/bin/stat -Lc '%d:%i' "$download_target")" \
    == "$(/usr/bin/stat -Lc '%d:%i' "$download_backing")" ]] \
  || policy_failure
[[ "$(/usr/bin/stat -Lc '%u:%a' "$download_target")" == "${gui_uid}:700" ]] \
  || policy_failure
[[ "$(/usr/bin/findmnt -rn -M "$download_target" -o TARGET)" == "$download_target" ]] \
  || policy_failure
download_options="$(/usr/bin/findmnt -rn -M "$download_target" -o OPTIONS)" \
  || policy_failure
for required_option in nodev nosuid noexec; do
  [[ ",$download_options," == *",$required_option,"* ]] || policy_failure
done
/usr/bin/printf 'policy-ok\n'
EOF_POLICY_HELPER
    chown root:root "$helper_tmp"
    chmod 0755 "$helper_tmp"
    mv -fT -- "$helper_tmp" "$VPN_POLICY_HELPER"

    sudoers_tmp="$(mktemp /etc/sudoers.d/.dynamicflow-pbp-vpn-policy.XXXXXXXX)"
    printf '%s\n' \
        'malwarelab ALL=(root) NOPASSWD: /usr/local/libexec/dynamicflow-pbp-vpn-verify ""' \
        >"$sudoers_tmp"
    chown root:root "$sudoers_tmp"
    chmod 0440 "$sudoers_tmp"
    visudo -cf "$sudoers_tmp" >/dev/null || die 'Generated PBP VPN sudo policy is invalid.'
    mv -fT -- "$sudoers_tmp" "$VPN_POLICY_SUDOERS"
    visudo -cf "$VPN_POLICY_SUDOERS" >/dev/null ||
        die 'Installed PBP VPN sudo policy is invalid.'
}

select_runtime_packages() {
    local candidate family selected
    local -a common=(
        ca-certificates dbus-x11 libcairo2 libdbus-1-3 libdbus-glib-1-2
        libdrm2 libgbm1
        libnspr4 libnss3 libpango-1.0-0 libx11-6 libx11-xcb1 libxcb1
        libxcomposite1 libxdamage1 libxext6 libxfixes3 libxkbcommon0
        libxrandr2 libxrender1 libxss1 libxt6 locales python3 xdg-utils xdotool
        zenity
    )
    local -a candidates=()
    RUNTIME_PACKAGES=("${common[@]}")

    for family in atk atk-bridge cups glib gtk3 alsa; do
        case "$family" in
        atk) candidates=(libatk1.0-0t64 libatk1.0-0) ;;
        atk-bridge) candidates=(libatk-bridge2.0-0t64 libatk-bridge2.0-0) ;;
        cups) candidates=(libcups2t64 libcups2) ;;
        glib) candidates=(libglib2.0-0t64 libglib2.0-0) ;;
        gtk3) candidates=(libgtk-3-0t64 libgtk-3-0) ;;
        alsa) candidates=(libasound2t64 libasound2) ;;
        *) die "Internal error: unknown runtime package family $family" ;;
        esac
        selected=''
        for candidate in "${candidates[@]}"; do
            if apt-cache show "$candidate" >/dev/null 2>&1; then
                selected="$candidate"
                break
            fi
        done
        [[ -n "$selected" ]] ||
            die "No supported $family runtime package is available."
        RUNTIME_PACKAGES+=("$selected")
    done
    if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns &&
        "$(tr -d '[:space:]' \
            </proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == '1' ]]; then
        RUNTIME_PACKAGES+=(apparmor)
    fi
}

install_apparmor_userns_profile() {
    local restriction='/proc/sys/kernel/apparmor_restrict_unprivileged_userns'
    local enabled='/sys/module/apparmor/parameters/enabled'
    local expected="$SCRIPT_DIR/apparmor/toolkit-pbp"

    [[ -r "$enabled" && "$(tr -d '[:space:]' <"$enabled")" == 'Y' &&
    -r "$restriction" &&
    "$(tr -d '[:space:]' <"$restriction")" == '1' ]] || return 0
    command -v apparmor_parser >/dev/null 2>&1 ||
        die 'AppArmor user-namespace restriction is active but apparmor_parser is missing.'
    [[ -f "$expected" && ! -L "$expected" ]] ||
        die 'The bundled PBP AppArmor profile is missing or unsafe.'
    if [[ -e "$APPARMOR_PROFILE" || -L "$APPARMOR_PROFILE" ]]; then
        [[ -f "$APPARMOR_PROFILE" && ! -L "$APPARMOR_PROFILE" &&
            "$(stat -c '%u:%a' "$APPARMOR_PROFILE")" == '0:644' ]] ||
            die "Unsafe AppArmor profile path: $APPARMOR_PROFILE"
        cmp -s "$expected" "$APPARMOR_PROFILE" ||
            die 'An unknown AppArmor profile already occupies the Toolkit PBP path.'
    else
        install -o root -g root -m 0644 "$expected" "$APPARMOR_PROFILE"
    fi
    run_logged 'Das enge AppArmor-userns-Profil für Firefox-Sandboxing wird geprüft.' \
        apparmor_parser -Q "$APPARMOR_PROFILE"
    run_logged 'Das AppArmor-userns-Profil wird geladen, ohne die globale Sperre abzuschalten.' \
        apparmor_parser -r "$APPARMOR_PROFILE"
}

ensure_no_conflicting_firefox_policy() {
    local expected
    [[ -e "$FIREFOX_POLICY" || -L "$FIREFOX_POLICY" ]] || return 0
    [[ -f "$FIREFOX_POLICY" && ! -L "$FIREFOX_POLICY" &&
        "$(stat -c '%u' "$FIREFOX_POLICY")" == '0' ]] ||
        die "Unsafe global Firefox policy path: $FIREFOX_POLICY"
    expected="$TMP_DIR/old-toolkit-firefox-policy.json"
    cat >"$expected" <<'EOF_POLICY'
{
  "policies": {
    "DNSOverHTTPS": {"Enabled": false, "Locked": true},
    "Proxy": {"Mode": "none", "Locked": true},
    "DontCheckDefaultBrowser": true,
    "DownloadDirectory": "${home}/Downloads",
    "Preferences": {
      "media.peerconnection.enabled": {"Value": false, "Status": "locked"}
    }
  }
}
EOF_POLICY
    cmp -s "$expected" "$FIREFOX_POLICY" ||
        die 'A non-Toolkit global Firefox policy could contradict the PBP persona.'
    rm -f -- "$FIREFOX_POLICY"
}

verify_asset_hashes() {
    local asset_lock="$SCRIPT_DIR/browser-assets.lock"
    local browser_expected ublock_expected browser_actual ublock_actual

    browser_expected="$(lock_value "browser_${PLATFORM_ARCH}_sha256" "$asset_lock")" ||
        die 'Missing browser hash for this architecture.'
    ublock_expected="$(lock_value ublock_sha256 "$asset_lock")" ||
        die 'Missing uBlock Origin hash.'
    browser_actual="$(sha256sum "$SCRIPT_DIR/assets/camoufox.zip" | awk '{print $1}')"
    ublock_actual="$(sha256sum "$SCRIPT_DIR/assets/ublock-origin.xpi" | awk '{print $1}')"
    [[ "$browser_actual" == "$browser_expected" ]] ||
        die 'The bundled Camoufox asset hash does not match its pinned upstream hash.'
    [[ "$ublock_actual" == "$ublock_expected" ]] ||
        die 'The bundled uBlock Origin asset hash does not match its pinned AMO hash.'
}

safe_extract() {
    local kind="$1" source="$2" destination="$3" limit="$4"
    install -d -o root -g root -m 0700 "$destination"
    /usr/bin/python3 "$SCRIPT_DIR/safe-extract.py" "$kind" "$source" "$destination" \
        --max-bytes "$limit"
    chown -R root:root "$destination"
    chmod -R go-w "$destination"
    chmod 0755 "$destination"
}
install_browser_search_policy() {
    local search_source hardening_source destination stage
    search_source="$SCRIPT_DIR/browser-search-policy.json"
    hardening_source="$SCRIPT_DIR/browser-hardening-policy.json"
    destination="$STAGE_DIR/browser/distribution/policies.json"

    [[ -f "$search_source" && ! -L "$search_source" ]] ||
        die 'The bundled browser search policy is missing or unsafe.'
    [[ -f "$hardening_source" && ! -L "$hardening_source" ]] ||
        die 'The bundled browser hardening policy is missing or unsafe.'
    [[ -f "$destination" && ! -L "$destination" &&
        "$(stat -c '%u' "$destination")" == '0' ]] ||
        die 'The extracted browser policy is missing or unsafe.'
    jq -e '
    .policies.SearchEngines.Default == "None"
    and (.policies.SearchEngines.Add | length) == 1
    and .policies.SearchEngines.Add[0].Name == "None"
    and .policies.SearchEngines.Add[0].URLTemplate == "http://127.0.0.1"
    and (.policies.ExtensionSettings | keys | sort) == [
      "magnolia@12.34", "uBlock0@raymondhill.net"
    ]
    and .policies.ExtensionSettings["magnolia@12.34"] == {
      "default_area": "navbar", "updates_disabled": true
    }
    and .policies.ExtensionSettings["uBlock0@raymondhill.net"] == {
      "default_area": "navbar", "updates_disabled": true
    }
  ' "$destination" >/dev/null ||
        die 'The pinned browser no longer has the reviewed search and extension policy.'
    jq -e '
    .PreventInstalls == true
    and .Default == "DuckDuckGo"
    and .Remove == ["Google", "Bing", "Amazon.com", "eBay", "Twitter", "Wikipedia (en)"]
    and (keys | sort) == ["Default", "PreventInstalls", "Remove"]
  ' "$search_source" >/dev/null ||
        die 'The bundled browser search policy is malformed.'
    jq -e '
    (keys == ["policies"])
    and (.policies | keys | sort) == [
      "BlockAboutAddons", "BlockAboutConfig", "BlockAboutProfiles",
      "DNSOverHTTPS", "DisableDeveloperTools", "DisableSecurityBypass",
      "ExtensionSettings", "HttpsOnlyMode", "InstallAddonsPermission",
      "NetworkPrediction", "Permissions", "PopupBlocking",
      "Preferences", "PromptForDownloadLocation", "Proxy"
    ]
    and .policies.BlockAboutAddons == true
    and .policies.BlockAboutConfig == true
    and .policies.BlockAboutProfiles == true
    and .policies.DisableDeveloperTools == true
    and .policies.DisableSecurityBypass == {
      "InvalidCertificate": true, "SafeBrowsing": true
    }
    and .policies.DNSOverHTTPS == {"Enabled": false, "Locked": true}
    and .policies.Proxy == {"Mode": "none", "Locked": true}
    and .policies.InstallAddonsPermission == {"Default": false}
    and .policies.ExtensionSettings == {
      "*": {"installation_mode": "blocked"},
      "uBlock0@raymondhill.net": {
        "installation_mode": "allowed", "updates_disabled": true
      }
    }
    and .policies.HttpsOnlyMode == "force_enabled"
    and .policies.NetworkPrediction == false
    and .policies.PopupBlocking == {"Default": true, "Locked": true}
    and .policies.PromptForDownloadLocation == true
    and .policies.Permissions == {
      "Camera": {"BlockNewRequests": true, "Locked": true},
      "Location": {"BlockNewRequests": true, "Locked": true},
      "Microphone": {"BlockNewRequests": true, "Locked": true},
      "Notifications": {"BlockNewRequests": true, "Locked": true}
    }
    and (.policies.Preferences | length) == 37
    and all(.policies.Preferences[];
      (keys | sort) == ["Status", "Value"] and .Status == "locked")
  ' "$hardening_source" >/dev/null ||
        die 'The bundled browser hardening policy has an unexpected schema.'
    jq -e '
    (.policies.Preferences | with_entries(.value = .value.Value)) == {
      "browser.download.start_downloads_in_tmp_dir": false,
      "browser.download.useDownloadDir": false,
      "browser.safebrowsing.allowOverride": false,
      "browser.safebrowsing.blockedURIs.enabled": true,
      "browser.safebrowsing.downloads.enabled": true,
      "browser.safebrowsing.malware.enabled": true,
      "browser.safebrowsing.phishing.enabled": true,
      "camoufox.uBO.assetsBootstrapLocation": "",
      "devtools.debugger.prompt-connection": true,
      "devtools.debugger.remote-enabled": false,
      "dom.disable_open_during_load": true,
      "dom.file.createInChild": false,
      "dom.filesystem.pathcheck.disabled": false,
      "dom.security.https_only_mode": true,
      "extensions.blocklist.enabled": true,
      "extensions.quarantinedDomains.enabled": true,
      "focusmanager.testmode": false,
      "network.cookie.cookieBehavior": 5,
      "network.dns.disablePrefetch": true,
      "network.dns.disablePrefetchFromHTTPS": true,
      "network.proxy.type": 0,
      "network.trr.mode": 5,
      "permissions.default.camera": 2,
      "permissions.default.desktop-notification": 2,
      "permissions.default.geo": 2,
      "permissions.default.microphone": 2,
      "privacy.partition.network_state": true,
      "privacy.trackingprotection.enabled": true,
      "security.certerror.hideAddException": true,
      "security.enterprise_roots.enabled": false,
      "security.fileuri.strict_origin_policy": true,
      "security.notification_enable_delay": 1000,
      "vulpineos.actionlock.enabled": false,
      "vulpineos.dom_export.enabled": false,
      "vulpineos.injection_filter.enabled": false,
      "vulpineos.sentinel.probe.enabled": false,
      "vulpineos.trustwarm.enabled": false
    }
  ' "$hardening_source" >/dev/null ||
        die 'The browser hardening preference set is not the reviewed PBP set.'

    stage="$TMP_DIR/browser-policies.json"
    jq --slurpfile search "$search_source" \
        --slurpfile hardening "$hardening_source" \
        --arg downloads "$GUI_HOME/Downloads" '
    . as $base
    | (. * {"policies": $hardening[0].policies})
    | .policies.ExtensionSettings["magnolia@12.34"] =
        ($base.policies.ExtensionSettings["magnolia@12.34"]
         * {"installation_mode": "allowed"})
    | .policies.SearchEngines = $search[0]
    | .policies.SearchSuggestEnabled = false
    | .policies.DownloadDirectory = $downloads
  ' "$destination" >"$stage"
    jq --slurpfile search "$search_source" \
        --slurpfile hardening "$hardening_source" \
        --slurpfile base "$destination" \
        --arg downloads "$GUI_HOME/Downloads" -e '
    . as $rendered
    | ([
        $hardening[0].policies
        | to_entries[]
        | . as $entry
        | select($entry.key != "ExtensionSettings")
        | select($rendered.policies[$entry.key] != $entry.value)
      ] | length) == 0
    and ([
      $base[0].policies
      | to_entries[]
      | . as $entry
      | select(($hardening[0].policies | has($entry.key)) | not)
      | select($entry.key != "SearchEngines")
      | select($rendered.policies[$entry.key] != $entry.value)
    ] | length) == 0
    and (.policies.ExtensionSettings | keys | sort) == [
      "*", "magnolia@12.34", "uBlock0@raymondhill.net"
    ]
    and .policies.ExtensionSettings["*"] == {
      "installation_mode": "blocked"
    }
    and .policies.ExtensionSettings["magnolia@12.34"] == {
      "default_area": "navbar",
      "installation_mode": "allowed",
      "updates_disabled": true
    }
    and .policies.ExtensionSettings["uBlock0@raymondhill.net"] == {
      "default_area": "navbar",
      "installation_mode": "allowed",
      "updates_disabled": true
    }
    and .policies.SearchEngines == $search[0]
    and .policies.SearchSuggestEnabled == false
    and .policies.DownloadDirectory == $downloads
    and .policies.DisableAppUpdate == true
    and .policies.DisableSystemAddonUpdate == true
    and .policies.DisableTelemetry == true
    and .policies.ExtensionUpdate == false
    and .policies.DNSOverHTTPS == {"Enabled": false, "Locked": true}
    and .policies.Proxy == {"Mode": "none", "Locked": true}
    and .policies.Preferences["network.trr.mode"] == {
      "Value": 5, "Status": "locked"
    }
    and .policies.Preferences["devtools.debugger.remote-enabled"] == {
      "Value": false, "Status": "locked"
    }
  ' "$stage" >/dev/null ||
        die 'The merged browser search and hardening policy failed verification.'
    install -o root -g root -m 0644 "$stage" "$destination"
}

smoke_runtime() {
    local release_dir="$1"
    run_logged 'Die gepinnte Python-/Camoufox-Runtime wird importiert.' \
        env -i PATH='/usr/bin:/bin' HOME='/root' LANG='C.UTF-8' \
        PYTHONNOUSERSITE=1 PYTHONPATH="$release_dir/python" \
        /usr/bin/python3 -c \
        'import camoufox, browserforge, playwright, lxml, numpy, orjson, yaml'
    run_logged 'Das Camoufox-Binary wird ohne Browserprofil geprüft.' \
        timeout --foreground 30s "$release_dir/browser/camoufox-bin" --version
}

build_release() {
    local bundle_hash installed_hash runtime_tar browser_version package_version

    install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
    bundle_hash="$(sha256sum "$SCRIPT_DIR/SHA256SUMS" | awk '{print $1}')"
    if [[ -e "$TARGET_RELEASE" || -L "$TARGET_RELEASE" ]]; then
        [[ -d "$TARGET_RELEASE" && ! -L "$TARGET_RELEASE" &&
            "$(stat -c '%u' "$TARGET_RELEASE")" == '0' ]] ||
            die "Unsafe existing PBP release path: $TARGET_RELEASE"
        installed_hash="$(tr -d '[:space:]' <"$TARGET_RELEASE/BUNDLE_SHA256" 2>/dev/null || true)"
        [[ "$installed_hash" == "$bundle_hash" ]] ||
            die "PBP release $RELEASE already exists with different content."
        smoke_runtime "$TARGET_RELEASE"
        return 0
    fi

    STAGE_DIR="$INSTALL_ROOT/releases/.${RELEASE}.tmp.$$"
    [[ ! -e "$STAGE_DIR" && ! -L "$STAGE_DIR" ]] ||
        die "Temporary PBP release path exists: $STAGE_DIR"
    install -d -o root -g root -m 0755 "$STAGE_DIR"
    safe_extract zip "$SCRIPT_DIR/assets/camoufox.zip" "$STAGE_DIR/browser" 1610612736
    install_browser_search_policy
    [[ -f "$STAGE_DIR/browser/camoufox-bin" &&
        ! -L "$STAGE_DIR/browser/camoufox-bin" ]] ||
        die 'Camoufox archive did not contain a safe root camoufox-bin.'
    chmod 0755 "$STAGE_DIR/browser/camoufox-bin"

    runtime_tar="$SCRIPT_DIR/python/${PYTHON_TAG}.tar.gz"
    safe_extract tar "$runtime_tar" "$STAGE_DIR/python" 1073741824
    install -d -o root -g root -m 0755 "$STAGE_DIR/assets"
    safe_extract zip "$SCRIPT_DIR/assets/ublock-origin.xpi" \
        "$STAGE_DIR/assets/ublock-origin" 67108864
    [[ -f "$STAGE_DIR/assets/ublock-origin/manifest.json" &&
        ! -L "$STAGE_DIR/assets/ublock-origin/manifest.json" ]] ||
        die 'uBlock Origin did not contain a safe root manifest.json.'
    install -o root -g root -m 0755 "$SCRIPT_DIR/launch-pbp.py" "$STAGE_DIR/launch-pbp.py"
    install -o root -g root -m 0644 "$SCRIPT_DIR/requirements.lock" \
        "$STAGE_DIR/requirements.lock"
    install -o root -g root -m 0644 "$SCRIPT_DIR/browser-assets.lock" \
        "$STAGE_DIR/browser-assets.lock"
    printf '%s\n' "$RELEASE" >"$STAGE_DIR/VERSION"
    printf '%s\n' "$PLATFORM_ARCH" >"$STAGE_DIR/ARCH"
    browser_version="$(lock_value browser_version "$SCRIPT_DIR/browser-assets.lock")"
    package_version="$(lock_value camoufox_package "$SCRIPT_DIR/browser-assets.lock")"
    printf '%s\n' "$browser_version" >"$STAGE_DIR/BROWSER_VERSION"
    printf '%s\n' "$package_version" >"$STAGE_DIR/CAMOUFOX_PACKAGE"
    printf '%s\n' "$bundle_hash" >"$STAGE_DIR/BUNDLE_SHA256"
    chown root:root "$STAGE_DIR"/{VERSION,ARCH,BROWSER_VERSION,CAMOUFOX_PACKAGE,BUNDLE_SHA256}
    chmod 0644 "$STAGE_DIR"/{VERSION,ARCH,BROWSER_VERSION,CAMOUFOX_PACKAGE,BUNDLE_SHA256}
    chmod 0755 "$STAGE_DIR"

    smoke_runtime "$STAGE_DIR"
    mv -T -- "$STAGE_DIR" "$TARGET_RELEASE"
    STAGE_DIR=''
}

ensure_user_directory() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" && ! -L "$path" && "$(stat -c '%u' "$path")" == "$GUI_UID" ]] ||
            die "Unsafe malwarelab directory: $path"
        chmod 0700 "$path"
    else
        install -d -o "$GUI_USER" -g "$GUI_USER" -m 0700 "$path"
    fi
}

verify_download_bind_mount() {
    local target="$GUI_HOME/Downloads" options required

    mountpoint -q "$target" || return 1
    [[ "$(findmnt -rn -M "$target" -o TARGET)" == "$target" ]] || return 1
    [[ "$(stat -Lc '%d:%i' "$target")" == "$(stat -Lc '%d:%i' "$DOWNLOAD_BACKING")" ]] ||
        return 1
    [[ "$(stat -Lc '%u:%a' "$target")" == "${GUI_UID}:700" ]] || return 1
    options="$(findmnt -rn -M "$target" -o OPTIONS)" || return 1
    for required in nodev nosuid noexec; do
        [[ ",$options," == *",$required,"* ]] || return 1
    done
}

install_download_bind_mount() {
    local target="$GUI_HOME/Downloads" target_state unit unit_tmp
    local needs_mount=0

    [[ "$GUI_HOME" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
        die 'The malwarelab home path is unsafe for a systemd mount unit.'
    if [[ ! -e "$target" && ! -L "$target" ]]; then
        install -d -o "$GUI_USER" -g "$GUI_USER" -m 0700 "$target"
    fi
    [[ -d "$target" && ! -L "$target" ]] ||
        die 'The PBP Downloads mountpoint is missing or unsafe.'
    if mountpoint -q "$target"; then
        verify_download_bind_mount ||
            die 'An unexpected mount already occupies the PBP Downloads path.'
    else
        target_state="$(stat -c '%u:%a' "$target")"
        [[ "$target_state" == "${GUI_UID}:700" || "$target_state" == '0:0' ]] ||
            die 'The unmounted PBP Downloads path has unsafe ownership or mode.'
        find "$target" -mindepth 1 -print -quit | grep -q . &&
            die 'Downloads must be empty before the hardened bind mount is installed.'
        needs_mount=1
    fi

    if [[ ! -e /var/lib/toolkit && ! -L /var/lib/toolkit ]]; then
        install -d -o root -g root -m 0755 /var/lib/toolkit
    fi
    safe_root_directory /var/lib/toolkit || die 'Unsafe /var/lib/toolkit directory.'
    if [[ ! -e /var/lib/toolkit/pbp && ! -L /var/lib/toolkit/pbp ]]; then
        install -d -o root -g root -m 0700 /var/lib/toolkit/pbp
    fi
    safe_root_directory /var/lib/toolkit/pbp || die 'Unsafe PBP state directory.'
    chmod 0700 /var/lib/toolkit/pbp
    if [[ -e "$DOWNLOAD_BACKING" || -L "$DOWNLOAD_BACKING" ]]; then
        [[ -d "$DOWNLOAD_BACKING" && ! -L "$DOWNLOAD_BACKING" &&
            "$(stat -c '%u:%a' "$DOWNLOAD_BACKING")" == "${GUI_UID}:700" ]] ||
            die 'Unsafe PBP download backing directory.'
    else
        install -d -o "$GUI_USER" -g "$GUI_USER" -m 0700 "$DOWNLOAD_BACKING"
    fi
    if ((needs_mount == 1)); then
        # keep the hidden mountpoint itself inaccessible. if mounting ever fails,
        # downloads fail closed instead of becoming a normal executable directory.
        chown root:root "$target"
        chmod 0000 "$target"
    fi

    unit="$(systemd-escape --path --suffix=mount "$target")"
    [[ "$unit" =~ ^[A-Za-z0-9_.@-]+[.]mount$ ]] ||
        die 'Could not derive a safe Downloads mount unit name.'
    unit_tmp="$(mktemp "/etc/systemd/system/.${unit}.XXXXXXXX")"
    cat >"$unit_tmp" <<EOF_DOWNLOAD_MOUNT
[Unit]
Description=Dynamicflow PBP hardened Downloads bind mount
Before=tigervncserver@:1.service

[Mount]
What=$DOWNLOAD_BACKING
Where=$target
Type=none
Options=bind,nodev,nosuid,noexec
DirectoryMode=0000

[Install]
WantedBy=local-fs.target
EOF_DOWNLOAD_MOUNT
    chown root:root "$unit_tmp"
    chmod 0644 "$unit_tmp"
    mv -fT -- "$unit_tmp" "/etc/systemd/system/$unit"
    systemctl daemon-reload
    run_logged 'Downloads werden als nodev,nosuid,noexec-Bind-Mount aktiviert.' \
        systemctl enable --now "$unit"
    systemctl is-enabled --quiet "$unit" ||
        die 'The hardened Downloads mount is not enabled.'
    systemctl is-active --quiet "$unit" ||
        die 'The hardened Downloads mount is not active.'
    verify_download_bind_mount ||
        die 'The hardened Downloads bind mount failed runtime verification.'
}

prepare_user_state() {
    ensure_user_directory "$GUI_HOME/.local"
    ensure_user_directory "$GUI_HOME/.local/share"
    ensure_user_directory "$GUI_HOME/.local/share/toolkit-pbp"
    ensure_user_directory "$GUI_HOME/.local/state"
    ensure_user_directory "$GUI_HOME/.local/state/dynamicflow"
    ensure_user_directory "$GUI_HOME/.local/state/dynamicflow/pbp"
    ensure_user_directory "$GUI_HOME/.local/state/dynamicflow/pbp/logs"
    ensure_user_directory "$GUI_HOME/.config"
    ensure_user_directory "$GUI_HOME/.cache"
    migrate_profile_state
}

migrate_profile_state() {
    local base stable legacy_root entry
    local nonempty=0
    base="$GUI_HOME/.local/share/toolkit-pbp"
    stable="$base/profile"
    legacy_root="$base/profiles"

    if [[ -e "$legacy_root" || -L "$legacy_root" ]]; then
        [[ -d "$legacy_root" && ! -L "$legacy_root" &&
            "$(stat -c '%u' "$legacy_root")" == "$GUI_UID" ]] ||
            die 'The legacy PBP profiles root is unsafe.'
        while IFS= read -r -d '' entry; do
            [[ -d "$entry" && ! -L "$entry" &&
                "$(stat -c '%u' "$entry")" == "$GUI_UID" ]] ||
                die 'A legacy PBP profile entry is unsafe.'
            if find "$entry" -mindepth 1 -print -quit | grep -q .; then
                nonempty=1
            fi
        done < <(find "$legacy_root" -mindepth 1 -maxdepth 1 -print0)
    fi
    ((nonempty == 0)) ||
        die 'A legacy PBP profile cannot be safely matched to the new persona classes; use a fresh disposable VM.'
    if [[ -e "$stable" || -L "$stable" ]]; then
        ensure_user_directory "$stable"
        return 0
    fi
    ensure_user_directory "$stable"
}

python_for_release() {
    env -i PATH='/usr/bin:/bin' HOME="$GUI_HOME" USER="$GUI_USER" \
        LOGNAME="$GUI_USER" SHELL='/bin/bash' LANG='de_DE.UTF-8' \
        LC_ALL='de_DE.UTF-8' TZ='Europe/Berlin' PYTHONNOUSERSITE=1 \
        PYTHONPATH="$TARGET_RELEASE/python" /usr/bin/python3 "$@"
}

install_persona() {
    local persona_class="$1" persona_tmp existing_class
    local browser="$TARGET_RELEASE/browser/camoufox-bin"
    local addon="$TARGET_RELEASE/assets/ublock-origin"

    valid_persona_class "$persona_class" || die 'Invalid selected persona class.'
    install -d -o root -g root -m 0755 /etc/toolkit
    if [[ -e "$PERSONA_FILE" || -L "$PERSONA_FILE" ]]; then
        [[ -f "$PERSONA_FILE" && ! -L "$PERSONA_FILE" &&
            "$(stat -c '%u:%a' "$PERSONA_FILE")" == '0:644' ]] ||
            die "Unsafe PBP persona path: $PERSONA_FILE"
        persona_tmp="$(mktemp /etc/toolkit/.pbp-persona.XXXXXXXX)"
        if ! python_for_release "$TARGET_RELEASE/launch-pbp.py" migrate-persona \
            --persona "$PERSONA_FILE" --browser "$browser" --addon "$addon" \
            >"$persona_tmp"; then
            rm -f -- "$persona_tmp"
            die 'The stable PBP persona is incompatible or legacy; rotate persona and profile together in a fresh disposable VM.'
        fi
        chown root:root "$persona_tmp"
        chmod 0644 "$persona_tmp"
        if ! python_for_release "$TARGET_RELEASE/launch-pbp.py" validate-persona \
            --persona "$persona_tmp" --release "$RELEASE" \
            --browser "$browser" --addon "$addon"; then
            rm -f -- "$persona_tmp"
            die 'The migrated stable PBP persona failed validation; it was not activated.'
        fi
        existing_class="$(jq -er '.persona_class | select(type == "string")' "$persona_tmp")" ||
            {
                rm -f -- "$persona_tmp"
                die 'The stable PBP persona does not name a valid class.'
            }
        if [[ "$existing_class" != "$persona_class" ]]; then
            rm -f -- "$persona_tmp"
            die "This VM is bound to persona class $existing_class; class changes require a fresh disposable VM."
        fi
        if cmp -s "$PERSONA_FILE" "$persona_tmp"; then
            rm -f -- "$persona_tmp"
        else
            mv -fT -- "$persona_tmp" "$PERSONA_FILE"
        fi
        return 0
    fi

    persona_tmp="$(mktemp /etc/toolkit/.pbp-persona.XXXXXXXX)"
    if ! runuser -u "$GUI_USER" -- \
        env -i PATH='/usr/bin:/bin' HOME="$GUI_HOME" USER="$GUI_USER" \
        LOGNAME="$GUI_USER" SHELL='/bin/bash' LANG='de_DE.UTF-8' \
        LC_ALL='de_DE.UTF-8' TZ='Europe/Berlin' PYTHONNOUSERSITE=1 \
        PYTHONPATH="$TARGET_RELEASE/python" /usr/bin/python3 \
        "$TARGET_RELEASE/launch-pbp.py" materialize-persona \
        --release "$RELEASE" --browser "$browser" --addon "$addon" \
        --home "$GUI_HOME" --persona-class "$persona_class" >"$persona_tmp"; then
        rm -f -- "$persona_tmp"
        die "Camoufox could not materialize the pinned $persona_class Windows persona."
    fi
    chown root:root "$persona_tmp"
    chmod 0644 "$persona_tmp"
    python_for_release "$TARGET_RELEASE/launch-pbp.py" validate-persona \
        --persona "$persona_tmp" --release "$RELEASE" \
        --browser "$browser" --addon "$addon"
    mv -fT -- "$persona_tmp" "$PERSONA_FILE"
}

install_launchers() {
    local wrapper_tmp desktop_tmp mime_type current_tmp

    install -d -o root -g root -m 0755 /usr/local/bin /usr/local/share/applications
    wrapper_tmp="$TMP_DIR/pbp-browser"
    cat >"$wrapper_tmp" <<'EOF_WRAPPER'
#!/bin/sh
set -eu
PATH='/usr/local/bin:/usr/bin:/bin'
export PATH
root='/opt/toolkit/pbp/current'
PYTHONNOUSERSITE=1
PYTHONPATH="$root/python"
export PYTHONNOUSERSITE PYTHONPATH
if [ "${1:-}" = 'desktop' ] || [ "${1:-}" = 'run' ]; then
  exec /usr/bin/python3 "$root/launch-pbp.py" "$@"
fi
exec /usr/bin/python3 "$root/launch-pbp.py" run "$@"
EOF_WRAPPER
    install -o root -g root -m 0755 "$wrapper_tmp" "$WRAPPER"

    desktop_tmp="$TMP_DIR/toolkit-pbp.desktop"
    cat >"$desktop_tmp" <<'EOF_DESKTOP'
[Desktop Entry]
Type=Application
Version=1.0
Name=PBP Browser
Comment=Windows-persona Firefox through Mullvad Germany
Exec=/usr/local/bin/pbp-browser desktop %u
TryExec=/usr/local/bin/pbp-browser
Icon=web-browser
Terminal=false
StartupNotify=true
Categories=Network;WebBrowser;
MimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;
EOF_DESKTOP
    install -o root -g root -m 0644 "$desktop_tmp" "$DESKTOP_FILE"

    current_tmp="$INSTALL_ROOT/.current.$$"
    rm -f -- "$current_tmp"
    ln -s "releases/$RELEASE" "$current_tmp"
    mv -fT -- "$current_tmp" "$INSTALL_ROOT/current"

    for mime_type in text/html x-scheme-handler/http x-scheme-handler/https; do
        runuser -u "$GUI_USER" -- env HOME="$GUI_HOME" \
            XDG_DATA_DIRS='/usr/local/share:/usr/share' \
            xdg-mime default toolkit-pbp.desktop "$mime_type"
        [[ "$(runuser -u "$GUI_USER" -- env HOME="$GUI_HOME" \
            XDG_DATA_DIRS='/usr/local/share:/usr/share' \
            xdg-mime query default "$mime_type")" == 'toolkit-pbp.desktop' ]] ||
            die "PBP is not the default handler for $mime_type."
    done
}

root_stage() {
    local admin_user="$1" persona_class="$2" accept_disposable_test="$3"
    local -a RUNTIME_PACKAGES=()

    [[ "$(id -u)" -eq 0 ]] || die 'Internal error: PBP root stage is not root.'
    validate_bundle_mode "$accept_disposable_test"
    valid_admin_user "$admin_user" || die 'Invalid SSH administrator identity.'
    valid_persona_class "$persona_class" || die 'Invalid selected persona class.'
    command -v flock >/dev/null 2>&1 || die 'flock is required.'
    install -d -o root -g root -m 0755 /run/lock
    exec 9>/run/lock/toolkit-pbp-bootstrap.lock
    flock -n 9 || die 'Another PBP bootstrap is already running.'
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    TMP_DIR="$(mktemp -d /tmp/toolkit-pbp.XXXXXXXX)"
    chmod 0700 "$TMP_DIR"
    prepare_log
    validate_platform
    validate_gui_user
    verify_mullvad_transport
    verify_asset_hashes
    ensure_no_conflicting_firefox_policy

    # close the installer race before package work: once the existing browser
    # has been confirmed stopped, harden its writable download path and apply
    # the UID deny-first guard before any longer-running installation steps.
    prepare_user_state
    install_download_bind_mount
    install_egress_guard

    run_logged 'Camoufox-Systembibliotheken werden erst hinter Mullvad installiert.' \
        apt-get -qq update
    select_runtime_packages
    run_logged 'Die minimale Camoufox-GUI-Runtime wird installiert.' \
        env DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
        "${RUNTIME_PACKAGES[@]}"
    run_logged 'Die deutsche UTF-8-Locale wird bereitgestellt.' locale-gen de_DE.UTF-8
    install_apparmor_userns_profile

    build_release
    install_persona "$persona_class"
    install_launchers
    install_vpn_policy_gate
    run_logged 'Mullvad-Routing wird nach den Paketänderungen erneut geladen und geprüft.' \
        systemctl restart "$EGRESS_GUARD_SERVICE"
    verify_mullvad_transport
    run_logged 'Kill-Switch, Download-Mount und Mullvad-Policy werden gemeinsam geprüft.' \
        "$VPN_POLICY_HELPER"

    cat >&2 <<EOF

[toolkit-pbp] Bereit.
Host:                 ${PLATFORM_ID} / ${PLATFORM_ARCH} (Linux bleibt Linux)
Browser-Persona:      Windows / Firefox \
$(lock_value browser_version "$SCRIPT_DIR/browser-assets.lock")
Browser-Freigabe:     ${BROWSER_RELEASE_STATUS}
Persona-Klasse:       ${persona_class}
Sprache / Zeitzone:   de-DE / Europe/Berlin
Mullvad-Ausgang:      Deutschland, IPv4 geprüft
Anti-Zensur:          Shadowsocks auf Port 443
Auto-Connect:         an
Lockdown-Mode:        an
Browserproxy:         keiner; normales Mullvad-Systemrouting
Persona:              pro VM einmalig erzeugt und innerhalb der VM stabil
Profil:               VM-weit stabil unter ${GUI_HOME}/.local/share/toolkit-pbp/profile
Runtime-Logs:         ${GUI_HOME}/.local/state/dynamicflow/pbp/logs (0600)
Downloads:            bind,nodev,nosuid,noexec und vor jedem Start geprüft
Browser-Kill-Switch:  UID ${GUI_UID}, nur lokaler DNS und Mullvad-Interface
Cloud-Firewall:       unverändert; von dieser VM nicht zuverlässig prüfbar
Standardbrowser:      PBP Browser

Der Launcher startet nur als malwarelab in der VNC-Sitzung und prüft vor
jedem Start und danach laufend einen deutschen Mullvad-Ausgang. Bei einem
unklaren Ausfall wird der Browser sofort offline geschaltet; erst zwei
erfolgreiche Prüfungen geben ihn wieder frei. Ein falscher Egress beendet PBP
fail-closed und sichtbar. Playwright übernimmt nur den Prozess-Lebenszyklus,
keine Klicks, Navigation oder Seiten-Skripte.

Wichtig: Fingerprinting hat keine mathematische 100-Prozent-Garantie. Dieses
Setup priorisiert eine konsistente reale Windows-Firefox-Persona und lehnt
widersprüchliche oder ungeprüfte Zustände ab.

Cloud-/SSH-Hinweis: Die bestehende SSH-Sitzung und eine unabhängige
Provider-Konsole offen lassen. Die exakte IPv4-Access-Regel (/32)
wirksam hinzufügen und die Provider-Aktivierung abwarten; erst danach breitere
SSH-Freigaben entfernen und im finalen Inbound-Zustand das lokale
./pbp-m-Gate bestätigen. Danach eine frische Verbindung testen und erst bei
Erfolg die alte Sitzung schließen. TCP-Port 5901 niemals öffentlich
freigeben. Ausgehende Regeln während Mullvad/PBP nicht versehentlich sperren.

Installationslog (root-only): $LOG_FILE
EOF
}

main() {
    verify_bundle
    if [[ "$(id -u)" -eq 0 ]]; then
        [[ "${1:-}" == '--root-stage' && "$#" -eq 4 ]] ||
            die 'Run PBP as the normal SSH administrator.'
        root_stage "$2" "$3" "$4"
    else
        user_stage "$@"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
