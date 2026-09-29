#!/usr/bin/env bash
set -Eeuo pipefail
set +x

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
export LC_ALL=C
umask 077
ulimit -c 0 >/dev/null 2>&1 || true

readonly MULLVAD_KEY_URL='https://repository.mullvad.net/deb/mullvad-keyring.asc'
readonly MULLVAD_KEY_FINGERPRINT='A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF'
readonly MULLVAD_GROUP='toolkit-mullvad'
readonly MULLVAD_SOCKET='/var/run/mullvad-vpn'
readonly DROPIN_DIR='/etc/systemd/system/mullvad-daemon.service.d'
readonly DROPIN_FILE="${DROPIN_DIR}/10-toolkit-management-group.conf"
readonly SSH_BYPASS_TABLE='toolkit_mullvad_ssh'
readonly SSH_RULES_FILE='/etc/toolkit/mullvad-ssh-bypass.nft'
readonly SSH_LOADER='/usr/local/libexec/toolkit-mullvad-ssh-bypass-load'
readonly SSH_DAEMON_DROPIN="${DROPIN_DIR}/20-toolkit-ssh-bypass.conf"
readonly EARLY_DROPIN_DIR='/etc/systemd/system/mullvad-early-boot-blocking.service.d'
readonly SSH_EARLY_DROPIN="${EARLY_DROPIN_DIR}/20-toolkit-ssh-bypass.conf"
readonly SSH_BOOT_SERVICE_FILE='/etc/systemd/system/toolkit-mullvad-ssh-bypass.service'
readonly SSH_BOOT_SERVICE='toolkit-mullvad-ssh-bypass.service'
readonly ROLLBACK_HELPER='/usr/local/libexec/toolkit-mullvad-rollback'
readonly ROLLBACK_SERVICE_FILE='/etc/systemd/system/toolkit-mullvad-rollback.service'
readonly ROLLBACK_TIMER_FILE='/etc/systemd/system/toolkit-mullvad-rollback.timer'
readonly ROLLBACK_SERVICE='toolkit-mullvad-rollback.service'
readonly ROLLBACK_TIMER='toolkit-mullvad-rollback.timer'
readonly FIREFOX_POLICY='/etc/firefox/policies/policies.json'
readonly IPV6_SYSCTL_FILE='/etc/sysctl.d/99-toolkit-vpn-ipv6.conf'
readonly MULLVAD_CHECK_URL='https://am.i.mullvad.net/json'
readonly LOG_FILE='/var/log/toolkit-vpn-bootstrap.log'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
TMP_DIR=''
TTY_PATH=''
TTY_STATE=''
ACCOUNT_NUMBER=''
LOGIN_CREATED=0
WATCHDOG_ARMED=0
VPN_MAY_BE_ACTIVE=0
PLATFORM_ID=''
PLATFORM_ARCH=''
CURRENT_SSH_PORT='-'
CURRENT_SSH_CLIENT_PORT='-'
GUI_READY=0
GUI_HOME=''
GUI_UID=''
XAUTH_READY=0
OUTBOUND_HTTPS_ENROLLMENT=0
declare -a SSH_PORTS=()

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '\n[toolkit-vpn] %s\n' "$*" >&2
}

restore_tty() {
    if [[ -n "$TTY_STATE" && -n "$TTY_PATH" ]]; then
        stty "$TTY_STATE" <"$TTY_PATH" >/dev/null 2>&1 || true
        TTY_STATE=''
    fi
}

cleanup() {
    local status=$?
    local disconnected=0
    trap - EXIT HUP INT TERM TSTP
    restore_tty
    ACCOUNT_NUMBER=''
    unset ACCOUNT_NUMBER
    if [[ "$status" -ne 0 ]]; then
        if [[ "$VPN_MAY_BE_ACTIVE" -eq 1 ]] &&
            command -v /usr/bin/mullvad >/dev/null 2>&1; then
            if emergency_disconnect; then
                disconnected=1
            fi
        fi
        if [[ "$WATCHDOG_ARMED" -eq 1 && "$disconnected" -eq 1 ]]; then
            systemctl stop "$ROLLBACK_TIMER" >/dev/null 2>&1 || true
            WATCHDOG_ARMED=0
        fi
        if [[ "$LOGIN_CREATED" -eq 1 ]] && command -v /usr/bin/mullvad >/dev/null 2>&1; then
            mullvad_cmd account logout >/dev/null 2>&1 || true
            sleep 10
        fi
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
        die 'Internal Toolkit VPN bundle checksum verification failed.'
}

validate_admin_user() {
    local admin_user="$1"
    local uid

    [[ "$admin_user" =~ ^[a-z_][a-z0-9_-]*$ ]] ||
        die "Invalid SSH administrator name: $admin_user"
    [[ "$admin_user" != 'root' && "$admin_user" != 'malwarelab' ]] ||
        die 'Run this installer as the normal SSH administrator, not root or malwarelab.'
    getent passwd "$admin_user" >/dev/null ||
        die "SSH administrator does not exist: $admin_user"
    uid="$(id -u "$admin_user")"
    [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]] ||
        die "Refusing a system account as SSH administrator: $admin_user"
}

valid_ssh_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    ((10#$port >= 1 && 10#$port <= 65535))
}

validate_location() {
    case "$1" in
    any | de) ;;
    *) die "Unsupported Mullvad location: $1 (expected any or de)." ;;
    esac
}

user_stage() {
    local admin_user ssh_port='-' ssh_client_port='-' ssh_family='-'
    local ssh_server_address location='any' install_firefox=1 return_after=0
    local outbound_https_enrollment=0
    local -a ssh_fields=()

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
        --location)
            [[ "$#" -ge 2 ]] || die '--location needs any or de.'
            location="$2"
            shift 2
            ;;
        --location=*)
            location="${1#*=}"
            shift
            ;;
        --skip-firefox)
            install_firefox=0
            shift
            ;;
        --return-after-install)
            return_after=1
            shift
            ;;
        --outbound-https-enrollment)
            outbound_https_enrollment=1
            shift
            ;;
        *) die "Unsupported Toolkit VPN argument: $1" ;;
        esac
    done
    validate_location "$location"
    [[ "$(id -u)" -ne 0 ]] ||
        die 'Run the Toolkit VPN command as the normal SSH administrator, not through sudo.'
    admin_user="$(id -un)"
    validate_admin_user "$admin_user"
    command -v sudo >/dev/null 2>&1 || die 'sudo is required.'

    if [[ "$outbound_https_enrollment" == '1' ]]; then
        [[ -z "${SSH_CONNECTION:-}" ]] ||
            die 'The outbound-HTTPS enrollment mode must run from a provider console, not SSH.'
        # a later systemd reconcile has no controlling TTY and is still safe when
        # the mullvad account is already configured. ensure_mullvad_account performs
        # the mandatory hidden /dev/tty prompt only when an account must be added.
        ssh_family='https'
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        IFS=' ' read -r -a ssh_fields <<<"$SSH_CONNECTION"
        [[ "${#ssh_fields[@]}" -eq 4 ]] ||
            die 'SSH_CONNECTION does not contain exactly four fields.'
        ssh_port="${ssh_fields[3]}"
        ssh_client_port="${ssh_fields[1]}"
        ssh_server_address="${ssh_fields[2]}"
        valid_ssh_port "$ssh_port" ||
            die 'SSH_CONNECTION contains an invalid server port.'
        valid_ssh_port "$ssh_client_port" ||
            die 'SSH_CONNECTION contains an invalid client port.'
        ssh_port="$((10#$ssh_port))"
        ssh_client_port="$((10#$ssh_client_port))"
        case "$ssh_server_address" in
        *:*) ssh_family='6' ;;
        *.*) ssh_family='4' ;;
        *) die 'SSH_CONNECTION contains an unknown server address family.' ;;
        esac
    fi
    [[ "$ssh_family" == '4' || "$ssh_family" == 'https' ]] ||
        die 'Run the IPv4-only VPN installer from direct IPv4 SSH, or explicitly from a provider console with --outbound-https-enrollment.'

    log 'Passwortloser Cloud-sudo-Zugriff wird verwendet.'
    if [[ "$return_after" == '1' ]]; then
        sudo -n -- "$SCRIPT_PATH" --root-stage \
            "$admin_user" "$ssh_port" "$ssh_client_port" "$ssh_family" "$location" \
            "$install_firefox"
    else
        exec sudo -n -- "$SCRIPT_PATH" --root-stage \
            "$admin_user" "$ssh_port" "$ssh_client_port" "$ssh_family" "$location" \
            "$install_firefox"
    fi
}

validate_platform() {
    local major architecture

    [[ -r /etc/os-release ]] || die 'Missing /etc/os-release.'
    [[ -d /run/systemd/system ]] || die 'A running systemd system is required.'
    for required_command in apt-get awk cmp dpkg dpkg-query env getent groupadd \
        install mktemp mv pgrep runuser sha256sum sort ss stat systemctl timeout; do
        command -v "$required_command" >/dev/null 2>&1 ||
            die "Missing required command: $required_command"
    done
    # shellcheck disable=SC1091
    source /etc/os-release
    major="${VERSION_ID%%.*}"
    [[ "$major" =~ ^[0-9]+$ ]] || die "Unsupported OS version: ${VERSION_ID:-unknown}"
    case "${ID:-}" in
    debian) ((major >= 12)) || die 'Mullvad requires Debian 12 or newer.' ;;
    ubuntu) ((major >= 24)) || die 'Mullvad requires Ubuntu 24.04 or newer.' ;;
    *) die 'This release supports Debian 12+ and Ubuntu 24.04+ only.' ;;
    esac

    architecture="$(dpkg --print-architecture)"
    case "$architecture" in
    amd64 | arm64) ;;
    *) die "Unsupported architecture for Mullvad: $architecture" ;;
    esac
    PLATFORM_ID="${ID}"
    PLATFORM_ARCH="$architecture"
}

prepare_log() {
    if [[ -e "$LOG_FILE" || -L "$LOG_FILE" ]]; then
        [[ -f "$LOG_FILE" && ! -L "$LOG_FILE" ]] ||
            die "Unsafe log path: $LOG_FILE"
    else
        : >"$LOG_FILE"
    fi
    : >"$LOG_FILE"
    chown root:root "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
}

run_logged() {
    local description="$1"
    local status
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

install_managed_file() {
    local source="$1"
    local destination="$2"
    local mode="$3"
    local first_line second_line stage

    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] ||
            die "Unsafe managed path: $destination"
        [[ "$(stat -c '%u' "$destination")" == '0' ]] ||
            die "Managed file is not owned by root: $destination"
        if ! cmp -s "$source" "$destination"; then
            {
                IFS= read -r first_line || true
                IFS= read -r second_line || true
            } <"$destination"
            [[ "$first_line" == '# Managed by Toolkit VPN.' ||
                "$second_line" == '# Managed by Toolkit VPN.' ]] ||
                die "Refusing to overwrite a non-Toolkit file: $destination"
        fi
    fi

    stage="$(mktemp "${destination}.toolkit.XXXXXXXX")"
    install -o root -g root -m "$mode" "$source" "$stage"
    mv -fT -- "$stage" "$destination"
}

install_exact_file() {
    local source="$1"
    local destination="$2"
    local mode="$3"
    local stage

    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] ||
            die "Unsafe exact-file path: $destination"
        [[ "$(stat -c '%u' "$destination")" == '0' ]] ||
            die "Exact file is not owned by root: $destination"
        cmp -s "$source" "$destination" ||
            die "Refusing to replace a different existing file: $destination"
    fi

    stage="$(mktemp "${destination}.toolkit.XXXXXXXX")"
    install -o root -g root -m "$mode" "$source" "$stage"
    mv -fT -- "$stage" "$destination"
}

has_usable_ipv6_default_route() {
    local route_type remainder

    while IFS=$' \t' read -r route_type remainder; do
        case "$route_type" in
        '' | unreachable | blackhole | prohibit)
            ;;
        *)
            return 0
            ;;
        esac
    done
    return 1
}

remove_ipv6_ra_default_routes() {
    local log_file="${1:-$LOG_FILE}"
    local ra_routes status
    local attempts=0

    while :; do
        if ra_routes="$(ip -6 route show exact ::/0 proto ra 2>>"$log_file")"; then
            :
        else
            status=$?
            printf 'IPv6 RA default-route inspection failed with exit code %s.\n' \
                "$status" >>"$log_file"
            return "$status"
        fi
        [[ -n "$ra_routes" ]] || return 0

        printf 'Removing IPv6 RA default route with a clean delete request:\n%s\n' \
            "$ra_routes" >>"$log_file"
        if ! ip -6 route del default proto ra >>"$log_file" 2>&1; then
            printf '%s\n' \
                'Targeted IPv6 RA route deletion failed; the strict final route check will decide.' \
                >>"$log_file"
            return 0
        fi

        attempts=$((attempts + 1))
        if ((attempts >= 32)); then
            printf '%s\n' \
                'Stopped IPv6 RA route deletion after 32 attempts; the strict final route check will decide.' \
                >>"$log_file"
            return 0
        fi
    done
}

disable_system_ipv6() {
    local config_tmp all_state default_state ipv6_default_routes

    command -v ip >/dev/null 2>&1 || die 'iproute2 is required for IPv4-only mode.'
    command -v sysctl >/dev/null 2>&1 || die 'procps/sysctl is required for IPv4-only mode.'
    config_tmp="$TMP_DIR/99-toolkit-vpn-ipv6.conf"
    cat >"$config_tmp" <<'EOF_IPV6'
# Managed by Toolkit VPN.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF_IPV6
    install_managed_file "$config_tmp" "$IPV6_SYSCTL_FILE" 0644
    run_logged 'IPv6 wird für die IPv4-only-VM dauerhaft deaktiviert.' \
        sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 \
        net.ipv6.conf.default.disable_ipv6=1 \
        net.ipv6.conf.all.accept_ra=0 \
        net.ipv6.conf.default.accept_ra=0

    all_state="$(sysctl -n net.ipv6.conf.all.disable_ipv6)"
    default_state="$(sysctl -n net.ipv6.conf.default.disable_ipv6)"
    [[ "$all_state" == '1' && "$default_state" == '1' ]] ||
        die 'IPv6 could not be disabled safely.'
    if ip -6 address show scope global | grep -q 'inet6 '; then
        die 'A global IPv6 address remained after IPv6 was disabled.'
    fi
    log 'Veraltete IPv6 Router-Advertisement-Routen werden entfernt.'
    remove_ipv6_ra_default_routes ||
        die 'IPv6 Router-Advertisement routes could not be inspected safely.'
    ipv6_default_routes="$(ip -6 route show default)" ||
        die 'IPv6 default routes could not be inspected.'
    if has_usable_ipv6_default_route <<<"$ipv6_default_routes"; then
        printf 'Remaining IPv6 default routes:\n%s\n' "$ipv6_default_routes" >&2
        die 'An IPv6 default route remained after IPv6 was disabled.'
    fi
}

prepare_gui_context() {
    local passwd_line expected_uid group
    local -a groups=()

    getent passwd malwarelab >/dev/null || return 0
    passwd_line="$(getent passwd malwarelab)"
    expected_uid="$(printf '%s\n' "$passwd_line" | awk -F: '{print $3}')"
    GUI_HOME="$(printf '%s\n' "$passwd_line" | awk -F: '{print $6}')"
    group="$(id -gn malwarelab)"
    [[ "$expected_uid" =~ ^[0-9]+$ && "$expected_uid" -ge 1000 ]] ||
        die 'malwarelab is not a normal GUI user.'
    [[ "$GUI_HOME" == /* && -d "$GUI_HOME" && ! -L "$GUI_HOME" ]] ||
        die 'malwarelab has an unsafe home directory.'
    [[ "$(stat -c '%u' "$GUI_HOME")" == "$expected_uid" ]] ||
        die 'malwarelab home has the wrong owner.'

    if pgrep -u malwarelab -f '(^|/)(firefox|firefox-esr)([[:space:]]|$)' >/dev/null 2>&1; then
        die 'Close Firefox in the VNC session before running the VPN installer.'
    fi

    IFS=' ' read -r -a groups <<<"$(id -nG malwarelab)"
    for group in "${groups[@]}"; do
        case "$group" in
        sudo | wheel | docker | lxd | lxd-admin | incus | incus-admin | libvirt | disk | kvm)
            die "malwarelab must not be a member of the privileged $group group."
            ;;
        esac
    done
    GUI_UID="$expected_uid"
    GUI_READY=1
}

add_ssh_port() {
    local port="$1"
    valid_ssh_port "$port" || die "Invalid SSH port: $port"
    SSH_PORTS+=("$((10#$port))")
}

collect_ssh_ports() {
    local current_port="$1"
    local sshd_path effective key value remainder

    SSH_PORTS=()
    if [[ "$current_port" != '-' ]]; then
        add_ssh_port "$current_port"
        CURRENT_SSH_PORT="$((10#$current_port))"
    fi

    sshd_path="$(command -v sshd)" ||
        die 'OpenSSH server binary was not found.'
    effective="$($sshd_path -T 2>/dev/null)" ||
        die 'Could not read the effective sshd configuration.'
    while read -r key value remainder; do
        [[ "$key" == 'port' && -n "$value" && -z "${remainder:-}" ]] || continue
        add_ssh_port "$value"
    done <<<"$effective"
    effective=''

    [[ "${#SSH_PORTS[@]}" -gt 0 ]] || die 'No SSH management port could be determined.'
    mapfile -t SSH_PORTS < <(printf '%s\n' "${SSH_PORTS[@]}" | sort -nu)
}

verify_current_ssh_session() {
    local port sockets=''

    if [[ "$CURRENT_SSH_PORT" != '-' ]]; then
        if [[ "$CURRENT_SSH_CLIENT_PORT" != '-' ]]; then
            sockets="$(ss -Htn state established \
                "( sport = :${CURRENT_SSH_PORT} and dport = :${CURRENT_SSH_CLIENT_PORT} )" \
                2>/dev/null)" || die 'Could not inspect the current SSH connection.'
        else
            sockets="$(ss -Htn state established \
                "( sport = :${CURRENT_SSH_PORT} )" 2>/dev/null)" ||
                die 'Could not inspect the current SSH connection.'
        fi
    else
        for port in "${SSH_PORTS[@]}"; do
            sockets+="$(ss -Htn state established "( sport = :${port} )" 2>/dev/null)"
        done
    fi
    [[ -n "$sockets" ]] ||
        die 'No established SSH management connection could be verified.'
    sockets=''
}

ssh_chain_packet_counter() {
    local chain="$1"
    local listing count

    listing="$(/usr/sbin/nft -nn list chain inet "$SSH_BYPASS_TABLE" "$chain")" ||
        die "Could not inspect nftables chain: $chain"
    count="$(awk '
    /counter packets/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "packets" && $(i + 1) ~ /^[0-9]+$/) total += $(i + 1)
      }
    }
    END { print total + 0 }
  ' <<<"$listing")"
    [[ "$count" =~ ^[0-9]+$ ]] || die "Invalid nftables packet counter: $chain"
    printf '%s' "$count"
}

verify_bidirectional_ssh_flow() {
    local incoming_before outgoing_before incoming_after outgoing_after

    verify_current_ssh_session
    incoming_before="$(ssh_chain_packet_counter allow_incoming)"
    outgoing_before="$(ssh_chain_packet_counter allow_outgoing)"
    log 'Die aktive SSH/VNC-Verbindung wird nach Lockdown bidirektional geprüft.'
    sleep 2
    incoming_after="$(ssh_chain_packet_counter allow_incoming)"
    outgoing_after="$(ssh_chain_packet_counter allow_outgoing)"
    ((incoming_after > incoming_before && outgoing_after > outgoing_before)) ||
        die 'SSH bypass packet counters did not advance in both directions.'
    verify_current_ssh_session
}

render_ssh_bypass_rules() {
    local destination="$1"
    local port ports=''

    for port in "${SSH_PORTS[@]}"; do
        ports+="${ports:+, }${port}"
    done
    [[ -n "$ports" ]] || die 'Internal error: empty SSH port set.'
    printf '%s\n' \
        '# Managed by Toolkit VPN.' \
        "define SSH_PORTS = { ${ports} }" \
        '' \
        "table inet ${SSH_BYPASS_TABLE} {" \
        '  chain allow_incoming {' \
        '    type filter hook input priority -100; policy accept;' \
        '    tcp dport $SSH_PORTS ct state new,established counter ct mark set 0x00000f41 meta mark set 0x6d6f6c65;' \
        '  }' \
        '' \
        '  chain allow_outgoing {' \
        '    type route hook output priority -100; policy accept;' \
        '    ct mark 0x00000f41 tcp sport $SSH_PORTS ct state established counter meta mark set 0x6d6f6c65;' \
        '  }' \
        '}' >"$destination"
}

render_ssh_loader() {
    local destination="$1"
    cat >"$destination" <<'EOF_LOADER'
#!/bin/sh
# Managed by Toolkit VPN.
set -eu
umask 077

PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
rules='/etc/toolkit/mullvad-ssh-bypass.nft'
table='toolkit_mullvad_ssh'
tmp="$(mktemp /run/toolkit-mullvad-ssh-bypass.XXXXXXXX)"
cleanup() { rm -f -- "$tmp"; }
trap cleanup EXIT HUP INT TERM

if nft list table inet "$table" >/dev/null 2>&1; then
  printf 'delete table inet %s\n' "$table" >"$tmp"
fi
cat -- "$rules" >>"$tmp"
nft --check --file "$tmp"
nft --file "$tmp"
nft list table inet "$table" >/dev/null
EOF_LOADER
}

render_bypass_dropin() {
    local destination="$1"
    cat >"$destination" <<'EOF_DROPIN'
# Managed by Toolkit VPN.
[Unit]
After=nftables.service

[Service]
ExecStartPre=/usr/local/libexec/toolkit-mullvad-ssh-bypass-load
EOF_DROPIN
}

render_bypass_boot_service() {
    local destination="$1"
    cat >"$destination" <<'EOF_BOOT_SERVICE'
# Managed by Toolkit VPN.
[Unit]
Description=Toolkit Mullvad SSH bypass after early-boot blocking
After=local-fs.target nftables.service mullvad-early-boot-blocking.service
Before=ssh.service sshd.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/toolkit-mullvad-ssh-bypass-load
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_BOOT_SERVICE
}

install_ssh_bypass() {
    local rules_tmp loader_tmp dropin_tmp boot_service_tmp

    install -d -o root -g root -m 0755 /etc/toolkit /usr/local/libexec \
        "$DROPIN_DIR" "$EARLY_DROPIN_DIR"
    rules_tmp="$TMP_DIR/mullvad-ssh-bypass.nft"
    loader_tmp="$TMP_DIR/mullvad-ssh-bypass-load"
    dropin_tmp="$TMP_DIR/20-toolkit-ssh-bypass.conf"
    boot_service_tmp="$TMP_DIR/toolkit-mullvad-ssh-bypass.service"
    render_ssh_bypass_rules "$rules_tmp"
    render_ssh_loader "$loader_tmp"
    render_bypass_dropin "$dropin_tmp"
    render_bypass_boot_service "$boot_service_tmp"
    install_managed_file "$rules_tmp" "$SSH_RULES_FILE" 0600
    install_managed_file "$loader_tmp" "$SSH_LOADER" 0755
    install_managed_file "$dropin_tmp" "$SSH_DAEMON_DROPIN" 0644
    install_managed_file "$dropin_tmp" "$SSH_EARLY_DROPIN" 0644
    install_managed_file "$boot_service_tmp" "$SSH_BOOT_SERVICE_FILE" 0644
    "$SSH_LOADER"
    /usr/sbin/nft list table inet "$SSH_BYPASS_TABLE" >/dev/null ||
        die 'The SSH management bypass table is not active.'
}

render_rollback_files() {
    local helper="$1"
    local service="$2"
    local timer="$3"

    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '1' ]]; then
        cat >"$helper" <<'EOF_ROLLBACK_FAIL_CLOSED'
#!/bin/sh
# Managed by Toolkit VPN.
set -u
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

# The provider-console/outbound-HTTPS path has no management SSH session to
# preserve. A partial transition therefore remains fail-closed until an
# operator deliberately recovers it from the provider console.
/usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect set off >/dev/null 2>&1 || :
/usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set on >/dev/null 2>&1 || :
/usr/bin/timeout --foreground 45s /usr/bin/mullvad disconnect --wait >/dev/null 2>&1 || :
EOF_ROLLBACK_FAIL_CLOSED
    else
        cat >"$helper" <<'EOF_ROLLBACK'
#!/bin/sh
# Managed by Toolkit VPN.
set -u
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

/usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect set off >/dev/null 2>&1 || :
/usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set off >/dev/null 2>&1 || :
/usr/bin/timeout --foreground 45s /usr/bin/mullvad disconnect --wait >/dev/null 2>&1 || :
EOF_ROLLBACK
    fi
    cat >"$service" <<'EOF_ROLLBACK_SERVICE'
# Managed by Toolkit VPN.
[Unit]
Description=Toolkit Mullvad emergency disconnect
After=mullvad-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/toolkit-mullvad-rollback
EOF_ROLLBACK_SERVICE
    cat >"$timer" <<'EOF_ROLLBACK_TIMER'
# Managed by Toolkit VPN.
[Unit]
Description=Toolkit Mullvad connection rollback timer

[Timer]
OnActiveSec=360s
AccuracySec=1s
Persistent=false
RemainAfterElapse=no
Unit=toolkit-mullvad-rollback.service
EOF_ROLLBACK_TIMER
}

install_rollback_watchdog() {
    local helper_tmp service_tmp timer_tmp

    helper_tmp="$TMP_DIR/toolkit-mullvad-rollback"
    service_tmp="$TMP_DIR/toolkit-mullvad-rollback.service"
    timer_tmp="$TMP_DIR/toolkit-mullvad-rollback.timer"
    render_rollback_files "$helper_tmp" "$service_tmp" "$timer_tmp"
    install -d -o root -g root -m 0755 /usr/local/libexec /etc/systemd/system
    install_managed_file "$helper_tmp" "$ROLLBACK_HELPER" 0700
    install_managed_file "$service_tmp" "$ROLLBACK_SERVICE_FILE" 0644
    install_managed_file "$timer_tmp" "$ROLLBACK_TIMER_FILE" 0644
}

render_firefox_policy() {
    local destination="$1"
    cat >"$destination" <<'EOF_FIREFOX_POLICY'
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
EOF_FIREFOX_POLICY
}

install_firefox_policy() {
    local policy_tmp

    policy_tmp="$TMP_DIR/firefox-policies.json"
    render_firefox_policy "$policy_tmp"
    jq -e . "$policy_tmp" >/dev/null ||
        die 'Internal Firefox policy JSON is invalid.'
    install -d -o root -g root -m 0755 /etc/firefox /etc/firefox/policies
    install_exact_file "$policy_tmp" "$FIREFOX_POLICY" 0644
}

install_management_dropin() {
    local expected group_line group_gid explicit_members primary_members

    if ! getent group "$MULLVAD_GROUP" >/dev/null; then
        groupadd --system "$MULLVAD_GROUP"
    fi
    group_line="$(getent group "$MULLVAD_GROUP")"
    group_gid="$(printf '%s\n' "$group_line" | awk -F: '{print $3}')"
    explicit_members="${group_line##*:}"
    primary_members="$(getent passwd | awk -F: -v gid="$group_gid" '$4 == gid { print $1 }')"
    [[ -z "$explicit_members" && -z "$primary_members" ]] ||
        die "$MULLVAD_GROUP must remain empty; Mullvad administration is sudo-only."

    install -d -o root -g root -m 0755 "$DROPIN_DIR"
    expected="$TMP_DIR/management-group.conf"
    printf '[Service]\nEnvironment="MULLVAD_MANAGEMENT_SOCKET_GROUP=%s"\n' \
        "$MULLVAD_GROUP" >"$expected"
    chmod 0644 "$expected"

    if [[ -e "$DROPIN_FILE" || -L "$DROPIN_FILE" ]]; then
        [[ -f "$DROPIN_FILE" && ! -L "$DROPIN_FILE" ]] ||
            die "Unsafe systemd drop-in path: $DROPIN_FILE"
        cmp -s "$expected" "$DROPIN_FILE" ||
            die "Refusing to overwrite a different systemd drop-in: $DROPIN_FILE"
    else
        install -o root -g root -m 0644 "$expected" "$DROPIN_FILE"
    fi
}

verify_repository_key() {
    local key_file="$1"
    local -a fingerprints=()

    mapfile -t fingerprints < <(
        gpg --batch --quiet --show-keys --with-colons "$key_file" |
            awk -F: '$1 == "pub" { primary = 1; next }
               primary && $1 == "fpr" { print $10; primary = 0 }'
    )
    [[ "${#fingerprints[@]}" -eq 1 ]] ||
        die 'The Mullvad repository key must contain exactly one primary key.'
    [[ "${fingerprints[0]}" == "$MULLVAD_KEY_FINGERPRINT" ]] ||
        die 'The Mullvad repository signing-key fingerprint did not match.'
}

install_base_packages() {
    local platform="$1"
    local install_firefox="$2"
    local firefox_package
    local -a packages=(
        ca-certificates curl gnupg iproute2 jq nftables procps xdg-utils
    )

    case "$platform" in
    ubuntu) firefox_package='firefox' ;;
    debian) firefox_package='firefox-esr' ;;
    *) die "Internal error: unsupported Firefox platform: $platform" ;;
    esac
    [[ "$install_firefox" == '0' || "$install_firefox" == '1' ]] ||
        die 'Internal error: invalid Firefox install mode.'
    if [[ "$install_firefox" == '1' ]]; then
        packages+=("$firefox_package")
    fi

    run_logged 'Paketmetadaten werden aktualisiert.' \
        apt-get -qq update
    run_logged 'Die abgesicherten VPN-Werkzeuge werden installiert.' \
        env DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
        "${packages[@]}"
}

verify_firefox_installation() {
    case "$PLATFORM_ID" in
    ubuntu)
        command -v snap >/dev/null 2>&1 ||
            die 'Ubuntu Firefox did not install the required Snap command.'
        timeout --foreground 60s snap list firefox >/dev/null 2>&1 ||
            die 'The Firefox Snap is not fully installed.'
        [[ -x /usr/bin/firefox ]] ||
            die 'Ubuntu Firefox launcher is missing.'
        [[ -f /var/lib/snapd/desktop/applications/firefox_firefox.desktop ]] ||
            die 'Ubuntu Firefox desktop entry is missing.'
        ;;
    debian)
        dpkg-query -W -f='${db:Status-Status}\n' firefox-esr 2>/dev/null |
            grep -Fxq 'installed' ||
            die 'Debian Firefox ESR is not fully installed.'
        [[ -x /usr/bin/firefox-esr ]] ||
            die 'Debian Firefox ESR launcher is missing.'
        [[ -f /usr/share/applications/firefox-esr.desktop ]] ||
            die 'Debian Firefox ESR desktop entry is missing.'
        ;;
    esac
}

refresh_snap_xauthority() {
    local status

    [[ "$GUI_READY" -eq 1 && "$PLATFORM_ID" == 'ubuntu' ]] || return 0
    set +e
    runuser -u malwarelab -- env HOME="$GUI_HOME" sh -c '
    set -eu
    source="$HOME/.Xauthority"
    if [ ! -e "$source" ] && [ ! -L "$source" ]; then
      exit 3
    fi
    uid="$(id -u)"
    [ -f "$source" ] && [ ! -L "$source" ] && [ -s "$source" ]
    [ "$(stat -c "%u:%a" "$source")" = "${uid}:600" ]
    for directory in "$HOME/snap" "$HOME/snap/firefox" "$HOME/snap/firefox/common"; do
      if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ]
        [ "$(stat -c %u "$directory")" = "$uid" ]
        chmod 0700 "$directory"
      else
        mkdir -m 0700 -- "$directory"
      fi
    done
    destination="$HOME/snap/firefox/common/.Xauthority"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
      [ -f "$destination" ] && [ ! -L "$destination" ]
      [ "$(stat -c %u "$destination")" = "$uid" ]
    fi
    tmp="$(mktemp "$HOME/snap/firefox/common/.Xauthority.toolkit.XXXXXXXX")"
    cleanup() { rm -f -- "$tmp"; }
    trap cleanup EXIT HUP INT TERM
    install -m 0600 "$source" "$tmp"
    cmp -s "$source" "$tmp"
    mv -fT -- "$tmp" "$destination"
    tmp=""
    trap - EXIT HUP INT TERM
    [ "$(stat -c "%u:%a" "$destination")" = "${uid}:600" ]
    cmp -s "$source" "$destination"
  '
    status=$?
    set -e
    case "$status" in
    0) XAUTH_READY=1 ;;
    3) log 'Die Firefox-Xauthority wird beim nächsten VNC-Start automatisch angelegt.' ;;
    *) die 'Could not safely prepare Firefox Xauthority for malwarelab.' ;;
    esac
}

set_firefox_default_for_gui() {
    local desktop_id="$1"
    local xdg_data_dirs="$2"
    local mime_type setting_state

    runuser -u malwarelab -- env HOME="$GUI_HOME" sh -c '
    set -eu
    destination="$HOME/Downloads"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
      [ -d "$destination" ] && [ ! -L "$destination" ]
      [ "$(stat -c %u "$destination")" = "$(id -u)" ]
      chmod 0700 "$destination"
    else
      mkdir -m 0700 -- "$destination"
    fi
  ' || die 'Could not safely prepare the malwarelab download directory.'
    for mime_type in text/html x-scheme-handler/http x-scheme-handler/https; do
        runuser -u malwarelab -- env HOME="$GUI_HOME" XDG_DATA_DIRS="$xdg_data_dirs" \
            xdg-mime default "$desktop_id" "$mime_type"
        [[ "$(runuser -u malwarelab -- env HOME="$GUI_HOME" \
            XDG_DATA_DIRS="$xdg_data_dirs" \
            xdg-mime query default "$mime_type")" == "$desktop_id" ]] ||
            die "Firefox is not the default handler for $mime_type."
    done

    if [[ "$XAUTH_READY" -eq 1 && -S "/run/user/${GUI_UID}/bus" ]]; then
        runuser -u malwarelab -- env HOME="$GUI_HOME" \
            DISPLAY=:1 XAUTHORITY="$GUI_HOME/.Xauthority" \
            XDG_RUNTIME_DIR="/run/user/${GUI_UID}" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${GUI_UID}/bus" \
            XDG_CURRENT_DESKTOP=XFCE DESKTOP_SESSION=xfce \
            XDG_DATA_DIRS="$xdg_data_dirs" \
            xdg-settings set default-web-browser "$desktop_id"
        setting_state="$(runuser -u malwarelab -- env HOME="$GUI_HOME" \
            DISPLAY=:1 XAUTHORITY="$GUI_HOME/.Xauthority" \
            XDG_RUNTIME_DIR="/run/user/${GUI_UID}" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${GUI_UID}/bus" \
            XDG_CURRENT_DESKTOP=XFCE DESKTOP_SESSION=xfce \
            XDG_DATA_DIRS="$xdg_data_dirs" \
            xdg-settings check default-web-browser "$desktop_id")"
        [[ "$setting_state" == 'yes' ]] ||
            die 'Firefox is not the active XFCE default browser.'
    fi
}

configure_firefox_for_gui() {
    local desktop_id xdg_data_dirs

    [[ "$GUI_READY" -eq 1 ]] || {
        log 'Firefox ist systemweit bereit; malwarelab wird beim späteren ssh-gui-Lauf angelegt.'
        return 0
    }
    case "$PLATFORM_ID" in
    ubuntu)
        desktop_id='firefox_firefox.desktop'
        xdg_data_dirs='/var/lib/snapd/desktop:/usr/local/share:/usr/share'
        ;;
    debian)
        desktop_id='firefox-esr.desktop'
        xdg_data_dirs='/usr/local/share:/usr/share'
        ;;
    esac
    refresh_snap_xauthority
    run_logged 'Firefox wird für malwarelab als Standardbrowser vorbereitet.' \
        set_firefox_default_for_gui "$desktop_id" "$xdg_data_dirs"
}

run_firefox_headless_test() {
    local test_user="$1"
    local test_home="$2"

    runuser -u "$test_user" -- env HOME="$test_home" \
        TOOLKIT_PLATFORM="$PLATFORM_ID" sh -c '
      set -eu
      uid="$(id -u)"
      cd "$HOME"
      case "$TOOLKIT_PLATFORM" in
        ubuntu)
          base="$HOME/snap/firefox/common"
          ;;
        debian)
          base="$HOME/.cache"
          ;;
        *) exit 2 ;;
      esac
      if [ -e "$base" ] || [ -L "$base" ]; then
        [ -d "$base" ] && [ ! -L "$base" ]
        [ "$(stat -c %u "$base")" = "$uid" ]
      else
        mkdir -p -m 0700 -- "$base"
      fi
      work="$(mktemp -d "$base/toolkit-firefox-test.XXXXXXXX")"
      cleanup() { rm -rf -- "$work"; }
      trap cleanup EXIT HUP INT TERM
      mkdir -m 0700 "$work/profile"
      if [ "$TOOLKIT_PLATFORM" = ubuntu ]; then
        timeout --kill-after=10s 60s /usr/bin/snap run firefox \
          --headless --no-remote --profile "$work/profile" \
          --screenshot "$work/firefox.png" about:blank >/dev/null 2>&1
      else
        timeout --kill-after=10s 60s /usr/bin/firefox-esr \
          --headless --no-remote --profile "$work/profile" \
          --screenshot "$work/firefox.png" about:blank >/dev/null 2>&1
      fi
      [ -s "$work/firefox.png" ]
      magic="$(od -An -tx1 -N8 "$work/firefox.png" | tr -d " \\n")"
      [ "$magic" = 89504e470d0a1a0a ]
    '
}

verify_firefox_runtime() {
    local admin_user="$1"
    local test_user="$admin_user" test_home

    if [[ "$GUI_READY" -eq 1 ]]; then
        test_user='malwarelab'
        test_home="$GUI_HOME"
    else
        test_home="$(getent passwd "$admin_user" | awk -F: '{print $6}')"
    fi
    [[ "$test_home" == /* && -d "$test_home" && ! -L "$test_home" ]] ||
        die 'Firefox runtime test user has an unsafe home directory.'
    run_logged 'Firefox wird mit einem Wegwerfprofil headless gestartet.' \
        run_firefox_headless_test "$test_user" "$test_home"
}

install_mullvad() {
    local architecture="$1"
    local key_file repo_tmp key_destination repo_destination

    key_file="$TMP_DIR/mullvad-keyring.asc"
    run_logged 'Der offizielle Mullvad-Signaturschlüssel wird geladen.' \
        curl --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 5 --retry-delay 2 --retry-all-errors \
        --output "$key_file" "$MULLVAD_KEY_URL"
    verify_repository_key "$key_file"

    key_destination='/usr/share/keyrings/mullvad-keyring.asc'
    [[ ! -L "$key_destination" ]] || die "Unsafe keyring path: $key_destination"
    install -o root -g root -m 0644 "$key_file" "$key_destination"

    repo_destination='/etc/apt/sources.list.d/mullvad.list'
    [[ ! -L "$repo_destination" ]] || die "Unsafe repository path: $repo_destination"
    repo_tmp="/etc/apt/sources.list.d/.mullvad.list.toolkit.$$"
    printf 'deb [signed-by=%s arch=%s] https://repository.mullvad.net/deb/stable stable main\n' \
        "$key_destination" "$architecture" >"$repo_tmp"
    chown root:root "$repo_tmp"
    chmod 0644 "$repo_tmp"
    mv -fT -- "$repo_tmp" "$repo_destination"

    run_logged 'Das signierte Mullvad-Repository wird eingelesen.' \
        apt-get -qq update
    run_logged 'Mullvad VPN wird installiert.' \
        env DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends mullvad-vpn
}

restrict_mullvad_exclude() {
    local override owner group mode path remainder

    [[ -f /usr/bin/mullvad-exclude && ! -L /usr/bin/mullvad-exclude ]] ||
        die 'Mullvad split-tunnel helper is missing or unsafe.'
    override="$(dpkg-statoverride --list /usr/bin/mullvad-exclude 2>/dev/null || true)"
    if [[ -n "$override" ]]; then
        IFS=' ' read -r owner group mode path remainder <<<"$override"
        [[ "$owner" == 'root' && "$group" == "$MULLVAD_GROUP" &&
            ("$mode" == '750' || "$mode" == '0750') &&
            "$path" == '/usr/bin/mullvad-exclude' && -z "${remainder:-}" ]] ||
            die 'A conflicting dpkg-statoverride exists for mullvad-exclude.'
        chown root:"$MULLVAD_GROUP" /usr/bin/mullvad-exclude
        chmod 0750 /usr/bin/mullvad-exclude
    else
        dpkg-statoverride --update --add root "$MULLVAD_GROUP" 0750 \
            /usr/bin/mullvad-exclude
    fi
    [[ "$(stat -c '%U:%G:%a' /usr/bin/mullvad-exclude)" == "root:${MULLVAD_GROUP}:750" ]] ||
        die 'mullvad-exclude is still available to untrusted local users.'
}

verify_management_socket() {
    local expected_gid socket_state

    systemctl daemon-reload
    systemctl cat mullvad-early-boot-blocking.service >/dev/null ||
        die 'Mullvad early-boot blocking service is missing.'
    systemctl cat mullvad-daemon.service | grep -Fq "$SSH_LOADER" ||
        die 'The SSH bypass is not attached to mullvad-daemon.service.'
    systemctl cat mullvad-early-boot-blocking.service | grep -Fq "$SSH_LOADER" ||
        die 'The SSH bypass is not attached to early-boot blocking.'
    systemctl cat "$SSH_BOOT_SERVICE" | grep -Fq \
        'After=local-fs.target nftables.service mullvad-early-boot-blocking.service' ||
        die 'The post-early-boot SSH bypass ordering is missing.'
    systemctl cat "$SSH_BOOT_SERVICE" | grep -Fq \
        'Before=ssh.service sshd.service' ||
        die 'The SSH bypass is not ordered before the SSH daemon.'
    systemctl enable mullvad-early-boot-blocking.service >/dev/null
    systemctl enable --now "$SSH_BOOT_SERVICE" >/dev/null
    systemctl enable --now mullvad-daemon.service >/dev/null
    systemctl is-enabled --quiet mullvad-early-boot-blocking.service ||
        die 'Mullvad early-boot blocking is not enabled.'
    systemctl is-enabled --quiet mullvad-daemon.service ||
        die 'Mullvad daemon is not enabled.'
    systemctl is-enabled --quiet "$SSH_BOOT_SERVICE" ||
        die 'The post-early-boot SSH bypass is not enabled.'
    systemctl is-active --quiet "$SSH_BOOT_SERVICE" ||
        die 'The post-early-boot SSH bypass is not active.'
    systemctl restart mullvad-daemon.service

    for _ in {1..30}; do
        [[ -S "$MULLVAD_SOCKET" && ! -L "$MULLVAD_SOCKET" ]] && break
        sleep 1
    done
    [[ -S "$MULLVAD_SOCKET" && ! -L "$MULLVAD_SOCKET" ]] ||
        die "Mullvad management socket did not appear: $MULLVAD_SOCKET"

    expected_gid="$(getent group "$MULLVAD_GROUP" | awk -F: '{print $3}')"
    socket_state="$(stat -c '%u:%g:%a' "$MULLVAD_SOCKET")"
    [[ "$socket_state" == "0:${expected_gid}:760" ]] ||
        die "Unsafe Mullvad management socket ownership/mode: $socket_state"
    systemctl is-active --quiet mullvad-daemon.service ||
        die 'mullvad-daemon.service is not active.'
    /usr/sbin/nft list table inet "$SSH_BYPASS_TABLE" >/dev/null ||
        die 'The persistent SSH management bypass disappeared after daemon restart.'

}

mullvad_cmd() {
    /usr/bin/mullvad "$@"
}

wait_for_mullvad() {
    for _ in {1..30}; do
        if mullvad_cmd status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die 'The Mullvad CLI could not reach its daemon.'
}

set_remote_safe_state() {
    mullvad_cmd auto-connect set off >/dev/null
    mullvad_cmd lockdown-mode set off >/dev/null
    mullvad_cmd disconnect --wait >/dev/null
}

preexisting_mullvad_detected() {
    [[ -e /usr/bin/mullvad || -L /usr/bin/mullvad ||
        -d /etc/mullvad-vpn ||
        -e /usr/lib/systemd/system/mullvad-daemon.service ||
        -e /lib/systemd/system/mullvad-daemon.service ]] &&
        return 0
    dpkg-query -W mullvad-vpn >/dev/null 2>&1
}

secure_preexisting_mullvad() {
    local status

    preexisting_mullvad_detected || return 0
    [[ -x /usr/bin/mullvad ]] ||
        die 'A partial or unusable pre-existing Mullvad installation was found; no package changes were made.'
    systemctl is-active --quiet mullvad-daemon.service ||
        die 'Pre-existing Mullvad is inactive. Secure it from the provider console before rerunning Toolkit.'
    mullvad_cmd status >/dev/null 2>&1 ||
        die 'Pre-existing Mullvad cannot be controlled safely; no system changes were made.'

    log 'Vorhandenes Mullvad wird vor Paket- oder Daemon-Änderungen sicher getrennt.'
    set_remote_safe_state ||
        die 'Could not disable and disconnect pre-existing Mullvad safely.'
    status="$(mullvad_cmd status 2>/dev/null)" ||
        die 'Could not verify the pre-existing Mullvad state.'
    grep -q '^Disconnected' <<<"$status" ||
        die 'Pre-existing Mullvad is not verifiably disconnected.'
}

account_is_configured() {
    local account_state

    account_state="$(mullvad_cmd account get 2>/dev/null)" ||
        die 'Could not read the Mullvad account state.'
    if [[ "$account_state" == *'Not logged in on any account'* ||
        "$account_state" == *'The current device has been revoked'* ]]; then
        account_state=''
        return 1
    fi
    if [[ "$account_state" =~ Mullvad[[:space:]]account:[[:space:]]*[0-9]{12,32} ]]; then
        account_state=''
        return 0
    fi
    account_state=''
    die 'Mullvad returned an unknown account state.'
}

prompt_and_login() {
    local login_status attempt

    for attempt in 1 2 3; do
        TTY_PATH='/dev/tty'
        [[ -r "$TTY_PATH" && -w "$TTY_PATH" ]] ||
            die 'An interactive terminal is required for the Mullvad account prompt.'
        TTY_STATE="$(stty -g <"$TTY_PATH")" ||
            die 'Could not read terminal settings.'
        stty -echo <"$TTY_PATH" ||
            die 'Could not disable terminal echo.'
        printf 'Mullvad-Accountnummer: ' >"$TTY_PATH"
        if IFS= read -r ACCOUNT_NUMBER <"$TTY_PATH"; then
            restore_tty
            printf '\n' >"$TTY_PATH"
        else
            restore_tty
            printf '\n' >"$TTY_PATH"
            die 'Could not read the Mullvad account number.'
        fi

        ACCOUNT_NUMBER="${ACCOUNT_NUMBER//[[:space:]]/}"
        if [[ ! "$ACCOUNT_NUMBER" =~ ^([0-9]{12}|[0-9]{13}|[0-9]{16})$ ]]; then
            ACCOUNT_NUMBER=''
            unset ACCOUNT_NUMBER
            printf 'Ungültiges Format; erwartet werden 12, 13 oder 16 Ziffern.\n' >"$TTY_PATH"
            continue
        fi

        set +e
        printf '%s\n' "$ACCOUNT_NUMBER" | mullvad_cmd account login >/dev/null 2>&1
        login_status=$?
        set -e
        ACCOUNT_NUMBER=''
        unset ACCOUNT_NUMBER
        if [[ "$login_status" -eq 0 ]]; then
            LOGIN_CREATED=1
            return 0
        fi
        printf 'Login abgelehnt; Accountnummer oder Geräteplätze prüfen.\n' >"$TTY_PATH"
    done
    die 'Mullvad login failed after three attempts.'
}

configure_shadowsocks() {
    local settings

    mullvad_cmd anti-censorship set shadowsocks --port 443 >/dev/null
    mullvad_cmd anti-censorship set mode shadowsocks >/dev/null
    settings="$(mullvad_cmd anti-censorship get)"
    grep -Fxq 'mode: shadowsocks' <<<"$settings" ||
        die 'Mullvad did not retain Shadowsocks mode.'
    grep -Fxq 'shadowsocks settings: port 443' <<<"$settings" ||
        die 'Mullvad did not retain Shadowsocks port 443.'
}

configure_mullvad_network() {
    local location="$1"

    validate_location "$location"
    mullvad_cmd relay set location "$location" >/dev/null
    mullvad_cmd relay set ip-version ipv4 >/dev/null
    mullvad_cmd relay set multihop off >/dev/null
    mullvad_cmd tunnel set daita off >/dev/null
    mullvad_cmd tunnel set ipv6 off >/dev/null
    mullvad_cmd tunnel set allowed-ips '0.0.0.0/0' >/dev/null
    mullvad_cmd split-tunnel clear >/dev/null
    mullvad_cmd lan set block >/dev/null
    mullvad_cmd dns set default >/dev/null
}

verify_untrusted_user_is_contained() {
    [[ "$GUI_READY" -eq 1 ]] || return 0
    if runuser -u malwarelab -- test -r "$MULLVAD_SOCKET"; then
        die 'malwarelab can read the Mullvad management socket.'
    fi
    if runuser -u malwarelab -- test -x /usr/bin/mullvad-exclude; then
        die 'malwarelab can execute the Mullvad split-tunnel helper.'
    fi
    if [[ -e /var/run/docker.sock || -L /var/run/docker.sock ]]; then
        [[ -S /var/run/docker.sock && ! -L /var/run/docker.sock ]] ||
            die 'The Docker control socket has an unsafe file type.'
        if runuser -u malwarelab -- test -w /var/run/docker.sock; then
            die 'malwarelab can write to the root-equivalent Docker control socket.'
        fi
    fi
}

emergency_disconnect() {
    local failed=0

    /usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect set off \
        >/dev/null 2>&1 || failed=1
    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '1' ]]; then
        /usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set on \
            >/dev/null 2>&1 || failed=1
    else
        /usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set off \
            >/dev/null 2>&1 || failed=1
    fi
    /usr/bin/timeout --foreground 45s /usr/bin/mullvad disconnect --wait \
        >/dev/null 2>&1 || failed=1
    VPN_MAY_BE_ACTIVE=0
    return "$failed"
}

arm_rollback_watchdog() {
    systemctl daemon-reload
    systemctl stop "$ROLLBACK_TIMER" "$ROLLBACK_SERVICE" >/dev/null 2>&1 || true
    systemctl reset-failed "$ROLLBACK_TIMER" "$ROLLBACK_SERVICE" >/dev/null 2>&1 || true
    systemctl start "$ROLLBACK_TIMER"
    systemctl is-active --quiet "$ROLLBACK_TIMER" ||
        die 'The Mullvad rollback timer could not be armed.'
    WATCHDOG_ARMED=1
}

disarm_rollback_watchdog() {
    [[ "$WATCHDOG_ARMED" -eq 1 ]] || die 'Internal error: rollback timer was not armed.'
    systemctl stop "$ROLLBACK_TIMER" "$ROLLBACK_SERVICE"
    if systemctl is-active --quiet "$ROLLBACK_TIMER" ||
        systemctl is-active --quiet "$ROLLBACK_SERVICE"; then
        die 'The Mullvad rollback watchdog is still active.'
    fi
    WATCHDOG_ARMED=0
}

verify_connected_transport() {
    local status_json

    status_json="$(mullvad_cmd status --json 2>/dev/null)" ||
        die 'Could not read Mullvad JSON connection status.'
    jq -e '
    .state == "connected"
    and .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"
    and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))
  ' <<<"$status_json" >/dev/null ||
        die 'Mullvad is not connected through Shadowsocks on port 443.'
    status_json=''
}

verify_mullvad_egress() {
    local family="$1"
    local location="$2"
    local check_file="$TMP_DIR/mullvad-check-ipv${family}.json"

    run_logged "Mullvad IPv${family}-Ausgang wird geprüft." \
        curl "-${family}" --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 --retry 2 --retry-delay 1 \
        --output "$check_file" "$MULLVAD_CHECK_URL"
    case "$location" in
    de)
        jq -e '.mullvad_exit_ip == true and .country == "Germany"' \
            "$check_file" >/dev/null ||
            die "IPv${family} is not using a Mullvad exit address in Germany."
        ;;
    any)
        jq -e '.mullvad_exit_ip == true' "$check_file" >/dev/null ||
            die "IPv${family} is not using a Mullvad exit address."
        ;;
    *) die "Internal error: unsupported Mullvad location: $location" ;;
    esac
}

verify_gui_egress() {
    local location="$1"
    local response

    [[ "$GUI_READY" -eq 1 ]] || return 0
    response="$(runuser -u malwarelab -- env HOME="$GUI_HOME" \
        curl -4 --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 "$MULLVAD_CHECK_URL")" ||
        die 'The malwarelab browser user has no protected Internet route.'
    case "$location" in
    de)
        jq -e '.mullvad_exit_ip == true and .country == "Germany"' \
            <<<"$response" >/dev/null ||
            die 'malwarelab traffic is not using a Mullvad exit address in Germany.'
        ;;
    any)
        jq -e '.mullvad_exit_ip == true' <<<"$response" >/dev/null ||
            die 'malwarelab traffic is not using a Mullvad exit address.'
        ;;
    *) die "Internal error: unsupported Mullvad location: $location" ;;
    esac
    response=''
}

verify_final_mullvad_state() {
    local auto_state lockdown_state

    auto_state="$(mullvad_cmd auto-connect get 2>/dev/null)" ||
        die 'Could not verify Mullvad auto-connect.'
    lockdown_state="$(mullvad_cmd lockdown-mode get 2>/dev/null)" ||
        die 'Could not verify Mullvad lockdown mode.'
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$auto_state" ||
        die 'Mullvad auto-connect is not on.'
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$lockdown_state" ||
        die 'Mullvad lockdown mode is not on.'
    auto_state=''
    lockdown_state=''
    verify_connected_transport
}

connect_and_lock_mullvad() {
    local admin_user="$1"
    local location="$2"
    local install_firefox="$3"

    arm_rollback_watchdog
    VPN_MAY_BE_ACTIVE=1
    run_logged 'Mullvad verbindet über Shadowsocks auf Port 443.' \
        timeout --foreground 120s /usr/bin/mullvad connect --wait
    verify_connected_transport
    verify_mullvad_egress 4 "$location"
    /usr/sbin/nft list table inet "$SSH_BYPASS_TABLE" >/dev/null ||
        die 'The SSH management bypass disappeared after connecting.'
    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '0' ]]; then
        verify_current_ssh_session
    fi
    verify_gui_egress "$location"
    if [[ "$install_firefox" == '1' ]]; then
        verify_firefox_runtime "$admin_user"
    fi

    mullvad_cmd lockdown-mode set on >/dev/null
    mullvad_cmd auto-connect set on >/dev/null
    verify_final_mullvad_state
    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '0' ]]; then
        verify_bidirectional_ssh_flow
    else
        log 'Providerkonsole-Modus: Mullvad-Egress ist geprüft; es gibt bewusst keine versteckte SSH-Liveness-Prüfung.'
    fi
    disarm_rollback_watchdog
    verify_final_mullvad_state
    VPN_MAY_BE_ACTIVE=0
}

root_stage() {
    local admin_user="$1"
    local requested_ssh_port="$2"
    local requested_client_port="$3"
    local requested_ssh_family="$4"
    local location="$5"
    local install_firefox="$6"
    local port ssh_port_text='' browser_text browser_policy_text

    [[ "$(id -u)" -eq 0 ]] || die 'Internal error: root stage is not root.'
    validate_admin_user "$admin_user"
    [[ "$requested_ssh_port" == '-' ]] || valid_ssh_port "$requested_ssh_port" ||
        die 'Internal error: invalid requested SSH port.'
    [[ "$requested_client_port" == '-' ]] || valid_ssh_port "$requested_client_port" ||
        die 'Internal error: invalid requested SSH client port.'
    [[ ("$requested_ssh_port" == '-' && "$requested_client_port" == '-') ||
        ("$requested_ssh_port" != '-' && "$requested_client_port" != '-') ]] ||
        die 'Internal error: incomplete SSH connection tuple.'
    case "$requested_ssh_family" in
    4)
        OUTBOUND_HTTPS_ENROLLMENT=0
        ;;
    https)
        [[ "$requested_ssh_port" == '-' && "$requested_client_port" == '-' ]] ||
            die 'Internal error: outbound-HTTPS mode cannot carry an SSH connection tuple.'
        OUTBOUND_HTTPS_ENROLLMENT=1
        ;;
    *) die 'IPv4-only mode requires verified IPv4 SSH or explicit outbound-HTTPS enrollment.' ;;
    esac
    validate_location "$location"
    [[ "$install_firefox" == '0' || "$install_firefox" == '1' ]] ||
        die 'Internal error: invalid Firefox install mode.'
    CURRENT_SSH_CLIENT_PORT="$requested_client_port"
    command -v flock >/dev/null 2>&1 || die 'flock is required.'
    install -d -o root -g root -m 0755 /run/lock
    exec 9>/run/lock/toolkit-vpn-bootstrap.lock
    flock -n 9 || die 'Another Toolkit VPN bootstrap is already running.'

    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 148' TSTP

    validate_platform
    prepare_gui_context
    collect_ssh_ports "$requested_ssh_port"
    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '0' ]]; then
        verify_current_ssh_session
    else
        log 'Providerkonsole-Modus aktiv: Ein Fehler bleibt absichtlich im Mullvad-Lockdown (Fail-Closed).'
    fi
    TMP_DIR="$(mktemp -d /tmp/toolkit-vpn.XXXXXXXX)"
    chmod 0700 "$TMP_DIR"
    prepare_log

    secure_preexisting_mullvad
    log 'Mullvad wird für die Remote-VM vorbereitet.'
    install_management_dropin
    install_base_packages "$PLATFORM_ID" "$install_firefox"
    disable_system_ipv6
    if [[ "$install_firefox" == '1' ]]; then
        install_firefox_policy
        verify_firefox_installation
        configure_firefox_for_gui
        browser_text='installiert und vorkonfiguriert'
        browser_policy_text='DoH und WebRTC gesperrt aus'
    else
        browser_text='bewusst übersprungen (PBP stellt Camoufox bereit)'
        browser_policy_text='keine globale Firefox-Policy installiert'
    fi
    install_ssh_bypass
    install_rollback_watchdog
    install_mullvad "$PLATFORM_ARCH"
    restrict_mullvad_exclude
    verify_management_socket
    wait_for_mullvad
    set_remote_safe_state
    verify_untrusted_user_is_contained

    if account_is_configured; then
        log 'Ein Mullvad-Account ist bereits angemeldet; er wird beibehalten.'
    else
        prompt_and_login
    fi
    configure_mullvad_network "$location"
    configure_shadowsocks
    set_remote_safe_state
    if [[ "$OUTBOUND_HTTPS_ENROLLMENT" == '0' ]]; then
        verify_current_ssh_session
    fi
    connect_and_lock_mullvad "$admin_user" "$location" "$install_firefox"

    for port in "${SSH_PORTS[@]}"; do
        ssh_port_text+="${ssh_port_text:+, }${port}"
    done

    cat >&2 <<EOF

[toolkit-vpn] Bereit.
Mullvad:             verbunden und IPv4 geprüft (Relay: ${location})
IPv6:                systemweit deaktiviert
Anti-Zensur:         Shadowsocks
Port:                443
Auto-Connect:        an
Lockdown-Mode:       an
Firefox:             ${browser_text}
Browser-Policy:      ${browser_policy_text}
Browser-Proxy:       keiner (normales Mullvad-Systemrouting)
SSH-Ausnahme:        TCP ${ssh_port_text}
VNC:                 nur localhost über den SSH-Tunnel
Management-Zugriff: nur sudo/root

Die SSH-Ausnahme verwendet absichtlich die echte VM-IP. Sämtlicher normaler
Anwendungs- und Browserverkehr läuft durch Mullvad. Bitte jetzt einen frischen
SSH-Login und danach VNC testen; vor Freigabe zusätzlich einmal neu starten.

Vor dem Löschen einer Wegwerf-VM den Mullvad-Geräteplatz freigeben:

  sudo mullvad auto-connect set off
  sudo mullvad lockdown-mode set off
  sudo mullvad disconnect --wait
  sudo mullvad account logout >/dev/null
  sleep 10

Installationslog (root-only): ${LOG_FILE}
EOF
}

main() {
    verify_bundle
    if [[ "$(id -u)" -eq 0 ]]; then
        [[ "${1:-}" == '--root-stage' && "$#" -eq 7 ]] ||
            die 'Run this installer as the normal SSH administrator.'
        root_stage "$2" "$3" "$4" "$5" "$6" "$7"
    else
        user_stage "$@"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
