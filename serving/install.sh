#!/bin/sh
set -eu

BASE_URL="${TOOLKIT_BASE_URL:-https://downloads.example.com}"
BASE_URL="${BASE_URL%/}"
REQUESTED_TOOL="${1:-}"
PINNED_VERSION="${2:-}"

tmpdir=""
release_tmp=""
index_tmp=""
release_set_tmp=""
release_set_state=""
CURL_PROTO="=https"
QUICK_MODE=""
tty_path=""
tty_state=""
auth_tmp=""
auth_config=""
mfa_code=""
bootstrap_pid=""
bootstrap_process_group=""
spinner_pid=""
bootstrap_log=""
progress_active=""
progress_file=""
decepticon_bootstrap_prefix=""

case "$REQUESTED_TOOL" in
--PBP | pbp)
    REQUESTED_TOOL="pbp"
    if [ "${TOOLKIT_INSTALL_ONLY:-0}" != "1" ]; then
        QUICK_MODE="pbp"
    fi
    ;;
vpn)
    if [ "${TOOLKIT_INSTALL_ONLY:-0}" != "1" ]; then
        QUICK_MODE="vpn"
    fi
    ;;
decepticon)
    if [ "${TOOLKIT_INSTALL_ONLY:-0}" != "1" ]; then
        QUICK_MODE="decepticon"
    fi
    ;;
examstation)
    if [ "${TOOLKIT_INSTALL_ONLY:-0}" != "1" ]; then
        QUICK_MODE="examstation"
    fi
    ;;
ssh-hardening)
    REQUESTED_TOOL="ssh"
    QUICK_MODE="ssh"
    ;;
ssh-gui-hardening)
    REQUESTED_TOOL="ssh"
    QUICK_MODE="ssh-gui"
    ;;
ssh-gui-clipboard)
    REQUESTED_TOOL="ssh"
    QUICK_MODE="ssh-gui-clipboard"
    ;;
esac

if [ "${TOOLKIT_INSTALL_ONLY:-0}" = "1" ]; then
    QUICK_MODE=""
    TOOLKIT_RUN_BOOTSTRAP=0
    TOOLKIT_BOOTSTRAP_ARGS=""
fi

die() {
    echo "ERROR: $*" >&2
    exit 1
}

restore_tty() {
    if [ -n "$tty_state" ] && [ -n "$tty_path" ]; then
        stty "$tty_state" <"$tty_path" >/dev/null 2>&1 || true
        tty_state=""
    fi
}

cleanup() {
    restore_tty
    if [ -n "$spinner_pid" ]; then
        kill "$spinner_pid" >/dev/null 2>&1 || true
        wait "$spinner_pid" >/dev/null 2>&1 || true
        spinner_pid=""
    fi
    if [ -n "$progress_active" ]; then
        printf '\r\033[2K' >&2
        progress_active=""
    fi
    if [ -n "$bootstrap_pid" ]; then
        if [ -n "$bootstrap_process_group" ]; then
            kill -TERM "-$bootstrap_pid" >/dev/null 2>&1 || true
        fi
        kill "$bootstrap_pid" >/dev/null 2>&1 || true
        wait "$bootstrap_pid" >/dev/null 2>&1 || true
        bootstrap_pid=""
        bootstrap_process_group=""
    fi
    if [ -n "$progress_file" ] && [ -f "$progress_file" ]; then
        rm -f -- "$progress_file"
        progress_file=""
        unset TOOLKIT_PROGRESS_FILE
    fi
    if [ -n "$auth_tmp" ] && [ -d "$auth_tmp" ]; then
        rm -rf -- "$auth_tmp"
        auth_tmp=""
        auth_config=""
    fi
    if [ -n "$release_tmp" ] && [ -d "$release_tmp" ]; then
        rm -rf -- "$release_tmp"
    fi
    if [ -n "$tmpdir" ] && [ -d "$tmpdir" ]; then
        rm -rf -- "$tmpdir"
    fi
    if [ -n "$release_set_tmp" ] && [ -f "$release_set_tmp" ]; then
        rm -f -- "$release_set_tmp"
        release_set_tmp=""
    fi
    if [ -n "$index_tmp" ] && [ -f "$index_tmp" ]; then
        rm -f -- "$index_tmp"
    fi
}
on_signal() {
    signal_status="$1"
    trap - 0
    trap '' 1 2 3 15 20
    cleanup
    exit "$signal_status"
}

trap cleanup 0
trap 'on_signal 129' 1
trap 'on_signal 130' 2
trap 'on_signal 131' 3
trap 'on_signal 143' 15
trap 'on_signal 148' 20

if [ -z "$REQUESTED_TOOL" ]; then
    echo "Usage: curl -fsSL ${BASE_URL}/install.sh | sh -s -- <tool|all> [version]" >&2
    echo "Quick Decepticon: use tool 'decepticon'; set TOOLKIT_INSTALL_ONLY=1 to skip its bootstrap." >&2
    echo "Quick Examstation: use tool 'examstation' on a dedicated Debian 13 VM." >&2
    echo "Quick SSH: curl -fsSL ${BASE_URL}/install.sh | sh -s -- ssh-hardening [version]" >&2
    echo "Quick SSH+GUI: use ssh-gui-hardening instead." >&2
    echo "Quick SSH+GUI with clipboard: use ssh-gui-clipboard instead." >&2
    echo "Quick Mullvad VPN: use tool 'vpn'." >&2
    echo "Quick PBP: use '--PBP' or 'pbp' after ssh-gui-hardening." >&2
    echo "Auth: every installer run prompts once for the download password and a fresh TOTP code." >&2
    echo "Automation: use mode-0600 TOOLKIT_AUTH_FILE and TOOLKIT_TOTP_FILE secret files." >&2
    exit 1
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

write_basic_auth_config() {
    set +x
    auth_value="$1"
    [ -n "$auth_value" ] || die "Download credentials must not be empty."
    need_cmd grep
    need_cmd sed

    if printf "%s" "$auth_value" | LC_ALL=C grep -q "[[:cntrl:]]"; then
        auth_value=""
        die "Download credentials must not contain control characters."
    fi

    escaped_auth="$(printf "%s" "$auth_value" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    auth_value=""
    auth_tmp="$(mktemp -d)"
    auth_config="${auth_tmp}/curl.conf"
    (
        umask 077
        printf 'user = "%s"\n' "$escaped_auth" >"$auth_config"
    )
    escaped_auth=""
}

read_secret_file() {
    secret_path="$1"
    secret_label="$2"
    [ -f "$secret_path" ] && [ ! -L "$secret_path" ] || die "$secret_label must be a regular non-symlink file."
    secret_mode="$(stat -c '%a' "$secret_path")"
    case "$secret_mode" in
    400 | 600) ;;
    *) die "$secret_label must have mode 0400 or 0600." ;;
    esac
    [ "$(stat -c '%u' "$secret_path")" = "$(id -u)" ] || die "$secret_label must be owned by the current user."
    IFS= read -r secret_value <"$secret_path" || true
    [ -n "$secret_value" ] || die "$secret_label must not be empty."
}

prepare_secret_file_auth() {
    set +x
    if [ -n "${TOOLKIT_AUTH:-}" ] || [ -n "${TOOLKIT_TOTP:-}" ]; then
        unset TOOLKIT_AUTH TOOLKIT_TOTP
        die "TOOLKIT_AUTH/TOOLKIT_TOTP environment secrets are disabled. Use 0600 secret files instead."
    fi
    if [ -z "${TOOLKIT_AUTH_FILE:-}" ] && [ -z "${TOOLKIT_TOTP_FILE:-}" ]; then
        return 0
    fi
    [ -n "${TOOLKIT_AUTH_FILE:-}" ] && [ -n "${TOOLKIT_TOTP_FILE:-}" ] ||
        die "TOOLKIT_AUTH_FILE and TOOLKIT_TOTP_FILE must be provided together."
    read_secret_file "$TOOLKIT_AUTH_FILE" "TOOLKIT_AUTH_FILE"
    file_auth="$secret_value"
    secret_value=""
    read_secret_file "$TOOLKIT_TOTP_FILE" "TOOLKIT_TOTP_FILE"
    mfa_code="$secret_value"
    secret_value=""
    unset TOOLKIT_AUTH_FILE TOOLKIT_TOTP_FILE
    write_basic_auth_config "$file_auth"
    file_auth=""
    case "$mfa_code" in
    *[!0-9]* | '') die "TOOLKIT_TOTP_FILE must contain exactly six digits." ;;
    esac
    [ "${#mfa_code}" -eq 6 ] || die "TOOLKIT_TOTP_FILE must contain exactly six digits."
}

prepare_interactive_auth() {
    set +x
    [ -z "$auth_config" ] || return 0
    need_cmd stty

    tty_path="/dev/tty"
    [ -r "$tty_path" ] && [ -w "$tty_path" ] ||
        die "MFA needs an interactive terminal. For automation, use mode-0600 TOOLKIT_AUTH_FILE and TOOLKIT_TOTP_FILE."

    tty_state="$(stty -g <"$tty_path")" || die "Could not read terminal settings from $tty_path"
    if ! stty -echo <"$tty_path"; then
        restore_tty
        die "Could not disable terminal echo for the password prompt."
    fi
    printf "Toolkit-Download-Passwort (Benutzer toolkit): " >"$tty_path"

    auth_password=""
    if IFS= read -r auth_password <"$tty_path"; then
        restore_tty
        printf "\n" >"$tty_path"
    else
        restore_tty
        printf "\n" >"$tty_path"
        die "Could not read the Toolkit download password."
    fi

    [ -n "$auth_password" ] || die "The Toolkit download password must not be empty."
    write_basic_auth_config "${TOOLKIT_AUTH_USER:-toolkit}:${auth_password}"
    auth_password=""

    tty_state="$(stty -g <"$tty_path")" || die "Could not read terminal settings from $tty_path"
    if ! stty -echo <"$tty_path"; then
        restore_tty
        die "Could not disable terminal echo for the TOTP prompt."
    fi
    printf "Toolkit-TOTP-Code: " >"$tty_path"
    if IFS= read -r mfa_code <"$tty_path"; then
        restore_tty
        printf "\n" >"$tty_path"
    else
        restore_tty
        printf "\n" >"$tty_path"
        die "Could not read the Toolkit TOTP code."
    fi
    case "$mfa_code" in
    *[!0-9]* | '') die "The Toolkit TOTP code must contain exactly six digits." ;;
    esac
    [ "${#mfa_code}" -eq 6 ] || die "The Toolkit TOTP code must contain exactly six digits."
}

write_token_config() {
    set +x
    access_token="$1"
    case "$access_token" in
    *[!A-Za-z0-9_-]* | '')
        access_token=""
        die "MFA endpoint returned an invalid token."
        ;;
    esac
    [ "${#access_token}" -eq 43 ] || {
        access_token=""
        die "MFA endpoint returned an invalid token."
    }
    rm -rf -- "$auth_tmp"
    auth_tmp="$(mktemp -d)"
    auth_config="${auth_tmp}/curl.conf"
    (
        umask 077
        printf 'header = "Authorization: Bearer %s"\n' "$access_token" >"$auth_config"
    )
    access_token=""
}

request_access_token() {
    set +x
    [ -n "$auth_config" ] || die "Missing first-factor download credentials."
    [ -n "$mfa_code" ] || die "Missing TOTP code."
    token_url="${BASE_URL}/_toolkit/auth/token"
    resolve_host="${TOOLKIT_RESOLVE_HOST:-downloads.example.com}"
    if [ -n "${TOOLKIT_RESOLVE_IP:-}" ]; then
        access_token="$(printf '%s\n' "$mfa_code" | curl --disable --config "$auth_config" \
            --fail --silent --show-error --request POST --data-binary @- --max-redirs 0 \
            --proto "$CURL_PROTO" --tlsv1.2 \
            --resolve "${resolve_host}:443:${TOOLKIT_RESOLVE_IP}" "$token_url")" || {
            mfa_code=""
            die "MFA failed. After three failures within ten minutes, Fail2ban blocks the source IP."
        }
    else
        access_token="$(printf '%s\n' "$mfa_code" | curl --disable --config "$auth_config" \
            --fail --silent --show-error --request POST --data-binary @- --max-redirs 0 \
            --proto "$CURL_PROTO" --tlsv1.2 "$token_url")" || {
            mfa_code=""
            die "MFA failed. After three failures within ten minutes, Fail2ban blocks the source IP."
        }
    fi
    mfa_code=""
    write_token_config "$access_token"
    access_token=""
    printf '%s\n' 'MFA erfolgreich; Downloadfreigabe für diesen Lauf (maximal zehn Minuten).' >&2
}

configure_quick_mode() {
    [ -n "$QUICK_MODE" ] || return 0

    case "$QUICK_MODE" in
    decepticon)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS="${TOOLKIT_BOOTSTRAP_ARGS:-}"
        printf "Toolkit quick mode: Decepticon with a VM-wide Mullvad tunnel.\n" >&2
        printf "After the separate Toolkit password, Mullvad asks for its account number without echo.\n" >&2
        printf "Normal host and container traffic uses Shadowsocks on port 443; only SSH management stays outside Mullvad.\n" >&2
        printf "If Docker group membership changes, reconnect and run the same command again.\n" >&2
        ;;
    examstation)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS=""
        printf "Toolkit quick mode: shared browser-only examination station.\n" >&2
        printf "Use a dedicated Debian 13 VM with public TCP 80/443 and a DNS name.\n" >&2
        printf "The candidate is informed of proctoring; active remote control is visibly indicated.\n" >&2
        ;;
    ssh | ssh-gui)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS="${QUICK_MODE} --accept-lockout-risk"
        printf "Toolkit quick mode: %s with immediate SSH hardening.\n" "$QUICK_MODE" >&2
        printf "The SSH bundle asks which public key to install; its default source is ~/.ssh/dynamic/*.pub on this VM, otherwise paste one.\n" >&2
        printf "Keep every matching private key only on your local workstation.\n" >&2
        printf "Keep the provider console open until key-based SSH login has been verified.\n" >&2
        ;;
    ssh-gui-clipboard)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS="ssh-gui --gui-clipboard --accept-lockout-risk"
        printf "Toolkit quick mode: ssh-gui with bidirectional VNC clipboard.\n" >&2
        printf "WARNING: Software in the VM can read clipboard data copied into it.\n" >&2
        printf "The SSH bundle asks which public key to install; its default source is ~/.ssh/dynamic/*.pub on this VM, otherwise paste one.\n" >&2
        printf "Keep every matching private key only on your local workstation.\n" >&2
        printf "Keep the provider console open until key-based SSH login has been verified.\n" >&2
        ;;
    vpn)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS=""
        printf "Toolkit quick mode: Firefox through Mullvad with Shadowsocks on port 443.\n" >&2
        printf "After the separate Toolkit password, Mullvad asks for its account number.\n" >&2
        printf "Only SSH management stays outside Mullvad; VNC remains inside that SSH tunnel.\n" >&2
        printf "Close Firefox first and keep the provider console open for the initial live test.\n" >&2
        ;;
    pbp)
        TOOLKIT_RUN_BOOTSTRAP=1
        TOOLKIT_BOOTSTRAP_ARGS=""
        printf "Toolkit quick mode: PBP Windows-Firefox persona through Mullvad Germany.\n" >&2
        printf "Mullvad uses Shadowsocks on port 443 with Auto-Connect and Lockdown.\n" >&2
        printf "Run ssh-gui-hardening first; PBP stays interactive and headful in VNC.\n" >&2
        printf "After the separate Toolkit password, Mullvad asks for its account number.\n" >&2
        ;;
    *)
        die "Unsupported quick mode: $QUICK_MODE"
        ;;
    esac
    export TOOLKIT_RUN_BOOTSTRAP TOOLKIT_BOOTSTRAP_ARGS
}

clear_access_auth() {
    unset TOOLKIT_AUTH TOOLKIT_TOTP TOOLKIT_AUTH_FILE TOOLKIT_TOTP_FILE
    mfa_code=""
    if [ -n "$auth_tmp" ] && [ -d "$auth_tmp" ]; then
        rm -rf -- "$auth_tmp"
    fi
    auth_tmp=""
    auth_config=""
}

run_bootstrap_command() {
    (
        cd "$bootstrap_dir"
        set -f
        if [ "$TOOL" = "decepticon" ]; then
            # intentional splitting: these are trusted option lists, not shell code.
            # shellcheck disable=SC2086
            "$bootstrap" ${decepticon_bootstrap_prefix:-} ${TOOLKIT_BOOTSTRAP_ARGS:-}
        else
            # intentional splitting: this is a trusted option list, not shell code.
            # shellcheck disable=SC2086
            "$bootstrap" ${TOOLKIT_BOOTSTRAP_ARGS:-}
        fi
    )
}

remove_progress_file() {
    [ -n "$progress_file" ] || return 0
    if [ -f "$progress_file" ]; then
        rm -f -- "$progress_file"
    fi
    progress_file=""
    unset TOOLKIT_PROGRESS_FILE
}

run_decepticon_vpn_phase() {
    mullvad_setup="${bootstrap_dir}/setup-mullvad.sh"
    if [ ! -e "$mullvad_setup" ] && [ ! -L "$mullvad_setup" ]; then
        return 0
    fi
    [ -f "$mullvad_setup" ] && [ ! -L "$mullvad_setup" ] && [ -x "$mullvad_setup" ] ||
        die "Refusing unsafe Mullvad setup companion: $mullvad_setup"

    printf '\nMullvad wird jetzt im Vordergrund eingerichtet.\n' >&2
    printf 'Die Accountnummer wird verdeckt direkt am Terminal abgefragt.\n' >&2
    if (
        cd "$bootstrap_dir"
        "$bootstrap" --vpn-only
    ); then
        :
    else
        vpn_status=$?
        printf 'Mullvad setup failed with exit code %s.\n' "$vpn_status" >&2
        return "$vpn_status"
    fi

    decepticon_bootstrap_prefix="--vpn-ready"
    prepare_decepticon_privileges || return $?
    printf '✓ Mullvad ist fail-closed über Shadowsocks Port 443 verbunden.\n' >&2
}

clear_progress_line() {
    [ -n "$progress_active" ] || return 0
    printf '\r\033[2K' >&2
    progress_active=""
}

render_progress() {
    progress_tick="$1"
    progress_seconds=$((progress_tick / 5))
    progress_minutes=$((progress_seconds / 60))
    progress_seconds=$((progress_seconds % 60))

    progress_phase_name="system"
    if [ -n "$progress_file" ] && [ -f "$progress_file" ] && [ ! -L "$progress_file" ]; then
        if IFS= read -r progress_candidate <"$progress_file"; then
            case "$progress_candidate" in
            system | docker | source | runtime | launcher | images | network | finish) progress_phase_name="$progress_candidate" ;;
            esac
        fi
    fi

    case "$progress_phase_name" in
    system)
        progress_step=1
        progress_label='System'
        ;;
    docker)
        progress_step=2
        progress_label='Docker'
        ;;
    source)
        progress_step=3
        progress_label='Quellpaket'
        ;;
    runtime)
        progress_step=4
        progress_label='Runtime'
        ;;
    launcher)
        progress_step=5
        progress_label='Launcher'
        ;;
    images)
        progress_step=6
        progress_label='Container-Images'
        ;;
    network)
        progress_step=7
        progress_label='Mullvad-Egress'
        ;;
    finish)
        progress_step=8
        progress_label='Fertig'
        ;;
    esac

    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8* | *utf8* | *UTF8*)
        case $((progress_tick % 10)) in
        0) progress_frame='⠋' ;; 1) progress_frame='⠙' ;;
        2) progress_frame='⠹' ;; 3) progress_frame='⠸' ;;
        4) progress_frame='⠼' ;; 5) progress_frame='⠴' ;;
        6) progress_frame='⠦' ;; 7) progress_frame='⠧' ;;
        8) progress_frame='⠇' ;; *) progress_frame='⠏' ;;
        esac
        progress_done='●'
        progress_current='◉'
        progress_wait='○'
        ;;
    *)
        case $((progress_tick % 4)) in
        0) progress_frame='|' ;; 1) progress_frame='/' ;;
        2) progress_frame='-' ;; *) progress_frame='\' ;;
        esac
        progress_done='#'
        progress_current='>'
        progress_wait='.'
        ;;
    esac

    progress_track=""
    progress_index=1
    while [ "$progress_index" -le 8 ]; do
        if [ "$progress_phase_name" = "finish" ] || [ "$progress_index" -lt "$progress_step" ]; then
            progress_track="${progress_track}${progress_done}"
        elif [ "$progress_index" -eq "$progress_step" ]; then
            progress_track="${progress_track}${progress_current}"
        else
            progress_track="${progress_track}${progress_wait}"
        fi
        progress_index=$((progress_index + 1))
    done

    if [ -z "${NO_COLOR:-}" ]; then
        printf '\r\033[2K  \033[38;5;45m%s\033[0m Toolkit baut Decepticon  \033[38;5;45m%s\033[0m  %-16s [%02d:%02d]' \
            "$progress_frame" "$progress_track" "$progress_label" "$progress_minutes" "$progress_seconds" >&2
    else
        printf '\r\033[2K  %s Toolkit baut Decepticon  %s  %-16s [%02d:%02d]' \
            "$progress_frame" "$progress_track" "$progress_label" "$progress_minutes" "$progress_seconds" >&2
    fi
}

spinner_loop() {
    progress_tick=0
    while :; do
        render_progress "$progress_tick"
        progress_tick=$((progress_tick + 1))
        sleep 0.2
    done
}

stop_spinner() {
    if [ -n "$spinner_pid" ]; then
        kill "$spinner_pid" >/dev/null 2>&1 || true
        wait "$spinner_pid" >/dev/null 2>&1 || true
        spinner_pid=""
    fi
    clear_progress_line
}

prepare_decepticon_privileges() {
    [ "$(id -u)" -ne 0 ] || return 0
    command -v sudo >/dev/null 2>&1 || return 0

    if sudo -n true >/dev/null 2>&1; then
        return 0
    fi

    if [ -t 2 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
        printf '\nAdministratorrechte werden vor der Animation bestätigt.\n' >&2
        sudo -v </dev/tty
        return $?
    fi

    die "Decepticon bootstrap needs passwordless sudo in a noninteractive session."
}

show_bootstrap_failure_tail() {
    [ -f "$bootstrap_log" ] || return 0
    printf '\nLast bootstrap messages (sanitized):\n' >&2
    (
        tail -c 16384 "$bootstrap_log" 2>/dev/null || true
    ) | LC_ALL=C tr -cd '\11\12\40-\176' | tail -n 40 >&2 || true
}

run_decepticon_bootstrap() {
    progress_mode="${TOOLKIT_PROGRESS:-auto}"
    case "$progress_mode" in
    auto | plain | spinner | verbose) ;;
    *) die "TOOLKIT_PROGRESS must be auto, plain, spinner or verbose" ;;
    esac

    prepare_decepticon_privileges
    if run_decepticon_vpn_phase; then
        :
    else
        vpn_status=$?
        return "$vpn_status"
    fi

    if [ "$progress_mode" = "verbose" ]; then
        if run_bootstrap_command; then
            return 0
        else
            return $?
        fi
    fi

    need_cmd setsid

    bootstrap_log_dir="${archive_root}/${TOOL}/logs"
    mkdir -p "$bootstrap_log_dir"
    chmod 0700 "$bootstrap_log_dir"
    previous_umask="$(umask)"
    umask 077
    bootstrap_log="$(mktemp "${bootstrap_log_dir}/${release}.bootstrap.XXXXXX.log")"
    progress_file="$(mktemp "${bootstrap_log_dir}/.${release}.progress.XXXXXX")"
    printf 'system\n' >"$progress_file"
    umask "$previous_umask"
    chmod 0600 "$bootstrap_log" "$progress_file"
    TOOLKIT_PROGRESS_FILE="$progress_file"
    export TOOLKIT_PROGRESS_FILE

    printf '\nInstallationsdetails: %s\n' "$bootstrap_log" >&2
    printf 'Der erste lokale Image-Build kann mehrere Minuten dauern.\n' >&2

    (
        trap - 1 2 3 15 20
        cd "$bootstrap_dir"
        set -f
        # intentional argument splitting: these variables are option lists, not shell code.
        # shellcheck disable=SC2086
        exec setsid "$bootstrap" ${decepticon_bootstrap_prefix:-} ${TOOLKIT_BOOTSTRAP_ARGS:-}
    ) >"$bootstrap_log" 2>&1 &
    bootstrap_pid=$!
    bootstrap_process_group=1

    use_spinner=0
    case "$progress_mode" in
    spinner) [ -t 2 ] && [ "${TERM:-dumb}" != dumb ] && use_spinner=1 ;;
    auto)
        [ -t 2 ] && [ "${TERM:-dumb}" != dumb ] && [ -z "${CI:-}" ] && use_spinner=1
        ;;
    esac

    if [ "$use_spinner" -eq 1 ]; then
        progress_active=1
        spinner_loop &
        spinner_pid=$!
    else
        printf 'Decepticon wird im Hintergrund vorbereitet ...\n' >&2
    fi

    if wait "$bootstrap_pid"; then
        bootstrap_status=0
    else
        bootstrap_status=$?
    fi
    bootstrap_pid=""
    bootstrap_process_group=""
    stop_spinner
    remove_progress_file

    if [ "$bootstrap_status" -eq 0 ]; then
        printf '✓ Decepticon wurde vorbereitet.\n' >&2
        return 0
    fi

    if [ "$bootstrap_status" -eq 20 ]; then
        printf 'Docker-Gruppenwechsel erforderlich; Details: %s\n' "$bootstrap_log" >&2
        return 20
    fi

    printf 'Bootstrap failed with exit code %s. Full log: %s\n' \
        "$bootstrap_status" "$bootstrap_log" >&2
    show_bootstrap_failure_tail
    return "$bootstrap_status"
}

valid_name() {
    case "$1" in
    '' | . | .. | *[!A-Za-z0-9._-]*) return 1 ;;
    *) return 0 ;;
    esac
}

valid_version() {
    printf '%s\n' "$1" | awk '
    /^v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*(-[A-Za-z0-9][A-Za-z0-9._-]*)?$/ { valid = 1 }
    END { exit(valid ? 0 : 1) }
  '
}

validate_base_url() {
    case "$BASE_URL" in
    https://*) ;;
    http://*)
        [ "${TOOLKIT_ALLOW_INSECURE_HTTP:-0}" = "1" ] ||
            die "Plain HTTP is disabled. Use HTTPS or explicitly set TOOLKIT_ALLOW_INSECURE_HTTP=1 for a local test server."
        CURL_PROTO="=http,https"
        ;;
    *) die "TOOLKIT_BASE_URL must start with https://" ;;
    esac

    case "$BASE_URL" in
    *[!A-Za-z0-9:/._~-]*) die "TOOLKIT_BASE_URL contains unsupported characters: $BASE_URL" ;;
    esac
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "Need root privileges and sudo is not installed."
    fi
}

curl_fetch() {
    resolve_host="${TOOLKIT_RESOLVE_HOST:-downloads.example.com}"

    if [ -n "${TOOLKIT_RESOLVE_IP:-}" ] && [ -n "$auth_config" ]; then
        curl --disable --config "$auth_config" --resolve "${resolve_host}:443:${TOOLKIT_RESOLVE_IP}" "$@"
    elif [ -n "$auth_config" ]; then
        curl --disable --config "$auth_config" "$@"
    elif [ -n "${TOOLKIT_RESOLVE_IP:-}" ]; then
        curl --disable --resolve "${resolve_host}:443:${TOOLKIT_RESOLVE_IP}" "$@"
    else
        curl --disable "$@"
    fi
}

curl_body() {
    curl_fetch \
        --fail \
        --proto "$CURL_PROTO" \
        --tlsv1.2 \
        --retry 5 \
        --retry-delay 2 \
        --retry-all-errors \
        "$@"
}

detect_platform() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$arch" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *) die "Unsupported arch: $arch" ;;
    esac

    distro=""
    distro_version=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        distro="${ID:-}"
        distro_version="${VERSION_ID:-}"
    fi
}

load_release_set() {
    if [ "${release_set_state:-}" = available ]; then
        return 0
    fi
    if [ "${release_set_state:-}" = unavailable ]; then
        return 1
    fi

    release_set_tmp="$(mktemp)"
    if curl_fetch --fail --silent --show-error --proto "$CURL_PROTO" --tlsv1.2 --output "$release_set_tmp" "${BASE_URL}/tools/release-set.tsv"; then
        if ! awk -F '\t' '
      /^#/ { next }
      NF != 7 { bad = 1; next }
      $1 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ { bad = 1 }
      $2 !~ /^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$/ { bad = 1 }
      END { exit bad ? 1 : 0 }
    ' "$release_set_tmp"; then
            die "Invalid atomic release set from ${BASE_URL}/tools/release-set.tsv"
        fi
        release_set_state=available
        return 0
    fi

    rm -f -- "$release_set_tmp"
    release_set_tmp=""
    release_set_state=unavailable
    return 1
}

release_from_set() {
    awk -F '\t' -v wanted="$1" '
    /^#/ { next }
    $1 == wanted {
      if (version == "") version = $2
      if (version != $2) bad = 1
      found = 1
    }
    END {
      if (!found || bad) exit 1
      print version
    }
  ' "$release_set_tmp"
}

select_release() {
    if [ -n "$PINNED_VERSION" ]; then
        release="$PINNED_VERSION"
    elif load_release_set; then
        if ! release="$(release_from_set "$TOOL")"; then
            die "Tool $TOOL is missing or ambiguous in the atomic release set."
        fi
    else
        version_url="${BASE_URL}/tools/${TOOL}/latest.txt"
        release="$(curl_body --silent --show-error "$version_url" | tr -d '[:space:]')"
        [ -n "$release" ] || die "Could not read release version from $version_url"
    fi

    valid_version "$release" || die "Invalid release version for ${TOOL}: $release"
}

select_artifact() {
    candidates=""

    if [ "$distro" = "debian" ] && [ -n "$distro_version" ]; then
        candidates="$candidates
debian-${distro_version}-${arch}/${TOOL}.deb"
    fi

    candidates="$candidates
${os}-${arch}/${TOOL}.tar.zst
${os}-${arch}/${TOOL}.tar.gz
any/${TOOL}.tar.zst
any/${TOOL}.tar.gz
${os}-${arch}/${TOOL}"

    artifact_rel=""
    for candidate in $candidates; do
        if awk -v f="$candidate" '
      $2 == f { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$checksums"; then
            artifact_rel="$candidate"
            break
        fi
    done

    if [ -z "$artifact_rel" ]; then
        echo "No artifact found for ${distro:-$os} ${distro_version:-} ${arch}." >&2
        echo "Checked these entries in ${base}/SHA256SUMS:" >&2
        for candidate in $candidates; do
            printf '%s/%s\n' "$base" "$candidate" >&2
        done
        exit 1
    fi

    artifact_url="${base}/${artifact_rel}"
}

fetch_checksums() {
    checksums="${tmpdir}/SHA256SUMS"

    if ! curl_body --silent --show-error --output "$checksums" "${base}/SHA256SUMS"; then
        rm -f -- "$checksums"
        die "Could not fetch ${base}/SHA256SUMS with the short-lived MFA token. Start a new installer run if it expired."
    fi

    [ -s "$checksums" ] || die "Downloaded an empty checksum manifest: ${base}/SHA256SUMS"
}

verify_checksum() {
    expected="$(
        awk -v f="$artifact_rel" '
      $2 == f { count += 1; value = $1 }
      END { if (count == 1) print value; else exit 1 }
    ' "$checksums"
    )" || die "SHA256SUMS must contain exactly one entry for $artifact_rel"

    [ "${#expected}" -eq 64 ] || die "Invalid SHA-256 value for $artifact_rel"
    case "$expected" in
    *[!0-9A-Fa-f]*) die "Invalid SHA-256 value for $artifact_rel" ;;
    esac

    printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >/dev/null ||
        die "Checksum verification failed for $artifact_rel"
}

validate_tar_members() {
    members="${tmpdir}/archive-members.txt"
    types="${tmpdir}/archive-types.txt"
    tar -tzf "$file" >"$members"
    [ -s "$members" ] || die "Archive is empty: $artifact_rel"

    LC_ALL=C tar -tvzf "$file" >"$types"
    [ -s "$types" ] || die "Archive type listing is empty: $artifact_rel"

    while IFS= read -r listing; do
        kind=${listing%"${listing#?}"}
        case "$kind" in
        - | d) ;;
        *) die "Archive contains a link or unsupported entry type ($kind): $artifact_rel" ;;
        esac
    done <"$types"

    while IFS= read -r member; do
        case "$member" in
        /* | .. | ../* | */../* | */..)
            die "Unsafe path in archive: $member"
            ;;
        esac
    done <"$members"
}

find_bootstrap() {
    bootstrap_list="${tmpdir}/bootstrap-files.txt"
    find "$release_dir" -maxdepth 3 -type f \
        \( -name 'bootstrap.sh' -o -name 'bootstrap-*.sh' \) |
        sort >"$bootstrap_list"

    bootstrap="$(
        awk 'NR == 1 { value = $0 } END { if (NR == 1) print value; else exit 1 }' "$bootstrap_list"
    )" || die "Expected exactly one bootstrap script below $release_dir"
}

activate_archive_release() {
    tool_root="${archive_root}/${TOOL}"
    current_link="${tool_root}/current"
    current_tmp="${tool_root}/.current.$$"

    if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
        die "Refusing to replace non-symlink path: $current_link"
    fi

    rm -f -- "$current_tmp"
    ln -s "releases/${release}" "$current_tmp"
    mv -f -- "$current_tmp" "$current_link"
}

install_tar_gz() {
    need_cmd find
    need_cmd sort
    need_cmd tar

    archive_root="${TOOLKIT_ARCHIVE_ROOT:-${HOME}/.local/share/toolkit}"
    archive_root="${archive_root%/}"
    case "$archive_root" in
    '' | /) die "Unsafe TOOLKIT_ARCHIVE_ROOT: ${archive_root:-<empty>}" ;;
    /*) ;;
    *) die "TOOLKIT_ARCHIVE_ROOT must be an absolute path" ;;
    esac
    case "/${archive_root}/" in
    */../*) die "TOOLKIT_ARCHIVE_ROOT must not contain '..' path components" ;;
    esac

    release_root="${archive_root}/${TOOL}/releases"
    release_dir="${release_root}/${release}"
    release_tmp="${release_root}/.${release}.tmp.$$"

    validate_tar_members
    mkdir -p "$release_root"
    [ ! -e "$release_tmp" ] || die "Temporary release path already exists: $release_tmp"
    mkdir "$release_tmp"
    tar --no-same-owner --no-same-permissions -xzf "$file" -C "$release_tmp"
    printf '%s\n' "$expected" >"${release_tmp}/.toolkit-artifact.sha256"
    chmod 0644 "${release_tmp}/.toolkit-artifact.sha256"

    if [ -e "$release_dir" ]; then
        installed_sha="$(cat "${release_dir}/.toolkit-artifact.sha256" 2>/dev/null || true)"
        [ "$installed_sha" = "$expected" ] ||
            die "Release directory already exists with different or unknown content: $release_dir"
        rm -rf -- "$release_tmp"
        release_tmp=""
    else
        mv -- "$release_tmp" "$release_dir"
        release_tmp=""
    fi

    if [ "${TOOLKIT_RUN_BOOTSTRAP:-0}" = "1" ]; then
        find_bootstrap
        chmod +x "$bootstrap"
        bootstrap_dir="${bootstrap%/*}"
        if [ "$TOOL" = "decepticon" ]; then
            bootstrap_runner=run_decepticon_bootstrap
        else
            bootstrap_runner=run_bootstrap_command
        fi
        if "$bootstrap_runner"; then
            :
        else
            bootstrap_status=$?
            if [ "$TOOL" = "decepticon" ] && [ "$bootstrap_status" -eq 20 ]; then
                cat >&2 <<EOF

Docker was installed, but this SSH session does not have the new group
membership yet. Reconnect to the VM and rerun the same verified release:

  curl -fsSL ${BASE_URL}/install.sh|sh -s -- decepticon ${release}

The current symlink was not changed; the immutable release remains available
for this safe retry.
EOF
            fi
            return "$bootstrap_status"
        fi
    else
        echo "Unpacked archive to ${release_dir}."
        echo "Set TOOLKIT_RUN_BOOTSTRAP=1 to run its single bootstrap script automatically."
    fi

    activate_archive_release
    echo "Current symlink: ${archive_root}/${TOOL}/current"
}

install_artifact() {
    case "$file" in
    *.deb)
        as_root apt-get install -y "$file"
        ;;
    *.tar.gz)
        install_tar_gz
        ;;
    *.tar.zst)
        need_cmd tar
        need_cmd unzstd
        tar --use-compress-program unzstd -xf "$file" -C "$tmpdir"

        extracted=""
        for candidate in "${tmpdir}/${TOOL}" "${tmpdir}/bin/${TOOL}"; do
            if [ -f "$candidate" ]; then
                extracted="$candidate"
                break
            fi
        done

        [ -n "$extracted" ] || die "Archive did not contain ${TOOL} or bin/${TOOL}."
        chmod +x "$extracted"
        as_root install -m 0755 "$extracted" "/usr/local/bin/${TOOL}"
        ;;
    *)
        chmod +x "$file"
        as_root install -m 0755 "$file" "/usr/local/bin/${TOOL}"
        ;;
    esac
}

install_current_tool() {
    valid_name "$TOOL" || die "Invalid tool name: $TOOL"
    select_release

    tmpdir="$(mktemp -d)"
    base="${BASE_URL}/tools/${TOOL}/${release}"
    fetch_checksums
    select_artifact
    file="${tmpdir}/${artifact_url##*/}"
    part="${file}.part"

    curl_body \
        --silent \
        --show-error \
        --continue-at - \
        --output "$part" \
        "$artifact_url"

    mv "$part" "$file"
    verify_checksum
    if [ "$REQUESTED_TOOL" != all ]; then
        clear_access_auth
    fi
    install_artifact

    rm -rf -- "$tmpdir"
    tmpdir=""
    echo "Installed ${TOOL} ${release} from ${artifact_rel}."
    if [ "$TOOL" = "decepticon" ] && [ "${TOOLKIT_RUN_BOOTSTRAP:-0}" = "1" ]; then
        if command -v decepticon >/dev/null 2>&1; then
            installed_home="${DECEPTICON_HOME:-${HOME}/.decepticon}"
            if [ "$installed_home" = "${HOME}/.decepticon" ]; then
                cat <<'EOF'

Decepticon ist bereit. Ab jetzt genügen die normalen Befehle:
  decepticon --version
  decepticon onboard --reset
  decepticon start
EOF
            else
                cat <<EOF

Decepticon ist mit einem eigenen Runtime-Home bereit:
  DECEPTICON_HOME="${installed_home}" decepticon --version
  DECEPTICON_HOME="${installed_home}" decepticon onboard --reset
  DECEPTICON_HOME="${installed_home}" decepticon start
EOF
            fi
        else
            printf '\nLegacy launcher installed. Reconnect once, then use: decepticon\n'
        fi
    fi
}

need_cmd awk
need_cmd curl
need_cmd id
need_cmd mktemp
need_cmd sha256sum
need_cmd stat
need_cmd uname
validate_base_url
detect_platform

if [ "$REQUESTED_TOOL" = "all" ]; then
    [ -z "$PINNED_VERSION" ] || die "A pinned version is only supported for a single tool, not for all."
    prepare_secret_file_auth
    prepare_interactive_auth
    request_access_token

    index_tmp="$(mktemp)"
    curl_body --silent --show-error --output "$index_tmp" "${BASE_URL}/tools/index.txt"
    while IFS= read -r tool_name || [ -n "$tool_name" ]; do
        tool_name="$(printf '%s' "$tool_name" | tr -d '\r')"
        case "$tool_name" in
        '' | \#*) continue ;;
        esac
        valid_name "$tool_name" || die "Invalid tool name in tools/index.txt: $tool_name"

        TOOL="$tool_name"
        PINNED_VERSION=""
        install_current_tool
    done <"$index_tmp"
    rm -f -- "$index_tmp"
    index_tmp=""
else
    valid_name "$REQUESTED_TOOL" || die "Invalid tool name: $REQUESTED_TOOL"
    TOOL="$REQUESTED_TOOL"
    valid_version "$PINNED_VERSION" || [ -z "$PINNED_VERSION" ] ||
        die "Invalid pinned version: $PINNED_VERSION"
    prepare_secret_file_auth
    prepare_interactive_auth
    request_access_token
    configure_quick_mode
    install_current_tool
fi

clear_access_auth

trap - 0 1 2 3 15 20
