#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

MANAGED_PUBLIC_KEY="${VM_SSH_PUBLIC_KEY:-}"
PUBLIC_KEY_FILE="${VM_SSH_PUBLIC_KEY_FILE:-}"
readonly SSHD_DROPIN='/etc/ssh/sshd_config.d/00-vm-bootstrap.conf'
readonly VNC_DISPLAY='1'
readonly VNC_PORT='5901'
readonly LOCK_DIR='/run/vm-bootstrap'
readonly LOCK_FILE="$LOCK_DIR/lock"
readonly STATE_DIR='/var/lib/vm-bootstrap'

MODE=''
TARGET_USER="${VM_SSH_USER:-${SUDO_USER:-}}"
GUI_USER="${VM_GUI_USER:-malwarelab}"
GUI_GEOMETRY="${VM_GUI_GEOMETRY:-1600x900}"
GUI_CLIPBOARD=0
REPLACE_AUTHORIZED_KEYS=0
ALLOW_UNRESTRICTED_KEY_COPY=0
KEY_TEST_CONFIRMED=0
ACCEPT_LOCKOUT_RISK=0
PUBLIC_KEY_FINGERPRINT=''
VNC_SECRET_FILE=''
SSHD_TX_ACTIVE=0
SSHD_TX_BACKUP=''
SSHD_TX_HAD_PREVIOUS=0
SSHD_TX_TEMP=''
SSHD_TX_SERVICE=''
SSHD_TX_RELOADED=0
SSHD_TX_SERVICE_WAS_ACTIVE=0
SSHD_TX_SERVICE_ENABLE_CHANGED=0
SSHD_TX_SERVICE_START_ATTEMPTED=0
SSH_INSTALL_MASK_ACTIVE=0
SSH_INSTALL_MASKED_UNITS=()
SSH_SERVER_INSTALLED_BY_BOOTSTRAP=0
VNC_TX_ACTIVE=0
VNC_CONFIG_FORMAT=''

log() {
    printf '\n[vm-bootstrap] %s\n' "$*"
}

warn() {
    printf '\n[vm-bootstrap] WARNING: %s\n' "$*" >&2
}

die() {
    printf '\n[vm-bootstrap] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF_USAGE'
Usage:
  vm-bootstrap.sh key-only [options]
  vm-bootstrap.sh ssh      [options]
  vm-bootstrap.sh ssh-gui  [options]

Modes:
  key-only  Install the managed public key, but do not harden/reload sshd.
  ssh       Install the key and enforce public-key-only SSH authentication.
  ssh-gui   Do the same, add XFCE/TigerVNC, and permit only the VNC SSH tunnel.

Options:
  --user USER                Existing non-root SSH account. Defaults to SUDO_USER.
  --public-key-file FILE     Public key selected by the wrapper. Required unless
                             VM_SSH_PUBLIC_KEY or VM_SSH_PUBLIC_KEY_FILE is set.
  --gui-user USER            GUI account for ssh-gui. Default: malwarelab.
                             It is created as a locked, non-sudo account if absent.
  --geometry WIDTHxHEIGHT    VNC size. Default: 1600x900.
  --gui-clipboard            Enable VNC clipboard sharing (off by default).
  --replace-authorized-keys  Replace authorized_keys with the managed key.
                             Default: preserve existing keys and append this key.
  --append-unrestricted-key  Explicitly append a bare copy when the same key
                             already exists with authorized_keys restrictions.
  --confirm-key-tested       Confirm the matching private key was tested in a
                             separate SSH session before hardening.
  --accept-lockout-risk      Allow one-shot hardening with console recovery.
  -h, --help                 Show this help.

Environment equivalents: VM_SSH_USER, VM_SSH_PUBLIC_KEY,
VM_SSH_PUBLIC_KEY_FILE, VM_GUI_USER, VM_GUI_GEOMETRY.

Examples:
  sudo bash vm-bootstrap.sh key-only --user ubuntu --public-key-file ./admin.pub
  sudo bash vm-bootstrap.sh ssh --user ubuntu --public-key-file ./admin.pub --confirm-key-tested
  sudo bash vm-bootstrap.sh ssh-gui --user ubuntu --public-key-file ./admin.pub --gui-user malwarelab --confirm-key-tested

  curl -fsSL https://YOUR-SERVER/vm-bootstrap.sh \
    | sudo bash -s -- ssh-gui --user ubuntu --gui-user malwarelab --accept-lockout-risk
EOF_USAGE
}

parse_args() {
    [ "$#" -gt 0 ] || {
        usage >&2
        exit 2
    }

    case "$1" in
    key-only | ssh | ssh-gui)
        MODE="$1"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        die "Unknown mode: $1"
        ;;
    esac

    while [ "$#" -gt 0 ]; do
        case "$1" in
        --user)
            [ "$#" -ge 2 ] || die '--user requires a value.'
            TARGET_USER="$2"
            shift 2
            ;;
        --user=*)
            TARGET_USER="${1#*=}"
            shift
            ;;
        --public-key-file)
            [ "$#" -ge 2 ] || die '--public-key-file requires a value.'
            PUBLIC_KEY_FILE="$2"
            shift 2
            ;;
        --public-key-file=*)
            PUBLIC_KEY_FILE="${1#*=}"
            shift
            ;;
        --gui-user)
            [ "$#" -ge 2 ] || die '--gui-user requires a value.'
            GUI_USER="$2"
            shift 2
            ;;
        --gui-user=*)
            GUI_USER="${1#*=}"
            shift
            ;;
        --geometry)
            [ "$#" -ge 2 ] || die '--geometry requires a value.'
            GUI_GEOMETRY="$2"
            shift 2
            ;;
        --geometry=*)
            GUI_GEOMETRY="${1#*=}"
            shift
            ;;
        --gui-clipboard)
            GUI_CLIPBOARD=1
            shift
            ;;
        --replace-authorized-keys)
            REPLACE_AUTHORIZED_KEYS=1
            shift
            ;;
        --append-unrestricted-key)
            ALLOW_UNRESTRICTED_KEY_COPY=1
            shift
            ;;
        --confirm-key-tested)
            KEY_TEST_CONFIRMED=1
            shift
            ;;
        --accept-lockout-risk)
            ACCEPT_LOCKOUT_RISK=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
        esac
    done
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die 'Run this script as root (normally with sudo).'
}

require_supported_os() {
    [ -r /etc/os-release ] || die '/etc/os-release is missing.'
    # shellcheck disable=SC1091
    . /etc/os-release

    case "${ID:-}" in
    debian | ubuntu)
        ;;
    *)
        case " ${ID_LIKE:-} " in
        *' debian '*) ;;
        *) die "Supported systems are Debian/Ubuntu. Detected: ${ID:-unknown}." ;;
        esac
        ;;
    esac

    command -v apt-get >/dev/null 2>&1 || die 'apt-get is required.'
    command -v dpkg-query >/dev/null 2>&1 || die 'dpkg-query is required.'
}

validate_username() {
    local user="$1"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,30}\$?$ ]] ||
        die "Unsupported account name: $user"
}

validate_inputs() {
    [ -n "$TARGET_USER" ] ||
        die 'Could not infer the SSH user. Pass --user EXISTING_USER.'

    validate_username "$TARGET_USER"
    [ "$TARGET_USER" != 'root' ] ||
        die 'The managed SSH account must not be root; root SSH will be disabled.'
    id "$TARGET_USER" >/dev/null 2>&1 ||
        die "SSH account does not exist: $TARGET_USER"

    if [ "$MODE" = 'ssh-gui' ]; then
        validate_username "$GUI_USER"
        [ "$GUI_USER" != "$TARGET_USER" ] ||
            die 'The GUI account must differ from the SSH admin account.'
        [[ "$GUI_GEOMETRY" =~ ^[0-9]{3,5}x[0-9]{3,5}$ ]] ||
            die 'Geometry must look like 1600x900.'

        local width="${GUI_GEOMETRY%x*}"
        local height="${GUI_GEOMETRY#*x}"
        ((10#$width >= 640 && 10#$width <= 7680 && 10#$height >= 480 && 10#$height <= 4320)) ||
            die 'Geometry must be between 640x480 and 7680x4320.'
    elif [ "$GUI_CLIPBOARD" -eq 1 ]; then
        die '--gui-clipboard is valid only with ssh-gui.'
    fi

    if [ "$MODE" != 'key-only' ] &&
        [ "$KEY_TEST_CONFIRMED" -ne 1 ] &&
        [ "$ACCEPT_LOCKOUT_RISK" -ne 1 ]; then
        die 'Run key-only and test the private key first, then pass --confirm-key-tested. For a console-controlled one-shot run, pass --accept-lockout-risk.'
    fi
}

acquire_lock() {
    command -v flock >/dev/null 2>&1 || die 'flock is required (package: util-linux).'
    [ ! -L "$LOCK_DIR" ] || die "Refusing symlinked lock directory: $LOCK_DIR"
    if [ -e "$LOCK_DIR" ] && [ ! -d "$LOCK_DIR" ]; then
        die "Lock path is not a directory: $LOCK_DIR"
    fi
    install -d -m 0700 -o root -g root "$LOCK_DIR"
    if [ -e "$LOCK_FILE" ] && { [ -L "$LOCK_FILE" ] || [ ! -f "$LOCK_FILE" ]; }; then
        die "Unsafe lock file: $LOCK_FILE"
    fi
    touch "$LOCK_FILE"
    chown root:root "$LOCK_FILE"
    chmod 0600 "$LOCK_FILE"
    exec 9>"$LOCK_FILE"
    flock -n 9 || die 'Another vm-bootstrap process is already running.'
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 || die 'systemd is required.'
    [ -d /run/systemd/system ] || die 'systemd is not running. Run this inside the VM, not in a build chroot.'
}

prepare_apt() {
    log 'Refreshing Debian/Ubuntu package metadata.'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
}

install_ssh_client() {
    log 'Installing the SSH client/key validation tools.'
    install_missing_packages openssh-client
}

secure_failed_ssh_install() {
    local unit state
    local failed=0

    [ "$SSH_INSTALL_MASK_ACTIVE" -eq 1 ] || return 0
    trap - EXIT HUP INT TERM

    for unit in ssh.service ssh.socket; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    for unit in ssh.service ssh.socket; do
        systemctl mask "$unit" >/dev/null 2>&1 || true
    done

    for unit in ssh.service ssh.socket; do
        if systemctl is-active --quiet "$unit"; then
            failed=1
        fi
        state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        case "$state" in
        masked | masked-runtime) ;;
        *) failed=1 ;;
        esac
    done

    if [ "$failed" -ne 0 ]; then
        warn 'CRITICAL: OpenSSH installation failed and at least one SSH unit could not be proven stopped and masked. Use the VM console immediately; a default sshd may be exposed.'
    else
        warn 'OpenSSH installation did not complete safely; ssh.service and ssh.socket are verified stopped and masked for console recovery.'
    fi
}

mask_ssh_autostart_for_install() {
    local unit state

    SSH_INSTALL_MASK_ACTIVE=1
    SSH_INSTALL_MASKED_UNITS=()
    trap 'secure_failed_ssh_install' EXIT
    trap 'exit 130' HUP INT TERM

    for unit in ssh.service ssh.socket; do
        state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        case "$state" in
        masked | masked-runtime)
            ;;
        *)
            systemctl mask "$unit" >/dev/null ||
                die "Could not mask $unit before installing OpenSSH."
            SSH_INSTALL_MASKED_UNITS+=("$unit")
            ;;
        esac
    done
}

finalize_ssh_install_masks() {
    local unit state

    for unit in ssh.service ssh.socket; do
        systemctl disable --now "$unit" >/dev/null ||
            die "Could not leave freshly installed $unit disabled."
    done
    for unit in "${SSH_INSTALL_MASKED_UNITS[@]}"; do
        systemctl unmask "$unit" >/dev/null ||
            die "Could not remove the temporary mask from $unit."
    done
    systemctl daemon-reload

    for unit in ssh.service ssh.socket; do
        if systemctl is-active --quiet "$unit"; then
            die "Freshly installed $unit became active before SSH hardening was validated."
        fi
        state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        case "$state" in
        disabled | static | indirect | alias | not-found) ;;
        *) die "Freshly installed $unit is not safely disabled: ${state:-unknown}" ;;
        esac
    done

    SSH_INSTALL_MASK_ACTIVE=0
    trap - EXIT HUP INT TERM
}

install_ssh_server() {
    log 'Installing the OpenSSH server.'
    if package_is_installed openssh-server; then
        log 'OpenSSH server is already installed; no package upgrade is performed.'
    elif [ "$MODE" = 'key-only' ]; then
        die 'OpenSSH server is not installed. key-only refuses to start a server with the distro default policy; use ssh/ssh-gui with --accept-lockout-risk from the VM console.'
    else
        log 'Temporarily blocking SSH service/socket autostart until hardening is validated.'
        mask_ssh_autostart_for_install
        install_missing_packages openssh-server
        finalize_ssh_install_masks
        SSH_SERVER_INSTALLED_BY_BOOTSTRAP=1
    fi
    install -d -m 0755 -o root -g root /run/sshd
}

install_gui_packages() {
    log 'Installing XFCE and TigerVNC. No browser will be installed.'
    install_missing_packages \
        dbus-x11 \
        diffutils \
        iproute2 \
        openssl \
        procps \
        tigervnc-standalone-server \
        tigervnc-tools \
        xfce4 \
        xfce4-terminal \
        x11-xserver-utils \
        xfonts-base \
        xdotool
}

package_is_installed() {
    dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null |
        grep -Fqx 'install ok installed'
}

install_missing_packages() {
    local missing=()
    local package

    for package in "$@"; do
        if ! package_is_installed "$package"; then
            missing+=("$package")
        fi
    done

    if [ "${#missing[@]}" -eq 0 ]; then
        log 'All requested packages are already installed; no package upgrade is performed.'
        return
    fi

    apt-get install -y --no-install-recommends "${missing[@]}"
}

preflight_key_only_ssh_server() {
    if [ "$MODE" = 'key-only' ] && ! package_is_installed openssh-server; then
        die 'OpenSSH server is not installed. key-only refuses to start a server with the distro default policy; use ssh/ssh-gui with --accept-lockout-risk from the VM console.'
    fi
}

passwd_record() {
    getent passwd "$1" || die "Could not read passwd entry for $1."
}

user_home() {
    local record
    record="$(passwd_record "$1")"
    printf '%s\n' "$record" | awk -F: '{print $6}'
}

user_uid() {
    local record
    record="$(passwd_record "$1")"
    printf '%s\n' "$record" | awk -F: '{print $3}'
}

validate_user_home() {
    local user="$1"
    local home="$2"
    local expected_uid owner_uid mode

    expected_uid="$(user_uid "$user")"
    [[ "$home" = /* && "$home" != '/' ]] || die "Unsafe home directory for $user: $home"
    [ -d "$home" ] || die "Home directory does not exist for $user: $home"
    [ ! -L "$home" ] || die "Refusing symlinked home directory: $home"
    owner_uid="$(stat -c '%u' "$home")"
    [ "$owner_uid" = "$expected_uid" ] ||
        die "Home directory is not owned by $user: $home"
    mode="$(stat -c '%a' "$home")"
    (((8#$mode & 0022) == 0)) ||
        die "Home directory is group/world writable: $home"
}

validate_login_shell() {
    local user="$1"
    local record shell
    record="$(passwd_record "$user")"
    shell="$(printf '%s\n' "$record" | awk -F: '{print $7}')"
    if [ -z "$shell" ] || [ ! -x "$shell" ]; then
        die "SSH account has no executable login shell: $user"
    fi
    case "$shell" in
    */false | */nologin)
        die "SSH account has a disabled login shell: $user"
        ;;
    esac
}

validate_public_key() {
    local key_file key_type extra_line

    if [ -n "$PUBLIC_KEY_FILE" ]; then
        [ -f "$PUBLIC_KEY_FILE" ] && [ ! -L "$PUBLIC_KEY_FILE" ] && [ -r "$PUBLIC_KEY_FILE" ] ||
            die "Public-key file is missing or unsafe: $PUBLIC_KEY_FILE"
        IFS= read -r MANAGED_PUBLIC_KEY <"$PUBLIC_KEY_FILE" ||
            die "Could not read public-key file: $PUBLIC_KEY_FILE"
        extra_line="$(sed -n '2,$p' "$PUBLIC_KEY_FILE" | awk 'NF {print; exit}')"
        [ -z "$extra_line" ] || die 'Public-key file must contain exactly one non-empty key line.'
    fi
    [ -n "$MANAGED_PUBLIC_KEY" ] ||
        die 'No public key selected. Use the wrapper picker or pass --public-key-file FILE.'

    key_file="$(mktemp)"
    key_type="${MANAGED_PUBLIC_KEY%% *}"
    case "$key_type" in
    ssh-ed25519 | ecdsa-sha2-nistp256 | ecdsa-sha2-nistp384 | ecdsa-sha2-nistp521 | ssh-rsa) ;;
    *) die 'Selected public key has an unsupported SSH key type.' ;;
    esac

    printf '%s\n' "$MANAGED_PUBLIC_KEY" >"$key_file"
    chmod 0600 "$key_file"

    if ! PUBLIC_KEY_FINGERPRINT="$(ssh-keygen -lf "$key_file" -E sha256 2>/dev/null | awk '{print $2}')"; then
        rm -f "$key_file"
        die 'The selected public key is invalid.'
    fi
    rm -f "$key_file"

    [ -n "$PUBLIC_KEY_FINGERPRINT" ] || die 'Could not determine the public-key fingerprint.'
}

install_public_key() {
    local user="$1"
    local home group ssh_dir auth_file backup_stamp
    local uid managed_type managed_blob

    home="$(user_home "$user")"
    uid="$(user_uid "$user")"
    group="$(id -gn "$user")"

    [ "$uid" -ne 0 ] || die 'Refusing to install the managed key for UID 0.'
    validate_user_home "$user" "$home"

    ssh_dir="$home/.ssh"
    auth_file="$ssh_dir/authorized_keys"

    [ ! -L "$ssh_dir" ] || die "Refusing symlinked SSH directory: $ssh_dir"
    [ ! -L "$auth_file" ] || die "Refusing symlinked authorized_keys: $auth_file"
    if [ -e "$ssh_dir" ] && [ ! -d "$ssh_dir" ]; then
        die "SSH path is not a directory: $ssh_dir"
    fi
    if [ -e "$auth_file" ] && [ ! -f "$auth_file" ]; then
        die "authorized_keys is not a regular file: $auth_file"
    fi

    install -d -m 0700 -o "$user" -g "$group" "$ssh_dir"

    if [ "$REPLACE_AUTHORIZED_KEYS" -eq 1 ]; then
        if [ -e "$auth_file" ]; then
            backup_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
            install -m 0600 -o "$user" -g "$group" \
                "$auth_file" "$auth_file.vm-bootstrap.bak.$backup_stamp"
            log "Backed up the previous authorized_keys file."
        fi
        printf '%s\n' "$MANAGED_PUBLIC_KEY" >"$auth_file"
        log "Replaced authorized_keys for $user with the managed key."
    else
        touch "$auth_file"
        chown "$user:$group" "$auth_file"
        chmod 0600 "$auth_file"

        IFS=' ' read -r managed_type managed_blob _ <<<"$MANAGED_PUBLIC_KEY"
        if awk -v type="$managed_type" -v blob="$managed_blob" \
            '$1 == type && $2 == blob {found=1} END {exit !found}' "$auth_file"; then
            log "Managed key is already present for $user."
        else
            if ssh-keygen -lf "$auth_file" -E sha256 2>/dev/null |
                awk '{print $2}' |
                grep -Fqx "$PUBLIC_KEY_FINGERPRINT"; then
                if [ "$ALLOW_UNRESTRICTED_KEY_COPY" -ne 1 ]; then
                    die 'The managed key already exists with authorized_keys options. Refusing to bypass those restrictions; review the existing line or pass --append-unrestricted-key explicitly.'
                fi
                warn 'Appending an unrestricted copy of a key that already has authorized_keys restrictions.'
            fi
            if [ -s "$auth_file" ] && [ "$(tail -c 1 "$auth_file" | od -An -tx1 | tr -d ' \n')" != '0a' ]; then
                printf '\n' >>"$auth_file"
            fi
            printf '%s\n' "$MANAGED_PUBLIC_KEY" >>"$auth_file"
            log "Added the managed key for $user without removing existing keys."
        fi
    fi

    chown "$user:$group" "$auth_file"
    chmod 0600 "$auth_file"
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -R "$ssh_dir" >/dev/null 2>&1 || true
    fi
}

sshd_context() {
    local client_ip='127.0.0.1'
    local server_ip='127.0.0.1'
    local server_port='22'
    local host
    host="$client_ip"

    if [ -n "${SSH_CONNECTION:-}" ]; then
        # SSH_CONNECTION: client-address client-port server-address server-port
        IFS=' ' read -r client_ip _ server_ip server_port <<<"$SSH_CONNECTION"
        host="$client_ip"
    fi

    printf 'user=%s,host=%s,addr=%s,laddr=%s,lport=%s\n' \
        "$TARGET_USER" "$host" "$client_ip" "$server_ip" "$server_port"
}

sshd_effective_config() {
    local context
    context="$(sshd_context)"
    sshd -T -C "$context"
}

effective_value() {
    local config="$1"
    local key="$2"
    printf '%s\n' "$config" | awk -v wanted="$key" '$1 == wanted {$1=""; sub(/^ /, ""); print; exit}'
}

assert_effective_value() {
    local config="$1"
    local key="$2"
    local expected="$3"
    local actual
    actual="$(effective_value "$config" "$key")"
    [ "$actual" = "$expected" ] || {
        printf 'Expected sshd %s=%s, got %s\n' "$key" "$expected" "${actual:-<missing>}" >&2
        return 1
    }
}

assert_single_effective_token() {
    local config="$1"
    local key="$2"
    local expected="$3"
    local values=()

    mapfile -t values < <(
        printf '%s\n' "$config" |
            awk -v wanted="$key" '$1 == wanted {for (i=2; i<=NF; i++) print $i}'
    )

    if [ "${#values[@]}" -ne 1 ] || [ "${values[0]:-}" != "$expected" ]; then
        printf 'Expected exactly one sshd %s token (%s), got: %s\n' \
            "$key" "$expected" "${values[*]:-<missing>}" >&2
        return 1
    fi
}

verify_authorized_keys_location() {
    local config auth_files
    config="$(sshd_effective_config)"
    auth_files="$(effective_value "$config" 'authorizedkeysfile')"

    case " $auth_files " in
    *' .ssh/authorized_keys '* | *' %h/.ssh/authorized_keys '*)
        ;;
    *)
        die "Effective AuthorizedKeysFile does not include .ssh/authorized_keys: ${auth_files:-missing}"
        ;;
    esac
}

ensure_gui_user() {
    local password_status marker marker_tmp expected_marker actual_marker
    local marker_owner marker_mode uid

    install -d -m 0700 -o root -g root "$STATE_DIR"
    marker="$STATE_DIR/gui-user-$GUI_USER"
    if id "$GUI_USER" >/dev/null 2>&1; then
        [ "$(user_uid "$GUI_USER")" -ne 0 ] || die 'The GUI account must not have UID 0.'
        if [ ! -f "$marker" ] || [ -L "$marker" ]; then
            die "Refusing pre-existing, unmanaged GUI account: $GUI_USER. Use a dedicated account created by this bootstrap."
        fi
        marker_owner="$(stat -c '%u' "$marker")"
        marker_mode="$(stat -c '%a' "$marker")"
        [ "$marker_owner" = '0' ] && [ "$marker_mode" = '600' ] ||
            die "Unsafe GUI account marker: $marker"
        uid="$(user_uid "$GUI_USER")"
        expected_marker="$GUI_USER:$uid"
        actual_marker="$(tr -d '\r\n' <"$marker")"
        [ "$actual_marker" = "$expected_marker" ] ||
            die "GUI account identity no longer matches its bootstrap marker: $GUI_USER"
        log "Reusing bootstrap-managed GUI account: $GUI_USER"
    else
        log "Creating locked, non-sudo GUI account: $GUI_USER"
        useradd --create-home --shell /bin/bash "$GUI_USER"
        uid="$(user_uid "$GUI_USER")"
        marker_tmp="$(mktemp "$STATE_DIR/.gui-user.XXXXXXXX")"
        printf '%s:%s\n' "$GUI_USER" "$uid" >"$marker_tmp"
        chown root:root "$marker_tmp"
        chmod 0600 "$marker_tmp"
        mv -fT "$marker_tmp" "$marker"
    fi

    passwd --lock "$GUI_USER" >/dev/null
    password_status="$(passwd --status "$GUI_USER" | awk '{print $2}')"
    [ "$password_status" = 'L' ] ||
        die "GUI account password could not be locked: $GUI_USER"
    if id -nG "$GUI_USER" | tr ' ' '\n' |
        grep -Eq '^(sudo|wheel|docker|lxd|incus|incus-admin|libvirt|disk|kvm)$'; then
        die "GUI account $GUI_USER belongs to a privileged host-control group. Use a dedicated unprivileged account."
    fi
    if command -v sudo >/dev/null 2>&1 &&
        LC_ALL=C sudo -n -l -U "$GUI_USER" 2>/dev/null |
        grep -Eq '^[[:space:]]*\('; then
        die "GUI account $GUI_USER has a sudoers command grant. Use a dedicated unprivileged account."
    fi
    if command -v sudo >/dev/null 2>&1 &&
        runuser -u "$GUI_USER" -- sudo -n true >/dev/null 2>&1; then
        die "GUI account $GUI_USER has passwordless sudo access. Use a dedicated unprivileged account."
    fi
}

generate_vnc_password() {
    local candidate
    while true; do
        candidate="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9')"
        if [ "${#candidate}" -ge 8 ]; then
            printf '%s\n' "${candidate:0:8}"
            return
        fi
    done
}

ensure_user_directory() {
    local user="$1"
    local directory="$2"
    local expected_uid owner_uid

    expected_uid="$(user_uid "$user")"
    runuser -u "$user" -- mkdir -p -- "$directory"
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        die "Unsafe user-owned directory: $directory"
    fi
    owner_uid="$(stat -c '%u' "$directory")"
    [ "$owner_uid" = "$expected_uid" ] ||
        die "Directory is not owned by $user: $directory"
    runuser -u "$user" -- chmod 0700 -- "$directory"
}

install_user_file() {
    local user="$1"
    local mode="$2"
    local source_file="$3"
    local destination="$4"
    local destination_dir expected_uid owner_uid actual_mode

    destination_dir="${destination%/*}"
    if [ ! -d "$destination_dir" ] || [ -L "$destination_dir" ]; then
        die "Unsafe destination directory for $user: $destination_dir"
    fi
    expected_uid="$(user_uid "$user")"
    owner_uid="$(stat -c '%u' "$destination_dir")"
    [ "$owner_uid" = "$expected_uid" ] ||
        die "Destination directory is not owned by $user: $destination_dir"

    runuser -u "$user" -- sh -c '
    set -eu
    destination=$1
    mode=$2
    directory=${destination%/*}
    basename=${destination##*/}
    temporary=$(mktemp "$directory/.$basename.XXXXXXXX")
    trap '\''rm -f "$temporary"'\'' EXIT HUP INT TERM
    cat >"$temporary"
    chmod "$mode" "$temporary"
    mv -fT "$temporary" "$destination"
    trap - EXIT HUP INT TERM
  ' sh "$destination" "$mode" <"$source_file"

    if [ ! -f "$destination" ] || [ -L "$destination" ]; then
        die "Unsafe installed user file: $destination"
    fi
    owner_uid="$(stat -c '%u' "$destination")"
    actual_mode="$(stat -c '%a' "$destination")"
    [ "$owner_uid" = "$expected_uid" ] && [ "$actual_mode" = "$mode" ] ||
        die "Wrong owner or mode on installed user file: $destination"
}

write_vnc_password() {
    local home="$1"
    local password password_filter tmp_pass secret_tmp vnc_dir

    VNC_SECRET_FILE="/root/.vm-bootstrap-vnc-${GUI_USER}"
    [ ! -L "$VNC_SECRET_FILE" ] || die "Refusing symlinked VNC secret file: $VNC_SECRET_FILE"
    if [ -e "$VNC_SECRET_FILE" ] && [ ! -f "$VNC_SECRET_FILE" ]; then
        die "VNC secret is not a regular file: $VNC_SECRET_FILE"
    fi

    if [ -s "$VNC_SECRET_FILE" ]; then
        password="$(tr -d '\r\n' <"$VNC_SECRET_FILE")"
        [[ "$password" =~ ^[A-Za-z0-9]{8}$ ]] ||
            die "Invalid stored VNC password in $VNC_SECRET_FILE"
    else
        password="$(generate_vnc_password)"
        secret_tmp="$(mktemp /root/.vm-bootstrap-vnc.XXXXXXXX)"
        printf '%s\n' "$password" >"$secret_tmp"
        chown root:root "$secret_tmp"
        chmod 0600 "$secret_tmp"
        mv -f "$secret_tmp" "$VNC_SECRET_FILE"
    fi
    chown root:root "$VNC_SECRET_FILE"
    chmod 0600 "$VNC_SECRET_FILE"

    password_filter="$(command -v tigervncpasswd || command -v vncpasswd || true)"
    [ -n "$password_filter" ] || die 'TigerVNC password utility was not installed.'

    tmp_pass="$(mktemp)"
    printf '%s\n' "$password" | "$password_filter" -f >"$tmp_pass"
    chmod 0600 "$tmp_pass"

    for vnc_dir in "$home/.vnc" "$home/.config/tigervnc"; do
        ensure_user_directory "$GUI_USER" "$vnc_dir"
        install_user_file "$GUI_USER" 600 "$tmp_pass" "$vnc_dir/passwd"
    done

    rm -f "$tmp_pass"
}

write_vnc_config() {
    local home="$1"
    local vnc_dir config_tmp xstartup_tmp

    config_tmp="$(mktemp)"
    {
        printf '%s\n' \
            'session=xfce' \
            "geometry=$GUI_GEOMETRY" \
            'depth=24' \
            'localhost' \
            'nolisten=tcp' \
            'securitytypes=VncAuth' \
            'nevershared' \
            'acceptsetdesktopsize=0' \
            'allowoverride=desktop,AcceptPointerEvents'
        if [ "$GUI_CLIPBOARD" -eq 0 ]; then
            printf '%s\n' \
                'noclipboard' 'acceptcuttext=0' 'sendcuttext=0' \
                'sendprimary=0' 'setprimary=0'
        else
            printf '%s\n' 'acceptcuttext=1' 'sendcuttext=1' 'sendprimary=1' 'setprimary=1'
        fi
    } >"$config_tmp"

    for vnc_dir in "$home/.vnc" "$home/.config/tigervnc"; do
        ensure_user_directory "$GUI_USER" "$vnc_dir"
        install_user_file "$GUI_USER" 600 "$config_tmp" "$vnc_dir/config"
    done
    rm -f "$config_tmp"

    xstartup_tmp="$(mktemp)"
    cat >"$xstartup_tmp" <<'EOF_XSTARTUP'
#!/bin/sh
set -eu

PATH='/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'
export PATH

fail() {
  printf 'xstartup: %s\n' "$*" >&2
  exit 1
}

case "${HOME:-}" in
  /*) ;;
  *) fail 'HOME is missing or not absolute.' ;;
esac
[ -d "$HOME" ] && [ ! -L "$HOME" ] || fail 'HOME is not a real directory.'

XAUTHORITY="$HOME/.Xauthority"
export XAUTHORITY
uid="$(id -u)"
[ "$(stat -c '%u' "$HOME")" = "$uid" ] || fail 'HOME has the wrong owner.'
[ -f "$XAUTHORITY" ] && [ ! -L "$XAUTHORITY" ] && [ -r "$XAUTHORITY" ] \
  || fail 'TigerVNC Xauthority is missing, unreadable, or unsafe.'
[ "$(stat -c '%u' "$XAUTHORITY")" = "$uid" ] \
  || fail 'TigerVNC Xauthority has the wrong owner.'
[ "$(stat -c '%a' "$XAUTHORITY")" = '600' ] \
  || fail 'TigerVNC Xauthority must have mode 0600.'
[ -s "$XAUTHORITY" ] || fail 'TigerVNC Xauthority is empty.'

snap_dir="$HOME/snap"
firefox_dir="$snap_dir/firefox"
common_dir="$firefox_dir/common"
for directory in "$snap_dir" "$firefox_dir" "$common_dir"; do
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    [ -d "$directory" ] && [ ! -L "$directory" ] \
      || fail "Unsafe Firefox Snap directory: $directory"
  else
    mkdir -m 0700 -- "$directory" \
      || fail "Could not create Firefox Snap directory: $directory"
  fi
  [ "$(stat -c '%u' "$directory")" = "$uid" ] \
    || fail "Firefox Snap directory has the wrong owner: $directory"
  chmod 0700 "$directory" \
    || fail "Could not protect Firefox Snap directory: $directory"
  [ "$(stat -c '%a' "$directory")" = '700' ] \
    || fail "Firefox Snap directory has unsafe mode: $directory"
done

destination="$common_dir/.Xauthority"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] \
    || fail "Unsafe Firefox Xauthority destination: $destination"
  [ "$(stat -c '%u' "$destination")" = "$uid" ] \
    || fail 'Firefox Xauthority destination has the wrong owner.'
fi

mirror_tmp=''
cleanup_mirror() {
  [ -z "$mirror_tmp" ] || rm -f -- "$mirror_tmp"
}
trap cleanup_mirror 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15

old_umask="$(umask)"
umask 077
mirror_tmp="$(mktemp "$common_dir/.Xauthority.XXXXXXXX")" \
  || fail 'Could not create Firefox Xauthority staging file.'
umask "$old_umask"
cat -- "$XAUTHORITY" >"$mirror_tmp" \
  || fail 'Could not copy TigerVNC Xauthority.'
[ -s "$mirror_tmp" ] || fail 'Refusing an empty Xauthority snapshot.'
cmp -s -- "$XAUTHORITY" "$mirror_tmp" \
  || fail 'Xauthority changed or was copied incorrectly.'
chmod 0600 "$mirror_tmp" \
  || fail 'Could not protect Firefox Xauthority staging file.'
mv -fT -- "$mirror_tmp" "$destination" \
  || fail 'Could not atomically activate Firefox Xauthority.'
mirror_tmp=''
trap - 0 1 2 3 15

[ -f "$destination" ] && [ ! -L "$destination" ] \
  && [ "$(stat -c '%u' "$destination")" = "$uid" ] \
  && [ "$(stat -c '%a' "$destination")" = '600' ] \
  && cmp -s -- "$XAUTHORITY" "$destination" \
  || fail 'Activated Firefox Xauthority failed verification.'

unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS

runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if [ -S "$runtime_dir/bus" ]; then
  export XDG_RUNTIME_DIR="$runtime_dir"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
  exec startxfce4
fi

exec dbus-launch --exit-with-session startxfce4
EOF_XSTARTUP
    for vnc_dir in "$home/.vnc" "$home/.config/tigervnc"; do
        install_user_file "$GUI_USER" 700 "$xstartup_tmp" "$vnc_dir/xstartup"
    done
    rm -f "$xstartup_tmp"
}

map_vnc_display() {
    local users_file='/etc/tigervnc/vncserver.users'
    local mappings current_mapping tmp_file

    install -d -m 0755 /etc/tigervnc
    [ ! -L "$users_file" ] || die "Refusing symlinked VNC users file: $users_file"
    if [ -e "$users_file" ] && [ ! -f "$users_file" ]; then
        die "VNC users path is not a regular file: $users_file"
    fi
    touch "$users_file"
    chown root:root "$users_file"
    chmod 0644 "$users_file"

    mappings="$(awk -F= -v display=":$VNC_DISPLAY" '$1 == display {print $2}' "$users_file")"
    while IFS= read -r current_mapping; do
        [ -n "$current_mapping" ] || continue
        [ "$current_mapping" = "$GUI_USER" ] ||
            die "VNC display :$VNC_DISPLAY is already assigned to $current_mapping in $users_file"
    done <<<"$mappings"

    tmp_file="$(mktemp /etc/tigervnc/.vncserver.users.XXXXXXXX)"
    awk -F= -v display=":$VNC_DISPLAY" '$1 != display {print}' "$users_file" >"$tmp_file"
    printf ':%s=%s\n' "$VNC_DISPLAY" "$GUI_USER" >>"$tmp_file"
    chown root:root "$tmp_file"
    chmod 0644 "$tmp_file"
    mv -f "$tmp_file" "$users_file"
}

detect_vnc_config_format() {
    local defaults="$1"

    if grep -Eq '^[[:space:]]*#.*\$localhost[[:space:]]*=' "$defaults" &&
        grep -Eq '^[[:space:]]*#.*\$SecurityTypes[[:space:]]*=' "$defaults"; then
        VNC_CONFIG_FORMAT='perl'
    elif grep -Eiq '^[[:space:]]*#+[[:space:]]*localhost([[:space:]]|$)' "$defaults" &&
        grep -Eiq '^[[:space:]]*#+[[:space:]]*securitytypes[[:space:]]*=' "$defaults"; then
        VNC_CONFIG_FORMAT='simple'
    else
        die "Could not identify the packaged TigerVNC configuration syntax from $defaults; refusing to guess a mandatory security policy."
    fi
}

render_vnc_mandatory_policy() {
    case "$VNC_CONFIG_FORMAT" in
    perl)
        cat <<'EOF_VNC_MANDATORY_PERL'
# Managed by vm-bootstrap.sh. Local changes will be overwritten.
$localhost = "yes";
$SecurityTypes = "VncAuth";
$rfbport = "5901";
$nolisten = "tcp";
$AlwaysShared = "no";
$NeverShared = "yes";
$AcceptSetDesktopSize = "no";
$AllowOverride = "desktop,AcceptPointerEvents";
EOF_VNC_MANDATORY_PERL
        if [ "$GUI_CLIPBOARD" -eq 1 ]; then
            cat <<'EOF_VNC_MANDATORY_PERL_CLIPBOARD_ON'
$AcceptCutText = "yes";
$SendCutText = "yes";
$SendPrimary = "yes";
$SetPrimary = "yes";
EOF_VNC_MANDATORY_PERL_CLIPBOARD_ON
        else
            cat <<'EOF_VNC_MANDATORY_PERL_CLIPBOARD_OFF'
$AcceptCutText = "no";
$SendCutText = "no";
$SendPrimary = "no";
$SetPrimary = "no";
EOF_VNC_MANDATORY_PERL_CLIPBOARD_OFF
        fi
        printf '%s\n' '1;'
        ;;
    simple)
        cat <<'EOF_VNC_MANDATORY_SIMPLE'
# Managed by vm-bootstrap.sh. Local changes will be overwritten.
localhost
securitytypes=VncAuth
rfbport=5901
nolisten=tcp
alwaysshared=0
nevershared
acceptsetdesktopsize=0
allowoverride=desktop,AcceptPointerEvents
EOF_VNC_MANDATORY_SIMPLE
        if [ "$GUI_CLIPBOARD" -eq 1 ]; then
            printf '%s\n' \
                'noclipboard=0' 'acceptcuttext=1' 'sendcuttext=1' \
                'sendprimary=1' 'setprimary=1'
        else
            printf '%s\n' \
                'noclipboard' 'acceptcuttext=0' 'sendcuttext=0' \
                'sendprimary=0' 'setprimary=0'
        fi
        ;;
    *)
        die 'TigerVNC configuration syntax was not validated.'
        ;;
    esac
}

validate_vnc_system_config() {
    local defaults='/etc/tigervnc/vncserver-config-defaults'
    local mandatory='/etc/tigervnc/vncserver-config-mandatory'
    local config line active owner_uid mode first_line

    for config in "$defaults" "$mandatory"; do
        if [ ! -f "$config" ] || [ -L "$config" ]; then
            die "Refusing missing, non-regular, or symlinked TigerVNC system config: $config"
        fi
        owner_uid="$(stat -c '%u' "$config")"
        mode="$(stat -c '%a' "$config")"
        [ "$owner_uid" = '0' ] || die "TigerVNC system config is not root-owned: $config"
        (((8#$mode & 0022) == 0)) ||
            die "TigerVNC system config is group/world writable: $config"
    done

    detect_vnc_config_format "$defaults"

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        active="$(printf '%s' "$line" | trim_whitespace)"
        [ -n "$active" ] || continue
        case "$VNC_CONFIG_FORMAT:$active" in
        'perl:1;') ;;
        *) die "Active TigerVNC defaults are not allowed: $defaults" ;;
        esac
    done <"$defaults"

    IFS= read -r first_line <"$mandatory" || true
    if [ "$first_line" = '# Managed by vm-bootstrap.sh. Local changes will be overwritten.' ]; then
        return
    else
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            active="$(printf '%s' "$line" | trim_whitespace)"
            [ -n "$active" ] || continue
            case "$VNC_CONFIG_FORMAT:$active" in
            'perl:1;') ;;
            *) die "Active TigerVNC mandatory overrides are not allowed: $mandatory" ;;
            esac
        done <"$mandatory"
    fi
}

write_vnc_mandatory_policy() {
    local mandatory='/etc/tigervnc/vncserver-config-mandatory'
    local mandatory_tmp

    mandatory_tmp="$(mktemp /etc/tigervnc/.vncserver-config-mandatory.XXXXXXXX)"
    render_vnc_mandatory_policy >"$mandatory_tmp"
    chown root:root "$mandatory_tmp"
    chmod 0644 "$mandatory_tmp"
    if [ "$VNC_CONFIG_FORMAT" = 'perl' ]; then
        perl -c "$mandatory_tmp" >/dev/null 2>&1 ||
            die 'Generated TigerVNC mandatory policy is not valid Perl syntax.'
    fi
    mv -fT "$mandatory_tmp" "$mandatory"
}

vnc_port_listeners() {
    ss -H -ltnp "sport = :$VNC_PORT" 2>/dev/null
}

stop_disable_vnc_service() {
    local unit="tigervncserver@:$VNC_DISPLAY.service"
    local state listeners

    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "$unit"; then
        return 1
    fi
    state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    case "$state" in
    disabled | static | indirect | not-found | masked | masked-runtime) ;;
    *) return 1 ;;
    esac
    listeners="$(vnc_port_listeners)" || return 1
    [ -z "$listeners" ]
}

fail_vnc_closed() {
    local message="$1"

    if ! stop_disable_vnc_service; then
        die "CRITICAL: TigerVNC could not be proven stopped and disabled. Original failure: $message"
    fi
    die "$message"
}

cleanup_vnc_transaction() {
    local status=$?

    trap - EXIT HUP INT TERM
    if [ "$VNC_TX_ACTIVE" -eq 1 ]; then
        if stop_disable_vnc_service; then
            warn 'Interrupted or failed GUI validation; TigerVNC was stopped and disabled.'
        else
            warn 'CRITICAL: Interrupted or failed GUI validation and TigerVNC/port 5901 could not be proven closed.'
        fi
    fi
    exit "$status"
}

assert_vnc_loopback_only() {
    local listeners listener local_address
    local seen=0
    local ipv4_seen=0

    systemctl is-active --quiet "tigervncserver@:$VNC_DISPLAY.service" || return 1
    listeners="$(vnc_port_listeners)" || return 1
    while IFS= read -r listener; do
        IFS=' ' read -r _ _ _ local_address _ <<<"$listener"
        [ -n "$local_address" ] || continue
        seen=1
        case "$local_address" in
        127.0.0.1:"$VNC_PORT")
            ipv4_seen=1
            ;;
        '[::1]':"$VNC_PORT" | ::1:"$VNC_PORT")
            ;;
        *)
            fail_vnc_closed "Unsafe VNC listener detected at $local_address."
            ;;
        esac
    done <<<"$listeners"

    [ "$seen" -eq 1 ] && [ "$ipv4_seen" -eq 1 ] || return 1
}

vnc_runtime_value() {
    local parameter="$1"
    local home
    home="$(user_home "$GUI_USER")"
    runuser -u "$GUI_USER" -- \
        env DISPLAY=":$VNC_DISPLAY" XAUTHORITY="$home/.Xauthority" \
        tigervncconfig -get "$parameter" 2>/dev/null
}

vnc_runtime_bool() {
    local parameter="$1" value
    value="$(vnc_runtime_value "$parameter")" || return 1
    case "${value,,}" in
    1 | on | yes | true) printf '%s\n' 1 ;;
    0 | off | no | false) printf '%s\n' 0 ;;
    *) return 1 ;;
    esac
}

vnc_server_args() {
    local pid args
    local pids=()

    mapfile -t pids < <(pgrep -u "$GUI_USER" -x Xtigervnc || true)
    for pid in "${pids[@]}"; do
        args="$(ps -ww -p "$pid" -o args=)"
        case " $args " in
        *" :$VNC_DISPLAY "*)
            printf '%s\n' "$args"
            return 0
            ;;
        esac
    done
    return 1
}

assert_vnc_runtime_policy() {
    local home runtime_password expected_uid password_uid password_mode args
    local geometry expected_geometry

    home="$(user_home "$GUI_USER")"
    runtime_password="$(vnc_runtime_value 'PasswordFile')" || return 1
    [[ "$runtime_password" = /* ]] || return 1
    if [ ! -f "$runtime_password" ] || [ -L "$runtime_password" ]; then
        return 1
    fi
    expected_uid="$(user_uid "$GUI_USER")"
    password_uid="$(stat -c '%u' "$runtime_password")"
    password_mode="$(stat -c '%a' "$runtime_password")"
    [ "$password_uid" = "$expected_uid" ] || return 1
    [ "$password_mode" = '600' ] || return 1
    if [ ! -f "$home/.vnc/passwd" ] || [ -L "$home/.vnc/passwd" ]; then
        return 1
    fi
    [ "$(stat -c '%u' "$home/.vnc/passwd")" = "$expected_uid" ] || return 1
    [ "$(stat -c '%a' "$home/.vnc/passwd")" = '600' ] || return 1
    cmp -s -- "$runtime_password" "$home/.vnc/passwd" || return 1

    [ "$(vnc_runtime_value 'SecurityTypes')" = 'VncAuth' ] || return 1
    [ "$(vnc_runtime_bool 'localhost')" = '1' ] || return 1
    [ "$(vnc_runtime_value 'rfbport')" = "$VNC_PORT" ] || return 1
    [ "$(vnc_runtime_bool 'AlwaysShared')" = '0' ] || return 1
    [ "$(vnc_runtime_bool 'NeverShared')" = '1' ] || return 1
    [ "$(vnc_runtime_bool 'AcceptSetDesktopSize')" = '0' ] || return 1
    [ "$(vnc_runtime_value 'AllowOverride')" = 'desktop,AcceptPointerEvents' ] || return 1

    geometry="$(runuser -u "$GUI_USER" -- \
        env DISPLAY=":$VNC_DISPLAY" XAUTHORITY="$home/.Xauthority" \
        xdotool getdisplaygeometry 2>/dev/null)" || return 1
    expected_geometry="${GUI_GEOMETRY/x/ }"
    [ "$geometry" = "$expected_geometry" ] || return 1

    args="$(vnc_server_args)" || return 1
    case " ${args,,} " in
    *' -password '* | *' -password='*) return 1 ;;
    esac
    case " ${args,,} " in
    *' -nolisten tcp '* | *' -nolisten=tcp '*) ;;
    *) return 1 ;;
    esac

    if [ "$GUI_CLIPBOARD" -eq 0 ]; then
        [ "$(vnc_runtime_bool 'AcceptCutText')" = '0' ] || return 1
        [ "$(vnc_runtime_bool 'SendCutText')" = '0' ] || return 1
        [ "$(vnc_runtime_bool 'SendPrimary')" = '0' ] || return 1
        [ "$(vnc_runtime_bool 'SetPrimary')" = '0' ] || return 1
        case " ${args,,} " in
        *' -noclipboard 0 '* | *' -noclipboard=0 '* | *' -noclipboard=no '* | *' -noclipboard=false '*)
            return 1
            ;;
        *' -noclipboard '* | *' -noclipboard=1 '* | *' -noclipboard=yes '* | *' -noclipboard=true '*)
            ;;
        *) return 1 ;;
        esac
    else
        [ "$(vnc_runtime_bool 'AcceptCutText')" = '1' ] || return 1
        [ "$(vnc_runtime_bool 'SendCutText')" = '1' ] || return 1
        [ "$(vnc_runtime_bool 'SendPrimary')" = '1' ] || return 1
        [ "$(vnc_runtime_bool 'SetPrimary')" = '1' ] || return 1
        case " ${args,,} " in
        *' -noclipboard 0 '* | *' -noclipboard=0 '* | *' -noclipboard=no '* | *' -noclipboard=false '*)
            ;;
        *' -noclipboard '* | *' -noclipboard='*) return 1 ;;
        esac
    fi
}

assert_firefox_snap_xauthority_bridge() {
    local home expected_uid source destination directory

    home="$(user_home "$GUI_USER")"
    expected_uid="$(user_uid "$GUI_USER")"
    source="$home/.Xauthority"
    destination="$home/snap/firefox/common/.Xauthority"

    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ "$(stat -c '%u' "$source")" = "$expected_uid" ] || return 1
    [ "$(stat -c '%a' "$source")" = '600' ] || return 1
    [ -s "$source" ] || return 1

    for directory in "$home/snap" "$home/snap/firefox" "$home/snap/firefox/common"; do
        [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
        [ "$(stat -c '%u' "$directory")" = "$expected_uid" ] || return 1
        [ "$(stat -c '%a' "$directory")" = '700' ] || return 1
    done

    [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
    [ "$(stat -c '%u' "$destination")" = "$expected_uid" ] || return 1
    [ "$(stat -c '%a' "$destination")" = '600' ] || return 1
    cmp -s -- "$source" "$destination"
}

assert_gui_session_ready() {
    local process home session_pid
    home="$(user_home "$GUI_USER")"

    for process in xfce4-session xfwm4 xfce4-panel xfdesktop; do
        pgrep -u "$GUI_USER" -x "$process" >/dev/null || return 1
    done

    session_pid="$(pgrep -o -u "$GUI_USER" -x xfce4-session)" || return 1
    [ -n "$session_pid" ] || return 1
    tr '\0' '\n' <"/proc/$session_pid/environ" |
        grep -Fqx "XAUTHORITY=$home/.Xauthority" || return 1
    assert_firefox_snap_xauthority_bridge || return 1

    runuser -u "$GUI_USER" -- \
        env DISPLAY=":$VNC_DISPLAY" XAUTHORITY="$home/.Xauthority" \
        xset q >/dev/null 2>&1
}

configure_gui() {
    local home unit primary_config
    local attempt
    local listener_ready=0

    unit="tigervncserver@:$VNC_DISPLAY.service"
    systemctl cat 'tigervncserver@.service' >/dev/null 2>&1 ||
        die 'Packaged tigervncserver@.service was not found.'
    if ! stop_disable_vnc_service; then
        die 'CRITICAL: Existing TigerVNC service could not be proven stopped and disabled before validation.'
    fi
    validate_vnc_system_config
    write_vnc_mandatory_policy

    ensure_gui_user
    home="$(user_home "$GUI_USER")"
    validate_user_home "$GUI_USER" "$home"
    if [ -e "$home/.config" ] && { [ -L "$home/.config" ] || [ ! -d "$home/.config" ]; }; then
        die "Unsafe GUI config directory: $home/.config"
    fi
    ensure_user_directory "$GUI_USER" "$home/.config"
    [ ! -L "$home/.vnc" ] || die "Refusing symlinked VNC directory: $home/.vnc"
    [ ! -L "$home/.config/tigervnc" ] || die "Refusing symlinked VNC directory: $home/.config/tigervnc"
    for primary_config in \
        "$home/.vnc/tigervnc.conf" \
        "$home/.config/tigervnc/config.pl"; do
        [ ! -e "$primary_config" ] ||
            die "Existing TigerVNC config would override managed settings: $primary_config"
    done

    [ -f /usr/share/xsessions/xfce.desktop ] || die 'XFCE session file was not installed.'

    write_vnc_password "$home"
    write_vnc_config "$home"
    map_vnc_display

    VNC_TX_ACTIVE=1
    trap 'cleanup_vnc_transaction' EXIT
    trap 'exit 130' HUP INT TERM

    log "Starting TigerVNC display :$VNC_DISPLAY for $GUI_USER."
    systemctl daemon-reload
    if ! systemctl restart "$unit"; then
        systemctl status "$unit" --no-pager >&2 || true
        fail_vnc_closed 'TigerVNC failed to start.'
    fi

    for ((attempt = 1; attempt <= 10; attempt++)); do
        if assert_vnc_loopback_only; then
            listener_ready=1
            break
        fi
        sleep 1
    done

    if [ "$listener_ready" -ne 1 ]; then
        systemctl status "$unit" --no-pager >&2 || true
        fail_vnc_closed "TigerVNC did not open loopback port $VNC_PORT."
    fi
    log "TigerVNC is listening only on loopback port $VNC_PORT."

    if ! assert_vnc_runtime_policy; then
        fail_vnc_closed 'TigerVNC runtime policy does not match VncAuth/loopback/fixed-geometry/clipboard requirements.'
    fi
    log 'TigerVNC runtime authentication, fixed geometry, and clipboard policy are verified.'

    for ((attempt = 1; attempt <= 15; attempt++)); do
        if assert_gui_session_ready; then
            if ! systemctl enable "$unit" >/dev/null; then
                fail_vnc_closed 'Could not enable the validated VNC service.'
            fi
            VNC_TX_ACTIVE=0
            trap - EXIT HUP INT TERM
            log 'XFCE session, window manager, panel, and desktop are responsive.'
            return
        fi
        sleep 1
    done

    systemctl status "$unit" --no-pager >&2 || true
    fail_vnc_closed 'XFCE did not become fully ready.'
}

write_sshd_dropin() {
    local output_file="$1"

    {
        cat <<'EOF_SSHD'
# Managed by vm-bootstrap.sh. Local changes will be overwritten.
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
StrictModes yes
X11Forwarding no
AllowAgentForwarding no
DisableForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
LoginGraceTime 30
MaxAuthTries 6
MaxSessions 4
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
EOF_SSHD

        if [ "$MODE" = 'ssh-gui' ]; then
            printf '%s\n' \
                "DenyUsers $GUI_USER" \
                'AllowTcpForwarding local' \
                "PermitOpen 127.0.0.1:$VNC_PORT"
        else
            printf '%s\n' \
                'AllowTcpForwarding no' \
                'PermitOpen none'
        fi
    } >"$output_file"
}

verify_hardened_sshd() {
    local config="$1"

    assert_effective_value "$config" 'pubkeyauthentication' 'yes' || return 1
    assert_effective_value "$config" 'authenticationmethods' 'publickey' || return 1
    assert_effective_value "$config" 'passwordauthentication' 'no' || return 1
    assert_effective_value "$config" 'kbdinteractiveauthentication' 'no' || return 1
    assert_effective_value "$config" 'permitemptypasswords' 'no' || return 1
    assert_effective_value "$config" 'permitrootlogin' 'no' || return 1
    assert_effective_value "$config" 'strictmodes' 'yes' || return 1
    assert_effective_value "$config" 'x11forwarding' 'no' || return 1
    assert_effective_value "$config" 'allowagentforwarding' 'no' || return 1
    assert_effective_value "$config" 'disableforwarding' 'no' || return 1
    assert_effective_value "$config" 'allowstreamlocalforwarding' 'no' || return 1
    assert_effective_value "$config" 'gatewayports' 'no' || return 1
    assert_effective_value "$config" 'permittunnel' 'no' || return 1
    assert_effective_value "$config" 'permituserrc' 'no' || return 1
    assert_effective_value "$config" 'permituserenvironment' 'no' || return 1

    if [ "$MODE" = 'ssh-gui' ]; then
        if ! printf '%s\n' "$config" |
            awk -v expected="$GUI_USER" '$1 == "denyusers" {for (i=2; i<=NF; i++) if ($i == expected) found=1} END {exit(found ? 0 : 1)}'; then
            printf 'Expected sshd DenyUsers to contain %s.\n' "$GUI_USER" >&2
            return 1
        fi
        assert_effective_value "$config" 'allowtcpforwarding' 'local' || return 1
        assert_single_effective_token "$config" 'permitopen' "127.0.0.1:$VNC_PORT" || return 1
    else
        assert_effective_value "$config" 'allowtcpforwarding' 'no' || return 1
        assert_single_effective_token "$config" 'permitopen' 'none' || return 1
    fi
}

detect_ssh_service() {
    if systemctl cat ssh.service >/dev/null 2>&1; then
        printf 'ssh.service\n'
    elif systemctl cat sshd.service >/dev/null 2>&1; then
        printf 'sshd.service\n'
    else
        return 1
    fi
}

trim_whitespace() {
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

validate_ssh_defaults_file() {
    local defaults='/etc/default/ssh'
    local line active value owner_uid mode

    [ -e "$defaults" ] || return 0
    if [ ! -f "$defaults" ] || [ -L "$defaults" ]; then
        die "Refusing unsafe SSH defaults file: $defaults"
    fi
    owner_uid="$(stat -c '%u' "$defaults")"
    mode="$(stat -c '%a' "$defaults")"
    [ "$owner_uid" = '0' ] || die "SSH defaults file is not root-owned: $defaults"
    (((8#$mode & 0022) == 0)) ||
        die "SSH defaults file is group/world writable: $defaults"

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        active="$(printf '%s' "$line" | trim_whitespace)"
        [ -n "$active" ] || continue
        if [[ "$active" =~ ^SSHD_OPTS[[:space:]]*=(.*)$ ]]; then
            value="$(printf '%s' "${BASH_REMATCH[1]}" | trim_whitespace)"
            case "$value" in
            '' | '""' | "''") ;;
            *) die 'Non-empty SSHD_OPTS in /etc/default/ssh can override the validated sshd configuration.' ;;
            esac
        elif [[ "${active^^}" == *SSHD_OPTS* ]]; then
            die 'Unsupported SSHD_OPTS syntax in /etc/default/ssh.'
        fi
    done <"$defaults"
}

validate_vendor_systemd_file() {
    local file="$1"
    local owner_uid mode

    case "$file" in
    /usr/lib/systemd/system/* | /lib/systemd/system/*) ;;
    *) die "Refusing non-vendor systemd file: ${file:-missing}" ;;
    esac
    if [ ! -f "$file" ] || [ -L "$file" ]; then
        die "Refusing missing, non-regular, or symlinked systemd file: $file"
    fi
    owner_uid="$(stat -c '%u' "$file")"
    mode="$(stat -c '%a' "$file")"
    [ "$owner_uid" = '0' ] || die "Systemd file is not root-owned: $file"
    (((8#$mode & 0022) == 0)) ||
        die "Systemd file is group/world writable: $file"
}

validate_ssh_service_invocation() {
    local service="$1"
    local fragment dropins exec_start unit_environment exec_path argv
    local ec2_dropin=0

    fragment="$(systemctl show "$service" -p FragmentPath --value)"
    case "$fragment" in
    /usr/lib/systemd/system/ssh.service | /lib/systemd/system/ssh.service | \
        /usr/lib/systemd/system/sshd.service | /lib/systemd/system/sshd.service)
        ;;
    *) die "Refusing non-vendor SSH service fragment: ${fragment:-missing}" ;;
    esac
    validate_vendor_systemd_file "$fragment"

    dropins="$(systemctl show "$service" -p DropInPaths --value)"
    case "$dropins" in
    '') ;;
    /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf | \
        /lib/systemd/system/ssh.service.d/ec2-instance-connect.conf)
        ec2_dropin=1
        validate_vendor_systemd_file "$dropins"
        ;;
    *)
        die "Refusing unknown SSH systemd drop-in set: $dropins"
        ;;
    esac

    unit_environment="$(systemctl show "$service" -p Environment --value)"
    case "$unit_environment" in
    *SSHD_OPTS=*) die 'Refusing SSHD_OPTS supplied by a systemd Environment directive.' ;;
    esac

    exec_start="$(systemctl show "$service" -p ExecStart --value)"
    exec_path="$(printf '%s\n' "$exec_start" | sed -n 's/^{ path=\([^ ]*\) ;.*$/\1/p')"
    argv="$(printf '%s\n' "$exec_start" | sed -n 's/^.* ; argv\[\]=\(.*\) ; ignore_errors=.*$/\1/p')"
    [ "$exec_path" = '/usr/sbin/sshd' ] || die 'SSH service does not execute exactly /usr/sbin/sshd.'
    [ -n "$argv" ] || die 'Could not parse the SSH service ExecStart arguments.'

    # these allowlisted systemd argv strings intentionally contain a literal variable token.
    # shellcheck disable=SC2016
    case "$argv" in
    '/usr/sbin/sshd -D $SSHD_OPTS' | '/usr/sbin/sshd -D')
        [ "$ec2_dropin" -eq 0 ] || die 'The EC2 SSH drop-in is present but not reflected in ExecStart.'
        ;;
    '/usr/sbin/sshd -D -o AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f -o AuthorizedKeysCommandUser ec2-instance-connect $SSHD_OPTS' | \
        '/usr/sbin/sshd -D -o AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f -o AuthorizedKeysCommandUser ec2-instance-connect')
        [ "$ec2_dropin" -eq 1 ] || die 'EC2 Instance Connect arguments lack the packaged vendor drop-in.'
        ;;
    *)
        die "Refusing unsupported SSH service ExecStart arguments: $argv"
        ;;
    esac

    validate_ssh_defaults_file
}

validate_active_sshd_process() {
    local service="$1"
    local pid executable cmdline dropins

    pid="$(systemctl show "$service" -p MainPID --value)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || return 1
    [ "$executable" = '/usr/sbin/sshd' ] || return 1
    [ "$(awk '/^Uid:/ {print $2}' "/proc/$pid/status")" = '0' ] || return 1
    cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline")" || return 1
    cmdline="${cmdline% }"
    dropins="$(systemctl show "$service" -p DropInPaths --value)"

    case "$dropins" in
    '')
        case "$cmdline" in
        'sshd: /usr/sbin/sshd -D [listener] '*) ;;
        *) return 1 ;;
        esac
        ;;
    /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf | \
        /lib/systemd/system/ssh.service.d/ec2-instance-connect.conf)
        case "$cmdline" in
        'sshd: /usr/sbin/sshd -D -o AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f -o AuthorizedKeysCommandUser ec2-instance-connect [listener] '*) ;;
        *) return 1 ;;
        esac
        ;;
    *) return 1 ;;
    esac
}

probe_live_sshd_authentication() {
    local effective port output methods

    effective="$(sshd_effective_config)" || return 1
    port="$(printf '%s\n' "$effective" | awk '$1 == "port" {print $2; exit}')"
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    output="$(LC_ALL=C timeout 5 ssh -vv -4 -F none -S none -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o IdentityFile=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=3 -p "$port" "$TARGET_USER@127.0.0.1" true 2>&1 || true)"
    methods="$(printf '%s\n' "$output" |
        sed -n 's/^debug1: Authentications that can continue: //p' |
        tr -d '\r' |
        sort -u)"
    [ "$methods" = 'publickey' ]
}

wait_for_active_sshd_process() {
    local service="$1"
    local attempt

    for ((attempt = 1; attempt <= 10; attempt++)); do
        sleep 1
        if systemctl is-active --quiet "$service" && validate_active_sshd_process "$service"; then
            return 0
        fi
    done
    return 1
}

wait_for_live_sshd_policy() {
    local service="$1"
    local attempt

    for ((attempt = 1; attempt <= 10; attempt++)); do
        sleep 1
        if systemctl is-active --quiet "$service" &&
            validate_active_sshd_process "$service" &&
            probe_live_sshd_authentication; then
            sleep 1
            if systemctl is-active --quiet "$service" &&
                validate_active_sshd_process "$service" &&
                probe_live_sshd_authentication; then
                return 0
            fi
        fi
    done
    return 1
}

reject_sshd_match_blocks() {
    local files=(/etc/ssh/sshd_config)
    local config_file line keyword include_path extra config_fd
    local standard_include_seen=0

    shopt -s nullglob
    files+=(/etc/ssh/sshd_config.d/*.conf)
    shopt -u nullglob

    for config_file in "${files[@]}"; do
        [ -r "$config_file" ] || die "Cannot read SSH configuration file: $config_file"
        exec {config_fd}<"$config_file"
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            IFS=$' \t=' read -r keyword include_path extra <<<"$line"
            [ -n "${keyword:-}" ] || continue

            case "${keyword,,}" in
            match)
                die "Existing SSH Match block in $config_file makes global hardening ambiguous. Remove or review it first."
                ;;
            include)
                if [ "$config_file" != '/etc/ssh/sshd_config' ] ||
                    [ "${include_path:-}" != '/etc/ssh/sshd_config.d/*.conf' ] ||
                    [ -n "${extra:-}" ]; then
                    die "Unsupported or nested SSH Include in $config_file: ${include_path:-<missing>}"
                fi
                standard_include_seen=1
                ;;
            esac
        done <&"$config_fd"
        exec {config_fd}<&-
    done

    [ "$standard_include_seen" -eq 1 ] ||
        die 'The standard /etc/ssh/sshd_config.d/*.conf Include is missing from sshd_config.'
}

restore_sshd_dropin() {
    local backup_file="$1"
    local had_previous="$2"
    local restore_tmp

    if [ "$had_previous" -eq 1 ]; then
        restore_tmp="$(mktemp /etc/ssh/sshd_config.d/.vm-bootstrap.restore.XXXXXXXX)" || return 1
        if ! cp -a "$backup_file" "$restore_tmp"; then
            rm -f "$restore_tmp"
            return 1
        fi
        if ! mv -fT "$restore_tmp" "$SSHD_DROPIN"; then
            rm -f "$restore_tmp"
            return 1
        fi
    else
        rm -f "$SSHD_DROPIN" || return 1
    fi
}

rollback_sshd_transaction() {
    local failed=0
    local config_restored=0
    local unit

    [ "$SSHD_TX_ACTIVE" -eq 1 ] || return 0

    if restore_sshd_dropin "$SSHD_TX_BACKUP" "$SSHD_TX_HAD_PREVIOUS"; then
        if sshd -t; then
            config_restored=1
        else
            warn 'The previous SSH configuration was restored on disk but failed sshd -t.'
            failed=1
        fi
    else
        warn 'Could not restore the previous SSH drop-in on disk.'
        failed=1
    fi

    if [ "$SSH_SERVER_INSTALLED_BY_BOOTSTRAP" -eq 1 ]; then
        for unit in "$SSHD_TX_SERVICE" ssh.socket; do
            if ! systemctl disable --now "$unit" >/dev/null 2>&1; then
                warn "Could not stop and disable $unit during SSH rollback."
                failed=1
            fi
        done
        for unit in "$SSHD_TX_SERVICE" ssh.socket; do
            if ! systemctl mask "$unit" >/dev/null 2>&1; then
                warn "Could not mask $unit during fresh-install SSH rollback."
                failed=1
            fi
        done
    elif [ "$SSHD_TX_SERVICE_WAS_ACTIVE" -eq 1 ] && [ "$SSHD_TX_RELOADED" -eq 1 ]; then
        if [ "$config_restored" -eq 1 ]; then
            if systemctl is-active --quiet "$SSHD_TX_SERVICE"; then
                if ! systemctl kill --kill-who=main --signal=HUP "$SSHD_TX_SERVICE"; then
                    warn 'Could not signal the original SSH daemon during rollback.'
                    failed=1
                fi
            else
                if ! systemctl start "$SSHD_TX_SERVICE"; then
                    warn 'Could not restore the originally active SSH service state.'
                    failed=1
                fi
            fi
            if ! wait_for_active_sshd_process "$SSHD_TX_SERVICE"; then
                warn 'The restored SSH service did not settle on the expected sshd process.'
                failed=1
            fi
        fi
    elif [ "$SSHD_TX_SERVICE_WAS_ACTIVE" -eq 0 ]; then
        if [ "$SSHD_TX_SERVICE_START_ATTEMPTED" -eq 1 ]; then
            if ! systemctl stop "$SSHD_TX_SERVICE" >/dev/null 2>&1; then
                warn 'Could not stop the SSH service that was started by this transaction.'
                failed=1
            fi
        fi
        if [ "$SSHD_TX_SERVICE_ENABLE_CHANGED" -eq 1 ]; then
            if ! systemctl disable "$SSHD_TX_SERVICE" >/dev/null 2>&1; then
                warn 'Could not restore the previous disabled SSH service state.'
                failed=1
            fi
        fi
    fi

    SSHD_TX_ACTIVE=0
    if [ "$failed" -ne 0 ]; then
        warn 'CRITICAL: SSH rollback was incomplete. Keep console access and repair SSH before rebooting.'
        return 1
    fi
    warn 'SSH rollback completed; the previous on-disk and service state was restored.'
}

cleanup_sshd_transaction() {
    local rollback_failed=0

    if ! rollback_sshd_transaction; then
        rollback_failed=1
        warn 'SSH transaction cleanup requires console intervention.'
    fi
    if [ "$rollback_failed" -eq 1 ]; then
        warn "Recovery files were retained. Backup: ${SSHD_TX_BACKUP:-none}; temporary config: ${SSHD_TX_TEMP:-none}"
        return 0
    fi
    if [ -n "$SSHD_TX_TEMP" ]; then
        rm -f "$SSHD_TX_TEMP" || warn "Could not remove temporary file: $SSHD_TX_TEMP"
    fi
    if [ -n "$SSHD_TX_BACKUP" ]; then
        rm -f "$SSHD_TX_BACKUP" || warn "Could not remove temporary file: $SSHD_TX_BACKUP"
    fi
    return 0
}

configure_sshd() {
    local config_tmp backup_file service effective
    local had_previous=0
    local first_line=''
    local service_was_active=0

    service="$(detect_ssh_service)" || die 'Could not find ssh.service or sshd.service.'
    install -d -m 0755 /etc/ssh/sshd_config.d
    validate_ssh_service_invocation "$service"
    if systemctl is-active --quiet "$service"; then
        service_was_active=1
        validate_active_sshd_process "$service" ||
            die 'The active SSH service main process is not the expected root-owned /usr/sbin/sshd.'
    fi
    reject_sshd_match_blocks

    config_tmp="$(mktemp /etc/ssh/sshd_config.d/.vm-bootstrap.new.XXXXXXXX)"
    backup_file="$(mktemp /etc/ssh/sshd_config.d/.vm-bootstrap.backup.XXXXXXXX)"
    if [ -e "$SSHD_DROPIN" ]; then
        if [ ! -f "$SSHD_DROPIN" ] || [ -L "$SSHD_DROPIN" ]; then
            die "Refusing unsafe managed SSH path: $SSHD_DROPIN"
        fi
        IFS= read -r first_line <"$SSHD_DROPIN" || true
        [ "$first_line" = '# Managed by vm-bootstrap.sh. Local changes will be overwritten.' ] ||
            die "Refusing to overwrite an unmanaged file: $SSHD_DROPIN"
        cp -a "$SSHD_DROPIN" "$backup_file"
        had_previous=1
    fi

    write_sshd_dropin "$config_tmp"
    chown root:root "$config_tmp"
    chmod 0600 "$config_tmp"

    SSHD_TX_ACTIVE=1
    SSHD_TX_BACKUP="$backup_file"
    SSHD_TX_HAD_PREVIOUS="$had_previous"
    SSHD_TX_TEMP="$config_tmp"
    SSHD_TX_SERVICE="$service"
    SSHD_TX_RELOADED=0
    SSHD_TX_SERVICE_WAS_ACTIVE="$service_was_active"
    SSHD_TX_SERVICE_ENABLE_CHANGED=0
    SSHD_TX_SERVICE_START_ATTEMPTED=0
    trap 'cleanup_sshd_transaction' EXIT
    trap 'exit 130' HUP INT TERM

    mv -fT "$config_tmp" "$SSHD_DROPIN"
    SSHD_TX_TEMP=''

    if ! sshd -t; then
        die 'sshd syntax validation failed; rollback will be attempted.'
    fi

    if ! effective="$(sshd_effective_config)"; then
        die 'Could not read effective sshd values; rollback will be attempted.'
    fi
    if ! verify_hardened_sshd "$effective"; then
        die 'Effective sshd values are not hardened. A preceding distro configuration probably overrides the managed drop-in; nothing was reloaded.'
    fi

    log "Applying the validated SSH configuration to $service."
    if [ "$service_was_active" -eq 1 ]; then
        SSHD_TX_RELOADED=1
        if ! systemctl kill --kill-who=main --signal=HUP "$service"; then
            die 'Could not signal sshd to reload; rollback will be attempted.'
        fi
    else
        if ! systemctl is-enabled --quiet "$service"; then
            SSHD_TX_SERVICE_ENABLE_CHANGED=1
            if ! systemctl enable "$service"; then
                die 'Could not enable the SSH service; rollback will be attempted.'
            fi
        fi
        SSHD_TX_SERVICE_START_ATTEMPTED=1
        if ! systemctl start "$service"; then
            die 'SSH service failed to start; rollback will be attempted.'
        fi
    fi

    if ! wait_for_live_sshd_policy "$service"; then
        die "$service did not settle or a fresh loopback connection offered methods other than exactly publickey; rollback will be attempted."
    fi
    log 'The active sshd process and a fresh publickey-only SSH connection are verified.'

    SSHD_TX_ACTIVE=0
    rm -f "$backup_file" || warn "Could not remove temporary file: $backup_file"
    SSHD_TX_BACKUP=''
    SSHD_TX_RELOADED=0
    SSHD_TX_SERVICE_WAS_ACTIVE=0
    SSHD_TX_SERVICE_ENABLE_CHANGED=0
    SSHD_TX_SERVICE_START_ATTEMPTED=0
    trap - EXIT HUP INT TERM
}

print_summary() {
    log "Completed mode: $MODE"
    printf '%s\n' \
        "SSH user:        $TARGET_USER" \
        "Public key:      $PUBLIC_KEY_FINGERPRINT"

    if [ "$MODE" = 'key-only' ]; then
        cat <<'EOF_KEY_ONLY'

SSH policy was not changed. From a second terminal, test the matching private key:
  ssh -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -i PRIVATE_KEY USER@VM true

After that succeeds, run this script again in ssh or ssh-gui mode.
EOF_KEY_ONLY
    else
        printf '%s\n' \
            'SSH authentication: public key only' \
            'SSH root login:     disabled' \
            'SSH agent/X11:      disabled'
    fi

    if [ "$MODE" = 'ssh-gui' ]; then
        cat <<EOF_GUI
GUI user:         $GUI_USER
VNC endpoint:     127.0.0.1:$VNC_PORT (not publicly reachable)
VNC password:     stored root-only in $VNC_SECRET_FILE
VNC clipboard:    $([ "$GUI_CLIPBOARD" -eq 1 ] && printf 'enabled' || printf 'disabled')
Firefox:          not installed and not downloaded

Reveal or rotate the VNC password only from the operator workstation through
the pinned, audited Dynamicflow command:
  flow instance secret reveal NAME --secret vnc
  flow instance secret rotate NAME --secret vnc

Open the tunnel on your workstation:
  ssh -NT -F none -S none \\
    -o ExitOnForwardFailure=yes -o ForwardAgent=no -o ForwardX11=no \\
    -o IdentitiesOnly=yes -o IdentityAgent=none \\
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no \\
    -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \\
    -o GlobalKnownHostsFile=none -o UserKnownHostsFile=PINNED_KNOWN_HOSTS \\
    -i PRIVATE_KEY \\
    -L 127.0.0.1:$VNC_PORT:127.0.0.1:$VNC_PORT $TARGET_USER@VM-IP

Then connect a VNC viewer to 127.0.0.1::$VNC_PORT.
EOF_GUI
    fi

    warn 'Keep the current console/SSH session open until a fresh key-only login works. The public key is useful only if you possess its matching private key.'
}

main() {
    parse_args "$@"
    require_root
    require_supported_os
    validate_inputs
    preflight_key_only_ssh_server
    acquire_lock

    if [ "$MODE" != 'key-only' ]; then
        require_systemd
    fi

    prepare_apt
    install_ssh_client
    validate_public_key
    install_public_key "$TARGET_USER"
    validate_login_shell "$TARGET_USER"
    install_ssh_server
    verify_authorized_keys_location

    if [ "$MODE" != 'key-only' ]; then
        configure_sshd
    fi

    if [ "$MODE" = 'ssh-gui' ]; then
        install_gui_packages
        configure_gui
    fi

    print_summary
}

main "$@"
