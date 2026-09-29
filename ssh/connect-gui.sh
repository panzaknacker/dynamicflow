#!/usr/bin/env bash
set -Eeuo pipefail

PATH='/usr/bin:/bin'
export PATH

LOCAL_PORT='5901'
SSH_PORT='22'
SSH_BIN='/usr/bin/ssh'
IDENTITY_FILE=''
IDENTITY_DEFAULT="${VM_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic}"
KNOWN_HOSTS_FILE=''
TARGET=''

usage() {
    cat <<'EOF_USAGE'
Usage:
  connect-gui.sh [options] USER@HOST

Options:
  --identity FILE    Explicit SSH private key (skips the picker).
  --identity-default FILE_OR_DIR
                     Picker location. Default: ~/.ssh/dynamic.
  --known-hosts FILE Pinned known_hosts file (required).
  --ssh-port PORT    SSH port. Default: 22.
  --local-port PORT  Local VNC port. Default: 5901.
  -h, --help         Show this help.

The VM-side destination is fixed to 127.0.0.1:5901 to match vm-bootstrap.sh.
EOF_USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((1 <= 10#$1 && 10#$1 <= 65535))
}

absolute_path_without_symlinks() {
    local value="$1"

    [ -n "$value" ] || die 'File path must not be empty.'
    case "$value" in
    '~') value="$HOME" ;;
    '~/'*) value="$HOME/${value#\~/}" ;;
    esac
    if [[ "$value" != /* ]]; then
        value="$PWD/$value"
    fi
    command -v realpath >/dev/null 2>&1 || die 'realpath is required for safe file validation.'
    realpath -m -s -- "$value" ||
        die "File path cannot be normalized safely: $1"
}

validate_safe_ancestors() {
    local path="$1" current metadata owner mode numeric_mode

    current="${path%/*}"
    [ -n "$current" ] || current='/'
    while true; do
        [ ! -L "$current" ] || die "Path contains a symlinked directory: $current"
        [ -d "$current" ] || die "Path ancestor is not a directory: $current"
        metadata="$(stat -c '%u %a' -- "$current")" ||
            die "Path ancestor cannot be inspected: $current"
        read -r owner mode <<<"$metadata"
        [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] ||
            die "Path ancestor returned invalid metadata: $current"
        numeric_mode=$((8#$mode))
        if [ "$owner" != '0' ] && [ "$owner" != "$EUID" ]; then
            die "Path ancestor has an untrusted owner: $current"
        fi
        if ((numeric_mode & 0022)); then
            if [ "$owner" != '0' ] || ((! (numeric_mode & 01000))); then
                die "Path ancestor is group/world-writable: $current"
            fi
        fi
        [ "$current" = '/' ] && break
        current="${current%/*}"
        [ -n "$current" ] || current='/'
    done
}

validate_safe_file() {
    local raw_path="$1" label="$2" private="$3"
    local path metadata owner mode numeric_mode

    path="$(absolute_path_without_symlinks "$raw_path")"
    validate_safe_ancestors "$path"
    [ ! -L "$path" ] || die "$label must not be a symlink: $path"
    [ -f "$path" ] || die "$label is not a regular file: $path"
    [ -r "$path" ] || die "$label is not readable: $path"
    metadata="$(stat -c '%u %a' -- "$path")" ||
        die "$label cannot be inspected: $path"
    read -r owner mode <<<"$metadata"
    [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] ||
        die "$label returned invalid metadata: $path"
    [ "$owner" = "$EUID" ] || die "$label is not owned by the current user: $path"
    numeric_mode=$((8#$mode))
    if [ "$private" = 'yes' ]; then
        ((! (numeric_mode & 0077))) ||
            die "$label permits group/other access: $path"
    else
        ((! (numeric_mode & 0022))) ||
            die "$label is group/world-writable: $path"
    fi
    printf '%s' "$path"
}

validate_literal_ssh_path() {
    local path="$1" label="$2"

    [[ "$path" =~ ^/[-A-Za-z0-9._/@:+,=]+$ ]] ||
        die "$label path contains characters OpenSSH may reinterpret; use an absolute path without whitespace, %, $, quotes, or backslashes: $path"
}

select_private_key() {
    local location="$1"
    local choice index key_candidate
    local -a keys=()

    case "$location" in
    '~') location="$HOME" ;;
    '~/'*) location="$HOME/${location#\~/}" ;;
    esac
    if [ -f "$location" ] && [ ! -L "$location" ] && [ -r "$location" ]; then
        printf '%s' "$location"
        return 0
    fi
    [ -d "$location" ] && [ ! -L "$location" ] ||
        die "Private-key picker path is neither a safe file nor directory: $location"
    [ -r /dev/tty ] && [ -w /dev/tty ] ||
        die 'Interactive private-key selection needs /dev/tty. Pass --identity FILE for automation.'

    while IFS= read -r -d '' key_candidate; do
        case "${key_candidate##*/}" in
        *.pub | authorized_keys | authorized_keys.* | config | known_hosts | known_hosts.*) continue ;;
        esac
        keys+=("$key_candidate")
    done < <(
        find "$location" -mindepth 1 -maxdepth 1 -type f -print0 |
            sort -z
    )
    ((${#keys[@]} > 0)) || die "No regular private-key candidates found in: $location"

    printf 'Available SSH private keys in %s:\n' "$location" >/dev/tty
    index=1
    for key_candidate in "${keys[@]}"; do
        printf '  %d) %s\n' "$index" "${key_candidate##*/}" >/dev/tty
        index=$((index + 1))
    done
    while true; do
        printf 'Select SSH private key [1]: ' >/dev/tty
        IFS= read -r choice </dev/tty || die 'Private-key selection was cancelled.'
        choice="${choice:-1}"
        if [[ "$choice" =~ ^[0-9]+$ ]] &&
            ((10#$choice >= 1 && 10#$choice <= ${#keys[@]})); then
            printf '%s' "${keys[10#$choice - 1]}"
            return 0
        fi
        printf 'Choose a number from 1 to %d.\n' "${#keys[@]}" >/dev/tty
    done
}
while [ "$#" -gt 0 ]; do
    case "$1" in
    --identity)
        [ "$#" -ge 2 ] || die '--identity requires a value.'
        IDENTITY_FILE="$2"
        shift 2
        ;;
    --identity=*)
        IDENTITY_FILE="${1#*=}"
        shift
        ;;
    --identity-default)
        [ "$#" -ge 2 ] || die '--identity-default requires a value.'
        IDENTITY_DEFAULT="$2"
        shift 2
        ;;
    --identity-default=*)
        IDENTITY_DEFAULT="${1#*=}"
        shift
        ;;
    --known-hosts)
        [ "$#" -ge 2 ] || die '--known-hosts requires a value.'
        KNOWN_HOSTS_FILE="$2"
        shift 2
        ;;
    --known-hosts=*)
        KNOWN_HOSTS_FILE="${1#*=}"
        shift
        ;;
    --ssh-port)
        [ "$#" -ge 2 ] || die '--ssh-port requires a value.'
        SSH_PORT="$2"
        shift 2
        ;;
    --ssh-port=*)
        SSH_PORT="${1#*=}"
        shift
        ;;
    --local-port)
        [ "$#" -ge 2 ] || die '--local-port requires a value.'
        LOCAL_PORT="$2"
        shift 2
        ;;
    --local-port=*)
        LOCAL_PORT="${1#*=}"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    -*)
        die "Unknown option: $1"
        ;;
    *)
        [ -z "$TARGET" ] || die 'Pass exactly one USER@HOST target.'
        TARGET="$1"
        shift
        ;;
    esac
done

[ -n "$TARGET" ] || {
    usage >&2
    exit 2
}
valid_port "$SSH_PORT" || die "Invalid SSH port: $SSH_PORT"
valid_port "$LOCAL_PORT" || die "Invalid local port: $LOCAL_PORT"
if [ -z "$IDENTITY_FILE" ]; then
    IDENTITY_FILE="$(select_private_key "$IDENTITY_DEFAULT")"
fi
[ -n "$KNOWN_HOSTS_FILE" ] || die '--known-hosts is required.'
IDENTITY_FILE="$(validate_safe_file "$IDENTITY_FILE" 'Private key' yes)"
KNOWN_HOSTS_FILE="$(validate_safe_file "$KNOWN_HOSTS_FILE" 'known_hosts file' no)"
validate_literal_ssh_path "$IDENTITY_FILE" 'Private key'
validate_literal_ssh_path "$KNOWN_HOSTS_FILE" 'known_hosts file'
[ -x /usr/bin/ssh-keygen ] || die '/usr/bin/ssh-keygen is required.'
/usr/bin/ssh-keygen -l -f "$IDENTITY_FILE" </dev/null >/dev/null 2>&1 ||
    die "Private key is structurally invalid: $IDENTITY_FILE"

ssh_args=(
    -F none
    -S none
    -N
    -T
    -p "$SSH_PORT"
    -o ConnectTimeout=12
    -o ConnectionAttempts=1
    -o ExitOnForwardFailure=yes
    -o ForwardAgent=no
    -o ForwardX11=no
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o PreferredAuthentications=publickey
    -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no
    -o RequestTTY=no
    -o StrictHostKeyChecking=yes
    -o GlobalKnownHostsFile=none
    -o "UserKnownHostsFile=$KNOWN_HOSTS_FILE"
    -o UpdateHostKeys=no
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
    -o TCPKeepAlive=no
    -i "$IDENTITY_FILE"
    -L "127.0.0.1:$LOCAL_PORT:127.0.0.1:5901"
)

printf 'Opening the SSH tunnel. After SSH connects, point the VNC viewer at 127.0.0.1::%s\n' "$LOCAL_PORT"
exec "$SSH_BIN" "${ssh_args[@]}" -- "$TARGET"
