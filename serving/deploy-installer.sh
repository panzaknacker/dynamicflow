#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SSH_KEY_PICKER="$ROOT_DIR/lib/ssh-key-picker.sh"
SOURCE="$ROOT_DIR/install.sh"
SSH_HOST="${TOOLKIT_SSH_HOST:-${TOOLKIT_SERVER:-downloads.example.com}}"
SSH_PORT="${TOOLKIT_SSH_PORT:-22}"
DEPLOY_USER="${TOOLKIT_DEPLOY_USER:-download}"
DOWNLOAD_ROOT="${TOOLKIT_DOWNLOAD_ROOT:-/srv/downloads}"
PUBLIC_BASE_URL="${TOOLKIT_PUBLIC_BASE_URL:-https://downloads.example.com}"
IDENTITY="${TOOLKIT_SSH_IDENTITY:-}"
IDENTITY_DEFAULT="${TOOLKIT_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic}"
snapshot=''

[[ -f "$SSH_KEY_PICKER" && ! -L "$SSH_KEY_PICKER" ]] || {
    printf 'ERROR: Unsafe or missing SSH key picker: %s\n' "$SSH_KEY_PICKER" >&2
    exit 1
}
# shellcheck source=lib/ssh-key-picker.sh
source "$SSH_KEY_PICKER"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: deploy-installer.sh

Validates the sibling install.sh, deploys it through one SSH connection, and
then verifies the public HTTPS response byte-for-byte by SHA-256.

Environment:
  TOOLKIT_SSH_HOST         SSH host. Default: downloads.example.com
  TOOLKIT_SSH_PORT         SSH port. Default: 22
  TOOLKIT_DEPLOY_USER      SSH user. Default: download
  TOOLKIT_DOWNLOAD_ROOT    Remote root. Default: /srv/downloads
  TOOLKIT_PUBLIC_BASE_URL  Public HTTPS base. Default: https://downloads.example.com
  TOOLKIT_SSH_IDENTITY     Explicit private-key path (skips the picker)
  TOOLKIT_SSH_IDENTITY_DEFAULT
                           Picker file/directory. Default: ~/.ssh/dynamic
EOF
}

cleanup() {
    if [ -n "$snapshot" ]; then
        rm -f -- "$snapshot" || true
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

validate_configuration() {
    local port_number

    [[ "$SSH_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        die "SSH host must be a DNS name or IPv4 address: $SSH_HOST"
    [[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] ||
        die "Invalid deploy user: $DEPLOY_USER"

    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] ||
        die "SSH port must be an integer between 1 and 65535: $SSH_PORT"
    ((${#SSH_PORT} <= 5)) ||
        die "SSH port must be between 1 and 65535: $SSH_PORT"
    port_number=$((10#$SSH_PORT))
    ((port_number >= 1 && port_number <= 65535)) ||
        die "SSH port must be between 1 and 65535: $SSH_PORT"
    SSH_PORT="$port_number"

    [[ "$DOWNLOAD_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
        die "Download root must be a simple absolute path: $DOWNLOAD_ROOT"
    [[ "$DOWNLOAD_ROOT" != *'//'* ]] ||
        die "Download root must not contain empty path components: $DOWNLOAD_ROOT"
    while [[ "$DOWNLOAD_ROOT" == */ && "$DOWNLOAD_ROOT" != '/' ]]; do
        DOWNLOAD_ROOT="${DOWNLOAD_ROOT%/}"
    done
    [[ "$DOWNLOAD_ROOT" != '/' && "/${DOWNLOAD_ROOT#/}/" != *'/../'* &&
        "/${DOWNLOAD_ROOT#/}/" != *'/./'* ]] ||
        die "Unsafe download root: $DOWNLOAD_ROOT"

    PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
    [[ "$PUBLIC_BASE_URL" =~ ^https://[A-Za-z0-9][A-Za-z0-9.:-]*(/[A-Za-z0-9._~/-]*)?$ ]] ||
        die "Public base URL must be a simple HTTPS URL: $PUBLIC_BASE_URL"

    [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] && [ -r "$SOURCE" ] ||
        die "Installer source is missing or unsafe: $SOURCE"
    [ -n "$IDENTITY" ] || die 'SSH identity selection returned an empty path.'
    [ -f "$IDENTITY" ] && [ ! -L "$IDENTITY" ] && [ -r "$IDENTITY" ] ||
        die "SSH identity is missing or unreadable: $IDENTITY"
}

case "${1:-}" in
-h | --help)
    usage
    exit 0
    ;;
esac
[ "$#" -eq 0 ] || {
    usage >&2
    exit 2
}

for command_name in curl find grep install mktemp sed sha256sum sh sort ssh; do
    require_command "$command_name"
done
if [ -z "$IDENTITY" ]; then
    IDENTITY="$(toolkit_select_ssh_private_key "$IDENTITY_DEFAULT")"
fi
validate_configuration

snapshot="$(mktemp)"
install -m 0600 -- "$SOURCE" "$snapshot"
default_base_line='BASE_URL="${TOOLKIT_BASE_URL:-https://downloads.example.com}"'
configured_base_line="BASE_URL=\"\${TOOLKIT_BASE_URL:-${PUBLIC_BASE_URL}}\""
[[ "$(grep -cF "$default_base_line" "$snapshot")" -eq 1 ]] || die 'Installer default base URL marker is missing or ambiguous.'
default_base_match="$(grep -nFx "$default_base_line" "$snapshot")"
default_base_number="${default_base_match%%:*}"
[[ "$default_base_number" =~ ^[0-9]+$ ]] || die 'Installer default base URL marker has no valid line number.'
sed -i "${default_base_number}c\\${configured_base_line}" "$snapshot"
grep -Fqx "$configured_base_line" "$snapshot" || die 'Could not configure installer public base URL.'
[ -s "$snapshot" ] || die "Installer snapshot is empty: $SOURCE"
sh -n "$snapshot" || die "Local POSIX shell syntax validation failed: $SOURCE"

expected_line="$(sha256sum "$snapshot")"
expected_sha="${expected_line%% *}"
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] ||
    die 'Could not calculate the local installer SHA-256.'

printf -v remote_command '%s\n' \
    'set -eu' \
    "download_root='$DOWNLOAD_ROOT'" \
    "expected_sha='$expected_sha'" \
    'die() { printf "ERROR: %s\n" "$*" >&2; exit 1; }' \
    'for command_name in cat chmod mktemp mv rm sha256sum sh; do command -v "$command_name" >/dev/null 2>&1 || die "Missing remote command: $command_name"; done' \
    '[ -d "$download_root" ] && [ ! -L "$download_root" ] && [ -w "$download_root" ] || die "Download root is missing, symlinked, or unwritable: $download_root"' \
    'canonical_root="$(cd "$download_root" && pwd -P)" || die "Could not resolve download root: $download_root"' \
    '[ "$canonical_root" = "$download_root" ] || die "Download root is not canonical: $download_root -> $canonical_root"' \
    'destination="$download_root/install.sh"' \
    'if [ -e "$destination" ] || [ -L "$destination" ]; then [ -f "$destination" ] && [ ! -L "$destination" ] || die "Refusing unsafe installer destination: $destination"; fi' \
    'tmp=""' \
    'cleanup() { [ -z "${tmp:-}" ] || rm -f -- "$tmp"; }' \
    'trap cleanup 0' \
    'trap "exit 129" 1' \
    'trap "exit 130" 2' \
    'trap "exit 143" 15' \
    'tmp="$(mktemp "$download_root/.install.sh.XXXXXXXX")"' \
    '[ -f "$tmp" ] && [ ! -L "$tmp" ] || die "mktemp returned an unsafe path: $tmp"' \
    'cat >"$tmp" || die "Could not receive installer on stdin."' \
    '[ -s "$tmp" ] || die "Received an empty installer."' \
    'actual_line="$(sha256sum "$tmp")"' \
    'actual_sha="${actual_line%% *}"' \
    '[ "$actual_sha" = "$expected_sha" ] || die "Installer SHA-256 changed in transit: $actual_sha"' \
    'sh -n "$tmp" || die "Remote POSIX shell syntax validation failed."' \
    'chmod 0755 "$tmp"' \
    'mv -fT -- "$tmp" "$destination"' \
    'tmp=""' \
    'trap - 0 1 2 15' \
    'printf "Remote installer activated: %s\nSHA-256: %s\n" "$destination" "$expected_sha"'

ssh_args=(
    -T
    -p "$SSH_PORT"
    -o ClearAllForwardings=yes
    -o ForwardAgent=no
    -o KbdInteractiveAuthentication=no
    -o PasswordAuthentication=no
    -o PreferredAuthentications=publickey
    -o StrictHostKeyChecking=yes
)
ssh_args+=(-o IdentitiesOnly=yes -i "$IDENTITY")

printf 'Deploying %s to %s@%s:%s using one SSH connection.\n' \
    "$SOURCE" "$DEPLOY_USER" "$SSH_HOST" "$DOWNLOAD_ROOT/install.sh"
if ! ssh "${ssh_args[@]}" -- "${DEPLOY_USER}@${SSH_HOST}" "$remote_command" <"$snapshot"; then
    die 'SSH deployment failed; the public HTTPS endpoint was not checked.'
fi

verify_url="${PUBLIC_BASE_URL}/install.sh?sha256=${expected_sha}"
printf 'Verifying the deployed bytes through %s/install.sh.\n' "$PUBLIC_BASE_URL"
if ! fetched_line="$(
    curl \
        --disable \
        --fail \
        --silent \
        --show-error \
        --location \
        --proto '=https' \
        --proto-redir '=https' \
        --tlsv1.2 \
        --connect-timeout 10 \
        --max-time 60 \
        --retry 5 \
        --retry-delay 1 \
        --retry-all-errors \
        --header 'Accept-Encoding: identity' \
        --header 'Cache-Control: no-cache' \
        "$verify_url" | sha256sum
)"; then
    die 'The remote installer was activated, but its public HTTPS response could not be verified.'
fi

fetched_sha="${fetched_line%% *}"
[[ "$fetched_sha" =~ ^[0-9a-f]{64}$ ]] ||
    die "The HTTPS response produced an invalid SHA-256: $fetched_sha"
[ "$fetched_sha" = "$expected_sha" ] ||
    die "The remote installer was activated, but HTTPS returned SHA-256 $fetched_sha instead of $expected_sha."

printf 'Installer deployed and verified successfully.\nURL: %s/install.sh\nSHA-256: %s\n' \
    "$PUBLIC_BASE_URL" "$expected_sha"
