#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SSH_KEY_PICKER="$HERE/lib/ssh-key-picker.sh"
SET_PATH="${TOOLKIT_RELEASE_SET:-$HERE/current}"
RELEASE_ROOT="${TOOLKIT_RELEASE_ROOT:-$HERE/releases}"
SSH_HOST="${TOOLKIT_SSH_HOST:-${TOOLKIT_SERVER:-downloads.example.com}}"
SSH_PORT="${TOOLKIT_SSH_PORT:-22}"
DEPLOY_USER="${TOOLKIT_DEPLOY_USER:-download}"
DOWNLOAD_ROOT="${TOOLKIT_DOWNLOAD_ROOT:-/srv/downloads}"
IDENTITY="${TOOLKIT_SSH_IDENTITY:-}"
IDENTITY_DEFAULT="${TOOLKIT_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic}"
PUBLIC_BASE_URL="${TOOLKIT_PUBLIC_BASE_URL:-https://downloads.example.com}"
DRY_RUN="${TOOLKIT_DRY_RUN:-0}"
WORK=''
REMOTE_STAGE=''
REMOTE_CREATED=0

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

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    [[ -z "$WORK" ]] || rm -rf -- "$WORK"
    if [[ "$REMOTE_CREATED" -eq 1 && -n "$REMOTE_STAGE" && "$DRY_RUN" -eq 0 ]]; then
        ssh "${ssh_args[@]}" -- "$DEPLOY_USER@$SSH_HOST" "rm -rf -- '$REMOTE_STAGE'" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

[[ "$#" -eq 0 ]] || die "Usage: ${0##*/}"
[[ "$DRY_RUN" == 0 || "$DRY_RUN" == 1 ]] || die 'TOOLKIT_DRY_RUN must be 0 or 1.'
[[ "$SSH_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "Unsafe SSH host: $SSH_HOST"
[[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Unsafe deploy user: $DEPLOY_USER"
[[ "$SSH_PORT" =~ ^[0-9]+$ && ${#SSH_PORT} -le 5 ]] || die "Invalid SSH port: $SSH_PORT"
port_number=$((10#$SSH_PORT))
((port_number >= 1 && port_number <= 65535)) || die "Invalid SSH port: $SSH_PORT"
SSH_PORT="$port_number"
[[ "$DOWNLOAD_ROOT" =~ ^/[A-Za-z0-9._/-]+$ && "$DOWNLOAD_ROOT" != / ]] || die 'Unsafe download root.'
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
[[ "$PUBLIC_BASE_URL" =~ ^https://[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || die 'Unsafe public base URL.'

if [[ "$DRY_RUN" -eq 0 && -z "$IDENTITY" ]]; then
    IDENTITY="$(toolkit_select_ssh_private_key "$IDENTITY_DEFAULT")"
fi
if [[ -n "$IDENTITY" ]]; then
    [[ -f "$IDENTITY" && ! -L "$IDENTITY" && -r "$IDENTITY" ]] || die "Unsafe SSH identity: $IDENTITY"
    identity_mode="$(stat -c '%a' "$IDENTITY")"
    case "$identity_mode" in 400 | 600) ;; *) die "SSH identity must have mode 0400 or 0600: $IDENTITY" ;; esac
fi

for command_name in awk cp curl find mktemp readlink scp sha256sum sort ssh stat; do
    command -v "$command_name" >/dev/null 2>&1 || die "Missing command: $command_name"
done
"$HERE/verify-release-set.sh" "$SET_PATH" >/dev/null
SET_DIR="$(readlink -f -- "$SET_PATH")"
MANIFEST="$SET_DIR/release-set.tsv"
SET_ID="$(basename "$SET_DIR")"
[[ "$SET_ID" =~ ^set-[0-9a-f]{20}$ ]] || die "Unsafe set identifier: $SET_ID"

ssh_args=(
    -T -p "$SSH_PORT"
    -o ClearAllForwardings=yes
    -o ForwardAgent=no
    -o KbdInteractiveAuthentication=no
    -o PasswordAuthentication=no
    -o PreferredAuthentications=publickey
    -o StrictHostKeyChecking=yes
)
scp_args=(
    -P "$SSH_PORT"
    -o ClearAllForwardings=yes
    -o ForwardAgent=no
    -o KbdInteractiveAuthentication=no
    -o PasswordAuthentication=no
    -o PreferredAuthentications=publickey
    -o StrictHostKeyChecking=yes
)
if [[ -n "$IDENTITY" ]]; then
    ssh_args+=(-o IdentitiesOnly=yes -i "$IDENTITY")
    scp_args+=(-o IdentitiesOnly=yes -i "$IDENTITY")
fi

WORK="$(mktemp -d)"
install -d -m 0700 "$WORK/blobs"
batch="$WORK/batch.tsv"
: >"$batch"
total_size=0
counter=0
while IFS=$'\t' read -r tool version target name size sha channel extra; do
    [[ -n "${tool:-}" && "$tool" != \#* ]] || continue
    [[ -z "${extra:-}" ]] || die "Unexpected catalog field for $tool"
    blob="$(printf 'blob-%04d' "$counter")"
    source="$RELEASE_ROOT/$tool/$version/$target/$name"
    cp --reflink=auto --preserve=mode,timestamps -- "$source" "$WORK/blobs/$blob"
    chmod 0600 "$WORK/blobs/$blob"
    line="$(sha256sum "$WORK/blobs/$blob")"
    [[ "${line%% *}" == "$sha" && "$(stat -c '%s' "$WORK/blobs/$blob")" == "$size" ]] ||
        die "Artifact changed while snapshotting: $source"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tool" "$version" "$target" "$name" "$size" "$sha" "$channel" "$blob" >>"$batch"
    total_size=$((total_size + size))
    counter=$((counter + 1))
done <"$MANIFEST"
[[ "$counter" -eq 5 ]] || die "Expected five artifacts, got $counter"
install -m 0700 "$HERE/server/publish-release-set-remote.sh" "$WORK/finalize.sh"

if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'Dry run verified %s (%s artifacts, %s bytes).\n' "$SET_ID" "$counter" "$total_size"
    printf 'Target: %s@%s:%s%s\n' "$DEPLOY_USER" "$SSH_HOST" "$SSH_PORT" "$DOWNLOAD_ROOT"
    printf 'No network changes were made.\n'
    exit 0
fi

REMOTE_STAGE="$DOWNLOAD_ROOT/.release-uploads/$SET_ID-$(date -u '+%Y%m%dT%H%M%SZ')-$$-$RANDOM"
required_kb=$(((total_size + 1023) / 1024 + 262144))
remote_available="$(
    ssh "${ssh_args[@]}" -- "$DEPLOY_USER@$SSH_HOST" "set -eu; install -d -m 0700 '$DOWNLOAD_ROOT/.release-uploads' '$REMOTE_STAGE'; df -k --output=avail '$DOWNLOAD_ROOT' | tail -n 1 | tr -d ' '"
)"
REMOTE_CREATED=1
[[ "$remote_available" =~ ^[0-9]+$ ]] || die 'Could not determine remote free space.'
((remote_available >= required_kb)) ||
    die "Insufficient remote space: need at least ${required_kb} KiB, have ${remote_available} KiB"

printf 'Uploading sealed release set %s (%s bytes).\n' "$SET_ID" "$total_size"
scp "${scp_args[@]}" -- "$batch" "$DEPLOY_USER@$SSH_HOST:$REMOTE_STAGE/batch.tsv"
scp "${scp_args[@]}" -- "$WORK/finalize.sh" "$DEPLOY_USER@$SSH_HOST:$REMOTE_STAGE/finalize.sh"
for blob_path in "$WORK"/blobs/blob-*; do
    scp "${scp_args[@]}" -- "$blob_path" "$DEPLOY_USER@$SSH_HOST:$REMOTE_STAGE/${blob_path##*/}"
done

ssh "${ssh_args[@]}" -- "$DEPLOY_USER@$SSH_HOST" "bash '$REMOTE_STAGE/finalize.sh' '$DOWNLOAD_ROOT' '$REMOTE_STAGE' '$SET_ID'"
REMOTE_CREATED=0

curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --retry 3 --retry-all-errors "$PUBLIC_BASE_URL/health.txt" | grep -Fxq ok ||
    die 'Release set was activated, but the public health check failed.'

printf 'Published and activated: %s\n' "$SET_ID"
printf 'Installer: %s/install.sh\n' "$PUBLIC_BASE_URL"
printf 'Protected tools require the download password plus a fresh TOTP.\n'
