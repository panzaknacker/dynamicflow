#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BOOTSTRAP="$SCRIPT_DIR/vm-bootstrap.sh"
SELECTED_PUBLIC_KEY_FILE=''
PUBLIC_KEY_TMP=''

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "$PUBLIC_KEY_TMP" ]; then
        rm -f -- "$PUBLIC_KEY_TMP" || true
    fi
}
trap cleanup EXIT HUP INT TERM

validate_public_key_file() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] ||
        die "Public key is missing or unsafe: $path"
    ssh-keygen -lf "$path" -E sha256 >/dev/null 2>&1 ||
        die "Invalid SSH public key: $path"
}

select_public_key() {
    local location="$1"
    local choice index paste_choice key_candidate pasted_key
    local -a keys=()

    [ -r /dev/tty ] && [ -w /dev/tty ] ||
        die 'Interactive public-key selection needs /dev/tty. Pass --public-key-file FILE for automation.'

    if [ -d "$location" ] && [ ! -L "$location" ]; then
        while IFS= read -r -d '' key_candidate; do
            keys+=("$key_candidate")
        done < <(
            find "$location" -mindepth 1 -maxdepth 1 -type f -name '*.pub' -print0 |
                sort -z
        )
    fi

    printf 'SSH public-key selection (private keys stay on your workstation):\n' >/dev/tty
    index=1
    for key_candidate in "${keys[@]}"; do
        printf '  %d) %s\n' "$index" "$key_candidate" >/dev/tty
        index=$((index + 1))
    done
    paste_choice="$index"
    printf '  %d) Paste a public key\n' "$paste_choice" >/dev/tty

    while true; do
        printf 'Select SSH public key [%d]: ' "$paste_choice" >/dev/tty
        IFS= read -r choice </dev/tty || die 'Public-key selection was cancelled.'
        choice="${choice:-$paste_choice}"
        if [[ "$choice" =~ ^[0-9]+$ ]] &&
            ((10#$choice >= 1 && 10#$choice <= paste_choice)); then
            break
        fi
        printf 'Choose a number from 1 to %d.\n' "$paste_choice" >/dev/tty
    done

    if ((10#$choice < paste_choice)); then
        SELECTED_PUBLIC_KEY_FILE="${keys[10#$choice - 1]}"
        validate_public_key_file "$SELECTED_PUBLIC_KEY_FILE"
        return 0
    fi

    printf 'Paste one ssh-ed25519/ecdsa/ssh-rsa public-key line: ' >/dev/tty
    IFS= read -r pasted_key </dev/tty || die 'Public-key paste was cancelled.'
    [ -n "$pasted_key" ] || die 'Public key must not be empty.'
    PUBLIC_KEY_TMP="$(mktemp)"
    chmod 0600 "$PUBLIC_KEY_TMP"
    printf '%s\n' "$pasted_key" >"$PUBLIC_KEY_TMP"
    pasted_key=''
    validate_public_key_file "$PUBLIC_KEY_TMP"
    SELECTED_PUBLIC_KEY_FILE="$PUBLIC_KEY_TMP"
}

[ -f "$BOOTSTRAP" ] || die "Missing bootstrap payload: $BOOTSTRAP"
[ -f "$SCRIPT_DIR/SHA256SUMS" ] || die 'Missing internal SHA256SUMS.'
(cd "$SCRIPT_DIR" && sha256sum -c --quiet SHA256SUMS) ||
    die 'Internal Toolkit SSH bundle checksum verification failed.'

mode='ssh'
case "${1:-}" in
key-only | ssh | ssh-gui)
    mode="$1"
    shift
    ;;
-h | --help)
    exec bash "$BOOTSTRAP" --help
    ;;
esac

invoking_user=''
if [ "$(id -u)" -eq 0 ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != 'root' ]; then
        invoking_user="$SUDO_USER"
    fi
else
    invoking_user="$(id -un)"
fi

explicit_user=0
for argument in "$@"; do
    case "$argument" in
    --user | --user=*) explicit_user=1 ;;
    esac
done

if [ "$explicit_user" -eq 0 ]; then
    [ -n "$invoking_user" ] ||
        die 'Could not infer the SSH admin account. Pass --user EXISTING_USER.'
    set -- --user "$invoking_user" "$@"
fi

explicit_public_key=0
for argument in "$@"; do
    case "$argument" in
    --public-key-file | --public-key-file=*) explicit_public_key=1 ;;
    esac
done

if [ "$explicit_public_key" -eq 0 ]; then
    if [ -n "${VM_SSH_PUBLIC_KEY_FILE:-}" ]; then
        SELECTED_PUBLIC_KEY_FILE="$VM_SSH_PUBLIC_KEY_FILE"
        validate_public_key_file "$SELECTED_PUBLIC_KEY_FILE"
    elif [ -n "${VM_SSH_PUBLIC_KEY:-}" ]; then
        PUBLIC_KEY_TMP="$(mktemp)"
        chmod 0600 "$PUBLIC_KEY_TMP"
        printf '%s\n' "$VM_SSH_PUBLIC_KEY" >"$PUBLIC_KEY_TMP"
        validate_public_key_file "$PUBLIC_KEY_TMP"
        SELECTED_PUBLIC_KEY_FILE="$PUBLIC_KEY_TMP"
    else
        selection_user="${invoking_user:-$(id -un)}"
        selection_home="$(getent passwd "$selection_user" | awk -F: 'NR == 1 {print $6}')"
        [ -n "$selection_home" ] || die "Could not resolve home directory for public-key selection: $selection_user"
        select_public_key "${VM_SSH_PUBLIC_KEY_DIR:-$selection_home/.ssh/dynamic}"
    fi
    set -- "$@" --public-key-file "$SELECTED_PUBLIC_KEY_FILE"
fi

command=(bash "$BOOTSTRAP" "$mode" "$@")
if [ "$(id -u)" -eq 0 ]; then
    "${command[@]}"
    exit 0
fi

command -v sudo >/dev/null 2>&1 ||
    die 'sudo is required when the Toolkit installer runs as a non-root user.'
sudo -- "${command[@]}"
