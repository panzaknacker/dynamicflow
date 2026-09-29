#!/usr/bin/env bash

# shared interactive SSH private-key selection for local operator scripts.
# explicit identity environment variables remain the noninteractive automation
# boundary; directory inputs are presented as a numbered list.

toolkit_expand_ssh_key_path() {
    local path="$1"

    case "$path" in
    '~') path="$HOME" ;;
    '~/'*) path="$HOME/${path#\~/}" ;;
    esac
    printf '%s' "$path"
}

toolkit_select_ssh_private_key() {
    local location
    local choice index key_candidate
    local -a keys=()

    location="$(toolkit_expand_ssh_key_path "${1:-${HOME}/.ssh/dynamic}")"

    if [[ -f "$location" && ! -L "$location" && -r "$location" ]]; then
        printf '%s' "$location"
        return 0
    fi
    [[ -d "$location" && ! -L "$location" ]] || {
        printf 'ERROR: SSH private-key path is neither a safe file nor directory: %s\n' "$location" >&2
        return 1
    }
    [[ -r /dev/tty && -w /dev/tty ]] || {
        printf 'ERROR: Interactive SSH key selection needs /dev/tty; provide an explicit identity path for automation.\n' >&2
        return 1
    }

    while IFS= read -r -d '' key_candidate; do
        case "${key_candidate##*/}" in
        *.pub | authorized_keys | authorized_keys.* | config | known_hosts | known_hosts.*) continue ;;
        esac
        keys+=("$key_candidate")
    done < <(
        find "$location" -mindepth 1 -maxdepth 1 -type f -print0 |
            sort -z
    )
    ((${#keys[@]} > 0)) || {
        printf 'ERROR: No regular SSH private-key candidates found in: %s\n' "$location" >&2
        return 1
    }

    printf 'Available SSH private keys in %s:\n' "$location" >/dev/tty
    index=1
    for key_candidate in "${keys[@]}"; do
        printf '  %d) %s\n' "$index" "${key_candidate##*/}" >/dev/tty
        index=$((index + 1))
    done

    while true; do
        printf 'Select SSH private key [1]: ' >/dev/tty
        IFS= read -r choice </dev/tty || {
            printf 'ERROR: SSH private-key selection was cancelled.\n' >&2
            return 1
        }
        choice="${choice:-1}"
        if [[ "$choice" =~ ^[0-9]+$ ]] &&
            ((10#$choice >= 1 && 10#$choice <= ${#keys[@]})); then
            printf '%s' "${keys[10#$choice - 1]}"
            return 0
        fi
        printf 'Choose a number from 1 to %d.\n' "${#keys[@]}" >/dev/tty
    done
}
