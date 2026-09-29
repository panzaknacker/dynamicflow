#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RELEASE_ROOT="${TOOLKIT_RELEASE_ROOT:-$HERE/releases}"
SET_PATH="${1:-$HERE/current}"
EXPECTED_TOOLS=$'decepticon\npbp\nssh\nvpn'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

safe_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && "$1" != . && "$1" != .. ]]
}

[[ -e "$SET_PATH" || -L "$SET_PATH" ]] || die "Release set does not exist: $SET_PATH"
SET_DIR="$(readlink -f -- "$SET_PATH")"
[[ -n "$SET_DIR" && -d "$SET_DIR" ]] || die "Could not resolve release set: $SET_PATH"
MANIFEST="$SET_DIR/release-set.tsv"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || die "Missing or unsafe release-set.tsv: $MANIFEST"

declare -A seen=()
declare -A tool_versions=()
declare -A tool_targets=()
tool_list=''
row_count=0

while IFS=$'\t' read -r tool version target remote_name size sha channel extra; do
    [[ -n "${tool:-}" ]] || continue
    [[ "$tool" == '#tool' ]] && continue
    [[ "$tool" != \#* ]] || continue
    [[ -z "${extra:-}" ]] || die "Unexpected extra catalog field for $tool"
    safe_name "$tool" || die "Unsafe tool name: $tool"
    [[ "$version" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] ||
        die "Invalid version for $tool: $version"
    safe_name "$target" || die "Unsafe target for $tool: $target"
    safe_name "$remote_name" || die "Unsafe artifact name for $tool: $remote_name"
    [[ "$size" =~ ^[1-9][0-9]*$ ]] || die "Invalid artifact size for $tool/$target"
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "Invalid SHA-256 for $tool/$target"
    case "$channel" in production | validation) ;; *) die "Invalid channel for $tool: $channel" ;; esac

    key="$tool/$version/$target/$remote_name"
    [[ -z "${seen[$key]:-}" ]] || die "Duplicate catalog row: $key"
    seen[$key]=1
    if [[ -n "${tool_versions[$tool]:-}" && "${tool_versions[$tool]}" != "$version" ]]; then
        die "A release set may contain only one version of $tool"
    fi
    tool_versions[$tool]="$version"
    tool_targets[$tool]="${tool_targets[$tool]:-}${tool_targets[$tool]:+$'\n'}$target"
    tool_list="${tool_list}${tool_list:+$'\n'}$tool"

    artifact="$RELEASE_ROOT/$tool/$version/$target/$remote_name"
    [[ -f "$artifact" && ! -L "$artifact" ]] || die "Missing or unsafe artifact: $artifact"
    actual_size="$(stat -c '%s' "$artifact")"
    [[ "$actual_size" == "$size" ]] || die "Size mismatch for $artifact: $actual_size != $size"
    actual_sha="$(sha256sum "$artifact")"
    actual_sha="${actual_sha%% *}"
    [[ "$actual_sha" == "$sha" ]] || die "SHA-256 mismatch for $artifact"
    row_count=$((row_count + 1))
done <"$MANIFEST"

[[ "$row_count" -eq 5 ]] || die "Release set must contain exactly five artifacts, got $row_count"
actual_tools="$(printf '%s\n' "$tool_list" | awk 'NF && !seen[$0]++' | sort)"
[[ "$actual_tools" == "$EXPECTED_TOOLS" ]] || {
    printf 'Expected tools:\n%s\nActual tools:\n%s\n' "$EXPECTED_TOOLS" "$actual_tools" >&2
    die 'Release set tool list is incomplete'
}
[[ "${tool_targets[ssh]}" == any ]] || die 'ssh must have target any'
[[ "${tool_targets[vpn]}" == any ]] || die 'vpn must have target any'
[[ "${tool_targets[decepticon]}" == any ]] || die 'decepticon must have target any'
pbp_targets="$(printf '%s\n' "${tool_targets[pbp]}" | sort)"
[[ "$pbp_targets" == $'linux-amd64\nlinux-arm64' ]] || die 'pbp must contain linux-amd64 and linux-arm64'

printf 'Verified release set: %s\nArtifacts: %s\n' "$SET_DIR" "$row_count"
