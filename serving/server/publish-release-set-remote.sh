#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

DOWNLOAD_ROOT="${1:-}"
STAGE="${2:-}"
SET_ID="${3:-}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

safe_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && "$1" != . && "$1" != .. ]]
}

[[ "$DOWNLOAD_ROOT" =~ ^/[A-Za-z0-9._/-]+$ && "$DOWNLOAD_ROOT" != / ]] ||
    die 'Unsafe download root.'
[[ "$STAGE" == "$DOWNLOAD_ROOT"/.release-uploads/* ]] || die 'Unsafe release stage.'
safe_name "$SET_ID" || die 'Unsafe release-set identifier.'
[[ -d "$DOWNLOAD_ROOT" && ! -L "$DOWNLOAD_ROOT" ]] || die 'Download root is missing or unsafe.'
[[ "$(cd "$DOWNLOAD_ROOT" && pwd -P)" == "$DOWNLOAD_ROOT" ]] || die 'Download root is not canonical.'
[[ -d "$STAGE" && ! -L "$STAGE" ]] || die 'Release stage is missing or unsafe.'
MANIFEST="$STAGE/batch.tsv"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || die 'Batch manifest is missing or unsafe.'

TOOLS_DIR="$DOWNLOAD_ROOT/tools"
install -d -m 0755 "$TOOLS_DIR"
exec 9>"$DOWNLOAD_ROOT/.publish.lock"
flock 9

declare -A versions=()
declare -A temp_dirs=()
declare -A destinations=()
declare -A latest_versions=()
declare -a keys=()
declare -a created=()
declare -a temporary=()
metadata_changed=0
BACKUP="$STAGE/backups"
install -d -m 0700 "$BACKUP"

backup_file() {
    local source="$1" label="$2"
    if [[ -e "$source" ]]; then
        [[ -f "$source" && ! -L "$source" ]] || die "Unsafe metadata path: $source"
        cp -p -- "$source" "$BACKUP/$label"
    else
        : >"$BACKUP/$label.absent"
    fi
}

restore_file() {
    local destination="$1" label="$2"
    if [[ -f "$BACKUP/$label" ]]; then
        install -m 0644 "$BACKUP/$label" "$destination"
    elif [[ -f "$BACKUP/$label.absent" ]]; then
        rm -f -- "$destination"
    fi
}

rollback() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ "$status" -ne 0 ]]; then
        if [[ "$metadata_changed" -eq 1 ]]; then
            restore_file "$TOOLS_DIR/index.txt" index
            restore_file "$TOOLS_DIR/release-set.tsv" release-set
            restore_file "$TOOLS_DIR/release-set-id.txt" release-set-id
            for tool in "${!latest_versions[@]}"; do
                restore_file "$TOOLS_DIR/$tool/latest.txt" "latest.$tool"
            done
        fi
        for destination in "${created[@]}"; do
            rm -rf -- "$destination"
        done
    fi
    for temporary_path in "${temporary[@]}"; do
        rm -rf -- "$temporary_path"
    done
    rm -rf -- "$STAGE"
    exit "$status"
}
trap rollback EXIT HUP INT TERM

row_count=0
while IFS=$'\t' read -r tool version target name size sha channel blob extra; do
    [[ -z "${extra:-}" ]] || die "Unexpected manifest field for $tool"
    safe_name "$tool" && safe_name "$target" && safe_name "$name" && safe_name "$blob" ||
        die 'Unsafe batch manifest name.'
    [[ "$version" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] ||
        die "Invalid version: $version"
    [[ "$size" =~ ^[1-9][0-9]*$ && "$sha" =~ ^[0-9a-f]{64}$ ]] ||
        die 'Invalid batch size or hash.'
    case "$channel" in production | validation) ;; *) die 'Invalid batch channel.' ;; esac
    artifact="$STAGE/$blob"
    [[ -f "$artifact" && ! -L "$artifact" ]] || die "Missing staged artifact: $blob"
    [[ "$(stat -c '%s' "$artifact")" == "$size" ]] || die "Staged size mismatch: $blob"
    line="$(sha256sum "$artifact")"
    [[ "${line%% *}" == "$sha" ]] || die "Staged hash mismatch: $blob"

    key="$tool/$version"
    if [[ -z "${versions[$key]:-}" ]]; then
        versions[$key]=1
        keys+=("$key")
        latest_versions[$tool]="$version"
        tool_dir="$TOOLS_DIR/$tool"
        install -d -m 0755 "$tool_dir"
        tmp="$(mktemp -d "$TOOLS_DIR/.version.$tool.$version.XXXXXXXX")"
        chmod 0755 "$tmp"
        temporary+=("$tmp")
        temp_dirs[$key]="$tmp"
        destinations[$key]="$tool_dir/$version"
    elif [[ "${latest_versions[$tool]}" != "$version" ]]; then
        die "Multiple versions of $tool in one set."
    fi

    tmp="${temp_dirs[$key]}"
    [[ ! -e "$tmp/$target" ]] || die "Duplicate target in set: $tool/$version/$target"
    install -d -m 0755 "$tmp/$target"
    mv -- "$artifact" "$tmp/$target/$name"
    chmod 0644 "$tmp/$target/$name"
    row_count=$((row_count + 1))
done <"$MANIFEST"
[[ "$row_count" -eq 5 ]] || die "Expected five staged artifacts, got $row_count"

for key in "${keys[@]}"; do
    tmp="${temp_dirs[$key]}"
    destination="${destinations[$key]}"
    (
        cd "$tmp"
        find . -type f ! -name SHA256SUMS -printf '%P\0' |
            sort -z |
            xargs -0 -r sha256sum >SHA256SUMS
        sha256sum -c SHA256SUMS >/dev/null
    )
    chmod 0644 "$tmp/SHA256SUMS"

    if [[ -e "$destination" ]]; then
        [[ -d "$destination" && ! -L "$destination" ]] || die "Unsafe existing release: $destination"
        chmod 0755 "$destination"
        (cd "$destination" && sha256sum -c SHA256SUMS >/dev/null) ||
            die "Existing release checksum failure: $destination"
        cmp -s "$tmp/SHA256SUMS" "$destination/SHA256SUMS" ||
            die "Immutable release conflicts with staged set: $destination"
        rm -rf -- "$tmp"
        temp_dirs[$key]=''
    fi
done

for key in "${keys[@]}"; do
    tmp="${temp_dirs[$key]}"
    [[ -n "$tmp" ]] || continue
    destination="${destinations[$key]}"
    [[ ! -e "$destination" ]] || die "Release appeared concurrently: $destination"
    mv -- "$tmp" "$destination"
    temp_dirs[$key]=''
    created+=("$destination")
done

backup_file "$TOOLS_DIR/index.txt" index
backup_file "$TOOLS_DIR/release-set.tsv" release-set
backup_file "$TOOLS_DIR/release-set-id.txt" release-set-id
for tool in "${!latest_versions[@]}"; do
    backup_file "$TOOLS_DIR/$tool/latest.txt" "latest.$tool"
done
metadata_changed=1

index_tmp="$(mktemp "$TOOLS_DIR/.index.XXXXXXXX")"
printf '%s\n' "${!latest_versions[@]}" | sort >"$index_tmp"
chmod 0644 "$index_tmp"
mv -f -- "$index_tmp" "$TOOLS_DIR/index.txt"

for tool in "${!latest_versions[@]}"; do
    latest_tmp="$(mktemp "$TOOLS_DIR/$tool/.latest.XXXXXXXX")"
    printf '%s\n' "${latest_versions[$tool]}" >"$latest_tmp"
    chmod 0644 "$latest_tmp"
    mv -f -- "$latest_tmp" "$TOOLS_DIR/$tool/latest.txt"
done

set_tmp="$(mktemp "$TOOLS_DIR/.release-set.XXXXXXXX")"
{
    printf '#tool\tversion\ttarget\tartifact\tsize\tsha256\tchannel\n'
    cut -f1-7 "$MANIFEST" | sort
} >"$set_tmp"
chmod 0644 "$set_tmp"
mv -f -- "$set_tmp" "$TOOLS_DIR/release-set.tsv"

id_tmp="$(mktemp "$TOOLS_DIR/.release-set-id.XXXXXXXX")"
printf '%s\n' "$SET_ID" >"$id_tmp"
chmod 0644 "$id_tmp"
mv -f -- "$id_tmp" "$TOOLS_DIR/release-set-id.txt"

metadata_changed=0
trap - EXIT HUP INT TERM
rm -rf -- "$STAGE"
printf 'Release set activated: %s\n' "$SET_ID"
printf 'Tools: %s\n' "$(printf '%s ' "${!latest_versions[@]}" | sed 's/ $//')"
