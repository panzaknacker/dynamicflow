#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd "$HERE/.." && pwd -P)"
SSH_SOURCE="${TOOLKIT_SSH_SOURCE:-$PROJECT_ROOT/ssh}"
VPN_SOURCE="${TOOLKIT_VPN_SOURCE:-$PROJECT_ROOT/vpn}"
PBP_SOURCE="${TOOLKIT_PBP_SOURCE:-$PROJECT_ROOT/pbp}"
DECEPTICON_SOURCE="${TOOLKIT_DECEPTICON_SOURCE:-$PROJECT_ROOT/decepticon}"
WORK=''

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    [[ -z "$WORK" ]] || rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

version_from() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" ]] || die "Missing or unsafe version file: $file"
    local value
    value="$(tr -d '[:space:]' <"$file")"
    [[ "$value" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] ||
        die "Invalid version in $file: $value"
    printf '%s' "$value"
}

copy_source_file() {
    local root="$1" relative="$2" destination="$3" mode
    [[ -f "$root/$relative" && ! -L "$root/$relative" ]] ||
        die "Missing or unsafe source input: $root/$relative"
    case "$relative" in *.sh) mode=0755 ;; *) mode=0644 ;; esac
    install -D -m "$mode" "$root/$relative" "$destination/$relative"
}

snapshot_origin_for() {
    local destination="$1" fallback="$2" origin_file value
    origin_file="$destination/SNAPSHOT-ORIGIN"
    if [[ ! -e "$origin_file" ]]; then
        printf '%s' "$fallback"
        return
    fi
    [[ -f "$origin_file" && ! -L "$origin_file" ]] ||
        die "Unsafe existing snapshot origin: $origin_file"
    value="$(awk 'NR == 1 && /^origin=./ { value=$0; sub(/^origin=/, "", value) } END { if (NR != 1 || value == "") exit 1; print value }' "$origin_file")" ||
        die "Invalid existing snapshot origin: $origin_file"
    printf '%s' "$value"
}

finish_source_snapshot() {
    local destination="$1" origin="$2"
    {
        printf 'origin=%s\n' "$origin"
    } >"$destination/SNAPSHOT-ORIGIN"
    (
        cd "$destination"
        find . -type f ! -name SOURCE-MANIFEST.tsv -printf '%m\t%P\0' |
            sort -z |
            while IFS=$'\t' read -r -d '' mode path; do
                hash="$(sha256sum "$path")"
                printf '%s\t%s\t%s\n' "$mode" "${hash%% *}" "$path"
            done >SOURCE-MANIFEST.tsv
    )
    chmod 0644 "$destination/SNAPSHOT-ORIGIN" "$destination/SOURCE-MANIFEST.tsv"
}

install_immutable_tree() {
    local source="$1" destination="$2"
    if [[ -e "$destination" ]]; then
        [[ -d "$destination" && ! -L "$destination" ]] || die "Unsafe existing snapshot: $destination"
        diff -qr -- "$source" "$destination" >/dev/null ||
            die "Immutable snapshot differs; bump the version before replacing $destination"
        return
    fi
    install -d -m 0755 "$(dirname "$destination")"
    mv -- "$source" "$destination"
}

install_immutable_artifact() {
    local source="$1" destination="$2" expected_sha="$3"
    install -d -m 0755 "$(dirname "$destination")"
    if [[ -e "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || die "Unsafe existing artifact: $destination"
        actual="$(sha256sum "$destination")"
        [[ "${actual%% *}" == "$expected_sha" ]] ||
            die "Immutable artifact differs; bump the version before replacing $destination"
        return
    fi
    install -m 0644 "$source" "$destination"
}

archive_version() {
    local archive="$1" member="$2" expected="$3"
    local embedded
    embedded="$(tar -xOzf "$archive" "$member" | tr -d '[:space:]')" ||
        die "Could not read $member from $archive"
    [[ "$embedded" == "$expected" ]] ||
        die "Embedded version mismatch in $archive: $embedded != $expected"
}

for command_name in awk bash date diff find gzip install mktemp mv readlink sha256sum sort stat tar tr; do
    command -v "$command_name" >/dev/null 2>&1 || die "Missing command: $command_name"
done
[[ "$#" -eq 0 ]] || die "Usage: ${0##*/}"

ssh_version="$(version_from "$SSH_SOURCE/VERSION")"
vpn_version="$(version_from "$VPN_SOURCE/VERSION")"
pbp_version="$(version_from "$PBP_SOURCE/VERSION")"
decepticon_version="$(version_from "$DECEPTICON_SOURCE/VERSION")"
[[ "$decepticon_version" == *-* ]] ||
    die 'The current Decepticon validation release must remain a prerelease version.'

WORK="$(mktemp -d)"
install -d -m 0700 "$WORK/build" "$WORK/sources" "$WORK/releases"

printf '[1/5] SSH/GUI source tests and reproducible package\n'
TOOLKIT_DIST_DIR="$WORK/build/ssh" "$SSH_SOURCE/make-toolkit-release.sh" "$ssh_version"
ssh_artifact="$WORK/build/ssh/ssh.tar.gz"
archive_version "$ssh_artifact" toolkit-ssh/VERSION "$ssh_version"

printf '[2/5] VPN source tests and reproducible package\n'
"$VPN_SOURCE/tests/static-checks.sh"
TOOLKIT_DIST_DIR="$WORK/build/vpn" "$VPN_SOURCE/make-release.sh" "$vpn_version"
vpn_artifact="$WORK/build/vpn/vpn.tar.gz"
archive_version "$vpn_artifact" toolkit-vpn/VERSION "$vpn_version"

printf '[3/5] PBP source tests and both architecture packages\n'
"$PBP_SOURCE/tests/static-checks.sh"
for arch in amd64 arm64; do
    TOOLKIT_DIST_DIR="$WORK/build/pbp" "$PBP_SOURCE/make-release.sh" "$arch" "$pbp_version"
    archive_version "$WORK/build/pbp/linux-$arch/pbp.tar.gz" toolkit-pbp/VERSION "$pbp_version"
done

printf '[4/5] Decepticon immutable validation package\n'
decepticon_snapshot="$HERE/sources/decepticon/$decepticon_version"
decepticon_artifact="$HERE/releases/decepticon/$decepticon_version/any/decepticon.tar.gz"
if [[ -e "$decepticon_artifact" ]]; then
    [[ -f "$decepticon_artifact" && ! -L "$decepticon_artifact" ]] ||
        die "Unsafe existing Decepticon artifact: $decepticon_artifact"
    [[ -d "$decepticon_snapshot" && ! -L "$decepticon_snapshot" && -f "$decepticon_snapshot/SOURCE-MANIFEST.tsv" ]] ||
        die "Existing Decepticon artifact has no immutable source snapshot: $decepticon_snapshot"
    printf 'Reusing already sealed Decepticon %s; current allowlisted sources are compared below.\n' "$decepticon_version"
else
    DECEPTICON_ALLOW_DIRTY="${DECEPTICON_ALLOW_DIRTY:-0}" \
        TOOLKIT_DIST_DIR="$WORK/build/decepticon" \
        "$DECEPTICON_SOURCE/make-release.sh" "$decepticon_version"
    decepticon_artifact="$WORK/build/decepticon/decepticon.tar.gz"
fi
archive_version "$decepticon_artifact" decepticon-vm-datapack/VERSION "$decepticon_version"
install -d -m 0755 "$WORK/decepticon-check"
tar -xzf "$decepticon_artifact" -C "$WORK/decepticon-check"
(
    cd "$WORK/decepticon-check/decepticon-vm-datapack"
    sha256sum -c SHA256SUMS >/dev/null
)
grep -Fqx 'source_dirty=false' "$WORK/decepticon-check/decepticon-vm-datapack/BUILD_INFO" ||
    die 'Expected the current Decepticon validation artifact to record source_dirty=false.'

ssh_source_stage="$WORK/sources/ssh/$ssh_version"
vpn_source_stage="$WORK/sources/vpn/$vpn_version"
pbp_source_stage="$WORK/sources/pbp/$pbp_version"
decepticon_source_stage="$WORK/sources/decepticon/$decepticon_version"
ssh_snapshot="$HERE/sources/ssh/$ssh_version"
vpn_snapshot="$HERE/sources/vpn/$vpn_version"
pbp_snapshot="$HERE/sources/pbp/$pbp_version"
install -d -m 0755 "$ssh_source_stage" "$vpn_source_stage" "$pbp_source_stage" "$decepticon_source_stage"

for file in bootstrap-ssh.sh vm-bootstrap.sh connect-gui.sh make-toolkit-release.sh README.md VERSION tests/static-checks.sh; do
    copy_source_file "$SSH_SOURCE" "$file" "$ssh_source_stage"
done
for file in bootstrap-vpn.sh make-release.sh README.md VERSION tests/static-checks.sh tests/prompt-login-harness.sh tests/pty-account.py tests/render-config-harness.sh; do
    copy_source_file "$VPN_SOURCE" "$file" "$vpn_source_stage"
done
for file in bootstrap-pbp.sh launch-pbp.py safe-extract.py make-release.sh fetch-vendor.sh README.md VERSION requirements.in requirements.lock browser-assets.lock browser-search-policy.json apparmor/toolkit-pbp tests/static-checks.sh tests/check_requirements.py tests/test_launcher.py tests/test_safe_extract.py; do
    copy_source_file "$PBP_SOURCE" "$file" "$pbp_source_stage"
done
for file in VERSION make-release.sh decepticon-vm-datapack/bootstrap-decepticon-vm.sh decepticon-vm-datapack/troubleshoot-decepticon-vm.sh decepticon-vm-datapack/fix-terminal.sh decepticon-vm-datapack/fix-decepticon-postgres.sh decepticon-vm-datapack/README.md; do
    copy_source_file "$DECEPTICON_SOURCE" "$file" "$decepticon_source_stage"
done
finish_source_snapshot "$ssh_source_stage" "$(snapshot_origin_for "$ssh_snapshot" "ssh")"
finish_source_snapshot "$vpn_source_stage" "$(snapshot_origin_for "$vpn_snapshot" "vpn")"
finish_source_snapshot "$pbp_source_stage" "$(snapshot_origin_for "$pbp_snapshot" "pbp")"
finish_source_snapshot "$decepticon_source_stage" "$(snapshot_origin_for "$decepticon_snapshot" "decepticon")"

install_immutable_tree "$ssh_source_stage" "$ssh_snapshot"
install_immutable_tree "$vpn_source_stage" "$vpn_snapshot"
install_immutable_tree "$pbp_source_stage" "$pbp_snapshot"
install_immutable_tree "$decepticon_source_stage" "$decepticon_snapshot"

declare -a rows=()
add_release() {
    local tool="$1" version="$2" target="$3" name="$4" source="$5" channel="$6"
    local sha size destination
    sha="$(sha256sum "$source")"
    sha="${sha%% *}"
    size="$(stat -c '%s' "$source")"
    destination="$HERE/releases/$tool/$version/$target/$name"
    install_immutable_artifact "$source" "$destination" "$sha"
    rows+=("$tool"$'\t'"$version"$'\t'"$target"$'\t'"$name"$'\t'"$size"$'\t'"$sha"$'\t'"$channel")
}

add_release ssh "$ssh_version" any ssh.tar.gz "$ssh_artifact" production
add_release vpn "$vpn_version" any vpn.tar.gz "$vpn_artifact" production
add_release pbp "$pbp_version" linux-amd64 pbp.tar.gz "$WORK/build/pbp/linux-amd64/pbp.tar.gz" production
add_release pbp "$pbp_version" linux-arm64 pbp.tar.gz "$WORK/build/pbp/linux-arm64/pbp.tar.gz" production
add_release decepticon "$decepticon_version" any decepticon.tar.gz "$decepticon_artifact" validation

manifest_tmp="$WORK/release-set.tsv"
{
    printf '#tool\tversion\ttarget\tartifact\tsize\tsha256\tchannel\n'
    printf '%s\n' "${rows[@]}" | sort
} >"$manifest_tmp"
set_hash="$(sha256sum "$manifest_tmp")"
set_hash="${set_hash%% *}"
set_id="set-${set_hash:0:20}"
set_dir="$HERE/sets/$set_id"
if [[ -e "$set_dir" ]]; then
    cmp -s "$manifest_tmp" "$set_dir/release-set.tsv" ||
        die "Release-set hash collision or modified immutable set: $set_dir"
else
    install -d -m 0755 "$set_dir"
    install -m 0644 "$manifest_tmp" "$set_dir/release-set.tsv"
fi

TOOLKIT_RELEASE_ROOT="$HERE/releases" "$HERE/verify-release-set.sh" "$set_dir"
link_tmp="$HERE/.current.$$"
ln -s "sets/$set_id" "$link_tmp"
mv -Tf -- "$link_tmp" "$HERE/current"

printf '[5/5] Current sealed release set: %s\n' "$set_id"
printf 'Sources: %s/sources\nArtifacts: %s/releases\n' "$HERE" "$HERE"
