#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd "$ROOT_DIR/.." && pwd -P)"
REPO_ROOT="${DECEPTICON_REPO:-$ROOT_DIR/Decepticon}"
DATAPACK_SOURCE="${DECEPTICON_DATAPACK_SOURCE:-$ROOT_DIR/decepticon-vm-datapack}"
VPN_ROOT="${DECEPTICON_VPN_ROOT:-$PROJECT_ROOT/vpn}"
VPN_BOOTSTRAP="${DECEPTICON_VPN_BOOTSTRAP:-$VPN_ROOT/bootstrap-vpn.sh}"
VPN_VERSION_FILE="${DECEPTICON_VPN_VERSION_FILE:-$VPN_ROOT/VERSION}"
DIST_ROOT="${TOOLKIT_DIST_DIR:-$ROOT_DIR/dist}"
VERSION_FILE="$ROOT_DIR/VERSION"
VERSION="${1:-}"
ALLOW_DIRTY="${DECEPTICON_ALLOW_DIRTY:-0}"
STAGE_PARENT=''
TAR_TMP=''
readonly VERSION_RE='^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    [[ -z "$STAGE_PARENT" ]] || rm -rf -- "$STAGE_PARENT"
    [[ -z "$TAR_TMP" || ! -e "$TAR_TMP" ]] || rm -f -- "$TAR_TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

case "${1:-}" in
-h | --help)
    printf 'Usage: %s [vX.Y.Z]\n' "${0##*/}"
    exit 0
    ;;
esac
[[ "$#" -le 1 ]] || die "Usage: ${0##*/} [vX.Y.Z]"
[[ "$ALLOW_DIRTY" == 0 || "$ALLOW_DIRTY" == 1 ]] ||
    die 'DECEPTICON_ALLOW_DIRTY must be 0 or 1.'
[[ -f "$VERSION_FILE" && ! -L "$VERSION_FILE" ]] ||
    die "Missing or unsafe version file: $VERSION_FILE"
VERSION="${VERSION:-$(tr -d '[:space:]' <"$VERSION_FILE")}"
[[ "$VERSION" =~ $VERSION_RE ]] || die "Invalid version: $VERSION"
case "$DIST_ROOT" in /*) ;; *) die 'TOOLKIT_DIST_DIR must be absolute.' ;; esac
[[ "$DIST_ROOT" != / && ! -L "$DIST_ROOT" ]] ||
    die "Unsafe dist directory: $DIST_ROOT"

for command_name in awk bash date diff find git go gzip install mktemp sha256sum sort tar tr; do
    command -v "$command_name" >/dev/null 2>&1 ||
        die "Missing required command: $command_name"
done
[[ -x "$REPO_ROOT/scripts/make-vm-bundle.sh" ]] ||
    die "Missing $REPO_ROOT/scripts/make-vm-bundle.sh"
[[ -d "$DATAPACK_SOURCE" && ! -L "$DATAPACK_SOURCE" ]] ||
    die "Missing or unsafe datapack source: $DATAPACK_SOURCE"
[[ -f "$VPN_BOOTSTRAP" && ! -L "$VPN_BOOTSTRAP" && -x "$VPN_BOOTSTRAP" ]] ||
    die "Missing or unsafe canonical VPN bootstrap: $VPN_BOOTSTRAP"
[[ -f "$VPN_VERSION_FILE" && ! -L "$VPN_VERSION_FILE" ]] ||
    die "Missing or unsafe VPN version file: $VPN_VERSION_FILE"
bash -n "$VPN_BOOTSTRAP"

payload_files=(
    bootstrap-decepticon-vm.sh
    troubleshoot-decepticon-vm.sh
    fix-terminal.sh
    fix-decepticon-postgres.sh
    README.md
)
for task_file in "${payload_files[@]}"; do
    [[ -f "$DATAPACK_SOURCE/$task_file" && ! -L "$DATAPACK_SOURCE/$task_file" ]] ||
        die "Missing or unsafe datapack source: $task_file"
done

unexpected="$({
    find "$DATAPACK_SOURCE" -mindepth 1 -maxdepth 1 -type f \
        ! -name bootstrap-decepticon-vm.sh \
        ! -name troubleshoot-decepticon-vm.sh \
        ! -name fix-terminal.sh \
        ! -name fix-decepticon-postgres.sh \
        ! -name README.md \
        ! -name BUILD_INFO \
        ! -name SHA256SUMS \
        ! -name VERSION \
        ! -name setup-mullvad.sh \
        ! -name decepticon-custom-vm.tar.gz \
        -printf '%f\n'
} | sort)"
[[ -z "$unexpected" ]] || {
    printf 'ERROR: Unexpected datapack source files:\n%s\n' "$unexpected" >&2
    exit 1
}

vpn_source_version="$(tr -d '[:space:]' <"$VPN_VERSION_FILE")"
[[ "$vpn_source_version" =~ $VERSION_RE ]] ||
    die "Invalid VPN source version: $vpn_source_version"
vpn_bootstrap_sha="$(sha256sum "$VPN_BOOTSTRAP" | awk '{print $1}')"

if git_top="$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null)" &&
    source_commit="$(git -C "$git_top" rev-parse --verify HEAD 2>/dev/null)"; then
    source_describe="$(git -C "$git_top" describe --tags --always --dirty 2>/dev/null ||
        printf '%s' "$source_commit")"
    if [[ -n "$(git -C "$git_top" status --porcelain --untracked-files=all)" ]]; then
        source_dirty=true
    else
        source_dirty=false
    fi
    default_epoch="$(git -C "$git_top" show -s --format=%ct HEAD)"
else
    source_commit=uncommitted
    source_describe=uncommitted
    source_dirty=true
    default_epoch=0
fi
[[ "$source_dirty" == false || "$ALLOW_DIRTY" == 1 ]] ||
    die 'Source tree is dirty or has no commit. Commit it, or set DECEPTICON_ALLOW_DIRTY=1 only for a validation build.'
build_epoch="${SOURCE_DATE_EPOCH:-$default_epoch}"
[[ "$build_epoch" =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH must be an integer.'
built_at="$(date -u -d "@$build_epoch" '+%Y-%m-%dT%H:%M:%SZ')"

install -d -m 0750 "$DIST_ROOT"
STAGE_PARENT="$(mktemp -d "$ROOT_DIR/.decepticon-build.XXXXXXXX")"
stage_dir="$STAGE_PARENT/decepticon-vm-datapack"
inner_artifact="$stage_dir/decepticon-custom-vm.tar.gz"
TAR_TMP="$(mktemp "$DIST_ROOT/.decepticon.tar.gz.XXXXXXXX")"
install -d -m 0755 "$stage_dir"

for task_file in "${payload_files[@]}"; do
    case "$task_file" in *.sh) task_mode=0755 ;; *) task_mode=0644 ;; esac
    install -m "$task_mode" "$DATAPACK_SOURCE/$task_file" "$stage_dir/$task_file"
done
install -m 0755 "$VPN_BOOTSTRAP" "$stage_dir/setup-mullvad.sh"

DECEPTICON_VERSION="$VERSION" \
    DECEPTICON_RELEASE_BUILD=1 \
    SOURCE_DATE_EPOCH="$build_epoch" \
    bash "$REPO_ROOT/scripts/make-vm-bundle.sh" "$inner_artifact"
chmod 0644 "$inner_artifact"

bundle_sha="$(sha256sum "$inner_artifact" | awk '{print $1}')"
cat >"$stage_dir/BUILD_INFO" <<EOF
download_version=$VERSION
target=any
source_commit=$source_commit
source_describe=$source_describe
source_dirty=$source_dirty
vpn_source_version=$vpn_source_version
vpn_bootstrap_sha256=$vpn_bootstrap_sha
built_at=$built_at
bundle_sha256=$bundle_sha
EOF
printf '%s\n' "$VERSION" >"$stage_dir/VERSION"
chmod 0644 "$stage_dir/BUILD_INFO" "$stage_dir/VERSION"
(
    cd "$stage_dir"
    sha256sum \
        decepticon-custom-vm.tar.gz \
        bootstrap-decepticon-vm.sh \
        setup-mullvad.sh \
        troubleshoot-decepticon-vm.sh \
        fix-terminal.sh \
        fix-decepticon-postgres.sh \
        VERSION BUILD_INFO README.md >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chmod 0644 "$stage_dir/SHA256SUMS"

expected_members="$(printf '%s\n' \
    BUILD_INFO README.md SHA256SUMS VERSION bootstrap-decepticon-vm.sh \
    decepticon-custom-vm.tar.gz fix-decepticon-postgres.sh fix-terminal.sh \
    setup-mullvad.sh troubleshoot-decepticon-vm.sh | sort)"
actual_members="$(find "$stage_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)"
[[ "$actual_members" == "$expected_members" ]] || {
    diff -u <(printf '%s\n' "$expected_members") <(printf '%s\n' "$actual_members") || true
    die 'Datapack staging does not match the release allowlist.'
}

tar --sort=name --format=posix --owner=0 --group=0 --numeric-owner \
    --mtime="@$build_epoch" --pax-option=delete=atime,delete=ctime \
    -C "$STAGE_PARENT" -cf - decepticon-vm-datapack | gzip -n >"$TAR_TMP"
gzip -t "$TAR_TMP"
tar -tzf "$TAR_TMP" >/dev/null
chmod 0644 "$TAR_TMP"

artifact="$DIST_ROOT/decepticon.tar.gz"
[[ ! -L "$artifact" ]] || die "Refusing symlinked artifact: $artifact"
mv -fT -- "$TAR_TMP" "$artifact"
TAR_TMP=''
printf 'Toolkit Decepticon artifact ready: %s\nVersion: %s\n' "$artifact" "$VERSION"
