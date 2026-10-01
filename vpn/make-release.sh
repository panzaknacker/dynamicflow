#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DIST_DIR="${TOOLKIT_DIST_DIR:-$ROOT_DIR/dist}"
VERSION_FILE="$ROOT_DIR/VERSION"
PACKAGE_NAME='toolkit-vpn'
readonly VERSION_REGEX='^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

case "${1:-}" in
-h | --help)
    printf 'Usage: %s [vX.Y.Z]\n' "${0##*/}"
    exit 0
    ;;
esac
[[ "$#" -le 1 ]] || die "Usage: ${0##*/} [vX.Y.Z]"

for source_file in bootstrap-vpn.sh VERSION; do
    [[ -f "$ROOT_DIR/$source_file" && ! -L "$ROOT_DIR/$source_file" ]] ||
        die "Missing or unsafe source file: $ROOT_DIR/$source_file"
done
version="${1:-$(tr -d '[:space:]' <"$VERSION_FILE")}"
[[ "$version" =~ $VERSION_REGEX ]] || die "Invalid version: $version"
case "$DIST_DIR" in /*) ;; *) die 'TOOLKIT_DIST_DIR must be absolute.' ;; esac
[[ "$DIST_DIR" != '/' && ! -L "$DIST_DIR" ]] || die "Unsafe dist directory: $DIST_DIR"

bash -n "$ROOT_DIR/bootstrap-vpn.sh"
install -d -m 0750 "$DIST_DIR"
build_root="$(mktemp -d "$ROOT_DIR/.toolkit-vpn-build.XXXXXXXX")"
tar_tmp="$(mktemp "$DIST_DIR/.vpn.tar.gz.XXXXXXXX")"
cleanup() {
    rm -rf -- "$build_root"
    rm -f -- "$tar_tmp"
}
trap cleanup EXIT HUP INT TERM

payload="$build_root/$PACKAGE_NAME"
install -d -m 0755 "$payload"
install -m 0755 "$ROOT_DIR/bootstrap-vpn.sh" "$payload/bootstrap-vpn.sh"
printf '%s\n' "$version" >"$payload/VERSION"
chmod 0644 "$payload/VERSION"
(
    cd "$payload"
    sha256sum bootstrap-vpn.sh VERSION >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chmod 0644 "$payload/SHA256SUMS"

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$build_root" -czf "$tar_tmp" "$PACKAGE_NAME"
chmod 0644 "$tar_tmp"

expected_entries="$(printf '%s\n' \
    "$PACKAGE_NAME" \
    "$PACKAGE_NAME/SHA256SUMS" \
    "$PACKAGE_NAME/VERSION" \
    "$PACKAGE_NAME/bootstrap-vpn.sh" | sort)"
actual_entries="$(tar -tzf "$tar_tmp" | sed 's#/$##' | awk 'NF' | sort)"
[[ "$actual_entries" == "$expected_entries" ]] ||
    die 'Toolkit VPN archive contains unexpected entries.'

artifact="$DIST_DIR/vpn.tar.gz"
[[ ! -L "$artifact" ]] || die "Refusing symlinked artifact path: $artifact"
mv -fT -- "$tar_tmp" "$artifact"
tar_tmp=''
printf 'Toolkit VPN artifact ready: %s\nVersion: %s\n' "$artifact" "$version"
