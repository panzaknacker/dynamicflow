#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DIST_DIR="${TOOLKIT_DIST_DIR:-$ROOT_DIR/dist}"
PACKAGE_NAME='toolkit-ssh'
VERSION_FILE="$ROOT_DIR/VERSION"
readonly VERSION_REGEX='^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'Usage: %s [vX.Y.Z]\n' "${0##*/}"
}

case "${1:-}" in
-h | --help)
    usage
    exit 0
    ;;
esac
[ "$#" -le 1 ] || {
    usage >&2
    exit 2
}

if [ ! -f "$VERSION_FILE" ] || [ -L "$VERSION_FILE" ]; then
    die "Missing or unsafe version file: $VERSION_FILE"
fi
version="${1:-$(tr -d '[:space:]' <"$VERSION_FILE")}"
[[ "$version" =~ $VERSION_REGEX ]] ||
    die "Version should look like v1.2.3: $version"

case "$DIST_DIR" in
/*) ;;
*) die "TOOLKIT_DIST_DIR must be an absolute path: $DIST_DIR" ;;
esac
[ "$DIST_DIR" != '/' ] || die 'Refusing to use / as the Toolkit dist directory.'

for source_file in \
    bootstrap-ssh.sh vm-bootstrap.sh connect-gui.sh \
    make-toolkit-release.sh tests/static-checks.sh \
    VERSION; do
    path="$ROOT_DIR/$source_file"
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        die "Missing or unsafe source file: $path"
    fi
done

bash -n "$ROOT_DIR/bootstrap-ssh.sh"
bash -n "$ROOT_DIR/vm-bootstrap.sh"
bash -n "$ROOT_DIR/connect-gui.sh"
"$ROOT_DIR/tests/static-checks.sh"

[ ! -L "$DIST_DIR" ] || die "Refusing symlinked dist directory: $DIST_DIR"
if [ -e "$DIST_DIR" ] && [ ! -d "$DIST_DIR" ]; then
    die "Dist path is not a directory: $DIST_DIR"
fi
install -d -m 0750 "$DIST_DIR"

build_root="$(mktemp -d "$ROOT_DIR/.toolkit-ssh-build.XXXXXXXX")"
tar_tmp="$(mktemp "$DIST_DIR/.ssh.tar.gz.XXXXXXXX")"
cleanup() {
    rm -rf "$build_root"
    rm -f "$tar_tmp"
}
trap cleanup EXIT HUP INT TERM

payload="$build_root/$PACKAGE_NAME"
install -d -m 0755 "$payload"
install -m 0755 "$ROOT_DIR/bootstrap-ssh.sh" "$payload/bootstrap-ssh.sh"
install -m 0755 "$ROOT_DIR/vm-bootstrap.sh" "$payload/vm-bootstrap.sh"
install -m 0755 "$ROOT_DIR/connect-gui.sh" "$payload/connect-gui.sh"
printf '%s\n' "$version" >"$payload/VERSION"
chmod 0644 "$payload/VERSION"

bash -n "$payload/bootstrap-ssh.sh"
bash -n "$payload/vm-bootstrap.sh"
bash -n "$payload/connect-gui.sh"

(
    cd "$payload"
    sha256sum bootstrap-ssh.sh vm-bootstrap.sh connect-gui.sh VERSION >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chmod 0644 "$payload/SHA256SUMS"

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$build_root" -czf "$tar_tmp" "$PACKAGE_NAME"
chmod 0644 "$tar_tmp"

expected_entries="$(printf '%s\n' \
    "$PACKAGE_NAME" \
    "$PACKAGE_NAME/bootstrap-ssh.sh" \
    "$PACKAGE_NAME/connect-gui.sh" \
    "$PACKAGE_NAME/SHA256SUMS" \
    "$PACKAGE_NAME/VERSION" \
    "$PACKAGE_NAME/vm-bootstrap.sh" | sort)"
actual_entries="$(tar -tzf "$tar_tmp" | sed 's#/$##' | awk 'NF' | sort)"
[ "$actual_entries" = "$expected_entries" ] ||
    die 'Toolkit archive contains an unexpected entry.'

artifact="$DIST_DIR/ssh.tar.gz"
[ ! -L "$artifact" ] || die "Refusing symlinked artifact path: $artifact"
mv -fT "$tar_tmp" "$artifact"
tar_tmp=''

printf 'Toolkit artifact ready: %s\n' "$artifact"
printf 'Version: %s\n' "$version"
printf 'Seal and publish it only through serving/snapshot-current-tools.sh.\n'
