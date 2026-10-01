#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DIST_ROOT="${TOOLKIT_DIST_DIR:-$ROOT_DIR/dist}"
VPN_BOOTSTRAP="${TOOLKIT_VPN_BOOTSTRAP:-$ROOT_DIR/../vpn/bootstrap-vpn.sh}"
PACKAGE_NAME='toolkit-pbp'
ARTIFACT_NAME='pbp.tar.gz'
DISPOSABLE_TEST_RUN=0
ARCH=''
VERSION=''
BUILD_ROOT=''
TAR_TMP=''
readonly VERSION_RE='^v[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9][A-Za-z0-9._-]*)?$'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    if [[ -n "$BUILD_ROOT" && -d "$BUILD_ROOT" ]]; then
        rm -rf -- "$BUILD_ROOT"
    fi
    if [[ -n "$TAR_TMP" && -f "$TAR_TMP" ]]; then
        rm -f -- "$TAR_TMP"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

case "${1:-}" in
-h | --help)
    printf '%s\n' \
        "Usage: ${0##*/} <amd64|arm64> [vX.Y.Z]" \
        "       ${0##*/} --disposable-test-run <amd64|arm64> [vX.Y.Z]"
    exit 0
    ;;
--disposable-test-run)
    DISPOSABLE_TEST_RUN=1
    PACKAGE_NAME='toolkit-pbp-disposable-test'
    ARTIFACT_NAME='pbp-disposable-test.tar.gz'
    shift
    ;;
esac
[[ "$#" -ge 1 && "$#" -le 2 ]] ||
    die "Usage: ${0##*/} [--disposable-test-run] <amd64|arm64> [vX.Y.Z]"
ARCH="$1"
VERSION="${2:-}"
case "$ARCH" in amd64 | arm64) ;; *) die "Unsupported architecture: $ARCH" ;; esac
VERSION="${VERSION:-$(tr -d '[:space:]' <"$ROOT_DIR/VERSION")}"
[[ "$VERSION" =~ $VERSION_RE ]] || die "Invalid PBP version: $VERSION"
if [[ "$DISPOSABLE_TEST_RUN" == '1' ]]; then
    VERSION="${VERSION}-disposable-test"
fi
case "$DIST_ROOT" in /*) ;; *) die 'TOOLKIT_DIST_DIR must be absolute.' ;; esac
[[ "$DIST_ROOT" != '/' && ! -L "$DIST_ROOT" ]] ||
    die "Unsafe dist directory: $DIST_ROOT"

for source in bootstrap-pbp.sh launch-pbp.py safe-extract.py \
    browser-maintenance.py requirements.lock \
    browser-assets.lock browser-security-policy.json browser-hardening-policy.json \
    browser-search-policy.json \
    VERSION apparmor/toolkit-pbp; do
    [[ -f "$ROOT_DIR/$source" && ! -L "$ROOT_DIR/$source" ]] ||
        die "Missing or unsafe PBP source: $source"
done
[[ -f "$VPN_BOOTSTRAP" && ! -L "$VPN_BOOTSTRAP" ]] ||
    die "Missing or unsafe VPN bootstrap: $VPN_BOOTSTRAP"
bash -n "$ROOT_DIR/bootstrap-pbp.sh"
bash -n "$VPN_BOOTSTRAP"
PYTHONPYCACHEPREFIX="$ROOT_DIR/.pycache-check" \
    python3 -m py_compile "$ROOT_DIR/launch-pbp.py" "$ROOT_DIR/safe-extract.py" \
    "$ROOT_DIR/browser-maintenance.py"
rm -rf -- "$ROOT_DIR/.pycache-check"
if [[ "$DISPOSABLE_TEST_RUN" == '1' ]]; then
    python3 "$ROOT_DIR/browser-maintenance.py" disposable-test
else
    python3 "$ROOT_DIR/browser-maintenance.py" release
fi

VENDOR="$ROOT_DIR/vendor/$ARCH"
[[ -d "$VENDOR" && ! -L "$VENDOR" &&
    -f "$VENDOR/.toolkit-pbp-vendor" &&
    "$(tr -d '\r\n' <"$VENDOR/.toolkit-pbp-vendor")" == 'toolkit-pbp-vendor-v1' ]] ||
    die "Run fetch-vendor.sh $ARCH before building PBP."
(
    cd "$VENDOR"
    sha256sum -c --quiet SHA256SUMS
)
locked_browser_hash="$(
    awk -v key="browser_${ARCH}_sha256" '$1 == key {print $2}' \
        "$ROOT_DIR/browser-assets.lock"
)"
locked_ublock_hash="$(
    awk '$1 == "ublock_sha256" {print $2}' "$ROOT_DIR/browser-assets.lock"
)"
[[ "$(sha256sum "$VENDOR/camoufox.zip" | awk '{print $1}')" == "$locked_browser_hash" &&
"$(sha256sum "$VENDOR/ublock-origin.xpi" | awk '{print $1}')" == "$locked_ublock_hash" ]] ||
    die 'Vendor browser or uBlock asset does not match browser-assets.lock.'
current_asset_lock="$(sha256sum "$ROOT_DIR/browser-assets.lock" | awk '{print $1}')"
current_requirements="$(sha256sum "$ROOT_DIR/requirements.lock" | awk '{print $1}')"
expected_asset_lock="$(awk '$2 == "browser-assets.lock" {print $1}' \
    "$VENDOR/SOURCE_LOCK_SHA256SUMS")"
expected_requirements="$(awk '$2 == "requirements.lock" {print $1}' \
    "$VENDOR/SOURCE_LOCK_SHA256SUMS")"
[[ "$current_asset_lock" == "$expected_asset_lock" &&
    "$current_requirements" == "$expected_requirements" ]] ||
    die 'Vendor cache was built from different source locks.'
for asset in camoufox.zip ublock-origin.xpi python/cp311.tar.gz \
    python/cp312.tar.gz python/cp313.tar.gz; do
    [[ -f "$VENDOR/$asset" && ! -L "$VENDOR/$asset" ]] ||
        die "Missing or unsafe vendor asset: $asset"
done

if [[ "$DISPOSABLE_TEST_RUN" == '1' ]]; then
    OUTPUT_DIR="$DIST_ROOT/disposable-test/linux-$ARCH"
else
    OUTPUT_DIR="$DIST_ROOT/linux-$ARCH"
fi
install -d -m 0750 "$OUTPUT_DIR"
BUILD_ROOT="$(mktemp -d "$ROOT_DIR/.toolkit-pbp-build.XXXXXXXX")"
TAR_TMP="$(mktemp "$OUTPUT_DIR/.${ARTIFACT_NAME}.XXXXXXXX")"
PAYLOAD="$BUILD_ROOT/$PACKAGE_NAME"
install -d -m 0755 "$PAYLOAD" "$PAYLOAD/apparmor" "$PAYLOAD/assets" "$PAYLOAD/python"
install -m 0755 "$ROOT_DIR/bootstrap-pbp.sh" "$PAYLOAD/bootstrap-pbp.sh"
install -m 0755 "$VPN_BOOTSTRAP" "$PAYLOAD/toolkit-vpn-stage"
install -m 0755 "$ROOT_DIR/launch-pbp.py" "$PAYLOAD/launch-pbp.py"
install -m 0755 "$ROOT_DIR/safe-extract.py" "$PAYLOAD/safe-extract.py"
install -m 0755 "$ROOT_DIR/browser-maintenance.py" "$PAYLOAD/browser-maintenance.py"
install -m 0644 "$ROOT_DIR/requirements.lock" "$PAYLOAD/requirements.lock"
install -m 0644 "$ROOT_DIR/browser-assets.lock" "$PAYLOAD/browser-assets.lock"
install -m 0644 "$ROOT_DIR/browser-security-policy.json" \
    "$PAYLOAD/browser-security-policy.json"
install -m 0644 "$ROOT_DIR/browser-hardening-policy.json" \
    "$PAYLOAD/browser-hardening-policy.json"
install -m 0644 "$ROOT_DIR/browser-search-policy.json" "$PAYLOAD/browser-search-policy.json"
install -m 0644 "$ROOT_DIR/apparmor/toolkit-pbp" "$PAYLOAD/apparmor/toolkit-pbp"
install -m 0644 "$VENDOR/camoufox.zip" "$PAYLOAD/assets/camoufox.zip"
install -m 0644 "$VENDOR/ublock-origin.xpi" "$PAYLOAD/assets/ublock-origin.xpi"
for tag in cp311 cp312 cp313; do
    install -m 0644 "$VENDOR/python/${tag}.tar.gz" "$PAYLOAD/python/${tag}.tar.gz"
done
printf '%s\n' "$VERSION" >"$PAYLOAD/VERSION"
printf '%s\n' "$ARCH" >"$PAYLOAD/ARCH"
chmod 0644 "$PAYLOAD/VERSION" "$PAYLOAD/ARCH"
if [[ "$DISPOSABLE_TEST_RUN" == '1' ]]; then
    python3 "$ROOT_DIR/browser-maintenance.py" disposable-test --json \
        >"$PAYLOAD/DISPOSABLE-TEST-GATE.json"
    chmod 0644 "$PAYLOAD/DISPOSABLE-TEST-GATE.json"
fi
(
    cd "$PAYLOAD"
    find . -type f ! -name SHA256SUMS -printf '%P\0' |
        sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c --quiet SHA256SUMS
)
chmod 0644 "$PAYLOAD/SHA256SUMS"

bootstrap_count="$(
    find "$PAYLOAD" -maxdepth 3 -type f \
        \( -name bootstrap.sh -o -name 'bootstrap-*.sh' \) | wc -l
)"
[[ "$bootstrap_count" -eq 1 && -f "$PAYLOAD/bootstrap-pbp.sh" ]] ||
    die 'PBP payload must contain exactly one bootstrap script.'
if find "$PAYLOAD" -xdev ! -type d ! -type f -print -quit | grep -q .; then
    die 'PBP payload contains a link or unsupported file type.'
fi

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$BUILD_ROOT" -cf - "$PACKAGE_NAME" | gzip -n >"$TAR_TMP"
chmod 0644 "$TAR_TMP"
if tar -tvzf "$TAR_TMP" | awk '$1 !~ /^[d-]/ { bad = 1 } END { exit bad ? 0 : 1 }'; then
    die 'PBP archive contains a link or unsupported member type.'
fi
archive_bootstraps="$(
    tar -tzf "$TAR_TMP" |
        awk -F/ '$NF == "bootstrap.sh" || $NF ~ /^bootstrap-.*[.]sh$/ {count++} END {print count+0}'
)"
[[ "$archive_bootstraps" -eq 1 ]] ||
    die 'PBP archive bootstrap count changed unexpectedly.'

ARTIFACT="$OUTPUT_DIR/$ARTIFACT_NAME"
[[ ! -L "$ARTIFACT" ]] || die "Refusing symlinked artifact: $ARTIFACT"
mv -fT -- "$TAR_TMP" "$ARTIFACT"
TAR_TMP=''
if [[ "$DISPOSABLE_TEST_RUN" == '1' ]]; then
    printf 'Toolkit PBP TEST-ONLY artifact ready: %s\nVersion: %s\nArchitecture: %s\n' \
        "$ARTIFACT" "$VERSION" "$ARCH"
else
    printf 'Toolkit PBP artifact ready: %s\nVersion: %s\nArchitecture: %s\n' \
        "$ARTIFACT" "$VERSION" "$ARCH"
fi
