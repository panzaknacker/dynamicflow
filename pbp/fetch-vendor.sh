#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
UV_BIN="${TOOLKIT_UV_BIN:-$(command -v uv 2>/dev/null || true)}"
PATH='/usr/local/bin:/usr/bin:/bin'
export PATH
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LOCK_FILE="$ROOT_DIR/browser-assets.lock"
REQUIREMENTS="$ROOT_DIR/requirements.lock"
VENDOR_ROOT="$ROOT_DIR/vendor"
ARCH="${1:-}"
BUILD_DIR=''

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    if [[ -n "$BUILD_DIR" && -d "$BUILD_DIR" ]]; then
        rm -rf -- "$BUILD_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

lock_value() {
    local key="$1"
    awk -v key="$key" '
    $1 == key { count += 1; value = $2 }
    END { if (count == 1 && value != "") print value; else exit 1 }
  ' "$LOCK_FILE"
}

[[ "$#" -eq 1 ]] || die "Usage: ${0##*/} <amd64|arm64>"
case "$ARCH" in
amd64) UV_PLATFORM='x86_64-manylinux_2_28' ;;
arm64) UV_PLATFORM='aarch64-manylinux_2_28' ;;
*) die "Unsupported architecture: $ARCH" ;;
esac
for command in awk curl find gzip python3 sha256sum sort tar; do
    command -v "$command" >/dev/null 2>&1 || die "Missing build command: $command"
done
case "$UV_BIN" in /*) ;; *) die 'Missing build command: uv' ;; esac
[[ -f "$UV_BIN" && ! -L "$UV_BIN" && -x "$UV_BIN" ]] ||
    die "Unsafe uv build command: $UV_BIN"
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" &&
    -f "$REQUIREMENTS" && ! -L "$REQUIREMENTS" &&
    -f "$ROOT_DIR/safe-extract.py" && ! -L "$ROOT_DIR/safe-extract.py" ]] ||
    die 'Missing or unsafe PBP lock files.'

BUILD_DIR="$(mktemp -d "$ROOT_DIR/.toolkit-pbp-vendor.XXXXXXXX")"
OUTPUT="$BUILD_DIR/$ARCH"
mkdir -m 0755 "$OUTPUT" "$OUTPUT/python"
printf 'toolkit-pbp-vendor-v1\n' >"$OUTPUT/.toolkit-pbp-vendor"

download_verified() {
    local url="$1" expected="$2" destination="$3"
    local part="${destination}.part"
    curl --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 5 --retry-delay 2 --retry-all-errors \
        --output "$part" "$url"
    printf '%s  %s\n' "$expected" "$part" | sha256sum -c - >/dev/null ||
        die "Pinned SHA-256 mismatch for $url"
    mv -fT -- "$part" "$destination"
    chmod 0644 "$destination"
}

browser_url="$(lock_value "browser_${ARCH}_url")" ||
    die 'Missing pinned browser URL.'
browser_sha="$(lock_value "browser_${ARCH}_sha256")" ||
    die 'Missing pinned browser hash.'
ublock_url="$(lock_value ublock_url)" || die 'Missing pinned uBlock URL.'
ublock_sha="$(lock_value ublock_sha256)" || die 'Missing pinned uBlock hash.'
download_verified "$browser_url" "$browser_sha" "$OUTPUT/camoufox.zip"
download_verified "$ublock_url" "$ublock_sha" "$OUTPUT/ublock-origin.xpi"

browser_check="$BUILD_DIR/browser-check"
mkdir -m 0755 "$browser_check"
python3 "$ROOT_DIR/safe-extract.py" zip "$OUTPUT/camoufox.zip" \
    "$browser_check" --max-bytes 1610612736
[[ -f "$browser_check/camoufox-bin" &&
    ! -L "$browser_check/camoufox-bin" &&
    -x "$browser_check/camoufox-bin" &&
    -f "$browser_check/libxul.so" &&
    ! -L "$browser_check/libxul.so" ]] ||
    die 'Pinned Camoufox archive is missing its executable browser runtime.'
rm -rf -- "$browser_check"

build_python_runtime() {
    local python_version="$1" tag="$2"
    local target="$BUILD_DIR/site-${tag}" archive="$OUTPUT/python/${tag}.tar.gz"
    local -a entries=()

    mkdir -m 0755 "$target"
    "$UV_BIN" pip install \
        --target "$target" \
        --python-version "$python_version" \
        --python-platform "$UV_PLATFORM" \
        --require-hashes \
        --only-binary=:all: \
        --no-config \
        --link-mode=copy \
        --requirements "$REQUIREMENTS"
    rm -rf -- "$target/bin"
    find "$target" -type d -name __pycache__ -prune -exec rm -rf -- {} +
    find "$target" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
    mapfile -d '' -t entries < <(
        find "$target" -mindepth 1 -maxdepth 1 -printf '%f\0' | sort -z
    )
    [[ "${#entries[@]}" -gt 0 ]] || die "Empty Python runtime: $tag"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        -C "$target" -cf - "${entries[@]}" | gzip -n >"$archive"
    chmod 0644 "$archive"
}

build_python_runtime 3.11 cp311
build_python_runtime 3.12 cp312
build_python_runtime 3.13 cp313

(
    cd "$OUTPUT"
    sha256sum camoufox.zip ublock-origin.xpi python/cp311.tar.gz \
        python/cp312.tar.gz python/cp313.tar.gz >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
{
    printf '%s  browser-assets.lock\n' "$(sha256sum "$LOCK_FILE" | awk '{print $1}')"
    printf '%s  requirements.lock\n' "$(sha256sum "$REQUIREMENTS" | awk '{print $1}')"
} >"$OUTPUT/SOURCE_LOCK_SHA256SUMS"
chmod 0644 "$OUTPUT/SHA256SUMS" "$OUTPUT/SOURCE_LOCK_SHA256SUMS" \
    "$OUTPUT/.toolkit-pbp-vendor"

destination="$VENDOR_ROOT/$ARCH"
if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" &&
        -f "$destination/.toolkit-pbp-vendor" &&
        "$(tr -d '\r\n' <"$destination/.toolkit-pbp-vendor")" == 'toolkit-pbp-vendor-v1' ]] ||
        die "Refusing to replace an unmanaged vendor path: $destination"
    rm -rf -- "$destination"
fi
mv -T -- "$OUTPUT" "$destination"
printf 'Verified PBP vendor cache ready: %s\n' "$destination"
