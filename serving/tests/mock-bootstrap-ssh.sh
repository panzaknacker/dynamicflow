#!/bin/sh
set -eu

: "${TOOLKIT_TEST_BOOTSTRAP_LOG:?}"
if [ -n "${TOOLKIT_AUTH:-}" ]; then
    echo "TOOLKIT_AUTH leaked into the quick-mode bootstrap." >&2
    exit 91
fi

bootstrap_log="$TOOLKIT_TEST_BOOTSTRAP_LOG"
bootstrap_phase="${1:-default}"
if [ "$bootstrap_phase" = "--vpn-only" ]; then
    bootstrap_log="${TOOLKIT_TEST_BOOTSTRAP_LOG}.vpn-only"
fi

{
    printf "argc=%s\n" "$#"
    for argument in "$@"; do
        printf "arg=%s\n" "$argument"
    done
} >"$bootstrap_log"

if [ -n "${TOOLKIT_TEST_BOOTSTRAP_SEQUENCE_LOG:-}" ]; then
    printf '%s\n' "$bootstrap_phase" >>"$TOOLKIT_TEST_BOOTSTRAP_SEQUENCE_LOG"
fi

# VPN preparation is a separate first phase. it must succeed independently;
# failure, retry and signal fixtures below are reserved for the main bootstrap.
if [ "$bootstrap_phase" = "--vpn-only" ]; then
    exit 0
fi

if [ "$bootstrap_phase" = "--vpn-ready" ]; then
    progress_file="${TOOLKIT_PROGRESS_FILE:-}"
    progress_root="${TOOLKIT_ARCHIVE_ROOT:-}"
    progress_name=""

    if [ -n "$progress_file" ] && [ -n "$progress_root" ]; then
        progress_prefix="${progress_root%/}/decepticon/logs/"
        case "$progress_file" in
        "$progress_prefix"*)
            progress_name="${progress_file#"$progress_prefix"}"
            ;;
        *) ;;
        esac
    fi

    case "$progress_name" in
    '' | */*) ;;
    *)
        if [ -f "$progress_file" ] && [ ! -L "$progress_file" ] && [ -O "$progress_file" ]; then
            printf 'images\n' >"$progress_file"
        fi
        ;;
    esac
fi

noise_lines="${TOOLKIT_TEST_NOISE_LINES:-0}"
case "$noise_lines" in
'' | *[!0-9]*)
    echo "invalid TOOLKIT_TEST_NOISE_LINES" >&2
    exit 92
    ;;
esac
noise_index=1
while [ "$noise_index" -le "$noise_lines" ]; do
    printf 'NOISE_STDOUT_%04d\n' "$noise_index"
    printf 'NOISE_STDERR_%04d\n' "$noise_index" >&2
    noise_index=$((noise_index + 1))
done

if [ -n "${TOOLKIT_TEST_SLEEP_SECONDS:-}" ]; then
    sleep "$TOOLKIT_TEST_SLEEP_SECONDS"
fi

if [ -n "${TOOLKIT_TEST_FINISH_FILE:-}" ]; then
    : >"$TOOLKIT_TEST_FINISH_FILE"
fi

if [ -n "${TOOLKIT_TEST_EXIT20_ONCE_FILE:-}" ] && [ ! -e "$TOOLKIT_TEST_EXIT20_ONCE_FILE" ]; then
    : >"$TOOLKIT_TEST_EXIT20_ONCE_FILE"
    exit 20
fi

if [ -n "${TOOLKIT_TEST_EXIT_CODE:-}" ]; then
    exit "$TOOLKIT_TEST_EXIT_CODE"
fi
