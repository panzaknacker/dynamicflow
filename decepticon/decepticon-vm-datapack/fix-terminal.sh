#!/usr/bin/env bash
# use this with: source ./fix-terminal.sh
if [[ -n "${TERM:-}" ]] && ! infocmp "$TERM" >/dev/null 2>&1; then
    export TERM=xterm-256color
fi
if [[ "${TERM:-}" = "xterm-kitty" ]] && ! infocmp xterm-kitty >/dev/null 2>&1; then
    export TERM=xterm-256color
fi
printf 'TERM=%s\n' "$TERM"
