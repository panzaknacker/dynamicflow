#!/usr/bin/env bash
set -Eeuo pipefail

: "${TOOLKIT_VPN_TEST_ARGS_LOG:?}"
: "${TOOLKIT_VPN_TEST_STDIN_LOG:?}"
: "${TOOLKIT_VPN_BOOTSTRAP:?}"
TOOLKIT_VPN_TEST_FAILURE_STATE="${TOOLKIT_VPN_TEST_FAILURE_STATE:-${TOOLKIT_VPN_TEST_ARGS_LOG}.state}"
TOOLKIT_VPN_TEST_LOGIN_FAILURES="${TOOLKIT_VPN_TEST_LOGIN_FAILURES:-0}"
[[ "$TOOLKIT_VPN_TEST_LOGIN_FAILURES" =~ ^[0-9]+$ ]]

# shellcheck source=/dev/null
source "$TOOLKIT_VPN_BOOTSTRAP"

mullvad_cmd() {
    {
        printf 'argc=%s\n' "$#"
        for argument in "$@"; do
            printf 'arg=%s\n' "$argument"
        done
    } >>"$TOOLKIT_VPN_TEST_ARGS_LOG"
    IFS= read -r received
    printf '%s\n' "$received" >>"$TOOLKIT_VPN_TEST_STDIN_LOG"
    printf 'x\n' >>"$TOOLKIT_VPN_TEST_FAILURE_STATE"
    calls="$(wc -l <"$TOOLKIT_VPN_TEST_FAILURE_STATE")"
    if ((calls <= TOOLKIT_VPN_TEST_LOGIN_FAILURES)); then
        return 1
    fi
}

prompt_and_login
[[ -z "${ACCOUNT_NUMBER+x}" ]] || die 'Account variable was not unset after login.'
