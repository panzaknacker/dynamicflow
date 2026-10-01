#!/usr/bin/env bash
# Local walkthrough with disposable state; no target hosts are contacted.
set -Eeuo pipefail

if (($# != 0)); then
    if [[ $# == 1 && ($1 == --help || $1 == -h) ]]; then
        printf '%s\n' 'Usage: scripts/portfolio-demo.sh' \
            'Builds flow, uses temporary local state, inspects profiles, runs one' \
            'signature regression test, and checks the current remote-route gate.' \
            'Requires Linux, Go (go.mod), make, bash, ssh and ssh-keygen.' \
            'The first build may fetch the pinned Go modules; no deployment occurs.'
        exit 0
    fi
    printf '%s\n' 'No arguments are accepted. Use --help for prerequisites.' >&2
    exit 2
fi

demo_repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$demo_repo_root"
demo_go="${GO:-go}"
for demo_tool in "$demo_go" make ssh ssh-keygen; do
    command -v "$demo_tool" >/dev/null || {
        printf 'Missing prerequisite: %s\nRun scripts/portfolio-demo.sh --help for prerequisites.\n' "$demo_tool" >&2
        exit 1
    }
done

umask 077
demo_state_dir="$(mktemp -d "${TMPDIR:-/tmp}/dynamicflow-demo.XXXXXXXX")"
cleanup() {
    case "$demo_state_dir" in
    "${TMPDIR:-/tmp}"/dynamicflow-demo.*) rm -rf -- "$demo_state_dir" ;;
    *) printf '%s\n' 'Refusing unexpected temporary cleanup path.' >&2 ;;
    esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

flow_demo() {
    "$demo_repo_root/.flow/bin/flow" --home "$demo_state_dir" \
        --source-root "$demo_repo_root" "$@"
}

printf '\n1/5 — Build the CLI and identify the version\n'
make build GO="$demo_go"
flow_demo --version

printf '\n2/5 — Initialize isolated local state and check prerequisites\n'
flow_demo init
flow_demo doctor

printf '\n3/5 — Inspect available profiles and the PBP dependency graph\n'
flow_demo profile list
flow_demo profile show pbp

printf '\n4/5 — Run the real signature regression test with synthetic data\n'
printf '%s\n' 'Checks: valid value accepted; changed value, wrong domain and wrong key rejected.'
GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 \
    "$demo_go" test -count=1 -v \
    -run '^TestCanonicalSignatureBindsDomainAndValue$' ./internal/signing

printf '\n5/5 — Confirm the unfinished remote route stays blocked\n'
demo_gate_status=0
flow_demo --json instance status demo-node \
    >"$demo_state_dir/gate.stdout" 2>"$demo_state_dir/gate.stderr" || demo_gate_status=$?
if [[ "$demo_gate_status" != 6 || -s "$demo_state_dir/gate.stdout" ]] ||
    ! grep -Fq '"code":"control_route_unavailable"' "$demo_state_dir/gate.stderr"; then
    printf '%s\n' 'Unexpected remote-gate behavior; demo failed.' >&2
    cat -- "$demo_state_dir/gate.stdout" "$demo_state_dir/gate.stderr" >&2
    exit 1
fi
cat -- "$demo_state_dir/gate.stderr"
printf '%s\n' 'Expected rejection verified (exit 6); no target was contacted.'

printf '\nDemo passed. Temporary operator state and keys are removed on exit.\n'
printf '%s\n' 'Scope: local core only. Run make check for the full core gate.'
