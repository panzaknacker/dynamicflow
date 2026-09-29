#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
serving_dir="$(cd "${script_dir}/.." && pwd -P)"
workspace_root="$(cd "${serving_dir}/.." && pwd -P)"
artifact="${TOOLKIT_TEST_DECEPTICON_ARTIFACT:-}"
mock_bin="${script_dir}/mock-bin"
tmpdir=""
server_pid=""

die() {
    printf 'TEST ERROR: %s\n' "$*" >&2
    exit 1
}

assert_decepticon_phase_logs() {
    local bootstrap_log="$1"
    local expected_vpn_only_log=$'argc=1\narg=--vpn-only'
    local expected_vpn_ready_log=$'argc=1\narg=--vpn-ready'

    [[ -f "${bootstrap_log}.vpn-only" ]] || die "decepticon vpn-only phase log is missing"
    [[ "$(cat "${bootstrap_log}.vpn-only")" == "$expected_vpn_only_log" ]] ||
        die "decepticon vpn-only arguments mismatch"
    [[ "$(cat "$bootstrap_log")" == "$expected_vpn_ready_log" ]] ||
        die "decepticon vpn-ready arguments mismatch"
}

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$tmpdir" && -d "$tmpdir" ]]; then
        rm -rf -- "$tmpdir"
    fi
}
trap cleanup EXIT INT TERM HUP

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"

case "$(uname -m)" in
x86_64 | amd64) target=linux-amd64 ;;
aarch64 | arm64) target=linux-arm64 ;;
*) die "Unsupported test architecture: $(uname -m)" ;;
esac

tmpdir="$(mktemp -d)"
download_root="${tmpdir}/downloads"
install_root="${tmpdir}/installed"
mkdir -p "$download_root" "$install_root"
export PATH="${mock_bin}:${PATH}"

if [[ -z "$artifact" ]]; then
    fixture_parent="${tmpdir}/decepticon-fixture"
    fixture_root="${fixture_parent}/decepticon-vm-datapack"
    artifact="${tmpdir}/decepticon-fixture.tar.gz"
    install -d -m 0755 "$fixture_root"
    for fixture_file in bootstrap-decepticon-vm.sh troubleshoot-decepticon-vm.sh \
        fix-terminal.sh fix-decepticon-postgres.sh; do
        install -m 0755 \
            "${workspace_root}/decepticon/decepticon-vm-datapack/${fixture_file}" \
            "${fixture_root}/${fixture_file}"
    done
    install -m 0755 "${workspace_root}/vpn/bootstrap-vpn.sh" \
        "${fixture_root}/setup-mullvad.sh"
    install -m 0644 "${workspace_root}/decepticon/decepticon-vm-datapack/README.md" \
        "${fixture_root}/README.md"
    printf 'test fixture\n' >"${fixture_root}/decepticon-custom-vm.tar.gz"
    printf 'v9.9.0\n' >"${fixture_root}/VERSION"
    printf '%s\n' \
        'download_version=v9.9.0' \
        'source_commit=test-fixture' \
        'source_dirty=true' >"${fixture_root}/BUILD_INFO"
    (
        cd "$fixture_root"
        sha256sum decepticon-custom-vm.tar.gz bootstrap-decepticon-vm.sh \
            setup-mullvad.sh troubleshoot-decepticon-vm.sh fix-terminal.sh \
            fix-decepticon-postgres.sh VERSION BUILD_INFO README.md >SHA256SUMS
    )
    tar -czf "$artifact" -C "$fixture_parent" decepticon-vm-datapack
fi
[[ -f "$artifact" && ! -L "$artifact" ]] || die "Missing or unsafe test artifact: $artifact"

stage_release() {
    local release_target="$1" update_latest=1 tool version source remote_name
    local version_dir remote_file
    shift
    if [[ "${1:-}" == --no-latest ]]; then
        update_latest=0
        shift
    fi
    [[ "$#" -eq 3 ]] || die 'stage_release requires TOOL VERSION ARTIFACT'
    tool="$1"
    version="$2"
    source="$3"
    case "$source" in
    *.tar.gz) remote_name="${tool}.tar.gz" ;;
    *.tar.zst) remote_name="${tool}.tar.zst" ;;
    *.deb) remote_name="${tool}.deb" ;;
    *) remote_name="$tool" ;;
    esac
    version_dir="${download_root}/tools/${tool}/${version}"
    remote_file="${version_dir}/${release_target}/${remote_name}"
    [[ ! -e "$remote_file" ]] || return 1
    install -d -m 0755 "${version_dir}/${release_target}"
    install -m 0644 "$source" "$remote_file"
    (
        cd "$version_dir"
        sha256sum "${release_target}/${remote_name}" >SHA256SUMS
    )
    if [[ "$update_latest" -eq 1 ]]; then
        printf '%s\n' "$version" >"${download_root}/tools/${tool}/latest.txt"
        find "${download_root}/tools" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
            sort >"${download_root}/tools/index.txt"
    fi
}

publish() {
    stage_release "$target" "$@"
}

publish_any() {
    stage_release any "$@"
}

printf '[test] prepare immutable release fixture\n'
publish decepticon v9.9.0 "$artifact" >/dev/null

version_dir="${download_root}/tools/decepticon/v9.9.0"
remote_artifact="${version_dir}/${target}/decepticon.tar.gz"
[[ -f "$remote_artifact" ]] || die "Published artifact is missing"
[[ "$(cat "${download_root}/tools/decepticon/latest.txt")" == v9.9.0 ]] || die "latest.txt mismatch"
[[ "$(cat "${download_root}/tools/index.txt")" == decepticon ]] || die "tools/index.txt mismatch"
[[ "$(wc -l <"${version_dir}/SHA256SUMS")" -eq 1 ]] || die "Checksum manifest must contain exactly one line"
! grep -q 'SHA256SUMS' "${version_dir}/SHA256SUMS" || die "Checksum manifest hashed itself"
(cd "$version_dir" && sha256sum -c SHA256SUMS >/dev/null)

before_sha="$(sha256sum "$remote_artifact" | awk '{print $1}')"
if publish decepticon v9.9.0 "$artifact" >/dev/null 2>&1; then
    die "Publisher overwrote an immutable release"
fi
after_sha="$(sha256sum "$remote_artifact" | awk '{print $1}')"
[[ "$before_sha" == "$after_sha" ]] || die "Immutable artifact changed after rejected republish"

printf '[test] --no-latest leaves index and latest untouched\n'
publish --no-latest decepticon v9.9.1 "$artifact" >/dev/null
[[ "$(cat "${download_root}/tools/decepticon/latest.txt")" == v9.9.0 ]] || die "--no-latest changed latest.txt"
[[ "$(cat "${download_root}/tools/index.txt")" == decepticon ]] || die "--no-latest changed tools/index.txt"

printf '[test] prepare link archive for extraction rejection\n'
link_source="${tmpdir}/link-source"
link_artifact="${tmpdir}/linktest.tar.gz"
mkdir -p "$link_source"
ln -s /tmp "${link_source}/escape"
tar -czf "$link_artifact" -C "$link_source" .
publish --no-latest linktest v9.9.2 "$link_artifact" >/dev/null
printf '[test] prepare ssh-hardening quick-mode archive\n'
quick_source="${tmpdir}/quick-source"
quick_artifact="${tmpdir}/ssh.tar.gz"
mkdir -p "$quick_source"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" "$quick_source/bootstrap-ssh.sh"
tar -czf "$quick_artifact" -C "$quick_source" .
publish ssh v9.9.3 "$quick_artifact" >/dev/null
printf '[test] prepare decepticon quick-mode archive\n'
quick_decepticon_source="${tmpdir}/quick-decepticon-source"
quick_decepticon_artifact="${tmpdir}/decepticon-quick.tar.gz"
mkdir -p "$quick_decepticon_source"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" \
    "$quick_decepticon_source/bootstrap-decepticon-vm.sh"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" \
    "$quick_decepticon_source/setup-mullvad.sh"
tar -czf "$quick_decepticon_artifact" -C "$quick_decepticon_source" .
publish decepticon v9.9.4 "$quick_decepticon_artifact" >/dev/null
publish --no-latest decepticon v9.9.5 "$quick_decepticon_artifact" >/dev/null
publish --no-latest decepticon v9.9.6 "$quick_decepticon_artifact" >/dev/null

printf '[test] progress mock rejects foreign progress paths\n'
foreign_progress_file="${tmpdir}/foreign-progress"
foreign_progress_log="${tmpdir}/foreign-progress-bootstrap.log"
printf 'system\n' >"$foreign_progress_file"
TOOLKIT_TEST_BOOTSTRAP_LOG="$foreign_progress_log" \
    TOOLKIT_ARCHIVE_ROOT="${tmpdir}/expected-progress-root" \
    TOOLKIT_PROGRESS_FILE="$foreign_progress_file" \
    sh "$script_dir/mock-bootstrap-ssh.sh" --vpn-ready
[[ "$(cat "$foreign_progress_file")" == system ]] ||
    die "decepticon progress mock accepted a foreign progress path"
printf '[test] prepare vpn quick-mode any archive\n'
quick_vpn_source="${tmpdir}/quick-vpn-source"
quick_vpn_artifact="${tmpdir}/vpn.tar.gz"
mkdir -p "$quick_vpn_source"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" "$quick_vpn_source/bootstrap-vpn.sh"
tar -czf "$quick_vpn_artifact" -C "$quick_vpn_source" .
publish_any vpn v9.9.7 "$quick_vpn_artifact" >/dev/null
printf '[test] prepare PBP architecture-specific quick-mode archive\n'
quick_pbp_source="${tmpdir}/quick-pbp-source"
quick_pbp_artifact="${tmpdir}/pbp.tar.gz"
mkdir -p "$quick_pbp_source"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" \
    "$quick_pbp_source/bootstrap-pbp.sh"
tar -czf "$quick_pbp_artifact" -C "$quick_pbp_source" .
publish pbp v9.9.8 "$quick_pbp_artifact" >/dev/null
printf '[test] prepare Examstation quick-mode any archive\n'
quick_examstation_source="${tmpdir}/quick-examstation-source"
quick_examstation_artifact="${tmpdir}/examstation.tar.gz"
mkdir -p "$quick_examstation_source"
install -m 0755 "$script_dir/mock-bootstrap-ssh.sh" \
    "$quick_examstation_source/bootstrap-examstation.sh"
tar -czf "$quick_examstation_artifact" -C "$quick_examstation_source" .
publish_any examstation v9.9.9-validation.1 "$quick_examstation_artifact" >/dev/null
install -m 0755 "$serving_dir/install.sh" "$download_root/install.sh"

printf '[test] installer rejects unsafe input before network access\n'
if TOOLKIT_BASE_URL=http://127.0.0.1:1 \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    sh "$serving_dir/install.sh" '../escape' v9.9.0 >/dev/null 2>&1; then
    die "Installer accepted unsafe tool name"
fi
if TOOLKIT_BASE_URL=http://127.0.0.1:1 \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    sh "$serving_dir/install.sh" decepticon '../../escape' >/dev/null 2>&1; then
    die "Installer accepted unsafe version"
fi

printf '[test] local MFA token flow verifies the archive without HEAD\n'
download_password='s"e\cr#et'
download_auth="toolkit:${download_password}"
download_totp=287082
auth_file="${tmpdir}/download-auth.secret"
totp_file="${tmpdir}/download-totp.secret"
printf '%s\n' "$download_auth" >"$auth_file"
printf '%s\n' "$download_totp" >"$totp_file"
chmod 0600 "$auth_file" "$totp_file"
port="$((20000 + ($$ % 20000)))"
python3 "$script_dir/auth-http-server.py" \
    --port "$port" \
    --directory "$download_root" \
    >"${tmpdir}/http.log" 2>&1 &
server_pid=$!

test_token=''
for _ in {1..50}; do
    if test_token="$(printf '%s\n' "$download_totp" | curl --user "$download_auth" -fsS \
        --data-binary @- "http://127.0.0.1:${port}/_toolkit/auth/token" 2>/dev/null)"; then
        break
    fi
    sleep 0.1
done
test_token="${test_token%$'\n'}"
[[ "${#test_token}" -eq 43 ]] || die "Local MFA test server did not start"
curl -H "Authorization: Bearer ${test_token}" -fsS "http://127.0.0.1:${port}/tools/decepticon/latest.txt" >/dev/null ||
    die "Local test server did not start"
[[ "$(curl -H "Authorization: Bearer ${test_token}" -sS -o /dev/null -w '%{http_code}' -I "http://127.0.0.1:${port}/tools/decepticon/v9.9.0/${target}/decepticon.tar.gz")" == 405 ]] ||
    die "Local test server unexpectedly accepted a protected HEAD request"

printf '[test] environment secrets are rejected before authentication\n'
if TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH="$download_auth" \
    TOOLKIT_TOTP="$download_totp" \
    sh "$serving_dir/install.sh" ssh-hardening v9.9.3 >/dev/null 2>&1; then
    die "Installer accepted long-lived authentication secrets from the environment"
fi

printf '[test] ssh-hardening alias authenticates and runs exact bootstrap args\n'
quick_root="${tmpdir}/quick-install"
quick_log="${tmpdir}/quick-bootstrap.log"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$quick_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_log" \
    sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- ssh-hardening v9.9.3' >/dev/null

expected_quick_log=$'argc=2\narg=ssh\narg=--accept-lockout-risk'
[[ "$(cat "$quick_log")" == "$expected_quick_log" ]] || die "ssh-hardening bootstrap arguments mismatch"
[[ -f "${quick_root}/ssh/releases/v9.9.3/bootstrap-ssh.sh" ]] || die "ssh-hardening installed the wrong tool/layout"
[[ "$(readlink "${quick_root}/ssh/current")" == releases/v9.9.3 ]] || die "ssh-hardening current symlink mismatch"

printf '[test] exact decepticon one-liner authenticates and runs its bootstrap\n'
quick_decepticon_root="${tmpdir}/quick-decepticon-install"
quick_decepticon_log="${tmpdir}/quick-decepticon-bootstrap.log"
quick_decepticon_sequence_log="${tmpdir}/quick-decepticon-bootstrap.sequence"
quick_decepticon_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$quick_decepticon_root" \
        TOOLKIT_PROGRESS=plain \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_decepticon_log" \
        TOOLKIT_TEST_BOOTSTRAP_SEQUENCE_LOG="$quick_decepticon_sequence_log" \
        TOOLKIT_TEST_NOISE_LINES=120 \
        sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- decepticon' 2>&1
)"

assert_decepticon_phase_logs "$quick_decepticon_log"
expected_decepticon_sequence=$'--vpn-only\n--vpn-ready'
[[ "$(cat "$quick_decepticon_sequence_log")" == "$expected_decepticon_sequence" ]] ||
    die "decepticon bootstrap did not run vpn-only before vpn-ready"
[[ "$quick_decepticon_output" != *NOISE_STDOUT* && "$quick_decepticon_output" != *NOISE_STDERR* ]] ||
    die "decepticon quick mode streamed bootstrap log noise"
[[ "$quick_decepticon_output" != *$'\033'* && "$quick_decepticon_output" != *$'\r'* ]] ||
    die "plain progress mode emitted terminal control sequences"
[[ "$quick_decepticon_output" == *'Decepticon wird im Hintergrund vorbereitet'* ]] ||
    die "plain progress mode did not print its stable status line"
quick_decepticon_persistent_log="$(
    find "${quick_decepticon_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' -print
)"
[[ -n "$quick_decepticon_persistent_log" && "$(printf '%s\n' "$quick_decepticon_persistent_log" | wc -l)" -eq 1 ]] ||
    die "decepticon quick mode did not create exactly one persistent bootstrap log"
grep -q 'NOISE_STDOUT_0120' "$quick_decepticon_persistent_log" || die "bootstrap stdout was missing from the persistent log"
grep -q 'NOISE_STDERR_0120' "$quick_decepticon_persistent_log" || die "bootstrap stderr was missing from the persistent log"
[[ "$(stat -c '%a' "$quick_decepticon_persistent_log")" == 600 ]] || die "bootstrap log mode is not 600"
if grep -Fq -- "$download_auth" "$quick_decepticon_persistent_log"; then
    die "bootstrap log exposed download credentials"
fi
[[ -f "${quick_decepticon_root}/decepticon/releases/v9.9.4/bootstrap-decepticon-vm.sh" ]] ||
    die "decepticon quick mode installed the wrong tool/layout"
[[ -f "${quick_decepticon_root}/decepticon/releases/v9.9.4/setup-mullvad.sh" ]] ||
    die "decepticon quick mode artifact is missing setup-mullvad.sh"
[[ "$(readlink "${quick_decepticon_root}/decepticon/current")" == releases/v9.9.4 ]] ||
    die "decepticon quick-mode current symlink mismatch"

printf '[test] Docker group exit prints a pinned retry and activates only after rerun\n'
rerun_root="${tmpdir}/rerun-decepticon-install"
rerun_log="${tmpdir}/rerun-decepticon-bootstrap.log"
rerun_state="${tmpdir}/rerun-exit20-once"
if rerun_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$rerun_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$rerun_log" \
        TOOLKIT_TEST_EXIT20_ONCE_FILE="$rerun_state" \
        sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- decepticon v9.9.5' 2>&1
)"; then
    die "decepticon quick mode ignored bootstrap exit 20"
else
    rerun_status=$?
fi
[[ "$rerun_status" -eq 20 ]] || die "decepticon quick mode changed bootstrap exit 20 to $rerun_status"
assert_decepticon_phase_logs "$rerun_log"
[[ "$rerun_output" == *'decepticon v9.9.5'* ]] || die "Docker group retry was not pinned to the verified version"
[[ ! -e "${rerun_root}/decepticon/current" ]] || die "failed bootstrap activated the current symlink"
[[ "$(find "${rerun_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' | wc -l)" -eq 1 ]] ||
    die "Docker group exit did not preserve exactly one bootstrap log"

TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$rerun_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$rerun_log" \
    TOOLKIT_TEST_EXIT20_ONCE_FILE="$rerun_state" \
    sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- decepticon v9.9.5' >/dev/null
assert_decepticon_phase_logs "$rerun_log"
[[ "$(readlink "${rerun_root}/decepticon/current")" == releases/v9.9.5 ]] ||
    die "successful Docker group retry did not activate the verified release"
[[ "$(find "${rerun_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' | wc -l)" -eq 2 ]] ||
    die "Docker group retry did not keep separate attempt logs"

printf '[test] bootstrap failures preserve their exact status and do not activate current\n'
failure_root="${tmpdir}/failure-decepticon-install"
failure_log="${tmpdir}/failure-decepticon-bootstrap.log"
if failure_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$failure_root" \
        TOOLKIT_PROGRESS=plain \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$failure_log" \
        TOOLKIT_TEST_NOISE_LINES=80 \
        TOOLKIT_TEST_EXIT_CODE=42 \
        sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- decepticon v9.9.6' 2>&1
)"; then
    die "decepticon quick mode ignored bootstrap exit 42"
else
    failure_status=$?
fi
[[ "$failure_status" -eq 42 ]] || die "decepticon quick mode changed bootstrap exit 42 to $failure_status"
assert_decepticon_phase_logs "$failure_log"
[[ "$failure_output" == *'Bootstrap failed with exit code 42'* ]] || die "bootstrap failure summary is missing"
[[ "$failure_output" == *'Full log:'* ]] || die "bootstrap failure did not print its log path"
[[ ! -e "${failure_root}/decepticon/current" ]] || die "failed bootstrap activated current"
[[ "$(find "${failure_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' | wc -l)" -eq 1 ]] ||
    die "failed bootstrap did not preserve exactly one log"

printf '[test] TERM stops the installer and its bootstrap process group\n'
signal_root="${tmpdir}/signal-decepticon-install"
signal_log="${tmpdir}/signal-decepticon-bootstrap.log"
signal_output="${tmpdir}/signal-decepticon-output.log"
signal_finish="${tmpdir}/signal-decepticon-finished"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$signal_root" \
    TOOLKIT_PROGRESS=plain \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$signal_log" \
    TOOLKIT_TEST_SLEEP_SECONDS=30 \
    TOOLKIT_TEST_FINISH_FILE="$signal_finish" \
    sh "$serving_dir/install.sh" decepticon v9.9.6 >"$signal_output" 2>&1 &
signal_pid=$!
for _ in {1..100}; do
    [[ -f "$signal_log" ]] && break
    sleep 0.05
done
[[ -f "$signal_log" ]] || die "signal test bootstrap did not start"
assert_decepticon_phase_logs "$signal_log"
kill -TERM "$signal_pid"
if wait "$signal_pid"; then
    die "TERM unexpectedly returned success"
else
    signal_status=$?
fi
[[ "$signal_status" -eq 143 ]] || die "TERM returned $signal_status instead of 143"
sleep 0.3
[[ ! -e "$signal_finish" ]] || die "bootstrap child survived installer TERM"
[[ ! -e "${signal_root}/decepticon/current" ]] || die "TERM-terminated install activated current"
[[ "$(find "${signal_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' | wc -l)" -eq 1 ]] ||
    die "TERM did not preserve exactly one bootstrap log"

printf '[test] exact decepticon one-liner prompts without echo\n'
prompt_decepticon_root="${tmpdir}/prompt-decepticon-install"
prompt_decepticon_log="${tmpdir}/prompt-decepticon-bootstrap.log"
prompt_decepticon_output="$(
    TOOLKIT_TEST_PASSWORD="$download_password" \
        TOOLKIT_TEST_TOTP="$download_totp" \
        TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_ARCHIVE_ROOT="$prompt_decepticon_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$prompt_decepticon_log" \
        TOOLKIT_TEST_NOISE_LINES=80 \
        TOOLKIT_TEST_SLEEP_SECONDS=1 \
        LANG=C.UTF-8 \
        TERM=xterm-256color \
        python3 "$script_dir/pty-password.py" \
        sh "$serving_dir/install.sh" decepticon 2>&1
)"
[[ "$prompt_decepticon_output" == *'Toolkit-Download-Passwort (Benutzer toolkit):'* ]] ||
    die "decepticon quick mode did not use the /dev/tty password prompt"
[[ "$prompt_decepticon_output" != *"$download_password"* ]] ||
    die "decepticon quick-mode password was echoed"
[[ "$prompt_decepticon_output" != *"$download_totp"* ]] ||
    die "decepticon quick-mode TOTP was echoed"
[[ "$prompt_decepticon_output" == *'Toolkit baut Decepticon'* ]] ||
    die "interactive decepticon quick mode did not render its spinner"
[[ "$prompt_decepticon_output" == *'Container-Images'* ]] ||
    die "interactive decepticon spinner did not render the image-build phase"
[[ "$prompt_decepticon_output" == *'●●●●●◉○○'* ]] ||
    die "interactive decepticon spinner did not render the image-build track"
[[ "$prompt_decepticon_output" != *NOISE_STDOUT* && "$prompt_decepticon_output" != *NOISE_STDERR* ]] ||
    die "interactive spinner leaked bootstrap log noise"
assert_decepticon_phase_logs "$prompt_decepticon_log"
prompt_decepticon_persistent_log="$(
    find "${prompt_decepticon_root}/decepticon/logs" -maxdepth 1 -type f -name '*.log' -print
)"
grep -q 'NOISE_STDOUT_0080' "$prompt_decepticon_persistent_log" ||
    die "interactive bootstrap log did not retain stdout"
grep -q 'NOISE_STDERR_0080' "$prompt_decepticon_persistent_log" ||
    die "interactive bootstrap log did not retain stderr"

printf '[test] quick mode disables xtrace before auth expansion\n'
xtrace_root="${tmpdir}/xtrace-install"
xtrace_log="${tmpdir}/xtrace-bootstrap.log"
xtrace_output="${tmpdir}/xtrace-output.log"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$xtrace_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$xtrace_log" \
    sh -x "$serving_dir/install.sh" ssh-hardening v9.9.3 >"$xtrace_output" 2>&1
if grep -Fq -- "$download_auth" "$xtrace_output" || grep -Fq -- "$download_totp" "$xtrace_output"; then
    die "Quick mode exposed password or TOTP while xtrace was active"
fi

printf '[test] /dev/tty password prompt authenticates without echo\n'
prompt_root="${tmpdir}/prompt-install"
prompt_log="${tmpdir}/prompt-bootstrap.log"
prompt_output="$(
    TOOLKIT_TEST_PASSWORD="$download_password" \
        TOOLKIT_TEST_TOTP="$download_totp" \
        TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_ARCHIVE_ROOT="$prompt_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$prompt_log" \
        python3 "$script_dir/pty-password.py" \
        sh "$serving_dir/install.sh" ssh-hardening v9.9.3 2>&1
)"
[[ "$prompt_output" == *'Toolkit-Download-Passwort (Benutzer toolkit):'* ]] || die "Quick mode did not use the /dev/tty password prompt"
[[ "$prompt_output" != *"$download_password"* ]] || die "Quick-mode password was echoed"
[[ "$prompt_output" != *"$download_totp"* ]] || die "Quick-mode TOTP was echoed"
[[ "$(cat "$prompt_log")" == "$expected_quick_log" ]] || die "Prompted ssh-hardening bootstrap arguments mismatch"

printf '[test] ssh-gui-hardening alias selects the GUI mode\n'
quick_gui_root="${tmpdir}/quick-gui-install"
quick_gui_log="${tmpdir}/quick-gui-bootstrap.log"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$quick_gui_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_gui_log" \
    sh "$serving_dir/install.sh" ssh-gui-hardening v9.9.3 >/dev/null

expected_quick_gui_log=$'argc=2\narg=ssh-gui\narg=--accept-lockout-risk'
[[ "$(cat "$quick_gui_log")" == "$expected_quick_gui_log" ]] || die "ssh-gui-hardening bootstrap arguments mismatch"

printf '[test] ssh-gui-clipboard alias explicitly enables clipboard\n'
quick_gui_clipboard_root="${tmpdir}/quick-gui-clipboard-install"
quick_gui_clipboard_log="${tmpdir}/quick-gui-clipboard-bootstrap.log"
quick_gui_clipboard_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$quick_gui_clipboard_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_gui_clipboard_log" \
        sh "$serving_dir/install.sh" ssh-gui-clipboard v9.9.3 2>&1
)"

expected_quick_gui_clipboard_log=$'argc=3\narg=ssh-gui\narg=--gui-clipboard\narg=--accept-lockout-risk'
[[ "$(cat "$quick_gui_clipboard_log")" == "$expected_quick_gui_clipboard_log" ]] ||
    die "ssh-gui-clipboard bootstrap arguments mismatch"
[[ "$quick_gui_clipboard_output" == *'Software in the VM can read clipboard data copied into it.'* ]] ||
    die "ssh-gui-clipboard did not print its trust-boundary warning"

printf '[test] vpn alias selects any artifact and exact zero-argument bootstrap\n'
quick_vpn_root="${tmpdir}/quick-vpn-install"
quick_vpn_log="${tmpdir}/quick-vpn-bootstrap.log"
quick_vpn_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$quick_vpn_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_vpn_log" \
        sh "$serving_dir/install.sh" vpn v9.9.7 2>&1
)"
[[ "$(cat "$quick_vpn_log")" == 'argc=0' ]] || die "vpn quick-mode bootstrap arguments mismatch"
[[ -f "${quick_vpn_root}/vpn/releases/v9.9.7/bootstrap-vpn.sh" ]] || die "vpn installed the wrong any artifact"
[[ "$(readlink "${quick_vpn_root}/vpn/current")" == releases/v9.9.7 ]] || die "vpn current symlink mismatch"
[[ "$quick_vpn_output" == *'Mullvad asks for its account number.'* ]] || die "vpn did not explain its separate secret prompt"
[[ "$quick_vpn_output" == *'Only SSH management stays outside Mullvad'* ]] || die "vpn did not print its SSH/VNC routing state"

printf '[test] TOOLKIT_INSTALL_ONLY skips vpn bootstrap\n'
install_only_vpn_root="${tmpdir}/install-only-vpn"
install_only_vpn_log="${tmpdir}/install-only-vpn.log"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_INSTALL_ONLY=1 \
    TOOLKIT_RUN_BOOTSTRAP=1 \
    TOOLKIT_ARCHIVE_ROOT="$install_only_vpn_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$install_only_vpn_log" \
    sh "$serving_dir/install.sh" vpn v9.9.7 >/dev/null
[[ ! -e "$install_only_vpn_log" ]] || die "TOOLKIT_INSTALL_ONLY ran the vpn bootstrap"
[[ "$(readlink "${install_only_vpn_root}/vpn/current")" == releases/v9.9.7 ]] || die "install-only vpn did not activate archive"

printf '[test] examstation alias selects any artifact and exact zero-argument bootstrap\n'
quick_examstation_root="${tmpdir}/quick-examstation-install"
quick_examstation_log="${tmpdir}/quick-examstation-bootstrap.log"
quick_examstation_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$quick_examstation_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_examstation_log" \
        sh "$serving_dir/install.sh" examstation v9.9.9-validation.1 2>&1
)"
[[ "$(cat "$quick_examstation_log")" == 'argc=0' ]] || die "examstation quick-mode bootstrap arguments mismatch"
[[ -f "${quick_examstation_root}/examstation/releases/v9.9.9-validation.1/bootstrap-examstation.sh" ]] || die "examstation installed the wrong any artifact"
[[ "$(readlink "${quick_examstation_root}/examstation/current")" == releases/v9.9.9-validation.1 ]] || die "examstation current symlink mismatch"
[[ "$quick_examstation_output" == *'shared browser-only examination station.'* ]] || die "examstation quick mode did not explain its purpose"
[[ "$quick_examstation_output" == *'active remote control is visibly indicated.'* ]] || die "examstation quick mode omitted the active-control disclosure"

printf '[test] --PBP pipe alias selects pbp and a zero-argument bootstrap\n'
quick_pbp_root="${tmpdir}/quick-pbp-install"
quick_pbp_log="${tmpdir}/quick-pbp-bootstrap.log"
quick_pbp_output="$(
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_ARCHIVE_ROOT="$quick_pbp_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$quick_pbp_log" \
        sh -c 'curl -fsS "$TOOLKIT_BASE_URL/install.sh" | sh -s -- --PBP v9.9.8' 2>&1
)"
[[ "$(cat "$quick_pbp_log")" == 'argc=0' ]] ||
    die "--PBP quick-mode bootstrap arguments mismatch"
[[ -f "${quick_pbp_root}/pbp/releases/v9.9.8/bootstrap-pbp.sh" ]] ||
    die "--PBP installed the wrong canonical tool/layout"
[[ "$(readlink "${quick_pbp_root}/pbp/current")" == releases/v9.9.8 ]] ||
    die "--PBP current symlink mismatch"
[[ "$quick_pbp_output" == *'PBP Windows-Firefox persona through Mullvad Germany.'* ]] ||
    die "--PBP did not explain its browser persona and exit country"
[[ "$quick_pbp_output" == *'Shadowsocks on port 443'* ]] ||
    die "--PBP did not explain its transport"
[[ "$quick_pbp_output" == *'Mullvad asks for its account number.'* ]] ||
    die "--PBP did not explain its separate Mullvad secret prompt"

printf '[test] canonical pbp alias selects the same verified release\n'
canonical_pbp_root="${tmpdir}/canonical-pbp-install"
canonical_pbp_log="${tmpdir}/canonical-pbp-bootstrap.log"
TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="$canonical_pbp_root" \
    TOOLKIT_TEST_BOOTSTRAP_LOG="$canonical_pbp_log" \
    sh "$serving_dir/install.sh" pbp v9.9.8 >/dev/null
[[ "$(cat "$canonical_pbp_log")" == 'argc=0' ]] ||
    die "pbp quick-mode bootstrap arguments mismatch"
[[ "$(readlink "${canonical_pbp_root}/pbp/current")" == releases/v9.9.8 ]] ||
    die "pbp canonical current symlink mismatch"

printf '[test] TOOLKIT_INSTALL_ONLY skips both PBP aliases\n'
for pbp_alias in --PBP pbp; do
    install_only_pbp_root="${tmpdir}/install-only-${pbp_alias#--}"
    install_only_pbp_log="${install_only_pbp_root}.log"
    TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
        TOOLKIT_ALLOW_INSECURE_HTTP=1 \
        TOOLKIT_AUTH_FILE="$auth_file" \
        TOOLKIT_TOTP_FILE="$totp_file" \
        TOOLKIT_INSTALL_ONLY=1 \
        TOOLKIT_RUN_BOOTSTRAP=1 \
        TOOLKIT_ARCHIVE_ROOT="$install_only_pbp_root" \
        TOOLKIT_TEST_BOOTSTRAP_LOG="$install_only_pbp_log" \
        sh "$serving_dir/install.sh" "$pbp_alias" v9.9.8 >/dev/null
    [[ ! -e "$install_only_pbp_log" ]] ||
        die "TOOLKIT_INSTALL_ONLY ran the $pbp_alias bootstrap"
    [[ "$(readlink "${install_only_pbp_root}/pbp/current")" == releases/v9.9.8 ]] ||
        die "install-only $pbp_alias did not activate canonical pbp"
done

TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_INSTALL_ONLY=1 \
    TOOLKIT_ARCHIVE_ROOT="$install_root" \
    sh "$serving_dir/install.sh" decepticon v9.9.0 >/dev/null

release_dir="${install_root}/decepticon/releases/v9.9.0"
current_link="${install_root}/decepticon/current"
[[ -f "${release_dir}/decepticon-vm-datapack/bootstrap-decepticon-vm.sh" ]] ||
    die "Installer unpacked the archive into an unexpected layout"
[[ -L "$current_link" ]] || die "Current path is not a symlink"
[[ "$(readlink "$current_link")" == releases/v9.9.0 ]] || die "Current symlink target mismatch"
[[ "$(cat "${release_dir}/.toolkit-artifact.sha256")" == "$before_sha" ]] ||
    die "Installed artifact marker mismatch"

printf '[test] archive links are rejected before extraction\n'
if TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="${tmpdir}/link-install" \
    sh "$serving_dir/install.sh" linktest v9.9.2 >/dev/null 2>&1; then
    die "Installer accepted an archive containing a symlink"
fi

printf '[test] checksum mismatch is fatal\n'
printf 'tampered\n' >>"$remote_artifact"
if TOOLKIT_BASE_URL="http://127.0.0.1:${port}" \
    TOOLKIT_ALLOW_INSECURE_HTTP=1 \
    TOOLKIT_AUTH_FILE="$auth_file" \
    TOOLKIT_TOTP_FILE="$totp_file" \
    TOOLKIT_ARCHIVE_ROOT="${tmpdir}/tampered-install" \
    sh "$serving_dir/install.sh" decepticon v9.9.0 >/dev/null 2>&1; then
    die "Installer accepted a tampered artifact"
fi

printf '[test] release flow OK\n'
