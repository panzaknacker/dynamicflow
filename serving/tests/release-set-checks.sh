#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=''
die() {
    printf 'TEST ERROR: %s\n' "$*" >&2
    exit 1
}
cleanup() { [[ -z "$TMP" ]] || rm -rf -- "$TMP"; }
trap cleanup EXIT HUP INT TERM

if [[ -e "$ROOT/current" || -L "$ROOT/current" ]]; then
    "$ROOT/verify-release-set.sh" "$ROOT/current" >/dev/null
    if find "$ROOT/sources" -type f \( -name '*.pem' -o -name '*.key' -o -name '.env' -o -name '.env.*' ! -name '.env.example' \) -print -quit | grep -q .; then
        die 'sealed sources contain a key or environment secret'
    fi
fi
grep -Fq 'PUBLISH_RELEASE_SET=' "$ROOT/provision-server.sh" || die 'provisioner does not publish a release set'
grep -Fq 'ensure_deploy_identity' "$ROOT/provision-server.sh" || die 'provisioner does not separate deploy identity'
grep -Fq 'TOOLKIT_SSH_IDENTITY="$deploy_key"' "$ROOT/provision-server.sh" || die 'provisioner still publishes with admin key'
grep -Fq 'dbpurgeage = 8d' "$ROOT/server/fail2ban/fail2ban.local" || die 'Fail2ban history is too short'
grep -Fq 'roll_interval 1h' "$ROOT/setup-caddy-mfa.sh" || die 'Caddy log interval is not pinned'
grep -Fq 'roll_keep_for 24h' "$ROOT/setup-caddy-mfa.sh" || die 'Caddy log retention is not pinned'
grep -Fq 'OnUnitActiveSec=1min' "$ROOT/server/toolkit-expire.timer" || die 'expiry timer cadence changed'
grep -Fq '/tools/release-set.tsv' "$ROOT/install.sh" || die 'installer does not use atomic set pointer'
grep -Fq 'Reusing already sealed Decepticon' "$ROOT/snapshot-current-tools.sh" || die 'snapshot builder does not preserve an unchanged immutable Decepticon release'
grep -Fq 'Existing Decepticon artifact has no immutable source snapshot' "$ROOT/snapshot-current-tools.sh" || die 'Decepticon reuse is not tied to an immutable source snapshot'
if grep -Eiq 'examstation|EXAMSTATION' "$ROOT/snapshot-current-tools.sh" "$ROOT/verify-release-set.sh"; then die 'Examstation is still part of the default serving release set'; fi
grep -Fq '[[ "$row_count" -eq 5 ]]' "$ROOT/server/publish-release-set-remote.sh" || die 'Remote publisher does not enforce the five-artifact standard set'
grep -Fq '[[ "$counter" -eq 5 ]]' "$ROOT/publish-release-set.sh" || die 'Local publisher does not enforce the five-artifact standard set'

TMP="$(mktemp -d)"
snapshot_fixture="$TMP/source-snapshot"
mkdir -m 0755 "$snapshot_fixture"
printf 'fixture source\n' >"$snapshot_fixture/VERSION"
{
    printf '%s\n' 'set -Eeuo pipefail'
    sed -n '/^finish_source_snapshot()/,/^}/p' "$ROOT/snapshot-current-tools.sh"
    printf '%s\n' 'finish_source_snapshot "$1" fixture'
} >"$TMP/finish-snapshot.sh"
(umask 077; bash "$TMP/finish-snapshot.sh" "$snapshot_fixture")
[[ "$(stat -c '%a' "$snapshot_fixture/SNAPSHOT-ORIGIN")" == 644 ]] ||
    die 'snapshot origin is not world-readable'
[[ "$(wc -l <"$snapshot_fixture/SOURCE-MANIFEST.tsv")" -eq 2 ]] ||
    die 'source manifest does not cover every source file exactly once'
while IFS=$'\t' read -r mode digest path; do
    [[ "$mode" == "$(stat -c '%a' "$snapshot_fixture/$path")" ]] ||
        die 'source manifest records incorrect file permissions'
    actual="$(sha256sum "$snapshot_fixture/$path")"
    [[ "$digest" == "${actual%% *}" ]] ||
        die 'source manifest records incorrect file contents'
done <"$snapshot_fixture/SOURCE-MANIFEST.tsv"

download_root="$TMP/downloads"
mkdir -p "$download_root"

make_stage() {
    local label="$1" ssh_value="$2"
    stage="$download_root/.release-uploads/$label"
    mkdir -p "$stage"
    : >"$stage/batch.tsv"
    local i=0
    while IFS='|' read -r tool version target name value channel; do
        [[ "$tool" != ssh ]] || value="$ssh_value"
        blob="$(printf 'blob-%04d' "$i")"
        printf '%s' "$value" >"$stage/$blob"
        size="$(stat -c '%s' "$stage/$blob")"
        sha="$(sha256sum "$stage/$blob")"
        sha="${sha%% *}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tool" "$version" "$target" "$name" "$size" "$sha" "$channel" "$blob" >>"$stage/batch.tsv"
        i=$((i + 1))
    done <<'ROWS'
ssh|v1.0.0|any|ssh.tar.gz|ssh-bytes|production
vpn|v1.0.0|any|vpn.tar.gz|vpn-bytes|production
pbp|v1.0.0|linux-amd64|pbp.tar.gz|pbp-amd64|production
pbp|v1.0.0|linux-arm64|pbp.tar.gz|pbp-arm64|production
decepticon|v1.0.0-validation.1|any|decepticon.tar.gz|decepticon-bytes|validation
ROWS
}

make_stage first ssh-bytes
bash "$ROOT/server/publish-release-set-remote.sh" "$download_root" "$stage" set-test-1 >/dev/null
[[ "$(wc -l <"$download_root/tools/pbp/v1.0.0/SHA256SUMS")" -eq 2 ]] ||
    die 'PBP multiarch manifest does not contain both targets'
[[ "$(stat -c '%a' "$download_root/tools/ssh/v1.0.0")" == 755 ]] ||
    die 'Release version directory is not traversable by Caddy'
first_sha="$(sha256sum "$download_root/tools/ssh/v1.0.0/any/ssh.tar.gz")"
first_sha="${first_sha%% *}"

make_stage retry ssh-bytes
bash "$ROOT/server/publish-release-set-remote.sh" "$download_root" "$stage" set-test-1 >/dev/null
[[ "$(cat "$download_root/tools/release-set-id.txt")" == set-test-1 ]] ||
    die 'idempotent retry changed set id'

make_stage conflict changed-ssh-bytes
if bash "$ROOT/server/publish-release-set-remote.sh" "$download_root" "$stage" set-test-2 >/dev/null 2>&1; then
    die 'conflicting immutable release was accepted'
fi
after_sha="$(sha256sum "$download_root/tools/ssh/v1.0.0/any/ssh.tar.gz")"
after_sha="${after_sha%% *}"
[[ "$first_sha" == "$after_sha" ]] || die 'conflict changed existing immutable bytes'
[[ "$(cat "$download_root/tools/release-set-id.txt")" == set-test-1 ]] ||
    die 'conflict changed active metadata'

if TOOLKIT_SSH_IDENTITY=/definitely/missing TOOLKIT_DRY_RUN=1 "$ROOT/publish-release-set.sh" >/dev/null 2>&1; then
    die 'release publisher accepted a missing identity'
fi

printf 'Release-set, multiarch, idempotency, conflict and security checks passed.\n'
