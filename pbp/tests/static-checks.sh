#!/usr/bin/env bash
set -Eeuo pipefail

report_failure() {
    local status=$?
    printf 'TEST ERROR: PBP static-checks failed at line %s (exit %s).\n' \
        "$1" "$status" >&2
    exit "$status"
}
trap 'report_failure "$LINENO"' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM

for script in bootstrap-pbp.sh fetch-vendor.sh make-release.sh tests/static-checks.sh; do
    bash -n "$ROOT_DIR/$script"
done
PYTHONPYCACHEPREFIX="$TMP_DIR/pycache" python3 -m py_compile \
    "$ROOT_DIR/launch-pbp.py" "$ROOT_DIR/safe-extract.py" \
    "$ROOT_DIR/browser-maintenance.py" "$ROOT_DIR/pbp-m" \
    "$ROOT_DIR/tests/test_launcher.py" "$ROOT_DIR/tests/test_safe_extract.py" \
    "$ROOT_DIR/tests/check_requirements.py" "$ROOT_DIR/tests/pbp-vm-soak.py" \
    "$ROOT_DIR/tests/test_vm_soak.py" "$ROOT_DIR/tests/test_browser_maintenance.py" \
    "$ROOT_DIR/tests/test_pbp_m.py"
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck "$ROOT_DIR/bootstrap-pbp.sh" "$ROOT_DIR/fetch-vendor.sh" \
        "$ROOT_DIR/make-release.sh" "$ROOT_DIR/tests/static-checks.sh"
fi
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -Q "$ROOT_DIR/apparmor/toolkit-pbp"
fi

python3 "$ROOT_DIR/tests/test_launcher.py"
python3 "$ROOT_DIR/tests/test_safe_extract.py"
python3 "$ROOT_DIR/tests/test_vm_soak.py"
python3 "$ROOT_DIR/tests/test_browser_maintenance.py"
python3 "$ROOT_DIR/tests/test_pbp_m.py"
python3 "$ROOT_DIR/tests/check_requirements.py" "$ROOT_DIR/requirements.lock"
if python3 "$ROOT_DIR/browser-maintenance.py" release >"$TMP_DIR/browser-gate.txt"; then
    printf 'TEST ERROR: the deliberately blocked real browser lock passed its release gate.\n' >&2
    exit 1
fi
grep -Fq 'Camoufox release gate: BLOCKED' "$TMP_DIR/browser-gate.txt"
python3 "$ROOT_DIR/browser-maintenance.py" disposable-test \
    >"$TMP_DIR/browser-disposable-gate.txt"
grep -Fq 'Camoufox disposable-test gate: TEST-ONLY' \
    "$TMP_DIR/browser-disposable-gate.txt"
grep -Fxq 'v0.1.9' "$ROOT_DIR/VERSION"
grep -Fq 'P0-Ursachenanalyse und Evidenzgrenze' "$ROOT_DIR/README.md"
grep -Fq 'Sie beweist **nicht**' "$ROOT_DIR/README.md"
grep -Fq 'Runbook: echter VM-Soak und Neustarttest' "$ROOT_DIR/README.md"
grep -Fq 'höchstens `BLOCKED`, niemals `PASS`' "$ROOT_DIR/README.md"
jq -e '
  .PreventInstalls == true
  and .Default == "DuckDuckGo"
  and .Remove == ["Google", "Bing", "Amazon.com", "eBay", "Twitter", "Wikipedia (en)"]
  and (keys | sort) == ["Default", "PreventInstalls", "Remove"]
' "$ROOT_DIR/browser-search-policy.json" >/dev/null
jq -e '
  .policies.BlockAboutAddons == true
  and .policies.BlockAboutConfig == true
  and .policies.BlockAboutProfiles == true
  and .policies.DisableDeveloperTools == true
  and .policies.DisableSecurityBypass == {
    "InvalidCertificate": true, "SafeBrowsing": true
  }
  and .policies.HttpsOnlyMode == "force_enabled"
  and .policies.NetworkPrediction == false
  and .policies.ExtensionSettings["*"]["installation_mode"] == "blocked"
  and .policies.ExtensionSettings["uBlock0@raymondhill.net"] == {
    "installation_mode": "allowed", "updates_disabled": true
  }
  and (.policies.Preferences | length) == 37
  and all(.policies.Preferences[];
    .Status == "locked" and (keys | sort) == ["Status", "Value"])
' "$ROOT_DIR/browser-hardening-policy.json" >/dev/null

grep -Fq '"$SCRIPT_DIR/toolkit-vpn-stage" \' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq -- '--location de --skip-firefox --return-after-install' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq -- '--outbound-https-enrollment' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq -- '--accept-disposable-test-browser' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq "DISPOSABLE_TEST_MARKER_NAME='DISPOSABLE-TEST-GATE.json'" \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'validate_disposable_test_marker' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '.details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'endswith(":443")' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '.mullvad_exit_ip == true' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '.country == "Germany"' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'mullvad_exit_ip") is not True' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'result.get("country") != "Germany"' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'def check_mullvad_policy()' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'checker: Callable[[], str] = check_mullvad_session' \
    "$ROOT_DIR/launch-pbp.py"
grep -Fq 'dynamicflow-pbp-vpn-verify ""' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'mv -fT -- "$helper_tmp" "$VPN_POLICY_HELPER"' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'visudo -cf "$VPN_POLICY_SUDOERS"' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'fingerprint_preset=preset' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'os="windows"' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'database_backed_windows_presets(candidates, sample_webgl)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'sample_webgl("win", vendor, renderer)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'locale=LOCALE' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'headless=False' "$ROOT_DIR/launch-pbp.py"
grep -Fq '"no_viewport": True' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'persistent_context=True' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'with context.expect_event(' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'predicate=lambda _page: False' "$ROOT_DIR/launch-pbp.py"
! grep -Fq 'closed.wait(' "$ROOT_DIR/launch-pbp.py"
grep -Fq '"webrtc:ipv4"' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'class EgressMonitor:' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'context.set_offline(offline)' "$ROOT_DIR/launch-pbp.py"
grep -Fq '"two healthy egress checks"' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'EGRESS_RECOVERY_ATTEMPTS = 5' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'EXIT_BROWSER_CRASH = 21' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'RUNTIME_LOG_RELATIVE = Path(".local/state/dynamicflow/pbp/logs")' \
    "$ROOT_DIR/launch-pbp.py"
grep -Fq 'os.O_WRONLY | os.O_CREAT | os.O_EXCL' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'os.fchmod(descriptor, 0o600)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'class StderrCapture' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'show_desktop_failure' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'PERSONA_SCHEMA = 3' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'LEGACY_PERSONA_SCHEMAS = frozenset({1, 2})' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'PERSONA_CLASSES:' "$ROOT_DIR/launch-pbp.py"
grep -Fq '"persona_class"' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'def migrate_persona(' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'fresh disposable VM' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'persona["config"].pop("addons", None)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'config.pop("window.history.length", None)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'if any(key.startswith("webrtc:") for key in config)' \
    "$ROOT_DIR/launch-pbp.py"
grep -Fq 'def harden_runtime_process()' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'NoNewPrivs:' "$ROOT_DIR/launch-pbp.py"
grep -Fq '["/usr/bin/xdotool", "getdisplaygeometry"]' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'PROFILE_RELATIVE = Path(".local/share/toolkit-pbp/profile")' \
    "$ROOT_DIR/launch-pbp.py"
grep -Fq 'reconcile_native_profile_locks' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'terminate_profile_processes' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'class ProfileProcessTracker:' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'profile.process_tracking_failed' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'app_lock_held=True' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'Exec=/usr/local/bin/pbp-browser desktop %u' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'zenity' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'xdotool' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq -- '--persona-class' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'install_egress_guard' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'install_download_bind_mount' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'toolkit_pbp_guard' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'dynamicflow-pbp-loopback-dns-udp' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'dynamicflow-pbp-loopback-replies' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'ct state established,related' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'Mullvad reports connected but browser routing is unhealthy' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '/usr/bin/mullvad disconnect --wait' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '/usr/bin/mullvad connect --wait' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '/usr/sbin/runuser -u malwarelab -- /usr/bin/curl' \
    "$ROOT_DIR/bootstrap-pbp.sh"
! grep -Fq '/usr/bin/runuser' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETUID' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETUID' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '/usr/bin/ip -j -d link show' "$ROOT_DIR/bootstrap-pbp.sh"
! grep -Fq '/usr/sbin/ip' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'Options=bind,nodev,nosuid,noexec' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'browser-hardening-policy.json' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'VM-weit stabil unter' "$ROOT_DIR/bootstrap-pbp.sh"
! grep -Fq 'profiles/$RELEASE' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'test_virtual_thirty_minute_soak_keeps_dispatching_then_closes_cleanly' \
    "$ROOT_DIR/tests/test_launcher.py"
grep -Fq 'test_three_full_close_and_restart_lifecycle_cycles' \
    "$ROOT_DIR/tests/test_launcher.py"
grep -Fq 'test_unexpected_runtime_failure_still_releases_kernel_lock_for_restart' \
    "$ROOT_DIR/tests/test_launcher.py"
[[ -x "$ROOT_DIR/tests/pbp-vm-soak.py" ]]
grep -Fq 'MINIMUM_SOAK_SECONDS = 30 * 60' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq -- '--exercise-vpn-failure' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq -- '--disposable-network-test' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'DYNAMICFLOW_LAB_VPN_TRIGGER' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'socket.AF_UNIX' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq '"qualifying_real_vm_pass": status_value == "PASS"' \
    "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'os.fchmod(descriptor, 0o600)' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'windowclose' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'signal.SIGKILL' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'transient_retry_observed' "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'read_secure_regular_file' "$ROOT_DIR/tests/pbp-vm-soak.py"
! grep -Eq 'unittest[.]mock|from unittest import mock|Mock[(]' \
    "$ROOT_DIR/tests/pbp-vm-soak.py"
grep -Fq 'install_browser_search_policy' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '.policies.SearchEngines.Add[0].URLTemplate == "http://127.0.0.1"' \
    "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq '.policies.SearchSuggestEnabled = false' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'local_env_vars(config, "win", browser_path.parent' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'camoufox_utils.get_env_vars = lambda mapping, target: local_env_vars' \
    "$ROOT_DIR/launch-pbp.py"
! grep -Fq 'from camoufox.utils import get_env_vars' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'ProxyHandler({})' "$ROOT_DIR/launch-pbp.py"
! grep -Eq 'page[.](goto|click|evaluate)|selenium|webdriver|remote-debugging|headless=True' \
    "$ROOT_DIR/launch-pbp.py"
! grep -Eq '(^|[^A-Za-z])proxy[[:space:]]*=' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'DefaultAddons.UBO' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'addons=[str(addon_path)]' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'require_addon_directory(addon, 0)' "$ROOT_DIR/launch-pbp.py"
grep -Fq 'assets/ublock-origin" 67108864' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'apparmor_restrict_unprivileged_userns' "$ROOT_DIR/bootstrap-pbp.sh"
grep -Fq 'flags=(unconfined)' "$ROOT_DIR/apparmor/toolkit-pbp"
grep -Fq 'userns,' "$ROOT_DIR/apparmor/toolkit-pbp"
grep -Fq 'apparmor_parser -r "$APPARMOR_PROFILE"' "$ROOT_DIR/bootstrap-pbp.sh"
! grep -Eq 'apparmor_restrict_unprivileged_userns[= ]+0|--no-sandbox' \
    "$ROOT_DIR/bootstrap-pbp.sh" "$ROOT_DIR/launch-pbp.py"
grep -Fq 'WHITELIST_SCHEMA = "dynamicflow/pbp-m-whitelist/v1"' "$ROOT_DIR/pbp-m"
grep -Fq 'Cloud-Firewall ist exakt so aktiv und der VM zugeordnet?' "$ROOT_DIR/pbp-m"
grep -Fq 'Ist der finale Firewall-Zustand exakt geprüft?' "$ROOT_DIR/pbp-m"
grep -Fq 'MANUELLE CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG' "$ROOT_DIR/pbp-m"
grep -Fq 'muss ALLOW TCP' "$ROOT_DIR/pbp-m"
grep -Fq 'für die Diagnose behalten' "$ROOT_DIR/pbp-m"
! grep -Fq 'Entferne jetzt die temporäre Inbound-Regel' "$ROOT_DIR/pbp-m"
! grep -Fq 'FIREWALL GEPRUEFT' "$ROOT_DIR/pbp-m"
grep -Fq 'prompt_tty("IP für Access: ")' "$ROOT_DIR/pbp-m"
grep -Fq 'write_tty(gate)' "$ROOT_DIR/pbp-m"
grep -Fq -- '--yes ist im manuellen Firewall-Modus verboten' "$ROOT_DIR/pbp-m"
grep -Fq 'verify_local_port_available(arguments.local_port)' "$ROOT_DIR/pbp-m"
grep -Fq 'muss genau einen exakten, unmarkierten' "$ROOT_DIR/pbp-m"
grep -Fq 'mehrere Keys, Wildcards, Hostlisten' "$ROOT_DIR/pbp-m"
grep -Fq '@cert-authority und @revoked sind verboten.' "$ROOT_DIR/pbp-m"
! grep -Eiq 'api[.]ipify[.]org|discover_public_ip|--no-ip-discovery' \
    "$ROOT_DIR/pbp-m"
grep -Fq 'StrictHostKeyChecking=yes' "$ROOT_DIR/../ssh/connect-gui.sh"
grep -Fq 'Ziel muss eine literale, global routbare öffentliche IP-Adresse sein.' \
    "$ROOT_DIR/pbp-m"

grep -Fxq 'browser_version 150.0.2-beta.25' "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'browser_major 150' "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'browser_release_repo VulpineOS/VulpineOS' "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'browser_amd64_sha256 dbd5dcffb2aead79f55ed305adb8e67e923094fc6f4181781bf55330f75d2a48' \
    "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'browser_arm64_sha256 9d541d991e297c44d93d6a10bd6dfef8efca7d50f3cd5468c3ac11056a569b6a' \
    "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'camoufox_wheel_sha256 9f7d26eb4e4f494bcd0f8bf043d5932cba11f7bd82c2795d595f5ff602a87744' \
    "$ROOT_DIR/browser-assets.lock"
grep -Fxq 'ublock_sha256 40c315b0da7871868155ecfae7a50a58dfa0920aebd865e008214986f1b7c578' \
    "$ROOT_DIR/browser-assets.lock"
! grep -Eiq 'browser_.*(url|name) .*latest' "$ROOT_DIR/browser-assets.lock"
grep -Fq -- '--require-hashes' "$ROOT_DIR/fetch-vendor.sh"
grep -Fq -- '--only-binary=:all:' "$ROOT_DIR/fetch-vendor.sh"
grep -Fq 'safe-extract.py" zip' "$ROOT_DIR/fetch-vendor.sh"
grep -Fq 'browser_check/camoufox-bin' "$ROOT_DIR/fetch-vendor.sh"
if grep -Fq -- '--no-build' "$ROOT_DIR/fetch-vendor.sh"; then
    printf 'TEST ERROR: uv rejects redundant --no-build with --only-binary=:all:.\n' >&2
    exit 1
fi
! grep -Eq 'camoufox[[:space:]]+fetch|pip[[:space:]]+install[[:space:]]+-U' \
    "$ROOT_DIR/bootstrap-pbp.sh" "$ROOT_DIR/fetch-vendor.sh"
for arch in amd64 arm64; do
    [[ -e "$ROOT_DIR/vendor/$arch" ]] || continue
    [[ -d "$ROOT_DIR/vendor/$arch" && ! -L "$ROOT_DIR/vendor/$arch" &&
        -f "$ROOT_DIR/vendor/$arch/camoufox.zip" ]] || {
        printf 'TEST ERROR: unsafe or incomplete optional vendor cache: %s\n' "$arch" >&2
        exit 1
    }
    python3 -c '
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    policies = json.loads(archive.read("distribution/policies.json"))["policies"]
search = policies["SearchEngines"]
assert search["Default"] == "None"
assert len(search["Add"]) == 1
assert search["Add"][0]["Name"] == "None"
assert search["Add"][0]["URLTemplate"] == "http://127.0.0.1"
' "$ROOT_DIR/vendor/$arch/camoufox.zip"
done

WORK="$TMP_DIR/work"
TEST_ROOT="$WORK/tools/pbp"
mkdir -p "$TEST_ROOT"
for source in bootstrap-pbp.sh launch-pbp.py safe-extract.py make-release.sh \
    browser-maintenance.py README.md CAMOUFOX-MAINTENANCE.md requirements.lock \
    browser-assets.lock browser-security-policy.json browser-hardening-policy.json \
    browser-search-policy.json VERSION; do
    cp -a "$ROOT_DIR/$source" "$TEST_ROOT/$source"
done
mkdir -p "$TEST_ROOT/apparmor"
cp -a "$ROOT_DIR/apparmor/toolkit-pbp" "$TEST_ROOT/apparmor/toolkit-pbp"
mkdir -p "$WORK/tools/vpn"
cp -a "$ROOT_DIR/../vpn/bootstrap-vpn.sh" "$WORK/tools/vpn/bootstrap-vpn.sh"
VENDOR="$TEST_ROOT/vendor/amd64"
mkdir -p "$VENDOR/python"
printf 'toolkit-pbp-vendor-v1\n' >"$VENDOR/.toolkit-pbp-vendor"
printf 'fake-browser-zip\n' >"$VENDOR/camoufox.zip"
printf 'fake-ublock-xpi\n' >"$VENDOR/ublock-origin.xpi"
for tag in cp311 cp312 cp313; do
    printf 'fake-runtime-%s\n' "$tag" >"$VENDOR/python/${tag}.tar.gz"
done
browser_hash="$(sha256sum "$VENDOR/camoufox.zip" | awk '{print $1}')"
ublock_hash="$(sha256sum "$VENDOR/ublock-origin.xpi" | awk '{print $1}')"
sed -i \
    -e "s/^browser_amd64_sha256 .*/browser_amd64_sha256 $browser_hash/" \
    -e "s/^ublock_sha256 .*/ublock_sha256 $ublock_hash/" \
    "$TEST_ROOT/browser-assets.lock"
observed_at="$(date -u -d '1 minute ago' '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(date -u -d '6 days' '+%Y-%m-%dT%H:%M:%SZ')"
jq --arg observed "$observed_at" --arg expires "$expires_at" \
    --arg browser_hash "$browser_hash" '
  .review.observed_at = $observed
  | .review.expires_at = $expires
  | .review.disposition = "approved"
  | .review.reason = "isolated release-fixture approval"
  | .security_gate.minimum_gecko_version = "150.0.2"
  | .locked_release.assets.amd64.sha256 = $browser_hash
' "$TEST_ROOT/browser-security-policy.json" \
    >"$TEST_ROOT/browser-security-policy.json.tmp"
mv -fT -- "$TEST_ROOT/browser-security-policy.json.tmp" \
    "$TEST_ROOT/browser-security-policy.json"
(
    cd "$VENDOR"
    sha256sum camoufox.zip ublock-origin.xpi python/cp311.tar.gz \
        python/cp312.tar.gz python/cp313.tar.gz >SHA256SUMS
)
{
    printf '%s  browser-assets.lock\n' \
        "$(sha256sum "$TEST_ROOT/browser-assets.lock" | awk '{print $1}')"
    printf '%s  requirements.lock\n' \
        "$(sha256sum "$TEST_ROOT/requirements.lock" | awk '{print $1}')"
} >"$VENDOR/SOURCE_LOCK_SHA256SUMS"

DIST_ONE="$TMP_DIR/dist-one"
DIST_TWO="$TMP_DIR/dist-two"
TOOLKIT_DIST_DIR="$DIST_ONE" bash "$TEST_ROOT/make-release.sh" amd64 >/dev/null
TOOLKIT_DIST_DIR="$DIST_TWO" bash "$TEST_ROOT/make-release.sh" amd64 >/dev/null
cmp -s "$DIST_ONE/linux-amd64/pbp.tar.gz" "$DIST_TWO/linux-amd64/pbp.tar.gz"
ARCHIVE="$DIST_ONE/linux-amd64/pbp.tar.gz"
archive_members="$(tar -tzf "$ARCHIVE")"
archive_bootstraps="$(awk -F/ \
    '$NF == "bootstrap.sh" || $NF ~ /^bootstrap-.*[.]sh$/ {count++} END {print count+0}' \
    <<<"$archive_members")"
[[ "$archive_bootstraps" -eq 1 ]]
grep -Fxq 'toolkit-pbp/bootstrap-pbp.sh' <<<"$archive_members"
grep -Fxq 'toolkit-pbp/toolkit-vpn-stage' <<<"$archive_members"
grep -Fxq 'toolkit-pbp/browser-search-policy.json' <<<"$archive_members"
grep -Fxq 'toolkit-pbp/browser-hardening-policy.json' <<<"$archive_members"
grep -Fxq 'toolkit-pbp/browser-security-policy.json' <<<"$archive_members"
! grep -Fq 'DISPOSABLE-TEST-GATE.json' <<<"$archive_members"
! grep -Fq 'bootstrap-vpn.sh' <<<"$archive_members"
if tar -tvzf "$ARCHIVE" | awk '$1 !~ /^[d-]/ {bad=1} END {exit bad ? 0 : 1}'; then
    printf 'TEST ERROR: release archive contains a link or special member\n' >&2
    exit 1
fi
EXTRACTED="$TMP_DIR/extracted"
mkdir "$EXTRACTED"
(
    umask 000
    tar -xzf "$ARCHIVE" -C "$EXTRACTED"
)
(
    cd "$EXTRACTED/toolkit-pbp"
    sha256sum -c --quiet SHA256SUMS
)
grep -Fxq 'v0.1.9' "$EXTRACTED/toolkit-pbp/VERSION"
[[ "$(stat -c '%a' "$EXTRACTED/toolkit-pbp/bootstrap-pbp.sh")" == '755' ]]
[[ "$(stat -c '%a' "$EXTRACTED/toolkit-pbp/toolkit-vpn-stage")" == '755' ]]
[[ "$(stat -c '%a' "$EXTRACTED/toolkit-pbp/launch-pbp.py")" == '755' ]]
[[ "$(stat -c '%a' "$EXTRACTED/toolkit-pbp/browser-maintenance.py")" == '755' ]]
for file in README.md CAMOUFOX-MAINTENANCE.md VERSION ARCH SHA256SUMS \
    requirements.lock browser-assets.lock browser-security-policy.json \
    browser-hardening-policy.json browser-search-policy.json apparmor/toolkit-pbp; do
    [[ "$(stat -c '%a' "$EXTRACTED/toolkit-pbp/$file")" == '644' ]]
done

jq '
  .review.disposition = "blocked"
  | .review.reason = "isolated disposable-test fixture"
  | .security_gate.minimum_gecko_version = "153.0"
' "$TEST_ROOT/browser-security-policy.json" \
    >"$TEST_ROOT/browser-security-policy.json.tmp"
mv -fT -- "$TEST_ROOT/browser-security-policy.json.tmp" \
    "$TEST_ROOT/browser-security-policy.json"
python3 "$TEST_ROOT/browser-maintenance.py" disposable-test --json \
    >"$TMP_DIR/disposable-gate.json"
jq -e '
  .mode == "disposable-test"
  and .result == "TEST-ONLY"
  and ([.checks[] | select(.passed == false) | .name] | sort)
    == ["gecko-security-baseline", "review-disposition"]
' "$TMP_DIR/disposable-gate.json" >/dev/null

DISPOSABLE_DIST_ONE="$TMP_DIR/disposable-dist-one"
DISPOSABLE_DIST_TWO="$TMP_DIR/disposable-dist-two"
TOOLKIT_DIST_DIR="$DISPOSABLE_DIST_ONE" \
    bash "$TEST_ROOT/make-release.sh" --disposable-test-run amd64 >/dev/null
TOOLKIT_DIST_DIR="$DISPOSABLE_DIST_TWO" \
    bash "$TEST_ROOT/make-release.sh" --disposable-test-run amd64 >/dev/null
DISPOSABLE_ARCHIVE="$DISPOSABLE_DIST_ONE/disposable-test/linux-amd64/pbp-disposable-test.tar.gz"
cmp -s "$DISPOSABLE_ARCHIVE" \
    "$DISPOSABLE_DIST_TWO/disposable-test/linux-amd64/pbp-disposable-test.tar.gz"
[[ ! -e "$DISPOSABLE_DIST_ONE/linux-amd64/pbp.tar.gz" ]]
disposable_members="$(tar -tzf "$DISPOSABLE_ARCHIVE")"
grep -Fxq 'toolkit-pbp-disposable-test/bootstrap-pbp.sh' \
    <<<"$disposable_members"
grep -Fxq 'toolkit-pbp-disposable-test/toolkit-vpn-stage' \
    <<<"$disposable_members"
grep -Fxq 'toolkit-pbp-disposable-test/DISPOSABLE-TEST-GATE.json' \
    <<<"$disposable_members"
! grep -Eq '^toolkit-pbp/' <<<"$disposable_members"
DISPOSABLE_EXTRACTED="$TMP_DIR/disposable-extracted"
mkdir "$DISPOSABLE_EXTRACTED"
(
    umask 000
    tar -xzf "$DISPOSABLE_ARCHIVE" -C "$DISPOSABLE_EXTRACTED"
)
DISPOSABLE_ROOT="$DISPOSABLE_EXTRACTED/toolkit-pbp-disposable-test"
(
    cd "$DISPOSABLE_ROOT"
    sha256sum -c --quiet SHA256SUMS
)
grep -Fxq 'v0.1.9-disposable-test' "$DISPOSABLE_ROOT/VERSION"
[[ "$(stat -c '%a' "$DISPOSABLE_ROOT/DISPOSABLE-TEST-GATE.json")" == '644' ]]
jq -e '
  .schema == 1
  and .mode == "disposable-test"
  and .result == "TEST-ONLY"
  and ([.checks[] | select(.passed == false) | .name] | sort)
    == ["gecko-security-baseline", "review-disposition"]
' "$DISPOSABLE_ROOT/DISPOSABLE-TEST-GATE.json" >/dev/null
if (
    source "$DISPOSABLE_ROOT/bootstrap-pbp.sh"
    verify_bundle
    validate_bundle_mode 0
) >"$TMP_DIR/disposable-refusal.out" 2>"$TMP_DIR/disposable-refusal.err"; then
    printf 'TEST ERROR: marked disposable bundle ran without explicit acceptance.\n' >&2
    exit 1
fi
grep -Fq 'requires --accept-disposable-test-browser' \
    "$TMP_DIR/disposable-refusal.err"
(
    source "$DISPOSABLE_ROOT/bootstrap-pbp.sh"
    verify_bundle
    validate_bundle_mode 1
    [[ "$BROWSER_RELEASE_STATUS" == 'TEST-ONLY: security baseline knowingly not met' ]]
) >/dev/null 2>"$TMP_DIR/disposable-accept.err"
grep -Fq 'TEST-ONLY browser accepted' "$TMP_DIR/disposable-accept.err"

printf 'PBP static checks passed.\n'
