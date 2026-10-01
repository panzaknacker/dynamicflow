#!/usr/bin/env python3

import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("browser_maintenance", ROOT / "browser-maintenance.py")
assert SPEC is not None and SPEC.loader is not None
browser_maintenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = browser_maintenance
SPEC.loader.exec_module(browser_maintenance)


class BrowserMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.lock = browser_maintenance.read_lock(ROOT / "browser-assets.lock")
        self.policy = browser_maintenance.read_json_object(ROOT / "browser-security-policy.json")
        self.now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)

    def approved_policy(self):
        policy = deepcopy(self.policy)
        policy["review"]["disposition"] = "approved"
        policy["review"]["reason"] = "test review"
        policy["security_gate"]["minimum_gecko_version"] = "150.0.2"
        return policy

    def test_current_lock_is_fail_closed_below_security_baseline(self):
        checks = browser_maintenance.validate_lock_against_policy(self.lock, self.policy, self.now)
        failures = {item.name for item in checks if not item.passed}
        self.assertIn("review-disposition", failures)
        self.assertIn("gecko-security-baseline", failures)

    def test_reviewed_exact_lock_can_pass(self):
        checks = browser_maintenance.validate_lock_against_policy(self.lock, self.approved_policy(), self.now)
        self.assertTrue(all(item.passed for item in checks))

    def test_disposable_test_accepts_exactly_the_two_known_failures(self):
        checks = browser_maintenance.validate_lock_against_policy(self.lock, self.policy, self.now)
        payload = browser_maintenance.report_payload(
            "disposable-test",
            ROOT / "browser-assets.lock",
            ROOT / "browser-security-policy.json",
            checks,
        )
        self.assertEqual(payload["result"], "TEST-ONLY")

    def test_disposable_test_rejects_an_additional_offline_failure(self):
        checks = browser_maintenance.validate_lock_against_policy(
            self.lock,
            self.policy,
            datetime(2026, 8, 3, 0, 0, 1, tzinfo=timezone.utc),
        )
        payload = browser_maintenance.report_payload(
            "disposable-test",
            ROOT / "browser-assets.lock",
            ROOT / "browser-security-policy.json",
            checks,
        )
        self.assertEqual(payload["result"], "BLOCKED")

    def test_disposable_test_rejects_only_one_known_failure(self):
        policy = deepcopy(self.policy)
        policy["review"]["disposition"] = "approved"
        checks = browser_maintenance.validate_lock_against_policy(self.lock, policy, self.now)
        payload = browser_maintenance.report_payload(
            "disposable-test",
            ROOT / "browser-assets.lock",
            ROOT / "browser-security-policy.json",
            checks,
        )
        self.assertEqual(payload["result"], "BLOCKED")

    def test_disposable_test_rejects_a_fully_approved_release(self):
        checks = browser_maintenance.validate_lock_against_policy(self.lock, self.approved_policy(), self.now)
        payload = browser_maintenance.report_payload(
            "disposable-test",
            ROOT / "browser-assets.lock",
            ROOT / "browser-security-policy.json",
            checks,
        )
        self.assertEqual(payload["result"], "BLOCKED")

    def test_disposable_test_rejects_an_unknown_or_missing_check(self):
        checks = browser_maintenance.validate_lock_against_policy(self.lock, self.policy, self.now)
        for changed in (
            checks[:-1],
            checks + [browser_maintenance.Check("future-check", True, "test")],
        ):
            with self.subTest(checks=[item.name for item in changed]):
                payload = browser_maintenance.report_payload(
                    "disposable-test",
                    ROOT / "browser-assets.lock",
                    ROOT / "browser-security-policy.json",
                    changed,
                )
                self.assertEqual(payload["result"], "BLOCKED")

    def test_any_asset_hash_drift_fails_provenance(self):
        lock = dict(self.lock)
        lock["browser_amd64_sha256"] = "0" * 64
        checks = browser_maintenance.validate_lock_against_policy(lock, self.approved_policy(), self.now)
        result = {item.name: item.passed for item in checks}
        self.assertFalse(result["exact-release-provenance"])

    def test_policy_expiry_blocks_release(self):
        policy = self.approved_policy()
        checks = browser_maintenance.validate_lock_against_policy(
            self.lock, policy, datetime(2026, 8, 3, 0, 0, 1, tzinfo=timezone.utc)
        )
        result = {item.name: item.passed for item in checks}
        self.assertFalse(result["policy-current"])

    def test_policy_cannot_create_a_long_lived_review(self):
        policy = self.approved_policy()
        policy["review"]["expires_at"] = "2026-09-01T00:00:00Z"
        with self.assertRaisesRegex(browser_maintenance.ValidationError, "review window exceeds"):
            browser_maintenance.validate_lock_against_policy(self.lock, policy, self.now)

    def test_future_observation_is_invalid(self):
        policy = self.approved_policy()
        policy["review"]["observed_at"] = "2026-07-28T00:00:00Z"
        with self.assertRaisesRegex(browser_maintenance.ValidationError, "observation is in the future"):
            browser_maintenance.validate_lock_against_policy(self.lock, policy, self.now)

    def test_duplicate_lock_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            path.write_text(
                "browser_version 150.0.2\nbrowser_version 150.0.3\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(browser_maintenance.ValidationError, "duplicate key"):
                browser_maintenance.read_lock(path)

    def test_online_url_allowlist_rejects_credentials_and_nonofficial_hosts(self):
        bad_urls = (
            "http://api.github.com/repos/example/example",
            "https://api.github.com.evil.example/repos/example/example",
            "https://user@api.github.com/repos/example/example",
            "https://pypi.org:444/pypi/example/json",
        )
        for value in bad_urls:
            with self.subTest(value=value), self.assertRaises(browser_maintenance.ValidationError):
                browser_maintenance.validate_online_url(value)

    def test_comparable_version_ignores_camoufox_suffix(self):
        self.assertEqual(
            browser_maintenance.comparable_version("152.0.4-beta.28", "test version"),
            (152, 0, 4, 0),
        )
        self.assertLess(
            browser_maintenance.comparable_version("152.0.4-beta.28", "checkpoint"),
            browser_maintenance.comparable_version("152.0.6", "minimum"),
        )

    def test_release_builder_runs_gate_before_vendor_and_packages_policy(self):
        script = (ROOT / "make-release.sh").read_text(encoding="utf-8")
        gate = 'python3 "$ROOT_DIR/browser-maintenance.py" release'
        self.assertLess(script.index(gate), script.index('VENDOR="$ROOT_DIR/vendor/$ARCH"'))
        self.assertIn(
            'python3 "$ROOT_DIR/browser-maintenance.py" disposable-test',
            script,
        )
        self.assertIn("PACKAGE_NAME='toolkit-pbp-disposable-test'", script)
        self.assertIn("ARTIFACT_NAME='pbp-disposable-test.tar.gz'", script)
        self.assertIn(
            '>"$PAYLOAD/DISPOSABLE-TEST-GATE.json"',
            script,
        )
        self.assertIn('install -m 0755 "$ROOT_DIR/browser-maintenance.py"', script)
        self.assertIn('install -m 0644 "$ROOT_DIR/browser-security-policy.json"', script)
        self.assertIn('install -m 0644 "$ROOT_DIR/browser-hardening-policy.json"', script)


if __name__ == "__main__":
    unittest.main()
