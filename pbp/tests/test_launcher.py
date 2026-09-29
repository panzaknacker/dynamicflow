#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("launch_pbp", ROOT / "launch-pbp.py")
assert SPEC and SPEC.loader
launch_pbp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = launch_pbp
SPEC.loader.exec_module(launch_pbp)

BROWSER = Path("/opt/toolkit/pbp/releases/v0.1.0/browser/camoufox-bin")
ADDON = Path("/opt/toolkit/pbp/releases/v0.1.0/assets/ublock-origin")


def sample_preset() -> dict:
    return {
        "navigator": {
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
            "platform": "Win32",
            "hardwareConcurrency": 4,
            "maxTouchPoints": 0,
        },
        "screen": {
            "width": 1600,
            "height": 900,
            "availWidth": 1600,
            "availHeight": 840,
            "colorDepth": 24,
            "devicePixelRatio": 1.2,
        },
        "webgl": {
            "unmaskedVendor": "Google Inc. (Intel)",
            "unmaskedRenderer": ("ANGLE (Intel, Intel(R) HD Graphics 400 Direct3D11 vs_5_0 ps_5_0), or similar"),
        },
        "speechVoices": [
            "Microsoft David - English (United States):en-US:local",
            "Microsoft Mark - English (United States):en-US:local",
            "Microsoft Zira - English (United States):en-US:local",
            "Microsoft David Desktop - English (United States):en-US:local",
            "Microsoft Zira Desktop - English (United States):en-US:local",
        ],
    }


def sample_persona(seed: int = 1234) -> dict:
    preset = sample_preset()
    persona = {
        "schema": 3,
        "browser_version": "150.0.2-beta.25",
        "browser_major": 150,
        "camoufox_package_version": "0.6.0",
        "persona_class": "basic",
        "os": "windows",
        "locale": "de-DE",
        "timezone": "Europe/Berlin",
        "preset": preset,
        "config": {
            "navigator.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
            "navigator.platform": "Win32",
            "navigator.oscpu": "Windows NT 10.0; Win64; x64",
            "navigator.hardwareConcurrency": 4,
            "navigator.maxTouchPoints": 0,
            "screen.width": 1600,
            "screen.height": 900,
            "screen.availWidth": 1600,
            "screen.availHeight": 840,
            "screen.colorDepth": 24,
            "screen.pixelDepth": 24,
            "window.devicePixelRatio": 1.2,
            "webGl:vendor": "Google Inc. (Intel)",
            "webGl:renderer": ("ANGLE (Intel, Intel(R) HD Graphics 400 Direct3D11 vs_5_0 ps_5_0), or similar"),
            "fonts": ["Arial", "Calibri", "Segoe UI", "Times New Roman"],
            "voices": [
                "Microsoft David - English (United States)",
                "Microsoft Mark - English (United States)",
                "Microsoft Zira - English (United States)",
                "Microsoft David Desktop - English (United States)",
                "Microsoft Zira Desktop - English (United States)",
            ],
            "fonts:spacing_seed": seed,
            "audio:seed": seed + 1,
            "canvas:seed": seed + 2,
            "timezone": "Europe/Berlin",
            "locale:language": "de",
            "locale:region": "DE",
            "locale:script": "Latn",
        },
        "firefox_user_prefs": {
            "webgl.force-enabled": True,
            "webgl.enable-webgl2": True,
            "browser.cache.disk.enable": True,
            **launch_pbp.HARDENED_FIREFOX_PREFS,
        },
    }
    persona["persona_id"] = launch_pbp.persona_id_for(persona)
    return persona


def legacy_persona(seed: int = 1234) -> dict:
    persona = sample_persona(seed)
    persona.pop("persona_id")
    persona.pop("persona_class")
    persona["schema"] = 1
    persona["release"] = "v0.1.0"
    persona["config"]["addons"] = [str(ADDON)]
    return persona


class FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self.status = status
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response

    def open(self, _request, timeout: int):
        assert timeout == 10
        return self.response


class FakeTimeout(Exception):
    pass


class FakeRuntimeLog:
    def __init__(self):
        self.records: list[tuple[str, dict]] = []

    def log(self, event: str, **fields):
        self.records.append((event, fields))

    def log_exception(self, event: str, error: BaseException, **fields):
        self.records.append((event, {"error": str(error), **fields}))


class FakePage:
    def __init__(self):
        self.handlers: dict[str, list] = {}

    def on(self, event: str, handler):
        self.handlers.setdefault(event, []).append(handler)

    def emit(self, event: str):
        for handler in list(self.handlers.get(event, [])):
            handler(self)


class FakeExpectation:
    def __init__(self, action):
        self.action = action

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.action()
        raise FakeTimeout()


class FakeContext:
    def __init__(self, actions=None):
        self.handlers: dict[str, list] = {}
        self.pages = [FakePage()]
        self.actions = list(actions or [])
        self.offline: list[bool] = []
        self.close_calls = 0
        self.pump_calls = 0

    def on(self, event: str, handler):
        self.handlers.setdefault(event, []).append(handler)

    def emit(self, event: str, value=None):
        for handler in list(self.handlers.get(event, [])):
            handler(self if value is None else value)

    def expect_event(self, event: str, predicate, timeout: int):
        assert event == "page"
        assert predicate(self.pages[0]) is False
        assert timeout == launch_pbp.DISPATCH_PUMP_MS
        self.pump_calls += 1
        action = self.actions.pop(0) if self.actions else (lambda: None)
        return FakeExpectation(action)

    def close(self):
        self.close_calls += 1
        self.emit("close")

    def set_offline(self, value: bool):
        self.offline.append(value)


class FakeMonitor:
    def __init__(self, events=()):
        self.events = queue.Queue()
        for event in events:
            self.events.put(event)
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FakeSignalLatch:
    def __init__(self, signum=None):
        self.event = threading.Event()
        self.signum = signum
        if signum is not None:
            self.event.set()


class LauncherTests(unittest.TestCase):
    def test_enterprise_policy_and_launcher_hardening_preferences_are_identical(self):
        policy = json.loads((ROOT / "browser-hardening-policy.json").read_text(encoding="utf-8"))
        preferences = policy["policies"]["Preferences"]
        self.assertEqual(
            {key: value["Value"] for key, value in preferences.items()},
            launch_pbp.HARDENED_FIREFOX_PREFS,
        )
        self.assertTrue(all(value["Status"] == "locked" for value in preferences.values()))

    def test_valid_persona_round_trip_is_stable(self):
        persona = sample_persona()
        validated = launch_pbp.validate_persona(
            deepcopy(persona),
            release="v0.1.0",
            browser_path=BROWSER,
            addon_path=ADDON,
        )
        encoded = json.dumps(validated, sort_keys=True, separators=(",", ":"))
        decoded = launch_pbp.parse_json(encoded)
        self.assertEqual(decoded, persona)

    def test_persona_rejects_linux_or_contradictory_values(self):
        for mutation in ("platform", "screen", "webgl", "timezone"):
            persona = sample_persona()
            if mutation == "platform":
                persona["config"]["navigator.platform"] = "Linux x86_64"
            elif mutation == "screen":
                persona["config"]["screen.width"] = 933
            elif mutation == "webgl":
                persona["config"]["webGl:renderer"] = "llvmpipe"
            else:
                persona["config"]["timezone"] = "Atlantic/Reykjavik"
            with self.subTest(mutation=mutation), self.assertRaises(launch_pbp.PBPError):
                launch_pbp.validate_persona(
                    persona,
                    release="v0.1.0",
                    browser_path=BROWSER,
                    addon_path=ADDON,
                )

    def test_stable_persona_rejects_session_specific_network_data(self):
        persona = sample_persona()
        persona["config"]["webrtc:ipv4"] = "185.65.134.1"
        persona["persona_id"] = launch_pbp.persona_id_for(persona)
        with self.assertRaisesRegex(launch_pbp.PBPError, "session-specific"):
            launch_pbp.validate_persona(
                persona,
                release="v0.1.0",
                browser_path=BROWSER,
                addon_path=ADDON,
            )

    def test_browser_options_are_headful_system_routed_and_stable(self):
        captured: list[dict] = []

        def get_env_vars(config, target_os, _browser_root, _home):
            self.assertEqual(target_os, "win")
            captured.append(deepcopy(config))
            return {
                "CAMOU_CONFIG_1": json.dumps(config, sort_keys=True),
                "FONTCONFIG_FILE": "/runtime/fontconfig/windows/fonts.conf",
            }

        environment = {
            "HOME": "/home/malwarelab",
            "DISPLAY": ":1",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        with mock.patch.object(launch_pbp, "local_env_vars", side_effect=get_env_vars):
            first = launch_pbp.browser_options(
                sample_persona(),
                browser_path=BROWSER,
                addon_path=ADDON,
                profile=Path("/home/malwarelab/.local/share/toolkit-pbp/profile"),
                environment=environment,
                exit_ip="185.65.134.1",
                url=None,
            )
            second = launch_pbp.browser_options(
                sample_persona(),
                browser_path=BROWSER,
                addon_path=ADDON,
                profile=Path("/home/malwarelab/.local/share/toolkit-pbp/profile"),
                environment=environment,
                exit_ip="185.65.134.2",
                url="https://example.com/",
            )
        self.assertIs(first["headless"], False)
        self.assertIs(first["no_viewport"], True)
        self.assertNotIn("viewport", first)
        self.assertNotIn("proxy", first)
        self.assertEqual(first["args"], [])
        self.assertEqual(second["args"], ["https://example.com/"])
        for key, expected in launch_pbp.HARDENED_FIREFOX_PREFS.items():
            self.assertEqual(first["firefox_user_prefs"][key], expected)
            self.assertEqual(second["firefox_user_prefs"][key], expected)
        self.assertEqual(captured[0]["webrtc:ipv4"], "185.65.134.1")
        self.assertEqual(captured[1]["webrtc:ipv4"], "185.65.134.2")
        stable_first = deepcopy(captured[0])
        stable_second = deepcopy(captured[1])
        stable_first.pop("webrtc:ipv4")
        stable_second.pop("webrtc:ipv4")
        self.assertEqual(stable_first, stable_second)

    def test_environment_cannot_override_camoufox_config(self):
        with mock.patch.object(launch_pbp, "local_env_vars", return_value={"CAMOU_CONFIG_1": "safe"}):
            with self.assertRaises(launch_pbp.PBPError):
                launch_pbp.browser_options(
                    sample_persona(),
                    browser_path=BROWSER,
                    addon_path=ADDON,
                    profile=Path("/tmp/profile"),
                    environment={"HOME": "/home/malwarelab", "CAMOU_CONFIG_1": "attacker"},
                    exit_ip="185.65.134.1",
                    url=None,
                )

    def test_runtime_process_hardening_sets_kernel_invariants(self):
        libc = mock.Mock()
        libc.prctl = mock.Mock(return_value=0)
        with (
            mock.patch.object(launch_pbp.ctypes, "CDLL", return_value=libc),
            mock.patch.object(launch_pbp.resource, "setrlimit") as setrlimit,
            mock.patch.object(launch_pbp.resource, "getrlimit", return_value=(0, 0)),
            mock.patch.object(Path, "read_text", return_value="Name:\ttest\nNoNewPrivs:\t1\n"),
        ):
            launch_pbp.harden_runtime_process()
        setrlimit.assert_called_once_with(launch_pbp.resource.RLIMIT_CORE, (0, 0))
        self.assertIn(mock.call(38, 1, 0, 0, 0), libc.prctl.call_args_list)
        self.assertIn(mock.call(4, 0, 0, 0, 0), libc.prctl.call_args_list)
        self.assertIn(mock.call(3, 0, 0, 0, 0), libc.prctl.call_args_list)

    def test_managed_display_must_be_exactly_1600_by_900(self):
        home = Path("/home/malwarelab")
        good = launch_pbp.subprocess.CompletedProcess([], 0, "1600 900\n", "")
        with (
            mock.patch.dict(
                launch_pbp.os.environ,
                {"DISPLAY": ":1", "XAUTHORITY": "/home/malwarelab/.Xauthority"},
                clear=True,
            ),
            mock.patch.object(launch_pbp, "require_regular_file"),
            mock.patch.object(launch_pbp, "require_real_directory"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(launch_pbp.subprocess, "run", return_value=good) as run,
        ):
            environment = launch_pbp.validate_display_environment(home, 1000)
        self.assertEqual(environment["DISPLAY"], ":1")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/xdotool", "getdisplaygeometry"])

        wrong = launch_pbp.subprocess.CompletedProcess([], 0, "1920 1080\n", "")
        with (
            mock.patch.dict(
                launch_pbp.os.environ,
                {"DISPLAY": ":1", "XAUTHORITY": "/home/malwarelab/.Xauthority"},
                clear=True,
            ),
            mock.patch.object(launch_pbp, "require_regular_file"),
            mock.patch.object(launch_pbp, "require_real_directory"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(launch_pbp.subprocess, "run", return_value=wrong),
            self.assertRaisesRegex(launch_pbp.PBPError, "1600x900"),
        ):
            launch_pbp.validate_display_environment(home, 1000)

    def test_mullvad_gate_requires_germany_and_true_exit(self):
        good = {"mullvad_exit_ip": True, "country": "Germany", "ip": "185.65.134.1"}
        with mock.patch.object(launch_pbp, "build_opener", return_value=FakeOpener(FakeResponse(good))):
            self.assertEqual(launch_pbp.fetch_mullvad_egress(attempts=1), "185.65.134.1")
        for bad in (
            {"mullvad_exit_ip": True, "country": "Sweden", "ip": "185.65.134.1"},
            {"mullvad_exit_ip": False, "country": "Germany", "ip": "185.65.134.1"},
            {"mullvad_exit_ip": True, "country": "Germany", "ip": "127.0.0.1"},
        ):
            with (
                self.subTest(payload=bad),
                mock.patch.object(launch_pbp, "build_opener", return_value=FakeOpener(FakeResponse(bad))),
                self.assertRaises(launch_pbp.PBPError),
            ):
                launch_pbp.fetch_mullvad_egress(attempts=1)

    def test_mullvad_policy_gate_distinguishes_policy_from_transient_failure(self):
        success = launch_pbp.subprocess.CompletedProcess([], 0, "policy-ok\n", "")
        with mock.patch.object(launch_pbp.subprocess, "run", return_value=success) as run:
            launch_pbp.check_mullvad_policy()
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/local/libexec/dynamicflow-pbp-vpn-verify",
            ],
        )
        self.assertIs(run.call_args.kwargs["stdin"], launch_pbp.subprocess.DEVNULL)
        with (
            mock.patch.object(
                launch_pbp.subprocess,
                "run",
                return_value=launch_pbp.subprocess.CompletedProcess([], 20, "", ""),
            ),
            self.assertRaises(launch_pbp.EgressDefinitiveError),
        ):
            launch_pbp.check_mullvad_policy()
        for result in (
            launch_pbp.subprocess.CompletedProcess([], 21, "", ""),
            launch_pbp.subprocess.CompletedProcess([], 0, "unexpected\n", ""),
            launch_pbp.subprocess.CompletedProcess([], 0, "policy-ok\n", "unexpected"),
        ):
            with (
                self.subTest(result=result),
                mock.patch.object(launch_pbp.subprocess, "run", return_value=result),
                self.assertRaises(launch_pbp.EgressTransientError),
            ):
                launch_pbp.check_mullvad_policy()

    def test_combined_mullvad_session_checks_policy_before_egress(self):
        calls: list[str] = []
        with (
            mock.patch.object(
                launch_pbp,
                "check_mullvad_policy",
                side_effect=lambda: calls.append("policy"),
            ),
            mock.patch.object(
                launch_pbp,
                "check_mullvad_egress",
                side_effect=lambda: calls.append("egress") or "185.65.134.1",
            ),
        ):
            self.assertEqual(launch_pbp.check_mullvad_session(), "185.65.134.1")
        self.assertEqual(calls, ["policy", "egress"])

    def test_runtime_monitor_default_does_not_attempt_post_hardening_sudo(self):
        monitor = launch_pbp.EgressMonitor()
        self.assertIs(monitor._checker, launch_pbp.check_mullvad_egress)
        self.assertIsNot(monitor._checker, launch_pbp.check_mullvad_session)

    def test_only_credential_free_http_urls_are_allowed(self):
        self.assertEqual(
            launch_pbp.validate_url("https://example.com/path?q=1"),
            "https://example.com/path?q=1",
        )
        for value in ("file:///etc/passwd", "https://user:pass@example.com/", "javascript:alert(1)"):
            with self.subTest(value=value), self.assertRaises(launch_pbp.PBPError):
                launch_pbp.validate_url(value)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(launch_pbp.PBPError):
            launch_pbp.parse_json('{"schema":1,"schema":2}')

    def test_windows_presets_require_a_database_backed_webgl_pair(self):
        valid = sample_preset()
        invalid = deepcopy(valid)
        invalid["webgl"]["unmaskedVendor"] = "Google Inc. (AMD)"
        invalid["webgl"]["unmaskedRenderer"] = "ANGLE (AMD, Radeon HD 5850 Direct3D11 vs_5_0 ps_5_0), or similar"
        calls: list[tuple[str, str, str]] = []

        def sample_webgl(target_os: str, vendor: str, renderer: str) -> dict:
            calls.append((target_os, vendor, renderer))
            if vendor == "Google Inc. (AMD)":
                raise ValueError("preset is absent from webgl_data.db")
            return {}

        supported = launch_pbp.database_backed_windows_presets(
            [invalid, valid, deepcopy(invalid)],
            sample_webgl,
        )
        self.assertEqual(supported, [valid])
        self.assertEqual(
            [call[1] for call in calls],
            ["Google Inc. (AMD)", "Google Inc. (Intel)"],
        )

    def test_all_three_persona_classes_have_an_exact_pinned_preset_signature(self):
        for persona_class, signature in launch_pbp.PERSONA_CLASSES.items():
            preset = sample_preset()
            preset["navigator"]["hardwareConcurrency"] = signature["hardwareConcurrency"]
            preset["navigator"]["maxTouchPoints"] = signature["maxTouchPoints"]
            for key in (
                "width",
                "height",
                "availWidth",
                "availHeight",
                "devicePixelRatio",
            ):
                preset["screen"][key] = signature[key]
            preset["webgl"]["unmaskedVendor"] = signature["vendor"]
            preset["webgl"]["unmaskedRenderer"] = signature["renderer"]
            with self.subTest(persona_class=persona_class):
                self.assertTrue(launch_pbp.preset_matches_persona_class(preset, persona_class))

    def test_legacy_personas_require_explicit_profile_and_vm_rotation(self):
        candidates = (legacy_persona(4242), {**sample_persona(4242), "schema": 2})
        for legacy in candidates:
            original = deepcopy(legacy)
            with (
                self.subTest(schema=legacy["schema"]),
                self.assertRaisesRegex(launch_pbp.PBPError, "fresh disposable VM"),
            ):
                launch_pbp.migrate_persona(
                    legacy,
                    browser_path=BROWSER,
                    addon_path=ADDON,
                )
            self.assertEqual(legacy, original)

    def test_schema_three_migration_command_is_validation_only(self):
        persona = sample_persona()
        self.assertEqual(
            launch_pbp.migrate_persona(
                persona,
                browser_path=BROWSER,
                addon_path=ADDON,
            ),
            persona,
        )

    def test_incompatible_persona_is_blocked_instead_of_replaced(self):
        persona = sample_persona()
        persona["browser_version"] = "151.0"
        with self.assertRaisesRegex(launch_pbp.PBPError, "incompatible"):
            launch_pbp.migrate_persona(
                persona,
                browser_path=BROWSER,
                addon_path=ADDON,
            )

    def test_runtime_logs_are_private_rotated_and_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for index in range(launch_pbp.LOG_RETAIN + 3):
                with launch_pbp.open_runtime_log(home, uid) as runtime_log:
                    runtime_log.log(
                        "test.event",
                        message=(
                            "https://alice:password@example.test/private?"
                            "enrollment_code=do-not-log token=also-secret "
                            "12345678901234567890 peer=185.65.134.1 "
                            "relay=[2001:db8::1]"
                        ),
                        metadata={
                            "token": "nested-raw-secret",
                            "nested": {"authorization": "Bearer raw-bearer"},
                        },
                        index=index,
                    )
            log_root = home / launch_pbp.RUNTIME_LOG_RELATIVE
            logs = list(log_root.glob("runtime-*.jsonl"))
            self.assertLessEqual(len(logs), launch_pbp.LOG_RETAIN)
            self.assertEqual(stat.S_IMODE(log_root.stat().st_mode), 0o700)
            for path in logs:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("do-not-log", content)
                self.assertNotIn("also-secret", content)
                self.assertNotIn("12345678901234567890", content)
                self.assertNotIn("alice:password", content)
                self.assertNotIn("/private", content)
                self.assertNotIn("example.test", content)
                self.assertNotIn("https://", content)
                self.assertNotIn("185.65.134.1", content)
                self.assertNotIn("2001:db8::1", content)
                self.assertNotIn("nested-raw-secret", content)
                self.assertNotIn("raw-bearer", content)
                for line in content.splitlines():
                    json.loads(line)

    def test_stderr_is_captured_and_sanitized(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            with launch_pbp.open_runtime_log(home, os.geteuid()) as runtime_log:
                path = runtime_log.path
                capture = launch_pbp.StderrCapture(runtime_log)
                with capture:
                    os.write(
                        2,
                        b"token=raw-secret https://example.test/a?q=secret "
                        b"peer=185.65.134.1 relay=2001:db8::1 "
                        b"CAMOU_CONFIG_1={fingerprint-data}\n",
                    )
                self.assertTrue(capture.wait_closed())
            content = path.read_text(encoding="utf-8")
            self.assertIn("runtime.stderr", content)
            self.assertNotIn("raw-secret", content)
            self.assertNotIn("q=secret", content)
            self.assertNotIn("example.test", content)
            self.assertNotIn("185.65.134.1", content)
            self.assertNotIn("2001:db8::1", content)
            self.assertNotIn("fingerprint-data", content)

    def test_oversized_stderr_line_discards_unstructured_continuation(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            with launch_pbp.open_runtime_log(home, os.geteuid()) as runtime_log:
                path = runtime_log.path
                capture = launch_pbp.StderrCapture(runtime_log)
                with capture:
                    payload = (
                        b"x" * 70000
                        + b"UNSTRUCTURED-SECRET-CONTINUATION\n"
                        + b"normal diagnostic after oversized line\n"
                    )
                    remaining = memoryview(payload)
                    while remaining:
                        written = os.write(2, remaining)
                        remaining = remaining[written:]
                self.assertTrue(capture.wait_closed())
            content = path.read_text(encoding="utf-8")
            self.assertIn("runtime.stderr_line_truncated", content)
            self.assertIn("normal diagnostic after oversized line", content)
            self.assertNotIn("UNSTRUCTURED-SECRET-CONTINUATION", content)

    def test_kernel_app_lock_is_released_across_restart_cycles(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for relative in (".local", ".local/share", ".local/share/toolkit-pbp"):
                path = home / relative
                path.mkdir()
                path.chmod(0o700)
            for _cycle in range(4):
                descriptor = launch_pbp.acquire_lock(home, uid)
                with self.assertRaisesRegex(launch_pbp.PBPError, "already running"):
                    launch_pbp.acquire_lock(home, uid)
                os.close(descriptor)

    def test_kernel_app_lock_rejects_hardlinks_without_mutating_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for relative in (".local", ".local/share", ".local/share/toolkit-pbp"):
                path = home / relative
                path.mkdir()
                path.chmod(0o700)
            target = home / "operator-owned-data"
            target.write_text("do not mutate", encoding="utf-8")
            target.chmod(0o640)
            lock_path = home / ".local/share/toolkit-pbp/browser.lock"
            os.link(target, lock_path)

            with self.assertRaisesRegex(launch_pbp.PBPError, "unsafe PBP browser lock"):
                launch_pbp.acquire_lock(home, uid)

            self.assertEqual(target.read_text(encoding="utf-8"), "do not mutate")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(target.stat().st_nlink, 2)

    def test_kernel_app_lock_rejects_unsafe_existing_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for relative in (".local", ".local/share", ".local/share/toolkit-pbp"):
                path = home / relative
                path.mkdir()
                path.chmod(0o700)
            lock_path = home / ".local/share/toolkit-pbp/browser.lock"
            lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o644)

            with self.assertRaisesRegex(launch_pbp.PBPError, "unsafe PBP browser lock"):
                launch_pbp.acquire_lock(home, uid)

            self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o644)

    def test_unexpected_runtime_failure_still_releases_kernel_lock_for_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for relative in (
                ".local",
                ".local/share",
                ".local/share/toolkit-pbp",
                ".local/share/toolkit-pbp/profile",
            ):
                path = home / relative
                path.mkdir()
                path.chmod(0o700)
            profile = home / launch_pbp.PROFILE_RELATIVE
            patches = (
                mock.patch.object(launch_pbp, "_runtime_identity", return_value=(uid, home)),
                mock.patch.object(
                    launch_pbp,
                    "current_paths",
                    return_value=("v0.1.8", BROWSER, ADDON),
                ),
                mock.patch.object(launch_pbp, "load_persona", return_value=sample_persona()),
                mock.patch.object(launch_pbp, "profile_path", return_value=profile),
                mock.patch.object(
                    launch_pbp,
                    "validate_display_environment",
                    return_value={"HOME": str(home)},
                ),
                mock.patch.object(launch_pbp, "assert_no_profile_processes"),
                mock.patch.object(
                    launch_pbp,
                    "reconcile_native_profile_locks",
                    return_value=[],
                ),
                mock.patch.object(
                    launch_pbp,
                    "fetch_mullvad_egress",
                    return_value="185.65.134.1",
                ),
                mock.patch.object(launch_pbp, "browser_options", return_value={}),
                mock.patch.object(launch_pbp, "harden_runtime_process"),
                mock.patch.object(
                    launch_pbp,
                    "launch_browser_session",
                    side_effect=RuntimeError("simulated browser transport crash"),
                ),
                mock.patch.object(
                    launch_pbp,
                    "terminate_profile_processes",
                    return_value=[],
                ),
                mock.patch.object(launch_pbp.sys, "stderr", io.StringIO()),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
                patches[7],
                patches[8],
                patches[9],
                patches[10],
                patches[11],
                patches[12],
            ):
                self.assertEqual(
                    launch_pbp.run_browser(None),
                    launch_pbp.EXIT_BROWSER_UNEXPECTED,
                )
            descriptor = launch_pbp.acquire_lock(home, uid)
            os.close(descriptor)

    def test_native_lock_reconciliation_is_exact_and_requires_app_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            lock = profile / "lock"
            lock.symlink_to("test-host:+999999")

            def dead(_pid: int, _signal: int):
                raise ProcessLookupError()

            with self.assertRaisesRegex(launch_pbp.PBPError, "exclusive"):
                launch_pbp.reconcile_native_profile_locks(
                    profile,
                    os.geteuid(),
                    app_lock_held=False,
                    proc_root=proc_root,
                    probe=dead,
                )
            removed = launch_pbp.reconcile_native_profile_locks(
                profile,
                os.geteuid(),
                app_lock_held=True,
                proc_root=proc_root,
                probe=dead,
            )
            self.assertEqual(removed, [lock])
            self.assertFalse(lock.exists())

    def test_native_lock_reconciliation_accepts_real_gecko_parentlock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            parentlock = profile / ".parentlock"
            parentlock.touch(mode=0o664)
            parentlock.chmod(0o664)

            removed = launch_pbp.reconcile_native_profile_locks(
                profile,
                os.geteuid(),
                app_lock_held=True,
                proc_root=proc_root,
            )

            self.assertEqual(removed, [parentlock])
            self.assertFalse(parentlock.exists())

    def test_native_lock_reconciliation_rejects_other_group_writable_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            lock = profile / "lock"
            lock.touch(mode=0o664)
            lock.chmod(0o664)

            with self.assertRaisesRegex(launch_pbp.PBPError, "unsafe"):
                launch_pbp.reconcile_native_profile_locks(
                    profile,
                    os.geteuid(),
                    app_lock_held=True,
                    proc_root=proc_root,
                )

            self.assertTrue(lock.exists())

    def test_native_lock_reconciliation_removes_reused_unrelated_live_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            lock = profile / "lock"
            lock.symlink_to("test-host:+4242")
            unrelated = launch_pbp.ProcessRecord(4242, 1, os.geteuid(), 99, ("unrelated-worker",))

            with mock.patch.object(launch_pbp, "read_process_record", return_value=unrelated):
                removed = launch_pbp.reconcile_native_profile_locks(
                    profile,
                    os.geteuid(),
                    app_lock_held=True,
                    proc_root=proc_root,
                    probe=lambda _pid, _signal: None,
                )

            self.assertEqual(removed, [lock])
            self.assertFalse(lock.exists())

    def test_native_lock_reconciliation_keeps_live_exact_profile_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            lock = profile / "lock"
            lock.symlink_to("test-host:+4242")
            browser = launch_pbp.ProcessRecord(
                4242,
                1,
                os.geteuid(),
                99,
                ("camoufox-bin", "-profile", str(profile)),
            )

            with (
                mock.patch.object(launch_pbp, "read_process_record", return_value=browser),
                self.assertRaisesRegex(launch_pbp.PBPError, "live profile process"),
            ):
                launch_pbp.reconcile_native_profile_locks(
                    profile,
                    os.geteuid(),
                    app_lock_held=True,
                    proc_root=proc_root,
                    probe=lambda _pid, _signal: None,
                )

            self.assertTrue(lock.is_symlink())

    def test_native_lock_reconciliation_keeps_unreadable_live_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            proc_root = root / "proc"
            profile.mkdir(mode=0o700)
            proc_root.mkdir(mode=0o700)
            lock = profile / "lock"
            lock.symlink_to("test-host:+4242")

            with (
                mock.patch.object(launch_pbp, "read_process_record", return_value=None),
                self.assertRaisesRegex(launch_pbp.PBPError, "verify process identity"),
            ):
                launch_pbp.reconcile_native_profile_locks(
                    profile,
                    os.geteuid(),
                    app_lock_held=True,
                    proc_root=proc_root,
                    probe=lambda _pid, _signal: None,
                )

            self.assertTrue(lock.is_symlink())

    def test_profile_process_matching_does_not_match_siblings(self):
        profile = Path("/home/malwarelab/.local/share/toolkit-pbp/profile")
        exact = launch_pbp.ProcessRecord(100, 1, 1000, 10, ("camoufox-bin", "-profile", str(profile)))
        sibling = launch_pbp.ProcessRecord(101, 1, 1000, 11, ("camoufox-bin", "--profile=" + str(profile) + "-other"))
        unrelated = launch_pbp.ProcessRecord(
            102, 1, 1000, 12, ("camoufox-bin", "https://example.test/?profile=" + str(profile))
        )
        self.assertTrue(launch_pbp.process_uses_profile(exact, profile))
        self.assertFalse(launch_pbp.process_uses_profile(sibling, profile))
        self.assertFalse(launch_pbp.process_uses_profile(unrelated, profile))

    def test_profile_cleanup_tree_contains_only_exact_root_and_descendants(self):
        profile = Path("/home/malwarelab/.local/share/toolkit-pbp/profile")
        records = [
            launch_pbp.ProcessRecord(100, 1, 1000, 1, ("browser", "-profile", str(profile))),
            launch_pbp.ProcessRecord(101, 100, 1000, 2, ("browser-child",)),
            launch_pbp.ProcessRecord(102, 101, 1000, 3, ("content-child",)),
            launch_pbp.ProcessRecord(200, 1, 1000, 4, ("unrelated",)),
        ]
        with mock.patch.object(launch_pbp, "list_user_processes", return_value=records):
            tree = launch_pbp._profile_process_tree(profile, 1000)
        self.assertEqual({record.pid for record in tree}, {100, 101, 102})

    def test_profile_cleanup_uses_term_then_bounded_kill_with_starttime_checks(self):
        profile = Path("/home/malwarelab/.local/share/toolkit-pbp/profile")
        records = [
            launch_pbp.ProcessRecord(100, 1, 1000, 1, ("browser", "-profile", str(profile))),
            launch_pbp.ProcessRecord(101, 100, 1000, 2, ("browser-child",)),
        ]
        alive = {100: True, 101: True}
        signals: list[tuple[int, int]] = []

        def same(record, _proc_root):
            return alive[record.pid]

        def kill(pid: int, signum: int):
            signals.append((pid, signum))
            if signum == launch_pbp.signal.SIGKILL:
                alive[pid] = False

        with (
            mock.patch.object(launch_pbp, "_profile_process_tree", return_value=records),
            mock.patch.object(launch_pbp, "_same_process", side_effect=same),
        ):
            survivors = launch_pbp.terminate_profile_processes(
                profile,
                1000,
                kill=kill,
                wait=lambda _delay: None,
                grace_seconds=0,
            )
        self.assertEqual(survivors, [])
        self.assertEqual(
            signals,
            [
                (101, launch_pbp.signal.SIGTERM),
                (100, launch_pbp.signal.SIGTERM),
                (100, launch_pbp.signal.SIGKILL),
                (101, launch_pbp.signal.SIGKILL),
            ],
        )

    def test_pidfd_recheck_refuses_a_reused_numeric_pid(self):
        record = launch_pbp.ProcessRecord(100, 1, 1000, 42, ("browser",))
        with (
            mock.patch.object(launch_pbp.os, "pidfd_open", return_value=77),
            mock.patch.object(launch_pbp.signal, "pidfd_send_signal") as send_signal,
            mock.patch.object(launch_pbp.os, "close") as close,
            mock.patch.object(launch_pbp, "_same_process", return_value=False),
        ):
            self.assertFalse(launch_pbp._signal_process_record(record, launch_pbp.signal.SIGTERM))
        send_signal.assert_not_called()
        close.assert_called_once_with(77)

    def test_process_tracker_retains_descendants_after_browser_root_disappears(self):
        profile = Path("/home/malwarelab/.local/share/toolkit-pbp/profile")
        records = [
            launch_pbp.ProcessRecord(100, 1, 1000, 1, ("browser", "-profile", str(profile))),
            launch_pbp.ProcessRecord(101, 100, 1000, 2, ("browser-child",)),
        ]
        clock_values = iter((0.0, 2.0))
        tracker = launch_pbp.ProfileProcessTracker(
            profile,
            1000,
            clock=lambda: next(clock_values),
        )
        with mock.patch.object(
            launch_pbp,
            "_profile_process_tree",
            side_effect=(records, []),
        ):
            tracker.sample()
            tracker.sample()
        self.assertEqual(
            {(record.pid, record.start_time) for record in tracker.captured()},
            {(100, 1), (101, 2)},
        )

    def test_initial_egress_retry_is_bounded_and_definitive_failure_is_immediate(self):
        calls = iter(
            [
                launch_pbp.EgressTransientError("temporary one"),
                launch_pbp.EgressTransientError("temporary two"),
                "185.65.134.1",
            ]
        )

        def checker():
            value = next(calls)
            if isinstance(value, BaseException):
                raise value
            return value

        sleeps: list[float] = []
        self.assertEqual(
            launch_pbp.fetch_mullvad_egress(
                attempts=3,
                sleep=sleeps.append,
                jitter=lambda: 0,
                checker=checker,
            ),
            "185.65.134.1",
        )
        self.assertEqual(sleeps, [1, 2])
        definite_calls = 0

        def definite():
            nonlocal definite_calls
            definite_calls += 1
            raise launch_pbp.EgressDefinitiveError("wrong country")

        with self.assertRaises(launch_pbp.EgressDefinitiveError):
            launch_pbp.fetch_mullvad_egress(
                attempts=9,
                sleep=lambda _delay: self.fail("must not retry a proven wrong egress"),
                checker=definite,
            )
        self.assertEqual(definite_calls, 1)

    def test_egress_recovery_requires_two_consecutive_successes(self):
        outcomes = iter(
            [
                "185.65.134.1",
                launch_pbp.EgressTransientError("again"),
                "185.65.134.1",
                "185.65.134.1",
            ]
        )

        def checker():
            value = next(outcomes)
            if isinstance(value, BaseException):
                raise value
            return value

        monitor = launch_pbp.EgressMonitor(checker=checker, attempts=4, random_value=lambda: 0)
        monitor._wait = lambda _delay: False
        self.assertTrue(monitor._recover())
        kinds = []
        while not monitor.events.empty():
            kinds.append(monitor.events.get_nowait().kind)
        self.assertEqual(kinds, ["confirming", "confirming", "recovered"])

    def test_egress_recovery_rejects_a_changed_relay_before_reenabling_network(self):
        monitor = launch_pbp.EgressMonitor(
            checker=lambda: "185.65.134.2",
            attempts=5,
            random_value=lambda: 0,
            expected_exit_ip="185.65.134.1",
        )
        monitor._wait = lambda _delay: False

        self.assertFalse(monitor._recover())
        event = monitor.events.get_nowait()
        self.assertEqual(event.kind, "changed")
        self.assertEqual(event.exit_ip, "185.65.134.2")
        self.assertTrue(monitor.events.empty())

    def test_periodic_relay_change_is_reported_without_retry(self):
        monitor = launch_pbp.EgressMonitor(
            checker=lambda: "185.65.134.2",
            interval=30,
            expected_exit_ip="185.65.134.1",
        )
        waits = iter([False])
        monitor._wait = lambda _delay: next(waits)
        monitor._run()
        event = monitor.events.get_nowait()
        self.assertEqual(event.kind, "changed")
        self.assertEqual(event.exit_ip, "185.65.134.2")
        self.assertTrue(monitor.events.empty())

    def test_unexpected_monitor_exception_is_terminal_fail_closed_event(self):
        monitor = launch_pbp.EgressMonitor(
            checker=lambda: (_ for _ in ()).throw(RuntimeError("worker defect")),
            interval=30,
        )
        monitor._wait = lambda _delay: False
        monitor._run()
        event = monitor.events.get_nowait()
        self.assertEqual(event.kind, "monitor_failure")
        self.assertNotIn("worker defect", event.detail)

    def test_monitor_stop_is_bounded_and_suppresses_late_checker_results(self):
        checker_started = threading.Event()
        release_checker = threading.Event()

        def checker():
            checker_started.set()
            release_checker.wait(5)
            return "185.65.134.1"

        monitor = launch_pbp.EgressMonitor(checker=checker, interval=0)
        monitor.start()
        self.assertTrue(checker_started.wait(1))
        started = time.monotonic()
        self.assertFalse(monitor.stop())
        self.assertLess(time.monotonic() - started, 1.0)
        release_checker.set()
        assert monitor._thread is not None
        monitor._thread.join(1)
        self.assertFalse(monitor._thread.is_alive())
        self.assertTrue(monitor.events.empty())

    def _supervise(self, context, events=(), signum=None, exit_ip="185.65.134.1"):
        monitor = FakeMonitor(events)
        runtime_log = FakeRuntimeLog()
        result = launch_pbp.supervise_context(
            context,
            monitor=monitor,
            runtime_log=runtime_log,
            signal_latch=FakeSignalLatch(signum),
            expected_exit_ip=exit_ip,
            timeout_error=FakeTimeout,
        )
        self.assertTrue(monitor.started)
        self.assertTrue(monitor.stopped)
        return result, runtime_log

    def test_dispatcher_is_pumped_and_normal_close_releases_lifecycle(self):
        context = FakeContext()
        page = context.pages[0]
        context.actions = [lambda: (page.emit("close"), context.emit("close"))]
        result, runtime_log = self._supervise(context)
        self.assertEqual(result.reason, "normal_user_close")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(context.pump_calls, 1)
        self.assertEqual(
            runtime_log.records[:3],
            [
                ("browser.page_opened", {"open_pages": 1}),
                ("browser.page_closed", {"open_pages": 0}),
                ("browser.context_closed", {"open_pages": 0}),
            ],
        )

    def test_unexpected_context_close_is_not_misreported_as_user_close(self):
        context = FakeContext()
        context.actions = [lambda: context.emit("close")]
        result, _log = self._supervise(context)
        self.assertEqual(result.reason, "browser_closed_unexpectedly")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_BROWSER_UNEXPECTED)

    def test_page_crash_is_visible_and_never_auto_restarted(self):
        context = FakeContext()
        page = context.pages[0]
        context.actions = [lambda: page.emit("crash")]
        result, runtime_log = self._supervise(context)
        self.assertEqual(result.reason, "browser_crash")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_BROWSER_CRASH)
        self.assertEqual(context.close_calls, 1)
        self.assertIn(
            ("browser.page_crashed", {"open_pages": 1}),
            runtime_log.records,
        )

    def test_process_tracking_failure_closes_browser_fail_closed(self):
        context = FakeContext()

        def fail_tracking():
            raise launch_pbp.PBPError("process table unavailable")

        monitor = FakeMonitor()
        runtime_log = FakeRuntimeLog()
        result = launch_pbp.supervise_context(
            context,
            monitor=monitor,
            runtime_log=runtime_log,
            signal_latch=FakeSignalLatch(),
            expected_exit_ip="185.65.134.1",
            timeout_error=FakeTimeout,
            process_tracker=fail_tracking,
        )
        self.assertEqual(result.reason, "browser_cleanup_failed")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_BROWSER_UNEXPECTED)
        self.assertEqual(context.offline, [True])
        self.assertEqual(context.close_calls, 1)

    def test_wrong_egress_immediately_forces_offline_and_closes(self):
        context = FakeContext()
        event = launch_pbp.EgressEvent("definitive", "outside Germany")
        result, _log = self._supervise(context, [event])
        self.assertEqual(result.reason, "vpn_wrong")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_VPN)
        self.assertEqual(context.offline, [True])
        self.assertEqual(context.close_calls, 1)
        self.assertEqual(context.pump_calls, 0)

    def test_monitor_worker_failure_forces_offline_and_closes(self):
        context = FakeContext()
        event = launch_pbp.EgressEvent("monitor_failure", "worker failed")
        result, _log = self._supervise(context, [event])
        self.assertEqual(result.reason, "vpn_control_failure")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_VPN)
        self.assertEqual(context.offline, [True])
        self.assertEqual(context.close_calls, 1)

    def test_temporary_egress_failure_stays_offline_until_confirmed_recovery(self):
        context = FakeContext()
        page = context.pages[0]
        context.actions = [lambda: (page.emit("close"), context.emit("close"))]
        events = [
            launch_pbp.EgressEvent("transient", "endpoint down"),
            launch_pbp.EgressEvent("confirming", "one success"),
            launch_pbp.EgressEvent("recovered", "two successes", "185.65.134.1"),
        ]
        result, _log = self._supervise(context, events)
        self.assertEqual(result.reason, "normal_user_close")
        self.assertEqual(context.offline, [True, False])

    def test_relay_change_remains_fail_closed_until_explicit_restart(self):
        context = FakeContext()
        events = [
            launch_pbp.EgressEvent("transient", "endpoint down"),
            launch_pbp.EgressEvent("recovered", "two successes", "185.65.134.2"),
        ]
        result, _log = self._supervise(context, events)
        self.assertEqual(result.reason, "vpn_relay_changed")
        self.assertEqual(result.exit_code, launch_pbp.EXIT_VPN)
        self.assertEqual(context.offline, [True])
        self.assertEqual(context.close_calls, 1)

    def test_signal_requests_controlled_close(self):
        context = FakeContext()
        result, _log = self._supervise(context, signum=15)
        self.assertEqual(result.reason, "signal")
        self.assertEqual(result.exit_code, 143)
        self.assertEqual(context.offline, [True])
        self.assertEqual(context.close_calls, 1)

    def test_virtual_thirty_minute_soak_keeps_dispatching_then_closes_cleanly(self):
        context = FakeContext()
        page = context.pages[0]
        ticks = int((30 * 60 * 1000) / launch_pbp.DISPATCH_PUMP_MS)
        context.actions = [lambda: None for _ in range(ticks - 1)]
        context.actions.append(lambda: (page.emit("close"), context.emit("close")))
        result, _log = self._supervise(context)
        self.assertEqual(result.reason, "normal_user_close")
        self.assertEqual(context.pump_calls, ticks)

    def test_three_full_close_and_restart_lifecycle_cycles(self):
        for _cycle in range(3):
            context = FakeContext()
            page = context.pages[0]
            context.actions = [lambda: (page.emit("close"), context.emit("close"))]
            result, _log = self._supervise(context)
            self.assertEqual(result.exit_code, 0)

    def test_v017_event_wait_model_keeps_lock_until_v018_dispatch_pump(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            uid = os.geteuid()
            for relative in (".local", ".local/share", ".local/share/toolkit-pbp"):
                path = home / relative
                path.mkdir()
                path.chmod(0o700)

            context = FakeContext()
            page = context.pages[0]
            context.actions = [lambda: (page.emit("close"), context.emit("close"))]
            legacy_closed = threading.Event()
            context.on("close", lambda *_args: legacy_closed.set())
            descriptor = launch_pbp.acquire_lock(home, uid)
            try:
                # this is the exact v0.1.7 control-flow model: Event.wait does
                # not enter a playwright sync call, so the queued close remains
                # undispatched and the launcher continues to own its flock.
                self.assertFalse(legacy_closed.wait(0.01))
                self.assertEqual(context.pump_calls, 0)
                with self.assertRaisesRegex(launch_pbp.PBPError, "already running"):
                    launch_pbp.acquire_lock(home, uid)

                result, _log = self._supervise(context)
                self.assertEqual(result.reason, "normal_user_close")
                self.assertTrue(legacy_closed.is_set())
                self.assertEqual(context.pump_calls, 1)
            finally:
                os.close(descriptor)
            restarted = launch_pbp.acquire_lock(home, uid)
            os.close(restarted)

    def test_desktop_failure_uses_visible_dialog_with_action_and_log_path(self):
        result = launch_pbp.LifecycleResult("vpn_wrong", launch_pbp.EXIT_VPN, "wrong")
        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(launch_pbp.subprocess, "run") as run,
        ):
            run.return_value.returncode = 0
            launch_pbp.show_desktop_failure(result, Path("/safe/runtime.jsonl"))
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[0], "/usr/bin/zenity")
        rendered = " ".join(arguments)
        self.assertIn("fail-closed", rendered)
        self.assertIn("/safe/runtime.jsonl", rendered)

    def test_pre_log_desktop_exception_still_opens_a_generic_visible_dialog(self):
        args = type("Args", (), {"url": None})()
        with (
            mock.patch.object(launch_pbp, "run_browser", side_effect=OSError("raw internal detail")),
            mock.patch.object(launch_pbp, "show_desktop_failure") as show,
        ):
            self.assertEqual(launch_pbp.command_desktop(args), launch_pbp.EXIT_STARTUP)
        result, log_path = show.call_args.args
        self.assertEqual(result.reason, "startup_error")
        self.assertNotIn("raw internal detail", result.detail)
        self.assertIsNone(log_path)

    def test_runtime_policy_treats_disconnect_as_transient_not_wrong_configuration(self):
        bootstrap = (ROOT / "bootstrap-pbp.sh").read_text(encoding="utf-8")
        helper = bootstrap.split("<<'EOF_POLICY_HELPER'\n", 1)[1].split("\nEOF_POLICY_HELPER", 1)[0]
        self.assertIn(
            "[[ \"$connection_state\" == 'connected' ]] || transient_failure",
            helper,
        )
        self.assertIn(
            '.obfuscation.Single.obfuscation_type == "Shadowsocks"',
            helper,
        )
        self.assertIn('<<<"$status_json" >/dev/null || policy_failure', helper)

    def test_boot_guard_repairs_connected_but_unroutable_mullvad_fail_closed(self):
        bootstrap = (ROOT / "bootstrap-pbp.sh").read_text(encoding="utf-8")
        helper = bootstrap.split("<<'EOF_EGRESS_GUARD'\n", 1)[1].split("\nEOF_EGRESS_GUARD", 1)[0]
        self.assertIn('apply_rules "$uid" || guard_error', helper)
        self.assertIn("dynamicflow-pbp-loopback-replies", helper)
        self.assertIn("ct state established,related", helper)
        self.assertIn("/usr/sbin/runuser -u malwarelab -- /usr/bin/curl", helper)
        self.assertIn("/usr/bin/mullvad disconnect --wait", helper)
        self.assertIn("/usr/bin/mullvad connect --wait", helper)
        self.assertIn("after one Mullvad reconnect", helper)
        self.assertIn(
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETUID",
            bootstrap,
        )

    def test_relay_change_dialog_explains_safe_restart_without_persona_rotation(self):
        result = launch_pbp.LifecycleResult("vpn_relay_changed", launch_pbp.EXIT_VPN, "relay changed")
        message = launch_pbp._public_failure(result, Path("/safe/runtime.jsonl"))
        self.assertIn("WebRTC", message)
        self.assertIn("bewusst erneut", message)
        self.assertIn("Persona wurde nicht ersetzt", message)
        self.assertIn("/safe/runtime.jsonl", message)


if __name__ == "__main__":
    unittest.main()
