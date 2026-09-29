#!/usr/bin/env python3
"""interactive Camoufox launcher for the toolkit PBP disposable VM."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from copy import deepcopy
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import pwd
import queue
import random
import re
import resource
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


EXPECTED_USER = "malwarelab"
PERSONA_PATH = Path("/etc/toolkit/pbp-persona.json")
CURRENT_ROOT = Path("/opt/toolkit/pbp/current")
MULLVAD_CHECK_URL = "https://am.i.mullvad.net/json"
MULLVAD_POLICY_HELPER = Path("/usr/local/libexec/dynamicflow-pbp-vpn-verify")
PERSONA_SCHEMA = 3
LEGACY_PERSONA_SCHEMAS = frozenset({1, 2})
CAMOUFOX_PACKAGE_VERSION = "0.6.0"
BROWSER_VERSION = "150.0.2-beta.25"
BROWSER_MAJOR = 150
LOCALE = "de-DE"
TIMEZONE = "Europe/Berlin"
RUNTIME_LOG_RELATIVE = Path(".local/state/dynamicflow/pbp/logs")
PROFILE_RELATIVE = Path(".local/share/toolkit-pbp/profile")
LOG_FILE_RE = re.compile(r"^runtime-[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}[.]jsonl$")
LOG_MAX_BYTES = 4 * 1024 * 1024
LOG_RETAIN = 8
DISPATCH_PUMP_MS = 250
EGRESS_CHECK_INTERVAL = 30.0
EGRESS_RECOVERY_ATTEMPTS = 5
EGRESS_BACKOFF_MAX = 16.0
EGRESS_SUCCESS_CONFIRMATION_DELAY = 2.0
EXIT_STARTUP = 20
EXIT_BROWSER_CRASH = 21
EXIT_VPN = 22
EXIT_BROWSER_UNEXPECTED = 23
RELEASE_RE = re.compile(r"^v[0-9]+[.][0-9]+[.][0-9]+(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?$")
COMMON_SCREENS = {
    (1600, 900),
}
DEFAULT_PERSONA_CLASS = "basic"
PERSONA_CLASSES: dict[str, dict[str, Any]] = {
    "basic": {
        "hardwareConcurrency": 4,
        "maxTouchPoints": 0,
        "width": 1600,
        "height": 900,
        "availWidth": 1600,
        "availHeight": 840,
        "devicePixelRatio": 1.2,
        "vendor": "Google Inc. (Intel)",
        "renderer": ("ANGLE (Intel, Intel(R) HD Graphics 400 Direct3D11 vs_5_0 ps_5_0), or similar"),
    },
    "performance": {
        "hardwareConcurrency": 8,
        "maxTouchPoints": 0,
        "width": 1600,
        "height": 900,
        "availWidth": 1600,
        "availHeight": 860,
        "devicePixelRatio": 1.0,
        "vendor": "Google Inc. (NVIDIA)",
        "renderer": ("ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar"),
    },
    "workstation": {
        "hardwareConcurrency": 12,
        "maxTouchPoints": 0,
        "width": 1600,
        "height": 900,
        "availWidth": 1600,
        "availHeight": 900,
        "devicePixelRatio": 1.2,
        "vendor": "Google Inc. (Intel)",
        "renderer": ("ANGLE (Intel, Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0), or similar"),
    },
}
HARDENED_FIREFOX_PREFS: dict[str, bool | int | str] = {
    "browser.download.start_downloads_in_tmp_dir": False,
    "browser.download.useDownloadDir": False,
    "browser.safebrowsing.allowOverride": False,
    "browser.safebrowsing.blockedURIs.enabled": True,
    "browser.safebrowsing.downloads.enabled": True,
    "browser.safebrowsing.malware.enabled": True,
    "browser.safebrowsing.phishing.enabled": True,
    "camoufox.uBO.assetsBootstrapLocation": "",
    "devtools.debugger.prompt-connection": True,
    "devtools.debugger.remote-enabled": False,
    "dom.disable_open_during_load": True,
    "dom.file.createInChild": False,
    "dom.filesystem.pathcheck.disabled": False,
    "dom.security.https_only_mode": True,
    "extensions.blocklist.enabled": True,
    "extensions.quarantinedDomains.enabled": True,
    "focusmanager.testmode": False,
    "network.cookie.cookieBehavior": 5,
    "network.dns.disablePrefetch": True,
    "network.dns.disablePrefetchFromHTTPS": True,
    "network.proxy.type": 0,
    "network.trr.mode": 5,
    "permissions.default.camera": 2,
    "permissions.default.desktop-notification": 2,
    "permissions.default.geo": 2,
    "permissions.default.microphone": 2,
    "privacy.partition.network_state": True,
    "privacy.trackingprotection.enabled": True,
    "security.enterprise_roots.enabled": False,
    "security.certerror.hideAddException": True,
    "security.fileuri.strict_origin_policy": True,
    "security.notification_enable_delay": 1000,
    "vulpineos.actionlock.enabled": False,
    "vulpineos.dom_export.enabled": False,
    "vulpineos.injection_filter.enabled": False,
    "vulpineos.sentinel.probe.enabled": False,
    "vulpineos.trustwarm.enabled": False,
}


class PBPError(RuntimeError):
    pass


class EgressTransientError(PBPError):
    """the egress could not be established, but was not proven unsafe."""


class EgressDefinitiveError(PBPError):
    """the egress was positively proven to violate the PBP policy."""


@dataclass(frozen=True)
class EgressEvent:
    kind: str
    detail: str
    exit_ip: str | None = None


@dataclass(frozen=True)
class LifecycleResult:
    reason: str
    exit_code: int
    detail: str


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    uid: int
    start_time: int
    argv: tuple[str, ...]


def no_duplicate_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PBPError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=no_duplicate_object)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise PBPError(f"invalid JSON: {error}") from error


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_IPV4_IN_TEXT_RE = re.compile(
    r"(?<![0-9.])"
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])[.]){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?![0-9.])"
)
_IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])")
_LONG_NUMBER_RE = re.compile(r"(?<![0-9])[0-9]{10,}(?![0-9])")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?"
    r"(password|passwd|secret|token|enrollment[_-]?code|authorization|"
    r"cookie|set-cookie|api[_-]?key)"
    r"[\"']?\s*[:=]\s*(?:[\"'][^\"']*[\"']|(?:bearer\s+)?[^\s,;]+)"
)
_SECRET_KEY_RE = re.compile(
    r"(?i)^(?:password|passwd|secret|token|enrollment[_-]?code|authorization|"
    r"cookie|set-cookie|api[_-]?key)$"
)
_CAMOU_CONFIG_RE = re.compile(r"\bCAMOU_CONFIG_[0-9]+\s*=\s*\S+")


def _redact_url(match: re.Match[str]) -> str:
    value = match.group(0)
    trailing = ""
    while value and value[-1] in ".,);]":
        trailing = value[-1] + trailing
        value = value[:-1]
    return "[redacted-url]" + trailing


def _redact_ipv6_candidate(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return "[redacted-ip]" if address.version == 6 else value


def sanitize_text(value: object, limit: int = 2048) -> str:
    """return bounded, single-line diagnostics without urls, tokens, or long ids."""
    text = str(value)
    text = "".join(char if 32 <= ord(char) != 127 else " " for char in text)
    text = _URL_IN_TEXT_RE.sub(_redact_url, text)
    text = _IPV4_IN_TEXT_RE.sub("[redacted-ip]", text)
    text = _IPV6_CANDIDATE_RE.sub(_redact_ipv6_candidate, text)
    text = _CAMOU_CONFIG_RE.sub("CAMOU_CONFIG=[redacted]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = _LONG_NUMBER_RE.sub("[redacted-number]", text)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 16] + "…[truncated]"
    return text


def _safe_log_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) < 10_000_000 else "[redacted-number]"
    if isinstance(value, float):
        return value
    if isinstance(value, (str, Path, BaseException)):
        return sanitize_text(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:64]:
            safe_key = sanitize_text(key, 128)
            result[safe_key] = "[redacted]" if _SECRET_KEY_RE.fullmatch(safe_key) else _safe_log_value(item)
        return result
    if isinstance(value, (list, tuple, set)):
        return [_safe_log_value(item) for item in list(value)[:64]]
    return sanitize_text(value)


def ensure_user_directory(path: Path, uid: int) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require_real_directory(path, uid, {0o700})


class RuntimeLog:
    """one bounded JSONL file per launch; all content is sanitized before writing."""

    def __init__(self, path: Path, descriptor: int, max_bytes: int = LOG_MAX_BYTES):
        self.path = path
        self._stream = os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)
        self._max_bytes = max_bytes
        self._bytes = 0
        self._truncated = False
        self._lock = threading.Lock()

    def log(self, event: str, **fields: Any) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", event):
            event = "invalid_event"
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **{key: _safe_log_value(value) for key, value in fields.items()},
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._lock:
            if self._truncated:
                return
            if self._bytes + len(encoded) + 1 > self._max_bytes:
                encoded = json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                        "event": "log_truncated",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                self._truncated = True
            self._stream.write(encoded + "\n")
            self._stream.flush()
            self._bytes += len(encoded) + 1

    def log_exception(self, event: str, error: BaseException, **fields: Any) -> None:
        self.log(
            event,
            error_type=type(error).__name__,
            error=sanitize_text(error),
            traceback=sanitize_text(traceback.format_exc(), 8192),
            **fields,
        )

    def close(self) -> None:
        with self._lock:
            if not self._stream.closed:
                self._stream.flush()
                os.fsync(self._stream.fileno())
                self._stream.close()

    def __enter__(self) -> "RuntimeLog":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def _prune_runtime_logs(log_root: Path, uid: int, retain: int = LOG_RETAIN) -> None:
    candidates: list[tuple[int, Path]] = []
    for path in log_root.iterdir():
        if not LOG_FILE_RE.fullmatch(path.name):
            continue
        try:
            details = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(details.st_mode) and details.st_uid == uid:
            candidates.append((details.st_mtime_ns, path))
    candidates.sort(reverse=True)
    for _mtime, path in candidates[retain - 1 :]:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def open_runtime_log(home: Path, uid: int) -> RuntimeLog:
    require_real_directory(home, uid, {0o700, 0o750})
    current = home
    for component in RUNTIME_LOG_RELATIVE.parts:
        current = current / component
        ensure_user_directory(current, uid)
    log_root = current
    _prune_runtime_logs(log_root, uid)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"runtime-{timestamp}-{os.getpid()}-{secrets.token_hex(4)}.jsonl"
    path = log_root / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != uid:
        os.close(descriptor)
        raise PBPError("unsafe PBP runtime log")
    os.fchmod(descriptor, 0o600)
    return RuntimeLog(path, descriptor)


class StderrCapture(AbstractContextManager["StderrCapture"]):
    """capture browser/runtime fd 2 without putting raw diagnostics on the desktop."""

    def __init__(self, runtime_log: RuntimeLog):
        self._log = runtime_log
        self._saved: int | None = None
        self._reader: int | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "StderrCapture":
        sys.stderr.flush()
        self._saved = os.dup(2)
        reader, writer = os.pipe()
        self._reader = reader
        os.dup2(writer, 2)
        os.close(writer)
        self._thread = threading.Thread(target=self._drain, name="pbp-stderr", daemon=True)
        self._thread.start()
        return self

    def _drain(self) -> None:
        assert self._reader is not None
        try:
            with os.fdopen(self._reader, "rb", closefd=True) as source:
                pending = b""
                discarding_oversized_line = False
                while True:
                    chunk = source.read(4096)
                    if not chunk:
                        break
                    pending += chunk
                    while True:
                        if discarding_oversized_line:
                            newline = pending.find(b"\n")
                            if newline < 0:
                                pending = b""
                                break
                            pending = pending[newline + 1 :]
                            discarding_oversized_line = False
                            continue
                        newline = pending.find(b"\n")
                        if newline >= 0:
                            line, pending = pending[:newline], pending[newline + 1 :]
                            self._log.log(
                                "runtime.stderr",
                                message=line.decode("utf-8", "replace"),
                            )
                            continue
                        if len(pending) > 65536:
                            self._log.log(
                                "runtime.stderr",
                                message=pending[:65536].decode("utf-8", "replace"),
                            )
                            self._log.log(
                                "runtime.stderr_line_truncated",
                                limit_bytes=65536,
                            )
                            pending = b""
                            discarding_oversized_line = True
                        break
                if pending and not discarding_oversized_line:
                    self._log.log("runtime.stderr", message=pending.decode("utf-8", "replace"))
        except OSError as error:
            self._log.log("runtime.stderr_capture_error", error=error)

    def __exit__(self, *_args: Any) -> None:
        if self._saved is not None:
            try:
                sys.stderr.flush()
                os.dup2(self._saved, 2)
            finally:
                os.close(self._saved)
                self._saved = None
        if self._thread is not None:
            self._thread.join(timeout=0.5)
        return None

    def wait_closed(self, timeout: float = 6.0) -> bool:
        if self._thread is None:
            return True
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()


def require_regular_file(path: Path, owner: int | None, modes: set[int]) -> os.stat_result:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise PBPError(f"missing file: {path}") from error
    if not stat.S_ISREG(details.st_mode):
        raise PBPError(f"not a regular file: {path}")
    if owner is not None and details.st_uid != owner:
        raise PBPError(f"wrong owner for {path}")
    if stat.S_IMODE(details.st_mode) not in modes:
        raise PBPError(f"unsafe mode for {path}")
    return details


def require_real_directory(path: Path, owner: int, allowed_modes: set[int]) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise PBPError(f"missing directory: {path}") from error
    if not stat.S_ISDIR(details.st_mode):
        raise PBPError(f"not a real directory: {path}")
    if details.st_uid != owner:
        raise PBPError(f"wrong owner for directory: {path}")
    if stat.S_IMODE(details.st_mode) not in allowed_modes:
        raise PBPError(f"unsafe mode for directory: {path}")


def require_addon_directory(path: Path, owner: int) -> None:
    require_real_directory(path, owner, {0o755})
    require_regular_file(path / "manifest.json", owner, {0o644})


def persona_id_for(persona: dict[str, Any]) -> str:
    identity = deepcopy(persona)
    identity.pop("persona_id", None)
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalized_preset_voices(preset: dict[str, Any]) -> list[str]:
    raw = preset.get("speechVoices")
    if not isinstance(raw, list) or not raw:
        raise PBPError("persona preset has no speech voice cohort")
    result: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry:
            raise PBPError("persona preset contains a malformed speech voice")
        name = entry.split(":", 1)[0]
        if not name or name in result:
            raise PBPError("persona preset contains an invalid speech voice cohort")
        result.append(name)
    return result


def preset_matches_persona_class(preset: dict[str, Any], persona_class: str) -> bool:
    signature = PERSONA_CLASSES.get(persona_class)
    if signature is None:
        return False
    navigator = preset.get("navigator")
    screen = preset.get("screen")
    webgl = preset.get("webgl")
    if not all(isinstance(section, dict) for section in (navigator, screen, webgl)):
        return False
    return bool(
        navigator.get("platform") == "Win32"
        and navigator.get("hardwareConcurrency") == signature["hardwareConcurrency"]
        and navigator.get("maxTouchPoints", 0) == signature["maxTouchPoints"]
        and screen.get("width") == signature["width"]
        and screen.get("height") == signature["height"]
        and screen.get("availWidth") == signature["availWidth"]
        and screen.get("availHeight") == signature["availHeight"]
        and screen.get("devicePixelRatio") == signature["devicePixelRatio"]
        and webgl.get("unmaskedVendor") == signature["vendor"]
        and webgl.get("unmaskedRenderer") == signature["renderer"]
    )


def validate_persona(
    persona: Any,
    *,
    release: str | None = None,
    browser_path: Path,
    addon_path: Path,
) -> dict[str, Any]:
    if not isinstance(persona, dict):
        raise PBPError("persona root must be an object")
    expected_keys = {
        "schema",
        "persona_id",
        "browser_version",
        "browser_major",
        "camoufox_package_version",
        "persona_class",
        "os",
        "locale",
        "timezone",
        "preset",
        "config",
        "firefox_user_prefs",
    }
    if set(persona) != expected_keys:
        raise PBPError("persona has missing or unexpected top-level keys")
    if (
        persona["schema"] != PERSONA_SCHEMA
        or persona["browser_version"] != BROWSER_VERSION
        or persona["browser_major"] != BROWSER_MAJOR
        or persona["camoufox_package_version"] != CAMOUFOX_PACKAGE_VERSION
        or persona["persona_class"] not in PERSONA_CLASSES
        or persona["os"] != "windows"
        or persona["locale"] != LOCALE
        or persona["timezone"] != TIMEZONE
    ):
        raise PBPError(
            "the stable persona is incompatible with this browser runtime; explicit operator rotation is required"
        )
    persona_id = persona["persona_id"]
    if (
        not isinstance(persona_id, str)
        or not re.fullmatch(r"[0-9a-f]{64}", persona_id)
        or persona_id != persona_id_for(persona)
    ):
        raise PBPError("persona identity hash is invalid")
    if release is not None and not RELEASE_RE.fullmatch(release):
        raise PBPError("invalid runtime release")

    preset = persona["preset"]
    config = persona["config"]
    prefs = persona["firefox_user_prefs"]
    if not isinstance(preset, dict) or not isinstance(config, dict) or not isinstance(prefs, dict):
        raise PBPError("persona sections must be objects")
    navigator = preset.get("navigator")
    if not isinstance(navigator, dict) or navigator.get("platform") != "Win32":
        raise PBPError("persona preset is not a Windows preset")
    preset_screen = preset.get("screen")
    preset_webgl = preset.get("webgl")
    if not isinstance(preset_screen, dict) or not isinstance(preset_webgl, dict):
        raise PBPError("persona preset is incomplete")
    persona_class = persona["persona_class"]
    if not preset_matches_persona_class(preset, persona_class):
        raise PBPError("persona preset does not match its selected class")

    required_config = {
        "navigator.userAgent",
        "navigator.platform",
        "navigator.oscpu",
        "navigator.hardwareConcurrency",
        "navigator.maxTouchPoints",
        "screen.width",
        "screen.height",
        "screen.availWidth",
        "screen.availHeight",
        "screen.colorDepth",
        "screen.pixelDepth",
        "window.devicePixelRatio",
        "webGl:vendor",
        "webGl:renderer",
        "fonts",
        "voices",
        "fonts:spacing_seed",
        "audio:seed",
        "canvas:seed",
        "timezone",
        "locale:language",
        "locale:region",
        "locale:script",
    }
    if not required_config.issubset(config):
        raise PBPError("persona is missing required fingerprint fields")
    if "window.history.length" in config:
        raise PBPError("persona contains session history as a persistent identity field")
    user_agent = config.get("navigator.userAgent")
    if not isinstance(user_agent, str) or not re.search(
        rf"\brv:{BROWSER_MAJOR}[.]0\b.*\bFirefox/{BROWSER_MAJOR}[.]0\b", user_agent
    ):
        raise PBPError("persona user agent does not match the browser engine")
    if config.get("navigator.platform") != "Win32":
        raise PBPError("persona JavaScript platform is not Win32")
    if config.get("navigator.hardwareConcurrency") != navigator.get("hardwareConcurrency"):
        raise PBPError("persona CPU value contradicts its real preset")
    if config.get("navigator.maxTouchPoints") != navigator.get("maxTouchPoints", 0):
        raise PBPError("persona touch value contradicts its real preset")
    oscpu = config.get("navigator.oscpu")
    if not isinstance(oscpu, str) or not oscpu.startswith("Windows NT "):
        raise PBPError("persona oscpu is not Windows")
    if (
        config.get("timezone") != TIMEZONE
        or config.get("locale:language") != "de"
        or config.get("locale:region") != "DE"
        or config.get("locale:script") != "Latn"
    ):
        raise PBPError("persona locale or timezone is inconsistent")
    if "addons" in config:
        raise PBPError("stable persona contains a release-specific add-on path")
    if any(key.startswith("webrtc:") for key in config):
        raise PBPError("stable persona contains session-specific network identity data")
    for key in ("fonts", "voices"):
        value = config.get(key)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise PBPError(f"invalid persona list: {key}")
    if config.get("voices") != normalized_preset_voices(preset):
        raise PBPError("persona voices contradict its real preset")
    for key in ("fonts:spacing_seed", "audio:seed", "canvas:seed"):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 4_294_967_295):
            raise PBPError(f"invalid persona seed: {key}")
    for key in (
        "screen.width",
        "screen.height",
        "screen.availWidth",
        "screen.availHeight",
        "screen.colorDepth",
        "screen.pixelDepth",
    ):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PBPError(f"invalid persona screen field: {key}")
    device_pixel_ratio = config.get("window.devicePixelRatio")
    if (
        not isinstance(device_pixel_ratio, (int, float))
        or isinstance(device_pixel_ratio, bool)
        or not (0.5 <= float(device_pixel_ratio) <= 4.0)
    ):
        raise PBPError("invalid persona device pixel ratio")
    if config["screen.availWidth"] > config["screen.width"] or config["screen.availHeight"] > config["screen.height"]:
        raise PBPError("persona available screen exceeds its screen dimensions")
    if (
        config.get("screen.width") != preset_screen.get("width")
        or config.get("screen.height") != preset_screen.get("height")
        or config.get("screen.availWidth") != preset_screen.get("availWidth")
        or config.get("screen.availHeight") != preset_screen.get("availHeight")
        or config.get("screen.colorDepth") != preset_screen.get("colorDepth")
        or config.get("screen.pixelDepth") != preset_screen.get("colorDepth")
        or config.get("window.devicePixelRatio") != preset_screen.get("devicePixelRatio")
        or config.get("webGl:vendor") != preset_webgl.get("unmaskedVendor")
        or config.get("webGl:renderer") != preset_webgl.get("unmaskedRenderer")
    ):
        raise PBPError("persona screen or WebGL values contradict its real preset")
    for key, expected in HARDENED_FIREFOX_PREFS.items():
        if prefs.get(key) != expected:
            raise PBPError(f"persona is missing locked browser hardening preference: {key}")
    if prefs.get("webgl.disabled") is True or prefs.get("media.peerconnection.enabled") is False:
        raise PBPError("persona disables a normal browser surface")
    if not isinstance(prefs.get("webgl.force-enabled"), bool) or not prefs["webgl.force-enabled"]:
        raise PBPError("persona does not enable its spoofed WebGL surface")
    if not browser_path.is_absolute() or not addon_path.is_absolute():
        raise PBPError("runtime paths must be absolute")
    return persona


def migrate_persona(
    persona: Any,
    *,
    browser_path: Path,
    addon_path: Path,
) -> dict[str, Any]:
    """validate schema 3; older fingerprints require an explicit VM rotation."""
    schema = persona.get("schema") if isinstance(persona, dict) else None
    if schema == PERSONA_SCHEMA:
        return validate_persona(
            deepcopy(persona),
            browser_path=browser_path,
            addon_path=addon_path,
        )
    if schema in LEGACY_PERSONA_SCHEMAS:
        raise PBPError(
            f"persona schema {schema} cannot be migrated without changing its fingerprint; "
            "rotate the persona and browser profile together in a fresh disposable VM"
        )
    raise PBPError("persona schema is unsupported; refusing to replace the persona")


def load_persona(
    path: Path,
    *,
    release: str | None,
    browser_path: Path,
    addon_path: Path,
    require_root_file: bool = True,
) -> dict[str, Any]:
    if require_root_file:
        details = require_regular_file(path, 0, {0o644})
        if details.st_size > 2 * 1024 * 1024:
            raise PBPError("persona file is unexpectedly large")
    data = path.read_text(encoding="utf-8")
    return validate_persona(
        parse_json(data),
        release=release,
        browser_path=browser_path,
        addon_path=addon_path,
    )


def database_backed_windows_presets(candidates: list[Any], sample_webgl: Any) -> list[dict[str, Any]]:
    supported: list[dict[str, Any]] = []
    pair_support: dict[tuple[str, str], bool] = {}

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        navigator = candidate.get("navigator", {})
        webgl = candidate.get("webgl", {})
        if navigator.get("platform") != "Win32" or not isinstance(webgl, dict):
            continue
        vendor = webgl.get("unmaskedVendor")
        renderer = webgl.get("unmaskedRenderer")
        if not isinstance(vendor, str) or not isinstance(renderer, str):
            continue
        pair = (vendor, renderer)
        if pair not in pair_support:
            try:
                sample_webgl("win", vendor, renderer)
            except ValueError:
                pair_support[pair] = False
            else:
                pair_support[pair] = True
        if not pair_support[pair]:
            continue
        supported.append(candidate)
    return supported


def choose_windows_preset(persona_class: str) -> dict[str, Any]:
    from camoufox.fingerprints import load_presets
    from camoufox.webgl import sample_webgl

    if persona_class not in PERSONA_CLASSES:
        raise PBPError(f"unknown persona class: {persona_class}")
    preset_data = load_presets(BROWSER_MAJOR)
    if not isinstance(preset_data, dict):
        raise PBPError("Camoufox did not provide fingerprint presets")
    groups = preset_data.get("presets")
    candidates = groups.get("windows") if isinstance(groups, dict) else None
    if not isinstance(candidates, list) or not candidates:
        raise PBPError("Camoufox has no real Windows fingerprint presets")
    supported = database_backed_windows_presets(candidates, sample_webgl)
    if not supported:
        raise PBPError("Camoufox has no database-backed Windows WebGL presets")

    matches = [candidate for candidate in supported if preset_matches_persona_class(candidate, persona_class)]
    if len(matches) != 1:
        raise PBPError(f"Camoufox must provide exactly one pinned {persona_class} persona preset")
    return deepcopy(matches[0])


def materialization_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "USER": EXPECTED_USER,
        "LOGNAME": EXPECTED_USER,
        "SHELL": "/bin/bash",
        "LANG": "de_DE.UTF-8",
        "LC_ALL": "de_DE.UTF-8",
        "TZ": TIMEZONE,
        "GDK_BACKEND": "x11",
        "MOZ_ENABLE_WAYLAND": "0",
    }


def local_fontconfig(browser_root: Path, home: Path) -> Path:
    require_real_directory(browser_root, 0, {0o755})
    require_real_directory(browser_root / "fonts", 0, {0o755})
    source = browser_root / "fontconfig" / "windows" / "fonts.conf"
    if not source.exists():
        source = browser_root / "fontconfigs" / "windows" / "fonts.conf"
    details = require_regular_file(source, 0, {0o644})
    if details.st_size > 1024 * 1024:
        raise PBPError("bundled fontconfig is unexpectedly large")
    try:
        content = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PBPError(f"could not read bundled fontconfig: {error}") from error
    marker = '<dir prefix="cwd">fonts</dir>'
    if content.count(marker) != 1:
        raise PBPError("bundled fontconfig has an unexpected font path")
    content = content.replace(marker, f"<dir>{browser_root / 'fonts'}</dir>")

    uid = os.geteuid()
    cache_root = home / ".cache"
    require_real_directory(cache_root, uid, {0o700})
    cache_dir = cache_root / "toolkit-pbp"
    try:
        cache_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require_real_directory(cache_dir, uid, {0o700})
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    destination = cache_dir / f"fontconfig-windows-{digest}.conf"
    if destination.exists() or destination.is_symlink():
        existing = require_regular_file(destination, uid, {0o600})
        if existing.st_size > 1024 * 1024 or destination.read_text(encoding="utf-8") != content:
            raise PBPError("existing PBP fontconfig does not match the pinned browser")
        return destination

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        payload = content.encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o600, follow_symlinks=False)
    return destination


def local_env_vars(config: dict[str, Any], target_os: str, browser_root: Path, home: Path) -> dict[str, str]:
    if target_os != "win":
        raise PBPError("PBP only serializes its pinned Windows persona")
    import orjson

    try:
        encoded = orjson.dumps(config).decode("utf-8")
    except (TypeError, UnicodeError) as error:
        raise PBPError(f"could not serialize the PBP persona: {error}") from error
    result = {
        f"CAMOU_CONFIG_{index + 1}": encoded[offset : offset + 32767]
        for index, offset in enumerate(range(0, len(encoded), 32767))
    }
    if not result:
        raise PBPError("PBP persona serialization was empty")
    result["FONTCONFIG_FILE"] = str(local_fontconfig(browser_root, home))
    return result


def materialize_persona(
    *,
    release: str,
    browser_path: Path,
    addon_path: Path,
    home: Path,
    persona_class: str,
) -> dict[str, Any]:
    from camoufox import DefaultAddons
    import camoufox.utils as camoufox_utils

    installed_package = importlib.metadata.version("cloverlabs-camoufox")
    if installed_package != CAMOUFOX_PACKAGE_VERSION:
        raise PBPError(f"wrong Camoufox package version: {installed_package}")
    require_regular_file(browser_path, 0, {0o755})
    require_addon_directory(addon_path, 0)
    if persona_class not in PERSONA_CLASSES:
        raise PBPError(f"unknown persona class: {persona_class}")
    preset = choose_windows_preset(persona_class)
    config: dict[str, Any] = {"timezone": TIMEZONE}
    upstream_env_vars = camoufox_utils.get_env_vars
    camoufox_utils.get_env_vars = lambda mapping, target: local_env_vars(mapping, target, browser_path.parent, home)
    try:
        options = camoufox_utils.launch_options(
            config=config,
            os="windows",
            locale=LOCALE,
            fingerprint_preset=preset,
            ff_version=BROWSER_MAJOR,
            headless=False,
            executable_path=browser_path,
            addons=[str(addon_path)],
            exclude_addons=[DefaultAddons.UBO],
            enable_cache=True,
            env=materialization_environment(home),
            i_know_what_im_doing=True,
        )
    finally:
        camoufox_utils.get_env_vars = upstream_env_vars
    if "proxy" in options:
        raise PBPError("browser materialization unexpectedly added a proxy")
    prefs = options.get("firefox_user_prefs")
    if not isinstance(prefs, dict):
        raise PBPError("Camoufox did not produce Firefox preferences")
    navigator = preset["navigator"]
    screen = preset["screen"]
    webgl = preset["webgl"]
    config.update(
        {
            "navigator.hardwareConcurrency": navigator["hardwareConcurrency"],
            "navigator.maxTouchPoints": navigator.get("maxTouchPoints", 0),
            "screen.width": screen["width"],
            "screen.height": screen["height"],
            "screen.availWidth": screen["availWidth"],
            "screen.availHeight": screen["availHeight"],
            "screen.colorDepth": screen["colorDepth"],
            "screen.pixelDepth": screen["colorDepth"],
            "window.devicePixelRatio": screen["devicePixelRatio"],
            "webGl:vendor": webgl["unmaskedVendor"],
            "webGl:renderer": webgl["unmaskedRenderer"],
            "voices": normalized_preset_voices(preset),
        }
    )
    config.pop("window.history.length", None)
    hardened_prefs = deepcopy(prefs)
    hardened_prefs.update(HARDENED_FIREFOX_PREFS)
    persona = {
        "schema": PERSONA_SCHEMA,
        "browser_version": BROWSER_VERSION,
        "browser_major": BROWSER_MAJOR,
        "camoufox_package_version": CAMOUFOX_PACKAGE_VERSION,
        "persona_class": persona_class,
        "os": "windows",
        "locale": LOCALE,
        "timezone": TIMEZONE,
        "preset": preset,
        "config": config,
        "firefox_user_prefs": hardened_prefs,
    }
    # add-ons are an immutable release asset, not part of the VM-wide persona.
    persona["config"].pop("addons", None)
    persona["persona_id"] = persona_id_for(persona)
    return validate_persona(
        persona,
        release=release,
        browser_path=browser_path,
        addon_path=addon_path,
    )


def read_release(root: Path) -> str:
    version_path = root / "VERSION"
    require_regular_file(version_path, 0, {0o644})
    release = version_path.read_text(encoding="ascii").strip()
    if not RELEASE_RE.fullmatch(release):
        raise PBPError("installed PBP version is invalid")
    return release


def current_paths() -> tuple[str, Path, Path]:
    try:
        resolved = CURRENT_ROOT.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as error:
        raise PBPError("PBP current release is missing or unsafe") from error
    releases_root = Path("/opt/toolkit/pbp/releases").resolve(strict=True)
    try:
        resolved.relative_to(releases_root)
    except ValueError as error:
        raise PBPError("PBP current release points outside the releases directory") from error
    require_real_directory(resolved, 0, {0o755})
    release = read_release(resolved)
    browser = resolved / "browser" / "camoufox-bin"
    addon = resolved / "assets" / "ublock-origin"
    require_regular_file(browser, 0, {0o755})
    require_addon_directory(addon, 0)
    return release, browser, addon


def validate_display_environment(home: Path, uid: int) -> dict[str, str]:
    display = os.environ.get("DISPLAY", "")
    if not re.fullmatch(r":[0-9]+(?:[.][0-9]+)?", display):
        raise PBPError("PBP must run inside the local VNC/X11 display")
    xauthority = Path(os.environ.get("XAUTHORITY", str(home / ".Xauthority")))
    if xauthority != home / ".Xauthority":
        raise PBPError("PBP requires the managed malwarelab Xauthority file")
    require_regular_file(xauthority, uid, {0o600})
    runtime_dir = Path(f"/run/user/{uid}")
    require_real_directory(runtime_dir, uid, {0o700, 0o750, 0o755})

    environment = materialization_environment(home)
    environment["DISPLAY"] = display
    environment["XAUTHORITY"] = str(xauthority)
    environment["XDG_RUNTIME_DIR"] = str(runtime_dir)
    bus = runtime_dir / "bus"
    if bus.exists():
        details = bus.lstat()
        if not stat.S_ISSOCK(details.st_mode) or details.st_uid != uid:
            raise PBPError("unsafe D-Bus session socket")
        environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    environment["XDG_CONFIG_HOME"] = str(home / ".config")
    environment["XDG_CACHE_HOME"] = str(home / ".cache")
    environment["XDG_DATA_HOME"] = str(home / ".local" / "share")
    try:
        geometry = subprocess.run(
            ["/usr/bin/xdotool", "getdisplaygeometry"],
            env={
                "PATH": "/usr/bin:/bin",
                "DISPLAY": display,
                "XAUTHORITY": str(xauthority),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PBPError("could not verify the managed X11 display geometry") from error
    if geometry.returncode != 0 or geometry.stderr or not re.fullmatch(r"1600 900\n?", geometry.stdout):
        raise PBPError("PBP requires the managed 1600x900 X11 display")
    return environment


def check_mullvad_egress() -> str:
    context = ssl.create_default_context()
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    try:
        request = Request(
            MULLVAD_CHECK_URL,
            headers={"Accept": "application/json", "User-Agent": "dynamicflow-pbp-egress/2"},
            method="GET",
        )
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise EgressTransientError("Mullvad verification endpoint returned a non-200 status")
            payload = response.read(128 * 1024 + 1)
        if len(payload) > 128 * 1024:
            raise EgressTransientError("Mullvad verification response is too large")
        result = parse_json(payload.decode("utf-8"))
        if not isinstance(result, dict):
            raise EgressTransientError("Mullvad verification response is not an object")
        if result.get("mullvad_exit_ip") is not True:
            raise EgressDefinitiveError("the active egress is not a Mullvad exit")
        if result.get("country") != "Germany":
            raise EgressDefinitiveError("the active Mullvad exit is outside Germany")
        try:
            address = ipaddress.ip_address(result.get("ip", ""))
        except ValueError as error:
            raise EgressTransientError("Mullvad verification returned a malformed address") from error
        if address.version != 4 or not address.is_global:
            raise EgressDefinitiveError("the active Mullvad exit is not a global IPv4 address")
        return str(address)
    except EgressDefinitiveError:
        raise
    except EgressTransientError:
        raise
    except (HTTPError, OSError, UnicodeError, URLError, PBPError) as error:
        raise EgressTransientError("Mullvad verification is temporarily unavailable") from error


def check_mullvad_policy() -> None:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        completed = subprocess.run(
            ["/usr/bin/sudo", "-n", "--", str(MULLVAD_POLICY_HELPER)],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EgressTransientError("Mullvad policy verification is temporarily unavailable") from error
    if completed.returncode == 20:
        raise EgressDefinitiveError("Mullvad auto-connect, lockdown, or Shadowsocks 443 policy is not active")
    if completed.returncode != 0 or completed.stdout != "policy-ok\n" or completed.stderr:
        raise EgressTransientError("Mullvad policy verification is temporarily unavailable")


def check_mullvad_session() -> str:
    check_mullvad_policy()
    return check_mullvad_egress()


def fetch_mullvad_egress(
    attempts: int = 4,
    *,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = random.random,
    checker: Callable[[], str] = check_mullvad_egress,
) -> str:
    last_error: EgressTransientError | None = None
    for attempt in range(attempts):
        try:
            return checker()
        except EgressDefinitiveError:
            raise
        except EgressTransientError as error:
            last_error = error
            if attempt + 1 < attempts:
                delay = min(2**attempt, EGRESS_BACKOFF_MAX)
                sleep(delay + jitter() * min(1.0, delay / 4))
    raise EgressTransientError(
        f"Mullvad Germany egress check remained unavailable after {attempts} attempts"
    ) from last_error


class EgressMonitor:
    """network worker that never touches playwright objects."""

    def __init__(
        self,
        *,
        # the complete root-owned policy/guard check runs synchronously before
        # harden_runtime_process(). once PR_SET_NO_NEW_PRIVS is active, sudo
        # must be unavailable by design, so the session monitor verifies the
        # effective mullvad egress directly without attempting privilege gain.
        checker: Callable[[], str] = check_mullvad_egress,
        interval: float = EGRESS_CHECK_INTERVAL,
        attempts: int = EGRESS_RECOVERY_ATTEMPTS,
        random_value: Callable[[], float] = random.random,
        expected_exit_ip: str | None = None,
    ):
        self.events: queue.Queue[EgressEvent] = queue.Queue()
        self._checker = checker
        self._interval = interval
        self._attempts = attempts
        self._random = random_value
        self._expected_exit_ip = expected_exit_ip
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise PBPError("egress monitor was started twice")
        self._thread = threading.Thread(target=self._run, name="pbp-egress", daemon=True)
        self._thread.start()

    def stop(self) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)
            return not self._thread.is_alive()
        return True

    def _emit(self, event: EgressEvent) -> None:
        if not self._stop.is_set():
            self.events.put(event)

    def _wait(self, delay: float) -> bool:
        return self._stop.wait(max(0.0, delay))

    def _run(self) -> None:
        if self._wait(self._interval):
            return
        while not self._stop.is_set():
            try:
                exit_ip = self._checker()
            except EgressDefinitiveError as error:
                self._emit(EgressEvent("definitive", sanitize_text(error)))
                return
            except (EgressTransientError, OSError) as error:
                self._emit(EgressEvent("transient", sanitize_text(error)))
                if not self._recover():
                    return
            except Exception:
                self._emit(
                    EgressEvent(
                        "monitor_failure",
                        "Mullvad verification worker failed unexpectedly",
                    )
                )
                return
            else:
                if self._stop.is_set():
                    return
                if self._expected_exit_ip is not None and exit_ip != self._expected_exit_ip:
                    self._emit(
                        EgressEvent(
                            "changed",
                            "Mullvad relay changed during the browser session",
                            exit_ip,
                        )
                    )
                    return
            if self._wait(self._interval):
                return

    def _recover(self) -> bool:
        consecutive_successes = 0
        for attempt in range(self._attempts):
            if consecutive_successes:
                delay = EGRESS_SUCCESS_CONFIRMATION_DELAY
            else:
                delay = min(2**attempt, EGRESS_BACKOFF_MAX)
                delay += self._random() * min(1.0, delay / 4)
            if self._wait(delay):
                return False
            try:
                exit_ip = self._checker()
            except EgressDefinitiveError as error:
                self._emit(EgressEvent("definitive", sanitize_text(error)))
                return False
            except (EgressTransientError, OSError):
                consecutive_successes = 0
                continue
            except Exception:
                self._emit(
                    EgressEvent(
                        "monitor_failure",
                        "Mullvad verification worker failed unexpectedly",
                    )
                )
                return False
            if self._stop.is_set():
                return False
            if self._expected_exit_ip is not None and exit_ip != self._expected_exit_ip:
                self._emit(
                    EgressEvent(
                        "changed",
                        "Mullvad relay changed during recovery",
                        exit_ip,
                    )
                )
                return False
            consecutive_successes += 1
            if consecutive_successes == 1:
                self._emit(EgressEvent("confirming", "first healthy egress check"))
                continue
            self._emit(EgressEvent("recovered", "two healthy egress checks", exit_ip))
            return True
        self._emit(
            EgressEvent(
                "exhausted",
                f"Mullvad verification failed after {self._attempts} bounded retries",
            )
        )
        return False


def validate_url(value: str) -> str:
    if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PBPError("unsafe or oversized URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise PBPError("PBP accepts only credential-free HTTP(S) URLs")
    return value


def profile_path(home: Path, uid: int) -> Path:
    base = home / ".local" / "share" / "toolkit-pbp"
    profile = home / PROFILE_RELATIVE
    require_real_directory(home, uid, {0o700, 0o750})
    for directory in (home / ".local", home / ".local" / "share", base, profile):
        require_real_directory(directory, uid, {0o700})
    return profile


def browser_options(
    persona: dict[str, Any],
    *,
    browser_path: Path,
    addon_path: Path,
    profile: Path,
    environment: dict[str, str],
    exit_ip: str,
    url: str | None,
) -> dict[str, Any]:
    config = deepcopy(persona["config"])
    config["addons"] = [str(addon_path)]
    config["webrtc:ipv4"] = exit_ip
    generated = local_env_vars(config, "win", browser_path.parent, Path(environment["HOME"]))
    if any(key.startswith("CAMOU_CONFIG") or key == "FONTCONFIG_FILE" for key in environment):
        raise PBPError("unsafe Camoufox environment override")
    prefs = deepcopy(persona["firefox_user_prefs"])
    prefs.update(HARDENED_FIREFOX_PREFS)
    options: dict[str, Any] = {
        "executable_path": str(browser_path),
        "args": [url] if url else [],
        "env": {**generated, **environment},
        "firefox_user_prefs": prefs,
        "headless": False,
        "no_viewport": True,
        "user_data_dir": str(profile),
    }
    if "proxy" in options:
        raise PBPError("PBP must use Mullvad system routing, not a browser proxy")
    return options


def harden_runtime_process() -> None:
    """make the launcher and all future browser children non-dumpable/non-privileged."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as error:
        raise PBPError("could not disable browser core dumps") from error

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    for option, value, label in (
        (38, 1, "no-new-privileges"),  # PR_SET_NO_NEW_PRIVS
        (4, 0, "non-dumpable"),  # PR_SET_DUMPABLE
    ):
        ctypes.set_errno(0)
        if prctl(option, value, 0, 0, 0) != 0:
            error_number = ctypes.get_errno() or errno.EPERM
            raise PBPError(f"could not enable {label} browser process policy") from OSError(
                error_number, os.strerror(error_number)
            )
    if prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE must be exactly zero.
        raise PBPError("browser process remained dumpable")
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError) as error:
        raise PBPError("could not verify no-new-privileges browser policy") from error
    if not re.search(r"^NoNewPrivs:\s+1$", status, flags=re.MULTILINE):
        raise PBPError("browser process did not enter no-new-privileges mode")
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise PBPError("browser core dump limit is not locked to zero")


def read_process_record(pid: int, proc_root: Path = Path("/proc")) -> ProcessRecord | None:
    if pid <= 0:
        return None
    root = proc_root / str(pid)
    try:
        status = (root / "status").read_text(encoding="ascii", errors="strict")
        stat_data = (root / "stat").read_text(encoding="ascii", errors="strict")
        cmdline = (root / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, UnicodeError, OSError):
        return None
    uid: int | None = None
    ppid: int | None = None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2:
                uid = int(fields[1])
        elif line.startswith("PPid:"):
            fields = line.split()
            if len(fields) == 2:
                ppid = int(fields[1])
    try:
        after_name = stat_data.rsplit(")", 1)[1].split()
        start_time = int(after_name[19])
        stat_ppid = int(after_name[1])
    except (IndexError, ValueError):
        return None
    if uid is None:
        return None
    if ppid is None:
        ppid = stat_ppid
    if len(cmdline) > 1024 * 1024:
        return None
    argv = tuple(item.decode("utf-8", "surrogateescape") for item in cmdline.rstrip(b"\0").split(b"\0") if item)
    return ProcessRecord(pid, ppid, uid, start_time, argv)


def _normalized_absolute(value: str) -> str | None:
    if not value.startswith("/"):
        return None
    return os.path.normpath(value)


def process_uses_profile(record: ProcessRecord, profile: Path) -> bool:
    expected = os.path.normpath(str(profile))
    options = ("-profile", "--profile", "--user-data-dir")
    for index, argument in enumerate(record.argv):
        if argument in options and index + 1 < len(record.argv):
            if _normalized_absolute(record.argv[index + 1]) == expected:
                return True
        for option in options:
            prefix = option + "="
            if argument.startswith(prefix) and _normalized_absolute(argument[len(prefix) :]) == expected:
                return True
    return False


def list_user_processes(uid: int, proc_root: Path = Path("/proc")) -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    try:
        children = list(proc_root.iterdir())
    except OSError as error:
        raise PBPError(f"could not inspect process table: {error}") from error
    for child in children:
        if not child.name.isdecimal():
            continue
        record = read_process_record(int(child.name), proc_root)
        if record is not None and record.uid == uid and record.pid != os.getpid():
            records.append(record)
    return records


def find_profile_processes(profile: Path, uid: int, proc_root: Path = Path("/proc")) -> list[ProcessRecord]:
    return [record for record in list_user_processes(uid, proc_root) if process_uses_profile(record, profile)]


def assert_no_profile_processes(profile: Path, uid: int, proc_root: Path = Path("/proc")) -> None:
    if find_profile_processes(profile, uid, proc_root):
        raise PBPError("a browser process still owns the PBP profile; close it or inspect the runtime log")


def _pid_is_alive(pid: int, probe: Callable[[int, int], None] = os.kill) -> bool:
    try:
        probe(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reconcile_native_profile_locks(
    profile: Path,
    uid: int,
    *,
    app_lock_held: bool,
    proc_root: Path = Path("/proc"),
    probe: Callable[[int, int], None] = os.kill,
) -> list[Path]:
    """remove only provably stale native locks for the exact PBP profile."""
    if not app_lock_held:
        raise PBPError("native lock reconciliation requires the exclusive PBP app lock")
    try:
        profile_details = profile.lstat()
    except OSError as error:
        raise PBPError("unsafe PBP profile for native lock reconciliation") from error
    if (
        not stat.S_ISDIR(profile_details.st_mode)
        or profile_details.st_uid != uid
        or stat.S_IMODE(profile_details.st_mode) != 0o700
    ):
        raise PBPError("unsafe PBP profile for native lock reconciliation")
    assert_no_profile_processes(profile, uid, proc_root)
    removed: list[Path] = []
    for name in ("lock", ".parentlock", "parent.lock"):
        path = profile / name
        try:
            details = path.lstat()
        except FileNotFoundError:
            continue
        if details.st_uid != uid:
            raise PBPError(f"unsafe owner for native browser lock {name}")
        if stat.S_ISLNK(details.st_mode):
            target = os.readlink(path)
            match = re.search(r"(?:^|[+])([0-9]+)$", target)
            if match is None:
                raise PBPError(f"unrecognized native browser lock {name}")
            lock_pid = int(match.group(1))
            if _pid_is_alive(lock_pid, probe):
                record = read_process_record(lock_pid, proc_root)
                if record is None:
                    # the process may have exited between the liveness probe and
                    # /proc inspection. if it is still alive, its identity is
                    # unreadable and removing the lock would be unsafe.
                    if _pid_is_alive(lock_pid, probe):
                        raise PBPError(f"could not verify process identity for native browser lock {name}")
                elif record.uid == uid and process_uses_profile(record, profile):
                    raise PBPError(f"native browser lock {name} still names a live profile process")
                # a live but unrelated process proves that the stale PID in the
                # native lock has been reused. continue only after the exact
                # profile scan and inode checks below.
            assert_no_profile_processes(profile, uid, proc_root)
            current_record = read_process_record(lock_pid, proc_root)
            if current_record is None and _pid_is_alive(lock_pid, probe):
                raise PBPError(f"could not reverify process identity for native browser lock {name}")
            if (
                current_record is not None
                and current_record.uid == uid
                and process_uses_profile(current_record, profile)
            ):
                raise PBPError(f"native browser lock {name} now names a live profile process")
            current = path.lstat()
            if current.st_dev != details.st_dev or current.st_ino != details.st_ino:
                raise PBPError(f"native browser lock {name} changed during reconciliation")
            path.unlink()
            removed.append(path)
            continue
        mode = stat.S_IMODE(details.st_mode)
        gecko_parentlock = name == ".parentlock" and mode == 0o664 and details.st_size == 0
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or (mode & 0o022 and not gecko_parentlock):
            raise PBPError(f"unsafe native browser lock {name}")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            opened_mode = stat.S_IMODE(opened.st_mode)
            opened_gecko_parentlock = name == ".parentlock" and opened_mode == 0o664 and opened.st_size == 0
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != uid
                or opened.st_nlink != 1
                or (opened_mode & 0o022 and not opened_gecko_parentlock)
                or opened.st_dev != details.st_dev
                or opened.st_ino != details.st_ino
            ):
                raise PBPError(f"native browser lock {name} changed during open")
            try:
                fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise PBPError(f"native browser lock {name} is still held") from error
                raise
            assert_no_profile_processes(profile, uid, proc_root)
            current = path.lstat()
            current_mode = stat.S_IMODE(current.st_mode)
            current_gecko_parentlock = name == ".parentlock" and current_mode == 0o664 and current.st_size == 0
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != uid
                or current.st_nlink != 1
                or (current_mode & 0o022 and not current_gecko_parentlock)
                or current.st_dev != opened.st_dev
                or current.st_ino != opened.st_ino
            ):
                raise PBPError(f"native browser lock {name} changed during reconciliation")
            path.unlink()
            removed.append(path)
        finally:
            os.close(descriptor)
    return removed


def _same_process(record: ProcessRecord, proc_root: Path = Path("/proc")) -> bool:
    current = read_process_record(record.pid, proc_root)
    return current is not None and current.uid == record.uid and current.start_time == record.start_time


def _signal_process_record(
    record: ProcessRecord,
    signum: int,
    *,
    proc_root: Path = Path("/proc"),
    kill: Callable[[int, int], None] = os.kill,
) -> bool:
    """signal one exact PID/start-time identity without a PID-reuse kill race."""
    if (
        proc_root == Path("/proc")
        and kill is os.kill
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal")
    ):
        try:
            descriptor = os.pidfd_open(record.pid, 0)
        except ProcessLookupError:
            return False
        except OSError as error:
            raise PBPError("could not pin browser process identity with pidfd") from error
        try:
            # open the pidfd first and then re-read /proc. if the numeric PID was
            # reused before pidfd_open(), the start-time comparison rejects it.
            # if it is reused afterwards, the pidfd still addresses the old task.
            if not _same_process(record, proc_root):
                return False
            try:
                signal.pidfd_send_signal(descriptor, signum)
            except ProcessLookupError:
                return False
            return True
        finally:
            os.close(descriptor)

    # supported target kernels expose pidfds. this conservative compatibility
    # path retains the start-time check for older python/kernel combinations.
    if not _same_process(record, proc_root):
        return False
    try:
        kill(record.pid, signum)
    except ProcessLookupError:
        return False
    return True


def _profile_process_tree(profile: Path, uid: int, proc_root: Path = Path("/proc")) -> list[ProcessRecord]:
    records = list_user_processes(uid, proc_root)
    selected = {record.pid for record in records if process_uses_profile(record, profile)}
    changed = True
    while changed:
        changed = False
        for record in records:
            if record.ppid in selected and record.pid not in selected:
                selected.add(record.pid)
                changed = True
    return [record for record in records if record.pid in selected]


class ProfileProcessTracker:
    """remember exact browser descendants before a crashing root can reparent them."""

    def __init__(
        self,
        profile: Path,
        uid: int,
        *,
        interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.profile = profile
        self.uid = uid
        self.interval = interval
        self.clock = clock
        self._last_sample: float | None = None
        self._records: dict[tuple[int, int], ProcessRecord] = {}

    def sample(self) -> None:
        now = self.clock()
        if self._last_sample is not None and now - self._last_sample < self.interval:
            return
        for record in _profile_process_tree(self.profile, self.uid):
            self._records[(record.pid, record.start_time)] = record
        self._last_sample = now

    def captured(self) -> tuple[ProcessRecord, ...]:
        return tuple(self._records.values())


def terminate_process_records(
    records: Iterable[ProcessRecord],
    *,
    proc_root: Path = Path("/proc"),
    kill: Callable[[int, int], None] = os.kill,
    wait: Callable[[float], None] = time.sleep,
    grace_seconds: float = 5.0,
) -> list[int]:
    """terminate only PID/start-time identities captured from the exact profile tree."""
    unique = {(record.pid, record.start_time): record for record in records}
    captured = list(unique.values())
    for record in sorted(captured, key=lambda item: item.pid, reverse=True):
        _signal_process_record(
            record,
            signal.SIGTERM,
            proc_root=proc_root,
            kill=kill,
        )
    deadline = time.monotonic() + grace_seconds
    survivors = captured
    while survivors and time.monotonic() < deadline:
        wait(0.1)
        survivors = [record for record in survivors if _same_process(record, proc_root)]
    for record in survivors:
        _signal_process_record(
            record,
            signal.SIGKILL,
            proc_root=proc_root,
            kill=kill,
        )
    if survivors:
        wait(0.1)
    return [record.pid for record in survivors if _same_process(record, proc_root)]


def terminate_profile_processes(
    profile: Path,
    uid: int,
    *,
    proc_root: Path = Path("/proc"),
    kill: Callable[[int, int], None] = os.kill,
    wait: Callable[[float], None] = time.sleep,
    grace_seconds: float = 5.0,
) -> list[int]:
    """reap only start-time-verified processes belonging to the exact profile tree."""
    records = _profile_process_tree(profile, uid, proc_root)
    return terminate_process_records(
        records,
        proc_root=proc_root,
        kill=kill,
        wait=wait,
        grace_seconds=grace_seconds,
    )


def _validate_app_lock(lock_path: Path, descriptor: int, uid: int) -> None:
    try:
        details = os.fstat(descriptor)
        path_details = lock_path.lstat()
    except OSError as error:
        raise PBPError("unsafe PBP browser lock") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != uid
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
        or not stat.S_ISREG(path_details.st_mode)
        or path_details.st_uid != uid
        or path_details.st_nlink != 1
        or path_details.st_dev != details.st_dev
        or path_details.st_ino != details.st_ino
    ):
        raise PBPError("unsafe PBP browser lock")


def acquire_lock(home: Path, uid: int) -> int:
    lock_path = home / ".local" / "share" / "toolkit-pbp" / "browser.lock"
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(lock_path, flags)
        except OSError as error:
            raise PBPError("unsafe PBP browser lock") from error
    except OSError as error:
        raise PBPError("unsafe PBP browser lock") from error
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        _validate_app_lock(lock_path, descriptor, uid)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _validate_app_lock(lock_path, descriptor, uid)
    except BlockingIOError as error:
        os.close(descriptor)
        raise PBPError("PBP Browser is already running in this VM") from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


class SignalLatch(AbstractContextManager["SignalLatch"]):
    def __init__(self):
        self.event = threading.Event()
        self.signum: int | None = None
        self._previous: dict[int, Any] = {}

    def _handle(self, signum: int, _frame: Any) -> None:
        if self.signum is None:
            self.signum = signum
        self.event.set()

    def __enter__(self) -> "SignalLatch":
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                self._previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self._handle)
        return self

    def __exit__(self, *_args: Any) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, previous)
        self._previous.clear()


def _set_offline(context: Any, offline: bool, runtime_log: RuntimeLog) -> bool:
    try:
        context.set_offline(offline)
    except Exception as error:
        runtime_log.log_exception("browser.offline_transition_failed", error, offline=offline)
        return False
    runtime_log.log("browser.network_mode", offline=offline)
    return True


def _close_context(context: Any, runtime_log: RuntimeLog, reason: str) -> None:
    runtime_log.log("browser.close_requested", reason=reason)
    try:
        context.close()
    except Exception as error:
        runtime_log.log_exception("browser.close_failed", error, reason=reason)


def supervise_context(
    context: Any,
    *,
    monitor: EgressMonitor,
    runtime_log: RuntimeLog,
    signal_latch: SignalLatch,
    expected_exit_ip: str,
    timeout_error: type[BaseException],
    process_tracker: Callable[[], None] | None = None,
) -> LifecycleResult:
    """pump playwright's sync dispatcher and supervise the browser on one thread."""
    page_ids: set[int] = set()
    page_closed = threading.Event()
    context_closed = threading.Event()
    browser_crashed = threading.Event()

    def register_page(page: Any) -> None:
        identity = id(page)
        if identity in page_ids:
            return
        page_ids.add(identity)
        runtime_log.log("browser.page_opened", open_pages=len(page_ids))

        def on_close(*_args: Any) -> None:
            page_ids.discard(identity)
            page_closed.set()
            runtime_log.log("browser.page_closed", open_pages=len(page_ids))

        def on_crash(*_args: Any) -> None:
            browser_crashed.set()
            runtime_log.log("browser.page_crashed", open_pages=len(page_ids))

        page.on("close", on_close)
        page.on("crash", on_crash)

    def on_context_close(*_args: Any) -> None:
        context_closed.set()
        runtime_log.log("browser.context_closed", open_pages=len(page_ids))

    context.on("page", register_page)
    context.on("close", on_context_close)
    for page in list(context.pages):
        register_page(page)

    monitor.start()
    offline = False
    try:
        while True:
            if process_tracker is not None:
                try:
                    process_tracker()
                except Exception as error:
                    runtime_log.log_exception("profile.process_tracking_failed", error)
                    _set_offline(context, True, runtime_log)
                    _close_context(context, runtime_log, "process_tracking_failed")
                    return LifecycleResult(
                        "browser_cleanup_failed",
                        EXIT_BROWSER_UNEXPECTED,
                        "browser process tracking failed",
                    )
            forced: LifecycleResult | None = None
            while True:
                try:
                    egress = monitor.events.get_nowait()
                except queue.Empty:
                    break
                runtime_log.log(
                    "egress.monitor",
                    kind=egress.kind,
                    detail=egress.detail,
                    has_exit_ip=egress.exit_ip is not None,
                )
                if egress.kind == "transient":
                    if not offline:
                        offline = True
                        if not _set_offline(context, True, runtime_log):
                            forced = LifecycleResult(
                                "vpn_control_failure",
                                EXIT_VPN,
                                "could not place the browser offline",
                            )
                elif egress.kind == "confirming":
                    continue
                elif egress.kind == "recovered":
                    if egress.exit_ip != expected_exit_ip:
                        forced = LifecycleResult(
                            "vpn_relay_changed",
                            EXIT_VPN,
                            "Mullvad relay changed; restart is required for a consistent persona",
                        )
                    elif offline and _set_offline(context, False, runtime_log):
                        offline = False
                    elif offline:
                        forced = LifecycleResult(
                            "vpn_control_failure",
                            EXIT_VPN,
                            "could not restore browser networking",
                        )
                elif egress.kind in (
                    "definitive",
                    "exhausted",
                    "changed",
                    "monitor_failure",
                ):
                    if not offline:
                        offline = True
                        _set_offline(context, True, runtime_log)
                    forced = LifecycleResult(
                        (
                            "vpn_wrong"
                            if egress.kind == "definitive"
                            else "vpn_relay_changed"
                            if egress.kind == "changed"
                            else "vpn_control_failure"
                            if egress.kind == "monitor_failure"
                            else "vpn_unavailable"
                        ),
                        EXIT_VPN,
                        egress.detail,
                    )

            if signal_latch.event.is_set():
                signum = signal_latch.signum or signal.SIGTERM
                if not offline:
                    _set_offline(context, True, runtime_log)
                forced = LifecycleResult(
                    "signal",
                    128 + int(signum),
                    f"received signal {int(signum)}",
                )
            elif browser_crashed.is_set():
                forced = LifecycleResult(
                    "browser_crash",
                    EXIT_BROWSER_CRASH,
                    "Playwright reported a page crash",
                )

            if forced is not None:
                _close_context(context, runtime_log, forced.reason)
                return forced
            if context_closed.is_set():
                if page_closed.is_set() and not page_ids:
                    return LifecycleResult("normal_user_close", 0, "last browser window closed")
                return LifecycleResult(
                    "browser_closed_unexpectedly",
                    EXIT_BROWSER_UNEXPECTED,
                    "browser context closed without a user page-close event",
                )
            if page_closed.is_set() and not page_ids:
                _close_context(context, runtime_log, "normal_user_close")
                return LifecycleResult("normal_user_close", 0, "last browser window closed")

            try:
                # playwright sync callbacks are dispatched only while its dispatcher
                # greenlet is pumped. a plain threading.Event.wait() deadlocks closure.
                with context.expect_event(
                    "page",
                    predicate=lambda _page: False,
                    timeout=DISPATCH_PUMP_MS,
                ):
                    pass
            except timeout_error:
                continue
            except KeyboardInterrupt:
                signal_latch.signum = signal.SIGINT
                signal_latch.event.set()
            except Exception as error:
                runtime_log.log_exception("playwright.dispatch_failed", error)
                if browser_crashed.is_set():
                    return LifecycleResult(
                        "browser_crash",
                        EXIT_BROWSER_CRASH,
                        "Playwright reported a page crash",
                    )
                if context_closed.is_set() and page_closed.is_set() and not page_ids:
                    return LifecycleResult("normal_user_close", 0, "last browser window closed")
                return LifecycleResult(
                    "browser_closed_unexpectedly",
                    EXIT_BROWSER_UNEXPECTED,
                    "Playwright dispatcher failed before a normal close event",
                )
    finally:
        if monitor.stop() is False:
            runtime_log.log("egress.monitor_stop_pending")


def launch_browser_session(
    options: dict[str, Any],
    *,
    runtime_log: RuntimeLog,
    expected_exit_ip: str,
    monitor: EgressMonitor | None = None,
    process_tracker: Callable[[], None] | None = None,
) -> LifecycleResult:
    from camoufox.sync_api import Camoufox
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    active_monitor = monitor or EgressMonitor(expected_exit_ip=expected_exit_ip)
    with SignalLatch() as signal_latch:
        with Camoufox(from_options=options, persistent_context=True) as context:
            runtime_log.log("browser.context_started")
            return supervise_context(
                context,
                monitor=active_monitor,
                runtime_log=runtime_log,
                signal_latch=signal_latch,
                expected_exit_ip=expected_exit_ip,
                timeout_error=PlaywrightTimeoutError,
                process_tracker=process_tracker,
            )


def _public_failure(result: LifecycleResult, log_path: Path | None) -> str:
    if result.reason == "browser_crash":
        action = (
            "Der Browser ist abgestürzt. PBP startet ihn nicht automatisch neu. "
            "Prüfe das technische Log und starte den Desktop-Eintrag danach erneut."
        )
    elif result.reason == "vpn_relay_changed":
        action = (
            "Der deutsche Mullvad-Relay beziehungsweise seine Exit-IP hat sich während "
            "der Sitzung geändert. PBP hat den Browser zuerst offline geschaltet und "
            "dann fail-closed beendet, weil die WebRTC-Konfiguration an die beim Start "
            "verifizierte Exit-IP gebunden ist. Die stabile Browser-Persona wurde nicht "
            "ersetzt. Warte auf eine stabile Mullvad-Verbindung und starte den Desktop-"
            "Eintrag danach bewusst erneut."
        )
    elif result.reason.startswith("vpn_"):
        action = (
            "Der deutsche Mullvad-Egress ist verloren, falsch oder nicht sicher prüfbar. "
            "PBP wurde fail-closed beendet. Prüfe Mullvad (Deutschland, Shadowsocks 443, "
            "Lockdown) und starte PBP danach bewusst erneut."
        )
    elif result.reason == "startup_error" and "already running" in result.detail.lower():
        action = (
            "PBP läuft bereits oder wird noch sauber beendet. Schließe das vorhandene "
            "Browserfenster, warte kurz und versuche es erneut."
        )
    elif result.reason == "startup_error" and "persona" in result.detail.lower():
        action = (
            "Die stabile Browser-Persona ist nicht kompatibel oder beschädigt. Sie wurde "
            "nicht ersetzt. Ein Operator muss das technische Log prüfen und eine bewusste "
            "Persona-Rotation durchführen."
        )
    elif result.reason == "signal":
        action = "PBP wurde kontrolliert beendet."
    else:
        action = (
            "PBP konnte nicht sicher gestartet oder beendet werden. Prüfe das technische "
            "Log, behebe die genannte Laufzeitursache und starte danach erneut."
        )
    if log_path is not None:
        action += f"\n\nTechnisches Log: {log_path}"
    return action


def show_desktop_failure(result: LifecycleResult, log_path: Path | None) -> None:
    message = _public_failure(result, log_path)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in (
            "DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_DATA_DIRS",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
        )
    }
    commands = (
        (Path("/usr/bin/zenity"), ["--error", "--title=PBP Browser", "--no-wrap", f"--text={message}"]),
        (Path("/usr/bin/xmessage"), ["-center", "-buttons", "OK:0", message]),
        (Path("/usr/bin/notify-send"), ["--urgency=critical", "PBP Browser", message]),
    )
    for binary, arguments in commands:
        if not binary.is_file():
            continue
        try:
            completed = subprocess.run(
                [str(binary), *arguments],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            if completed.returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            continue
    sys.stderr.write("PBP ERROR: " + message.replace("\n", " ") + "\n")
    sys.stderr.flush()


def _runtime_identity() -> tuple[int, Path]:
    effective_name = pwd.getpwuid(os.geteuid()).pw_name
    if os.geteuid() == 0 or effective_name != EXPECTED_USER:
        raise PBPError(f"PBP Browser must run as {EXPECTED_USER}, never as root")
    account = pwd.getpwnam(EXPECTED_USER)
    uid = account.pw_uid
    home = Path(account.pw_dir)
    if os.geteuid() != uid:
        raise PBPError("effective user does not match malwarelab")
    require_real_directory(home, uid, {0o700, 0o750})
    return uid, home


def run_browser(url: str | None, *, desktop: bool = False) -> int:
    uid, home = _runtime_identity()
    runtime_log = open_runtime_log(home, uid)
    result = LifecycleResult("startup_error", EXIT_STARTUP, "startup did not complete")
    lock_descriptor: int | None = None
    profile: Path | None = None
    process_tracker: ProfileProcessTracker | None = None
    launch_attempted = False
    capture: StderrCapture | None = None
    with runtime_log:
        runtime_log.log("launch.begin", desktop=desktop, url_supplied=url is not None)
        try:
            release, browser_path, addon_path = current_paths()
            persona = load_persona(
                PERSONA_PATH,
                release=release,
                browser_path=browser_path,
                addon_path=addon_path,
            )
            profile = profile_path(home, uid)
            environment = validate_display_environment(home, uid)
            validated_url = validate_url(url) if url else None
            lock_descriptor = acquire_lock(home, uid)
            assert_no_profile_processes(profile, uid)
            removed = reconcile_native_profile_locks(
                profile,
                uid,
                app_lock_held=True,
            )
            runtime_log.log("profile.reconciled", stale_locks_removed=len(removed))
            exit_ip = fetch_mullvad_egress(checker=check_mullvad_session)
            runtime_log.log("egress.initial_verified")
            options = browser_options(
                persona,
                browser_path=browser_path,
                addon_path=addon_path,
                profile=profile,
                environment=environment,
                exit_ip=exit_ip,
                url=validated_url,
            )
            harden_runtime_process()
            runtime_log.log("process.hardening_enabled")
            process_tracker = ProfileProcessTracker(profile, uid)
            launch_attempted = True
            capture = StderrCapture(runtime_log)
            with capture:
                result = launch_browser_session(
                    options,
                    runtime_log=runtime_log,
                    expected_exit_ip=exit_ip,
                    process_tracker=process_tracker.sample,
                )
            runtime_log.log(
                "launch.lifecycle_complete",
                reason=result.reason,
                exit_code=result.exit_code,
            )
        except EgressDefinitiveError as error:
            runtime_log.log_exception("launch.egress_rejected", error)
            result = LifecycleResult("vpn_wrong", EXIT_VPN, sanitize_text(error))
        except EgressTransientError as error:
            runtime_log.log_exception("launch.egress_unavailable", error)
            result = LifecycleResult("vpn_unavailable", EXIT_VPN, sanitize_text(error))
        except PBPError as error:
            runtime_log.log_exception("launch.rejected", error)
            result = LifecycleResult("startup_error", EXIT_STARTUP, sanitize_text(error))
        except Exception as error:
            runtime_log.log_exception("launch.internal_error", error)
            result = LifecycleResult(
                "browser_closed_unexpectedly",
                EXIT_BROWSER_UNEXPECTED,
                "internal launcher failure",
            )
        finally:
            try:
                if lock_descriptor is not None and profile is not None and launch_attempted:
                    survivors = terminate_profile_processes(profile, uid)
                    if process_tracker is not None:
                        survivors.extend(terminate_process_records(process_tracker.captured()))
                    if survivors:
                        raise PBPError("browser processes survived bounded profile cleanup")
                    removed = reconcile_native_profile_locks(
                        profile,
                        uid,
                        app_lock_held=True,
                    )
                    runtime_log.log("profile.cleanup_complete", stale_locks_removed=len(removed))
            except Exception as error:
                runtime_log.log_exception("profile.cleanup_failed", error)
                result = LifecycleResult(
                    "browser_cleanup_failed",
                    EXIT_BROWSER_UNEXPECTED,
                    "browser profile cleanup did not complete",
                )
            finally:
                if lock_descriptor is not None:
                    os.close(lock_descriptor)
                    runtime_log.log("lock.released")
            if capture is not None and not capture.wait_closed():
                runtime_log.log("runtime.stderr_capture_incomplete")
        runtime_log.log("launch.end", reason=result.reason, exit_code=result.exit_code)

    if result.exit_code != 0:
        if desktop:
            show_desktop_failure(result, runtime_log.path)
        else:
            sys.stderr.write("PBP ERROR: " + _public_failure(result, runtime_log.path).replace("\n", " ") + "\n")
            sys.stderr.flush()
    return result.exit_code


def command_materialize(args: argparse.Namespace) -> int:
    persona = materialize_persona(
        release=args.release,
        browser_path=args.browser,
        addon_path=args.addon,
        home=args.home,
        persona_class=args.persona_class,
    )
    json.dump(persona, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write("\n")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    load_persona(
        args.persona,
        release=args.release,
        browser_path=args.browser,
        addon_path=args.addon,
        require_root_file=False,
    )
    return 0


def command_migrate(args: argparse.Namespace) -> int:
    details = require_regular_file(args.persona, None, {0o600, 0o644})
    if details.st_size > 2 * 1024 * 1024:
        raise PBPError("persona file is unexpectedly large")
    persona = migrate_persona(
        parse_json(args.persona.read_text(encoding="utf-8")),
        browser_path=args.browser,
        addon_path=args.addon,
    )
    json.dump(persona, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write("\n")
    return 0


def command_desktop(args: argparse.Namespace) -> int:
    try:
        return run_browser(args.url, desktop=True)
    except PBPError as error:
        result = LifecycleResult("startup_error", EXIT_STARTUP, sanitize_text(error))
        show_desktop_failure(result, None)
        return result.exit_code
    except Exception:
        # failures before the per-launch log can be opened must still be visible
        # from a Terminal=false desktop entry. Do not expose an unchecked
        # exception string when no sanitizer-backed runtime log exists.
        result = LifecycleResult(
            "startup_error",
            EXIT_STARTUP,
            "desktop launcher initialization failed",
        )
        show_desktop_failure(result, None)
        return result.exit_code


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="pbp-browser")
    subparsers = result.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser("materialize-persona")
    materialize.add_argument("--release", required=True)
    materialize.add_argument("--browser", type=Path, required=True)
    materialize.add_argument("--addon", type=Path, required=True)
    materialize.add_argument("--home", type=Path, required=True)
    materialize.add_argument(
        "--persona-class",
        choices=sorted(PERSONA_CLASSES),
        required=True,
    )
    materialize.set_defaults(handler=command_materialize)
    validate = subparsers.add_parser("validate-persona")
    validate.add_argument("--persona", type=Path, required=True)
    validate.add_argument("--release", required=True)
    validate.add_argument("--browser", type=Path, required=True)
    validate.add_argument("--addon", type=Path, required=True)
    validate.set_defaults(handler=command_validate)
    migrate = subparsers.add_parser("migrate-persona")
    migrate.add_argument("--persona", type=Path, required=True)
    migrate.add_argument("--browser", type=Path, required=True)
    migrate.add_argument("--addon", type=Path, required=True)
    migrate.set_defaults(handler=command_migrate)
    launch = subparsers.add_parser("run")
    launch.add_argument("url", nargs="?")
    launch.set_defaults(handler=lambda args: run_browser(args.url))
    desktop = subparsers.add_parser("desktop")
    desktop.add_argument("url", nargs="?")
    desktop.set_defaults(handler=command_desktop)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PBPError as error:
        raise SystemExit(f"PBP ERROR: {error}") from error
