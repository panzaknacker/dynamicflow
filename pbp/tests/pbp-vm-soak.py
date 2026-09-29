#!/usr/bin/env python3
"""real-VM PBP soak, restart, crash, GUI-error, and fail-closed harness.

this program deliberately does not provide a mocked PASS path.  a qualifying
PASS requires the installed PBP runtime, a live malwarelab VNC/X11 session,
mullvad germany, at least 30 wall-clock minutes, real browser processes/windows,
and the explicitly armed network-failure phase.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


EXPECTED_USER = "malwarelab"
WRAPPER = Path("/usr/local/bin/pbp-browser")
CURRENT_ROOT = Path("/opt/toolkit/pbp/current")
PERSONA = Path("/etc/toolkit/pbp-persona.json")
PROFILE_RELATIVE = Path(".local/share/toolkit-pbp/profile")
LOG_RELATIVE = Path(".local/state/dynamicflow/pbp/logs")
RESULT_RELATIVE = Path(".local/state/dynamicflow/pbp/test-results")
MULLVAD_CHECK_URL = "https://am.i.mullvad.net/json"
MULLVAD_POLICY_HELPER = Path("/usr/local/libexec/dynamicflow-pbp-vpn-verify")
MINIMUM_SOAK_SECONDS = 30 * 60
LAB_VPN_TRIGGER_SOCKET = Path("/run/dynamicflow-lab-pbp-vpn.sock")
LOG_NAME_RE = re.compile(r"^runtime-[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}[.]jsonl$")
URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
IPV4_RE = re.compile(
    r"(?<![0-9.])"
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])[.]){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?![0-9.])"
)
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])")
RAW_SECRET_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?"
    r"(?:password|passwd|secret|token|enrollment[_-]?code|authorization|"
    r"cookie|set-cookie|api[_-]?key)"
    r"[\"']?\s*[:=]\s*(?![\"']?\[redacted\])"
    r"(?:[\"'][^\"']*[\"']|(?:bearer\s+)?[^,\s\";]+)"
)
RAW_CAMOU_CONFIG_RE = re.compile(r"\bCAMOU_CONFIG_[0-9]+\s*=")
LONG_NUMBER_RE = re.compile(r"(?<![0-9])[0-9]{12,}(?![0-9])")


class Blocked(RuntimeError):
    pass


class TestFailure(RuntimeError):
    pass


class EgressUnavailable(RuntimeError):
    pass


def contains_ip_literal(value: str) -> bool:
    if IPV4_RE.search(value):
        return True
    for match in IPV6_CANDIDATE_RE.finditer(value):
        try:
            if ipaddress.ip_address(match.group(0)).version == 6:
                return True
        except ValueError:
            continue
    return False


class EgressWrong(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    uid: int
    start_time: int
    argv: tuple[str, ...]


@dataclass
class Launch:
    process: subprocess.Popen[bytes]
    log_path: Path
    browser_root: ProcessRecord
    captured: dict[tuple[int, int], ProcessRecord]
    desktop: bool


@dataclass(frozen=True)
class PersonaSnapshot:
    inode: int
    size: int
    sha256: str
    stable_fields: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def qualifies_real_soak(requested_seconds: int, observed_seconds: float) -> bool:
    return requested_seconds >= MINIMUM_SOAK_SECONDS and observed_seconds >= MINIMUM_SOAK_SECONDS


def safe_detail(value: str, limit: int = 240) -> str:
    value = "".join(character if 32 <= ord(character) != 127 else " " for character in value)
    value = " ".join(value.split())
    return value[:limit]


def require_real_directory(path: Path, uid: int, modes: set[int]) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise Blocked(f"missing directory: {path}") from error
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != uid or stat.S_IMODE(details.st_mode) not in modes:
        raise Blocked(f"unsafe directory: {path}")


def ensure_private_directory(path: Path, uid: int) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require_real_directory(path, uid, {0o700})


def read_secure_regular_file(
    path: Path,
    *,
    uid: int,
    mode: int,
    maximum: int,
    error_type: type[RuntimeError],
    detail: str,
) -> tuple[os.stat_result, bytes]:
    """read through a pinned, no-follow descriptor with bounded memory use."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except (FileNotFoundError, PermissionError, OSError) as error:
        raise error_type(detail) from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != uid
            or stat.S_IMODE(details.st_mode) != mode
            or details.st_size > maximum
        ):
            raise error_type(detail)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(128 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise error_type(detail)
        return details, raw
    finally:
        os.close(descriptor)


class ResultWriter:
    def __init__(self, path: Path, uid: int, configuration: dict[str, Any]):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_uid != uid:
            os.close(descriptor)
            raise Blocked("unsafe result file")
        os.fchmod(descriptor, 0o600)
        self.path = path
        self._descriptor = descriptor
        self.data: dict[str, Any] = {
            "schema": 1,
            "test": "pbp-real-vm-soak",
            "started_at": utc_now(),
            "finished_at": None,
            "status": "RUNNING",
            "configuration": configuration,
            "phases": [],
            "summary": {},
        }
        self.write()

    def write(self) -> None:
        encoded = (json.dumps(self.data, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        os.ftruncate(self._descriptor, 0)
        view = memoryview(encoded)
        while view:
            written = os.write(self._descriptor, view)
            view = view[written:]
        os.fsync(self._descriptor)

    def begin(self, name: str) -> int:
        self.data["phases"].append(
            {
                "name": name,
                "status": "RUNNING",
                "started_at": utc_now(),
                "finished_at": None,
                "detail": "",
                "metrics": {},
            }
        )
        self.write()
        return len(self.data["phases"]) - 1

    def finish(
        self,
        index: int,
        status_value: str,
        detail: str,
        metrics: dict[str, int | bool] | None = None,
    ) -> None:
        phase = self.data["phases"][index]
        phase["status"] = status_value
        phase["finished_at"] = utc_now()
        phase["detail"] = safe_detail(detail)
        phase["metrics"] = metrics or {}
        self.write()

    def finalize(self, status_value: str, summary: dict[str, int | bool | str]) -> None:
        self.data["status"] = status_value
        self.data["finished_at"] = utc_now()
        self.data["summary"] = summary
        self.write()

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def result_path(home: Path, uid: int, requested: Path | None) -> Path:
    state = home / ".local" / "state"
    dynamicflow = state / "dynamicflow"
    pbp = dynamicflow / "pbp"
    results = home / RESULT_RELATIVE
    for directory in (home / ".local", state, dynamicflow, pbp, results):
        ensure_private_directory(directory, uid)
    if requested is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return results / f"vm-soak-{stamp}-{os.getpid()}.json"
    if not requested.is_absolute():
        raise Blocked("--result must be an absolute path")
    try:
        requested.parent.resolve(strict=True).relative_to(home.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        raise Blocked("--result must be below the malwarelab home") from error
    require_real_directory(requested.parent, uid, {0o700})
    return requested


def read_process(pid: int, proc_root: Path = Path("/proc")) -> ProcessRecord | None:
    root = proc_root / str(pid)
    try:
        status_data = (root / "status").read_text(encoding="ascii")
        stat_data = (root / "stat").read_text(encoding="ascii")
        command_data = (root / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, UnicodeError):
        return None
    uid: int | None = None
    ppid: int | None = None
    try:
        for line in status_data.splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])
        fields = stat_data.rsplit(")", 1)[1].split()
        start_time = int(fields[19])
        if ppid is None:
            ppid = int(fields[1])
    except (IndexError, ValueError):
        return None
    if uid is None or ppid is None or len(command_data) > 1024 * 1024:
        return None
    argv = tuple(item.decode("utf-8", "surrogateescape") for item in command_data.rstrip(b"\0").split(b"\0") if item)
    return ProcessRecord(pid, ppid, uid, start_time, argv)


def user_processes(uid: int) -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        record = read_process(int(entry.name))
        if record is not None and record.uid == uid and record.pid != os.getpid():
            records.append(record)
    return records


def normalized_absolute(value: str) -> str | None:
    return os.path.normpath(value) if value.startswith("/") else None


def uses_profile(record: ProcessRecord, profile: Path) -> bool:
    expected = os.path.normpath(str(profile))
    options = ("-profile", "--profile", "--user-data-dir")
    for index, argument in enumerate(record.argv):
        if (
            argument in options
            and index + 1 < len(record.argv)
            and normalized_absolute(record.argv[index + 1]) == expected
        ):
            return True
        for option in options:
            prefix = option + "="
            if argument.startswith(prefix) and normalized_absolute(argument[len(prefix) :]) == expected:
                return True
    return False


def descendants(records: list[ProcessRecord], roots: set[int]) -> list[ProcessRecord]:
    selected = set(roots)
    changed = True
    while changed:
        changed = False
        for record in records:
            if record.ppid in selected and record.pid not in selected:
                selected.add(record.pid)
                changed = True
    return [record for record in records if record.pid in selected]


def profile_tree(uid: int, profile: Path) -> tuple[ProcessRecord, list[ProcessRecord]] | None:
    records = user_processes(uid)
    matching = [record for record in records if uses_profile(record, profile)]
    if not matching:
        return None
    matching_ids = {record.pid for record in matching}
    roots = [record for record in matching if record.ppid not in matching_ids]
    if len(roots) != 1:
        raise TestFailure("profile process tree has no unique root")
    return roots[0], descendants(records, {roots[0].pid})


def same_process(record: ProcessRecord) -> bool:
    current = read_process(record.pid)
    return current is not None and current.uid == record.uid and current.start_time == record.start_time


def signal_process(record: ProcessRecord, signum: int) -> bool:
    """signal the captured task through a pidfd after rechecking its identity."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise TestFailure("the qualifying VM/Python runtime does not expose pidfds")
    try:
        descriptor = os.pidfd_open(record.pid, 0)
    except ProcessLookupError:
        return False
    except OSError as error:
        raise TestFailure("could not pin a test-owned process identity") from error
    try:
        if not same_process(record):
            return False
        try:
            signal.pidfd_send_signal(descriptor, signum)
        except ProcessLookupError:
            return False
        return True
    finally:
        os.close(descriptor)


def check_mullvad_policy() -> None:
    try:
        completed = subprocess.run(
            ["/usr/bin/sudo", "-n", "--", str(MULLVAD_POLICY_HELPER)],
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EgressUnavailable("Mullvad policy helper unavailable") from error
    if completed.returncode == 20:
        raise EgressWrong("Mullvad policy is not PBP-compatible")
    if completed.returncode != 0 or completed.stdout != "policy-ok\n" or completed.stderr:
        raise EgressUnavailable("Mullvad policy helper unavailable")


def check_mullvad_egress() -> str:
    opener = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=ssl.create_default_context()),
    )
    request = Request(
        MULLVAD_CHECK_URL,
        headers={"Accept": "application/json", "User-Agent": "dynamicflow-pbp-vm-test/1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=20) as response:
            if response.status != 200:
                raise EgressUnavailable("verification endpoint status")
            payload = response.read(128 * 1024 + 1)
        if len(payload) > 128 * 1024:
            raise EgressUnavailable("verification response size")
        result = json.loads(payload.decode("utf-8"))
        if not isinstance(result, dict):
            raise EgressUnavailable("verification response shape")
        if result.get("mullvad_exit_ip") is not True:
            raise EgressWrong("not a Mullvad exit")
        if result.get("country") != "Germany":
            raise EgressWrong("not a German exit")
        address = ipaddress.ip_address(result.get("ip", ""))
        if address.version != 4 or not address.is_global:
            raise EgressWrong("not a global IPv4 exit")
        return str(address)
    except EgressWrong:
        raise
    except EgressUnavailable:
        raise
    except (HTTPError, URLError, OSError, UnicodeError, ValueError) as error:
        raise EgressUnavailable("verification endpoint unavailable") from error


def check_mullvad_session() -> str:
    check_mullvad_policy()
    return check_mullvad_egress()


def persona_snapshot(path: Path) -> PersonaSnapshot:
    details, raw = read_secure_regular_file(
        path,
        uid=0,
        mode=0o644,
        maximum=2 * 1024 * 1024,
        error_type=Blocked,
        detail="installed persona is unavailable or unsafe",
    )
    if len(raw) != details.st_size:
        raise Blocked("installed persona changed while it was being read")
    try:
        persona = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Blocked("installed persona is malformed") from error
    if not isinstance(persona, dict) or persona.get("schema") != 2:
        raise Blocked("installed persona has not been migrated to schema 2")
    stable = {
        key: persona.get(key)
        for key in (
            "persona_id",
            "browser_version",
            "browser_major",
            "camoufox_package_version",
            "os",
            "locale",
            "timezone",
            "preset",
            "config",
            "firefox_user_prefs",
        )
    }
    return PersonaSnapshot(
        inode=details.st_ino,
        size=details.st_size,
        sha256=hashlib.sha256(raw).hexdigest(),
        stable_fields=json.dumps(stable, sort_keys=True, separators=(",", ":")),
    )


def assert_persona_unchanged(baseline: PersonaSnapshot) -> None:
    current = persona_snapshot(PERSONA)
    if current != baseline:
        raise TestFailure("persona inode, hash, size, or stable fields changed")


def log_paths(home: Path) -> set[Path]:
    root = home / LOG_RELATIVE
    require_real_directory(root, os.geteuid(), {0o700})
    result: set[Path] = set()
    for path in root.iterdir():
        if not LOG_NAME_RE.fullmatch(path.name):
            continue
        try:
            details = path.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise TestFailure("runtime log directory contains an unsafe matching entry")
        result.add(path)
    return result


def wait_until(
    predicate: Callable[[], Any],
    timeout: float,
    description: str,
    interval: float = 0.2,
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise TestFailure(f"timed out waiting for {description}")


def wait_new_log(home: Path, before: set[Path], process: subprocess.Popen[bytes]) -> Path:
    def find() -> Path | None:
        new = log_paths(home) - before
        if new:
            candidates: list[tuple[int, Path]] = []
            for path in new:
                try:
                    candidates.append((path.lstat().st_mtime_ns, path))
                except FileNotFoundError:
                    continue
            if candidates:
                return max(candidates)[1]
        if process.poll() is not None:
            raise TestFailure("launcher exited before creating a runtime log")
        return None

    return wait_until(find, 15, "a new runtime log")


def read_log_events(path: Path, uid: int) -> list[dict[str, Any]]:
    _details, raw_bytes = read_secure_regular_file(
        path,
        uid=uid,
        mode=0o600,
        maximum=5 * 1024 * 1024,
        error_type=TestFailure,
        detail="runtime log owner, mode, type, or size is unsafe",
    )
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeError as error:
        raise TestFailure("runtime log is not UTF-8") from error
    if (
        URL_RE.search(raw)
        or contains_ip_literal(raw)
        or RAW_SECRET_RE.search(raw)
        or RAW_CAMOU_CONFIG_RE.search(raw)
        or LONG_NUMBER_RE.search(raw)
    ):
        raise TestFailure("runtime log contains an unredacted sensitive pattern")
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise TestFailure("runtime log contains malformed JSONL") from error
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise TestFailure("runtime log event shape is invalid")
        events.append(event)
    if not events:
        raise TestFailure("runtime log is empty")
    return events


def wait_for_log_event(
    path: Path,
    uid: int,
    predicate: Callable[[dict[str, Any]], bool],
    timeout: float,
    description: str,
) -> dict[str, Any]:
    def find() -> dict[str, Any] | None:
        for event in read_log_events(path, uid):
            if predicate(event):
                return event
        return None

    return wait_until(find, timeout, description, interval=0.5)


class Harness:
    def __init__(
        self,
        *,
        uid: int,
        home: Path,
        writer: ResultWriter,
        duration: int,
        cycles: int,
        vpn_armed: bool,
    ):
        self.uid = uid
        self.home = home
        self.writer = writer
        self.duration = duration
        self.cycles = cycles
        self.vpn_armed = vpn_armed
        self.profile = home / PROFILE_RELATIVE
        self.log_root = home / LOG_RELATIVE
        self.baseline_persona: PersonaSnapshot | None = None
        self.observed_logs: set[str] = set()
        self.processes: list[subprocess.Popen[bytes]] = []
        self.process_roots: dict[tuple[int, int], ProcessRecord] = {}
        self.launches: list[Launch] = []
        self.launch_attempted = False
        self.egress_checks = 0
        self.soak_wall_clock_seconds = 0
        self.soak_qualified = False
        self.log_redaction_verified = False

    def track_process(self, process: subprocess.Popen[bytes]) -> None:
        self.processes.append(process)
        record = read_process(process.pid)
        if record is not None and record.uid == self.uid:
            self.process_roots[(record.pid, record.start_time)] = record

    def run_phase(
        self,
        name: str,
        operation: Callable[[], dict[str, int | bool] | None],
    ) -> None:
        print(f"[PBP VM TEST] {name}", flush=True)
        index = self.writer.begin(name)
        try:
            metrics = operation() or {}
        except Blocked:
            self.writer.finish(index, "BLOCKED", "required real-VM precondition is missing")
            raise
        except TestFailure:
            self.writer.finish(index, "FAIL", "real-VM assertion failed")
            raise
        except Exception as error:
            self.writer.finish(
                index,
                "FAIL",
                f"unexpected harness error ({type(error).__name__})",
            )
            raise TestFailure("unexpected harness error") from error
        self.writer.finish(index, "PASS", "real-VM assertions passed", metrics)

    def preflight(self) -> dict[str, int | bool]:
        effective = pwd.getpwuid(os.geteuid())
        if os.geteuid() == 0 or effective.pw_name != EXPECTED_USER:
            raise Blocked("run the harness as malwarelab inside VNC")
        require_real_directory(self.home, self.uid, {0o700, 0o750})
        require_real_directory(self.profile, self.uid, {0o700})
        require_real_directory(self.log_root, self.uid, {0o700})
        if not WRAPPER.is_file() or not os.access(WRAPPER, os.X_OK):
            raise Blocked("installed PBP wrapper is missing")
        try:
            current = CURRENT_ROOT.resolve(strict=True)
            current.relative_to(Path("/opt/toolkit/pbp/releases").resolve(strict=True))
        except (FileNotFoundError, RuntimeError, ValueError) as error:
            raise Blocked("installed PBP current release is unsafe") from error
        version = (current / "VERSION").read_text(encoding="ascii").strip()
        if version != "v0.1.9":
            raise Blocked("PBP v0.1.9 is not installed")
        display = os.environ.get("DISPLAY", "")
        if not re.fullmatch(r":[0-9]+(?:[.][0-9]+)?", display):
            raise Blocked("no managed VNC/X11 DISPLAY")
        xauthority = Path(os.environ.get("XAUTHORITY", str(self.home / ".Xauthority")))
        if xauthority != self.home / ".Xauthority":
            raise Blocked("unexpected XAUTHORITY")
        details = xauthority.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_uid != self.uid or stat.S_IMODE(details.st_mode) != 0o600:
            raise Blocked("managed XAUTHORITY is missing or unsafe")
        if shutil.which("xdotool") != "/usr/bin/xdotool":
            raise Blocked("xdotool from the v0.1.9 runtime is missing")
        if not Path("/usr/bin/zenity").is_file():
            raise Blocked("zenity from the v0.1.9 runtime is missing")
        if profile_tree(self.uid, self.profile) is not None:
            raise Blocked("a PBP profile process already exists")
        self.assert_lock_free(allow_missing=True)
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise Blocked("qualifying process cleanup requires Linux pidfds")
        try:
            check_mullvad_session()
        except (EgressUnavailable, EgressWrong) as error:
            raise Blocked("Mullvad Germany egress is not healthy") from error
        self.egress_checks += 1
        self.baseline_persona = persona_snapshot(PERSONA)
        return {"pinned_release": True, "egress_verified": True}

    def launcher_environment(self) -> dict[str, str]:
        allowed = (
            "DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "LANG",
        )
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update(
            {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(self.home),
                "USER": EXPECTED_USER,
                "LOGNAME": EXPECTED_USER,
            }
        )
        return environment

    def xdotool_windows(self, pids: set[int]) -> list[str]:
        windows: set[str] = set()
        for pid in pids:
            completed = subprocess.run(
                ["/usr/bin/xdotool", "search", "--onlyvisible", "--pid", str(pid)],
                env=self.launcher_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            if completed.returncode not in (0, 1):
                continue
            for line in completed.stdout.decode("ascii", "ignore").splitlines():
                if line.isdecimal():
                    windows.add(line)
        return sorted(windows)

    def close_windows(self, windows: list[str]) -> None:
        if not windows:
            raise TestFailure("no visible process-owned window was found")
        for window in windows:
            completed = subprocess.run(
                ["/usr/bin/xdotool", "windowclose", window],
                env=self.launcher_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0:
                probe = subprocess.run(
                    ["/usr/bin/xdotool", "getwindowpid", window],
                    env=self.launcher_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                if probe.returncode == 0:
                    raise TestFailure("WM_DELETE window close failed")

    def find_browser_ready(
        self, process: subprocess.Popen[bytes]
    ) -> tuple[ProcessRecord, list[ProcessRecord], list[str]] | None:
        if process.poll() is not None:
            raise TestFailure("launcher exited before a browser window appeared")
        tree = profile_tree(self.uid, self.profile)
        if tree is None:
            return None
        root, records = tree
        windows = self.xdotool_windows({record.pid for record in records})
        if not windows:
            return None
        return root, records, windows

    def start_browser(self, *, desktop: bool) -> Launch:
        before = log_paths(self.home)
        command = [str(WRAPPER), "desktop" if desktop else "run"]
        self.launch_attempted = True
        process = subprocess.Popen(
            command,
            env=self.launcher_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.track_process(process)
        log_path = wait_new_log(self.home, before, process)
        root, records, _windows = wait_until(
            lambda: self.find_browser_ready(process),
            90,
            "the real PBP browser window",
            interval=0.5,
        )
        launch = Launch(
            process=process,
            log_path=log_path,
            browser_root=root,
            captured={(record.pid, record.start_time): record for record in records},
            desktop=desktop,
        )
        self.launches.append(launch)
        self.observed_logs.add(log_path.name)
        return launch

    def refresh_capture(self, launch: Launch) -> list[str]:
        tree = profile_tree(self.uid, self.profile)
        if tree is None:
            return []
        root, records = tree
        if root.pid != launch.browser_root.pid or root.start_time != launch.browser_root.start_time:
            raise TestFailure("browser profile root changed unexpectedly")
        for record in records:
            launch.captured[(record.pid, record.start_time)] = record
        return self.xdotool_windows({record.pid for record in records})

    def assert_lock_free(self, *, allow_missing: bool = False) -> None:
        path = self.home / ".local/share/toolkit-pbp/browser.lock"
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            if allow_missing:
                return
            raise TestFailure("PBP app-lock file is missing")
        except OSError as error:
            raise TestFailure("PBP app-lock file is missing or unsafe") from error
        try:
            details = os.fstat(descriptor)
            try:
                path_details = path.lstat()
            except OSError as error:
                raise TestFailure("PBP app-lock path changed during verification") from error
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != self.uid
                or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o600
                or not stat.S_ISREG(path_details.st_mode)
                or path_details.st_uid != self.uid
                or path_details.st_nlink != 1
                or path_details.st_dev != details.st_dev
                or path_details.st_ino != details.st_ino
            ):
                raise TestFailure("PBP app-lock metadata is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise TestFailure("PBP kernel app-lock was not released") from error
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def wait_clean_exit(self, launch: Launch, expected: set[int], timeout: float) -> int:
        try:
            returncode = launch.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise TestFailure("launcher did not exit within its bounded lifecycle") from error
        if returncode not in expected:
            raise TestFailure("launcher returned an unexpected exit code")

        def no_orphans() -> bool:
            if profile_tree(self.uid, self.profile) is not None:
                return False
            return not any(same_process(record) for record in launch.captured.values())

        wait_until(no_orphans, 20, "all exact browser profile processes to be reaped")
        self.assert_lock_free()
        if self.baseline_persona is None:
            raise TestFailure("missing persona baseline")
        assert_persona_unchanged(self.baseline_persona)
        read_log_events(launch.log_path, self.uid)
        return returncode

    def normal_close_cycle(self, cycle: int) -> dict[str, int | bool]:
        launch = self.start_browser(desktop=False)
        time.sleep(2)
        windows = self.refresh_capture(launch)
        self.close_windows(windows)
        self.wait_clean_exit(launch, {0}, 45)
        return {"cycle": cycle, "normal_exit": True, "lock_reacquired": True}

    def visible_lock_error(self, primary: Launch) -> dict[str, int | bool]:
        before = log_paths(self.home)
        secondary = subprocess.Popen(
            [str(WRAPPER), "desktop"],
            env=self.launcher_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.track_process(secondary)
        log_path = wait_new_log(self.home, before, secondary)
        self.observed_logs.add(log_path.name)
        self.wait_and_close_dialog(secondary, 45)
        if secondary.wait(timeout=15) != 20:
            raise TestFailure("concurrent desktop launcher did not return EXIT_STARTUP")
        events = read_log_events(log_path, self.uid)
        if not any(event.get("event") == "launch.rejected" for event in events):
            raise TestFailure("concurrent launch rejection was not logged")
        if primary.process.poll() is not None:
            raise TestFailure("primary browser died during visible lock-error test")
        return {"visible_dialog": True, "secondary_exit_code": 20}

    def dialog_windows(self, process: subprocess.Popen[bytes]) -> list[str]:
        records = user_processes(self.uid)
        owned = descendants(records, {process.pid})
        dialog_pids = {
            record.pid for record in owned if record.argv and Path(record.argv[0]).name in ("zenity", "xmessage")
        }
        return self.xdotool_windows(dialog_pids)

    def wait_and_close_dialog(self, process: subprocess.Popen[bytes], timeout: float) -> None:
        def find() -> list[str] | None:
            windows = self.dialog_windows(process)
            if windows:
                return windows
            if process.poll() is not None:
                raise TestFailure("desktop launcher exited without a visible error dialog")
            return None

        windows = wait_until(find, timeout, "a visible PBP desktop error dialog")
        self.close_windows(windows)

    def soak(self) -> dict[str, int | bool]:
        launch = self.start_browser(desktop=False)
        lock_metrics = self.visible_lock_error(launch)
        started = time.monotonic()
        next_egress = started
        transient_checks = 0
        while time.monotonic() - started < self.duration:
            if launch.process.poll() is not None:
                raise TestFailure("browser launcher exited during the wall-clock soak")
            if profile_tree(self.uid, self.profile) is None:
                raise TestFailure("browser process disappeared during the wall-clock soak")
            if self.baseline_persona is None:
                raise TestFailure("missing persona baseline")
            assert_persona_unchanged(self.baseline_persona)
            now = time.monotonic()
            if now >= next_egress:
                try:
                    check_mullvad_session()
                except EgressWrong as error:
                    raise TestFailure("egress became definitively unsafe during soak") from error
                except EgressUnavailable:
                    transient_checks += 1
                else:
                    self.egress_checks += 1
                next_egress = now + 60
            time.sleep(min(5.0, max(0.1, self.duration - (time.monotonic() - started))))
        observed = time.monotonic() - started
        elapsed = int(observed)
        self.soak_wall_clock_seconds = elapsed
        self.soak_qualified = qualifies_real_soak(self.duration, observed)
        if self.duration >= MINIMUM_SOAK_SECONDS and not self.soak_qualified:
            raise TestFailure("observed wall-clock soak was shorter than 1800 seconds")
        events = read_log_events(launch.log_path, self.uid)
        launcher_transient = any(
            event.get("event") == "egress.monitor" and event.get("kind") == "transient" for event in events
        )
        if launcher_transient:
            modes = [event.get("offline") for event in events if event.get("event") == "browser.network_mode"]
            if True not in modes:
                raise TestFailure("egress check failed but no fail-closed offline signal was logged")
        windows = self.refresh_capture(launch)
        self.close_windows(windows)
        self.wait_clean_exit(launch, {0}, 45)
        return {
            "wall_clock_seconds": elapsed,
            "minimum_30_minutes": self.soak_qualified,
            "egress_checks": self.egress_checks,
            "transient_egress_checks": transient_checks,
            "visible_lock_dialog": bool(lock_metrics["visible_dialog"]),
        }

    def unexpected_browser_exit(self) -> dict[str, int | bool]:
        launch = self.start_browser(desktop=True)
        self.refresh_capture(launch)
        if not same_process(launch.browser_root):
            raise TestFailure("browser root changed before crash injection")
        if not signal_process(launch.browser_root, signal.SIGKILL):
            raise TestFailure("browser root disappeared before crash injection")
        self.wait_and_close_dialog(launch.process, 60)
        returncode = self.wait_clean_exit(launch, {21, 23}, 30)
        events = read_log_events(launch.log_path, self.uid)
        endings = [
            event for event in events if event.get("event") == "launch.end" and event.get("exit_code") in (21, 23)
        ]
        if not endings:
            raise TestFailure("unexpected browser exit was not classified in the runtime log")
        return {
            "browser_sigkill": True,
            "visible_dialog": True,
            "launcher_exit_code": returncode,
        }

    def run_mullvad(self, action: str) -> None:
        trigger = os.environ.get("DYNAMICFLOW_LAB_VPN_TRIGGER", "")
        if trigger:
            if trigger != str(LAB_VPN_TRIGGER_SOCKET) or action not in (
                "disconnect",
                "connect",
            ):
                raise TestFailure("unsafe lab VPN trigger configuration")
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(900)
            try:
                client.connect(trigger)
                client.sendall((action + "\n").encode("ascii"))
                client.shutdown(socket.SHUT_WR)
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = client.recv(17 - total)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 16:
                        raise TestFailure("bounded lab VPN trigger response is too large")
                if b"".join(chunks) != b"OK\n":
                    raise TestFailure("bounded lab VPN trigger rejected the action")
            except (OSError, TimeoutError) as error:
                raise TestFailure("bounded lab VPN trigger failed") from error
            finally:
                client.close()
            return
        completed = subprocess.run(
            ["/usr/bin/mullvad", action, "--wait"],
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(f"mullvad {action} failed")

    def restore_mullvad(self) -> str:
        self.run_mullvad("connect")

        recovered_exit: list[str] = []

        def healthy() -> bool:
            try:
                recovered_exit[:] = [check_mullvad_session()]
            except (EgressUnavailable, EgressWrong):
                return False
            return True

        wait_until(healthy, 180, "Mullvad Germany recovery", interval=3)
        self.egress_checks += 1
        if len(recovered_exit) != 1:
            raise TestFailure("Mullvad recovery did not expose one verified egress identity")
        return recovered_exit[0]

    def vpn_fail_closed(self) -> dict[str, int | bool]:
        if shutil.which("mullvad") != "/usr/bin/mullvad":
            raise Blocked("Mullvad CLI is missing")
        try:
            baseline_exit = check_mullvad_session()
        except (EgressUnavailable, EgressWrong) as error:
            raise Blocked("Mullvad baseline egress is not healthy") from error
        launch = self.start_browser(desktop=True)
        disconnect_attempted = False
        test_error: BaseException | None = None
        try:
            disconnect_attempted = True
            disconnected_at = time.monotonic()
            self.run_mullvad("disconnect")
            wait_for_log_event(
                launch.log_path,
                self.uid,
                lambda event: event.get("event") == "browser.network_mode" and event.get("offline") is True,
                90,
                "the fail-closed offline signal",
            )
            self.wait_and_close_dialog(launch.process, 300)
            returncode = self.wait_clean_exit(launch, {22}, 45)
            events = read_log_events(launch.log_path, self.uid)
            monitor_kinds = [event.get("kind") for event in events if event.get("event") == "egress.monitor"]
            retry_window = int(time.monotonic() - disconnected_at)
            if "transient" not in monitor_kinds or "exhausted" not in monitor_kinds:
                raise TestFailure("real disconnect did not exercise transient bounded retries")
            if retry_window < 25:
                raise TestFailure("real disconnect did not exercise the bounded backoff window")
            if not any(
                event.get("event") == "launch.end"
                and event.get("reason") in ("vpn_unavailable", "vpn_wrong")
                and event.get("exit_code") == 22
                for event in events
            ):
                raise TestFailure("VPN fail-closed terminal event is missing")
            metrics = {
                "real_disconnect": True,
                "offline_signal": True,
                "visible_dialog": True,
                "launcher_exit_code": returncode,
                "transient_retry_observed": True,
                "bounded_backoff_observed": True,
                "retry_window_seconds": retry_window,
            }
        except BaseException as error:
            test_error = error
            metrics = {}
        finally:
            if disconnect_attempted:
                try:
                    recovered_exit = self.restore_mullvad()
                    if recovered_exit == baseline_exit:
                        raise TestFailure("Mullvad recovery did not switch to a different real egress")
                    metrics["real_relay_switch"] = True
                    metrics["egress_identity_changed"] = True
                    restart = self.normal_close_cycle(self.cycles + 1)
                    if not restart.get("normal_exit") or not restart.get("lock_reacquired"):
                        raise TestFailure("PBP did not restart cleanly after the real relay switch")
                    metrics["restart_after_relay_switch"] = True
                except BaseException as restore_error:
                    raise TestFailure(
                        "Mullvad recovery failed; use the provider console and recovery runbook"
                    ) from restore_error
        if test_error is not None:
            raise test_error
        return metrics

    def log_rotation(self) -> dict[str, int | bool]:
        current = log_paths(self.home)
        if len(current) > 8:
            raise TestFailure("runtime log retention exceeded eight files")
        expected_minimum = self.cycles + 3 + (1 if self.vpn_armed else 0)
        if len(self.observed_logs) < expected_minimum:
            raise TestFailure("launch phases did not produce distinct rotated runtime logs")
        for path in current:
            read_log_events(path, self.uid)
        self.log_redaction_verified = True
        return {
            "distinct_logs_observed": len(self.observed_logs),
            "retained_logs": len(current),
            "retention_bounded": True,
            "redaction_checked": True,
        }

    def cleanup(self) -> None:
        records = user_processes(self.uid)
        roots = {record.pid for record in self.process_roots.values() if same_process(record)}
        owned = descendants(records, roots)
        for launch in reversed(self.launches):
            try:
                tree = profile_tree(self.uid, self.profile)
            except (OSError, TestFailure):
                tree = None
            if tree is not None:
                root, records = tree
                if root.pid == launch.browser_root.pid and root.start_time == launch.browser_root.start_time:
                    for record in records:
                        launch.captured[(record.pid, record.start_time)] = record
            if launch.process.poll() is None:
                try:
                    launch.process.send_signal(signal.SIGTERM)
                    launch.process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            for record in launch.captured.values():
                if same_process(record):
                    signal_process(record, signal.SIGKILL)
            if launch.process.poll() is None:
                try:
                    launch.process.kill()
                except OSError:
                    pass
        for process in self.processes:
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait(timeout=5)
                    except OSError:
                        pass
                    except subprocess.TimeoutExpired:
                        raise TestFailure("test-owned launcher survived SIGKILL")
                except OSError:
                    pass
        for record in reversed(owned):
            if same_process(record):
                signal_process(record, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(same_process(record) for record in owned):
            time.sleep(0.1)
        for record in reversed(owned):
            if same_process(record):
                signal_process(record, signal.SIGKILL)

        if self.launch_attempted:
            records = user_processes(self.uid)
            profile_roots = {record.pid for record in records if uses_profile(record, self.profile)}
            exact_profile = descendants(records, profile_roots)
            for record in reversed(exact_profile):
                if same_process(record):
                    signal_process(record, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(same_process(record) for record in exact_profile):
                time.sleep(0.1)
            for record in reversed(exact_profile):
                if same_process(record):
                    signal_process(record, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(same_process(record) for record in exact_profile):
                time.sleep(0.1)
            if any(same_process(record) for record in exact_profile):
                raise TestFailure("test-owned exact profile processes survived cleanup")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="pbp-vm-soak",
        description=(
            "Real PBP VM soak/restart/crash test. A qualifying PASS needs >=30 minutes "
            "and the explicitly armed Mullvad disconnect phase."
        ),
    )
    result.add_argument("--duration-seconds", type=int, default=MINIMUM_SOAK_SECONDS)
    result.add_argument("--normal-cycles", type=int, default=3)
    result.add_argument("--result", type=Path)
    result.add_argument(
        "--exercise-vpn-failure",
        action="store_true",
        help="perform a real Mullvad disconnect/reconnect fail-closed test",
    )
    result.add_argument(
        "--disposable-network-test",
        action="store_true",
        help="confirm that this VM/session may lose networking during the Mullvad phase",
    )
    result.add_argument(
        "--allow-short-nonqualifying",
        action="store_true",
        help="allow a short diagnostic run; its overall result is always BLOCKED",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    account = pwd.getpwuid(os.geteuid())
    home = Path(account.pw_dir)
    uid = account.pw_uid
    path = result_path(home, uid, args.result)
    qualifying_duration = args.duration_seconds >= MINIMUM_SOAK_SECONDS
    configuration = {
        "duration_seconds": args.duration_seconds,
        "minimum_duration_seconds": MINIMUM_SOAK_SECONDS,
        "normal_cycles": args.normal_cycles,
        "vpn_failure_armed": bool(args.exercise_vpn_failure and args.disposable_network_test),
        "qualifying_duration": qualifying_duration,
    }
    writer = ResultWriter(path, uid, configuration)
    harness = Harness(
        uid=uid,
        home=home,
        writer=writer,
        duration=args.duration_seconds,
        cycles=args.normal_cycles,
        vpn_armed=bool(args.exercise_vpn_failure and args.disposable_network_test),
    )
    status_value = "FAIL"
    exit_code = 1
    try:
        if args.normal_cycles < 2:
            raise Blocked("at least two normal restart cycles are required")
        if args.duration_seconds <= 0:
            raise Blocked("soak duration must be positive")
        if not qualifying_duration and not args.allow_short_nonqualifying:
            raise Blocked("qualifying soak duration is at least 1800 seconds")
        if args.exercise_vpn_failure != args.disposable_network_test:
            raise Blocked("the Mullvad phase requires both explicit network-test options")

        harness.run_phase("preflight", harness.preflight)
        for cycle in range(1, args.normal_cycles + 1):
            harness.run_phase(
                f"normal_close_restart_{cycle}",
                lambda cycle=cycle: harness.normal_close_cycle(cycle),
            )
        harness.run_phase("thirty_minute_soak", harness.soak)
        harness.run_phase("unexpected_browser_process_exit", harness.unexpected_browser_exit)
        if args.exercise_vpn_failure and args.disposable_network_test:
            harness.run_phase("vpn_real_disconnect_fail_closed", harness.vpn_fail_closed)
            vpn_complete = True
        else:
            index = writer.begin("vpn_real_disconnect_fail_closed")
            writer.finish(
                index,
                "SKIP",
                "real network mutation was not explicitly armed",
            )
            vpn_complete = False
        harness.run_phase("log_rotation_redaction", harness.log_rotation)
        if harness.baseline_persona is None:
            raise TestFailure("missing persona baseline")
        assert_persona_unchanged(harness.baseline_persona)

        if qualifying_duration and harness.soak_qualified and vpn_complete:
            status_value = "PASS"
            exit_code = 0
        else:
            status_value = "BLOCKED"
            exit_code = 2
    except Blocked:
        status_value = "BLOCKED"
        exit_code = 2
    except (TestFailure, EgressUnavailable, EgressWrong):
        status_value = "FAIL"
        exit_code = 1
    except KeyboardInterrupt:
        status_value = "BLOCKED"
        exit_code = 130
    except Exception:
        status_value = "FAIL"
        exit_code = 1
    finally:
        try:
            harness.cleanup()
        except Exception:
            status_value = "FAIL"
            exit_code = 1
            index = writer.begin("bounded_cleanup")
            writer.finish(index, "FAIL", "test-owned process cleanup failed")
        writer.finalize(
            status_value,
            {
                "qualifying_real_vm_pass": status_value == "PASS",
                "observed_wall_clock_seconds": harness.soak_wall_clock_seconds,
                "soak_wall_clock_qualified": harness.soak_qualified,
                "egress_checks": harness.egress_checks,
                "distinct_logs_observed": len(harness.observed_logs),
                "runtime_logs_redaction_verified": harness.log_redaction_verified,
                "no_secrets_recorded": harness.log_redaction_verified,
            },
        )
        writer.close()
    print(f"[PBP VM TEST] {status_value}; result: {path}", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
