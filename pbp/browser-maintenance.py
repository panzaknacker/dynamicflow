#!/usr/bin/env python3
"""fail-closed camoufox release gates and read-only upstream audit.

the release and disposable-test commands are deliberately offline.  the audit
command only reads allow-listed official HTTPS endpoints and never edits the
lock or policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parent
DEFAULT_LOCK = ROOT / "browser-assets.lock"
DEFAULT_POLICY = ROOT / "browser-security-policy.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^([0-9]+(?:[.][0-9]+){0,3})")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)$")
ALLOWED_ONLINE_HOSTS = frozenset(
    {
        "api.github.com",
        "product-details.mozilla.org",
        "pypi.org",
    }
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
EXIT_BLOCKED = 1
EXIT_INVALID = 2
OFFLINE_CHECK_NAMES = frozenset(
    {
        "policy-current",
        "review-disposition",
        "exact-release-provenance",
        "exact-wrapper-provenance",
        "gecko-security-baseline",
    }
)
DISPOSABLE_TEST_FAILURES = frozenset(
    {
        "review-disposition",
        "gecko-security-baseline",
    }
)


class ValidationError(ValueError):
    """the checked input is malformed or fails a security invariant."""


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError(f"{field} must be an RFC3339 UTC timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidationError(f"{field} is not a valid timestamp") from error
    if result.tzinfo != timezone.utc:
        raise ValidationError(f"{field} must use UTC")
    return result


def parse_version(value: Any, field: str) -> tuple[int, ...]:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    match = VERSION_RE.match(value)
    if match is None:
        raise ValidationError(f"{field} has no numeric Gecko version")
    return tuple(int(part) for part in match.group(1).split("."))


def comparable_version(value: Any, field: str) -> tuple[int, int, int, int]:
    parts = parse_version(value, field)
    return (parts + (0, 0, 0, 0))[:4]


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValidationError(f"cannot read {path}: {error}") from error
    if len(raw) > 1024 * 1024:
        raise ValidationError(f"{path} is unexpectedly large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{path} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must contain a JSON object")
    return value


def read_lock(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValidationError(f"cannot read {path}: {error}") from error
    if len(lines) > 256:
        raise ValidationError(f"{path} has too many lines")
    result: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != 2:
            raise ValidationError(f"{path}:{number}: expected exactly key and value")
        key, value = fields
        if key in result:
            raise ValidationError(f"{path}:{number}: duplicate key {key}")
        result[key] = value
    return result


def require_object(parent: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ValidationError(f"policy.{key} must be an object")
    return value


def require_string(parent: Mapping[str, Any], key: str, field: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def require_bool(parent: Mapping[str, Any], key: str, field: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be a boolean")
    return value


def require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256")
    return value


def validate_policy_shape(policy: Mapping[str, Any], now: datetime) -> list[Check]:
    if policy.get("schema") != 1:
        raise ValidationError("unsupported browser security policy schema")
    review = require_object(policy, "review")
    gate = require_object(policy, "security_gate")
    mozilla = require_object(policy, "mozilla")
    locked = require_object(policy, "locked_release")
    wrapper = require_object(policy, "python_wrapper")
    checkpoint = require_object(policy, "latest_reviewed_checkpoint")

    observed = parse_timestamp(review.get("observed_at"), "policy.review.observed_at")
    expires = parse_timestamp(review.get("expires_at"), "policy.review.expires_at")
    maximum_window = gate.get("maximum_review_window_days")
    if not isinstance(maximum_window, int) or isinstance(maximum_window, bool):
        raise ValidationError("policy.security_gate.maximum_review_window_days must be an integer")
    if maximum_window < 1 or maximum_window > 14:
        raise ValidationError("policy review window must be between 1 and 14 days")
    if expires <= observed:
        raise ValidationError("policy review expiry must be after observation")
    if (expires - observed).total_seconds() > maximum_window * 86400:
        raise ValidationError("policy review window exceeds its fail-closed maximum")
    if observed > now:
        raise ValidationError("policy observation is in the future")

    minimum = require_string(gate, "minimum_gecko_version", "policy.security_gate.minimum_gecko_version")
    latest = require_string(mozilla, "latest_version", "policy.mozilla.latest_version")
    parse_version(minimum, "policy.security_gate.minimum_gecko_version")
    parse_version(latest, "policy.mozilla.latest_version")
    if comparable_version(minimum, "minimum Gecko version") > comparable_version(latest, "latest Mozilla version"):
        raise ValidationError("minimum Gecko version exceeds reviewed Mozilla release")

    for name, release in (("locked_release", locked), ("checkpoint", checkpoint)):
        repository = require_string(release, "repository", f"policy.{name}.repository")
        if REPOSITORY_RE.fullmatch(repository) is None:
            raise ValidationError(f"policy.{name}.repository is invalid")
        require_string(release, "tag", f"policy.{name}.tag")
        commit = require_string(release, "tag_commit", f"policy.{name}.tag_commit")
        if COMMIT_RE.fullmatch(commit) is None:
            raise ValidationError(f"policy.{name}.tag_commit must be a Git commit")
        require_bool(
            release,
            "commit_signature_verified",
            f"policy.{name}.commit_signature_verified",
        )
        require_bool(release, "release_immutable", f"policy.{name}.release_immutable")
        parse_timestamp(
            release.get("release_published_at"),
            f"policy.{name}.release_published_at",
        )
        parse_version(release.get("browser_version"), f"policy.{name}.browser_version")
        assets = require_object(release, "assets")
        for architecture in ("amd64", "arm64"):
            asset = require_object(assets, architecture)
            require_string(asset, "name", f"policy.{name}.assets.{architecture}.name")
            url = require_string(asset, "url", f"policy.{name}.assets.{architecture}.url")
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname != "github.com" or "/releases/download/" not in parsed.path:
                raise ValidationError(
                    f"policy.{name}.assets.{architecture}.url is not a pinned GitHub HTTPS release URL"
                )
            require_hash(
                asset.get("sha256"),
                f"policy.{name}.assets.{architecture}.sha256",
            )

    project = require_string(wrapper, "project", "policy.python_wrapper.project")
    version = require_string(wrapper, "version", "policy.python_wrapper.version")
    wheel = require_string(wrapper, "wheel", "policy.python_wrapper.wheel")
    if not wheel.startswith(project.replace("-", "_") + "-" + version + "-"):
        raise ValidationError("policy wrapper wheel does not match project/version")
    require_hash(wrapper.get("wheel_sha256"), "policy.python_wrapper.wheel_sha256")

    return [
        Check("policy-current", now <= expires, f"expires {expires.isoformat()}"),
        Check(
            "review-disposition",
            review.get("disposition") == "approved",
            str(review.get("reason", "no review reason")),
        ),
    ]


def validate_lock_against_policy(lock: Mapping[str, str], policy: Mapping[str, Any], now: datetime) -> list[Check]:
    checks = validate_policy_shape(policy, now)
    locked = require_object(policy, "locked_release")
    gate = require_object(policy, "security_gate")
    wrapper = require_object(policy, "python_wrapper")

    required_lock_keys = {
        "browser_version",
        "browser_major",
        "browser_release_tag",
        "browser_release_repo",
        "browser_amd64_name",
        "browser_amd64_url",
        "browser_amd64_sha256",
        "browser_arm64_name",
        "browser_arm64_url",
        "browser_arm64_sha256",
        "camoufox_package",
        "camoufox_wheel_sha256",
    }
    missing = sorted(required_lock_keys.difference(lock))
    if missing:
        raise ValidationError("browser lock is missing: " + ", ".join(missing))

    browser_version = lock["browser_version"]
    browser_tuple = comparable_version(browser_version, "lock.browser_version")
    try:
        browser_major = int(lock["browser_major"])
    except ValueError as error:
        raise ValidationError("lock.browser_major must be an integer") from error
    if browser_major != browser_tuple[0]:
        raise ValidationError("lock.browser_major disagrees with browser_version")

    exact_pairs = {
        "browser_version": locked.get("browser_version"),
        "browser_release_tag": locked.get("tag"),
        "browser_release_repo": locked.get("repository"),
    }
    exact_ok = all(lock[key] == expected for key, expected in exact_pairs.items())
    for architecture in ("amd64", "arm64"):
        asset = require_object(require_object(locked, "assets"), architecture)
        for suffix in ("name", "url", "sha256"):
            key = f"browser_{architecture}_{suffix}"
            expected = asset.get(suffix)
            exact_ok = exact_ok and lock[key] == expected
        require_hash(lock[f"browser_{architecture}_sha256"], f"lock {architecture}")
        if "latest" in lock[f"browser_{architecture}_url"].lower():
            raise ValidationError("browser asset URL must never use latest")
    checks.append(
        Check(
            "exact-release-provenance",
            exact_ok,
            f"{lock['browser_release_repo']} {lock['browser_release_tag']} at {locked.get('tag_commit')}",
        )
    )

    package_match = PACKAGE_RE.fullmatch(lock["camoufox_package"])
    if package_match is None:
        raise ValidationError("lock.camoufox_package must be an exact == pin")
    wrapper_ok = (
        package_match.group(1) == wrapper.get("project")
        and package_match.group(2) == wrapper.get("version")
        and lock["camoufox_wheel_sha256"] == wrapper.get("wheel_sha256")
    )
    require_hash(lock["camoufox_wheel_sha256"], "lock wrapper wheel")
    checks.append(
        Check(
            "exact-wrapper-provenance",
            wrapper_ok,
            lock["camoufox_package"],
        )
    )

    minimum = require_string(gate, "minimum_gecko_version", "policy minimum Gecko version")
    gecko_ok = browser_tuple >= comparable_version(minimum, "minimum Gecko version")
    checks.append(
        Check(
            "gecko-security-baseline",
            gecko_ok,
            f"locked {browser_version}; required >= {minimum}",
        )
    )
    return checks


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        validate_online_url(new_url)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def validate_online_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_ONLINE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise ValidationError(f"refusing non-official audit endpoint: {url}")


def fetch_json(url: str, timeout: float = 15.0) -> dict[str, Any]:
    validate_online_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json, application/json",
            "User-Agent": "dynamicflow-pbp-browser-audit/1",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        RestrictedRedirect(),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValidationError(f"audit endpoint returned HTTP {response.status}")
            content_type = response.headers.get_content_type()
            if content_type not in ("application/json", "application/octet-stream"):
                raise ValidationError(f"audit endpoint returned unexpected type {content_type}")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise ValidationError(f"official upstream audit failed for {url}: {error}") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValidationError(f"audit response is too large: {url}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"audit endpoint returned invalid JSON: {url}") from error
    if not isinstance(value, dict):
        raise ValidationError(f"audit endpoint did not return an object: {url}")
    return value


def github_api(repository: str, suffix: str) -> str:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise ValidationError(f"invalid GitHub repository: {repository}")
    owner, name = repository.split("/", 1)
    safe_repository = "/".join(urllib.parse.quote(part, safe="") for part in (owner, name))
    return f"https://api.github.com/repos/{safe_repository}/{suffix}"


def release_asset_map(release: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValidationError("GitHub release has no asset list")
    result: dict[str, Mapping[str, Any]] = {}
    for value in assets:
        if not isinstance(value, dict):
            raise ValidationError("GitHub release contains an invalid asset")
        name = value.get("name")
        if not isinstance(name, str) or name in result:
            raise ValidationError("GitHub release contains unnamed/duplicate assets")
        result[name] = value
    return result


def check_online_release(expected: Mapping[str, Any], fetcher: Callable[[str], dict[str, Any]]) -> list[Check]:
    repository = require_string(expected, "repository", "release repository")
    tag = require_string(expected, "tag", "release tag")
    tag_path = urllib.parse.quote(tag, safe="")
    release = fetcher(github_api(repository, f"releases/tags/{tag_path}"))
    reference = fetcher(github_api(repository, f"git/ref/tags/{tag_path}"))
    reference_object = require_object(reference, "object")
    if reference_object.get("type") != "commit":
        raise ValidationError("annotated Git tags require an explicitly dereferenced commit")
    actual_commit = reference_object.get("sha")
    if not isinstance(actual_commit, str) or COMMIT_RE.fullmatch(actual_commit) is None:
        raise ValidationError("GitHub tag did not resolve to a commit")
    assets = release_asset_map(release)

    checks = [
        Check("tag-still-resolves", actual_commit == expected.get("tag_commit"), actual_commit),
        Check("release-tag", release.get("tag_name") == tag, str(release.get("tag_name"))),
        Check(
            "release-published-at",
            release.get("published_at") == expected.get("release_published_at"),
            str(release.get("published_at")),
        ),
        Check(
            "release-state",
            release.get("draft") is False and release.get("prerelease") is False,
            f"draft={release.get('draft')} prerelease={release.get('prerelease')}",
        ),
    ]
    expected_assets = require_object(expected, "assets")
    for architecture in ("amd64", "arm64"):
        wanted = require_object(expected_assets, architecture)
        name = require_string(wanted, "name", f"expected {architecture} name")
        actual = assets.get(name)
        digest = actual.get("digest") if actual is not None else None
        url = actual.get("browser_download_url") if actual is not None else None
        checks.append(
            Check(
                f"{architecture}-release-asset",
                digest == "sha256:" + str(wanted.get("sha256")) and url == wanted.get("url"),
                f"{name} {digest}",
            )
        )
    return checks


def run_online_audit(
    lock: Mapping[str, str],
    policy: Mapping[str, Any],
    now: datetime,
    fetcher: Callable[[str], dict[str, Any]] = fetch_json,
) -> list[Check]:
    checks = validate_lock_against_policy(lock, policy, now)
    locked = require_object(policy, "locked_release")
    checkpoint = require_object(policy, "latest_reviewed_checkpoint")
    wrapper = require_object(policy, "python_wrapper")
    mozilla = require_object(policy, "mozilla")
    checks.extend(check_online_release(locked, fetcher))

    repository = require_string(checkpoint, "repository", "latest checkpoint repository")
    latest_release = fetcher(github_api(repository, "releases/latest"))
    latest_tag = latest_release.get("tag_name")
    checks.append(
        Check(
            "latest-checkpoint-tag",
            latest_tag == checkpoint.get("tag"),
            f"official latest is {latest_tag}",
        )
    )
    checks.extend(check_online_release(checkpoint, fetcher))
    minimum = require_string(
        require_object(policy, "security_gate"),
        "minimum_gecko_version",
        "minimum Gecko version",
    )
    checkpoint_version = require_string(checkpoint, "browser_version", "checkpoint browser version")
    checks.append(
        Check(
            "checkpoint-security-baseline",
            comparable_version(checkpoint_version, "checkpoint version")
            >= comparable_version(minimum, "minimum Gecko version"),
            f"checkpoint {checkpoint_version}; required >= {minimum}",
        )
    )

    product_url = require_string(mozilla, "product_details_url", "Mozilla product details URL")
    products = fetcher(product_url)
    current_firefox = products.get("LATEST_FIREFOX_VERSION")
    current_date = products.get("LAST_RELEASE_DATE")
    checks.append(
        Check(
            "mozilla-version-observation",
            current_firefox == mozilla.get("latest_version") and current_date == mozilla.get("last_release_date"),
            f"Mozilla reports {current_firefox} released {current_date}",
        )
    )

    pypi_url = require_string(wrapper, "pypi_json_url", "PyPI JSON URL")
    package = fetcher(pypi_url)
    info = require_object(package, "info")
    files = package.get("urls")
    if not isinstance(files, list):
        raise ValidationError("PyPI response has no files")
    expected_wheel = wrapper.get("wheel")
    expected_digest = wrapper.get("wheel_sha256")
    wheel_ok = False
    wheel_signed: bool | None = None
    for file_info in files:
        if not isinstance(file_info, dict) or file_info.get("filename") != expected_wheel:
            continue
        digests = file_info.get("digests")
        if isinstance(digests, dict):
            wheel_ok = digests.get("sha256") == expected_digest
        wheel_signed = file_info.get("has_sig")
    checks.append(
        Check(
            "pypi-wrapper",
            info.get("version") == wrapper.get("version") and wheel_ok,
            f"latest={info.get('version')} wheel_signature={wheel_signed}",
        )
    )
    return checks


def report_payload(
    mode: str,
    lock_path: Path,
    policy_path: Path,
    checks: list[Check],
) -> dict[str, Any]:
    policy_digest = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    names = [check.name for check in checks]
    failures = frozenset(check.name for check in checks if not check.passed)
    if (
        mode == "disposable-test"
        and len(names) == len(set(names))
        and frozenset(names) == OFFLINE_CHECK_NAMES
        and failures == DISPOSABLE_TEST_FAILURES
    ):
        result = "TEST-ONLY"
    elif all(check.passed for check in checks):
        result = "PASS" if mode != "disposable-test" else "BLOCKED"
    else:
        result = "BLOCKED"
    return {
        "schema": 1,
        "mode": mode,
        "result": result,
        "lock_sha256": lock_digest,
        "policy_sha256": policy_digest,
        "checks": [{"name": item.name, "passed": item.passed, "detail": item.detail} for item in checks],
    }


def print_human(payload: Mapping[str, Any]) -> None:
    print(f"Camoufox {payload['mode']} gate: {payload['result']}")
    for item in payload["checks"]:
        marker = "PASS" if item["passed"] else "FAIL"
        print(f"  {marker:4}  {item['name']}: {item['detail']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed PBP Camoufox maintenance checks")
    parser.add_argument(
        "mode",
        choices=("release", "disposable-test", "audit"),
        help=("release and disposable-test are offline; audit reads official upstream metadata"),
    )
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        lock = read_lock(arguments.lock)
        policy = read_json_object(arguments.policy)
        if arguments.mode in ("release", "disposable-test"):
            checks = validate_lock_against_policy(lock, policy, utc_now())
        else:
            checks = run_online_audit(lock, policy, utc_now())
        payload = report_payload(arguments.mode, arguments.lock, arguments.policy, checks)
    except ValidationError as error:
        payload = {
            "schema": 1,
            "mode": arguments.mode,
            "result": "INVALID",
            "error": str(error),
        }
        if arguments.json:
            json.dump(payload, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(f"Camoufox {arguments.mode} gate: INVALID", file=sys.stderr)
            print(f"  {error}", file=sys.stderr)
        return EXIT_INVALID

    if arguments.json:
        json.dump(payload, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print_human(payload)
    return 0 if payload["result"] in ("PASS", "TEST-ONLY") else EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
