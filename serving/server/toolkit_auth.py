#!/usr/bin/env python3
"""minimal RFC 6238 broker for short-lived, source-IP-bound download tokens."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socketserver
import stat
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Callable


CODE_RE = re.compile(r"^[0-9]{6}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
TOKEN_TTL_DEFAULT = 600
TOKEN_LIMIT_PER_USER = 8
LOGGER = logging.getLogger("toolkit-auth")


def canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def decode_secret(secret_base32: str) -> bytes:
    normalized = "".join(secret_base32.split()).upper()
    if not normalized or not re.fullmatch(r"[A-Z2-7]+", normalized):
        raise ValueError("invalid Base32 TOTP secret")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    secret = base64.b32decode(normalized + padding, casefold=False)
    if len(secret) < 20:
        raise ValueError("TOTP secret must contain at least 160 bits")
    return secret


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    if counter < 0:
        raise ValueError("counter must not be negative")
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % (10**digits):0{digits}d}"


def totp(secret: bytes, timestamp: int, period: int = 30, digits: int = 6) -> str:
    return hotp(secret, int(timestamp) // period, digits)


@dataclasses.dataclass(frozen=True)
class TokenRecord:
    user: str
    client_ip: str
    expires_at: int
    issued_at: int


class AuthState:
    def __init__(
        self,
        config_path: Path,
        state_path: Path,
        *,
        token_ttl: int = TOKEN_TTL_DEFAULT,
        now: Callable[[], float] = time.time,
    ) -> None:
        if token_ttl < 60 or token_ttl > 3600:
            raise ValueError("token TTL must be between 60 and 3600 seconds")
        self.config_path = config_path
        self.state_path = state_path
        self.token_ttl = token_ttl
        self.now = now
        self.lock = threading.Lock()
        self.users = self._load_users()
        self.secret_fingerprints = {user: hashlib.sha256(secret).hexdigest() for user, secret in self.users.items()}
        self.last_counters = self._load_state()
        self.tokens: dict[str, TokenRecord] = {}

    def _load_users(self) -> dict[str, bytes]:
        raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        if raw.get("version") != 1 or not isinstance(raw.get("users"), dict):
            raise ValueError("unsupported users credential format")
        users: dict[str, bytes] = {}
        for user, settings in raw["users"].items():
            if not re.fullmatch(r"[A-Za-z0-9._@-]{1,128}", user):
                raise ValueError("invalid user in credential")
            if not isinstance(settings, dict):
                raise ValueError("invalid user settings")
            users[user] = decode_secret(str(settings.get("secret_base32", "")))
        if not users:
            raise ValueError("credential contains no users")
        return users

    def _load_state(self) -> dict[str, int]:
        if not self.state_path.exists():
            return {}
        if self.state_path.is_symlink() or not self.state_path.is_file():
            raise ValueError("unsafe state path")
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        if raw.get("version") != 1 or not isinstance(raw.get("last_counters"), dict):
            raise ValueError("unsupported state format")
        fingerprints = raw.get("secret_fingerprints", {})
        if not isinstance(fingerprints, dict):
            raise ValueError("invalid secret fingerprint state")
        result: dict[str, int] = {}
        for user, value in raw["last_counters"].items():
            if user not in self.users or not isinstance(value, int) or value < 0:
                raise ValueError("invalid counter state")
            if fingerprints.get(user) == self.secret_fingerprints[user]:
                result[user] = value
        return result

    def _persist_state(self) -> None:
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_path.parent.is_symlink():
            raise ValueError("unsafe state directory")
        payload = (
            json.dumps(
                {
                    "version": 1,
                    "last_counters": self.last_counters,
                    "secret_fingerprints": self.secret_fingerprints,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        fd, temporary = tempfile.mkstemp(prefix=".state.", dir=self.state_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
            directory_fd = os.open(self.state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _prune_tokens(self, now: int) -> None:
        expired = [digest for digest, record in self.tokens.items() if record.expires_at <= now]
        for digest in expired:
            del self.tokens[digest]

    def issue_token(self, user: str, code: str, client_ip: str) -> str | None:
        if user not in self.users:
            LOGGER.info("token rejected reason=invalid-user")
            return None
        if CODE_RE.fullmatch(code) is None:
            LOGGER.info("token rejected reason=invalid-code-format length=%d", len(code))
            return None
        try:
            normalized_ip = canonical_ip(client_ip)
        except ValueError:
            LOGGER.info("token rejected reason=invalid-client-ip")
            return None
        current_time = int(self.now())
        current_counter = current_time // 30
        matching_counter = None
        for candidate in (current_counter, current_counter - 1, current_counter + 1):
            if candidate < 0:
                continue
            if hmac.compare_digest(hotp(self.users[user], candidate), code):
                matching_counter = candidate
                break
        if matching_counter is None:
            LOGGER.info("token rejected reason=totp-mismatch")
            return None

        with self.lock:
            if matching_counter <= self.last_counters.get(user, -1):
                LOGGER.info("token rejected reason=totp-replay")
                return None
            self.last_counters[user] = matching_counter
            self._persist_state()
            self._prune_tokens(current_time)
            user_tokens = sorted(
                ((digest, record) for digest, record in self.tokens.items() if record.user == user),
                key=lambda item: item[1].issued_at,
            )
            while len(user_tokens) >= TOKEN_LIMIT_PER_USER:
                digest, _record = user_tokens.pop(0)
                del self.tokens[digest]
            token = secrets.token_urlsafe(32)
            self.tokens[self._token_digest(token)] = TokenRecord(
                user=user,
                client_ip=normalized_ip,
                issued_at=current_time,
                expires_at=current_time + self.token_ttl,
            )
            LOGGER.info("token issued successfully")
            return token

    def verify_token(self, token: str, client_ip: str) -> bool:
        if TOKEN_RE.fullmatch(token) is None:
            return False
        try:
            normalized_ip = canonical_ip(client_ip)
        except ValueError:
            return False
        current_time = int(self.now())
        digest = self._token_digest(token)
        with self.lock:
            self._prune_tokens(current_time)
            record = self.tokens.get(digest)
            return bool(record and record.client_ip == normalized_ip and record.expires_at > current_time)


class BrokerHandler(BaseHTTPRequestHandler):
    server: "BrokerServer"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _send(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _client_ip(self) -> str:
        return self.headers.get("X-Toolkit-Client-IP", "")

    def do_POST(self) -> None:
        if self.path not in ("/token", "/_toolkit/auth/token"):
            self._send(404, b"Not found\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 6 or length > 7:
            self._send(401, b"Unauthorized\n")
            return
        raw = self.rfile.read(length)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        try:
            code = raw.decode("ascii")
        except UnicodeDecodeError:
            self._send(401, b"Unauthorized\n")
            return
        token = self.server.auth_state.issue_token(self.headers.get("X-Toolkit-User", ""), code, self._client_ip())
        if token is None:
            self._send(401, b"Unauthorized\n")
            return
        self._send(200, token.encode("ascii") + b"\n")

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, b"ok\n")
            return
        if self.path != "/verify":
            self._send(404, b"Not found\n")
            return
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            self._send(401, b"Unauthorized\n")
            return
        if self.server.auth_state.verify_token(authorization[len("Bearer ") :], self._client_ip()):
            self._send(204)
        else:
            self._send(401, b"Unauthorized\n")


class BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str, auth_state: AuthState):
        self.auth_state = auth_state
        super().__init__(socket_path, BrokerHandler)


def serve(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    socket_path = Path(args.socket)
    if socket_path.exists() or socket_path.is_symlink():
        mode = socket_path.lstat().st_mode
        if not stat.S_ISSOCK(mode):
            raise RuntimeError(f"refusing non-socket path: {socket_path}")
        socket_path.unlink()
    socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    state = AuthState(Path(args.config), Path(args.state), token_ttl=args.token_ttl)
    server = BrokerServer(str(socket_path), state)
    os.chmod(socket_path, 0o660)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
    return 0


def verify_stdin_totp() -> int:
    secret_text = os.sys.stdin.readline().rstrip("\n")
    code = os.sys.stdin.readline().rstrip("\n")
    try:
        secret = decode_secret(secret_text)
    except ValueError:
        return 1
    current = int(time.time()) // 30
    valid = any(
        candidate >= 0 and hmac.compare_digest(hotp(secret, candidate), code)
        for candidate in (current, current - 1, current + 1)
    )
    return 0 if valid else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--socket", required=True)
    serve_parser.add_argument("--config", required=True)
    serve_parser.add_argument("--state", required=True)
    serve_parser.add_argument("--token-ttl", type=int, default=TOKEN_TTL_DEFAULT)
    subparsers.add_parser("verify-stdin-totp")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "verify-stdin-totp":
        return verify_stdin_totp()
    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
