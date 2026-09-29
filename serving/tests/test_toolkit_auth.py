#!/usr/bin/env python3
import importlib.util
import json
import os
import socket
import threading
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("toolkit_auth", ROOT / "server" / "toolkit_auth.py")
assert SPEC and SPEC.loader
AUTH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUTH
SPEC.loader.exec_module(AUTH)

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class Clock:
    def __init__(self, value: int):
        self.value = value

    def __call__(self) -> float:
        return float(self.value)


class AuthStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "users.json"
        self.state = self.root / "state" / "state.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "users": {"toolkit": {"secret_base32": RFC_SECRET}},
                }
            ),
            encoding="utf-8",
        )
        self.clock = Clock(59)
        self.auth = AUTH.AuthState(self.config, self.state, token_ttl=60, now=self.clock)

    def tearDown(self):
        self.temporary.cleanup()

    def test_rfc6238_vector_and_six_digit_projection(self):
        secret = AUTH.decode_secret(RFC_SECRET)
        self.assertEqual(AUTH.totp(secret, 59, digits=8), "94287082")
        self.assertEqual(AUTH.totp(secret, 59), "287082")

    def test_issue_verify_ip_binding_expiry_and_tamper(self):
        token = self.auth.issue_token("toolkit", "287082", "192.0.2.10")
        self.assertIsNotNone(token)
        assert token is not None
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        self.assertTrue(self.auth.verify_token(token, "192.0.2.10"))
        self.assertFalse(self.auth.verify_token(token, "192.0.2.11"))
        replacement = "B" if token[-1] == "A" else "A"
        self.assertFalse(self.auth.verify_token(token[:-1] + replacement, "192.0.2.10"))
        self.clock.value += 60
        self.assertFalse(self.auth.verify_token(token, "192.0.2.10"))

    def test_totp_counter_is_single_use_and_persisted(self):
        token = self.auth.issue_token("toolkit", "287082", "2001:db8::1")
        self.assertIsNotNone(token)
        self.assertIsNone(self.auth.issue_token("toolkit", "287082", "2001:0db8:0:0:0:0:0:1"))
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        restarted = AUTH.AuthState(self.config, self.state, token_ttl=60, now=self.clock)
        self.assertIsNone(restarted.issue_token("toolkit", "287082", "2001:db8::1"))
        assert token is not None
        self.assertFalse(restarted.verify_token(token, "2001:db8::1"))

    def test_adjacent_time_step_is_accepted_once(self):
        secret = AUTH.decode_secret(RFC_SECRET)
        previous_code = AUTH.totp(secret, 30)
        token = self.auth.issue_token("toolkit", previous_code, "198.51.100.5")
        self.assertIsNotNone(token)

    def test_invalid_inputs_are_rejected(self):
        self.assertIsNone(self.auth.issue_token("missing", "287082", "192.0.2.1"))
        self.assertIsNone(self.auth.issue_token("toolkit", "abc", "192.0.2.1"))
        self.assertIsNone(self.auth.issue_token("toolkit", "287082", "not-an-ip"))
        self.assertFalse(self.auth.verify_token("short", "192.0.2.1"))

    def test_unix_socket_http_token_and_verify_flow(self):
        socket_path = str(self.root / "auth.sock")
        server = AUTH.BrokerServer(socket_path, self.auth)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def request(payload: bytes) -> bytes:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(socket_path)
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                chunks = []
                while chunk := client.recv(4096):
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                client.close()

        try:
            issued = request(
                b"POST /_toolkit/auth/token HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"X-Toolkit-User: toolkit\r\n"
                b"X-Toolkit-Client-IP: 192.0.2.44\r\n"
                b"Content-Length: 7\r\n"
                b"Connection: close\r\n\r\n287082\n"
            )
            self.assertIn(b" 200 ", issued.split(b"\r\n", 1)[0])
            token = issued.split(b"\r\n\r\n", 1)[1].strip().decode("ascii")
            self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")

            verified = request(
                f"GET /verify HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Toolkit-Client-IP: 192.0.2.44\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            self.assertIn(b" 204 ", verified.split(b"\r\n", 1)[0])

            wrong_ip = request(
                f"GET /verify HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Toolkit-Client-IP: 192.0.2.45\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            self.assertIn(b" 401 ", wrong_ip.split(b"\r\n", 1)[0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_rotated_secret_does_not_reuse_old_counter_state(self):
        self.assertIsNotNone(self.auth.issue_token("toolkit", "287082", "192.0.2.20"))
        rotated_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "users": {"toolkit": {"secret_base32": rotated_secret}},
                }
            ),
            encoding="utf-8",
        )
        rotated = AUTH.AuthState(self.config, self.state, token_ttl=60, now=self.clock)
        code = AUTH.totp(AUTH.decode_secret(rotated_secret), 59)
        self.assertIsNotNone(rotated.issue_token("toolkit", code, "192.0.2.20"))


if __name__ == "__main__":
    unittest.main()
