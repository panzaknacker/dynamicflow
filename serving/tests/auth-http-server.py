#!/usr/bin/env python3
"""local MFA test server: basic+TOTP token issuance, then bearer downloads."""

import argparse
import base64
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TEST_TOKEN = "A" * 43
TEST_TOTP = b"287082\n"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--port", required=True, type=int)
    return parser.parse_args()


class AuthHandler(SimpleHTTPRequestHandler):
    expected_basic = "Basic " + base64.b64encode(b'toolkit:s"e\\cr#et').decode("ascii")
    expected_bearer = "Bearer " + TEST_TOKEN

    def _path(self):
        return urlsplit(self.path).path

    def _is_protected(self):
        path = self._path()
        return path == "/tools" or path.startswith("/tools/")

    def _send_unauthorized(self):
        self.send_response(401)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _reject_protected(self):
        if not self._is_protected():
            return False
        if self.headers.get("Authorization") == self.expected_bearer:
            return False
        self._send_unauthorized()
        return True

    def do_POST(self):
        if self._path() != "/_toolkit/auth/token":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        body = self.rfile.read(length) if 0 <= length <= 16 else b""
        if self.headers.get("Authorization") != self.expected_basic or body != TEST_TOTP:
            self._send_unauthorized()
            return
        payload = (TEST_TOKEN + "\n").encode("ascii")
        self.send_response(200)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self):
        if self._reject_protected():
            return
        if self._is_protected():
            self.send_response(405)
            self.end_headers()
            return
        super().do_HEAD()

    def do_GET(self):
        if self._reject_protected():
            return
        super().do_GET()

    def log_message(self, _format, *args):
        pass


def main():
    args = parse_args()
    handler = functools.partial(AuthHandler, directory=args.directory)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
