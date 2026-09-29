#!/usr/bin/env python3
"""run a command in a PTY and answer the toolkit password and TOTP prompts."""

import errno
import os
import pty
import sys

PROMPT = b"Toolkit-Download-Passwort (Benutzer toolkit): "
TOTP_PROMPT = b"Toolkit-TOTP-Code: "


def child_exit_code(status):
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 99


def main():
    if len(sys.argv) < 2:
        print("usage: pty-password.py COMMAND [ARG ...]", file=sys.stderr)
        return 2

    password = os.environ.pop("TOOLKIT_TEST_PASSWORD", None)
    totp = os.environ.pop("TOOLKIT_TEST_TOTP", None)
    if password is None:
        print("TOOLKIT_TEST_PASSWORD is required", file=sys.stderr)
        return 2
    if totp is None:
        print("TOOLKIT_TEST_TOTP is required", file=sys.stderr)
        return 2

    pid, master_fd = pty.fork()
    if pid == 0:
        os.execvpe(sys.argv[1], sys.argv[1:], os.environ)

    captured = bytearray()
    password_sent = False
    totp_sent = False
    try:
        while True:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break

            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            captured.extend(chunk)
            if not password_sent and PROMPT in captured:
                os.write(master_fd, password.encode("utf-8") + b"\n")
                password_sent = True
            if password_sent and not totp_sent and TOTP_PROMPT in captured:
                os.write(master_fd, totp.encode("ascii") + b"\n")
                totp_sent = True
    finally:
        os.close(master_fd)

    _, status = os.waitpid(pid, 0)
    if not password_sent:
        print("Toolkit password prompt was not observed", file=sys.stderr)
        return 98
    if not totp_sent:
        print("Toolkit TOTP prompt was not observed", file=sys.stderr)
        return 97
    return child_exit_code(status)


if __name__ == "__main__":
    raise SystemExit(main())
