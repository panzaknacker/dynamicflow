#!/usr/bin/env python3
"""run a command in a PTY and answer the hidden mullvad account prompt."""

import errno
import os
import pty
import sys

PROMPT = b"Mullvad-Accountnummer: "


def child_exit_code(status):
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 99


def main():
    if len(sys.argv) < 2:
        print("usage: pty-account.py COMMAND [ARG ...]", file=sys.stderr)
        return 2
    account_list = os.environ.pop("TOOLKIT_VPN_TEST_ACCOUNTS", None)
    single_account = os.environ.pop("TOOLKIT_VPN_TEST_ACCOUNT", None)
    if account_list is not None and single_account is not None:
        print("set only one account test variable", file=sys.stderr)
        return 2
    if account_list is not None:
        accounts = account_list.split(",")
    elif single_account is not None:
        accounts = [single_account]
    else:
        print("TOOLKIT_VPN_TEST_ACCOUNT or TOOLKIT_VPN_TEST_ACCOUNTS is required", file=sys.stderr)
        return 2
    if not accounts or any(not account for account in accounts):
        print("account test inputs must not be empty", file=sys.stderr)
        return 2

    pid, master_fd = pty.fork()
    if pid == 0:
        os.execvpe(sys.argv[1], sys.argv[1:], os.environ)

    captured = bytearray()
    sent = 0
    prompt_scan_offset = 0
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
            while sent < len(accounts):
                prompt_offset = captured.find(PROMPT, prompt_scan_offset)
                if prompt_offset < 0:
                    break
                os.write(master_fd, accounts[sent].encode("ascii") + b"\n")
                sent += 1
                prompt_scan_offset = prompt_offset + len(PROMPT)
    finally:
        os.close(master_fd)

    _, status = os.waitpid(pid, 0)
    if sent != len(accounts):
        print(
            f"expected {len(accounts)} Mullvad prompts, answered {sent}",
            file=sys.stderr,
        )
        return 98
    return child_exit_code(status)


if __name__ == "__main__":
    raise SystemExit(main())
