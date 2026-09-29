#!/usr/bin/env python3

from __future__ import annotations

import base64
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PBP_M = ROOT / "pbp-m"


def load_pbp_m_module() -> object:
    """load the extensionless executable without running its CLI entry point."""
    name = "_dynamicflow_pbp_m_under_test"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    loader = importlib.machinery.SourceFileLoader(name, str(PBP_M))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError("could not create pbp-m test module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


PBP_M_MODULE = load_pbp_m_module()


class PbpMTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(parents=True, mode=0o700)
        self.key = self.ssh / "id_test"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        self.key.chmod(0o600)
        public_fields = self.key.with_suffix(".pub").read_text(encoding="ascii").split()
        self.host_public_key = f"{public_fields[0]} {public_fields[1]}"
        self.known_hosts = self.ssh / "known_hosts"
        self.known_hosts.write_text(
            f"9.9.9.9 {self.host_public_key}\n",
            encoding="ascii",
        )
        self.known_hosts.chmod(0o600)

        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.whitelist_log = self.base / "whitelist.jsonl"
        self.connect_log = self.base / "connect.json"
        self.connect_env_log = self.base / "connect-env.json"
        self.whitelist = self.bin / "pbp-m-whitelist"
        self.connect = self.bin / "connect-gui.sh"
        self._write_executable(
            self.whitelist,
            """
            #!/usr/bin/env python3
            import json
            import os
            import sys
            from pathlib import Path

            if os.environ.get("EMIT_SECRET"):
                print(os.environ["EMIT_SECRET"], file=sys.stderr)
            log = Path(os.environ["WHITELIST_LOG"])
            with log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(sys.argv[1:]) + "\\n")
            if sys.argv[1] == "release":
                raise SystemExit(int(os.environ.get("RELEASE_EXIT", "0")))
            if os.environ.get("ACQUIRE_EXIT"):
                raise SystemExit(int(os.environ["ACQUIRE_EXIT"]))
            if os.environ.get("OVERSIZED_OUTPUT"):
                sys.stdout.write("x" * 5000)
                raise SystemExit(0)
            values = dict(zip(sys.argv[2::2], sys.argv[3::2]))
            document = {
                "schema": "dynamicflow/pbp-m-whitelist/v1",
                "lease_id": "test-lease.1",
                "host": values["--host"],
                "source_cidr": values["--source-cidr"],
                "ssh_port": int(values["--ssh-port"]),
            }
            if os.environ.get("MISMATCH_HOST"):
                document["host"] = "1.1.1.1"
            print(json.dumps(document))
            """,
        )
        self._write_executable(
            self.connect,
            """
            #!/usr/bin/env python3
            import json
            import os
            import signal
            import sys
            import time
            from pathlib import Path

            def stopped(signum, _frame):
                raise SystemExit(128 + signum)

            for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
                if hasattr(signal, name):
                    signal.signal(getattr(signal, name), stopped)
            base = Path(__file__).resolve().parent.parent
            (base / "connect.json").write_text(
                json.dumps(sys.argv[1:]), encoding="utf-8"
            )
            (base / "connect-env.json").write_text(
                json.dumps(dict(os.environ)), encoding="utf-8"
            )
            if (base / "connect-wait").exists():
                while True:
                    time.sleep(1)
            exit_file = base / "connect-exit"
            raise SystemExit(int(exit_file.read_text()) if exit_file.exists() else 0)
            """,
        )

    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(0o700)

    def environment(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(self.home),
                "PATH": f"{self.bin}:{environment['PATH']}",
                "PBP_M_CONNECT_HELPER": str(self.connect),
                "WHITELIST_LOG": str(self.whitelist_log),
            }
        )
        if extra:
            environment.update(extra)
        return environment

    def run_pbp_m(
        self,
        *arguments: str,
        input_text: str = "",
        extra_environment: dict[str, str] | None = None,
        start_new_session: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(PBP_M), *arguments],
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(extra_environment),
            check=False,
            start_new_session=start_new_session,
        )

    def run_pbp_m_pty(
        self,
        *arguments: str,
        input_text: str,
        extra_environment: dict[str, str] | None = None,
        redirect_stdio: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(PBP_M), *arguments]
        redirected_path = self.base / "redirected-stdio.log"
        redirected_path.unlink(missing_ok=True)
        process_id, descriptor = pty.fork()
        if process_id == 0:
            if redirect_stdio:
                output_descriptor = os.open(
                    redirected_path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                )
                os.dup2(output_descriptor, 1)
                os.dup2(output_descriptor, 2)
                os.close(output_descriptor)
            os.execve(str(PBP_M), command, self.environment(extra_environment))
            os._exit(127)

        output = bytearray()
        status: int | None = None
        deadline = time.monotonic() + 10
        try:
            os.write(descriptor, input_text.encode("utf-8"))
            while True:
                if time.monotonic() >= deadline:
                    os.kill(process_id, signal.SIGKILL)
                    os.waitpid(process_id, 0)
                    self.fail("pbp-m PTY test timed out")
                ready, _, _ = select.select([descriptor], [], [], 0.05)
                if ready:
                    try:
                        chunk = os.read(descriptor, 4096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output.extend(chunk)
                if status is None:
                    waited, candidate = os.waitpid(process_id, os.WNOHANG)
                    if waited == process_id:
                        status = candidate
                elif not ready:
                    break
            if status is None:
                _, status = os.waitpid(process_id, 0)
        finally:
            os.close(descriptor)
        decoded = output.decode("utf-8", errors="replace")
        redirected = (
            redirected_path.read_text(encoding="utf-8", errors="replace")
            if redirect_stdio and redirected_path.exists()
            else decoded
        )
        return subprocess.CompletedProcess(
            command,
            os.waitstatus_to_exitcode(status),
            decoded,
            redirected,
        )

    def common_explicit_arguments(self) -> list[str]:
        return [
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "--whitelist-helper",
            str(self.whitelist),
            "--yes",
        ]

    def read_whitelist_log(self) -> list[list[str]]:
        return [json.loads(line) for line in self.whitelist_log.read_text(encoding="utf-8").splitlines()]

    def test_human_size_formats_transfer_sizes_readably(self) -> None:
        self.assertEqual(PBP_M_MODULE.human_size(0), "0 B")
        self.assertEqual(PBP_M_MODULE.human_size(1023), "1023 B")
        self.assertEqual(PBP_M_MODULE.human_size(1024), "1.0 KiB")
        self.assertEqual(PBP_M_MODULE.human_size(909_244_805), "867.1 MiB")
        self.assertEqual(PBP_M_MODULE.human_size(2 * 1024**3), "2.0 GiB")

    def test_progress_step_prints_a_clear_numbered_phase(self) -> None:
        with mock.patch.object(PBP_M_MODULE, "write_stderr") as write_stderr:
            PBP_M_MODULE.progress_step(3, 6, "Artefakte sicher zur VM übertragen")
        write_stderr.assert_called_once_with("\n[3/6] Artefakte sicher zur VM übertragen")

    def test_progress_step_rejects_invalid_counters(self) -> None:
        for current, total in ((0, 6), (7, 6), (1, 0)):
            with self.subTest(current=current, total=total):
                with self.assertRaises(PBP_M_MODULE.UserError):
                    PBP_M_MODULE.progress_step(current, total, "ungültig")

    def test_setup_vnc_access_is_one_prominent_password_display(self) -> None:
        with mock.patch.object(PBP_M_MODULE, "write_tty") as write_tty:
            PBP_M_MODULE.write_setup_vnc_access("Ab12Cd34", 5901)
        output = write_tty.call_args.args[0]
        self.assertIn("VNC-ZUGANG – JETZT KOPIEREN", output)
        self.assertIn("127.0.0.1::5901", output)
        self.assertEqual(output.count("Ab12Cd34"), 1)
        self.assertIn("genau einmal", output)

    def test_setup_vnc_access_rejects_malformed_secret_or_port(self) -> None:
        for password, port in (("too-short", 5901), ("Ab12Cd34", 0)):
            with self.subTest(password=password, port=port):
                with self.assertRaises(PBP_M_MODULE.UserError):
                    PBP_M_MODULE.write_setup_vnc_access(password, port)

    def test_explicit_values_acquire_connect_and_release_with_separate_arguments(self) -> None:
        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Neue disposable", result.stdout)
        self.assertEqual(
            self.read_whitelist_log(),
            [
                [
                    "acquire",
                    "--host",
                    "9.9.9.9",
                    "--source-cidr",
                    "8.8.8.8/32",
                    "--ssh-port",
                    "22",
                    "--ttl-seconds",
                    "14400",
                ],
                ["release", "--lease-id", "test-lease.1"],
            ],
        )
        connector = json.loads(self.connect_log.read_text(encoding="utf-8"))
        self.assertEqual(connector[-1], "ubuntu@9.9.9.9")
        self.assertIn(str(self.key), connector)
        self.assertIn(str(self.known_hosts), connector)

    def test_connect_prefers_existing_per_vm_managed_hostkey_pin(self) -> None:
        managed_root = self.ssh / "pbp-m-known-hosts"
        managed_root.mkdir(mode=0o700)
        managed_pin = managed_root / "9_9_9_9-22.known_hosts"
        managed_pin.write_text(
            f"9.9.9.9 {self.host_public_key}\n",
            encoding="ascii",
        )
        managed_pin.chmod(0o600)

        result = self.run_pbp_m(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--whitelist-helper",
            str(self.whitelist),
            "--yes",
            "9.9.9.9",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        connector = json.loads(self.connect_log.read_text(encoding="utf-8"))
        known_hosts_index = connector.index("--known-hosts") + 1
        self.assertEqual(connector[known_hosts_index], str(managed_pin))

    def test_connect_without_managed_pin_keeps_legacy_known_hosts_default(self) -> None:
        result = self.run_pbp_m(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--whitelist-helper",
            str(self.whitelist),
            "--yes",
            "9.9.9.9",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        connector = json.loads(self.connect_log.read_text(encoding="utf-8"))
        known_hosts_index = connector.index("--known-hosts") + 1
        self.assertEqual(connector[known_hosts_index], str(self.known_hosts))

    def test_manual_default_uses_tty_ip_key_picker_and_yes_confirmation(self) -> None:
        result = self.run_pbp_m_pty(
            "--known-hosts",
            str(self.known_hosts),
            input_text="9.9.9.9\n1\n8.8.8.8\ny\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("IP für Access:", result.stdout)
        self.assertIn("Verfügbare private SSH-Schlüssel", result.stdout)
        self.assertIn("FINAL wirksamen Firewall-Zustand", result.stdout)
        self.assertIn("0.0.0.0/0", result.stdout)
        self.assertIn("::/0", result.stdout)
        self.assertIn("TCP 5901 niemals extern", result.stdout)
        self.assertIn("Outbound-Regeln", result.stdout)
        self.assertIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stderr)
        self.assertIn("alte/stale Access-IPs", result.stderr)
        self.assertIn("bestehen bleiben", result.stderr)
        self.assertFalse(self.whitelist_log.exists())
        self.assertTrue(self.connect_log.exists())

    def test_connector_failure_is_returned_and_lease_is_still_released(self) -> None:
        (self.base / "connect-exit").write_text("23", encoding="ascii")
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.read_whitelist_log()[-1], ["release", "--lease-id", "test-lease.1"])

    def test_allowlist_failure_prevents_connection(self) -> None:
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"ACQUIRE_EXIT": "7"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SSH wird nicht gestartet", result.stderr)
        self.assertFalse(self.connect_log.exists())

    def test_oversized_adapter_stdout_is_bounded_and_prevents_connection(self) -> None:
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"OVERSIZED_OUTPUT": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("4096-Byte-Antwortlimit", result.stderr)
        self.assertFalse(self.connect_log.exists())

    def test_mismatched_lease_confirmation_prevents_connection(self) -> None:
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"MISMATCH_HOST": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bestätigte nicht exakt", result.stderr)
        self.assertFalse(self.connect_log.exists())
        self.assertEqual(self.read_whitelist_log()[-1], ["release", "--lease-id", "test-lease.1"])

    def test_malformed_lease_field_types_fail_without_traceback(self) -> None:
        original = self.whitelist.read_text(encoding="utf-8")
        self.whitelist.write_text(
            original.replace(
                'document["host"] = "1.1.1.1"',
                'document["host"] = ["not", "a", "host"]',
            ),
            encoding="utf-8",
        )
        self.whitelist.chmod(0o700)
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"MISMATCH_HOST": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ungültige Feldtypen", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.connect_log.exists())

    def test_target_shell_metacharacters_are_rejected_before_helpers(self) -> None:
        marker = self.base / "injected"
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            f"9.9.9.9;touch{marker}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertFalse(self.whitelist_log.exists())

    def test_dns_target_is_rejected_to_prevent_lease_ssh_rebinding(self) -> None:
        result = self.run_pbp_m(*self.common_explicit_arguments(), "pbp.example")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("literale", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_broad_source_network_is_rejected(self) -> None:
        arguments = self.common_explicit_arguments()
        arguments[1] = "8.8.8.0/24"
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kein breites Netz", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_insecure_private_key_permissions_are_rejected(self) -> None:
        self.key.chmod(0o644)
        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsicheren Gruppen-/Fremdzugriff", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_private_key_symlink_is_rejected(self) -> None:
        link = self.ssh / "linked-key"
        link.symlink_to(self.key)
        arguments = self.common_explicit_arguments()
        arguments[3] = str(link)
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nicht sicher geöffnet", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_fake_private_key_header_is_rejected(self) -> None:
        fake_key = self.ssh / "fake-key"
        fake_header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
        fake_key.write_text(
            f"{fake_header}\nnot-a-key\n-----END OPENSSH PRIVATE KEY-----\n",
            encoding="ascii",
        )
        fake_key.chmod(0o600)
        arguments = self.common_explicit_arguments()
        arguments[3] = str(fake_key)
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("strukturell ungültig", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_private_key_in_writable_parent_is_rejected(self) -> None:
        unsafe = self.base / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        unsafe_key = unsafe / "key"
        unsafe_key.write_text(self.key.read_text(encoding="ascii"), encoding="ascii")
        unsafe_key.chmod(0o600)
        arguments = self.common_explicit_arguments()
        arguments[3] = str(unsafe_key)
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gruppen-/weltbeschreibbar", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_openssh_token_paths_are_rejected_before_helpers(self) -> None:
        token_key = self.ssh / "id_%h"
        token_key.write_bytes(self.key.read_bytes())
        token_key.chmod(0o600)
        token_hosts = self.ssh / "known_hosts_%h"
        token_hosts.write_bytes(self.known_hosts.read_bytes())
        token_hosts.chmod(0o600)
        for label, identity, known_hosts in (
            ("identity", token_key, self.known_hosts),
            ("known_hosts", self.key, token_hosts),
        ):
            with self.subTest(path=label):
                result = self.run_pbp_m(
                    "--source-ip",
                    "8.8.8.8",
                    "--identity",
                    str(identity),
                    "--known-hosts",
                    str(known_hosts),
                    "--whitelist-helper",
                    str(self.whitelist),
                    "--yes",
                    "9.9.9.9",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("OpenSSH umdeuten", result.stderr)
                self.assertFalse(self.whitelist_log.exists())

    def test_scoped_ipv6_source_is_rejected(self) -> None:
        arguments = self.common_explicit_arguments()
        arguments[1] = "2606:4700:4700::1111%eth0"
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deaktiviert IPv6 systemweit", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_wrapper_contains_no_external_access_ip_discovery(self) -> None:
        source = PBP_M.read_text(encoding="utf-8")
        self.assertNotIn("api.ipify", source)
        self.assertNotIn("discover_public_ip", source)
        self.assertNotIn("--no-ip-discovery", source)
        self.assertNotIn('name="curl"', source)

    def test_ipv6_target_is_rejected_because_pbp_is_ipv4_only(self) -> None:
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "2606:4700:4700::1111",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deaktiviert IPv6 systemweit", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_ipv6_access_ip_is_rejected_in_helper_mode_too(self) -> None:
        arguments = self.common_explicit_arguments()
        arguments[1] = "2606:4700:4700::1111/128"
        result = self.run_pbp_m(*arguments, "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deaktiviert IPv6 systemweit", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_missing_known_host_pin_stops_before_ip_lookup_or_firewall(self) -> None:
        result = self.run_pbp_m(
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "1.1.1.1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Host-Key", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_manual_mode_requires_controlling_tty_before_gate(self) -> None:
        result = self.run_pbp_m(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "9.9.9.9",
            input_text="y\n",
            start_new_session=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kontrollierendes /dev/tty", result.stderr)
        self.assertNotIn("MANUELLER CLOUD-FIREWALL-GATE", result.stdout)
        self.assertFalse(self.connect_log.exists())

    def test_manual_yes_is_hard_error_and_cannot_bypass_gate(self) -> None:
        result = self.run_pbp_m(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "--yes",
            "9.9.9.9",
            start_new_session=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--yes ist im manuellen Firewall-Modus verboten", result.stderr)
        self.assertNotIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stderr)
        self.assertFalse(self.connect_log.exists())

    def test_manual_no_stops_without_cleanup_reminder(self) -> None:
        result = self.run_pbp_m_pty(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "9.9.9.9",
            input_text="n\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Firewall-Gate wurde nicht bestätigt", result.stderr)
        self.assertNotIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stderr)
        self.assertIn("BEDINGTER FIREWALL-HINWEIS", result.stderr)
        self.assertIn("Falls du bereits Cloud-Regeln geändert hast", result.stderr)
        self.assertFalse(self.connect_log.exists())

    def test_local_port_collision_stops_before_manual_gate(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        local_port = listener.getsockname()[1]
        listener.listen(1)
        result = self.run_pbp_m(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "--local-port",
            str(local_port),
            "9.9.9.9",
            start_new_session=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ist bereits belegt", result.stderr)
        self.assertNotIn("MANUELLER CLOUD-FIREWALL-GATE", result.stdout)
        self.assertFalse(self.connect_log.exists())

    def test_manual_connector_failure_keeps_exact_access_rule_for_diagnostics(self) -> None:
        (self.base / "connect-exit").write_text("23", encoding="ascii")
        result = self.run_pbp_m_pty(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "9.9.9.9",
            input_text="y\n",
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stderr)
        self.assertIn("TCP 22 von 8.8.8.8/32", result.stderr)
        self.assertIn("für die Diagnose behalten", result.stderr)
        self.assertNotIn("Entferne jetzt die temporäre Inbound-Regel", result.stderr)

    def test_gate_and_cleanup_reminder_stay_on_tty_when_stdio_is_redirected(self) -> None:
        result = self.run_pbp_m_pty(
            "--source-ip",
            "8.8.8.8",
            "--identity",
            str(self.key),
            "--known-hosts",
            str(self.known_hosts),
            "9.9.9.9",
            input_text="y\n",
            redirect_stdio=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MANUELLER CLOUD-FIREWALL-GATE", result.stdout)
        self.assertIn("Host-Firewall", result.stdout)
        self.assertIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stdout)
        self.assertNotIn("MANUELLER CLOUD-FIREWALL-GATE", result.stderr)
        self.assertNotIn("CLOUD-FIREWALL-ABSCHLUSSPRÜFUNG", result.stderr)

    def test_nondefault_port_requires_and_accepts_exact_bracketed_pin(self) -> None:
        self.known_hosts.write_text(
            f"[9.9.9.9]:2222 {self.host_public_key}\n",
            encoding="ascii",
        )
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "--ssh-port",
            "2222",
            "9.9.9.9",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        acquire = self.read_whitelist_log()[0]
        self.assertEqual(acquire[acquire.index("--ssh-port") + 1], "2222")

    def test_hashed_exact_known_host_pin_is_accepted(self) -> None:
        subprocess.run(
            ["ssh-keygen", "-q", "-H", "-f", str(self.known_hosts)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        self.known_hosts.chmod(0o600)
        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_multiple_exact_hostkeys_for_same_target_are_rejected_before_helpers(self) -> None:
        second_key = self.ssh / "id_second_host"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(second_key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        second_fields = second_key.with_suffix(".pub").read_text(encoding="ascii").split()
        second_host_public_key = f"{second_fields[0]} {second_fields[1]}"
        self.assertNotEqual(second_host_public_key, self.host_public_key)
        self.known_hosts.write_text(
            f"9.9.9.9 {self.host_public_key}\n9.9.9.9 {second_host_public_key}\n",
            encoding="ascii",
        )
        self.known_hosts.chmod(0o600)

        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("genau einen exakten", result.stderr)
        self.assertIn("mehrere Keys", result.stderr)
        self.assertFalse(self.whitelist_log.exists())
        self.assertFalse(self.connect_log.exists())

    def test_wildcard_known_host_entry_is_not_an_exact_pin(self) -> None:
        self.known_hosts.write_text(f"* {self.host_public_key}\n", encoding="ascii")
        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wildcards", result.stderr)
        self.assertFalse(self.whitelist_log.exists())

    def test_marked_known_host_entries_are_not_exact_pins(self) -> None:
        for marker in ("@cert-authority", "@revoked"):
            with self.subTest(marker=marker):
                self.whitelist_log.unlink(missing_ok=True)
                self.known_hosts.write_text(
                    f"{marker} 9.9.9.9 {self.host_public_key}\n",
                    encoding="ascii",
                )
                result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("@cert-authority", result.stderr)
                self.assertIn("@revoked", result.stderr)
                self.assertFalse(self.whitelist_log.exists())

    def test_adapter_stderr_is_not_forwarded_to_operator(self) -> None:
        secret = "provider-token-must-not-appear"
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"EMIT_SECRET": secret},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)
        connector_environment = json.loads(self.connect_env_log.read_text(encoding="utf-8"))
        self.assertNotIn("EMIT_SECRET", connector_environment)

    def test_pythonpath_injection_is_ignored_by_wrapper_and_children(self) -> None:
        poison = self.base / "poison"
        poison.mkdir()
        marker = self.base / "pythonpath-executed"
        (poison / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
            encoding="utf-8",
        )
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"PYTHONPATH": str(poison)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_broken_stderr_during_signal_still_releases_active_lease(self) -> None:
        wait_file = self.base / "connect-wait"
        wait_file.touch()
        process = subprocess.Popen(
            [str(PBP_M), *self.common_explicit_arguments(), "9.9.9.9"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(),
        )
        deadline = time.monotonic() + 5
        while not self.connect_log.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("connector did not start before broken-pipe signal test")
            time.sleep(0.02)
        assert process.stderr is not None
        process.stderr.close()
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
        wait_file.unlink(missing_ok=True)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
        self.assertEqual(
            self.read_whitelist_log()[-1],
            ["release", "--lease-id", "test-lease.1"],
        )
        if process.stdout is not None:
            process.stdout.close()

    def test_all_supported_termination_signals_release_active_lease(self) -> None:
        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
            if not hasattr(signal, name):
                continue
            signum = getattr(signal, name)
            with self.subTest(signal=name):
                self.whitelist_log.unlink(missing_ok=True)
                self.connect_log.unlink(missing_ok=True)
                (self.base / "connect-wait").touch()
                process = subprocess.Popen(
                    [str(PBP_M), *self.common_explicit_arguments(), "9.9.9.9"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self.environment(),
                )
                deadline = time.monotonic() + 5
                while not self.connect_log.exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        process.kill()
                        self.fail(f"connector did not start before {name}")
                    time.sleep(0.02)
                process.send_signal(signum)
                _stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 128 + signum, stderr)
                self.assertEqual(
                    self.read_whitelist_log()[-1],
                    ["release", "--lease-id", "test-lease.1"],
                )
                (self.base / "connect-wait").unlink(missing_ok=True)

    def test_release_failure_is_fail_closed_for_result(self) -> None:
        result = self.run_pbp_m(
            *self.common_explicit_arguments(),
            "9.9.9.9",
            extra_environment={"RELEASE_EXIT": "9"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("providerseitige TTL", result.stderr)

    def test_invalid_explicit_provider_adapter_never_falls_back_to_manual(self) -> None:
        self.whitelist.unlink()
        result = self.run_pbp_m(*self.common_explicit_arguments(), "9.9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pbp-m-whitelist", result.stderr)
        self.assertNotIn("MANUELLER CLOUD-FIREWALL-GATE", result.stdout)
        self.assertFalse(self.connect_log.exists())

    def test_no_arguments_shows_menu_and_can_select_existing_vm_connect(self) -> None:
        result = self.run_pbp_m_pty(
            input_text="2\n9.9.9.9\n1\n8.8.8.8\ny\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Neue disposable", result.stdout)
        self.assertIn("Vorhandene PBP-VM", result.stdout)
        self.assertTrue(self.connect_log.exists())
        self.assertFalse(self.whitelist_log.exists())

    def test_setup_parser_exposes_modes_persona_hostkey_and_test_gate_options(self) -> None:
        fingerprint = "SHA256:" + "A" * 43
        parser = PBP_M_MODULE.build_parser()
        arguments = parser.parse_args(
            [
                "--setup",
                "--persona-class",
                "performance",
                "--hostkey-fingerprint",
                fingerprint,
                "--accept-disposable-test-browser",
                "--no-open",
                "9.9.9.9",
            ]
        )
        self.assertTrue(arguments.setup)
        self.assertFalse(arguments.connect)
        self.assertEqual(arguments.persona_class, "performance")
        self.assertEqual(arguments.hostkey_fingerprint, fingerprint)
        self.assertTrue(arguments.accept_disposable_test_browser)
        self.assertTrue(arguments.no_open)
        with mock.patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--setup", "--connect"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["--setup", "--persona-class", "server"])

    def test_setup_firewall_gate_is_exact_ipv4_only_and_keeps_outbound_unchanged(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="9.9.9.9")
        mode = PBP_M_MODULE.BrowserBuildMode(disposable_test=True)
        with (
            mock.patch.object(PBP_M_MODULE, "write_tty") as write_tty,
            mock.patch.object(
                PBP_M_MODULE,
                "prompt_tty",
                return_value="y",
            ),
        ):
            PBP_M_MODULE.confirm_setup_firewall(
                target,
                "8.8.8.8/32",
                2222,
                self.key,
                "performance",
                mode,
            )
        gate = write_tty.call_args.args[0]
        self.assertIn("8.8.8.8/32", gate)
        self.assertIn("ALLOW  TCP  Port 2222", gate)
        self.assertIn("0.0.0.0/0", gate)
        self.assertIn("::/0", gate)
        self.assertRegex(gate, r"5901[^\n]*(?:niemals|geschlossen)")
        self.assertIn("OUTBOUND", gate)
        self.assertIn("unverändert", gate.lower())
        self.assertIn("performance", gate)
        self.assertIn("DISPOSABLE", gate)

    def test_setup_hostkey_mismatch_never_persists_candidate(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="7.7.7.7")
        observed = "SHA256:" + "A" * 43
        expected = "SHA256:" + "B" * 43
        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, observed),
            ),
            mock.patch.object(PBP_M_MODULE, "write_tty"),
            mock.patch.object(PBP_M_MODULE, "atomic_write_known_host") as persist,
        ):
            with self.assertRaisesRegex(
                PBP_M_MODULE.UserError,
                "stimmt nicht mit der neuen VM überein",
            ):
                PBP_M_MODULE.ensure_setup_host_pin(
                    target,
                    22,
                    self.ssh,
                    None,
                    expected,
                )
        persist.assert_not_called()

    def test_setup_expected_fingerprint_mismatch_fails_before_managed_pin_reuse(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="9.9.9.9")
        managed_root = self.ssh / "pbp-m-known-hosts"
        managed_root.mkdir(mode=0o700)
        managed_pin = managed_root / "9_9_9_9-22.known_hosts"
        managed_pin.write_text(
            f"9.9.9.9 {self.host_public_key}\n",
            encoding="ascii",
        )
        managed_pin.chmod(0o600)
        observed = "SHA256:" + "A" * 43
        expected = "SHA256:" + "B" * 43

        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, observed),
            ),
            mock.patch.object(
                PBP_M_MODULE,
                "managed_pin_matches",
                return_value=True,
            ) as managed_pin_matches,
        ):
            with self.assertRaisesRegex(
                PBP_M_MODULE.UserError,
                "stimmt nicht mit der neuen VM überein",
            ):
                PBP_M_MODULE.ensure_setup_host_pin(
                    target,
                    22,
                    self.ssh,
                    None,
                    expected,
                )

        managed_pin_matches.assert_not_called()
        self.assertEqual(
            managed_pin.read_text(encoding="ascii"),
            f"9.9.9.9 {self.host_public_key}\n",
        )

    def test_setup_rejects_explicit_known_hosts_plus_expected_fingerprint(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="9.9.9.9")
        expected = "SHA256:" + "A" * 43
        with mock.patch.object(PBP_M_MODULE, "scan_ed25519_host_key") as scan:
            with self.assertRaisesRegex(
                PBP_M_MODULE.UserError,
                "alternative Vertrauensanker",
            ):
                PBP_M_MODULE.ensure_setup_host_pin(
                    target,
                    22,
                    self.ssh,
                    self.known_hosts,
                    expected,
                )
        scan.assert_not_called()

    def test_setup_hostkey_exact_oob_fingerprint_is_saved_as_exact_pin(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="7.7.7.7")
        key_blob = base64.b64decode(self.host_public_key.split()[1], validate=True)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, fingerprint),
            ),
            mock.patch.object(PBP_M_MODULE, "write_tty"),
        ):
            pin = PBP_M_MODULE.ensure_setup_host_pin(
                target,
                22,
                self.ssh,
                None,
                fingerprint,
            )
        self.assertEqual(
            pin.read_text(encoding="ascii"),
            f"7.7.7.7 {self.host_public_key}\n",
        )
        self.assertEqual(pin.stat().st_mode & 0o777, 0o600)

    def test_setup_hostkey_console_verification_can_be_skipped_with_tofu_warning(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="7.7.7.7")
        observed = "SHA256:" + "A" * 43
        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, observed),
            ),
            mock.patch.object(PBP_M_MODULE, "prompt_tty", return_value="n") as prompt_tty,
            mock.patch.object(PBP_M_MODULE, "write_tty") as write_tty,
        ):
            pin = PBP_M_MODULE.ensure_setup_host_pin(
                target,
                22,
                self.ssh,
                None,
                None,
            )

        self.assertEqual(
            pin.read_text(encoding="ascii"),
            f"7.7.7.7 {self.host_public_key}\n",
        )
        self.assertEqual(pin.stat().st_mode & 0o777, 0o600)
        self.assertIn("[Y/n]", prompt_tty.call_args.args[0])
        output = "".join(call.args[0] for call in write_tty.call_args_list)
        self.assertIn("TOFU-Pin", output)
        self.assertIn("nicht ausgeschlossen", output)
        self.assertNotIn("Fingerprint aus Providerkonsole:", prompt_tty.call_args.args[0])

    def test_setup_hostkey_console_verification_remains_safe_default(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="7.7.7.7")
        key_blob = base64.b64decode(self.host_public_key.split()[1], validate=True)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, fingerprint),
            ),
            mock.patch.object(
                PBP_M_MODULE,
                "prompt_tty",
                side_effect=["", fingerprint],
            ) as prompt_tty,
            mock.patch.object(PBP_M_MODULE, "write_tty") as write_tty,
        ):
            pin = PBP_M_MODULE.ensure_setup_host_pin(
                target,
                22,
                self.ssh,
                None,
                None,
            )

        self.assertEqual(
            pin.read_text(encoding="ascii"),
            f"7.7.7.7 {self.host_public_key}\n",
        )
        self.assertEqual(prompt_tty.call_count, 2)
        self.assertIn("[Y/n]", prompt_tty.call_args_list[0].args[0])
        self.assertEqual(
            prompt_tty.call_args_list[1].args[0],
            "Fingerprint aus Providerkonsole: ",
        )
        output = "".join(call.args[0] for call in write_tty.call_args_list)
        self.assertIn("ssh-keyscan allein", output)
        self.assertNotIn("TOFU-Pin", output)

    def test_setup_matching_expected_fingerprint_reuses_matching_managed_pin(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="9.9.9.9")
        managed_root = self.ssh / "pbp-m-known-hosts"
        managed_root.mkdir(mode=0o700)
        managed_pin = managed_root / "9_9_9_9-22.known_hosts"
        managed_pin.write_text(
            f"9.9.9.9 {self.host_public_key}\n",
            encoding="ascii",
        )
        managed_pin.chmod(0o600)
        key_blob = base64.b64decode(self.host_public_key.split()[1], validate=True)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")

        with (
            mock.patch.object(
                PBP_M_MODULE,
                "scan_ed25519_host_key",
                return_value=(self.host_public_key, fingerprint),
            ),
            mock.patch.object(PBP_M_MODULE, "write_stderr") as write_stderr,
            mock.patch.object(PBP_M_MODULE, "write_tty") as write_tty,
            mock.patch.object(PBP_M_MODULE, "prompt_tty") as prompt_tty,
            mock.patch.object(PBP_M_MODULE, "atomic_write_known_host") as persist,
        ):
            pin = PBP_M_MODULE.ensure_setup_host_pin(
                target,
                22,
                self.ssh,
                None,
                fingerprint,
            )

        self.assertEqual(pin, managed_pin)
        self.assertIn("wiederverwendet", write_stderr.call_args.args[0])
        write_tty.assert_not_called()
        prompt_tty.assert_not_called()
        persist.assert_not_called()

    def test_provisioning_ssh_arguments_are_fail_closed(self) -> None:
        target = PBP_M_MODULE.Target(user="ubuntu", host="9.9.9.9")
        arguments = PBP_M_MODULE.provisioning_ssh_arguments(
            Path("/usr/bin/ssh"),
            target,
            2222,
            self.key,
            self.known_hosts,
        )
        options = {arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == "-o"}
        self.assertEqual(arguments[:4], ["-F", "none", "-p", "2222"])
        self.assertIn("ClearAllForwardings=yes", options)
        self.assertIn("ForwardAgent=no", options)
        self.assertIn("ForwardX11=no", options)
        self.assertIn("IdentitiesOnly=yes", options)
        self.assertIn("IdentityAgent=none", options)
        self.assertIn("PreferredAuthentications=publickey", options)
        self.assertIn("PasswordAuthentication=no", options)
        self.assertIn("KbdInteractiveAuthentication=no", options)
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertIn("GlobalKnownHostsFile=none", options)
        self.assertIn(f"UserKnownHostsFile={self.known_hosts}", options)
        self.assertIn("UpdateHostKeys=no", options)
        self.assertEqual(arguments[-2:], ["-i", str(self.key)])
        self.assertFalse(any("accept-new" in value for value in arguments))
        with self.assertRaisesRegex(PBP_M_MODULE.UserError, "nicht absolut"):
            PBP_M_MODULE.provisioning_ssh_arguments(
                Path("ssh"),
                target,
                22,
                self.key,
                self.known_hosts,
            )

    def test_remote_pbp_verification_calls_vpn_helper_without_empty_argument(self) -> None:
        with mock.patch.object(
            PBP_M_MODULE,
            "remote_command",
            return_value=b"PBP_READY Abcd1234\n",
        ) as remote_command:
            password = PBP_M_MODULE.verify_remote_pbp(
                mock.sentinel.ssh_master,
                "performance",
            )

        self.assertEqual(password, "Abcd1234")
        remote_command.assert_called_once()
        call = remote_command.call_args
        self.assertIs(call.args[0], mock.sentinel.ssh_master)
        script = call.args[1]
        helper = "/usr/local/libexec/dynamicflow-pbp-vpn-verify"
        self.assertIn(f"sudo -n {helper} >/dev/null\n", script)
        self.assertNotIn(f'{helper} ""', script)
        self.assertNotIn(f"{helper} ''", script)
        self.assertIn(".schema == 3 and .persona_class == $selected", script)
        self.assertIn("--arg selected performance", script)
        self.assertIn("/usr/bin/xdotool getdisplaygeometry", script)
        self.assertIn("test \"$geometry\" = '1600 900'", script)
        self.assertIn("127.0.0.1:5901", script)
        self.assertIn("'[::1]:5901'", script)
        self.assertIn("*) exit 51", script)
        self.assertEqual(call.kwargs["label"], "PBP-Abschlussprüfung")
        self.assertEqual(call.kwargs["timeout"], PBP_M_MODULE.REMOTE_VERIFY_TIMEOUT)

    def test_remote_output_limit_kills_process_without_unbounded_communicate(self) -> None:
        process = mock.Mock()
        process.stdout = mock.Mock()
        process.stdout.fileno.return_value = 73
        process.poll.return_value = None
        process.wait.return_value = -signal.SIGKILL
        read_limits: list[int] = []

        def fill_requested_buffer(descriptor: int, limit: int) -> bytes:
            self.assertEqual(descriptor, 73)
            read_limits.append(limit)
            return b"x" * limit

        with (
            mock.patch.object(
                PBP_M_MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(PBP_M_MODULE.os, "set_blocking") as set_blocking,
            mock.patch.object(
                PBP_M_MODULE.os,
                "read",
                side_effect=fill_requested_buffer,
            ),
        ):
            with self.assertRaisesRegex(
                PBP_M_MODULE.UserError,
                "Remote-Ausgabe überschritt das feste",
            ):
                PBP_M_MODULE.run_remote_bounded(
                    ["/usr/bin/ssh", "example"],
                    timeout=30,
                )

        set_blocking.assert_called_once_with(73, False)
        self.assertEqual(sum(read_limits), PBP_M_MODULE.MAX_REMOTE_OUTPUT + 1)
        self.assertLessEqual(max(read_limits), 4096)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2)
        process.communicate.assert_not_called()
        process.stdout.close.assert_called_once_with()

    def test_tty_remote_command_routes_all_stdio_through_controlling_tty(self) -> None:
        master = mock.Mock()
        master.ssh = Path("/usr/bin/ssh")
        master.common_arguments = ["-F", "none"]
        master.socket_path = Path("/tmp/pbp-test-control")
        master.destination = "ubuntu@9.9.9.9"
        result = mock.Mock(returncode=0, stdout=None)

        with (
            mock.patch.object(PBP_M_MODULE.os, "open", return_value=91) as open_tty,
            mock.patch.object(PBP_M_MODULE.os, "isatty", return_value=True) as isatty,
            mock.patch.object(PBP_M_MODULE.os, "close") as close_tty,
            mock.patch.object(
                PBP_M_MODULE.subprocess,
                "run",
                return_value=result,
            ) as run,
            mock.patch.object(PBP_M_MODULE, "run_remote_bounded") as bounded,
        ):
            output = PBP_M_MODULE.remote_command(
                master,
                "./bootstrap-pbp.sh",
                label="Mullvad-/PBP-Installation",
                timeout=60,
                allocate_tty=True,
                capture=False,
            )

        self.assertEqual(output, b"")
        open_tty.assert_called_once_with(
            "/dev/tty",
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
        )
        isatty.assert_called_once_with(91)
        call = run.call_args
        self.assertIn("-tt", call.args[0])
        self.assertNotIn("-T", call.args[0])
        self.assertEqual(call.kwargs["stdin"], 91)
        self.assertEqual(call.kwargs["stdout"], 91)
        self.assertEqual(call.kwargs["stderr"], 91)
        close_tty.assert_called_once_with(91)
        bounded.assert_not_called()

    def test_setup_signal_guard_interrupts_work_defers_cleanup_and_restores(self) -> None:
        guarded_signals = (signal.SIGTERM, signal.SIGINT)
        previous = {
            signal.SIGTERM: mock.sentinel.previous_sigterm,
            signal.SIGINT: mock.sentinel.previous_sigint,
        }
        guard = PBP_M_MODULE.SetupSignalGuard()

        with (
            mock.patch.object(
                PBP_M_MODULE.SignalCoordinator,
                "supported_signals",
                return_value=guarded_signals,
            ),
            mock.patch.object(
                PBP_M_MODULE.signal,
                "getsignal",
                side_effect=lambda signum: previous[signum],
            ),
            mock.patch.object(PBP_M_MODULE.signal, "signal") as set_handler,
        ):
            guard.install()
            with self.assertRaises(PBP_M_MODULE.SetupInterrupted) as interrupted:
                guard._handle(signal.SIGTERM, None)
            self.assertEqual(interrupted.exception.signum, signal.SIGTERM)
            self.assertEqual(guard.received, signal.SIGTERM)

            guard.begin_cleanup()
            guard._handle(signal.SIGINT, None)
            guard._handle(signal.SIGINT, None)
            self.assertEqual(guard.received, signal.SIGTERM)
            guard.restore()

        self.assertEqual(
            set_handler.call_args_list,
            [
                mock.call(signal.SIGTERM, guard._handle),
                mock.call(signal.SIGINT, guard._handle),
                mock.call(signal.SIGTERM, previous[signal.SIGTERM]),
                mock.call(signal.SIGINT, previous[signal.SIGINT]),
            ],
        )
        self.assertEqual(guard._previous, {})

    def test_setup_no_open_skips_local_tunnel_port_check(self) -> None:
        class StopAfterPortDecision(Exception):
            pass

        arguments = PBP_M_MODULE.build_parser().parse_args(
            [
                "--setup",
                "--no-open",
                "--identity",
                str(self.key),
                "--source-ip",
                "8.8.8.8",
                "--persona-class",
                "basic",
                "9.9.9.9",
            ]
        )
        with (
            mock.patch.object(PBP_M_MODULE, "verify_controlling_tty"),
            mock.patch.object(
                PBP_M_MODULE,
                "validate_private_key",
                return_value=self.key,
            ),
            mock.patch.object(
                PBP_M_MODULE,
                "derive_public_key",
                return_value=self.host_public_key,
            ),
            mock.patch.object(PBP_M_MODULE, "verify_local_port_available") as port_check,
            mock.patch.object(
                PBP_M_MODULE,
                "choose_browser_build_mode",
                side_effect=StopAfterPortDecision,
            ),
        ):
            with self.assertRaises(StopAfterPortDecision):
                PBP_M_MODULE.run_setup(arguments)

        port_check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
