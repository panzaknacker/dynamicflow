#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pbp_vm_soak",
    ROOT / "tests" / "pbp-vm-soak.py",
)
assert SPEC and SPEC.loader
pbp_vm_soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pbp_vm_soak
SPEC.loader.exec_module(pbp_vm_soak)


class VMSoakContractTests(unittest.TestCase):
    def test_defaults_can_only_describe_a_qualifying_wall_clock_run(self):
        args = pbp_vm_soak.parser().parse_args([])
        self.assertGreaterEqual(
            args.duration_seconds,
            pbp_vm_soak.MINIMUM_SOAK_SECONDS,
        )
        self.assertGreaterEqual(args.normal_cycles, 2)
        self.assertFalse(args.exercise_vpn_failure)
        self.assertFalse(args.disposable_network_test)

    def test_qualification_requires_observed_not_only_requested_wall_clock(self):
        self.assertFalse(
            pbp_vm_soak.qualifies_real_soak(
                pbp_vm_soak.MINIMUM_SOAK_SECONDS,
                pbp_vm_soak.MINIMUM_SOAK_SECONDS - 0.001,
            )
        )
        self.assertFalse(
            pbp_vm_soak.qualifies_real_soak(
                pbp_vm_soak.MINIMUM_SOAK_SECONDS - 1,
                pbp_vm_soak.MINIMUM_SOAK_SECONDS + 60,
            )
        )
        self.assertTrue(
            pbp_vm_soak.qualifies_real_soak(
                pbp_vm_soak.MINIMUM_SOAK_SECONDS,
                pbp_vm_soak.MINIMUM_SOAK_SECONDS,
            )
        )

    def test_profile_matching_is_exact(self):
        profile = Path("/home/malwarelab/.local/share/toolkit-pbp/profile")
        exact = pbp_vm_soak.ProcessRecord(
            100,
            1,
            1000,
            10,
            ("camoufox-bin", "-profile", str(profile)),
        )
        sibling = pbp_vm_soak.ProcessRecord(
            101,
            1,
            1000,
            11,
            ("camoufox-bin", "--profile=" + str(profile) + "-other"),
        )
        self.assertTrue(pbp_vm_soak.uses_profile(exact, profile))
        self.assertFalse(pbp_vm_soak.uses_profile(sibling, profile))

    def test_descendant_capture_excludes_unrelated_processes(self):
        records = [
            pbp_vm_soak.ProcessRecord(100, 1, 1000, 1, ("root",)),
            pbp_vm_soak.ProcessRecord(101, 100, 1000, 2, ("child",)),
            pbp_vm_soak.ProcessRecord(102, 101, 1000, 3, ("grandchild",)),
            pbp_vm_soak.ProcessRecord(200, 1, 1000, 4, ("unrelated",)),
        ]
        selected = pbp_vm_soak.descendants(records, {100})
        self.assertEqual({record.pid for record in selected}, {100, 101, 102})

    def test_pidfd_recheck_refuses_a_reused_numeric_pid(self):
        record = pbp_vm_soak.ProcessRecord(100, 1, 1000, 42, ("browser",))
        with (
            mock.patch.object(pbp_vm_soak.os, "pidfd_open", return_value=77),
            mock.patch.object(pbp_vm_soak.signal, "pidfd_send_signal") as send_signal,
            mock.patch.object(pbp_vm_soak.os, "close") as close,
            mock.patch.object(pbp_vm_soak, "same_process", return_value=False),
        ):
            self.assertFalse(pbp_vm_soak.signal_process(record, pbp_vm_soak.signal.SIGTERM))
        send_signal.assert_not_called()
        close.assert_called_once_with(77)

    def test_policy_helper_exit_contract_is_fail_closed(self):
        success = pbp_vm_soak.subprocess.CompletedProcess([], 0, "policy-ok\n", "")
        with mock.patch.object(pbp_vm_soak.subprocess, "run", return_value=success):
            pbp_vm_soak.check_mullvad_policy()
        with (
            mock.patch.object(
                pbp_vm_soak.subprocess,
                "run",
                return_value=pbp_vm_soak.subprocess.CompletedProcess([], 20, "", ""),
            ),
            self.assertRaises(pbp_vm_soak.EgressWrong),
        ):
            pbp_vm_soak.check_mullvad_policy()
        with (
            mock.patch.object(
                pbp_vm_soak.subprocess,
                "run",
                return_value=pbp_vm_soak.subprocess.CompletedProcess([], 21, "", ""),
            ),
            self.assertRaises(pbp_vm_soak.EgressUnavailable),
        ):
            pbp_vm_soak.check_mullvad_policy()

    def test_bounded_lab_vpn_trigger_sends_only_the_fixed_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trigger.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            received: list[bytes] = []

            def serve() -> None:
                connection, _ = server.accept()
                with connection:
                    chunks = []
                    while True:
                        chunk = connection.recv(32)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    received.append(b"".join(chunks))
                    connection.sendall(b"OK\n")

            worker = threading.Thread(target=serve)
            worker.start()
            harness = object.__new__(pbp_vm_soak.Harness)
            with (
                mock.patch.object(pbp_vm_soak, "LAB_VPN_TRIGGER_SOCKET", path),
                mock.patch.dict(
                    os.environ,
                    {"DYNAMICFLOW_LAB_VPN_TRIGGER": str(path)},
                ),
            ):
                harness.run_mullvad("disconnect")
            worker.join(timeout=5)
            server.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(received, [b"disconnect\n"])

    def test_lab_vpn_trigger_rejects_unbounded_action_or_path(self):
        harness = object.__new__(pbp_vm_soak.Harness)
        with mock.patch.dict(
            os.environ,
            {"DYNAMICFLOW_LAB_VPN_TRIGGER": "/tmp/untrusted.sock"},
        ):
            with self.assertRaises(pbp_vm_soak.TestFailure):
                harness.run_mullvad("disconnect")
        with mock.patch.dict(
            os.environ,
            {"DYNAMICFLOW_LAB_VPN_TRIGGER": str(pbp_vm_soak.LAB_VPN_TRIGGER_SOCKET)},
        ):
            with self.assertRaises(pbp_vm_soak.TestFailure):
                harness.run_mullvad("status")

    def test_result_writer_is_json_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            writer = pbp_vm_soak.ResultWriter(
                path,
                os.geteuid(),
                {
                    "duration_seconds": 1800,
                    "normal_cycles": 3,
                    "vpn_failure_armed": True,
                },
            )
            index = writer.begin("preflight")
            writer.finish(index, "PASS", "real prerequisites present", {"checked": True})
            writer.finalize(
                "PASS",
                {
                    "qualifying_real_vm_pass": True,
                    "no_secrets_recorded": True,
                },
            )
            writer.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            result = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["phases"][0]["status"], "PASS")

    def test_log_contract_accepts_redaction_and_rejects_raw_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            safe = Path(temporary) / "runtime-safe.jsonl"
            safe.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-07-23T00:00:00+00:00",
                        "event": "runtime.stderr",
                        "message": ("token=[redacted] [redacted-url] [redacted-ip] CAMOU_CONFIG=[redacted]"),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            safe.chmod(0o600)
            self.assertEqual(
                pbp_vm_soak.read_log_events(safe, os.geteuid())[0]["event"],
                "runtime.stderr",
            )

            unsafe = Path(temporary) / "runtime-unsafe.jsonl"
            unsafe.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-07-23T00:00:00+00:00",
                        "event": "runtime.stderr",
                        "message": "sanitizer contract probe",
                        "metadata": {"token": "nested-raw-value"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            unsafe.chmod(0o600)
            with self.assertRaises(pbp_vm_soak.TestFailure):
                pbp_vm_soak.read_log_events(unsafe, os.geteuid())

            for index, raw_message in enumerate(
                (
                    "endpoint=https://example.test",
                    "peer=185.65.134.1",
                    "relay=2001:db8::1",
                )
            ):
                unsafe_transport = Path(temporary) / f"runtime-unsafe-{index}.jsonl"
                unsafe_transport.write_text(
                    json.dumps(
                        {
                            "timestamp": "2026-07-23T00:00:00+00:00",
                            "event": "runtime.stderr",
                            "message": raw_message,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                unsafe_transport.chmod(0o600)
                with self.assertRaises(pbp_vm_soak.TestFailure):
                    pbp_vm_soak.read_log_events(unsafe_transport, os.geteuid())

    def test_log_contract_rejects_symlinks_and_wrong_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.jsonl"
            target.write_text('{"event":"launch.end"}\n', encoding="utf-8")
            target.chmod(0o600)
            link = root / "runtime-link.jsonl"
            link.symlink_to(target)
            with self.assertRaises(pbp_vm_soak.TestFailure):
                pbp_vm_soak.read_log_events(link, os.geteuid())

            target.chmod(0o644)
            with self.assertRaises(pbp_vm_soak.TestFailure):
                pbp_vm_soak.read_log_events(target, os.geteuid())


if __name__ == "__main__":
    unittest.main()
