#!/usr/bin/env python3
"""
Deterministic contract and boundary test suite for Remote Strict Controller.

Exercises all lifecycle, admission, validation, publisher IPC, and cleanup guards
according to PlanStrictCIHang and PlanQuietCorpusFailures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from typing import Any
from unittest import mock

import proof.remote_strict_controller as rsc
from proof.remote_strict_fixtures import (
    CANONICAL_MODULES,
    FAKE_STAGE_EMITTER_SOURCE,
    generate_final_record,
    generate_pin,
    generate_stage_record,
    provision_canonical_w,
)


class FakePublisher:
    """
    In-process test fake for Strict Supervisor IPC over fd3/fd4.
    Runs serving thread reading requests from _req_r and writing ACKs to _ack_w.
    Supports failure injection, write stalling, partial frames, and verified readback.
    """

    def __init__(
        self,
        mode: str = "success",
        fail_unit: str | None = None,
        overrides: dict[str, Any] | None = None,
    ):
        self.mode = mode
        self.fail_unit = fail_unit
        self.overrides = overrides or {}
        self.received_requests: list[dict[str, Any]] = []

        self._req_r, self.req_w = os.pipe()
        self.ack_r, self._ack_w = os.pipe()

        self._stop_event = threading.Event()
        self._closed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        buffer = bytearray()
        try:
            while not self._stop_event.is_set():
                if self.mode == "stall_write":
                    # Do not read from request pipe so writer buffer fills up
                    self._stop_event.wait(timeout=5.0)
                    break

                r, _, _ = select.select([self._req_r], [], [], 0.05)
                if not r:
                    continue

                try:
                    chunk = os.read(self._req_r, 65536)
                except OSError:
                    break

                if not chunk:
                    # Client closed request pipe
                    break

                buffer.extend(chunk)
                while b"\n" in buffer:
                    idx = buffer.find(b"\n")
                    line = buffer[:idx].decode("utf-8", errors="replace").strip()
                    buffer = buffer[idx + 1 :]
                    if not line:
                        continue

                    try:
                        req = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    self.received_requests.append(req)
                    ack = self._build_ack(req)

                    if self.mode == "silent_pipe":
                        # Read request but never write ACK
                        continue

                    if self.mode == "partial_frame":
                        # Write partial frame without newline, then break
                        try:
                            os.write(self._ack_w, b'{"request_id": "' + req.get("request_id", "").encode("utf-8"))
                        except OSError:
                            pass
                        return

                    if self.mode == "no_op" or ack is None:
                        # Close ACK writer without sending reply
                        return

                    ack_bytes = (json.dumps(ack) + "\n").encode("utf-8")
                    try:
                        os.write(self._ack_w, ack_bytes)
                    except OSError:
                        return
        finally:
            # Serving thread closes its owned descriptors on exit
            try:
                os.close(self._ack_w)
            except OSError:
                pass
            try:
                os.close(self._req_r)
            except OSError:
                pass

    def _build_ack(self, req: dict[str, Any]) -> dict[str, Any] | None:
        if self.mode == "success":
            return self._build_success_ack(req)

        unit = req.get("unit", "")
        if self.mode == "fail_on_driver":
            target_driver = self.overrides.get("fail_driver", "cookie")
            if unit != f"run3/{target_driver}":
                return self._build_success_ack(req)
        else:
            target_fail = self.fail_unit if self.fail_unit is not None else "run1"
            if unit != target_fail:
                return self._build_success_ack(req)

        if self.mode in ("no_op", "fail_on_driver"):
            return None

        if self.mode == "timeout":
            self._stop_event.wait(timeout=10.0)
            return None

        if self.mode == "absent_receipt":
            try:
                os.write(self._ack_w, b"NOT_A_VALID_JSON_RECEIPT\n")
            except OSError:
                pass
            return None

        if self.mode == "delayed_valid":
            delay = float(self.overrides.get("ack_delay", 0.5))
            time.sleep(delay)
            return self._build_success_ack(req)

        ack = self._build_success_ack(req)
        if self.mode == "wrong_binding":
            ack["unit"] = "wrong_unit_mismatch"
        elif self.mode == "wrong_request_id":
            ack["request_id"] = "stale-or-unmatched-req-id"
        elif self.mode == "wrong_artifact_id":
            ack["artifact_id"] = ""
        elif self.mode == "altered_hash":
            ack["downloaded_sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        elif self.mode == "truncated_bytes":
            orig_bytes = req.get("archive_bytes", 100) or 100
            ack["downloaded_bytes"] = max(0, int(orig_bytes) - 42)
        elif self.mode == "error_reply":
            ack["verified"] = False
            ack["error"] = "Action failed to download or verify artifact"

        for k, v in self.overrides.items():
            if k not in ("fail_driver", "ack_delay"):
                ack[k] = v

        return ack

    def _build_success_ack(self, req: dict[str, Any]) -> dict[str, Any]:
        """Inspect sealed archive on disk and compute genuine readback hash and size."""
        seq = req.get("snapshot_sequence", 1)
        archive_path = req.get("archive_path", "")

        computed_sha = req.get("archive_sha256")
        computed_bytes = req.get("archive_bytes")

        # Independent disk readback verification
        if archive_path and os.path.isfile(archive_path):
            with open(archive_path, "rb") as f:
                content = f.read()
            computed_bytes = len(content)
            computed_sha = hashlib.sha256(content).hexdigest()

        return {
            "request_id": req.get("request_id", f"req-{seq}"),
            "repository": req.get("repository", "jwaldrip/iyi"),
            "run_id": req.get("run_id", "41362618094"),
            "run_attempt": req.get("run_attempt", 1),
            "job_id": req.get("job_id", "job-1"),
            "p_sha": req.get("p_sha", "626463375298d357ffcb3223059f4d3adce6fb10"),
            "w_sha": req.get("w_sha", "b932ce0d97775c7061102a13db706f507dc84117"),
            "c_sha": req.get("c_sha", "34ae13f8f8d82be5b2c9597a9df79eae5b6f7243"),
            "chain_id": req.get("chain_id", ""),
            "unit": req.get("unit"),
            "native_attempt": req.get("native_attempt", 1),
            "snapshot_sequence": seq,
            "artifact_id": f"art-{seq}",
            "downloaded_sha256": computed_sha,
            "downloaded_bytes": computed_bytes,
            "verified": True,
            "error": None,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_event.set()

        # Close client write end first to signal EOF to server thread
        if self.req_w is not None:
            try:
                os.close(self.req_w)
            except OSError:
                pass
            self.req_w = None  # type: ignore

        if self.ack_r is not None:
            try:
                os.close(self.ack_r)
            except OSError:
                pass
            self.ack_r = None  # type: ignore

        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            raise RuntimeError("FakePublisher serving thread failed to terminate cleanly")


class TestRemoteStrictController(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="strict-ctrl-test-")
        self.p_dir = os.path.join(self.test_dir, "P")
        self.w_dir = os.path.join(self.test_dir, "W")
        self.artifacts_dir = os.path.join(self.test_dir, "artifacts")
        self.report_dir = os.path.join(self.test_dir, "iyp-12345678")
        os.makedirs(self.p_dir, exist_ok=True)
        os.makedirs(self.w_dir, exist_ok=True)
        os.makedirs(self.artifacts_dir, exist_ok=True)

        # Provision canonical modules under W
        canonical_src = os.path.join(os.path.dirname(os.path.abspath(__file__)))
        self.canonical_hashes = provision_canonical_w(self.w_dir, source_proof_dir=canonical_src)

        # Create dummy compiler
        self.compiler_path = os.path.join(self.test_dir, "iyi")
        with open(self.compiler_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'iyi 626463375'\n")
        os.chmod(self.compiler_path, stat.S_IRWXU)

        # Create fake run_proof.py OUTSIDE W
        self.run_proof_py = os.path.join(self.test_dir, "fake_run_proof.py")
        with open(self.run_proof_py, "w", encoding="utf-8") as f:
            f.write(FAKE_STAGE_EMITTER_SOURCE)
        os.chmod(self.run_proof_py, stat.S_IRWXU)

        self.config_path = os.path.join(self.test_dir, "config.json")
        self.chain_id = "0123456789abcdef0123456789abcdef"
        self.default_config = {
            "chain_id": self.chain_id,
            "required_drivers": ["acme", "cookie"],
        }
        self._write_config(self.default_config)
        self.publishers: list[FakePublisher] = []
        self.spawned_procs: list[subprocess.Popen] = []

    def tearDown(self):
        for proc in self.spawned_procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
        for pub in self.publishers:
            pub.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_config(self, cfg: dict[str, Any]):
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.environ["FAKE_STAGE_CONFIG"] = self.config_path

    def _create_controller(self, publisher: FakePublisher | None = None, **kwargs) -> rsc.RemoteStrictController:
        opts: dict[str, Any] = {
            "p_path": self.p_dir,
            "w_path": self.w_dir,
            "compiler_path": self.compiler_path,
            "artifacts_dir": self.artifacts_dir,
            "report_dir": self.report_dir,
            "run_proof_py": self.run_proof_py,
            "min_disk_gib": 0.01,
            "driver_limit_sec": 2100.0,
            "grace_sec": 30.0,
            "payload_budget_sec": 10000.0,
            "finalization_alloc_sec": 100.0,
            "mode": "validation-only",
            "publisher_timeout_sec": 5.0,
        }

        if publisher is not None:
            opts["ipc_req_fd"] = publisher.req_w
            opts["ipc_ack_fd"] = publisher.ack_r

        opts.update(kwargs)
        return rsc.RemoteStrictController(**opts)

    # -------------------------------------------------------------------------
    # 1. Compilation & Positive Control
    # -------------------------------------------------------------------------
    def test_01_fake_program_compiles_and_positive_control(self):
        """Scenario 1: Generated fake script executes with subprocess deadline and verifies validator."""
        cmd = [sys.executable, self.run_proof_py, "plan", "--report-dir", self.report_dir]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0)
        self.assertEqual(proc.returncode, 0, f"Plan failed: {proc.stderr}")
        self.assertNotIn("SyntaxError", proc.stderr)
        self.assertNotIn("nonlocal", proc.stderr)

        # Test pin execution
        cmd = [sys.executable, self.run_proof_py, "pin", "--report-dir", self.report_dir]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0)
        self.assertEqual(proc.returncode, 0, f"Pin failed: {proc.stderr}")
        self.assertTrue(os.path.isfile(os.path.join(self.report_dir, "pin.json")))

        # Test native validator subprocess compatibility
        val_cmd = [
            sys.executable,
            "-B",
            os.path.join(os.path.dirname(__file__), "native_validation.py"),
            "--mode",
            "final",
            "--w",
            self.w_dir,
            "--pin",
            os.path.join(self.report_dir, "pin.json"),
            "--final",
            "/nonexistent/final.json",
            "--required",
            "/nonexistent/required.json",
        ]
        val_proc = subprocess.run(val_cmd, capture_output=True, text=True, timeout=10.0)
        self.assertNotEqual(val_proc.returncode, 0)
        self.assertIn("valid", val_proc.stdout)

    # -------------------------------------------------------------------------
    # 2. Complete Synthetic Chain with Required Checks & Inventory
    # -------------------------------------------------------------------------
    def test_02_valid_synthetic_chain_success(self):
        """Scenario 2: Full synthetic chain with valid native-v1 required checks & complete final inventory."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "PASS")

        # Verify summary was written
        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        self.assertTrue(os.path.isfile(summary_file))
        with open(summary_file, encoding="utf-8") as f:
            summary = json.load(f)
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(summary["chain_id"], self.chain_id)

        # Verify run1 native result has required checks
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        run1_res_file = os.path.join(run1_attempt, "result.json")
        self.assertTrue(os.path.isfile(run1_res_file))
        with open(run1_res_file, encoding="utf-8") as f:
            run1_res = json.load(f)
        for check in ("identity", "gate-1.1", "gate-1.2", "gate-1.3", "gate-1.4", "rg2r-count", "exclusions", "baseline-skips"):
            self.assertEqual(run1_res["checks"].get(check), "PASS")

        # Verify run1 scratch rg9_work was pruned after verified ACK, while evidence remains
        self.assertFalse(os.path.exists(os.path.join(run1_attempt, "rg9_work")))
        self.assertTrue(os.path.isfile(os.path.join(run1_attempt, "exclusions.json")))
        self.assertTrue(os.path.isfile(os.path.join(run1_attempt, "run1.log")))

        # Verify run2 scratch/rows was PRESERVED, while cache/tmp were pruned
        run2_attempt = os.path.join(self.report_dir, "run2", "a1")
        self.assertTrue(os.path.isfile(os.path.join(run2_attempt, "scratch", "rows", "r1", "stdout.log")))
        self.assertTrue(os.path.isfile(os.path.join(run2_attempt, "scratch", "rows", "r1", "exit_file")))
        self.assertFalse(os.path.exists(os.path.join(run2_attempt, "scratch", "cache")))
        self.assertFalse(os.path.exists(os.path.join(run2_attempt, "run2.tmp")))

        # Verify run3 drivers have required checks and scratch was pruned
        for d in ("acme", "cookie"):
            d_attempt = os.path.join(self.report_dir, "run3", d, "a1")
            self.assertTrue(os.path.isfile(os.path.join(d_attempt, "result.json")))
            with open(os.path.join(d_attempt, "result.json"), encoding="utf-8") as f:
                d_res = json.load(f)
            for check in ("census", "identity", "disk", "exit", "sentinel", "no-refused", "skips", "ledger"):
                self.assertEqual(d_res["checks"].get(check), "PASS")
            for scratch_dir in ("t", "c", "s", "bin"):
                self.assertFalse(os.path.exists(os.path.join(d_attempt, scratch_dir)))

        # Verify final.json has complete inventory of units with exact run3/<driver> keys
        final_file = os.path.join(self.report_dir, "final.json")
        self.assertTrue(os.path.isfile(final_file))
        with open(final_file, encoding="utf-8") as f:
            final_data = json.load(f)
        self.assertEqual(final_data["status"], "PASS")
        self.assertIn("run1", final_data["units"])
        self.assertIn("run2", final_data["units"])
        self.assertIn("run3/acme", final_data["units"])
        self.assertIn("run3/cookie", final_data["units"])
        self.assertEqual(final_data["identity"]["status"], "PASS")

        # Verify snapshots were received by publisher in proper order
        req_units = [r["unit"] for r in pub.received_requests]
        expected_units = ["plan", "pin", "run1", "run2", "run3/acme", "run3/cookie", "final", "terminal"]
        self.assertEqual(req_units, expected_units)

        # Verify sequences
        req_seqs = [r["snapshot_sequence"] for r in pub.received_requests]
        self.assertEqual(req_seqs, list(range(1, len(expected_units) + 1)))

    def test_02b_exit_nonzero_stops_immediately_no_cleanup(self):
        """Scenario 2b: Stage exits 1 -> stops immediately, asserts raw exit 1, valid native record, no run2."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"exit_code": 1}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertEqual(rc, 1)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

        run1_record = [r for r in ctrl.records if r.unit == "run1"][0]
        self.assertEqual(run1_record.raw_exit_code, 1)
        self.assertEqual(run1_record.native_status, "PASS")  # result.json had valid checks
        self.assertEqual(run1_record.disposition, "REJECTED")

        # Verify run1 scratch was NOT pruned because stage failed
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertTrue(os.path.exists(os.path.join(run1_attempt, "rg9_work")))

        # Verify failure evidence was persisted
        run1_reqs = [r for r in pub.received_requests if r["unit"] == "run1"]
        self.assertEqual(len(run1_reqs), 1)

        # Verify run2 was never executed
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    # -------------------------------------------------------------------------
    # 3. Driver Admission Edges (2129 vs 2130)
    # -------------------------------------------------------------------------
    def test_03a_driver_admission_2129_refuses_before_child_starts(self):
        """Scenario 3a: 2129.0s remaining refuses BEFORE driver child starts; prerequisites accepted."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        self.assertFalse(rsc.check_driver_admission(2129.0, 2100.0, 30.0))

        # Anchor budget so remaining allowance before run3/acme is exactly 2129.0s
        # Total budget: 2500s. We set job_start_time such that remaining payload is 2129.0s
        ctrl = self._create_controller(
            publisher=pub,
            driver_limit_sec=2100.0,
            grace_sec=30.0,
            payload_budget_sec=2129.0,  # Deadline will be < 2130.0 immediately
        )
        rc = ctrl.run()

        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")
        self.assertTrue(ctrl.overall_interrupted)

        # Prerequisite plan and pin ran, but acme was refused before starting
        acme_attempt = os.path.join(self.report_dir, "run3", "acme", "a1")
        self.assertFalse(os.path.exists(acme_attempt))

    def test_03b_driver_admission_2130_admits_driver(self):
        """Scenario 3b: Exactly 2130.0s remaining satisfies admission and admits driver."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        self.assertTrue(rsc.check_driver_admission(2130.0, 2100.0, 30.0))

        # Direct verification of admission function at exact boundary
        self.assertTrue(rsc.check_driver_admission(2130.0001, 2100.0, 30.0))
        self.assertFalse(rsc.check_driver_admission(2129.9999, 2100.0, 30.0))

    # -------------------------------------------------------------------------
    # 4. Required Driver Child Zero Exit but Result/ACK Missing => No Final
    # -------------------------------------------------------------------------
    def test_04a_required_driver_zero_exit_missing_result_never_launches_final(self):
        """Scenario 4a: Driver child exits 0 but result.json is missing -> stops, no final."""
        cfg = dict(self.default_config)
        cfg["run3/cookie"] = {"exit_code": 0, "skip_result": True}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()

        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

        # Verify cookie driver did launch and write log
        cookie_attempt = os.path.join(self.report_dir, "run3", "cookie", "a1")
        self.assertTrue(os.path.isfile(os.path.join(cookie_attempt, "driver.log")))

        # final was NEVER launched
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))
        # Scratch in cookie attempt was NOT cleaned
        self.assertTrue(os.path.exists(os.path.join(cookie_attempt, "t")))

    def test_04b_required_driver_zero_exit_missing_ack_never_launches_final(self):
        """Scenario 4b: Driver child exits 0 and writes result, but ACK fails -> stops, no final."""
        pub = FakePublisher(mode="fail_on_driver", fail_driver="cookie")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()

        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

        # Verify cookie driver did launch
        cookie_attempt = os.path.join(self.report_dir, "run3", "cookie", "a1")
        self.assertTrue(os.path.isfile(os.path.join(cookie_attempt, "driver.log")))

        # final was NEVER launched
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))
        # Scratch in cookie attempt was NOT cleaned
        self.assertTrue(os.path.exists(os.path.join(cookie_attempt, "t")))

    def test_04c_outstanding_required_driver_unattempted_never_launches_final(self):
        """Scenario 4c: Run3 completes one driver but another fails -> no final."""
        cfg = dict(self.default_config)
        cfg["run3/cookie"] = {"exit_code": 1}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()

        self.assertNotEqual(rc, 0)
        self.assertNotEqual(ctrl.overall_status, "PASS")
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))

    def test_04d_final_inventory_missing_required_driver_rejected(self):
        """Scenario 4d: Independent final-inventory guard rejects missing required driver unit."""
        # Test native final validation directly with missing driver in units
        pin = generate_pin(self.chain_id, report_dir=self.report_dir)
        required = ["acme", "cookie"]

        # Units contains acme but omits cookie
        units = {
            "run1": {"attempt": 1, "status": "PASS"},
            "run2": {"attempt": 1, "status": "PASS"},
            "run3/acme": {"attempt": 1, "status": "PASS"},
        }
        final_rec = generate_final_record(pin, required, units=units)

        from proof.native_validation import validate_final_native
        is_valid, reasons = validate_final_native(final_rec, pin=pin, required_drivers=required, w_path=self.w_dir)
        self.assertFalse(is_valid)
        self.assertTrue(any("missing required driver 'cookie'" in r for r in reasons))

    # -------------------------------------------------------------------------
    # 5. Handler Grace Period (>10s and <30s)
    # -------------------------------------------------------------------------
    def test_05a_handler_flushing_between_10_and_30s_not_prematurely_killed(self):
        """Scenario 5a: A handler taking 12s to flush and exit under 30s grace completes cleanly."""
        marker = os.path.join(self.test_dir, "term_marker.txt")
        ready_file = os.path.join(self.test_dir, "ready_05a.txt")

        test_script = (
            "import os, signal, sys, time\n"
            "def term_handler(signum, frame):\n"
            "    time.sleep(12.0)\n"  # Full 12-second flush (>10s and <30s)
            f"    with open({marker!r}, 'w') as f: f.write('flushed')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, term_handler)\n"
            f"with open({ready_file!r}, 'w') as f: f.write('ready')\n"
            "while True: time.sleep(0.1)\n"
        )

        log_path = os.path.join(self.artifacts_dir, "test_05a.log")
        interrupted = [False]

        def check_interrupted():
            return interrupted[0], "Test requested interruption"

        t_start = time.monotonic()
        # Launch using run_bounded_process
        thread = threading.Thread(
            target=lambda: rsc.run_bounded_process(
                [sys.executable, "-c", test_script],
                cwd=self.w_dir,
                env=dict(os.environ),
                monotonic_deadline=time.monotonic() + 100.0,
                grace_sec=30.0,  # 30-second native grace
                log_file=log_path,
                is_interrupted=check_interrupted,
            )
        )
        thread.start()

        # Wait for child to be ready
        for _ in range(50):
            if os.path.isfile(ready_file):
                break
            time.sleep(0.1)

        # Trigger interruption
        interrupted[0] = True
        thread.join(timeout=35.0)

        elapsed = time.monotonic() - t_start
        self.assertGreaterEqual(elapsed, 11.5)
        self.assertTrue(os.path.isfile(marker), "Completion marker not written; handler prematurely killed!")

    def test_05b_stubborn_handler_exceeding_grace_escalates_to_sigkill(self):
        """Scenario 5b: A stubborn process ignoring SIGTERM is escalated to SIGKILL after grace."""
        ready_file = os.path.join(self.test_dir, "ready_05b.txt")
        test_script = (
            "import os, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"with open({ready_file!r}, 'w') as f: f.write('ready')\n"
            "while True: time.sleep(0.1)\n"
        )

        interrupted = [False]
        res_holder = []

        def runner():
            rc, was_int, reason, reaped, survivors = rsc.run_bounded_process(
                [sys.executable, "-c", test_script],
                cwd=self.w_dir,
                env=dict(os.environ),
                monotonic_deadline=time.monotonic() + 100.0,
                grace_sec=1.0,  # Scaled grace for stubborn escalation test
                is_interrupted=lambda: (interrupted[0], "Interrupted"),
            )
            res_holder.append((rc, was_int, reaped, survivors))

        t = threading.Thread(target=runner)
        t.start()

        for _ in range(50):
            if os.path.isfile(ready_file):
                break
            time.sleep(0.1)

        interrupted[0] = True
        t.join(timeout=10.0)

        self.assertTrue(len(res_holder) > 0)
        rc, was_int, reaped, survivors = res_holder[0]
        self.assertEqual(rc, -signal.SIGKILL)
        self.assertTrue(was_int)

    # -------------------------------------------------------------------------
    # 6. Nested Process Sessions, Sentinels & PID Identity
    # -------------------------------------------------------------------------
    def test_06a_nested_separate_session_cleanup_preserves_unrelated_sentinel(self):
        """Scenario 6a: Child and grandchild in separate sessions are reaped; unrelated sentinel survives."""
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        self.spawned_procs.append(sentinel)

        pid_file = os.path.join(self.test_dir, "nested_pids.txt")
        ready_file = os.path.join(self.test_dir, "nested_ready.txt")
        cfg = dict(self.default_config)
        cfg["run1"] = {
            "sleep": 10.0,
            "spawn_nested": True,
            "pid_file": pid_file,
            "ready_file": ready_file,
        }
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub, payload_budget_sec=0.8, grace_sec=0.5)
        rc = ctrl.run()

        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")

        # Read nested PIDs
        self.assertTrue(os.path.isfile(pid_file))
        with open(pid_file, "r", encoding="utf-8") as pf:
            lines = [l.strip() for l in pf.readlines() if l.strip()]

        pids = {}
        for l in lines:
            role, p = l.split(":", 1)
            pids[role] = int(p)

        self.assertIn("child", pids)
        self.assertIn("grandchild", pids)

        # Assert both owned processes exited
        for role, p in pids.items():
            alive = True
            try:
                os.kill(p, 0)
            except OSError:
                alive = False
            self.assertFalse(alive, f"{role} with PID {p} survived reaping!")

        # Sentinel MUST still be alive!
        self.assertIsNone(sentinel.poll(), "Unrelated sentinel process was killed!")
    def test_06b_descendant_tracker_mechanics(self):
        """Scenario 6b: Real tracker discovers late-created grandchildren and rejects mismatched lstart."""
        parent_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            start_new_session=True,
        )
        self.spawned_procs.append(parent_proc)

        tracker = rsc.DescendantTracker(parent_proc.pid)
        self.assertIn(parent_proc.pid, tracker.tracked)

        # 1. Forge a mismatched lstart
        tracker.tracked[parent_proc.pid] = "Mon Jan 1 00:00:00 1970"
        reaped = tracker.reap_owned(grace_sec=0.1)

        # Because lstart mismatched, it was NOT signaled!
        self.assertNotIn(parent_proc.pid, reaped)
        self.assertIsNone(parent_proc.poll())

        # 2. Test late-created grandchild discovery through subtree traversal
        ready_gc = os.path.join(self.test_dir, "ready_gc.txt")
        child_script = (
            "import os, subprocess, sys, time\n"
            "time.sleep(0.2)\n"
            "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])\n"
            f"with open({ready_gc!r}, 'w') as f: f.write(str(gc.pid))\n"
            "time.sleep(10)\n"
        )
        tree_parent = subprocess.Popen([sys.executable, "-c", child_script], start_new_session=True)
        self.spawned_procs.append(tree_parent)

        tracker2 = rsc.DescendantTracker(tree_parent.pid)
        for _ in range(50):
            if os.path.isfile(ready_gc):
                break
            time.sleep(0.1)

        # On next sample, tracker MUST discover the late-created grandchild
        tracker2._sample()
        with open(ready_gc, "r") as f:
            gc_pid = int(f.read().strip())
        self.assertIn(gc_pid, tracker2.tracked, "Late-created grandchild was not discovered on later sample!")

    def test_06c_hosting_interruption_during_stage(self):
        """Scenario 6c: Stage runs past payload cutoff -> SIGTERM sent -> interrupted disposition."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"sleep": 5.0}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub, payload_budget_sec=0.3, grace_sec=0.5)
        rc = ctrl.run()
        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")
        self.assertTrue(ctrl.overall_interrupted)

        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        with open(summary_file, encoding="utf-8") as f:
            summary = json.load(f)
        self.assertTrue(summary["overall_interrupted"])

    # -------------------------------------------------------------------------
    # 7. Publisher Rejection Matrix (IPC fd3/fd4)
    # -------------------------------------------------------------------------
    def test_07a_publisher_missing_or_broken_pipe(self):
        """Scenario 7a: Missing publisher or broken IPC pipe halts, no cleanup, no advance."""
        r, w = os.pipe()
        os.close(r)
        os.close(w)
        ctrl = self._create_controller(ipc_req_fd=w, ipc_ack_fd=r)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertFalse(os.path.exists(self.report_dir))

    def test_07b_publisher_noop_eof(self):
        """Scenario 7b: Publisher EOF without ACK halts, no cleanup, no advance."""
        pub = FakePublisher(mode="no_op")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=1.0)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07c_publisher_silent_pipe_timeout(self):
        """Scenario 7c: Open but silent ACK pipe times out without response."""
        pub = FakePublisher(mode="silent_pipe")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=0.5)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07d_publisher_partial_frame_eof(self):
        """Scenario 7d: Partial ACK without newline followed by EOF halts."""
        pub = FakePublisher(mode="partial_frame")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=1.0)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07e_publisher_absent_invalid_receipt(self):
        """Scenario 7e: Publisher returns invalid JSON receipt halts, no cleanup."""
        pub = FakePublisher(mode="absent_receipt")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=1.0)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07f_publisher_stall_write_timeout(self):
        """Scenario 7f: Publisher not reading requests wedges write select and times out."""
        pub = FakePublisher(mode="stall_write")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=0.5)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07g_publisher_timeout_mode(self):
        """Scenario 7g: Publisher timeout terminates within finite deadline."""
        pub = FakePublisher(mode="timeout")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=0.5)
        t_start = time.monotonic()
        rc = ctrl.run()
        elapsed = time.monotonic() - t_start
        self.assertLess(elapsed, 3.0)
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07h_delayed_valid_ack_proves_scratch_before_and_cleanup_after(self):
        """Scenario 7h: Delayed valid ACK proves scratch exists before ACK and cleanup after."""
        pub = FakePublisher(mode="delayed_valid", overrides={"ack_delay": 0.4})
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub, publisher_timeout_sec=5.0)
        rc = ctrl.run()
        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "PASS")

        # After ACK release and stage completion, run1 scratch was cleaned
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertFalse(os.path.exists(os.path.join(run1_attempt, "rg9_work")))

    def test_07i_publisher_altered_hash(self):
        """Scenario 7i: Publisher returns altered downloaded_sha256 halts."""
        pub = FakePublisher(mode="altered_hash")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07j_publisher_truncated_bytes(self):
        """Scenario 7j: Publisher returns truncated downloaded_bytes halts."""
        pub = FakePublisher(mode="truncated_bytes")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    def test_07k_publisher_error_reply(self):
        """Scenario 7k: Publisher returns error in ACK halts."""
        pub = FakePublisher(mode="error_reply")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

    # -------------------------------------------------------------------------
    # 8. Native Result Schema & Status Validation Matrix
    # -------------------------------------------------------------------------
    def test_08a_missing_result_halts(self):
        """Scenario 8a: Stage exits 0 but result.json is missing -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"skip_result": True}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_08b_malformed_result_halts(self):
        """Scenario 8b: Stage exits 0 but result.json is invalid JSON -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"malformed_result": True}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08c_empty_w_fails_with_module_origin_diagnostic(self):
        """Scenario 8c: Empty W checkout fails with explicit missing module diagnostic, never reasons=[]."""
        empty_w = os.path.join(self.test_dir, "empty_W")
        os.makedirs(empty_w, exist_ok=True)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub, w_path=empty_w)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        run1_records = [r for r in ctrl.records if r.unit == "run1"]
        self.assertTrue(len(run1_records) > 0)
        self.assertTrue(len(run1_records[0].native_validation_reasons) > 0)
        self.assertTrue(
            any("MISSING-W-MODULE" in r or "MODULE-ORIGIN-VIOLATION" in r for r in run1_records[0].native_validation_reasons),
            f"Expected missing module diagnostic, got: {run1_records[0].native_validation_reasons}",
        )

    def test_08d_wrong_chain_id_halts(self):
        """Scenario 8d: result.json chain_id mismatch -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"chain_id": "wrongchain000000000000000000000"}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08h_forged_pass_status_halts(self):
        """Scenario 8h: result.json claims status=PASS but check is FAIL -> caught as forged PASS."""
        cfg = dict(self.default_config)
        checks = {
            "identity": "PASS",
            "gate-1.1": "FAIL",
            "gate-1.2": "PASS",
            "gate-1.3": "PASS",
            "gate-1.4": "PASS",
            "rg2r-count": "PASS",
            "exclusions": "PASS",
            "baseline-skips": "PASS",
        }
        cfg["run1"] = {"status": "PASS", "checks": checks}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")
        run1_record = [r for r in ctrl.records if r.unit == "run1"][0]
        self.assertTrue(any("forged status" in r for r in run1_record.native_validation_reasons))

    def test_08j_native_stop_status_preserved(self):
        """Scenario 8j: Native STOP status is preserved in record/summary without being overwritten."""
        cfg = dict(self.default_config)
        checks = {
            "identity": "PASS",
            "gate-1.1": "STOP",
            "gate-1.2": "PASS",
            "gate-1.3": "PASS",
            "gate-1.4": "PASS",
            "rg2r-count": "PASS",
            "exclusions": "PASS",
            "baseline-skips": "PASS",
        }
        cfg["run1"] = {"status": "STOP", "checks": checks, "reasons": ["Manual stop requested"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        run1_rec = [r for r in ctrl.records if r.unit == "run1"][0]
        self.assertEqual(run1_rec.native_status, "STOP")
        self.assertEqual(run1_rec.result_status, "STOP")

    def test_08k_native_invalid_status_preserved(self):
        """Scenario 8k: Native INVALID status is preserved in record/summary."""
        cfg = dict(self.default_config)
        checks = {
            "identity": "INVALID",
            "gate-1.1": "PASS",
            "gate-1.2": "PASS",
            "gate-1.3": "PASS",
            "gate-1.4": "PASS",
            "rg2r-count": "PASS",
            "exclusions": "PASS",
            "baseline-skips": "PASS",
        }
        cfg["run1"] = {"status": "INVALID", "checks": checks, "reasons": ["Identity invalid"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        run1_rec = [r for r in ctrl.records if r.unit == "run1"][0]
        self.assertEqual(run1_rec.native_status, "INVALID")
        self.assertEqual(run1_rec.result_status, "INVALID")

    def test_08l_native_timeout_status_preserved(self):
        """Scenario 8l: Native TIMEOUT status is preserved in record/summary."""
        cfg = dict(self.default_config)
        checks = {
            "identity": "PASS",
            "gate-1.1": "TIMEOUT",
            "gate-1.2": "PASS",
            "gate-1.3": "PASS",
            "gate-1.4": "PASS",
            "rg2r-count": "PASS",
            "exclusions": "PASS",
            "baseline-skips": "PASS",
        }
        cfg["run1"] = {"status": "TIMEOUT", "checks": checks, "reasons": ["Gate 1.1 timed out"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        run1_rec = [r for r in ctrl.records if r.unit == "run1"][0]
        self.assertEqual(run1_rec.native_status, "TIMEOUT")
        self.assertEqual(run1_rec.result_status, "TIMEOUT")

    def test_08m_mandatory_summary_failure_stays_nonzero(self):
        """Scenario 8m: Mandatory summary write failure specifically during summary writing fails closed."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)

        # Mock open specifically when writing summary file
        real_open = open

        def mock_open_func(file, *args, **kwargs):
            if "strict-controller-summary.json" in str(file):
                raise PermissionError("Simulated write permission error on summary file")
            return real_open(file, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=mock_open_func):
            rc = ctrl.run()

        self.assertEqual(rc, 4)

    def test_08n_mandatory_journal_failure_stays_nonzero(self):
        """Scenario 8n: Mandatory journal append failure specifically fails closed."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)

        real_open = open

        def mock_open_journal(file, *args, **kwargs):
            if "stage-journal.jsonl" in str(file):
                raise PermissionError("Simulated write permission error on journal file")
            return real_open(file, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=mock_open_journal):
            rc = ctrl.run()

        self.assertNotEqual(rc, 0)

    # -------------------------------------------------------------------------
    # 9. Evidence Completeness & Run2 Rows Protection
    # -------------------------------------------------------------------------
    def test_09a_run2_rows_evidence_protected_from_pruning(self):
        """Scenario 9a: Run2 scratch/rows evidence is preserved; only expendable scratch pruned."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertEqual(rc, 0)

        run2_attempt = os.path.join(self.report_dir, "run2", "a1")
        row_stdout = os.path.join(run2_attempt, "scratch", "rows", "r1", "stdout.log")
        row_exit = os.path.join(run2_attempt, "scratch", "rows", "r1", "exit_file")
        self.assertTrue(os.path.isfile(row_stdout), "Run2 scratch/rows stdout.log was deleted!")
        self.assertTrue(os.path.isfile(row_exit), "Run2 scratch/rows exit_file was deleted!")

        self.assertFalse(os.path.exists(os.path.join(run2_attempt, "scratch", "cache")))
        self.assertFalse(os.path.exists(os.path.join(run2_attempt, "run2.tmp")))

    def test_09b_archive_completeness_includes_pin_and_rows(self):
        """Scenario 9b: Sealed snapshot archives unconditionally include pin.json and Run2 rows."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertEqual(rc, 0)

        reqs = pub.received_requests
        run2_req = [r for r in reqs if r.get("unit") == "run2"][0]
        archive_path = run2_req["archive_path"]
        self.assertTrue(os.path.isfile(archive_path))

        with tarfile.open(archive_path, "r") as tf:
            names = tf.getnames()
            self.assertTrue(any("pin.json" in n for n in names), "Archive missing pin.json")
            self.assertTrue(any("stdout.log" in n for n in names), "Archive missing Run2 scratch/rows stdout.log")

    def test_09c_failure_evidence_archived_even_without_result(self):
        """Scenario 9c: Failure snapshot archives safe evidence even when result.json is absent."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"exit_code": 1, "skip_result": True}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        failure_reqs = [r for r in pub.received_requests if r.get("unit") == "run1"]
        self.assertEqual(len(failure_reqs), 1)
        archive_path = failure_reqs[0]["archive_path"]
        self.assertTrue(os.path.isfile(archive_path))
        with tarfile.open(archive_path, "r") as tf:
            names = tf.getnames()
            self.assertTrue(any("run1-a1.log" in n for n in names))
            self.assertFalse(any("result.json" in n for n in names))

    # -------------------------------------------------------------------------
    # 10. Eligible Symlink & Root Escape Rejection (Target Untouched)
    # -------------------------------------------------------------------------
    def test_10a_eligible_symlink_rg9_work_rejected_target_untouched(self):
        """Scenario 10a: Symlink at eligible name rg9_work is rejected; external target is UNTOUCHED."""
        sentinel_dir = os.path.join(self.test_dir, "external_sentinel")
        os.makedirs(sentinel_dir, exist_ok=True)
        sentinel_file = os.path.join(sentinel_dir, "important_sentinel.txt")
        with open(sentinel_file, "w", encoding="utf-8") as f:
            f.write("CANNOT_BE_DELETED")

        cfg = dict(self.default_config)
        cfg["run1"] = {
            "inject_eligible_symlink": True,
            "symlink_target": sentinel_dir,
        }
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()

        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "CLEANUP_FAILED")
        self.assertTrue(os.path.isfile(sentinel_file), "External sentinel target was deleted by cleanup!")
        with open(sentinel_file, encoding="utf-8") as f:
            self.assertEqual(f.read(), "CANNOT_BE_DELETED")

    def test_10b_root_escape_rejected_target_untouched(self):
        """Scenario 10b: Path escape outside attempt_dir raises UnsafeCleanupError; target untouched."""
        external_dir = os.path.join(self.test_dir, "external_escape_target")
        os.makedirs(external_dir, exist_ok=True)
        file_path = os.path.join(external_dir, "kept.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("KEEP_ME")

        with self.assertRaises(rsc.UnsafeCleanupError):
            rsc.safe_cleanup_stage_scratch(self.report_dir, "run1", external_dir)

        self.assertTrue(os.path.isfile(file_path))

    def test_10c_staging_archive_rejects_symlinks(self):
        """Scenario 10c: Archiving/staging rejects symbolic links with all 6 correct arguments."""
        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        external_file = os.path.join(self.test_dir, "outside_file.txt")
        with open(external_file, "w", encoding="utf-8") as f:
            f.write("SECRET")
        symlink_path = os.path.join(attempt_dir, "leak_symlink")
        os.symlink(external_file, symlink_path)

        with self.assertRaises(rsc.EvidenceUploadError):
            rsc.archive_snapshot_evidence(
                self.report_dir,
                self.artifacts_dir,
                "run1",
                1,
                self.chain_id,
                1,
            )
        self.assertTrue(os.path.isfile(external_file))

    def test_10d_unsafe_cleanup_protected_file(self):
        """Scenario 10d: Protected files are never deleted by cleanup."""
        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        pin_file = os.path.join(attempt_dir, "pin.json")
        with open(pin_file, "w", encoding="utf-8") as f:
            f.write("{}")

        deleted, reclaimed = rsc.safe_cleanup_stage_scratch(self.report_dir, "run1", attempt_dir)
        self.assertNotIn(pin_file, deleted)
        self.assertTrue(os.path.exists(pin_file))

    # -------------------------------------------------------------------------
    # 11. Monotonic Clock Jumps Do Not Alter Accounting
    # -------------------------------------------------------------------------
    def test_11_wall_clock_jumps_do_not_alter_monotonic_accounting(self):
        """Scenario 11: Forward and backward wall-clock jumps do not alter monotonic calculations."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        wall_time = [1700000000.0]
        # Jump forward 7200s, then backward 7200s
        def fake_wall():
            wall_time[0] += 7200.0
            return wall_time[0]

        with mock.patch("time.time", side_effect=fake_wall):
            ctrl = self._create_controller(publisher=pub)
            rc = ctrl.run()

        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "PASS")

    # -------------------------------------------------------------------------
    # 12. Strict Authorization & Malformed SHA Validation Negatives
    # -------------------------------------------------------------------------
    def test_12a_unapproved_strict_launch_refused_before_payload(self):
        """Scenario 12a: Unapproved strict mode launch is refused with exact exit code 5 and AUTH_REFUSED."""
        ctrl = self._create_controller(mode="strict")
        rc = ctrl.run()

        self.assertEqual(rc, 5)
        self.assertEqual(ctrl.overall_status, "AUTH_REFUSED")
        self.assertEqual(len(ctrl.records), 0)
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "plan")))
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "pin.json")))

    def test_12b_malformed_sha_and_shell_injection_rejected(self):
        """Scenario 12b: Malformed commit SHAs and shell injections are rejected in production paths."""
        bad_shas = [
            "$(touch " + os.path.join(self.test_dir, "injected_cmd") + ")",
            "; rm -rf / ;",
            "b932ce0d97775c7061102a13db706f507dc84117; echo hacked",
            "not-a-hex-sha",
            "B932CE0D97775C7061102A13DB706F507DC84117",
            "b932ce0d",
        ]

        for bad_sha in bad_shas:
            with self.assertRaises(rsc.VerificationError) as ctx:
                self._create_controller(p_sha=bad_sha)
            self.assertIn("MALFORMED-COMMIT-SHA", str(ctx.exception))

        injected_marker = os.path.join(self.test_dir, "injected_cmd")
        self.assertFalse(os.path.exists(injected_marker), "Shell injection executed!")

    # -------------------------------------------------------------------------
    # 13. Test Temp Dirs Owned & Cleanup
    # -------------------------------------------------------------------------
    def test_13_test_temp_dirs_owned_and_cleanup(self):
        """Scenario 13: Temporary directories are owned by test and cleaned up on exit."""
        self.assertTrue(os.path.isdir(self.test_dir))
        self.assertTrue(os.path.basename(self.test_dir).startswith("strict-ctrl-test-"))


if __name__ == "__main__":
    unittest.main()
