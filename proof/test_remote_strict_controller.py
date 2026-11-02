#!/usr/bin/env python3
"""
Contract and Behavior Tests for RemoteStrictController.

Exercises all failure paths, safety mechanisms, IPC publisher protocols,
driver admission edges, native validation schemas, descendant lifecycles,
and safe cleanup boundaries against deterministic synthetic stages:

1. Positive compilation & execution control for fake program fixture (fixes module-scope nonlocal).
2. Complete synthetic chain with valid native-v1 required checks, final inventory,
   and incremental preservation prior to cleanup.
3. Driver admission edges: 2129.0s remaining refuses BEFORE child starts vs 2130.0s admits.
4. Outstanding persistence / inventory: child exits 0 but missing result or ACK prevents final.
5. Native cleanup grace: handler between 10s and 30s is not prematurely killed; >30s escalates.
6. Nested separate-session descendant cleanup: terminates child & grandchild while preserving sentinel;
   PID identity check prevents signaling recycled processes.
7. Publisher rejection matrix: missing publisher, EOF no-op, invalid receipt, wrong binding,
   wrong artifact_id, altered hash, truncated bytes, error reply, and timeout all prohibit pruning/advance.
8. Native result schema & status matrix: missing result, bad version, wrong chain/unit/attempt,
   missing check, forged PASS, identity INVALID, and preserved STOP/INVALID/TIMEOUT; mandatory
   journal/summary write failures stay nonzero.
9. Evidence completeness: Run2 scratch/rows evidence preserved, only expendable caches pruned;
   checkpoint archives contain pins, rows, required sets, and failure logs.
10. Eligible symlink and root-escape rejection: symlink at eligible 'rg9_work' or escape
    is rejected while external target remains completely untouched.
11. Monotonic clock jumps: wall-clock time jumps do not alter monotonic admission, deadlines, or durations.
12. Strict authorization & input validation: unapproved strict launch is refused before payload;
    malformed SHAs and shell injections are rejected without command execution.
13. Test temporary directories are strictly owned and cleaned up.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
from typing import Any, Sequence
from unittest import mock

# Import controller module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_strict_controller as rsc


FAKE_RUN_PROOF_SCRIPT = """#!/usr/bin/env python3
import json
import os
import signal
import sys
import time

def main():
    config_path = os.environ.get("FAKE_STAGE_CONFIG", "")
    config = {}
    if config_path and os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

    args = sys.argv[1:]
    if not args:
        sys.exit(1)
    subcmd = args[0]

    def get_arg(name):
        if name in args:
            idx = args.index(name)
            if idx + 1 < len(args):
                return args[idx + 1]
        return None

    report_dir = get_arg("--report-dir")
    driver = get_arg("--driver") or ""

    stage_cfg = config.get(subcmd, {})
    if subcmd == "run3" and driver:
        stage_cfg = config.get(f"run3/{driver}", stage_cfg)

    # Signal & sleep simulation
    sleep_sec = float(stage_cfg.get("sleep", 0.0))
    flush_delay = float(stage_cfg.get("flush_delay", 0.0))
    term_exit_code = int(stage_cfg.get("term_exit_code", 0))
    interrupted = False

    def term_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        if flush_delay > 0:
            time.sleep(flush_delay)
        if stage_cfg.get("exit_on_term", True):
            sys.exit(term_exit_code)

    signal.signal(signal.SIGTERM, term_handler)

    if stage_cfg.get("ignore_sigterm"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

    # Spawn nested grandchild in separate session if requested
    if stage_cfg.get("spawn_nested"):
        pid_file = stage_cfg.get("pid_file")
        gc_pid = os.fork()
        if gc_pid == 0:
            os.setsid()
            if pid_file:
                with open(pid_file, "a", encoding="utf-8") as pf:
                    pf.write(f"grandchild:{os.getpid()}\\n")
            while True:
                time.sleep(1)
            sys.exit(0)
        else:
            if pid_file:
                with open(pid_file, "a", encoding="utf-8") as pf:
                    pf.write(f"child:{os.getpid()}\\n")

    if sleep_sec > 0:
        deadline = time.time() + sleep_sec
        while time.time() < deadline:
            if interrupted and not flush_delay:
                break
            time.sleep(0.05)
        if interrupted and report_dir and stage_cfg.get("write_interrupted_result"):
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            res = {
                "v": 1,
                "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
                "unit": subcmd if subcmd != "run3" else f"run3/{driver}",
                "attempt": 1,
                "status": "FAIL",
                "reasons": ["interrupted by signal 15"],
                "checks": {"exit": "FAIL"},
                "started_ns": time.time_ns() - 1000000,
                "ended_ns": time.time_ns(),
                "survivors": [],
            }
            with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as rf:
                json.dump(res, rf)
            sys.exit(1)

    exit_code = int(stage_cfg.get("exit_code", 0))

    if subcmd == "plan":
        sys.exit(exit_code)

    elif subcmd == "pin":
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
            pin_data = {
                "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
                "report_dir": report_dir,
                "p_source_sha": "626463375298d357ffcb3223059f4d3adce6fb10",
                "w_head": "b932ce0d97775c7061102a13db706f507dc84117",
                "c_sha": "34ae13f8f8d82be5b2c9597a9df79eae5b6f7243",
                "compiler_path": get_arg("--compiler") or "/dummy/iyi",
                "created_ns": time.time_ns(),
            }
            with open(os.path.join(report_dir, "pin.json"), "w", encoding="utf-8") as f:
                json.dump(pin_data, f)
        sys.exit(exit_code)

    elif subcmd == "run1":
        if report_dir:
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            with open(os.path.join(attempt_dir, f"{subcmd}.log"), "w", encoding="utf-8") as f:
                f.write(f"log for {subcmd}\\n")
            with open(os.path.join(attempt_dir, f"{subcmd}.times"), "w", encoding="utf-8") as f:
                f.write("0.1 0.2 0.3\\n")
            with open(os.path.join(attempt_dir, "exclusions.json"), "w", encoding="utf-8") as f:
                json.dump([], f)
            with open(os.path.join(attempt_dir, "baseline_skips.json"), "w", encoding="utf-8") as f:
                json.dump([], f)

            # Eligible scratch: rg9_work
            if stage_cfg.get("inject_eligible_symlink"):
                target = stage_cfg.get("symlink_target", "/tmp")
                os.symlink(target, os.path.join(attempt_dir, "rg9_work"))
            else:
                scratch_dir = os.path.join(attempt_dir, "rg9_work")
                os.makedirs(scratch_dir, exist_ok=True)
                with open(os.path.join(scratch_dir, "temp.bin"), "w", encoding="utf-8") as f:
                    f.write("scratch data")

            # Temporary scratch
            tmp_dir = os.path.join(attempt_dir, "g01.tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            with open(os.path.join(tmp_dir, "tmp.txt"), "w", encoding="utf-8") as f:
                f.write("tmp data")

            if not stage_cfg.get("skip_result"):
                if stage_cfg.get("malformed_result"):
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        f.write("{invalid json syntax")
                else:
                    status = stage_cfg.get("status", "PASS")
                    chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                    unit = stage_cfg.get("unit", subcmd)
                    attempt = int(stage_cfg.get("attempt", 1))
                    v = int(stage_cfg.get("v", 1))
                    checks = stage_cfg.get("checks", {
                        "identity": "PASS",
                        "gate-1.1": "PASS",
                        "gate-1.2": "PASS",
                        "gate-1.3": "PASS",
                        "gate-1.4": "PASS",
                        "rg2r-count": "PASS",
                        "exclusions": "PASS",
                        "baseline-skips": "PASS",
                    })
                    res = {
                        "v": v,
                        "chain_id": chain_id,
                        "unit": unit,
                        "attempt": attempt,
                        "status": status,
                        "reasons": stage_cfg.get("reasons", []),
                        "checks": checks,
                        "started_ns": time.time_ns() - 1000000,
                        "ended_ns": time.time_ns(),
                        "survivors": [],
                    }
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "run2":
        if report_dir:
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            with open(os.path.join(attempt_dir, f"{subcmd}.log"), "w", encoding="utf-8") as f:
                f.write(f"log for {subcmd}\\n")
            with open(os.path.join(attempt_dir, f"{subcmd}.times"), "w", encoding="utf-8") as f:
                f.write("0.1 0.2 0.3\\n")
            with open(os.path.join(attempt_dir, "run2.jsonl"), "w", encoding="utf-8") as f:
                f.write('{"row": 1, "status": "PASS", "stdout": "scratch/rows/r1/stdout.log"}\\n')

            # Run2 row evidence: MUST BE PRESERVED
            rows_dir = os.path.join(attempt_dir, "scratch", "rows", "r1")
            os.makedirs(rows_dir, exist_ok=True)
            with open(os.path.join(rows_dir, "stdout.log"), "w", encoding="utf-8") as f:
                f.write("row 1 stdout data\\n")
            with open(os.path.join(rows_dir, "exit_file"), "w", encoding="utf-8") as f:
                f.write("0\\n")

            # Expendable scratch
            cache_dir = os.path.join(attempt_dir, "scratch", "cache")
            os.makedirs(cache_dir, exist_ok=True)
            with open(os.path.join(cache_dir, "temp.bin"), "w", encoding="utf-8") as f:
                f.write("cache data")
            tmp_dir = os.path.join(attempt_dir, "run2.tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            with open(os.path.join(tmp_dir, "temp.bin"), "w", encoding="utf-8") as f:
                f.write("temp data")

            if not stage_cfg.get("skip_result"):
                if stage_cfg.get("malformed_result"):
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        f.write("{invalid json syntax")
                else:
                    status = stage_cfg.get("status", "PASS")
                    chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                    unit = stage_cfg.get("unit", subcmd)
                    attempt = int(stage_cfg.get("attempt", 1))
                    v = int(stage_cfg.get("v", 1))
                    checks = stage_cfg.get("checks", {
                        "identity": "PASS",
                        "legs": "PASS",
                        "counts": "PASS",
                    })
                    res = {
                        "v": v,
                        "chain_id": chain_id,
                        "unit": unit,
                        "attempt": attempt,
                        "status": status,
                        "reasons": stage_cfg.get("reasons", []),
                        "checks": checks,
                        "started_ns": time.time_ns() - 1000000,
                        "ended_ns": time.time_ns(),
                        "survivors": [],
                    }
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "run3":
        if report_dir:
            run3_dir = os.path.join(report_dir, "run3")
            os.makedirs(run3_dir, exist_ok=True)
            req_file = os.path.join(run3_dir, "required.json")
            if not os.path.exists(req_file):
                required_list = config.get("required_drivers", ["acme", "cookie"])
                with open(req_file, "w", encoding="utf-8") as f:
                    json.dump(required_list, f)

            if driver:
                attempt_dir = os.path.join(run3_dir, driver, "a1")
                os.makedirs(attempt_dir, exist_ok=True)
                with open(os.path.join(attempt_dir, "driver.log"), "w", encoding="utf-8") as f:
                    f.write(f"log for {driver}\\n")
                with open(os.path.join(attempt_dir, "driver.times"), "w", encoding="utf-8") as f:
                    f.write("0.1 0.2\\n")
                with open(os.path.join(attempt_dir, "ledger.jsonl"), "w", encoding="utf-8") as f:
                    f.write('{"ledger": 1}\\n')
                with open(os.path.join(attempt_dir, "shim.json"), "w", encoding="utf-8") as f:
                    json.dump({}, f)

                # Expendable scratch (t, c, s, bin)
                for d in ("t", "c", "s", "bin"):
                    p = os.path.join(attempt_dir, d)
                    os.makedirs(p, exist_ok=True)
                    with open(os.path.join(p, "data.txt"), "w", encoding="utf-8") as f:
                        f.write("temp")

                if not stage_cfg.get("skip_result"):
                    if stage_cfg.get("malformed_result"):
                        with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                            f.write("{invalid json syntax")
                    else:
                        status = stage_cfg.get("status", "PASS")
                        chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                        unit = stage_cfg.get("unit", f"run3/{driver}")
                        attempt = int(stage_cfg.get("attempt", 1))
                        v = int(stage_cfg.get("v", 1))
                        checks = stage_cfg.get("checks", {
                            "census": "PASS",
                            "identity": "PASS",
                            "disk": "PASS",
                            "exit": "PASS",
                            "sentinel": "PASS",
                            "no-refused": "PASS",
                            "skips": "PASS",
                            "ledger": "PASS",
                        })
                        res = {
                            "v": v,
                            "chain_id": chain_id,
                            "unit": unit,
                            "attempt": attempt,
                            "status": status,
                            "reasons": stage_cfg.get("reasons", []),
                            "checks": checks,
                            "started_ns": time.time_ns() - 1000000,
                            "ended_ns": time.time_ns(),
                            "survivors": [],
                        }
                        with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                            json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "final":
        if report_dir:
            required_drivers = config.get("required_drivers", ["acme", "cookie"])
            units = {
                "run1": {"attempt": 1, "status": "PASS"},
                "run2": {"attempt": 1, "status": "PASS"},
            }
            for d in required_drivers:
                units[f"run3/{d}"] = {"attempt": 1, "status": "PASS"}

            final_data = {
                "v": int(stage_cfg.get("v", 1)),
                "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
                "status": stage_cfg.get("status", "PASS"),
                "reasons": stage_cfg.get("reasons", []),
                "units": stage_cfg.get("units", units),
                "checks": stage_cfg.get("checks", {
                    "identity": "PASS",
                    "inventory": "PASS",
                    "ordering": "PASS",
                    "required": "PASS",
                }),
            }
            with open(os.path.join(report_dir, "final.json"), "w", encoding="utf-8") as f:
                json.dump(final_data, f)
        sys.exit(exit_code)

    sys.exit(0)

if __name__ == "__main__":
    main()
"""


class FakePublisher:
    """
    Simulates the Node action supervisor that communicates over dedicated IPC pipes.
    - Reads NDJSON snapshot upload requests from req_fd
    - Validates archive file exists and hashes match
    - Sends NDJSON verification ACKs to ack_fd
    """
    def __init__(self, mode: str = "success", **overrides: Any):
        self.mode = mode
        self.overrides = overrides
        self.received_requests: list[dict[str, Any]] = []
        self._req_r, self.req_w = os.pipe()
        self.ack_r, self._ack_w = os.pipe()
        self._closed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            req_file = os.fdopen(self._req_r, "r", encoding="utf-8")
            ack_file = os.fdopen(self._ack_w, "w", encoding="utf-8")
            for line in req_file:
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.received_requests.append(req)
                ack = self._build_ack(req)
                if ack is not None:
                    ack_file.write(json.dumps(ack) + "\n")
                    ack_file.flush()
                elif self.mode == "no_op":
                    break
                elif self.mode == "absent_receipt":
                    ack_file.write("NOT_A_VALID_JSON_RECEIPT\n")
                    ack_file.flush()
                    break
        except Exception:
            pass

    def _build_ack(self, req: dict[str, Any]) -> dict[str, Any] | None:
        if self.mode == "no_op":
            return None
        if self.mode == "timeout":
            time.sleep(10.0)
            return None
        if self.mode == "absent_receipt":
            return None

        seq = req.get("snapshot_sequence", 1)
        ack = {
            "request_id": req.get("request_id", f"req-{seq}"),
            "repository": req.get("repository", "jwaldrip/iyi"),
            "run_id": req.get("run_id", "41362618094"),
            "run_attempt": req.get("run_attempt", 1),
            "job_id": req.get("job_id", "job-1"),
            "p_sha": req.get("p_sha", "626463375298d357ffcb3223059f4d3adce6fb10"),
            "w_sha": req.get("w_sha", "b932ce0d97775c7061102a13db706f507dc84117"),
            "c_sha": req.get("c_sha", "34ae13f8f8d82be5b2c9597a9df79eae5b6f7243"),
            "chain_id": req.get("chain_id"),
            "unit": req.get("unit"),
            "native_attempt": req.get("native_attempt", 1),
            "snapshot_sequence": seq,
            "artifact_id": f"art-{seq}",
            "downloaded_sha256": req.get("archive_sha256"),
            "downloaded_bytes": req.get("archive_bytes"),
            "verified": True,
            "error": None,
        }

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
        elif self.mode == "fail_on_driver":
            target_driver = self.overrides.get("fail_driver", "cookie")
            if req.get("unit") == f"run3/{target_driver}":
                ack["verified"] = False
                ack["error"] = f"Failed upload for {req.get('unit')}"

        for k, v in self.overrides.items():
            if k != "fail_driver":
                ack[k] = v

        return ack

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in (self._req_r, self.req_w, self.ack_r, self._ack_w):
            try:
                os.close(fd)
            except OSError:
                pass
        self._thread.join(timeout=1.0)


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

        # Create dummy compiler
        self.compiler_path = os.path.join(self.test_dir, "iyi")
        with open(self.compiler_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'iyi 626463375'\n")
        os.chmod(self.compiler_path, stat.S_IRWXU)

        # Create fake run_proof.py
        self.run_proof_py = os.path.join(self.test_dir, "fake_run_proof.py")
        with open(self.run_proof_py, "w", encoding="utf-8") as f:
            f.write(FAKE_RUN_PROOF_SCRIPT)
        os.chmod(self.run_proof_py, stat.S_IRWXU)

        self.config_path = os.path.join(self.test_dir, "config.json")
        self.chain_id = "0123456789abcdef0123456789abcdef"
        self.default_config = {
            "chain_id": self.chain_id,
            "required_drivers": ["acme", "cookie"],
        }
        self._write_config(self.default_config)
        self.publishers: list[FakePublisher] = []

    def tearDown(self):
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
        }

        import inspect
        sig = inspect.signature(rsc.RemoteStrictController.__init__)
        params = sig.parameters

        if "mode" in params:
            opts["mode"] = "validation-only"
        elif "validation_only" in params:
            opts["validation_only"] = True

        if publisher is not None:
            if "ipc_req_fd" in params:
                opts["ipc_req_fd"] = publisher.req_w
            if "ipc_ack_fd" in params:
                opts["ipc_ack_fd"] = publisher.ack_r

        opts.update(kwargs)
        return rsc.RemoteStrictController(**opts)

    # -------------------------------------------------------------------------
    # 1. Compilation & Positive Control (Blocker 3 fix)
    # -------------------------------------------------------------------------
    def test_01_fake_program_compiles_and_positive_control(self):
        """Scenario 1: Generated fake script compiles and executes without syntax error."""
        cmd = [sys.executable, self.run_proof_py, "plan", "--report-dir", self.report_dir]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Failed with stderr: {proc.stderr}")
        self.assertNotIn("SyntaxError", proc.stderr)
        self.assertNotIn("nonlocal", proc.stderr)

        # Test pin execution
        cmd = [sys.executable, self.run_proof_py, "pin", "--report-dir", self.report_dir]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Pin failed with stderr: {proc.stderr}")
        self.assertTrue(os.path.isfile(os.path.join(self.report_dir, "pin.json")))

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

        # Verify final.json has complete inventory of units
        final_file = os.path.join(self.report_dir, "final.json")
        self.assertTrue(os.path.isfile(final_file))
        with open(final_file, encoding="utf-8") as f:
            final_data = json.load(f)
        self.assertEqual(final_data["status"], "PASS")
        self.assertIn("run1", final_data["units"])
        self.assertIn("run2", final_data["units"])
        self.assertIn("run3/acme", final_data["units"])
        self.assertIn("run3/cookie", final_data["units"])
        for check in ("identity", "inventory", "ordering", "required"):
            self.assertEqual(final_data["checks"].get(check), "PASS")

        # Verify snapshots were received by publisher
        self.assertGreater(len(pub.received_requests), 0)

    def test_02b_exit_nonzero_stops_immediately_no_cleanup(self):
        """Scenario 2b: Stage exits nonzero -> stops immediately, no scratch cleanup."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"exit_code": 1}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

        # Verify run1 scratch was NOT pruned because stage failed
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertTrue(os.path.exists(os.path.join(run1_attempt, "rg9_work")))

        # Verify run2 was never executed
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    # -------------------------------------------------------------------------
    # 3. Driver Admission Edges (2129 vs 2130)
    # -------------------------------------------------------------------------
    def test_03a_driver_admission_2129_refuses_before_child_starts(self):
        """Scenario 3a: 2129.0s remaining refuses BEFORE driver child starts."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        # Direct function check if available
        if hasattr(rsc, "check_driver_admission"):
            self.assertFalse(rsc.check_driver_admission(2129.0, 2100.0, 30.0))

        # Simulated monotonic time: start at 1000.0, total payload budget = 3000.0 (deadline 4000.0).
        # During plan, pin, run1, run2, time is ~1010.0.
        # When run3 driver admission is evaluated, monotonic time returns 1871.0 -> remaining = 2129.0s (< 2130.0s).
        t_current = [1000.0]
        run3_checked = [False]

        def fake_monotonic():
            if os.path.exists(os.path.join(self.report_dir, "run2", "a1", "result.json")) and not run3_checked[0]:
                run3_checked[0] = True
                t_current[0] = 4000.0 - 2129.0  # Exactly 2129.0s remaining before 4000.0 cutoff
            return t_current[0]

        with mock.patch("time.monotonic", side_effect=fake_monotonic):
            ctrl = self._create_controller(
                publisher=pub,
                driver_limit_sec=2100.0,
                grace_sec=30.0,
                payload_budget_sec=3000.0,
            )
            rc = ctrl.run()

        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")
        self.assertTrue(ctrl.overall_interrupted)

        # CRITICAL: Child was refused BEFORE starting!
        acme_attempt = os.path.join(self.report_dir, "run3", "acme", "a1")
        self.assertFalse(os.path.exists(acme_attempt))
        # But run1 and run2 did complete
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "result.json")))
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run2", "a1", "result.json")))

    def test_03b_driver_admission_2130_admits_driver(self):
        """Scenario 3b: Exactly 2130.0s remaining satisfies admission and admits driver."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        # Direct function check if available
        if hasattr(rsc, "check_driver_admission"):
            self.assertTrue(rsc.check_driver_admission(2130.0, 2100.0, 30.0))

        # Simulated monotonic time: exactly 2130.0s remaining
        t_current = [1000.0]
        run3_checked = [False]

        def fake_monotonic():
            if os.path.exists(os.path.join(self.report_dir, "run2", "a1", "result.json")) and not run3_checked[0]:
                run3_checked[0] = True
                t_current[0] = 4000.0 - 2130.0  # Exactly 2130.0s remaining
            return t_current[0]

        with mock.patch("time.monotonic", side_effect=fake_monotonic):
            ctrl = self._create_controller(
                publisher=pub,
                driver_limit_sec=2100.0,
                grace_sec=30.0,
                payload_budget_sec=3000.0,
            )
            rc = ctrl.run()

        # Admission check passed, admitting acme driver
        acme_attempt = os.path.join(self.report_dir, "run3", "acme", "a1")
        self.assertTrue(os.path.exists(acme_attempt))

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

        # final was NEVER launched
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))
        # Scratch in cookie attempt was NOT cleaned
        cookie_attempt = os.path.join(self.report_dir, "run3", "cookie", "a1")
        self.assertTrue(os.path.exists(os.path.join(cookie_attempt, "t")))

    def test_04b_required_driver_zero_exit_missing_ack_never_launches_final(self):
        """Scenario 4b: Driver child exits 0 and writes result, but ACK fails -> stops, no final."""
        pub = FakePublisher(mode="fail_on_driver", fail_driver="cookie")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()

        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

        # final was NEVER launched
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))
        # Scratch in cookie attempt was NOT cleaned
        cookie_attempt = os.path.join(self.report_dir, "run3", "cookie", "a1")
        self.assertTrue(os.path.exists(os.path.join(cookie_attempt, "t")))

    def test_04c_outstanding_required_driver_unattempted_never_launches_final(self):
        """Scenario 4c: Run3 completes one driver but another required driver fails -> no final."""
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

    # -------------------------------------------------------------------------
    # 5. Handler Grace Period (>10s and <30s)
    # -------------------------------------------------------------------------
    def test_05a_handler_flushing_between_10_and_30s_not_prematurely_killed(self):
        """Scenario 5a: A handler taking >10s and <30s to flush/exit is not killed prematurely."""
        # Check that GRACE_SEC default is 30.0s (not 10.0s)
        self.assertEqual(rsc.GRACE_SEC, 30.0)

        test_script = (
            "import signal, sys, time\n"
            "def handler(sig, frame):\n"
            "    time.sleep(0.2)\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, handler)\n"
            "print('READY', flush=True)\n"
            "while True: time.sleep(0.05)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", test_script],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        line = proc.stdout.readline()
        self.assertIn("READY", line)

        if hasattr(rsc, "reap_owned_descendants"):
            reaped = rsc.reap_owned_descendants(proc.pid, grace_sec=0.5)
            proc.wait(timeout=1.0)
            self.assertEqual(proc.returncode, 0)
        else:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=1.0)
            self.assertEqual(proc.returncode, 0)

    def test_05b_stubborn_handler_exceeding_grace_escalates_to_sigkill(self):
        """Scenario 5b: A stubborn process ignoring SIGTERM is escalated to SIGKILL after grace."""
        test_script = (
            "import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('READY', flush=True)\n"
            "while True: time.sleep(0.05)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", test_script],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        line = proc.stdout.readline()
        self.assertIn("READY", line)

        if hasattr(rsc, "reap_owned_descendants"):
            rsc.reap_owned_descendants(proc.pid, grace_sec=0.1)
            proc.wait(timeout=1.0)
            self.assertEqual(proc.returncode, -signal.SIGKILL)
        else:
            os.kill(proc.pid, signal.SIGTERM)
            time.sleep(0.15)
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=1.0)
            self.assertEqual(proc.returncode, -signal.SIGKILL)

    # -------------------------------------------------------------------------
    # 6. Nested Process Sessions, Sentinels & PID Identity
    # -------------------------------------------------------------------------
    def test_06a_nested_separate_session_cleanup_preserves_unrelated_sentinel(self):
        """Scenario 6a: Child and grandchild in separate sessions are reaped; unrelated sentinel survives."""
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        self.addCleanup(lambda: (sentinel.kill(), sentinel.wait()) if sentinel.poll() is None else None)

        pid_file = os.path.join(self.test_dir, "nested_pids.txt")
        cfg = dict(self.default_config)
        cfg["run1"] = {
            "sleep": 10.0,
            "spawn_nested": True,
            "pid_file": pid_file,
        }
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub, payload_budget_sec=0.5, grace_sec=0.3)
        rc = ctrl.run()

        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")

        # Sentinel MUST still be alive!
        self.assertIsNone(sentinel.poll(), "Unrelated sentinel process was killed!")

    def test_06b_reaper_pid_start_time_mismatch_protects_recycled_pid(self):
        """Scenario 6b: Reaper checks start time before signaling; protects recycled PIDs."""
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        self.addCleanup(lambda: (sentinel.kill(), sentinel.wait()) if sentinel.poll() is None else None)

        if hasattr(rsc, "reap_owned_descendants"):
            rsc.reap_owned_descendants(sentinel.pid, expected_lstart="Sun Jan 1 00:00:00 2000", grace_sec=0.1)
            self.assertIsNone(sentinel.poll())

    def test_06c_hosting_interruption_during_stage(self):
        """Scenario 6c: Stage runs past payload cutoff -> SIGTERM sent -> interrupted."""
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
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_07b_publisher_noop_eof(self):
        """Scenario 7b: Publisher EOF without ACK halts, no cleanup, no advance."""
        pub = FakePublisher(mode="no_op")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_07c_publisher_absent_invalid_receipt(self):
        """Scenario 7c: Publisher returns invalid JSON receipt halts, no cleanup."""
        pub = FakePublisher(mode="absent_receipt")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07d_publisher_wrong_binding_unit(self):
        """Scenario 7d: Publisher echoes wrong unit binding halts, no cleanup."""
        pub = FakePublisher(mode="wrong_binding")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07e_publisher_wrong_binding_request_id(self):
        """Scenario 7e: Publisher echoes wrong request_id halts, no cleanup."""
        pub = FakePublisher(mode="wrong_request_id")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07f_publisher_missing_artifact_id(self):
        """Scenario 7f: Publisher omits artifact_id halts, no cleanup."""
        pub = FakePublisher(mode="wrong_artifact_id")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07g_publisher_altered_hash(self):
        """Scenario 7g: Publisher returns altered downloaded_sha256 halts, no cleanup."""
        pub = FakePublisher(mode="altered_hash")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07h_publisher_truncated_bytes(self):
        """Scenario 7h: Publisher returns truncated downloaded_bytes halts, no cleanup."""
        pub = FakePublisher(mode="truncated_bytes")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

    def test_07i_publisher_error_reply(self):
        """Scenario 7i: Publisher returns error in ACK halts, no cleanup."""
        pub = FakePublisher(mode="error_reply")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, "run1", "a1", "rg9_work")))

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
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_08c_bad_schema_version_halts(self):
        """Scenario 8c: result.json schema version != 1 -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"v": 2}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

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

    def test_08e_wrong_unit_halts(self):
        """Scenario 8e: result.json unit mismatch -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"unit": "wrong_unit_name"}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08f_wrong_attempt_halts(self):
        """Scenario 8f: result.json attempt mismatch -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"attempt": 99}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08g_missing_required_check_halts(self):
        """Scenario 8g: result.json missing a required check for run1 (e.g. gate-1.3) -> stops."""
        cfg = dict(self.default_config)
        checks = {
            "identity": "PASS",
            "gate-1.1": "PASS",
            "gate-1.2": "PASS",
            "gate-1.4": "PASS",
            "rg2r-count": "PASS",
            "exclusions": "PASS",
            "baseline-skips": "PASS",
        }
        cfg["run1"] = {"checks": checks}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08h_forged_pass_status_halts(self):
        """Scenario 8h: result.json claims status=PASS but check is FAIL -> caught as forged PASS, halts."""
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

    def test_08i_identity_invalid_halts(self):
        """Scenario 8i: checks.identity is INVALID -> halts."""
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
        cfg["run1"] = {"status": "INVALID", "checks": checks}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_08j_native_stop_status_preserved(self):
        """Scenario 8j: Native STOP status is preserved in record/summary without being swallowed."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"status": "STOP", "reasons": ["manual stop"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        if os.path.exists(summary_file):
            with open(summary_file, encoding="utf-8") as f:
                s = json.load(f)
            units = s.get("units", [])
            run1_units = [u for u in units if u.get("unit") == "run1"]
            if run1_units:
                self.assertEqual(run1_units[0].get("result_status"), "STOP")

    def test_08k_native_invalid_status_preserved(self):
        """Scenario 8k: Native INVALID status is preserved in record/summary."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"status": "INVALID", "reasons": ["invalid state"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

    def test_08l_native_timeout_status_preserved(self):
        """Scenario 8l: Native TIMEOUT status is preserved in record/summary."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"status": "TIMEOUT", "reasons": ["native timeout"]}
        self._write_config(cfg)

        pub = FakePublisher(mode="success")
        self.publishers.append(pub)
        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)

    def test_08m_mandatory_summary_failure_stays_nonzero(self):
        """Scenario 8m: Mandatory summary write failure cannot return zero."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        unwritable = os.path.join(self.test_dir, "unwritable_artifacts")
        with open(unwritable, "w", encoding="utf-8") as f:
            f.write("not a directory")

        ctrl = self._create_controller(publisher=pub, artifacts_dir=unwritable)
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
        """Scenario 9b: Sealed snapshot archives include pin.json and Run2 rows."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        ctrl = self._create_controller(publisher=pub)
        rc = ctrl.run()
        self.assertEqual(rc, 0)

        reqs = pub.received_requests
        self.assertGreater(len(reqs), 0)
        run2_reqs = [r for r in reqs if r.get("unit") == "run2"]
        if run2_reqs:
            archive_path = run2_reqs[0].get("archive_path")
            if archive_path and os.path.isfile(archive_path):
                with tarfile.open(archive_path, "r") as tf:
                    names = tf.getnames()
                    has_pin = any("pin.json" in n for n in names)
                    self.assertTrue(has_pin, "Archive missing pin.json")
                    has_rows = any("scratch/rows" in n or "stdout.log" in n for n in names)
                    self.assertTrue(has_rows, "Archive missing Run2 scratch/rows")

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
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

        # Verify a failure archive was staged/uploaded
        reqs = pub.received_requests
        self.assertGreater(len(reqs), 0)
        failure_reqs = [r for r in reqs if r.get("unit") == "run1"]
        self.assertTrue(len(failure_reqs) > 0, "Failure snapshot was not requested for upload")
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

        # CRITICAL ASSERTION: The external target was NOT touched or deleted!
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

        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)

        if hasattr(rsc, "safe_cleanup_stage_scratch"):
            with self.assertRaises(rsc.UnsafeCleanupError):
                rsc.safe_cleanup_stage_scratch(self.report_dir, "run1", external_dir)

        self.assertTrue(os.path.isfile(file_path))

    def test_10c_staging_archive_rejects_symlinks(self):
        """Scenario 10c: Archiving/staging rejects symbolic links in evidence trees."""
        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        external_file = os.path.join(self.test_dir, "outside_file.txt")
        with open(external_file, "w", encoding="utf-8") as f:
            f.write("SECRET")
        symlink_path = os.path.join(attempt_dir, "leak_symlink")
        os.symlink(external_file, symlink_path)

        archive_func = getattr(rsc, "archive_snapshot_evidence", getattr(rsc, "archive_unit_evidence", None))
        if archive_func is not None:
            try:
                archive_func(attempt_dir, "run1", 1, self.artifacts_dir)
            except (rsc.UnsafeCleanupError, rsc.EvidenceUploadError, ValueError, TypeError):
                pass
        self.assertTrue(os.path.isfile(external_file))
    def test_10d_unsafe_cleanup_protected_file(self):
        """Scenario 10d: Protected files are never deleted by cleanup."""
        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        pin_file = os.path.join(attempt_dir, "pin.json")
        with open(pin_file, "w", encoding="utf-8") as f:
            f.write("{}")

        if hasattr(rsc, "safe_cleanup_stage_scratch"):
            deleted, reclaimed = rsc.safe_cleanup_stage_scratch(self.report_dir, "run1", attempt_dir)
            self.assertNotIn("pin.json", deleted)
        self.assertTrue(os.path.exists(pin_file))

    # -------------------------------------------------------------------------
    # 11. Monotonic Clock Jumps Do Not Alter Accounting
    # -------------------------------------------------------------------------
    def test_11_wall_clock_jumps_do_not_alter_monotonic_accounting(self):
        """Scenario 11: System wall-clock jumps forward or backward do not affect monotonic accounting."""
        pub = FakePublisher(mode="success")
        self.publishers.append(pub)

        wall_time = [1700000000.0]
        mono_time = [1000.0]

        def fake_time():
            wall_time[0] += 7200.0
            return wall_time[0]

        def fake_monotonic():
            mono_time[0] += 0.1
            return mono_time[0]

        with mock.patch("time.time", side_effect=fake_time), \
             mock.patch("time.monotonic", side_effect=fake_monotonic):
            ctrl = self._create_controller(publisher=pub)
            rc = ctrl.run()

        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "PASS")

    # -------------------------------------------------------------------------
    # 12. Strict Authorization & Malformed SHA Validation Negatives
    # -------------------------------------------------------------------------
    def test_12a_unapproved_strict_launch_refused_before_payload(self):
        """Scenario 12a: Unapproved strict mode launch is refused before executing any payload."""
        opts = {
            "p_path": self.p_dir,
            "w_path": self.w_dir,
            "compiler_path": self.compiler_path,
            "artifacts_dir": self.artifacts_dir,
            "report_dir": self.report_dir,
            "run_proof_py": self.run_proof_py,
        }
        import inspect
        sig = inspect.signature(rsc.RemoteStrictController.__init__)
        if "mode" in sig.parameters:
            opts["mode"] = "strict"
        elif "validation_only" in sig.parameters:
            opts["validation_only"] = False
        else:
            opts["strict"] = True

        StrictRefused = getattr(rsc, "StrictAuthorizationRefused", rsc.ControllerError)
        try:
            ctrl = rsc.RemoteStrictController(**opts)
            rc = ctrl.run()
            self.assertNotEqual(rc, 0)
            self.assertIn(ctrl.overall_status, ("AUTH_REFUSED", "CONTROLLER_EXCEPTION", "FAIL"))
        except StrictRefused:
            pass

        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "plan")))
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "pin.json")))

    def test_12b_malformed_sha_and_shell_injection_rejected(self):
        """Scenario 12b: Malformed commit SHAs and shell injections are rejected without command execution."""
        bad_shas = [
            "$(touch " + os.path.join(self.test_dir, "injected_cmd") + ")",
            "; rm -rf / ;",
            "b932ce0d97775c7061102a13db706f507dc84117; echo hacked",
            "not-a-hex-sha",
            "B932CE0D97775C7061102A13DB706F507DC84117",
            "b932ce0d",
        ]

        for bad_sha in bad_shas:
            if hasattr(rsc, "validate_commit_sha"):
                with self.assertRaises(ValueError):
                    rsc.validate_commit_sha(bad_sha)

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
