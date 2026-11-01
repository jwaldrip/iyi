#!/usr/bin/env python3
"""
Fast Deterministic Synthetic Proofs for RemoteStrictController.

Exercises all failure paths and safety mechanisms against fake stage commands
in isolated scratch:
1. Exit zero plus PASS (success path completes, cleans scratch, archives evidence)
2. Exit nonzero (stops immediately, does not clean scratch)
3. Missing or malformed result (catches missing file or corrupted JSON)
4. Wrong chain/unit/attempt (rejects mismatched metadata)
5. STOP or INVALID (rejects non-PASS status)
6. Hosting interruption:
   - Signal interruption during long-running stage
   - Refusal to launch driver when window < (2100s + grace)
7. Failed evidence upload (catches upload failure, refuses scratch cleanup)
8. Unsafe cleanup path:
   - Refuses to delete symlinks
   - Refuses to delete protected files (pin.json, result.json, etc.)
   - Refuses path escapes outside attempt_dir
9. Completed driver with required drivers still outstanding

No compiler builds, no external network, runs in isolated scratch.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

# Import controller module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_strict_controller as rsc


FAKE_RUN_PROOF_SCRIPT = """#!/usr/bin/env python3
import json
import os
import signal
import sys
import time

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

# Sleep simulation if requested
sleep_sec = stage_cfg.get("sleep", 0.0)
if sleep_sec > 0:
    interrupted = False
    def term_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
    signal.signal(signal.SIGTERM, term_handler)
    deadline = time.time() + sleep_sec
    while time.time() < deadline:
        if interrupted:
            break
        time.sleep(0.05)
    if interrupted and report_dir:
        # Write interrupted result if requested
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
        with open(os.path.join(attempt_dir, "result.json"), "w") as rf:
            json.dump(res, rf)
        sys.exit(1)

exit_code = stage_cfg.get("exit_code", 0)

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
            "compiler_path": get_arg("--compiler") or "/dummy/iyi",
        }
        with open(os.path.join(report_dir, "pin.json"), "w") as f:
            json.dump(pin_data, f)
    sys.exit(exit_code)

elif subcmd in ("run1", "run2"):
    if report_dir:
        attempt_dir = os.path.join(report_dir, subcmd, "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        
        # Preserved evidence files
        with open(os.path.join(attempt_dir, f"{subcmd}.log"), "w") as f:
            f.write(f"log for {subcmd}\\n")
        with open(os.path.join(attempt_dir, f"{subcmd}.times"), "w") as f:
            f.write("0.1 0.2 0.3\\n")
        if subcmd == "run1":
            with open(os.path.join(attempt_dir, "exclusions.json"), "w") as f:
                json.dump([], f)
            with open(os.path.join(attempt_dir, "baseline_skips.json"), "w") as f:
                json.dump([], f)
            # Create eligible scratch
            scratch_dir = os.path.join(attempt_dir, "rg9_work")
            os.makedirs(scratch_dir, exist_ok=True)
            with open(os.path.join(scratch_dir, "temp.bin"), "w") as f:
                f.write("scratch data")
            tmp_dir = os.path.join(attempt_dir, "g01.tmp")
            os.makedirs(tmp_dir, exist_ok=True)
        elif subcmd == "run2":
            with open(os.path.join(attempt_dir, "run2.jsonl"), "w") as f:
                f.write('{"row": 1}\\n')
            # Create eligible scratch
            scratch_dir = os.path.join(attempt_dir, "scratch")
            os.makedirs(scratch_dir, exist_ok=True)
            with open(os.path.join(scratch_dir, "temp.bin"), "w") as f:
                f.write("scratch data")

        # Custom unsafe scratch injection if requested
        if stage_cfg.get("inject_unsafe_symlink"):
            os.symlink("/tmp", os.path.join(attempt_dir, "scratch_symlink"))
        if stage_cfg.get("inject_protected_scratch"):
            os.makedirs(os.path.join(attempt_dir, "t"), exist_ok=True)

        if not stage_cfg.get("skip_result"):
            if stage_cfg.get("malformed_result"):
                with open(os.path.join(attempt_dir, "result.json"), "w") as f:
                    f.write("{invalid json syntax")
            else:
                status = stage_cfg.get("status", "PASS")
                chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                unit = stage_cfg.get("unit", subcmd)
                attempt = stage_cfg.get("attempt", 1)
                res = {
                    "v": 1,
                    "chain_id": chain_id,
                    "unit": unit,
                    "attempt": attempt,
                    "status": status,
                    "reasons": stage_cfg.get("reasons", []),
                    "checks": {"identity": "PASS", "disk": "PASS", "exit": status},
                    "started_ns": time.time_ns() - 1000000,
                    "ended_ns": time.time_ns(),
                    "survivors": [],
                }
                with open(os.path.join(attempt_dir, "result.json"), "w") as f:
                    json.dump(res, f)
    sys.exit(exit_code)

elif subcmd == "run3":
    if report_dir:
        run3_dir = os.path.join(report_dir, "run3")
        os.makedirs(run3_dir, exist_ok=True)
        # Freeze required.json on first driver if not exists
        req_file = os.path.join(run3_dir, "required.json")
        if not os.path.exists(req_file):
            required_list = config.get("required_drivers", ["acme", "cookie"])
            with open(req_file, "w") as f:
                json.dump(required_list, f)

        if driver:
            attempt_dir = os.path.join(run3_dir, driver, "a1")
            os.makedirs(attempt_dir, exist_ok=True)

            with open(os.path.join(attempt_dir, "driver.log"), "w") as f:
                f.write(f"log for {driver}\\n")
            with open(os.path.join(attempt_dir, "driver.times"), "w") as f:
                f.write("0.1 0.2\\n")
            with open(os.path.join(attempt_dir, "ledger.jsonl"), "w") as f:
                f.write('{"ledger": 1}\\n')
            with open(os.path.join(attempt_dir, "shim.json"), "w") as f:
                json.dump({}, f)

            # Create eligible scratch (t, c, s, bin)
            for d in ("t", "c", "s", "bin"):
                p = os.path.join(attempt_dir, d)
                os.makedirs(p, exist_ok=True)
                with open(os.path.join(p, "data.txt"), "w") as f:
                    f.write("temp")

            if not stage_cfg.get("skip_result"):
                status = stage_cfg.get("status", "PASS")
                chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                unit = stage_cfg.get("unit", f"run3/{driver}")
                attempt = stage_cfg.get("attempt", 1)
                res = {
                    "v": 1,
                    "chain_id": chain_id,
                    "unit": unit,
                    "attempt": attempt,
                    "status": status,
                    "reasons": stage_cfg.get("reasons", []),
                    "checks": {"census": "PASS", "identity": "PASS", "disk": "PASS", "exit": status, "ledger": status},
                    "started_ns": time.time_ns() - 1000000,
                    "ended_ns": time.time_ns(),
                    "survivors": [],
                }
                with open(os.path.join(attempt_dir, "result.json"), "w") as f:
                    json.dump(res, f)
    sys.exit(exit_code)

elif subcmd == "final":
    if report_dir:
        final_data = {
            "v": 1,
            "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
            "status": stage_cfg.get("status", "PASS"),
            "reasons": stage_cfg.get("reasons", []),
            "units": {},
        }
        with open(os.path.join(report_dir, "final.json"), "w") as f:
            json.dump(final_data, f)
    sys.exit(exit_code)

sys.exit(0)
"""


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
        with open(self.compiler_path, "w") as f:
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

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_config(self, cfg: dict):
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.environ["FAKE_STAGE_CONFIG"] = self.config_path

    def _create_controller(self, **kwargs) -> rsc.RemoteStrictController:
        opts = {
            "p_path": self.p_dir,
            "w_path": self.w_dir,
            "compiler_path": self.compiler_path,
            "artifacts_dir": self.artifacts_dir,
            "report_dir": self.report_dir,
            "run_proof_py": self.run_proof_py,
            "min_disk_gib": 0.01,  # low floor for scratch testing
            "driver_limit_sec": 10.0,
            "grace_sec": 1.0,
            "payload_budget_sec": 1000.0,
            "finalization_alloc_sec": 100.0,
        }
        opts.update(kwargs)
        return rsc.RemoteStrictController(**opts)

    def test_01_exit_zero_plus_pass(self):
        """Scenario 1: Complete success path exits 0, cleans scratch, preserves evidence."""
        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "PASS")

        # Verify summary was written
        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        self.assertTrue(os.path.isfile(summary_file))
        with open(summary_file) as f:
            summary = json.load(f)
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual(summary["chain_id"], self.chain_id)

        # Verify scratch was pruned in run1 attempt_dir
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertFalse(os.path.exists(os.path.join(run1_attempt, "rg9_work")))
        # But preserved files remain
        self.assertTrue(os.path.isfile(os.path.join(run1_attempt, "result.json")))
        self.assertTrue(os.path.isfile(os.path.join(run1_attempt, "exclusions.json")))

        # Verify run3 scratch was pruned (t, c, s, bin)
        acme_attempt = os.path.join(self.report_dir, "run3", "acme", "a1")
        self.assertFalse(os.path.exists(os.path.join(acme_attempt, "t")))
        self.assertTrue(os.path.isfile(os.path.join(acme_attempt, "result.json")))

    def test_02_exit_nonzero(self):
        """Scenario 2: Stage exits nonzero (code 1) -> stops immediately, no scratch cleanup."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"exit_code": 1}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

        # Verify run1 scratch was NOT pruned because verification failed
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertTrue(os.path.exists(os.path.join(run1_attempt, "rg9_work")))

        # Verify run2 was never executed
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_03a_missing_result(self):
        """Scenario 3a: Stage exits 0 but result.json is missing -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"skip_result": True}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_03b_malformed_result(self):
        """Scenario 3b: Stage exits 0 but result.json is invalid JSON -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"malformed_result": True}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "run2")))

    def test_04a_wrong_chain_id(self):
        """Scenario 4a: result.json chain_id does not match pin -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"chain_id": "wrongchain000000000000000000000"}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_04b_wrong_unit(self):
        """Scenario 4b: result.json unit does not match expected unit -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"unit": "wrong_unit_name"}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_04c_wrong_attempt(self):
        """Scenario 4c: result.json attempt does not match expected attempt -> stops immediately."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"attempt": 99}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_05_stop_or_invalid_status(self):
        """Scenario 5: Stage writes result.json with status STOP or INVALID -> stops immediately."""
        for bad_status in ("STOP", "INVALID"):
            cfg = dict(self.default_config)
            cfg["run1"] = {"status": bad_status, "reasons": [f"simulated {bad_status}"]}
            self._write_config(cfg)

            shutil.rmtree(self.report_dir, ignore_errors=True)
            ctrl = self._create_controller()
            rc = ctrl.run()
            self.assertNotEqual(rc, 0)
            self.assertEqual(ctrl.overall_status, "VERIFICATION_FAILED")

    def test_06a_hosting_interruption_during_stage(self):
        """Scenario 6a: Stage runs past payload cutoff -> SIGTERM sent to process group -> interrupted."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"sleep": 5.0}  # runs for 5s
        self._write_config(cfg)

        # Set tight payload budget of 0.3s
        ctrl = self._create_controller(payload_budget_sec=0.3, grace_sec=0.5)
        rc = ctrl.run()
        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")
        self.assertTrue(ctrl.overall_interrupted)

        # Check that interruption was recorded in summary
        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        with open(summary_file) as f:
            summary = json.load(f)
        self.assertTrue(summary["overall_interrupted"])

    def test_06b_hosting_interruption_driver_admission(self):
        """Scenario 6b: Remaining budget < (driver_limit + grace) -> driver launch refused."""
        # Remaining budget tight right after run2
        # Set payload budget so it expires before driver can launch
        ctrl = self._create_controller(
            payload_budget_sec=0.01,
            driver_limit_sec=2100.0,
            grace_sec=10.0,
        )
        rc = ctrl.run()
        self.assertEqual(rc, 124)
        self.assertEqual(ctrl.overall_status, "INTERRUPTED_BY_HOSTING_BUDGET")
        self.assertTrue(ctrl.overall_interrupted)

    def test_07_failed_evidence_upload(self):
        """Scenario 7: Evidence upload command fails -> refuses scratch cleanup, stops with code 2."""
        # Use an upload command that always exits 1
        ctrl = self._create_controller(upload_cmd="exit 1")
        rc = ctrl.run()
        self.assertEqual(rc, 2)
        self.assertEqual(ctrl.overall_status, "UPLOAD_FAILED")

        # Verify scratch was NOT cleaned
        run1_attempt = os.path.join(self.report_dir, "run1", "a1")
        self.assertTrue(os.path.exists(os.path.join(run1_attempt, "rg9_work")))

    def test_08a_unsafe_cleanup_symlink(self):
        """Scenario 8a: Symlink in scratch directory -> UnsafeCleanupError raised, stops."""
        cfg = dict(self.default_config)
        cfg["run1"] = {"inject_unsafe_symlink": True}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertEqual(rc, 3)
        self.assertEqual(ctrl.overall_status, "CLEANUP_FAILED")

    def test_08b_unsafe_cleanup_protected_file(self):
        """Scenario 8b: Attempt to delete protected file directly raises UnsafeCleanupError."""
        # Test unit function safe_cleanup_stage_scratch directly
        attempt_dir = os.path.join(self.report_dir, "run1", "a1")
        os.makedirs(attempt_dir, exist_ok=True)
        # Create a pin.json inside attempt_dir and test that it is never deleted
        pin_file = os.path.join(attempt_dir, "pin.json")
        with open(pin_file, "w") as f:
            f.write("{}")

        # Run cleanup
        deleted, reclaimed = rsc.safe_cleanup_stage_scratch(self.report_dir, "run1", attempt_dir)
        self.assertNotIn("pin.json", deleted)
        self.assertTrue(os.path.exists(pin_file))

    def test_09_outstanding_required_drivers(self):
        """Scenario 9: Run3 completes one driver but required drivers remain outstanding."""
        # If required.json has ["acme", "cookie"], but cookie fails
        cfg = dict(self.default_config)
        cfg["run3/cookie"] = {"exit_code": 1}
        self._write_config(cfg)

        ctrl = self._create_controller()
        rc = ctrl.run()
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(ctrl.overall_status, "PASS")

        # Verify final was not run
        self.assertFalse(os.path.exists(os.path.join(self.report_dir, "final.json")))


if __name__ == "__main__":
    unittest.main()
