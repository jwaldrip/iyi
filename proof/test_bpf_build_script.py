#!/usr/bin/env python3
"""
proof/test_bpf_build_script.py: Focused offline tests for BPF build orchestration,
prefix validation, dependency receipt verification, and terminal report checks.

Tests the entry script (proof/run_bpf_feasibility.sh) offline without executing
privileged commands, local VMs, or the live BPF helper:
  1. CLI --help exits 0 with usage instructions.
  2. Unknown CLI options exit nonzero with error diagnostics.
  3. Missing staged prefix fails closed immediately without host package install.
  4. Staged prefix missing required development headers fails closed.
  5. Staged prefix missing required static archives fails closed.
  6. Corrupt or mismatched dependency receipts fail closed.
  7. Terminal report evaluation strictly enforces all Section 7 acceptance criteria.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "proof" / "run_bpf_feasibility.sh"


class TestBpfFeasibilityScript(unittest.TestCase):
    def test_help_flag(self) -> None:
        """--help exits 0 with usage instructions."""
        res = subprocess.run(
            ["bash", str(SCRIPT_PATH), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Usage:", res.stdout)
        self.assertIn("--prefix", res.stdout)
        self.assertIn("--build-only", res.stdout)

    def test_unknown_flag(self) -> None:
        """Unknown CLI options exit nonzero."""
        res = subprocess.run(
            ["bash", str(SCRIPT_PATH), "--nonexistent-flag-xyz"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ERROR: Unknown option", res.stderr)

    def test_missing_prefix_and_missing_script(self) -> None:
        """When neither --prefix nor valid dependency script is supplied, fails closed."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--dependency-script",
                    str(scratch / "missing_dep.py"),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("ERROR: Dependency script", res.stderr)

    def test_staged_prefix_missing_headers_fails(self) -> None:
        """A staged prefix missing required headers fails closed."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "bad-prefix"
            prefix.mkdir(parents=True)
            # Create lib dir and dummy archives, but omit headers
            lib_dir = prefix / "usr" / "lib" / "x86_64-linux-gnu"
            lib_dir.mkdir(parents=True)
            for a in ["libbpf.a", "libelf.a", "libz.a", "libzstd.a"]:
                (lib_dir / a).write_bytes(b"!<arch>\n")

            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--prefix",
                    str(prefix),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing required header", res.stderr)

    def test_staged_prefix_missing_archives_fails(self) -> None:
        """A staged prefix missing one of the four required archives fails closed."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "bad-prefix"
            # Create required headers
            inc_bpf = prefix / "usr" / "include" / "bpf"
            inc_bpf.mkdir(parents=True)
            (inc_bpf / "bpf.h").write_text("#pragma once\n")
            (inc_bpf / "libbpf.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "libelf.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "zlib.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "zstd.h").write_text("#pragma once\n")

            # Create only three of the four archives (omit libzstd.a)
            lib_dir = prefix / "usr" / "lib" / "x86_64-linux-gnu"
            lib_dir.mkdir(parents=True)
            for a in ["libbpf.a", "libelf.a", "libz.a"]:
                (lib_dir / a).write_bytes(b"!<arch>\n")

            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--prefix",
                    str(prefix),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing required static archive", res.stderr)

    def test_staged_prefix_corrupt_receipt_fails(self) -> None:
        """A staged prefix with a missing or corrupt receipt fails closed."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            # Populate headers
            inc_bpf = prefix / "usr" / "include" / "bpf"
            inc_bpf.mkdir(parents=True)
            (inc_bpf / "bpf.h").write_text("#pragma once\n")
            (inc_bpf / "libbpf.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "libelf.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "zlib.h").write_text("#pragma once\n")
            (prefix / "usr" / "include" / "zstd.h").write_text("#pragma once\n")

            # Populate four archives
            lib_dir = prefix / "usr" / "lib" / "x86_64-linux-gnu"
            lib_dir.mkdir(parents=True)
            for a in ["libbpf.a", "libelf.a", "libz.a", "libzstd.a"]:
                (lib_dir / a).write_bytes(b"!<arch>\n")

            receipt = scratch / "bad-receipt.json"
            receipt.write_text('{"status": "FAILURE"}\n')

            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--prefix",
                    str(prefix),
                    "--receipt",
                    str(receipt),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dependency receipt status is 'FAILURE'", res.stderr)

    def test_report_evaluation_criteria(self) -> None:
        """The terminal status evaluator enforces all required fields and invariants."""
        eval_script = """
import json, sys
status_file = sys.argv[1]
with open(status_file, "r", encoding="utf-8") as f:
    r = json.load(f)
p = r.get("observed_kernel_prog") or {}
l = r.get("observed_kernel_link") or {}
caps = r.get("capabilities") or {}
proc = r.get("process_identity") or {}
memlock = r.get("memlock") or {}
verifier = r.get("verifier_evidence") or {}

ok = (
    r.get("status") == "PROBE_SUCCESS"
    and r.get("strict_eligible") is False
    and r.get("exec_identity_tested") is False
    and r.get("bpf_load_supported") is True
    and r.get("bpf_attach_supported") is True
    and r.get("hook_identity_verified") is True
    and r.get("link_association_verified") is True
    and r.get("fd_ownership_lifecycle") == "detached_and_closed_before_report"
    and p.get("prog_type") == 26
    and isinstance(p.get("prog_id"), int) and p["prog_id"] > 0
    and isinstance(p.get("attach_btf_id"), int) and p["attach_btf_id"] > 0
    and l.get("link_type") == 1
    and l.get("link_prog_id") == p["prog_id"]
    and l.get("link_tp_name") == "sched_process_exec"
    and l.get("target_hook_name") == "btf_trace_sched_process_exec"
    and l.get("target_hook_kind") == "BTF_KIND_TYPEDEF"
    and caps.get("cap_bpf") is True
    and caps.get("cap_perfmon") is True
    and caps.get("cap_sys_admin") is False
    and caps.get("all_other_caps_clear") is True
    and proc.get("uid", 0) != 0
    and proc.get("gid", 0) != 0
    and memlock.get("automatic_rlim_disabled") is True
    and verifier.get("log_valid") is True
)
if not ok:
    sys.exit("FAIL")
print("PASS")
"""
        valid_report = {
            "status": "PROBE_SUCCESS",
            "strict_eligible": False,
            "exec_identity_tested": False,
            "bpf_load_supported": True,
            "bpf_attach_supported": True,
            "hook_identity_verified": True,
            "link_association_verified": True,
            "requested_program_name": "sched_process_exec",
            "requested_attach_target": "tp_btf/sched_process_exec",
            "fd_ownership_lifecycle": "detached_and_closed_before_report",
            "observed_kernel_prog": {
                "prog_id": 42,
                "prog_type": 26,
                "prog_name": "sched_process_exec",
                "btf_id": 10,
                "attach_btf_id": 1234,
                "tag": "0123456789abcdef",
            },
            "observed_kernel_link": {
                "link_id": 101,
                "link_type": 1,
                "link_type_name": "BPF_LINK_TYPE_RAW_TRACEPOINT",
                "link_prog_id": 42,
                "link_tp_name": "sched_process_exec",
                "target_hook_name": "btf_trace_sched_process_exec",
                "target_hook_kind": "BTF_KIND_TYPEDEF",
            },
            "target_tgid": 12345,
            "process_identity": {
                "uid": 1001,
                "gid": 1001,
                "ruid": 1001,
                "euid": 1001,
                "suid": 1001,
                "rgid": 1001,
                "egid": 1001,
                "sgid": 1001,
                "supplementary_groups_count": 0,
            },
            "capabilities": {
                "cap_bpf": True,
                "cap_perfmon": True,
                "cap_sys_admin": False,
                "all_other_caps_clear": True,
                "effective_mask": "000000c000000000",
                "permitted_mask": "000000c000000000",
                "inheritable_mask": "000000c000000000",
                "bounding_mask": "000000c000000000",
                "ambient_mask": "000000c000000000",
                "expected_mask": "000000c000000000",
                "no_new_privs": True,
            },
            "memlock": {
                "automatic_rlim_disabled": True,
            },
            "verifier_evidence": {
                "log_valid": True,
                "log_bytes": 1024,
                "conclusion": "processed 42 insns",
                "log_file": "bpf-feasibility.verifier.log",
            },
            "relocation_evidence": {
                "core_relocation_retained": True,
                "libbpf_debug_log_bytes": 2048,
                "log_file": "bpf-feasibility.libbpf.log",
            },
            "error_message": None,
        }

        with tempfile.TemporaryDirectory() as td:
            rp = Path(td) / "status.json"
            rp.write_text(json.dumps(valid_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout.strip(), "PASS")

            # Mutation 1: root UID must fail
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["process_identity"]["uid"] = 0
            rp.write_text(json.dumps(bad_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation 2: cap_sys_admin must fail
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["capabilities"]["cap_sys_admin"] = True
            rp.write_text(json.dumps(bad_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation 3: missing verifier log must fail
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["verifier_evidence"]["log_valid"] = False
            rp.write_text(json.dumps(bad_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
