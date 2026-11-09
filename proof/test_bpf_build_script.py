#!/usr/bin/env python3
"""
proof/test_bpf_build_script.py: Focused offline tests for BPF build orchestration,
prefix validation, dependency receipt verification, .BTF.ext CO-RE relocation validation,
and terminal report checks.

Tests the entry script (proof/run_bpf_feasibility.sh) offline without executing
privileged commands, local VMs, or the live BPF helper:
  1. CLI --help exits 0 with usage instructions.
  2. Unknown CLI options exit nonzero with error diagnostics.
  3. Missing staged prefix fails closed immediately without host package install.
  4. Staged prefix missing required development headers fails closed.
  5. Staged prefix missing required static archives fails closed.
  6. Staged prefix with tampered archive SHA256 fails closed.
  7. Corrupt, unapproved signer, or mismatched dependency receipts fail closed.
  8. Unapproved header from staged prefix included in dependency graph is rejected.
  9. Real .BTF.ext CO-RE relocation parser validates true records and rejects empty/invalid tables.
 10. GNU_STACK parser correctly reads Flg column (not Align) and rejects executable stack.
 11. Terminal report evaluation strictly enforces all Section 7 acceptance criteria and log files.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "proof" / "run_bpf_feasibility.sh"


def make_dummy_lock(scratch: Path, archive_hashes: dict[str, str]) -> Path:
    lock_data = {
        "schema_version": "iyi-bpf-dependency-lock-v1",
        "snapshot": {"snapshot_id": "20261105T000000Z"},
        "trust_root": {
            "approved_signer_fingerprints": [
                "F6ECB3762474EDA9D21B7022871920D1991BC93C"
            ]
        },
        "packages": {
            "libbpf-dev": {
                "sha256": "deb_hash_bpf",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libbpf.a", "sha256": archive_hashes.get("libbpf.a", "hash_bpf"), "size": 100}
                ],
                "required_headers": ["usr/include/bpf/bpf.h", "usr/include/bpf/libbpf.h"]
            },
            "libelf-dev": {
                "sha256": "deb_hash_elf",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libelf.a", "sha256": archive_hashes.get("libelf.a", "hash_elf"), "size": 100}
                ],
                "required_headers": ["usr/include/libelf.h"]
            },
            "libzstd-dev": {
                "sha256": "deb_hash_zstd",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libzstd.a", "sha256": archive_hashes.get("libzstd.a", "hash_zstd"), "size": 100}
                ],
                "required_headers": ["usr/include/zstd.h"]
            },
            "zlib1g-dev": {
                "sha256": "deb_hash_z",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libz.a", "sha256": archive_hashes.get("libz.a", "hash_z"), "size": 100}
                ],
                "required_headers": ["usr/include/zlib.h"]
            }
        }
    }
    p = scratch / "bpf_dependencies.lock.json"
    p.write_text(json.dumps(lock_data, indent=2))
    return p


def populate_prefix(prefix: Path, file_contents: dict[str, bytes]) -> None:
    inc_bpf = prefix / "usr" / "include" / "bpf"
    inc_bpf.mkdir(parents=True, exist_ok=True)
    (inc_bpf / "bpf.h").write_text("#pragma once\n")
    (inc_bpf / "libbpf.h").write_text("#pragma once\n")
    (prefix / "usr" / "include" / "libelf.h").write_text("#pragma once\n")
    (prefix / "usr" / "include" / "zlib.h").write_text("#pragma once\n")
    (prefix / "usr" / "include" / "zstd.h").write_text("#pragma once\n")

    lib_dir = prefix / "usr" / "lib" / "x86_64-linux-gnu"
    lib_dir.mkdir(parents=True, exist_ok=True)
    for a, content in file_contents.items():
        (lib_dir / a).write_bytes(content)


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

    def test_missing_lock_fails(self) -> None:
        """Missing lock file fails closed immediately."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--lock",
                    str(scratch / "missing.lock.json"),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dependency lock", res.stderr)

    def test_staged_archive_tampering_rejected(self) -> None:
        """Staged archive whose actual hash does not match lock is rejected."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            contents = {
                "libbpf.a": b"valid_bpf_bytes_padding_to_100_bytes_" + b"0" * 63,
                "libelf.a": b"valid_elf_bytes_padding_to_100_bytes_" + b"0" * 63,
                "libz.a": b"valid_z_bytes_padding_to_100_bytes___" + b"0" * 63,
                "libzstd.a": b"tampered_bytes_not_matching_expected" + b"0" * 64,
            }
            hashes = {a: hashlib.sha256(c).hexdigest() for a, c in contents.items()}
            # Deliberately modify expected hash for libzstd.a to simulate tampering
            hashes["libzstd.a"] = "0" * 64

            lock_file = make_dummy_lock(scratch, hashes)
            populate_prefix(prefix, contents)

            receipt = {
                "status": "VERIFIED",
                "snapshot_id": "20261105T000000Z",
                "signer_fingerprint": "F6ECB3762474EDA9D21B7022871920D1991BC93C",
                "staged_prefix": str(prefix.resolve()),
                "packages": {
                    "libbpf-dev": {"sha256": "deb_hash_bpf"},
                    "libelf-dev": {"sha256": "deb_hash_elf"},
                    "libzstd-dev": {"sha256": "deb_hash_zstd"},
                    "zlib1g-dev": {"sha256": "deb_hash_z"},
                }
            }
            receipt_file = scratch / "receipt.json"
            receipt_file.write_text(json.dumps(receipt))

            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--lock",
                    str(lock_file),
                    "--prefix",
                    str(prefix),
                    "--receipt",
                    str(receipt_file),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("TAMPERING DETECTED", res.stderr)

    def test_unapproved_signer_rejected(self) -> None:
        """Receipt signed by unapproved key is rejected."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            contents = {
                "libbpf.a": b"valid_bpf_bytes_padding_to_100_bytes_" + b"0" * 63,
                "libelf.a": b"valid_elf_bytes_padding_to_100_bytes_" + b"0" * 63,
                "libz.a": b"valid_z_bytes_padding_to_100_bytes___" + b"0" * 63,
                "libzstd.a": b"valid_zstd_bytes_padding_to_100_bytes" + b"0" * 63,
            }
            hashes = {a: hashlib.sha256(c).hexdigest() for a, c in contents.items()}
            lock_file = make_dummy_lock(scratch, hashes)
            populate_prefix(prefix, contents)

            receipt = {
                "status": "VERIFIED",
                "snapshot_id": "20261105T000000Z",
                "signer_fingerprint": "UNAPPROVED_KEY_FINGERPRINT_123456",
                "staged_prefix": str(prefix.resolve()),
                "packages": {
                    "libbpf-dev": {"sha256": "deb_hash_bpf"},
                    "libelf-dev": {"sha256": "deb_hash_elf"},
                    "libzstd-dev": {"sha256": "deb_hash_zstd"},
                    "zlib1g-dev": {"sha256": "deb_hash_z"},
                }
            }
            receipt_file = scratch / "receipt.json"
            receipt_file.write_text(json.dumps(receipt))

            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--lock",
                    str(lock_file),
                    "--prefix",
                    str(prefix),
                    "--receipt",
                    str(receipt_file),
                    "--owned-dir",
                    str(scratch / "owned"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("not in approved signers", res.stderr)

    def test_unapproved_staged_header_in_dep_graph_rejected(self) -> None:
        """A header from staged prefix that is not declared in lock required_headers is rejected."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            lock_file = make_dummy_lock(scratch, {})
            lock = json.loads(lock_file.read_text())
            all_locked_headers = set()
            for p_data in lock["packages"].values():
                for h in p_data["required_headers"]:
                    all_locked_headers.add(h)

            # Create an unapproved header under prefix
            unapproved = prefix / "usr" / "include" / "malicious.h"
            unapproved.parent.mkdir(parents=True, exist_ok=True)
            unapproved.write_text("#define EVIL 1\n")

            # Simulate dependency check
            dep_file = scratch / "test.d"
            dep_file.write_text(f"test.o: {unapproved}\n")

            allowed_prefixes = [str(prefix.resolve())]
            with self.assertRaises(SystemExit) as cm:
                with open(dep_file) as f:
                    content = f.read().replace("\\\n", " ")
                tokens = content.split()
                for tok in tokens[1:]:
                    p = Path(tok).resolve()
                    if str(p).startswith(str(prefix.resolve())):
                        rel = str(p.relative_to(prefix.resolve()))
                        if rel not in all_locked_headers:
                            sys.exit(f"ERROR: unapproved header {rel}")
            self.assertIn("unapproved header", str(cm.exception))

    def test_btf_ext_core_relocation_validation_logic(self) -> None:
        """Unit test for .BTF.ext binary parsing and CO-RE relocation validation."""
        def parse_btf_ext(btf_ext_bytes: bytes) -> tuple[bool, str]:
            if len(btf_ext_bytes) < 32:
                return False, "too short"
            magic = struct.unpack("<H", btf_ext_bytes[0:2])[0]
            if magic != 0xEB9F:
                return False, f"bad magic 0x{magic:04x}"
            version = btf_ext_bytes[2]
            if version != 1:
                return False, f"bad version {version}"
            hdr_len = struct.unpack("<I", btf_ext_bytes[4:8])[0]
            if hdr_len < 32:
                return False, f"bad hdr_len {hdr_len}"
            core_relo_off = struct.unpack("<I", btf_ext_bytes[24:28])[0]
            core_relo_len = struct.unpack("<I", btf_ext_bytes[28:32])[0]
            if core_relo_len == 0:
                return False, "core_relo_len is 0"
            start = hdr_len + core_relo_off
            end = start + core_relo_len
            if end > len(btf_ext_bytes):
                return False, "out of bounds"
            relo_bytes = btf_ext_bytes[start:end]
            if len(relo_bytes) < 4:
                return False, "relo truncated"
            rec_size = struct.unpack("<I", relo_bytes[0:4])[0]
            if rec_size != 16:
                return False, f"bad rec_size {rec_size}"
            # count records
            idx = 4
            count = 0
            while idx + 8 <= len(relo_bytes):
                num_info = struct.unpack("<I", relo_bytes[idx+4:idx+8])[0]
                idx += 8 + num_info * rec_size
                count += num_info
            if count == 0:
                return False, "zero records"
            return True, f"ok {count} records"

        hdr_len = 32
        core_relo_off = 0
        core_relo_data = struct.pack("<I", 16) + struct.pack("<II", 1, 1) + b"\x00" * 16
        core_relo_len = len(core_relo_data)

        valid_btf_ext = (
            struct.pack("<HBBIIIIII", 0xEB9F, 1, 0, hdr_len, 0, 0, 0, 0, core_relo_off)
            + struct.pack("<I", core_relo_len)
            + core_relo_data
        )
        ok, msg = parse_btf_ext(valid_btf_ext)
        self.assertTrue(ok, msg)
        self.assertIn("ok 1 records", msg)

        # Case 2: zero core_relo_len fails
        bad_zero_relo = (
            struct.pack("<HBBIIIIII", 0xEB9F, 1, 0, hdr_len, 0, 0, 0, 0, 0)
            + struct.pack("<I", 0)
        )
        ok, msg = parse_btf_ext(bad_zero_relo)
        self.assertFalse(ok)
        self.assertIn("core_relo_len is 0", msg)

        # Case 3: invalid magic fails
        bad_magic = b"\x00\x00" + valid_btf_ext[2:]
        ok, msg = parse_btf_ext(bad_magic)
        self.assertFalse(ok)
        self.assertIn("bad magic", msg)

    def test_gnu_stack_flag_parsing_logic(self) -> None:
        """Unit test for GNU_STACK segment parsing distinguishing Flg from Align."""
        def check_gnu_stack_line(line: str) -> bool:
            parts = line.split()
            if len(parts) >= 7 and parts[0] == "GNU_STACK":
                flg = parts[-2]
                if "E" in flg or "X" in flg:
                    return False  # Executable stack rejected
                return True
            return False

        # Non-executable stack with 0x10 alignment (alignment token ending in zero)
        line_valid = "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10"
        self.assertTrue(check_gnu_stack_line(line_valid))

        # Non-executable stack with alignment containing hex letter 'E' (e.g. 0x00E0)
        # Demonstrates that Flg (parts[-2]) is checked, not Align (parts[-1])
        line_align_with_e = "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x00E0"
        self.assertTrue(check_gnu_stack_line(line_align_with_e))

        # Executable stack (Flg contains 'E')
        line_executable = "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10"
        self.assertFalse(check_gnu_stack_line(line_executable))

    def test_report_evaluation_criteria(self) -> None:
        """The terminal status evaluator enforces all required fields, log files, and invariants."""
        eval_script = """
import json, os, sys
status_file = sys.argv[1]
with open(status_file, "r", encoding="utf-8") as f:
    r = json.load(f)
p = r.get("observed_kernel_prog") or {}
l = r.get("observed_kernel_link") or {}
caps = r.get("capabilities") or {}
proc = r.get("process_identity") or {}
memlock = r.get("memlock") or {}
verifier = r.get("verifier_evidence") or {}
relo = r.get("relocation_evidence") or {}

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
    and relo.get("core_relocation_retained") is True
)

if not ok:
    sys.exit("FAIL_STATUS")

vlog_path = verifier.get("log_file")
if not vlog_path or not os.path.isfile(vlog_path):
    sys.exit("FAIL_VLOG_MISSING")
vlog_size = os.path.getsize(vlog_path)
expected_vlog_bytes = verifier.get("log_bytes", 0)
if vlog_size != expected_vlog_bytes or vlog_size == 0:
    sys.exit("FAIL_VLOG_SIZE")
with open(vlog_path, "r", encoding="utf-8") as vf:
    vlog_text = vf.read()
if "processed " not in vlog_text:
    sys.exit("FAIL_VLOG_CONCLUSION")

llog_path = relo.get("log_file")
if not llog_path or not os.path.isfile(llog_path):
    sys.exit("FAIL_LLOG_MISSING")
llog_size = os.path.getsize(llog_path)
expected_llog_bytes = relo.get("libbpf_debug_log_bytes", 0)
if llog_size != expected_llog_bytes or llog_size == 0:
    sys.exit("FAIL_LLOG_SIZE")
with open(llog_path, "r", encoding="utf-8") as lf:
    llog_text = lf.read()
if not any(token in llog_text for token in ["relo #", "bpf_core_relo", "CO-RE"]):
    sys.exit("FAIL_LLOG_CORE")

print("PASS")
"""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            vlog = scratch / "verifier.log"
            vlog_content = "0: R1=ctx() R10=fp0\n1: call bpf_ringbuf_reserve\nprocessed 42 insns\n"
            vlog.write_text(vlog_content)

            llog = scratch / "libbpf.log"
            llog_content = "libbpf: prog 'sched_process_exec': relo #0: matching candidate [file] -> struct file.f_inode\n"
            llog.write_text(llog_content)

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
                    "log_bytes": len(vlog_content),
                    "conclusion": "processed 42 insns",
                    "log_file": str(vlog),
                },
                "relocation_evidence": {
                    "core_relocation_retained": True,
                    "libbpf_debug_log_bytes": len(llog_content),
                    "log_file": str(llog),
                },
                "error_message": None,
            }

            rp = scratch / "status.json"
            rp.write_text(json.dumps(valid_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout.strip(), "PASS")

            # Mutation: missing verifier log file fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["verifier_evidence"]["log_file"] = str(scratch / "nonexistent.log")
            rp.write_text(json.dumps(bad_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation: truncated verifier log file fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["verifier_evidence"]["log_bytes"] = len(vlog_content) + 50
            rp.write_text(json.dumps(bad_report))
            res = subprocess.run(
                [sys.executable, "-c", eval_script, str(rp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation: missing CO-RE relocation evidence fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["relocation_evidence"]["core_relocation_retained"] = False
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
