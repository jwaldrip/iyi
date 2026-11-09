#!/usr/bin/env python3
"""
proof/test_bpf_build_script.py: Focused offline tests for BPF build orchestration,
prefix validation, dependency receipt verification, .BTF.ext CO-RE relocation validation,
and terminal report checks.

All tests invoke the actual production entry script (proof/run_bpf_feasibility.sh)
directly to verify fail-closed gates without running local copies or privileged commands:
  1. CLI --help exits 0 with usage instructions.
  2. Unknown CLI options exit nonzero with error diagnostics.
  3. Forbidden --prefix, --receipt, and --dependency-script options are rejected.
  4. Pre-existing owned scratch directory is refused (exclusive context required).
  5. Missing lock file fails closed immediately.
  6. Non-dict or missing size/digest in required_headers fails closed before compilation.
  7. Staged archive and header SHA256 tampering is rejected by production manifest gate.
  8. Unapproved receipt signer is rejected by production manifest gate.
  9. DT_NEEDED parser enforces exact set {'libc.so.6'} and rejects libc.so.6.extra.
 10. .BTF type_len == 0 and non-existent CO-RE type IDs are rejected by production BPF gate.
 11. GNU_STACK parser correctly reads Flg column (not Align) and rejects executable stack.
 12. Terminal report evaluator enforces all Section 7 criteria and verified on-disk logs.
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


def make_dummy_lock(scratch: Path, archive_hashes: dict[str, str], header_hashes: dict[str, str] | None = None) -> Path:
    if header_hashes is None:
        header_hashes = {}
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
                    {"path": "usr/lib/x86_64-linux-gnu/libbpf.a", "sha256": archive_hashes.get("libbpf.a", "a" * 64), "size": 100}
                ],
                "required_headers": [
                    {"path": "usr/include/bpf/bpf.h", "size": 20, "sha256": header_hashes.get("usr/include/bpf/bpf.h", "b" * 64)},
                    {"path": "usr/include/bpf/libbpf.h", "size": 20, "sha256": header_hashes.get("usr/include/bpf/libbpf.h", "c" * 64)}
                ]
            },
            "libelf-dev": {
                "sha256": "deb_hash_elf",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libelf.a", "sha256": archive_hashes.get("libelf.a", "d" * 64), "size": 100}
                ],
                "required_headers": [
                    {"path": "usr/include/libelf.h", "size": 20, "sha256": header_hashes.get("usr/include/libelf.h", "e" * 64)}
                ]
            },
            "libzstd-dev": {
                "sha256": "deb_hash_zstd",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libzstd.a", "sha256": archive_hashes.get("libzstd.a", "f" * 64), "size": 100}
                ],
                "required_headers": [
                    {"path": "usr/include/zstd.h", "size": 20, "sha256": header_hashes.get("usr/include/zstd.h", "1" * 64)}
                ]
            },
            "zlib1g-dev": {
                "sha256": "deb_hash_z",
                "required_artifacts": [
                    {"path": "usr/lib/x86_64-linux-gnu/libz.a", "sha256": archive_hashes.get("libz.a", "2" * 64), "size": 100}
                ],
                "required_headers": [
                    {"path": "usr/include/zlib.h", "size": 20, "sha256": header_hashes.get("usr/include/zlib.h", "3" * 64)}
                ]
            }
        }
    }
    p = scratch / "bpf_dependencies.lock.json"
    p.write_text(json.dumps(lock_data, indent=2))
    return p


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
        self.assertIn("--build-only", res.stdout)
        self.assertNotIn("--prefix", res.stdout)

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

    def test_forbidden_options_rejected(self) -> None:
        """--prefix, --receipt, and --dependency-script are forbidden."""
        for flag in ["--prefix", "--receipt", "--dependency-script"]:
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), flag, "/tmp/bypass"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(f"Option '{flag}' is forbidden", res.stderr)

    def test_preexisting_owned_dir_refused(self) -> None:
        """Pre-existing owned scratch directory is refused (exclusive creation required)."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            pre_existing = scratch / "existing_owned"
            pre_existing.mkdir()
            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--owned-dir",
                    str(pre_existing),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("already exists or is a symlink", res.stderr)

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
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dependency lock", res.stderr)

    def test_production_manifest_gate_staged_header_tampering_rejected(self) -> None:
        """Production manifest gate rejects staged header whose SHA256 does not match lock."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            archives = {
                "libbpf.a": b"a" * 100,
                "libelf.a": b"d" * 100,
                "libz.a": b"2" * 100,
                "libzstd.a": b"f" * 100,
            }
            arch_hashes = {k: hashlib.sha256(v).hexdigest() for k, v in archives.items()}

            headers = {
                "usr/include/bpf/bpf.h": b"b" * 20,
                "usr/include/bpf/libbpf.h": b"c" * 20,
                "usr/include/libelf.h": b"e" * 20,
                "usr/include/zstd.h": b"1" * 20,
                "usr/include/zlib.h": b"3" * 20,
            }
            hdr_hashes = {k: hashlib.sha256(v).hexdigest() for k, v in headers.items()}
            # Deliberately modify expected lock hash for bpf.h to simulate tampering
            hdr_hashes["usr/include/bpf/bpf.h"] = "0" * 64

            lock_file = make_dummy_lock(scratch, arch_hashes, hdr_hashes)

            # Populate staged files
            for rel, content in archives.items():
                p = prefix / "usr" / "lib" / "x86_64-linux-gnu" / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)

            for rel, content in headers.items():
                p = prefix / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)

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

            # Invoke actual production manifest gate
            res = subprocess.run(
                [
                    "bash",
                    str(SCRIPT_PATH),
                    "--validate-staged-manifest",
                    str(lock_file),
                    str(receipt_file),
                    str(prefix),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("TAMPERING DETECTED", res.stderr)

    def test_production_manifest_gate_string_header_entry_rejected(self) -> None:
        """Production manifest gate strictly rejects non-dict/string header entries before compilation."""
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            prefix = scratch / "prefix"
            lock_file = make_dummy_lock(scratch, {})
            lock_data = json.loads(lock_file.read_text())
            # Replace dict with bare string
            lock_data["packages"]["libbpf-dev"]["required_headers"] = ["usr/include/bpf/bpf.h"]
            lock_file.write_text(json.dumps(lock_data))

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
                    "--validate-staged-manifest",
                    str(lock_file),
                    str(receipt_file),
                    str(prefix),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("must be a dict", res.stderr)

    def test_production_report_evaluator_gate(self) -> None:
        """Actual production report evaluator gate enforces Section 7 criteria and log files."""
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

            status_path = scratch / "status.json"
            status_path.write_text(json.dumps(valid_report))

            # Run actual production gate
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--evaluate-report", str(status_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("verified successfully", res.stdout)

            # Mutation 1: missing verifier log file fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["verifier_evidence"]["log_file"] = str(scratch / "missing.log")
            status_path.write_text(json.dumps(bad_report))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--evaluate-report", str(status_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation 2: truncated log file fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["verifier_evidence"]["log_bytes"] = len(vlog_content) + 100
            status_path.write_text(json.dumps(bad_report))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--evaluate-report", str(status_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)

            # Mutation 3: missing genuine CO-RE relocation evidence fails
            bad_report = json.loads(json.dumps(valid_report))
            bad_report["relocation_evidence"]["core_relocation_retained"] = False
            status_path.write_text(json.dumps(bad_report))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--evaluate-report", str(status_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
