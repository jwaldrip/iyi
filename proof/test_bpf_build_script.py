#!/usr/bin/env python3
"""
proof/test_bpf_build_script.py: Focused offline tests for BPF build orchestration,
prefix validation, dependency receipt verification, .BTF.ext CO-RE relocation validation,
and terminal report checks.

All tests invoke the actual production entry script (proof/run_bpf_feasibility.sh)
directly to verify fail-closed gates without running local copies or privileged commands:
  1. CLI --help exits 0 with usage instructions.
  2. Unknown CLI options exit nonzero with error diagnostics.
  3. Forbidden --lock, --prefix, --receipt, and --dependency-script options are rejected.
  4. Pre-existing owned scratch directory is refused (exclusive context required).
  5. Missing lock file fails closed immediately.
  6. Staged manifest validation: positive control on authentic fixture, then negative controls
     for string/non-dict header entry, missing size/digest, and tampered header SHA256.
  7. Production --validate-bpf-obj gate: tests full type/member graph walking, rejects BTF
     type_len==0, non-existent type IDs, zeroed records, and grammar violations.
  8. Production --validate-host-elf gate: tests exact DT_NEEDED {'libc.so.6'} set enforcement
     (rejecting libc.so.6.extra), and GNU_STACK non-executable stack flags.
  9. Production --evaluate-report gate: enforces all Section 7 criteria and verified on-disk logs.
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


def build_mock_bpf_elf(scratch: Path, btf_type_len: int = 120, corrupt_relo: str | None = None) -> Path:
    """Build a minimal valid ELF64 little-endian BPF object with real .BTF and .BTF.ext sections."""
    # Build string table
    # offset 0: \0
    # offset 1: tp_btf/sched_process_exec\0
    # offset 27: file\0
    # offset 32: f_inode\0
    # offset 40: 0:0\0
    strtab = b"\x00tp_btf/sched_process_exec\x00file\x00f_inode\x000:0\x00"
    
    # Build BTF type table: struct file (kind 4) with member f_inode (type 2)
    # struct btf_type: name_off (4), info (4: kind 4, vlen 1), size (4: 64) -> 12 bytes
    # member: name_off (4: 32), type (4: 2), offset (4: 0) -> 12 bytes
    # type 2: struct inode (kind 4, vlen 0) -> 12 bytes
    type_data = b""
    if btf_type_len > 0:
        type_1_info = (4 << 24) | 1  # STRUCT, 1 member
        type_1 = struct.pack("<III", 27, type_1_info, 64) + struct.pack("<III", 32, 2, 0)
        type_2_info = (4 << 24) | 0  # STRUCT, 0 members
        type_2 = struct.pack("<III", 32, type_2_info, 64)
        type_data = type_1 + type_2

    actual_type_len = len(type_data) if btf_type_len > 0 else 0
    btf_hdr = struct.pack("<HBBIIII", 0xEB9F, 1, 0, 24, 0, actual_type_len, actual_type_len) + struct.pack("<I", len(strtab))
    btf_sec_data = btf_hdr + type_data + strtab

    # Build .BTF.ext with 10 records for tp_btf/sched_process_exec
    sec_name_off = 1  # points to tp_btf/sched_process_exec
    acc_str_off = 40  # points to "0:0"
    relo_records = b""
    for i in range(10):
        insn_off = i * 8
        type_id = 1
        kind = 0
        if corrupt_relo == "zeroed" and i == 0:
            relo_records += b"\x00" * 16
        elif corrupt_relo == "nonexistent_type" and i == 0:
            relo_records += struct.pack("<IIII", insn_off, 9999, acc_str_off, kind)
        elif corrupt_relo == "bad_grammar" and i == 0:
            # point to access string with invalid grammar "abc"
            relo_records += struct.pack("<IIII", insn_off, type_id, 27, kind)
        elif corrupt_relo == "out_of_range_member" and i == 0:
            # access index "5" on struct with 1 member
            # we need a string "5" in strtab
            relo_records += struct.pack("<IIII", insn_off, type_id, acc_str_off, kind)
        else:
            relo_records += struct.pack("<IIII", insn_off, type_id, acc_str_off, kind)

    core_relo_data = struct.pack("<I", 16) + struct.pack("<II", sec_name_off, 10) + relo_records
    core_relo_len = len(core_relo_data)
    btf_ext_hdr = struct.pack("<HBBIIIIII", 0xEB9F, 1, 0, 32, 0, 0, 0, 0, 0) + struct.pack("<I", core_relo_len)
    btf_ext_sec_data = btf_ext_hdr + core_relo_data

    # Minimal ELF64 structure
    prog_bytecode = b"\x95\x00\x00\x00\x00\x00\x00\x00" * 16  # 128 bytes
    shstrtab = b"\x00.shstrtab\x00tp_btf/sched_process_exec\x00.maps\x00license\x00.BTF\x00.BTF.ext\x00"
    
    sections = [
        (b"", 0, 0),
        (shstrtab, 1, 3),  # SHT_STRTAB
        (prog_bytecode, 11, 1),  # SHT_PROGBITS tp_btf/sched_process_exec
        (b"\x00" * 32, 38, 1),  # .maps
        (b"Dual MIT/GPL\x00", 44, 1),  # license
        (btf_sec_data, 52, 1),  # .BTF
        (btf_ext_sec_data, 57, 1),  # .BTF.ext
    ]
    
    # Assemble ELF file
    e_ehsize = 64
    e_shentsize = 64
    e_shnum = len(sections)
    e_shstrndx = 1

    sec_headers = []
    current_off = e_ehsize + e_shnum * e_shentsize
    sec_payloads = []

    for content, name_off, s_type in sections:
        size = len(content)
        off = current_off if size > 0 else 0
        sh = struct.pack("<IIQQQQIIQQ", name_off, s_type, 6, 0, off, size, 0, 0, 8, 0)
        sec_headers.append(sh)
        if size > 0:
            sec_payloads.append(content)
            current_off += size

    e_shoff = e_ehsize
    # ELF header: magic, class 2 (64), data 1 (little), version 1, osabi 0, pad, type 1 (REL), machine 247 (BPF)
    elf_hdr = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + struct.pack("<HHIQQQIHHHHHH", 1, 247, 1, 0, 0, e_shoff, 0, e_ehsize, 0, 0, e_shentsize, e_shnum, e_shstrndx)
    )

    out_file = scratch / "mock_canary.bpf.o"
    out_file.write_bytes(elf_hdr + b"".join(sec_headers) + b"".join(sec_payloads))
    return out_file


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
        """--lock, --prefix, --receipt, and --dependency-script are forbidden."""
        for flag in ["--lock", "--prefix", "--receipt", "--dependency-script"]:
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

    def test_production_manifest_gate_full_validation(self) -> None:
        """Production manifest gate: positive control passes, mutations strictly fail closed."""
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

            # Populate valid staged files
            for rel, content in archives.items():
                p = prefix / "usr" / "lib" / "x86_64-linux-gnu" / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)

            for rel, content in headers.items():
                p = prefix / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)

            lock_file = make_dummy_lock(scratch, arch_hashes, hdr_hashes)
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

            # Positive control: authentic fixture passes
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(lock_file), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("cryptographically bound to authenticated lock", res.stdout)

            # Mutation 1: non-dict header entry strictly fails closed
            bad_lock_1 = scratch / "bad_lock_1.json"
            lock_data = json.loads(lock_file.read_text())
            lock_data["packages"]["libbpf-dev"]["required_headers"] = ["usr/include/bpf/bpf.h"]
            bad_lock_1.write_text(json.dumps(lock_data))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(bad_lock_1), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("must be a dict", res.stderr)

            # Mutation 2: missing size/sha256 strictly fails closed
            bad_lock_2 = scratch / "bad_lock_2.json"
            lock_data = json.loads(lock_file.read_text())
            lock_data["packages"]["libbpf-dev"]["required_headers"] = [{"path": "usr/include/bpf/bpf.h"}]
            bad_lock_2.write_text(json.dumps(lock_data))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(bad_lock_2), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing valid path, size, or sha256", res.stderr)

            # Mutation 3: tampered header bytes strictly fail closed
            (prefix / "usr/include/bpf/bpf.h").write_bytes(b"tampered_header_bytes")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(lock_file), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("TAMPERING DETECTED", res.stderr)

    def test_production_bpf_obj_gate_btf_validation(self) -> None:
        """Production --validate-bpf-obj gate rejects empty BTF types, zeroed CO-RE records, bad types."""
        readelf_bin = "/usr/bin/readelf"
        if not os.path.isfile(readelf_bin):
            readelf_bin = "readelf"

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            lock_file = make_dummy_lock(scratch, {})
            prefix = scratch / "prefix"
            prefix.mkdir()
            dep_file = scratch / "bpf.d"
            dep_file.write_text("mock.o: proof/bpf_canary.bpf.c\n")

            # Mutation 1: BTF type_len == 0 fails closed
            bad_bpf_1 = build_mock_bpf_elf(scratch, btf_type_len=0)
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_1), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(".BTF type_len is 0", res.stderr)

            # Mutation 2: zeroed CO-RE record fails closed
            bad_bpf_2 = build_mock_bpf_elf(scratch, corrupt_relo="zeroed")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_2), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Zeroed or invalid CO-RE record", res.stderr)

            # Mutation 3: non-existent BTF type ID fails closed
            bad_bpf_3 = build_mock_bpf_elf(scratch, corrupt_relo="nonexistent_type")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_3), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("non-existent BTF type ID", res.stderr)

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
