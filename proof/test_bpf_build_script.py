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
  5. Staged manifest validation: positive control on authentic fixture, then negative controls
     for string/non-dict header entry, missing size/digest, and tampered header SHA256.
  6. Production --validate-bpf-obj gate: tests full type/member graph walking, positive control
     with multiple distinct inputs and escaped spaces, rejects BTF type_len==0, non-existent
     type IDs, zeroed records, grammar violations, target-only .d, and missing primary source.
  7. Production --validate-host-elf gate: positive control passes, exact DT_NEEDED {'libc.so.6'}
     enforcement (rejecting libc.so.6.extra), GNU_STACK non-executable stack flags, missing
     BPF combined record refusal, target-only host .d, and missing primary host source.
  8. Production --evaluate-report gate: enforces all Section 7 criteria and verified on-disk logs.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "proof" / "run_bpf_feasibility.sh"


def make_strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    res = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(res)
        res += name.encode("latin1") + b"\x00"
    return res, offsets


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


def build_mock_bpf_elf(scratch: Path, btf_type_len: int = 120, corrupt_relo: str | None = None, filename: str = "mock_canary.bpf.o", scenario: str | None = None) -> Path:
    """Build a valid ELF64 little-endian BPF object with real .BTF, .BTF.ext, and .symtab sections."""
    shstrtab, sh_offsets = make_strtab([
        ".shstrtab", "tp_btf/sched_process_exec", ".maps", "license",
        ".BTF", ".BTF.ext", ".symtab", ".strtab"
    ])

    strtab, strtab_offsets = make_strtab(["sched_process_exec"])
    sched_sym_name_off = strtab_offsets["sched_process_exec"]
    symtab = b"\x00" * 24 + struct.pack("<IBBHQQ", sched_sym_name_off, 0x12, 0, 2, 0, 128)

    if scenario == "cyclic_typedef":
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "type_a", "type_b", "0:0"])
        # Type 1: TYPEDEF (kind 8), pointing to Type 2
        type_1_info = (8 << 24)
        type_1 = struct.pack("<III", btf_offsets["type_a"], type_1_info, 2)
        # Type 2: TYPEDEF (kind 8), pointing to Type 1 (CYCLE!)
        type_2_info = (8 << 24)
        type_2 = struct.pack("<III", btf_offsets["type_b"], type_2_info, 1)
        type_data = type_1 + type_2
        relo_kind = 0
        acc_str = "0:0"
    elif scenario in ("valid_array", "oob_array"):
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "my_struct", "arr", "int", "0:0:2", "0:0:7"])
        # Type 1: STRUCT (kind 4), 1 member (arr, type 3, off 0)
        type_1_info = (4 << 24) | 1
        type_1 = struct.pack("<III", btf_offsets["my_struct"], type_1_info, 32) + struct.pack("<III", btf_offsets["arr"], 3, 0)
        # Type 2: INT (kind 1), size 4
        type_2_info = (1 << 24)
        type_2 = struct.pack("<III", btf_offsets["int"], type_2_info, 4) + struct.pack("<I", (1 << 24) | 32)
        # Type 3: ARRAY (kind 3), elem type 2 (int), idx type 2, nelems 5
        type_3_info = (3 << 24)
        type_3 = struct.pack("<III", 0, type_3_info, 0) + struct.pack("<III", 2, 2, 5)
        type_data = type_1 + type_2 + type_3
        relo_kind = 0
        acc_str = "0:0:2" if scenario == "valid_array" else "0:0:7"
    elif scenario in ("type_size_invalid", "type_size_valid"):
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "my_struct", "f", "0:0", "0"])
        # Type 1: STRUCT, 1 member
        type_1_info = (4 << 24) | 1
        type_1 = struct.pack("<III", btf_offsets["my_struct"], type_1_info, 8) + struct.pack("<III", btf_offsets["f"], 1, 0)
        type_data = type_1
        relo_kind = 9  # BPF_CORE_TYPE_SIZE
        acc_str = "0:0" if scenario == "type_size_invalid" else "0"
    elif scenario == "rejected_kind":
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "my_struct", "0:0"])
        type_1_info = (4 << 24) | 0
        type_1 = struct.pack("<III", btf_offsets["my_struct"], type_1_info, 8)
        type_data = type_1
        relo_kind = 13  # Disallowed kind
        acc_str = "0:0"
    elif scenario in ("valid_enum", "oob_enum"):
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "my_enum", "ENUM_A", "ENUM_B", "1", "5"])
        # Type 1: ENUM (kind 6), vlen 2
        type_1_info = (6 << 24) | 2
        type_1 = struct.pack("<III", btf_offsets["my_enum"], type_1_info, 4) + \
                 struct.pack("<Ii", btf_offsets["ENUM_A"], 10) + \
                 struct.pack("<Ii", btf_offsets["ENUM_B"], 20)
        type_data = type_1
        relo_kind = 10  # ENUMVAL_EXISTS
        acc_str = "1" if scenario == "valid_enum" else "5"
    elif scenario in ("valid_enum64", "oob_enum64"):
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "my_enum64", "ENUM64_A", "ENUM64_B", "1", "5"])
        # Type 1: ENUM64 (kind 19), vlen 2
        type_1_info = (19 << 24) | 2
        type_1 = struct.pack("<III", btf_offsets["my_enum64"], type_1_info, 8) + \
                 struct.pack("<III", btf_offsets["ENUM64_A"], 10, 0) + \
                 struct.pack("<III", btf_offsets["ENUM64_B"], 20, 1)
        type_data = type_1
        relo_kind = 10  # ENUMVAL_EXISTS
        acc_str = "1" if scenario == "valid_enum64" else "5"
    elif scenario == "truncated_int":
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "file", "int", "0:0"])
        type_1_info = (1 << 24)
        type_data = struct.pack("<III", btf_offsets["int"], type_1_info, 4) + b"\x12\x34"
        relo_kind = 0
        acc_str = "0:0"
    elif scenario == "trailing_type_bytes":
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "file", "0:0"])
        type_1_info = (4 << 24) | 0
        type_1 = struct.pack("<III", btf_offsets["file"], type_1_info, 64)
        type_data = type_1 + b"\xaa\xbb\xcc\xdd\xee"
        relo_kind = 0
        acc_str = "0:0"
    elif scenario == "trailing_core_bytes":
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "file", "f_inode", "0:0"])
        type_1_info = (4 << 24) | 1
        type_1 = struct.pack("<III", btf_offsets["file"], type_1_info, 64) + struct.pack("<III", btf_offsets["f_inode"], 2, 0)
        type_2_info = (4 << 24) | 0
        type_2 = struct.pack("<III", btf_offsets["f_inode"], type_2_info, 64)
        type_data = type_1 + type_2
        relo_kind = 0
        acc_str = "0:0"
    else:
        btf_strtab, btf_offsets = make_strtab(["tp_btf/sched_process_exec", "file", "f_inode", "0:0"])
        type_1_info = (4 << 24) | 1  # STRUCT, 1 member
        type_1 = struct.pack("<III", btf_offsets["file"], type_1_info, 64) + struct.pack("<III", btf_offsets["f_inode"], 2, 0)
        type_2_info = (4 << 24) | 0  # STRUCT, 0 members
        type_2 = struct.pack("<III", btf_offsets["f_inode"], type_2_info, 64)
        type_data = (type_1 + type_2) if btf_type_len > 0 else b""
        relo_kind = 0
        acc_str = "0:0"

    actual_type_len = len(type_data)
    btf_hdr = struct.pack("<HBBIIII", 0xEB9F, 1, 0, 24, 0, actual_type_len, actual_type_len) + struct.pack("<I", len(btf_strtab))
    btf_sec_data = btf_hdr + type_data + btf_strtab

    sec_name_off = btf_offsets["tp_btf/sched_process_exec"]
    acc_str_off = btf_offsets[acc_str]
    relo_records = b""
    for i in range(10):
        insn_off = i * 8
        type_id = 1
        kind = relo_kind
        if corrupt_relo == "zeroed" and i == 0:
            relo_records += b"\x00" * 16
        elif corrupt_relo == "nonexistent_type" and i == 0:
            relo_records += struct.pack("<IIII", insn_off, 9999, acc_str_off, kind)
        elif corrupt_relo == "bad_grammar" and i == 0:
            relo_records += struct.pack("<IIII", insn_off, type_id, btf_offsets["file"], kind)
        else:
            relo_records += struct.pack("<IIII", insn_off, type_id, acc_str_off, kind)

    core_relo_data = struct.pack("<I", 16) + struct.pack("<II", sec_name_off, 10) + relo_records + (b"\xff" if scenario == "trailing_core_bytes" else b"")
    core_relo_len = len(core_relo_data)
    btf_ext_hdr = struct.pack("<HBBIIIIII", 0xEB9F, 1, 0, 32, 0, 0, 0, 0, 0) + struct.pack("<I", core_relo_len)
    btf_ext_sec_data = btf_ext_hdr + core_relo_data
    sections = [
        (b"", 0, 0, 0, 0, 0),
        (shstrtab, sh_offsets[".shstrtab"], 3, 0, 0, 1),
        (b"\x95\x00\x00\x00\x00\x00\x00\x00" * 16, sh_offsets["tp_btf/sched_process_exec"], 1, 0, 0, 8),
        (b"\x00" * 32, sh_offsets[".maps"], 1, 0, 0, 4),
        (b"Dual MIT/GPL\x00", sh_offsets["license"], 1, 0, 0, 1),
        (btf_sec_data, sh_offsets[".BTF"], 1, 0, 0, 4),
        (btf_ext_sec_data, sh_offsets[".BTF.ext"], 1, 0, 0, 4),
        (symtab, sh_offsets[".symtab"], 2, 8, 1, 24),
        (strtab, sh_offsets[".strtab"], 3, 0, 0, 1),
    ]

    e_ehsize = 64
    e_shentsize = 64
    e_shnum = len(sections)
    e_shstrndx = 1

    sec_headers = []
    current_off = e_ehsize + e_shnum * e_shentsize
    sec_payloads = []

    for content, name_off, s_type, sh_link, sh_info, sh_entsize in sections:
        size = len(content)
        off = current_off if size > 0 else 0
        align = 8 if s_type in (1, 2) else 1
        sh = struct.pack("<IIQQQQIIQQ", name_off, s_type, 6, 0, off, size, sh_link, sh_info, align, sh_entsize)
        sec_headers.append(sh)
        if size > 0:
            sec_payloads.append(content)
            current_off += size

    e_shoff = e_ehsize
    elf_hdr = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + struct.pack("<HHIQQQIHHHHHH", 1, 247, 1, 0, 0, e_shoff, 0, e_ehsize, 0, 0, e_shentsize, e_shnum, e_shstrndx)
    )

    out_file = scratch / filename
    out_file.write_bytes(elf_hdr + b"".join(sec_headers) + b"".join(sec_payloads))
    return out_file


def build_mock_host_elf(scratch: Path, needed_name: str = "libc.so.6", stack_flags: int = 6, filename: str = "mock_canary_host") -> Path:
    """Build a valid ELF64 x86-64 host executable with mock .dynamic, .interp, and defined symbols."""
    shstrtab, sh_offsets = make_strtab([
        ".shstrtab", ".interp", ".dynamic", ".dynstr", ".symtab", ".strtab", ".text"
    ])
    interp_str = b"/lib64/ld-linux-x86-64.so.2\x00"
    dynstr, dyn_offsets = make_strtab([needed_name])
    needed_off = dyn_offsets[needed_name]

    req_syms = ["bpf_object__open_file", "bpf_object__load", "elf_begin", "deflate", "ZSTD_decompress"]
    strtab, str_offsets = make_strtab(req_syms)

    sym_records = [b"\x00" * 24]
    for s in req_syms:
        sym_records.append(struct.pack("<IBBHQQ", str_offsets[s], 0x12, 0, 7, 0x100, 32))
    symtab = b"".join(sym_records)

    dynamic = (
        struct.pack("<QQ", 1, needed_off)
        + struct.pack("<QQ", 5, 0x300)  # DT_STRTAB at vaddr 0x300
        + struct.pack("<QQ", 10, len(dynstr))
        + struct.pack("<QQ", 0, 0)
    )

    sections = [
        (b"", 0, 0, 0, 0, 0, 0, 0),
        (shstrtab, sh_offsets[".shstrtab"], 3, 0, 0, 1, 0x600, len(shstrtab)),
        (interp_str, sh_offsets[".interp"], 1, 0, 0, 1, 0x150, len(interp_str)),
        (dynamic, sh_offsets[".dynamic"], 6, 4, 0, 16, 0x200, len(dynamic)),
        (dynstr, sh_offsets[".dynstr"], 3, 0, 0, 1, 0x300, len(dynstr)),
        (symtab, sh_offsets[".symtab"], 2, 6, 1, 24, 0x400, len(symtab)),
        (strtab, sh_offsets[".strtab"], 3, 0, 0, 1, 0x500, len(strtab)),
        (b"\x90" * 64, sh_offsets[".text"], 1, 0, 0, 16, 0x700, 64),
    ]

    sec_headers = []
    for content, name_off, s_type, sh_link, sh_info, sh_entsize, off, size in sections:
        align = 8 if s_type in (1, 2) else 1
        sh = struct.pack("<IIQQQQIIQQ", name_off, s_type, 6, 0, off, size, sh_link, sh_info, align, sh_entsize)
        sec_headers.append(sh)

    ph_interp = struct.pack("<IIQQQQQQ", 3, 4, 0x150, 0x150, 0x150, len(interp_str), len(interp_str), 1)
    ph_load = struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    ph_dynamic = struct.pack("<IIQQQQQQ", 2, 6, 0x200, 0x200, 0x200, len(dynamic), len(dynamic), 8)
    ph_stack = struct.pack("<IIQQQQQQ", 0x6474e551, stack_flags, 0, 0, 0, 0, 0, 0x10)

    phdrs = ph_interp + ph_load + ph_dynamic + ph_stack
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 4
    e_shentsize = 64
    e_shnum = 8
    e_shstrndx = 1

    e_phoff = 64
    e_shoff = 0x800

    elf_hdr = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, e_phoff, e_shoff, 0, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
    )

    data = bytearray(0x1000)
    data[:len(elf_hdr)] = elf_hdr
    data[64:64+len(phdrs)] = phdrs
    data[0x150:0x150+len(interp_str)] = interp_str
    data[0x200:0x200+len(dynamic)] = dynamic
    data[0x300:0x300+len(dynstr)] = dynstr
    data[0x400:0x400+len(symtab)] = symtab
    data[0x500:0x500+len(strtab)] = strtab
    data[0x600:0x600+len(shstrtab)] = shstrtab
    data[0x700:0x700+64] = b"\x90" * 64
    data[0x800:0x800+len(sec_headers)*64] = b"".join(sec_headers)

    out_file = scratch / filename
    out_file.write_bytes(data)
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
        self.assertNotIn("--lock", res.stdout)

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


    def test_missing_default_lock_fails(self) -> None:
        """Missing default lock file fails closed immediately on isolated repo fixture."""
        with tempfile.TemporaryDirectory() as td:
            t_root = Path(td)
            fake_repo = t_root / "fake_repo"
            fake_proof = fake_repo / "proof"
            fake_proof.mkdir(parents=True)
            fake_script = fake_proof / "run_bpf_feasibility.sh"
            shutil.copy2(SCRIPT_PATH, fake_script)
            fake_script.chmod(0o755)

            fresh_owned = t_root / "fresh_owned"
            res = subprocess.run(
                [
                    "bash",
                    str(fake_script),
                    "--owned-dir",
                    str(fresh_owned),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dependency lock", res.stderr)
            self.assertIn("not found", res.stderr)
            self.assertIn(str(fake_repo), res.stderr)
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

            # Mutation 3: tampered header bytes (same-size mutation: exactly 20 bytes) strictly fails closed on SHA
            (prefix / "usr/include/bpf/bpf.h").write_bytes(b"tampered_header_byte")  # exactly 20 bytes
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(lock_file), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("TAMPERING DETECTED", res.stderr)

            # Mutation 4: size mismatch strictly fails closed
            (prefix / "usr/include/bpf/bpf.h").write_bytes(b"short_bytes")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-staged-manifest", str(lock_file), str(receipt_file), str(prefix)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("size mismatch", res.stderr)

    def test_production_bpf_obj_gate_btf_validation(self) -> None:
        """Production --validate-bpf-obj gate: positive control passes, mutations strictly fail closed."""
        readelf_bin = shutil.which("readelf") or shutil.which("llvm-readelf") or "/usr/bin/readelf"

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            lock_file = make_dummy_lock(scratch, {})
            prefix = scratch / "prefix"
            prefix.mkdir()
            dep_file = scratch / "bpf.d"
            # Dep file with line continuation and escaped space
            escaped_repo = str(REPO_ROOT).replace(" ", r"\ ")
            dep_file.write_text(f"mock.o: \\\n  {escaped_repo}/proof/bpf_canary.bpf.c \\\n  {escaped_repo}/proof/bpf_canary_types.h\n")

            # Positive control: authentic mock BPF ELF passes gate completely with multiple inputs
            valid_bpf = build_mock_bpf_elf(scratch)
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)
            self.assertTrue((scratch / "bpf-compiled-headers.json").is_file())

            # Mutation 1: BTF type_len == 0 fails closed
            bad_bpf_1 = build_mock_bpf_elf(scratch, btf_type_len=0, filename="bad1.o")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_1), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(".BTF type_len is 0", res.stderr)

            # Mutation 2: zeroed CO-RE record fails closed
            bad_bpf_2 = build_mock_bpf_elf(scratch, corrupt_relo="zeroed", filename="bad2.o")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_2), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Zeroed or invalid CO-RE record", res.stderr)

            # Mutation 3: non-existent BTF type ID fails closed
            bad_bpf_3 = build_mock_bpf_elf(scratch, corrupt_relo="nonexistent_type", filename="bad3.o")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_3), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("non-existent BTF type ID", res.stderr)

            # Mutation 4: invalid access string grammar fails closed
            bad_bpf_4 = build_mock_bpf_elf(scratch, corrupt_relo="bad_grammar", filename="bad4.o")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_4), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Invalid CO-RE access string grammar", res.stderr)

            # Mutation 5: target-only .d file with no prerequisites fails closed
            dep_target_only = scratch / "target_only.d"
            dep_target_only.write_text("mock.o:\n")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_target_only), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("contains no prerequisites (target-only)", res.stderr)

            # Mutation 6: missing primary source in .d fails closed
            dep_no_src = scratch / "no_src.d"
            dep_no_src.write_text(f"mock.o: {escaped_repo}/proof/bpf_canary_types.h\n")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_no_src), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing primary source bpf_canary.bpf.c", res.stderr)

            # Mutation 7: cyclic typedef detected and fails closed
            bad_bpf_cyclic = build_mock_bpf_elf(scratch, filename="cyclic.o", scenario="cyclic_typedef")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_cyclic), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Cyclic BTF type modifier detected", res.stderr)

            # Positive control 2: valid array traversal passes gate
            valid_bpf_array = build_mock_bpf_elf(scratch, filename="valid_array.o", scenario="valid_array")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf_array), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)

            # Mutation 8: out-of-bounds array traversal fails closed
            bad_bpf_oob_array = build_mock_bpf_elf(scratch, filename="oob_array.o", scenario="oob_array")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_oob_array), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Array index 7 out of bounds (nelems 5)", res.stderr)

            # Mutation 9: TYPE_SIZE (kind 9) with invalid access string "0:0" fails closed
            bad_bpf_type_size = build_mock_bpf_elf(scratch, filename="bad_type_size.o", scenario="type_size_invalid")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_type_size), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Type-based CO-RE relocation (kind 9) must have access string '0'", res.stderr)

            # Positive control 3: TYPE_SIZE (kind 9) with valid access string "0" passes gate
            valid_bpf_type_size = build_mock_bpf_elf(scratch, filename="valid_type_size.o", scenario="type_size_valid")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf_type_size), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)

            # Mutation 10: unsupported/rejected relocation kind (13) fails closed
            bad_bpf_kind = build_mock_bpf_elf(scratch, filename="bad_kind.o", scenario="rejected_kind")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_kind), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Disallowed or unknown CO-RE relocation kind: 13", res.stderr)

            # Positive control 4: valid enum value relocation passes gate
            valid_bpf_enum = build_mock_bpf_elf(scratch, filename="valid_enum.o", scenario="valid_enum")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf_enum), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)

            # Mutation 11: out-of-bounds enum index fails closed
            bad_bpf_oob_enum = build_mock_bpf_elf(scratch, filename="oob_enum.o", scenario="oob_enum")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_oob_enum), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Enum value index 5 out of range (count 2)", res.stderr)

            # Mutation 12: truncated non-STRUCT kind payload fails closed
            bad_bpf_trunc_int = build_mock_bpf_elf(scratch, filename="trunc_int.o", scenario="truncated_int")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_trunc_int), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(".BTF int payload truncated", res.stderr)

            # Mutation 13: trailing type section bytes fails closed
            bad_bpf_trailing_type = build_mock_bpf_elf(scratch, filename="trailing_type.o", scenario="trailing_type_bytes")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_trailing_type), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(".BTF type section has 5 trailing bytes (incomplete binary grammar)", res.stderr)

            # Mutation 14: trailing core relocation bytes fails closed
            bad_bpf_trailing_core = build_mock_bpf_elf(scratch, filename="trailing_core.o", scenario="trailing_core_bytes")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_trailing_core), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(".BTF.ext core_relo has 1 trailing bytes (incomplete binary grammar)", res.stderr)

            # Positive control 5: valid enum64 value relocation passes gate
            valid_bpf_enum64 = build_mock_bpf_elf(scratch, filename="valid_enum64.o", scenario="valid_enum64")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf_enum64), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)

            # Mutation 15: out-of-bounds enum64 index fails closed
            bad_bpf_oob_enum64 = build_mock_bpf_elf(scratch, filename="oob_enum64.o", scenario="oob_enum64")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(bad_bpf_oob_enum64), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Enum value index 5 out of range (count 2)", res.stderr)

            # Mutation 16: raw substring match traversal attempt rejected by exact canonical resolution
            dep_bpf_traversal = scratch / "bpf_traversal.d"
            dep_bpf_traversal.write_text(f"mock.o: {escaped_repo}/proof/bpf_canary.bpf.c/../bpf_canary_types.h\n")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_bpf_traversal), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing primary source bpf_canary.bpf.c", res.stderr)

            # Positive control 6: multi-input dependency graph with escaped $$ dollar signs and \  spaces
            prefix_dollar = scratch / "staged$prefix with space"
            prefix_dollar.mkdir(parents=True, exist_ok=True)
            bpf_hdr = prefix_dollar / "usr" / "include" / "bpf" / "bpf.h"
            bpf_hdr.parent.mkdir(parents=True, exist_ok=True)
            hdr_bytes_bpf = b"b" * 20
            bpf_hdr.write_bytes(hdr_bytes_bpf)
            bpf_sha = hashlib.sha256(hdr_bytes_bpf).hexdigest()

            libbpf_hdr = prefix_dollar / "usr" / "include" / "bpf" / "libbpf.h"
            hdr_bytes_libbpf = b"c" * 20
            libbpf_hdr.write_bytes(hdr_bytes_libbpf)
            libbpf_sha = hashlib.sha256(hdr_bytes_libbpf).hexdigest()

            scratch_dollar = scratch / "dollar_lock_dir"
            scratch_dollar.mkdir(parents=True, exist_ok=True)
            lock_dollar = make_dummy_lock(scratch_dollar, {}, {
                "usr/include/bpf/bpf.h": bpf_sha,
                "usr/include/bpf/libbpf.h": libbpf_sha
            })

            escaped_bpf_hdr = str(bpf_hdr).replace(" ", r"\ ").replace("$", "$$")
            escaped_libbpf_hdr = str(libbpf_hdr).replace(" ", r"\ ").replace("$", "$$")
            dep_multi_dollar = scratch / "multi_dollar.d"
            dep_multi_dollar.write_text(
                f"mock.o: \\\n"
                f"  {escaped_repo}/proof/bpf_canary.bpf.c \\\n"
                f"  {escaped_repo}/proof/bpf_canary_types.h \\\n"
                f"  {escaped_bpf_hdr} \\\n"
                f"  {escaped_libbpf_hdr}\n"
            )

            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_multi_dollar), "/usr/lib/clang/18", str(prefix_dollar), str(REPO_ROOT), str(lock_dollar), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verified genuine .BTF.ext CO-RE relocations", res.stdout)
            compiled_hdrs = json.loads((scratch / "bpf-compiled-headers.json").read_text())
            self.assertIn(str(bpf_hdr.resolve()), compiled_hdrs)
            self.assertIn(str(libbpf_hdr.resolve()), compiled_hdrs)

            # Mutation 17: negative dangling escape backslash in depfile fails closed
            dep_dangling_bs = scratch / "dangling_bs.d"
            dep_dangling_bs.write_text(f"mock.o: {escaped_repo}/proof/bpf_canary.bpf.c \\\n  {escaped_repo}/proof/bpf_canary_types.h \\")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_dangling_bs), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dangling escape backslash", res.stderr)

            # Mutation 18: negative dangling/unescaped single dollar in depfile fails closed
            dep_dangling_dollar = scratch / "dangling_dollar.d"
            dep_dangling_dollar.write_text(f"mock.o: {escaped_repo}/proof/bpf_canary.bpf.c \\\n  {escaped_repo}/proof/bpf_canary_types.h $")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-bpf-obj", readelf_bin, str(valid_bpf), str(dep_dangling_dollar), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(lock_file), str(scratch)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Dangling or unescaped dollar sign", res.stderr)

    def test_production_host_elf_gate_validation(self) -> None:
        """Production --validate-host-elf gate: positive control passes, mutations strictly fail closed."""
        readelf_bin = shutil.which("readelf") or shutil.which("llvm-readelf") or "/usr/bin/readelf"

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            lock_file = make_dummy_lock(scratch, {})
            prefix = scratch / "prefix"
            prefix.mkdir()
            dep_file = scratch / "host.d"
            escaped_repo = str(REPO_ROOT).replace(" ", r"\ ")
            dep_file.write_text(f"mock_host.o: {escaped_repo}/proof/bpf_canary_host.c\n")

            # Seed bpf-compiled-headers.json in scratch as required by dual graph merge contract
            (scratch / "bpf-compiled-headers.json").write_text(json.dumps({
                f"{REPO_ROOT}/proof/bpf_canary.bpf.c": {"sha256": "0" * 64, "size": 100}
            }))

            # Positive control: authentic mock host binary passes gate completely
            valid_host = build_mock_host_elf(scratch)
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Validated Host helper binary", res.stdout)
            self.assertTrue((scratch / "compiled-headers.json").is_file())

            # Mutation 1: libc.so.6.extra substring rejected by exact set equality
            bad_host_1 = build_mock_host_elf(scratch, needed_name="libc.so.6.extra", filename="bad_host_1")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(bad_host_1), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Disallowed dynamic dependencies in host helper", res.stderr)

            # Mutation 2: executable stack (RWE) rejected
            bad_host_2 = build_mock_host_elf(scratch, stack_flags=7, filename="bad_host_2")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(bad_host_2), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("EXECUTABLE STACK", res.stderr)

            # Mutation 3: missing BPF combined record fails closed
            (scratch / "bpf-compiled-headers.json").unlink()
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Missing or empty BPF compiled headers record", res.stderr)

            # Mutation 4: host raw substring traversal attempt rejected by exact canonical resolution
            dep_host_traversal = scratch / "host_traversal.d"
            dep_host_traversal.write_text(f"mock_host.o: {escaped_repo}/proof/bpf_canary_host.c/../bpf_canary_types.h\n")
            # Re-seed valid bpf combined record for host dependency check
            (scratch / "bpf-compiled-headers.json").write_text(json.dumps({
                f"{REPO_ROOT}/proof/bpf_canary.bpf.c": {"sha256": "0" * 64, "size": 100}
            }))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_host_traversal), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing primary source bpf_canary_host.c", res.stderr)

            # Mutation 5: host BPF combined record empty JSON dict {} fails closed
            (scratch / "bpf-compiled-headers.json").write_text("{}")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("BPF compiled headers record contains 0 records", res.stderr)

            # Mutation 6: host BPF combined record malformed JSON fails closed
            (scratch / "bpf-compiled-headers.json").write_text("{bad json")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Malformed BPF compiled headers record", res.stderr)

            # Mutation 7: host BPF combined record missing primary BPF source fails closed
            (scratch / "bpf-compiled-headers.json").write_text(json.dumps({
                "/some/other/file.h": {"sha256": "0" * 64, "size": 100}
            }))
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing primary source", res.stderr)

            # Mutation 8: host BPF combined record 0-byte file fails closed
            (scratch / "bpf-compiled-headers.json").write_text("")
            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--validate-host-elf", readelf_bin, str(valid_host), str(dep_file), "/usr/lib/clang/18", str(prefix), str(REPO_ROOT), str(scratch), str(lock_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Missing or empty BPF compiled headers record", res.stderr)

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
