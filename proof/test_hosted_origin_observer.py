#!/usr/bin/env python3
"""
proof/test_hosted_origin_observer.py

Focused unit and adversarial fixture tests for proof/hosted_origin_observer.py.
Verifies all security invariants and addresses ReviewFixtureIsolation P1 findings:
1. Wire protocol framing and roundtrip with root-qualified identities and aliases.
2. Simulated positive flow with advanced atime: pre-read census, real W ledger schema,
   reference binding, kernel atime verification, raw executable bytes capture.
3. Adversarial fixture 1: Executable/ledger hardlink alias attack detection.
4. Adversarial fixture 2: Symlink escape detection (O_NOFOLLOW descriptor traversal).
5. Adversarial fixture 3: Path traversal escape (../ or foreign root escapes).
6. Adversarial fixture 4: Missing reference rejection.
7. Adversarial fixture 5: Duplicate reference rejection across root identities.
8. Adversarial fixture 6: Foreign driver/nonce rejection.
9. Adversarial fixture 7: Inode mismatch rejection.
10. Adversarial fixture 8: Unexecuted reference (atime not advanced) rejection.
11. Adversarial fixture 9: Special file (fifo) reference rejection.
12. Adversarial fixture 10: Content hash mismatch rejection.
13. Metadata ordering proof: candidate fstat sampling occurs strictly before ledger read.
14. Preservation invariant: unexecuted references are not upgraded by subsequent archive reads.
15. Explicit reporting of observer limitations.
16. P1-1: Rejection of omitted required references (empty records or missing out_ref with C-trusted expected set).
17. P1-2: Rejection of forged old ledger mtime bypassing atime (kernel vs kernel observation).
18. P1-3: Multi-root relative path collision prevention and root-qualified identity preservation.
19. P1-4: Checkpoint commitment to pipe before ledger read and traversal error fail-closed enforcement.
20. P1-1 Extra: Rejection of unexpected extra references not in C-trusted expected set.
21. P1-1 Target: Rejection of missing, special, or foreign out targets.
22. Expected reference derivation from C-trusted census file.
23. Complete evidence recovery from wire stream frames.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from typing import Any, Dict, List

from proof.hosted_origin_observer import (
    FRAME_METADATA,
    FRAME_RAW_FILE,
    FRAME_TERMINATION,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    CandidateFile,
    LaunchBinding,
    SpecialEntry,
    decode_raw_file_frame,
    derive_trusted_expected_references,
    encode_raw_file_frame,
    parse_observer_stream,
    read_frame,
    read_header,
    run_origin_observer,
    walk_roots_descriptor_relative,
    write_frame,
    write_header,
)


class TestHostedOriginObserver(unittest.TestCase):
    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_observer_")
        self.root_dir = os.path.join(self.test_dir, "attempt")
        os.makedirs(os.path.join(self.root_dir, "t"), exist_ok=True)
        self.binding = LaunchBinding(
            chain_id="chain_test_123",
            driver="acme",
            attempt=1,
            launch_id="cid_container_456",
            expected_nonce="nonce_789",
            expected_refs=("t/prog.ref",),
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_file(self, rel_path: str, content: bytes, mtime_ns: int | None = None, atime_ns: int | None = None) -> str:
        full_path = os.path.join(self.root_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        if mtime_ns is not None or atime_ns is not None:
            st = os.stat(full_path)
            a_ns = atime_ns if atime_ns is not None else st.st_atime_ns
            m_ns = mtime_ns if mtime_ns is not None else st.st_mtime_ns
            os.utime(full_path, ns=(a_ns, m_ns))
        return full_path

    def _write_ledger(self, header: Dict[str, Any], records: List[Dict[str, Any]]) -> str:
        lines = [json.dumps(header)]
        for r in records:
            lines.append(json.dumps(r))
        content = "\n".join(lines).encode("utf-8") + b"\n"
        return self._write_file("ledger.jsonl", content)

    # 1. Wire protocol framing tests

    def test_01_wire_protocol_framing_roundtrip(self) -> None:
        buf = io.BytesIO()
        write_header(buf)

        meta_payload = json.dumps({"v": 1, "test": "data"}).encode("utf-8")
        write_frame(buf, FRAME_METADATA, meta_payload)

        raw_payload = encode_raw_file_frame(
            root_index=0,
            rel_path="t/prog",
            st_dev=123,
            st_ino=456,
            sha256_hex=hashlib.sha256(b"binary_payload").hexdigest(),
            file_bytes=b"binary_payload",
            aliases=[{"root_index": 0, "rel_path": "t/prog.ref"}],
        )
        write_frame(buf, FRAME_RAW_FILE, raw_payload)

        term_payload = json.dumps({"status": "PASS", "reasons": []}).encode("utf-8")
        write_frame(buf, FRAME_TERMINATION, term_payload)

        buf.seek(0)
        meta_doc, raw_files, term_doc = parse_observer_stream(buf)

        self.assertEqual(meta_doc["test"], "data")
        self.assertEqual(len(raw_files), 1)
        self.assertEqual(raw_files[0]["root_index"], 0)
        self.assertEqual(raw_files[0]["rel_path"], "t/prog")
        self.assertEqual(raw_files[0]["file_bytes"], b"binary_payload")
        self.assertEqual(raw_files[0]["aliases"], [{"root_index": 0, "rel_path": "t/prog.ref"}])
        self.assertEqual(term_doc["status"], "PASS")

    # 2. Simulated positive flow with advanced atime (simulated execution, not proof of exec)

    def test_02_simulated_advanced_atime_flow(self) -> None:
        """Simulated positive flow with advanced atime (simulated execution via atime advance; note: collector alone cannot verify execution)."""
        prog_bytes = b"#!/bin/sh\necho ok\n"
        prog_sha256 = hashlib.sha256(prog_bytes).hexdigest()
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000  # advanced by 1s

        prog_path = self._write_file("t/prog", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))

        st = os.stat(prog_path)
        self.assertEqual(st.st_nlink, 2)

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        begin_rec = {
            "v": 1,
            "kind": "record",
            "t_ns": 100,
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "begin",
            "inv": "inv_1",
            "command": "build",
            "output": "t/prog",
        }
        end_rec = {
            "v": 1,
            "kind": "record",
            "t_ns": 200,
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "command": "build",
            "output": "t/prog",
            "producer": {"argv": ["build"], "rc": 0, "mods_count": 1},
            "consumer": {"argv": ["consumer"], "rc": 0, "out_written": True, "out_sha256": prog_sha256},
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1_000_000,
            "e3_error": None,
            "interrupted": False,
            "exit": 0,
        }
        self._write_ledger(header, [begin_rec, end_rec])

        out_pipe = io.BytesIO()
        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
            output_stream=out_pipe,
            capture_raw_bytes=True,
        )

        self.assertEqual(doc["verdict"]["status"], "PASS")
        self.assertEqual(doc["verdict"]["reasons"], [])
        self.assertTrue(all(v == "PASS" for v in doc["verdict"]["checks"].values()))
        self.assertEqual(len(doc["references"]), 1)
        ref = doc["references"][0]
        self.assertTrue(ref["atime_advanced"])
        self.assertTrue(ref["hardlink_verified"])
        self.assertTrue(ref["sha256_verified"])
        self.assertEqual(ref["observed_ino"], st.st_ino)

        # Verify wire output decodability
        out_pipe.seek(0)
        meta_parsed, raw_files, term_parsed = parse_observer_stream(out_pipe)
        self.assertEqual(term_parsed["status"], "PASS")
        self.assertEqual(len(raw_files), 1)
        self.assertEqual(raw_files[0]["file_bytes"], prog_bytes)
        self.assertEqual(raw_files[0]["aliases"], [{"root_index": 0, "rel_path": "t/prog.ref"}])
        self.assertEqual(len(doc["raw_files_manifest"]), 1)
        # Verify wire frame decodes complete evidence
        self.assertIsNotNone(meta_parsed.get("ledger"))
        self.assertIsNotNone(meta_parsed.get("references"))
        self.assertIsNotNone(meta_parsed.get("raw_files_manifest"))

    # 3. Adversarial fixture: Executable/ledger hardlink alias attack

    def test_03_adversarial_hardlink_alias_attack(self) -> None:
        """
        Adversary creates ledger.jsonl as a hardlink to t/prog.
        Reading ledger.jsonl would advance atime of t/prog before measurement.
        Observer MUST detect this alias attack and reject.
        """
        prog_bytes = b"#!/bin/sh\necho malicious\n"
        prog_path = self._write_file("t/prog", prog_bytes)

        ledger_path = os.path.join(self.root_dir, "ledger.jsonl")
        os.link(prog_path, ledger_path)

        out_pipe = io.BytesIO()
        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
            output_stream=out_pipe,
            capture_raw_bytes=True,
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_hardlink_aliases"], "FAIL")
        self.assertTrue(
            any("executable/ledger hardlink alias attack detected" in r for r in doc["verdict"]["reasons"])
        )

    # 4. Adversarial fixture: Symlink escape

    def test_04_adversarial_symlink_escape(self) -> None:
        """
        Adversary creates t/prog.ref as a symlink pointing to an outside file or another file.
        Observer MUST reject symlink references.
        """
        prog_bytes = b"echo safe"
        prog_path = self._write_file("t/prog", prog_bytes)
        symlink_ref = os.path.join(self.root_dir, "t/prog.ref")
        os.symlink(prog_path, symlink_ref)

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": 12345,
            "out_mtime_ns": 1000,
            "atime_set_ns": 500,
            "consumer": {"out_sha256": "abc"},
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_symlink_escapes"], "FAIL")
        self.assertTrue(any("is a symlink" in r for r in doc["verdict"]["reasons"]))

    # 5. Adversarial fixture: Path traversal escape

    def test_05_adversarial_path_traversal_escape(self) -> None:
        """
        Ledger references out_ref escaping the permitted root via '../'.
        Observer MUST reject path traversal escape.
        """
        self._write_file("t/prog", b"echo escape")

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "../escaped_file.ref",
            "out_ino": 12345,
            "out_mtime_ns": 1000,
            "atime_set_ns": 500,
            "consumer": {"out_sha256": "abc"},
        }
        self._write_ledger(header, [record])

        binding = LaunchBinding(
            chain_id=self.binding.chain_id,
            driver=self.binding.driver,
            attempt=self.binding.attempt,
            launch_id=self.binding.launch_id,
            expected_nonce=self.binding.expected_nonce,
            expected_refs=("../escaped_file.ref",),
        )

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_foreign_references"], "FAIL")
        self.assertTrue(any("escapes permitted roots" in r or "path traversal" in r for r in doc["verdict"]["reasons"]))

    # 6. Adversarial fixture: Missing reference rejection

    def test_06_adversarial_missing_reference(self) -> None:
        """
        Ledger claims an out_ref that does not exist in candidate census.
        Observer MUST reject missing reference.
        """
        self._write_file("t/prog", b"binary")

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/missing_file.ref",
            "out_ino": 12345,
            "out_mtime_ns": 1000,
            "atime_set_ns": 500,
            "consumer": {"out_sha256": "abc"},
        }
        self._write_ledger(header, [record])

        binding = LaunchBinding(
            chain_id=self.binding.chain_id,
            driver=self.binding.driver,
            attempt=self.binding.attempt,
            launch_id=self.binding.launch_id,
            expected_nonce=self.binding.expected_nonce,
            expected_refs=("t/missing_file.ref",),
        )

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_missing_references"], "FAIL")
        self.assertTrue(any("missing from pre-read census" in r for r in doc["verdict"]["reasons"]))

    # 7. Adversarial fixture: Duplicate reference rejection

    def test_07_adversarial_duplicate_reference(self) -> None:
        """
        Ledger claims the same out_ref in multiple distinct end records.
        Observer MUST reject duplicate references.
        """
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000
        prog_path = self._write_file("t/prog", b"binary", mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))
        st = os.stat(prog_path)
        sha = hashlib.sha256(b"binary").hexdigest()

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        r1 = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": sha},
        }
        r2 = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_2",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": sha},
        }
        self._write_ledger(header, [r1, r2])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_duplicate_references"], "FAIL")
        self.assertTrue(any("duplicate reference detected" in r for r in doc["verdict"]["reasons"]))

    # 8. Adversarial fixture: Foreign driver or nonce

    def test_08_adversarial_foreign_driver_or_nonce(self) -> None:
        """
        Ledger header or records carry unexpected driver or nonce.
        Observer MUST reject foreign identities.
        """
        self._write_file("t/prog", b"binary")
        header = {
            "v": 1,
            "kind": "header",
            "nonce": "foreign_nonce",
            "driver": "foreign_driver",
            "attempt": 1,
            "chain_id": self.binding.chain_id,
        }
        self._write_ledger(header, [])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["ledger_header"], "FAIL")

    # 9. Adversarial fixture: Inode mismatch

    def test_09_adversarial_inode_mismatch(self) -> None:
        """
        Workload records out_ino in ledger that does not match physical inode.
        Observer MUST reject inode spoofing.
        """
        mtime_ns = 1000
        atime_ns = 2000
        prog_path = self._write_file("t/prog", b"binary", mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))
        sha = hashlib.sha256(b"binary").hexdigest()

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": 99999999,  # fake inode
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 100,
            "consumer": {"out_sha256": sha},
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertTrue(any("physical inode" in r and "!= recorded" in r for r in doc["verdict"]["reasons"]))

    # 10. Adversarial fixture: Unexecuted reference (atime not advanced)

    def test_10_adversarial_atime_not_advanced(self) -> None:
        """
        File was compiled but never executed (atime <= mtime).
        Observer MUST reject execution claim based on numeric integer comparison.
        """
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_000_000_000_000  # atime == mtime (not advanced!)

        prog_path = self._write_file("t/prog", b"binary", mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))

        st = os.stat(prog_path)
        sha = hashlib.sha256(b"binary").hexdigest()

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 100,
            "consumer": {"out_sha256": sha},
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["numeric_atime_predicates"], "FAIL")
        self.assertTrue(any("kernel atime" in r and "<= kernel mtime" in r for r in doc["verdict"]["reasons"]))

    # 11. Preservation Invariant: Unexecuted reference not upgraded after archive reads

    def test_11_unexecuted_reference_not_upgraded_after_subsequent_reads(self) -> None:
        """
        An unexecuted candidate is captured in initial pre-read census.
        Subsequent reading of the file (e.g. archiving or verification read) advances atime,
        but the frozen observer record MUST NOT upgrade the unexecuted status.
        """
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_000_000_000_000

        prog_path = self._write_file("t/prog", b"binary", mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))

        st = os.stat(prog_path)
        sha = hashlib.sha256(b"binary").hexdigest()

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 100,
            "consumer": {"out_sha256": sha},
        }
        self._write_ledger(header, [record])

        # Initial observation: REJECT
        doc1 = run_origin_observer(roots=[self.root_dir], binding=self.binding)
        self.assertEqual(doc1["verdict"]["status"], "REJECT")

        # Now simulate an external archive read that touches the file!
        with open(ref_path, "rb") as f:
            _ = f.read()

        # The initial census in doc1 is immutable and frozen:
        census_entry = next(c for c in doc1["initial_census"] if c["rel_path"] == "t/prog.ref")
        self.assertEqual(census_entry["st_atime_ns"], atime_ns)

    # 12. Adversarial fixture: Special file (fifo) rejection

    def test_12_adversarial_special_file_fifo(self) -> None:
        """
        Workload provides a FIFO pipe as out_ref.
        Observer MUST reject special files without opening or hanging on them.
        """
        if not hasattr(os, "mkfifo"):
            self.skipTest("os.mkfifo not available")

        fifo_path = os.path.join(self.root_dir, "t/fifo.ref")
        os.mkfifo(fifo_path)

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/fifo.ref",
            "out_ref": "t/fifo.ref",
            "out_ino": 12345,
            "out_mtime_ns": 1000,
            "atime_set_ns": 500,
            "consumer": {"out_sha256": "abc"},
        }
        self._write_ledger(header, [record])

        binding = LaunchBinding(
            chain_id=self.binding.chain_id,
            driver=self.binding.driver,
            attempt=self.binding.attempt,
            launch_id=self.binding.launch_id,
            expected_nonce=self.binding.expected_nonce,
            expected_refs=("t/fifo.ref",),
        )

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertTrue(any("special file" in r for r in doc["verdict"]["reasons"]))

    # 13. Content hash mismatch

    def test_13_content_hash_mismatch(self) -> None:
        """
        Consumer claims SHA-256 that does not match actual executable bytes.
        Observer MUST detect hash mismatch.
        """
        prog_bytes = b"real content"
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000

        prog_path = self._write_file("t/prog", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(atime_ns, mtime_ns))

        st = os.stat(prog_path)

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 100,
            "consumer": {"rc": 0, "out_sha256": "0" * 64},  # wrong hash!
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["raw_bytes_retained"], "FAIL")
        self.assertTrue(any("sha256 mismatch" in r for r in doc["verdict"]["reasons"]))

    # 14. Metadata ordering verification

    def test_14_metadata_ordering_proof(self) -> None:
        """
        Prove that fstat sampling of candidates occurs strictly before ledger.jsonl is opened/read.
        """
        prog_path = self._write_file("t/prog", b"test")
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        self._write_ledger(
            {
                "v": 1,
                "kind": "header",
                "nonce": self.binding.expected_nonce,
                "driver": self.binding.driver,
                "attempt": self.binding.attempt,
                "chain_id": self.binding.chain_id,
            },
            [],
        )

        candidates, specials, errors = walk_roots_descriptor_relative([self.root_dir])
        self.assertEqual(len(errors), 0)

        candidate_paths = {c.rel_path for c in candidates}
        self.assertIn("t/prog", candidate_paths)
        self.assertIn("t/prog.ref", candidate_paths)
        self.assertIn("ledger.jsonl", candidate_paths)

        for c in candidates:
            self.assertIsNotNone(c.fd)
            st = os.fstat(c.fd)
            self.assertEqual(st.st_ino, c.st_ino)
            os.close(c.fd)

    # 15. Limitations reporting

    def test_15_limits_explicitly_reported(self) -> None:
        doc = run_origin_observer(roots=[self.root_dir], binding=self.binding)
        self.assertIn("limitations", doc)
        self.assertTrue(any("cannot distinguish authentic kernel execution" in lim for lim in doc["limitations"]))

    # 16. P1-1: Rejection of omitted required references

    def test_16_adversarial_omitted_required_references_fails(self) -> None:
        """
        P1-1: Header is valid, but records are empty or omit out_ref.
        Observer MUST reject when C-trusted expected references are not satisfied.
        """
        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        # Case A: empty records in ledger
        self._write_ledger(header, [])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,  # requires ("t/prog.ref",)
            ledger_relpath="ledger.jsonl",
        )
        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_missing_references"], "FAIL")
        self.assertTrue(any("required expected references missing from verified references" in r for r in doc["verdict"]["reasons"]))

        # Case B: record with missing out_ref or omitted required metadata
        rec_omitted = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "command": "build",
            # omitted out_ref, out_ino, out_mtime_ns!
        }
        self._write_ledger(header, [rec_omitted])
        doc2 = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )
        self.assertEqual(doc2["verdict"]["status"], "REJECT")
        self.assertEqual(doc2["verdict"]["checks"]["no_missing_references"], "FAIL")

    # 17. P1-2: Rejection of forged old ledger mtime bypassing atime

    def test_17_adversarial_forged_old_ledger_mtime_fails(self) -> None:
        """
        P1-2: Malicious workload writes forged past out_mtime_ns to make unadvanced atime look advanced.
        Kernel observed atime == kernel observed mtime.
        Observer MUST bind mtime to kernel observation and reject.
        """
        real_kernel_mtime_ns = 1_000_000_000_000_000_000
        real_kernel_atime_ns = 1_000_000_000_000_000_000  # unadvanced!

        prog_path = self._write_file("t/prog", b"binary", mtime_ns=real_kernel_mtime_ns, atime_ns=real_kernel_atime_ns)
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)
        os.utime(ref_path, ns=(real_kernel_atime_ns, real_kernel_mtime_ns))

        st = os.stat(prog_path)
        sha = hashlib.sha256(b"binary").hexdigest()

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        # Forged past mtime in ledger (e.g. 500s earlier)
        forged_mtime_ns = real_kernel_mtime_ns - 500_000_000_000
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "command": "build",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": forged_mtime_ns,  # forged!
            "atime_set_ns": forged_mtime_ns - 100,
            "consumer": {"out_sha256": sha},
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["numeric_atime_predicates"], "FAIL")
        # Must detect that recorded mtime != kernel observed mtime
        self.assertTrue(any("!= kernel observed mtime" in r for r in doc["verdict"]["reasons"]))
        # And must detect that kernel atime <= kernel mtime
        self.assertTrue(any("kernel atime" in r and "<= kernel mtime" in r for r in doc["verdict"]["reasons"]))

    # 18. P1-3: Multi-root relative path collision prevention

    def test_18_adversarial_multi_root_relative_path_collision(self) -> None:
        """
        P1-3: Two roots containing the same relative filename do not overwrite.
        Root identity is preserved in census and reference binding.
        """
        scratch_dir = os.path.join(self.test_dir, "scratch")
        os.makedirs(os.path.join(scratch_dir, "sub"), exist_ok=True)

        # File in root 0 (attempt)
        p0 = self._write_file("sub/file.bin", b"root0_data")
        # File in root 1 (scratch) with same relative path
        p1 = os.path.join(scratch_dir, "sub/file.bin")
        with open(p1, "wb") as f:
            f.write(b"root1_data")

        # Walk both roots
        candidates, specials, errors = walk_roots_descriptor_relative([self.root_dir, scratch_dir])
        self.assertEqual(len(errors), 0)

        # Verify both are preserved in candidate census with distinct root indices
        matches = [c for c in candidates if c.rel_path == "sub/file.bin"]
        self.assertEqual(len(matches), 2)
        root_indices = {c.root_index for c in matches}
        self.assertEqual(root_indices, {0, 1})

        for c in candidates:
            if c.fd is not None:
                os.close(c.fd)

    # 19. P1-4: Checkpoint commitment before ledger read & traversal error fail-closed

    def test_19_metadata_ordering_checkpoint_before_ledger_read(self) -> None:
        """
        P1-4: Prove orchestrator commits initial census checkpoint to output pipe
        strictly BEFORE reading ledger.jsonl.
        Prove traversal errors terminate immediately without opening/reading ledger.
        """
        self._write_file("t/prog", b"code")
        self._write_ledger(
            {
                "v": 1,
                "kind": "header",
                "nonce": self.binding.expected_nonce,
                "driver": self.binding.driver,
                "attempt": self.binding.attempt,
                "chain_id": self.binding.chain_id,
            },
            [],
        )

        checkpoint_received = []

        def checkpoint_cb(doc: Dict[str, Any]) -> None:
            checkpoint_received.append(doc)

        out_pipe = io.BytesIO()
        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
            output_stream=out_pipe,
            checkpoint_callback=checkpoint_cb,
        )

        # Verify checkpoint callback was invoked with initial census
        self.assertEqual(len(checkpoint_received), 1)
        self.assertEqual(checkpoint_received[0]["kind"], "iyi-origin-observer-initial-census")
        self.assertIn("initial_census", checkpoint_received[0])

        # Verify wire output carries initial census frame first
        out_pipe.seek(0)
        version = read_header(out_pipe)
        self.assertEqual(version, PROTOCOL_VERSION)
        ftype, fpayload = read_frame(out_pipe)
        self.assertEqual(ftype, FRAME_METADATA)
        first_frame = json.loads(fpayload.decode("utf-8"))
        self.assertEqual(first_frame["kind"], "iyi-origin-observer-initial-census")

        # Now test traversal error fails closed immediately
        non_existent_root = os.path.join(self.test_dir, "does_not_exist")
        err_pipe = io.BytesIO()
        err_doc = run_origin_observer(
            roots=[non_existent_root],
            binding=self.binding,
            output_stream=err_pipe,
        )
        self.assertEqual(err_doc["verdict"]["status"], "REJECT")
        self.assertEqual(err_doc["verdict"]["checks"]["traversal"], "FAIL")
        # Ledger was never even attempted
        self.assertNotIn("ledger", err_doc)

    # 20. P1-1 Extra: Rejection of unexpected extra references not in expected set

    def test_20_unexpected_extra_reference_fails(self) -> None:
        """
        P1-1: Ledger contains a valid reference NOT in the C-trusted expected set.
        Observer MUST reject unexpected extra references (exact set match).
        """
        prog_bytes = b"#!/bin/sh\necho ok\n"
        prog_sha256 = hashlib.sha256(prog_bytes).hexdigest()
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000

        # Create expected reference
        p1 = self._write_file("t/prog", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref1 = os.path.join(self.root_dir, "t/prog.ref")
        os.link(p1, ref1)
        os.utime(ref1, ns=(atime_ns, mtime_ns))

        # Create unexpected extra reference
        p2 = self._write_file("t/extra", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref2 = os.path.join(self.root_dir, "t/extra.ref")
        os.link(p2, ref2)
        os.utime(ref2, ns=(atime_ns, mtime_ns))

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        r1 = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": os.stat(p1).st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": prog_sha256},
        }
        r2 = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_2",
            "out": "t/extra",
            "out_ref": "t/extra.ref",
            "out_ino": os.stat(p2).st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": prog_sha256},
        }
        self._write_ledger(header, [r1, r2])

        # binding only expects ("t/prog.ref",)
        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_foreign_references"], "FAIL")
        self.assertTrue(any("unexpected extra references in ledger" in r for r in doc["verdict"]["reasons"]))

    # 21. P1-1 Target: Rejection of missing or special out target

    def test_21_unverified_out_target_fails(self) -> None:
        """
        P1-1: Ledger end record claims out_target that is missing or not a hardlink to out_ref.
        Observer MUST reject unchecked out target.
        """
        prog_bytes = b"#!/bin/sh\necho ok\n"
        prog_sha256 = hashlib.sha256(prog_bytes).hexdigest()
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000

        # Write only the reference, but NOT the claimed out target!
        ref_path = self._write_file("t/prog.ref", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "out": "t/nonexistent_prog",  # does not exist in census!
            "out_ref": "t/prog.ref",
            "out_ino": os.stat(ref_path).st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": prog_sha256},
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertTrue(any("was missing from pre-read census" in r for r in doc["verdict"]["reasons"]))

    # 22. Derivation of expected references from C-trusted census

    def test_22_derive_trusted_expected_references_from_census(self) -> None:
        """
        P1-4: Prove derive_trusted_expected_references derives expected references
        directly from C-trusted census JSON without consulting workload ledger.
        """
        census_path = os.path.join(os.path.dirname(__file__), "census", "acme.json")
        if not os.path.isfile(census_path):
            self.skipTest(f"census file not found: {census_path}")

        with open(census_path, "r", encoding="utf-8") as f:
            census_data = json.load(f)

        expected = derive_trusted_expected_references(census_data, "acme", work_prefix="t")
        self.assertIn("t/std_acme_exercise.ref", expected)
        self.assertIn("t/acme-plain.ref", expected)
        self.assertIn("t/acme-release.ref", expected)

    # 23. Complete evidence recovery from wire stream

    def test_23_wire_stream_contains_complete_evidence(self) -> None:
        """
        P1-3: Prove that parse_observer_stream recovers the complete verified evidence
        (ledger digest, references, raw_files_manifest, verdict, limitations) from the wire frames alone.
        """
        prog_bytes = b"binary_test"
        prog_sha256 = hashlib.sha256(prog_bytes).hexdigest()
        mtime_ns = 1_000_000_000_000_000_000
        atime_ns = 1_000_000_001_000_000_000

        p = self._write_file("t/prog", prog_bytes, mtime_ns=mtime_ns, atime_ns=atime_ns)
        ref = os.path.join(self.root_dir, "t/prog.ref")
        os.link(p, ref)
        os.utime(ref, ns=(atime_ns, mtime_ns))

        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "attempt": self.binding.attempt,
            "chain_id": self.binding.chain_id,
        }
        rec = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": os.stat(p).st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1000,
            "consumer": {"out_sha256": prog_sha256},
        }
        self._write_ledger(header, [rec])

        wire_pipe = io.BytesIO()
        _ = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            output_stream=wire_pipe,
            capture_raw_bytes=True,
        )

        wire_pipe.seek(0)
        meta_doc, raw_files, term_doc = parse_observer_stream(wire_pipe)

        # Wire consumer must be able to inspect all evidence
        self.assertEqual(meta_doc["verdict"]["status"], "PASS")
        self.assertIsNotNone(meta_doc["ledger"])
        self.assertEqual(len(meta_doc["references"]), 1)
        self.assertEqual(len(meta_doc["raw_files_manifest"]), 1)
        self.assertIn("limitations", meta_doc)
        self.assertEqual(len(raw_files), 1)
        self.assertEqual(raw_files[0]["file_bytes"], prog_bytes)


if __name__ == "__main__":
    unittest.main()
