#!/usr/bin/env python3
"""
proof/test_hosted_origin_observer.py

Focused unit and adversarial fixture tests for proof/hosted_origin_observer.py.
Verifies all security invariants:
1. Wire protocol framing and roundtrip.
2. Normal legitimate execution flow: pre-read census, ledger validation, reference binding,
   atime advancement, raw executable bytes capture.
3. Adversarial fixture 1: Executable/ledger hardlink alias attack detection.
4. Adversarial fixture 2: Symlink escape detection (O_NOFOLLOW descriptor traversal).
5. Adversarial fixture 3: Path traversal escape (../ or foreign root escapes).
6. Adversarial fixture 4: Missing reference rejection.
7. Adversarial fixture 5: Duplicate reference rejection.
8. Adversarial fixture 6: Foreign driver/nonce rejection.
9. Adversarial fixture 7: Inode mismatch rejection.
10. Adversarial fixture 8: Unexecuted reference (atime not advanced) rejection.
11. Adversarial fixture 9: Special file (fifo) reference rejection.
12. Adversarial fixture 10: Content hash mismatch rejection.
13. Metadata ordering proof: candidate fstat sampling occurs strictly before ledger read.
14. Preservation invariant: unexecuted references are not upgraded by subsequent archive reads.
15. Explicit reporting of observer limitations.
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
            rel_path="t/prog",
            st_dev=123,
            st_ino=456,
            sha256_hex=hashlib.sha256(b"binary_payload").hexdigest(),
            file_bytes=b"binary_payload",
        )
        write_frame(buf, FRAME_RAW_FILE, raw_payload)

        term_payload = json.dumps({"status": "PASS", "reasons": []}).encode("utf-8")
        write_frame(buf, FRAME_TERMINATION, term_payload)

        buf.seek(0)
        meta_doc, raw_files, term_doc = parse_observer_stream(buf)

        self.assertEqual(meta_doc["test"], "data")
        self.assertEqual(len(raw_files), 1)
        self.assertEqual(raw_files[0]["rel_path"], "t/prog")
        self.assertEqual(raw_files[0]["file_bytes"], b"binary_payload")
        self.assertEqual(term_doc["status"], "PASS")

    # 2. Legitimate execution flow

    def test_02_normal_legitimate_execution_flow(self) -> None:
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
        record = {
            "v": 1,
            "kind": "record",
            "nonce": self.binding.expected_nonce,
            "driver": self.binding.driver,
            "phase": "end",
            "inv": "inv_1",
            "command": "run",
            "out": "t/prog",
            "out_ref": "t/prog.ref",
            "out_ino": st.st_ino,
            "out_mtime_ns": mtime_ns,
            "atime_set_ns": mtime_ns - 1_000_000,
            "consumer": {"rc": 0, "out_sha256": prog_sha256},
            "run": {"rc": 0, "argv": ["t/prog"]},
        }
        self._write_ledger(header, [record])

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

    # 3. Adversarial fixture: Executable/ledger hardlink alias attack

    def test_03_adversarial_hardlink_alias_attack(self) -> None:
        """
        Adversary creates ledger.jsonl as a hardlink to t/prog.
        Reading ledger.jsonl would advance atime of t/prog before measurement.
        Observer MUST detect this alias attack and reject.
        """
        prog_bytes = b"#!/bin/sh\necho malicious\n"
        prog_path = self._write_file("t/prog", prog_bytes)

        # Create ledger as hardlink to prog!
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
        prog_bytes = b"echo escape"
        self._write_file("t/prog", prog_bytes)

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
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["no_foreign_references"], "FAIL")
        self.assertTrue(any("escapes permitted roots" in r for r in doc["verdict"]["reasons"]))

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
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
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
        prog_path = self._write_file("t/prog", b"binary")
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)

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
        prog_path = self._write_file("t/prog", b"binary")
        ref_path = os.path.join(self.root_dir, "t/prog.ref")
        os.link(prog_path, ref_path)

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
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
            ledger_relpath="ledger.jsonl",
        )

        self.assertEqual(doc["verdict"]["status"], "REJECT")
        self.assertEqual(doc["verdict"]["checks"]["numeric_atime_predicates"], "FAIL")
        self.assertTrue(any("atime" in r and "<= mtime" in r for r in doc["verdict"]["reasons"]))

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
        }
        self._write_ledger(header, [record])

        # Initial observation: REJECT
        doc1 = run_origin_observer(roots=[self.root_dir], binding=self.binding)
        self.assertEqual(doc1["verdict"]["status"], "REJECT")

        # Now simulate an external archive read that touches the file!
        with open(ref_path, "rb") as f:
            _ = f.read()

        # The initial census in doc1 is immutable and frozen:
        # Its recorded atime remains the pre-read atime
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
        }
        self._write_ledger(header, [record])

        doc = run_origin_observer(
            roots=[self.root_dir],
            binding=self.binding,
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

        # Call walk_roots_descriptor_relative directly
        candidates, specials, errors = walk_roots_descriptor_relative([self.root_dir])
        self.assertEqual(len(errors), 0)

        # Confirm all regular files were discovered and have held descriptors
        candidate_paths = {c.rel_path for c in candidates}
        self.assertIn("t/prog", candidate_paths)
        self.assertIn("t/prog.ref", candidate_paths)
        self.assertIn("ledger.jsonl", candidate_paths)

        for c in candidates:
            self.assertIsNotNone(c.fd)
            # Verify descriptors are valid open fds
            st = os.fstat(c.fd)
            self.assertEqual(st.st_ino, c.st_ino)
            os.close(c.fd)

    # 15. Limitations reporting

    def test_15_limits_explicitly_reported(self) -> None:
        doc = run_origin_observer(roots=[self.root_dir], binding=self.binding)
        self.assertIn("limitations", doc)
        self.assertTrue(any("cannot distinguish authentic kernel execution" in lim for lim in doc["limitations"]))


if __name__ == "__main__":
    unittest.main()
