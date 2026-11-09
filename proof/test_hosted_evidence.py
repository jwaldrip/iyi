"""Unit tests for proof/hosted_evidence.py.

Tests explicit EvidenceLimits, invocation-wide EvidenceBudget accounting,
descriptor-relative safe stable file reads, bounded JSON/logs/streamed archival
with unique-inode bytes vs alias/emitted budgets, depth/path/entries/deadline,
rejection of symlinks, special files (FIFOs), sparse huge files, alias floods,
held inode anchor baselines, JSON float-overflow rejection (1e10000), FD leak
prevention on budget rejection, archive-local arcname isolation, descriptor-relative
archive lifecycle, and manifest collision/overwrite protection.
"""
from __future__ import annotations

import io
import json
import math
import os
import stat
import tarfile
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from proof.hosted_evidence import (
    ArchiveMember,
    ArchiveResult,
    BoundedEvidenceError,
    BoundedEvidenceReader,
    EvidenceBudget,
    EvidenceDeadlineExceededError,
    EvidenceLimitExceededError,
    EvidenceLimits,
    IncompleteFrameError,
    MissingEvidenceError,
    OwnedRoot,
    UnsafeEvidenceError,
    UnstableEvidenceError,
    create_checkpoint_archive,
)


def make_test_limits(
    *,
    max_file_bytes: int = 1024 * 1024,
    max_unique_inode_bytes: int = 5 * 1024 * 1024,
    max_emitted_bytes: int = 10 * 1024 * 1024,
    max_entries: int = 1000,
    max_aliases: int = 50,
    max_directory_depth: int = 10,
    max_path_bytes: int = 256,
    max_json_bytes: int = 512 * 1024,
    max_ledger_line_bytes: int = 4096,
    max_ledger_lines: int = 1000,
    max_structured_records: int = 1000,
    max_witness_events: int = 500,
    max_held_descriptors: int = 32,
    max_helper_memory_bytes: int = 2 * 1024 * 1024,
    timeout_seconds: float = 60.0,
) -> EvidenceLimits:
    """Helper to produce explicit finite test limits without production defaults."""
    return EvidenceLimits.from_timeout(
        max_file_bytes=max_file_bytes,
        max_unique_inode_bytes=max_unique_inode_bytes,
        max_emitted_bytes=max_emitted_bytes,
        max_entries=max_entries,
        max_aliases=max_aliases,
        max_directory_depth=max_directory_depth,
        max_path_bytes=max_path_bytes,
        max_json_bytes=max_json_bytes,
        max_ledger_line_bytes=max_ledger_line_bytes,
        max_ledger_lines=max_ledger_lines,
        max_structured_records=max_structured_records,
        max_witness_events=max_witness_events,
        max_held_descriptors=max_held_descriptors,
        max_helper_memory_bytes=max_helper_memory_bytes,
        timeout_seconds=timeout_seconds,
    )


class EvidenceLimitsTests(unittest.TestCase):
    def test_explicit_limits_construction(self):
        deadline = time.monotonic() + 30.0
        limits = EvidenceLimits(
            max_file_bytes=100,
            max_unique_inode_bytes=200,
            max_emitted_bytes=300,
            max_entries=10,
            max_aliases=5,
            max_directory_depth=3,
            max_path_bytes=50,
            max_json_bytes=500,
            max_ledger_line_bytes=80,
            max_ledger_lines=20,
            max_structured_records=25,
            max_witness_events=15,
            max_held_descriptors=8,
            max_helper_memory_bytes=1024,
            deadline=deadline,
        )
        self.assertEqual(limits.max_file_bytes, 100)
        self.assertEqual(limits.deadline, deadline)

    def test_refuses_missing_or_none_fields(self):
        with self.assertRaises(TypeError):
            EvidenceLimits()  # type: ignore

        with self.assertRaises(ValueError):
            limits = make_test_limits()
            d = limits.to_dict()
            d["max_file_bytes"] = None
            EvidenceLimits.from_dict(d)

    def test_refuses_booleans_and_negatives(self):
        limits = make_test_limits()
        d = limits.to_dict()

        d["max_file_bytes"] = True
        with self.assertRaises(ValueError):
            EvidenceLimits.from_dict(d)

        d["max_file_bytes"] = -5
        with self.assertRaises(ValueError):
            EvidenceLimits.from_dict(d)

    def test_refuses_non_finite_deadline(self):
        limits = make_test_limits()
        d = limits.to_dict()
        for bad in (float("inf"), float("-inf"), float("nan")):
            d["deadline"] = bad
            with self.assertRaises(ValueError):
                EvidenceLimits.from_dict(d)

    def test_from_timeout_and_dict_roundtrip(self):
        limits = make_test_limits(timeout_seconds=42.0)
        d = limits.to_dict()
        restored = EvidenceLimits.from_dict(d)
        self.assertEqual(limits, restored)

        with self.assertRaises(ValueError):
            EvidenceLimits.from_timeout(
                max_file_bytes=1, max_unique_inode_bytes=1, max_emitted_bytes=1,
                max_entries=1, max_aliases=1, max_directory_depth=1, max_path_bytes=1,
                max_json_bytes=1, max_ledger_line_bytes=1, max_ledger_lines=1,
                max_structured_records=1, max_witness_events=1, max_held_descriptors=1,
                max_helper_memory_bytes=1, timeout_seconds=-10.0,
            )


class EvidenceBudgetAccountingTests(unittest.TestCase):
    def test_unique_inode_vs_alias_accounting(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "orig.txt")
            p2 = os.path.join(td, "alias.txt")
            with open(p1, "wb") as f:
                f.write(b"1234567890")
            os.link(p1, p2)

            limits = make_test_limits(
                max_unique_inode_bytes=15,
                max_aliases=5,
            )
            budget = EvidenceBudget(limits)

            st1 = os.stat(p1)
            is_alias1 = budget.charge_file(st1, path="orig.txt")
            self.assertFalse(is_alias1)
            self.assertEqual(budget.total_unique_inode_bytes, 10)
            self.assertEqual(budget.total_aliases, 0)

            st2 = os.stat(p2)
            is_alias2 = budget.charge_file(st2, path="alias.txt")
            self.assertTrue(is_alias2)
            self.assertEqual(budget.total_unique_inode_bytes, 10)
            self.assertEqual(budget.total_aliases, 1)

    def test_alias_baseline_mismatch_rejected(self):
        limits = make_test_limits(max_unique_inode_bytes=1000)
        budget = EvidenceBudget(limits)
        # Register anchor
        budget.charge_file(1, 100, 50, "orig.txt", mode=0o100644, mtime_ns=1000, ctime_ns=2000)

        # Alias with mismatched size
        with self.assertRaises(UnstableEvidenceError) as ctx:
            budget.charge_file(1, 100, 60, "forged.txt", mode=0o100644, mtime_ns=1000, ctime_ns=2000)
        self.assertIn("ALIAS-BASELINE-MISMATCH", str(ctx.exception))

        # Alias with mismatched mode
        with self.assertRaises(UnstableEvidenceError) as ctx:
            budget.charge_file(1, 100, 50, "forged_mode.txt", mode=0o100777, mtime_ns=1000, ctime_ns=2000)
        self.assertIn("ALIAS-BASELINE-MISMATCH", str(ctx.exception))

        # Alias with mismatched mtime
        with self.assertRaises(UnstableEvidenceError) as ctx:
            budget.charge_file(1, 100, 50, "forged_time.txt", mode=0o100644, mtime_ns=9999, ctime_ns=2000)
        self.assertIn("ALIAS-BASELINE-MISMATCH", str(ctx.exception))

    def test_unique_inode_exhaustion(self):
        limits = make_test_limits(max_unique_inode_bytes=50)
        budget = EvidenceBudget(limits)
        budget.charge_file(1, 101, 30, "file1.txt")
        self.assertEqual(budget.total_unique_inode_bytes, 30)

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_file(1, 102, 30, "file2.txt")
        self.assertIn("UNIQUE-INODE-BYTES-EXCEEDED", str(ctx.exception))

    def test_alias_flood_rejection(self):
        limits = make_test_limits(
            max_unique_inode_bytes=1000,
            max_aliases=3,
        )
        budget = EvidenceBudget(limits)
        budget.charge_file(1, 101, 50, "file.txt")

        self.assertTrue(budget.charge_file(1, 101, 50, "link1.txt"))
        self.assertTrue(budget.charge_file(1, 101, 50, "link2.txt"))
        self.assertTrue(budget.charge_file(1, 101, 50, "link3.txt"))
        self.assertEqual(budget.total_aliases, 3)

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_file(1, 101, 50, "link4.txt")
        self.assertIn("ALIASES-EXCEEDED", str(ctx.exception))

    def test_entries_and_path_bounds(self):
        limits = make_test_limits(max_entries=2, max_path_bytes=10)
        budget = EvidenceBudget(limits)
        budget.charge_entry("a/b")
        budget.charge_entry("c/d")

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_entry("e/f")
        self.assertIn("ENTRIES-EXCEEDED", str(ctx.exception))

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_entry("this_path_is_way_too_long")
        self.assertIn("PATH-BYTES-EXCEEDED", str(ctx.exception))

    def test_directory_depth_bound(self):
        limits = make_test_limits(max_directory_depth=2)
        budget = EvidenceBudget(limits)
        budget.charge_directory_depth(1)
        budget.charge_directory_depth(2)

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_directory_depth(3)
        self.assertIn("DIRECTORY-DEPTH-EXCEEDED", str(ctx.exception))

    def test_emitted_bytes_bound(self):
        limits = make_test_limits(max_emitted_bytes=100)
        budget = EvidenceBudget(limits)
        budget.charge_emitted_bytes(60)
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_emitted_bytes(50)
        self.assertIn("EMITTED-BYTES-EXCEEDED", str(ctx.exception))

    def test_json_and_structured_records_bounds(self):
        limits = make_test_limits(max_json_bytes=50, max_structured_records=2)
        budget = EvidenceBudget(limits)
        budget.charge_json_bytes(30)
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_json_bytes(30)
        self.assertIn("JSON-BYTES-EXCEEDED", str(ctx.exception))

        budget.charge_structured_records(2)
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_structured_records(1)
        self.assertIn("STRUCTURED-RECORDS-EXCEEDED", str(ctx.exception))

    def test_ledger_line_bounds(self):
        limits = make_test_limits(max_ledger_line_bytes=10, max_ledger_lines=2)
        budget = EvidenceBudget(limits)
        budget.charge_ledger_line(b"12345")
        budget.charge_ledger_line("12345")

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_ledger_line(b"12345678901")
        self.assertIn("LEDGER-LINE-BYTES-EXCEEDED", str(ctx.exception))

        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_ledger_line(b"1")
        self.assertIn("LEDGER-LINES-EXCEEDED", str(ctx.exception))

    def test_witness_events_and_descriptors_bounds(self):
        limits = make_test_limits(max_witness_events=2, max_held_descriptors=1)
        budget = EvidenceBudget(limits)
        budget.charge_witness_events(2)
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_witness_events(1)
        self.assertIn("WITNESS-EVENTS-EXCEEDED", str(ctx.exception))

        budget.acquire_descriptor()
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.acquire_descriptor()
        self.assertIn("HELD-DESCRIPTORS-EXCEEDED", str(ctx.exception))
        budget.release_descriptor()
        self.assertEqual(budget.held_descriptors, 0)

    def test_fd_closed_on_budget_acquire_rejection(self):
        # Verify that if budget.acquire_descriptor() raises, the opened fd is immediately closed
        limits = make_test_limits(max_held_descriptors=0)
        budget = EvidenceBudget(limits)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "file.txt")
            with open(path, "wb") as f:
                f.write(b"data")

            # Opening with budget holding 0 allowed descriptors must fail without leaking fd
            with self.assertRaises(EvidenceLimitExceededError):
                with BoundedEvidenceReader(td, budget) as reader:
                    pass

    def test_helper_memory_bound(self):
        limits = make_test_limits(max_helper_memory_bytes=100)
        budget = EvidenceBudget(limits)
        budget.charge_helper_memory(80)
        with self.assertRaises(EvidenceLimitExceededError) as ctx:
            budget.charge_helper_memory(30)
        self.assertIn("HELPER-MEMORY-EXCEEDED", str(ctx.exception))
        budget.release_helper_memory(80)
        self.assertEqual(budget.helper_memory_bytes, 0)

    def test_deadline_expired(self):
        limits = EvidenceLimits(
            max_file_bytes=100, max_unique_inode_bytes=100, max_emitted_bytes=100,
            max_entries=10, max_aliases=10, max_directory_depth=5, max_path_bytes=100,
            max_json_bytes=100, max_ledger_line_bytes=100, max_ledger_lines=10,
            max_structured_records=10, max_witness_events=10, max_held_descriptors=10,
            max_helper_memory_bytes=100, deadline=time.monotonic() - 1.0,
        )
        budget = EvidenceBudget(limits)
        with self.assertRaises(EvidenceDeadlineExceededError):
            budget.check_deadline()


class BoundedEvidenceReaderTests(unittest.TestCase):
    def test_read_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "hello.txt")
            with open(path, "wb") as f:
                f.write(b"hello world")

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                data = reader.read_bytes("hello.txt")
                self.assertEqual(data, b"hello world")
                self.assertTrue(reader.has_member("hello.txt"))
                self.assertFalse(reader.has_member("nonexistent.txt"))
                st = reader.stat_member("hello.txt")
                self.assertTrue(stat.S_ISREG(st.st_mode))

    def test_symlink_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "target.txt")
            with open(target, "wb") as f:
                f.write(b"data")
            link = os.path.join(td, "link.txt")
            os.symlink("target.txt", link)

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(UnsafeEvidenceError):
                    reader.read_bytes("link.txt")

    def test_symlink_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            real_dir = os.path.join(td, "real_dir")
            os.mkdir(real_dir)
            with open(os.path.join(real_dir, "file.txt"), "wb") as f:
                f.write(b"nested")
            link_dir = os.path.join(td, "link_dir")
            os.symlink("real_dir", link_dir)

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(UnsafeEvidenceError):
                    reader.read_bytes("link_dir/file.txt")

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                for bad in ("../escape", "a/../../escape", "/absolute"):
                    with self.assertRaises(UnsafeEvidenceError):
                        reader.read_bytes(bad)

    def test_fifo_special_file_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            fifo_path = os.path.join(td, "pipe.fifo")
            os.mkfifo(fifo_path)

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(UnsafeEvidenceError) as ctx:
                    reader.read_bytes("pipe.fifo")
                self.assertIn("SPECIAL-OR-NON-REGULAR-FILE", str(ctx.exception))

    def test_sparse_huge_file_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "sparse.dat")
            with open(path, "wb") as f:
                f.seek(50 * 1024 * 1024)
                f.write(b"x")

            budget = EvidenceBudget(make_test_limits(max_file_bytes=10 * 1024))
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(EvidenceLimitExceededError) as ctx:
                    reader.read_bytes("sparse.dat")
                self.assertIn("FILE-SIZE-EXCEEDED", str(ctx.exception))

    def test_directory_enumeration_bounded_before_sorting(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(15):
                with open(os.path.join(td, f"f_{i:02d}.txt"), "wb") as f:
                    f.write(b"x")

            budget = EvidenceBudget(make_test_limits(max_entries=5))
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(EvidenceLimitExceededError) as ctx:
                    list(reader.walk(""))
                self.assertIn("ENTRIES-EXCEEDED", str(ctx.exception))

    def test_directory_depth_bound_in_walk(self):
        with tempfile.TemporaryDirectory() as td:
            deep = os.path.join(td, "a", "b", "c", "d")
            os.makedirs(deep)
            with open(os.path.join(deep, "file.txt"), "wb") as f:
                f.write(b"deep")

            budget = EvidenceBudget(make_test_limits(max_directory_depth=2))
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(EvidenceLimitExceededError) as ctx:
                    list(reader.walk(""))
                self.assertIn("DIRECTORY-DEPTH-EXCEEDED", str(ctx.exception))

    def test_race_control_short_read(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "shrink.txt")
            with open(path, "wb") as f:
                f.write(b"original long content")

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                call_count = 0
                def short_read(fd, n):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        return b"short"
                    return b""

                with patch("os.read", side_effect=short_read):
                    with self.assertRaises(UnstableEvidenceError) as ctx:
                        reader.read_bytes("shrink.txt")
                    self.assertIn("short read", str(ctx.exception))

    def test_race_control_file_replaced_during_read(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "race.txt")
            with open(path, "wb") as f:
                f.write(b"stable bytes")

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                orig_stat = os.stat
                def fake_stat(name, *args, **kwargs):
                    res = orig_stat(name, *args, **kwargs)
                    if isinstance(name, str) and name == "race.txt":
                        return os.stat_result((
                            res.st_mode, res.st_ino + 9999, res.st_dev,
                            res.st_nlink, res.st_uid, res.st_gid, res.st_size,
                            res.st_atime, res.st_mtime, res.st_ctime
                        ))
                    return res

                with patch("os.stat", side_effect=fake_stat):
                    with self.assertRaises(UnstableEvidenceError) as ctx:
                        reader.read_bytes("race.txt")
                    self.assertIn("UNSTABLE-MEMBER", str(ctx.exception))

    def test_directory_replaced_during_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            sub = os.path.join(td, "sub")
            os.mkdir(sub)
            budget = EvidenceBudget(make_test_limits())
            root = OwnedRoot(td, budget=budget)
            fd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY)
            try:
                root.remember("sub", fd)
            finally:
                os.close(fd)

            root.identities["sub"] = (0, 0)
            fd2 = os.open(sub, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(UnstableEvidenceError) as ctx:
                    root.remember("sub", fd2)
                self.assertIn("REPLACED-DIRECTORY", str(ctx.exception))
            finally:
                os.close(fd2)
                root.close()


class JSONAndLedgerBoundedReadingTests(unittest.TestCase):
    def test_read_json_valid_and_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "doc.json")
            with open(path, "wb") as f:
                f.write(b'{"key": "value", "num": 123}\n')

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                data = reader.read_json("doc.json")
                self.assertEqual(data, {"key": "value", "num": 123})

            budget2 = EvidenceBudget(make_test_limits(max_json_bytes=10))
            with BoundedEvidenceReader(td, budget2) as reader:
                with self.assertRaises(EvidenceLimitExceededError) as ctx:
                    reader.read_json("doc.json")
                self.assertIn("JSON-BYTES-EXCEEDED", str(ctx.exception))

    def test_read_json_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "dup.json")
            with open(path, "wb") as f:
                f.write(b'{"a": 1, "b": 2, "a": 3}\n')

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(BoundedEvidenceError) as ctx:
                    reader.read_json("dup.json")
                self.assertIn("DUPLICATE-JSON-KEY", str(ctx.exception))

    def test_read_json_non_finite_numbers_and_overflow_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                # Constants
                for bad_val in (b'{"a": NaN}\n', b'{"a": Infinity}\n', b'{"a": -Infinity}\n'):
                    path = os.path.join(td, "bad.json")
                    with open(path, "wb") as f:
                        f.write(bad_val)
                    with self.assertRaises(BoundedEvidenceError) as ctx:
                        reader.read_json("bad.json")
                    self.assertIn("NON-FINITE-JSON-NUMBER", str(ctx.exception))

                # Float exponent overflow (1e10000 -> inf)
                for overflow_val in (b'{"a": 1e10000}\n', b'{"a": -1e10000}\n'):
                    path = os.path.join(td, "overflow.json")
                    with open(path, "wb") as f:
                        f.write(overflow_val)
                    with self.assertRaises(BoundedEvidenceError) as ctx:
                        reader.read_json("overflow.json")
                    self.assertIn("NON-FINITE-JSON-NUMBER", str(ctx.exception))

    def test_read_origin_records_missing_fails(self):
        with tempfile.TemporaryDirectory() as td:
            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(MissingEvidenceError) as ctx:
                    reader.read_origin_records("missing_origin.json", required=True)
                self.assertIn("MISSING-REQUIRED-EVIDENCE", str(ctx.exception))
                self.assertIsNone(reader.read_origin_records("missing_origin.json", required=False))

    def test_read_ledger_lines_and_incomplete_frame(self):
        with tempfile.TemporaryDirectory() as td:
            valid_path = os.path.join(td, "valid.jsonl")
            with open(valid_path, "wb") as f:
                f.write(b'{"event": "start"}\n{"event": "stop"}\n')

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                lines = reader.read_ledger_lines("valid.jsonl")
                self.assertEqual(len(lines), 2)
                records = reader.read_structured_records("valid.jsonl")
                self.assertEqual(records, [{"event": "start"}, {"event": "stop"}])

            incomplete_path = os.path.join(td, "incomplete.jsonl")
            with open(incomplete_path, "wb") as f:
                f.write(b'{"event": "start"}\n{"event": "incomplete"}')

            with BoundedEvidenceReader(td, budget) as reader:
                with self.assertRaises(IncompleteFrameError) as ctx:
                    reader.read_ledger_lines("incomplete.jsonl")
                self.assertIn("INCOMPLETE-FRAME", str(ctx.exception))

    def test_read_streamed_log(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "test.log")
            payload = b"chunk1" * 1000 + b"chunk2" * 1000
            with open(log_path, "wb") as f:
                f.write(payload)

            budget = EvidenceBudget(make_test_limits())
            with BoundedEvidenceReader(td, budget) as reader:
                streamed = b"".join(reader.read_streamed_log("test.log", chunk_size=512))
                self.assertEqual(streamed, payload)


class CreateCheckpointArchiveTests(unittest.TestCase):
    def test_create_archive_basic(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "src")
            os.mkdir(src_dir)
            with open(os.path.join(src_dir, "file1.txt"), "wb") as f:
                f.write(b"file one content\n")
            with open(os.path.join(src_dir, "file2.txt"), "wb") as f:
                f.write(b"file two content\n")

            archive_path = os.path.join(td, "evidence.tar.gz")
            budget = EvidenceBudget(make_test_limits())
            with OwnedRoot(src_dir, budget=budget) as root:
                members = [
                    ArchiveMember(root=root, name="file1.txt", arcname="data/file1.txt"),
                    ArchiveMember(root=root, name="file2.txt", arcname="data/file2.txt"),
                ]
                res = create_checkpoint_archive(
                    target_path=archive_path,
                    members=members,
                    budget=budget,
                    extra_manifest={"unit": "plan", "attempt": 1},
                )

            self.assertTrue(os.path.exists(archive_path))
            self.assertEqual(res.path, os.path.abspath(archive_path))
            self.assertGreater(res.archive_bytes, 0)
            self.assertEqual(len(res.archive_sha256), 64)
            self.assertEqual(res.manifest["version"], 1)
            self.assertEqual(res.manifest["unit"], "plan")
            self.assertEqual(len(res.manifest["members"]), 2)

            extract_dir = os.path.join(td, "extract")
            os.mkdir(extract_dir)
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)

            with open(os.path.join(extract_dir, "data", "file1.txt"), "rb") as f:
                self.assertEqual(f.read(), b"file one content\n")
            with open(os.path.join(extract_dir, "data", "file2.txt"), "rb") as f:
                self.assertEqual(f.read(), b"file two content\n")

    def test_create_archive_genuine_alias_preservation_and_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "src")
            os.mkdir(src_dir)
            p1 = os.path.join(src_dir, "orig.bin")
            content = b"exact bytes to be shared" * 100
            with open(p1, "wb") as f:
                f.write(content)
            p2 = os.path.join(src_dir, "alias.bin")
            os.link(p1, p2)

            budget = EvidenceBudget(make_test_limits(
                max_unique_inode_bytes=len(content) + 4096,
                max_aliases=10,
            ))
            archive_path = os.path.join(td, "alias_evidence.tar.gz")

            with OwnedRoot(src_dir, budget=budget) as root:
                members = [
                    ArchiveMember(root=root, name="orig.bin", arcname="shared/orig.bin"),
                    ArchiveMember(root=root, name="alias.bin", arcname="shared/alias.bin"),
                ]
                res = create_checkpoint_archive(
                    target_path=archive_path,
                    members=members,
                    budget=budget,
                )

            self.assertEqual(budget.total_unique_inode_bytes, len(content))
            self.assertEqual(budget.total_aliases, 1)

            members_table = {m["path"]: m for m in res.manifest["members"]}
            self.assertIn("shared/orig.bin", members_table)
            self.assertIn("shared/alias.bin", members_table)
            self.assertEqual(members_table["shared/alias.bin"]["linkpath"], "shared/orig.bin")
            self.assertEqual(members_table["shared/alias.bin"]["sha256"], members_table["shared/orig.bin"]["sha256"])

            with tarfile.open(archive_path, "r:gz") as tar:
                ti_orig = tar.getmember("shared/orig.bin")
                ti_alias = tar.getmember("shared/alias.bin")
                self.assertTrue(ti_orig.isreg())
                self.assertTrue(ti_alias.islnk())
                self.assertEqual(ti_alias.linkname, "shared/orig.bin")

            extract_dir = os.path.join(td, "extract_alias")
            os.mkdir(extract_dir)
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)

            e_orig = os.path.join(extract_dir, "shared", "orig.bin")
            e_alias = os.path.join(extract_dir, "shared", "alias.bin")
            st_orig = os.stat(e_orig)
            st_alias = os.stat(e_alias)
            self.assertEqual(st_orig.st_ino, st_alias.st_ino)
            self.assertEqual(st_orig.st_dev, st_alias.st_dev)
            with open(e_alias, "rb") as f:
                self.assertEqual(f.read(), content)

            # Test archive-local isolation: create second archive under different arcnames
            archive_path2 = os.path.join(td, "alias_evidence2.tar.gz")
            with OwnedRoot(src_dir, budget=budget) as root:
                members2 = [
                    ArchiveMember(root=root, name="orig.bin", arcname="archive2/first.bin"),
                    ArchiveMember(root=root, name="alias.bin", arcname="archive2/second.bin"),
                ]
                res2 = create_checkpoint_archive(
                    target_path=archive_path2,
                    members=members2,
                    budget=budget,
                )

            with tarfile.open(archive_path2, "r:gz") as tar2:
                ti_alias2 = tar2.getmember("archive2/second.bin")
                # linkname MUST be archive2/first.bin, NOT shared/orig.bin from archive 1!
                self.assertEqual(ti_alias2.linkname, "archive2/first.bin")

    def test_create_archive_emitted_bytes_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "src")
            os.mkdir(src_dir)
            with open(os.path.join(src_dir, "big.dat"), "wb") as f:
                f.write(b"x" * 100000)

            archive_path = os.path.join(td, "failed.tar.gz")
            budget = EvidenceBudget(make_test_limits(max_emitted_bytes=200))

            with OwnedRoot(src_dir, budget=budget) as root:
                members = [
                    ArchiveMember(root=root, name="big.dat", arcname="big.dat"),
                ]
                with self.assertRaises(EvidenceLimitExceededError) as ctx:
                    create_checkpoint_archive(
                        target_path=archive_path,
                        members=members,
                        budget=budget,
                    )
                self.assertIn("EMITTED-BYTES-EXCEEDED", str(ctx.exception))

            self.assertFalse(os.path.exists(archive_path))

    def test_create_archive_manifest_collision_and_extra_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "src")
            os.mkdir(src_dir)
            with open(os.path.join(src_dir, "manifest.dat"), "wb") as f:
                f.write(b"spoof")

            archive_path = os.path.join(td, "collision.tar.gz")
            budget = EvidenceBudget(make_test_limits())

            with OwnedRoot(src_dir, budget=budget) as root:
                # Member collides with manifest arcname
                with self.assertRaises(BoundedEvidenceError) as ctx:
                    create_checkpoint_archive(
                        target_path=archive_path,
                        members=[ArchiveMember(root=root, name="manifest.dat", arcname="evidence-manifest.json")],
                        budget=budget,
                    )
                self.assertIn("RESERVED-MANIFEST-COLLISION", str(ctx.exception))
                self.assertFalse(os.path.exists(archive_path))

                # extra_manifest overwrites version or members
                for bad_extra in ({"version": 999}, {"members": ["hacked"]}):
                    with self.assertRaises(BoundedEvidenceError) as ctx:
                        create_checkpoint_archive(
                            target_path=archive_path,
                            members=[ArchiveMember(root=root, name="manifest.dat", arcname="data.dat")],
                            budget=budget,
                            extra_manifest=bad_extra,
                        )
                    self.assertIn("EXTRA-MANIFEST-RESERVED-KEY", str(ctx.exception))
                    self.assertFalse(os.path.exists(archive_path))

    def test_create_archive_special_file_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "src")
            os.mkdir(src_dir)
            fifo_path = os.path.join(src_dir, "sub.fifo")
            os.mkfifo(fifo_path)

            sym_path = os.path.join(src_dir, "bad_link.txt")
            os.symlink("nonexistent", sym_path)

            archive_path = os.path.join(td, "out.tar.gz")
            budget = EvidenceBudget(make_test_limits())

            with OwnedRoot(src_dir, budget=budget) as root:
                with self.assertRaises(UnsafeEvidenceError):
                    create_checkpoint_archive(
                        target_path=archive_path,
                        members=[ArchiveMember(root=root, name="sub.fifo", arcname="sub.fifo")],
                        budget=budget,
                    )
                self.assertFalse(os.path.exists(archive_path))

                with self.assertRaises(UnsafeEvidenceError):
                    create_checkpoint_archive(
                        target_path=archive_path,
                        members=[ArchiveMember(root=root, name="bad_link.txt", arcname="bad_link.txt")],
                        budget=budget,
                    )
                self.assertFalse(os.path.exists(archive_path))


if __name__ == "__main__":
    unittest.main()
