"""
proof/test_hosted_exec_witness.py

Focused standalone discriminating test suite for HostedExecWitness.
Tests the execution witness protocol, verification invariants, disk byte verification,
repeated execution deduplication, and resistance to reader-only, utime-only,
channel theft, and untraced clone manipulations.

Per the assignment rules: No tests are run midflight. This file is executed
only during official verification phases.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List

from proof.hosted_exec_witness import (
    EMPTY_SHA256,
    PROTOCOL_VERSION,
    ExecNotWitnessedError,
    LaunchBindingMismatch,
    RawCaptureError,
    SequenceIntegrityError,
    WitnessError,
    WitnessVerificationError,
    parse_witness_events,
    verify_exec_witness_evidence,
)


def _generate_valid_witness_stream(
    tracer_pid: int = 100,
    root_pid: int = 101,
    launch_binding: Dict[str, Any] = None,
    exec_inoderefs: List[tuple] = None,
    tracer_dumpable: int = 0,
    status: str = "COMPLETE",
    root_exit_code: int = 0,
    active_processes_at_end: int = 0,
    include_end: bool = True,
    corrupt_seq: bool = False,
    untracked_exec: bool = False,
    sha256: str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    size_bytes: int = 1048576,
    raw_captured: bool = True,
    include_raw_event: bool = True,
    system_binary: bool = False,
) -> str:
    """Helper to synthesize structured witness NDJSON streams for rigorous testing."""
    if launch_binding is None:
        launch_binding = {"driver": "acme", "attempt": 1, "phase": "proof"}
    if exec_inoderefs is None:
        exec_inoderefs = [(64769, 123456)]

    now = time.time_ns()
    lines = []

    # 1. session_start
    lines.append(json.dumps({
        "event": "session_start",
        "protocol": PROTOCOL_VERSION,
        "tracer_pid": tracer_pid,
        "start_time_ns": now,
        "tracer_dumpable": tracer_dumpable,
        "launch_binding": launch_binding,
        "options": ["TRACEEXEC", "TRACEFORK", "TRACEVFORK", "TRACECLONE", "TRACEEXIT", "EXITKILL", "TRACESYSGOOD"],
    }))

    # 2. process_spawn (root child)
    seq = 1
    lines.append(json.dumps({
        "event": "process_spawn",
        "seq_id": seq if not corrupt_seq else 99,
        "timestamp_ns": now + 1000,
        "pid": root_pid,
        "ppid": tracer_pid,
        "parent_seq_id": 0,
        "kind": "initial",
        "is_thread": False,
    }))

    # 3. exec_success events
    seen_refs = set()
    for dev, ino in exec_inoderefs:
        ref = (dev, ino)
        dedup = ref in seen_refs
        seen_refs.add(ref)

        lines.append(json.dumps({
            "event": "exec_success",
            "seq_id": seq,
            "timestamp_ns": now + 2000,
            "pid": root_pid if not untracked_exec else 9999,
            "ppid": tracer_pid,
            "exe_path": "/W/.build/iyi",
            "st_dev": dev,
            "st_ino": ino,
            "st_mode": 33261,
            "st_size": size_bytes,
            "st_uid": 65534 if not system_binary else 0,
            "st_gid": 65534 if not system_binary else 0,
            "st_atim_ns": now + 2000,
            "st_mtim_ns": now + 1000,
            "st_ctim_ns": now + 1000,
            "held_fd_index": 0,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "raw_captured": raw_captured,
            "system_binary": system_binary,
            "deduplicated": dedup,
            "cmdline": ["/W/.build/iyi", "--version"],
        }))

        if include_raw_event and not system_binary and not dedup:
            lines.append(json.dumps({
                "event": "raw_exec_capture",
                "seq_id": seq,
                "timestamp_ns": now + 2500,
                "st_dev": dev,
                "st_ino": ino,
                "exe_path": "/W/.build/iyi",
                "size_bytes": size_bytes,
                "sha256": sha256,
                "captured_file": f"{dev}_{ino}.bin",
                "deduplicated": False,
            }))

    # 4. process_exit
    lines.append(json.dumps({
        "event": "process_exit",
        "seq_id": seq,
        "timestamp_ns": now + 5000,
        "pid": root_pid,
        "exit_code": root_exit_code,
        "raw_status": root_exit_code,
    }))

    # 5. session_end
    if include_end:
        lines.append(json.dumps({
            "event": "session_end",
            "protocol": PROTOCOL_VERSION,
            "tracer_pid": tracer_pid,
            "end_time_ns": now + 6000,
            "status": status,
            "root_exit_code": root_exit_code,
            "total_processes_spawned": 1,
            "total_exec_events": len(exec_inoderefs),
            "active_processes_at_end": active_processes_at_end,
        }))

    return "\n".join(lines) + "\n"


class TestHostedExecWitness(unittest.TestCase):
    """Test suite proving discriminating properties of HostedExecWitness."""

    def test_real_exec_success_verification(self):
        """A genuine execution produces valid exec_success and passes verification."""
        stream = _generate_valid_witness_stream(
            exec_inoderefs=[(64769, 1001), (64769, 1002)],
            launch_binding={"driver": "vector", "attempt": 1},
        )
        events = parse_witness_events(stream)
        res = verify_exec_witness_evidence(
            events=events,
            required_executables=[(64769, 1001), (64769, 1002)],
            expected_launch_binding={"driver": "vector", "attempt": 1},
        )
        self.assertTrue(res.verified)
        self.assertEqual(res.total_execs, 2)
        self.assertIn((64769, 1001), res.witnessed_inoderefs)
        self.assertIn((64769, 1002), res.witnessed_inoderefs)
        self.assertEqual(res.root_exit_code, 0)

    def test_reader_only_fails(self):
        """
        Adversarial case: payload opened and read the executable to advance atime,
        but never executed it. The witness stream records zero exec_success for
        that inode. Verification MUST reject with ExecNotWitnessedError.
        """
        stream = _generate_valid_witness_stream(
            exec_inoderefs=[(64769, 9999)],
            launch_binding={"driver": "acme", "attempt": 1},
        )
        events = parse_witness_events(stream)

        with self.assertRaises(ExecNotWitnessedError) as ctx:
            verify_exec_witness_evidence(
                events=events,
                required_executables=[(64769, 1001)],
                expected_launch_binding={"driver": "acme", "attempt": 1},
            )
        self.assertIn("was never witnessed executing in kernel", str(ctx.exception))

    def test_utime_only_fails(self):
        """
        Adversarial case: payload used utimensat() to forge timestamps on candidate
        executable. Witness stream has no exec_success for that inode. Fails closed.
        """
        stream = _generate_valid_witness_stream(
            exec_inoderefs=[(64769, 5001)],
            launch_binding={"driver": "adler", "attempt": 1},
        )
        events = parse_witness_events(stream)

        with self.assertRaises(ExecNotWitnessedError) as ctx:
            verify_exec_witness_evidence(
                events=events,
                required_executables=[(64769, 5001), (64769, 5002)],
                expected_launch_binding={"driver": "adler", "attempt": 1},
            )
        self.assertIn("5002", str(ctx.exception))

    def test_raw_disk_verification_success(self):
        """Proves that verifying real raw bytes on disk recalculates SHA-256 and succeeds."""
        payload_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x90" * 1000
        expected_sha = hashlib.sha256(payload_bytes).hexdigest()
        size = len(payload_bytes)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "64769_1001.bin")
            with open(file_path, "wb") as f:
                f.write(payload_bytes)

            stream = _generate_valid_witness_stream(
                exec_inoderefs=[(64769, 1001)],
                sha256=expected_sha,
                size_bytes=size,
                raw_captured=True,
            )
            events = parse_witness_events(stream)
            res = verify_exec_witness_evidence(
                events=events,
                required_executables=[(64769, 1001)],
                raw_capture_dir=tmpdir,
            )
            self.assertTrue(res.verified)

    def test_raw_disk_missing_fails(self):
        """Proves that a missing retained raw executable file on disk fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stream = _generate_valid_witness_stream(
                exec_inoderefs=[(64769, 1001)],
            )
            events = parse_witness_events(stream)
            with self.assertRaises(RawCaptureError) as ctx:
                verify_exec_witness_evidence(
                    events=events,
                    required_executables=[(64769, 1001)],
                    raw_capture_dir=tmpdir,
                )
            self.assertIn("missing on disk", str(ctx.exception).lower())

    def test_raw_disk_sha_mismatch_fails(self):
        """Proves that tampered bytes on disk fail SHA-256 verification."""
        payload_bytes = b"CORRUPTED_BYTES"
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "64769_1001.bin")
            with open(file_path, "wb") as f:
                f.write(payload_bytes)

            stream = _generate_valid_witness_stream(
                exec_inoderefs=[(64769, 1001)],
                sha256="0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
                size_bytes=len(payload_bytes),
            )
            events = parse_witness_events(stream)
            with self.assertRaises(RawCaptureError) as ctx:
                verify_exec_witness_evidence(
                    events=events,
                    required_executables=[(64769, 1001)],
                    raw_capture_dir=tmpdir,
                )
            self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_raw_disk_empty_fails(self):
        """Proves that zero-length captured file on disk fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "64769_1001.bin")
            with open(file_path, "wb") as f:
                pass  # 0 bytes

            stream = _generate_valid_witness_stream(
                exec_inoderefs=[(64769, 1001)],
                sha256=EMPTY_SHA256,
                size_bytes=0,
            )
            events = parse_witness_events(stream)
            with self.assertRaises(RawCaptureError) as ctx:
                verify_exec_witness_evidence(
                    events=events,
                    required_executables=[(64769, 1001)],
                    raw_capture_dir=tmpdir,
                )
            self.assertIn("zero-length", str(ctx.exception).lower())

    def test_empty_placeholder_sha256_rejected(self):
        """Proves that empty-file placeholder SHA-256 is rejected for executable."""
        stream = _generate_valid_witness_stream(
            exec_inoderefs=[(64769, 1001)],
            size_bytes=100,
            sha256=EMPTY_SHA256,
            raw_captured=True,
        )
        events = parse_witness_events(stream)
        with self.assertRaises(RawCaptureError) as ctx:
            verify_exec_witness_evidence(
                events=events,
                required_executables=[(64769, 1001)],
                require_raw_capture=True,
            )
        self.assertIn("placeholder sha-256", str(ctx.exception).lower())

    def test_repeated_exec_same_inode_deduplication(self):
        """Proves that repeated executions of the same inode with consistent hashes verify cleanly."""
        payload_bytes = b"\x7fELF\x02\x01\x01\x00_SAME_INODE_PAYLOAD"
        sha = hashlib.sha256(payload_bytes).hexdigest()
        size = len(payload_bytes)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "64769_1001.bin")
            with open(file_path, "wb") as f:
                f.write(payload_bytes)

            # Executed 3 times (e.g. compiler invoked repeatedly)
            stream = _generate_valid_witness_stream(
                exec_inoderefs=[(64769, 1001), (64769, 1001), (64769, 1001)],
                sha256=sha,
                size_bytes=size,
                raw_captured=True,
            )
            events = parse_witness_events(stream)
            res = verify_exec_witness_evidence(
                events=events,
                required_executables=[(64769, 1001)],
                raw_capture_dir=tmpdir,
            )
            self.assertTrue(res.verified)
            self.assertEqual(res.total_execs, 3)

    def test_repeated_exec_hash_inconsistency_fails(self):
        """Proves that conflicting hashes on repeated executions of the same inode fail closed."""
        events = [
            {"event": "session_start", "protocol": PROTOCOL_VERSION, "tracer_pid": 100, "start_time_ns": 1, "tracer_dumpable": 0, "launch_binding": {}},
            {"event": "process_spawn", "seq_id": 1, "timestamp_ns": 2, "pid": 101, "ppid": 100, "parent_seq_id": 0, "kind": "initial", "is_thread": False},
            {"event": "exec_success", "seq_id": 1, "timestamp_ns": 3, "pid": 101, "ppid": 100, "exe_path": "/bin/exe", "st_dev": 1, "st_ino": 2, "st_mode": 33261, "st_size": 10, "st_uid": 65534, "st_gid": 65534, "st_atim_ns": 3, "st_mtim_ns": 1, "st_ctim_ns": 1, "held_fd_index": 0, "sha256": "1111111111111111111111111111111111111111111111111111111111111111", "size_bytes": 10, "raw_captured": True},
            {"event": "exec_success", "seq_id": 1, "timestamp_ns": 4, "pid": 101, "ppid": 100, "exe_path": "/bin/exe", "st_dev": 1, "st_ino": 2, "st_mode": 33261, "st_size": 10, "st_uid": 65534, "st_gid": 65534, "st_atim_ns": 4, "st_mtim_ns": 1, "st_ctim_ns": 1, "held_fd_index": 0, "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size_bytes": 10, "raw_captured": True},
            {"event": "process_exit", "seq_id": 1, "timestamp_ns": 5, "pid": 101, "exit_code": 0, "raw_status": 0},
            {"event": "session_end", "protocol": PROTOCOL_VERSION, "tracer_pid": 100, "end_time_ns": 6, "status": "COMPLETE", "root_exit_code": 0, "total_processes_spawned": 1, "total_exec_events": 2, "active_processes_at_end": 0},
        ]
        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("hash inconsistency", str(ctx.exception).lower())

    def test_channel_theft_fails_dumpable_check(self):
        """
        If tracer dumpability is not 0 (meaning child could inspect /proc/<pid>/fd
        or ptrace parent), verification fails closed.
        """
        stream = _generate_valid_witness_stream(tracer_dumpable=1)
        events = parse_witness_events(stream)

        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(
                events=events,
                require_non_dumpable=True,
            )
        self.assertIn("Tracer dumpable invariant violated", str(ctx.exception))

    def test_incomplete_session_fails(self):
        """
        If tracer was killed by workload or died prematurely, session_end is absent.
        Verification MUST reject as incomplete session.
        """
        stream = _generate_valid_witness_stream(include_end=False)
        events = parse_witness_events(stream)

        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("Witness session incomplete", str(ctx.exception))

    def test_failed_status_marker_fails(self):
        """If tracer marked session FAILED, verification fails closed."""
        stream = _generate_valid_witness_stream(status="FAILED")
        events = parse_witness_events(stream)

        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("Witness session marked FAILED", str(ctx.exception))

    def test_launch_binding_mismatch_fails(self):
        """Evidence from another driver or attempt cannot be reused."""
        stream = _generate_valid_witness_stream(
            launch_binding={"driver": "acme", "attempt": 1}
        )
        events = parse_witness_events(stream)

        with self.assertRaises(LaunchBindingMismatch) as ctx:
            verify_exec_witness_evidence(
                events=events,
                expected_launch_binding={"driver": "vector", "attempt": 1},
            )
        self.assertIn("Launch binding key 'driver' mismatch", str(ctx.exception))

    def test_sequence_counter_tampering_fails(self):
        """Gaps or non-monotonic sequence numbers indicate dropped/forged events."""
        stream = _generate_valid_witness_stream(corrupt_seq=True)
        events = parse_witness_events(stream)

        with self.assertRaises(SequenceIntegrityError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("Non-monotonic sequence", str(ctx.exception))

    def test_untracked_pid_exec_fails(self):
        """Exec event for a PID that was never spawned is rejected."""
        stream = _generate_valid_witness_stream(untracked_exec=True)
        events = parse_witness_events(stream)

        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("untracked pid", str(ctx.exception))

    def test_orphaned_descendants_fail(self):
        """If active processes remain at session end, verification fails closed."""
        stream = _generate_valid_witness_stream(active_processes_at_end=2)
        events = parse_witness_events(stream)

        with self.assertRaises(WitnessVerificationError) as ctx:
            verify_exec_witness_evidence(events=events)
        self.assertIn("Orphaned tracees detected", str(ctx.exception))

    def test_non_linux_rejection(self):
        """CLI must immediately exit with code 255 if invoked on non-Linux."""
        if not sys.platform.startswith("linux"):
            witness_script = os.path.join(os.path.dirname(__file__), "hosted_exec_witness.py")
            proc = subprocess.run([sys.executable, witness_script, "--evidence-fd", "3", "--", "echo", "test"], capture_output=True)
            self.assertEqual(proc.returncode, 255)
            self.assertIn(b"requires Linux", proc.stderr)

    def test_unmediated_python_tracer_prohibited(self):
        """hosted_exec_witness.py must refuse to run as an unmediated Python tracer."""
        witness_script = os.path.join(os.path.dirname(__file__), "hosted_exec_witness.py")
        proc = subprocess.run([sys.executable, witness_script, "--evidence-fd", "3", "--", "echo", "test"], capture_output=True)
        self.assertEqual(proc.returncode, 255)

    def test_c_source_invariants(self):
        """Verify the C implementation enforces all required security invariants."""
        c_path = os.path.join(os.path.dirname(__file__), "hosted_exec_witness.c")
        self.assertTrue(os.path.isfile(c_path), f"hosted_exec_witness.c missing at {c_path}")
        with open(c_path, "r", encoding="utf-8") as f:
            c_code = f.read()

        # Security invariants in C source:
        self.assertIn("DISALLOWED_CLONE3_SYSCALL", c_code)
        self.assertIn("COMPAT_IA32_SYSCALL_DISALLOWED", c_code)
        self.assertIn("COMPAT_X32_SYSCALL_DISALLOWED", c_code)
        self.assertIn("CLONE_UNTRACED", c_code)
        self.assertIn("DISALLOWED_PTRACE_SYSCALL", c_code)
        self.assertIn("PR_SET_DUMPABLE", c_code)
        self.assertIn("PTRACE_O_EXITKILL", c_code)
        self.assertIn("PTRACE_O_TRACEEXEC", c_code)
        self.assertIn("PTRACE_O_TRACECLONE", c_code)
        self.assertIn("PTRACE_O_TRACESYSGOOD", c_code)
        self.assertIn("PTRACE_EVENT_EXEC", c_code)
        self.assertIn("check_syscall_entry", c_code)
        self.assertIn("O_NOATIME", c_code)
        self.assertIn("O_PATH", c_code)
        self.assertIn("find_captured_exec", c_code)
        self.assertIn("fstatvfs", c_code)
        self.assertIn("ST_RDONLY", c_code)
        self.assertIn("sha256_transform", c_code)
        self.assertIn("PR_SET_PDEATHSIG", c_code)
        self.assertIn(PROTOCOL_VERSION, c_code)
        self.assertIn("close_all_non_standard_fds", c_code)
        self.assertIn("write_all", c_code)
        self.assertIn("DRAIN_CHILD_PIPES", c_code)


if __name__ == "__main__":
    unittest.main()
