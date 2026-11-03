#!/usr/bin/env python3
"""
Remote Strict Proof Controller (macOS-15 GitHub Actions)

Implements the single sequential strict-chain supervisor according to
PlanQuietCorpusFailures sections 1, 4-8 and PlanStrictCIHang.

Key Properties:
- Exact sequential execution: plan -> pin -> run1 -> run2 -> run3(drivers) -> final.
- One host pin: ties inode, path, compiler, temp, and environment.
- Strict result verification: requires exit 0 AND native latest result status PASS
  matching chain/unit/attempt. Recomputed status and native checks must match.
- Hosting budget accounting: anchored to actual job start (default 19800s payload cutoff,
  1800s finalization allocation, 21600s total host job limit) with strictly monotonic deadlines.
- Driver admission check: refuses to launch another driver unless full 2100s + 30s grace
  fits before payload cutoff (minimum 2130s).
- Interruption handling: signals stage CLI via SIGTERM to process group, allowing
  native child reaping and result writing with 30s grace; tracks and reaps owned
  descendants across separate sessions with start-time identity validation; exits nonzero.
- Incremental preservation and verified upload: typed NDJSON publisher IPC over fd3/fd4;
  archives and verifies readback by exact Artifact ID before ANY scratch cleanup or advance.
  No shell uploader and no local success fallback.
- Safe allowlisted owned-path cleanup: strictly prunes eligible scratch for that completed
  stage only; rejects symlinks, path escapes, protected files, and non-scratch files;
  NEVER deletes pin, results, required.json, prereqs, P, W, the compiler, or Run2 rows.
"""

from __future__ import annotations

import argparse
import dataclasses
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Default budget constants (seconds)
HOST_JOB_LIMIT_SEC = 21600.0       # 360 minutes (6 hours)
PAYLOAD_BUDGET_SEC = 19800.0       # 330 minutes (5.5 hours)
FINALIZATION_ALLOC_SEC = 1800.0    # 30 minutes
DRIVER_LIMIT_SEC = 2100.0          # 35 minutes per driver
GRACE_SEC = 30.0                   # cleanup grace period (MUST be 30.0s for native drivers)
MIN_DISK_GIB = 20.0                # minimum free disk floor
AUTH_REFUSED_EXIT_CODE = 5         # exit code for unauthenticated strict mode refusal

# Protected files that MUST NEVER be pruned during cleanup
PROTECTED_FILENAMES = frozenset({
    "pin.json",
    "result.json",
    "required.json",
    "final.json",
    "exclusions.json",
    "baseline_skips.json",
    "run2.jsonl",
    "ledger.jsonl",
    "shim.json",
    "failure.log",
})

# Allowlisted scratch patterns by unit type
RUN1_SCRATCH_NAMES = frozenset({"rg9_work"})
RUN2_SCRATCH_NAMES = frozenset({"scratch", "run2.tmp", "run2.cache"})
RUN3_SCRATCH_NAMES = frozenset({"t", "c", "s", "bin"})


class ControllerError(Exception):
    """Base error for controller failures."""


class VerificationError(ControllerError):
    """Raised when stage result or exit code verification fails."""


class HostingBudgetInterrupted(ControllerError):
    """Raised when execution is interrupted by hosting budget policy."""


class EvidenceUploadError(ControllerError):
    """Raised when evidence archiving or upload verification fails."""


class IpcProtocolError(EvidenceUploadError):
    """Raised when publisher IPC encounters a protocol violation."""


class UnsafeCleanupError(ControllerError):
    """Raised when an unsafe cleanup path is detected."""


class StrictAuthorizationRefused(ControllerError):
    """Raised when strict mode is requested without authenticated independent GO authorization."""


@dataclasses.dataclass
class UnitTiming:
    start_ns: int
    end_ns: int
    elapsed_sec: float


@dataclasses.dataclass
class DiskObservation:
    before_bytes: int
    after_bytes: int
    min_observed_bytes: int


@dataclasses.dataclass
class StageExecutionRecord:
    unit: str
    attempt: int
    raw_exit_code: int
    native_status: str
    result_status: str
    disposition: str
    timing: UnitTiming
    disk: DiskObservation
    archive_path: str | None = None
    archive_size_bytes: int | None = None
    archive_sha256: str | None = None
    artifact_id: str | int | None = None
    upload_verified: bool = False
    cleanup_performed: bool = False
    reclaimed_bytes: int = 0
    interrupted: bool = False
    interruption_reason: str | None = None
    error_detail: str | None = None
    native_validation_reasons: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit": self.unit,
            "attempt": self.attempt,
            "raw_exit_code": self.raw_exit_code,
            "native_status": self.native_status,
            "result_status": self.result_status,
            "disposition": self.disposition,
            "start_ns": self.timing.start_ns,
            "end_ns": self.timing.end_ns,
            "elapsed_sec": round(self.timing.elapsed_sec, 3),
            "disk_before_bytes": self.disk.before_bytes,
            "disk_after_bytes": self.disk.after_bytes,
            "archive_path": self.archive_path,
            "archive_size_bytes": self.archive_size_bytes,
            "archive_sha256": self.archive_sha256,
            "artifact_id": self.artifact_id,
            "upload_verified": self.upload_verified,
            "cleanup_performed": self.cleanup_performed,
            "reclaimed_bytes": self.reclaimed_bytes,
            "interrupted": self.interrupted,
            "interruption_reason": self.interruption_reason,
            "error_detail": self.error_detail,
            "native_validation_reasons": self.native_validation_reasons,
        }


def parse_job_start_time(val: float | str | None) -> float:
    """Parse job start time from epoch float or ISO 8601 string."""
    if val is None:
        return time.time()
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        val_str = val.strip()
        try:
            return float(val_str)
        except ValueError:
            pass
        try:
            iso_str = val_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            return dt.timestamp()
        except Exception as exc:
            raise ValueError(f"Failed to parse job_start_time {val!r}: {exc}") from exc
    raise TypeError(f"Invalid type for job_start_time: {type(val)}")


def resolve_git_sha(path: str) -> str:
    """Resolve git commit SHA at path, or 40 zeros if unavailable."""
    try:
        proc = subprocess.run(
            ["git", "-C", path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            sha = proc.stdout.strip()
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                return sha
    except Exception:
        pass
    return "0" * 40


def get_disk_free_bytes(path: str) -> int:
    """Return free bytes on filesystem volume containing path."""
    cur = path
    while cur and not os.path.exists(cur):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    if not cur or not os.path.exists(cur):
        cur = "/"
    st = os.statvfs(cur)
    return st.f_bavail * st.f_frsize


def verify_disk_floor(path: str, min_gib: float) -> float:
    """Verify filesystem has at least min_gib free; raise VerificationError if not."""
    free_bytes = get_disk_free_bytes(path)
    free_gib = free_bytes / (1024.0 ** 3)
    if free_gib < min_gib:
        raise VerificationError(
            f"DISK-FLOOR-VIOLATION: Free disk space on {path} is {free_gib:.2f} GiB, "
            f"below required floor of {min_gib:.1f} GiB"
        )
    return free_gib


def generate_report_dir() -> str:
    """Generate a report directory matching /tmp/iyp-<8 lowercase hex>."""
    suffix = secrets.token_hex(4)
    return os.path.join("/tmp", f"iyp-{suffix}")


def find_latest_attempt_info(report_dir: str, unit: str) -> tuple[int, str] | None:
    """Find the numerically highest attempt directory in report_dir/unit."""
    unit_dir = os.path.join(report_dir, unit)
    if not os.path.isdir(unit_dir):
        return None
    highest = -1
    highest_dir: str | None = None
    try:
        entries = os.listdir(unit_dir)
    except OSError:
        return None
    for entry in entries:
        m = re.fullmatch(r"a([1-9][0-9]*)", entry)
        if m:
            attempt_num = int(m.group(1))
            if attempt_num > highest:
                highest = attempt_num
                highest_dir = os.path.join(unit_dir, entry)
    if highest > 0 and highest_dir is not None:
        return highest, highest_dir
    return None


def check_driver_admission(
    remaining_sec: float,
    driver_limit_sec: float = DRIVER_LIMIT_SEC,
    grace_sec: float = GRACE_SEC,
) -> bool:
    """Require at least full driver_limit_sec + grace_sec (minimum 2130s)."""
    required = driver_limit_sec + grace_sec
    return remaining_sec >= required


class DescendantTracker:
    """
    Tracks child and descendant processes with their start identities (lstart).
    Ensures that on interruption or normal exit, all owned descendants across separate
    sessions are reaped while unrelated sentinels and recycled PIDs remain untouched.
    """

    def __init__(self, root_pid: int):
        self.root_pid = root_pid
        self.tracked: dict[int, str] = {}  # pid -> immutable birth lstart
        self.signaled: list[int] = []
        self.survivors: list[int] = []
        self._sample()

    def _sample(self) -> None:
        """Sample ps and record any descendants of root_pid or processes in its session/group."""
        try:
            ps_bin = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
            proc = subprocess.run(
                [ps_bin, "-axo", "pid=,ppid=,pgid=,lstart="],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if proc.returncode != 0:
                return
        except Exception:
            return

        lines = proc.stdout.splitlines()
        tree: dict[int, list[int]] = {}
        pgids: dict[int, int] = {}
        lstarts: dict[int, str] = {}

        for line in lines:
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                pgid = int(parts[2])
                lstart = parts[3].strip()
            except ValueError:
                continue

            tree.setdefault(ppid, []).append(pid)
            pgids[pid] = pgid
            lstarts[pid] = lstart

        if self.root_pid in lstarts and self.root_pid not in self.tracked:
            if lstarts[self.root_pid]:
                self.tracked[self.root_pid] = lstarts[self.root_pid]

        # Recursive descent traversing entire subtree from root_pid
        # Uses visited set so already-known intermediate children still traverse their own new children/grandchildren!
        visited: set[int] = {self.root_pid}
        queue = [self.root_pid]
        while queue:
            curr = queue.pop(0)
            for child in tree.get(curr, []):
                if child not in visited:
                    visited.add(child)
                    if child not in self.tracked and child in lstarts and lstarts[child]:
                        self.tracked[child] = lstarts[child]
                    queue.append(child)

        # Include processes sharing root_pid's process group
        for pid, pg in pgids.items():
            if pg == self.root_pid and pid not in self.tracked and pid in lstarts and lstarts[pid]:
                self.tracked[pid] = lstarts[pid]

    def _get_current_procs(self) -> dict[int, str]:
        """Return dict of current {pid: lstart} from ps."""
        try:
            ps_bin = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
            proc = subprocess.run(
                [ps_bin, "-axo", "pid=,lstart="],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if proc.returncode != 0:
                return {}
            current_procs: dict[int, str] = {}
            for line in proc.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    try:
                        p = int(parts[0])
                        current_procs[p] = parts[1].strip()
                    except ValueError:
                        pass
            return current_procs
        except Exception:
            return {}

    def reap_owned(self, grace_sec: float = 5.0) -> list[int]:
        """
        Reap all alive owned descendants whose start identity matches.
        Escalates stubborn descendants to SIGKILL.
        Updates self.signaled and self.survivors. Returns list of signaled PIDs.
        """
        self._sample()
        if not self.tracked:
            self.signaled = []
            self.survivors = []
            return []

        current_procs = self._get_current_procs()
        my_pid = os.getpid()

        # Strict identity verification: PID must be present, have nonempty recorded lstart,
        # and current ps lstart must match recorded birth lstart exactly!
        target_pids: list[int] = []
        for pid, recorded_lstart in self.tracked.items():
            if pid == my_pid or not recorded_lstart:
                continue
            if pid in current_procs and current_procs[pid] and current_procs[pid] == recorded_lstart:
                target_pids.append(pid)

        self.signaled = list(target_pids)
        if not target_pids:
            self.survivors = []
            return []

        # 1. Send SIGTERM to strictly matching identities
        for pid in target_pids:
            fresh_procs = self._get_current_procs()
            if fresh_procs.get(pid) == self.tracked[pid]:
                try:
                    os.kill(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass

        # Wait for grace period
        deadline = time.monotonic() + max(0.1, grace_sec)
        while time.monotonic() < deadline:
            current_procs = self._get_current_procs()
            still_alive = [p for p in target_pids if current_procs.get(p) == self.tracked[p]]
            if not still_alive:
                break
            time.sleep(0.05)

        # 2. Escalate matching survivors to SIGKILL
        current_procs = self._get_current_procs()
        stubborn_survivors = [p for p in target_pids if current_procs.get(p) == self.tracked[p]]
        if stubborn_survivors:
            for pid in stubborn_survivors:
                fresh_procs = self._get_current_procs()
                if fresh_procs.get(pid) == self.tracked[pid]:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass

            kill_deadline = time.monotonic() + 5.0
            while time.monotonic() < kill_deadline:
                current_procs = self._get_current_procs()
                final_survivors = [p for p in stubborn_survivors if current_procs.get(p) == self.tracked[p]]
                if not final_survivors:
                    break
                time.sleep(0.05)

        final_procs = self._get_current_procs()
        self.survivors = [p for p in target_pids if final_procs.get(p) == self.tracked[p]]
        return self.signaled

    def _is_pid_alive(self, pid: int) -> bool:
        """Check if process is alive and matches tracked identity."""
        procs = self._get_current_procs()
        expected = self.tracked.get(pid)
        return bool(expected and procs.get(pid) == expected)


class EvidencePublisher:
    """Abstract persistence publisher interface."""

    def persist(self, request: dict[str, Any], timeout_sec: float | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class IpcEvidencePublisher(EvidencePublisher):
    """
    Dedicated typed newline JSON publisher over fd3 (request) and fd4 (ack).
    Uses nonblocking byte framing and absolute monotonic deadlines.
    Enforces strict echoed ACK binding and verified readback equality.
    """

    def __init__(self, req_fd: int, ack_fd: int, timeout_sec: float = 30.0):
        self.req_fd = req_fd
        self.ack_fd = ack_fd
        self.timeout_sec = float(timeout_sec)
        self.broken = False
        self.broken_reason: str | None = None
        self._ack_buffer = bytearray()
        self.seen_request_ids: set[str] = set()

        try:
            os.set_inheritable(self.req_fd, False)
            os.set_inheritable(self.ack_fd, False)
        except OSError:
            pass

        try:
            os.set_blocking(self.req_fd, False)
            os.set_blocking(self.ack_fd, False)
        except OSError as exc:
            self.broken = True
            self.broken_reason = f"Failed to set nonblocking mode: {exc}"

    def close(self) -> None:
        if self.req_fd is not None:
            try:
                os.close(self.req_fd)
            except OSError:
                pass
            self.req_fd = None  # type: ignore
        if self.ack_fd is not None:
            try:
                os.close(self.ack_fd)
            except OSError:
                pass
            self.ack_fd = None  # type: ignore

    def persist(self, request: dict[str, Any], timeout_sec: float | None = None) -> dict[str, Any]:
        if self.broken or self.req_fd is None or self.ack_fd is None:
            raise EvidenceUploadError(
                f"IPC-PIPE-BROKEN: Publisher IPC pipe is invalid or broken: {self.broken_reason or 'unopened'}"
            )
        req_id = request.get("request_id")
        if not req_id or req_id in self.seen_request_ids:
            raise IpcProtocolError(f"DUPLICATE-REQUEST-ID: {req_id!r} already used or empty")
        self.seen_request_ids.add(req_id)

        eff_timeout = float(timeout_sec) if timeout_sec is not None else self.timeout_sec
        deadline = time.monotonic() + eff_timeout

        # Encode request to bytes
        req_bytes = (json.dumps(request) + "\n").encode("utf-8")
        total_to_write = len(req_bytes)
        written = 0

        # Nonblocking write loop bounded by monotonic deadline
        while written < total_to_write:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise EvidenceUploadError(
                    f"IPC-WRITE-TIMEOUT: Timed out waiting to write request after {eff_timeout:.2f}s"
                )
            try:
                _, writable, _ = select.select([], [self.req_fd], [], max(0.0, rem))
            except (OSError, ValueError) as exc:
                raise EvidenceUploadError(f"IPC-SELECT-ERROR: Error selecting request fd for write: {exc}") from exc

            if not writable:
                raise EvidenceUploadError(
                    f"IPC-WRITE-TIMEOUT: Timed out waiting to write request after {eff_timeout:.2f}s"
                )

            try:
                n = os.write(self.req_fd, req_bytes[written:])
                if n == 0:
                    raise EvidenceUploadError("IPC-WRITE-ERROR: os.write returned 0 bytes")
                written += n
            except (BrokenPipeError, OSError) as exc:
                raise EvidenceUploadError(f"IPC-PIPE-CLOSED: Request pipe closed or broken during write: {exc}") from exc

        # Nonblocking read loop for newline-delimited ACK bounded by same monotonic deadline
        while True:
            newline_idx = self._ack_buffer.find(b"\n")
            if newline_idx != -1:
                line_bytes = self._ack_buffer[:newline_idx]
                self._ack_buffer = self._ack_buffer[newline_idx + 1 :]
                break

            rem = deadline - time.monotonic()
            if rem <= 0:
                if len(self._ack_buffer) > 0:
                    partial = bytes(self._ack_buffer).decode("utf-8", errors="replace")
                    raise EvidenceUploadError(
                        f"IPC-TIMEOUT: Timed out waiting for newline in ACK (partial frame: {partial!r})"
                    )
                raise EvidenceUploadError(
                    f"IPC-TIMEOUT: Open but silent ACK pipe timed out after {eff_timeout:.2f}s without response"
                )

            try:
                readable, _, _ = select.select([self.ack_fd], [], [], max(0.0, rem))
            except (OSError, ValueError) as exc:
                raise EvidenceUploadError(f"IPC-SELECT-ERROR: Error selecting ack fd for read: {exc}") from exc

            if not readable:
                if len(self._ack_buffer) > 0:
                    partial = bytes(self._ack_buffer).decode("utf-8", errors="replace")
                    raise EvidenceUploadError(
                        f"IPC-TIMEOUT: Timed out waiting for newline in ACK (partial frame: {partial!r})"
                    )
                raise EvidenceUploadError(
                    f"IPC-TIMEOUT: Open but silent ACK pipe timed out after {eff_timeout:.2f}s without response"
                )

            try:
                chunk = os.read(self.ack_fd, 65536)
            except (OSError, BlockingIOError) as exc:
                if isinstance(exc, BlockingIOError):
                    continue
                raise EvidenceUploadError(f"IPC-READ-ERROR: Failed to read from ACK pipe: {exc}") from exc

            if not chunk:
                # EOF reached!
                if len(self._ack_buffer) > 0:
                    partial = bytes(self._ack_buffer).decode("utf-8", errors="replace")
                    raise EvidenceUploadError(
                        f"IPC-PARTIAL-FRAME-EOF: Pipe closed before newline with partial frame: {partial!r}"
                    )
                raise EvidenceUploadError("IPC-EOF: Node publisher closed ACK descriptor unexpectedly")

            self._ack_buffer.extend(chunk)

        # Parse ACK JSON
        line_str = line_bytes.decode("utf-8", errors="replace").strip()
        if not line_str:
            raise EvidenceUploadError("IPC-EMPTY-FRAME: Received empty line on ACK pipe")

        try:
            ack = json.loads(line_str)
        except json.JSONDecodeError as exc:
            raise EvidenceUploadError(f"MALFORMED-ACK: JSON decode error on ACK line: {exc}") from exc

        if not isinstance(ack, dict):
            raise EvidenceUploadError(f"MALFORMED-ACK: ACK is not a dictionary: {ack}")

        if ack.get("error"):
            raise EvidenceUploadError(f"UPLOAD-FAILED: Node publisher reported error: {ack.get('error')}")

        if ack.get("verified") is not True:
            raise EvidenceUploadError(f"UNVERIFIED-ACK: Node publisher returned verified={ack.get('verified')!r}")

        for field in (
            "request_id",
            "repository",
            "run_id",
            "run_attempt",
            "job_id",
            "p_sha",
            "w_sha",
            "c_sha",
            "chain_id",
            "unit",
            "native_attempt",
            "snapshot_sequence",
        ):
            if field == "chain_id":
                req_chain = request.get("chain_id")
                ack_chain = ack.get("chain_id")
                if req_chain is None:
                    if ack_chain is not None:
                        raise EvidenceUploadError(
                            f"ACK-BINDING-MISMATCH: field 'chain_id' expected null/None for plan, got {ack_chain!r}"
                        )
                else:
                    if ack_chain != req_chain:
                        raise EvidenceUploadError(
                            f"ACK-BINDING-MISMATCH: field 'chain_id' echoed as {ack_chain!r} != expected {req_chain!r}"
                        )
            else:
                if str(ack.get(field)) != str(request.get(field)):
                    raise EvidenceUploadError(
                        f"ACK-BINDING-MISMATCH: field {field!r} echoed as {ack.get(field)!r} != expected {request.get(field)!r}"
                    )

        req_sha = request.get("archive_sha256")
        ack_sha = ack.get("downloaded_sha256")
        if ack_sha != req_sha:
            raise EvidenceUploadError(
                f"ACK-HASH-MISMATCH: downloaded_sha256 {ack_sha!r} != archive_sha256 {req_sha!r}"
            )

        req_bytes = request.get("archive_bytes")
        ack_bytes = ack.get("downloaded_bytes")
        if ack_bytes != req_bytes:
            raise EvidenceUploadError(
                f"ACK-SIZE-MISMATCH: downloaded_bytes {ack_bytes!r} != archive_bytes {req_bytes!r}"
            )

        artifact_id = ack.get("artifact_id")
        if artifact_id is None or artifact_id == "":
            raise EvidenceUploadError("ACK-MISSING-ARTIFACT-ID: Node publisher returned empty artifact_id")

        return ack


def archive_snapshot_evidence(
    report_dir: str,
    artifacts_dir: str,
    unit: str,
    attempt: int,
    chain_id: str | None,
    sequence: int,
) -> tuple[str, int, str]:
    """
    Create a sealed, regular-file-only tar.gz archive of preserved evidence.
    Includes chain-level files (pin.json, required.json, final.json), controller journal,
    logs, and attempt directory regular files (preserving Run2 scratch/rows/**).
    Rejects symlinks, special files, and path escapes.
    Returns (archive_path, size_bytes, sha256).
    """
    archives_subdir = os.path.join(artifacts_dir, "incremental-archives")
    os.makedirs(archives_subdir, exist_ok=True)

    slug = unit.replace("/", "_")
    short_chain = chain_id[:8] if chain_id else "prepin"
    archive_name = f"evidence-{short_chain}-seq{sequence:03d}-{slug}-a{attempt}.tar.gz"
    archive_path = os.path.join(archives_subdir, archive_name)

    report_real = os.path.realpath(report_dir)
    attempt_dir = os.path.join(report_dir, unit, f"a{attempt}") if unit not in ("plan", "pin", "terminal") else report_dir
    attempt_real = os.path.realpath(attempt_dir)

    # Reject symlink report or attempt roots
    if os.path.islink(report_dir) or os.path.islink(attempt_dir):
        raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: report or attempt dir is a symlink: {attempt_dir}")

    files_to_archive: list[tuple[str, str]] = []  # (abs_path, arcname)

    # 1. Chain-level metadata files if present in report_dir root
    for name in ("pin.json", "final.json"):
        p = os.path.join(report_dir, name)
        if os.path.isfile(p):
            if os.path.islink(p):
                raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: Chain metadata {p} is a symlink")
            files_to_archive.append((p, f"meta/{name}"))

    req_p = os.path.join(report_dir, "run3", "required.json")
    if os.path.isfile(req_p):
        if os.path.islink(req_p):
            raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: required.json {req_p} is a symlink")
        files_to_archive.append((req_p, "meta/run3/required.json"))

    # 2. Controller journal and stage logs if available
    journal_path = os.path.join(artifacts_dir, "stage-journal.jsonl")
    if os.path.isfile(journal_path):
        files_to_archive.append((journal_path, "controller/stage-journal.jsonl"))

    log_path = os.path.join(artifacts_dir, "controller-logs", f"{slug}-a{attempt}.log")
    if os.path.isfile(log_path):
        files_to_archive.append((log_path, f"controller-logs/{slug}-a{attempt}.log"))

    # 3. Unit attempt directory regular files
    if os.path.isdir(attempt_dir) and unit not in ("plan", "pin", "terminal"):
        for root, dirs, files in os.walk(attempt_dir, followlinks=False):
            rel_root = os.path.relpath(root, attempt_dir)
            if rel_root == ".":
                # Filter out expendable scratch directories so they are not archived
                if unit == "run1":
                    prune_dirs = [d for d in dirs if d in RUN1_SCRATCH_NAMES or d.endswith(".tmp") or d.endswith(".cache")]
                elif unit == "run2":
                    prune_dirs = [d for d in dirs if d in ("run2.tmp", "run2.cache") or d.endswith(".tmp") or d.endswith(".cache")]
                elif unit.startswith("run3") or unit == "run3":
                    prune_dirs = [d for d in dirs if d in RUN3_SCRATCH_NAMES]
                else:
                    prune_dirs = []
                for pd in prune_dirs:
                    dirs.remove(pd)
            elif rel_root == "scratch" and unit == "run2":
                # For run2, inside attempt_dir/scratch: only keep 'rows'
                prune_dirs = [d for d in dirs if d != "rows"]
                for pd in prune_dirs:
                    dirs.remove(pd)

            for d in list(dirs):
                dir_path = os.path.join(root, d)
                if os.path.islink(dir_path):
                    raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: Symlink directory detected: {dir_path}")

            for f in files:
                file_path = os.path.join(root, f)
                # At top level of attempt_dir, filter out scratch files/symlinks
                if rel_root == ".":
                    is_scratch = False
                    if unit == "run1" and (f in RUN1_SCRATCH_NAMES or f.endswith(".tmp") or f.endswith(".cache")):
                        is_scratch = True
                    elif unit == "run2" and (f in ("run2.tmp", "run2.cache") or f.endswith(".tmp") or f.endswith(".cache")):
                        is_scratch = True
                    elif (unit.startswith("run3") or unit == "run3") and f in RUN3_SCRATCH_NAMES:
                        is_scratch = True
                    if is_scratch:
                        continue
                elif rel_root == "scratch" and unit == "run2":
                    continue

                if os.path.islink(file_path):
                    raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: Symlink file detected: {file_path}")
                st = os.lstat(file_path)
                if not stat.S_ISREG(st.st_mode):
                    raise EvidenceUploadError(f"ARCHIVE-SECURITY-VIOLATION: Special non-regular file: {file_path}")
                rel = os.path.relpath(file_path, attempt_dir)
                files_to_archive.append((file_path, f"attempt/{rel}"))
    # Create deterministic tar.gz archive
    hasher = hashlib.sha256()
    size_bytes = 0

    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for abs_p, arcname in sorted(files_to_archive, key=lambda x: x[1]):
            ti = tar.gettarinfo(abs_p, arcname=arcname)
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            ti.mtime = 0
            ti.mode = 0o644
            with open(abs_p, "rb") as f:
                tar.addfile(ti, f)

    with open(archive_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            size_bytes += len(chunk)

    sha256 = hasher.hexdigest()
    return archive_path, size_bytes, sha256


def safe_cleanup_stage_scratch(
    report_dir: str,
    unit: str,
    attempt_dir: str,
    upload_verified: bool = True,
) -> tuple[list[str], int]:
    """
    Prune only eligible scratch for the completed unit after verification and upload.
    Enforces strict safety rules:
    - upload_verified must be True.
    - Never prune pin.json, results, required.json, prereq JSON/JSONL, P/W, compiler.
    - Never prune Run2 scratch/rows/**.
    - All deleted paths must resolve strictly inside attempt_dir.
    - Reject symlinks and root escapes.
    - Matches only allowlisted scratch names for that unit.
    """
    if not upload_verified:
        raise UnsafeCleanupError("UNSAFE-CLEANUP: Refusing cleanup because evidence upload was not verified")

    if unit not in ("run1", "run2") and not unit.startswith("run3") and unit != "run3":
        return [], 0

    report_real = os.path.realpath(report_dir)
    attempt_real = os.path.realpath(attempt_dir)

    common = os.path.commonpath([report_real, attempt_real])
    if common != report_real or attempt_real == report_real:
        raise UnsafeCleanupError(
            f"UNSAFE-CLEANUP: attempt_dir {attempt_real!r} is not strictly within report_dir {report_real!r}"
        )

    if unit == "run1":
        scratch_names = RUN1_SCRATCH_NAMES
        allow_exts = (".tmp", ".cache")
    elif unit == "run2":
        scratch_names = RUN2_SCRATCH_NAMES
        allow_exts = (".tmp", ".cache")
    elif unit.startswith("run3/") or unit == "run3":
        scratch_names = RUN3_SCRATCH_NAMES
        allow_exts = ()
    else:
        return [], 0

    deleted: list[str] = []
    reclaimed_bytes = 0

    try:
        entries = sorted(os.listdir(attempt_dir))
    except OSError as exc:
        raise UnsafeCleanupError(f"CLEANUP-LISTDIR-FAILED: Could not list {attempt_dir}: {exc}") from exc

    for name in entries:
        full_path = os.path.join(attempt_dir, name)

        is_eligible = (name in scratch_names) or any(name.endswith(ext) for ext in allow_exts)
        if not is_eligible:
            continue

        if name in PROTECTED_FILENAMES:
            raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Inviolable file {name!r} matched eligible scratch rule!")
        if name.endswith(".log") or name.endswith(".times"):
            raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Log/times file {name!r} matched eligible scratch rule!")

        if os.path.islink(full_path):
            raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Refusing to delete symlink {full_path!r}")

        target_real = os.path.realpath(full_path)
        item_common = os.path.commonpath([attempt_real, target_real])
        if item_common != attempt_real or target_real == attempt_real:
            raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Path escape detected: {full_path} resolves to {target_real}")

        # For Run2: scratch directory must NOT delete scratch/rows!
        if unit == "run2" and name == "scratch" and os.path.isdir(full_path):
            try:
                sub_entries = sorted(os.listdir(full_path))
            except OSError:
                sub_entries = []
            for sub in sub_entries:
                if sub == "rows":
                    continue  # Preserve rows!
                sub_path = os.path.join(full_path, sub)
                if os.path.islink(sub_path):
                    raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Refusing to delete symlink {sub_path!r}")
                sub_real = os.path.realpath(sub_path)
                if os.path.commonpath([attempt_real, sub_real]) != attempt_real or sub_real == attempt_real:
                    raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Path escape detected: {sub_path} resolves to {sub_real}")

                sub_size = _get_dir_size(sub_path)
                if os.path.isdir(sub_path):
                    shutil.rmtree(sub_path)
                else:
                    os.remove(sub_path)
                deleted.append(sub_path)
                reclaimed_bytes += sub_size
            continue

        # For general scratch directories/files
        item_size = _get_dir_size(full_path) if os.path.isdir(full_path) else os.path.getsize(full_path)
        if os.path.isdir(full_path):
            # Check nested items for symlinks before removal
            for r, dirs, files in os.walk(full_path, followlinks=False):
                for d in dirs:
                    dp = os.path.join(r, d)
                    if os.path.islink(dp):
                        raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Refusing to delete nested symlink dir {dp!r}")
                for fl in files:
                    fp = os.path.join(r, fl)
                    if os.path.islink(fp):
                        raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Refusing to delete nested symlink {fp!r}")
            shutil.rmtree(full_path)
        else:
            os.remove(full_path)

        deleted.append(full_path)
        reclaimed_bytes += item_size

    return deleted, reclaimed_bytes


def _get_dir_size(path: str) -> int:
    total = 0
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path) and not os.path.islink(path):
        return os.path.getsize(path)
    for root, _, files in os.walk(path, followlinks=False):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.islink(fp) and os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


def run_bounded_process(
    cmd: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    monotonic_deadline: float,
    grace_sec: float = GRACE_SEC,
    log_file: str | None = None,
    on_spawn: Callable[[int], None] | None = None,
    is_interrupted: Callable[[], tuple[bool, str | None]] | None = None,
) -> tuple[int, bool, str | None, list[int], list[int]]:
    """
    Run command in its own session (start_new_session=True).
    Monitors deadline monotonically and checks external interruption.
    Signals process group and reaps owned descendants on timeout or signal.
    Returns (exit_code, was_interrupted, interruption_reason, reaped_pids, surviving_pids).
    """
    log_fp = None
    temp_log_file = None
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        log_fp = open(log_file, "w", encoding="utf-8")
    else:
        temp_log_file = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        log_fp = temp_log_file

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # setsid: proc.pid is session/pg leader
            close_fds=True,          # close control descriptors for native stages
        )
    finally:
        if log_fp and not log_file:
            log_fp.close()

    if on_spawn:
        on_spawn(proc.pid)

    tracker = DescendantTracker(proc.pid)
    interrupted = False
    interruption_reason: str | None = None

    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                # Leader exited normally! Sample and reap any detached descendants left behind
                tracker._sample()
                reaped = tracker.reap_owned(grace_sec=min(grace_sec, 5.0))
                survivors = list(tracker.survivors)
                return rc, False, None, reaped, survivors

            if is_interrupted:
                was_int, int_reason = is_interrupted()
                if was_int:
                    interrupted = True
                    interruption_reason = int_reason or "Interrupted by controller signal"
                    break

            now_mono = time.monotonic()
            if now_mono >= monotonic_deadline:
                interrupted = True
                interruption_reason = (
                    f"Hosting payload budget cutoff reached (monotonic deadline {monotonic_deadline:.1f})."
                )
                break

            tracker._sample()
            time.sleep(0.05)

        # Interrupted or deadline cutoff path:
        print(
            f"\n[CONTROLLER] {interruption_reason}. Signaling process group {proc.pid} with SIGTERM (grace {grace_sec}s)...",
            file=sys.stderr,
        )
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

        term_deadline = time.monotonic() + grace_sec
        while time.monotonic() < term_deadline:
            if proc.poll() is not None:
                break
            tracker._sample()
            time.sleep(0.05)

        if proc.poll() is None:
            print(
                f"[CONTROLLER] Process group {proc.pid} did not exit within {grace_sec}s grace. Escalating to SIGKILL...",
                file=sys.stderr,
            )
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass

        reaped_pids = tracker.reap_owned(grace_sec=5.0)
        survivors = list(tracker.survivors)
        return proc.returncode if proc.returncode is not None else -1, True, interruption_reason, reaped_pids, survivors
    finally:
        if log_file and log_fp and not log_fp.closed:
            log_fp.close()
        if temp_log_file:
            try:
                os.remove(temp_log_file.name)
            except OSError:
                pass


def load_and_verify_stage_result(
    report_dir: str,
    unit: str,
    expected_attempt: int,
    expected_chain_id: str,
    w_path: str,
) -> tuple[dict[str, Any], str, list[str]]:
    """
    Load result.json for unit attempt and verify structure and non-forged status.
    Uses canonical validation helper.
    Returns (result_dict, validated_status, reasons).
    """
    attempt_dir = os.path.join(report_dir, unit, f"a{expected_attempt}")
    result_path = os.path.join(attempt_dir, "result.json")
    pin_path = os.path.join(report_dir, "pin.json")

    if not os.path.isfile(result_path):
        raise VerificationError(f"RESULT-MISSING: {result_path} does not exist")

    with open(result_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"RESULT-CORRUPT: Failed to parse JSON from {result_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise VerificationError(f"RESULT-INVALID: {result_path} is not a JSON object")

    pin = {"chain_id": expected_chain_id}
    if os.path.isfile(pin_path):
        try:
            with open(pin_path, "r", encoding="utf-8") as pf:
                pin = json.load(pf)
        except Exception:
            pass

    from proof.native_validation import validate_record_native

    kind = "run1" if unit == "run1" else ("run2" if unit == "run2" else "run3")
    status, reasons = validate_record_native(
        data,
        pin=pin,
        unit=unit,
        attempt=expected_attempt,
        kind=kind,
        w_path=w_path,
    )
    return data, status, reasons


class RemoteStrictController:
    """
    Supervises the execution of the remote strict proof chain.
    """

    def __init__(
        self,
        *,
        p_path: str,
        w_path: str,
        compiler_path: str,
        artifacts_dir: str = "strict-proof-artifacts",
        report_dir: str | None = None,
        run_proof_py: str | None = None,
        validator_py: str | None = None,
        job_start_time: float | str | None = None,
        host_job_limit_sec: float = HOST_JOB_LIMIT_SEC,
        payload_budget_sec: float = PAYLOAD_BUDGET_SEC,
        finalization_alloc_sec: float = FINALIZATION_ALLOC_SEC,
        driver_limit_sec: float = DRIVER_LIMIT_SEC,
        grace_sec: float = GRACE_SEC,
        min_disk_gib: float = MIN_DISK_GIB,
        mode: str = "strict",
        ipc_req_fd: int | None = None,
        ipc_ack_fd: int | None = None,
        p_sha: str | None = None,
        w_sha: str | None = None,
        c_sha: str | None = None,
        repository: str | None = None,
        run_id: str | int | None = None,
        run_attempt: str | int | None = None,
        job_id: str | int | None = None,
        upload_cmd: str | None = None,
        publisher_timeout_sec: float = 30.0,
    ):
        self.p_path = os.path.abspath(p_path)
        self.w_path = os.path.abspath(w_path)
        self.compiler_path = os.path.abspath(compiler_path)
        self.artifacts_dir = os.path.abspath(artifacts_dir)
        self.report_dir = report_dir if report_dir else generate_report_dir()
        self.run_proof_py = run_proof_py if run_proof_py else os.path.join(self.w_path, "proof", "run_proof.py")
        self.validator_py = (
            os.path.abspath(validator_py)
            if validator_py
            else os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_validation.py")
        )

        self.job_start_time = parse_job_start_time(job_start_time)
        self.host_job_limit_sec = float(host_job_limit_sec)
        self.payload_budget_sec = float(payload_budget_sec)
        self.finalization_alloc_sec = float(finalization_alloc_sec)
        self.driver_limit_sec = float(driver_limit_sec)
        self.grace_sec = float(grace_sec)
        self.min_disk_gib = float(min_disk_gib)
        self.mode = mode
        self.publisher_timeout_sec = float(publisher_timeout_sec)

        self.p_sha = p_sha or resolve_git_sha(self.p_path)
        self.w_sha = w_sha or resolve_git_sha(self.w_path)
        self.c_sha = c_sha or resolve_git_sha(os.path.dirname(self.validator_py))
        self.repository = repository or os.environ.get("GITHUB_REPOSITORY", "unknown/repo")
        self.run_id = str(run_id or os.environ.get("GITHUB_RUN_ID", "0"))
        self.run_attempt = str(run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
        self.job_id = str(job_id or os.environ.get("GITHUB_JOB", "job-1"))

        # Validate commit SHAs strictly if provided
        for sha_name, sha_val in (("p-sha", self.p_sha), ("w-sha", self.w_sha), ("c-sha", self.c_sha)):
            if sha_val is not None:
                if not isinstance(sha_val, str) or not re.fullmatch(r"[0-9a-f]{40}", sha_val):
                    raise VerificationError(f"MALFORMED-COMMIT-SHA: {sha_name} {sha_val!r} is not a valid 40-character hex SHA")

        # Anchored monotonic timing
        self.monotonic_anchor = time.monotonic()
        now_wall = time.time()
        elapsed_at_init = max(0.0, now_wall - self.job_start_time)
        remaining_budget = max(0.0, self.payload_budget_sec - elapsed_at_init)
        self.monotonic_deadline = self.monotonic_anchor + remaining_budget

        self.records: list[StageExecutionRecord] = []
        self.chain_id: str | None = None
        self.overall_status = "UNKNOWN"
        self.overall_interrupted = False
        self.interruption_reason: str | None = None
        self.interruption_envelope: dict[str, Any] = {}
        self.snapshot_sequence = 0
        self.current_child_pid: int | None = None

        self.publisher: EvidencePublisher | None = None
        if ipc_req_fd is not None and ipc_ack_fd is not None:
            self.publisher = IpcEvidencePublisher(
                ipc_req_fd,
                ipc_ack_fd,
                timeout_sec=self.publisher_timeout_sec,
            )

        os.makedirs(self.artifacts_dir, exist_ok=True)
        os.makedirs(os.path.join(self.artifacts_dir, "controller-logs"), exist_ok=True)

    def get_elapsed_from_job_start_sec(self) -> float:
        """Monotonic elapsed time since job anchor."""
        return max(0.0, (time.monotonic() - self.monotonic_anchor) + max(0.0, (time.time() - self.job_start_time)))

    def get_remaining_payload_sec(self) -> float:
        """Monotonic remaining seconds before payload cutoff."""
        return max(0.0, self.monotonic_deadline - time.monotonic())

    def _record_journal_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Append controller event to stage-journal.jsonl."""
        journal_file = os.path.join(self.artifacts_dir, "stage-journal.jsonl")
        event = {
            "type": event_type,
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "monotonic_now": time.monotonic(),
            **payload,
        }
        try:
            with open(journal_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")
        except Exception as exc:
            print(f"[CONTROLLER] Warning: Failed to record journal event: {exc}", file=sys.stderr)

    def execute_single_stage(
        self,
        unit: str,
        cmd: list[str],
        expected_attempt: int = 1,
        requires_pass_result: bool = True,
    ) -> StageExecutionRecord:
        """
        Execute one stage attempt, verify results with native validation helper,
        archive snapshot evidence, verify persistence ACK, and prune scratch.
        """
        print(f"\n================================================================================")
        print(f"[CONTROLLER] Launching stage: {unit} (attempt {expected_attempt})")
        print(f"[CONTROLLER] Command: {' '.join(cmd)}")
        print(f"================================================================================")

        disk_before = get_disk_free_bytes(self.report_dir if os.path.exists(self.report_dir) else "/tmp")
        start_ns = time.monotonic_ns()

        stage_slug = unit.replace("/", "_")
        log_file = os.path.join(self.artifacts_dir, "controller-logs", f"{stage_slug}-a{expected_attempt}.log")

        def on_spawn(pid: int) -> None:
            self.current_child_pid = pid

        def check_interrupted() -> tuple[bool, str | None]:
            return self.overall_interrupted, self.interruption_reason

        exit_code, interrupted, interrupt_reason, reaped, survivors = run_bounded_process(
            cmd,
            cwd=self.w_path,
            env=dict(os.environ),
            monotonic_deadline=self.monotonic_deadline,
            grace_sec=self.grace_sec,
            log_file=log_file,
            on_spawn=on_spawn,
            is_interrupted=check_interrupted,
        )
        self.current_child_pid = None

        end_ns = time.monotonic_ns()
        elapsed_sec = (end_ns - start_ns) / 1e9
        disk_after = get_disk_free_bytes(self.report_dir if os.path.exists(self.report_dir) else "/tmp")

        record = StageExecutionRecord(
            unit=unit,
            attempt=expected_attempt,
            raw_exit_code=exit_code,
            native_status="NONE",
            result_status="UNKNOWN",
            disposition="REJECTED",
            timing=UnitTiming(start_ns=start_ns, end_ns=end_ns, elapsed_sec=elapsed_sec),
            disk=DiskObservation(before_bytes=disk_before, after_bytes=disk_after, min_observed_bytes=min(disk_before, disk_after)),
            interrupted=interrupted,
            interruption_reason=interrupt_reason,
        )

        attempt_dir = os.path.join(self.report_dir, unit, f"a{expected_attempt}")
        validation_reasons: list[str] = []
        raw_native_status = "NONE"
        val_status = "FAIL"
        native_valid = False

        if requires_pass_result:
            rec_data, raw_nat, validated_status, nat_reasons = self._validate_stage_record_with_helper(unit, expected_attempt)
            raw_native_status = raw_nat
            val_status = validated_status
            validation_reasons = nat_reasons
            native_valid = (val_status == "PASS" and not nat_reasons)
        else:
            if exit_code == 0:
                raw_native_status = "PASS"
                val_status = "PASS"
                native_valid = True
            else:
                raw_native_status = "FAIL"
                val_status = "FAIL"
                native_valid = False
                validation_reasons = [f"Stage exited with nonzero code {exit_code}"]

        # Preserve raw native status separately from recomputed/validated status
        record.native_status = raw_native_status
        record.result_status = val_status
        record.native_validation_reasons = validation_reasons

        # Determine disposition
        if interrupted:
            record.result_status = "INTERRUPTED"
            record.disposition = "INTERRUPTED"
            record.error_detail = interrupt_reason
        elif survivors:
            # Surviving detached descendants cannot be accepted as clean PASS
            record.disposition = "REJECTED"
            record.result_status = "FAIL"
            record.error_detail = f"Stage {unit!r} left surviving detached descendants: {survivors}"
        elif exit_code == 0 and val_status == "PASS" and native_valid and not interrupted:
            record.disposition = "ACCEPTED"
            record.result_status = "PASS"
        else:
            record.disposition = "REJECTED"
            record.result_status = val_status if val_status != "NONE" else "FAIL"
            record.error_detail = (
                f"Stage {unit!r} rejected: exit={exit_code}, raw_native={raw_native_status}, "
                f"val_status={val_status}, reasons={validation_reasons}"
            )

        # If pinning, extract chain_id from pin.json if created so archive name and request carry it
        if unit == "pin" and os.path.isfile(os.path.join(self.report_dir, "pin.json")):
            try:
                with open(os.path.join(self.report_dir, "pin.json"), "r", encoding="utf-8") as f:
                    pin_data = json.load(f)
                self.chain_id = pin_data.get("chain_id")
            except Exception:
                pass

        # Stage and upload evidence snapshot for ALL attempted stages (including plan and pin failures)
        try:
            req_chain_id: str | None = None if unit == "plan" else self.chain_id
            if unit != "plan":
                if not req_chain_id or not isinstance(req_chain_id, str) or not req_chain_id.strip() or req_chain_id in ("nochain", "null"):
                    raise EvidenceUploadError(
                        f"Post-pin stage {unit!r} requires valid nonempty chain_id, got {req_chain_id!r}"
                    )
            archive_path, size_bytes, sha256 = archive_snapshot_evidence(
                report_dir=self.report_dir,
                artifacts_dir=self.artifacts_dir,
                unit=unit,
                attempt=expected_attempt,
                chain_id=req_chain_id,
                sequence=self.snapshot_sequence + 1,
            )
            self.snapshot_sequence += 1
            record.archive_path = archive_path
            record.archive_size_bytes = size_bytes
            record.archive_sha256 = sha256

            if self.publisher is not None:
                req = {
                    "request_id": secrets.token_hex(16),
                    "repository": self.repository,
                    "run_id": str(self.run_id),
                    "run_attempt": str(self.run_attempt),
                    "job_id": str(self.job_id),
                    "p_sha": self.p_sha,
                    "w_sha": self.w_sha,
                    "c_sha": self.c_sha,
                    "chain_id": req_chain_id,
                    "unit": unit,
                    "native_attempt": expected_attempt,
                    "snapshot_sequence": self.snapshot_sequence,
                    "archive_path": archive_path,
                    "archive_bytes": size_bytes,
                    "archive_sha256": sha256,
                }
                ack = self.publisher.persist(req)
                record.artifact_id = ack.get("artifact_id")
                record.upload_verified = True
                print(
                    f"[CONTROLLER] Verified incremental persistence for {unit} "
                    f"(seq {self.snapshot_sequence}, artifact_id={record.artifact_id})"
                )
        except Exception as exc:
            record.upload_verified = False
            record.error_detail = (record.error_detail or "") + f" [Evidence persistence failed: {exc}]"
            self.records.append(record)
            self._write_stage_journal(record)
            self._write_controller_summary()
            raise EvidenceUploadError(f"Evidence persistence failed for unit {unit!r}: {exc}") from exc

        # Safe scratch cleanup ONLY after acceptance and verified upload
        if unit not in ("plan", "pin") and record.disposition == "ACCEPTED" and record.upload_verified:
            cleaned_items, reclaimed = safe_cleanup_stage_scratch(
                self.report_dir,
                unit,
                attempt_dir,
                upload_verified=True,
            )
            record.cleanup_performed = True
            record.reclaimed_bytes = reclaimed
            report_for_disk = self.report_dir if os.path.exists(self.report_dir) else "/tmp"
            record.disk.after_bytes = get_disk_free_bytes(report_for_disk)
            if reclaimed > 0:
                print(f"[CONTROLLER] Completed {unit} (attempt {expected_attempt}): PASS. Reclaimed {reclaimed} bytes scratch.")

        self.records.append(record)
        self._write_stage_journal(record)

        if interrupted:
            raise HostingBudgetInterrupted(interrupt_reason or "Stage interrupted by hosting budget")
        if record.disposition != "ACCEPTED":
            raise VerificationError(record.error_detail or f"Stage {unit!r} failed verification")

        return record

    def run(self) -> int:
        """
        Execute the complete strict proof chain sequentially.
        Returns 0 on complete verified success, nonzero on any failure, refusal, or interruption.
        """
        print(f"[CONTROLLER] Starting remote strict chain controller.")
        print(f"[CONTROLLER] Mode: {self.mode}")
        print(f"[CONTROLLER] P: {self.p_path} ({self.p_sha})")
        print(f"[CONTROLLER] W: {self.w_path} ({self.w_sha})")
        print(f"[CONTROLLER] C: ({self.c_sha})")
        print(f"[CONTROLLER] Compiler: {self.compiler_path}")
        print(f"[CONTROLLER] Report dir: {self.report_dir}")

        previous_sig_handlers: dict[int, Any] = {}
        try:
            if threading.current_thread() is threading.main_thread():
                def ctrl_sig_handler(signum: int, _frame: Any) -> None:
                    sig_name = signal.Signals(signum).name
                    self.overall_interrupted = True
                    self.interruption_reason = f"Controller received external signal {sig_name}"
                    if self.current_child_pid is not None:
                        try:
                            os.killpg(self.current_child_pid, signal.SIGTERM)
                        except (ProcessLookupError, PermissionError):
                            pass

                for s in (signal.SIGINT, signal.SIGTERM):
                    previous_sig_handlers[s] = signal.getsignal(s)
                    signal.signal(s, ctrl_sig_handler)

            # 1. Strict mode authorization check: unconditional refusal until authenticated independent GO exists
            if self.mode == "strict":
                self.overall_status = "AUTH_REFUSED"
                refusal_msg = (
                    "STRICT_MODE_AUTH_REFUSED: Real strict execution requires independent "
                    "authenticated authorization for exact (P, W, C) tuple. No authorization "
                    "exists; refusing execution nonzero before planning, pinning, or native execution."
                )
                print(f"\n[CONTROLLER] {refusal_msg}", file=sys.stderr)
                self._record_journal_event(
                    "strict_auth_refusal",
                    {"refusal_code": AUTH_REFUSED_EXIT_CODE, "message": refusal_msg},
                )
                self._write_controller_summary()
                raise StrictAuthorizationRefused(refusal_msg)

            # 2. Require disk floor before starting
            verify_disk_floor("/tmp", self.min_disk_gib)

            # 3. Stage: plan
            cmd_plan = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "plan",
                "--p",
                self.p_path,
                "--w",
                self.w_path,
                "--compiler",
                self.compiler_path,
            ]
            self.execute_single_stage("plan", cmd_plan, expected_attempt=1, requires_pass_result=False)

            # 4. Stage: pin
            cmd_pin = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "pin",
                "--report-dir",
                self.report_dir,
                "--p",
                self.p_path,
                "--w",
                self.w_path,
                "--compiler",
                self.compiler_path,
            ]
            self.execute_single_stage("pin", cmd_pin, expected_attempt=1, requires_pass_result=False)

            # Read pin.json to extract chain_id
            pin_file = os.path.join(self.report_dir, "pin.json")
            if not os.path.isfile(pin_file):
                raise VerificationError(f"PIN-MISSING: pin.json not found in {self.report_dir}")
            with open(pin_file, "r", encoding="utf-8") as f:
                pin_data = json.load(f)
            self.chain_id = pin_data.get("chain_id")
            if not self.chain_id or not re.fullmatch(r"[0-9a-f]{32}", self.chain_id):
                raise VerificationError(f"INVALID-CHAIN-ID: {self.chain_id!r} in pin.json")
            print(f"[CONTROLLER] Established chain_id: {self.chain_id}")

            # 5. Stage: run1
            cmd_run1 = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "run1",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("run1", cmd_run1, requires_pass_result=True)

            # 6. Stage: run2
            cmd_run2 = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "run2",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("run2", cmd_run2, requires_pass_result=True)

            # 7. Stage: run3 first driver ("acme") to compute and freeze required.json
            first_driver = "acme"
            remaining_payload = self.get_remaining_payload_sec()
            if not check_driver_admission(remaining_payload, self.driver_limit_sec, self.grace_sec):
                required_window = self.driver_limit_sec + self.grace_sec
                raise HostingBudgetInterrupted(
                    f"Hosting budget cutoff: remaining payload window {remaining_payload:.1f}s "
                    f"< driver allocation {required_window:.1f}s before launching '{first_driver}'"
                )

            cmd_run3_first = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "run3",
                "--report-dir",
                self.report_dir,
                "--driver",
                first_driver,
            ]
            self.execute_single_stage(f"run3/{first_driver}", cmd_run3_first, requires_pass_result=True)

            # 8. Read frozen required.json
            required_path = os.path.join(self.report_dir, "run3", "required.json")
            if not os.path.isfile(required_path):
                raise VerificationError(f"REQUIRED-JSON-MISSING: {required_path} does not exist")
            with open(required_path, "r", encoding="utf-8") as f:
                required_drivers = json.load(f)
            if not isinstance(required_drivers, list) or not all(isinstance(d, str) for d in required_drivers):
                raise VerificationError(f"REQUIRED-JSON-INVALID: {required_drivers!r} is not a list of strings")
            if not required_drivers:
                raise VerificationError("REQUIRED-JSON-EMPTY: required.json is empty")
            print(f"[CONTROLLER] Frozen required drivers ({len(required_drivers)}): {required_drivers}")

            # 9. Iterate through remaining frozen required drivers
            required_window = self.driver_limit_sec + self.grace_sec
            for driver in required_drivers:
                if driver == first_driver:
                    continue

                remaining_payload = self.get_remaining_payload_sec()
                if not check_driver_admission(remaining_payload, self.driver_limit_sec, self.grace_sec):
                    interruption_msg = (
                        f"Hosting budget cutoff: remaining payload window {remaining_payload:.1f}s "
                        f"is less than required driver window {required_window:.1f}s. "
                        f"Refusing to launch driver '{driver}'."
                    )
                    print(f"\n[CONTROLLER] {interruption_msg}", file=sys.stderr)
                    self.overall_interrupted = True
                    self.interruption_envelope = {
                        "interrupted_by_hosting_budget": True,
                        "cutoff_at_elapsed_sec": self.get_elapsed_from_job_start_sec(),
                        "remaining_payload_sec": remaining_payload,
                        "next_driver": driver,
                        "outstanding_drivers": [d for d in required_drivers if not self._is_driver_passed(d)],
                    }
                    raise HostingBudgetInterrupted(interruption_msg)

                cmd_driver = [
                    sys.executable,
                    "-B",
                    self.run_proof_py,
                    "run3",
                    "--report-dir",
                    self.report_dir,
                    "--driver",
                    driver,
                ]
                self.execute_single_stage(f"run3/{driver}", cmd_driver, requires_pass_result=True)

            # 10. Stage: final
            cmd_final = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "final",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("final", cmd_final, requires_pass_result=False)

            # Validate final.json completeness and integrity via validator helper
            is_valid_final, final_reasons = self._validate_final(required_drivers)
            if not is_valid_final:
                raise VerificationError(f"FINAL-VERIFICATION-FAILED: {final_reasons}")

            # Upload terminal final snapshot
            self._upload_terminal_snapshot()

            self.overall_status = "PASS"
            print(f"\n================================================================================")
            print(f"[CONTROLLER] STRICT PROOF CHAIN COMPLETED SUCCESSFULLY: PASS")
            print(f"================================================================================")
            ret = 0

        except StrictAuthorizationRefused:
            ret = AUTH_REFUSED_EXIT_CODE
        except HostingBudgetInterrupted as exc:
            self.overall_status = "INTERRUPTED_BY_HOSTING_BUDGET"
            self.overall_interrupted = True
            print(f"\n[CONTROLLER] Execution interrupted by hosting budget: {exc}", file=sys.stderr)
            ret = 124
        except VerificationError as exc:
            self.overall_status = "VERIFICATION_FAILED"
            print(f"\n[CONTROLLER] Verification failure: {exc}", file=sys.stderr)
            ret = 1
        except EvidenceUploadError as exc:
            self.overall_status = "UPLOAD_FAILED"
            print(f"\n[CONTROLLER] Evidence upload failure: {exc}", file=sys.stderr)
            ret = 2
        except UnsafeCleanupError as exc:
            self.overall_status = "CLEANUP_FAILED"
            print(f"\n[CONTROLLER] Unsafe cleanup failure: {exc}", file=sys.stderr)
            ret = 3
        except Exception as exc:
            self.overall_status = "CONTROLLER_EXCEPTION"
            print(f"\n[CONTROLLER] Unexpected exception: {exc}", file=sys.stderr)
            ret = 4
        finally:
            for s, h in previous_sig_handlers.items():
                try:
                    signal.signal(s, h)
                except Exception:
                    pass
            if self.publisher is not None:
                try:
                    self.publisher.close()
                except Exception:
                    pass
            try:
                self._write_controller_summary()
            except Exception as exc:
                print(f"[CONTROLLER] CRITICAL: Mandatory summary write failed: {exc}", file=sys.stderr)
                if ret == 0:
                    ret = 4
        return ret

    def _is_driver_passed(self, driver: str) -> bool:
        """Check if driver has a PASS record in self.records."""
        unit = f"run3/{driver}"
        return any((r.unit == unit or r.unit == driver) and r.result_status == "PASS" for r in self.records)

    def _validate_stage_record_with_helper(
        self, unit: str, attempt: int
    ) -> tuple[dict[str, Any] | None, str, str, list[str]]:
        """
        Validate native stage result using the narrow validation helper in a fresh subprocess.
        Returns (record_dict, raw_status, validated_status, reasons).
        """
        attempt_dir = os.path.join(self.report_dir, unit, f"a{attempt}")
        result_file = os.path.join(attempt_dir, "result.json")
        pin_file = os.path.join(self.report_dir, "pin.json")

        raw_rec: dict[str, Any] | None = None
        raw_status = "NONE"

        if os.path.isfile(result_file):
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    raw_rec = json.load(f)
                if isinstance(raw_rec, dict):
                    raw_status = str(raw_rec.get("status", "NONE"))
            except Exception as exc:
                return None, "NONE", "FAIL", [f"CORRUPT-RESULT-JSON: Failed to parse {result_file}: {exc}"]
        else:
            return None, "NONE", "FAIL", [f"MISSING-RESULT: result.json does not exist in {attempt_dir}"]

        if unit == "run1":
            kind = "run1"
        elif unit == "run2":
            kind = "run2"
        elif unit.startswith("run3/") or unit == "run3":
            kind = "run3"
        else:
            kind = unit

        if not os.path.isfile(self.validator_py):
            return raw_rec, raw_status, "FAIL", [f"VALIDATOR-SCRIPT-MISSING: {self.validator_py} does not exist"]

        if not os.path.isfile(pin_file):
            return raw_rec, raw_status, "FAIL", [f"PIN-MISSING: {pin_file} does not exist"]

        cmd = [
            sys.executable,
            "-B",
            self.validator_py,
            "--mode",
            "record",
            "--w",
            self.w_path,
            "--pin",
            pin_file,
            "--record",
            result_file,
            "--unit",
            unit,
            "--attempt",
            str(attempt),
            "--kind",
            kind,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=15.0,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return raw_rec, raw_status, "FAIL", [f"NATIVE-VALIDATOR-TIMEOUT: Helper timed out after 15s for {unit}"]
        except Exception as exc:
            return raw_rec, raw_status, "FAIL", [f"NATIVE-VALIDATOR-SPAWN-ERROR: {exc}"]

        stdout_trimmed = proc.stdout.strip()
        data: dict[str, Any] = {}
        if stdout_trimmed:
            try:
                data = json.loads(stdout_trimmed)
            except json.JSONDecodeError:
                pass

        if proc.returncode != 0:
            reasons = list(data.get("reasons", []))
            err = data.get("error")
            if err and err not in reasons:
                reasons.insert(0, err)
            if not reasons:
                reasons = [f"NATIVE-VALIDATOR-FAILURE: exit={proc.returncode} stderr={proc.stderr.strip()!r}"]
            # Contradictory check: helper exited nonzero while outputting valid=True
            if data.get("valid") is True:
                reasons.append(f"CONTRADICTORY-VALIDATOR-OUTPUT: helper exited {proc.returncode} while claiming valid=True")
            val_status = data.get("status", "FAIL")
            if val_status == "PASS":
                val_status = "FAIL"
            return raw_rec, raw_status, val_status, reasons

        # Returncode 0: require coherent valid PASS
        if not data:
            return raw_rec, raw_status, "FAIL", [f"MALFORMED-VALIDATOR-OUTPUT: stdout={stdout_trimmed!r}"]

        val_status = data.get("status", "FAIL")
        reasons = list(data.get("reasons", []))

        if data.get("valid") is True and val_status == "PASS" and not reasons:
            return raw_rec, raw_status, "PASS", []

        if not reasons:
            reasons = [f"CONTRADICTORY-VALIDATOR-OUTPUT: exit=0 but valid={data.get('valid')!r}, status={val_status!r}"]
        return raw_rec, raw_status, val_status, reasons

    def _validate_final(self, required_drivers: list[str]) -> tuple[bool, list[str]]:
        """Validate final.json structure and completeness strictly through validator helper."""
        final_path = os.path.join(self.report_dir, "final.json")
        pin_path = os.path.join(self.report_dir, "pin.json")
        req_path = os.path.join(self.report_dir, "run3", "required.json")

        if not os.path.isfile(final_path):
            return False, [f"FINAL-JSON-MISSING: {final_path} does not exist"]

        if not os.path.isfile(self.validator_py):
            return False, [f"VALIDATOR-SCRIPT-MISSING: {self.validator_py} does not exist"]
        if not os.path.isfile(pin_path):
            return False, [f"PIN-MISSING: {pin_path} does not exist"]
        if not os.path.isfile(req_path):
            return False, [f"REQUIRED-JSON-MISSING: {req_path} does not exist"]

        cmd = [
            sys.executable,
            "-B",
            self.validator_py,
            "--mode",
            "final",
            "--w",
            self.w_path,
            "--pin",
            pin_path,
            "--final",
            final_path,
            "--required",
            req_path,
            "--report-dir",
            self.report_dir,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=15.0,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return False, ["NATIVE-VALIDATOR-TIMEOUT: Final validation helper timed out after 15s"]
        except Exception as exc:
            return False, [f"NATIVE-VALIDATOR-SPAWN-ERROR: {exc}"]

        stdout_trimmed = proc.stdout.strip()
        data: dict[str, Any] = {}
        if stdout_trimmed:
            try:
                data = json.loads(stdout_trimmed)
            except json.JSONDecodeError:
                pass

        if proc.returncode != 0:
            reasons = list(data.get("reasons", []))
            err = data.get("error")
            if err and err not in reasons:
                reasons.insert(0, err)
            if not reasons:
                reasons = [f"NATIVE-VALIDATOR-FAILURE: Final validation exited {proc.returncode}: {proc.stderr.strip()!r}"]
            return False, reasons

        if not data:
            return False, [f"MALFORMED-VALIDATOR-OUTPUT: Final validation stdout={stdout_trimmed!r}"]

        is_valid = bool(data.get("valid"))
        reasons = list(data.get("reasons", []))
        if is_valid and not reasons:
            return True, []
        if not reasons:
            reasons = ["Final validation helper returned false without explicit reasons"]
        return False, reasons

    def _upload_terminal_snapshot(self) -> None:
        """Create and upload terminal sealed snapshot containing final.json and summary."""
        if self.publisher is None:
            return
        if not self.chain_id or not isinstance(self.chain_id, str) or not self.chain_id.strip() or self.chain_id in ("nochain", "null"):
            raise EvidenceUploadError(
                f"Terminal snapshot requires valid nonempty chain_id, got {self.chain_id!r}"
            )

        archive_path, size_bytes, sha256 = archive_snapshot_evidence(
            report_dir=self.report_dir,
            artifacts_dir=self.artifacts_dir,
            unit="terminal",
            attempt=1,
            chain_id=self.chain_id,
            sequence=self.snapshot_sequence + 1,
        )
        self.snapshot_sequence += 1

        req = {
            "request_id": secrets.token_hex(16),
            "repository": self.repository,
            "run_id": str(self.run_id),
            "run_attempt": str(self.run_attempt),
            "job_id": str(self.job_id),
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "chain_id": self.chain_id,
            "unit": "terminal",
            "native_attempt": 1,
            "snapshot_sequence": self.snapshot_sequence,
            "archive_path": archive_path,
            "archive_bytes": size_bytes,
            "archive_sha256": sha256,
        }
        ack = self.publisher.persist(req)
        if ack.get("verified") is not True:
            raise EvidenceUploadError("Terminal snapshot upload could not be verified by publisher")
        print(
            f"[CONTROLLER] Verified terminal persistence "
            f"(seq {self.snapshot_sequence}, artifact_id={ack.get('artifact_id')})"
        )
    def _write_stage_journal(self, record: StageExecutionRecord) -> None:
        """Append record to mandatory stage-journal.jsonl."""
        journal_file = os.path.join(self.artifacts_dir, "stage-journal.jsonl")
        try:
            with open(journal_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        except Exception as exc:
            print(f"[CONTROLLER] CRITICAL: Failed to append to journal {journal_file}: {exc}", file=sys.stderr)
            raise ControllerError(f"Mandatory journal writing failed: {exc}") from exc

    def _write_controller_summary(self) -> None:
        """Write mandatory controller execution summary envelope to artifacts directory."""
        now = time.time()
        summary = {
            "controller_version": "2.0.0",
            "mode": self.mode,
            "overall_status": self.overall_status,
            "overall_interrupted": self.overall_interrupted,
            "interruption_envelope": self.interruption_envelope,
            "chain_id": self.chain_id,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "job_start_time": self.job_start_time,
            "job_end_time": now,
            "total_elapsed_sec": round(self.get_elapsed_from_job_start_sec(), 3),
            "payload_budget_sec": self.payload_budget_sec,
            "finalization_alloc_sec": self.finalization_alloc_sec,
            "p_path": self.p_path,
            "w_path": self.w_path,
            "compiler_path": self.compiler_path,
            "report_dir": self.report_dir,
            "records": [r.to_dict() for r in self.records],
            "units": [r.to_dict() for r in self.records],
        }

        summary_file = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        try:
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, sort_keys=True)
                f.write("\n")
            print(f"[CONTROLLER] Summary report written to: {summary_file}")
        except Exception as exc:
            print(f"[CONTROLLER] CRITICAL: Failed to write summary report {summary_file}: {exc}", file=sys.stderr)
            raise ControllerError(f"Mandatory summary writing failed: {exc}") from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remote Strict Proof Controller")
    parser.add_argument("--p", required=True, help="Path to clean P source checkout")
    parser.add_argument("--w", required=True, help="Path to clean W audited proof checkout")
    parser.add_argument("--compiler", required=True, help="Path to P1 compiled compiler executable")
    parser.add_argument("--artifacts-dir", default="strict-proof-artifacts", help="Path to controller artifacts output directory")
    parser.add_argument("--report-dir", default=None, help="Explicit report directory (/tmp/iyp-<8hex>)")
    parser.add_argument("--run-proof-py", default=None, help="Explicit run_proof.py path (override for testing)")
    parser.add_argument("--validator-py", default=None, help="Explicit native_validation.py path")
    parser.add_argument("--job-start-time", default=None, help="Epoch timestamp or ISO 8601 string of job start")
    parser.add_argument("--host-job-limit-sec", type=float, default=HOST_JOB_LIMIT_SEC, help="Total host job limit in seconds")
    parser.add_argument("--payload-budget-sec", type=float, default=PAYLOAD_BUDGET_SEC, help="Payload budget in seconds (cutoff)")
    parser.add_argument("--finalization-alloc-sec", type=float, default=FINALIZATION_ALLOC_SEC, help="Finalization allocation seconds")
    parser.add_argument("--driver-limit-sec", type=float, default=DRIVER_LIMIT_SEC, help="Driver limit seconds")
    parser.add_argument("--grace-sec", type=float, default=GRACE_SEC, help="Cleanup grace seconds")
    parser.add_argument("--min-disk-gib", type=float, default=MIN_DISK_GIB, help="Minimum free disk space in GiB")
    parser.add_argument("--mode", choices=["strict", "validation-only"], default="strict", help="Execution mode")
    parser.add_argument("--validation-only", action="store_true", help="Shortcut for --mode validation-only")
    parser.add_argument("--strict", action="store_true", help="Explicit strict mode")
    parser.add_argument("--ipc-req-fd", type=int, default=None, help="File descriptor for writing publisher requests")
    parser.add_argument("--ipc-ack-fd", type=int, default=None, help="File descriptor for reading publisher acks")
    parser.add_argument("--p-sha", default=None, help="Explicit P commit SHA")
    parser.add_argument("--w-sha", default=None, help="Explicit W commit SHA")
    parser.add_argument("--c-sha", default=None, help="Explicit C commit SHA")
    parser.add_argument("--repository", default=None, help="GitHub repository name")
    parser.add_argument("--run-id", default=None, help="GitHub Actions run ID")
    parser.add_argument("--run-attempt", default=None, help="GitHub Actions run attempt")
    parser.add_argument("--job-id", default=None, help="GitHub Actions job ID")
    parser.add_argument("--upload-cmd", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--publisher-timeout-sec", type=float, default=30.0, help="Timeout in seconds for evidence publisher requests")
    args = parser.parse_args(argv)
    if args.validation_only:
        args.mode = "validation-only"
    elif args.strict:
        args.mode = "strict"
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    controller = RemoteStrictController(
        p_path=args.p,
        w_path=args.w,
        compiler_path=args.compiler,
        artifacts_dir=args.artifacts_dir,
        report_dir=args.report_dir,
        run_proof_py=args.run_proof_py,
        validator_py=args.validator_py,
        job_start_time=args.job_start_time,
        host_job_limit_sec=args.host_job_limit_sec,
        payload_budget_sec=args.payload_budget_sec,
        finalization_alloc_sec=args.finalization_alloc_sec,
        driver_limit_sec=args.driver_limit_sec,
        grace_sec=args.grace_sec,
        min_disk_gib=args.min_disk_gib,
        mode=args.mode,
        ipc_req_fd=args.ipc_req_fd,
        ipc_ack_fd=args.ipc_ack_fd,
        p_sha=args.p_sha,
        w_sha=args.w_sha,
        c_sha=args.c_sha,
        repository=args.repository,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        job_id=args.job_id,
        upload_cmd=args.upload_cmd,
        publisher_timeout_sec=args.publisher_timeout_sec,
    )
    return controller.run()


if __name__ == "__main__":
    sys.exit(main())
