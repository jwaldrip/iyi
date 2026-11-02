#!/usr/bin/env python3
"""
Remote Strict Proof Controller (macOS-15 GitHub Actions)

Implements the single sequential strict-chain supervisor according to
PlanQuietCorpusFailures sections 1, 4-8.

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

# Default budget constants (seconds)
HOST_JOB_LIMIT_SEC = 21600.0       # 360 minutes (6 hours)
PAYLOAD_BUDGET_SEC = 19800.0       # 330 minutes (5.5 hours)
FINALIZATION_ALLOC_SEC = 1800.0    # 30 minutes
DRIVER_LIMIT_SEC = 2100.0          # 35 minutes per driver
GRACE_SEC = 30.0                   # cleanup grace period (MUST be 30.0s for native drivers)
MIN_DISK_GIB = 20.0                # minimum free disk floor

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
            "disk_min_observed_bytes": self.disk.min_observed_bytes,
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
        if val_str.endswith("Z"):
            val_str = val_str[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(val_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception as exc:
            raise ValueError(f"Cannot parse job start time {val!r}: {exc}") from exc
    raise ValueError(f"Invalid type for job start time: {type(val)}")


def resolve_git_sha(path: str) -> str:
    """Resolve git commit SHA at path, or 40 zeros if unavailable."""
    try:
        proc = subprocess.run(
            ["git", "-C", path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        sha = proc.stdout.strip()
        if re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            return sha.lower()
    except Exception:
        pass
    return "0" * 40


def get_disk_free_bytes(path: str) -> int:
    """Return free bytes on filesystem volume containing path."""
    try:
        statvfs = os.statvfs(path)
        return statvfs.f_bavail * statvfs.f_frsize
    except OSError:
        usage = shutil.disk_usage(path)
        return usage.free


def verify_disk_floor(path: str, min_gib: float) -> float:
    """Verify filesystem has at least min_gib free; raise VerificationError if not."""
    free_bytes = get_disk_free_bytes(path)
    free_gib = free_bytes / (1024.0 ** 3)
    if free_gib < min_gib:
        raise VerificationError(
            f"DISK-FLOOR-BREACH: Free disk space on {path} is {free_gib:.2f} GiB, "
            f"which is below required minimum {min_gib:.2f} GiB."
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
    pattern = re.compile(r"^a([1-9][0-9]*)$")
    highest_num = -1
    highest_path: str | None = None
    try:
        for entry in os.listdir(unit_dir):
            match = pattern.match(entry)
            if match:
                num = int(match.group(1))
                if num > highest_num:
                    highest_num = num
                    highest_path = os.path.join(unit_dir, entry)
    except OSError:
        return None
    if highest_path is not None and highest_num >= 1:
        return highest_num, highest_path
    return None


def check_driver_admission(
    remaining_sec: float,
    driver_limit_sec: float = DRIVER_LIMIT_SEC,
    grace_sec: float = GRACE_SEC,
) -> bool:
    """Check if remaining payload budget can accommodate a driver + grace allowance."""
    required = driver_limit_sec + grace_sec
    return remaining_sec >= required


class DescendantTracker:
    """
    Tracks child and descendant processes with their start identities (lstart).
    Ensures that on interruption, all owned descendants across separate sessions
    are reaped while unrelated sentinels and recycled PIDs remain untouched.
    """

    def __init__(self, root_pid: int):
        self.root_pid = root_pid
        self.tracked: dict[int, str] = {}  # pid -> lstart
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

        if self.root_pid in lstarts:
            self.tracked[self.root_pid] = lstarts[self.root_pid]

        # Recursive descent for children
        queue = [self.root_pid]
        while queue:
            curr = queue.pop(0)
            for child in tree.get(curr, []):
                if child not in self.tracked:
                    self.tracked[child] = lstarts.get(child, "")
                    queue.append(child)

        # Include processes sharing root_pid's process group
        for pid, pg in pgids.items():
            if pg == self.root_pid and pid not in self.tracked:
                self.tracked[pid] = lstarts.get(pid, "")

    def reap_owned(self, grace_sec: float = 5.0) -> list[int]:
        """
        Reap all alive owned descendants whose start identity matches.
        Escalates stubborn descendants to SIGKILL.
        """
        self._sample()
        if not self.tracked:
            return []

        try:
            ps_bin = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
            proc = subprocess.run(
                [ps_bin, "-axo", "pid=,lstart="],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                return []
        except Exception:
            return []

        current_procs: dict[int, str] = {}
        for line in proc.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                try:
                    p = int(parts[0])
                    current_procs[p] = parts[1].strip()
                except ValueError:
                    pass

        my_pid = os.getpid()
        owned_alive: list[int] = []
        for pid, recorded_lstart in self.tracked.items():
            if pid == my_pid:
                continue
            if pid in current_procs:
                if not recorded_lstart or not current_procs[pid] or recorded_lstart == current_procs[pid]:
                    owned_alive.append(pid)

        if not owned_alive:
            return []

        for pid in owned_alive:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        deadline = time.monotonic() + grace_sec
        while time.monotonic() < deadline:
            still_alive = [p for p in owned_alive if self._is_pid_alive(p)]
            if not still_alive:
                break
            time.sleep(0.05)

        survivors = [p for p in owned_alive if self._is_pid_alive(p)]
        if survivors:
            for pid in survivors:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

            kill_deadline = time.monotonic() + 5.0
            while time.monotonic() < kill_deadline:
                final_survivors = [p for p in survivors if self._is_pid_alive(p)]
                if not final_survivors:
                    break
                time.sleep(0.05)

        return owned_alive

    def _is_pid_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


class EvidencePublisher:
    """Abstract persistence publisher interface."""

    def persist(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class IpcEvidencePublisher(EvidencePublisher):
    """
    Dedicated typed newline JSON publisher over fd3 (request) and fd4 (ack).
    Enforces strict echoed ACK binding and verified readback equality.
    """

    def __init__(self, req_fd: int, ack_fd: int):
        self.req_fd = req_fd
        self.ack_fd = ack_fd
        try:
            os.set_inheritable(req_fd, False)
            os.set_inheritable(ack_fd, False)
        except OSError:
            pass
        self.req_file = open(req_fd, "w", encoding="utf-8", buffering=1)
        self.ack_file = open(ack_fd, "r", encoding="utf-8", buffering=1)
        self.seen_request_ids: set[str] = set()

    def persist(self, request: dict[str, Any]) -> dict[str, Any]:
        req_id = request.get("request_id")
        if not req_id or req_id in self.seen_request_ids:
            raise IpcProtocolError(f"DUPLICATE-REQUEST-ID: {req_id!r} already used or empty")
        self.seen_request_ids.add(req_id)

        try:
            line = json.dumps(request) + "\n"
            self.req_file.write(line)
            self.req_file.flush()
        except Exception as exc:
            raise EvidenceUploadError(f"IPC-WRITE-ERROR: Failed to write upload request: {exc}") from exc

        try:
            reply_line = self.ack_file.readline()
            if not reply_line:
                raise EvidenceUploadError("IPC-EOF: Node publisher closed ACK descriptor unexpectedly")
            ack = json.loads(reply_line)
        except json.JSONDecodeError as exc:
            raise EvidenceUploadError(f"MALFORMED-ACK: JSON decode error on ACK line: {exc}") from exc
        except Exception as exc:
            raise EvidenceUploadError(f"IPC-READ-ERROR: Failed to read ACK line: {exc}") from exc

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
    chain_id: str,
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
    short_chain = chain_id[:8] if chain_id else "nochain"
    archive_name = f"{slug}-a{attempt}-{short_chain}-s{sequence}.tar.gz"
    archive_path = os.path.join(archives_subdir, archive_name)

    report_real = os.path.realpath(report_dir)
    artifacts_real = os.path.realpath(artifacts_dir)

    files_to_add: list[tuple[str, str]] = []

    # 1. Chain-level files from report_dir root
    for fn in ("pin.json", "final.json"):
        p = os.path.join(report_dir, fn)
        if os.path.isfile(p):
            files_to_add.append((p, fn))

    req_path = os.path.join(report_dir, "run3", "required.json")
    if os.path.isfile(req_path):
        files_to_add.append((req_path, os.path.join("run3", "required.json")))

    # 2. Stage journal and summary if available
    journal_path = os.path.join(artifacts_dir, "stage-journal.jsonl")
    if os.path.isfile(journal_path):
        files_to_add.append((journal_path, "stage-journal.jsonl"))

    # 3. Unit attempt files
    attempt_dir = os.path.join(report_dir, unit, f"a{attempt}")
    if os.path.isdir(attempt_dir):
        for root, dirs, files in os.walk(attempt_dir):
            rel_root = os.path.relpath(root, attempt_dir)
            if rel_root != ".":
                first_seg = rel_root.split(os.sep)[0]
                if unit == "run2" and first_seg == "scratch":
                    # Crucial: preserve Run2 scratch/rows/** ! Skip other scratch
                    if not (rel_root == "scratch/rows" or rel_root.startswith("scratch/rows" + os.sep)):
                        continue
                elif first_seg in ("t", "c", "s", "bin", "scratch", "rg9_work"):
                    continue
                if first_seg.endswith(".tmp") or first_seg.endswith(".cache"):
                    continue

            for f in files:
                fp = os.path.join(root, f)
                rel_to_attempt = os.path.relpath(fp, attempt_dir)
                arcname = os.path.join(unit, f"a{attempt}", rel_to_attempt)
                files_to_add.append((fp, arcname))

    # 4. Controller log for this stage
    log_file = os.path.join(artifacts_dir, "controller-logs", f"{slug}-a{attempt}.log")
    if os.path.isfile(log_file):
        files_to_add.append((log_file, os.path.join("controller-logs", f"{slug}-a{attempt}.log")))

    seen_arcnames: set[str] = set()
    unique_files: list[tuple[str, str]] = []
    for abs_path, arcname in files_to_add:
        if arcname in seen_arcnames:
            continue
        seen_arcnames.add(arcname)
        unique_files.append((abs_path, arcname))

    # Strict safety checks on every file before adding
    for abs_path, arcname in unique_files:
        if os.path.islink(abs_path):
            raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Symlink detected in evidence: {abs_path}")

        try:
            st = os.stat(abs_path, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Non-regular file in evidence: {abs_path}")
        except OSError as exc:
            raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Cannot stat file {abs_path}: {exc}") from exc

        real_p = os.path.realpath(abs_path)
        in_report = (os.path.commonpath([report_real, real_p]) == report_real and real_p != report_real)
        in_artifacts = (os.path.commonpath([artifacts_real, real_p]) == artifacts_real and real_p != artifacts_real)
        if not (in_report or in_artifacts):
            raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Path escape detected: {abs_path} resolves to {real_p}")

        if arcname.startswith("/") or ".." in arcname.split(os.sep):
            raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Invalid arcname {arcname!r} for {abs_path}")

    # Write sealed tar archive
    with tarfile.open(archive_path, "w:gz") as tar:
        for abs_path, arcname in unique_files:
            tar.add(abs_path, arcname=arcname, recursive=False)

    if not os.path.isfile(archive_path):
        raise EvidenceUploadError(f"ARCHIVE-MISSING: Failed to create archive {archive_path}")

    size_bytes = os.path.getsize(archive_path)
    if size_bytes == 0:
        raise EvidenceUploadError(f"ARCHIVE-EMPTY: Archive {archive_path} has 0 bytes")

    hasher = hashlib.sha256()
    try:
        with tarfile.open(archive_path, "r:gz") as test_tar:
            members = test_tar.getmembers()
            if not members:
                raise EvidenceUploadError(f"ARCHIVE-EMPTY: No members in {archive_path}")
            for m in members:
                if m.issym() or m.islnk():
                    raise EvidenceUploadError(f"UNSAFE-ARCHIVE: Archive contains link member: {m.name}")
        with open(archive_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    except Exception as exc:
        raise EvidenceUploadError(f"ARCHIVE-CORRUPT: Integrity check failed on {archive_path}: {exc}") from exc

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
                if os.path.isdir(sub_path):
                    for r, d_list, f_list in os.walk(sub_path):
                        for d in d_list:
                            dp = os.path.join(r, d)
                            if os.path.islink(dp):
                                raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Symlink inside scratch: {dp}")
                        for f in f_list:
                            fp = os.path.join(r, f)
                            if os.path.islink(fp):
                                raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Symlink inside scratch: {fp}")
                            reclaimed_bytes += os.path.getsize(fp)
                    shutil.rmtree(sub_path)
                else:
                    reclaimed_bytes += os.path.getsize(sub_path)
                    os.unlink(sub_path)
                deleted.append(f"scratch/{sub}")
            continue

        if os.path.isdir(full_path):
            for r, d_list, f_list in os.walk(full_path):
                for d in d_list:
                    dp = os.path.join(r, d)
                    if os.path.islink(dp):
                        raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Symlink inside scratch directory: {dp}")
                for f in f_list:
                    fp = os.path.join(r, f)
                    if os.path.islink(fp):
                        raise UnsafeCleanupError(f"UNSAFE-CLEANUP: Symlink inside scratch directory: {fp}")
                    reclaimed_bytes += os.path.getsize(fp)
            shutil.rmtree(full_path)
        else:
            reclaimed_bytes += os.path.getsize(full_path)
            os.unlink(full_path)
        deleted.append(name)

    return deleted, reclaimed_bytes


def run_bounded_process(
    cmd: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    monotonic_deadline: float,
    grace_sec: float = GRACE_SEC,
    log_file: str | None = None,
    on_spawn: Callable[[int], None] | None = None,
) -> tuple[int, bool, str | None, list[int]]:
    """
    Run command in its own session (start_new_session=True).
    Monitors deadline monotonically. Signals process group and reaps owned
    descendants on timeout or signal. Returns (exit_code, was_interrupted, interruption_reason, reaped_pids).
    """
    log_fp = None
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        log_fp = open(log_file, "w", encoding="utf-8")

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_fp if log_fp else subprocess.PIPE,
            stderr=subprocess.STDOUT if log_fp else subprocess.PIPE,
            start_new_session=True,  # setsid: proc.pid is session/pg leader
            close_fds=True,          # close control descriptors for native stages
        )
    finally:
        if log_fp:
            pass

    if on_spawn:
        on_spawn(proc.pid)

    tracker = DescendantTracker(proc.pid)
    interrupted = False
    interruption_reason: str | None = None
    reaped_pids: list[int] = []

    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                return rc, False, None, []

            now_mono = time.monotonic()
            if now_mono >= monotonic_deadline:
                interrupted = True
                interruption_reason = (
                    f"Hosting payload budget cutoff reached (monotonic deadline {monotonic_deadline:.1f})."
                )
                print(
                    f"\n[CONTROLLER] {interruption_reason}. Signaling process group {proc.pid} with SIGTERM (grace {grace_sec}s)...",
                    file=sys.stderr,
                )
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass

                try:
                    proc.wait(timeout=grace_sec)
                except subprocess.TimeoutExpired:
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
                return proc.returncode if proc.returncode is not None else -1, True, interruption_reason, reaped_pids

            tracker._sample()
            time.sleep(0.05)
    finally:
        if log_fp:
            try:
                log_fp.flush()
                log_fp.close()
            except OSError:
                pass


def load_and_verify_stage_result(
    report_dir: str,
    unit: str,
    expected_attempt: int,
    expected_chain_id: str,
    w_path: str | None = None,
) -> tuple[dict[str, Any], str]:
    """
    Verify latest stage result in report_dir/unit/a<expected_attempt>/result.json.
    Enforces schema shape, chain_id, unit, attempt, and valid PASS status without forgery.
    """
    latest = find_latest_attempt_info(report_dir, unit)
    if latest is None:
        raise VerificationError(f"MISSING-RESULT: No attempt directory found for unit {unit!r}")
    actual_attempt, attempt_dir = latest
    if actual_attempt != expected_attempt:
        raise VerificationError(
            f"WRONG-ATTEMPT: Unit {unit!r} latest attempt is {actual_attempt}, "
            f"expected attempt {expected_attempt}"
        )

    result_file = os.path.join(attempt_dir, "result.json")
    if not os.path.isfile(result_file):
        raise VerificationError(
            f"MISSING-RESULT: result.json does not exist in {attempt_dir}"
        )
    try:
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise VerificationError(
            f"MALFORMED-RESULT: Failed to decode JSON from {result_file}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise VerificationError(f"MALFORMED-RESULT: {result_file} is not a JSON object")

    actual_chain = data.get("chain_id")
    if actual_chain != expected_chain_id:
        raise VerificationError(
            f"WRONG-CHAIN: result.json chain_id {actual_chain!r} != expected {expected_chain_id!r}"
        )

    actual_unit = data.get("unit")
    if actual_unit != unit:
        raise VerificationError(
            f"WRONG-UNIT: result.json unit {actual_unit!r} != expected {unit!r}"
        )

    result_attempt = data.get("attempt")
    if result_attempt != expected_attempt:
        raise VerificationError(
            f"WRONG-ATTEMPT: result.json attempt {result_attempt!r} != expected {expected_attempt!r}"
        )

    if unit == "run1":
        kind = "run1"
    elif unit == "run2":
        kind = "run2"
    elif unit.startswith("run3/") or unit == "run3":
        kind = "run3"
    else:
        kind = unit

    pin = {"chain_id": expected_chain_id}
    from proof.native_validation import validate_record_native

    status, reasons = validate_record_native(
        data,
        pin=pin,
        unit=unit,
        attempt=expected_attempt,
        kind=kind,
        w_path=w_path,
    )
    if status != "PASS" or reasons:
        raise VerificationError(
            f"NON-PASS-STATUS: Unit {unit!r} result status is {status!r} (expected 'PASS'). Reasons: {reasons}"
        )

    return data, attempt_dir


class RemoteStrictController:
    """
    Supervises the execution of the remote strict proof chain.
    """

    def __init__(
        self,
        p_path: str,
        w_path: str,
        compiler_path: str,
        artifacts_dir: str,
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
        publisher: Any = None,
        p_sha: str | None = None,
        w_sha: str | None = None,
        c_sha: str | None = None,
        repository: str | None = None,
        run_id: str | None = None,
        run_attempt: str | None = None,
        job_id: str | None = None,
        upload_cmd: str | None = None,
    ):
        if upload_cmd is not None:
            raise EvidenceUploadError(
                "--upload-cmd is prohibited per shared interface; use typed IPC publisher (--ipc-req-fd, --ipc-ack-fd)"
            )

        self.mode = mode.lower()
        if self.mode == "strict":
            if grace_sec != 30.0:
                raise ValueError("In strict mode, grace-sec must be 30.0 to match native driver semantics")
            if driver_limit_sec != 2100.0:
                raise ValueError("In strict mode, driver-limit-sec must be 2100.0")

        self.p_path = os.path.realpath(p_path)
        self.w_path = os.path.realpath(w_path)
        self.compiler_path = os.path.realpath(compiler_path)
        self.artifacts_dir = os.path.realpath(artifacts_dir)
        os.makedirs(self.artifacts_dir, exist_ok=True)

        self.report_dir = (
            os.path.realpath(report_dir)
            if report_dir
            else generate_report_dir()
        )
        self.run_proof_py = (
            os.path.realpath(run_proof_py)
            if run_proof_py
            else os.path.join(self.w_path, "proof", "run_proof.py")
        )
        self.validator_py = (
            os.path.realpath(validator_py)
            if validator_py
            else os.path.join(os.path.dirname(__file__), "native_validation.py")
        )

        self.job_start_time = parse_job_start_time(job_start_time)
        self.host_job_limit_sec = host_job_limit_sec
        self.payload_budget_sec = payload_budget_sec
        self.finalization_alloc_sec = finalization_alloc_sec
        self.driver_limit_sec = driver_limit_sec
        self.grace_sec = grace_sec
        self.min_disk_gib = min_disk_gib

        # Establish monotonic deadline anchored to actual job start
        self.init_wall_time = time.time()
        self.init_monotonic = time.monotonic()
        self.initial_elapsed_sec = max(0.0, self.init_wall_time - self.job_start_time)
        self.monotonic_deadline = self.init_monotonic + (self.payload_budget_sec - self.initial_elapsed_sec)

        # Revisions and metadata
        self.p_sha = p_sha.lower() if p_sha else resolve_git_sha(self.p_path)
        self.w_sha = w_sha.lower() if w_sha else resolve_git_sha(self.w_path)
        self.c_sha = c_sha.lower() if c_sha else resolve_git_sha(os.path.dirname(__file__))
        self.repository = repository or os.environ.get("GITHUB_REPOSITORY", "jwaldrip/iyi")
        self.run_id = str(run_id or os.environ.get("GITHUB_RUN_ID", "0"))
        self.run_attempt = str(run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
        self.job_id = str(job_id or os.environ.get("GITHUB_JOB", "remote-strict-proof"))

        # Publisher setup
        if publisher is not None:
            self.publisher: EvidencePublisher | None = publisher
        elif ipc_req_fd is not None and ipc_ack_fd is not None:
            self.publisher = IpcEvidencePublisher(ipc_req_fd, ipc_ack_fd)
        else:
            self.publisher = None

        self.chain_id: str | None = None
        self.snapshot_sequence = 0
        self.records: list[StageExecutionRecord] = []
        self.overall_status = "INITIALIZING"
        self.overall_interrupted = False
        self.interruption_envelope: dict[str, Any] | None = None
        self.current_child_pid: int | None = None

    def get_remaining_payload_sec(self) -> float:
        """Return remaining seconds until payload budget cutoff using monotonic clock."""
        return self.monotonic_deadline - time.monotonic()

    def get_elapsed_from_job_start_sec(self) -> float:
        """Return elapsed seconds from actual job start using monotonic clock."""
        return self.initial_elapsed_sec + (time.monotonic() - self.init_monotonic)

    def execute_single_stage(
        self,
        unit: str,
        cmd: list[str],
        expected_attempt: int | None = None,
        requires_pass_result: bool = True,
    ) -> StageExecutionRecord:
        """
        Execute one discrete stage, verify exit and result, preserve/upload evidence,
        and clean scratch if PASS.
        """
        if expected_attempt is None:
            prior = find_latest_attempt_info(self.report_dir, unit)
            expected_attempt = 1 if prior is None else prior[0] + 1

        print(f"\n================================================================================")
        print(f"[CONTROLLER] Starting stage: {unit} (attempt {expected_attempt})")
        print(f"[CONTROLLER] Command: {' '.join(cmd)}")
        print(f"================================================================================")

        disk_before = get_disk_free_bytes(self.report_dir if os.path.exists(self.report_dir) else "/tmp")
        start_ns = time.monotonic_ns()

        stage_slug = unit.replace("/", "_")
        log_file = os.path.join(self.artifacts_dir, "controller-logs", f"{stage_slug}-a{expected_attempt}.log")

        def on_spawn(pid: int) -> None:
            self.current_child_pid = pid

        exit_code, interrupted, interrupt_reason, reaped = run_bounded_process(
            cmd,
            cwd=self.w_path,
            env=dict(os.environ),
            monotonic_deadline=self.monotonic_deadline,
            grace_sec=self.grace_sec,
            log_file=log_file,
            on_spawn=on_spawn,
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
        native_status = "NONE"
        native_valid = False

        if requires_pass_result:
            rec_data, nat_status, nat_reasons = self._validate_stage_record_with_helper(unit, expected_attempt)
            native_status = nat_status
            validation_reasons = nat_reasons
            native_valid = (nat_status == "PASS" and not nat_reasons)
        else:
            if exit_code == 0:
                native_status = "PASS"
                native_valid = True
            else:
                native_status = "FAIL"
                native_valid = False
                validation_reasons = [f"Stage exited with nonzero code {exit_code}"]

        record.native_status = native_status
        record.result_status = native_status
        record.native_validation_reasons = validation_reasons

        # Determine disposition
        if interrupted:
            record.result_status = "INTERRUPTED"
            record.disposition = "INTERRUPTED"
            record.error_detail = interrupt_reason
        elif exit_code == 0 and native_status == "PASS" and native_valid and not interrupted:
            record.disposition = "ACCEPTED"
            record.result_status = "PASS"
        else:
            record.disposition = "REJECTED"
            record.result_status = native_status if native_status != "NONE" else "FAIL"
            record.error_detail = (
                f"Stage {unit!r} rejected: exit={exit_code}, native={native_status}, reasons={validation_reasons}"
            )

        # Stage and upload evidence snapshot for ALL attempted stages (including failures)
        try:
            archive_path, size_bytes, sha256 = archive_snapshot_evidence(
                report_dir=self.report_dir,
                artifacts_dir=self.artifacts_dir,
                unit=unit,
                attempt=expected_attempt,
                chain_id=self.chain_id or "nochain",
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
                    "chain_id": self.chain_id or "",
                    "unit": unit,
                    "native_attempt": expected_attempt,
                    "snapshot_sequence": self.snapshot_sequence,
                    "archive_path": archive_path,
                    "archive_bytes": size_bytes,
                    "archive_sha256": sha256,
                }
                ack = self.publisher.persist(req)
                record.upload_verified = (ack.get("verified") is True)
                record.artifact_id = ack.get("artifact_id")
            else:
                raise EvidenceUploadError(
                    "PUBLISHER-UNCONFIGURED: No evidence publisher configured; fd3/fd4 required and no local success fallback permitted"
                )
        except Exception as exc:
            record.upload_verified = False
            record.error_detail = f"Evidence persistence failed: {exc}"
            self.records.append(record)
            self._write_stage_journal(record)
            self._write_controller_summary()
            raise EvidenceUploadError(f"Evidence persistence failed for unit {unit!r}: {exc}") from exc

        # Safe scratch cleanup ONLY after acceptance and verified upload
        if record.disposition == "ACCEPTED" and record.upload_verified:
            cleaned_items, reclaimed = safe_cleanup_stage_scratch(
                self.report_dir,
                unit,
                attempt_dir,
                upload_verified=True,
            )
            record.cleanup_performed = True
            record.reclaimed_bytes = reclaimed
            record.disk.after_bytes = get_disk_free_bytes(self.report_dir)
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
        print(f"[CONTROLLER] Job start anchor: {self.job_start_time} (initial elapsed: {self.initial_elapsed_sec:.1f}s)")
        print(f"[CONTROLLER] Host job limit: {self.host_job_limit_sec}s, Payload cutoff: {self.payload_budget_sec}s")
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
                self.overall_status = "STRICT_AUTHORIZATION_REFUSED"
                refusal_msg = (
                    "STRICT-MODE-REFUSAL: Strict proof run unconditionally refused. "
                    "No authenticated independent GO authorization mechanism has been established. "
                    "(Validation-only runs permitted with --validation-only or --mode validation-only)."
                )
                print(f"\n[CONTROLLER] {refusal_msg}", file=sys.stderr)
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

            # 10. Verify all required drivers have PASS results before running final
            outstanding = [d for d in required_drivers if not self._is_driver_passed(d)]
            if outstanding:
                raise VerificationError(
                    f"OUTSTANDING-DRIVERS: Required drivers still outstanding: {outstanding}"
                )

            # 11. Stage: final
            cmd_final = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "final",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("final", cmd_final, expected_attempt=1, requires_pass_result=False)

            # 12. Validate final.json with native schema and driver inventory
            is_valid, reasons = self._validate_final(required_drivers)
            if not is_valid:
                raise VerificationError(f"FINAL-VALIDATION-FAILED: {reasons}")

            # 13. Persist terminal completion snapshot
            self._persist_terminal_snapshot()

            self.overall_status = "PASS"
            print(f"\n================================================================================")
            print(f"[CONTROLLER] STRICT PROOF CHAIN COMPLETED SUCCESSFULLY: PASS")
            print(f"================================================================================")
            return 0

        except StrictAuthorizationRefused as exc:
            return 5
        except HostingBudgetInterrupted as exc:
            self.overall_status = "INTERRUPTED_BY_HOSTING_BUDGET"
            self.overall_interrupted = True
            print(f"\n[CONTROLLER] Execution interrupted by hosting budget: {exc}", file=sys.stderr)
            return 124
        except VerificationError as exc:
            self.overall_status = "VERIFICATION_FAILED"
            print(f"\n[CONTROLLER] Verification failure: {exc}", file=sys.stderr)
            return 1
        except EvidenceUploadError as exc:
            self.overall_status = "UPLOAD_FAILED"
            print(f"\n[CONTROLLER] Evidence upload failure: {exc}", file=sys.stderr)
            return 2
        except UnsafeCleanupError as exc:
            self.overall_status = "CLEANUP_FAILED"
            print(f"\n[CONTROLLER] Unsafe cleanup failure: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            self.overall_status = "CONTROLLER_EXCEPTION"
            print(f"\n[CONTROLLER] Unexpected exception: {exc}", file=sys.stderr)
            return 4
        finally:
            for s, h in previous_sig_handlers.items():
                try:
                    signal.signal(s, h)
                except Exception:
                    pass
            self._write_controller_summary()

    def _is_driver_passed(self, driver: str) -> bool:
        """Check if driver has a PASS record in self.records."""
        unit = f"run3/{driver}"
        return any((r.unit == unit or r.unit == driver) and r.result_status == "PASS" for r in self.records)

    def _validate_stage_record_with_helper(
        self, unit: str, attempt: int
    ) -> tuple[dict[str, Any] | None, str, list[str]]:
        """Validate native stage result using the narrow validation helper in a fresh subprocess."""
        attempt_dir = os.path.join(self.report_dir, unit, f"a{attempt}")
        result_file = os.path.join(attempt_dir, "result.json")
        pin_file = os.path.join(self.report_dir, "pin.json")

        if not os.path.isfile(result_file):
            return None, "NONE", [f"MISSING-RESULT: result.json does not exist in {attempt_dir}"]

        if unit == "run1":
            kind = "run1"
        elif unit == "run2":
            kind = "run2"
        elif unit.startswith("run3/") or unit == "run3":
            kind = "run3"
        else:
            kind = unit

        if os.path.isfile(self.validator_py) and os.path.isfile(pin_file):
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
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, close_fds=True)
                if proc.stdout.strip():
                    data = json.loads(proc.stdout)
                    rec: dict[str, Any] | None = None
                    try:
                        with open(result_file, "r", encoding="utf-8") as f:
                            rec = json.load(f)
                    except Exception:
                        pass
                    return rec, data.get("status", "FAIL"), list(data.get("reasons", []))
            except Exception:
                pass

        try:
            with open(result_file, "r", encoding="utf-8") as f:
                rec = json.load(f)
            pin = {}
            if os.path.isfile(pin_file):
                with open(pin_file, "r", encoding="utf-8") as f:
                    pin = json.load(f)
            from proof.native_validation import validate_record_native

            status, reasons = validate_record_native(
                rec,
                pin=pin,
                unit=unit,
                attempt=attempt,
                kind=kind,
                w_path=self.w_path,
            )
            return rec, status, reasons
        except Exception as exc:
            return None, "FAIL", [f"Validation exception: {exc}"]

    def _validate_final(self, required_drivers: list[str]) -> tuple[bool, list[str]]:
        """Validate final.json structure and completeness."""
        final_path = os.path.join(self.report_dir, "final.json")
        pin_path = os.path.join(self.report_dir, "pin.json")
        req_path = os.path.join(self.report_dir, "run3", "required.json")

        if not os.path.isfile(final_path):
            return False, [f"FINAL-JSON-MISSING: {final_path} does not exist"]

        if os.path.isfile(self.validator_py) and os.path.isfile(pin_path) and os.path.isfile(req_path):
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
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, close_fds=True)
                if proc.stdout.strip():
                    data = json.loads(proc.stdout)
                    return bool(data.get("valid")), list(data.get("reasons", []))
            except Exception:
                pass

        try:
            with open(final_path, "r", encoding="utf-8") as f:
                final_data = json.load(f)
            with open(pin_path, "r", encoding="utf-8") as f:
                pin = json.load(f)
            from proof.native_validation import validate_final_native

            return validate_final_native(
                final_data,
                pin=pin,
                required_drivers=required_drivers,
                w_path=self.w_path,
            )
        except Exception as exc:
            return False, [f"Final validation error: {exc}"]

    def _persist_terminal_snapshot(self) -> None:
        """Persist terminal completion evidence snapshot."""
        archive_path, size_bytes, sha256 = archive_snapshot_evidence(
            report_dir=self.report_dir,
            artifacts_dir=self.artifacts_dir,
            unit="terminal",
            attempt=1,
            chain_id=self.chain_id or "nochain",
            sequence=self.snapshot_sequence + 1,
        )
        self.snapshot_sequence += 1
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
                "chain_id": self.chain_id or "",
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
    parser.add_argument("--artifacts-dir", required=True, help="Path to controller artifacts output directory")
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
    )
    return controller.run()


if __name__ == "__main__":
    sys.exit(main())
