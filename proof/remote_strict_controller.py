#!/usr/bin/env python3
"""
Remote Strict Proof Controller (macOS-15 GitHub Actions)

Implements the single sequential strict-chain supervisor according to
PlanQuietCorpusFailures sections 1, 4-8.

Key Properties:
- Exact sequential execution: plan -> pin -> run1 -> run2 -> run3(drivers) -> final.
- One host pin: ties inode, path, compiler, temp, and environment.
- Strict result verification: requires exit 0 AND native latest result status PASS
  matching chain/unit/attempt. Stops immediately on non-PASS or disagreement.
- Hosting budget accounting: anchored to actual job start (default 19800s payload cutoff,
  1800s finalization allocation, 21600s total host job limit).
- Driver admission check: refuses to launch another driver unless full 2100s + grace
  fits before payload cutoff.
- Interruption handling: signals stage CLI via SIGTERM to process group, allowing
  native child reaping and result writing; records hosting envelope; exits nonzero.
- Incremental preservation and verified upload: archives and verifies uploads after each
  completed unit BEFORE any scratch cleanup.
- Safe allowlisted owned-path cleanup: strictly prunes eligible scratch for that completed
  stage only; rejects symlinks, path escapes, protected files, and non-scratch files;
  NEVER deletes pin, results, required.json, prereqs, P, W, or the compiler.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Sequence

# Default budget constants (seconds)
HOST_JOB_LIMIT_SEC = 21600.0       # 360 minutes (6 hours)
PAYLOAD_BUDGET_SEC = 19800.0       # 330 minutes (5.5 hours)
FINALIZATION_ALLOC_SEC = 1800.0    # 30 minutes
DRIVER_LIMIT_SEC = 2100.0          # 35 minutes per driver
GRACE_SEC = 10.0                   # cleanup grace period
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


class UnsafeCleanupError(ControllerError):
    """Raised when an unsafe cleanup path is detected."""


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
    result_status: str
    timing: UnitTiming
    disk: DiskObservation
    archive_path: str | None = None
    archive_size_bytes: int | None = None
    archive_sha256: str | None = None
    upload_verified: bool = False
    cleanup_performed: bool = False
    reclaimed_bytes: int = 0
    interrupted: bool = False
    interruption_reason: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit": self.unit,
            "attempt": self.attempt,
            "raw_exit_code": self.raw_exit_code,
            "result_status": self.result_status,
            "start_ns": self.timing.start_ns,
            "end_ns": self.timing.end_ns,
            "elapsed_sec": round(self.timing.elapsed_sec, 3),
            "disk_before_bytes": self.disk.before_bytes,
            "disk_after_bytes": self.disk.after_bytes,
            "disk_min_observed_bytes": self.disk.min_observed_bytes,
            "archive_path": self.archive_path,
            "archive_size_bytes": self.archive_size_bytes,
            "archive_sha256": self.archive_sha256,
            "upload_verified": self.upload_verified,
            "cleanup_performed": self.cleanup_performed,
            "reclaimed_bytes": self.reclaimed_bytes,
            "interrupted": self.interrupted,
            "interruption_reason": self.interruption_reason,
            "error_detail": self.error_detail,
        }


def get_disk_free_bytes(path: str) -> int:
    """Return free bytes on filesystem volume containing path."""
    try:
        stat = os.statvfs(path)
        return stat.f_bavail * stat.f_frsize
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
    """
    Generate a valid report directory matching /private/tmp/iyp-<8 lowercase hex>.
    On Darwin /tmp resolves to /private/tmp.
    """
    import secrets
    suffix = secrets.token_hex(4)  # 8 hex characters
    report_dir = os.path.join("/tmp", f"iyp-{suffix}")
    return report_dir


def find_latest_attempt_info(report_dir: str, unit: str) -> tuple[int, str] | None:
    """
    Find the numerically highest attempt directory in report_dir/unit.
    Attempts are named a1, a2, a3, ... (1-indexed, matching run_proof.py).
    Returns (attempt_number, attempt_dir_path) or None.
    """
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


def load_and_verify_stage_result(
    report_dir: str,
    unit: str,
    expected_attempt: int,
    expected_chain_id: str,
) -> tuple[dict[str, Any], str]:
    """
    Verify latest stage result in report_dir/unit/a<expected_attempt>/result.json.
    Requires:
    - file exists and is valid JSON dictionary
    - chain_id matches expected_chain_id
    - unit matches unit
    - attempt matches expected_attempt
    - status == 'PASS'
    Returns (result_dict, attempt_dir).
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

    status = data.get("status")
    if status != "PASS":
        reasons = data.get("reasons", [])
        raise VerificationError(
            f"NON-PASS-STATUS: Unit {unit!r} result status is {status!r} (expected 'PASS'). "
            f"Reasons: {reasons}"
        )

    return data, attempt_dir


def archive_unit_evidence(
    attempt_dir: str,
    unit: str,
    attempt: int,
    chain_id: str,
    artifacts_dir: str,
) -> tuple[str, int, str]:
    """
    Archive preserved evidence for a completed unit attempt into a .tar.gz file.
    Verifies archive integrity and returns (archive_path, size_bytes, sha256).
    """
    import hashlib

    archives_subdir = os.path.join(artifacts_dir, "incremental-archives")
    os.makedirs(archives_subdir, exist_ok=True)

    slug = unit.replace("/", "_")
    archive_name = f"{slug}-a{attempt}-{chain_id[:8]}.tar.gz"
    archive_path = os.path.join(archives_subdir, archive_name)

    # Collect files in attempt_dir to archive (preserving logs, times, json, etc.)
    with tarfile.open(archive_path, "w:gz") as tar:
        for root, dirs, files in os.walk(attempt_dir):
            # Do not pack giant scratch subdirectories if they still exist
            rel_root = os.path.relpath(root, attempt_dir)
            if rel_root != ".":
                first_seg = rel_root.split(os.sep)[0]
                if first_seg in ("t", "c", "s", "bin", "scratch", "rg9_work"):
                    continue
                if first_seg.endswith(".tmp") or first_seg.endswith(".cache"):
                    continue
            for file_name in files:
                file_path = os.path.join(root, file_name)
                arcname = os.path.relpath(file_path, attempt_dir)
                tar.add(file_path, arcname=arcname, recursive=False)

    # Verify archive integrity by reading it back
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
        with open(archive_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    except Exception as exc:
        raise EvidenceUploadError(f"ARCHIVE-CORRUPT: Integrity check failed on {archive_path}: {exc}") from exc

    sha256 = hasher.hexdigest()
    return archive_path, size_bytes, sha256


def execute_upload_and_verify(
    upload_cmd: str | None,
    archive_path: str,
    unit: str,
    attempt: int,
    chain_id: str,
    sha256: str,
    size_bytes: int,
) -> bool:
    """
    Execute incremental upload command and verify successful completion.
    If no upload_cmd is configured, incremental archive on local disk is considered verified.
    """
    if not upload_cmd:
        # Default local preservation mode: archive is verified by archive_unit_evidence
        return True

    cmd_formatted = upload_cmd.format(
        archive_path=archive_path,
        unit_name=unit,
        attempt=str(attempt),
        chain_id=chain_id,
        sha256=sha256,
        size=str(size_bytes),
    )

    try:
        proc = subprocess.run(
            cmd_formatted,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180.0,
        )
    except Exception as exc:
        raise EvidenceUploadError(
            f"UPLOAD-FAILED: Upload command execution failed for unit {unit!r}: {exc}"
        ) from exc

    if proc.returncode != 0:
        raise EvidenceUploadError(
            f"UPLOAD-FAILED: Upload command for unit {unit!r} exited with code {proc.returncode}. "
            f"stderr: {proc.stderr.strip()}"
        )

    # Check for verification sentinel if output is present
    output = proc.stdout + proc.stderr
    if "UPLOAD_FAILED" in output:
        raise EvidenceUploadError(
            f"UPLOAD-FAILED: Upload command reported failure sentinel for unit {unit!r}: {output}"
        )

    return True


def safe_cleanup_stage_scratch(
    report_dir: str,
    unit: str,
    attempt_dir: str,
) -> tuple[list[str], int]:
    """
    Prune only eligible scratch for the completed unit after verification and upload.
    Enforces strict safety rules:
    - Never prune pin.json, results, required.json, prereq JSON/JSONL, P/W, compiler.
    - All deleted paths must resolve strictly inside attempt_dir.
    - Reject symlinks and root escapes.
    - Matches only allowlisted scratch names for that unit.
    Returns (list_of_deleted_entries, total_reclaimed_bytes).
    """
    report_real = os.path.realpath(report_dir)
    attempt_real = os.path.realpath(attempt_dir)

    # Invariant: attempt_dir must be strictly within report_dir
    common = os.path.commonpath([report_real, attempt_real])
    if common != report_real or attempt_real == report_real:
        raise UnsafeCleanupError(
            f"UNSAFE-CLEANUP: attempt_dir {attempt_real!r} is not strictly within report_dir {report_real!r}"
        )

    # Determine allowlist
    if unit == "run1":
        scratch_names = RUN1_SCRATCH_NAMES
        allow_exts = (".tmp", ".cache")
    elif unit == "run2":
        scratch_names = RUN2_SCRATCH_NAMES
        allow_exts = (".tmp", ".cache")
    elif unit.startswith("run3/"):
        scratch_names = RUN3_SCRATCH_NAMES
        allow_exts = ()
    else:
        # plan, pin, final have no eligible scratch
        return [], 0

    deleted: list[str] = []
    reclaimed_bytes = 0

    try:
        entries = sorted(os.listdir(attempt_dir))
    except OSError as exc:
        raise UnsafeCleanupError(f"CLEANUP-LISTDIR-FAILED: Could not list {attempt_dir}: {exc}") from exc

    for name in entries:
        full_path = os.path.join(attempt_dir, name)

        # Check if eligible by exact name or extension
        is_eligible = (name in scratch_names) or any(name.endswith(ext) for ext in allow_exts)
        if not is_eligible:
            continue

        # Reject any attempt to delete protected filenames
        if name in PROTECTED_FILENAMES:
            raise UnsafeCleanupError(
                f"UNSAFE-CLEANUP: Inviolable file {name!r} matched eligible scratch rule!"
            )
        if name.endswith(".log") or name.endswith(".times"):
            raise UnsafeCleanupError(
                f"UNSAFE-CLEANUP: Log/times file {name!r} matched eligible scratch rule!"
            )

        # Reject symlinks unconditionally
        if os.path.islink(full_path):
            raise UnsafeCleanupError(
                f"UNSAFE-CLEANUP: Refusing to delete symlink {full_path!r}"
            )

        # Verify realpath confinement
        target_real = os.path.realpath(full_path)
        item_common = os.path.commonpath([attempt_real, target_real])
        if item_common != attempt_real or target_real == attempt_real:
            raise UnsafeCleanupError(
                f"UNSAFE-CLEANUP: Path escape detected: {full_path} resolves to {target_real}"
            )

        # Measure size before deleting
        item_size = 0
        try:
            if os.path.isdir(full_path):
                for root, _, files in os.walk(full_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        if not os.path.islink(fp):
                            item_size += os.path.getsize(fp)
                shutil.rmtree(full_path)
            else:
                item_size = os.path.getsize(full_path)
                os.unlink(full_path)
            deleted.append(name)
            reclaimed_bytes += item_size
        except Exception as exc:
            raise UnsafeCleanupError(
                f"CLEANUP-DELETE-FAILED: Failed to delete {full_path}: {exc}"
            ) from exc

    return deleted, reclaimed_bytes


def run_bounded_process(
    cmd: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    job_start_time: float,
    payload_budget_sec: float,
    grace_sec: float = GRACE_SEC,
    log_file: str | None = None,
) -> tuple[int, bool, str | None]:
    """
    Run command in its own process group (start_new_session=True).
    Monitors process and terminates via SIGTERM if hosting payload budget is exceeded.
    Returns (exit_code, was_interrupted, interruption_reason).
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
            stdout=log_fp if log_fp else subprocess.PIPE,
            stderr=subprocess.STDOUT if log_fp else subprocess.PIPE,
            start_new_session=True,  # setsid: proc.pid is its own process group leader
        )
    finally:
        if log_fp:
            pass

    interrupted = False
    interruption_reason: str | None = None

    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                return rc, False, None

            now = time.time()
            elapsed_from_job_start = now - job_start_time
            if elapsed_from_job_start >= payload_budget_sec:
                interrupted = True
                interruption_reason = (
                    f"Hosting payload budget cutoff ({payload_budget_sec}s) reached "
                    f"after {elapsed_from_job_start:.1f}s from job start."
                )
                print(f"\n[CONTROLLER] {interruption_reason}. Signaling process group {proc.pid} with SIGTERM...", file=sys.stderr)
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

                # Wait for child's native interruption handler to exit and write result
                try:
                    proc.wait(timeout=grace_sec)
                except subprocess.TimeoutExpired:
                    print(f"[CONTROLLER] Process group {proc.pid} did not exit within {grace_sec}s grace. Sending SIGKILL...", file=sys.stderr)
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5.0)
                return proc.returncode if proc.returncode is not None else -1, True, interruption_reason

            time.sleep(0.1)
    finally:
        if log_fp:
            log_fp.flush()
            log_fp.close()


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
        job_start_time: float | None = None,
        host_job_limit_sec: float = HOST_JOB_LIMIT_SEC,
        payload_budget_sec: float = PAYLOAD_BUDGET_SEC,
        finalization_alloc_sec: float = FINALIZATION_ALLOC_SEC,
        driver_limit_sec: float = DRIVER_LIMIT_SEC,
        grace_sec: float = GRACE_SEC,
        min_disk_gib: float = MIN_DISK_GIB,
        upload_cmd: str | None = None,
    ):
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

        self.job_start_time = job_start_time if job_start_time is not None else time.time()
        self.host_job_limit_sec = host_job_limit_sec
        self.payload_budget_sec = payload_budget_sec
        self.finalization_alloc_sec = finalization_alloc_sec
        self.driver_limit_sec = driver_limit_sec
        self.grace_sec = grace_sec
        self.min_disk_gib = min_disk_gib
        self.upload_cmd = upload_cmd

        self.chain_id: str | None = None
        self.records: list[StageExecutionRecord] = []
        self.overall_status = "INITIALIZING"
        self.overall_interrupted = False
        self.interruption_envelope: dict[str, Any] | None = None

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
        start_ns = time.time_ns()
        start_time = time.time()

        stage_slug = unit.replace("/", "_")
        log_file = os.path.join(self.artifacts_dir, "controller-logs", f"{stage_slug}-a{expected_attempt}.log")

        env = dict(os.environ)

        exit_code, interrupted, interrupt_reason = run_bounded_process(
            cmd,
            cwd=self.w_path,
            env=env,
            job_start_time=self.job_start_time,
            payload_budget_sec=self.payload_budget_sec,
            grace_sec=self.grace_sec,
            log_file=log_file,
        )

        end_ns = time.time_ns()
        elapsed_sec = time.time() - start_time
        disk_after = get_disk_free_bytes(self.report_dir if os.path.exists(self.report_dir) else "/tmp")

        record = StageExecutionRecord(
            unit=unit,
            attempt=expected_attempt,
            raw_exit_code=exit_code,
            result_status="UNKNOWN",
            timing=UnitTiming(start_ns=start_ns, end_ns=end_ns, elapsed_sec=elapsed_sec),
            disk=DiskObservation(before_bytes=disk_before, after_bytes=disk_after, min_observed_bytes=min(disk_before, disk_after)),
            interrupted=interrupted,
            interruption_reason=interrupt_reason,
        )

        if interrupted:
            record.result_status = "INTERRUPTED"
            record.error_detail = interrupt_reason
            self.records.append(record)
            raise HostingBudgetInterrupted(interrupt_reason or "Stage interrupted by hosting budget")

        if not requires_pass_result:
            # For plan or pin which do not produce a result.json
            if exit_code != 0:
                record.result_status = "FAIL"
                record.error_detail = f"Stage exited with nonzero code {exit_code}"
                self.records.append(record)
                raise VerificationError(f"Stage {unit!r} exited with code {exit_code}")
            record.result_status = "PASS"
            self.records.append(record)
            return record

        # For stages that produce a result.json (run1, run2, run3/driver):
        if exit_code != 0:
            record.result_status = "FAIL"
            record.error_detail = f"Stage exited with nonzero code {exit_code}"
            try:
                data, _ = load_and_verify_stage_result(self.report_dir, unit, expected_attempt, self.chain_id or "")
                record.result_status = data.get("status", "FAIL")
            except Exception:
                pass
            self.records.append(record)
            raise VerificationError(f"Stage {unit!r} failed with exit code {exit_code}")

        # Verify result.json
        if not self.chain_id:
            raise VerificationError("chain_id not established before stage requiring result verification")

        res_data, attempt_dir = load_and_verify_stage_result(
            self.report_dir,
            unit,
            expected_attempt,
            self.chain_id,
        )
        record.result_status = res_data.get("status", "FAIL")

        # Incrementally archive and verify upload BEFORE any scratch cleanup
        archive_path, size_bytes, sha256 = archive_unit_evidence(
            attempt_dir,
            unit,
            expected_attempt,
            self.chain_id,
            self.artifacts_dir,
        )
        record.archive_path = archive_path
        record.archive_size_bytes = size_bytes
        record.archive_sha256 = sha256

        upload_ok = execute_upload_and_verify(
            self.upload_cmd,
            archive_path,
            unit,
            expected_attempt,
            self.chain_id,
            sha256,
            size_bytes,
        )
        record.upload_verified = upload_ok

        # Prune eligible scratch only after verification and evidence upload succeeded
        cleaned_items, reclaimed = safe_cleanup_stage_scratch(
            self.report_dir,
            unit,
            attempt_dir,
        )
        record.cleanup_performed = True
        record.reclaimed_bytes = reclaimed

        # Record disk space after cleanup
        post_cleanup_disk = get_disk_free_bytes(self.report_dir)
        record.disk.after_bytes = post_cleanup_disk

        print(f"[CONTROLLER] Completed {unit} (attempt {expected_attempt}): PASS. Reclaimed {reclaimed} bytes scratch.")
        self.records.append(record)
        return record

    def run(self) -> int:
        """
        Execute the complete strict proof chain sequentially.
        Returns 0 on complete verified success, nonzero on any failure or interruption.
        """
        controller_start_time = time.time()
        print(f"[CONTROLLER] Starting remote strict chain controller.")
        print(f"[CONTROLLER] Job start anchor: {self.job_start_time} (elapsed so far: {controller_start_time - self.job_start_time:.1f}s)")
        print(f"[CONTROLLER] Host job limit: {self.host_job_limit_sec}s, Payload cutoff: {self.payload_budget_sec}s")
        print(f"[CONTROLLER] P: {self.p_path}")
        print(f"[CONTROLLER] W: {self.w_path}")
        print(f"[CONTROLLER] Compiler: {self.compiler_path}")
        print(f"[CONTROLLER] Report dir: {self.report_dir}")

        try:
            # 1. Require disk floor before starting
            verify_disk_floor("/tmp", self.min_disk_gib)

            # 2. Stage: plan
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

            # 3. Stage: pin
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

            # 4. Stage: run1
            cmd_run1 = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "run1",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("run1", cmd_run1, requires_pass_result=True)

            # 5. Stage: run2
            cmd_run2 = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "run2",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("run2", cmd_run2, requires_pass_result=True)

            # 6. Stage: run3 first driver ("acme") to compute and freeze required.json
            first_driver = "acme"
            remaining_payload = (self.job_start_time + self.payload_budget_sec) - time.time()
            required_driver_window = self.driver_limit_sec + self.grace_sec
            if remaining_payload < required_driver_window:
                raise HostingBudgetInterrupted(
                    f"Hosting budget cutoff: remaining payload window {remaining_payload:.1f}s "
                    f"< driver allocation {required_driver_window:.1f}s before launching '{first_driver}'"
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

            # 7. Read frozen required.json
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

            # 8. Iterate through remaining frozen required drivers
            for driver in required_drivers:
                if driver == first_driver:
                    continue  # already completed above

                # Check hosting budget policy: must fit full driver limit + grace
                now = time.time()
                remaining_payload = (self.job_start_time + self.payload_budget_sec) - now
                if remaining_payload < required_driver_window:
                    interruption_msg = (
                        f"Hosting budget cutoff: remaining payload window {remaining_payload:.1f}s "
                        f"is less than required driver window {required_driver_window:.1f}s. "
                        f"Refusing to launch driver '{driver}'."
                    )
                    print(f"\n[CONTROLLER] {interruption_msg}", file=sys.stderr)
                    self.overall_interrupted = True
                    self.interruption_envelope = {
                        "interrupted_by_hosting_budget": True,
                        "cutoff_at_elapsed_sec": now - self.job_start_time,
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

            # 9. Verify all required drivers have PASS results before running final
            outstanding = [d for d in required_drivers if not self._is_driver_passed(d)]
            if outstanding:
                raise VerificationError(
                    f"OUTSTANDING-DRIVERS: Required drivers still outstanding: {outstanding}"
                )

            # 10. Stage: final
            cmd_final = [
                sys.executable,
                "-B",
                self.run_proof_py,
                "final",
                "--report-dir",
                self.report_dir,
            ]
            self.execute_single_stage("final", cmd_final, expected_attempt=1, requires_pass_result=False)

            # Verify final.json
            final_path = os.path.join(self.report_dir, "final.json")
            if not os.path.isfile(final_path):
                raise VerificationError(f"FINAL-JSON-MISSING: {final_path} does not exist")
            with open(final_path, "r", encoding="utf-8") as f:
                final_data = json.load(f)
            final_status = final_data.get("status")
            if final_status != "PASS":
                raise VerificationError(
                    f"FINAL-STATUS-NON-PASS: final.json status is {final_status!r}. Reasons: {final_data.get('reasons')}"
                )

            self.overall_status = "PASS"
            print(f"\n================================================================================")
            print(f"[CONTROLLER] STRICT PROOF CHAIN COMPLETED SUCCESSFULLY: PASS")
            print(f"================================================================================")
            return 0

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
            self._write_controller_summary()

    def _is_driver_passed(self, driver: str) -> bool:
        """Check if driver has a PASS record in self.records."""
        unit = f"run3/{driver}"
        return any(r.unit == unit and r.result_status == "PASS" for r in self.records)

    def _write_controller_summary(self) -> None:
        """Write controller execution summary envelope to artifacts directory."""
        now = time.time()
        summary = {
            "controller_version": "1.0.0",
            "overall_status": self.overall_status,
            "overall_interrupted": self.overall_interrupted,
            "interruption_envelope": self.interruption_envelope,
            "chain_id": self.chain_id,
            "job_start_time": self.job_start_time,
            "job_end_time": now,
            "total_elapsed_sec": round(now - self.job_start_time, 3),
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
            print(f"[CONTROLLER] Warning: failed to write summary report {summary_file}: {exc}", file=sys.stderr)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remote Strict Proof Controller")
    parser.add_argument("--p", required=True, help="Path to clean P source checkout")
    parser.add_argument("--w", required=True, help="Path to clean W audited proof checkout")
    parser.add_argument("--compiler", required=True, help="Path to P1 compiled compiler executable")
    parser.add_argument("--artifacts-dir", required=True, help="Path to controller artifacts output directory")
    parser.add_argument("--report-dir", default=None, help="Explicit report directory (/tmp/iyp-<8hex>)")
    parser.add_argument("--run-proof-py", default=None, help="Explicit run_proof.py path (override for testing)")
    parser.add_argument("--job-start-time", type=float, default=None, help="Epoch timestamp of job start")
    parser.add_argument("--host-job-limit-sec", type=float, default=HOST_JOB_LIMIT_SEC, help="Total host job limit in seconds")
    parser.add_argument("--payload-budget-sec", type=float, default=PAYLOAD_BUDGET_SEC, help="Payload budget in seconds (cutoff)")
    parser.add_argument("--finalization-alloc-sec", type=float, default=FINALIZATION_ALLOC_SEC, help="Finalization allocation seconds")
    parser.add_argument("--driver-limit-sec", type=float, default=DRIVER_LIMIT_SEC, help="Driver limit seconds")
    parser.add_argument("--grace-sec", type=float, default=GRACE_SEC, help="Cleanup grace seconds")
    parser.add_argument("--min-disk-gib", type=float, default=MIN_DISK_GIB, help="Minimum free disk space in GiB")
    parser.add_argument("--upload-cmd", default=None, help="Command template to execute for incremental uploads")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    controller = RemoteStrictController(
        p_path=args.p,
        w_path=args.w,
        compiler_path=args.compiler,
        artifacts_dir=args.artifacts_dir,
        report_dir=args.report_dir,
        run_proof_py=args.run_proof_py,
        job_start_time=args.job_start_time,
        host_job_limit_sec=args.host_job_limit_sec,
        payload_budget_sec=args.payload_budget_sec,
        finalization_alloc_sec=args.finalization_alloc_sec,
        driver_limit_sec=args.driver_limit_sec,
        grace_sec=args.grace_sec,
        min_disk_gib=args.min_disk_gib,
        upload_cmd=args.upload_cmd,
    )
    return controller.run()


if __name__ == "__main__":
    sys.exit(main())
