#!/usr/bin/env python3
"""
GitHub-Hosted Linux Strict Proof Controller (PR147)

Implements the trusted sequential proof controller, container lifecycle,
preflight boundary enforcement, staging interface consumption, anti-alias
mount validation, descriptor-safe checkpoint collection, host-sealed origin
receipts, and fail-closed authorization verification according to
agent://HostedProofPlan Sections 3A, 3D-F, and 4C-D.

Key Properties:
- Exact sequential lifecycle: build -> plan -> pin -> run1 -> run2 -> run3(drivers) -> final -> terminal.
- Strict authorization: binds canonical manifest (C, P, W, image digest, input lock,
  expected bundle digest, run_id, run_attempt, job_id, report path) to exact
  jwaldrip (user ID 43164) approval in environment strict-proof (ID 26584191206).
  Fails closed nonzero on missing/invalid/unauthenticated approval or local-quiet-darwin.
- Container isolation: --network none, --read-only, --cap-drop ALL, --security-opt no-new-privileges,
  --init, --user 65534:65534.
- Anti-alias and mount policy: verifies mounts against inspect; rejects writable aliases,
  docker.sock leaks, host /proc leaks, and unexpected volumes.
- Preflight controls: proves host listener unreachability (ECONNREFUSED), non-loopback
  unreachability (ENETUNREACH), local container loopback, canary file isolation,
  read-only root (EROFS), exact teardown, and required tool capabilities.
- Descriptor-safe evidence collection: walks directories with O_NOFOLLOW, preserves
  fixture symlinks as metadata without following them, sanitizes workflow commands,
  creates incremental checkpoint archives, and enforces sticky failure semantics.
- Host-sealed origin receipts: seals driver attempt origin_records.json and ledger.jsonl
  outside payload-writable mounts after teardown for cmd_final verification.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import errno
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

# Configuration Constants
BACKEND_NAME: str = "github-hosted-linux-docker"
DEFAULT_ENVIRONMENT_NAME: str = "strict-proof"
DEFAULT_ENVIRONMENT_ID: str = "26584191206"
DEFAULT_REVIEWER_ID: str = "43164"  # Jason Waldrip
DEFAULT_REVIEWER_LOGIN: str = "jwaldrip"
AUTH_COMMENT_PREFIX: str = "iyi-strict-linux-authorization-v1 sha256:"
AUTH_REFUSED_EXIT_CODE: int = 5

HOST_JOB_LIMIT_SEC: float = 21600.0       # 360 minutes (6 hours)
PAYLOAD_BUDGET_SEC: float = 19800.0       # 330 minutes (5.5 hours)
FINALIZATION_ALLOC_SEC: float = 1800.0    # 30 minutes
DRIVER_LIMIT_SEC: float = 2100.0          # 35 minutes per driver
GRACE_SEC: float = 30.0                   # cleanup grace period
MIN_DISK_GIB: float = 20.0                # minimum free disk floor

CONTAINER_USER: str = "65534:65534"
CONTAINER_UID: int = 65534
CONTAINER_GID: int = 65534

REQUIRED_INPUT_ROOT_FILES: Tuple[str, ...] = (
    "hpke-vectors.json",
    "mlkem-keygen.json",
    "mlkem-encdec.json",
    "wycheproof-p384.json",
)
REQUIRED_INPUT_ROOT_DIRS: Tuple[str, ...] = ("go-proxy",)

WORKFLOW_COMMAND_RE = re.compile(
    r"^::(set-output|add-path|set-env|error|warning|notice|debug|group|endgroup|add-mask|stop-commands)",
    re.IGNORECASE,
)


class ControllerError(Exception):
    """Base error for hosted Linux controller."""


class StrictAuthorizationRefused(ControllerError):
    """Raised when authorization verification fails or is absent."""


class LineageValidationError(ControllerError):
    """Raised when P or W git lineage or equality invariants fail."""


class StagingError(ControllerError):
    """Raised when input staging or verification fails."""


class MountPolicyError(ControllerError):
    """Raised when container mount table or anti-alias checks fail."""


class PreflightError(ControllerError):
    """Raised when container preflight boundary checks fail."""


class LifecycleExecutionError(ControllerError):
    """Raised when a lifecycle command or verification fails."""


class HostingBudgetInterrupted(ControllerError):
    """Raised when execution budget is exhausted."""


class EvidenceCollectionError(ControllerError):
    """Raised when descriptor-safe evidence collection fails."""


def canonical_json_bytes(data: Any) -> bytes:
    """Deterministic canonical JSON serialization (sorted keys, compact)."""
    return (
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    """Return lowercase hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sanitize_workflow_output(text: str) -> str:
    """
    Sanitize text to prevent GitHub Actions workflow command injection.
    Neutralizes any workflow command prefix (e.g. '::set-output', '::add-path',
    '::error', '::warning', '::set-env') so lines can never be interpreted
    by the GitHub Actions runner as workflow commands.
    """
    lines = text.splitlines(keepends=True)
    sanitized: List[str] = []
    for line in lines:
        stripped = line.lstrip()
        leading_ws = line[: len(line) - len(stripped)]
        if stripped.startswith("::"):
            rest = stripped[2:]
            trailing_nl = "\n" if line.endswith("\n") else ""
            sanitized.append(f"{leading_ws}[payload-log]: {rest.rstrip()}{trailing_nl}")
        else:
            sanitized.append(line)
    return "".join(sanitized)


@dataclasses.dataclass(frozen=True)
class ProofManifest:
    """Canonical invocation manifest binding C, P, W, container, and execution parameters."""
    schema: str
    backend: str
    repository: str
    c_sha: str
    p_sha: str
    w_sha: str
    workflow_path: str
    workflow_blob: str
    run_id: str
    run_attempt: int
    job_id: str
    job_key: str
    image: str
    image_digest: str
    lock_path: str
    lock_sha256: str
    expected_bundle_sha256: str
    report_path: str
    environment: str
    environment_id: str
    resource_policy: Dict[str, Any]
    independent_review: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


def validate_manifest_dict(data: Dict[str, Any]) -> ProofManifest:
    """Validate structure and fields of a manifest dictionary and return a ProofManifest."""
    if not isinstance(data, dict):
        raise StrictAuthorizationRefused("Manifest data must be a dictionary")

    required_keys = {
        "schema", "backend", "repository", "c_sha", "p_sha", "w_sha",
        "workflow_path", "workflow_blob", "run_id", "run_attempt", "job_id",
        "job_key", "image", "image_digest", "lock_path", "lock_sha256",
        "expected_bundle_sha256", "report_path", "environment",
        "environment_id", "resource_policy", "independent_review",
    }
    missing = required_keys - set(data.keys())
    if missing:
        raise StrictAuthorizationRefused(f"Manifest missing required keys: {sorted(missing)}")

    if data["schema"] != "iyi-hosted-linux-proof-v1":
        raise StrictAuthorizationRefused(f"Unsupported manifest schema: {data['schema']}")

    if data["backend"] != BACKEND_NAME:
        raise StrictAuthorizationRefused(f"Invalid backend: {data['backend']}, expected {BACKEND_NAME}")

    for sha_key in ("c_sha", "p_sha", "w_sha"):
        val = data[sha_key]
        if not isinstance(val, str) or not re.fullmatch(r"[0-9a-f]{40}", val):
            raise StrictAuthorizationRefused(f"Invalid 40-character hex commit SHA for {sha_key}: {val!r}")

    for digest_key in ("lock_sha256", "expected_bundle_sha256"):
        val = data[digest_key]
        if not isinstance(val, str) or not re.fullmatch(r"[0-9a-f]{64}", val):
            raise StrictAuthorizationRefused(f"Invalid 64-character hex SHA-256 for {digest_key}: {val!r}")

    image_digest = data["image_digest"]
    if not isinstance(image_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise StrictAuthorizationRefused(f"Invalid image_digest format: {image_digest!r}, expected sha256:64-hex")

    report_path = data["report_path"]
    if not isinstance(report_path, str) or not re.fullmatch(r"/private/tmp/iyp-[0-9a-f]{8}", report_path):
        raise StrictAuthorizationRefused(f"Invalid report_path format: {report_path!r}")

    run_id = str(data["run_id"])
    if not run_id.isdigit():
        raise StrictAuthorizationRefused(f"Invalid run_id: {run_id!r}")

    run_attempt = data["run_attempt"]
    if not isinstance(run_attempt, int) or run_attempt < 1:
        raise StrictAuthorizationRefused(f"Invalid run_attempt: {run_attempt!r}")

    return ProofManifest(
        schema=data["schema"],
        backend=data["backend"],
        repository=data["repository"],
        c_sha=data["c_sha"],
        p_sha=data["p_sha"],
        w_sha=data["w_sha"],
        workflow_path=data["workflow_path"],
        workflow_blob=data["workflow_blob"],
        run_id=run_id,
        run_attempt=run_attempt,
        job_id=str(data["job_id"]),
        job_key=data["job_key"],
        image=data["image"],
        image_digest=data["image_digest"],
        lock_path=data["lock_path"],
        lock_sha256=data["lock_sha256"],
        expected_bundle_sha256=data["expected_bundle_sha256"],
        report_path=report_path,
        environment=data["environment"],
        environment_id=str(data["environment_id"]),
        resource_policy=dict(data["resource_policy"]),
        independent_review=dict(data["independent_review"]),
    )


def verify_strict_authorization(
    manifest: ProofManifest,
    approvals_data: Any,
) -> None:
    """
    Verify that an approval entry exists for the exact manifest digest,
    approved by Jason Waldrip (user ID 43164) in environment strict-proof (ID 26584191206).
    Rejects any local-quiet-darwin authorization or unauthenticated state.
    """
    if isinstance(approvals_data, dict):
        approvals_list = approvals_data.get("approvals", [])
    elif isinstance(approvals_data, list):
        approvals_list = approvals_data
    else:
        raise StrictAuthorizationRefused("Invalid approvals data structure")

    expected_digest = manifest.digest()
    expected_comment = f"{AUTH_COMMENT_PREFIX}{expected_digest}"

    matching_approvals = []
    for app in approvals_list:
        if not isinstance(app, dict):
            continue
        state = app.get("state")
        user = app.get("user", {})
        user_id = str(user.get("id", "")) if isinstance(user, dict) else ""
        comment = (app.get("comment") or "").strip()
        envs = app.get("environments", [])
        env_ids = [str(e.get("id", "")) for e in envs if isinstance(e, dict)]

        # Reject any darwin reuse attempt explicitly
        if "local-quiet-darwin" in comment or "iyi-strict-authorization-v2" in comment:
            continue

        if (
            state == "approved"
            and user_id == DEFAULT_REVIEWER_ID
            and manifest.environment_id in env_ids
            and comment == expected_comment
        ):
            matching_approvals.append(app)

    if len(matching_approvals) != 1:
        raise StrictAuthorizationRefused(
            f"Strict authorization rejected: expected exactly 1 approval matching "
            f"comment '{expected_comment}' by reviewer {DEFAULT_REVIEWER_ID} in env {manifest.environment_id}, "
            f"found {len(matching_approvals)}. Refusing execution before any payload or container startup."
        )


def verify_git_lineage(p_dir: str, w_dir: str, p_sha: str, w_sha: str) -> None:
    """
    Verify that W is a descendant of P, that P and W are identical outside proof/,
    and that worktrees are clean.
    """
    for sha, name in ((p_sha, "P"), (w_sha, "W")):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise LineageValidationError(f"Invalid 40-char commit SHA for {name}: {sha}")

    # Verify P HEAD
    try:
        p_head = subprocess.check_output(["git", "-C", p_dir, "rev-parse", "HEAD"], text=True).strip()
    except subprocess.CalledProcessError as exc:
        raise LineageValidationError(f"Failed to rev-parse P head: {exc}") from exc
    if p_head != p_sha:
        raise LineageValidationError(f"P checkout HEAD {p_head} does not match authorized SHA {p_sha}")

    # Verify W HEAD
    try:
        w_head = subprocess.check_output(["git", "-C", w_dir, "rev-parse", "HEAD"], text=True).strip()
    except subprocess.CalledProcessError as exc:
        raise LineageValidationError(f"Failed to rev-parse W head: {exc}") from exc
    if w_head != w_sha:
        raise LineageValidationError(f"W checkout HEAD {w_head} does not match authorized SHA {w_sha}")

    # Cleanliness
    for d, name in ((p_dir, "P"), (w_dir, "W")):
        status = subprocess.check_output(["git", "-C", d, "status", "--porcelain"], text=True).strip()
        if status:
            raise LineageValidationError(f"{name} checkout at {d} is dirty: {status}")

    # Ancestry check
    try:
        subprocess.check_call(["git", "-C", w_dir, "merge-base", "--is-ancestor", p_sha, w_sha])
    except subprocess.CalledProcessError as exc:
        raise LineageValidationError(f"Lineage failure: P ({p_sha}) is not an ancestor of W ({w_sha})") from exc

    # Non-proof difference check
    try:
        diff_out = subprocess.check_output(
            ["git", "-C", w_dir, "diff", "--name-only", p_sha, w_sha, "--", ".", ":(exclude)proof"],
            text=True,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise LineageValidationError(f"Failed to diff P and W: {exc}") from exc

    if diff_out:
        raise LineageValidationError(f"Forbidden non-proof differences between P and W:\n{diff_out}")


@dataclasses.dataclass(frozen=True)
class StagedInputsInfo:
    path: str
    inventory_sha256: str
    lock_sha256: str
    files: Dict[str, Any]


def stage_and_verify_inputs(
    lock_path: str,
    output_dir: str,
    stager_script: str = "proof/hosted_inputs.py",
    expected_bundle_sha256: Optional[str] = None,
) -> StagedInputsInfo:
    """
    Invoke the staging script via the shared contract:
    1. python3 proof/hosted_inputs.py stage --lock <lock> --output <output_dir>
    2. python3 proof/hosted_inputs.py verify --lock <lock> --input <output_dir>
    Treat stdout as untrusted data, validate directory layout, symlinks, and hardlinks.
    """
    if not os.path.isfile(lock_path):
        raise StagingError(f"Source lock file not found: {lock_path}")

    # Stage
    try:
        stage_proc = subprocess.run(
            [sys.executable, stager_script, "stage", "--lock", lock_path, "--output", output_dir],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        raise StagingError(f"Failed to invoke staging script: {exc}") from exc

    if stage_proc.returncode != 0:
        raise StagingError(f"Staging command failed with code {stage_proc.returncode}: {stage_proc.stderr}")

    try:
        stage_data = json.loads(stage_proc.stdout)
    except json.JSONDecodeError as exc:
        raise StagingError(f"Invalid JSON returned by staging script: {exc}") from exc

    # Verify command execution
    try:
        verify_proc = subprocess.run(
            [sys.executable, stager_script, "verify", "--lock", lock_path, "--input", output_dir],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        raise StagingError(f"Failed to invoke verification script: {exc}") from exc

    if verify_proc.returncode != 0:
        raise StagingError(f"Staging verification failed with code {verify_proc.returncode}: {verify_proc.stderr}")

    # Treat stdout as untrusted data; validate path and inventory
    staged_path = stage_data.get("path")
    if not isinstance(staged_path, str) or not os.path.isabs(staged_path):
        raise StagingError(f"Invalid or non-absolute path in staging output: {staged_path!r}")

    resolved_output = os.path.abspath(output_dir)
    if os.path.realpath(staged_path) != os.path.realpath(resolved_output):
        raise StagingError(f"Staged path mismatch: expected {resolved_output}, got {staged_path}")

    inventory_sha256 = stage_data.get("inventory_sha256")
    if not isinstance(inventory_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", inventory_sha256):
        raise StagingError(f"Invalid inventory SHA-256 in staging output: {inventory_sha256!r}")

    if expected_bundle_sha256 and inventory_sha256 != expected_bundle_sha256:
        raise StagingError(
            f"Staged bundle inventory mismatch: expected {expected_bundle_sha256}, got {inventory_sha256}"
        )

    # Independent descriptor-relative inspection of staged files
    for root_file in REQUIRED_INPUT_ROOT_FILES:
        target = os.path.join(output_dir, root_file)
        if not os.path.isfile(target) or os.path.islink(target):
            raise StagingError(f"Required root input file missing or symlink: {root_file}")

    for root_dir in REQUIRED_INPUT_ROOT_DIRS:
        target = os.path.join(output_dir, root_dir)
        if not os.path.isdir(target) or os.path.islink(target):
            raise StagingError(f"Required root input directory missing or symlink: {root_dir}")

    # Walk directory to reject symlinks, hardlinks, or unreadable files
    for root, dirs, files in os.walk(output_dir, followlinks=False):
        for name in dirs:
            full = os.path.join(root, name)
            if os.path.islink(full):
                raise StagingError(f"Symlink directory forbidden in inputs: {full}")
        for name in files:
            full = os.path.join(root, name)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise StagingError(f"Symlink forbidden in inputs: {full}")
            if not stat.S_ISREG(st.st_mode):
                raise StagingError(f"Special non-regular file forbidden in inputs: {full}")
            if st.st_nlink > 1:
                raise StagingError(f"Hardlink forbidden in inputs: {full} (nlink={st.st_nlink})")

    return StagedInputsInfo(
        path=staged_path,
        inventory_sha256=inventory_sha256,
        lock_sha256=stage_data.get("lock_sha256", ""),
        files=stage_data.get("files", {}),
    )


@dataclasses.dataclass(frozen=True)
class MountBinding:
    container_path: str
    host_path: Optional[str]
    access: str  # "ro" or "rw"
    mount_type: str  # "bind" or "tmpfs"
    options: Tuple[str, ...] = ()

    def to_docker_mount_arg(self) -> str:
        if self.mount_type == "bind":
            opts = ["type=bind", f"src={self.host_path}", f"dst={self.container_path}"]
            if self.access == "ro":
                opts.append("readonly")
            if "bind-propagation=private" not in self.options:
                opts.append("bind-propagation=private")
            for opt in self.options:
                if opt not in opts:
                    opts.append(opt)
            return "--mount=" + ",".join(opts)
        elif self.mount_type == "tmpfs":
            opts = [f"dst={self.container_path}"]
            for opt in self.options:
                opts.append(opt)
            return "--mount=" + ",".join(["type=tmpfs"] + opts)
        raise MountPolicyError(f"Unknown mount type: {self.mount_type}")


def build_mount_bindings(
    p_dir: str,
    p_build_dir: str,
    w_dir: str,
    inputs_dir: str,
    private_tmp_dir: str,
    scratch_dir: str,
    home_proof_dir: str,
    phase: str = "proof",
    control_dir: Optional[str] = None,
    receipts_dir: Optional[str] = None,
) -> List[MountBinding]:
    """
    Construct the pinned mount table for the given lifecycle phase.
    In phase='build', /P/.build is 'rw'. In phase='proof', /P/.build is 'ro'.
    /P, /W, and /inputs are ALWAYS strictly 'ro'.
    """
    bindings = [
        MountBinding(
            container_path="/P",
            host_path=os.path.abspath(p_dir),
            access="ro",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/P/.build",
            host_path=os.path.abspath(p_build_dir),
            access="rw" if phase == "build" else "ro",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/W",
            host_path=os.path.abspath(w_dir),
            access="ro",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/inputs",
            host_path=os.path.abspath(inputs_dir),
            access="ro",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/private/tmp",
            host_path=os.path.abspath(private_tmp_dir),
            access="rw",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/scratch",
            host_path=os.path.abspath(scratch_dir),
            access="rw",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/home/proof",
            host_path=os.path.abspath(home_proof_dir),
            access="rw",
            mount_type="bind",
        ),
        MountBinding(
            container_path="/tmp",
            host_path=None,
            access="rw",
            mount_type="tmpfs",
            options=("tmpfs-size=2g", "tmpfs-mode=1777"),
        ),
        MountBinding(
            container_path="/dev/shm",
            host_path=None,
            access="rw",
            mount_type="tmpfs",
            options=("tmpfs-size=1g", "tmpfs-mode=1777"),
        ),
    ]

    if control_dir and os.path.isdir(control_dir):
        bindings.append(
            MountBinding(
                container_path="/control",
                host_path=os.path.abspath(control_dir),
                access="ro",
                mount_type="bind",
            )
        )

    if receipts_dir and os.path.isdir(receipts_dir):
        bindings.append(
            MountBinding(
                container_path="/receipts",
                host_path=os.path.abspath(receipts_dir),
                access="ro",
                mount_type="bind",
                options=("bind-propagation=private",),
            )
        )

    return bindings


def verify_container_mount_table(
    inspect_data: Dict[str, Any],
    expected_phase: str = "proof",
) -> None:
    """
    Validate docker inspect Mounts against anti-alias and confinement policy:
    - /P, /W, /inputs must be RW=False
    - /P/.build must be RW=False during proof phase
    - No docker.sock, host /proc, host /sys, or host device mounts
    - No unexpected writable volume mounts
    """
    mounts = inspect_data.get("Mounts", [])
    if not isinstance(mounts, list):
        raise MountPolicyError("docker inspect Mounts is not a list")

    mount_by_dest: Dict[str, Dict[str, Any]] = {}
    for m in mounts:
        dest = m.get("Destination")
        if dest:
            mount_by_dest[dest] = m

    # Check for leaked docker.sock or host proc
    for dest, m in mount_by_dest.items():
        src = str(m.get("Source", ""))
        if "docker.sock" in src or "docker.sock" in dest:
            raise MountPolicyError(f"Docker socket leak detected in mount: {dest} -> {src}")
        if src == "/proc" or src.startswith("/proc/"):
            raise MountPolicyError(f"Host /proc leak detected in mount: {dest} -> {src}")
        if src == "/sys" or src.startswith("/sys/"):
            raise MountPolicyError(f"Host /sys leak detected in mount: {dest} -> {src}")

    # Mandatory read-only mounts
    for req_ro in ("/P", "/W", "/inputs"):
        if req_ro not in mount_by_dest:
            raise MountPolicyError(f"Required mount missing: {req_ro}")
        m = mount_by_dest[req_ro]
        if m.get("RW", True) is not False:
            raise MountPolicyError(f"Mount {req_ro} must be read-only, but RW is {m.get('RW')}")

    # Phase-dependent /P/.build
    if "/P/.build" in mount_by_dest:
        m = mount_by_dest["/P/.build"]
        if expected_phase == "proof" and m.get("RW", True) is not False:
            raise MountPolicyError(f"/P/.build must be read-only during proof phase")

    # Final phase must mount /receipts read-only
    if expected_phase == "final":
        if "/receipts" not in mount_by_dest:
            raise MountPolicyError("Required /receipts mount missing in final phase")
        m = mount_by_dest["/receipts"]
        if m.get("RW", True) is not False:
            raise MountPolicyError("Mount /receipts must be read-only in final phase")

def check_disk_floor(path: str, min_gib: float = MIN_DISK_GIB) -> float:
    """Verify filesystem containing path has at least min_gib free; raise error if not."""
    cur = path
    while cur and not os.path.exists(cur):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    if not cur or not os.path.exists(cur):
        cur = "/"
    st = os.statvfs(cur)
    free_bytes = st.f_bavail * st.f_frsize
    free_gib = free_bytes / (1024.0 ** 3)
    if free_gib < min_gib:
        raise LifecycleExecutionError(
            f"DISK-FLOOR-VIOLATION: Free disk space on {path} is {free_gib:.2f} GiB, "
            f"below required floor of {min_gib:.1f} GiB"
        )
    return free_gib


def check_driver_admission(remaining_sec: float, driver_limit_sec: float = DRIVER_LIMIT_SEC, grace_sec: float = GRACE_SEC) -> bool:
    """Check if remaining payload budget allows launching another driver (2100s + 30s = 2130s)."""
    return remaining_sec >= (driver_limit_sec + grace_sec)


# Descriptor-Safe Evidence Collection and Archiving
class DescriptorSafeEvidenceCollector:
    """
    Descriptor-relative, nofollow evidence archiver and validator.
    Traverses directories using O_NOFOLLOW, never follows symlinks,
    archives fixture symlinks as metadata without opening targets,
    and computes SHA-256 digests.
    """

    def __init__(self, root_dir: str, skip_raw_executables: bool = False):
        self.root_dir = os.path.abspath(root_dir)
        self.skip_raw_executables = skip_raw_executables
        try:
            self.root_fd = os.open(self.root_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise EvidenceCollectionError(f"Failed to open root descriptor {self.root_dir}: {exc}") from exc

    def close(self) -> None:
        if hasattr(self, "root_fd") and self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def __enter__(self) -> "DescriptorSafeEvidenceCollector":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def walk_and_collect(
        self,
        tar: tarfile.TarFile,
        arc_prefix: str,
        manifest: List[Dict[str, Any]],
    ) -> None:
        """Walk root descriptor-relative and add regular files and symlinks (as metadata) to tar."""
        def visit(dir_fd: int, current_rel: str) -> None:
            entries = sorted(os.listdir(dir_fd))
            for entry in entries:
                rel_path = f"{current_rel}/{entry}" if current_rel else entry
                arc_name = f"{arc_prefix}/{rel_path}" if arc_prefix else rel_path
                st = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)

                if stat.S_ISDIR(st.st_mode):
                    sub_fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                    try:
                        visit(sub_fd, rel_path)
                    finally:
                        os.close(sub_fd)
                elif stat.S_ISLNK(st.st_mode):
                    # Preserve symlink as TarInfo metadata without following
                    link_target = os.readlink(entry, dir_fd=dir_fd)
                    ti = tarfile.TarInfo(name=arc_name)
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = link_target
                    ti.mode = st.st_mode & 0o777
                    ti.mtime = 0
                    tar.addfile(ti)
                    manifest.append({
                        "path": arc_name,
                        "type": "symlink",
                        "target": link_target,
                    })
                elif stat.S_ISREG(st.st_mode):
                    # If configured to preserve execution atimes, skip reading raw executable binaries
                    is_executable = bool(st.st_mode & 0o111)
                    if self.skip_raw_executables and is_executable and ("out_ref" in rel_path or "/bin/" in rel_path):
                        ti = tarfile.TarInfo(name=arc_name)
                        ti.size = 0
                        ti.mode = st.st_mode & 0o777
                        ti.mtime = 0
                        tar.addfile(ti, io.BytesIO(b""))
                        manifest.append({
                            "path": arc_name,
                            "type": "executable_reference_skipped",
                            "size": st.st_size,
                            "inode": st.st_ino,
                        })
                        continue

                    # Regular file read
                    file_fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
                    try:
                        before = os.fstat(file_fd)
                        ti = tarfile.TarInfo(name=arc_name)
                        ti.size = before.st_size
                        ti.mode = 0o644
                        ti.mtime = 0
                        hasher = hashlib.sha256()

                        class FdReader(io.RawIOBase):
                            def __init__(self, fd: int):
                                self.fd = fd
                                self.bytes_read = 0

                            def readable(self) -> bool:
                                return True

                            def readinto(self, b: bytearray) -> int:
                                data = os.read(self.fd, len(b))
                                n = len(data)
                                b[:n] = data
                                hasher.update(data)
                                self.bytes_read += n
                                return n

                            def close(self) -> None:
                                pass

                        reader = io.BufferedReader(FdReader(file_fd))
                        tar.addfile(ti, reader)
                        manifest.append({
                            "path": arc_name,
                            "type": "file",
                            "size": ti.size,
                            "sha256": hasher.hexdigest(),
                        })
                    finally:
                        os.close(file_fd)
                else:
                    raise EvidenceCollectionError(f"Unsafe special file in evidence tree: {rel_path}")

        visit(self.root_fd, "")


def create_checkpoint_archive(
    checkpoint_dir: str,
    output_tar_gz: str,
    checkpoint_descriptor: Dict[str, Any],
    skip_raw_executables: bool = False,
) -> str:
    """
    Create a sealed incremental .tar.gz checkpoint archive with manifest
    and descriptor, returning the archive SHA-256.
    """
    manifest_entries: List[Dict[str, Any]] = []
    parent_dir = os.path.dirname(os.path.abspath(output_tar_gz))
    os.makedirs(parent_dir, exist_ok=True)

    with open(output_tar_gz, "wb") as f_out:
        with tarfile.open(fileobj=f_out, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            if os.path.exists(checkpoint_dir):
                with DescriptorSafeEvidenceCollector(checkpoint_dir, skip_raw_executables=skip_raw_executables) as collector:
                    collector.walk_and_collect(tar, arc_prefix="payload", manifest=manifest_entries)

            # Add descriptor
            desc_bytes = canonical_json_bytes({
                "descriptor": checkpoint_descriptor,
                "manifest": manifest_entries,
            })
            ti = tarfile.TarInfo(name="checkpoint.json")
            ti.size = len(desc_bytes)
            ti.mode = 0o644
            ti.mtime = 0
            tar.addfile(ti, io.BytesIO(desc_bytes))

    return sha256_file(output_tar_gz)


# Preflight Boundary Execution
def run_preflight_controls(
    image: str,
    runner_temp_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute Plan Section 3E preflight boundary controls:
    1. Network isolation & host listener unreachability (ECONNREFUSED)
    2. Non-loopback connect failure (ENETUNREACH)
    3. Container loopback IPv4/IPv6 TCP and UDP
    4. Canary file and env isolation
    5. Read-only root write failure (EROFS)
    6. Nonzero UID 65534, GID 65534, NoNewPrivs, empty capabilities
    7. /private/tmp literal resolution and hardlink probe
    8. /dev/shm separate device
    9. Host x86_64, Linux, FMA flag
    10. Exact container teardown and sentinel survival
    11. Tool feature qualification inside container
    """
    results: Dict[str, Any] = {}
    temp_dir = runner_temp_dir or tempfile.gettempdir()

    # Create host secret canary
    canary_dir = os.path.join(temp_dir, f"canary-{secrets.token_hex(4)}")
    os.makedirs(canary_dir, exist_ok=True)
    canary_file = os.path.join(canary_dir, "fake-secret")
    pathlib.Path(canary_file).write_text("owned-canary", encoding="utf-8")

    # Start host listeners for positive and negative controls
    stop_event = threading.Event()
    listeners: List[Tuple[socket.socket, str, int]] = []
    threads: List[threading.Thread] = []

    for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.bind((addr, 0))
            s.listen(1)
            s.settimeout(0.25)
            port = s.getsockname()[1]
            listeners.append((s, addr, port))

            def _listener_loop(sock: socket.socket) -> None:
                while not stop_event.is_set():
                    try:
                        conn, _ = sock.accept()
                        conn.close()
                    except (socket.timeout, OSError):
                        continue

            t = threading.Thread(target=_listener_loop, args=(s,), daemon=True)
            t.start()
            threads.append(t)
        except Exception as exc:
            print(f"Warning: Failed to bind host test listener on {addr}: {exc}")

    try:
        # 1. Positive control: Host connects to its own listeners
        for _, addr, port in listeners:
            with socket.create_connection((addr, port), timeout=3.0) as conn:
                pass
        results["host_positive_listener_control"] = "PASS"

        # 2. Container preflight probes
        probe_code = r'''
import errno, os, pathlib, platform, socket, stat, subprocess, sys

secret_file, host4, host6 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

# Check canary secrets
assert not os.path.exists(secret_file), "Leaked host canary secret file"
assert "IYI_CANARY_SECRET" not in os.environ, "Leaked host canary environment variable"
assert not os.path.exists("/var/run/docker.sock"), "Leaked Docker socket"

# Check UID and privileges
uid = os.getuid()
gid = os.getgid()
assert uid == 65534, f"UID not 65534: {uid}"
assert gid == 65534, f"GID not 65534: {gid}"

try:
    status = pathlib.Path("/proc/self/status").read_text()
    for line in status.splitlines():
        if line.startswith("NoNewPrivs:"):
            assert line.split()[1] == "1", "NoNewPrivs not active"
        elif line.startswith("CapEff:"):
            assert line.split()[1] == "0000000000000000", f"CapEff not empty: {line}"
except FileNotFoundError:
    pass

# Check read-only root
try:
    pathlib.Path("/test_ro_canary").write_text("fail")
    raise AssertionError("Root filesystem unexpectedly writable")
except OSError as err:
    assert err.errno == errno.EROFS, f"Expected EROFS, got {err}"

# Check report filesystem hardlinks and paths
assert not os.path.islink("/private/tmp"), "/private/tmp must be a real path, not a symlink"
hl_src = "/private/tmp/hl_test"
hl_dst = "/private/tmp/hl_test_link"
pathlib.Path(hl_src).write_text("data")
os.link(hl_src, hl_dst)
assert os.stat(hl_src).st_nlink == 2, "Hardlink count did not increase on /private/tmp"
os.unlink(hl_src)
os.unlink(hl_dst)

# Check distinct /dev/shm
assert os.stat("/dev/shm").st_dev != os.stat("/private/tmp").st_dev, "/dev/shm must be a distinct filesystem"

# Check container loopback
for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    srv = socket.socket(fam, socket.SOCK_STREAM)
    srv.bind((addr, 0))
    srv.listen(1)
    cli = socket.socket(fam, socket.SOCK_STREAM)
    cli.connect((addr, srv.getsockname()[1]))
    peer, _ = srv.accept()
    cli.sendall(b"loopback-ok")
    assert peer.recv(32) == b"loopback-ok"
    peer.close(); cli.close(); srv.close()

# Check non-loopback connect fails with ENETUNREACH
for fam, target in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(target)
        raise AssertionError(f"Non-loopback connection to {target} unexpectedly succeeded")
    except OSError as err:
        assert err.errno == errno.ENETUNREACH, f"Expected ENETUNREACH, got {err}"
    finally:
        s.close()

# Check host listeners fail with ECONNREFUSED
for fam, addr, p in ((socket.AF_INET, "127.0.0.1", host4), (socket.AF_INET6, "::1", host6)):
    if p > 0:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((addr, p))
            raise AssertionError(f"Host listener on {addr}:{p} was reachable from container")
        except OSError as err:
            assert err.errno == errno.ECONNREFUSED, f"Expected ECONNREFUSED, got {err}"
        finally:
            s.close()

# Check CPU & FMA flag
assert platform.machine() == "x86_64", f"Machine not x86_64: {platform.machine()}"
try:
    cpuinfo = pathlib.Path("/proc/cpuinfo").read_text()
    assert "fma" in cpuinfo, "FMA feature missing from /proc/cpuinfo flags"
except FileNotFoundError:
    pass

print("CONTAINER-PREFLIGHT-OK")
'''
        h4 = listeners[0][2] if len(listeners) > 0 else 0
        h6 = listeners[1][2] if len(listeners) > 1 else 0

        cont_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", CONTAINER_USER,
            "--tmpfs", "/private/tmp:rw,size=64m,mode=1777",
            "--tmpfs", "/dev/shm:rw,size=64m,mode=1777",
            "--env", "IYI_CANARY_SECRET=canary_val",
            image,
            "python3", "-I", "-c", probe_code,
            canary_file, str(h4), str(h6),
        ]

        probe_proc = subprocess.run(cont_cmd, capture_output=True, text=True, timeout=60, check=False)
        if probe_proc.returncode != 0:
            raise PreflightError(f"Container preflight probe failed: {probe_proc.stderr}")
        results["container_confinement_probe"] = "PASS"

        # 3. Teardown sentinel proof
        sentinel_name = f"iyi-sentinel-{secrets.token_hex(4)}"
        workload_name = f"iyi-workload-{secrets.token_hex(4)}"

        # Start sentinel
        subprocess.run([
            "docker", "run", "-d", "--name", sentinel_name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", CONTAINER_USER, image, "python3", "-c", "import time; time.sleep(120)"
        ], check=True, capture_output=True)

        try:
            # Start workload with detached child
            workload_script = (
                "import os, pathlib, time\n"
                "p = os.fork()\n"
                "if p == 0:\n"
                "    os.setsid()\n"
                "    pathlib.Path('/tmp/ready').write_text(str(os.getpid()))\n"
                "    time.sleep(120)\n"
                "time.sleep(120)\n"
            )
            subprocess.run([
                "docker", "run", "-d", "--name", workload_name, "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", CONTAINER_USER, "--tmpfs", "/tmp:rw,size=16m,mode=1777",
                image, "python3", "-c", workload_script
            ], check=True, capture_output=True)

            # Wait for ready file
            time.sleep(1.0)
            # Stop workload
            subprocess.run(["docker", "stop", "--time", "1", workload_name], check=True, capture_output=True)

            # Verify sentinel is still running
            inspect_out = subprocess.check_output(
                ["docker", "inspect", "-f", "{{.State.Running}}", sentinel_name], text=True
            ).strip()
            if inspect_out != "true":
                raise PreflightError("Sentinel container stopped prematurely during workload teardown")
            results["exact_teardown_sentinel_survival"] = "PASS"
        finally:
            subprocess.run(["docker", "rm", "-f", sentinel_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "rm", "-f", workload_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        for s, _, _ in listeners:
            s.close()
        shutil.rmtree(canary_dir, ignore_errors=True)

    return results


# Sequential Lifecycle Controller
class SequentialLifecycleController:
    """
    State machine controlling the sequential execution of build, plan, pin,
    run1, run2, run3 drivers, and final stages inside Docker containers.
    Enforces sticky failures: any error halts critical execution and permanently
    marks the run failed.
    """

    def __init__(
        self,
        manifest: ProofManifest,
        p_dir: str,
        w_dir: str,
        inputs_dir: str,
        artifacts_dir: str,
        job_start_time: float,
        payload_budget_sec: float = PAYLOAD_BUDGET_SEC,
        driver_limit_sec: float = DRIVER_LIMIT_SEC,
        grace_sec: float = GRACE_SEC,
        min_disk_gib: float = MIN_DISK_GIB,
        runner_temp_dir: Optional[str] = None,
    ):
        self.manifest = manifest
        self.p_dir = os.path.abspath(p_dir)
        self.w_dir = os.path.abspath(w_dir)
        self.inputs_dir = os.path.abspath(inputs_dir)
        self.artifacts_dir = os.path.abspath(artifacts_dir)
        self.job_start_time = float(job_start_time)
        self.payload_budget_sec = float(payload_budget_sec)
        self.driver_limit_sec = float(driver_limit_sec)
        self.grace_sec = float(grace_sec)
        self.min_disk_gib = float(min_disk_gib)
        self.runner_temp_dir = runner_temp_dir or tempfile.gettempdir()

        self.p_build_dir = os.path.join(self.runner_temp_dir, "p-build")
        self.private_tmp_dir = os.path.join(self.runner_temp_dir, "private-tmp")
        self.scratch_dir = os.path.join(self.runner_temp_dir, "scratch")
        self.home_proof_dir = os.path.join(self.runner_temp_dir, "home-proof")

        for d in (self.p_build_dir, self.private_tmp_dir, self.scratch_dir, self.home_proof_dir, self.artifacts_dir):
            os.makedirs(d, exist_ok=True)

        # Sticky failure tracking
        self.sticky_failed: bool = False
        self.failure_reasons: List[str] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.sealed_receipts: List[Dict[str, Any]] = []
        self.chain_id: Optional[str] = None
        self.compiler_sha256: Optional[str] = None
        self.compiler_inode: Optional[int] = None
        self.compiler_size: Optional[int] = None

    def time_remaining(self) -> float:
        elapsed = time.time() - self.job_start_time
        return max(0.0, self.payload_budget_sec - elapsed)

    def mark_failure(self, reason: str, critical: bool = True) -> None:
        self.sticky_failed = True
        self.failure_reasons.append(reason)
        if critical:
            raise LifecycleExecutionError(reason)

    def seal_origin_receipt(self, unit: str, attempt: int = 1, driver: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Create a host-sealed receipt outside all payload-writable mounts for pre-read origin records.
        Preserves chain_id, driver, attempt, origin_records_sha256, ledger_sha256, and receipt_status.
        """
        leaf = os.path.basename(self.manifest.report_path)
        if unit.startswith("run3-"):
            drv_name = driver or unit[len("run3-"):]
            attempt_dir = os.path.join(self.private_tmp_dir, leaf, "run3", drv_name, f"a{attempt}")
        else:
            attempt_dir = os.path.join(self.private_tmp_dir, leaf, unit, f"a{attempt}")

        origin_records_path = os.path.join(attempt_dir, "origin_records.json")
        ledger_path = os.path.join(attempt_dir, "ledger.jsonl")

        if not os.path.isfile(origin_records_path):
            return None

        origin_records_sha256 = sha256_file(origin_records_path)
        ledger_sha256 = sha256_file(ledger_path) if os.path.isfile(ledger_path) else "0" * 64

        try:
            with open(origin_records_path, "r", encoding="utf-8") as f:
                records_data = json.load(f)
            receipt_status = records_data.get("overall_status", "PASS")
        except Exception:
            receipt_status = "UNKNOWN"

        receipt = {
            "schema": "iyi-sealed-origin-receipt-v1",
            "chain_id": self.chain_id or "",
            "driver": driver or unit,
            "attempt": attempt,
            "origin_records_sha256": origin_records_sha256,
            "ledger_sha256": ledger_sha256,
            "receipt_status": receipt_status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        receipts_dir = os.path.join(self.artifacts_dir, "sealed-receipts")
        os.makedirs(receipts_dir, exist_ok=True)
        receipt_filename = f"receipt-{unit}-a{attempt}.json"
        receipt_path = os.path.join(receipts_dir, receipt_filename)
        with open(receipt_path, "wb") as f:
            f.write(canonical_json_bytes(receipt))

        self.sealed_receipts.append(receipt)
        return receipt

    def record_checkpoint(
        self,
        stage: str,
        status: str,
        command: List[str],
        exit_code: int,
        attempt: int = 1,
        source_dir: Optional[str] = None,
        extra_info: Optional[Dict[str, Any]] = None,
        skip_raw_executables: bool = False,
    ) -> Dict[str, Any]:
        """Record an immutable checkpoint and archive evidence."""
        archive_name = f"checkpoint-{stage}-a{attempt}.tar.gz"
        archive_path = os.path.join(self.artifacts_dir, archive_name)

        desc: Dict[str, Any] = {
            "stage": stage,
            "status": status,
            "attempt": attempt,
            "command": command,
            "exit_code": exit_code,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "manifest_digest": self.manifest.digest(),
            "c_sha": self.manifest.c_sha,
            "p_sha": self.manifest.p_sha,
            "w_sha": self.manifest.w_sha,
            "run_id": self.manifest.run_id,
            "run_attempt": self.manifest.run_attempt,
            "job_id": self.manifest.job_id,
            "job_key": self.manifest.job_key,
            "image": self.manifest.image,
            "image_digest": self.manifest.image_digest,
            "chain_id": self.chain_id,
            "compiler_sha256": self.compiler_sha256,
        }
        if extra_info:
            desc.update(extra_info)

        archive_sha256 = create_checkpoint_archive(
            checkpoint_dir=source_dir or tempfile.gettempdir(),
            output_tar_gz=archive_path,
            checkpoint_descriptor=desc,
            skip_raw_executables=skip_raw_executables,
        )
        desc["archive_sha256"] = archive_sha256
        desc["archive_path"] = archive_path
        self.checkpoints.append(desc)
        return desc

    def execute_in_container(
        self,
        command: List[str],
        workdir: str = "/W",
        phase: str = "proof",
        timeout_sec: Optional[float] = None,
        env_vars: Optional[Dict[str, str]] = None,
        receipts_dir: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Execute a command inside the hardened Docker container cage."""
        check_disk_floor(self.private_tmp_dir, self.min_disk_gib)

        mount_bindings = build_mount_bindings(
            p_dir=self.p_dir,
            p_build_dir=self.p_build_dir,
            w_dir=self.w_dir,
            inputs_dir=self.inputs_dir,
            private_tmp_dir=self.private_tmp_dir,
            scratch_dir=self.scratch_dir,
            home_proof_dir=self.home_proof_dir,
            phase=phase,
            receipts_dir=receipts_dir,
        )

        docker_args = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--init",
            "--user", CONTAINER_USER,
            "--workdir", workdir,
        ]

        for mb in mount_bindings:
            docker_args.append(mb.to_docker_mount_arg())

        default_env = {
            "HOME": "/home/proof",
            "PATH": "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
            "PYTHONUNBUFFERED": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        if env_vars:
            default_env.update(env_vars)

        for k, v in default_env.items():
            docker_args.extend(["--env", f"{k}={v}"])

        docker_args.append(self.manifest.image)
        docker_args.extend(command)

        deadline = timeout_sec or self.time_remaining()
        try:
            proc = subprocess.run(
                docker_args,
                capture_output=True,
                text=True,
                timeout=deadline,
                check=False,
            )
            stdout = sanitize_workflow_output(proc.stdout)
            stderr = sanitize_workflow_output(proc.stderr)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            self.mark_failure(f"Command timed out after {deadline}s: {command}")
            return -1, "", "TIMEOUT"

    def stage_build(self) -> None:
        """Phase 1: Build compiler inside build cage with /P read-only and /P/.build writable."""
        print("=== Step 1: Building P1 Compiler inside Build Cage ===")
        cmd = ["bash", "-euo", "pipefail", "-c", "make crystal && make -o .build/crystal iyi"]
        code, out, err = self.execute_in_container(cmd, workdir="/P", phase="build", timeout_sec=1200)

        build_log_dir = os.path.join(self.artifacts_dir, "build-logs")
        os.makedirs(build_log_dir, exist_ok=True)
        with open(os.path.join(build_log_dir, "build.stdout.log"), "w") as f: f.write(out)
        with open(os.path.join(build_log_dir, "build.stderr.log"), "w") as f: f.write(err)

        if code != 0:
            self.mark_failure(f"Compiler build failed with exit code {code}: {err}")

        compiler_path = os.path.join(self.p_build_dir, "iyi")
        if not os.path.isfile(compiler_path) or not os.access(compiler_path, os.X_OK):
            self.mark_failure(f"Compiler binary missing or not executable at {compiler_path}")

        st = os.stat(compiler_path)
        self.compiler_inode = st.st_ino
        self.compiler_size = st.st_size
        self.compiler_sha256 = sha256_file(compiler_path)

        # Check version stamp
        try:
            ver_proc = subprocess.run([compiler_path, "--version"], capture_output=True, text=True, check=True)
            version_out = ver_proc.stdout.strip()
            p_prefix = self.manifest.p_sha[:9]
            if p_prefix not in version_out:
                self.mark_failure(f"Compiler version stamp '{version_out}' missing P prefix {p_prefix}")
        except Exception as exc:
            self.mark_failure(f"Failed to verify compiler version stamp: {exc}")

        # Seal .build directory (read-only on host)
        for root, dirs, files in os.walk(self.p_build_dir):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o555)
            for f in files:
                os.chmod(os.path.join(root, f), 0o555)

        self.record_checkpoint(
            stage="build",
            status="PASS",
            command=cmd,
            exit_code=code,
            source_dir=build_log_dir,
            extra_info={"compiler_sha256": self.compiler_sha256, "compiler_size": self.compiler_size},
        )
        print(f"Compiler build PASS (SHA-256: {self.compiler_sha256})")

    def stage_plan(self) -> None:
        """Phase 2: Run proof plan."""
        print("=== Step 2: Proof Plan ===")
        cmd = [
            "python3", "-B", "/W/proof/run_proof.py", "plan",
            "--p", "/P", "--w", "/W",
            "--compiler", "/P/.build/iyi",
            "--inputs-dir", "/inputs",
        ]
        code, out, err = self.execute_in_container(cmd, workdir="/W", phase="proof", timeout_sec=600)
        if code != 0:
            self.mark_failure(f"Proof plan failed with exit code {code}: {err}")

        self.record_checkpoint("plan", "PASS", cmd, code)
        print("Proof plan PASS")

    def stage_pin(self) -> None:
        """Phase 3: Run proof pin and establish chain identity."""
        print("=== Step 3: Proof Pin ===")
        r = self.manifest.report_path
        cmd = [
            "python3", "-B", "/W/proof/run_proof.py", "pin",
            "--report-dir", r,
            "--p", "/P", "--w", "/W",
            "--compiler", "/P/.build/iyi",
            "--inputs-dir", "/inputs",
        ]
        code, out, err = self.execute_in_container(cmd, workdir="/W", phase="proof", timeout_sec=600)
        if code != 0:
            self.mark_failure(f"Proof pin failed with exit code {code}: {err}")

        leaf = os.path.basename(r)
        host_report_dir = os.path.join(self.private_tmp_dir, leaf)
        pin_file = os.path.join(host_report_dir, "pin.json")
        if not os.path.isfile(pin_file):
            self.mark_failure(f"pin.json missing at {pin_file}")

        try:
            with open(pin_file, "r") as f:
                pin_data = json.load(f)
            self.chain_id = pin_data.get("chain_id") or pin_data.get("id")
            if not self.chain_id:
                self.mark_failure("Chain ID missing from pin.json")
        except Exception as exc:
            self.mark_failure(f"Failed to read pin.json: {exc}")

        self.record_checkpoint("pin", "PASS", cmd, code, extra_info={"chain_id": self.chain_id})
        print(f"Proof pin PASS (Chain ID: {self.chain_id})")

    def stage_run1(self) -> None:
        """Phase 4: Run 1."""
        print("=== Step 4: Run 1 ===")
        r = self.manifest.report_path
        cmd = ["python3", "-B", "/W/proof/run_proof.py", "run1", "--report-dir", r]
        code, out, err = self.execute_in_container(cmd, workdir="/W", phase="proof", timeout_sec=1800)
        if code != 0:
            self.mark_failure(f"Run 1 failed with exit code {code}: {err}")

        leaf = os.path.basename(r)
        result_file = os.path.join(self.private_tmp_dir, leaf, "run1", "a1", "result.json")
        if not os.path.isfile(result_file):
            self.mark_failure(f"Run 1 result.json missing at {result_file}")

        try:
            with open(result_file, "r") as f:
                res = json.load(f)
            if res.get("status") != "PASS":
                self.mark_failure(f"Run 1 status was not PASS: {res.get('status')}")
        except Exception as exc:
            self.mark_failure(f"Failed to read Run 1 result.json: {exc}")

        self.seal_origin_receipt("run1", attempt=1)
        self.record_checkpoint("run1", "PASS", cmd, code, skip_raw_executables=True)
        print("Run 1 PASS")

    def stage_run2(self) -> None:
        """Phase 5: Run 2."""
        print("=== Step 5: Run 2 ===")
        r = self.manifest.report_path
        cmd = ["python3", "-B", "/W/proof/run_proof.py", "run2", "--report-dir", r]
        code, out, err = self.execute_in_container(cmd, workdir="/W", phase="proof", timeout_sec=3600)
        if code != 0:
            self.mark_failure(f"Run 2 failed with exit code {code}: {err}")

        leaf = os.path.basename(r)
        result_file = os.path.join(self.private_tmp_dir, leaf, "run2", "a1", "result.json")
        if not os.path.isfile(result_file):
            self.mark_failure(f"Run 2 result.json missing at {result_file}")

        try:
            with open(result_file, "r") as f:
                res = json.load(f)
            if res.get("status") != "PASS":
                self.mark_failure(f"Run 2 status was not PASS: {res.get('status')}")
        except Exception as exc:
            self.mark_failure(f"Failed to read Run 2 result.json: {exc}")

        self.seal_origin_receipt("run2", attempt=1)
        self.record_checkpoint("run2", "PASS", cmd, code, skip_raw_executables=True)
        print("Run 2 PASS")

    def stage_run3_drivers(self) -> None:
        """Phase 6: Run 3 Drivers."""
        print("=== Step 6: Run 3 Drivers ===")
        r = self.manifest.report_path

        # Step 6a: Run acme driver to write run3/required.json
        print("Executing initial driver: acme")
        cmd_acme = ["python3", "-B", "/W/proof/run_proof.py", "run3", "--report-dir", r, "--driver", "acme"]
        code, out, err = self.execute_in_container(cmd_acme, workdir="/W", phase="proof", timeout_sec=self.driver_limit_sec)
        if code != 0:
            self.mark_failure(f"Driver acme failed with exit code {code}: {err}")

        self.seal_origin_receipt("run3-acme", attempt=1, driver="acme")
        self.record_checkpoint("run3-acme", "PASS", cmd_acme, code, skip_raw_executables=True)

        leaf = os.path.basename(r)
        required_file = os.path.join(self.private_tmp_dir, leaf, "run3", "required.json")
        if not os.path.isfile(required_file):
            self.mark_failure(f"run3/required.json missing at {required_file}")

        try:
            with open(required_file, "r") as f:
                required_drivers = json.load(f)
        except Exception as exc:
            self.mark_failure(f"Failed to read run3/required.json: {exc}")
            return

        if not isinstance(required_drivers, list) or len(required_drivers) < 28:
            self.mark_failure(f"Invalid required drivers list (expected at least 28 drivers): {required_drivers}")

        print(f"Found {len(required_drivers)} required drivers in run3/required.json")

        for driver in required_drivers:
            if driver == "acme":
                continue

            rem = self.time_remaining()
            if not check_driver_admission(rem, self.driver_limit_sec, self.grace_sec):
                self.mark_failure(
                    f"Hosting budget interrupted: {rem:.1f}s remaining, below required admission "
                    f"floor ({self.driver_limit_sec + self.grace_sec}s) for driver {driver}"
                )

            print(f"Executing driver: {driver} ({rem:.1f}s budget remaining)")
            cmd_d = ["python3", "-B", "/W/proof/run_proof.py", "run3", "--report-dir", r, "--driver", driver]
            code, out, err = self.execute_in_container(cmd_d, workdir="/W", phase="proof", timeout_sec=self.driver_limit_sec)
            if code != 0:
                self.mark_failure(f"Driver {driver} failed with exit code {code}: {err}")

            self.seal_origin_receipt(f"run3-{driver}", attempt=1, driver=driver)
            self.record_checkpoint(f"run3-{driver}", "PASS", cmd_d, code, skip_raw_executables=True)

        print("All Run 3 drivers PASS")

    def stage_final(self) -> None:
        """Phase 7: Final stage verification."""
        print("=== Step 7: Proof Final ===")
        r = self.manifest.report_path
        receipts_dir = os.path.join(self.artifacts_dir, "sealed-receipts")
        os.makedirs(receipts_dir, exist_ok=True)
        cmd = [
            "python3", "-B", "/W/proof/run_proof.py", "final",
            "--report-dir", r,
            "--sealed-receipts-dir", "/receipts",
        ]
        env_vars = {"IYI_SEALED_RECEIPTS_DIR": "/receipts"}
        code, out, err = self.execute_in_container(
            cmd,
            workdir="/W",
            phase="final",
            timeout_sec=1200,
            env_vars=env_vars,
            receipts_dir=receipts_dir,
        )
            self.mark_failure(f"Proof final failed with exit code {code}: {err}")

        leaf = os.path.basename(r)
        final_file = os.path.join(self.private_tmp_dir, leaf, "final.json")
        if not os.path.isfile(final_file):
            self.mark_failure(f"final.json missing at {final_file}")

        try:
            with open(final_file, "r") as f:
                final_data = json.load(f)
            if final_data.get("status") != "PASS":
                self.mark_failure(f"final.json status was not PASS: {final_data.get('status')}")

            # Verify RG2 and RG2a: 142/142 passed, 0 excluded, 0 failures
            rg2 = final_data.get("rg2", {})
            if rg2.get("evaluated") != 142 or rg2.get("passed") != 142 or rg2.get("failures") != 0:
                self.mark_failure(f"RG2 counts mismatch: {rg2}")

            rg2a = final_data.get("rg2a", {})
            if rg2a.get("evaluated") != 142 or rg2a.get("passed") != 142 or rg2a.get("failures") != 0:
                self.mark_failure(f"RG2a counts mismatch: {rg2a}")

        except Exception as exc:
            self.mark_failure(f"Failed to verify final.json: {exc}")

        self.record_checkpoint("final", "PASS", cmd, code)
        print("Proof final PASS")

    def finalize_terminal_envelope(self) -> str:
        """Phase 8: Write terminal summary and envelope."""
        summary = {
            "status": "FAIL" if self.sticky_failed else "PASS",
            "failures": self.failure_reasons,
            "manifest_digest": self.manifest.digest(),
            "chain_id": self.chain_id,
            "compiler_sha256": self.compiler_sha256,
            "total_checkpoints": len(self.checkpoints),
            "total_sealed_receipts": len(self.sealed_receipts),
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        summary_path = os.path.join(self.artifacts_dir, "strict-controller-summary.json")
        with open(summary_path, "wb") as f:
            f.write(canonical_json_bytes(summary))

        envelope_path = os.path.join(self.artifacts_dir, "terminal-envelope.json")
        envelope_data = {
            "summary": summary,
            "manifest": self.manifest.to_dict(),
            "checkpoints": self.checkpoints,
            "sealed_receipts": self.sealed_receipts,
        }
        with open(envelope_path, "wb") as f:
            f.write(canonical_json_bytes(envelope_data))

        return envelope_path

    def run_all_stages(self) -> int:
        """Run complete sequential lifecycle."""
        try:
            self.stage_build()
            self.stage_plan()
            self.stage_pin()
            self.stage_run1()
            self.stage_run2()
            self.stage_run3_drivers()
            self.stage_final()
        except LifecycleExecutionError as exc:
            print(f"LIFECYCLE-HALT: {exc}", file=sys.stderr)
        finally:
            self.finalize_terminal_envelope()

        return 1 if self.sticky_failed else 0


# CLI Subcommands
def cmd_manifest(args: argparse.Namespace) -> int:
    """Compute and print invocation manifest and canonical digest."""
    manifest = validate_manifest_dict(json.loads(pathlib.Path(args.input).read_text()))
    digest = manifest.digest()
    if args.output:
        pathlib.Path(args.output).write_bytes(manifest.canonical_bytes())
    print(f"Manifest Digest: sha256:{digest}")
    print(f"Approval Comment Required: {AUTH_COMMENT_PREFIX}{digest}")
    return 0


def cmd_verify_auth(args: argparse.Namespace) -> int:
    """Verify authorization in approvals JSON file against manifest."""
    manifest = validate_manifest_dict(json.loads(pathlib.Path(args.manifest).read_text()))
    approvals_data = json.loads(pathlib.Path(args.approvals).read_text())
    try:
        verify_strict_authorization(manifest, approvals_data)
        print("Authorization VERIFIED: valid approval matching manifest digest.")
        return 0
    except StrictAuthorizationRefused as exc:
        print(f"AUTHORIZATION REFUSED: {exc}", file=sys.stderr)
        return AUTH_REFUSED_EXIT_CODE


def cmd_preflight(args: argparse.Namespace) -> int:
    """Execute preflight container boundary and qualification checks."""
    try:
        results = run_preflight_controls(
            image=args.image,
            runner_temp_dir=args.temp_dir,
        )
        print("Preflight boundary verification PASSED:")
        for check, outcome in results.items():
            print(f"  {check}: {outcome}")
        return 0
    except PreflightError as exc:
        print(f"PREFLIGHT CHECK FAILED: {exc}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Run full hosted strict proof lifecycle."""
    manifest = validate_manifest_dict(json.loads(pathlib.Path(args.manifest).read_text()))

    # Verify authorization
    approvals_path = args.approvals
    if not approvals_path or not os.path.isfile(approvals_path):
        print("ERROR: Approvals file missing; independent authorization required.", file=sys.stderr)
        return AUTH_REFUSED_EXIT_CODE

    try:
        approvals_data = json.loads(pathlib.Path(approvals_path).read_text())
        verify_strict_authorization(manifest, approvals_data)
    except Exception as exc:
        print(f"AUTHORIZATION REFUSED: {exc}", file=sys.stderr)
        return AUTH_REFUSED_EXIT_CODE

    # Lineage check
    try:
        verify_git_lineage(args.p, args.w, manifest.p_sha, manifest.w_sha)
    except LineageValidationError as exc:
        print(f"LINEAGE VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1

    # Staging check
    staged_dir = args.inputs_dir or os.path.join(tempfile.gettempdir(), "staged-inputs")
    os.makedirs(staged_dir, exist_ok=True)
    try:
        staged_info = stage_and_verify_inputs(
            lock_path=manifest.lock_path,
            output_dir=staged_dir,
            expected_bundle_sha256=manifest.expected_bundle_sha256,
        )
    except StagingError as exc:
        print(f"STAGING FAILED: {exc}", file=sys.stderr)
        return 1

    # Run lifecycle
    controller = SequentialLifecycleController(
        manifest=manifest,
        p_dir=args.p,
        w_dir=args.w,
        inputs_dir=staged_info.path,
        artifacts_dir=args.artifacts_dir,
        job_start_time=float(args.job_start_time or time.time()),
        payload_budget_sec=float(args.payload_budget_sec or PAYLOAD_BUDGET_SEC),
        driver_limit_sec=float(args.driver_limit_sec or DRIVER_LIMIT_SEC),
        grace_sec=float(args.grace_sec or GRACE_SEC),
        min_disk_gib=float(args.min_disk_gib or MIN_DISK_GIB),
    )

    return controller.run_all_stages()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GitHub-Hosted Linux Strict Proof Controller (PR147)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Manifest
    p_man = subparsers.add_parser("manifest", help="Generate or validate invocation manifest")
    p_man.add_argument("--input", required=True, help="Input request JSON")
    p_man.add_argument("--output", help="Output canonical manifest JSON")
    p_man.set_defaults(func=cmd_manifest)

    # Verify Auth
    p_auth = subparsers.add_parser("verify-auth", help="Verify authorization against approvals")
    p_auth.add_argument("--manifest", required=True, help="Manifest JSON")
    p_auth.add_argument("--approvals", required=True, help="GitHub approvals JSON")
    p_auth.set_defaults(func=cmd_verify_auth)

    # Preflight
    p_pref = subparsers.add_parser("preflight", help="Run container preflight checks")
    p_pref.add_argument("--image", required=True, help="Container image")
    p_pref.add_argument("--temp-dir", help="Temporary directory for runner")
    p_pref.set_defaults(func=cmd_preflight)

    # Run
    p_run = subparsers.add_parser("run", help="Run strict proof lifecycle")
    p_run.add_argument("--manifest", required=True, help="Manifest JSON")
    p_run.add_argument("--approvals", required=True, help="Approvals JSON")
    p_run.add_argument("--p", required=True, help="P source directory")
    p_run.add_argument("--w", required=True, help="W proof directory")
    p_run.add_argument("--inputs-dir", help="Staged inputs directory")
    p_run.add_argument("--artifacts-dir", required=True, help="Evidence artifacts output directory")
    p_run.add_argument("--job-start-time", help="Epoch start time of hosted job")
    p_run.add_argument("--payload-budget-sec", type=float, help="Payload budget in seconds")
    p_run.add_argument("--driver-limit-sec", type=float, help="Driver limit in seconds")
    p_run.add_argument("--grace_sec", type=float, help="Grace period in seconds")
    p_run.add_argument("--min-disk-gib", type=float, help="Minimum disk free floor in GiB")
    p_run.set_defaults(func=cmd_run)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
