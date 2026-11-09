#!/usr/bin/env python3
"""
proof/hosted_containers.py: Owned container lifecycle, creation intent,
exact ID reconciliation, cage/mount inspection, bounded execution, and verified teardown.

Implements PlanControllerRepairs Section 3.5 and Slice C (lines 138-161, 280-295),
incorporating all security review remediations (ReviewOwnedContainers exact826d):
- OwnedContainerSession: owns pending creations, exact container IDs, teardown,
  and retained ownership records.
- ContainerSpec: command, effective cage policy, exact mount bindings, stage/attempt,
  and finite positive deadline/timeout.
- ContainerOutcome: command execution outcome plus mandatory TeardownResult.
- TeardownResult: verified removal or unresolved ownership, with raw bounded evidence.

Lifecycle guarantees:
1. Record private creation intent before invoking Docker (unique owned name, invocation/stage labels).
2. Reconcile stdout/cidfile/inspect to one exact 64-character container ID before any failure-prone step.
   Conflicting identity evidence fails closed immediately.
3. Reconcile uncertain create outcomes using ONLY recorded intent (NEVER broad prefix sweeps).
4. Inspect mounts and cage settings before container start (reject undeclared mounts, docker.sock,
   host /proc, /sys, /dev, unconfined seccomp, host namespaces, and inode aliasing).
5. Execute with bounded output handling and finite positive deadline enforcement.
   Output stream overflow or failed EOF collection fails the invocation.
6. Encompassing teardown in finally blocks across ALL exit paths (normal, error, cancellation, timeout).
   Teardown exceptions are captured without escaping; failure records unresolved ownership and fails closed.
7. Unregister only after verified removal (daemon-verified 'No such container').
8. Removal never deletes attached volumes (no -v flag).
9. Destructive operations strictly validate container ownership before invoking Docker.
10. Image reference strictly validated against option injection, and terminated with '--'.
11. Detached preflight starts enforce the identical inspection, cancellation, and fail-closed admission.
12. Auxiliary Docker commands (create, inspect, rm, exec, top) execute with strict output bounds.
13. Signal handling requests cancellation and unwinds through normal try...finally cleanup.
    Zero reentrant Docker invocations inside signal handlers; signal-safe teardown orchestration.
"""

from __future__ import annotations

import atexit
import dataclasses
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

try:
    from proof.hosted_contracts import (
        CagePolicy,
        TeardownDisposition,
        ContractError,
        TypeValidationError,
        canonical_json_bytes,
        sha256_bytes,
    )
except ImportError:
    try:
        from hosted_contracts import (
            CagePolicy,
            TeardownDisposition,
            ContractError,
            TypeValidationError,
            canonical_json_bytes,
            sha256_bytes,
        )
    except ImportError:
        class ContractError(Exception):
            """Base exception for contract errors."""

        class TypeValidationError(ContractError):
            """Validation error."""

        def canonical_json_bytes(data: Any) -> bytes:
            return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

        def sha256_bytes(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()

        @dataclasses.dataclass(frozen=True)
        class CagePolicy:
            uid: int
            gid: int
            network: str
            read_only_root: bool
            drop_capabilities: str
            no_new_privileges: bool
            private_pid_namespace: bool
            default_confined_seccomp: bool
            init_process: bool
            pids_limit: int
            tmpfs_tmp_size: str
            tmpfs_dev_shm_size: str

            def to_dict(self) -> Dict[str, Any]:
                return dataclasses.asdict(self)

        @dataclasses.dataclass(frozen=True)
        class TeardownDisposition:
            launch_id: str
            container_id: str
            containers_stopped: bool
            containers_removed: bool
            clean_exit: bool
            unresolved_processes: int = 0


# Constants and Regexes
CONTAINER_ID_REGEX = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$")
IMAGE_REF_REGEX = re.compile(
    r"^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*(?::[a-zA-Z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?$"
)

LABEL_MANAGED = "iyi.managed"
LABEL_INTENT_ID = "iyi.intent_id"
LABEL_INVOCATION_ID = "iyi.invocation_id"
LABEL_STAGE = "iyi.stage"
LABEL_ATTEMPT = "iyi.attempt"
LABEL_CREATED_AT = "iyi.created_at_utc"

DEFAULT_MAX_STDOUT_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_STDERR_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_AUX_BYTES = 2 * 1024 * 1024      # 2 MB auxiliary bound (inspect/create/rm/exec/top)
DEFAULT_GRACE_SEC = 5.0
DEFAULT_INSPECT_TIMEOUT_SEC = 15.0
DEFAULT_STOP_TIMEOUT_SEC = 25.0
DEFAULT_RM_TIMEOUT_SEC = 20.0


# Exceptions
class ContainerLifecycleError(ContractError):
    """Base exception for container lifecycle and ownership errors."""


class CreationIntentError(ContainerLifecycleError):
    """Raised when container creation intent cannot be formed or recorded."""


class OwnershipReconciliationError(ContainerLifecycleError):
    """Raised when container creation cannot be reconciled to a single exact ID."""


class ConflictingIdentityError(OwnershipReconciliationError):
    """Raised when conflicting container identity evidence is detected."""


class UnresolvedOwnershipError(ContainerLifecycleError):
    """Raised when container ownership or removal is unresolved, requiring fail-closed halt."""


class CageInspectionError(ContainerLifecycleError):
    """Raised when container cage settings violate isolation policy upon pre-start inspect."""


class MountInspectionError(ContainerLifecycleError):
    """Raised when container mounts violate confinement or anti-aliasing policy upon pre-start inspect."""


class ContainerTimeoutError(ContainerLifecycleError):
    """Raised when container execution or command exceeds the deadline."""


class ContainerCancelledError(ContainerLifecycleError):
    """Raised when container execution is cancelled via signal or cooperative request."""


@dataclasses.dataclass(frozen=True)
class MountBinding:
    """Exact mount specification for container execution."""
    container_path: str
    host_path: Optional[str]
    access: str  # "ro" or "rw"
    mount_type: str = "bind"  # "bind" or "tmpfs"
    options: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.container_path or not self.container_path.startswith("/"):
            raise TypeValidationError(f"Invalid container_path: {self.container_path!r}")
        if self.access not in ("ro", "rw"):
            raise TypeValidationError(f"Invalid access mode: {self.access!r} (must be 'ro' or 'rw')")
        if self.mount_type not in ("bind", "tmpfs"):
            raise TypeValidationError(f"Invalid mount_type: {self.mount_type!r} (must be 'bind' or 'tmpfs')")
        if self.mount_type == "bind":
            if not self.host_path:
                raise TypeValidationError("host_path is required for bind mounts")

    def to_docker_mount_arg(self) -> str:
        """Serialize to docker --mount argument."""
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
        raise TypeValidationError(f"Unknown mount type: {self.mount_type}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "container_path": self.container_path,
            "host_path": self.host_path,
            "access": self.access,
            "mount_type": self.mount_type,
            "options": list(self.options),
        }


@dataclasses.dataclass(frozen=True)
class ContainerSpec:
    """
    Specification for container execution under strict cage isolation.
    Binds command, mandatory cage policy, exact mounts, stage/attempt, and finite positive deadlines.
    """
    command: Tuple[str, ...]
    image: str
    stage: str
    attempt: int
    cage_policy: CagePolicy  # Mandatory: omitting cage policy is strictly forbidden
    deadline: Optional[float] = None
    timeout_sec: Optional[float] = None
    mount_bindings: Tuple[MountBinding, ...] = ()
    env: Mapping[str, str] = dataclasses.field(default_factory=dict)
    working_dir: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES
    interactive: bool = False
    name_hint: Optional[str] = None
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.command, (list, tuple)) or not self.command:
            raise TypeValidationError("command must be a non-empty sequence of strings")
        for arg in self.command:
            if not isinstance(arg, str):
                raise TypeValidationError(f"command arguments must be strings, got {type(arg).__name__}")

        if not isinstance(self.image, str) or not self.image:
            raise TypeValidationError("image must be a non-empty string")
        if self.image.startswith("-") or not IMAGE_REF_REGEX.fullmatch(self.image):
            raise TypeValidationError(f"Invalid image reference (option injection rejected): {self.image!r}")

        if not isinstance(self.stage, str) or not self.stage:
            raise TypeValidationError("stage must be a non-empty string")
        if not isinstance(self.attempt, int) or self.attempt < 1:
            raise TypeValidationError(f"attempt must be a positive integer, got {self.attempt!r}")

        # Cage policy is mandatory
        if not isinstance(self.cage_policy, CagePolicy):
            raise TypeValidationError("cage_policy is mandatory; omitting cage policy is strictly forbidden")

        # Deadline & timeout: must be finite positive numbers
        if self.deadline is not None:
            if not isinstance(self.deadline, (int, float)) or not math.isfinite(self.deadline):
                raise TypeValidationError(f"deadline must be a finite numeric timestamp, got {self.deadline!r}")
        if self.timeout_sec is not None:
            if not isinstance(self.timeout_sec, (int, float)) or not math.isfinite(self.timeout_sec) or self.timeout_sec <= 0:
                raise TypeValidationError(f"timeout_sec must be a finite positive number, got {self.timeout_sec!r}")

        if self.deadline is None and self.timeout_sec is None:
            raise TypeValidationError("Either timeout_sec or deadline must be provided as a finite positive number")

        if not isinstance(self.mount_bindings, (list, tuple)):
            raise TypeValidationError("mount_bindings must be a tuple of MountBinding")
        for mb in self.mount_bindings:
            if not isinstance(mb, MountBinding):
                raise TypeValidationError(f"Expected MountBinding, got {type(mb).__name__}")

        if not isinstance(self.max_stdout_bytes, int) or self.max_stdout_bytes <= 0:
            raise TypeValidationError("max_stdout_bytes must be a positive integer")
        if not isinstance(self.max_stderr_bytes, int) or self.max_stderr_bytes <= 0:
            raise TypeValidationError("max_stderr_bytes must be a positive integer")

        # Freeze sequence and mapping fields
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "mount_bindings", tuple(self.mount_bindings))
        object.__setattr__(self, "env", dict(self.env))
        object.__setattr__(self, "labels", dict(self.labels))

    def digest(self) -> str:
        """Compute deterministic digest of container execution spec."""
        canonical_dict = {
            "command": list(self.command),
            "image": self.image,
            "stage": self.stage,
            "attempt": self.attempt,
            "timeout_sec": self.timeout_sec,
            "cage_policy": self.cage_policy.to_dict() if hasattr(self.cage_policy, "to_dict") else None,
            "mount_bindings": [mb.to_dict() for mb in self.mount_bindings],
            "env": dict(sorted(self.env.items())),
            "working_dir": self.working_dir,
            "user": self.user,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
        }
        return sha256_bytes(canonical_json_bytes(canonical_dict))


@dataclasses.dataclass(frozen=True)
class CreationIntent:
    """
    Immutable private record created before Docker invocation.
    Binds unique container name, cidfile path, and audit labels.
    """
    intent_id: str
    container_name: str
    invocation_id: str
    stage: str
    attempt: int
    cidfile_path: str
    labels: Mapping[str, str]
    created_at_utc: str
    spec_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "container_name": self.container_name,
            "invocation_id": self.invocation_id,
            "stage": self.stage,
            "attempt": self.attempt,
            "cidfile_path": self.cidfile_path,
            "labels": dict(self.labels),
            "created_at_utc": self.created_at_utc,
            "spec_digest": self.spec_digest,
        }


@dataclasses.dataclass(frozen=True)
class TeardownResult:
    """
    Result of container teardown.
    Either verified removal (resolved=True) or unresolved ownership (resolved=False).
    Includes raw bounded evidence.
    """
    resolved: bool
    container_id: Optional[str]
    container_name: str
    stopped: bool
    removed: bool
    clean_exit: bool
    unresolved_processes: int = 0
    unresolved_reason: Optional[str] = None
    evidence: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def is_resolved(self) -> bool:
        """True if container was cleanly stopped, removed, verified gone, and 0 unresolved processes."""
        return (
            self.resolved is True
            and self.stopped is True
            and self.removed is True
            and self.clean_exit is True
            and self.unresolved_processes == 0
            and self.unresolved_reason is None
        )

    def to_disposition(self, launch_id: str) -> TeardownDisposition:
        """Convert verified teardown result into typed TeardownDisposition."""
        if not self.is_resolved():
            raise UnresolvedOwnershipError(
                f"Cannot create TeardownDisposition from unresolved teardown: {self.unresolved_reason}"
            )
        cid = self.container_id or self.container_name
        return TeardownDisposition(
            launch_id=launch_id,
            container_id=cid,
            containers_stopped=self.stopped,
            containers_removed=self.removed,
            clean_exit=self.clean_exit,
            unresolved_processes=self.unresolved_processes,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resolved": self.resolved,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "stopped": self.stopped,
            "removed": self.removed,
            "clean_exit": self.clean_exit,
            "unresolved_processes": self.unresolved_processes,
            "unresolved_reason": self.unresolved_reason,
            "evidence": dict(self.evidence),
        }


@dataclasses.dataclass(frozen=True)
class ContainerOutcome:
    """
    Command outcome plus mandatory TeardownResult.
    """
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool
    cancelled: bool
    teardown: TeardownResult
    container_id: Optional[str] = None
    container_name: str = ""
    error: Optional[str] = None
    bounded: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.teardown, TeardownResult):
            raise TypeValidationError(f"teardown must be a TeardownResult, got {type(self.teardown).__name__}")


@dataclasses.dataclass(frozen=True)
class ContainerRecord:
    """Internal registration record for an active owned container."""
    container_id: str
    container_name: str
    intent: CreationIntent
    spec: ContainerSpec
    registered_at_utc: str
    state: str  # "created", "started", "stopping", "stopped", "removed", "unresolved"


@dataclasses.dataclass(frozen=True)
class UnresolvedRecord:
    """Record of an unresolved container ownership situation."""
    identity: str
    intent: Optional[CreationIntent]
    reason: str
    raw_evidence: Mapping[str, Any]
    recorded_at_utc: str


class OwnedContainerSession:
    """
    Session owning pending creations, exact container IDs, teardown,
    and retained ownership records.

    Provides hermetic container management for both production stages
    and preflight boundary qualification.
    """

    def __init__(
        self,
        invocation_id: str,
        session_dir: Optional[Union[str, pathlib.Path]] = None,
        docker_cmd: Sequence[str] = ("docker",),
        default_grace_sec: float = DEFAULT_GRACE_SEC,
        subprocess_runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not invocation_id or not isinstance(invocation_id, str):
            raise TypeValidationError("invocation_id must be a non-empty string")
        self.invocation_id = invocation_id
        self.docker_cmd = tuple(docker_cmd)
        self.default_grace_sec = float(default_grace_sec)
        self._custom_runner = subprocess_runner
        self._logger = logger

        # Directory for cidfiles and session metadata
        if session_dir is not None:
            self.session_dir = pathlib.Path(session_dir)
            self.session_dir.mkdir(parents=True, exist_ok=True)
            self._owned_session_dir = False
        else:
            self.session_dir = pathlib.Path(tempfile.mkdtemp(prefix=f"iyi-session-{self.invocation_id[:8]}-"))
            self._owned_session_dir = True

        # State tracking
        self._lock = threading.RLock()
        self._pending_intents: Dict[str, CreationIntent] = {}  # intent_id -> intent
        self._active_containers: Dict[str, ContainerRecord] = {}  # container_id -> record
        self._unresolved_containers: Dict[str, UnresolvedRecord] = {}  # identity -> record
        self._completed_teardowns: List[TeardownResult] = []
        self._ownership_journal: List[Dict[str, Any]] = []

        # Fail-closed state
        self._failed_closed = False
        self._fail_closed_reason: Optional[str] = None
        self._in_teardown = False

        # Cooperative cancellation
        self._cancellation_requested = threading.Event()
        self._cancellation_signal: Optional[int] = None
        self._current_popen: Optional[subprocess.Popen] = None

        # Signal handlers tracking
        self._signal_handlers_installed = False
        self._previous_signal_handlers: Dict[int, Any] = {}

        # Register supplementary atexit cleanup
        self._atexit_cleanup_registered = True
        atexit.register(self._atexit_cleanup)

    def log(self, message: str) -> None:
        if self._logger:
            self._logger(message)

    def _now_utc(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _run_cmd(
        self,
        cmd: Sequence[str],
        timeout: Optional[float] = None,
        check: bool = False,
        input_data: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        max_output_bytes: int = DEFAULT_MAX_AUX_BYTES,
    ) -> subprocess.CompletedProcess:
        """
        Execute auxiliary Docker command with strict bounded output reading.
        Applies bounded streaming to create, inspect, stop, rm, exec, top.
        """
        if self._custom_runner:
            res = self._custom_runner(
                cmd,
                timeout=timeout,
                check=check,
                capture_output=True,
                text=True,
                input_data=input_data,
                env=env,
            )
            # Bound check custom runner outputs as well
            out_bytes = (res.stdout or "").encode("utf-8")
            err_bytes = (res.stderr or "").encode("utf-8")
            if len(out_bytes) > max_output_bytes or len(err_bytes) > max_output_bytes:
                raise ContainerLifecycleError(
                    f"Auxiliary command output exceeded maximum bound of {max_output_bytes} bytes"
                )
            return res

        # Real subprocess execution with bounded pipe consumption
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if input_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except OSError as exc:
            raise ContainerLifecycleError(f"Failed to spawn command {' '.join(cmd[:3])}: {exc}") from exc

        stdout_buf: List[bytes] = []
        stderr_buf: List[bytes] = []
        overflow = False
        pipe_exc: Optional[Exception] = None

        def read_pipe(pipe: Any, buf: List[bytes]) -> None:
            nonlocal overflow, pipe_exc
            tot = 0
            try:
                while True:
                    chunk = pipe.read(65536)
                    if not chunk:
                        break
                    tot += len(chunk)
                    if tot > max_output_bytes:
                        overflow = True
                        break
                    buf.append(chunk)
            except Exception as e:
                pipe_exc = e

        t_out = threading.Thread(target=read_pipe, args=(proc.stdout, stdout_buf))
        t_err = threading.Thread(target=read_pipe, args=(proc.stderr, stderr_buf))
        t_out.daemon = True
        t_err.daemon = True
        t_out.start()
        t_err.start()

        if input_data is not None and proc.stdin:
            try:
                proc.stdin.write(input_data.encode("utf-8"))
                proc.stdin.close()
            except OSError:
                pass

        start_t = time.monotonic()
        poll_interval = 0.05
        timed_out = False

        while proc.poll() is None:
            if timeout is not None and (time.monotonic() - start_t) >= timeout:
                timed_out = True
                proc.terminate()
                break
            if self.is_cancelled() and not self._in_teardown:
                proc.terminate()
                break
            time.sleep(poll_interval)

        if timed_out:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait(timeout=5.0)
            raise subprocess.TimeoutExpired(cmd, timeout)

        retcode = proc.wait(timeout=5.0)
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        if overflow:
            raise ContainerLifecycleError(
                f"Auxiliary command output exceeded maximum bound of {max_output_bytes} bytes: {' '.join(cmd[:3])}"
            )
        if pipe_exc:
            raise ContainerLifecycleError(f"Pipe error during command execution: {pipe_exc}") from pipe_exc

        out_str = b"".join(stdout_buf).decode("utf-8", errors="replace")
        err_str = b"".join(stderr_buf).decode("utf-8", errors="replace")
        res = subprocess.CompletedProcess(cmd, retcode, stdout=out_str, stderr=err_str)
        if check and retcode != 0:
            raise subprocess.CalledProcessError(retcode, cmd, output=out_str, stderr=err_str)
        return res

    # -------------------------------------------------------------------------
    # Fail-Closed & Cancellation Status
    # -------------------------------------------------------------------------

    def has_unresolved_ownership(self) -> bool:
        """True if session has encountered unresolved container ownership."""
        with self._lock:
            return self._failed_closed or len(self._unresolved_containers) > 0

    def get_fail_closed_reason(self) -> Optional[str]:
        with self._lock:
            return self._fail_closed_reason

    def _fail_closed(self, reason: str) -> None:
        with self._lock:
            self._failed_closed = True
            if not self._fail_closed_reason:
                self._fail_closed_reason = reason
            self._ownership_journal.append({
                "timestamp": self._now_utc(),
                "event": "session_failed_closed",
                "reason": reason,
            })
            self.log(f"[CONTAINER-FAIL-CLOSED] {reason}")

    def request_cancellation(self, signum: Optional[int] = None) -> None:
        """
        Request cooperative cancellation.
        Sets the cancellation event and terminates any in-flight docker command.
        Does NOT perform Docker cleanup reentrantly.
        """
        with self._lock:
            self._cancellation_requested.set()
            if signum is not None:
                self._cancellation_signal = signum
            self._ownership_journal.append({
                "timestamp": self._now_utc(),
                "event": "cancellation_requested",
                "signal": signum,
            })
            if self._current_popen and not self._in_teardown:
                try:
                    self._current_popen.terminate()
                except OSError:
                    pass

    def is_cancelled(self) -> bool:
        return self._cancellation_requested.is_set()

    # -------------------------------------------------------------------------
    # Ownership Validation Before Any Destructive Action
    # -------------------------------------------------------------------------

    def _verify_owned_target(self, target: str) -> None:
        """
        Validate that target matches a known registered owned container or pending intent.
        Rejects foreign container IDs before issuing destructive Docker operations.
        """
        with self._lock:
            is_active_id = target in self._active_containers
            is_active_name = any(rec.container_name == target for rec in self._active_containers.values())
            is_pending_name = any(intent.container_name == target for intent in self._pending_intents.values())
            is_pending_id = any(intent.intent_id == target for intent in self._pending_intents.values())
            is_unresolved = target in self._unresolved_containers

            if not (is_active_id or is_active_name or is_pending_name or is_pending_id or is_unresolved):
                raise OwnershipReconciliationError(
                    f"Refusing destructive operation on unowned container target: {target!r}"
                )

    # -------------------------------------------------------------------------
    # Lifecycle Behavior 1: Record Creation Intent Before Invoking Docker
    # -------------------------------------------------------------------------

    def record_creation_intent(self, spec: ContainerSpec) -> CreationIntent:
        """
        Record a private creation intent before invoking Docker.
        Binds a unique owned container name, cidfile path, and stage/attempt labels.
        Fails closed if session already has unresolved ownership.
        """
        with self._lock:
            if self.has_unresolved_ownership():
                raise UnresolvedOwnershipError(
                    f"Refusing container creation: session failed closed ({self._fail_closed_reason})"
                )

            intent_id = uuid.uuid4().hex
            inv_prefix = re.sub(r"[^a-zA-Z0-9_.-]", "", self.invocation_id[:12])
            stage_clean = re.sub(r"[^a-zA-Z0-9_.-]", "", spec.stage[:16])
            intent_prefix = intent_id[:8]

            container_name = f"iyi-c-{inv_prefix}-{stage_clean}-{spec.attempt}-{intent_prefix}"
            if spec.name_hint:
                hint_clean = re.sub(r"[^a-zA-Z0-9_.-]", "", spec.name_hint[:16])
                container_name = f"iyi-c-{inv_prefix}-{hint_clean}-{spec.attempt}-{intent_prefix}"

            if not SAFE_NAME_REGEX.fullmatch(container_name):
                raise CreationIntentError(f"Generated container name is invalid: {container_name!r}")

            cidfile_path = str(self.session_dir / f"{container_name}.cid")
            if os.path.exists(cidfile_path):
                try:
                    os.unlink(cidfile_path)
                except OSError as exc:
                    raise CreationIntentError(f"Pre-existing cidfile cannot be unlinked: {cidfile_path}: {exc}") from exc

            labels = {
                LABEL_MANAGED: "true",
                LABEL_INTENT_ID: intent_id,
                LABEL_INVOCATION_ID: self.invocation_id,
                LABEL_STAGE: spec.stage,
                LABEL_ATTEMPT: str(spec.attempt),
                LABEL_CREATED_AT: self._now_utc(),
            }
            if spec.labels:
                labels.update(spec.labels)

            intent = CreationIntent(
                intent_id=intent_id,
                container_name=container_name,
                invocation_id=self.invocation_id,
                stage=spec.stage,
                attempt=spec.attempt,
                cidfile_path=cidfile_path,
                labels=labels,
                created_at_utc=self._now_utc(),
                spec_digest=spec.digest(),
            )

            self._pending_intents[intent_id] = intent
            self._ownership_journal.append({
                "timestamp": self._now_utc(),
                "event": "creation_intent_recorded",
                "intent": intent.to_dict(),
            })
            return intent

    # -------------------------------------------------------------------------
    # Lifecycle Behavior 2: Reconcile Exactly One 64-char ID & Register
    # -------------------------------------------------------------------------

    def _reconcile_create_id(
        self,
        intent: CreationIntent,
        stdout_str: str,
        cidfile_path: str,
    ) -> str:
        """
        Reconcile stdout, cidfile, and inspect to one exact 64-character container ID.
        Conflicting identity evidence raises ConflictingIdentityError and fails closed.
        """
        stdout_id: Optional[str] = None
        cidfile_id: Optional[str] = None

        cand_stdout = stdout_str.strip()
        if CONTAINER_ID_REGEX.fullmatch(cand_stdout):
            stdout_id = cand_stdout

        if os.path.exists(cidfile_path):
            try:
                cand_cid = pathlib.Path(cidfile_path).read_text(encoding="utf-8").strip()
                if CONTAINER_ID_REGEX.fullmatch(cand_cid):
                    cidfile_id = cand_cid
            except OSError:
                pass

        if stdout_id and cidfile_id:
            if stdout_id != cidfile_id:
                raise ConflictingIdentityError(
                    f"Disagreement between stdout ({stdout_id}) and cidfile ({cidfile_id}) for {intent.container_name}"
                )
            candidate_id = stdout_id
        elif stdout_id:
            candidate_id = stdout_id
        elif cidfile_id:
            candidate_id = cidfile_id
        else:
            raise OwnershipReconciliationError(
                f"Neither stdout nor cidfile produced a valid 64-character container ID for {intent.container_name}. "
                f"stdout={stdout_str!r}"
            )

        # Inspect candidate ID to ensure daemon agrees and labels match
        try:
            inspect_res = self._run_cmd(
                list(self.docker_cmd) + ["inspect", candidate_id],
                timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
            )
        except Exception as exc:
            raise OwnershipReconciliationError(f"Inspect failed for reconciled ID {candidate_id}: {exc}") from exc

        if inspect_res.returncode != 0:
            raise OwnershipReconciliationError(
                f"Inspect failed for reconciled ID {candidate_id}: {inspect_res.stderr}"
            )

        try:
            inspect_list = json.loads(inspect_res.stdout)
            if not isinstance(inspect_list, list) or len(inspect_list) != 1:
                raise OwnershipReconciliationError(
                    f"Ambiguous inspect output cardinality for {candidate_id}: expected 1, got {len(inspect_list) if isinstance(inspect_list, list) else type(inspect_list)}"
                )
            inspect_data = inspect_list[0]
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            raise OwnershipReconciliationError(f"Failed to parse inspect JSON for {candidate_id}: {exc}") from exc

        actual_id = inspect_data.get("Id", "")
        if actual_id != candidate_id:
            raise ConflictingIdentityError(
                f"Inspect Id mismatch: expected {candidate_id}, got {actual_id}"
            )

        raw_name = inspect_data.get("Name", "").lstrip("/")
        if raw_name != intent.container_name:
            raise ConflictingIdentityError(
                f"Container inspect name mismatch: expected {intent.container_name}, got {raw_name}"
            )

        labels = inspect_data.get("Config", {}).get("Labels", {})
        if not isinstance(labels, dict) or labels.get(LABEL_INTENT_ID) != intent.intent_id:
            raise ConflictingIdentityError(
                f"Container audit label {LABEL_INTENT_ID} mismatch for {candidate_id}"
            )

        return candidate_id

    # -------------------------------------------------------------------------
    # Lifecycle Behavior 3: Reconcile Uncertain Create Outcomes (NO broad sweeps)
    # -------------------------------------------------------------------------

    def reconcile_uncertain_create(self, intent: CreationIntent) -> Optional[str]:
        """
        Reconcile an uncertain container create outcome using ONLY the recorded intent.
        NEVER performs broad sweeps or prefix queries.
        Preserves unresolved ownership rather than converting generic failures into 'gone'.
        """
        cid_candidate: Optional[str] = None
        if os.path.exists(intent.cidfile_path):
            try:
                raw_cid = pathlib.Path(intent.cidfile_path).read_text(encoding="utf-8").strip()
                if CONTAINER_ID_REGEX.fullmatch(raw_cid):
                    cid_candidate = raw_cid
            except OSError:
                pass

        if cid_candidate:
            try:
                inspect_cid = self._run_cmd(
                    list(self.docker_cmd) + ["inspect", cid_candidate],
                    timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
                )
                if inspect_cid.returncode == 0:
                    inspect_list = json.loads(inspect_cid.stdout)
                    if isinstance(inspect_list, list) and len(inspect_list) == 1:
                        data = inspect_list[0]
                        if data.get("Id") == cid_candidate and data.get("Name", "").lstrip("/") == intent.container_name:
                            labels = data.get("Config", {}).get("Labels", {})
                            if labels.get(LABEL_INTENT_ID) == intent.intent_id:
                                return cid_candidate
            except Exception:
                pass

        # Query exact container name directly (NEVER by prefix)
        try:
            inspect_name = self._run_cmd(
                list(self.docker_cmd) + ["inspect", intent.container_name],
                timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
            )
        except Exception as exc:
            raise UnresolvedOwnershipError(
                f"Exception during uncertain create inspect for {intent.container_name}: {exc}"
            ) from exc

        if inspect_name.returncode == 0:
            try:
                inspect_list = json.loads(inspect_name.stdout)
                if not isinstance(inspect_list, list) or len(inspect_list) != 1:
                    raise UnresolvedOwnershipError(
                        f"Ambiguous inspect cardinality for {intent.container_name}: expected 1"
                    )
                data = inspect_list[0]
                exact_id = data.get("Id", "")
                if not CONTAINER_ID_REGEX.fullmatch(exact_id):
                    raise UnresolvedOwnershipError(
                        f"Ambiguous non-64char container Id in inspect for {intent.container_name}: {exact_id!r}"
                    )
                labels = data.get("Config", {}).get("Labels", {})
                if labels.get(LABEL_INTENT_ID) != intent.intent_id:
                    raise UnresolvedOwnershipError(
                        f"Container {intent.container_name} exists but intent_id mismatch: "
                        f"{labels.get(LABEL_INTENT_ID)} != {intent.intent_id}"
                    )
                return exact_id
            except (json.JSONDecodeError, KeyError, IndexError) as exc:
                raise UnresolvedOwnershipError(
                    f"Ambiguous inspect output for uncertain create {intent.container_name}: {exc}"
                ) from exc

        combined_err = f"{inspect_name.stderr} {inspect_name.stdout}".lower()
        is_daemon_error = any(phrase in combined_err for phrase in (
            "cannot connect to the docker daemon",
            "is the docker daemon running",
            "connection refused",
            "connection reset",
            "dial unix",
            "permission denied",
            "socket:",
        ))

        if is_daemon_error:
            raise UnresolvedOwnershipError(
                f"Docker daemon outage during uncertain create reconciliation for {intent.container_name}: "
                f"{inspect_name.stderr}"
            )

        is_not_found = (
            inspect_name.returncode in (1, 125)
            and ("no such container" in combined_err or "no such object" in combined_err)
        )

        if is_not_found and not os.path.exists(intent.cidfile_path):
            # Cleanly verified: container does not exist
            return None

        raise UnresolvedOwnershipError(
            f"Ambiguous inspect failure for uncertain create {intent.container_name}: "
            f"code={inspect_name.returncode}, stderr={inspect_name.stderr}"
        )

    # -------------------------------------------------------------------------
    # Create Container Operation (Orchestrates Intent & ID Reconciliation)
    # -------------------------------------------------------------------------

    def create_container(self, spec: ContainerSpec) -> Tuple[CreationIntent, str]:
        """
        Record intent, invoke `docker create`, reconcile exact ID, and register.
        Enforces option termination before image to prevent option injection.
        """
        intent = self.record_creation_intent(spec)

        create_cmd = list(self.docker_cmd) + [
            "create",
            "--name", intent.container_name,
            "--cidfile", intent.cidfile_path,
        ]

        for k, v in intent.labels.items():
            create_cmd.extend(["--label", f"{k}={v}"])

        # Effective cage isolation arguments
        cp = spec.cage_policy
        create_cmd.extend([
            "--user", f"{cp.uid}:{cp.gid}",
            "--network", cp.network,
            "--cap-drop", cp.drop_capabilities,
            "--pids-limit", str(cp.pids_limit),
        ])
        if cp.read_only_root:
            create_cmd.append("--read-only")
        if cp.no_new_privileges:
            create_cmd.extend(["--security-opt", "no-new-privileges"])
        if cp.init_process:
            create_cmd.append("--init")
        if cp.tmpfs_tmp_size:
            create_cmd.extend(["--tmpfs", f"/tmp:rw,nosuid,nodev,size={cp.tmpfs_tmp_size},mode=1777"])
        if cp.tmpfs_dev_shm_size:
            create_cmd.extend(["--tmpfs", f"/dev/shm:rw,nosuid,nodev,size={cp.tmpfs_dev_shm_size},mode=1777"])

        for mb in spec.mount_bindings:
            create_cmd.append(mb.to_docker_mount_arg())

        for k, v in spec.env.items():
            create_cmd.extend(["--env", f"{k}={v}"])

        if spec.working_dir:
            create_cmd.extend(["--workdir", spec.working_dir])
        if spec.hostname:
            create_cmd.extend(["--hostname", spec.hostname])

        # Terminate options before image to prevent Docker option injection
        create_cmd.append("--")
        create_cmd.append(spec.image)
        create_cmd.extend(spec.command)

        uncertain = False
        create_res: Optional[subprocess.CompletedProcess] = None
        create_exc: Optional[Exception] = None

        try:
            create_res = self._run_cmd(create_cmd, timeout=30.0)
            if create_res.returncode != 0:
                uncertain = True
        except (subprocess.TimeoutExpired, OSError, Exception) as exc:
            uncertain = True
            create_exc = exc

        container_id: Optional[str] = None
        if not uncertain and create_res is not None:
            try:
                container_id = self._reconcile_create_id(intent, create_res.stdout, intent.cidfile_path)
            except ConflictingIdentityError as conflict_exc:
                # Identity evidence conflict: fail closed immediately, do NOT guess or swallow
                with self._lock:
                    self._unresolved_containers[intent.container_name] = UnresolvedRecord(
                        identity=intent.container_name,
                        intent=intent,
                        reason=str(conflict_exc),
                        raw_evidence={"stdout": create_res.stdout, "cidfile": intent.cidfile_path},
                        recorded_at_utc=self._now_utc(),
                    )
                    self._fail_closed(f"Conflicting container identity: {conflict_exc}")
                raise UnresolvedOwnershipError(f"Conflicting container identity: {conflict_exc}") from conflict_exc
            except OwnershipReconciliationError:
                uncertain = True

        if uncertain:
            self.log(f"[CONTAINER-UNCERTAIN-CREATE] Reconciling {intent.container_name}")
            try:
                reconciled_id = self.reconcile_uncertain_create(intent)
                if reconciled_id:
                    container_id = reconciled_id
                else:
                    with self._lock:
                        self._pending_intents.pop(intent.intent_id, None)
                    err_msg = create_res.stderr if create_res else str(create_exc)
                    raise CreationIntentError(f"docker create failed (verified not created): {err_msg}")
            except UnresolvedOwnershipError as u_exc:
                with self._lock:
                    self._unresolved_containers[intent.container_name] = UnresolvedRecord(
                        identity=intent.container_name,
                        intent=intent,
                        reason=str(u_exc),
                        raw_evidence={"stderr": create_res.stderr if create_res else None, "exc": str(create_exc)},
                        recorded_at_utc=self._now_utc(),
                    )
                    self._fail_closed(f"Unresolved create for {intent.container_name}: {u_exc}")
                raise

        assert container_id is not None
        with self._lock:
            record = ContainerRecord(
                container_id=container_id,
                container_name=intent.container_name,
                intent=intent,
                spec=spec,
                registered_at_utc=self._now_utc(),
                state="created",
            )
            self._active_containers[container_id] = record
            self._pending_intents.pop(intent.intent_id, None)
            self._ownership_journal.append({
                "timestamp": self._now_utc(),
                "event": "container_registered",
                "container_id": container_id,
                "container_name": intent.container_name,
            })

        return intent, container_id

    # -------------------------------------------------------------------------
    # Lifecycle Behavior 4: Inspect Mounts and Cage Settings Before Start
    # -------------------------------------------------------------------------

    def inspect_and_verify_cage_and_mounts(
        self,
        container_id: str,
        spec: ContainerSpec,
    ) -> Dict[str, Any]:
        """
        Inspect container configuration, effective cage isolation, and mounts before start.
        Raises CageInspectionError or MountInspectionError on violation.
        Does NOT permit container start if any check fails.
        """
        try:
            inspect_res = self._run_cmd(
                list(self.docker_cmd) + ["inspect", container_id],
                timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
            )
        except Exception as exc:
            raise CageInspectionError(f"Failed to inspect container {container_id}: {exc}") from exc

        if inspect_res.returncode != 0:
            raise CageInspectionError(f"Failed to inspect container {container_id}: {inspect_res.stderr}")

        try:
            inspect_list = json.loads(inspect_res.stdout)
            if not isinstance(inspect_list, list) or len(inspect_list) != 1:
                raise CageInspectionError(f"Ambiguous inspect output cardinality for {container_id}")
            inspect_data = inspect_list[0]
        except Exception as exc:
            raise CageInspectionError(f"Invalid inspect JSON for {container_id}: {exc}") from exc

        host_cfg = inspect_data.get("HostConfig", {})
        cfg = inspect_data.get("Config", {})

        # 1. Privileged check: never allowed
        if host_cfg.get("Privileged", False) is not False:
            raise CageInspectionError("Privileged container is strictly forbidden")

        # 2. Host namespace leaks: host, container:<id>, etc.
        pid_mode = str(host_cfg.get("PidMode", ""))
        if pid_mode not in ("", "private"):
            raise CageInspectionError(f"Invalid PidMode: {pid_mode!r} (must be private namespace)")

        ipc_mode = str(host_cfg.get("IpcMode", ""))
        if ipc_mode not in ("", "private"):
            raise CageInspectionError(f"Invalid IpcMode: {ipc_mode!r} (must be private namespace)")

        uts_mode = str(host_cfg.get("UtsMode", ""))
        if uts_mode not in ("", "private"):
            raise CageInspectionError(f"Invalid UtsMode: {uts_mode!r} (must be private namespace)")

        # 3. Cage policy checks
        cp = spec.cage_policy

        # UID / GID
        actual_user = str(cfg.get("User", ""))
        expected_user_prefix = f"{cp.uid}:{cp.gid}"
        if actual_user != expected_user_prefix and actual_user != str(cp.uid):
            raise CageInspectionError(
                f"User mismatch: expected {expected_user_prefix} or {cp.uid}, got {actual_user!r}"
            )

        # Network
        net_mode = str(host_cfg.get("NetworkMode", ""))
        if net_mode != cp.network:
            raise CageInspectionError(
                f"NetworkMode mismatch: expected {cp.network!r}, got {net_mode!r}"
            )

        # Read-only root
        if cp.read_only_root and host_cfg.get("ReadonlyRootfs", False) is not True:
            raise CageInspectionError("ReadonlyRootfs must be True")

        # Capabilities dropped
        cap_drop = host_cfg.get("CapDrop", [])
        if not isinstance(cap_drop, list) or cp.drop_capabilities not in cap_drop:
            raise CageInspectionError(
                f"CapDrop must contain {cp.drop_capabilities!r}, got {cap_drop!r}"
            )

        # CapAdd must be empty
        cap_add = host_cfg.get("CapAdd")
        if cap_add:
            raise CageInspectionError(f"CapAdd is strictly forbidden, got: {cap_add!r}")

        # Security options: no-new-privileges and confined seccomp
        sec_opts = [str(o).lower() for o in host_cfg.get("SecurityOpt", [])]
        has_no_new_priv = any("no-new-privileges" in o for o in sec_opts)
        if not has_no_new_priv:
            raise CageInspectionError("SecurityOpt missing no-new-privileges")
        if any("seccomp=unconfined" in o or "seccomp:unconfined" in o for o in sec_opts):
            raise CageInspectionError("Unconfined seccomp is strictly forbidden")

        # Init process
        if cp.init_process and host_cfg.get("Init", False) is not True:
            raise CageInspectionError("Container Init process must be True")

        # Pids limit
        pids_limit = host_cfg.get("PidsLimit", 0)
        if cp.pids_limit > 0:
            if not isinstance(pids_limit, int) or pids_limit <= 0 or pids_limit > cp.pids_limit:
                raise CageInspectionError(
                    f"PidsLimit violation: expected <= {cp.pids_limit}, got {pids_limit!r}"
                )

        # 4. Mount Table & Confinement Inspection
        raw_mounts = inspect_data.get("Mounts", [])
        if not isinstance(raw_mounts, list):
            raise MountInspectionError("docker inspect Mounts is not a list")

        # Allowed destination set
        allowed_dests: Set[str] = {
            "/etc/resolv.conf",
            "/etc/hostname",
            "/etc/hosts",
        }
        if cp.tmpfs_tmp_size:
            allowed_dests.add("/tmp")
        if cp.tmpfs_dev_shm_size:
            allowed_dests.add("/dev/shm")
        for mb in spec.mount_bindings:
            allowed_dests.add(mb.container_path)

        mount_by_dest: Dict[str, Dict[str, Any]] = {}
        for m in raw_mounts:
            if not isinstance(m, dict):
                continue
            dest = str(m.get("Destination", ""))
            src = str(m.get("Source", ""))
            rw = m.get("RW", True)

            # Reject undeclared mounts (such as image-defined VOLUME directives)
            if dest not in allowed_dests:
                raise MountInspectionError(f"Undeclared mount destination detected in container: {dest}")

            # Prohibit docker.sock leaks
            if "docker.sock" in src or "docker.sock" in dest:
                raise MountInspectionError(f"Docker socket leak detected in mount: {dest} -> {src}")

            # Prohibit host /proc, /sys, /dev leaks
            if src == "/proc" or src.startswith("/proc/"):
                raise MountInspectionError(f"Host /proc leak detected in mount: {dest} -> {src}")
            if src == "/sys" or src.startswith("/sys/"):
                raise MountInspectionError(f"Host /sys leak detected in mount: {dest} -> {src}")
            if src == "/dev" or (src.startswith("/dev/") and not src.startswith("/dev/shm")):
                raise MountInspectionError(f"Host /dev leak detected in mount: {dest} -> {src}")

            if dest:
                mount_by_dest[dest] = m

        # Validate declared mount bindings against actual inspect
        sources_seen: Dict[Tuple[int, int], str] = {}
        for mb in spec.mount_bindings:
            if mb.container_path not in mount_by_dest:
                raise MountInspectionError(f"Expected mount {mb.container_path} missing in container inspect")

            actual_m = mount_by_dest[mb.container_path]
            actual_rw = actual_m.get("RW", True)
            actual_type = str(actual_m.get("Type", ""))

            # Mount type match
            if actual_type != mb.mount_type:
                raise MountInspectionError(
                    f"Mount type mismatch for {mb.container_path}: expected {mb.mount_type}, got {actual_type}"
                )

            # Read-only enforcement
            if mb.access == "ro" and actual_rw is not False:
                raise MountInspectionError(
                    f"Mount {mb.container_path} expected read-only, but inspect reported RW={actual_rw}"
                )
            if mb.access == "rw" and actual_rw is not True:
                raise MountInspectionError(
                    f"Mount {mb.container_path} expected writable, but inspect reported RW={actual_rw}"
                )

            # Bind mount source verification and anti-aliasing
            if mb.mount_type == "bind":
                if not mb.host_path:
                    raise MountInspectionError(f"Bind mount {mb.container_path} missing host_path")
                expected_real = os.path.realpath(mb.host_path)
                actual_real = os.path.realpath(str(actual_m.get("Source", "")))
                if expected_real != actual_real:
                    raise MountInspectionError(
                        f"Mount source mismatch for {mb.container_path}: expected {expected_real}, got {actual_real}"
                    )
                try:
                    st = os.stat(actual_real)
                    ident = (st.st_dev, st.st_ino)
                except OSError as exc:
                    raise MountInspectionError(
                        f"Failed to stat mount source {actual_real} for {mb.container_path}: {exc}"
                    ) from exc

                if ident in sources_seen:
                    prev_dest = sources_seen[ident]
                    if mb.access == "rw" or actual_rw or mount_by_dest[prev_dest].get("RW", True):
                        raise MountInspectionError(
                            f"Host mount aliasing detected: {mb.container_path} and {prev_dest} share inode {ident}"
                        )
                sources_seen[ident] = mb.container_path

        return inspect_data

    # -------------------------------------------------------------------------
    # Lifecycle Behavior 5: Execute with Bounded Output Handling
    # -------------------------------------------------------------------------

    def _execute_bounded(
        self,
        container_id: str,
        spec: ContainerSpec,
    ) -> Tuple[int, str, str, bool, bool]:
        """
        Start container and execute with bounded output handling.
        Returns: (exit_code, stdout, stderr, timed_out, bounded)
        Raises ContainerLifecycleError on overflow or stream EOF collection failure.
        """
        timeout_sec = spec.timeout_sec
        if spec.deadline is not None:
            remaining = spec.deadline - time.monotonic()
            if remaining <= 0:
                raise ContainerTimeoutError(f"Container deadline expired before start: {spec.deadline}")
            timeout_sec = min(timeout_sec, remaining) if timeout_sec is not None else remaining

        start_cmd = list(self.docker_cmd) + ["start", "-a", container_id]
        start_time = time.monotonic()
        timed_out = False
        bounded = False
        exit_code = -1
        stdout_buf: List[bytes] = []
        stderr_buf: List[bytes] = []

        if self._custom_runner:
            res = self._custom_runner(start_cmd, timeout=timeout_sec)
            exit_code = res.returncode
            out_raw = res.stdout if isinstance(res.stdout, bytes) else (res.stdout or "").encode("utf-8")
            err_raw = res.stderr if isinstance(res.stderr, bytes) else (res.stderr or "").encode("utf-8")
            if len(out_raw) > spec.max_stdout_bytes or len(err_raw) > spec.max_stderr_bytes:
                raise ContainerLifecycleError(
                    f"Container output exceeded bound of {spec.max_stdout_bytes}/{spec.max_stderr_bytes} bytes"
                )
            return exit_code, out_raw.decode("utf-8", errors="replace"), err_raw.decode("utf-8", errors="replace"), False, False

        overflow_err: Optional[str] = None
        pipe_exc: Optional[Exception] = None

        try:
            proc = subprocess.Popen(
                start_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self._lock:
                self._current_popen = proc

            def read_pipe(pipe: Any, buf: List[bytes], max_bytes: int, is_stdout: bool) -> None:
                nonlocal overflow_err, pipe_exc
                tot = 0
                try:
                    while True:
                        chunk = pipe.read(65536)
                        if not chunk:
                            break
                        tot += len(chunk)
                        if tot > max_bytes:
                            stream_name = "stdout" if is_stdout else "stderr"
                            overflow_err = f"Container {stream_name} exceeded bound of {max_bytes} bytes"
                            break
                        buf.append(chunk)
                except Exception as exc:
                    pipe_exc = exc

            t_out = threading.Thread(target=read_pipe, args=(proc.stdout, stdout_buf, spec.max_stdout_bytes, True))
            t_err = threading.Thread(target=read_pipe, args=(proc.stderr, stderr_buf, spec.max_stderr_bytes, False))
            t_out.daemon = True
            t_err.daemon = True
            t_out.start()
            t_err.start()

            poll_interval = 0.05
            while proc.poll() is None:
                if self.is_cancelled() and not self._in_teardown:
                    proc.terminate()
                    raise ContainerCancelledError("Container execution cancelled via signal/request")
                if timeout_sec is not None:
                    elapsed = time.monotonic() - start_t if 'start_t' in locals() else (time.monotonic() - start_time)
                    if elapsed >= timeout_sec:
                        timed_out = True
                        proc.terminate()
                        break
                time.sleep(poll_interval)

            if timed_out:
                try:
                    proc.kill()
                except OSError:
                    pass
                proc.wait(timeout=5.0)
                raise ContainerTimeoutError(f"Container {container_id} timed out after {timeout_sec:.2f}s")

            exit_code = proc.wait(timeout=5.0)
            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)

            # Ensure clean EOF established
            if t_out.is_alive() or t_err.is_alive():
                raise ContainerLifecycleError("Container output stream collection failed to establish clean EOF")
            if pipe_exc:
                raise ContainerLifecycleError(f"Stream collection error during container execution: {pipe_exc}") from pipe_exc
            if overflow_err:
                raise ContainerLifecycleError(overflow_err)

        finally:
            with self._lock:
                self._current_popen = None

        stdout_str = b"".join(stdout_buf).decode("utf-8", errors="replace")
        stderr_str = b"".join(stderr_buf).decode("utf-8", errors="replace")
        return exit_code, stdout_str, stderr_str, timed_out, bounded

    # -------------------------------------------------------------------------
    # Lifecycle Behaviors 6 & 7: Verified Teardown on Every Path
    # -------------------------------------------------------------------------

    def stop_and_remove(
        self,
        target: str,
        grace_sec: float = DEFAULT_GRACE_SEC,
    ) -> TeardownResult:
        """
        Stop as needed, remove (without -v), and establish teardown on EVERY exit path.
        Strictly validates ownership before invoking Docker.
        Captures all exceptions without letting them escape, recording unresolved status.
        """
        # Validate ownership first: never issue mutating commands to unowned containers
        self._verify_owned_target(target)

        self.log(f"[CONTAINER-TEARDOWN] Initiating stop_and_remove for {target}")
        evidence: Dict[str, Any] = {"target": target, "started_at_utc": self._now_utc()}

        stopped = False
        removed = False
        clean_exit = False
        unresolved_processes = 0
        unresolved_reason: Optional[str] = None

        with self._lock:
            self._in_teardown = True

        try:
            # 1. Stop container (graceful stop, kill fallback)
            try:
                stop_res = self._run_cmd(
                    list(self.docker_cmd) + ["stop", "--time", str(max(1, int(grace_sec))), target],
                    timeout=DEFAULT_STOP_TIMEOUT_SEC,
                )
                evidence["stop_exit"] = stop_res.returncode
                evidence["stop_stderr"] = stop_res.stderr
                if stop_res.returncode == 0:
                    stopped = True
                else:
                    kill_res = self._run_cmd(
                        list(self.docker_cmd) + ["kill", target],
                        timeout=10.0,
                    )
                    evidence["kill_exit"] = kill_res.returncode
                    evidence["kill_stderr"] = kill_res.stderr
                    if kill_res.returncode == 0:
                        stopped = True
            except Exception as exc:
                evidence["stop_exc"] = str(exc)

            # Check running state via inspect
            try:
                inspect_state = self._run_cmd(
                    list(self.docker_cmd) + ["inspect", "-f", "{{.State.Running}}", target],
                    timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
                )
                evidence["inspect_state_exit"] = inspect_state.returncode
                evidence["inspect_state_out"] = inspect_state.stdout.strip()
                evidence["inspect_state_err"] = inspect_state.stderr.strip()

                if inspect_state.returncode == 0:
                    is_running = inspect_state.stdout.strip().lower() == "true"
                    if not is_running:
                        stopped = True
                    else:
                        unresolved_reason = f"Container {target} is still running after stop/kill"
                else:
                    combined_err = f"{inspect_state.stderr} {inspect_state.stdout}".lower()
                    if "no such container" in combined_err or "no such object" in combined_err:
                        stopped = True
                        removed = True
                        clean_exit = True
            except Exception as exc:
                evidence["inspect_state_exc"] = str(exc)

            # 2. Remove container without deleting volumes (no -v)
            if not removed:
                try:
                    rm_res = self._run_cmd(
                        list(self.docker_cmd) + ["rm", "-f", target],
                        timeout=DEFAULT_RM_TIMEOUT_SEC,
                    )
                    evidence["rm_exit"] = rm_res.returncode
                    evidence["rm_stderr"] = rm_res.stderr
                except Exception as exc:
                    evidence["rm_exc"] = str(exc)

            # 3. VERIFY REMOVAL
            try:
                verify_inspect = self._run_cmd(
                    list(self.docker_cmd) + ["inspect", target],
                    timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
                )
                evidence["verify_inspect_exit"] = verify_inspect.returncode
                evidence["verify_inspect_err"] = verify_inspect.stderr

                combined_verify_err = f"{verify_inspect.stderr} {verify_inspect.stdout}".lower()
                is_daemon_error = any(phrase in combined_verify_err for phrase in (
                    "cannot connect to the docker daemon",
                    "is the docker daemon running",
                    "connection refused",
                    "connection reset",
                    "dial unix",
                    "permission denied",
                    "socket:",
                ))

                if is_daemon_error:
                    unresolved_reason = f"Docker daemon failure during removal verification for {target}: {verify_inspect.stderr}"
                    removed = False
                    clean_exit = False
                elif verify_inspect.returncode == 0:
                    unresolved_reason = f"Container {target} still exists on daemon after removal"
                    removed = False
                    clean_exit = False
                else:
                    is_not_found = (
                        verify_inspect.returncode in (1, 125)
                        and ("no such container" in combined_verify_err or "no such object" in combined_verify_err)
                    )
                    if is_not_found:
                        removed = True
                        clean_exit = True
                        stopped = True
                    else:
                        unresolved_reason = f"Ambiguous inspect response after rm for {target}: {verify_inspect.stderr}"
                        removed = False
                        clean_exit = False
            except Exception as exc:
                unresolved_reason = f"Exception during removal verification for {target}: {exc}"
                evidence["verify_inspect_exc"] = str(exc)
                removed = False
                clean_exit = False

        finally:
            with self._lock:
                self._in_teardown = False

        resolved = (
            stopped is True
            and removed is True
            and clean_exit is True
            and unresolved_processes == 0
            and unresolved_reason is None
        )

        with self._lock:
            matched_id: Optional[str] = None
            matched_record: Optional[ContainerRecord] = None
            for cid, rec in self._active_containers.items():
                if cid == target or rec.container_name == target:
                    matched_id = cid
                    matched_record = rec
                    break

            if resolved:
                if matched_id:
                    self._active_containers.pop(matched_id, None)
                    if matched_record and os.path.exists(matched_record.intent.cidfile_path):
                        try:
                            os.unlink(matched_record.intent.cidfile_path)
                        except OSError:
                            pass
                self._ownership_journal.append({
                    "timestamp": self._now_utc(),
                    "event": "container_teardown_resolved",
                    "target": target,
                    "container_id": matched_id,
                })
            else:
                unres_rec = UnresolvedRecord(
                    identity=target,
                    intent=matched_record.intent if matched_record else None,
                    reason=unresolved_reason or "unknown teardown failure",
                    raw_evidence=evidence,
                    recorded_at_utc=self._now_utc(),
                )
                self._unresolved_containers[target] = unres_rec
                self._fail_closed(f"Unresolved teardown for {target}: {unresolved_reason}")

        result = TeardownResult(
            resolved=resolved,
            container_id=matched_id,
            container_name=target,
            stopped=stopped,
            removed=removed,
            clean_exit=clean_exit,
            unresolved_processes=unresolved_processes,
            unresolved_reason=unresolved_reason,
            evidence=evidence,
        )
        with self._lock:
            self._completed_teardowns.append(result)
        return result

    # -------------------------------------------------------------------------
    # High-Level Run Orchestration (Lifecycle Guarantees in finally)
    # -------------------------------------------------------------------------

    def run_container(self, spec: ContainerSpec) -> ContainerOutcome:
        """
        Execute container lifecycle with full ownership, pre-start inspection,
        bounded output capture, and encompassing teardown on every exit path.
        """
        with self._lock:
            if self.has_unresolved_ownership():
                raise UnresolvedOwnershipError(
                    f"Refusing to run container: session failed closed ({self._fail_closed_reason})"
                )

        intent: Optional[CreationIntent] = None
        container_id: Optional[str] = None
        teardown_result: Optional[TeardownResult] = None
        start_time = time.monotonic()
        timed_out = False
        cancelled = False
        exit_code = -1
        stdout = ""
        stderr = ""
        error_msg: Optional[str] = None
        bounded = False

        try:
            # 1. Record creation intent & create container
            intent, container_id = self.create_container(spec)

            if self.is_cancelled():
                cancelled = True
                raise ContainerCancelledError("Session cancellation requested before start")

            # 2. Inspect cage settings and mounts before start
            self.inspect_and_verify_cage_and_mounts(container_id, spec)

            if self.is_cancelled():
                cancelled = True
                raise ContainerCancelledError("Session cancellation requested before start")

            # 3. Start container & execute with bounded output
            with self._lock:
                if container_id in self._active_containers:
                    rec = self._active_containers[container_id]
                    object.__setattr__(rec, "state", "started")

            exit_code, stdout, stderr, timed_out, bounded = self._execute_bounded(
                container_id, spec
            )

        except ContainerCancelledError as exc:
            cancelled = True
            error_msg = str(exc)
            exit_code = 130
        except ContainerTimeoutError as exc:
            timed_out = True
            error_msg = str(exc)
            exit_code = 124
        except (MountInspectionError, CageInspectionError, ContainerLifecycleError) as exc:
            error_msg = str(exc)
            exit_code = -1
        except Exception as exc:
            error_msg = str(exc)
            exit_code = -1
        finally:
            # 4. Mandatory teardown in finally block on EVERY exit path
            target = container_id or (intent.container_name if intent else None)
            if target:
                try:
                    teardown_result = self.stop_and_remove(target, grace_sec=self.default_grace_sec)
                except Exception as exc:
                    self._fail_closed(f"Teardown exception for {target}: {exc}")
                    teardown_result = TeardownResult(
                        resolved=False,
                        container_id=container_id,
                        container_name=target,
                        stopped=False,
                        removed=False,
                        clean_exit=False,
                        unresolved_processes=1,
                        unresolved_reason=f"Teardown raised unhandled exception: {exc}",
                        evidence={"exception": str(exc)},
                    )
            else:
                teardown_result = TeardownResult(
                    resolved=True,
                    container_id=None,
                    container_name="",
                    stopped=False,
                    removed=False,
                    clean_exit=True,
                    unresolved_processes=0,
                    unresolved_reason=None,
                    evidence={"note": "no container created"},
                )

        outcome = ContainerOutcome(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_sec=time.monotonic() - start_time,
            timed_out=timed_out,
            cancelled=cancelled,
            teardown=teardown_result,
            container_id=container_id,
            container_name=intent.container_name if intent else "",
            error=error_msg,
            bounded=bounded,
        )

        if not teardown_result.is_resolved():
            raise UnresolvedOwnershipError(
                f"Container {target} teardown failed closed: {teardown_result.unresolved_reason}"
            )

        return outcome

    # -------------------------------------------------------------------------
    # Preflight Operations (Using the exact same ownership mechanism)
    # -------------------------------------------------------------------------

    def run_probe(self, spec: ContainerSpec) -> ContainerOutcome:
        """Alias for run_container; preflight probes use the identical owned lifecycle."""
        return self.run_container(spec)

    def start_container_detached(self, container_id: str) -> None:
        """
        Start container in detached mode for multi-container preflight tests.
        Enforces identical pre-start cage and mount inspection, cancellation checks,
        ownership verification, and fail-closed admission.
        """
        with self._lock:
            if self.has_unresolved_ownership():
                raise UnresolvedOwnershipError(
                    f"Refusing to start container: session failed closed ({self._fail_closed_reason})"
                )
            if self.is_cancelled():
                raise ContainerCancelledError("Session cancellation requested before start")
            if container_id not in self._active_containers:
                raise OwnershipReconciliationError(
                    f"Refusing operation on unregistered/unowned container: {container_id!r}"
                )
            rec = self._active_containers[container_id]

        # Enforce pre-start inspection before starting detached container
        try:
            self.inspect_and_verify_cage_and_mounts(container_id, rec.spec)
        except Exception:
            self.stop_and_remove(container_id, grace_sec=self.default_grace_sec)
            raise

        inspect_res = self._run_cmd(
            list(self.docker_cmd) + ["start", container_id],
            timeout=15.0,
        )
        if inspect_res.returncode != 0:
            raise ContainerLifecycleError(f"Failed to start container {container_id}: {inspect_res.stderr}")
        with self._lock:
            if container_id in self._active_containers:
                rec = self._active_containers[container_id]
                object.__setattr__(rec, "state", "started")

    def inspect_container(self, target: str) -> Dict[str, Any]:
        """Inspect owned container and return parsed JSON."""
        self._verify_owned_target(target)
        inspect_res = self._run_cmd(
            list(self.docker_cmd) + ["inspect", target],
            timeout=DEFAULT_INSPECT_TIMEOUT_SEC,
        )
        if inspect_res.returncode != 0:
            raise ContainerLifecycleError(f"Inspect failed for {target}: {inspect_res.stderr}")
        try:
            inspect_list = json.loads(inspect_res.stdout)
            if not isinstance(inspect_list, list) or len(inspect_list) != 1:
                raise ContainerLifecycleError(f"Ambiguous inspect output cardinality for {target}")
            return inspect_list[0]
        except Exception as exc:
            raise ContainerLifecycleError(f"Invalid inspect JSON for {target}: {exc}") from exc

    def exec_in_container(
        self,
        container_id: str,
        command: Sequence[str],
        timeout_sec: float = 30.0,
    ) -> Tuple[int, str, str]:
        """Execute command in running owned container via docker exec with output bounds."""
        self._verify_owned_target(container_id)
        with self._lock:
            if container_id not in self._active_containers:
                raise OwnershipReconciliationError(f"Cannot exec in inactive container: {container_id!r}")

        exec_cmd = list(self.docker_cmd) + ["exec", container_id] + list(command)
        res = self._run_cmd(exec_cmd, timeout=timeout_sec, max_output_bytes=DEFAULT_MAX_AUX_BYTES)
        return res.returncode, res.stdout, res.stderr

    def top_container(
        self,
        container_id: str,
        args: Sequence[str] = (),
    ) -> str:
        """Run docker top on running owned container."""
        self._verify_owned_target(container_id)
        with self._lock:
            if container_id not in self._active_containers:
                raise OwnershipReconciliationError(f"Cannot run top on inactive container: {container_id!r}")

        top_cmd = list(self.docker_cmd) + ["top", container_id] + list(args)
        res = self._run_cmd(top_cmd, timeout=15.0, max_output_bytes=DEFAULT_MAX_AUX_BYTES)
        if res.returncode != 0:
            raise ContainerLifecycleError(f"docker top failed for {container_id}: {res.stderr}")
        return res.stdout

    def stop_container(self, container_id: str, timeout_sec: float = 5.0) -> bool:
        """Stop owned container with grace timeout."""
        self._verify_owned_target(container_id)
        res = self._run_cmd(
            list(self.docker_cmd) + ["stop", "--time", str(int(timeout_sec)), container_id],
            timeout=timeout_sec + 10.0,
        )
        return res.returncode == 0

    # -------------------------------------------------------------------------
    # Session Cleanup & Signal Handlers
    # -------------------------------------------------------------------------

    def cleanup_all(self) -> List[TeardownResult]:
        """
        Tear down all active and pending containers in the session.
        Interruption-resistant loop: attempts all targets even if one fails.
        """
        results: List[TeardownResult] = []
        with self._lock:
            active_ids = list(self._active_containers.keys())

        for cid in active_ids:
            try:
                res = self.stop_and_remove(cid, grace_sec=self.default_grace_sec)
                results.append(res)
            except Exception as exc:
                self._fail_closed(f"Unhandled exception during cleanup of active container {cid}: {exc}")

        with self._lock:
            pending = list(self._pending_intents.values())

        for intent in pending:
            try:
                reconciled_id = self.reconcile_uncertain_create(intent)
                if reconciled_id:
                    res = self.stop_and_remove(reconciled_id, grace_sec=self.default_grace_sec)
                    results.append(res)
                else:
                    with self._lock:
                        self._pending_intents.pop(intent.intent_id, None)
            except Exception as exc:
                self._fail_closed(f"Failed to reconcile pending creation {intent.container_name}: {exc}")

        return results

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """
        Signal handler for SIGINT and SIGTERM.
        Requests cooperative cancellation.
        Does NOT raise if already in teardown, allowing all containers to be cleaned up.
        Zero reentrant Docker invocations occur inside this signal handler.
        """
        self.request_cancellation(signum)
        if not self._in_teardown:
            raise ContainerCancelledError(f"Container execution interrupted by signal {signum}")

    def install_signal_handlers(self) -> None:
        """Install signal handlers for graceful, non-reentrant cleanup."""
        if threading.current_thread() is not threading.main_thread():
            return
        with self._lock:
            if not self._signal_handlers_installed:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    try:
                        prev = signal.signal(sig, self._handle_signal)
                        self._previous_signal_handlers[sig] = prev
                    except (ValueError, OSError):
                        pass
                self._signal_handlers_installed = True

    def restore_signal_handlers(self) -> None:
        """Restore previous signal handlers."""
        if threading.current_thread() is not threading.main_thread():
            return
        with self._lock:
            if self._signal_handlers_installed:
                for sig, prev in self._previous_signal_handlers.items():
                    try:
                        signal.signal(sig, prev)
                    except (ValueError, OSError):
                        pass
                self._previous_signal_handlers.clear()
                self._signal_handlers_installed = False

    def _atexit_cleanup(self) -> None:
        """Supplementary atexit hook."""
        try:
            self.cleanup_all()
        except Exception:
            pass

    def close(self) -> None:
        """Close session, clean up all owned containers, and restore handlers."""
        try:
            self.cleanup_all()
        finally:
            self.restore_signal_handlers()
            if self._atexit_cleanup_registered:
                try:
                    atexit.unregister(self._atexit_cleanup)
                except Exception:
                    pass
                self._atexit_cleanup_registered = False

            # Only remove session dir if ALL containers were resolved and none remain active/pending
            has_remaining = (
                self.has_unresolved_ownership()
                or len(self._active_containers) > 0
                or len(self._pending_intents) > 0
            )
            if self._owned_session_dir and self.session_dir.exists() and not has_remaining:
                try:
                    for p in self.session_dir.iterdir():
                        p.unlink(missing_ok=True)
                    self.session_dir.rmdir()
                except OSError:
                    pass

    def __enter__(self) -> "OwnedContainerSession":
        self.install_signal_handlers()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            self.cleanup_all()
        finally:
            self.restore_signal_handlers()
            if self.has_unresolved_ownership():
                raise UnresolvedOwnershipError(
                    f"Session closed with unresolved container ownership: {self._fail_closed_reason}"
                )
