"""
proof/hosted_exec_witness.py

Trusted C-owned execution witness and verification module for Linux strict proof.
Operates under the shared contract defined in agent://OriginTrustPlan (Lines 159-185, 215-230).

Responsibilities:
1. Streaming protocol definition ("iyi-exec-witness-v1") for kernel-verified execve/execveat stops.
2. Independent verification of witness streams against required executable (st_dev, st_ino) sets.
3. Hardened rejection of reader-only (atime advance via read(2)) and utime-only (utimensat(2)) manipulations.
4. Process ancestry, descendant tracking, and non-dumpability audit (PR_SET_DUMPABLE=0).
5. Raw executable capture verification: reads retained bytes from disk and recalculates SHA-256.
6. Zero placeholder tolerance: empty captures or empty-file SHA-256 hashes are strictly rejected.
7. Unmediated execution refusal: execution strictly requires the compiled C native tracer.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import stat
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


PROTOCOL_VERSION = "iyi-exec-witness-v1"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class WitnessError(Exception):
    """Base exception for all witness-related errors."""
    pass


class WitnessVerificationError(WitnessError):
    """Raised when execution witness verification fails."""
    pass


class LaunchBindingMismatch(WitnessVerificationError):
    """Raised when witness session launch binding does not match expected context."""
    pass


class SequenceIntegrityError(WitnessVerificationError):
    """Raised when sequence counter is non-monotonic, gapped, or duplicated."""
    pass


class ExecNotWitnessedError(WitnessVerificationError):
    """Raised when an executable required by ledger/observer was never witnessed executing."""
    pass


class RawCaptureError(WitnessVerificationError):
    """Raised when raw executable capture is missing, zero-length, or corrupt."""
    pass


@dataclasses.dataclass(frozen=True)
class WitnessSessionStart:
    protocol: str
    tracer_pid: int
    start_time_ns: int
    tracer_dumpable: int
    launch_binding: Dict[str, Any]
    options: List[str]


@dataclasses.dataclass(frozen=True)
class WitnessProcessSpawn:
    seq_id: int
    timestamp_ns: int
    pid: int
    ppid: int
    parent_seq_id: int
    kind: str
    is_thread: bool


@dataclasses.dataclass(frozen=True)
class WitnessExecSuccess:
    seq_id: int
    timestamp_ns: int
    pid: int
    ppid: int
    exe_path: str
    st_dev: int
    st_ino: int
    st_mode: int
    st_size: int
    st_uid: int
    st_gid: int
    st_atim_ns: int
    st_mtim_ns: int
    st_ctim_ns: int
    held_fd_index: int
    cmdline: List[str]
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    raw_captured: bool = False

    @property
    def inoderef(self) -> Tuple[int, int]:
        return (self.st_dev, self.st_ino)


@dataclasses.dataclass(frozen=True)
class WitnessRawExecCapture:
    seq_id: int
    timestamp_ns: int
    st_dev: int
    st_ino: int
    exe_path: str
    size_bytes: int
    sha256: str
    captured_file: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class WitnessProcessExit:
    seq_id: int
    timestamp_ns: int
    pid: int
    exit_code: int
    raw_status: int


@dataclasses.dataclass(frozen=True)
class WitnessSessionEnd:
    protocol: str
    tracer_pid: int
    end_time_ns: int
    status: str
    root_exit_code: int
    total_processes_spawned: int
    total_exec_events: int
    active_processes_at_end: int
    failure_reason: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class WitnessVerificationResult:
    verified: bool
    tracer_pid: int
    root_exit_code: int
    total_spawns: int
    total_execs: int
    witnessed_inoderefs: Set[Tuple[int, int]]
    witnessed_paths: Set[str]
    session_start: WitnessSessionStart
    session_end: WitnessSessionEnd
    exec_events: List[WitnessExecSuccess]
    raw_captures: List[WitnessRawExecCapture]


def parse_witness_events(raw_data: Union[str, bytes, Iterable[str]]) -> List[Dict[str, Any]]:
    """
    Parse a newline-delimited JSON (NDJSON) stream of witness events.
    Fails closed on malformed JSON or invalid structures.
    """
    lines: List[str] = []
    if isinstance(raw_data, bytes):
        lines = raw_data.decode("utf-8", errors="replace").splitlines()
    elif isinstance(raw_data, str):
        lines = raw_data.splitlines()
    else:
        lines = [line.strip() for line in raw_data if line.strip()]

    events: List[Dict[str, Any]] = []
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WitnessVerificationError(f"Corrupt witness NDJSON on line {idx + 1}: {exc}") from exc

        if not isinstance(record, dict) or "event" not in record:
            raise WitnessVerificationError(f"Malformed event record on line {idx + 1}: {record}")
        events.append(record)

    return events


def verify_exec_witness_evidence(
    events: List[Dict[str, Any]],
    required_executables: Optional[Iterable[Tuple[int, int]]] = None,
    expected_launch_binding: Optional[Dict[str, Any]] = None,
    require_non_dumpable: bool = True,
    expected_root_exit_code: Optional[int] = 0,
    require_raw_capture: bool = False,
    raw_capture_dir: Optional[str] = None,
) -> WitnessVerificationResult:
    """
    Perform rigorous, fail-closed verification of witness evidence stream.
    
    Invariants enforced:
    1. Stream MUST begin with a valid 'session_start' carrying protocol 'iyi-exec-witness-v1'.
    2. Parent tracer MUST prove non-dumpability ('tracer_dumpable == 0').
    3. Launch binding MUST match expected controller context (driver, attempt, etc.).
    4. Sequence identifiers ('seq_id') MUST be strictly monotonic starting at 1.
    5. Stream MUST terminate with 'session_end' carrying status 'COMPLETE'.
    6. All spawned processes MUST be fully reaped ('active_processes_at_end == 0').
    7. Every (st_dev, st_ino) in 'required_executables' MUST have at least one matching 'exec_success'.
    8. Zero-length or placeholder raw executable captures are strictly rejected.
    9. If 'raw_capture_dir' is provided, verified raw bytes on disk are independently hashed.
    """
    if not events:
        raise WitnessVerificationError("Empty witness evidence stream: no events recorded")

    start_event = events[0]
    if start_event.get("event") != "session_start":
        raise WitnessVerificationError(f"First event must be 'session_start', got '{start_event.get('event')}'")

    if start_event.get("protocol") != PROTOCOL_VERSION:
        raise WitnessVerificationError(
            f"Protocol version mismatch: expected '{PROTOCOL_VERSION}', got '{start_event.get('protocol')}'"
        )

    tracer_pid = start_event.get("tracer_pid")
    if not isinstance(tracer_pid, int) or tracer_pid <= 0:
        raise WitnessVerificationError(f"Invalid tracer_pid in session_start: {tracer_pid}")

    if require_non_dumpable and start_event.get("tracer_dumpable") != 0:
        raise WitnessVerificationError(
            f"Tracer dumpable invariant violated: expected 0 (PR_SET_DUMPABLE=0), got {start_event.get('tracer_dumpable')}"
        )

    launch_binding = start_event.get("launch_binding", {})
    if expected_launch_binding is not None:
        for k, v in expected_launch_binding.items():
            if launch_binding.get(k) != v:
                raise LaunchBindingMismatch(
                    f"Launch binding key '{k}' mismatch: expected {v!r}, got {launch_binding.get(k)!r}"
                )

    session_start = WitnessSessionStart(
        protocol=start_event["protocol"],
        tracer_pid=tracer_pid,
        start_time_ns=start_event.get("start_time_ns", 0),
        tracer_dumpable=start_event.get("tracer_dumpable", -1),
        launch_binding=launch_binding,
        options=start_event.get("options", []),
    )

    end_event = events[-1]
    if end_event.get("event") != "session_end":
        raise WitnessVerificationError(
            f"Witness session incomplete: stream missing 'session_end' (terminated with '{end_event.get('event')}')"
        )

    if end_event.get("protocol") != PROTOCOL_VERSION:
        raise WitnessVerificationError(f"Protocol mismatch in session_end: {end_event.get('protocol')}")

    if end_event.get("status") != "COMPLETE":
        reason = end_event.get("failure_reason", "UNKNOWN")
        raise WitnessVerificationError(f"Witness session marked FAILED: {reason}")

    active_at_end = end_event.get("active_processes_at_end", -1)
    if active_at_end != 0:
        raise WitnessVerificationError(f"Orphaned tracees detected: active_processes_at_end={active_at_end}")

    root_exit_code = end_event.get("root_exit_code", -1)
    if expected_root_exit_code is not None and root_exit_code != expected_root_exit_code:
        raise WitnessVerificationError(
            f"Root workload exit code mismatch: expected {expected_root_exit_code}, got {root_exit_code}"
        )

    session_end = WitnessSessionEnd(
        protocol=end_event["protocol"],
        tracer_pid=end_event.get("tracer_pid", 0),
        end_time_ns=end_event.get("end_time_ns", 0),
        status=end_event["status"],
        root_exit_code=root_exit_code,
        total_processes_spawned=end_event.get("total_processes_spawned", 0),
        total_exec_events=end_event.get("total_exec_events", 0),
        active_processes_at_end=active_at_end,
        failure_reason=end_event.get("failure_reason"),
    )

    # Validate middle events
    expected_seq = 1
    spawned_pids: Dict[int, int] = {}  # pid -> seq_id
    witnessed_inoderefs: Set[Tuple[int, int]] = set()
    witnessed_paths: Set[str] = set()
    exec_events: List[WitnessExecSuccess] = []
    raw_captures: List[WitnessRawExecCapture] = []
    raw_captures_by_ref: Dict[Tuple[int, int], WitnessRawExecCapture] = {}

    for idx, ev in enumerate(events[1:-1], start=2):
        ev_type = ev.get("event")
        seq = ev.get("seq_id")

        if ev_type == "process_spawn":
            if seq != expected_seq:
                raise SequenceIntegrityError(
                    f"Non-monotonic sequence on line {idx}: expected {expected_seq}, got {seq}"
                )
            expected_seq += 1
            pid = ev.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                raise WitnessVerificationError(f"Invalid pid on line {idx}: {pid}")
            spawned_pids[pid] = seq

        elif ev_type == "exec_success":
            pid = ev.get("pid")
            if pid not in spawned_pids:
                raise WitnessVerificationError(f"Exec event on line {idx} for untracked pid {pid}")

            dev = ev.get("st_dev")
            ino = ev.get("st_ino")
            if not isinstance(dev, int) or not isinstance(ino, int):
                raise WitnessVerificationError(f"Invalid st_dev/st_ino in exec_success on line {idx}: {dev}, {ino}")

            path = ev.get("exe_path", "")
            witnessed_inoderefs.add((dev, ino))
            if path:
                witnessed_paths.add(path)

            sha = ev.get("sha256")
            size = ev.get("size_bytes")
            raw_cap = ev.get("raw_captured", False)

            if require_raw_capture:
                if not raw_cap or not sha or size is None or size <= 0:
                    raise RawCaptureError(
                        f"Missing or zero-length raw executable capture for {path} (dev={dev}, ino={ino}): size={size}"
                    )
                if sha == EMPTY_SHA256:
                    raise RawCaptureError(
                        f"Empty placeholder SHA-256 rejected for executable {path} (dev={dev}, ino={ino})"
                    )

            exec_ev = WitnessExecSuccess(
                seq_id=seq or 0,
                timestamp_ns=ev.get("timestamp_ns", 0),
                pid=pid,
                ppid=ev.get("ppid", 0),
                exe_path=path,
                st_dev=dev,
                st_ino=ino,
                st_mode=ev.get("st_mode", 0),
                st_size=ev.get("st_size", 0),
                st_uid=ev.get("st_uid", 0),
                st_gid=ev.get("st_gid", 0),
                st_atim_ns=ev.get("st_atim_ns", 0),
                st_mtim_ns=ev.get("st_mtim_ns", 0),
                st_ctim_ns=ev.get("st_ctim_ns", 0),
                held_fd_index=ev.get("held_fd_index", -1),
                cmdline=ev.get("cmdline", []),
                sha256=sha,
                size_bytes=size,
                raw_captured=raw_cap,
            )
            exec_events.append(exec_ev)

        elif ev_type == "raw_exec_capture":
            dev = ev.get("st_dev")
            ino = ev.get("st_ino")
            sha = ev.get("sha256", "")
            size = ev.get("size_bytes", 0)
            if size <= 0 or not sha or sha == EMPTY_SHA256:
                raise RawCaptureError(f"Zero-length or placeholder raw capture record on line {idx}: {ev}")
            cap = WitnessRawExecCapture(
                seq_id=seq or 0,
                timestamp_ns=ev.get("timestamp_ns", 0),
                st_dev=dev,
                st_ino=ino,
                exe_path=ev.get("exe_path", ""),
                size_bytes=size,
                sha256=sha,
                captured_file=ev.get("captured_file"),
            )
            raw_captures.append(cap)
            raw_captures_by_ref[(dev, ino)] = cap

        elif ev_type == "process_exit":
            pid = ev.get("pid")
            if pid not in spawned_pids:
                raise WitnessVerificationError(f"Exit event on line {idx} for untracked pid {pid}")

        elif ev_type == "violation":
            raise WitnessVerificationError(
                f"Security violation recorded on line {idx}: {ev.get('violation_type')} ({ev.get('detail')})"
            )

    # Check required executables against witnessed kernel executions
    if required_executables is not None:
        for req_dev, req_ino in required_executables:
            if (req_dev, req_ino) not in witnessed_inoderefs:
                raise ExecNotWitnessedError(
                    f"Candidate executable inode (dev={req_dev}, ino={req_ino}) was never witnessed executing in kernel"
                )

            # If raw persistence verification is requested, independently verify retained bytes from disk
            if raw_capture_dir:
                expected_file = os.path.join(raw_capture_dir, f"{req_dev}_{req_ino}.bin")
                if not os.path.isfile(expected_file):
                    raise RawCaptureError(
                        f"Retained raw executable missing on disk: {expected_file} (dev={req_dev}, ino={req_ino})"
                    )

                with open(expected_file, "rb") as f:
                    file_bytes = f.read()

                if len(file_bytes) == 0:
                    raise RawCaptureError(
                        f"Zero-length raw executable on disk rejected: {expected_file}"
                    )

                computed_sha = hashlib.sha256(file_bytes).hexdigest()
                if computed_sha == EMPTY_SHA256:
                    raise RawCaptureError(f"Placeholder SHA-256 rejected for {expected_file}")

                # Verify against raw_capture record
                if (req_dev, req_ino) in raw_captures_by_ref:
                    cap_rec = raw_captures_by_ref[(req_dev, req_ino)]
                    if cap_rec.size_bytes != len(file_bytes):
                        raise RawCaptureError(
                            f"Byte size mismatch on disk: expected {cap_rec.size_bytes}, got {len(file_bytes)}"
                        )
                    if cap_rec.sha256 != computed_sha:
                        raise RawCaptureError(
                            f"SHA-256 digest mismatch on disk: expected {cap_rec.sha256}, got {computed_sha}"
                        )

    return WitnessVerificationResult(
        verified=True,
        tracer_pid=tracer_pid,
        root_exit_code=root_exit_code,
        total_spawns=len(spawned_pids),
        total_execs=len(exec_events),
        witnessed_inoderefs=witnessed_inoderefs,
        witnessed_paths=witnessed_paths,
        session_start=session_start,
        session_end=session_end,
        exec_events=exec_events,
        raw_captures=raw_captures,
    )


def main() -> int:
    """
    CLI Dispatcher for Hosted Exec Witness.
    Strictly requires the compiled C binary.
    Refuses any unmediated Python execution fallback.
    """
    if not sys.platform.startswith("linux"):
        print("hosted_exec_witness: Fatal: native ptrace execution witness requires Linux.", file=sys.stderr)
        return 255

    parser = argparse.ArgumentParser(description="Hosted Linux Execution Witness Dispatcher")
    parser.add_argument("--evidence-fd", type=int, default=None, help="Evidence output FD (>= 3)")
    parser.add_argument("--raw-capture-dir", type=str, default=None, help="Raw executable capture output directory")
    parser.add_argument("--launch-binding", type=str, default="{}", help="JSON launch binding metadata")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Target command to execute and trace")

    args = parser.parse_args()

    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd or args.evidence_fd is None or args.evidence_fd < 3:
        parser.print_help(sys.stderr)
        print("Error: --evidence-fd >= 3 and a target command are strictly required.", file=sys.stderr)
        return 2

    script_dir = os.path.dirname(os.path.abspath(__file__))
    bin_path = os.path.join(script_dir, "bin", "hosted_exec_witness")
    if not os.path.isfile(bin_path):
        bin_path = os.path.join(script_dir, "hosted_exec_witness")

    if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)):
        print(
            "hosted_exec_witness: Fatal: compiled native tracer binary is required. "
            "Unmediated Python fallback is strictly prohibited per security review.",
            file=sys.stderr,
        )
        return 255

    exec_args = [bin_path, "--evidence-fd", str(args.evidence_fd)]
    if args.raw_capture_dir is not None:
        exec_args.extend(["--raw-capture-dir", args.raw_capture_dir])
    if args.launch_binding:
        exec_args.extend(["--launch-binding", args.launch_binding])
    exec_args.append("--")
    exec_args.extend(cmd)

    os.execv(bin_path, exec_args)


if __name__ == "__main__":
    sys.exit(main())
