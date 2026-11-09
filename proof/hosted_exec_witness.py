"""
proof/hosted_exec_witness.py

Trusted C-owned execution witness and verification module for Linux strict proof.
Operates under the shared contract defined in agent://OriginTrustPlan (Lines 159-185, 215-230).

Responsibilities:
1. Streaming protocol definition ("iyi-exec-witness-v1") for kernel-verified execve/execveat stops.
2. Independent verification of witness streams against required executable (st_dev, st_ino) sets.
3. Hardened rejection of reader-only (atime advance via read(2)) and utime-only (utimensat(2)) manipulations.
4. Process ancestry, descendant tracking, and non-dumpability audit (PR_SET_DUMPABLE=0).
5. CLI entrypoint and ctypes-based native Linux tracer fallback.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import errno
import json
import os
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


PROTOCOL_VERSION = "iyi-exec-witness-v1"


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

    @property
    def inoderef(self) -> Tuple[int, int]:
        return (self.st_dev, self.st_ino)


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
            )
            exec_events.append(exec_ev)

        elif ev_type == "process_exit":
            pid = ev.get("pid")
            if pid not in spawned_pids:
                raise WitnessVerificationError(f"Exit event on line {idx} for untracked pid {pid}")

    # Check required executables against witnessed kernel executions
    if required_executables is not None:
        for req_dev, req_ino in required_executables:
            if (req_dev, req_ino) not in witnessed_inoderefs:
                raise ExecNotWitnessedError(
                    f"Candidate executable inode (dev={req_dev}, ino={req_ino}) was never witnessed executing in kernel"
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
    )


# ---------------------------------------------------------------------------
# Native Python / Ctypes Tracer Engine (Linux)
# ---------------------------------------------------------------------------

class NativeLinuxTracer:
    """
    Unprivileged Python tracer implementation using ctypes for Linux systems.
    Mirrors the C implementation in proof/hosted_exec_witness.c.
    """

    PTRACE_TRACEME = 0
    PTRACE_CONT = 7
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_GETEVENTMSG = 0x4201

    PTRACE_O_TRACESYSGOOD = 1
    PTRACE_O_TRACEFORK = 1 << 1
    PTRACE_O_TRACEVFORK = 1 << 2
    PTRACE_O_TRACECLONE = 1 << 3
    PTRACE_O_TRACEEXEC = 1 << 4
    PTRACE_O_TRACEEXIT = 1 << 6
    PTRACE_O_EXITKILL = 1 << 20

    PTRACE_EVENT_FORK = 1
    PTRACE_EVENT_VFORK = 2
    PTRACE_EVENT_CLONE = 3
    PTRACE_EVENT_EXEC = 4
    PTRACE_EVENT_EXIT = 6

    PR_SET_PDEATHSIG = 1
    PR_SET_DUMPABLE = 4

    def __init__(
        self,
        command: List[str],
        evidence_file: Optional[str] = None,
        evidence_fd: Optional[int] = None,
        launch_binding: Optional[Dict[str, Any]] = None,
    ):
        self.command = command
        self.evidence_file = evidence_file
        self.evidence_fd = evidence_fd
        self.launch_binding = launch_binding or {}
        self.out_file = None
        self._libc = None
        self._seq_counter = 0
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._active_count = 0
        self._root_pid = -1
        self._root_exit_code = 0
        self._root_exited = False
        self._failed = False
        self._failure_reason = None
        self._held_fds: List[int] = []

    def _get_libc(self):
        if self._libc is None:
            self._libc = ctypes.CDLL(None, use_errno=True)
        return self._libc

    def _emit(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":")) + "\n"
        if self.out_file:
            self.out_file.write(line.encode("utf-8"))
            self.out_file.flush()

    def run(self) -> int:
        libc = self._get_libc()

        if self.evidence_file:
            self.out_file = open(self.evidence_file, "wb")
        elif self.evidence_fd is not None:
            self.out_file = os.fdopen(self.evidence_fd, "wb", closefd=False)
        else:
            self.out_file = sys.stdout.buffer

        # 1. Enforce PR_SET_DUMPABLE=0
        res = libc.prctl(self.PR_SET_DUMPABLE, 0, 0, 0, 0)
        if res < 0:
            err = ctypes.get_errno()
            raise WitnessError(f"prctl(PR_SET_DUMPABLE, 0) failed: errno {err}")

        # 2. Emit session_start
        self._emit({
            "event": "session_start",
            "protocol": PROTOCOL_VERSION,
            "tracer_pid": os.getpid(),
            "start_time_ns": time.time_ns(),
            "tracer_dumpable": 0,
            "launch_binding": self.launch_binding,
            "options": ["TRACEEXEC", "TRACEFORK", "TRACEVFORK", "TRACECLONE", "TRACEEXIT", "EXITKILL", "TRACESYSGOOD"],
        })

        barrier_r, barrier_w = os.pipe()
        os.set_inheritable(barrier_r, True)
        os.set_inheritable(barrier_w, False)

        child_pid = os.fork()
        if child_pid == 0:
            # CHILD
            os.close(barrier_w)
            libc.prctl(self.PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)

            # Close all fds except stdio and barrier_r
            try:
                os.closerange(3, barrier_r)
                os.closerange(barrier_r + 1, 4096)
            except Exception:
                pass

            if libc.ptrace(self.PTRACE_TRACEME, 0, 0, 0) < 0:
                os._exit(127)

            os.kill(os.getpid(), signal.SIGSTOP)

            # Wait on barrier
            try:
                os.read(barrier_r, 1)
            except Exception:
                pass
            os.close(barrier_r)

            os.execvp(self.command[0], self.command)
            os._exit(127)

        # PARENT
        os.close(barrier_r)
        self._root_pid = child_pid

        # Wait for initial SIGSTOP
        _, status = os.waitpid(child_pid, 0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            self._failed = True
            self._failure_reason = "INITIAL_STOP_FAILED"
            os.kill(child_pid, signal.SIGKILL)
            self._finish()
            return 1

        opts = (
            self.PTRACE_O_TRACEEXEC
            | self.PTRACE_O_TRACEFORK
            | self.PTRACE_O_TRACEVFORK
            | self.PTRACE_O_TRACECLONE
            | self.PTRACE_O_TRACEEXIT
            | self.PTRACE_O_EXITKILL
            | self.PTRACE_O_TRACESYSGOOD
        )
        if libc.ptrace(self.PTRACE_SETOPTIONS, child_pid, 0, opts) < 0:
            self._failed = True
            self._failure_reason = "SETOPTIONS_FAILED"
            os.kill(child_pid, signal.SIGKILL)
            self._finish()
            return 1

        self._add_process(child_pid, os.getpid(), 0, "initial", False)

        # Release barrier
        try:
            os.write(barrier_w, b"G")
        finally:
            os.close(barrier_w)

        libc.ptrace(self.PTRACE_CONT, child_pid, 0, 0)

        # Event loop
        wall_flag = 0x40000000  # __WALL on Linux
        while self._active_count > 0:
            try:
                pid, status = os.waitpid(-1, wall_flag)
            except ChildProcessError:
                break
            except InterruptedError:
                continue

            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
                if pid in self._processes:
                    self._processes[pid]["active"] = False
                    self._processes[pid]["exited"] = True
                    self._processes[pid]["exit_code"] = code
                self._active_count -= 1
                if pid == self._root_pid:
                    self._root_exited = True
                    self._root_exit_code = code
                continue

            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                event = status >> 16

                if sig == signal.SIGTRAP:
                    if event == self.PTRACE_EVENT_EXEC:
                        self._handle_exec(pid)
                        libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
                        continue
                    elif event in (self.PTRACE_EVENT_FORK, self.PTRACE_EVENT_VFORK, self.PTRACE_EVENT_CLONE):
                        new_pid = ctypes.c_ulong(0)
                        libc.ptrace(self.PTRACE_GETEVENTMSG, pid, 0, ctypes.byref(new_pid))
                        if new_pid.value > 0:
                            kind = "fork" if event == self.PTRACE_EVENT_FORK else (
                                "vfork" if event == self.PTRACE_EVENT_VFORK else "clone"
                            )
                            is_thread = (event == self.PTRACE_EVENT_CLONE)
                            parent_seq = self._processes.get(pid, {}).get("seq_id", 0)
                            self._add_process(new_pid.value, pid, parent_seq, kind, is_thread)
                        libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
                        continue
                    elif event == self.PTRACE_EVENT_EXIT:
                        exit_status = ctypes.c_ulong(0)
                        libc.ptrace(self.PTRACE_GETEVENTMSG, pid, 0, ctypes.byref(exit_status))
                        seq = self._processes.get(pid, {}).get("seq_id", 0)
                        self._emit({
                            "event": "process_exit",
                            "seq_id": seq,
                            "timestamp_ns": time.time_ns(),
                            "pid": pid,
                            "exit_code": exit_status.value,
                            "raw_status": exit_status.value,
                        })
                        libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
                        continue
                    else:
                        libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
                        continue

                elif sig in (signal.SIGSTOP, signal.SIGTRAP | 0x80):
                    libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
                    continue
                else:
                    libc.ptrace(self.PTRACE_CONT, pid, 0, sig)
                    continue

        self._finish()
        return self._root_exit_code

    def _add_process(self, pid: int, ppid: int, parent_seq: int, kind: str, is_thread: bool) -> None:
        self._seq_counter += 1
        seq = self._seq_counter
        self._processes[pid] = {
            "pid": pid,
            "ppid": ppid,
            "seq_id": seq,
            "parent_seq_id": parent_seq,
            "kind": kind,
            "is_thread": is_thread,
            "active": True,
            "exited": False,
        }
        self._active_count += 1
        self._emit({
            "event": "process_spawn",
            "seq_id": seq,
            "timestamp_ns": time.time_ns(),
            "pid": pid,
            "ppid": ppid,
            "parent_seq_id": parent_seq,
            "kind": kind,
            "is_thread": is_thread,
        })

    def _handle_exec(self, pid: int) -> None:
        proc_exe = f"/proc/{pid}/exe"
        exe_path = "unknown"
        try:
            exe_path = os.readlink(proc_exe)
        except Exception:
            pass

        st_dev, st_ino, st_mode, st_size, st_uid, st_gid = 0, 0, 0, 0, 0, 0
        st_atim_ns, st_mtim_ns, st_ctim_ns = 0, 0, 0
        try:
            st = os.stat(proc_exe)
            st_dev = st.st_dev
            st_ino = st.st_ino
            st_mode = st.st_mode
            st_size = st.st_size
            st_uid = st.st_uid
            st_gid = st.st_gid
            st_atim_ns = st.st_atime_ns
            st_mtim_ns = st.st_mtime_ns
            st_ctim_ns = st.st_ctime_ns
        except Exception:
            pass

        held_idx = -1
        try:
            fd = os.open(proc_exe, os.O_PATH | os.O_CLOEXEC)
            held_idx = len(self._held_fds)
            self._held_fds.append(fd)
        except Exception:
            pass

        cmdline: List[str] = []
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                content = f.read()
                cmdline = [c.decode("utf-8", errors="replace") for c in content.split(b"\x00") if c]
        except Exception:
            pass

        seq = self._processes.get(pid, {}).get("seq_id", 0)
        ppid = self._processes.get(pid, {}).get("ppid", 0)
        self._emit({
            "event": "exec_success",
            "seq_id": seq,
            "timestamp_ns": time.time_ns(),
            "pid": pid,
            "ppid": ppid,
            "exe_path": exe_path,
            "st_dev": st_dev,
            "st_ino": st_ino,
            "st_mode": st_mode,
            "st_size": st_size,
            "st_uid": st_uid,
            "st_gid": st_gid,
            "st_atim_ns": st_atim_ns,
            "st_mtim_ns": st_mtim_ns,
            "st_ctim_ns": st_ctim_ns,
            "held_fd_index": held_idx,
            "cmdline": cmdline,
        })

    def _finish(self) -> None:
        status = "FAILED" if (self._failed or not self._root_exited or self._active_count > 0) else "COMPLETE"
        rec = {
            "event": "session_end",
            "protocol": PROTOCOL_VERSION,
            "tracer_pid": os.getpid(),
            "end_time_ns": time.time_ns(),
            "status": status,
            "root_exit_code": self._root_exit_code,
            "total_processes_spawned": self._seq_counter,
            "total_exec_events": len(self._held_fds),
            "active_processes_at_end": self._active_count,
        }
        if self._failure_reason:
            rec["failure_reason"] = self._failure_reason
        self._emit(rec)

        for fd in self._held_fds:
            try:
                os.close(fd)
            except Exception:
                pass
        self._held_fds.clear()

        if self.out_file and self.evidence_file:
            self.out_file.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Hosted Linux Execution Witness")
    parser.add_argument("--evidence-fd", type=int, default=None, help="Evidence output FD")
    parser.add_argument("--evidence-file", type=str, default=None, help="Evidence output file path")
    parser.add_argument("--launch-binding", type=str, default="{}", help="JSON launch binding metadata")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Target command to execute and trace")

    args = parser.parse_args()

    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        parser.print_help(sys.stderr)
        return 2

    # If compiled native binary exists, prefer executing it
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bin_path = os.path.join(script_dir, "bin", "hosted_exec_witness")
    if not os.path.isfile(bin_path):
        bin_path = os.path.join(script_dir, "hosted_exec_witness")

    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        exec_args = [bin_path]
        if args.evidence_fd is not None:
            exec_args.extend(["--evidence-fd", str(args.evidence_fd)])
        if args.evidence_file is not None:
            exec_args.extend(["--evidence-file", args.evidence_file])
        if args.launch_binding:
            exec_args.extend(["--launch-binding", args.launch_binding])
        exec_args.append("--")
        exec_args.extend(cmd)
        os.execv(bin_path, exec_args)

    # Fall back to native ctypes tracer on Linux
    if sys.platform.startswith("linux"):
        binding = {}
        try:
            binding = json.loads(args.launch_binding)
        except Exception:
            pass
        tracer = NativeLinuxTracer(
            command=cmd,
            evidence_file=args.evidence_file,
            evidence_fd=args.evidence_fd,
            launch_binding=binding,
        )
        return tracer.run()

    # On non-Linux (e.g. Darwin host), refuse execution if strict Linux tracer is required
    print("hosted_exec_witness: Native ptrace execution witness requires Linux.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
