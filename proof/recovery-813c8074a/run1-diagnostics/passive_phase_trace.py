#!/usr/bin/env python3
"""Passive process, output phase tracer, and thread profiler for YAML foldcopy diagnostics.

Observes only descendants of the captured parent shell between foldcopy start
and end markers. Collects:
  - Process snapshots (250 ms until generated executable observed, 1 s thereafter)
  - Output file size and marker samples (every 100 ms)
  - Process attributes: PID, PPID, PGID, start identity, actual executable path
    via Darwin libproc proc_pidpath, CPU/RSS/state, observation times, gaps, errors
  - Native Darwin proc_taskinfo CPU accounting converted via mach_timebase_info
    retaining raw ticks and converted seconds separately, exposing pti_threadnum
    and pti_numrunning
  - Per-thread snapshots using Darwin PROC_PIDLISTTHREADS, PROC_PIDTHREADID64INFO,
    and PROC_PIDTHREADINFO (struct proc_threadinfo) retaining IDs, names, run states,
    and raw user/system counters
  - Upon 10s of verified generated PID identity, revalidates executable and start identity,
    takes per-thread snapshot, runs exactly one /usr/bin/sample bounded independently to 20s,
    takes second per-thread snapshot, and computes thread CPU deltas
  - Preserves generated executable and available companion DWARF with SHA-256 hashes
    before runner cleanup
  - Bounded phase intervals rather than exact times or fabricated thresholds.

Reference: agent://PlanQuietCorpusFailures (Ordered diagnostic plan section 3)
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Sequence

# Fixed observation policies from specification
DEFAULT_PROCESS_SAMPLE_INTERVAL_FAST_SEC = 0.250  # 250 ms until program observed
DEFAULT_PROCESS_SAMPLE_INTERVAL_SLOW_SEC = 1.000  # 1.0 s thereafter
DEFAULT_OUTPUT_SAMPLE_INTERVAL_SEC = 0.100        # 100 ms output file check
DEFAULT_OUTER_TIMEOUT_SEC = 2130                  # 2100s + 30s cleanup grace

# Darwin libproc constants
PROC_PIDPATHINFO_MAXSIZE = 4096
PROC_PIDTASKINFO = 4
PROC_PIDTHREADINFO = 5
PROC_PIDLISTTHREADS = 6
PROC_PIDTHREADID64INFO = 15

# Thread run states from Darwin <sys/proc_info.h>
THREAD_RUN_STATES = {
    1: "TH_STATE_RUNNING",
    2: "TH_STATE_STOPPED",
    3: "TH_STATE_WAITING",
    4: "TH_STATE_UNINTERRUPTIBLE",
    5: "TH_STATE_HALTED",
}

# Runtime output markers in foldcopy.out to timestamp
RUNTIME_MARKERS = [
    ("scalars_and_collections", "== scalars and collections"),
    ("tab_after_block_scalar", "  a tab after a block scalar's indentation is text"),
    ("plain_scalar_dash", "  a plain scalar's next line may start with '- ', as text"),
    ("signal_term_death", "iyi: the program was killed by signal TERM (terminated abnormally)"),
    ("assertion_failed", "ASSERTION FAILED: quoted scalars of 20,000 lines read in under a second"),
    ("generic_assertion_failed", "ASSERTION FAILED:"),
    ("panic", "panic:"),
]


class MachTimebaseInfo(ctypes.Structure):
    """Darwin mach_timebase_info from <mach/mach_time.h>."""
    _fields_ = [
        ("numer", ctypes.c_uint32),
        ("denom", ctypes.c_uint32),
    ]


_TIMEBASE_INFO: MachTimebaseInfo | None = None


def get_mach_timebase_info() -> tuple[int, int]:
    """Query mach_timebase_info from Darwin libc. Returns (numer, denom)."""
    global _TIMEBASE_INFO
    if _TIMEBASE_INFO is None and sys.platform == "darwin":
        try:
            libc = ctypes.CDLL(None)
            tb = MachTimebaseInfo()
            libc.mach_timebase_info.argtypes = [ctypes.POINTER(MachTimebaseInfo)]
            libc.mach_timebase_info.restype = ctypes.c_int
            ret = libc.mach_timebase_info(ctypes.byref(tb))
            if ret == 0 and tb.numer > 0 and tb.denom > 0:
                _TIMEBASE_INFO = tb
        except Exception:
            pass
    if _TIMEBASE_INFO is not None:
        return _TIMEBASE_INFO.numer, _TIMEBASE_INFO.denom
    return 1, 1


class ProcTaskInfo(ctypes.Structure):
    """Darwin proc_taskinfo structure from <sys/proc_info.h>."""
    _fields_ = [
        ("pti_virtual_size", ctypes.c_uint64),
        ("pti_resident_size", ctypes.c_uint64),
        ("pti_total_user", ctypes.c_uint64),       # Mach absolute time ticks on Darwin
        ("pti_total_system", ctypes.c_uint64),     # Mach absolute time ticks on Darwin
        ("pti_threads_user", ctypes.c_uint64),
        ("pti_threads_system", ctypes.c_uint64),
        ("pti_policy", ctypes.c_int32),
        ("pti_faults", ctypes.c_int32),
        ("pti_pageins", ctypes.c_int32),
        ("pti_cow_faults", ctypes.c_int32),
        ("pti_messages_sent", ctypes.c_int32),
        ("pti_messages_received", ctypes.c_int32),
        ("pti_syscalls_mach", ctypes.c_int32),
        ("pti_syscalls_unix", ctypes.c_int32),
        ("pti_csw", ctypes.c_int32),
        ("pti_threadnum", ctypes.c_int32),
        ("pti_numrunning", ctypes.c_int32),
        ("pti_priority", ctypes.c_int32),
    ]


class ProcThreadInfo(ctypes.Structure):
    """Darwin proc_threadinfo structure from <sys/proc_info.h>."""
    _fields_ = [
        ("pth_user_time", ctypes.c_uint64),          # user run time
        ("pth_system_time", ctypes.c_uint64),        # system run time
        ("pth_cpu_usage", ctypes.c_int32),          # scaled cpu usage percentage
        ("pth_policy", ctypes.c_int32),             # scheduling policy in effect
        ("pth_run_state", ctypes.c_int32),          # run state (see TH_STATE_*)
        ("pth_flags", ctypes.c_int32),              # various flags (see TH_FLAGS_*)
        ("pth_sleep_time", ctypes.c_int32),         # number of seconds that thread has slept
        ("pth_curpri", ctypes.c_int32),             # cur priority
        ("pth_priority", ctypes.c_int32),           # priority
        ("pth_maxpriority", ctypes.c_int32),        # max priority
        ("pth_name", ctypes.c_char * 64),           # thread name (MAXTHREADNAMESIZE = 64)
    ]


def sha256_file(path: str | Path) -> str:
    """Compute hex SHA-256 of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


_LIBPROC: ctypes.CDLL | None = None


def get_libproc() -> ctypes.CDLL | None:
    """Load Darwin libproc.dylib via ctypes."""
    global _LIBPROC
    if _LIBPROC is None and sys.platform == "darwin":
        try:
            lib_path = ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib"
            lib = ctypes.CDLL(lib_path, use_errno=True)
            lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            lib.proc_pidpath.restype = ctypes.c_int
            lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            lib.proc_pidinfo.restype = ctypes.c_int
            _LIBPROC = lib
        except Exception:
            _LIBPROC = None
    return _LIBPROC


def query_proc_pidpath(pid: int) -> tuple[str | None, str | None]:
    """Query actual executable path for a PID using Darwin libproc proc_pidpath."""
    if sys.platform != "darwin":
        return None, "Not running on Darwin"
    lib = get_libproc()
    if lib is None:
        return None, "Darwin libproc not available"
    try:
        buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
        ret = lib.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(PROC_PIDPATHINFO_MAXSIZE))
        if ret > 0:
            return buf.value.decode("utf-8", errors="replace"), None
        errno = ctypes.get_errno()
        return None, f"proc_pidpath returned {ret}, errno={errno}"
    except Exception as err:
        return None, str(err)


def query_proc_taskinfo(pid: int) -> tuple[dict[str, Any] | None, str | None]:
    """Query CPU time and memory for a PID using Darwin libproc proc_pidinfo(PROC_PIDTASKINFO).

    Retains raw task CPU ticks and converted seconds separately using mach_timebase_info.
    Exposes pti_threadnum and pti_numrunning.
    """
    if sys.platform != "darwin":
        return None, "Not running on Darwin"
    lib = get_libproc()
    if lib is None:
        return None, "Darwin libproc not available"
    try:
        info = ProcTaskInfo()
        ret = lib.proc_pidinfo(
            ctypes.c_int(pid),
            ctypes.c_int(PROC_PIDTASKINFO),
            ctypes.c_uint64(0),
            ctypes.byref(info),
            ctypes.c_int(ctypes.sizeof(info)),
        )
        if ret == ctypes.sizeof(info):
            numer, denom = get_mach_timebase_info()
            tb_ratio = numer / denom if denom else 1.0
            user_sec = (info.pti_total_user * tb_ratio) / 1e9
            system_sec = (info.pti_total_system * tb_ratio) / 1e9
            total_sec = ((info.pti_total_user + info.pti_total_system) * tb_ratio) / 1e9
            return {
                "raw_user_ticks": int(info.pti_total_user),
                "raw_system_ticks": int(info.pti_total_system),
                "raw_total_ticks": int(info.pti_total_user + info.pti_total_system),
                "mach_timebase_numer": numer,
                "mach_timebase_denom": denom,
                "mach_timebase_ratio": tb_ratio,
                "user_cpu_sec": user_sec,
                "system_cpu_sec": system_sec,
                "total_cpu_sec": total_sec,
                "rss_bytes": int(info.pti_resident_size),
                "virtual_bytes": int(info.pti_virtual_size),
                "faults": int(info.pti_faults),
                "pageins": int(info.pti_pageins),
                "cow_faults": int(info.pti_cow_faults),
                "pti_threadnum": int(info.pti_threadnum),
                "pti_numrunning": int(info.pti_numrunning),
                "pti_csw": int(info.pti_csw),
                "pti_syscalls_mach": int(info.pti_syscalls_mach),
                "pti_syscalls_unix": int(info.pti_syscalls_unix),
            }, None
        errno = ctypes.get_errno()
        return None, f"proc_pidinfo returned {ret}, errno={errno}"
    except Exception as err:
        return None, str(err)


def query_proc_threads(pid: int) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Query active threads for a PID using Darwin PROC_PIDLISTTHREADS and proc_threadinfo.

    Retains thread IDs, names, run states, and raw user/system counters without claiming
    units unless verified.
    """
    if sys.platform != "darwin":
        return None, "Not running on Darwin"
    lib = get_libproc()
    if lib is None:
        return None, "Darwin libproc not available"

    try:
        capacity = 64
        buf = None
        ret = 0
        while capacity <= 4096:
            buf = (ctypes.c_uint64 * capacity)()
            ret = lib.proc_pidinfo(
                ctypes.c_int(pid),
                ctypes.c_int(PROC_PIDLISTTHREADS),
                ctypes.c_uint64(0),
                buf,
                ctypes.c_int(ctypes.sizeof(buf)),
            )
            if ret <= 0:
                errno = ctypes.get_errno()
                return None, f"proc_pidinfo(PROC_PIDLISTTHREADS) returned {ret}, errno={errno}"
            if ret < ctypes.sizeof(buf):
                break
            capacity *= 2

        entry_size = ctypes.sizeof(ctypes.c_uint64)
        thread_count = ret // entry_size
        threads_info: list[dict[str, Any]] = []

        for i in range(thread_count):
            tid_entry = buf[i]
            tinfo = ProcThreadInfo()
            # Try PROC_PIDTHREADINFO (flavor 5)
            tret = lib.proc_pidinfo(
                ctypes.c_int(pid),
                ctypes.c_int(PROC_PIDTHREADINFO),
                ctypes.c_uint64(tid_entry),
                ctypes.byref(tinfo),
                ctypes.c_int(ctypes.sizeof(tinfo)),
            )
            flavor_used = "PROC_PIDTHREADINFO"
            if tret != ctypes.sizeof(tinfo):
                # Fallback to PROC_PIDTHREADID64INFO (flavor 15)
                tret = lib.proc_pidinfo(
                    ctypes.c_int(pid),
                    ctypes.c_int(PROC_PIDTHREADID64INFO),
                    ctypes.c_uint64(tid_entry),
                    ctypes.byref(tinfo),
                    ctypes.c_int(ctypes.sizeof(tinfo)),
                )
                flavor_used = "PROC_PIDTHREADID64INFO"

            if tret == ctypes.sizeof(tinfo):
                raw_name = bytes(tinfo.pth_name).split(b"\x00", 1)[0]
                name_str = raw_name.decode("utf-8", errors="replace")
                state_str = THREAD_RUN_STATES.get(tinfo.pth_run_state, f"UNKNOWN({tinfo.pth_run_state})")
                threads_info.append({
                    "thread_id": int(tid_entry),
                    "flavor_used": flavor_used,
                    "thread_name": name_str,
                    "run_state_code": int(tinfo.pth_run_state),
                    "run_state": state_str,
                    "flags": int(tinfo.pth_flags),
                    "raw_user_counter": int(tinfo.pth_user_time),
                    "raw_system_counter": int(tinfo.pth_system_time),
                    "raw_total_counter": int(tinfo.pth_user_time + tinfo.pth_system_time),
                    "cpu_usage": int(tinfo.pth_cpu_usage),
                    "policy": int(tinfo.pth_policy),
                    "curpri": int(tinfo.pth_curpri),
                    "priority": int(tinfo.pth_priority),
                    "maxpriority": int(tinfo.pth_maxpriority),
                    "sleep_time_sec": int(tinfo.pth_sleep_time),
                })
            else:
                errno = ctypes.get_errno()
                threads_info.append({
                    "thread_id": int(tid_entry),
                    "query_error": f"proc_pidinfo returned {tret}, errno={errno}",
                })

        return threads_info, None
    except Exception as err:
        return None, str(err)


def validate_proc_pidpath() -> dict[str, Any]:
    """Validate Darwin proc_pidpath lookup on an owned short-lived child.

    Spawns an owned short-lived child process (sys.executable), looks up its
    executable path using Darwin libproc proc_pidpath, verifies path matches,
    and terminates the owned child cleanly.
    """
    if sys.platform != "darwin":
        return {
            "platform": sys.platform,
            "status": "SKIPPED_NON_DARWIN",
            "message": "proc_pidpath is specific to Darwin / macOS",
            "paths_match": False,
        }

    # Spawn an owned short-lived child process
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = child.pid

    try:
        path, err = query_proc_pidpath(child_pid)
        expected_executable = str(Path(sys.executable).resolve())
        actual_path = str(Path(path).resolve()) if path else None

        matches = False
        if actual_path:
            try:
                matches = os.path.samefile(actual_path, expected_executable)
            except OSError:
                matches = (actual_path == expected_executable)
            if not matches:
                expected_prefix = str(Path(expected_executable).parent.parent)
                if (expected_prefix in actual_path) and Path(actual_path).name.lower().startswith("python"):
                    matches = True
        taskinfo, _ = query_proc_taskinfo(child_pid)

        return {
            "status": "VALIDATED" if matches else "MISMATCH",
            "child_pid": child_pid,
            "query_error": err,
            "expected_executable": expected_executable,
            "actual_pidpath": actual_path,
            "paths_match": matches,
            "taskinfo_available": taskinfo is not None,
            "platform": sys.platform,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
    finally:
        try:
            child.terminate()
            child.wait(timeout=2)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            try:
                child.kill()
                child.wait(timeout=2)
            except Exception:
                pass


def validate_accounting() -> dict[str, Any]:
    """Validate Darwin proc_pidpath, mach_timebase_info, proc_taskinfo, and thread snapshots
    on an owned short-lived multi-threaded child process.

    Spawns an owned child process (sys.executable) with a background worker thread,
    verifies:
      1. mach_timebase_info queried and non-zero (numer, denom)
      2. proc_pidpath matches expected sys.executable
      3. proc_taskinfo returns raw ticks, converted seconds, pti_threadnum >= 2, pti_numrunning
      4. PROC_PIDLISTTHREADS lists threads
      5. struct proc_threadinfo snapshots retain IDs, names, run states, raw counters
    Terminates child cleanly. Must not invoke compiler or benchmark.
    """
    if sys.platform != "darwin":
        return {
            "platform": sys.platform,
            "status": "SKIPPED_NON_DARWIN",
            "message": "Accounting validation is specific to Darwin / macOS",
            "overall_verified": False,
        }

    child_code = (
        "import threading, time\n"
        "def worker():\n"
        "    t_end = time.perf_counter() + 0.1\n"
        "    while time.perf_counter() < t_end: pass\n"
        "    time.sleep(5)\n"
        "t = threading.Thread(target=worker, name='test_worker_diag')\n"
        "t.start()\n"
        "time.sleep(5)\n"
        "t.join()\n"
    )

    child = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = child.pid

    try:
        # Give thread time to spawn and begin execution
        time.sleep(0.05)

        # 1. Mach timebase
        numer, denom = get_mach_timebase_info()
        tb_verified = (numer > 0 and denom > 0)

        # 2. proc_pidpath
        path, path_err = query_proc_pidpath(child_pid)
        expected_executable = str(Path(sys.executable).resolve())
        actual_path = str(Path(path).resolve()) if path else None
        paths_match = False
        if actual_path:
            try:
                paths_match = os.path.samefile(actual_path, expected_executable)
            except OSError:
                paths_match = (actual_path == expected_executable)
            if not paths_match:
                # Handle macOS framework Python where bin/ stub executes Python.app binary
                expected_prefix = str(Path(expected_executable).parent.parent)
                if (expected_prefix in actual_path) and Path(actual_path).name.lower().startswith("python"):
                    paths_match = True

        # 3. proc_taskinfo
        taskinfo, taskinfo_err = query_proc_taskinfo(child_pid)
        taskinfo_verified = False
        if taskinfo:
            taskinfo_verified = (
                taskinfo.get("raw_total_ticks", -1) >= 0
                and taskinfo.get("total_cpu_sec", -1.0) >= 0.0
                and taskinfo.get("pti_threadnum", 0) >= 1
                and "pti_numrunning" in taskinfo
                and taskinfo.get("mach_timebase_numer") == numer
                and taskinfo.get("mach_timebase_denom") == denom
            )

        # 4. Thread snapshots via PROC_PIDLISTTHREADS / proc_threadinfo
        threads, threads_err = query_proc_threads(child_pid)
        threads_verified = False
        found_named_worker = False
        if threads and len(threads) >= 1:
            threads_verified = True
            for th in threads:
                if th.get("thread_name") == "test_worker_diag":
                    found_named_worker = True

        all_ok = (
            tb_verified
            and paths_match
            and taskinfo_verified
            and threads_verified
        )

        return {
            "status": "VALIDATED" if all_ok else "VERIFICATION_FAILED",
            "child_pid": child_pid,
            "platform": sys.platform,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "mach_timebase": {
                "numer": numer,
                "denom": denom,
                "ratio": numer / denom if denom else 1.0,
                "verified": tb_verified,
            },
            "proc_pidpath": {
                "expected": expected_executable,
                "actual": actual_path,
                "error": path_err,
                "matches": paths_match,
            },
            "proc_taskinfo": {
                "taskinfo": taskinfo,
                "error": taskinfo_err,
                "verified": taskinfo_verified,
            },
            "proc_threads": {
                "thread_count": len(threads) if threads else 0,
                "threads": threads,
                "found_named_worker": found_named_worker,
                "error": threads_err,
                "verified": threads_verified,
            },
            "overall_verified": all_ok,
        }
    finally:
        try:
            child.terminate()
            child.wait(timeout=2)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            try:
                child.kill()
                child.wait(timeout=2)
            except Exception:
                pass


def parse_ps_time(time_str: str) -> float:
    """Parse ps cumulative CPU time string into seconds."""
    try:
        days = 0.0
        if "-" in time_str:
            d_part, time_str = time_str.split("-", 1)
            days = float(d_part)
        parts = time_str.split(":")
        if len(parts) == 3:
            h, m, s = float(parts[0]), float(parts[1]), float(parts[2])
            return days * 86400.0 + h * 3600.0 + m * 60.0 + s
        elif len(parts) == 2:
            m, s = float(parts[0]), float(parts[1])
            return days * 86400.0 + m * 60.0 + s
        else:
            return float(parts[0])
    except Exception:
        return 0.0


def read_ps_table() -> tuple[dict[int, dict[str, Any]], str | None]:
    """Read the current system process table via ps."""
    try:
        proc = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,pgid=,state=,time=,rss=,lstart="],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return {}, f"ps failed with rc {proc.returncode}: {proc.stderr.strip()}"

        table: dict[int, dict[str, Any]] = {}
        for line in proc.stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            parts = line_str.split(None, 6)
            if len(parts) < 7:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                pgid = int(parts[2])
                state = parts[3]
                time_str = parts[4]
                rss_kb = int(parts[5])
                lstart = parts[6]
                table[pid] = {
                    "pid": pid,
                    "ppid": ppid,
                    "pgid": pgid,
                    "state": state,
                    "cputime_str": time_str,
                    "cputime_sec": parse_ps_time(time_str),
                    "rss_kb": rss_kb,
                    "lstart": lstart,
                }
            except (ValueError, IndexError):
                continue
        return table, None
    except Exception as err:
        return {}, str(err)


def find_descendant_pids(parent_pid: int, all_procs: dict[int, dict[str, Any]]) -> list[int]:
    """Find all descendant PIDs of parent_pid in process table."""
    children_map: dict[int, list[int]] = {}
    for pid, proc in all_procs.items():
        ppid = proc.get("ppid")
        if ppid is not None:
            children_map.setdefault(ppid, []).append(pid)

    descendants: list[int] = []
    queue = list(children_map.get(parent_pid, []))
    visited = set(queue)
    while queue:
        curr = queue.pop(0)
        descendants.append(curr)
        for child in children_map.get(curr, []):
            if child not in visited:
                visited.add(child)
                queue.append(child)
    return descendants


def classify_descendant(
    proc_entry: dict[str, Any],
    parent_bash_pid: int,
    known_roles: dict[int, str],
    compiler_path: str | None = None,
) -> str:
    """Classify descendant process role strictly based on executable path and parentage.

    Distinguishes:
      1. inner_timeout: direct child of parent bash, executable is timeout/gtimeout
      2. compiler: child of inner_timeout (or parent bash), executable matches compiler path
      3. generated_executable: child of compiler, actual executable path matches
         iyi-run-std_yaml_exercise-<compiler-pid>.tmp (src/compiler/iyi/util.cr:301-303,331-332)
      4. compiler_helper: child/descendant of compiler, but NOT generated_executable (cc, clang, ld)
      5. other_descendant: any other verified descendant of parent bash
    """
    pid = proc_entry["pid"]
    ppid = proc_entry["ppid"]
    exe_path = proc_entry.get("actual_executable_path")
    exe_name = Path(exe_path).name if exe_path else ""

    # 1. Inner timeout
    if ppid == parent_bash_pid and exe_name in ("timeout", "gtimeout"):
        return "inner_timeout"

    # 2. Compiler process
    timeout_pid = next((p for p, r in known_roles.items() if r == "inner_timeout"), None)
    is_compiler_parent = (ppid == timeout_pid) if timeout_pid else (ppid == parent_bash_pid)

    if is_compiler_parent:
        if compiler_path and exe_path:
            try:
                if os.path.samefile(exe_path, compiler_path):
                    return "compiler"
            except OSError:
                if exe_path == compiler_path:
                    return "compiler"
        if exe_name == "iyi" or exe_name.startswith("iyi-"):
            if not (exe_name.startswith("iyi-run-std_yaml_exercise-") and exe_name.endswith(".tmp")):
                return "compiler"

    # 3. Generated executable: child of compiler, actual executable path matches
    compiler_pid = next((p for p, r in known_roles.items() if r == "compiler"), None)
    if exe_name.startswith("iyi-run-std_yaml_exercise-") and exe_name.endswith(".tmp"):
        if compiler_pid is None or ppid == compiler_pid:
            return "generated_executable"

    # 4. Compiler helpers: child or descendant of compiler, but NOT generated executable
    if compiler_pid and (ppid == compiler_pid or known_roles.get(ppid) in ("compiler", "compiler_helper")):
        return "compiler_helper"

    return "other_descendant"


def check_output_file(
    output_path: Path,
    start_mono_ns: int,
    observed_markers: dict[str, dict[str, Any]],
    last_size: int,
) -> tuple[int, dict[str, Any] | None, list[dict[str, Any]]]:
    """Check output file size and search for unobserved runtime markers."""
    if not output_path.is_file():
        return 0, None, []

    try:
        st = output_path.stat()
        current_size = st.st_size
    except OSError:
        return last_size, None, []

    first_output_sample = None
    new_marker_events = []

    if current_size > 0:
        try:
            with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            content = ""

        now_mono_ns = time.monotonic_ns()
        now_wall_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        elapsed_sec = (now_mono_ns - start_mono_ns) / 1e9

        if last_size == 0 and current_size > 0:
            first_line = content.splitlines()[0] if content.splitlines() else ""
            first_output_sample = {
                "observed_at_mono_ns": now_mono_ns,
                "observed_at_wall_iso": now_wall_iso,
                "elapsed_sec": elapsed_sec,
                "file_size_bytes": current_size,
                "first_line": first_line,
            }

        for marker_id, marker_str in RUNTIME_MARKERS:
            if marker_id not in observed_markers and marker_str in content:
                event = {
                    "marker_id": marker_id,
                    "marker_text": marker_str,
                    "observed_at_mono_ns": now_mono_ns,
                    "observed_at_wall_iso": now_wall_iso,
                    "elapsed_sec": elapsed_sec,
                    "file_size_bytes": current_size,
                }
                observed_markers[marker_id] = event
                new_marker_events.append(event)

    return current_size, first_output_sample, new_marker_events


class PassivePhaseTracer:
    """Manages passive observation of foldcopy descendant processes, output markers,
    per-thread snapshots, and bounded thread sampling."""

    def __init__(
        self,
        capture_dir: Path,
        parent_pid: int | None = None,
        outer_timeout_sec: int = DEFAULT_OUTER_TIMEOUT_SEC,
    ) -> None:
        self.capture_dir = capture_dir.resolve()
        self.preconfigured_parent_pid = parent_pid
        self.outer_timeout_sec = outer_timeout_sec

        self.start_marker_path = self.capture_dir / "foldcopy_start_marker.json"
        self.end_marker_path = self.capture_dir / "foldcopy_end_marker.json"
        self.trace_output_path = self.capture_dir / "foldcopy_phase_trace.json"
        self.summary_output_path = self.capture_dir / "foldcopy_phase_summary.json"

        # Observation state
        self.parent_bash_pid: int | None = None
        self.output_path: Path | None = None
        self.compiler_path: str | None = None
        self.cache_path: str | None = None
        self.foldcopy_start_mono_ns: int = 0
        self.foldcopy_start_time_ns: int = 0
        self.foldcopy_start_marker: dict[str, Any] = {}

        self.process_snapshots: list[dict[str, Any]] = []
        self.output_samples: list[dict[str, Any]] = []
        self.observed_markers: dict[str, dict[str, Any]] = {}
        self.first_runtime_output: dict[str, Any] | None = None

        self.known_roles: dict[int, str] = {}
        self.last_snap_without_prog: dict[str, Any] | None = None
        self.first_snap_with_prog: dict[str, Any] | None = None
        self.generated_executable_observed: bool = False
        self.generated_pid: int | None = None
        self.generated_observed_first_mono_ns: int | None = None
        self.generated_lstart: str | None = None
        self.generated_executable_path: str | None = None

        # Artifact preservation & profile window state
        self.preserved_artifacts: dict[str, Any] = {}
        self.profile_window_executed: bool = False
        self.profile_window_result: dict[str, Any] | None = None

        self.errors: list[str] = []
        self.max_sampling_gap_sec: float = 0.0

    def wait_for_start_marker(self, poll_interval_sec: float = 0.050) -> bool:
        """Wait for foldcopy start marker to appear in capture directory.

        Observer remains dormant and collects nothing before this marker.
        """
        start_wait_mono = time.monotonic()
        while True:
            if self.start_marker_path.is_file():
                try:
                    data = json.loads(self.start_marker_path.read_text(encoding="utf-8"))
                    self.parent_bash_pid = int(data["parent_bash_pid"])
                    self.output_path = Path(data["output_path"]).resolve()
                    self.compiler_path = data.get("compiler_path")
                    self.cache_path = data.get("cache_path")
                    self.foldcopy_start_mono_ns = int(data.get("monotonic_ns", time.monotonic_ns()))
                    self.foldcopy_start_time_ns = int(data.get("time_ns", time.time_ns()))
                    self.foldcopy_start_marker = data
                    return True
                except (json.JSONDecodeError, KeyError, ValueError) as err:
                    time.sleep(0.02)
                    continue

            # Check timeout
            if (time.monotonic() - start_wait_mono) > self.outer_timeout_sec:
                self.errors.append("Timed out waiting for foldcopy_start_marker.json")
                return False

            time.sleep(poll_interval_sec)

    def _preserve_generated_executable(self, pid: int, exe_path: str) -> dict[str, Any]:
        """Preserve generated executable and available matching DWARF before runner cleanup.

        Computes and records SHA-256 hashes for all preserved artifacts.
        Only writes inside self.capture_dir (owned report directory).
        """
        p_exe = Path(exe_path)
        if not p_exe.is_file():
            record = {
                "status": "SOURCE_NOT_FOUND",
                "source_path": exe_path,
                "pid": pid,
                "error": "Source executable path does not exist",
            }
            self.preserved_artifacts = record
            return record

        t0 = time.monotonic()
        artifacts_dir = self.capture_dir / "preserved_artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        dest_exe = artifacts_dir / p_exe.name
        try:
            shutil.copy2(p_exe, dest_exe)
            exe_sha256 = sha256_file(dest_exe)
            exe_size = dest_exe.stat().st_size
        except Exception as err:
            record = {
                "status": "COPY_FAILED",
                "source_path": exe_path,
                "pid": pid,
                "error": str(err),
            }
            self.preserved_artifacts = record
            return record

        dwarf_record = None
        # Check for flat .dwarf file
        flat_dwarf = Path(f"{exe_path}.dwarf")
        if flat_dwarf.is_file():
            dest_dwarf = artifacts_dir / f"{p_exe.name}.dwarf"
            try:
                shutil.copy2(flat_dwarf, dest_dwarf)
                dwarf_record = {
                    "type": "flat_dwarf",
                    "source_path": str(flat_dwarf),
                    "dest_path": str(dest_dwarf),
                    "sha256": sha256_file(dest_dwarf),
                    "size_bytes": dest_dwarf.stat().st_size,
                }
            except Exception as err:
                dwarf_record = {"type": "flat_dwarf", "error": str(err)}

        # Check for .dSYM bundle directory
        dsym_dir = Path(f"{exe_path}.dSYM")
        if dsym_dir.is_dir() and dwarf_record is None:
            dest_dsym = artifacts_dir / f"{p_exe.name}.dSYM"
            try:
                if dest_dsym.exists():
                    shutil.rmtree(dest_dsym)
                shutil.copytree(dsym_dir, dest_dsym)
                inner_bin = dest_dsym / "Contents" / "Resources" / "DWARF" / p_exe.name
                dwarf_sha256 = sha256_file(inner_bin) if inner_bin.is_file() else None
                dwarf_record = {
                    "type": "dsym_bundle",
                    "source_path": str(dsym_dir),
                    "dest_path": str(dest_dsym),
                    "inner_dwarf_sha256": dwarf_sha256,
                }
            except Exception as err:
                dwarf_record = {"type": "dsym_bundle", "error": str(err)}

        t_duration = time.monotonic() - t0
        record = {
            "status": "PRESERVED",
            "pid": pid,
            "source_executable": exe_path,
            "preserved_executable": str(dest_exe),
            "executable_sha256": exe_sha256,
            "executable_size_bytes": exe_size,
            "dwarf": dwarf_record,
            "preservation_duration_sec": t_duration,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.preserved_artifacts = record
        return record

    def _revalidate_generated_process(self) -> tuple[bool, str, dict[str, Any]]:
        """Revalidate PID/start identity and executable path of generated process."""
        if not self.generated_pid:
            return False, "No generated PID recorded", {}

        pid = self.generated_pid
        current_path, path_err = query_proc_pidpath(pid)
        if path_err or not current_path:
            return False, f"proc_pidpath failed: {path_err}", {}

        if self.generated_executable_path and current_path != self.generated_executable_path:
            return False, f"Executable path changed from {self.generated_executable_path} to {current_path}", {}

        exe_name = Path(current_path).name
        if not (exe_name.startswith("iyi-run-std_yaml_exercise-") and exe_name.endswith(".tmp")):
            return False, f"Executable name {exe_name} does not match generated pattern", {}

        all_procs, ps_err = read_ps_table()
        if pid not in all_procs:
            return False, f"PID {pid} no longer in process table", {}

        proc_info = all_procs[pid]
        if self.generated_lstart and proc_info.get("lstart") != self.generated_lstart:
            return False, f"PID start identity changed: expected {self.generated_lstart}, got {proc_info.get('lstart')}", {}

        descendants = find_descendant_pids(self.parent_bash_pid, all_procs)
        if pid not in descendants:
            return False, f"PID {pid} is no longer a descendant of parent bash {self.parent_bash_pid}", {}

        return True, "Identity verified", {
            "pid": pid,
            "executable_path": current_path,
            "lstart": proc_info.get("lstart"),
            "ppid": proc_info.get("ppid"),
            "pgid": proc_info.get("pgid"),
        }

    def _execute_profile_window(self) -> dict[str, Any]:
        """Execute bounded profile window upon 10 seconds of verified generated PID identity.

        Steps:
          1. Revalidate PID/start identity and executable path.
          2. Per-thread CPU/state snapshot BEFORE sample.
          3. Run exactly one /usr/bin/sample <verified-pid> 1 10 -mayDie -file <capture_dir>/generated-all-threads.sample.txt
             independently bound to 20s.
          4. Per-thread CPU/state snapshot AFTER sample.
          5. Compute thread and taskinfo deltas and record perturbation.
        """
        if self.profile_window_executed:
            return self.profile_window_result or {}

        valid, reason, id_info = self._revalidate_generated_process()
        if not valid:
            result = {
                "status": "REVALIDATION_FAILED",
                "reason": reason,
                "profile_executed": False,
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.profile_window_executed = True
            self.profile_window_result = result
            return result

        pid = self.generated_pid
        sample_file = self.capture_dir / "generated-all-threads.sample.txt"

        # Step 3: Per-thread CPU/state snapshot BEFORE sample
        t_before_mono_ns = time.monotonic_ns()
        threads_before, threads_err_before = query_proc_threads(pid)
        taskinfo_before, taskinfo_err_before = query_proc_taskinfo(pid)
        snap_before = {
            "timestamp_mono_ns": t_before_mono_ns,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "taskinfo": taskinfo_before,
            "taskinfo_error": taskinfo_err_before,
            "threads": threads_before,
            "threads_error": threads_err_before,
        }

        # Step 4: Run exactly one /usr/bin/sample independently bounded
        sample_cmd = [
            "/usr/bin/sample",
            str(pid),
            "1",
            "10",
            "-mayDie",
            "-file",
            str(sample_file),
        ]

        t_sample_start_mono = time.monotonic()
        t_sample_start_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sampler_rc = None
        sampler_stdout = ""
        sampler_stderr = ""
        sampler_timed_out = False

        try:
            res = subprocess.run(
                sample_cmd,
                capture_output=True,
                text=True,
                timeout=20,  # Independently bound so cannot extend foreground timeout
                check=False,
            )
            sampler_rc = res.returncode
            sampler_stdout = res.stdout
            sampler_stderr = res.stderr
        except subprocess.TimeoutExpired as exc:
            sampler_timed_out = True
            sampler_rc = -1
            sampler_stderr = f"Sampler timed out after 20 seconds: {exc}"
        except Exception as exc:
            sampler_rc = -1
            sampler_stderr = f"Sampler execution exception: {exc}"

        t_sample_end_mono = time.monotonic()
        sample_duration_sec = t_sample_end_mono - t_sample_start_mono

        # Step 5: Per-thread CPU/state snapshot AFTER sample
        t_after_mono_ns = time.monotonic_ns()
        threads_after, threads_err_after = query_proc_threads(pid)
        taskinfo_after, taskinfo_err_after = query_proc_taskinfo(pid)
        snap_after = {
            "timestamp_mono_ns": t_after_mono_ns,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "taskinfo": taskinfo_after,
            "taskinfo_error": taskinfo_err_after,
            "threads": threads_after,
            "threads_error": threads_err_after,
        }

        # Compute per-thread deltas
        thread_deltas: list[dict[str, Any]] = []
        before_by_id = {th["thread_id"]: th for th in (threads_before or []) if "thread_id" in th}
        after_by_id = {th["thread_id"]: th for th in (threads_after or []) if "thread_id" in th}
        all_tids = sorted(set(before_by_id.keys()) | set(after_by_id.keys()))

        for tid in all_tids:
            b = before_by_id.get(tid)
            a = after_by_id.get(tid)
            name = (a.get("thread_name") if a else None) or (b.get("thread_name") if b else "")
            delta_entry: dict[str, Any] = {
                "thread_id": tid,
                "thread_name": name,
                "run_state_before": b.get("run_state") if b else None,
                "run_state_after": a.get("run_state") if a else None,
            }
            if b and a and "raw_user_counter" in b and "raw_user_counter" in a:
                delta_user = a["raw_user_counter"] - b["raw_user_counter"]
                delta_sys = a["raw_system_counter"] - b["raw_system_counter"]
                delta_entry["delta_raw_user_counter"] = delta_user
                delta_entry["delta_raw_system_counter"] = delta_sys
                delta_entry["delta_raw_total_counter"] = delta_user + delta_sys
            thread_deltas.append(delta_entry)

        # Compute taskinfo deltas
        taskinfo_delta: dict[str, Any] = {}
        if taskinfo_before and taskinfo_after:
            taskinfo_delta = {
                "delta_raw_user_ticks": taskinfo_after["raw_user_ticks"] - taskinfo_before["raw_user_ticks"],
                "delta_raw_system_ticks": taskinfo_after["raw_system_ticks"] - taskinfo_before["raw_system_ticks"],
                "delta_raw_total_ticks": taskinfo_after["raw_total_ticks"] - taskinfo_before["raw_total_ticks"],
                "delta_user_cpu_sec": taskinfo_after["user_cpu_sec"] - taskinfo_before["user_cpu_sec"],
                "delta_system_cpu_sec": taskinfo_after["system_cpu_sec"] - taskinfo_before["system_cpu_sec"],
                "delta_total_cpu_sec": taskinfo_after["total_cpu_sec"] - taskinfo_before["total_cpu_sec"],
            }

        sample_exists = sample_file.is_file()
        sample_size = sample_file.stat().st_size if sample_exists else 0
        sample_sha256 = sha256_file(sample_file) if sample_exists else None

        result = {
            "status": "COMPLETED" if (sampler_rc == 0 and sample_exists) else "SAMPLER_FAILED",
            "profile_executed": True,
            "target_pid": pid,
            "target_identity": id_info,
            "sampler_invocation": {
                "command": sample_cmd,
                "returncode": sampler_rc,
                "timed_out": sampler_timed_out,
                "timeout_bound_sec": 20,
                "duration_sec": sample_duration_sec,
                "started_utc": t_sample_start_utc,
                "sample_file_path": str(sample_file),
                "sample_file_exists": sample_exists,
                "sample_file_bytes": sample_size,
                "sample_file_sha256": sample_sha256,
                "stdout_preview": sampler_stdout[:500] if sampler_stdout else "",
                "stderr_preview": sampler_stderr[:500] if sampler_stderr else "",
            },
            "diagnostic_perturbation": (
                "The installed /usr/share/man/man1/sample.1 documents that this captures all "
                "thread stacks and briefly suspends the process at sampling intervals. "
                "It is a diagnostic perturbation, not zero-overhead timing proof."
            ),
            "snapshot_before": snap_before,
            "snapshot_after": snap_after,
            "thread_deltas": thread_deltas,
            "taskinfo_delta": taskinfo_delta,
        }

        self.profile_window_executed = True
        self.profile_window_result = result
        return result

    def run_observation(self) -> dict[str, Any]:
        """Execute the active observation loop between start and end markers."""
        if not self.parent_bash_pid or not self.output_path:
            raise RuntimeError("Observer must activate only after start marker is read.")

        loop_start_mono = time.monotonic()
        next_process_time = time.monotonic()
        next_output_time = time.monotonic()
        last_process_end_mono: float | None = None
        last_output_size = 0
        sample_index = 0

        # Active observation loop
        while True:
            now_mono = time.monotonic()

            # 1. Output file observation (every 100 ms)
            if now_mono >= next_output_time:
                last_output_size, first_out, new_markers = check_output_file(
                    output_path=self.output_path,
                    start_mono_ns=self.foldcopy_start_mono_ns,
                    observed_markers=self.observed_markers,
                    last_size=last_output_size,
                )
                if first_out and not self.first_runtime_output:
                    self.first_runtime_output = first_out

                self.output_samples.append({
                    "sample_mono_ns": time.monotonic_ns(),
                    "elapsed_sec": (time.monotonic_ns() - self.foldcopy_start_mono_ns) / 1e9,
                    "file_size_bytes": last_output_size,
                    "new_markers": [m["marker_id"] for m in new_markers],
                })
                next_output_time = now_mono + DEFAULT_OUTPUT_SAMPLE_INTERVAL_SEC

            # 2. Process snapshot observation (250 ms fast / 1.0 s slow)
            if now_mono >= next_process_time:
                snap_start_mono = time.monotonic()
                snap_start_ns = time.monotonic_ns()

                gap_sec = (snap_start_mono - last_process_end_mono) if last_process_end_mono else 0.0
                if gap_sec > self.max_sampling_gap_sec:
                    self.max_sampling_gap_sec = gap_sec

                snapshot = self._take_process_snapshot(
                    sample_index=sample_index,
                    snap_start_ns=snap_start_ns,
                    gap_sec=gap_sec,
                )
                snap_end_mono = time.monotonic()
                snapshot["duration_sec"] = snap_end_mono - snap_start_mono
                last_process_end_mono = snap_end_mono

                self.process_snapshots.append(snapshot)
                sample_index += 1

                # Cadence policy: 250 ms until generated executable observed, 1 s thereafter
                interval = (
                    DEFAULT_PROCESS_SAMPLE_INTERVAL_SLOW_SEC
                    if self.generated_executable_observed
                    else DEFAULT_PROCESS_SAMPLE_INTERVAL_FAST_SEC
                )
                next_process_time = snap_end_mono + interval

            # 3. Check profile window trigger (after 10s of verified observation of generated process)
            if (
                self.generated_executable_observed
                and not self.profile_window_executed
                and self.generated_observed_first_mono_ns is not None
            ):
                observed_sec = (time.monotonic_ns() - self.generated_observed_first_mono_ns) / 1e9
                if observed_sec >= 10.0:
                    self._execute_profile_window()

            # 4. Check for end marker
            if self.end_marker_path.is_file():
                break

            # 5. Check if parent bash PID is still alive
            try:
                os.kill(self.parent_bash_pid, 0)
            except ProcessLookupError:
                self.errors.append("Parent bash PID terminated before foldcopy_end_marker.json was written")
                break
            except PermissionError:
                pass

            # 6. Check outer safety timeout
            if (now_mono - loop_start_mono) > self.outer_timeout_sec:
                self.errors.append("Observer reached outer safety timeout ceiling")
                break

            # Bounded sleep until next due event
            soonest_next = min(next_output_time, next_process_time)
            sleep_sec = max(0.005, soonest_next - time.monotonic())
            time.sleep(min(sleep_sec, 0.050))

        # Final flush snapshot and output check
        self._take_final_snapshot(sample_index, last_output_size)

        # Build and write final structured traces
        return self._compile_and_write_results()

    def _take_process_snapshot(
        self,
        sample_index: int,
        snap_start_ns: int,
        gap_sec: float,
    ) -> dict[str, Any]:
        """Take a single process table snapshot of descendants."""
        all_procs, ps_err = read_ps_table()
        if ps_err:
            self.errors.append(ps_err)

        descendant_pids = find_descendant_pids(self.parent_bash_pid, all_procs)
        descendants_records: list[dict[str, Any]] = []

        has_generated_prog = False
        current_generated_pid: int | None = None
        current_compiler_pid: int | None = None
        current_timeout_pid: int | None = None

        for d_pid in descendant_pids:
            proc_raw = all_procs.get(d_pid, {
                "pid": d_pid, "ppid": 0, "pgid": 0, "state": "unknown",
                "cputime_str": "0:00", "cputime_sec": 0.0, "rss_kb": 0, "lstart": ""
            })

            # Darwin libproc actual executable path
            exe_path, pidpath_err = query_proc_pidpath(d_pid)
            if pidpath_err:
                self.errors.append(f"PID {d_pid}: {pidpath_err}")

            # Darwin libproc taskinfo
            taskinfo, _ = query_proc_taskinfo(d_pid)

            record = {
                "pid": d_pid,
                "ppid": proc_raw.get("ppid"),
                "pgid": proc_raw.get("pgid"),
                "state": proc_raw.get("state"),
                "lstart": proc_raw.get("lstart"),
                "actual_executable_path": exe_path,
                "pidpath_error": pidpath_err,
                "ps_cputime_sec": proc_raw.get("cputime_sec", 0.0),
                "ps_rss_kb": proc_raw.get("rss_kb", 0),
                "kernel_taskinfo": taskinfo,
            }

            # Classify role
            role = classify_descendant(
                proc_entry=record,
                parent_bash_pid=self.parent_bash_pid,
                known_roles=self.known_roles,
                compiler_path=self.compiler_path,
            )
            record["role"] = role
            self.known_roles[d_pid] = role

            if role == "generated_executable":
                has_generated_prog = True
                current_generated_pid = d_pid
                # Capture thread snapshot for generated executable
                threads_list, threads_err = query_proc_threads(d_pid)
                record["threads"] = threads_list
                if threads_err:
                    record["threads_error"] = threads_err
            elif role == "compiler":
                current_compiler_pid = d_pid
            elif role == "inner_timeout":
                current_timeout_pid = d_pid

            descendants_records.append(record)

        snapshot = {
            "sample_index": sample_index,
            "sample_mono_ns": snap_start_ns,
            "elapsed_sec": (snap_start_ns - self.foldcopy_start_mono_ns) / 1e9,
            "gap_sec": gap_sec,
            "descendant_count": len(descendants_records),
            "descendants": descendants_records,
            "timeout_pid": current_timeout_pid,
            "compiler_pid": current_compiler_pid,
            "generated_pid": current_generated_pid,
            "has_generated_prog": has_generated_prog,
        }

        # Track first and last observation bracketing program spawn
        if not has_generated_prog and self.first_snap_with_prog is None:
            self.last_snap_without_prog = snapshot
        elif has_generated_prog and self.first_snap_with_prog is None:
            self.first_snap_with_prog = snapshot
            self.generated_executable_observed = True
            self.generated_pid = current_generated_pid
            self.generated_observed_first_mono_ns = snap_start_ns
            self.generated_lstart = next((d.get("lstart") for d in descendants_records if d["pid"] == current_generated_pid), None)
            self.generated_executable_path = next((d.get("actual_executable_path") for d in descendants_records if d["pid"] == current_generated_pid), None)
            if self.generated_executable_path:
                self._preserve_generated_executable(current_generated_pid, self.generated_executable_path)

        # Retry preservation if path was delayed on first snapshot
        if self.generated_executable_observed and self.preserved_artifacts.get("status") != "PRESERVED":
            current_path = next((d.get("actual_executable_path") for d in descendants_records if d["pid"] == self.generated_pid), None)
            if current_path:
                self.generated_executable_path = current_path
                self._preserve_generated_executable(self.generated_pid, current_path)

        return snapshot

    def _take_final_snapshot(self, sample_index: int, last_output_size: int) -> None:
        """Capture final state after exit marker or termination."""
        final_mono = time.monotonic_ns()
        check_output_file(
            output_path=self.output_path,
            start_mono_ns=self.foldcopy_start_mono_ns,
            observed_markers=self.observed_markers,
            last_size=last_output_size,
        )
        self._take_process_snapshot(
            sample_index=sample_index,
            snap_start_ns=final_mono,
            gap_sec=0.0,
        )

    def _compile_and_write_results(self) -> dict[str, Any]:
        """Compile bounded phase intervals and write full and summary traces."""
        # Read end marker
        end_marker = {}
        if self.end_marker_path.is_file():
            try:
                end_marker = json.loads(self.end_marker_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        # 1. Bounded generated program start interval
        start_interval: dict[str, Any] = {
            "program_observed": self.generated_executable_observed,
            "lower_bound_mono_ns": None,
            "upper_bound_mono_ns": None,
            "lower_bound_elapsed_sec": None,
            "upper_bound_elapsed_sec": None,
            "interval_width_sec": None,
        }
        if self.generated_executable_observed and self.first_snap_with_prog:
            lower_ns = (
                self.last_snap_without_prog["sample_mono_ns"]
                if self.last_snap_without_prog
                else self.foldcopy_start_mono_ns
            )
            upper_ns = self.first_snap_with_prog["sample_mono_ns"]
            start_interval["lower_bound_mono_ns"] = lower_ns
            start_interval["upper_bound_mono_ns"] = upper_ns
            start_interval["lower_bound_elapsed_sec"] = (lower_ns - self.foldcopy_start_mono_ns) / 1e9
            start_interval["upper_bound_elapsed_sec"] = (upper_ns - self.foldcopy_start_mono_ns) / 1e9
            start_interval["interval_width_sec"] = (upper_ns - lower_ns) / 1e9

        # 2. Compiler and helper CPU accumulation before program start
        compiler_cpu_before_prog = {
            "ps_total_cpu_sec": 0.0,
            "native_total_cpu_sec": 0.0,
            "native_user_cpu_sec": 0.0,
            "native_system_cpu_sec": 0.0,
            "native_raw_total_ticks": 0,
        }
        cutoff_ns = (
            self.first_snap_with_prog["sample_mono_ns"]
            if self.first_snap_with_prog
            else time.monotonic_ns()
        )

        max_compiler_ps = 0.0
        max_compiler_native = 0.0
        max_compiler_user = 0.0
        max_compiler_sys = 0.0
        max_compiler_ticks = 0

        max_helpers_ps_by_pid: dict[int, float] = {}
        max_helpers_native_by_pid: dict[int, float] = {}

        for snap in self.process_snapshots:
            if snap["sample_mono_ns"] <= cutoff_ns:
                for d in snap["descendants"]:
                    role = d.get("role")
                    ps_cpu = d.get("ps_cputime_sec", 0.0)
                    taskinfo = d.get("kernel_taskinfo")
                    native_cpu = taskinfo["total_cpu_sec"] if taskinfo else 0.0

                    if role == "compiler":
                        if ps_cpu > max_compiler_ps:
                            max_compiler_ps = ps_cpu
                        if native_cpu > max_compiler_native:
                            max_compiler_native = native_cpu
                            max_compiler_user = taskinfo["user_cpu_sec"]
                            max_compiler_sys = taskinfo["system_cpu_sec"]
                            max_compiler_ticks = taskinfo["raw_total_ticks"]
                    elif role == "compiler_helper":
                        pid = d["pid"]
                        if ps_cpu > max_helpers_ps_by_pid.get(pid, 0.0):
                            max_helpers_ps_by_pid[pid] = ps_cpu
                        if native_cpu > max_helpers_native_by_pid.get(pid, 0.0):
                            max_helpers_native_by_pid[pid] = native_cpu

        compiler_cpu_before_prog["ps_total_cpu_sec"] = max_compiler_ps + sum(max_helpers_ps_by_pid.values())
        compiler_cpu_before_prog["native_total_cpu_sec"] = max_compiler_native + sum(max_helpers_native_by_pid.values())
        compiler_cpu_before_prog["native_user_cpu_sec"] = max_compiler_user
        compiler_cpu_before_prog["native_system_cpu_sec"] = max_compiler_sys
        compiler_cpu_before_prog["native_raw_total_ticks"] = max_compiler_ticks

        # 3. Generated program CPU accumulation during observed lifetime
        # Keep ps CPU and native kernel task CPU as separate named measurements (no max(ps, native))
        program_cpu_observed = {
            "ps_total_cpu_sec": 0.0,
            "native_total_cpu_sec": 0.0,
            "native_user_cpu_sec": 0.0,
            "native_system_cpu_sec": 0.0,
            "native_raw_user_ticks": 0,
            "native_raw_system_ticks": 0,
            "native_raw_total_ticks": 0,
            "ps_max_rss_kb": 0,
            "native_max_rss_bytes": 0,
            "native_max_rss_kb": 0,
            "native_max_virtual_bytes": 0,
            "max_thread_count": 0,
            "max_running_thread_count": 0,
        }
        if self.generated_pid:
            for snap in self.process_snapshots:
                for d in snap["descendants"]:
                    if d["pid"] == self.generated_pid or d.get("role") == "generated_executable":
                        ps_cpu = d.get("ps_cputime_sec", 0.0)
                        ps_rss = d.get("ps_rss_kb", 0)
                        if ps_cpu > program_cpu_observed["ps_total_cpu_sec"]:
                            program_cpu_observed["ps_total_cpu_sec"] = ps_cpu
                        if ps_rss > program_cpu_observed["ps_max_rss_kb"]:
                            program_cpu_observed["ps_max_rss_kb"] = ps_rss

                        taskinfo = d.get("kernel_taskinfo")
                        if taskinfo:
                            if taskinfo["total_cpu_sec"] > program_cpu_observed["native_total_cpu_sec"]:
                                program_cpu_observed["native_total_cpu_sec"] = taskinfo["total_cpu_sec"]
                                program_cpu_observed["native_user_cpu_sec"] = taskinfo["user_cpu_sec"]
                                program_cpu_observed["native_system_cpu_sec"] = taskinfo["system_cpu_sec"]
                                program_cpu_observed["native_raw_user_ticks"] = taskinfo["raw_user_ticks"]
                                program_cpu_observed["native_raw_system_ticks"] = taskinfo["raw_system_ticks"]
                                program_cpu_observed["native_raw_total_ticks"] = taskinfo["raw_total_ticks"]
                            if taskinfo["rss_bytes"] > program_cpu_observed["native_max_rss_bytes"]:
                                program_cpu_observed["native_max_rss_bytes"] = taskinfo["rss_bytes"]
                                program_cpu_observed["native_max_rss_kb"] = taskinfo["rss_bytes"] // 1024
                            if taskinfo["virtual_bytes"] > program_cpu_observed["native_max_virtual_bytes"]:
                                program_cpu_observed["native_max_virtual_bytes"] = taskinfo["virtual_bytes"]
                            if taskinfo.get("pti_threadnum", 0) > program_cpu_observed["max_thread_count"]:
                                program_cpu_observed["max_thread_count"] = taskinfo["pti_threadnum"]
                            if taskinfo.get("pti_numrunning", 0) > program_cpu_observed["max_running_thread_count"]:
                                program_cpu_observed["max_running_thread_count"] = taskinfo["pti_numrunning"]

        # 4. Timeout and compiler first observed
        first_timeout_observed = None
        first_compiler_observed = None
        for snap in self.process_snapshots:
            if first_timeout_observed is None and snap.get("timeout_pid"):
                first_timeout_observed = {
                    "pid": snap["timeout_pid"],
                    "elapsed_sec": snap["elapsed_sec"],
                }
            if first_compiler_observed is None and snap.get("compiler_pid"):
                first_compiler_observed = {
                    "pid": snap["compiler_pid"],
                    "elapsed_sec": snap["elapsed_sec"],
                }

        # Query timebase for receipt
        numer, denom = get_mach_timebase_info()

        # Summary structure
        summary = {
            "status": "COMPLETED",
            "foldcopy_start_marker": self.foldcopy_start_marker,
            "foldcopy_end_marker": end_marker,
            "raw_returncode": end_marker.get("raw_returncode"),
            "mach_timebase": {
                "numer": numer,
                "denom": denom,
                "ratio": numer / denom if denom else 1.0,
            },
            "first_observed_timeout": first_timeout_observed,
            "first_observed_compiler": first_compiler_observed,
            "generated_program_start_interval": start_interval,
            "compiler_cpu_before_program_start": compiler_cpu_before_prog,
            "program_cpu_observed": program_cpu_observed,
            "first_observed_runtime_output": self.first_runtime_output,
            "runtime_output_markers_observed": self.observed_markers,
            "preserved_artifacts": self.preserved_artifacts,
            "profile_window": self.profile_window_result or {
                "status": "NOT_EXECUTED",
                "profile_executed": False,
                "reason": "Process ended or profile window was not triggered",
            },
            "observer_telemetry": {
                "process_snapshot_count": len(self.process_snapshots),
                "output_sample_count": len(self.output_samples),
                "max_sampling_gap_sec": self.max_sampling_gap_sec,
                "error_count": len(self.errors),
                "errors": self.errors[:20],
            },
        }

        # Full trace structure
        full_trace = {
            **summary,
            "process_snapshots": self.process_snapshots,
            "output_samples": self.output_samples,
        }

        # Save files
        self.trace_output_path.write_text(json.dumps(full_trace, indent=2) + "\n", encoding="utf-8")
        self.summary_output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        return summary


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for passive phase trace observer."""
    parser = argparse.ArgumentParser(
        description="Passive process and output phase tracer for YAML foldcopy diagnostics"
    )
    parser.add_argument(
        "--capture-dir",
        "--report-dir",
        default=".",
        help="Directory to watch for foldcopy start/end markers and write trace JSON",
    )
    parser.add_argument(
        "--parent-pid",
        type=int,
        default=None,
        help="Preconfigured parent bash PID (if known in advance)",
    )
    parser.add_argument(
        "--outer-timeout",
        type=int,
        default=DEFAULT_OUTER_TIMEOUT_SEC,
        help=f"Outer safety timeout in seconds (default: {DEFAULT_OUTER_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--validate-pidpath",
        action="store_true",
        help="Validate Darwin proc_pidpath on an owned short-lived child and exit",
    )
    parser.add_argument(
        "--validate-accounting",
        action="store_true",
        help="Validate Darwin mach_timebase_info, proc_taskinfo, and thread snapshots on an owned child and exit",
    )

    args = parser.parse_args(argv)

    if args.validate_pidpath:
        receipt = validate_proc_pidpath()
        print(json.dumps(receipt, indent=2))
        return 0 if receipt.get("paths_match") else 1

    if args.validate_accounting:
        receipt = validate_accounting()
        print(json.dumps(receipt, indent=2))
        return 0 if receipt.get("overall_verified") else 1

    capture_dir = Path(args.capture_dir).resolve()
    tracer = PassivePhaseTracer(
        capture_dir=capture_dir,
        parent_pid=args.parent_pid,
        outer_timeout_sec=args.outer_timeout,
    )

    # 1. Wait dormant until start marker appears
    if not tracer.wait_for_start_marker():
        print(f"PASSIVE-TRACER-ERROR: Failed to activate: {tracer.errors}", file=sys.stderr)
        return 2

    # 2. Run observation loop
    results = tracer.run_observation()
    print(json.dumps({
        "status": results["status"],
        "program_observed": results["generated_program_start_interval"]["program_observed"],
        "interval_width_sec": results["generated_program_start_interval"]["interval_width_sec"],
        "max_sampling_gap_sec": results["observer_telemetry"]["max_sampling_gap_sec"],
        "snapshot_count": results["observer_telemetry"]["process_snapshot_count"],
        "profile_window_executed": results["profile_window"].get("profile_executed", False),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
