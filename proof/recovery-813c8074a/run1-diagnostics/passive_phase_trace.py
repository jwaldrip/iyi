#!/usr/bin/env python3
"""Passive process and output phase tracer for YAML foldcopy diagnostics.

Observes only descendants of the captured parent shell between foldcopy start
and end markers. Collects:
  - Process snapshots (250 ms until generated executable observed, 1 s thereafter)
  - Output file size and marker samples (every 100 ms)
  - Process attributes: PID, PPID, PGID, start identity, actual executable path
    via Darwin libproc proc_pidpath, CPU/RSS/state, observation times, gaps, errors
  - Generated executable identification from source actual path and parentage:
    `iyi-run-std_yaml_exercise-<compiler-pid>.tmp`, never linker command lines.
  - Bounded phase intervals rather than exact times or fabricated thresholds.

Reference: agent://PlanQuietCorpusFailures (Ordered diagnostic plan sections 1-4)
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import datetime
import json
import os
from pathlib import Path
import re
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


class ProcTaskInfo(ctypes.Structure):
    """Darwin proc_taskinfo structure from <sys/proc_info.h>."""
    _fields_ = [
        ("pti_virtual_size", ctypes.c_uint64),
        ("pti_resident_size", ctypes.c_uint64),
        ("pti_total_user", ctypes.c_uint64),       # nanoseconds
        ("pti_total_system", ctypes.c_uint64),     # nanoseconds
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
    """Query CPU time and memory for a PID using Darwin libproc proc_pidinfo(PROC_PIDTASKINFO)."""
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
            return {
                "user_cpu_sec": info.pti_total_user / 1e9,
                "system_cpu_sec": info.pti_total_system / 1e9,
                "total_cpu_sec": (info.pti_total_user + info.pti_total_system) / 1e9,
                "rss_bytes": info.pti_resident_size,
                "virtual_bytes": info.pti_virtual_size,
                "faults": info.pti_faults,
                "pageins": info.pti_pageins,
                "cow_faults": info.pti_cow_faults,
            }, None
        errno = ctypes.get_errno()
        return None, f"proc_pidinfo returned {ret}, errno={errno}"
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
    """Manages passive observation of foldcopy descendant processes and output markers."""

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

            # 3. Check for end marker
            if self.end_marker_path.is_file():
                break

            # 4. Check if parent bash PID is still alive
            try:
                os.kill(self.parent_bash_pid, 0)
            except ProcessLookupError:
                self.errors.append("Parent bash PID terminated before foldcopy_end_marker.json was written")
                break
            except PermissionError:
                pass

            # 5. Check outer safety timeout
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
        compiler_cpu_before_prog = {"user_sec": 0.0, "system_sec": 0.0, "total_sec": 0.0}
        cutoff_ns = (
            self.first_snap_with_prog["sample_mono_ns"]
            if self.first_snap_with_prog
            else time.monotonic_ns()
        )

        max_compiler_cpu = 0.0
        max_helpers_cpu_by_pid: dict[int, float] = {}

        for snap in self.process_snapshots:
            if snap["sample_mono_ns"] <= cutoff_ns:
                for d in snap["descendants"]:
                    role = d.get("role")
                    cputime = d.get("ps_cputime_sec", 0.0)
                    if d.get("kernel_taskinfo"):
                        cputime = max(cputime, d["kernel_taskinfo"]["total_cpu_sec"])

                    if role == "compiler":
                        if cputime > max_compiler_cpu:
                            max_compiler_cpu = cputime
                    elif role == "compiler_helper":
                        pid = d["pid"]
                        if cputime > max_helpers_cpu_by_pid.get(pid, 0.0):
                            max_helpers_cpu_by_pid[pid] = cputime

        compiler_cpu_before_prog["total_sec"] = max_compiler_cpu + sum(max_helpers_cpu_by_pid.values())

        # 3. Generated program CPU accumulation during observed lifetime
        program_cpu_observed = {"total_sec": 0.0, "max_rss_kb": 0}
        if self.generated_pid:
            for snap in self.process_snapshots:
                for d in snap["descendants"]:
                    if d["pid"] == self.generated_pid or d.get("role") == "generated_executable":
                        cputime = d.get("ps_cputime_sec", 0.0)
                        rss = d.get("ps_rss_kb", 0)
                        if d.get("kernel_taskinfo"):
                            cputime = max(cputime, d["kernel_taskinfo"]["total_cpu_sec"])
                            rss = max(rss, int(d["kernel_taskinfo"]["rss_bytes"] / 1024))
                        if cputime > program_cpu_observed["total_sec"]:
                            program_cpu_observed["total_sec"] = cputime
                        if rss > program_cpu_observed["max_rss_kb"]:
                            program_cpu_observed["max_rss_kb"] = rss

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

        # Summary structure
        summary = {
            "status": "COMPLETED",
            "foldcopy_start_marker": self.foldcopy_start_marker,
            "foldcopy_end_marker": end_marker,
            "raw_returncode": end_marker.get("raw_returncode"),
            "first_observed_timeout": first_timeout_observed,
            "first_observed_compiler": first_compiler_observed,
            "generated_program_start_interval": start_interval,
            "compiler_cpu_before_program_start": compiler_cpu_before_prog,
            "program_cpu_observed": program_cpu_observed,
            "first_observed_runtime_output": self.first_runtime_output,
            "runtime_output_markers_observed": self.observed_markers,
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

    args = parser.parse_args(argv)

    if args.validate_pidpath:
        receipt = validate_proc_pidpath()
        print(json.dumps(receipt, indent=2))
        return 0 if receipt.get("paths_match") else 1

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
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
