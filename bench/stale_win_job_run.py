#!/usr/bin/env python3
"""Probe helper: run a command inside a Windows job object with a job memory limit.

    python3 bench/stale_win_job_run.py LIMIT_BYTES COMMAND [ARGS...]

The same wrapper row 28 of bench/stale_tests.sh uses for its job-object limit
(`r28_limited`): this process joins a new job whose JOB_OBJECT_LIMIT_JOB_MEMORY
is LIMIT_BYTES, and the command, a child, inherits it. The exit status is the
command's.
"""

import ctypes
import subprocess
import sys
from ctypes import wintypes


class Basic(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD), ("min_ws", ctypes.c_size_t),
                ("max_ws", ctypes.c_size_t), ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD)]


class IO(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]


class Extended(ctypes.Structure):
    _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t)]


def main() -> int:
    limit = int(sys.argv[1])
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    job = k.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Extended()
    limits.basic.flags = 0x200  # JOB_OBJECT_LIMIT_JOB_MEMORY
    limits.job_memory = limit
    if not k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not k.AssignProcessToJobObject(job, k.GetCurrentProcess()):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return subprocess.call(sys.argv[2:])
    finally:
        k.CloseHandle(job)


if __name__ == "__main__":
    sys.exit(main())
