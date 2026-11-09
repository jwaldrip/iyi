#!/usr/bin/env python3
"""Owned subprocess boundary for version probes; not imported by fixture tests."""
import ctypes
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from types import SimpleNamespace

_LIMIT = 65536
_CANCELLED = None
_SIGNALS = {signal.SIGTERM, signal.SIGINT}


def _cancel(signum, frame):
    global _CANCELLED
    _CANCELLED = signum


def _child_setup(parent, old_mask):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise RuntimeError("parent-death protection unavailable")
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if 0 in os.getresuid() or 0 in os.getresgid():
        raise RuntimeError("root identity")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if key not in status or int(status[key].strip(), 16) != 0:
            raise RuntimeError(f"unsafe capability state: {key}")
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise RuntimeError("no_new_privs unavailable")


def run_version(path):
    global _CANCELLED
    if _CANCELLED is not None:
        raise RuntimeError(f"cancelled by signal {_CANCELLED}")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("SIGCHLD disposition is not default")
    previous_handlers = {sig: signal.getsignal(sig) for sig in _SIGNALS}
    for sig in _SIGNALS:
        signal.signal(sig, _cancel)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _SIGNALS)
    child = None
    selector = None
    data = bytearray()
    result = None
    deadline = time.monotonic() + 5
    try:
        parent = os.getpid()
        child = subprocess.Popen([path, "--version"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                 start_new_session=True,
                                 preexec_fn=lambda: _child_setup(parent, old_mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if _CANCELLED is not None:
                raise RuntimeError(f"cancelled by signal {_CANCELLED}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("version probe timed out")
            if not selector.select(min(remaining, 0.1)):
                continue
            chunk = os.read(child.stdout.fileno(), min(8192, _LIMIT + 1 - len(data)))
            if not chunk:
                selector.unregister(child.stdout)
                break
            data.extend(chunk)
            if len(data) > _LIMIT:
                raise ValueError("version output exceeds limit")
        while time.monotonic() < deadline:
            if _CANCELLED is not None:
                raise RuntimeError(f"cancelled by signal {_CANCELLED}")
            info = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if info is not None:
                code = info.si_status if info.si_code == os.CLD_EXITED else -info.si_status
                result = SimpleNamespace(returncode=code, stdout=bytes(data))
                break
            time.sleep(0.01)
        if result is None:
            raise TimeoutError("version probe timed out")
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, _SIGNALS)
        try:
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    child.wait(timeout=2)
        finally:
            if selector is not None:
                selector.close()
            if child is not None and child.stdout is not None:
                child.stdout.close()
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
    if _CANCELLED is not None:
        raise RuntimeError(f"cancelled by signal {_CANCELLED}")
    return result
