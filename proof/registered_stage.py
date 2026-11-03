"""Gated native-stage launch. The supervisor is the ownership authority.

Polling can observe previously discovered descendants after reparenting, but cannot
prove the absence of an entirely unobserved fast fork and reparent.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
import sys
import time
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class StageRunResult:
    exit_code: int | None
    timed_out: bool
    interrupted: bool
    ownership_resolved: bool
    ownership_error: str | None


_GATE = """import os,sys
fd=int(sys.argv[1])
try:
    ok=os.read(fd,1)
finally:
    os.close(fd)
if ok != b'G':
    os._exit(125)
os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
"""


def run_registered_stage(
    cmd: Sequence[str], *, cwd: str, env: Mapping[str, str], log_file,
    unit: str, attempt: int, monotonic_deadline: float, grace_sec: float,
    register: Callable[[dict], dict], is_interrupted: Callable[[], bool],
) -> StageRunResult:
    """Launch behind a pipe barrier; never exec until durable registration ACK.

    ``register`` exchanges typed ownership control messages with the independent
    supervisor. An unresolved or failed exchange is never interpreted as an
    empty process census. The supervisor performs any descendant recovery.
    """
    if not cmd:
        raise ValueError("empty stage command")
    read_fd, write_fd = os.pipe()
    proc = None
    timed_out = False
    interrupted = False
    try:
        if not hasattr(log_file, "fileno"):
            raise TypeError("log_file must be an already validated open file")
        output = log_file
        proc = subprocess.Popen(
            [sys.executable, "-c", _GATE, str(read_fd), *cmd],
            cwd=cwd, env=dict(env), stdout=output, stderr=subprocess.STDOUT,
            pass_fds=(read_fd,), start_new_session=True,
        )
        os.close(read_fd)
        read_fd = -1
        request = {"event": "ownership-register", "pid": proc.pid,
                   "unit": unit, "native_attempt": attempt}
        try:
            ack = register(request)
            if not isinstance(ack, dict) or ack.get("verified") is not True or any(
                ack.get(k) != request[k] for k in ("pid", "unit", "native_attempt")
            ) or ack.get("event") != "ownership-register-ack":
                raise RuntimeError("registration ACK does not match gated process")
        except Exception as exc:
            # This is our still-gated direct child, never a guessed descendant.
            os.close(write_fd)
            write_fd = -1
            proc.wait()
            return StageRunResult(proc.returncode, False, False, False,
                                  f"registration failed: {exc}")
        os.write(write_fd, b"G")
        os.close(write_fd)
        write_fd = -1
        while proc.poll() is None:
            state = is_interrupted()
            interrupted = bool(state[0] if isinstance(state, tuple) else state)
            timed_out = time.monotonic() >= monotonic_deadline
            if interrupted or timed_out:
                break
            time.sleep(min(0.1, max(0.0, monotonic_deadline - time.monotonic())))
        request = {"event": "ownership-resolve", "pid": proc.pid,
                   "unit": unit, "native_attempt": attempt,
                   "grace_sec": grace_sec}
        try:
            ack = register(request)
            if not isinstance(ack, dict) or ack.get("verified") is not True or any(
                ack.get(k) != request[k] for k in ("pid", "unit", "native_attempt")
            ) or ack.get("event") != "ownership-resolve-ack":
                raise RuntimeError("ownership resolution ACK does not match stage")
            try:
                proc.wait(timeout=max(1.0, grace_sec + 5.0))
            except subprocess.TimeoutExpired:
                raise RuntimeError("registered root remained alive after resolution")
            return StageRunResult(proc.returncode, timed_out, interrupted, True, None)
        except Exception as exc:
            return StageRunResult(proc.poll(), timed_out, interrupted, False,
                                  f"ownership unresolved: {exc}")
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
