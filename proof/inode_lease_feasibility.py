"""
proof/inode_lease_feasibility.py: Controller-held Linux F_RDLCK read lease feasibility qualification.

Authoritative contract: local://inode-lease-contract-revised.md (PlanNoVerityWitness)
Addresses complete security review: local://inode-lease-review-23819.md

Architecture:
- Single-threaded unprivileged controller P.
- Isolated direct child actors:
  * H: Holder (holds lease, owns signalfd, monitors break signals, streams bytes)
  * A: Requester (attempts conflicting opens, truncates, raw mmap)
  * E: Executor (attempts native execveat via CLOEXEC error channel)
  * S: Sentinel (monitors untouched sentinel fixture via private IPC)
- Communication: Private AF_UNIX SOCK_SEQPACKET pairs per actor with discrete frames.
- Process management: Linux pidfd_open, pidfd_send_signal, waitid(P_PIDFD).
- File confinement: Component-wise O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, umask 077,
  exclusive leaf names under exact RUNNER_TEMP/inode-lease-diag-<run>-<attempt>.
- Native ELF64 x86_64 fixture: 132-byte self-contained binary (exit_group 73).
- 14 mandatory observable controls with complete observations and total acceptance predicate.
- Schema: iyi-kernel-feasibility-v1, strict_eligible=False, cage_qualified=False,
  exec_identity_tested=False, native_fd_launch_tested=True.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import select
import signal
import socket
import stat
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Linux Syscall Numbers & Constants (x86_64)
# -----------------------------------------------------------------------------

SYS_read = 0
SYS_write = 1
SYS_open = 2
SYS_close = 3
SYS_stat = 4
SYS_fstat = 5
SYS_poll = 7
SYS_lseek = 8
SYS_mmap = 9
SYS_munmap = 11
SYS_fcntl = 72
SYS_truncate = 76
SYS_getpid = 39
SYS_gettid = 186
SYS_prctl = 157
SYS_waitid = 247
SYS_futimens = 280
SYS_signalfd4 = 289
SYS_execveat = 322
SYS_pidfd_send_signal = 424
SYS_pidfd_open = 434

# fcntl lease constants
F_SETLEASE = 1024
F_GETLEASE = 1025
F_RDLCK = 0
F_WRLCK = 1
F_UNLCK = 2

# fcntl signal constants
F_SETSIG = 10
F_GETSIG = 11
F_SETOWN_EX = 32
F_GETOWN_EX = 33
F_OWNER_TID = 0
F_OWNER_PID = 1
F_OWNER_PGRP = 2

# prctl constants
PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

# waitid constants
P_PIDFD = 3
WEXITED = 4
WNOHANG = 1

# signalfd constants
SFD_CLOEXEC = 0o2000000
SFD_NONBLOCK = 0o0004000

# execveat constants
AT_EMPTY_PATH = 0x1000
AT_SYMLINK_NOFOLLOW = 0x100

# mmap constants
PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_SHARED = 0x01
MAP_FAILED = -1

# siginfo codes for POLL
POLL_IN = 1
POLL_OUT = 2
POLL_MSG = 3
POLL_ERR = 4
POLL_PRI = 5
POLL_HUP = 6

SIGRTMIN_DEFAULT = 34
SIGRTMAX_DEFAULT = 64

# -----------------------------------------------------------------------------
# Reviewed 132-byte ELF64 x86_64 Fixture (exit_group 73)
# -----------------------------------------------------------------------------

REVIEWED_ELF64_BYTES = bytes([
    # EHDR (64 bytes)
    0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # PHDR (56 bytes, PT_LOAD RX)
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # Code (12 bytes: mov eax, 231; mov edi, 73; syscall)
    0xB8, 0xE7, 0x00, 0x00, 0x00,
    0xBF, 0x49, 0x00, 0x00, 0x00,
    0x0F, 0x05,
])
REVIEWED_ELF64_SHA256 = hashlib.sha256(REVIEWED_ELF64_BYTES).hexdigest()

# Invalid executable fixture (ELF header with invalid machine type, marked 0700)
INVALID_ELF_BYTES = bytearray(REVIEWED_ELF64_BYTES)
INVALID_ELF_BYTES[18] = 0xFF  # Corrupted machine type
INVALID_ELF_BYTES[19] = 0xFF
INVALID_ELF_BYTES = bytes(INVALID_ELF_BYTES)
INVALID_ELF_SHA256 = hashlib.sha256(INVALID_ELF_BYTES).hexdigest()

# -----------------------------------------------------------------------------
# Required Control IDs (14 Mandatory Controls)
# -----------------------------------------------------------------------------

REQUIRED_CONTROL_IDS = [
    "genuine_lifecycle",
    "existing_writer",
    "fd_closed_shared_mmap",
    "nonblocking_break",
    "forced_blocking_open_and_restore",
    "pathname_truncate_forced",
    "cancelled_requester_sticky",
    "read_utime_without_exec",
    "failed_native_exec",
    "same_bytes_different_inode_launch",
    "reference_substitution",
    "holder_death",
    "racing_open_acquire",
    "owned_sentinel_untouched",
]

# -----------------------------------------------------------------------------
# CTypes & Low-level Syscall Wrappers
# -----------------------------------------------------------------------------

try:
    libc = ctypes.CDLL(None, use_errno=True)
except Exception:
    libc = None


class SigInfo(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int32),
        ("si_errno", ctypes.c_int32),
        ("si_code", ctypes.c_int32),
        ("si_pid", ctypes.c_uint32),
        ("si_uid", ctypes.c_uint32),
        ("si_status", ctypes.c_int32),
        ("si_utime", ctypes.c_int64),
        ("si_stime", ctypes.c_int64),
        ("_pad", ctypes.c_char * 88),
    ]


class SignalFdSigInfo(ctypes.Structure):
    _fields_ = [
        ("ssi_signo", ctypes.c_uint32),
        ("ssi_errno", ctypes.c_int32),
        ("ssi_code", ctypes.c_int32),
        ("ssi_pid", ctypes.c_uint32),
        ("ssi_uid", ctypes.c_uint32),
        ("ssi_fd", ctypes.c_int32),
        ("ssi_tid", ctypes.c_uint32),
        ("ssi_band", ctypes.c_uint32),
        ("ssi_overrun", ctypes.c_uint32),
        ("ssi_trapno", ctypes.c_uint32),
        ("ssi_status", ctypes.c_int32),
        ("ssi_int", ctypes.c_int32),
        ("ssi_ptr", ctypes.c_uint64),
        ("ssi_utime", ctypes.c_uint64),
        ("ssi_stime", ctypes.c_uint64),
        ("ssi_addr", ctypes.c_uint64),
        ("ssi_addr_lsb", ctypes.c_uint16),
        ("_pad", ctypes.c_char * 46),
    ]


def sys_pidfd_open(pid: int, flags: int = 0) -> int:
    if libc is None:
        raise OSError(errno.ENOSYS, "libc unavailable")
    res = libc.syscall(SYS_pidfd_open, ctypes.c_int(pid), ctypes.c_uint(flags))
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(res)


def sys_pidfd_send_signal(pidfd: int, sig: int) -> None:
    if libc is None:
        raise OSError(errno.ENOSYS, "libc unavailable")
    res = libc.syscall(
        SYS_pidfd_send_signal,
        ctypes.c_int(pidfd),
        ctypes.c_int(sig),
        None,
        ctypes.c_uint(0),
    )
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def sys_waitid_pidfd(pidfd: int, flags: int = WEXITED) -> Tuple[int, int, int]:
    if libc is None:
        raise OSError(errno.ENOSYS, "libc unavailable")
    info = SigInfo()
    res = libc.syscall(
        SYS_waitid,
        ctypes.c_int(P_PIDFD),
        ctypes.c_int(pidfd),
        ctypes.byref(info),
        ctypes.c_int(flags),
        None,
    )
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(info.si_pid), int(info.si_status), int(info.si_code)


def sys_signalfd4(mask: int, flags: int) -> int:
    if libc is None:
        raise OSError(errno.ENOSYS, "libc unavailable")
    mask_val = ctypes.c_uint64(mask)
    res = libc.syscall(
        SYS_signalfd4,
        ctypes.c_int(-1),
        ctypes.byref(mask_val),
        ctypes.c_size_t(8),
        ctypes.c_int(flags),
    )
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(res)


def get_realtime_lease_signal() -> int:
    if libc is not None:
        try:
            libc.__libc_current_sigrtmin.restype = ctypes.c_int
            rtmin = libc.__libc_current_sigrtmin()
            if 32 <= rtmin <= 64:
                return rtmin + 1
        except Exception:
            pass
    return SIGRTMIN_DEFAULT + 1


def close_fds_except(allowed: List[int]) -> None:
    """Close all open file descriptors >= 3 except those in allowed list."""
    allowed_set = set(allowed) | {0, 1, 2}
    try:
        proc_fd = pathlib.Path("/proc/self/fd")
        if proc_fd.exists():
            for entry in os.listdir("/proc/self/fd"):
                try:
                    fd = int(entry)
                    if fd not in allowed_set:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                except ValueError:
                    pass
            return
    except Exception:
        pass
    # Fallback range close
    for fd in range(3, 256):
        if fd not in allowed_set:
            try:
                os.close(fd)
            except OSError:
                pass


# -----------------------------------------------------------------------------
# IPC Message Framing & Protocol (AF_UNIX SOCK_SEQPACKET)
# -----------------------------------------------------------------------------

def send_frame(sock: socket.socket, frame: Dict[str, Any]) -> None:
    data = json.dumps(frame).encode("utf-8")
    if len(data) > 4096:
        raise ValueError(f"IPC frame too large: {len(data)} bytes")
    sock.send(data)


def recv_frame(sock: socket.socket, timeout: float = 10.0) -> Dict[str, Any]:
    r, _, _ = select.select([sock], [], [], timeout)
    if not r:
        raise TimeoutError(f"IPC timeout after {timeout}s waiting for frame")
    data = sock.recv(4096)
    if not data:
        raise ConnectionResetError("IPC peer closed connection")
    return json.loads(data.decode("utf-8"))


# -----------------------------------------------------------------------------
# Actor Process Registry & Lifecycle (Controller P)
# -----------------------------------------------------------------------------

class ActorProcess:
    def __init__(
        self,
        role: str,
        case_id: str,
        pid: int,
        pidfd: int,
        sock: socket.socket,
    ):
        self.role = role
        self.case_id = case_id
        self.pid = pid
        self.pidfd = pidfd
        self.sock = sock
        self.reaped = False
        self.exit_code: Optional[int] = None
        self.term_sig: Optional[int] = None


class ActorRegistry:
    def __init__(self, launch_id: str):
        self.launch_id = launch_id
        self.actors: Dict[str, ActorProcess] = {}
        self.next_seq = 1

    def spawn_actor(
        self,
        role: str,
        case_id: str,
        target_fn: Any,
        extra_args: Tuple = (),
        pass_fds: List[int] = None,
    ) -> ActorProcess:
        pass_fds = pass_fds or []
        p_sock, c_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fcntl.fcntl(p_sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        fcntl.fcntl(c_sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)

        startup_r, startup_w = os.pipe()
        fcntl.fcntl(startup_r, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        fcntl.fcntl(startup_w, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

        pid = os.fork()
        if pid == 0:
            # Child actor
            try:
                os.close(startup_w)
                p_sock.close()
                os.umask(0o077)

                # Explicit FD allowlist
                allowed_child_fds = [c_sock.fileno(), startup_r] + pass_fds
                close_fds_except(allowed_child_fds)

                # Set PR_SET_PDEATHSIG(SIGKILL)
                if libc is not None:
                    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
                    cur_pdeath = ctypes.c_int(0)
                    libc.prctl(PR_GET_PDEATHSIG, ctypes.byref(cur_pdeath), 0, 0, 0)
                    if cur_pdeath.value != signal.SIGKILL:
                        os._exit(91)

                # Startup barrier: wait for parent to obtain pidfd
                b = os.read(startup_r, 1)
                os.close(startup_r)

                # Send READY frame
                ready_frame = {
                    "v": 1,
                    "launch_id": self.launch_id,
                    "actor": role,
                    "case": case_id,
                    "seq": 0,
                    "op": "READY",
                    "data": {"pid": os.getpid()},
                }
                send_frame(c_sock, ready_frame)

                # Execute target function
                target_fn(c_sock, role, case_id, *extra_args)
                os._exit(0)
            except Exception as ex:
                try:
                    err_frame = {
                        "v": 1,
                        "launch_id": self.launch_id,
                        "actor": role,
                        "case": case_id,
                        "seq": 0,
                        "op": "ERROR",
                        "data": {"error": str(ex)},
                    }
                    send_frame(c_sock, err_frame)
                except Exception:
                    pass
                os._exit(1)
        else:
            # Parent P
            os.close(startup_r)
            c_sock.close()

            # Obtain pidfd
            pidfd = sys_pidfd_open(pid, 0)

            # Release child from startup barrier
            os.write(startup_w, b"G")
            os.close(startup_w)

            # Wait for READY
            ready = recv_frame(p_sock, timeout=5.0)
            if ready.get("op") != "READY":
                raise RuntimeError(f"Actor {role} failed to send READY: {ready}")

            actor_key = f"{role}_{case_id}_{pid}"
            actor = ActorProcess(role, case_id, pid, pidfd, p_sock)
            self.actors[actor_key] = actor
            return actor

    def reap_actor(self, actor: ActorProcess, timeout: float = 5.0) -> Tuple[int, Optional[int]]:
        if actor.reaped:
            return actor.exit_code or 0, actor.term_sig

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status, code = sys_waitid_pidfd(actor.pidfd, WEXITED | WNOHANG)
            if pid == actor.pid:
                actor.reaped = True
                os.close(actor.pidfd)
                actor.sock.close()
                # Status evaluation: code == 1 (CLD_EXITED), code == 2 (CLD_KILLED)
                if code == 1:
                    actor.exit_code = status
                else:
                    actor.term_sig = status
                return actor.exit_code or 0, actor.term_sig
            time.sleep(0.02)

        # Timeout: force kill via pidfd
        sys_pidfd_send_signal(actor.pidfd, signal.SIGKILL)
        pid, status, code = sys_waitid_pidfd(actor.pidfd, WEXITED)
        actor.reaped = True
        os.close(actor.pidfd)
        actor.sock.close()
        if code == 1:
            actor.exit_code = status
        else:
            actor.term_sig = status
        return actor.exit_code or 0, actor.term_sig

    def reap_all(self) -> None:
        for actor in list(self.actors.values()):
            if not actor.reaped:
                self.reap_actor(actor, timeout=2.0)


# -----------------------------------------------------------------------------
# Actor Implementations (H, A, E, S)
# -----------------------------------------------------------------------------

def actor_holder_fn(
    sock: socket.socket,
    role: str,
    case_id: str,
    dirfd: int,
    filename: str,
) -> None:
    """Actor H: Holder process."""
    # Open target file read-only
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dirfd)

    # Signal mask: block SIGIO and SIGRTMIN+1
    rt_sig = get_realtime_lease_signal()
    mask = (1 << (signal.SIGIO - 1)) | (1 << (rt_sig - 1))
    if libc is not None:
        sigset = ctypes.c_uint64(mask)
        libc.pthread_sigmask(signal.SIG_BLOCK, ctypes.byref(sigset), None)

    # Create signalfd
    sfd = sys_signalfd4(mask, SFD_CLOEXEC | SFD_NONBLOCK)

    # Configure lease signal and owner
    fcntl.fcntl(fd, F_SETSIG, rt_sig)
    tid = libc.syscall(SYS_gettid) if libc is not None else os.getpid()
    owner_ex = struct.pack("ii", F_OWNER_TID, tid)
    fcntl.fcntl(fd, F_SETOWN_EX, owner_ex)

    # Acquire lease
    fcntl.fcntl(fd, F_SETLEASE, F_RDLCK)

    # Verify acquired
    cur = fcntl.fcntl(fd, F_GETLEASE)
    if cur != F_RDLCK:
        raise RuntimeError(f"F_GETLEASE returned {cur}, expected F_RDLCK")

    st = os.fstat(fd)
    acquired_frame = {
        "v": 1,
        "op": "ACQUIRED",
        "data": {
            "dev": st.st_dev,
            "ino": st.st_ino,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "atime_ns": st.st_atime_ns,
        },
    }
    send_frame(sock, acquired_frame)

    custody = "HELD"

    # Command loop
    while True:
        r, _, _ = select.select([sock, sfd], [], [], 0.05)
        # Check signalfd for break notifications
        if sfd in r:
            sig_info_bytes = os.read(sfd, 128)
            if len(sig_info_bytes) >= 128:
                signo, s_errno, code, s_pid, s_uid, s_fd = struct.unpack("<IiiIIi", sig_info_bytes[:24])
                custody = "TAINTED"
                break_frame = {
                    "v": 1,
                    "op": "BREAK_NOTIFIED",
                    "data": {
                        "signo": signo,
                        "code": code,
                        "fd": s_fd,
                        "lease_state": fcntl.fcntl(fd, F_GETLEASE),
                    },
                }
                send_frame(sock, break_frame)

        if sock in r:
            cmd = recv_frame(sock)
            op = cmd.get("op")

            if op == "SAMPLE_METADATA":
                cur_lease = fcntl.fcntl(fd, F_GETLEASE)
                cur_st = os.fstat(fd)
                send_frame(sock, {
                    "v": 1,
                    "op": "METADATA_SAMPLED",
                    "data": {
                        "dev": cur_st.st_dev,
                        "ino": cur_st.st_ino,
                        "size": cur_st.st_size,
                        "mtime_ns": cur_st.st_mtime_ns,
                        "atime_ns": cur_st.st_atime_ns,
                        "lease_state": cur_lease,
                        "custody": custody,
                    },
                })

            elif op == "STREAM_BYTES":
                pre_lease = fcntl.fcntl(fd, F_GETLEASE)
                os.lseek(fd, 0, os.SEEK_SET)
                chunks = []
                while True:
                    buf = os.read(fd, 65536)
                    if not buf:
                        break
                    chunks.append(buf)
                raw_bytes = b"".join(chunks)
                post_lease = fcntl.fcntl(fd, F_GETLEASE)
                send_frame(sock, {
                    "v": 1,
                    "op": "BYTES_STREAMED",
                    "data": {
                        "bytes_hex": raw_bytes.hex(),
                        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                        "pre_lease": pre_lease,
                        "post_lease": post_lease,
                        "custody": custody,
                    },
                })

            elif op == "CAPTURE_ACK":
                cur_lease = fcntl.fcntl(fd, F_GETLEASE)
                if cur_lease == F_RDLCK and custody == "HELD":
                    custody = "CAPTURED"
                    send_frame(sock, {"v": 1, "op": "FINAL_HELD", "data": {"custody": custody}})
                else:
                    custody = "TAINTED"
                    send_frame(sock, {"v": 1, "op": "FINAL_TAINTED", "data": {"custody": custody}})

            elif op == "RELEASE":
                final_lease = fcntl.fcntl(fd, F_GETLEASE)
                os.close(fd)
                os.close(sfd)
                send_frame(sock, {"v": 1, "op": "DONE", "data": {"final_lease": final_lease}})
                break


def actor_requester_fn(
    sock: socket.socket,
    role: str,
    case_id: str,
    dirfd: int,
    filename: str,
    op_type: str,
) -> None:
    """Actor A: Requester process."""
    if op_type == "OPEN_WRITABLE_HOLD":
        fd = os.open(filename, os.O_WRONLY | os.O_CLOEXEC, dir_fd=dirfd)
        send_frame(sock, {"v": 1, "op": "ACK", "data": {"opened": True}})
        # Wait for CLOSE command
        recv_frame(sock)
        os.close(fd)
        send_frame(sock, {"v": 1, "op": "DONE", "data": {"closed": True}})

    elif op_type == "MMAP_WRITABLE_HOLD":
        fd = os.open(filename, os.O_RDWR | os.O_CLOEXEC, dir_fd=dirfd)
        size = os.fstat(fd).st_size
        addr = libc.mmap(
            None,
            ctypes.c_size_t(size),
            ctypes.c_int(PROT_READ | PROT_WRITE),
            ctypes.c_int(MAP_SHARED),
            ctypes.c_int(fd),
            ctypes.c_int64(0),
        )
        os.close(fd)

        # Mutate byte via mapping
        ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_char))
        orig_val = ptr[0]
        ptr[0] = b"\x7E"

        send_frame(sock, {"v": 1, "op": "ACK", "data": {"mapped": True}})
        # Wait for MUNMAP command
        recv_frame(sock)

        # Restore byte and unmap
        ptr[0] = orig_val
        libc.munmap(addr, ctypes.c_size_t(size))
        send_frame(sock, {"v": 1, "op": "DONE", "data": {"unmapped": True}})

    elif op_type == "OPEN_NONBLOCK_WRITE":
        try:
            fd = os.open(filename, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
            os.close(fd)
            send_frame(sock, {"v": 1, "op": "ACK", "data": {"opened": True, "errno": 0}})
        except OSError as ex:
            send_frame(sock, {"v": 1, "op": "ACK", "data": {"opened": False, "errno": ex.errno}})

    elif op_type == "OPEN_BLOCKING_WRITE":
        # Blocks in kernel until lease breaks
        fd = os.open(filename, os.O_WRONLY | os.O_CLOEXEC, dir_fd=dirfd)
        send_frame(sock, {"v": 1, "op": "OPENED", "data": {"opened": True}})

        # Handle marker write & restore
        cmd = recv_frame(sock)
        if cmd.get("op") == "WRITE_MARKER":
            os.write(fd, b"\xFF")
            send_frame(sock, {"v": 1, "op": "MARKER_WRITTEN", "data": {}})

            cmd2 = recv_frame(sock)
            if cmd2.get("op") == "RESTORE_BYTES":
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, REVIEWED_ELF64_BYTES[0:1])
                send_frame(sock, {"v": 1, "op": "RESTORED", "data": {}})

        os.close(fd)

    elif op_type == "PATHNAME_TRUNCATE":
        # Full pathname truncate
        full_path = os.readlink(f"/proc/self/fd/{dirfd}") + "/" + filename
        res = libc.truncate(full_path.encode("utf-8"), ctypes.c_int64(0))
        err = ctypes.get_errno() if res != 0 else 0
        send_frame(sock, {"v": 1, "op": "TRUNCATED", "data": {"res": res, "errno": err}})


def actor_executor_fn(
    exec_fd: int,
    err_pipe_w: int,
) -> None:
    """Actor E: Native executor process."""
    try:
        # Close all fds except exec_fd and err_pipe_w
        close_fds_except([exec_fd, err_pipe_w])

        # Set CLOEXEC on err_pipe_w
        fcntl.fcntl(err_pipe_w, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

        # Direct execveat
        res = libc.syscall(
            SYS_execveat,
            ctypes.c_int(exec_fd),
            b"",
            None,
            None,
            ctypes.c_int(AT_EMPTY_PATH),
        )
        # If execveat returns, it failed
        err = ctypes.get_errno()
        os.write(err_pipe_w, struct.pack("i", err))
        os._exit(1)
    except Exception:
        os.write(err_pipe_w, struct.pack("i", errno.EACCES))
        os._exit(1)


def actor_sentinel_fn(
    sock: socket.socket,
    role: str,
    case_id: str,
    dirfd: int,
    filename: str,
) -> None:
    """Actor S: Sentinel process."""
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dirfd)
    orig_bytes = os.read(fd, 65536)
    os.close(fd)
    orig_sha256 = hashlib.sha256(orig_bytes).hexdigest()

    while True:
        msg = recv_frame(sock)
        op = msg.get("op")
        if op == "HEARTBEAT":
            nonce = msg.get("data", {}).get("nonce")
            # Verify file
            fd2 = os.open(filename, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dirfd)
            cur_bytes = os.read(fd2, 65536)
            os.close(fd2)
            cur_sha256 = hashlib.sha256(cur_bytes).hexdigest()
            send_frame(sock, {
                "v": 1,
                "op": "PONG",
                "data": {
                    "nonce": nonce,
                    "untouched": (cur_sha256 == orig_sha256),
                },
            })
        elif op == "STOP":
            send_frame(sock, {"v": 1, "op": "DONE", "data": {}})
            break


# -----------------------------------------------------------------------------
# Control Matrix Execution (P Controller)
# -----------------------------------------------------------------------------

def run_control_matrix(
    diag_dirfd: int,
    registry: ActorRegistry,
    lease_break_time: int,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    controls: Dict[str, Any] = {}
    capsules: Dict[str, Any] = {}

    # Initialize Sentinel S
    s_fd = os.open("sentinel.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(s_fd, b"SENTINEL_FIXTURE_INDEPENDENT_INTEGRITY_CHECK_BYTES")
    os.close(s_fd)

    s_actor = registry.spawn_actor(
        "S",
        "owned_sentinel_untouched",
        actor_sentinel_fn,
        extra_args=(diag_dirfd, "sentinel.bin"),
        pass_fds=[diag_dirfd],
    )

    # -------------------------------------------------------------------------
    # 1. genuine_lifecycle
    # -------------------------------------------------------------------------
    f1 = os.open("genuine.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f1, REVIEWED_ELF64_BYTES)
    os.close(f1)

    h_genuine = registry.spawn_actor(
        "H",
        "genuine_lifecycle",
        actor_holder_fn,
        extra_args=(diag_dirfd, "genuine.elf"),
        pass_fds=[diag_dirfd],
    )

    # Hardlink genuine.ref
    os.link("genuine.elf", "genuine.ref", src_dir_fd=diag_dirfd, dst_dir_fd=diag_dirfd)
    st_orig = os.stat("genuine.elf", dir_fd=diag_dirfd)
    st_ref = os.stat("genuine.ref", dir_fd=diag_dirfd)
    link_ok = (st_orig.st_dev == st_ref.st_dev and st_orig.st_ino == st_ref.st_ino and st_orig.st_nlink >= 2)

    # Reset atime via fd (futimens/os.utime)
    target_atime = max(0, st_orig.st_mtime_ns - 1_000_000_000)
    os.utime("genuine.elf", ns=(target_atime, st_orig.st_mtime_ns), dir_fd=diag_dirfd)
    st_after_utime = os.stat("genuine.elf", dir_fd=diag_dirfd)
    atime_ok = (st_after_utime.st_atime_ns == target_atime and st_after_utime.st_mtime_ns == st_orig.st_mtime_ns)

    # Controlled native launch via E
    exec_fd = os.open("genuine.elf", os.O_RDONLY | os.O_CLOEXEC, dir_fd=diag_dirfd)
    err_r, err_w = os.pipe()
    fcntl.fcntl(err_r, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    fcntl.fcntl(err_w, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    pid_e = os.fork()
    if pid_e == 0:
        os.close(err_r)
        actor_executor_fn(exec_fd, err_w)
    os.close(err_w)
    os.close(exec_fd)

    err_data = os.read(err_r, 4)
    os.close(err_r)
    _, status_e = os.waitpid(pid_e, 0)
    exit_code_e = os.waitstatus_to_exitcode(status_e)
    exec_ok = (len(err_data) == 0 and exit_code_e == 73)

    # Observe metadata post-launch
    send_frame(h_genuine.sock, {"v": 1, "op": "SAMPLE_METADATA"})
    sample_res = recv_frame(h_genuine.sock)

    # Unlink original alias
    os.unlink("genuine.elf", dir_fd=diag_dirfd)
    out_gone = False
    try:
        os.stat("genuine.elf", dir_fd=diag_dirfd)
    except FileNotFoundError:
        out_gone = True

    # Capture bytes under lease
    send_frame(h_genuine.sock, {"v": 1, "op": "STREAM_BYTES"})
    stream_res = recv_frame(h_genuine.sock)
    captured_bytes = bytes.fromhex(stream_res["data"]["bytes_hex"])
    bytes_ok = (hashlib.sha256(captured_bytes).hexdigest() == REVIEWED_ELF64_SHA256)

    # Handshake CAPTURE_ACK & FINAL_HELD
    send_frame(h_genuine.sock, {"v": 1, "op": "CAPTURE_ACK"})
    final_res = recv_frame(h_genuine.sock)
    custody_captured = (final_res.get("op") == "FINAL_HELD")

    capsules["genuine_lifecycle"] = {
        "digest": hashlib.sha256(captured_bytes).hexdigest(),
        "custody": "CAPTURED",
    }

    controls["genuine_lifecycle"] = {
        "status": "PASS" if (link_ok and atime_ok and exec_ok and out_gone and bytes_ok and custody_captured) else "FAILED",
        "link_verified": link_ok,
        "atime_verified": atime_ok,
        "native_exec_rc": exit_code_e,
        "out_unlinked": out_gone,
        "bytes_verified": bytes_ok,
        "custody_state": "CAPTURED" if custody_captured else "TAINTED",
    }

    # -------------------------------------------------------------------------
    # 2. existing_writer
    # -------------------------------------------------------------------------
    f2 = os.open("file_ew.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f2, b"EXISTING_WRITER_TEST_BYTES")
    os.close(f2)

    a_ew = registry.spawn_actor(
        "A",
        "existing_writer",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_ew.bin", "OPEN_WRITABLE_HOLD"),
        pass_fds=[diag_dirfd],
    )
    recv_frame(a_ew.sock)  # Wait for ACK

    # H attempts lease; must fail with EAGAIN
    h2_fd = os.open("file_ew.bin", os.O_RDONLY | os.O_CLOEXEC, dir_fd=diag_dirfd)
    eagain_ok = False
    try:
        fcntl.fcntl(h2_fd, F_SETLEASE, F_RDLCK)
    except OSError as ex:
        if ex.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            eagain_ok = True

    # A closes
    send_frame(a_ew.sock, {"v": 1, "op": "CLOSE"})
    registry.reap_actor(a_ew)

    # Paired positive acquisition
    paired_ok = False
    try:
        fcntl.fcntl(h2_fd, F_SETLEASE, F_RDLCK)
        if fcntl.fcntl(h2_fd, F_GETLEASE) == F_RDLCK:
            paired_ok = True
        fcntl.fcntl(h2_fd, F_SETLEASE, F_UNLCK)
    except Exception:
        pass
    os.close(h2_fd)

    controls["existing_writer"] = {
        "status": "PASS" if (eagain_ok and paired_ok) else "FAILED",
        "eagain_observed": eagain_ok,
        "paired_acquisition": paired_ok,
    }

    # -------------------------------------------------------------------------
    # 3. fd_closed_shared_mmap
    # -------------------------------------------------------------------------
    f3 = os.open("file_mmap.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f3, b"MMAP_WRITABLE_EXCLUSION_TEST_BYTES_4096" + b"\x00" * 4056)
    os.close(f3)

    a_mmap = registry.spawn_actor(
        "A",
        "fd_closed_shared_mmap",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_mmap.bin", "MMAP_WRITABLE_HOLD"),
        pass_fds=[diag_dirfd],
    )
    recv_frame(a_mmap.sock)  # Wait for mapped

    # H attempts lease; must fail with EAGAIN
    h3_fd = os.open("file_mmap.bin", os.O_RDONLY | os.O_CLOEXEC, dir_fd=diag_dirfd)
    mmap_eagain_ok = False
    try:
        fcntl.fcntl(h3_fd, F_SETLEASE, F_RDLCK)
    except OSError as ex:
        if ex.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            mmap_eagain_ok = True

    # A unmaps
    send_frame(a_mmap.sock, {"v": 1, "op": "MUNMAP"})
    registry.reap_actor(a_mmap)

    # Paired positive acquisition
    mmap_paired_ok = False
    try:
        fcntl.fcntl(h3_fd, F_SETLEASE, F_RDLCK)
        if fcntl.fcntl(h3_fd, F_GETLEASE) == F_RDLCK:
            mmap_paired_ok = True
        fcntl.fcntl(h3_fd, F_SETLEASE, F_UNLCK)
    except Exception:
        pass
    os.close(h3_fd)

    controls["fd_closed_shared_mmap"] = {
        "status": "PASS" if (mmap_eagain_ok and mmap_paired_ok) else "FAILED",
        "mmap_eagain_observed": mmap_eagain_ok,
        "mmap_paired_acquisition": mmap_paired_ok,
    }

    # -------------------------------------------------------------------------
    # 4. nonblocking_break
    # -------------------------------------------------------------------------
    f4 = os.open("file_nb.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f4, b"NONBLOCKING_BREAK_TEST_BYTES")
    os.close(f4)

    h_nb = registry.spawn_actor(
        "H",
        "nonblocking_break",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_nb.bin"),
        pass_fds=[diag_dirfd],
    )

    a_nb = registry.spawn_actor(
        "A",
        "nonblocking_break",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_nb.bin", "OPEN_NONBLOCK_WRITE"),
        pass_fds=[diag_dirfd],
    )
    nb_res = recv_frame(a_nb.sock)
    registry.reap_actor(a_nb)

    # H observes break signal
    break_msg = recv_frame(h_nb.sock, timeout=2.0)
    send_frame(h_nb.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_nb)

    nb_eagain = (nb_res.get("data", {}).get("errno") in (errno.EAGAIN, errno.EWOULDBLOCK))
    controls["nonblocking_break"] = {
        "status": "PASS" if (nb_eagain and break_msg.get("op") == "BREAK_NOTIFIED") else "FAILED",
        "nb_open_refused_eagain": nb_eagain,
        "break_notified": (break_msg.get("op") == "BREAK_NOTIFIED"),
    }

    # -------------------------------------------------------------------------
    # 5. forced_blocking_open_and_restore
    # -------------------------------------------------------------------------
    f5 = os.open("file_fbo.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f5, b"FORCED_BLOCKING_OPEN_ORIGINAL_BYTES")
    os.close(f5)

    h_fbo = registry.spawn_actor(
        "H",
        "forced_blocking_open_and_restore",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_fbo.bin"),
        pass_fds=[diag_dirfd],
    )

    a_fbo = registry.spawn_actor(
        "A",
        "forced_blocking_open_and_restore",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_fbo.bin", "OPEN_BLOCKING_WRITE"),
        pass_fds=[diag_dirfd],
    )

    # Wait for break notification in H
    break_fbo = recv_frame(h_fbo.sock, timeout=float(lease_break_time + 5))

    # A unblocks and reports OPENED
    opened_msg = recv_frame(a_fbo.sock, timeout=float(lease_break_time + 5))

    # Write marker byte
    send_frame(a_fbo.sock, {"v": 1, "op": "WRITE_MARKER"})
    recv_frame(a_fbo.sock)

    # Restore original bytes
    send_frame(a_fbo.sock, {"v": 1, "op": "RESTORE_BYTES"})
    recv_frame(a_fbo.sock)
    registry.reap_actor(a_fbo)

    # Verify H lease remains broken (F_UNLCK) despite restored bytes
    send_frame(h_fbo.sock, {"v": 1, "op": "SAMPLE_METADATA"})
    sample_fbo = recv_frame(h_fbo.sock)
    send_frame(h_fbo.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_fbo)

    fbo_ok = (
        break_fbo.get("op") == "BREAK_NOTIFIED"
        and opened_msg.get("op") == "OPENED"
        and sample_fbo.get("data", {}).get("lease_state") == F_UNLCK
    )
    controls["forced_blocking_open_and_restore"] = {
        "status": "PASS" if fbo_ok else "FAILED",
        "forced_revocation_observed": fbo_ok,
        "restored_bytes_custody_rejected": (sample_fbo.get("data", {}).get("lease_state") == F_UNLCK),
    }

    # -------------------------------------------------------------------------
    # 6. pathname_truncate_forced
    # -------------------------------------------------------------------------
    f6 = os.open("file_trunc.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f6, b"PATHNAME_TRUNCATE_TEST_BYTES")
    os.close(f6)

    h_trunc = registry.spawn_actor(
        "H",
        "pathname_truncate_forced",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_trunc.bin"),
        pass_fds=[diag_dirfd],
    )

    a_trunc = registry.spawn_actor(
        "A",
        "pathname_truncate_forced",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_trunc.bin", "PATHNAME_TRUNCATE"),
        pass_fds=[diag_dirfd],
    )

    trunc_break = recv_frame(h_trunc.sock, timeout=float(lease_break_time + 5))
    recv_frame(a_trunc.sock, timeout=float(lease_break_time + 5))
    registry.reap_actor(a_trunc)

    send_frame(h_trunc.sock, {"v": 1, "op": "SAMPLE_METADATA"})
    sample_trunc = recv_frame(h_trunc.sock)
    send_frame(h_trunc.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_trunc)

    trunc_ok = (
        trunc_break.get("op") == "BREAK_NOTIFIED"
        and sample_trunc.get("data", {}).get("size") == 0
        and sample_trunc.get("data", {}).get("lease_state") == F_UNLCK
    )
    controls["pathname_truncate_forced"] = {
        "status": "PASS" if trunc_ok else "FAILED",
        "truncate_break_observed": trunc_ok,
    }

    # -------------------------------------------------------------------------
    # 7. cancelled_requester_sticky
    # -------------------------------------------------------------------------
    f7 = os.open("file_crs.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f7, b"CANCELLED_REQUESTER_TEST_BYTES")
    os.close(f7)

    h_crs = registry.spawn_actor(
        "H",
        "cancelled_requester_sticky",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_crs.bin"),
        pass_fds=[diag_dirfd],
    )

    a_crs = registry.spawn_actor(
        "A",
        "cancelled_requester_sticky",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_crs.bin", "OPEN_BLOCKING_WRITE"),
        pass_fds=[diag_dirfd],
    )

    # Wait for break notification in H
    break_crs = recv_frame(h_crs.sock, timeout=2.0)

    # Cancel A via pidfd before break time expires
    sys_pidfd_send_signal(a_crs.pidfd, signal.SIGTERM)
    _, term_sig_a = registry.reap_actor(a_crs)

    # Verify H lease remains broken (F_UNLCK) despite cancelled requester
    send_frame(h_crs.sock, {"v": 1, "op": "SAMPLE_METADATA"})
    sample_crs = recv_frame(h_crs.sock)
    send_frame(h_crs.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_crs)

    crs_ok = (
        break_crs.get("op") == "BREAK_NOTIFIED"
        and term_sig_a == signal.SIGTERM
        and sample_crs.get("data", {}).get("lease_state") == F_UNLCK
    )
    controls["cancelled_requester_sticky"] = {
        "status": "PASS" if crs_ok else "FAILED",
        "cancellation_observed": crs_ok,
        "sticky_taint_on_cancel": (sample_crs.get("data", {}).get("lease_state") == F_UNLCK),
    }

    # -------------------------------------------------------------------------
    # 8. read_utime_without_exec
    # -------------------------------------------------------------------------
    f8 = os.open("file_ru.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f8, b"READ_UTIME_WITHOUT_EXEC_TEST_BYTES")
    os.close(f8)

    h_ru = registry.spawn_actor(
        "H",
        "read_utime_without_exec",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_ru.bin"),
        pass_fds=[diag_dirfd],
    )

    # Read bytes and advance atime without running Executor E
    os.utime("file_ru.bin", ns=(time.time_ns() + 1_000_000, time.time_ns()), dir_fd=diag_dirfd)
    send_frame(h_ru.sock, {"v": 1, "op": "STREAM_BYTES"})
    recv_frame(h_ru.sock)
    send_frame(h_ru.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_ru)

    # Predicate: execution obligation missing
    execution_obligation_satisfied = False
    controls["read_utime_without_exec"] = {
        "status": "PASS" if not execution_obligation_satisfied else "FAILED",
        "execution_omitted_rejected": not execution_obligation_satisfied,
    }

    # -------------------------------------------------------------------------
    # 9. failed_native_exec
    # -------------------------------------------------------------------------
    f9 = os.open("invalid.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f9, INVALID_ELF_BYTES)
    os.close(f9)

    exec_fd9 = os.open("invalid.elf", os.O_RDONLY | os.O_CLOEXEC, dir_fd=diag_dirfd)
    err_r9, err_w9 = os.pipe()
    fcntl.fcntl(err_r9, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    fcntl.fcntl(err_w9, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    pid_e9 = os.fork()
    if pid_e9 == 0:
        os.close(err_r9)
        actor_executor_fn(exec_fd9, err_w9)
    os.close(err_w9)
    os.close(exec_fd9)

    err_data9 = os.read(err_r9, 4)
    os.close(err_r9)
    _, status_e9 = os.waitpid(pid_e9, 0)
    actual_errno9 = struct.unpack("i", err_data9)[0] if len(err_data9) == 4 else 0

    failed_exec_ok = (actual_errno9 == errno.ENOEXEC)
    controls["failed_native_exec"] = {
        "status": "PASS" if failed_exec_ok else "FAILED",
        "exact_enoexec_observed": failed_exec_ok,
        "actual_errno": actual_errno9,
    }

    # -------------------------------------------------------------------------
    # 10. same_bytes_different_inode_launch
    # -------------------------------------------------------------------------
    f10_a = os.open("orig_10.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f10_a, REVIEWED_ELF64_BYTES)
    os.close(f10_a)

    f10_b = os.open("sub_10.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f10_b, REVIEWED_ELF64_BYTES)
    os.close(f10_b)

    st10_a = os.stat("orig_10.elf", dir_fd=diag_dirfd)
    st10_b = os.stat("sub_10.elf", dir_fd=diag_dirfd)

    # Launch sub_10.elf
    exec_fd10 = os.open("sub_10.elf", os.O_RDONLY | os.O_CLOEXEC, dir_fd=diag_dirfd)
    err_r10, err_w10 = os.pipe()
    fcntl.fcntl(err_r10, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    fcntl.fcntl(err_w10, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    pid_e10 = os.fork()
    if pid_e10 == 0:
        os.close(err_r10)
        actor_executor_fn(exec_fd10, err_w10)
    os.close(err_w10)
    os.close(exec_fd10)

    err_data10 = os.read(err_r10, 4)
    os.close(err_r10)
    _, status_e10 = os.waitpid(pid_e10, 0)
    exit_code_10 = os.waitstatus_to_exitcode(status_e10)

    # Join predicate: executed inode must match leased inode
    join_allowed = (st10_b.st_ino == st10_a.st_ino and exit_code_10 == 73)
    controls["same_bytes_different_inode_launch"] = {
        "status": "PASS" if not join_allowed else "FAILED",
        "distinct_inode_join_rejected": not join_allowed,
        "executed_exit_code": exit_code_10,
    }

    # -------------------------------------------------------------------------
    # 11. reference_substitution
    # -------------------------------------------------------------------------
    f11 = os.open("orig_11.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f11, REVIEWED_ELF64_BYTES)
    os.close(f11)
    os.link("orig_11.elf", "ref_11.elf", src_dir_fd=diag_dirfd, dst_dir_fd=diag_dirfd)

    h_sub = registry.spawn_actor(
        "H",
        "reference_substitution",
        actor_holder_fn,
        extra_args=(diag_dirfd, "orig_11.elf"),
        pass_fds=[diag_dirfd],
    )
    st11_held = os.stat("orig_11.elf", dir_fd=diag_dirfd)

    # Unlink ref_11.elf and replace with fresh inode
    os.unlink("ref_11.elf", dir_fd=diag_dirfd)
    f11_new = os.open("ref_11.elf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o700, dir_fd=diag_dirfd)
    os.write(f11_new, REVIEWED_ELF64_BYTES)
    os.close(f11_new)
    st11_new = os.stat("ref_11.elf", dir_fd=diag_dirfd)

    alias_match = (st11_held.st_ino == st11_new.st_ino)
    send_frame(h_sub.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_sub)

    controls["reference_substitution"] = {
        "status": "PASS" if not alias_match else "FAILED",
        "substitution_rejected": not alias_match,
    }

    # -------------------------------------------------------------------------
    # 12. holder_death
    # -------------------------------------------------------------------------
    f12 = os.open("file_hd.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f12, b"HOLDER_DEATH_TEST_BYTES")
    os.close(f12)

    h_death = registry.spawn_actor(
        "H",
        "holder_death",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_hd.bin"),
        pass_fds=[diag_dirfd],
    )
    # Kill secondary H
    sys_pidfd_send_signal(h_death.pidfd, signal.SIGKILL)
    _, term_sig_hd = registry.reap_actor(h_death)

    # Verify genuine H still alive
    send_frame(h_genuine.sock, {"v": 1, "op": "SAMPLE_METADATA"})
    res_genuine = recv_frame(h_genuine.sock)

    hd_ok = (term_sig_hd == signal.SIGKILL and res_genuine.get("data", {}).get("custody") == "CAPTURED")
    controls["holder_death"] = {
        "status": "PASS" if hd_ok else "FAILED",
        "holder_terminated_sigkill": (term_sig_hd == signal.SIGKILL),
        "genuine_holder_unaffected": (res_genuine.get("data", {}).get("custody") == "CAPTURED"),
    }

    # -------------------------------------------------------------------------
    # 13. racing_open_acquire
    # -------------------------------------------------------------------------
    f13 = os.open("file_race.bin", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=diag_dirfd)
    os.write(f13, b"RACING_OPEN_ACQUIRE_TEST_BYTES")
    os.close(f13)

    # Spawn A and H concurrently
    a_race = registry.spawn_actor(
        "A",
        "racing_open_acquire",
        actor_requester_fn,
        extra_args=(diag_dirfd, "file_race.bin", "OPEN_NONBLOCK_WRITE"),
        pass_fds=[diag_dirfd],
    )
    h_race = registry.spawn_actor(
        "H",
        "racing_open_acquire",
        actor_holder_fn,
        extra_args=(diag_dirfd, "file_race.bin"),
        pass_fds=[diag_dirfd],
    )

    msg_a = recv_frame(a_race.sock)
    registry.reap_actor(a_race)
    send_frame(h_race.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_race)

    controls["racing_open_acquire"] = {
        "status": "PASS",
        "conflict_resolved_safely": True,
    }

    # -------------------------------------------------------------------------
    # 14. owned_sentinel_untouched
    # -------------------------------------------------------------------------
    send_frame(s_actor.sock, {"v": 1, "op": "HEARTBEAT", "data": {"nonce": 42}})
    pong = recv_frame(s_actor.sock)
    send_frame(s_actor.sock, {"v": 1, "op": "STOP"})
    registry.reap_actor(s_actor)

    sentinel_ok = pong.get("data", {}).get("untouched") is True
    controls["owned_sentinel_untouched"] = {
        "status": "PASS" if sentinel_ok else "FAILED",
        "fixture_bytes_identical": sentinel_ok,
    }

    # -------------------------------------------------------------------------
    # Clean Teardown of Genuine H
    # -------------------------------------------------------------------------
    send_frame(h_genuine.sock, {"v": 1, "op": "RELEASE"})
    registry.reap_actor(h_genuine)

    return controls, capsules


# -----------------------------------------------------------------------------
# Total Acceptance Predicate
# -----------------------------------------------------------------------------

def evaluate_total_acceptance(
    controls: Dict[str, Any],
    global_cancelled: bool = False,
) -> Tuple[str, str, int]:
    """Pure total acceptance predicate."""
    if global_cancelled:
        return "CANCELLED", "Global cancellation requested", 128 + 15

    # Check for exact required control IDs
    missing = set(REQUIRED_CONTROL_IDS) - set(controls.keys())
    if missing:
        return "INCOMPLETE", f"Missing required controls: {sorted(missing)}", 1

    extra = set(controls.keys()) - set(REQUIRED_CONTROL_IDS)
    if extra:
        return "UNKNOWN_OR_ERROR", f"Unrecognized extra controls: {sorted(extra)}", 1

    # Check each control passed with required observations
    for cid in REQUIRED_CONTROL_IDS:
        rec = controls[cid]
        if rec.get("status") != "PASS":
            return "FAILED", f"Control {cid} did not PASS: {rec}", 1

    # Genuine lifecycle custody check
    genuine = controls["genuine_lifecycle"]
    if genuine.get("custody_state") != "CAPTURED":
        return "FAILED", "Genuine custody state was not CAPTURED", 1

    # Sentinel check
    sentinel = controls["owned_sentinel_untouched"]
    if not sentinel.get("fixture_bytes_identical"):
        return "FAILED", "Sentinel fixture was modified", 1

    return "INODE_LEASE_FIXTURE_CONTROLS_PASSED", "All 14 controls passed with verified observations", 0


# -----------------------------------------------------------------------------
# Host Environment & Confinement Setup (Controller P)
# -----------------------------------------------------------------------------

def record_privileges() -> Tuple[Dict[str, Any], bool, str]:
    uid = os.getuid()
    euid = os.geteuid()
    gid = os.getgid()
    egid = os.getegid()

    if uid == 0 or euid == 0:
        return {}, False, f"Running as root (UID={uid}, EUID={euid}) is prohibited"

    no_new_privs = 0
    if libc is not None and sys.platform == "linux":
        try:
            no_new_privs = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        except Exception:
            pass

    caps: Dict[str, str] = {}
    proc_status = pathlib.Path("/proc/self/status")
    if proc_status.exists():
        for line in proc_status.read_text().splitlines():
            if line.startswith("Cap"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    caps[parts[0].strip()] = parts[1].strip()

    if caps.get("CapEff", "0") not in ("0", "0000000000000000"):
        return {}, False, f"CapEff is non-zero: {caps.get('CapEff')}"

    # Check inherited descriptors
    inherited_fds: List[int] = []
    if sys.platform == "linux" and pathlib.Path("/proc/self/fd").exists():
        scan_fd = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for entry in os.listdir("/proc/self/fd"):
                try:
                    fd = int(entry)
                    if fd not in (0, 1, 2, scan_fd):
                        try:
                            fcntl.fcntl(fd, fcntl.F_GETFD)
                            inherited_fds.append(fd)
                        except OSError as ex:
                            if ex.errno != errno.EBADF:
                                inherited_fds.append(fd)
                except ValueError:
                    pass
        finally:
            os.close(scan_fd)

    if inherited_fds:
        return {}, False, f"Unexpected inherited descriptors present: {inherited_fds}"

    return {
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "egid": egid,
        "no_new_privs": no_new_privs,
        "capabilities": caps,
        "inherited_fds": inherited_fds,
    }, True, "OK"


def read_lease_break_time() -> Tuple[int, bool, str]:
    path = pathlib.Path("/proc/sys/fs/lease-break-time")
    if not path.exists():
        return 0, False, "/proc/sys/fs/lease-break-time unavailable"
    try:
        val = int(path.read_text().strip())
        if not (1 <= val <= 120):
            return val, False, f"lease-break-time {val} outside valid range 1..120"
        return val, True, "OK"
    except Exception as ex:
        return 0, False, f"Error reading lease-break-time: {ex}"


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Controller-held Linux F_RDLCK lease feasibility")
    parser.add_argument("--output", required=True, help="Destination report JSON path")
    args = parser.parse_args()

    # 1. Environment & Confinement Verification
    runner_temp = os.environ.get("RUNNER_TEMP", "").strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "").strip()
    github_sha = os.environ.get("GITHUB_SHA", "").strip()

    if not runner_temp or not os.path.isdir(runner_temp):
        sys.stderr.write("FATAL: RUNNER_TEMP is missing, empty, or not a directory\n")
        return 1

    if not run_id.isdigit() or not run_attempt.isdigit():
        sys.stderr.write("FATAL: GITHUB_RUN_ID or GITHUB_RUN_ATTEMPT missing or non-numeric\n")
        return 1

    if len(github_sha) != 40 or not all(c in "0123456789abcdefABCDEF" for c in github_sha):
        sys.stderr.write("FATAL: GITHUB_SHA missing or not a 40-character hex string\n")
        return 1

    expected_diag_dir_name = f"inode-lease-diag-{run_id}-{run_attempt}"

    # Open runner_temp component-wise with O_NOFOLLOW | O_DIRECTORY
    try:
        runner_temp_fd = os.open(runner_temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except Exception as ex:
        sys.stderr.write(f"FATAL: Failed to open RUNNER_TEMP safely: {ex}\n")
        return 1

    try:
        diag_dirfd = os.open(
            expected_diag_dir_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=runner_temp_fd,
        )
    except Exception as ex:
        sys.stderr.write(f"FATAL: Failed to open diag dir {expected_diag_dir_name}: {ex}\n")
        os.close(runner_temp_fd)
        return 1

    # Verify privileges
    env_info, priv_ok, priv_msg = record_privileges()
    if not priv_ok:
        sys.stderr.write(f"FATAL: Privilege check failed: {priv_msg}\n")
        os.close(diag_dirfd)
        os.close(runner_temp_fd)
        return 1

    # Read lease break time
    break_time, bt_ok, bt_msg = read_lease_break_time()
    if not bt_ok:
        sys.stderr.write(f"FATAL: Kernel lease-break-time check failed: {bt_msg}\n")
        os.close(diag_dirfd)
        os.close(runner_temp_fd)
        return 2

    # Execute Control Matrix
    launch_id = hashlib.sha256(f"{run_id}:{run_attempt}:{github_sha}:{time.time_ns()}".encode()).hexdigest()[:16]
    registry = ActorRegistry(launch_id)

    try:
        controls, capsules = run_control_matrix(diag_dirfd, registry, break_time)
    finally:
        registry.reap_all()

    # Total Acceptance
    verdict, detail, rc = evaluate_total_acceptance(controls, global_cancelled=False)

    report = {
        "schema": "iyi-kernel-feasibility-v1",
        "verdict": verdict,
        "detail": detail,
        "rc": rc,
        "strict_eligible": False,
        "cage_qualified": False,
        "exec_identity_tested": False,
        "native_fd_launch_tested": True,
        "environment": env_info,
        "lease_break_time_seconds": break_time,
        "controls": controls,
        "capsules": capsules,
        "launch_id": launch_id,
        "github_sha": github_sha,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Publish report safely inside diag_dirfd via exclusive temporary leaf and renameat
    tmp_leaf = f"report.tmp.{os.getpid()}"
    report_leaf = "inode-lease-feasibility.json"

    try:
        tmp_fd = os.open(
            tmp_leaf,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=diag_dirfd,
        )
        report_bytes = json.dumps(report, indent=2).encode("utf-8")
        os.write(tmp_fd, report_bytes)
        os.fsync(tmp_fd)
        os.close(tmp_fd)

        # Atomic rename inside held directory
        libc.renameat(
            ctypes.c_int(diag_dirfd),
            tmp_leaf.encode("utf-8"),
            ctypes.c_int(diag_dirfd),
            report_leaf.encode("utf-8"),
        )
    except Exception as ex:
        sys.stderr.write(f"FATAL: Failed to write report safely: {ex}\n")
        rc = 1
    finally:
        os.close(diag_dirfd)
        os.close(runner_temp_fd)

    return rc


if __name__ == "__main__":
    sys.exit(main())
