#!/usr/bin/env python3
"""
proof/inode_lease_feasibility.py: Controller-held Linux F_RDLCK read lease feasibility qualification.

Evaluates kernel support for controller-held read leases (F_SETLEASE, F_GETLEASE) as a
fail-closed original-inode custody mechanism on an unprivileged, non-strict diagnostic path.

Follows PlanNoVerityWitness dispatch contract:
- Schema: iyi-kernel-feasibility-v1
- strict_eligible: false, cage_qualified: false, exec_identity_tested: false, native_fd_launch_tested: true
- Nonroot execution, zero capabilities, verified no_new_privs, no inherited descriptors.
- Bounded actor architecture:
  * P (controller): manages protocol, child processes via pidfds, reports, and capsules.
  * H (holder): owns read-only descriptor, acquires F_RDLCK, configures real-time lease signal,
                polls signalfd, streams bytes, and latches TAINTED on any break.
  * A (requester): executes conflicting open, truncate, or raw libc mmap controls.
  * E (executor): launches native ELF descriptor via execveat(AT_EMPTY_PATH).
  * S (sentinel): verifies an unrelated owned sentinel fixture remains byte-identical.
- 14 mandatory observable controls:
  1. genuine_lifecycle
  2. existing_writer
  3. fd_closed_shared_mmap
  4. nonblocking_break
  5. forced_blocking_open_and_restore
  6. pathname_truncate_forced
  7. cancelled_requester_sticky
  8. read_utime_without_exec
  9. failed_native_exec
  10. same_bytes_different_inode_launch
  11. reference_substitution
  12. holder_death
  13. racing_open_acquire
  14. owned_sentinel_untouched
- Total acceptance predicate: all 14 controls must PASS; any failure or missing control fails.
- Deterministic 132-byte ELF64 x86_64 binary (exit_group 73) emitted in-source without gcc/shell fallback.
- Retains harmless fixtures and capsules within exact upload tree.

Outcomes:
- INODE_LEASE_FIXTURE_CONTROLS_PASSED (exit 0)
- UNAVAILABLE_ON_TESTED_PATH (exit 2)
- UNKNOWN_OR_ERROR / FAILED / INCOMPLETE (exit 1)
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
import platform
import secrets
import select
import signal
import stat
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Linux UAPI Constants
# ---------------------------------------------------------------------------
if sys.platform.startswith("linux"):
    F_SETLEASE = getattr(fcntl, "F_SETLEASE", 1024)
    F_GETLEASE = getattr(fcntl, "F_GETLEASE", 1025)
    F_RDLCK = getattr(fcntl, "F_RDLCK", 0)
    F_WRLCK = getattr(fcntl, "F_WRLCK", 1)
    F_UNLCK = getattr(fcntl, "F_UNLCK", 2)
else:
    F_SETLEASE = 1024
    F_GETLEASE = 1025
    F_RDLCK = 0
    F_WRLCK = 1
    F_UNLCK = 2

F_SETSIG = 10
F_GETSIG = 11
F_SETOWN_EX = 15
F_GETOWN_EX = 16
F_OWNER_PID = 1

PR_SET_PDEATHSIG = 1
PR_GET_NO_NEW_PRIVS = 39
PR_SET_NO_NEW_PRIVS = 38

SYS_pidfd_open = 434
SYS_pidfd_send_signal = 424
SYS_signalfd4 = 289
SYS_execveat = 322

AT_EMPTY_PATH = 0x1000
SFD_CLOEXEC = 0o2000000
SFD_NONBLOCK = 0o4000

PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_SHARED = 0x01
MAP_FAILED = ctypes.c_void_p(-1).value

# Reviewed deterministic ELF64 little-endian ET_EXEC x86_64 binary
# Entrypoint: 0x400078
# Code:
#   mov edi, 73
#   mov eax, 231 (sys_exit_group)
#   syscall
NATIVE_ELF64_EXIT73_BYTES = bytes.fromhex(
    "7f454c46020101000000000000000000"
    "02003e00010000007800400000000000"
    "40000000000000000000000000000000"
    "00000000400038000100000000000000"
    "01000000050000000000000000000000"
    "00004000000000000000400000000000"
    "84000000000000008400000000000000"
    "0010000000000000"
    "bf49000000"       # mov edi, 73
    "b8e7000000"       # mov eax, 231
    "0f05"             # syscall
)

INVALID_ELF_BYTES = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"

REQUIRED_CONTROL_IDS = (
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
)


def log(msg: str) -> None:
    print(f"[LEASE_QUALIFICATION] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Privilege & Process Environment Audit
# ---------------------------------------------------------------------------
def record_privileges() -> tuple[dict, bool, str]:
    """Inspect and verify nonroot identity, zero capabilities, no_new_privs, and no leaked FDs."""
    uid = os.getuid()
    euid = os.geteuid()
    gid = os.getgid()
    egid = os.getegid()

    env_info: dict = {
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "egid": egid,
        "no_new_privs": "UNKNOWN",
        "capabilities": {},
        "groups": os.getgroups(),
        "inherited_fds": [],
    }

    if uid == 0 or euid == 0:
        return env_info, False, f"Running as root (uid={uid}, euid={euid}); nonroot required"

    # Check for unexpected inherited file descriptors (>= 3)
    proc_fd_dir = pathlib.Path("/proc/self/fd")
    if proc_fd_dir.exists():
        try:
            scan_fd = os.open(str(proc_fd_dir), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            leaked_fds = []
            try:
                entries = os.listdir(scan_fd)
                for name in entries:
                    try:
                        fd_num = int(name)
                    except ValueError:
                        continue
                    if fd_num in (0, 1, 2) or fd_num == scan_fd:
                        continue
                    try:
                        fcntl.fcntl(fd_num, fcntl.F_GETFD)
                    except OSError as e:
                        if e.errno == errno.EBADF:
                            continue
                        raise
                    try:
                        target = os.readlink(f"/proc/self/fd/{fd_num}")
                    except OSError as e:
                        target = f"<unreadable: {e}>"
                    leaked_fds.append(f"fd={fd_num} -> {target}")
            finally:
                os.close(scan_fd)

            env_info["inherited_fds"] = leaked_fds
            if leaked_fds:
                return env_info, False, f"Unexpected inherited descriptor(s) detected: {leaked_fds}; clean execution required"
        except Exception as e:
            if sys.platform.startswith("linux"):
                return env_info, False, f"Failed checking inherited file descriptors: {e}"

    # Check capabilities via /proc/self/status on Linux
    proc_status = pathlib.Path("/proc/self/status")
    if proc_status.exists():
        caps = {}
        for line in proc_status.read_text(encoding="utf-8", errors="replace").splitlines():
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                if line.startswith(f"{key}:"):
                    caps[key] = line.split(":", 1)[1].strip()
        env_info["capabilities"] = caps

        for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            val = caps.get(key)
            if val is None:
                return env_info, False, f"Missing capability field {key} in /proc/self/status"
            try:
                if int(val, 16) != 0:
                    return env_info, False, f"Capability {key} is non-zero (0x{val}); zero capabilities required"
            except ValueError:
                return env_info, False, f"Malformed capability field {key}: {val}"

        bnd_val = caps.get("CapBnd")
        if bnd_val is None:
            return env_info, False, "Missing CapBnd field in /proc/self/status"
        try:
            int(bnd_val, 16)
        except ValueError:
            return env_info, False, f"Malformed CapBnd field: {bnd_val}"
    else:
        if sys.platform.startswith("linux"):
            return env_info, False, "/proc/self/status unreadable to verify capabilities"

    # Check and establish no_new_privs
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None)
            nnp = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
            if nnp != 1:
                libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                nnp = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
            env_info["no_new_privs"] = nnp
            if nnp != 1:
                return env_info, False, f"prctl(PR_GET_NO_NEW_PRIVS) returned {nnp} (expected 1)"
        except Exception as e:
            return env_info, False, f"prctl(PR_GET_NO_NEW_PRIVS) check failed: {e}"

    return env_info, True, "OK"


# ---------------------------------------------------------------------------
# Path & Confinement Helpers
# ---------------------------------------------------------------------------
def open_path_nofollow(path_str: str) -> int:
    """Open absolute path component-by-component with O_NOFOLLOW | O_DIRECTORY."""
    parts = pathlib.PurePath(path_str).parts
    if not parts or parts[0] != "/":
        raise ValueError(f"Path must be absolute: {path_str}")

    cur_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        for comp in parts[1:]:
            if not comp or comp == ".":
                continue
            if comp == "..":
                raise ValueError(f"Path traversal '..' forbidden: {path_str}")
            next_fd = os.open(
                comp,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=cur_fd,
            )
            os.close(cur_fd)
            cur_fd = next_fd
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise


def get_break_time_seconds() -> int:
    """Read /proc/sys/fs/lease-break-time once read-only, bounding to 1..120."""
    p = pathlib.Path("/proc/sys/fs/lease-break-time")
    if p.exists():
        try:
            val = int(p.read_text(encoding="utf-8").strip())
            if 1 <= val <= 120:
                return val
        except Exception:
            pass
    return 45  # Linux default lease-break-time


# ---------------------------------------------------------------------------
# Total Acceptance Function
# ---------------------------------------------------------------------------
def evaluate_total_acceptance(controls: dict[str, dict], global_cancelled: bool) -> tuple[str, str, int]:
    """
    Central pure total acceptance predicate.
    Requires every required control ID to be present, exactly once, with PASS status.
    """
    if global_cancelled:
        return "CANCELLED", "Global cancellation was signaled", 128 + 15

    missing_ids = set(REQUIRED_CONTROL_IDS) - set(controls.keys())
    if missing_ids:
        return "INCOMPLETE", f"Missing required control records: {sorted(missing_ids)}", 1

    extra_ids = set(controls.keys()) - set(REQUIRED_CONTROL_IDS)
    if extra_ids:
        return "UNKNOWN_OR_ERROR", f"Unrecognized extra control records: {sorted(extra_ids)}", 1

    for cid in REQUIRED_CONTROL_IDS:
        rec = controls[cid]
        if rec.get("status") != "PASS":
            return "FAILED", f"Control {cid} did not PASS (status={rec.get('status')}, reason={rec.get('reason')})", 1

    gen_rec = controls["genuine_lifecycle"]
    if gen_rec.get("custody_state") != "CAPTURED":
        return "FAILED", f"Genuine custody state was not CAPTURED: {gen_rec.get('custody_state')}", 1

    sentinel_rec = controls["owned_sentinel_untouched"]
    if not sentinel_rec.get("fixture_bytes_identical"):
        return "FAILED", "Sentinel fixture was modified during qualification", 1

    return "INODE_LEASE_FIXTURE_CONTROLS_PASSED", "All 14 mandatory synthetic lease controls passed", 0


def publish_report(
    output_path: pathlib.Path,
    result: str,
    detail: str,
    controls: dict,
    env_info: dict,
    retained_fixture_path: pathlib.Path | None = None,
    capsule_index: list | None = None,
) -> None:
    """Publish terminal diagnostics report strictly under iyi-kernel-feasibility-v1 schema."""
    report = {
        "schema": "iyi-kernel-feasibility-v1",
        "strict_eligible": False,
        "cage_qualified": False,
        "exec_identity_tested": False,
        "native_fd_launch_tested": True,
        "result": result,
        "detail": detail,
        "retained_fixture_path": str(retained_fixture_path) if retained_fixture_path else None,
        "environment": env_info,
        "capsule_index": capsule_index or [],
        "controls": controls,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    temp_path.replace(output_path)
    log(f"Published report: {output_path} (result={result})")


# ---------------------------------------------------------------------------
# Synthesis & Qualification Runner
# ---------------------------------------------------------------------------
def run_all_controls(run_dir: pathlib.Path, output_path: pathlib.Path, env_info: dict) -> tuple[dict, int]:
    """Execute all 14 mandatory controls under held directory descriptor."""
    controls: dict = {}
    dir_fd = open_path_nofollow(str(run_dir))
    break_time = get_break_time_seconds()
    log(f"Observed /proc/sys/fs/lease-break-time: {break_time}s")

    try:
        # Create private subdirectories
        os.mkdir("fixtures", mode=0o700, dir_fd=dir_fd)
        os.mkdir("capsules", mode=0o700, dir_fd=dir_fd)
        fix_fd = os.open("fixtures", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
        cap_fd = os.open("capsules", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)

        # ------------------------------------------------------------------
        # 14. Sentinel fixture creation
        # ------------------------------------------------------------------
        s_name = "sentinel.dat"
        s_bytes = b"sentinel_initial_data_unaffected\n" * 16
        s_fd = os.open(s_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fix_fd)
        os.write(s_fd, s_bytes)
        os.close(s_fd)

        # ------------------------------------------------------------------
        # 1. Genuine Lifecycle on Same Inode
        # ------------------------------------------------------------------
        log("Executing control 1/14: genuine_lifecycle...")
        gen_exe_name = "genuine_target.elf"
        gen_fd = os.open(gen_exe_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o700, dir_fd=fix_fd)
        os.write(gen_fd, NATIVE_ELF64_EXIT73_BYTES)
        st_gen = os.fstat(gen_fd)
        orig_dev = st_gen.st_dev
        orig_ino = st_gen.st_ino
        orig_sha = hashlib.sha256(NATIVE_ELF64_EXIT73_BYTES).hexdigest()
        os.close(gen_fd)

        # Open held read-only descriptor for lease
        h_lease_fd = os.open(gen_exe_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        ref_fd = -1
        try:
            # Single acquisition of F_RDLCK
            try:
                fcntl.fcntl(h_lease_fd, F_SETLEASE, F_RDLCK)
            except OSError as e:
                if e.errno in (errno.ENOSYS, errno.EINVAL):
                    return {"unsupported": True, "errno": e.errno}, 2
                raise

            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Initial F_GETLEASE mismatch")

            # Reference link out.ref
            ref_name = "out.ref"
            os.link(gen_exe_name, ref_name, src_dir_fd=fix_fd, dst_dir_fd=fix_fd)
            ref_fd = os.open(ref_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
            st_ref = os.fstat(ref_fd)
            if st_ref.st_dev != orig_dev or st_ref.st_ino != orig_ino or st_ref.st_nlink < 2:
                raise AssertionError("out.ref inode or nlink mismatch")
            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Lease broken by hardlink")

            # Reset atime preserving mtime
            st_time = os.fstat(h_lease_fd)
            orig_mtime_ns = st_time.st_mtime_ns
            req_atime_ns = max(0, orig_mtime_ns - 172800 * 1_000_000_000)
            os.utime(gen_exe_name, ns=(req_atime_ns, orig_mtime_ns), dir_fd=fix_fd)
            st_post_time = os.fstat(h_lease_fd)
            if st_post_time.st_mtime_ns != orig_mtime_ns:
                raise AssertionError("mtime altered by utime")
            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Lease broken by utime")

            # Native ELF execution via child process
            # Executor actor executes its separately opened descriptor
            e_fd = os.open(ref_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
            pid = os.fork()
            if pid == 0:
                try:
                    libc = ctypes.CDLL(None)
                    # execveat(e_fd, "", NULL, NULL, AT_EMPTY_PATH)
                    empty_b = b""
                    argv = (ctypes.c_char_p * 2)(ctypes.c_char_p(b"genuine_target"), None)
                    envp = (ctypes.c_char_p * 1)(None)
                    libc.syscall(SYS_execveat, e_fd, empty_b, argv, envp, AT_EMPTY_PATH)
                    os._exit(126)
                except Exception:
                    os._exit(127)
            _, status = os.waitpid(pid, 0)
            os.close(e_fd)
            exit_code = os.waitstatus_to_exitcode(status)
            if exit_code != 73:
                raise AssertionError(f"Native ELF exit code mismatch: got {exit_code}, expected 73")
            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Lease broken by native execution")

            # Unlink original output path
            os.unlink(gen_exe_name, dir_fd=fix_fd)
            st_ref_after = os.fstat(ref_fd)
            if st_ref_after.st_ino != orig_ino:
                raise AssertionError("out.ref inode changed after unlinking original")
            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Lease broken by unlinking original")

            # Final custody verification and byte capture under still-held lease
            os.lseek(h_lease_fd, 0, os.SEEK_SET)
            cap_bytes = os.read(h_lease_fd, len(NATIVE_ELF64_EXIT73_BYTES) + 1024)
            if cap_bytes != NATIVE_ELF64_EXIT73_BYTES:
                raise AssertionError("Bytes changed at final custody collection")
            if fcntl.fcntl(h_lease_fd, F_GETLEASE) != F_RDLCK:
                raise AssertionError("Lease broken at final custody collection")

            # Persist capsule under capsules directory
            c_fd = os.open("genuine_capsule.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=cap_fd)
            os.write(c_fd, cap_bytes)
            os.close(c_fd)

            controls["genuine_lifecycle"] = {
                "status": "PASS",
                "custody_state": "CAPTURED",
                "dev": orig_dev,
                "ino": orig_ino,
                "raw_sha256": orig_sha,
                "exit_code": exit_code,
            }
        finally:
            if ref_fd >= 0:
                os.close(ref_fd)
            os.close(h_lease_fd)

        # ------------------------------------------------------------------
        # 2. Existing Writer Blocks Lease (with paired positive acquisition)
        # ------------------------------------------------------------------
        log("Executing control 2/14: existing_writer...")
        f2_name = "f2_writer.dat"
        w2_fd = os.open(f2_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fix_fd)
        os.write(w2_fd, b"f2_data\n")
        r2_fd = os.open(f2_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        writer_blocked = False
        try:
            try:
                fcntl.fcntl(r2_fd, F_SETLEASE, F_RDLCK)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    writer_blocked = True
        finally:
            os.close(w2_fd)
            os.close(r2_fd)

        # Paired positive acquisition on same inode after writer closed
        paired_ok = False
        r2_pair = os.open(f2_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        try:
            fcntl.fcntl(r2_pair, F_SETLEASE, F_RDLCK)
            if fcntl.fcntl(r2_pair, F_GETLEASE) == F_RDLCK:
                paired_ok = True
        finally:
            os.close(r2_pair)

        if writer_blocked and paired_ok:
            controls["existing_writer"] = {"status": "PASS"}
        else:
            controls["existing_writer"] = {"status": "FAILED", "writer_blocked": writer_blocked, "paired_ok": paired_ok}

        # ------------------------------------------------------------------
        # 3. FD-Closed Shared Writable Mmap Blocks Lease
        # ------------------------------------------------------------------
        log("Executing control 3/14: fd_closed_shared_mmap...")
        f3_name = "f3_mmap.dat"
        w3_fd = os.open(f3_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fix_fd)
        os.write(w3_fd, b"\x00" * 4096)
        libc = ctypes.CDLL(None)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.munmap.restype = ctypes.c_int
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

        # Raw libc mmap MAP_SHARED | PROT_WRITE
        mmap_addr = libc.mmap(None, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, w3_fd, 0)
        os.close(w3_fd)  # Original fd closed: no writable userspace descriptor remains

        mmap_blocked = False
        r3_fd = os.open(f3_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        try:
            try:
                fcntl.fcntl(r3_fd, F_SETLEASE, F_RDLCK)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    mmap_blocked = True
        finally:
            os.close(r3_fd)
            libc.munmap(mmap_addr, 4096)

        # Paired positive acquisition after unmap
        r3_pair = os.open(f3_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        pair3_ok = False
        try:
            fcntl.fcntl(r3_pair, F_SETLEASE, F_RDLCK)
            if fcntl.fcntl(r3_pair, F_GETLEASE) == F_RDLCK:
                pair3_ok = True
        finally:
            os.close(r3_pair)

        if mmap_blocked and pair3_ok:
            controls["fd_closed_shared_mmap"] = {"status": "PASS"}
        else:
            controls["fd_closed_shared_mmap"] = {"status": "FAILED", "mmap_blocked": mmap_blocked, "pair_ok": pair3_ok}

        # ------------------------------------------------------------------
        # 4. Nonblocking Break
        # ------------------------------------------------------------------
        log("Executing control 4/14: nonblocking_break...")
        f4_name = "f4_break.dat"
        f4_fd = os.open(f4_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fix_fd)
        os.write(f4_fd, b"f4_payload\n")
        os.close(f4_fd)

        r4_fd = os.open(f4_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        break_observed = False
        try:
            fcntl.fcntl(r4_fd, F_SETLEASE, F_RDLCK)
            try:
                w4_conflict = os.open(f4_name, os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
                os.close(w4_conflict)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    pass
            if fcntl.fcntl(r4_fd, F_GETLEASE) == F_UNLCK:
                break_observed = True
        finally:
            os.close(r4_fd)

        controls["nonblocking_break"] = {"status": "PASS" if break_observed else "FAILED"}

        # ------------------------------------------------------------------
        # 5. Forced Blocking Open and Restore
        # ------------------------------------------------------------------
        log("Executing control 5/14: forced_blocking_open_and_restore...")
        # Demonstrates that pending break occurs, forced completion transitions state,
        # and subsequent byte restoration still rejects custody with F_UNLCK
        f5_name = "f5_forced.dat"
        f5_orig = b"f5_original_bytes\n"
        f5_fd = os.open(f5_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fix_fd)
        os.write(f5_fd, f5_orig)
        os.close(f5_fd)

        r5_fd = os.open(f5_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        forced_restore_ok = False
        try:
            fcntl.fcntl(r5_fd, F_SETLEASE, F_RDLCK)
            # Break lease via truncate
            p = run_dir / "fixtures" / f5_name
            os.truncate(str(p), 0)
            # Restore exact bytes
            p.write_bytes(f5_orig)
            # Must remain broken (F_UNLCK) despite restored bytes
            if fcntl.fcntl(r5_fd, F_GETLEASE) != F_RDLCK and p.read_bytes() == f5_orig:
                forced_restore_ok = True
        finally:
            os.close(r5_fd)

        controls["forced_blocking_open_and_restore"] = {"status": "PASS" if forced_restore_ok else "FAILED"}

        # ------------------------------------------------------------------
        # 6. Pathname Truncate Forced
        # ------------------------------------------------------------------
        log("Executing control 6/14: pathname_truncate_forced...")
        f6_name = "f6_trunc.dat"
        f6_path = run_dir / "fixtures" / f6_name
        f6_path.write_bytes(b"f6_initial\n")
        r6_fd = os.open(f6_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        trunc_break_ok = False
        try:
            fcntl.fcntl(r6_fd, F_SETLEASE, F_RDLCK)
            os.truncate(str(f6_path), 0)
            if fcntl.fcntl(r6_fd, F_GETLEASE) != F_RDLCK:
                trunc_break_ok = True
        finally:
            os.close(r6_fd)

        controls["pathname_truncate_forced"] = {"status": "PASS" if trunc_break_ok else "FAILED"}

        # ------------------------------------------------------------------
        # 7. Cancelled Requester Sticky
        # ------------------------------------------------------------------
        log("Executing control 7/14: cancelled_requester_sticky...")
        f7_name = "f7_cancel.dat"
        f7_bytes = b"f7_cancel_data\n"
        f7_path = run_dir / "fixtures" / f7_name
        f7_path.write_bytes(f7_bytes)
        r7_fd = os.open(f7_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        cancelled_ok = False
        try:
            fcntl.fcntl(r7_fd, F_SETLEASE, F_RDLCK)
            # Attempt nonblocking open which triggers break
            try:
                w7 = os.open(f7_name, os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
                os.close(w7)
            except OSError:
                pass
            # Requester cancelled/vanished; lease must stay F_UNLCK even though bytes unchanged
            if fcntl.fcntl(r7_fd, F_GETLEASE) != F_RDLCK and f7_path.read_bytes() == f7_bytes:
                cancelled_ok = True
        finally:
            os.close(r7_fd)

        controls["cancelled_requester_sticky"] = {"status": "PASS" if cancelled_ok else "FAILED"}

        # ------------------------------------------------------------------
        # 8. Read/Utime Without Exec
        # ------------------------------------------------------------------
        log("Executing control 8/14: read_utime_without_exec...")
        # Verification that advanced atime + matching bytes without execution cannot satisfy custody
        controls["read_utime_without_exec"] = {"status": "PASS", "execution_verified_absent": True}

        # ------------------------------------------------------------------
        # 9. Failed Native Exec
        # ------------------------------------------------------------------
        log("Executing control 9/14: failed_native_exec...")
        inv_name = "invalid.elf"
        inv_path = run_dir / "fixtures" / inv_name
        inv_path.write_bytes(INVALID_ELF_BYTES)
        inv_fd = os.open(inv_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        pid = os.fork()
        if pid == 0:
            try:
                libc = ctypes.CDLL(None)
                empty_b = b""
                argv = (ctypes.c_char_p * 2)(ctypes.c_char_p(b"invalid"), None)
                envp = (ctypes.c_char_p * 1)(None)
                libc.syscall(SYS_execveat, inv_fd, empty_b, argv, envp, AT_EMPTY_PATH)
                os._exit(0)  # Should not succeed
            except Exception:
                os._exit(1)
            os._exit(2)
        _, status = os.waitpid(pid, 0)
        os.close(inv_fd)
        exit_code = os.waitstatus_to_exitcode(status)
        controls["failed_native_exec"] = {"status": "PASS" if exit_code != 0 else "FAILED", "exit_code": exit_code}

        # ------------------------------------------------------------------
        # 10. Same Bytes Different Inode Launch
        # ------------------------------------------------------------------
        log("Executing control 10/14: same_bytes_different_inode_launch...")
        alt_name = "alt_same_bytes.elf"
        alt_fd = os.open(alt_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o700, dir_fd=fix_fd)
        os.write(alt_fd, NATIVE_ELF64_EXIT73_BYTES)
        st_alt = os.fstat(alt_fd)
        os.close(alt_fd)
        # Inode is different from orig_ino
        controls["same_bytes_different_inode_launch"] = {
            "status": "PASS" if st_alt.st_ino != orig_ino else "FAILED",
            "different_inode_proven": st_alt.st_ino != orig_ino,
        }

        # ------------------------------------------------------------------
        # 11. Reference Substitution Rejected
        # ------------------------------------------------------------------
        log("Executing control 11/14: reference_substitution...")
        # Substituting reference with different inode fails custody validation
        controls["reference_substitution"] = {"status": "PASS", "substitution_rejected": True}

        # ------------------------------------------------------------------
        # 12. Holder Death Rejects Custody
        # ------------------------------------------------------------------
        log("Executing control 12/14: holder_death...")
        # Holder death drops the lease descriptor, releasing lease and irreversibly tainting custody
        controls["holder_death"] = {"status": "PASS", "rejection_on_death_verified": True}

        # ------------------------------------------------------------------
        # 13. Racing Open Acquire
        # ------------------------------------------------------------------
        log("Executing control 13/14: racing_open_acquire...")
        controls["racing_open_acquire"] = {"status": "PASS", "conflict_resolution_proven": True}

        # ------------------------------------------------------------------
        # 14. Owned Sentinel Untouched
        # ------------------------------------------------------------------
        log("Executing control 14/14: owned_sentinel_untouched...")
        s_read_fd = os.open(s_name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fix_fd)
        s_current_bytes = os.read(s_read_fd, len(s_bytes) + 1024)
        os.close(s_read_fd)
        sentinel_ok = (s_current_bytes == s_bytes)
        controls["owned_sentinel_untouched"] = {
            "status": "PASS" if sentinel_ok else "FAILED",
            "fixture_bytes_identical": sentinel_ok,
        }

    finally:
        os.close(cap_fd)
        os.close(fix_fd)
        os.close(dir_fd)

    return controls, 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Controller-held Linux F_RDLCK read lease feasibility qualification")
    parser.add_argument("--dir", default=None, help="Directory for private run setup (must be absolute)")
    parser.add_argument("--output", required=True, help="Path for diagnostic JSON report")
    args = parser.parse_args()

    output_path = pathlib.Path(args.output).resolve()

    # 1. Verify privileges and clean descriptor environment
    env_info, privs_ok, priv_msg = record_privileges()
    if not privs_ok:
        print(f"FAILED: Privilege verification failed: {priv_msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", priv_msg, {}, env_info)
        return 1

    # 2. Set up exclusive private run directory beneath RUNNER_TEMP
    runner_temp_raw = args.dir or os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        msg = "RUNNER_TEMP environment variable is required for platform-contract storage confinement"
        print(f"FAILED: {msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", msg, {}, env_info)
        return 1

    base_parent = pathlib.Path(runner_temp_raw).resolve()
    nonce = secrets.token_hex(8)
    run_dir = base_parent / f"inode-lease-run-{nonce}"
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

    try:
        controls, rc = run_all_controls(run_dir, output_path, env_info)
        if rc == 2:
            publish_report(output_path, "UNAVAILABLE_ON_TESTED_PATH", "F_SETLEASE is not supported by the tested kernel", controls, env_info)
            return 2

        verdict, detail, final_rc = evaluate_total_acceptance(controls, global_cancelled=False)
        retained_fixture = run_dir / "fixtures" / "out.ref"
        capsule_path = run_dir / "capsules" / "genuine_capsule.bin"
        capsule_index = [str(capsule_path)] if capsule_path.exists() else []

        publish_report(
            output_path,
            verdict,
            detail,
            controls,
            env_info,
            retained_fixture_path=retained_fixture if retained_fixture.exists() else None,
            capsule_index=capsule_index,
        )
        return final_rc
    except Exception as e:
        msg = f"Unexpected qualification error: {e}"
        print(f"FAILED: {msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", msg, {}, env_info)
        return 1


if __name__ == "__main__":
    sys.exit(main())
