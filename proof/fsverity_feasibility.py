#!/usr/bin/env python3
"""
proof/fsverity_feasibility.py: In-process nonroot owned-file fs-verity feasibility probe.

Evaluates kernel and filesystem fs-verity feasibility directly in Python using standard
library calls and Linux UAPI ioctls (FS_IOC_ENABLE_VERITY, FS_IOC_MEASURE_VERITY).

Follows SimplifyKernelQualification specification (section 2):
1. Verifies nonroot identity, zero effective/permitted/inheritable/ambient capabilities,
   and no_new_privs.
2. Opens its private directory by descriptor.
3. Exclusively creates one small regular file, mode 0600, containing fixed known bytes.
   Rejects existing paths, symlinks, unexpected ownership, type, size, or link count.
4. Demonstrates ordinary writing works, then closes every writable descriptor.
5. Opens the file read-only and retains that descriptor throughout.
6. Records fstat identity and bounded raw SHA-256.
7. Calls FS_IOC_ENABLE_VERITY with a zero-initialized version-1 argument and SHA-256 parameters.
8. Calls FS_IOC_MEASURE_VERITY; requires expected algorithm and digest length.
9. Verifies device, inode, size, and raw bytes remain unchanged.
10. Attempts one ordinary write-open and requires the verity-enforced refusal.
11. Closes descriptors and publishes the diagnostic result (schema: iyi-kernel-feasibility-v1),
    including the exact retained fixture path.

The fixture is explicitly retained (no deletion or cleanup). An interrupted probe yields
incomplete evidence; no custom process reclamation is used.

Outcomes:
- FS_VERITY_SUPPORTED_ON_TESTED_MOUNT (exit 0)
- UNAVAILABLE_ON_TESTED_PATH (exit 2)
- UNKNOWN_OR_ERROR (exit 1)
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import stat
import struct
import sys


FS_IOC_ENABLE_VERITY = (1 << 30) | (128 << 16) | (ord('f') << 8) | 133
FS_IOC_MEASURE_VERITY = (3 << 30) | (4 << 16) | (ord('f') << 8) | 134
FS_VERITY_HASH_ALG_SHA256 = 1


def record_privileges() -> tuple[dict, bool, str]:
    """Inspect and verify nonroot identity, capabilities, and no_new_privs."""
    uid = os.getuid()
    euid = os.geteuid()
    gid = os.getgid()
    egid = os.getegid()

    env_info = {
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "egid": egid,
        "no_new_privs": "UNKNOWN",
        "capabilities": {},
    }

    if uid == 0 or euid == 0:
        return env_info, False, f"Running as root (uid={uid}, euid={euid}); nonroot required"

    # Check capabilities via /proc/self/status on Linux
    proc_status = pathlib.Path("/proc/self/status")
    if proc_status.exists():
        caps = {}
        for line in proc_status.read_text(encoding="utf-8", errors="replace").splitlines():
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                if line.startswith(f"{key}:"):
                    caps[key] = line.split(":", 1)[1].strip()
        env_info["capabilities"] = caps

        # Enforce zero effective, permitted, inheritable, and ambient capabilities per planner.
        # Strictly fail closed if any required capability field is missing or malformed.
        for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            val = caps.get(key)
            if val is None:
                return env_info, False, f"Missing capability field {key} in /proc/self/status"
            try:
                if int(val, 16) != 0:
                    return env_info, False, f"Capability {key} is non-zero (0x{val}); zero capabilities required"
            except ValueError:
                return env_info, False, f"Malformed capability field {key}: {val}"

        # Record CapBnd without requiring it zero, but fail closed if missing or malformed
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
    # Check and establish no_new_privs via prctl
    if sys.platform.startswith("linux"):
        try:
            import ctypes
            libc = ctypes.CDLL(None)
            PR_SET_NO_NEW_PRIVS = 38
            PR_GET_NO_NEW_PRIVS = 39
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


def publish_report(
    output_path: pathlib.Path,
    result: str,
    detail: str,
    fixture_path: pathlib.Path | None,
    env_info: dict,
    details: dict | None = None,
) -> None:
    """Publish diagnostic report strictly under iyi-kernel-feasibility-v1 schema."""
    report = {
        "schema": "iyi-kernel-feasibility-v1",
        "strict_eligible": False,
        "probe_type": "fsverity",
        "result": result,
        "detail": detail,
        "retained_fixture_path": str(fixture_path) if fixture_path else None,
        "environment": env_info,
        "details": details or {},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    temp_path.replace(output_path)
    print(f"[FSVERITY_PROBE] Published report: {output_path} (result={result})", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="In-process fs-verity feasibility probe")
    parser.add_argument("--dir", required=True, help="Private directory for fixture creation")
    parser.add_argument("--output", required=True, help="Path for diagnostic result JSON report")
    args = parser.parse_args()

    private_dir = pathlib.Path(args.dir).resolve()
    output_path = pathlib.Path(args.output).resolve()
    fixture_path = private_dir / "fsverity_fixture.dat"

    print("=== fs-verity In-Process Feasibility Probe ===", flush=True)
    print(f"Target private directory: {private_dir}", flush=True)
    print(f"Diagnostic output: {output_path}", flush=True)

    # 1. Verify privileges and capabilities
    env_info, privs_ok, priv_msg = record_privileges()
    if not privs_ok:
        print(f"FAILED: Privilege verification failed: {priv_msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", priv_msg, None, env_info)
        return 1

    # 2. Open private directory by descriptor
    try:
        dir_fd = os.open(private_dir, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except Exception as e:
        msg = f"Failed to open private directory by descriptor: {e}"
        print(f"FAILED: {msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info)
        return 1

    ro_fd = -1
    try:
        # 3. Exclusively create one small regular file, mode 0600, containing fixed known bytes
        # Reject existing paths, symlinks, unexpected ownership, type, size, or link count
        if fixture_path.exists(follow_symlinks=False):
            msg = f"Fixture path already exists before exclusive creation: {fixture_path}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        try:
            fd = os.open(
                fixture_path.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=dir_fd,
            )
        except Exception as e:
            msg = f"Exclusive fixture creation failed: {e}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        # Write fixed known bytes
        fixed_payload = b"iyi-kernel-fsverity-feasibility-payload-20261109\n" * 64
        expected_size = len(fixed_payload)
        os.write(fd, fixed_payload)

        # Inspect initial metadata
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            msg = f"Created fixture is not a regular file (mode=0{st.st_mode:o})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st.st_size != expected_size:
            os.close(fd)
            msg = f"Fixture size mismatch: {st.st_size} vs expected {expected_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st.st_uid != os.getuid():
            os.close(fd)
            msg = f"Fixture uid mismatch: {st.st_uid} vs {os.getuid()}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st.st_nlink != 1:
            os.close(fd)
            msg = f"Fixture link count mismatch: {st.st_nlink} vs expected 1"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if (st.st_mode & 0o777) != 0o600:
            os.close(fd)
            msg = f"Fixture permissions mismatch: 0{st.st_mode & 0o777:o} vs expected 0600"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        # 4. Demonstrate ordinary writing works, then close every writable descriptor
        control_marker = b"\nCONTROL_WRITABLE_CHECK"
        os.write(fd, control_marker)
        os.ftruncate(fd, expected_size)
        os.close(fd)
        print("[CONTROL_POSITIVE] Ordinary writing and truncation on fixture succeeded", flush=True)

        # 5. Open the file read-only with O_NOFOLLOW and retain that descriptor throughout
        ro_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            ro_fd = os.open(fixture_path.name, ro_flags, dir_fd=dir_fd)
        except Exception as e:
            msg = f"Failed to open fixture read-only with O_NOFOLLOW: {e}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        # 6. Revalidate dev/inode against original created file, type, ownership, nlink, mode,
        # exact fixed payload length, and bounded read before ioctl
        st_before = os.fstat(ro_fd)
        if st_before.st_dev != st.st_dev:
            os.close(ro_fd)
            msg = f"Reopened fixture device mismatch: {st_before.st_dev} vs original {st.st_dev}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st_before.st_ino != st.st_ino:
            os.close(ro_fd)
            msg = f"Reopened fixture inode mismatch: {st_before.st_ino} vs original {st.st_ino}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if not stat.S_ISREG(st_before.st_mode):
            os.close(ro_fd)
            msg = f"Reopened fixture is not a regular file (mode=0{st_before.st_mode:o})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st_before.st_uid != os.getuid():
            os.close(ro_fd)
            msg = f"Reopened fixture uid mismatch: {st_before.st_uid} vs {os.getuid()}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st_before.st_nlink != 1:
            os.close(ro_fd)
            msg = f"Reopened fixture link count mismatch: {st_before.st_nlink} vs expected 1"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if (st_before.st_mode & 0o777) != 0o600:
            os.close(ro_fd)
            msg = f"Reopened fixture mode mismatch: 0{st_before.st_mode & 0o777:o} vs expected 0600"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st_before.st_size != expected_size:
            os.close(ro_fd)
            msg = f"Reopened fixture size mismatch: {st_before.st_size} vs expected {expected_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        initial_dev = st_before.st_dev
        initial_ino = st_before.st_ino
        initial_size = st_before.st_size

        # Bounded read of exact fixed payload length
        os.lseek(ro_fd, 0, os.SEEK_SET)
        read_content = os.read(ro_fd, expected_size + 1)
        if len(read_content) != expected_size or read_content != fixed_payload:
            os.close(ro_fd)
            msg = f"Read content mismatch or size out of bounds (got {len(read_content)}, expected {expected_size})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        raw_sha256 = hashlib.sha256(read_content).hexdigest()
        print(f"[FIXTURE_IDENTITY] dev={initial_dev} ino={initial_ino} size={initial_size} sha256={raw_sha256}", flush=True)
        # 7. Call FS_IOC_ENABLE_VERITY with a zero-initialized version-1 argument and SHA-256 parameters
        enable_arg = struct.pack("=IIIIQIIQ11Q", 1, FS_VERITY_HASH_ALG_SHA256, 4096, 0, 0, 0, 0, 0, *([0] * 11))
        try:
            fcntl.ioctl(ro_fd, FS_IOC_ENABLE_VERITY, enable_arg)
            print("[FS_IOC_ENABLE_VERITY] Successfully enabled fs-verity on held descriptor", flush=True)
        except OSError as e:
            os.close(ro_fd)
            err_name = errno.errorcode.get(e.errno, str(e.errno))
            if e.errno in (errno.ENOTTY, errno.EOPNOTSUPP):
                msg = f"FS_IOC_ENABLE_VERITY failed with {err_name} ({e.errno}): {os.strerror(e.errno)}"
                print(f"[UNAVAILABLE] {msg}", flush=True)
                publish_report(
                    output_path,
                    "UNAVAILABLE_ON_TESTED_PATH",
                    msg,
                    fixture_path,
                    env_info,
                    details={"errno": e.errno, "errno_name": err_name},
                )
                return 2
            msg = f"FS_IOC_ENABLE_VERITY failed with unexpected error {err_name} ({e.errno}): {os.strerror(e.errno)}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(
                output_path,
                "UNKNOWN_OR_ERROR",
                msg,
                fixture_path,
                env_info,
                details={"errno": e.errno, "errno_name": err_name},
            )
            return 1

        # 8. Call FS_IOC_MEASURE_VERITY; require expected algorithm and digest length
        meas_buf = bytearray(struct.pack("=HH", 0, 64) + b"\x00" * 64)
        try:
            fcntl.ioctl(ro_fd, FS_IOC_MEASURE_VERITY, meas_buf, True)
        except OSError as e:
            os.close(ro_fd)
            err_name = errno.errorcode.get(e.errno, str(e.errno))
            msg = f"FS_IOC_MEASURE_VERITY failed with {err_name} ({e.errno}): {os.strerror(e.errno)}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(
                output_path,
                "UNKNOWN_OR_ERROR",
                msg,
                fixture_path,
                env_info,
                details={"errno": e.errno, "errno_name": err_name},
            )
            return 1

        algo, digest_len = struct.unpack_from("=HH", meas_buf, 0)
        if algo != FS_VERITY_HASH_ALG_SHA256:
            os.close(ro_fd)
            msg = f"FS_IOC_MEASURE_VERITY returned unexpected algorithm {algo}, expected SHA256 (1)"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if digest_len != 32:
            os.close(ro_fd)
            msg = f"FS_IOC_MEASURE_VERITY returned unexpected digest length {digest_len}, expected 32"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        verity_digest_hex = bytes(meas_buf[4:4 + digest_len]).hex()
        print(f"[FS_IOC_MEASURE_VERITY] algo=SHA256 digest={verity_digest_hex}", flush=True)

        # 9. Verify device, inode, size, and raw bytes remain unchanged
        st_after = os.fstat(ro_fd)
        if st_after.st_dev != initial_dev or st_after.st_ino != initial_ino:
            os.close(ro_fd)
            msg = f"Device or inode changed after enable! ({st_after.st_dev},{st_after.st_ino}) vs ({initial_dev},{initial_ino})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        if st_after.st_size != initial_size:
            os.close(ro_fd)
            msg = f"Size changed after enable: {st_after.st_size} vs {initial_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        os.lseek(ro_fd, 0, os.SEEK_SET)
        content_after = os.read(ro_fd, initial_size + 4096)
        if content_after != fixed_payload:
            os.close(ro_fd)
            msg = "Raw file content changed after enable!"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        post_sha256 = hashlib.sha256(content_after).hexdigest()
        if post_sha256 != raw_sha256:
            os.close(ro_fd)
            msg = f"Raw SHA-256 changed after enable: {post_sha256} vs {raw_sha256}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1
        print("[INODE_AND_BYTES_PRESERVED] dev, ino, size, and raw bytes confirmed unchanged", flush=True)

        # 10. Attempt one ordinary write-open and require the verity-enforced refusal
        # Kernel documents EPERM for post-enable write open (ETXTBSY also tolerated)
        write_refused = False
        refusal_errno = None
        try:
            wfd = os.open(fixture_path.name, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
            os.close(wfd)
        except OSError as e:
            write_refused = True
            refusal_errno = e.errno

        if not write_refused:
            os.close(ro_fd)
            msg = "open(O_WRONLY) unexpectedly succeeded on verity-sealed file!"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        refusal_name = errno.errorcode.get(refusal_errno, str(refusal_errno))
        if refusal_errno not in (errno.EPERM, errno.ETXTBSY):
            os.close(ro_fd)
            msg = f"open(O_WRONLY) failed with unexpected errno {refusal_name} ({refusal_errno}), expected EPERM/ETXTBSY"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info)
            return 1

        print(f"[POST_VERITY_WRITE_REFUSAL] open(O_WRONLY) refused with {refusal_name} ({refusal_errno}): PASS", flush=True)

        # 11. Close descriptors and publish diagnostic result
        os.close(ro_fd)
        ro_fd = -1
        os.close(dir_fd)
        dir_fd = -1

        details = {
            "dev": initial_dev,
            "ino": initial_ino,
            "size": initial_size,
            "raw_sha256": raw_sha256,
            "verity_algorithm": algo,
            "verity_digest_length": digest_len,
            "verity_digest_hex": verity_digest_hex,
            "write_refusal_errno": refusal_errno,
            "write_refusal_name": refusal_name,
        }
        publish_report(
            output_path,
            "FS_VERITY_SUPPORTED_ON_TESTED_MOUNT",
            "Unprivileged in-process fs-verity enablement, measurement, byte preservation, and write refusal succeeded",
            fixture_path,
            env_info,
            details=details,
        )
        print("=== fs-verity Feasibility Probe: PASS ===", flush=True)
        return 0

    finally:
        if ro_fd >= 0:
            try:
                os.close(ro_fd)
            except Exception:
                pass
        if dir_fd >= 0:
            try:
                os.close(dir_fd)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
