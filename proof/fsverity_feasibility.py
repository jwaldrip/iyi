#!/usr/bin/env python3
"""
proof/fsverity_feasibility.py: In-process nonroot fs-verity feasibility probe with bounded mount discovery.

Evaluates kernel and filesystem fs-verity feasibility directly in Python using standard
library calls and Linux UAPI ioctls (FS_IOC_ENABLE_VERITY, FS_IOC_MEASURE_VERITY).

Modes:
  --dir <path>: Execute the in-process probe in an absolute path (component-wise nofollow).
  --existing-mounts: Execute read-only census and bounded existing-mount discovery across
                     RUNNER_TEMP, GITHUB_WORKSPACE, HOME, /mnt, deduplicating mount
                     identities, avoiding re-testing root mounts per policy, gating on
                     proven job-local storage, and probing an eligible candidate mount if found.
  --output <path>: Required output path for diagnostic JSON report.

Conforms strictly to ReplanVerityFeasibility and ReviewHostedBoundary:
- Schema: iyi-kernel-feasibility-v1
- strict_eligible: false
- No Docker, no mounts, no root, no device operations, no package installs, no child workloads.
- Component-wise no-follow directory traversal (no Path.resolve() symlink bypass).
- Job-local storage trust anchor: RUNNER_TEMP and GITHUB_WORKSPACE are assumed disposable per
  GitHub Actions platform contract; uncertain HOME and /mnt storage is strictly evaluated
  read-only and never written to without independent proof of disposable job-local lifetime.
- Persistent descriptor-to-mount binding (via /proc/self/fdinfo mnt_id) verified at every step;
  missing or invalid mnt_id in --dir mode fails closed immediately before fixture creation.
- Kernel filesystem identity derived from fstat st_dev and fstatvfs (f_fsid, f_type);
  fstatvfs failures and root inspection failures are sticky and fail closed immediately.
- Inherited-FD scan excludes only its exact opened scan descriptor and rejects live leaks
  (including memfd, socket, pipe, and /proc descriptors) without substring exemptions,
  ignoring closed transient descriptors from os.listdir/fdopendir via fcntl F_GETFD.
- Harmless fixtures are explicitly retained (no deletion/cleanup); diagnostic fixture copy
  uses descriptor-confined complete-write verification, and retention failure is fatal.

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
import secrets
import stat
import struct
import sys


FS_IOC_ENABLE_VERITY = (1 << 30) | (128 << 16) | (ord('f') << 8) | 133
FS_IOC_MEASURE_VERITY = (3 << 30) | (4 << 16) | (ord('f') << 8) | 134
FS_VERITY_HASH_ALG_SHA256 = 1


def open_path_nofollow(path_str: str) -> int:
    """
    Open an absolute directory path component-by-component using O_NOFOLLOW | O_DIRECTORY.
    Strictly avoids Path.resolve() to prevent following symlinks in intermediate path components.
    Fails with OSError (ELOOP/ENOTDIR) if any intermediate component is a symlink.
    """
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


def record_privileges() -> tuple[dict, bool, str]:
    """Inspect and verify nonroot identity, capabilities, no_new_privs, and no unexpected inherited FDs."""
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
    # Open /proc/self/fd directly so the scanner's own descriptor is explicitly known.
    # Entries that were closed by opendir/fdopendir inside os.listdir fail fcntl F_GETFD with
    # EBADF and are ignored. Any live descriptor (> 2 and != scan_fd) is an active leak.
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

                    # 0, 1, 2 are standard stdio; scan_fd is our own temporary scan handle
                    if fd_num in (0, 1, 2) or fd_num == scan_fd:
                        continue

                    # Verify if fd_num is an ACTIVE, OPEN descriptor in this process
                    try:
                        fcntl.fcntl(fd_num, fcntl.F_GETFD)
                    except OSError as e:
                        if e.errno == errno.EBADF:
                            # Transient closed descriptor from opendir/fdopendir inside os.listdir
                            continue
                        raise

                    # If fcntl succeeded, fd_num is an active, open, unexpected inherited descriptor!
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


def parse_mountinfo() -> list[dict]:
    """Parse /proc/self/mountinfo into structured records."""
    mounts = []
    p = pathlib.Path("/proc/self/mountinfo")
    if not p.exists():
        return mounts

    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            sep_idx = parts.index("-")
        except ValueError:
            continue

        mnt_id = int(parts[0])
        parent_id = int(parts[1])
        major_minor = parts[2]
        root = parts[3]
        mount_point = parts[4]
        mount_opts = parts[5].split(",")
        optional_fields = parts[6:sep_idx]
        fstype = parts[sep_idx + 1]
        mount_source = parts[sep_idx + 2]
        super_opts = parts[sep_idx + 3].split(",") if len(parts) > sep_idx + 3 else []

        mounts.append({
            "mnt_id": mnt_id,
            "parent_id": parent_id,
            "major_minor": major_minor,
            "root": root,
            "mount_point": mount_point,
            "mount_opts": mount_opts,
            "optional_fields": optional_fields,
            "fstype": fstype,
            "mount_source": mount_source,
            "super_opts": super_opts,
            "raw": line,
        })
    return mounts


def get_fd_mnt_id(fd: int) -> int | None:
    """Read descriptor's mnt_id from /proc/self/fdinfo/<fd> per proc_pid_fdinfo(5)."""
    fdinfo_path = pathlib.Path(f"/proc/self/fdinfo/{fd}")
    if not fdinfo_path.exists():
        return None
    try:
        for line in fdinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1].strip())
    except Exception:
        pass
    return None


def get_fd_fs_identity(fd: int) -> tuple[int, str, int, int]:
    """
    Derive kernel filesystem identity directly from descriptor via fstat st_dev
    and fstatvfs (f_fsid, f_type). Fails closed on any fstatvfs error rather than
    silently degrading to zero.
    Returns (st_dev, major_minor, f_fsid, f_type).
    """
    st = os.fstat(fd)
    dev = st.st_dev
    major_minor = f"{os.major(dev)}:{os.minor(dev)}"
    vfs = os.fstatvfs(fd)
    fsid = getattr(vfs, "f_fsid", None)
    if fsid is None:
        raise OSError(errno.EIO, f"fstatvfs on fd {fd} did not supply f_fsid")
    ftype = getattr(vfs, "f_type", 0)
    return (dev, major_minor, fsid, ftype)


def record_census() -> dict:
    """Collect read-only census data before discovery."""
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    checkout_sha = os.environ.get("GITHUB_SHA", "UNKNOWN")

    try:
        probe_path = pathlib.Path(__file__).resolve()
        probe_digest = hashlib.sha256(probe_path.read_bytes()).hexdigest()
    except Exception:
        probe_digest = "UNKNOWN"

    runner_image = os.environ.get("ImageOS", "UNKNOWN")
    runner_os = os.environ.get("RUNNER_OS", "UNKNOWN")
    kernel_release = platform.release()

    boot_id_p = pathlib.Path("/proc/sys/kernel/random/boot_id")
    boot_id = boot_id_p.read_text(encoding="utf-8", errors="replace").strip() if boot_id_p.exists() else "UNKNOWN"

    btf_p = pathlib.Path("/sys/kernel/btf/vmlinux")
    btf_digest = "UNKNOWN"
    if btf_p.exists():
        try:
            btf_digest = hashlib.sha256(btf_p.read_bytes()).hexdigest()
        except Exception:
            btf_digest = "UNKNOWN"

    ext4_verity_p = pathlib.Path("/sys/fs/ext4/features/verity")
    if ext4_verity_p.exists():
        try:
            # Distinguish readable vs unreadable error state
            _ = ext4_verity_p.read_text(encoding="utf-8")
            ext4_verity = "present_and_readable"
        except Exception as e:
            ext4_verity = f"unreadable: {e}"
    else:
        ext4_verity = "missing"

    # Kernel configuration and verity signature policy
    kconfig = "UNKNOWN"
    for cand in (pathlib.Path(f"/boot/config-{kernel_release}"), pathlib.Path("/proc/config.gz")):
        if cand.exists():
            try:
                if cand.suffix == ".gz":
                    import gzip
                    content = gzip.decompress(cand.read_bytes()).decode("utf-8", errors="replace")
                else:
                    content = cand.read_text(encoding="utf-8", errors="replace")
                matched = [l for l in content.splitlines() if "VERITY" in l]
                kconfig = matched if matched else "NO_VERITY_ENTRIES"
                break
            except Exception as e:
                kconfig = f"error: {e}"

    sig_policy_p = pathlib.Path("/proc/sys/fs/verity")
    sig_policy = "UNKNOWN"
    if sig_policy_p.exists():
        try:
            sig_policy = {p.name: p.read_text().strip() for p in sig_policy_p.iterdir() if p.is_file()}
        except Exception as e:
            sig_policy = f"error: {e}"

    mounts = parse_mountinfo()

    return {
        "run_id": run_id,
        "run_attempt": run_attempt,
        "checkout_sha": checkout_sha,
        "probe_digest": probe_digest,
        "runner_image": runner_image,
        "runner_os": runner_os,
        "uname": platform.uname()._asdict(),
        "boot_id": boot_id,
        "live_btf_digest": btf_digest,
        "ext4_features_verity": ext4_verity,
        "kernel_config": kconfig,
        "signature_policy": sig_policy,
        "mountinfo": mounts,
        "mount_count": len(mounts),
        "storage_locality_trust_anchor": (
            "RUNNER_TEMP and GITHUB_WORKSPACE are assumed disposable per GitHub Actions "
            "platform contract; HOME and /mnt lack this proof and are strictly evaluated read-only."
        ),
    }


def publish_report(
    output_path: pathlib.Path,
    result: str,
    detail: str,
    fixture_path: pathlib.Path | None,
    env_info: dict,
    details: dict | None = None,
    census: dict | None = None,
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
        "census": census or {},
        "details": details or {},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    temp_path.replace(output_path)
    print(f"[FSVERITY_PROBE] Published report: {output_path} (result={result})", flush=True)


def execute_probe_on_directory_fd(
    dir_fd: int,
    expected_mnt_id: int,
    target_dir_path: pathlib.Path,
    output_path: pathlib.Path,
    env_info: dict,
    census: dict | None = None,
) -> int:
    """
    Execute controlled single-inode fs-verity probe using a held directory descriptor.
    Verifies that the child directory and fixture remain strictly bound to expected_mnt_id.
    """
    fixture_name = "fsverity_fixture.dat"
    fixture_path = target_dir_path / fixture_name
    ro_fd = -1

    try:
        # Exclusively create mode 0600 regular fixture containing fixed known bytes
        if fixture_path.exists(follow_symlinks=False):
            msg = f"Fixture path already exists before exclusive creation: {fixture_path}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        try:
            fd = os.open(
                fixture_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=dir_fd,
            )
        except Exception as e:
            msg = f"Exclusive fixture creation failed: {e}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        # Verify created fixture descriptor mnt_id matches expected mount
        fd_mnt = get_fd_mnt_id(fd)
        if fd_mnt != expected_mnt_id:
            os.close(fd)
            msg = f"Created fixture mnt_id ({fd_mnt}) does not match expected mount ({expected_mnt_id})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        fixed_payload = b"iyi-kernel-fsverity-feasibility-payload-20261109\n" * 64
        expected_size = len(fixed_payload)
        os.write(fd, fixed_payload)

        # Inspect initial metadata on created fd
        st_created = os.fstat(fd)
        if not stat.S_ISREG(st_created.st_mode):
            os.close(fd)
            msg = f"Created fixture is not a regular file (mode=0{st_created.st_mode:o})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_created.st_size != expected_size:
            os.close(fd)
            msg = f"Fixture size mismatch: {st_created.st_size} vs expected {expected_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_created.st_uid != os.getuid():
            os.close(fd)
            msg = f"Fixture uid mismatch: {st_created.st_uid} vs {os.getuid()}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_created.st_nlink != 1:
            os.close(fd)
            msg = f"Fixture link count mismatch: {st_created.st_nlink} vs expected 1"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if (st_created.st_mode & 0o777) != 0o600:
            os.close(fd)
            msg = f"Fixture permissions mismatch: 0{st_created.st_mode & 0o777:o} vs expected 0600"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        initial_dev = st_created.st_dev
        initial_ino = st_created.st_ino
        initial_size = st_created.st_size

        # Writable control check
        control_marker = b"\nCONTROL_WRITABLE_CHECK"
        os.write(fd, control_marker)
        os.ftruncate(fd, expected_size)
        os.close(fd)
        print("[CONTROL_POSITIVE] Ordinary writing and truncation on fixture succeeded", flush=True)

        # Reopen read-only with O_NOFOLLOW relative to held dir_fd
        ro_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            ro_fd = os.open(fixture_name, ro_flags, dir_fd=dir_fd)
        except Exception as e:
            msg = f"Failed to open fixture read-only with O_NOFOLLOW: {e}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        # Verify reopened ro_fd mnt_id matches expected mount
        ro_mnt = get_fd_mnt_id(ro_fd)
        if ro_mnt != expected_mnt_id:
            os.close(ro_fd)
            msg = f"Reopened fixture mnt_id ({ro_mnt}) does not match expected mount ({expected_mnt_id})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        # Revalidate dev/inode against original created file, regular file, ownership,
        # link count, mode 0600, exact fixed payload length, and bounded read
        st_before = os.fstat(ro_fd)
        if st_before.st_dev != initial_dev:
            os.close(ro_fd)
            msg = f"Reopened fixture device mismatch: {st_before.st_dev} vs original {initial_dev}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_before.st_ino != initial_ino:
            os.close(ro_fd)
            msg = f"Reopened fixture inode mismatch: {st_before.st_ino} vs original {initial_ino}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if not stat.S_ISREG(st_before.st_mode):
            os.close(ro_fd)
            msg = f"Reopened fixture is not a regular file (mode=0{st_before.st_mode:o})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_before.st_uid != os.getuid():
            os.close(ro_fd)
            msg = f"Reopened fixture uid mismatch: {st_before.st_uid} vs {os.getuid()}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_before.st_nlink != 1:
            os.close(ro_fd)
            msg = f"Reopened fixture link count mismatch: {st_before.st_nlink} vs expected 1"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if (st_before.st_mode & 0o777) != 0o600:
            os.close(ro_fd)
            msg = f"Reopened fixture mode mismatch: 0{st_before.st_mode & 0o777:o} vs expected 0600"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_before.st_size != initial_size:
            os.close(ro_fd)
            msg = f"Reopened fixture size mismatch: {st_before.st_size} vs expected {initial_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        # Bounded read of exact fixed payload length
        os.lseek(ro_fd, 0, os.SEEK_SET)
        read_content = os.read(ro_fd, expected_size + 1)
        if len(read_content) != expected_size or read_content != fixed_payload:
            os.close(ro_fd)
            msg = f"Read content mismatch or size out of bounds (got {len(read_content)}, expected {expected_size})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        raw_sha256 = hashlib.sha256(read_content).hexdigest()
        print(f"[FIXTURE_IDENTITY] dev={initial_dev} ino={initial_ino} size={initial_size} sha256={raw_sha256}", flush=True)

        # Call FS_IOC_ENABLE_VERITY
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
                    census=census,
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
                census=census,
            )
            return 1

        # Call FS_IOC_MEASURE_VERITY
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
                census=census,
            )
            return 1

        algo, digest_len = struct.unpack_from("=HH", meas_buf, 0)
        if algo != FS_VERITY_HASH_ALG_SHA256:
            os.close(ro_fd)
            msg = f"FS_IOC_MEASURE_VERITY returned unexpected algorithm {algo}, expected SHA256 (1)"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if digest_len != 32:
            os.close(ro_fd)
            msg = f"FS_IOC_MEASURE_VERITY returned unexpected digest length {digest_len}, expected 32"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        verity_digest_hex = bytes(meas_buf[4:4 + digest_len]).hex()
        print(f"[FS_IOC_MEASURE_VERITY] algo=SHA256 digest={verity_digest_hex}", flush=True)

        # Verify device, inode, size, and raw bytes remain unchanged
        st_after = os.fstat(ro_fd)
        if st_after.st_dev != initial_dev or st_after.st_ino != initial_ino:
            os.close(ro_fd)
            msg = f"Device or inode changed after enable! ({st_after.st_dev},{st_after.st_ino}) vs ({initial_dev},{initial_ino})"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        if st_after.st_size != initial_size:
            os.close(ro_fd)
            msg = f"Size changed after enable: {st_after.st_size} vs {initial_size}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        os.lseek(ro_fd, 0, os.SEEK_SET)
        content_after = os.read(ro_fd, initial_size + 4096)
        if content_after != fixed_payload:
            os.close(ro_fd)
            msg = "Raw file content changed after enable!"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        post_sha256 = hashlib.sha256(content_after).hexdigest()
        if post_sha256 != raw_sha256:
            os.close(ro_fd)
            msg = f"Raw SHA-256 changed after enable: {post_sha256} vs {raw_sha256}"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1
        print("[INODE_AND_BYTES_PRESERVED] dev, ino, size, and raw bytes confirmed unchanged", flush=True)

        # Verify write refusal post-enable
        write_refused = False
        refusal_errno = None
        try:
            wfd = os.open(fixture_name, os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
            os.close(wfd)
        except OSError as e:
            write_refused = True
            refusal_errno = e.errno

        if not write_refused:
            os.close(ro_fd)
            msg = "open(O_WRONLY) unexpectedly succeeded on verity-sealed file!"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        refusal_name = errno.errorcode.get(refusal_errno, str(refusal_errno))
        if refusal_errno not in (errno.EPERM, errno.ETXTBSY):
            os.close(ro_fd)
            msg = f"open(O_WRONLY) failed with unexpected errno {refusal_name} ({refusal_errno}), expected EPERM/ETXTBSY"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
            return 1

        print(f"[POST_VERITY_WRITE_REFUSAL] open(O_WRONLY) refused with {refusal_name} ({refusal_errno}): PASS", flush=True)

        # Preserve diagnostic copy of harmless fixture through descriptor before closing ro_fd
        # Complete-write verification ensures no partial/truncated artifact copy is accepted
        if output_path.parent.resolve() != target_dir_path.resolve():
            try:
                copy_path = output_path.parent / "fsverity_fixture.dat.copy"
                copy_fd = os.open(
                    copy_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                try:
                    total_written = 0
                    while total_written < len(fixed_payload):
                        n = os.write(copy_fd, fixed_payload[total_written:])
                        if n <= 0:
                            raise OSError(errno.EIO, f"Short write copying artifact: wrote {total_written} of {len(fixed_payload)} bytes")
                        total_written += n
                    st_copy = os.fstat(copy_fd)
                    if st_copy.st_size != len(fixed_payload):
                        raise OSError(errno.EIO, f"Copied artifact size mismatch: {st_copy.st_size} vs expected {len(fixed_payload)}")
                finally:
                    os.close(copy_fd)
                print(f"[ARTIFACT] Preserved diagnostic copy of harmless fixture: {copy_path} ({total_written} bytes)", flush=True)
            except Exception as e:
                # Retention failure is fatal
                os.close(ro_fd)
                msg = f"CRITICAL: Failed to preserve diagnostic fixture copy: {e}"
                print(f"FAILED: {msg}", flush=True)
                publish_report(output_path, "UNKNOWN_OR_ERROR", msg, fixture_path, env_info, census=census)
                return 1

        os.close(ro_fd)
        ro_fd = -1

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
            census=census,
        )
        print("=== fs-verity Feasibility Probe: PASS ===", flush=True)
        return 0

    finally:
        if ro_fd >= 0:
            try:
                os.close(ro_fd)
            except Exception:
                pass


def run_probe_on_directory(
    target_dir: pathlib.Path,
    output_path: pathlib.Path,
    env_info: dict,
    census: dict | None = None,
) -> int:
    """Wrapper for --dir mode: opens directory component-wise with no-follow and executes probe."""
    try:
        dir_fd = open_path_nofollow(str(target_dir))
    except Exception as e:
        msg = f"Failed to open target directory component-wise with O_NOFOLLOW: {e}"
        print(f"FAILED: {msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
        return 1

    try:
        mnt_id = get_fd_mnt_id(dir_fd)
        if mnt_id is None or mnt_id <= 0:
            msg = f"MNT_ID_UNRESOLVED: target directory fd mnt_id ({mnt_id}) could not be resolved from fdinfo"
            print(f"FAILED: {msg}", flush=True)
            publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
            return 1
        return execute_probe_on_directory_fd(dir_fd, mnt_id, target_dir, output_path, env_info, census=census)
    finally:
        os.close(dir_fd)


def run_existing_mounts_discovery(output_path: pathlib.Path, env_info: dict) -> int:
    """Execute read-only census and bounded existing-mount discovery across candidate bases."""
    print("=== fs-verity Bounded Mount Discovery ===", flush=True)
    census = record_census()
    mounts = census.get("mountinfo", [])
    mount_by_id = {m["mnt_id"]: m for m in mounts}

    # Bounded candidate bases in strict order per ReplanVerityFeasibility
    # RUNNER_TEMP and GITHUB_WORKSPACE are assumed disposable per GitHub Actions platform contract.
    # Uncertain storage (HOME and /mnt) lacks this disposable proof and is strictly evaluated read-only.
    candidate_base_specs = [
        ("RUNNER_TEMP", os.environ.get("RUNNER_TEMP"), True),           # Disposable platform-contract storage
        ("GITHUB_WORKSPACE", os.environ.get("GITHUB_WORKSPACE"), True), # Disposable platform-contract storage
        ("HOME", os.environ.get("HOME"), False),                        # Uncertain locality: evaluated read-only
        ("/mnt", "/mnt" if os.path.exists("/mnt") else None, False),    # Uncertain locality: evaluated read-only
    ]

    print(f"Inspecting {len(candidate_base_specs)} candidate base paths in order...", flush=True)

    tested_devs = set()
    tested_fsids = set()

    # Identify the root filesystem identity from "/" mount descriptor
    # Policy: exclude current root filesystem to avoid repeating earlier tested root-path attempt,
    # without asserting its underlying feature configuration.
    # Failure to inspect root filesystem is a STICKY error: discovery must fail closed
    try:
        root_fd = open_path_nofollow("/")
        try:
            root_dev, root_major_minor, root_fsid, _ = get_fd_fs_identity(root_fd)
            print(f"[CENSUS] Root filesystem identity: dev={root_dev} ({root_major_minor}), fsid={root_fsid}", flush=True)
        finally:
            os.close(root_fd)
    except Exception as e:
        msg = f"ROOT_IDENTITY_FAILURE: failed to inspect root filesystem identity: {e}"
        print(f"FAILED (STICKY ERROR): {msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
        return 1

    evaluated_candidates = []
    eligible_candidate = None
    target_probe_fd = -1
    target_dir_path = None
    target_mnt_id = None

    try:
        for label, base_raw, is_job_local_storage in candidate_base_specs:
            if not base_raw:
                evaluated_candidates.append({
                    "label": label,
                    "status": "NOT_SET_OR_MISSING",
                })
                continue

            # Component-wise no-follow open: strictly avoids Path.resolve()
            try:
                base_fd = open_path_nofollow(base_raw)
            except Exception as e:
                evaluated_candidates.append({
                    "label": label,
                    "path": base_raw,
                    "status": f"COMPONENT_NOFOLLOW_OPEN_FAILED: {e}",
                })
                continue

            try:
                # 1. Job-local runner storage ownership check
                st_base = os.fstat(base_fd)
                if not stat.S_ISDIR(st_base.st_mode):
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "status": "NOT_A_DIRECTORY",
                    })
                    continue

                if st_base.st_uid != os.getuid():
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "st_uid": st_base.st_uid,
                        "expected_uid": os.getuid(),
                        "status": "REJECTED_UNPROVEN_LOCAL_OWNERSHIP (base not owned by runner UID)",
                    })
                    print(f"[DISCOVERY] Rejection: {label} ({base_raw}) is owned by uid {st_base.st_uid}, not runner {os.getuid()}", flush=True)
                    continue

                # 2. Bind descriptor to mountinfo via mnt_id from fdinfo
                mnt_id = get_fd_mnt_id(base_fd)
                if mnt_id is None or mnt_id not in mount_by_id:
                    msg = f"MNT_ID_UNRESOLVED: base {label} fd mnt_id={mnt_id} not verified in mountinfo"
                    print(f"FAILED (STICKY IDENTITY ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                mount_info = mount_by_id[mnt_id]
                fstype = mount_info["fstype"]
                mount_src = mount_info["mount_source"]
                major_minor = mount_info["major_minor"]
                mount_opts = mount_info["mount_opts"]

                # 3. Kernel filesystem identity (dev, major_minor, fsid, ftype) from descriptor
                try:
                    cand_dev, cand_mm, cand_fsid, cand_ftype = get_fd_fs_identity(base_fd)
                except Exception as e:
                    msg = f"FS_IDENTITY_ERROR: failed reading fstatvfs on base {label}: {e}"
                    print(f"FAILED (STICKY IDENTITY ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                # Consistency check: stat st_dev major:minor must match mountinfo major:minor
                if cand_mm != major_minor:
                    msg = f"DEVICE_MISMATCH: base {label} st_dev ({cand_mm}) != mountinfo ({major_minor})"
                    print(f"FAILED (STICKY IDENTITY ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                # 4. Check filesystem type
                if fstype not in ("ext4", "f2fs", "btrfs"):
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "fstype": fstype,
                        "status": f"INELIGIBLE_FSTYPE: {fstype} not in (ext4, f2fs, btrfs)",
                    })
                    continue

                # 5. Must be mounted read-write
                if "rw" not in mount_opts or "ro" in mount_opts:
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "fstype": fstype,
                        "status": "READ_ONLY_MOUNT",
                    })
                    continue

                # 6. Reject shared/network-backed stores
                if any(netfs in fstype.lower() for netfs in ("nfs", "cifs", "fuse", "9p", "virtiofs")):
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "status": f"SHARED_OR_NETWORK_STORE: {fstype}",
                    })
                    continue

                # 7. Deduplicate against root policy exclusion and already-tested filesystems
                is_root_fs = (
                    (root_dev is not None and cand_dev == root_dev) or
                    (root_major_minor is not None and cand_mm == root_major_minor) or
                    (root_fsid is not None and root_fsid != 0 and cand_fsid == root_fsid)
                )
                if is_root_fs:
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "major_minor": major_minor,
                        "status": "POLICY_EXCLUDED_ROOT_FILESYSTEM",
                    })
                    print(f"[DISCOVERY] Skipping {label}: shares policy-excluded root filesystem ({major_minor})", flush=True)
                    continue

                if cand_dev in tested_devs or (cand_fsid != 0 and cand_fsid in tested_fsids):
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "dev": cand_dev,
                        "fsid": cand_fsid,
                        "status": "SKIPPED_ALREADY_EVALUATED_FILESYSTEM",
                    })
                    continue

                # 8. Storage locality predicate: uncertain HOME or /mnt storage is evaluated
                # read-only and rejected for writing unless separate evidence proves disposable job-local lifetime
                if not is_job_local_storage:
                    status_msg = "EVALUATED_READ_ONLY (writes forbidden without independent proof of disposable job-local lifetime)"
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "status": status_msg,
                        "storage_locality": {
                            "trust_anchor": "unproven_for_job_local_disposal",
                            "status": status_msg,
                        },
                    })
                    print(f"[DISCOVERY] Read-only candidate {label}: storage locality not proven disposable job-local; skipping writes", flush=True)
                    continue

                # 9. Unprivileged write access check without elevation
                if not os.access(base_raw, os.W_OK | os.X_OK):
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "status": "PERMISSION_DENIED_UNPRIVILEGED_ACCESS",
                    })
                    continue

                # Candidate is eligible! Create exclusive mode 0700 private probe directory
                nonce = secrets.token_hex(8)
                probe_dir_name = f"fsverity-diag-probe-{nonce}"
                try:
                    os.mkdir(probe_dir_name, mode=0o700, dir_fd=base_fd)
                except Exception as e:
                    msg = f"FAILED_CREATING_PRIVATE_PROBE_DIR in {label}: {e}"
                    print(f"FAILED (STICKY CREATION ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                # Open probe directory descriptor relative to base_fd with O_NOFOLLOW
                try:
                    child_fd = os.open(
                        probe_dir_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=base_fd,
                    )
                except Exception as e:
                    msg = f"FAILED_OPENING_PRIVATE_PROBE_DIR in {label}: {e}"
                    print(f"FAILED (STICKY OPEN ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                # Verify child directory descriptor mnt_id matches base_fd mnt_id
                child_mnt_id = get_fd_mnt_id(child_fd)
                if child_mnt_id != mnt_id:
                    os.close(child_fd)
                    msg = f"MOUNT_BOUNDARY_CROSSED: child probe dir mnt_id ({child_mnt_id}) != base ({mnt_id})"
                    print(f"FAILED (STICKY MOUNT ERROR): {msg}", flush=True)
                    census["evaluated_candidates"] = evaluated_candidates
                    publish_report(output_path, "UNKNOWN_OR_ERROR", msg, None, env_info, census=census)
                    return 1

                tested_devs.add(cand_dev)
                if cand_fsid != 0:
                    tested_fsids.add(cand_fsid)

                target_dir_path = pathlib.Path(base_raw) / probe_dir_name
                eligible_candidate_record = {
                    "label": label,
                    "base_path": base_raw,
                    "target_dir": str(target_dir_path),
                    "mnt_id": mnt_id,
                    "mount_source": mount_src,
                    "major_minor": major_minor,
                    "fstype": fstype,
                    "storage_locality": {
                        "trust_anchor": "github_hosted_platform_contract",
                        "disposable_guarantee": "assumed_from_platform_contract",
                        "verified_runner_ownership": True,
                        "path": base_raw,
                    },
                }
                census["selected_candidate"] = eligible_candidate_record
                census["evaluated_candidates"] = evaluated_candidates

                print(f"[DISCOVERY] Executing probe on eligible candidate {label}: {base_raw} on {mount_src} ({fstype}, mnt_id={mnt_id})", flush=True)
                try:
                    rc = execute_probe_on_directory_fd(
                        child_fd,
                        mnt_id,
                        target_dir_path,
                        output_path,
                        env_info,
                        census=census,
                    )
                finally:
                    os.close(child_fd)

                if rc == 0:
                    # Supported! Complete success.
                    return 0
                elif rc == 2:
                    # UNAVAILABLE_ON_TESTED_PATH: record evaluated candidate and permit next distinct candidate
                    # per ReplanVerityFeasibility:165
                    evaluated_candidates.append({
                        "label": label,
                        "path": base_raw,
                        "mnt_id": mnt_id,
                        "status": "EVALUATED_FS_VERITY_UNAVAILABLE_ON_MOUNT (EOPNOTSUPP/ENOTTY)",
                    })
                    print(f"[DISCOVERY] Candidate {label} returned UNAVAILABLE; continuing to evaluate next distinct candidate...", flush=True)
                    continue
                else:
                    # Error or failure: stop sequence immediately (sticky error)
                    return rc

            finally:
                os.close(base_fd)

        census["evaluated_candidates"] = evaluated_candidates

        # If candidate(s) were evaluated and returned 2 (UNAVAILABLE), re-publish final report with full census
        if tested_devs:
            msg = "fs-verity is unavailable (EOPNOTSUPP/ENOTTY) on tested eligible candidate mount(s)."
            print(f"[STOP] {msg}", flush=True)
            publish_report(
                output_path,
                "UNAVAILABLE_ON_TESTED_PATH",
                msg,
                None,
                env_info,
                details={
                    "evaluated_candidates": evaluated_candidates,
                },
                census=census,
            )
            return 2

        # If no eligible candidate mount exists, stop per planner rule
        msg = (
            "No eligible distinct fs-verity capable mounted filesystem found among candidate bases "
            "(RUNNER_TEMP, GITHUB_WORKSPACE, HOME, /mnt) under verified job-local runner ownership; "
            "stopping after discovery per planner rule."
        )
        print(f"[STOP] {msg}", flush=True)
        publish_report(
            output_path,
            "UNKNOWN_OR_ERROR",
            msg,
            None,
            env_info,
            details={
                "prerequisite_missing": "Eligible mounted filesystem (ext4 -O verity or btrfs) under proven job-local runner storage is not available in current runner environment",
                "evaluated_candidates": evaluated_candidates,
            },
            census=census,
        )
        return 1
    finally:
        if target_probe_fd >= 0:
            try:
                os.close(target_probe_fd)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="In-process fs-verity feasibility probe with bounded mount discovery")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir", help="Private directory for fixture creation (must be an absolute path)")
    group.add_argument("--existing-mounts", action="store_true", help="Bounded discovery on existing mounted filesystems")
    parser.add_argument("--output", required=True, help="Path for diagnostic result JSON report")
    args = parser.parse_args()

    output_path = pathlib.Path(args.output).resolve()

    # 1. Verify privileges and capabilities
    env_info, privs_ok, priv_msg = record_privileges()
    if not privs_ok:
        print(f"FAILED: Privilege verification failed: {priv_msg}", flush=True)
        publish_report(output_path, "UNKNOWN_OR_ERROR", priv_msg, None, env_info)
        return 1

    if args.existing_mounts:
        return run_existing_mounts_discovery(output_path, env_info)
    else:
        # Pass args.dir directly without Path.resolve() so open_path_nofollow can catch symlink components
        return run_probe_on_directory(pathlib.Path(args.dir), output_path, env_info)


if __name__ == "__main__":
    sys.exit(main())
