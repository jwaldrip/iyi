#!/usr/bin/env python3
"""Read-only runner inventory, not an approval or a diagnostic launch."""
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import selectors
import stat
import signal
import subprocess
import sys
import time

TOOLS = {
    "clang18": "/usr/bin/clang-18", "gcc": "/usr/bin/gcc-13",
    "readelf": "/usr/bin/readelf", "gpgv": "/usr/bin/gpgv",
    "dpkg-deb": "/usr/bin/dpkg-deb", "setpriv": "/usr/bin/setpriv",
    "sudo": "/usr/bin/sudo",
}
MAX_OUTPUT = 65536
MAX_FILE = 256 * 1024 * 1024
CANCELLED = None
CANCEL_SIGNALS = {signal.SIGTERM, signal.SIGINT}


def check_cancelled():
    if CANCELLED is not None:
        raise CensusCancelled(f"received signal {CANCELLED}")


def child_no_privileges(parent_pid, previous_mask):
    # Install the death signal before checking the parent to close the race.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        raise RuntimeError("cannot establish parent-death protection")
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    # Runs in the owned child before exec, never in the parent.
    if 0 in os.getresuid() or 0 in os.getresgid():
        raise RuntimeError("root real, effective, or saved uid or gid")
    status = pathlib.Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if key not in fields or int(fields[key].strip(), 16) != 0:
            raise RuntimeError(f"nonzero or missing {key}")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError(ctypes.get_errno(), "cannot establish no_new_privs")


def safe_to_execute(name, info):
    if name == "sudo":
        return "privilege-bearing executable: metadata only"
    try:
        if not info.get("regular") or not info.get("canonical"):
            return "missing regular executable"
        path = pathlib.Path(info["canonical"])
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
            return "unsafe owner, writable mode, or set-id bit"
        for parent in (path.parent, *path.parent.parents):
            s = parent.stat()
            if s.st_uid != 0 or s.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return "unsafe canonical ancestor"
        try:
            os.getxattr(path, "security.capability")
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                return f"file capability state unknown: {exc}"
        else:
            return "file capability present"
        return None
    except (OSError, ValueError) as exc:
        return f"cannot establish tool safety: {exc}"


def bounded_command(args):
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("SIGCHLD must have its default disposition")
    check_cancelled()
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
    child = None
    sel = None
    output = bytearray()
    deadline = time.monotonic() + 5
    reason = None
    code = None
    try:
        parent_pid = os.getpid()
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                 start_new_session=True,
                                 preexec_fn=lambda: child_no_privileges(parent_pid, previous_mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        sel = selectors.DefaultSelector()
        sel.register(child.stdout, selectors.EVENT_READ)
        while sel.get_map():
            if CANCELLED is not None:
                reason = "cancelled"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                break
            events = sel.select(min(remaining, 0.1))
            if not events:
                continue
            chunk = os.read(child.stdout.fileno(), min(8192, MAX_OUTPUT + 1 - len(output)))
            if not chunk:
                sel.unregister(child.stdout)
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                reason = "output_limit"
                break
        if reason is None:
            # Observe exit without reaping: the leader PID cannot be reused
            # before the private group has been cleaned up.
            while time.monotonic() < deadline:
                if CANCELLED is not None:
                    reason = "cancelled"
                    break
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None:
                    code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                    break
                time.sleep(0.01)
            else:
                reason = "timeout"
        result = {"exit_code": code, "error": reason,
                  "output": bytes(output[:MAX_OUTPUT]).decode("utf-8", errors="replace")}
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
        try:
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    child.wait(timeout=2)
        finally:
            if sel is not None:
                sel.close()
            if child is not None and child.stdout is not None:
                child.stdout.close()
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    check_cancelled()
    return result


def path_info(value):
    path = pathlib.Path(value)
    chain = []
    current = pathlib.Path("/")
    try:
        for part in path.parts[1:]:
            current = current / part
            st = current.lstat()
            item = {"path": str(current), "uid": st.st_uid,
                    "gid": st.st_gid, "mode": oct(stat.S_IMODE(st.st_mode))}
            if stat.S_ISLNK(st.st_mode):
                item["symlink_target"] = os.readlink(current)
            chain.append(item)
        resolved = path.resolve(strict=True)
        st = resolved.stat()
        ancestors = []
        for ancestor in reversed(resolved.parents):
            parent_stat = ancestor.stat()
            ancestors.append({"path": str(ancestor), "uid": parent_stat.st_uid,
                              "gid": parent_stat.st_gid,
                              "mode": oct(stat.S_IMODE(parent_stat.st_mode))})
        info = {"requested": value, "canonical": str(resolved), "chain": chain,
                "canonical_ancestors": ancestors,
                "uid": st.st_uid, "gid": st.st_gid, "mode": oct(stat.S_IMODE(st.st_mode)),
                "size": st.st_size, "regular": stat.S_ISREG(st.st_mode)}
        if stat.S_ISREG(st.st_mode):
            if st.st_size > MAX_FILE:
                info["hash_error"] = "file_size_limit"
            else:
                h = hashlib.sha256()
                with resolved.open("rb") as stream:
                    remaining = MAX_FILE + 1
                    while remaining:
                        check_cancelled()
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            break
                        h.update(block)
                        remaining -= len(block)
                if remaining == 0:
                    info["hash_error"] = "file_size_limit"
                else:
                    info["sha256"] = h.hexdigest()
        return info
    except (OSError, RuntimeError) as exc:
        return {"requested": value, "chain": chain, "error": str(exc)}


def resource_headers(directory):
    result = {"files": [], "complete": False}
    try:
        root = pathlib.Path(directory).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("resource include is not a directory")
        total = 0
        entries = 0
        def walk_error(exc):
            raise exc
        for base, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            check_cancelled()
            dirs.sort()
            files.sort()
            if any((pathlib.Path(base) / name).is_symlink() for name in dirs):
                raise ValueError(f"resource directory symlink not inventoried: {base}")
            entries += len(dirs) + len(files)
            if entries > 8192:
                raise ValueError("resource entry limit exceeded")
            for name in files:
                check_cancelled()
                path = pathlib.Path(base) / name
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    raise ValueError(f"resource header escapes root: {path}")
                st = resolved.stat()
                if not stat.S_ISREG(st.st_mode) or st.st_size > 16 * 1024 * 1024:
                    raise ValueError(f"unsupported resource header: {path}")
                total += st.st_size
                if total > 64 * 1024 * 1024:
                    raise ValueError("resource byte limit exceeded")
                result["files"].append(path_info(str(path)))
        result["complete"] = True
    except (OSError, RuntimeError, ValueError) as exc:
        result["error"] = str(exc)
    return result


class CensusCancelled(BaseException):
    pass


def interrupted(signum, frame):
    global CANCELLED
    CANCELLED = signum


def main():
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        sys.exit("SIGCHLD must have its default disposition")
    if len(sys.argv) != 2:
        sys.exit("usage: bpf_tool_census.py OUTPUT_DIRECTORY")
    checkout_sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if re.fullmatch(r"[0-9a-fA-F]{40}", checkout_sha) is None:
        sys.exit("GITHUB_SHA must be a 40-character hexadecimal commit ID")
    for name, value in (("GITHUB_RUN_ID", run_id), ("GITHUB_RUN_ATTEMPT", run_attempt)):
        if re.fullmatch(r"[0-9]+", value) is None or not any(c != "0" for c in value):
            sys.exit(f"{name} must be a positive ASCII decimal integer")
    root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    runner = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    st = root.stat()
    if not root.is_dir() or root == runner or not root.is_relative_to(runner) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        sys.exit("census output directory must be runner-owned mode 0700 under RUNNER_TEMP")
    uname = os.uname()
    report = {"schema": "iyi-bpf-tool-census-v1", "strict_eligible": False,
              "checkout_sha": checkout_sha, "run_id": run_id, "run_attempt": run_attempt,
              "repository": os.environ.get("GITHUB_REPOSITORY"), "ref": os.environ.get("GITHUB_REF"),
              "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
              "kernel": {"sysname": uname.sysname, "nodename": uname.nodename,
                         "release": uname.release, "version": uname.version,
                         "machine": uname.machine}, "tools": {}}
    for name, path in TOOLS.items():
        check_cancelled()
        info = path_info(path)
        reason = safe_to_execute(name, info)
        if reason is None:
            try:
                info["version"] = bounded_command([info["canonical"], "--version"])
            except (OSError, subprocess.SubprocessError) as exc:
                info["version"] = {"error": str(exc), "exit_code": None}
        else:
            info["version"] = {"error": reason, "exit_code": None}
        report["tools"][name] = info
    # Compare the driver with the existing, source-bound census immediately
    # before using it to query the include root. No baseline is updated here.
    baseline_file = pathlib.Path(__file__).resolve().with_name("bpf_runner_baseline.py")
    spec = importlib.util.spec_from_file_location("bpf_runner_baseline", baseline_file)
    if spec is None or spec.loader is None:
        raise ValueError("reviewed runner baseline verifier unavailable")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    raw_baseline = gate.BASELINE.read_bytes()
    if hashlib.sha256(raw_baseline).hexdigest() != gate.CENSUS_SHA256:
        raise ValueError("reviewed runner baseline digest mismatch")
    gcc_expected = json.loads(raw_baseline)["tools"]["gcc"]
    gate.check_path(gcc_expected, True)
    gcc = report["tools"]["gcc"]
    gcc_version = gcc.get("version", {})
    if (safe_to_execute("gcc", gcc) is not None or
            gcc.get("canonical") != gcc_expected["canonical"] or
            gcc_version.get("error") is not None or gcc_version.get("exit_code") != 0 or
            gcc_version.get("output") != gcc_expected["version"]["output"]):
        raise ValueError("GCC driver differs from reviewed baseline")
    gcc_root = "/usr/lib/gcc/x86_64-linux-gnu/13/include"
    gcc_command = bounded_command([gcc["canonical"], "-print-file-name=include"])
    report["gcc_include_command"] = gcc_command
    if (gcc_command["exit_code"] != 0 or gcc_command["error"] is not None or
            gcc_command["output"] != gcc_root + "\n"):
        raise ValueError("GCC include query did not return the reviewed directory")
    gcc_info = path_info(gcc_root)
    if gcc_info.get("canonical") != gcc_root or gcc_info.get("regular") is not False:
        raise ValueError("GCC include directory identity unavailable")
    gcc_headers = resource_headers(gcc_root)
    if not gcc_headers.get("complete") or not gcc_headers.get("files"):
        raise ValueError("GCC include inventory incomplete or empty")
    for item in gcc_headers["files"]:
        if (item.get("error") or item.get("hash_error") or item.get("regular") is not True or
                not isinstance(item.get("size"), int) or item["size"] < 0 or
                not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64 or
                not item.get("chain") or not item.get("canonical_ancestors")):
            raise ValueError("GCC header identity incomplete")
    required = {gcc_root + "/" + name for name in ("stddef.h", "stdbool.h", "stdint.h", "stdarg.h")}
    if not required.issubset({item["requested"] for item in gcc_headers["files"]}):
        raise ValueError("GCC include inventory lacks an observed dependency")
    report["gcc_include"] = gcc_info
    report["gcc_include_headers"] = gcc_headers
    check_cancelled()
    clang = report["tools"]["clang18"]
    if safe_to_execute("clang18", clang) is None:
        try:
            resource = bounded_command([clang["canonical"], "-print-resource-dir"])
            report["clang_resource_command"] = resource
            if resource["exit_code"] == 0 and resource["error"] is None:
                resource_dir = resource["output"].strip()
                if resource_dir.startswith("/") and "\n" not in resource_dir:
                    report["clang_resource"] = path_info(resource_dir)
                    report["clang_resource_include"] = path_info(resource_dir + "/include")
                    report["clang_resource_headers"] = resource_headers(resource_dir + "/include")
        except (OSError, subprocess.SubprocessError) as exc:
            report["clang_resource_command"] = {"error": str(exc), "exit_code": None}
    check_cancelled()
    report["header_roots"] = [path_info(p) for p in ("/usr/include", "/usr/include/x86_64-linux-gnu")]
    check_cancelled()
    with (root / "tool-census.json").open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
