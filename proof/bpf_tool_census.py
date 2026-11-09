#!/usr/bin/env python3
"""Read-only runner inventory, not an approval or a diagnostic launch."""
import hashlib
import json
import os
import pathlib
import platform
import selectors
import stat
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


def bounded_command(args):
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    sel = selectors.DefaultSelector()
    sel.register(child.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + 5
    reason = None
    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                break
            events = sel.select(remaining)
            if not events:
                reason = "timeout"
                break
            chunk = os.read(child.stdout.fileno(), min(8192, MAX_OUTPUT + 1 - len(output)))
            if not chunk:
                sel.unregister(child.stdout)
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                reason = "output_limit"
                break
        if reason is None:
            try:
                code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = "timeout"
        if reason is not None:
            # This process only signals the exact child it spawned, never a group.
            child.kill()
            child.wait()
            code = None
        return {"exit_code": code, "error": reason,
                "output": bytes(output[:MAX_OUTPUT]).decode("utf-8", errors="replace")}
    finally:
        sel.close()
        child.stdout.close()


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
        info = {"requested": value, "canonical": str(resolved), "chain": chain,
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


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: bpf_tool_census.py OUTPUT_DIRECTORY")
    root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    runner = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    st = root.stat()
    if not root.is_dir() or root == runner or not root.is_relative_to(runner) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        sys.exit("census output directory must be runner-owned mode 0700 under RUNNER_TEMP")
    report = {"schema": "iyi-bpf-tool-census-v1", "strict_eligible": False,
              "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
              "kernel": platform.uname()._asdict(), "tools": {}}
    for name, path in TOOLS.items():
        info = path_info(path)
        if info.get("regular"):
            try:
                info["version"] = bounded_command([path, "--version"])
            except OSError as exc:
                info["version"] = {"error": str(exc), "exit_code": None}
        report["tools"][name] = info
    clang = report["tools"]["clang18"]
    if clang.get("regular"):
        try:
            resource = bounded_command([TOOLS["clang18"], "-print-resource-dir"])
            report["clang_resource_command"] = resource
            if resource["exit_code"] == 0 and resource["error"] is None:
                resource_dir = resource["output"].strip()
                if resource_dir.startswith("/") and "\n" not in resource_dir:
                    report["clang_resource"] = path_info(resource_dir)
                    report["clang_resource_include"] = path_info(resource_dir + "/include")
        except OSError as exc:
            report["clang_resource_command"] = {"error": str(exc), "exit_code": None}
    report["header_roots"] = [path_info(p) for p in ("/usr/include", "/usr/include/x86_64-linux-gnu")]
    with (root / "tool-census.json").open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
