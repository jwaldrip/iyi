#!/usr/bin/env python3
"""Fail-closed comparison with the independently preserved runner census."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

# Raw census from run 42676201314, census source a1cd0c04dae096185bdabf0b370e0ac44a572508,
# preserved at Git commit 7d75ba5b6751f1bcc886721fab42a17ab3b1b9ee.
CENSUS_SHA256 = "149850a909e042c8e87606ac99a920da001eb1cd75880419bc900fc9d2404794"
BASELINE = Path(__file__).resolve().with_name("bpf_tool_baseline.json")
TOOL_NAMES = {"clang18", "gcc", "readelf", "gpgv", "dpkg-deb", "setpriv", "sudo"}
MAX_BYTES = 256 * 1024 * 1024


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def digest(path):
    h = hashlib.sha256()
    remaining = MAX_BYTES + 1
    with path.open("rb") as f:
        while remaining:
            data = f.read(min(1024 * 1024, remaining))
            if not data:
                return h.hexdigest()
            h.update(data)
            remaining -= len(data)
    raise ValueError(f"file too large: {path}")


def metadata(entry):
    path = Path(entry["path"])
    actual = path.lstat()
    require(actual.st_uid == entry["uid"] and actual.st_gid == entry["gid"] and
            oct(stat.S_IMODE(actual.st_mode)) == entry["mode"], f"metadata mismatch: {path}")
    if "symlink_target" in entry:
        require(stat.S_ISLNK(actual.st_mode) and os.readlink(path) == entry["symlink_target"],
                f"symlink mismatch: {path}")
    else:
        require(not stat.S_ISLNK(actual.st_mode), f"unexpected symlink: {path}")


def check_path(entry, expected_file):
    require("error" not in entry and entry.get("regular") is expected_file, "invalid census entry")
    path = Path(entry["requested"])
    require(str(path.resolve(strict=True)) == entry["canonical"], f"canonical path mismatch: {path}")
    for item in entry["chain"] + entry["canonical_ancestors"]:
        metadata(item)
    st = path.stat()
    require(st.st_uid == entry["uid"] and st.st_gid == entry["gid"] and
            oct(stat.S_IMODE(st.st_mode)) == entry["mode"], f"metadata mismatch: {path}")
    if expected_file:
        require(stat.S_ISREG(st.st_mode) and st.st_size == entry["size"] and
                digest(path) == entry["sha256"], f"file identity mismatch: {path}")
    else:
        require(stat.S_ISDIR(st.st_mode), f"not a directory: {path}")


def compare_version(actual, expected):
    require(expected.get("error") is None and expected.get("exit_code") == 0,
            "unreviewed version baseline")
    require(actual.returncode == 0 and actual.stdout == expected["output"].encode("utf-8"),
            "tool version differs from reviewed census")


def verify(baseline, environment, version_runner):
    require(environment.get("ImageOS") == baseline["image_os"] == "ubuntu24" and
            environment.get("ImageVersion") == baseline["image_version"] == "20261101.360.1",
            "runner image does not match reviewed census")
    tools = baseline["tools"]
    require(set(tools) == TOOL_NAMES, "unexpected tool inventory")
    for name, entry in tools.items():
        check_path(entry, True)
        if name != "sudo":
            compare_version(version_runner(entry["canonical"]), entry["version"])
    check_path(baseline["clang_resource"], False)
    check_path(baseline["clang_resource_include"], False)
    for entry in baseline["header_roots"]:
        check_path(entry, False)
    headers = baseline["clang_resource_headers"]
    require(headers["complete"] is True and len(headers["files"]) > 0, "incomplete resource inventory")
    root = Path(baseline["clang_resource_include"]["canonical"])
    expected_paths = {entry["requested"] for entry in headers["files"]}
    require(len(expected_paths) == len(headers["files"]), "duplicate resource headers")
    found = set()
    def fail_walk(exc):
        raise exc
    for base, dirs, files in os.walk(root, followlinks=False, onerror=fail_walk):
        require(not any((Path(base) / d).is_symlink() for d in dirs), "resource directory symlink")
        for name in files:
            found.add(str(Path(base) / name))
            require(len(found) <= 8192, "resource header count exceeded")
    require(found == expected_paths, "resource header inventory changed")
    for entry in headers["files"]:
        check_path(entry, True)


def run_version(path):
    # Files have already been matched to reviewed hashes and root-owned paths.
    return subprocess.run([path, "--version"], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=5, check=False)


def main():
    raw = BASELINE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == CENSUS_SHA256, "census provenance hash mismatch")
    verify(json.loads(raw), os.environ, run_version)
    print("Reviewed runner baseline matched; no privileged executable was probed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        sys.exit(f"ERROR: runner baseline prerequisite failed: {exc}")
