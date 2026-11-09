#!/usr/bin/env python3
"""Fail-closed comparison with the independently preserved runner census."""
import errno
import importlib.util
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
GCC_CENSUS_SHA256 = "10551b14c2a6339a5363d8bb5993b9779efaac1847a6f19f85992af7008a1fa7"
GCC_BASELINE = Path(__file__).resolve().with_name("bpf_gcc_include_baseline.json")
GCC_ROOT = Path("/usr/lib/gcc/x86_64-linux-gnu/13/include")
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
def load_gcc_baseline():
    original_raw = BASELINE.read_bytes()
    require(hashlib.sha256(original_raw).hexdigest() == CENSUS_SHA256, "original census digest mismatch")
    raw = GCC_BASELINE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == GCC_CENSUS_SHA256, "GCC census digest mismatch")
    original, supplement = json.loads(original_raw), json.loads(raw)
    require(supplement["image_os"] == original["image_os"] and
            supplement["image_version"] == original["image_version"], "GCC census image mismatch")
    require(supplement["tools"]["gcc"] == original["tools"]["gcc"], "GCC driver census mismatch")
    query = supplement["gcc_include_command"]
    require(query["error"] is None and query["exit_code"] == 0 and
            query["output"] == str(GCC_ROOT) + "\n", "GCC include query mismatch")
    root = supplement["gcc_include"]
    require(root["requested"] == root["canonical"] == str(GCC_ROOT), "GCC include root mismatch")
    inventory = supplement["gcc_include_headers"]
    require(inventory["complete"] is True and inventory["files"], "GCC inventory incomplete")
    requested = [item["requested"] for item in inventory["files"]]
    require(len(requested) == len(set(requested)), "duplicate GCC inventory entry")
    return supplement


def verify_gcc_entry(entry, root):
    requested = Path(entry["requested"])
    canonical = Path(entry["canonical"])
    require(requested.is_absolute() and ".." not in requested.parts and
            requested.is_relative_to(root) and canonical.is_relative_to(root), "GCC header escapes root")
    require(entry.get("regular") is True and isinstance(entry.get("size"), int) and
            entry["size"] >= 0 and isinstance(entry.get("sha256"), str) and
            len(entry["sha256"]) == 64, "invalid GCC header record")
    for ancestor in entry["canonical_ancestors"]:
        p = Path(ancestor["path"])
        st = p.stat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                f"unsafe GCC ancestor: {p}")
    check_path(entry, True)
    st = requested.stat()
    require(st.st_uid == 0 and not st.st_mode & 0o022, f"unsafe GCC header: {requested}")


def check_gcc_dependency(token, supplement):
    path = Path(token)
    require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(GCC_ROOT),
            "unapproved GCC dependency path")
    entries = {item["requested"]: item for item in supplement["gcc_include_headers"]["files"]}
    require(str(path) in entries, f"unrecorded GCC header: {path}")
    check_path(supplement["gcc_include"], False)
    verify_gcc_entry(entries[str(path)], GCC_ROOT)
    return entries[str(path)]


def verify_gcc_inventory(supplement):
    root_entry = supplement["gcc_include"]
    check_path(root_entry, False)
    root_stat = GCC_ROOT.stat()
    require(root_stat.st_uid == 0 and not root_stat.st_mode & 0o022, "unsafe GCC root")
    for item in root_entry["canonical_ancestors"]:
        st = Path(item["path"]).stat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                "unsafe GCC root ancestor")
    entries = supplement["gcc_include_headers"]["files"]
    expected = {item["requested"] for item in entries}
    found = set()
    def fail_walk(exc):
        raise exc
    for base, dirs, files in os.walk(GCC_ROOT, followlinks=False, onerror=fail_walk):
        require(not any((Path(base) / name).is_symlink() for name in dirs), "GCC directory symlink")
        for name in files:
            found.add(str(Path(base) / name))
            require(len(found) <= 8192, "GCC header count exceeded")
    require(found == expected, "GCC header inventory changed")
    for entry in entries:
        verify_gcc_entry(entry, GCC_ROOT)



def verify(baseline, environment, version_runner):
    require(environment.get("ImageOS") == baseline["image_os"] == "ubuntu24" and
            environment.get("ImageVersion") == baseline["image_version"] == "20261101.360.1",
            "runner image does not match reviewed census")
    tools = baseline["tools"]
    require(set(tools) == TOOL_NAMES, "unexpected tool inventory")
    for name, entry in tools.items():
        check_path(entry, True)
        if name != "sudo":
            try:
                os.getxattr(entry["canonical"], "security.capability")
            except OSError as exc:
                require(exc.errno == errno.ENODATA, f"file capability status unknown: {name}")
            else:
                raise ValueError(f"file capability present: {name}")
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




def main():
    raw = BASELINE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == CENSUS_SHA256, "census provenance hash mismatch")
    helper_path = Path(__file__).resolve().with_name("bpf_baseline_process.py")
    spec = importlib.util.spec_from_file_location("bpf_baseline_process", helper_path)
    require(spec is not None and spec.loader is not None, "version runner unavailable")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    verify(json.loads(raw), os.environ, helper.run_version)
    verify_gcc_inventory(load_gcc_baseline())
    print("Reviewed runner baseline matched; no privileged executable was probed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit(f"ERROR: runner baseline prerequisite failed: {exc}")
