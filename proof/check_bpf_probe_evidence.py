#!/usr/bin/env python3
"""Offline candidate checker, not an authenticated execution-custody verifier.

The caller supplies expectations independently of the archive. No current interface
establishes that a terminal record came from a protected independent collector, so
this tool always returns a non-success result even for a structurally valid bundle.
It does not extract archive members or execute anything.
"""

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

MAX_ARCHIVE = 32 * 1024 * 1024
LIMITS = {
    "build-manifest.json": 256 * 1024,
    "runtime-manifest.json": 256 * 1024,
    "bpf_canary_host": 12 * 1024 * 1024,
    "bpf_canary.bpf.o": 4 * 1024 * 1024,
    "dependency-receipt.json": 2 * 1024 * 1024,
    "loader": 4 * 1024 * 1024,
    "report.json": 256 * 1024,
    "verifier.log": 4 * 1024 * 1024,
    "relocation.log": 4 * 1024 * 1024,
    "terminal.json": 64 * 1024,
}
BUILD_FILES = ("bpf_canary_host", "bpf_canary.bpf.o", "dependency-receipt.json", "loader")
RUNTIME_FILES = ("report.json", "verifier.log", "relocation.log", "terminal.json")
SUBJECT_KEYS = ("repository", "workflow", "run_id", "attempt", "artifact_id", "recipe_sha", "source_sha")
SHA = re.compile(r"[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(data, label):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"invalid {label} JSON") from exc
    require(type(value) is dict, f"{label} must be an object")
    return value


def read_bounded(path, limit):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f"{path}: size limit exceeded")
    return data


def read_archive(data):
    require(len(data) <= MAX_ARCHIVE, "archive size limit exceeded")
    members = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for entry in archive:
                require(entry.name in LIMITS, "unexpected archive member")
                require(entry.name not in members, "duplicate archive member")
                require(entry.type in (tarfile.REGTYPE, tarfile.AREGTYPE), "archive member is not a regular file")
                require(not entry.pax_headers, "extended archive headers are not allowed")
                require(entry.offset_data == entry.offset + 512, "extended archive headers are not allowed")
                require(0 < entry.size <= LIMITS[entry.name], "archive member size limit exceeded or empty")
                stream = archive.extractfile(entry)
                require(stream is not None, "archive member unreadable")
                content = stream.read(entry.size + 1)
                require(len(content) == entry.size, "archive member truncated")
                members[entry.name] = content
            end = archive.offset
        require(end + 1024 <= len(data) and not any(data[end:]), "archive has missing terminator or trailing content")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise EvidenceError("invalid or truncated archive") from exc
    require(set(members) == set(LIMITS), "missing archive member")
    return members


def validate_expectations(expected):
    require(set(expected) == set(SUBJECT_KEYS) | {"archive_sha256", "build_manifest_sha256", "runtime_manifest_sha256"},
            "unexpected or missing trusted expectation")
    for key in ("repository", "workflow"):
        value = expected[key]
        require(type(value) is str and 0 < len(value) <= 256 and not any(ord(c) < 32 for c in value), f"invalid {key}")
    for key in ("run_id", "attempt", "artifact_id"):
        require(type(expected[key]) is int and 0 < expected[key] < 2**63, f"invalid {key}")
    for key in ("recipe_sha", "source_sha"):
        require(type(expected[key]) is str and REV.fullmatch(expected[key]) is not None, f"invalid {key}")
    for key in ("archive_sha256", "build_manifest_sha256", "runtime_manifest_sha256"):
        require(type(expected[key]) is str and SHA.fullmatch(expected[key]) is not None, f"invalid {key}")


def validate_report(report, members):
    def obj(key):
        value = report.get(key)
        require(type(value) is dict, f"missing report {key}")
        return value
    p, link, caps = obj("observed_kernel_prog"), obj("observed_kernel_link"), obj("capabilities")
    proc, memlock = obj("process_identity"), obj("memlock")
    verifier, relo = obj("verifier_evidence"), obj("relocation_evidence")
    for key in ("bpf_load_supported", "bpf_attach_supported", "hook_identity_verified", "link_association_verified"):
        require(report.get(key) is True, f"report {key}")
    require(report.get("status") == "PROBE_SUCCESS", "report status")
    require(report.get("strict_eligible") is False and report.get("exec_identity_tested") is False, "report eligibility")
    require(report.get("fd_ownership_lifecycle") == "detached_and_closed_before_report", "report teardown")
    require(p.get("prog_type") == 26 and type(p.get("prog_id")) is int and p["prog_id"] > 0 and
            type(p.get("attach_btf_id")) is int and p["attach_btf_id"] > 0, "report program")
    require(link.get("link_type") == 1 and link.get("link_prog_id") == p["prog_id"] and
            link.get("link_tp_name") == "sched_process_exec" and
            link.get("target_hook_name") == "btf_trace_sched_process_exec" and
            link.get("target_hook_kind") == "BTF_KIND_TYPEDEF", "report link")
    require(caps.get("cap_bpf") is True and caps.get("cap_perfmon") is True and
            caps.get("cap_sys_admin") is False and caps.get("all_other_caps_clear") is True, "report capabilities")
    require(type(proc.get("uid")) is int and proc["uid"] > 0 and type(proc.get("gid")) is int and proc["gid"] > 0,
            "report process identity")
    require(memlock.get("automatic_rlim_disabled") is True, "report memlock")
    require(verifier.get("log_valid") is True and type(verifier.get("log_bytes")) is int and
            verifier["log_bytes"] == len(members["verifier.log"]) and b"processed " in members["verifier.log"],
            "report verifier log")
    require(relo.get("core_relocation_retained") is True and type(relo.get("libbpf_debug_log_bytes")) is int and
            relo["libbpf_debug_log_bytes"] == len(members["relocation.log"]) and
            any(token in members["relocation.log"] for token in (b"relo #", b"bpf_core_relo", b"CO-RE")),
            "report relocation log")


def validate_candidate(data, expected):
    """Check consistency only; even a return is not an execution or custody proof."""
    validate_expectations(expected)
    require(digest(data) == expected["archive_sha256"], "archive digest mismatch")
    members = read_archive(data)
    for name, key in (("build-manifest.json", "build_manifest_sha256"),
                      ("runtime-manifest.json", "runtime_manifest_sha256")):
        require(digest(members[name]) == expected[key], f"{name} digest mismatch")
    build = parse_json(members["build-manifest.json"], "build manifest")
    runtime = parse_json(members["runtime-manifest.json"], "runtime manifest")
    require(build.get("schema") == "iyi-bpf-canary-build-v1", "build manifest schema")
    require(runtime.get("schema") == "iyi-bpf-canary-runtime-v1", "runtime manifest schema")
    for manifest in (build, runtime):
        require(type(manifest.get("subject")) is dict and manifest["subject"] == {k: expected[k] for k in SUBJECT_KEYS},
                "manifest subject mismatch")
    require(runtime.get("build_manifest_sha256") == expected["build_manifest_sha256"], "runtime build subject mismatch")
    for manifest, names in ((build, BUILD_FILES), (runtime, RUNTIME_FILES)):
        files = manifest.get("files")
        require(type(files) is dict and set(files) == set(names), "manifest file set mismatch")
        for name in names:
            require(type(files[name]) is str and SHA.fullmatch(files[name]) is not None and
                    digest(members[name]) == files[name], f"{name} digest mismatch")
    terminal = parse_json(members["terminal.json"], "terminal")
    require(terminal.get("exit_code") == 0 and type(terminal.get("exit_code")) is int and
            terminal.get("completed") is True and terminal.get("teardown_complete") is True and
            terminal.get("interrupted") is False, "terminal incomplete or unsuccessful")
    validate_report(parse_json(members["report.json"], "report"), members)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True, help="independently supplied expectations JSON; never read from bundle")
    parser.add_argument("--archive", required=True, help="downloaded uncompressed tar bundle")
    args = parser.parse_args(argv)
    try:
        expected = parse_json(read_bounded(Path(args.expectations), 64 * 1024), "expectations")
        validate_candidate(read_bounded(Path(args.archive), MAX_ARCHIVE), expected)
    except (EvidenceError, OSError) as exc:
        print(json.dumps({"result": "INVALID", "detail": str(exc), "strict_eligible": False,
                          "exec_identity_tested": False}), file=sys.stderr)
        return 1
    print(json.dumps({"result": "CUSTODY_UNAVAILABLE", "strict_eligible": False,
                      "exec_identity_tested": False,
                      "detail": "No authenticated protected independent terminal/exit collector interface is established; consistency checks are not kernel observation or custody proof."}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
