#!/usr/bin/env python3
"""Check a bounded, selected canary-build evidence tar, never runtime custody.

The producer uploads a directory, not this tar format. This tool accepts a
separately selected tar of the fixed producer members below; it does not verify
GitHub artifact identity or authenticate the selection. External expectations,
including source hashes and the loader digest, must come from a trusted caller.
No runtime manifest or independent terminal collector is available. Even a
consistent build returns CUSTODY_UNAVAILABLE, never a capability success.
"""
import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

MAX_ARCHIVE = 64 * 1024 * 1024
OWNED = "owned/"
STAGED = OWNED + "staged-prefix/usr/lib/x86_64-linux-gnu/"
ARTIFACTS = ("bpf_canary_host", "bpf_canary.bpf.o", "bpf_canary_host.d", "bpf_canary.bpf.d",
             "compiled-headers.json", "bpf-compiled-headers.json", "bpf-dependency-receipt.json",
             "canary-source.json", "diagnostic-build-record.json")
ARCHIVES = ("libbpf.a", "libelf.a", "libz.a", "libzstd.a")
MANIFEST = OWNED + "canary-build-manifest.json"
LIMITS = {MANIFEST: 2 * 1024 * 1024, **{OWNED + n: 12 * 1024 * 1024 for n in ARTIFACTS},
          **{STAGED + n: 16 * 1024 * 1024 for n in ARCHIVES}}
SHA = re.compile(r"[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")


class EvidenceError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON key")
        out[key] = value
    return out


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
                require(not entry.pax_headers and entry.offset_data == entry.offset + 512,
                        "extended archive headers are not allowed")
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


def valid_sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def validate_expectations(expected):
    keys = {"repository", "workflow", "workflow_ref", "run_id", "attempt", "artifact_id", "recipe_sha",
            "source_sha256", "archive_sha256", "build_manifest_sha256", "loader_sha256"}
    require(set(expected) == keys, "unexpected or missing trusted expectation")
    for key in ("repository", "workflow", "workflow_ref"):
        value = expected[key]
        require(type(value) is str and 0 < len(value) <= 512 and not any(ord(c) < 32 for c in value), f"invalid {key}")
    for key in ("run_id", "attempt", "artifact_id"):
        require(type(expected[key]) is int and 0 < expected[key] < 2**63, f"invalid {key}")
    require(type(expected["recipe_sha"]) is str and REV.fullmatch(expected["recipe_sha"]) is not None, "invalid recipe_sha")
    for key in ("archive_sha256", "build_manifest_sha256", "loader_sha256"):
        require(valid_sha(expected[key]), f"invalid {key}")
    sources = expected["source_sha256"]
    require(type(sources) is dict and sources and all(type(k) is str and valid_sha(v) for k, v in sources.items()),
            "invalid source_sha256")
    require(expected["workflow_ref"].startswith(expected["repository"] + "/" + expected["workflow"] + "@") and
            bool(expected["workflow_ref"].split("@", 1)[1]), "invalid workflow_ref")


def validate_candidate(data, expected, loader):
    """Validate producer build records only, not artifact identity or execution."""
    validate_expectations(expected)
    require(digest(data) == expected["archive_sha256"], "archive digest mismatch")
    require(digest(loader) == expected["loader_sha256"], "external loader digest mismatch")
    members = read_archive(data)
    require(digest(members[MANIFEST]) == expected["build_manifest_sha256"], "build manifest digest mismatch")
    manifest = parse_json(members[MANIFEST], "build manifest")
    require(manifest.get("schema") == "iyi-bpf-canary-build-v1", "build manifest schema")
    for flag in ("strict_eligible", "exec_identity_tested", "load_attempted", "attach_attempted"):
        require(manifest.get(flag) is False, f"build manifest {flag}")
    source = manifest.get("source")
    require(type(source) is dict and source.get("schema") == "iyi-bpf-canary-source-v1" and
            source.get("repository") == expected["repository"] and source.get("workflow_path") == expected["workflow"] and
            source.get("workflow_ref") == expected["workflow_ref"] and source.get("recipe_sha") == expected["recipe_sha"] and
            source.get("source_sha256") == expected["source_sha256"], "build source subject mismatch")
    require(parse_json(members[OWNED + "canary-source.json"], "source") == source, "source record mismatch")
    build = manifest.get("build")
    require(type(build) is dict and build.get("schema") == "iyi-bpf-build-record-v1" and
            build.get("source") == source and build.get("source_checkout_sha") == expected["recipe_sha"] and
            build.get("github_run_id") == str(expected["run_id"]) and
            build.get("github_run_attempt") == str(expected["attempt"]), "build record subject mismatch")
    for flag in ("strict_eligible", "exec_identity_tested", "load_attempted", "attach_attempted"):
        require(build.get(flag) is False, f"build record {flag}")
    require(parse_json(members[OWNED + "diagnostic-build-record.json"], "build record") == build,
            "build record mismatch")
    for label, names, prefix in (("artifacts", ARTIFACTS, OWNED), ("static_archives", ARCHIVES, STAGED)):
        recorded = manifest.get(label)
        require(type(recorded) is dict and set(recorded) == set(names), f"{label} set mismatch")
        for name in names:
            entry, content = recorded[name], members[prefix + name]
            require(type(entry) is dict and set(entry) == {"size", "sha256"} and
                    type(entry["size"]) is int and entry["size"] == len(content) and
                    valid_sha(entry["sha256"]) and digest(content) == entry["sha256"], f"{name} digest or size mismatch")
    for field, name in (("host_bin", "bpf_canary_host"), ("bpf_obj", "bpf_canary.bpf.o")):
        outputs = build.get("outputs")
        require(type(outputs) is dict and type(outputs.get(field)) is dict and
                outputs[field].get("sha256") == digest(members[OWNED + name]), f"{field} build digest mismatch")
    deps = build.get("dynamic_dependencies")
    require(type(deps) is dict and type(deps.get("ld_linux")) is dict and
            deps["ld_linux"].get("path") == "/lib64/ld-linux-x86-64.so.2" and
            deps["ld_linux"].get("sha256") == expected["loader_sha256"], "build loader mismatch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", required=True, help="independently supplied expectations JSON")
    parser.add_argument("--archive", required=True, help="selected uncompressed tar, not the original GitHub artifact")
    parser.add_argument("--loader", required=True, help="separately obtained loader bytes, not from the tar")
    args = parser.parse_args(argv)
    try:
        expected = parse_json(read_bounded(Path(args.expectations), 512 * 1024), "expectations")
        validate_candidate(read_bounded(Path(args.archive), MAX_ARCHIVE), expected,
                           read_bounded(Path(args.loader), 16 * 1024 * 1024))
    except (EvidenceError, OSError) as exc:
        print(json.dumps({"result": "INVALID", "detail": str(exc), "strict_eligible": False,
                          "exec_identity_tested": False}), file=sys.stderr)
        return 1
    print(json.dumps({"result": "CUSTODY_UNAVAILABLE", "strict_eligible": False, "exec_identity_tested": False,
                      "detail": "Selected build records are consistent only. Original artifact identity, runtime manifest, independently authenticated terminal/exit and protected collector are not verified; no kernel observation is made."}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
