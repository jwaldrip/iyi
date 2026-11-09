#!/usr/bin/env python3
"""Offline controls for candidate consistency and the unavailable custody gate."""

import contextlib
import copy
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from proof import check_bpf_probe_evidence as check


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def subject():
    return {"repository": "example/iyi", "workflow": ".github/workflows/canary.yml",
            "run_id": 123, "attempt": 1, "artifact_id": 456,
            "recipe_sha": "a" * 40, "source_sha": "b" * 40}


def fixture():
    vlog, rlog = b"processed 10 insns\n", b"CO-RE relocation\n"
    report = {
        "status": "PROBE_SUCCESS", "strict_eligible": False, "exec_identity_tested": False,
        "bpf_load_supported": True, "bpf_attach_supported": True, "hook_identity_verified": True,
        "link_association_verified": True, "fd_ownership_lifecycle": "detached_and_closed_before_report",
        "observed_kernel_prog": {"prog_type": 26, "prog_id": 7, "attach_btf_id": 9},
        "observed_kernel_link": {"link_type": 1, "link_prog_id": 7, "link_tp_name": "sched_process_exec",
                                 "target_hook_name": "btf_trace_sched_process_exec", "target_hook_kind": "BTF_KIND_TYPEDEF"},
        "capabilities": {"cap_bpf": True, "cap_perfmon": True, "cap_sys_admin": False, "all_other_caps_clear": True},
        "process_identity": {"uid": 1000, "gid": 1000}, "memlock": {"automatic_rlim_disabled": True},
        "verifier_evidence": {"log_valid": True, "log_bytes": len(vlog)},
        "relocation_evidence": {"core_relocation_retained": True, "libbpf_debug_log_bytes": len(rlog)},
    }
    files = {"bpf_canary_host": b"helper", "bpf_canary.bpf.o": b"object", "dependency-receipt.json": b"{}",
             "loader": b"loader", "report.json": encoded(report), "verifier.log": vlog, "relocation.log": rlog,
             "terminal.json": encoded({"exit_code": 0, "completed": True, "teardown_complete": True, "interrupted": False})}
    return files


def make_bundle(files, build_subject=None, runtime_subject=None, entries=None):
    s = subject()
    build = {"schema": "iyi-bpf-canary-build-v1", "subject": build_subject or s,
             "files": {name: check.digest(files[name]) for name in check.BUILD_FILES}}
    build_bytes = encoded(build)
    runtime = {"schema": "iyi-bpf-canary-runtime-v1", "subject": runtime_subject or s,
               "build_manifest_sha256": check.digest(build_bytes),
               "files": {name: check.digest(files[name]) for name in check.RUNTIME_FILES}}
    runtime_bytes = encoded(runtime)
    members = {**files, "build-manifest.json": build_bytes, "runtime-manifest.json": runtime_bytes}
    archive = pack(entries if entries is not None else [(name, content, tarfile.REGTYPE) for name, content in members.items()])
    expected = {**s, "archive_sha256": check.digest(archive), "build_manifest_sha256": check.digest(build_bytes),
                "runtime_manifest_sha256": check.digest(runtime_bytes)}
    return archive, expected, members


def pack(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            else:
                item.linkname = "bpf_canary_host"
                tar.addfile(item)
    return out.getvalue()


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.files = fixture()
        self.archive, self.expected, self.members = make_bundle(self.files)

    def reject(self, archive, expected, reason):
        with self.assertRaisesRegex(check.EvidenceError, reason):
            check.validate_candidate(archive, expected)

    def test_plausible_self_authored_pass_cannot_establish_custody(self):
        check.validate_candidate(self.archive, self.expected)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "candidate.tar"
            expectations = Path(directory) / "expectations.json"
            bundle.write_bytes(self.archive)
            expectations.write_bytes(encoded(self.expected))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = check.main(["--archive", str(bundle), "--expectations", str(expectations)])
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output.getvalue())["result"], "CUSTODY_UNAVAILABLE")

    def test_each_external_subject_is_required(self):
        for key in check.SUBJECT_KEYS:
            with self.subTest(key=key):
                expected = copy.deepcopy(self.expected)
                expected[key] = (expected[key] + 1 if type(expected[key]) is int else
                                 ("f" * 40 if key.endswith("sha") else "other"))
                self.reject(self.archive, expected, "manifest subject mismatch")

    def test_manifest_and_archive_digests_are_external(self):
        for key in ("archive_sha256", "build_manifest_sha256", "runtime_manifest_sha256"):
            with self.subTest(key=key):
                expected = {**self.expected, key: "f" * 64}
                self.reject(self.archive, expected, "digest mismatch")

    def test_each_build_input_and_runtime_output_is_bound(self):
        for name in check.BUILD_FILES + check.RUNTIME_FILES:
            with self.subTest(name=name):
                members = {**self.members, name: self.members[name] + b"altered"}
                archive = pack([(n, b, tarfile.REGTYPE) for n, b in members.items()])
                self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)}, "digest mismatch")

    def test_traversal_links_duplicate_and_unexpected_are_rejected(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("bpf_canary_host", tarfile.SYMTYPE),
                           ("bpf_canary_host", tarfile.LNKTYPE), ("unknown", tarfile.REGTYPE),
                           ("bpf_canary_host", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind):
                base = [(n, b, tarfile.REGTYPE) for n, b in self.members.items() if n != name]
                if kind == tarfile.REGTYPE and name == "bpf_canary_host":
                    base.append((name, b"a", kind))
                archive = pack(base + [(name, b"x", kind)])
                self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)},
                            "unexpected archive member|not a regular file|duplicate archive member")

    def test_missing_and_extended_evidence(self):
        archive = pack([(n, b, tarfile.REGTYPE) for n, b in self.members.items() if n != "terminal.json"])
        self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)}, "missing archive member")
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode="r:") as tar:
            list(tar)
            truncated = self.archive[:tar.offset + 512]
        self.reject(truncated, {**self.expected, "archive_sha256": check.digest(truncated)},
                    "terminator|invalid|truncated")
        extended = self.archive + b"untrusted trailing data"
        self.reject(extended, {**self.expected, "archive_sha256": check.digest(extended)}, "trailing content")

    def test_bounds(self):
        with self.assertRaisesRegex(check.EvidenceError, "size limit"):
            check.read_archive(b"x" * (check.MAX_ARCHIVE + 1))
        members = {**self.members, "terminal.json": b"x" * (check.LIMITS["terminal.json"] + 1)}
        archive = pack([(n, b, tarfile.REGTYPE) for n, b in members.items()])
        self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)}, "size limit")

    def test_terminal_exit_interrupt_and_teardown(self):
        for change in ({"exit_code": 1}, {"completed": False}, {"interrupted": True}, {"teardown_complete": False}):
            with self.subTest(change=change):
                terminal = json.loads(self.files["terminal.json"])
                terminal.update(change)
                archive, expected, _ = make_bundle({**self.files, "terminal.json": encoded(terminal)})
                self.reject(archive, expected, "terminal incomplete")

    def test_no_eligibility_or_identity_promotion(self):
        for key in ("strict_eligible", "exec_identity_tested"):
            report = json.loads(self.files["report.json"])
            report[key] = True
            archive, expected, _ = make_bundle({**self.files, "report.json": encoded(report)})
            self.reject(archive, expected, "report eligibility")

    def test_report_and_logs_must_agree(self):
        for name in ("verifier.log", "relocation.log"):
            archive, expected, _ = make_bundle({**self.files, name: b"fake log"})
            self.reject(archive, expected, "report .* log")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(check.EvidenceError, "invalid.*JSON"):
            check.parse_json(b'{"x":1,"x":2}', "test")


if __name__ == "__main__":
    unittest.main()
