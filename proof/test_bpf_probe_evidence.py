#!/usr/bin/env python3
"""Offline producer-contract controls; no BPF, privileges or network."""
import contextlib
import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from proof import check_bpf_probe_evidence as check


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


def pack(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind in members:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            else:
                entry.linkname = check.OWNED + "bpf_canary_host"
                archive.addfile(entry)
    return output.getvalue()


def producer_fixture(root):
    """Execute the producer's manifest-assembly block against local fixture inputs.

    This is not a Linux build or a runtime observation. The block comes from the
    current script rather than a second, hand-maintained manifest implementation.
    """
    script = (Path(__file__).parent / "run_bpf_feasibility.sh").read_text()
    start = script.index('names = ("bpf_canary_host", "bpf_canary.bpf.o"')
    end = script.index('\nPY\n', start)
    assembly = script[start:end]
    owned = root / "owned"
    staged = owned / "staged-prefix/usr/lib/x86_64-linux-gnu"
    staged.mkdir(parents=True)
    loader = b"separately collected loader bytes"
    src = {"schema": "iyi-bpf-canary-source-v1", "recipe_sha": "a" * 40,
           "repository": "example/iyi", "workflow_path": ".github/workflows/pr147-bpf-feasibility.yml",
           "workflow_ref": "example/iyi/.github/workflows/pr147-bpf-feasibility.yml@refs/heads/main",
           "source_sha256": {"proof/bpf_canary_host.c": "b" * 64}}
    for name in check.ARTIFACTS:
        (owned / name).write_bytes((name + " fixture bytes").encode())
    for name in check.ARCHIVES:
        (staged / name).write_bytes((name + " fixture archive").encode())
    (owned / "canary-source.json").write_bytes(encode(src))
    flags = {"strict_eligible": False, "exec_identity_tested": False, "load_attempted": False, "attach_attempted": False}
    record = {"schema": "iyi-bpf-build-record-v1", **flags, "source": src, "source_checkout_sha": src["recipe_sha"],
              "github_run_id": "123", "github_run_attempt": "1",
              "outputs": {"host_bin": {"sha256": check.digest((owned / "bpf_canary_host").read_bytes())},
                          "bpf_obj": {"sha256": check.digest((owned / "bpf_canary.bpf.o").read_bytes())}},
              "dynamic_dependencies": {"ld_linux": {"path": "/lib64/ld-linux-x86-64.so.2", "sha256": check.digest(loader)}}}
    (owned / "diagnostic-build-record.json").write_bytes(encode(record))
    scope = {"owned_dir": owned, "sha256_file": lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest(),
             "source": src, "record": record, "os": os, "json": json}
    with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
        exec(compile(assembly, "producer-manifest-assembly", "exec"), scope)
    members = {name: (root / name).read_bytes() for name in check.LIMITS}
    archive = pack([(n, b, tarfile.REGTYPE) for n, b in members.items()])
    expected = {"repository": src["repository"], "workflow": src["workflow_path"], "workflow_ref": src["workflow_ref"],
                "run_id": 123, "attempt": 1, "artifact_id": 456, "recipe_sha": src["recipe_sha"],
                "source_sha256": src["source_sha256"], "archive_sha256": check.digest(archive),
                "build_manifest_sha256": check.digest(members[check.MANIFEST]), "loader_sha256": check.digest(loader)}
    return members, archive, expected, loader


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.members, self.archive, self.expected, self.loader = producer_fixture(self.root)

    def reject(self, archive, expected, reason, loader=None):
        with self.assertRaisesRegex(check.EvidenceError, reason):
            check.validate_candidate(archive, expected, self.loader if loader is None else loader)

    def test_producer_manifest_reaches_custody_hold_not_success(self):
        check.validate_candidate(self.archive, self.expected, self.loader)
        bundle, expectations, loader = (self.root / n for n in ("selected.tar", "expectations.json", "loader"))
        bundle.write_bytes(self.archive)
        expectations.write_bytes(encode(self.expected))
        loader.write_bytes(self.loader)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = check.main(["--archive", str(bundle), "--expectations", str(expectations), "--loader", str(loader)])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(result["result"], "CUSTODY_UNAVAILABLE")
        self.assertIs(result["strict_eligible"], False)
        self.assertIs(result["exec_identity_tested"], False)

    def test_subjects_and_external_hashes(self):
        for key, value in (("repository", "other"), ("workflow", "other"), ("workflow_ref", "other"),
                           ("run_id", 2), ("attempt", 2), ("recipe_sha", "f" * 40),
                           ("source_sha256", {"other": "f" * 64}), ("archive_sha256", "f" * 64),
                           ("build_manifest_sha256", "f" * 64), ("loader_sha256", "f" * 64)):
            with self.subTest(key=key):
                expected = copy.deepcopy(self.expected)
                expected[key] = value
                self.reject(self.archive, expected, "mismatch|invalid")
        self.reject(self.archive, self.expected, "loader digest mismatch", loader=b"altered")

    def test_artifact_id_is_not_proven_by_payload(self):
        # Different caller-supplied IDs cannot be authenticated by any field in the producer record.
        other = {**self.expected, "artifact_id": 999}
        check.validate_candidate(self.archive, other, self.loader)
        # main always stops at the custody hold, regardless of this unchecked identity.

    def test_each_producer_artifact_and_static_archive_is_bound(self):
        for name in tuple(check.OWNED + n for n in check.ARTIFACTS) + tuple(check.STAGED + n for n in check.ARCHIVES):
            with self.subTest(name=name):
                suffix = b" " if name.endswith(".json") else b"altered"
                members = {**self.members, name: self.members[name] + suffix}
                archive = pack([(n, b, tarfile.REGTYPE) for n, b in members.items()])
                self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)}, "mismatch")

    def test_traversal_links_duplicates_and_unknown_members(self):
        for name, kind in (("../escape", tarfile.REGTYPE), (check.OWNED + "bpf_canary_host", tarfile.SYMTYPE),
                           (check.OWNED + "bpf_canary_host", tarfile.LNKTYPE), ("unknown", tarfile.REGTYPE),
                           (check.OWNED + "bpf_canary_host", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind):
                entries = [(n, b, tarfile.REGTYPE) for n, b in self.members.items() if n != name]
                if kind == tarfile.REGTYPE and name in self.members:
                    entries.append((name, b"a", kind))
                archive = pack(entries + [(name, b"x", kind)])
                self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)},
                            "unexpected archive member|not a regular file|duplicate archive member")

    def test_missing_extended_truncated_and_bounds(self):
        archive = pack([(n, b, tarfile.REGTYPE) for n, b in self.members.items() if n != check.MANIFEST])
        self.reject(archive, {**self.expected, "archive_sha256": check.digest(archive)}, "missing archive member")
        extended = self.archive + b"extra"
        self.reject(extended, {**self.expected, "archive_sha256": check.digest(extended)}, "trailing content")
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode="r:") as archive_file:
            list(archive_file)
            truncated = self.archive[:archive_file.offset + 512]
        self.reject(truncated, {**self.expected, "archive_sha256": check.digest(truncated)}, "terminator|invalid|truncated")
        with self.assertRaisesRegex(check.EvidenceError, "size limit"):
            check.read_archive(b"x" * (check.MAX_ARCHIVE + 1))

    def test_forged_pass_never_satisfies_build_schema(self):
        members = {**self.members, check.MANIFEST: b'{"status":"PROBE_SUCCESS","strict_eligible":true}'}
        archive = pack([(n, b, tarfile.REGTYPE) for n, b in members.items()])
        expected = {**self.expected, "archive_sha256": check.digest(archive),
                    "build_manifest_sha256": check.digest(members[check.MANIFEST])}
        self.reject(archive, expected, "build manifest schema")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(check.EvidenceError, "invalid.*JSON"):
            check.parse_json(b'{"x":1,"x":2}', "test")


if __name__ == "__main__":
    unittest.main()
