#!/usr/bin/env python3
"""Offline census controls against a temporary fake filesystem."""
import ast
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from proof import host_custody_preflight as census


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.workspace = Path(self.tmp.name) / "workspace"
        self.root.mkdir()
        self.workspace.mkdir()

    def put(self, path, value, root=None):
        file = (root or self.root) / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(value)
        return file

    def collect(self, env=None):
        with mock.patch.object(census.os, "getpid", return_value=123), \
             mock.patch.object(census.os, "getuid", return_value=1000), \
             mock.patch.object(census.os, "geteuid", return_value=1000), \
             mock.patch.object(census.os, "getgid", return_value=1001), \
             mock.patch.object(census.os, "getegid", return_value=1001), \
             mock.patch.object(census.os, "getgroups", return_value=[1001, 999]):
            return census.collect(str(self.root), str(self.workspace), env or {})

    def test_inventory_records_sources_and_never_admits(self):
        self.put("proc/sys/kernel/osrelease", b"6.1-test\n")
        self.put("proc/sys/kernel/random/boot_id", b"fixture-boot\n")
        self.put("proc/1/comm", b"systemd\n")
        self.put("proc/123/uid_map", b"0 1000 1\n")
        self.put("sys/kernel/btf/vmlinux", b"fixture-btf")
        self.put(".git/HEAD", b"a" * 40 + b"\n", self.workspace)
        record = self.collect({"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "17",
                               "GITHUB_RUN_ATTEMPT": "2", "ImageVersion": "test-image"})
        for key in ("strict_eligible", "load_attempted", "attach_attempted", "exec_identity_tested"):
            self.assertIs(record[key], False)
        self.assertEqual(record["identity"]["checkout_head"]["value"], "a" * 40)
        self.assertEqual(record["identity"]["run_id"]["source"], "env:GITHUB_RUN_ID")
        self.assertEqual(record["identity"]["workflow_sha"]["status"], "unavailable")
        self.assertEqual(record["inventory"]["kernel_release"]["value"], "6.1-test")
        self.assertEqual(record["inventory"]["uid_map"]["source"], "/proc/123/uid_map")
        self.assertEqual(record["inventory"]["btf_sha256"]["value"], hashlib.sha256(b"fixture-btf").hexdigest())
        self.assertEqual(record["inventory"]["systemd_version"]["status"], "unavailable")
        self.assertEqual(record["inventory"]["manager_dbus_availability"]["status"], "unavailable")
        self.assertEqual(record["inventory"]["approval_subject"]["status"], "unavailable")
        self.assertIn("passwordless sudo", record["threat_model"])

    def test_unavailable_does_not_become_empty_or_success(self):
        self.put("proc/sys/kernel/osrelease", b"\xff")
        self.put("proc/sys/kernel/random/boot_id", b"\n")
        self.put("proc/1/comm", b"x" * (census.TEXT_LIMIT + 1))
        record = self.collect({"GITHUB_RUN_ID": "x" * (census.ENV_LIMIT + 1)})
        for name in ("kernel_release", "boot_id", "pid1_comm", "btf_sha256"):
            self.assertEqual(record["inventory"][name]["status"], "unavailable")
            self.assertIsNone(record["inventory"][name]["value"])
        self.assertEqual(record["identity"]["run_id"]["status"], "unavailable")

    def test_confined_reads_refuse_symlink_and_special_files(self):
        outside = self.put("outside", b"secret", root=Path(self.tmp.name))
        (self.root / "link").symlink_to(outside)
        (self.root / "dirlink").symlink_to(outside.parent, target_is_directory=True)
        os.mkfifo(self.root / "pipe")
        safe = census.SafeRoot(str(self.root))
        for path in ("link", "dirlink/outside", "pipe", "../outside", "/outside"):
            value, error = safe.read(path, 32)
            self.assertIsNone(value)
            self.assertEqual(error["status"], "unavailable")
        self.assertEqual(safe.metadata("link")["value"]["type"], 0o120000)
        self.assertEqual(safe.metadata("dirlink/outside")["status"], "unavailable")

    def test_link_is_metadata_not_followed_content(self):
        pid = self.root / "proc/1"
        pid.mkdir(parents=True)
        (pid / "exe").symlink_to("/usr/lib/systemd/systemd")
        rec = self.collect()
        self.assertEqual(rec["inventory"]["pid1_exe_link"]["value"], "/usr/lib/systemd/systemd")
        self.assertEqual(rec["inventory"]["systemd_version"]["status"], "unavailable")

    def test_checkout_mismatch_is_retained_without_resolution(self):
        self.put(".git/HEAD", b"b" * 40, self.workspace)
        record = self.collect({"GITHUB_SHA": "a" * 40})
        self.assertNotEqual(record["identity"]["event_sha"]["value"], record["identity"]["checkout_head"]["value"])
        self.assertIs(record["strict_eligible"], False)


class WorkflowControls(unittest.TestCase):
    def test_manual_only_pinned_read_only_workflow(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/pr147-host-custody.yml").read_text()
        self.assertIn("on:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n", workflow)
        self.assertEqual(workflow.count("uses:"), 2)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", workflow)
        self.assertIn("actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("pr147-host-custody.stdout", workflow)
        self.assertIn("pr147-host-custody.json", workflow)
        for forbidden in ("pull_request:", "push:", "schedule:", "sudo", "setpriv", "docker", "privileged:", "write-all", "id-token:"):
            self.assertNotIn(forbidden, workflow)

    def test_collector_has_no_process_or_privilege_operations(self):
        source = Path(census.__file__).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module]
                self.assertFalse(set(names) & {"subprocess", "multiprocessing", "socket", "ctypes"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {"system", "popen", "fork", "execve", "kill", "setuid", "setgid", "chmod", "chown", "connect"})


if __name__ == "__main__":
    unittest.main()
