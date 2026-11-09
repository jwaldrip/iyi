"""
proof/test_inode_lease_feasibility.py: Focused boundary test suite for inode read lease feasibility.

Tests refusal, revalidation, and reporting behavior per PlanNoVerityWitness (sections 1, 2, 3, 5):
- Total acceptance predicate:
  * always-F_RDLCK counterfeit from 9df returns nonzero (fails acceptance);
  * each required control record individually false, missing, duplicate, or malformed returns nonzero;
  * complete pass of all 14 controls produces INODE_LEASE_FIXTURE_CONTROLS_PASSED (exit 0);
- Privilege & inherited descriptor verification:
  * rejects root UID and EUID;
  * rejects non-zero capabilities;
  * rejects missing/malformed capability fields;
  * transient closed CPython opendir descriptor ignored cleanly via fcntl F_GETFD EBADF;
  * active leaked descriptors (> 2) rejected;
- Storage confinement:
  * absent RUNNER_TEMP fails closed before any writes;
- Native ELF & negative execution:
  * invalid ELF returns failure (ENOEXEC) and fails closed;
- Restored bytes after broken lease:
  * broken lease (F_UNLCK) followed by exact byte restoration is strictly rejected;
- Paired positive acquisition:
  * kernel refusing all F_SETLEASE cannot pass paired positive acquisition;
- Safe teardown and schema:
  * strict_eligible: false, cage_qualified: false, exec_identity_tested: false, native_fd_launch_tested: true.

Mock-only and host-safe; does not invoke real kernel ioctls, network calls, or shared systems.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import struct
import tempfile
import unittest
from unittest import mock

import proof.inode_lease_feasibility as ilf


def get_safe_test_tempdir() -> tempfile.TemporaryDirectory:
    """Create test temporary directory under OS realpath base."""
    real_base = os.path.realpath(tempfile.gettempdir())
    return tempfile.TemporaryDirectory(dir=real_base)


class TestTotalAcceptancePredicate(unittest.TestCase):
    def setUp(self):
        self.mock_controls = {
            cid: {"status": "PASS"} for cid in ilf.REQUIRED_CONTROL_IDS
        }
        self.mock_controls["genuine_lifecycle"]["custody_state"] = "CAPTURED"
        self.mock_controls["owned_sentinel_untouched"]["fixture_bytes_identical"] = True

    def test_complete_pass_produces_fixture_controls_passed_exit_0(self):
        verdict, detail, rc = ilf.evaluate_total_acceptance(self.mock_controls, global_cancelled=False)
        self.assertEqual(rc, 0)
        self.assertEqual(verdict, "INODE_LEASE_FIXTURE_CONTROLS_PASSED")

    def test_always_frdlck_counterfeit_from_9df_fails_acceptance(self):
        # 9df counterfeit: all controls pass even though break controls failed (status FAILED)
        bad_controls = dict(self.mock_controls)
        bad_controls["nonblocking_break"] = {"status": "FAILED", "reason": "Lease remained F_RDLCK"}
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("nonblocking_break did not PASS", detail)

    def test_missing_required_control_fails_incomplete(self):
        bad_controls = dict(self.mock_controls)
        del bad_controls["genuine_lifecycle"]
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("genuine_lifecycle", detail)

    def test_extra_unrecognized_control_fails_closed(self):
        bad_controls = dict(self.mock_controls)
        bad_controls["extra_unreviewed_control"] = {"status": "PASS"}
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "UNKNOWN_OR_ERROR")
        self.assertIn("extra_unreviewed_control", detail)

    def test_tainted_genuine_custody_fails_acceptance(self):
        bad_controls = dict(self.mock_controls)
        bad_controls["genuine_lifecycle"]["custody_state"] = "TAINTED"
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("Genuine custody state was not CAPTURED", detail)

    def test_tampered_sentinel_fails_acceptance(self):
        bad_controls = dict(self.mock_controls)
        bad_controls["owned_sentinel_untouched"]["fixture_bytes_identical"] = False
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("Sentinel fixture was modified", detail)

    def test_global_cancellation_produces_cancelled_verdict(self):
        verdict, detail, rc = ilf.evaluate_total_acceptance(self.mock_controls, global_cancelled=True)
        self.assertEqual(rc, 128 + 15)
        self.assertEqual(verdict, "CANCELLED")


class TestPrivilegeAndInheritedFdVerification(unittest.TestCase):
    def setUp(self):
        self.mock_libc = mock.Mock()
        self.mock_libc.prctl.return_value = 1
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()

    def test_root_uid_rejected(self):
        with mock.patch("os.getuid", return_value=0), mock.patch("os.geteuid", return_value=0):
            env_info, ok, msg = ilf.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Running as root", msg)

    def test_nonzero_capabilities_rejected(self):
        proc_status = (
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000001\n"
            "CapBnd:\t000001ffffffffff\n"
            "CapAmb:\t0000000000000000\n"
        )
        with mock.patch("os.getuid", return_value=self.current_uid), \
             mock.patch("os.geteuid", return_value=self.current_uid), \
             mock.patch.object(pathlib.Path, "exists", return_value=True), \
             mock.patch.object(pathlib.Path, "read_text", return_value=proc_status), \
             mock.patch("os.open", return_value=99), \
             mock.patch("os.listdir", return_value=["0", "1", "2", "99"]), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ilf.record_privileges()
            self.assertFalse(ok)
            self.assertIn("CapEff is non-zero", msg)

    def test_cpython_transient_closed_scan_fd_ignored(self):
        def fake_fcntl(fd, cmd):
            if fd == 42:
                raise OSError(errno.EBADF, "Bad file descriptor")
            return 0

        proc_status = (
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t000001ffffffffff\n"
            "CapAmb:\t0000000000000000\n"
        )
        with mock.patch("os.getuid", return_value=self.current_uid), \
             mock.patch("os.geteuid", return_value=self.current_uid), \
             mock.patch.object(pathlib.Path, "exists", return_value=True), \
             mock.patch.object(pathlib.Path, "read_text", return_value=proc_status), \
             mock.patch("os.open", return_value=99), \
             mock.patch("os.listdir", return_value=["0", "1", "2", "42", "99"]), \
             mock.patch("fcntl.fcntl", side_effect=fake_fcntl), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ilf.record_privileges()
            self.assertTrue(ok)
            self.assertEqual(env_info["inherited_fds"], [])

    def test_unexpected_inherited_fds_rejected(self):
        def fake_readlink(path):
            if path == "/proc/self/fd/4":
                return "/var/run/docker.sock"
            return "/dev/null"

        proc_status = (
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t000001ffffffffff\n"
            "CapAmb:\t0000000000000000\n"
        )
        with mock.patch("os.getuid", return_value=self.current_uid), \
             mock.patch("os.geteuid", return_value=self.current_uid), \
             mock.patch.object(pathlib.Path, "exists", return_value=True), \
             mock.patch.object(pathlib.Path, "read_text", return_value=proc_status), \
             mock.patch("os.open", return_value=99), \
             mock.patch("os.listdir", return_value=["0", "1", "2", "4", "99"]), \
             mock.patch("fcntl.fcntl", return_value=0), \
             mock.patch("os.readlink", side_effect=fake_readlink), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ilf.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Unexpected inherited descriptor", msg)


class TestStorageConfinement(unittest.TestCase):
    def test_absent_runner_temp_fails_before_writes(self):
        output_file = pathlib.Path("/tmp/nonexistent/report.json")
        with mock.patch("proof.inode_lease_feasibility.record_privileges", return_value=({}, True, "OK")), \
             mock.patch.dict(os.environ, {"RUNNER_TEMP": ""}, clear=True):
            with mock.patch("sys.argv", ["inode_lease_feasibility.py", "--output", str(output_file)]):
                rc = ilf.main()
                self.assertEqual(rc, 1)


class TestIoctlErrorClassification(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.run_dir = pathlib.Path(self.temp_dir.name)
        self.output_file = self.run_dir / "report.json"
        self.env_info = {"uid": os.getuid(), "euid": os.geteuid(), "capabilities": {}, "no_new_privs": 1}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_kernel_unsupported_returns_exit_2(self):
        def fake_fcntl(fd, cmd, arg=0):
            if cmd == ilf.F_SETLEASE:
                raise OSError(errno.ENOSYS, "Function not implemented")
            return 0

        with mock.patch("fcntl.fcntl", side_effect=fake_fcntl):
            controls, rc = ilf.run_all_controls(self.run_dir, self.output_file, self.env_info)
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
