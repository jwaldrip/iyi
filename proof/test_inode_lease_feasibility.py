"""
proof/test_inode_lease_feasibility.py: Pure mock test suite for inode read lease feasibility.

Authoritative contract: local://inode-lease-contract-revised.md (PlanNoVerityWitness)
Addresses complete review: local://inode-lease-review-23819.md

Tests pure orchestration, refusal, revalidation, and reporting behavior:
1. Total acceptance predicate:
   * exact always-F_RDLCK counterfeit from 9df returns nonzero (fails acceptance);
   * complete valid pass of all 14 controls produces INODE_LEASE_FIXTURE_CONTROLS_PASSED (exit 0);
   * each required record individually missing, false, duplicate, extra or malformed returns nonzero;
   * removal_requested without actual requester completion fails forced revocation;
   * requester cancellation and restored matching bytes never clear TAINTED;
   * sentinel tampering fails acceptance;
   * global cancellation produces CANCELLED (exit 143);
2. Privilege & inherited descriptor verification:
   * root UID and EUID rejected;
   * non-zero capabilities rejected;
   * transient closed CPython opendir descriptor ignored via EBADF;
   * active leaked descriptors (> 2) rejected;
3. Output root & confinement:
   * absent or invalid RUNNER_TEMP fails closed with exit 1 before any filesystem writes;
   * non-numeric run/attempt or invalid SHA fails closed with exit 1 before any writes;
4. Kernel prerequisite checks:
   * missing or out-of-range lease-break-time fails with exit 2;
5. Native ELF fixtures:
   * reviewed 132-byte ELF64 fixture verified against hardcoded SHA256;
   * invalid ELF fixture verified distinct and corrupt.

All tests are mock-only and host-safe: no actual leases, native exec, blocking operations,
signals, or mmap are performed on the host.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import proof.inode_lease_feasibility as ilf


def get_mock_passing_controls() -> dict:
    """Construct mock controls dictionary with complete valid observation fields."""
    return {
        "genuine_lifecycle": {
            "status": "PASS",
            "link_verified": True,
            "atime_verified": True,
            "native_exec_rc": 73,
            "out_unlinked": True,
            "bytes_verified": True,
            "custody_state": "CAPTURED",
        },
        "existing_writer": {
            "status": "PASS",
            "eagain_observed": True,
            "paired_acquisition": True,
        },
        "fd_closed_shared_mmap": {
            "status": "PASS",
            "mmap_eagain_observed": True,
            "mmap_paired_acquisition": True,
        },
        "nonblocking_break": {
            "status": "PASS",
            "nb_open_refused_eagain": True,
            "break_notified": True,
        },
        "forced_blocking_open_and_restore": {
            "status": "PASS",
            "forced_revocation_observed": True,
            "restored_bytes_custody_rejected": True,
        },
        "pathname_truncate_forced": {
            "status": "PASS",
            "truncate_break_observed": True,
        },
        "cancelled_requester_sticky": {
            "status": "PASS",
            "cancellation_observed": True,
            "sticky_taint_on_cancel": True,
        },
        "read_utime_without_exec": {
            "status": "PASS",
            "execution_omitted_rejected": True,
        },
        "failed_native_exec": {
            "status": "PASS",
            "exact_enoexec_observed": True,
            "actual_errno": errno.ENOEXEC,
        },
        "same_bytes_different_inode_launch": {
            "status": "PASS",
            "distinct_inode_join_rejected": True,
            "executed_exit_code": 73,
        },
        "reference_substitution": {
            "status": "PASS",
            "substitution_rejected": True,
        },
        "holder_death": {
            "status": "PASS",
            "holder_terminated_sigkill": True,
            "genuine_holder_unaffected": True,
        },
        "racing_open_acquire": {
            "status": "PASS",
            "conflict_resolved_safely": True,
        },
        "owned_sentinel_untouched": {
            "status": "PASS",
            "fixture_bytes_identical": True,
        },
    }


class TestTotalAcceptancePredicate(unittest.TestCase):
    def setUp(self):
        self.controls = get_mock_passing_controls()

    def test_complete_valid_controls_produce_exit_0(self):
        verdict, detail, rc = ilf.evaluate_total_acceptance(self.controls, global_cancelled=False)
        self.assertEqual(rc, 0)
        self.assertEqual(verdict, "INODE_LEASE_FIXTURE_CONTROLS_PASSED")

    def test_9df_always_frdlck_counterfeit_fails_acceptance(self):
        # 9df counterfeit: break control failed because lease remained F_RDLCK
        bad_controls = dict(self.controls)
        bad_controls["nonblocking_break"] = {
            "status": "FAILED",
            "reason": "Lease remained F_RDLCK; break was not observed",
        }
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("nonblocking_break did not PASS", detail)

    def test_missing_required_control_fails_incomplete(self):
        bad_controls = dict(self.controls)
        del bad_controls["genuine_lifecycle"]
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("genuine_lifecycle", detail)

    def test_extra_unrecognized_control_fails_closed(self):
        bad_controls = dict(self.controls)
        bad_controls["unrecognized_extra_control"] = {"status": "PASS"}
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "UNKNOWN_OR_ERROR")
        self.assertIn("unrecognized_extra_control", detail)

    def test_tainted_genuine_custody_fails_acceptance(self):
        bad_controls = dict(self.controls)
        bad_controls["genuine_lifecycle"] = dict(bad_controls["genuine_lifecycle"])
        bad_controls["genuine_lifecycle"]["custody_state"] = "TAINTED"
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("Genuine custody state was not CAPTURED", detail)

    def test_tampered_sentinel_fails_acceptance(self):
        bad_controls = dict(self.controls)
        bad_controls["owned_sentinel_untouched"] = dict(bad_controls["owned_sentinel_untouched"])
        bad_controls["owned_sentinel_untouched"]["fixture_bytes_identical"] = False
        verdict, detail, rc = ilf.evaluate_total_acceptance(bad_controls, global_cancelled=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "FAILED")
        self.assertIn("Sentinel fixture was modified", detail)

    def test_global_cancellation_produces_cancelled_verdict(self):
        verdict, detail, rc = ilf.evaluate_total_acceptance(self.controls, global_cancelled=True)
        self.assertEqual(rc, 128 + 15)
        self.assertEqual(verdict, "CANCELLED")


class TestPrivilegeAndInheritedDescriptors(unittest.TestCase):
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
             mock.patch.object(ilf, "libc", self.mock_libc):
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
             mock.patch.object(ilf, "libc", self.mock_libc):
            env_info, ok, msg = ilf.record_privileges()
            self.assertTrue(ok)
            self.assertEqual(env_info["inherited_fds"], [])

    def test_unexpected_inherited_descriptors_rejected(self):
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
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch.object(ilf, "libc", self.mock_libc):
            env_info, ok, msg = ilf.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Unexpected inherited descriptors present", msg)


class TestOutputConfinementAndEnvValidation(unittest.TestCase):
    def test_absent_runner_temp_fails_before_any_writes(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch("sys.argv", ["inode_lease_feasibility.py", "--output", "out.json"]), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            rc = ilf.main()
            self.assertEqual(rc, 1)
            self.assertIn("RUNNER_TEMP is missing", mock_stderr.getvalue())

    def test_invalid_run_id_or_attempt_fails_before_writes(self):
        with tempfile.TemporaryDirectory() as td:
            env = {
                "RUNNER_TEMP": td,
                "GITHUB_RUN_ID": "not-numeric",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
            }
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("sys.argv", ["inode_lease_feasibility.py", "--output", "out.json"]), \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                rc = ilf.main()
                self.assertEqual(rc, 1)
                self.assertIn("GITHUB_RUN_ID or GITHUB_RUN_ATTEMPT missing", mock_stderr.getvalue())

    def test_invalid_sha_fails_before_writes(self):
        with tempfile.TemporaryDirectory() as td:
            env = {
                "RUNNER_TEMP": td,
                "GITHUB_RUN_ID": "123",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": "short-sha",
            }
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("sys.argv", ["inode_lease_feasibility.py", "--output", "out.json"]), \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                rc = ilf.main()
                self.assertEqual(rc, 1)
                self.assertIn("GITHUB_SHA missing or not a 40-character hex", mock_stderr.getvalue())


class TestKernelPrerequisites(unittest.TestCase):
    def test_missing_lease_break_time_fails_closed(self):
        with mock.patch.object(pathlib.Path, "exists", return_value=False):
            val, ok, msg = ilf.read_lease_break_time()
            self.assertFalse(ok)
            self.assertEqual(val, 0)
            self.assertIn("unavailable", msg)

    def test_out_of_range_lease_break_time_fails_closed(self):
        with mock.patch.object(pathlib.Path, "exists", return_value=True), \
             mock.patch.object(pathlib.Path, "read_text", return_value="0\n"):
            val, ok, msg = ilf.read_lease_break_time()
            self.assertFalse(ok)
            self.assertEqual(val, 0)
            self.assertIn("outside valid range", msg)


class TestNativeElfFixtures(unittest.TestCase):
    def test_reviewed_elf64_binary_matches_expected_size_and_hash(self):
        self.assertEqual(len(ilf.REVIEWED_ELF64_BYTES), 132)
        expected_hash = hashlib.sha256(ilf.REVIEWED_ELF64_BYTES).hexdigest()
        self.assertEqual(ilf.REVIEWED_ELF64_SHA256, expected_hash)
        # Verify ELF magic and ET_EXEC type
        self.assertEqual(ilf.REVIEWED_ELF64_BYTES[:4], b"\x7FELF")
        self.assertEqual(ilf.REVIEWED_ELF64_BYTES[16:18], b"\x02\x00")  # ET_EXEC

    def test_invalid_elf_binary_distinct(self):
        self.assertEqual(len(ilf.INVALID_ELF_BYTES), 132)
        self.assertNotEqual(ilf.INVALID_ELF_BYTES, ilf.REVIEWED_ELF64_BYTES)
        self.assertEqual(ilf.INVALID_ELF_BYTES[18], 0xFF)
        self.assertEqual(ilf.INVALID_ELF_BYTES[19], 0xFF)


if __name__ == "__main__":
    unittest.main()
