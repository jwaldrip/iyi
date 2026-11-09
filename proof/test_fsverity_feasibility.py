"""
proof/test_fsverity_feasibility.py: Focused boundary test suite for in-process fs-verity feasibility probe.

Tests refusal, revalidation, and reporting behavior per ReplanVerityFeasibility and ReviewHostedBoundary:
- Missing/malformed privilege fields and unexpected inherited FDs;
- CPython transient closed opendir descriptor handled cleanly without false positive;
- Rejection of active leaked descriptors (including memfd, socket, pipe, and /proc descriptors);
- Component-wise no-follow open (open_path_nofollow) rejecting symlink components and relative paths;
- Job-local storage gating rejecting unproven locality (HOME/mnt evaluated read-only with no writes);
- Sticky identity errors (root open failure, root identity-read error with no candidate writes,
  unresolved mnt_id, dev mismatch, fstatvfs failure, mount boundary crossing);
- Deduplication by st_dev and f_fsid against policy-excluded root mounts and alias presentations;
- Descriptor-confined fixture verification and retention controls:
  * verified retained-byte equality
  * partial-write rejection (short write fails closed)
  * zero-write rejection (no progress fails closed)
  * copied-size mismatch rejection (fstat size discrepancy fails closed)
  * fatal retention error;
- Legacy --dir entry mode requiring valid positive mnt_id;
- ENOTSUP/ENOTTY versus permission and I/O errors;
- Malformed measurement and unexpected writable success;
- Post-verity write refusal (EPERM/ETXTBSY);
- Full successful eligible-candidate execution path with harmless fixture copy collection.

All tests are mock-only and host-safe; they do not invoke real filesystem ioctls, network calls,
or shared systems.
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

import proof.fsverity_feasibility as ff


def get_safe_test_tempdir() -> tempfile.TemporaryDirectory:
    """
    Create temporary directory under OS realpath base.
    On Darwin, /var and /tmp are symlinks to /private/var and /private/tmp.
    Using os.path.realpath on the temp base ensures component-wise nofollow
    traversal does not encounter intermediate symlinks on the test base path.
    """
    real_base = os.path.realpath(tempfile.gettempdir())
    return tempfile.TemporaryDirectory(dir=real_base)


class TestOpenPathNofollow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.base = pathlib.Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_relative_path_rejected(self):
        with self.assertRaises(ValueError):
            ff.open_path_nofollow("relative/path")

    def test_dot_dot_traversal_rejected(self):
        # Create path under safe realpath temp base so it traverses real components
        # before hitting the '..' component, reaching the traversal logic cleanly
        sub = self.base / "sub"
        sub.mkdir(mode=0o700)
        dot_dot_path = f"{sub}/../etc"
        with self.assertRaises(ValueError) as ctx:
            ff.open_path_nofollow(dot_dot_path)
        self.assertIn("Path traversal '..' forbidden", str(ctx.exception))

    def test_symlink_component_rejected(self):
        real_subdir = self.base / "real_dir"
        real_subdir.mkdir(mode=0o700)
        symlink_dir = self.base / "symlink_dir"
        os.symlink(real_subdir, symlink_dir)

        # Attempting to open through symlink_dir with open_path_nofollow must fail
        with self.assertRaises(OSError) as ctx:
            ff.open_path_nofollow(str(symlink_dir))
        self.assertIn(ctx.exception.errno, (errno.ELOOP, errno.ENOTDIR, errno.EEXIST))


class TestPrivilegeAndInheritedFdVerification(unittest.TestCase):
    def setUp(self):
        self.mock_libc = mock.Mock()
        self.mock_libc.prctl.return_value = 1  # PR_GET_NO_NEW_PRIVS returns 1
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()

    def test_root_uid_rejected(self):
        with mock.patch("os.getuid", return_value=0), mock.patch("os.geteuid", return_value=0):
            env_info, ok, msg = ff.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Running as root", msg)

    def test_root_euid_rejected(self):
        with mock.patch("os.getuid", return_value=self.current_uid), mock.patch("os.geteuid", return_value=0):
            env_info, ok, msg = ff.record_privileges()
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
            env_info, ok, msg = ff.record_privileges()
            self.assertFalse(ok)
            self.assertIn("CapEff is non-zero", msg)

    def test_missing_capability_field_fails_closed(self):
        proc_status = (
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
             mock.patch("os.listdir", return_value=["0", "1", "2", "99"]), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ff.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Missing capability field CapInh", msg)

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
            env_info, ok, msg = ff.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Unexpected inherited descriptor", msg)

    def test_memfd_and_proc_handles_rejected(self):
        def fake_readlink(path):
            if path == "/proc/self/fd/5":
                return "memfd:test (deleted)"
            if path == "/proc/self/fd/6":
                return "/proc/sys/kernel/random/boot_id"
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
             mock.patch("os.listdir", return_value=["0", "1", "2", "5", "6", "99"]), \
             mock.patch("fcntl.fcntl", return_value=0), \
             mock.patch("os.readlink", side_effect=fake_readlink), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ff.record_privileges()
            self.assertFalse(ok)
            self.assertIn("Unexpected inherited descriptor", msg)

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
            env_info, ok, msg = ff.record_privileges()
            self.assertTrue(ok)
            self.assertEqual(env_info["inherited_fds"], [])

    def test_positive_privilege_check_mocked_isolation(self):
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
             mock.patch("os.listdir", return_value=["0", "1", "2", "99"]), \
             mock.patch("os.close"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("ctypes.CDLL", return_value=self.mock_libc):
            env_info, ok, msg = ff.record_privileges()
            self.assertTrue(ok)
            self.assertEqual(env_info["no_new_privs"], 1)
            self.assertEqual(env_info["uid"], self.current_uid)


class TestJobLocalOwnershipAndMountBinding(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.target_dir = pathlib.Path(self.temp_dir.name)
        self.output_file = self.target_dir / "report.json"
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self.env_info = {"uid": self.current_uid, "euid": self.current_uid, "capabilities": {}, "no_new_privs": 1}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_root_open_failure_stops_discovery_stickily_no_candidate_writes(self):
        candidate_dir = self.target_dir / "candidate_runner_temp"
        candidate_dir.mkdir(mode=0o700)

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": []}), \
             mock.patch("proof.fsverity_feasibility.open_path_nofollow", side_effect=OSError(errno.EACCES, "Permission denied")):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(candidate_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
                self.assertIn("ROOT_IDENTITY_FAILURE", report["detail"])
                # Explicit assertion: NO candidate files or probe directories were created
                created_items = list(candidate_dir.iterdir())
                self.assertEqual(created_items, [])

    def test_root_identity_read_error_stops_discovery_stickily_no_candidate_writes(self):
        candidate_dir = self.target_dir / "candidate_runner_temp"
        candidate_dir.mkdir(mode=0o700)

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": []}), \
             mock.patch("proof.fsverity_feasibility.open_path_nofollow", return_value=10), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=OSError(errno.EIO, "Root fstatvfs failed")), \
             mock.patch("os.close"):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(candidate_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
                self.assertIn("ROOT_IDENTITY_FAILURE", report["detail"])
                # Explicit assertion: NO candidate files or probe directories were created
                created_items = list(candidate_dir.iterdir())
                self.assertEqual(created_items, [])

    def test_different_uid_base_directory_rejected(self):
        fake_mountinfo = [{
            "mnt_id": 50,
            "parent_id": 1,
            "major_minor": "8:16",
            "root": "/",
            "mount_point": "/mnt",
            "mount_opts": ["rw"],
            "fstype": "ext4",
            "mount_source": "/dev/sdb",
            "super_opts": ["rw"],
        }]
        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.open_path_nofollow", return_value=10), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),  # Root / identity
                 (2064, "8:16", 88888, 0xef53), # Candidate identity
             ]), \
             mock.patch("os.fstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=self.current_uid + 1, st_dev=2064)), \
             mock.patch("os.close"):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": "", "GITHUB_WORKSPACE": "", "HOME": "", "MNT": "/mnt"}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")

    def test_unproven_job_local_storage_rejected_for_writing(self):
        # Real candidate directory under safe tempdir owned by current UID
        home_test_dir = self.target_dir / "home_runner"
        home_test_dir.mkdir(mode=0o700)

        fake_mountinfo = [{
            "mnt_id": 60,
            "parent_id": 1,
            "major_minor": "8:32",
            "root": str(home_test_dir),
            "mount_point": str(home_test_dir),
            "mount_opts": ["rw"],
            "fstype": "ext4",
            "mount_source": "/dev/sdc",
            "super_opts": ["rw"],
        }]
        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=60), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),   # Root / identity
                 (2080, "8:32", 12345, 0xef53),  # HOME candidate identity
             ]):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": "", "GITHUB_WORKSPACE": "", "HOME": str(home_test_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
                home_cand = next(c for c in report["census"]["evaluated_candidates"] if c.get("label") == "HOME")
                self.assertIn("EVALUATED_READ_ONLY", home_cand["status"])
                # Explicit assertion: prove no probe directories or files were written to HOME
                self.assertEqual(list(home_test_dir.iterdir()), [])

    def test_unresolved_mnt_id_is_sticky_failure(self):
        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": []}), \
             mock.patch("proof.fsverity_feasibility.open_path_nofollow", return_value=10), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", return_value=(2048, "8:0", 99999, 0xef53)), \
             mock.patch("os.fstat", return_value=mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=self.current_uid, st_dev=2064)), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=None), \
             mock.patch("os.close"):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": "/tmp/runner"}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
                self.assertIn("MNT_ID_UNRESOLVED", report["detail"])

    def test_alias_deduplication_by_fsid(self):
        c1_dir = self.target_dir / "c1"
        c1_dir.mkdir(mode=0o700)
        c2_dir = self.target_dir / "c2"
        c2_dir.mkdir(mode=0o700)

        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "0:50", "root": "/subvol1", "mount_point": str(c1_dir), "mount_opts": ["rw"], "fstype": "btrfs", "mount_source": "/dev/sdb", "super_opts": ["rw"]},
            {"mnt_id": 20, "parent_id": 1, "major_minor": "0:51", "root": "/subvol2", "mount_point": str(c2_dir), "mount_opts": ["rw"], "fstype": "btrfs", "mount_source": "/dev/sdb", "super_opts": ["rw"]},
        ]
        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[
                 10,  # c1 base_fd mnt_id
                 10,  # c1 child probe_dir mnt_id
                 20,  # c2 base_fd mnt_id
             ]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),   # Root /
                 (50, "0:50", 77777, 0x9123683e),  # Candidate 1 (btrfs fsid=77777)
                 (51, "0:51", 77777, 0x9123683e),  # Candidate 2 (same btrfs fsid=77777)
             ]):
            probe_invocations = []

            def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
                probe_invocations.append((mnt_id, str(target_dir_path)))
                return 2  # Candidate 1 returned UNAVAILABLE_ON_TESTED_PATH

            with mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(c1_dir), "GITHUB_WORKSPACE": str(c2_dir)}, clear=True):
                    rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                    self.assertEqual(rc, 2)
                    report = json.loads(self.output_file.read_text())
                    self.assertEqual(report["result"], "UNAVAILABLE_ON_TESTED_PATH")
                    all_cands = report["census"]["evaluated_candidates"]

                    # Filter records by labels RUNNER_TEMP and GITHUB_WORKSPACE per planner specification
                    c1_cand = next(c for c in all_cands if c.get("label") == "RUNNER_TEMP")
                    c2_cand = next(c for c in all_cands if c.get("label") == "GITHUB_WORKSPACE")

                    self.assertIn("EVALUATED_FS_VERITY_UNAVAILABLE_ON_MOUNT", c1_cand["status"])
                    self.assertIn("SKIPPED_ALREADY_EVALUATED_FILESYSTEM", c2_cand["status"])

                    # Assert exact probe count: candidate 1 was probed; candidate 2 was deduplicated and not probed
                    self.assertEqual(len(probe_invocations), 1)
                    self.assertEqual(probe_invocations[0][0], 10)

class TestEligibleCandidateExecution(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.base_dir = pathlib.Path(self.temp_dir.name)
        self.diag_dir = self.base_dir / "diag"
        self.diag_dir.mkdir(mode=0o700)
        self.output_file = self.diag_dir / "report.json"
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self.env_info = {"uid": self.current_uid, "euid": self.current_uid, "capabilities": {}, "no_new_privs": 1}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_eligible_candidate_full_success_path_with_byte_equality(self):
        fake_mountinfo = [
            {
                "mnt_id": 1,
                "parent_id": 0,
                "major_minor": "8:0",
                "root": "/",
                "mount_point": "/",
                "mount_opts": ["rw"],
                "fstype": "ext4",
                "mount_source": "/dev/root",
                "super_opts": ["rw"],
            },
            {
                "mnt_id": 99,
                "parent_id": 1,
                "major_minor": "8:32",
                "root": "/",
                "mount_point": str(self.base_dir),
                "mount_opts": ["rw"],
                "fstype": "ext4",
                "mount_source": "/dev/sdc",
                "super_opts": ["rw"],
            },
        ]

        def fake_ioctl(fd, request, buf=None, *args):
            if request == ff.FS_IOC_ENABLE_VERITY:
                return 0
            if request == ff.FS_IOC_MEASURE_VERITY:
                struct.pack_into("=HH", buf, 0, 1, 32)
                buf[4:36] = b"\xcc" * 32
                return 0
            return 0

        orig_open = os.open

        def fake_open(path, flags, *open_args, **kwargs):
            if (flags & os.O_ACCMODE) == os.O_WRONLY and not (flags & os.O_CREAT):
                raise OSError(errno.EPERM, "Operation not permitted")
            return orig_open(path, flags, *open_args, **kwargs)

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[
                 99,  # base_fd mnt_id
                 99,  # child probe_dir mnt_id
                 99,  # created fixture fd mnt_id
                 99,  # reopened ro_fd mnt_id
             ]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),   # Root "/" identity
                 (2080, "8:32", 12345, 0xef53),  # Candidate identity
             ]), \
             mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("os.open", side_effect=fake_open), \
             mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.base_dir)}, clear=True):
            rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
            self.assertEqual(rc, 0)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "FS_VERITY_SUPPORTED_ON_TESTED_MOUNT")
            self.assertEqual(report["strict_eligible"], False)
            self.assertEqual(report["details"]["verity_algorithm"], 1)
            self.assertEqual(report["details"]["verity_digest_length"], 32)
            self.assertEqual(report["details"]["write_refusal_errno"], errno.EPERM)

            # Verified retained-byte equality
            artifact_copy = self.output_file.parent / "fsverity_fixture.dat.copy"
            self.assertTrue(artifact_copy.exists())
            expected_payload = b"iyi-kernel-fsverity-feasibility-payload-20261109\n" * 64
            self.assertEqual(artifact_copy.read_bytes(), expected_payload)

    def test_retention_short_write_fails_nonzero(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 99, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.base_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sdc", "super_opts": ["rw"]},
        ]

        def fake_ioctl(fd, request, buf=None, *args):
            if request in (ff.FS_IOC_ENABLE_VERITY, ff.FS_IOC_MEASURE_VERITY):
                if request == ff.FS_IOC_MEASURE_VERITY:
                    struct.pack_into("=HH", buf, 0, 1, 32)
                    buf[4:36] = b"\xcc" * 32
                return 0
            return 0

        orig_open = os.open
        orig_write = os.write
        copy_fd_recorded = None

        def fake_open(path, flags, *open_args, **kwargs):
            nonlocal copy_fd_recorded
            if (flags & os.O_ACCMODE) == os.O_WRONLY and not (flags & os.O_CREAT):
                raise OSError(errno.EPERM, "Operation not permitted")
            opened_fd = orig_open(path, flags, *open_args, **kwargs)
            if "fsverity_fixture.dat.copy" in str(path):
                copy_fd_recorded = opened_fd
            return opened_fd

        def fake_write(fd, data):
            if copy_fd_recorded is not None and fd == copy_fd_recorded:
                return 0  # Injected zero-write failure (no progress) on artifact copy
            return orig_write(fd, data)

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[99, 99, 99, 99]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),
                 (2080, "8:32", 12345, 0xef53),
             ]), \
             mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("os.open", side_effect=fake_open), \
             mock.patch("os.write", side_effect=fake_write), \
             mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.base_dir)}, clear=True):
            rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
            self.assertEqual(rc, 1)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
            self.assertIn("Short write copying artifact", report["detail"])

    def test_retention_size_mismatch_fails_nonzero(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 99, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.base_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sdc", "super_opts": ["rw"]},
        ]

        def fake_ioctl(fd, request, buf=None, *args):
            if request in (ff.FS_IOC_ENABLE_VERITY, ff.FS_IOC_MEASURE_VERITY):
                if request == ff.FS_IOC_MEASURE_VERITY:
                    struct.pack_into("=HH", buf, 0, 1, 32)
                    buf[4:36] = b"\xcc" * 32
                return 0
            return 0

        orig_open = os.open
        orig_fstat = os.fstat
        copy_fd_recorded = None

        def fake_open(path, flags, *open_args, **kwargs):
            nonlocal copy_fd_recorded
            if (flags & os.O_ACCMODE) == os.O_WRONLY and not (flags & os.O_CREAT):
                raise OSError(errno.EPERM, "Operation not permitted")
            opened_fd = orig_open(path, flags, *open_args, **kwargs)
            if "fsverity_fixture.dat.copy" in str(path):
                copy_fd_recorded = opened_fd
            return opened_fd

        def fake_fstat(fd):
            res = orig_fstat(fd)
            if copy_fd_recorded is not None and fd == copy_fd_recorded:
                return os.stat_result((
                    res.st_mode,
                    res.st_ino,
                    res.st_dev,
                    res.st_nlink,
                    res.st_uid,
                    res.st_gid,
                    999,  # Injected size discrepancy on copied artifact
                    res.st_atime,
                    res.st_mtime,
                    res.st_ctime,
                ))
            return res

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[99, 99, 99, 99]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),
                 (2080, "8:32", 12345, 0xef53),
             ]), \
             mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("os.open", side_effect=fake_open), \
             mock.patch("os.fstat", side_effect=fake_fstat), \
             mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.base_dir)}, clear=True):
            rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
            self.assertEqual(rc, 1)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
            self.assertIn("Copied artifact size mismatch", report["detail"])


class TestDirModeAndIoctlErrorClassification(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.target_dir = pathlib.Path(self.temp_dir.name)
        self.output_file = self.target_dir / "report.json"
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self.env_info = {"uid": self.current_uid, "euid": self.current_uid, "capabilities": {}, "no_new_privs": 1}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dir_mode_unresolved_mnt_id_fails_closed(self):
        with mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=None):
            rc = ff.run_probe_on_directory(self.target_dir, self.output_file, self.env_info)
            self.assertEqual(rc, 1)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
            self.assertIn("MNT_ID_UNRESOLVED", report["detail"])

    def test_enotsup_returns_unavailable_exit_2(self):
        def fake_ioctl(fd, request, *args):
            if request == ff.FS_IOC_ENABLE_VERITY:
                raise OSError(errno.EOPNOTSUPP, "Operation not supported")
            raise OSError(errno.EINVAL, "Unexpected ioctl")

        with mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=42):
            rc = ff.run_probe_on_directory(self.target_dir, self.output_file, self.env_info)
            self.assertEqual(rc, 2)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNAVAILABLE_ON_TESTED_PATH")
            self.assertEqual(report["strict_eligible"], False)
            self.assertEqual(report["details"]["errno"], errno.EOPNOTSUPP)

    def test_enotty_returns_unavailable_exit_2(self):
        def fake_ioctl(fd, request, *args):
            if request == ff.FS_IOC_ENABLE_VERITY:
                raise OSError(errno.ENOTTY, "Inappropriate ioctl for device")
            raise OSError(errno.EINVAL, "Unexpected ioctl")

        with mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=42):
            rc = ff.run_probe_on_directory(self.target_dir, self.output_file, self.env_info)
            self.assertEqual(rc, 2)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNAVAILABLE_ON_TESTED_PATH")
            self.assertEqual(report["strict_eligible"], False)
            self.assertEqual(report["details"]["errno"], errno.ENOTTY)

    def test_permission_error_returns_unknown_or_error_exit_1(self):
        def fake_ioctl(fd, request, *args):
            if request == ff.FS_IOC_ENABLE_VERITY:
                raise OSError(errno.EACCES, "Permission denied")
            raise OSError(errno.EINVAL, "Unexpected ioctl")

        with mock.patch("fcntl.ioctl", side_effect=fake_ioctl), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=42):
            rc = ff.run_probe_on_directory(self.target_dir, self.output_file, self.env_info)
            self.assertEqual(rc, 1)
            report = json.loads(self.output_file.read_text())
            self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")



class TestDescriptorClosureAndMultiCandidateTransitions(unittest.TestCase):
    def setUp(self):
        self.temp_dir = get_safe_test_tempdir()
        self.target_dir = pathlib.Path(self.temp_dir.name)
        self.c1_dir = self.target_dir / "c1"
        self.c1_dir.mkdir(mode=0o700)
        self.c2_dir = self.target_dir / "c2"
        self.c2_dir.mkdir(mode=0o700)
        self.output_file = self.target_dir / "report.json"
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self.env_info = {"uid": self.current_uid, "euid": self.current_uid, "capabilities": {}, "no_new_privs": 1}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_child_fd_closed_on_success(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
        ]
        captured_child_fd = None

        def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
            nonlocal captured_child_fd
            captured_child_fd = dir_fd
            flags = fcntl.fcntl(dir_fd, fcntl.F_GETFD)
            self.assertIsNotNone(flags)
            return 0

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[10, 10]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),
                 (2080, "8:32", 12345, 0xef53),
             ]), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 0)
                self.assertIsNotNone(captured_child_fd)
                with self.assertRaises(OSError) as ctx:
                    fcntl.fcntl(captured_child_fd, fcntl.F_GETFD)
                self.assertEqual(ctx.exception.errno, errno.EBADF)

    def test_child_fd_closed_on_unavailable(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
        ]
        captured_child_fd = None

        def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
            nonlocal captured_child_fd
            captured_child_fd = dir_fd
            return 2

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[10, 10]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),
                 (2080, "8:32", 12345, 0xef53),
             ]), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 2)
                self.assertIsNotNone(captured_child_fd)
                with self.assertRaises(OSError) as ctx:
                    fcntl.fcntl(captured_child_fd, fcntl.F_GETFD)
                self.assertEqual(ctx.exception.errno, errno.EBADF)

    def test_child_fd_closed_on_exception(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
        ]
        captured_child_fd = None

        def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
            nonlocal captured_child_fd
            captured_child_fd = dir_fd
            raise RuntimeError("Simulated unexpected probe failure")

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[10, 10]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),
                 (2080, "8:32", 12345, 0xef53),
             ]), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir)}, clear=True):
                with self.assertRaises(RuntimeError):
                    ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertIsNotNone(captured_child_fd)
                with self.assertRaises(OSError) as ctx:
                    fcntl.fcntl(captured_child_fd, fcntl.F_GETFD)
                self.assertEqual(ctx.exception.errno, errno.EBADF)

    def test_two_distinct_mounts_2_to_0(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
            {"mnt_id": 20, "parent_id": 1, "major_minor": "8:48", "root": "/", "mount_point": str(self.c2_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sdb", "super_opts": ["rw"]},
        ]
        probe_calls = []

        def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
            probe_calls.append((mnt_id, str(target_dir_path)))
            if mnt_id == 10:
                return 2  # Mount 1 returns UNAVAILABLE
            if mnt_id == 20:
                return 0  # Mount 2 returns SUPPORTED
            return 1

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[
                 10,  # c1 base_fd
                 10,  # c1 child_fd
                 20,  # c2 base_fd
                 20,  # c2 child_fd
             ]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),  # Root /
                 (2080, "8:32", 11111, 0xef53), # Candidate 1
                 (2096, "8:48", 22222, 0xef53), # Candidate 2
             ]), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir), "GITHUB_WORKSPACE": str(self.c2_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 0)
                self.assertEqual(len(probe_calls), 2)
                self.assertEqual(probe_calls[0][0], 10)
                self.assertEqual(probe_calls[1][0], 20)

    def test_two_distinct_mounts_2_to_1(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
            {"mnt_id": 20, "parent_id": 1, "major_minor": "8:48", "root": "/", "mount_point": str(self.c2_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sdb", "super_opts": ["rw"]},
        ]
        probe_calls = []

        def fake_execute_probe(dir_fd, mnt_id, target_dir_path, output_path, env_info, census=None):
            probe_calls.append((mnt_id, str(target_dir_path)))
            if mnt_id == 10:
                return 2  # Mount 1 returns UNAVAILABLE
            if mnt_id == 20:
                return 1  # Mount 2 returns ERROR
            return 1

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", side_effect=[
                 10,  # c1 base_fd
                 10,  # c1 child_fd
                 20,  # c2 base_fd
                 20,  # c2 child_fd
             ]), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", side_effect=[
                 (2048, "8:0", 99999, 0xef53),  # Root /
                 (2080, "8:32", 11111, 0xef53), # Candidate 1
                 (2096, "8:48", 22222, 0xef53), # Candidate 2
             ]), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir), "GITHUB_WORKSPACE": str(self.c2_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                self.assertEqual(len(probe_calls), 2)

    def test_initial_error_stops_without_evaluating_later_candidates(self):
        fake_mountinfo = [
            {"mnt_id": 1, "parent_id": 0, "major_minor": "8:0", "root": "/", "mount_point": "/", "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/root", "super_opts": ["rw"]},
            {"mnt_id": 10, "parent_id": 1, "major_minor": "8:32", "root": "/", "mount_point": str(self.c1_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sda", "super_opts": ["rw"]},
            {"mnt_id": 20, "parent_id": 1, "major_minor": "8:48", "root": "/", "mount_point": str(self.c2_dir), "mount_opts": ["rw"], "fstype": "ext4", "mount_source": "/dev/sdb", "super_opts": ["rw"]},
        ]
        probe_calls = []

        def fake_execute_probe(*args, **kwargs):
            probe_calls.append(args)
            return 0

        with mock.patch("proof.fsverity_feasibility.record_census", return_value={"mountinfo": fake_mountinfo}), \
             mock.patch("proof.fsverity_feasibility.get_fd_mnt_id", return_value=None), \
             mock.patch("proof.fsverity_feasibility.get_fd_fs_identity", return_value=(2048, "8:0", 99999, 0xef53)), \
             mock.patch("proof.fsverity_feasibility.execute_probe_on_directory_fd", side_effect=fake_execute_probe):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.c1_dir), "GITHUB_WORKSPACE": str(self.c2_dir)}, clear=True):
                rc = ff.run_existing_mounts_discovery(self.output_file, self.env_info)
                self.assertEqual(rc, 1)
                report = json.loads(self.output_file.read_text())
                self.assertEqual(report["result"], "UNKNOWN_OR_ERROR")
                self.assertIn("MNT_ID_UNRESOLVED", report["detail"])
                self.assertEqual(len(probe_calls), 0)
if __name__ == "__main__":
    unittest.main()
