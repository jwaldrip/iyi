"""
test_hosted_boundary.py: Focused tests for host boundary policy, canary verification, and execution.

Tests:
  1. Forbidden environment variable key patterns and stripping of caller credentials.
  2. Clean allowlisted environment construction with private HOME and TMPDIR.
  3. Boundary policy creation, validation, and normalization.
  4. macOS SBPL sandbox profile generation and rule ordering.
  5. Host boundary capability detection on Darwin runner.
  6. Canary receipt validation: rejection of fakes, mocks, and unproven results.
  7. Fail-closed policy execution when unsupported or unproven.
  8. Real native execution of all 8 canary probes:
     - Caller-owned fake secret read denial (EPERM).
     - Actions command-file read denial (EPERM).
     - Disallowed network connection denial (EPERM).
     - Permitted fixture read success.
     - Owned root write success.
     - Outside root write denial (EPERM).
     - Owned loopback server connect success.
     - Clean allowlisted environment verification.
  9. Real command execution under proven boundary.
  10. CLI diagnostics and canary execution.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from proof.hosted_boundary import (
    BoundaryCapabilities,
    BoundaryPolicy,
    CanaryReceipt,
    HostBoundaryCanaryFailedError,
    HostBoundaryError,
    HostBoundaryFakedProofError,
    HostBoundaryPolicyError,
    HostBoundaryUnsupportedError,
    build_clean_boundary_env,
    create_boundary_policy,
    detect_host_boundary_capabilities,
    execute_under_boundary,
    generate_macos_sbpl,
    is_forbidden_env_key,
    main,
    run_boundary_canary,
    sanitize_path,
)


class TestHostBoundaryPolicy(unittest.TestCase):
    """Unit tests for boundary policy data structures and environment rules."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_boundary_policy_")

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_is_forbidden_env_key(self) -> None:
        forbidden = [
            "GITHUB_TOKEN",
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "ACTIONS_RUNTIME_TOKEN",
            "GH_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "GPG_KEY",
            "MY_API_KEY",
            "DB_PASSWORD",
            "SERVICE_SECRET",
            "USER_AUTH_TOKEN",
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONHOME",
            "PYTHONOPTIMIZE",
            "PERL5OPT",
            "RUBYOPT",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "TEST_SANDBOX",
            "IYI_TARGET",
            "CRYSTAL_PATH",
        ]
        for key in forbidden:
            self.assertTrue(
                is_forbidden_env_key(key),
                f"Expected '{key}' to be recognized as forbidden environment variable",
            )

        allowed = [
            "PATH",
            "HOME",
            "TMPDIR",
            "USER",
            "LOGNAME",
            "SHELL",
            "LANG",
            "LC_ALL",
            "PYTHONDONTWRITEBYTECODE",
            "GOBIN",
            "GOCACHE",
        ]
        for key in allowed:
            self.assertFalse(
                is_forbidden_env_key(key),
                f"Expected '{key}' to NOT be marked forbidden",
            )

    def test_sanitize_path(self) -> None:
        raw = f"/usr/bin:.:/bin::relative/path:{self.test_dir}:/usr/bin"
        cleaned = sanitize_path(raw)
        segments = cleaned.split(os.pathsep)
        self.assertIn("/usr/bin", segments)
        self.assertIn("/bin", segments)
        self.assertIn(self.test_dir, segments)
        self.assertNotIn(".", segments)
        self.assertNotIn("relative/path", segments)
        self.assertNotIn("", segments)
        # Verify deduplication
        self.assertEqual(segments.count("/usr/bin"), 1)

    def test_create_boundary_policy_valid(self) -> None:
        policy = create_boundary_policy(
            owned_root=self.test_dir,
            extra_allowed_env={"GOBIN": os.path.join(self.test_dir, "bin")},
        )
        self.assertEqual(policy.owned_root, os.path.abspath(self.test_dir))
        self.assertEqual(policy.private_home, os.path.join(os.path.abspath(self.test_dir), "home"))
        self.assertEqual(policy.private_tmpdir, os.path.join(os.path.abspath(self.test_dir), "tmp"))
        self.assertIn(policy.owned_root, policy.allowed_write_roots)
        self.assertIn(policy.private_home, policy.allowed_write_roots)
        self.assertIn(policy.private_tmpdir, policy.allowed_write_roots)
        self.assertEqual(policy.extra_allowed_env["GOBIN"], os.path.join(self.test_dir, "bin"))

    def test_create_boundary_policy_invalid_root(self) -> None:
        with self.assertRaises(HostBoundaryPolicyError):
            create_boundary_policy(owned_root="relative/path")

    def test_create_boundary_policy_forbidden_extra_env(self) -> None:
        with self.assertRaises(HostBoundaryPolicyError):
            create_boundary_policy(
                owned_root=self.test_dir,
                extra_allowed_env={"GITHUB_TOKEN": "forbidden_token"},
            )

    def test_build_clean_boundary_env(self) -> None:
        policy = create_boundary_policy(owned_root=self.test_dir)
        env = build_clean_boundary_env(policy)

        # Must not contain dangerous ambient variables
        for pattern_str in ["TOKEN", "SECRET", "KEY", "GITHUB", "ACTIONS", "AWS", "SSH"]:
            for k in env:
                self.assertNotIn(pattern_str, k.upper())

        self.assertEqual(env["HOME"], policy.private_home)
        self.assertEqual(env["TMPDIR"], policy.private_tmpdir)
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")

        # Directories must exist with 0700 permissions
        self.assertTrue(os.path.isdir(policy.private_home))
        self.assertTrue(os.path.isdir(policy.private_tmpdir))

        home_stat = os.stat(policy.private_home)
        tmp_stat = os.stat(policy.private_tmpdir)
        self.assertEqual(stat.S_IMODE(home_stat.st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(tmp_stat.st_mode), 0o700)

    def test_build_clean_boundary_env_rejects_injected_forbidden_keys(self) -> None:
        policy = create_boundary_policy(owned_root=self.test_dir)
        with self.assertRaises(HostBoundaryPolicyError):
            build_clean_boundary_env(policy, extra_env={"SSH_AUTH_SOCK": "/tmp/ssh.sock"})

    def test_generate_macos_sbpl(self) -> None:
        secret_path = os.path.join(self.test_dir, "secret.key")
        policy = create_boundary_policy(
            owned_root=self.test_dir,
            forbidden_read_paths=[secret_path],
        )
        sbpl = generate_macos_sbpl(policy)

        # Network controls
        self.assertIn("(deny network-outbound)", sbpl)
        self.assertIn('(allow network-outbound (remote ip "localhost:*"))', sbpl)

        # File write controls
        self.assertIn("(deny file-write*)", sbpl)
        self.assertIn('(allow file-write-data (literal "/dev/null"))', sbpl)
        self.assertIn('(allow file-write-data (literal "/dev/zero"))', sbpl)
        self.assertIn('(allow file-write-data (literal "/dev/tty"))', sbpl)
        self.assertIn(f'(allow file-write* (subpath "{os.path.realpath(self.test_dir)}"))', sbpl)

        # File read controls for secrets
        self.assertIn(f'(deny file-read* (literal "{os.path.realpath(secret_path)}"))', sbpl)
        self.assertIn(f'(deny file-read* (subpath "{os.path.realpath(secret_path)}"))', sbpl)

        # Default allow
        self.assertIn("(allow default)", sbpl)


class TestCanaryReceiptAndValidation(unittest.TestCase):
    """Tests for canary receipt validation, fake rejection, and fail-closed behaviors."""

    def test_receipt_rejects_fakes(self) -> None:
        fake_receipt = CanaryReceipt(
            proven=True,
            is_fake=True,
            host_platform="darwin",
            probes={},
            diagnostic="Test fake claiming success",
            timestamp=1234567.0,
        )
        with self.assertRaises(HostBoundaryFakedProofError):
            fake_receipt.verify_for_hosted_execution()

    def test_receipt_rejects_unproven(self) -> None:
        failed_receipt = CanaryReceipt(
            proven=False,
            is_fake=False,
            host_platform="darwin",
            probes={},
            diagnostic="Probe secret_read failed",
            timestamp=1234567.0,
        )
        with self.assertRaises(HostBoundaryCanaryFailedError):
            failed_receipt.verify_for_hosted_execution()

    def test_receipt_rejects_non_darwin(self) -> None:
        linux_receipt = CanaryReceipt(
            proven=True,
            is_fake=False,
            host_platform="linux",
            probes={},
            diagnostic="Pretended success on Linux",
            timestamp=1234567.0,
        )
        with self.assertRaises(HostBoundaryUnsupportedError):
            linux_receipt.verify_for_hosted_execution()

    def test_receipt_valid_darwin_passes(self) -> None:
        valid_receipt = CanaryReceipt(
            proven=True,
            is_fake=False,
            host_platform="darwin",
            probes={"p1": {"passed": True}},
            diagnostic="All probes passed",
            timestamp=1234567.0,
        )
        # Must not raise
        valid_receipt.verify_for_hosted_execution()


class TestHostBoundaryCapabilities(unittest.TestCase):
    """Tests for host boundary capability detection."""

    def test_detect_capabilities(self) -> None:
        cap = detect_host_boundary_capabilities()
        self.assertIsInstance(cap, BoundaryCapabilities)
        if sys.platform == "darwin":
            self.assertTrue(cap.is_darwin)
            self.assertTrue(cap.sandbox_exec_functional)
            self.assertTrue(cap.can_enforce_sandbox)
            self.assertIsNotNone(cap.sandbox_exec_path)
            self.assertIn("Darwin", cap.diagnostic)
        else:
            self.assertFalse(cap.is_darwin)
            self.assertFalse(cap.can_enforce_sandbox)


class TestNativeCanaryExecution(unittest.TestCase):
    """
    Live native execution tests on the runner host.
    Verifies actual OS/kernel-enforced boundary probes without live shared services.
    """

    def setUp(self) -> None:
        self.owned_root = tempfile.mkdtemp(prefix="test_native_canary_")
        self.policy = create_boundary_policy(owned_root=self.owned_root)

    def tearDown(self) -> None:
        shutil.rmtree(self.owned_root, ignore_errors=True)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox-exec required for native canary")
    def test_run_boundary_canary_proves_all_probes(self) -> None:
        receipt = run_boundary_canary(self.policy)

        self.assertTrue(receipt.proven, f"Canary failed: {receipt.diagnostic}")
        self.assertFalse(receipt.is_fake)
        self.assertEqual(receipt.host_platform, "darwin")
        self.assertIn("verified", receipt.diagnostic)

        probes = receipt.probes
        self.assertGreaterEqual(len(probes), 8)

        # 1. Caller-owned fake secret read denial
        self.assertTrue(probes["fake_secret_read"]["passed"])
        self.assertTrue(probes["fake_secret_read"]["observed_denial"])

        # 2. Actions command-file read denial
        self.assertTrue(probes["actions_command_file_read"]["passed"])
        self.assertTrue(probes["actions_command_file_read"]["observed_denial"])

        # 3. Disallowed network connect denial
        self.assertTrue(probes["disallowed_network_connect"]["passed"])
        self.assertTrue(probes["disallowed_network_connect"]["observed_denial"])

        # 4. Permitted fixture read success
        self.assertTrue(probes["permitted_fixture_read"]["passed"])
        self.assertFalse(probes["permitted_fixture_read"]["observed_denial"])

        # 5. Owned root write success
        self.assertTrue(probes["owned_root_write"]["passed"])
        self.assertFalse(probes["owned_root_write"]["observed_denial"])

        # 6. Outside root write denial
        self.assertTrue(probes["outside_root_write"]["passed"])
        self.assertTrue(probes["outside_root_write"]["observed_denial"])

        # 7. Owned loopback server connect success
        self.assertTrue(probes["owned_loopback_connect"]["passed"])
        self.assertFalse(probes["owned_loopback_connect"]["observed_denial"])

        # 8. Clean environment verification
        self.assertTrue(probes["clean_allowlisted_env"]["passed"])

        # Receipt must pass verification check
        receipt.verify_for_hosted_execution()

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox-exec required for execution")
    def test_execute_under_boundary_real_command(self) -> None:
        # Run a simple python echo command under the boundary
        cmd = [sys.executable, "-c", "import os; print('HOSTED_BOUNDARY_ACTIVE:' + os.environ['HOME'])"]
        res = execute_under_boundary(self.policy, cmd)

        self.assertEqual(res.returncode, 0)
        self.assertIn("HOSTED_BOUNDARY_ACTIVE:", res.stdout)
        self.assertIn(self.policy.private_home, res.stdout)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox-exec required for execution")
    def test_execute_under_boundary_denies_outside_write(self) -> None:
        outside_dir = tempfile.mkdtemp(prefix="test_outside_forbidden_")
        try:
            forbidden_target = os.path.join(outside_dir, "should_fail.txt")
            cmd = [
                sys.executable,
                "-c",
                f"with open({forbidden_target!r}, 'w') as f: f.write('FAIL')\nprint('UNEXPECTED_SUCCESS')",
            ]
            res = execute_under_boundary(self.policy, cmd)

            # Must not succeed
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("UNEXPECTED_SUCCESS", res.stdout)
            self.assertIn("PermissionError", res.stderr + res.stdout)
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox-exec required for execution")
    def test_execute_under_boundary_denies_non_loopback_network(self) -> None:
        cmd = [
            sys.executable,
            "-c",
            "import socket\ns = socket.socket(); s.settimeout(0.5); s.connect(('192.0.2.1', 80))\nprint('UNEXPECTED_NET')",
        ]
        res = execute_under_boundary(self.policy, cmd)

        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn("UNEXPECTED_NET", res.stdout)
        self.assertIn("PermissionError", res.stderr + res.stdout)

    def test_cli_diagnose(self) -> None:
        rc = main(["--diagnose"])
        if sys.platform == "darwin":
            self.assertEqual(rc, 0)
        else:
            self.assertEqual(rc, 1)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox-exec required for CLI canary")
    def test_cli_canary(self) -> None:
        rc = main(["--canary", "--owned-root", self.owned_root])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
