"""Focused unit and invariant tests for Linux platform port of the proof harness.

Verifies:
  1. base_env platform library configuration and ambient IYI_* stripping.
  2. probe_atime_observable true-binary resolution and fail-closed checks.
  3. _process_group_members BSD vs POSIX ps options.
  4. Census schema validation: closed-key schema with 'linux' field,
     Darwin old-census support on Darwin, and strict fail-closed
     rejection of missing 'linux' field on Linux.
  5. verify_ledger and verify_evidence platform requirement derivation,
     ensuring no fallback from Linux to Darwin and SCHEMA-UNCLASSIFIED on missing linux.
  6. Pin-bound IYI_PROOF_INPUTS_DIR digest verification and stage reinjection.
  7. artifact_legs.py compare_r1 invocation through frames_equivalent CLI on Linux.
  8. /private/tmp/iyp-* invariance preservation.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from proof.proofkit import (
    DRIVERS_29,
    IdentityError,
    base_env,
    compute_inputs_bundle_digest,
    inspect_pin_inputs,
    probe_atime_observable,
    sha256_file,
    write_pin,
    _process_group_members,
    _validate_census_schema,
    validate_census,
    verify_ledger,
    check_identity,
    _validated_report_dir,
    write_origin_records,
    verify_origin_records,
)
from proof.run_proof import fresh_stage_env
import proof.artifact_legs as artifact_legs


class TestBaseEnvPlatform(unittest.TestCase):
    def test_darwin_sets_homebrew_paths(self):
        with patch("platform.system", return_value="Darwin"):
            env = base_env({"env_path": "/bin", "env_home": "/home"})
            self.assertEqual(env.get("LIBRARY_PATH"), "/opt/homebrew/opt/bdw-gc/lib")
            self.assertEqual(
                env.get("PKG_CONFIG_PATH"),
                "/opt/homebrew/opt/openssl@3/lib/pkgconfig",
            )
            self.assertEqual(env.get("PYTHONDONTWRITEBYTECODE"), "1")
            self.assertEqual(env.get("PATH"), "/bin")
            self.assertEqual(env.get("HOME"), "/home")

    def test_linux_omits_homebrew_paths(self):
        with patch("platform.system", return_value="Linux"):
            with patch.dict(os.environ, {}, clear=True):
                env = base_env({"env_path": "/usr/bin", "env_home": "/root"})
                self.assertNotIn("LIBRARY_PATH", env)
                self.assertNotIn("PKG_CONFIG_PATH", env)
                self.assertEqual(env.get("PYTHONDONTWRITEBYTECODE"), "1")
                self.assertEqual(env.get("PATH"), "/usr/bin")
                self.assertEqual(env.get("HOME"), "/root")

    def test_strips_ambient_iyi_vars(self):
        ambient = {
            "IYI_OPTS": "--debug",
            "IYI_PATH": "/custom/path",
            "CRYSTAL_PATH": "/custom/crystal",
            "IYI_PROOF_INPUTS_DIR": "/untrusted/inputs",
            "PYTHONOPTIMIZE": "1",
            "PATH": "/ambient/bin",
            "HOME": "/ambient/home",
        }
        with patch.dict(os.environ, ambient, clear=True):
            env = base_env({"env_path": "/pinned/bin", "env_home": "/pinned/home"})
            self.assertNotIn("IYI_OPTS", env)
            self.assertNotIn("IYI_PATH", env)
            self.assertNotIn("CRYSTAL_PATH", env)
            self.assertNotIn("IYI_PROOF_INPUTS_DIR", env)
            self.assertNotIn("PYTHONOPTIMIZE", env)
            self.assertEqual(env.get("PATH"), "/pinned/bin")
            self.assertEqual(env.get("HOME"), "/pinned/home")


class TestProbeAtimeObservable(unittest.TestCase):
    def test_resolves_true_binary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # When true binary exists, it advances atime and succeeds
            result = probe_atime_observable(tmpdir)
            self.assertIn("atime_after_exec_ns", result)
            self.assertIn("mtime_ns", result)
            self.assertGreater(result["atime_after_exec_ns"], result["mtime_ns"])

    def test_fails_closed_when_true_binary_absent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("os.path.exists", return_value=False), patch("shutil.which", return_value=None):
                with self.assertRaises(IdentityError) as ctx:
                    probe_atime_observable(tmpdir)
                self.assertEqual(ctx.exception.reason, "EXEC-UNOBSERVABLE")


class TestProcessGroupMembers(unittest.TestCase):
    def test_ps_args_darwin(self):
        with patch("platform.system", return_value="Darwin"):
            mock_proc = MagicMock(returncode=0, stdout="100 200\n101 200\n", stderr="")
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                members = _process_group_members(200, exclude=100)
                self.assertEqual(members, (101,))
                cmd = mock_run.call_args[0][0]
                self.assertIn("-axo", cmd)

    def test_ps_args_linux(self):
        with patch("platform.system", return_value="Linux"):
            mock_proc = MagicMock(returncode=0, stdout="100 200\n102 200\n", stderr="")
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                members = _process_group_members(200, exclude=100)
                self.assertEqual(members, (102,))
                cmd = mock_run.call_args[0][0]
                self.assertIn("-eo", cmd)


class TestCensusSchemaPlatform(unittest.TestCase):
    def _make_variant(self, variant_id="v1", kind="positive", darwin="required", linux="required", **kwargs):
        v = {
            "id": variant_id,
            "kind": kind,
            "first_root": "r1",
            "vars": {},
            "sources": ["s1"],
            "output": None,
            "darwin": darwin,
            "requires": [],
            "verdict": {"lines": [10], "contains": ["OK"]},
        }
        if linux is not None:
            v["linux"] = linux
        v.update(kwargs)
        return v

    def _make_census(self, variants):
        return {
            "census_version": 1,
            "driver": "test",
            "script": "bench/std_test_exercise.sh",
            "script_sha256": "0" * 64,
            "sites": [
                {
                    "lines": [10],
                    "command": "run",
                    "kind": "positive",
                    "contains": ["test"],
                    "variants": variants,
                }
            ],
            "non_invocations": [],
            "skips": [],
            "not_skips": [],
            "pass_sentinel": {"line": 100, "regex": "^PASS$", "text": "PASS"},
            "exec_evidence": [],
        }

    def test_schema_closed_keys_allows_linux_and_darwin(self):
        census = self._make_census([self._make_variant(darwin="required", linux="required")])
        violations = []
        _validate_census_schema(census, violations)
        self.assertEqual(violations, [])

    def test_schema_closed_keys_rejects_unknown_platform(self):
        census = self._make_census([self._make_variant(darwin="required", linux="required", windows="required")])
        violations = []
        _validate_census_schema(census, violations)
        self.assertTrue(any(v[0] == "C5.0-schema" and "unknown keys" in v[2] for v in violations))

    def test_darwin_old_census_without_linux_supported_on_darwin(self):
        census = self._make_census([self._make_variant(darwin="required", linux=None)])
        violations = []
        _validate_census_schema(census, violations, target_platform="darwin")
        self.assertEqual(violations, [])

    def test_linux_fails_closed_when_linux_field_missing(self):
        census = self._make_census([self._make_variant(darwin="required", linux=None)])
        violations = []
        _validate_census_schema(census, violations, target_platform="linux")
        self.assertTrue(any(v[0] == "C5.0-schema" and ("missing keys" in v[2] or "invalid fields" in v[2]) for v in violations))

    def test_linux_accepts_valid_dual_platform_census(self):
        census = self._make_census([
            self._make_variant(variant_id="v1", darwin="required", linux="required"),
            self._make_variant(variant_id="v2", darwin="platform-excluded", linux="required"),
            self._make_variant(variant_id="v3", darwin="required", linux="platform-excluded"),
        ])
        violations = []
        _validate_census_schema(census, violations, target_platform="linux")
        self.assertEqual(violations, [])


class TestVerifyLedgerPlatform(unittest.TestCase):
    def _create_ledger_file(self, tmpdir, nonce="n1", driver="test", attempt=1, chain_id="0"*32, records=None):
        ledger_path = os.path.join(tmpdir, "ledger.jsonl")
        with open(ledger_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "v": 1,
                "kind": "header",
                "nonce": nonce,
                "driver": driver,
                "attempt": attempt,
                "chain_id": chain_id,
            }) + "\n")
            if records:
                for r in records:
                    f.write(json.dumps(r) + "\n")
        return ledger_path

    def test_linux_fails_closed_on_unclassified_variant(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = self._create_ledger_file(tmpdir)
            census = {
                "driver": "test",
                "script": "bench/std_test_exercise.sh",
                "sites": [
                    {
                        "lines": [10],
                        "variants": [
                            {
                                "id": "v_unclass",
                                "kind": "positive",
                                "darwin": "required",
                                "verdict": {"lines": [10], "contains": ["OK"]},
                            }
                        ],
                    }
                ],
            }
            verdict = verify_ledger(
                ledger,
                census=census,
                driver="test",
                nonce="n1",
                attempt=1,
                chain_id="0"*32,
                work_tmp=tmpdir,
                repo=tmpdir,
                platform_tmp=None,
                target_platform="linux",
            )
            self.assertIn("SCHEMA-UNCLASSIFIED", verdict.statuses)
            self.assertTrue(any("lacks explicit linux classification" in r for r in verdict.reasons))

    def test_linux_discriminates_required_vs_platform_excluded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = self._create_ledger_file(tmpdir)
            census = {
                "driver": "test",
                "script": "bench/std_test_exercise.sh",
                "sites": [
                    {
                        "lines": [10],
                        "variants": [
                            {
                                "id": "v_darwin_only",
                                "kind": "positive",
                                "darwin": "required",
                                "linux": "platform-excluded",
                                "verdict": {"lines": [10], "contains": ["OK"]},
                            }
                        ],
                    }
                ],
            }
            verdict = verify_ledger(
                ledger,
                census=census,
                driver="test",
                nonce="n1",
                attempt=1,
                chain_id="0"*32,
                work_tmp=tmpdir,
                repo=tmpdir,
                platform_tmp=None,
                target_platform="linux",
            )
            # Not exercised should NOT be present because it is platform-excluded on Linux
            self.assertNotIn("NOT-EXERCISED", verdict.statuses)

    def test_darwin_retains_darwin_requirements(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger = self._create_ledger_file(tmpdir)
            census = {
                "driver": "test",
                "script": "bench/std_test_exercise.sh",
                "sites": [
                    {
                        "lines": [10],
                        "variants": [
                            {
                                "id": "v_darwin_req",
                                "kind": "positive",
                                "darwin": "required",
                                "linux": "platform-excluded",
                                "verdict": {"lines": [10], "contains": ["OK"]},
                            }
                        ],
                    }
                ],
            }
            verdict = verify_ledger(
                ledger,
                census=census,
                driver="test",
                nonce="n1",
                attempt=1,
                chain_id="0"*32,
                work_tmp=tmpdir,
                repo=tmpdir,
                platform_tmp=None,
                target_platform="darwin",
            )
            self.assertIn("NOT-EXERCISED", verdict.statuses)


class TestOfflineInputsBinding(unittest.TestCase):
    def test_compute_inputs_bundle_digest_manifest_payload_verified(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = os.path.join(tmpdir, "payload.txt")
            with open(payload, "w") as f:
                f.write("contentA\n")
            sha_a = hashlib.sha256(b"contentA\n").hexdigest()
            manifest_file = os.path.join(tmpdir, "bundle.sha256")
            with open(manifest_file, "w") as f:
                f.write(f"{sha_a}  payload.txt\n")
            digest = compute_inputs_bundle_digest(tmpdir)
            self.assertTrue(bool(digest))

            # Mutating payload while leaving manifest unchanged must fail closed
            with open(payload, "w") as f:
                f.write("contentB_mutated\n")
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-MANIFEST-MISMATCH")

    def test_compute_inputs_bundle_digest_manifest_unlisted_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = os.path.join(tmpdir, "payload.txt")
            with open(payload, "w") as f:
                f.write("contentA\n")
            sha_a = hashlib.sha256(b"contentA\n").hexdigest()
            manifest_file = os.path.join(tmpdir, "bundle.sha256")
            with open(manifest_file, "w") as f:
                f.write(f"{sha_a}  payload.txt\n")
            # Add unlisted file
            unlisted = os.path.join(tmpdir, "unlisted.txt")
            with open(unlisted, "w") as f:
                f.write("unlisted\n")
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-MANIFEST-MISMATCH")

    def test_compute_inputs_bundle_digest_manifest_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = os.path.join(tmpdir, "bundle.sha256")
            with open(manifest_file, "w") as f:
                f.write("0123456789abcdef" * 4 + "  nonexistent.txt\n")
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-MANIFEST-MISMATCH")

    def test_compute_inputs_bundle_digest_rejects_symlink_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = os.path.join(tmpdir, "real.txt")
            with open(real_file, "w") as f:
                f.write("data\n")
            symlink_file = os.path.join(tmpdir, "link.txt")
            os.symlink(real_file, symlink_file)
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-SYMLINK")

    def test_compute_inputs_bundle_digest_rejects_symlink_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            real_dir = os.path.join(tmpdir, "real_dir")
            os.makedirs(real_dir)
            symlink_dir = os.path.join(tmpdir, "link_dir")
            os.symlink(real_dir, symlink_dir)
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-SYMLINK")

    def test_compute_inputs_bundle_digest_includes_hidden_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "file.txt"), "w") as f:
                f.write("visible\n")
            digest1 = compute_inputs_bundle_digest(tmpdir)
            # Add a dotfile (hidden file)
            with open(os.path.join(tmpdir, ".hidden"), "w") as f:
                f.write("hidden\n")
            digest2 = compute_inputs_bundle_digest(tmpdir)
            self.assertNotEqual(digest1, digest2)

    def test_compute_inputs_bundle_digest_rejects_unreadable_nested_dir(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root bypasses filesystem permissions")
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "unreadable_dir")
            os.makedirs(nested)
            with open(os.path.join(nested, "hidden.txt"), "w") as f:
                f.write("secret\n")
            os.chmod(nested, 0o000)
            try:
                with self.assertRaises(IdentityError) as ctx:
                    compute_inputs_bundle_digest(tmpdir)
                self.assertEqual(ctx.exception.reason, "INPUTS-UNREADABLE")
            finally:
                os.chmod(nested, 0o755)

    def test_compute_inputs_bundle_digest_rejects_fifo_special_file(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo not supported on this platform")
        with tempfile.TemporaryDirectory() as tmpdir:
            fifo_path = os.path.join(tmpdir, "test.fifo")
            try:
                os.mkfifo(fifo_path)
            except (OSError, PermissionError):
                self.skipTest("mkfifo failed")
            with self.assertRaises(IdentityError) as ctx:
                compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(ctx.exception.reason, "INPUTS-SPECIAL-FILE")

    def test_fresh_stage_env_reinjects_pinned_inputs_dir(self):
        pin = {
            "env_path": "/bin",
            "env_home": "/home",
            "inputs_dir": "/trusted/inputs/dir",
        }
        with tempfile.TemporaryDirectory() as attempt_dir:
            env = fresh_stage_env(pin, attempt_dir, "test_stage")
            self.assertEqual(env.get("IYI_PROOF_INPUTS_DIR"), "/trusted/inputs/dir")

    def test_check_identity_fails_on_tampered_inputs_digest(self):
        from proof.smoke_test import PinFixture
        with tempfile.TemporaryDirectory(prefix="iyi-inputs-test-") as inputs_dir:
            payload = os.path.join(inputs_dir, "payload.txt")
            with open(payload, "w") as f:
                f.write("clean\n")
            with PinFixture() as fixture:
                pin = write_pin(
                    fixture.report,
                    fixture.p,
                    fixture.w,
                    fixture.compiler,
                    DRIVERS_29,
                    inputs_dir=inputs_dir,
                )
                # Untampered pin passes check_identity
                check_identity(pin)

                # Intentionally mutate payload in real owned inputs directory
                with open(payload, "w") as f:
                    f.write("tampered\n")

                with self.assertRaises(IdentityError) as ctx:
                    check_identity(pin)
                self.assertEqual(ctx.exception.reason, "INPUTS-DIGEST-CHANGED")

    def test_check_identity_fails_on_missing_inputs_dir(self):
        from proof.smoke_test import PinFixture
        missing_dir = os.path.join(tempfile.gettempdir(), f"iyi-missing-inputs-{os.urandom(8).hex()}")
        os.makedirs(missing_dir)
        with open(os.path.join(missing_dir, "file.txt"), "w") as f:
            f.write("data\n")
        with PinFixture() as fixture:
            pin = write_pin(
                fixture.report,
                fixture.p,
                fixture.w,
                fixture.compiler,
                DRIVERS_29,
                inputs_dir=missing_dir,
            )
            check_identity(pin)

            # Remove the directory
            shutil.rmtree(missing_dir)

            with self.assertRaises(IdentityError) as ctx:
                check_identity(pin)
            self.assertEqual(ctx.exception.reason, "INPUTS-DIR-CHANGED")

    def test_linux_pin_fails_closed_without_inputs_dir(self):
        from proof.smoke_test import PinFixture
        with PinFixture() as fixture:
            with patch.dict(os.environ):
                os.environ.pop("IYI_PROOF_INPUTS_DIR", None)
                with self.assertRaises(IdentityError) as ctx:
                    write_pin(
                        fixture.report,
                        fixture.p,
                        fixture.w,
                        fixture.compiler,
                        DRIVERS_29,
                        inputs_dir=None,
                        target_platform="linux",
                    )
                self.assertEqual(ctx.exception.reason, "INPUTS-DIR-REQUIRED")

    def test_darwin_pin_default_unchanged_without_inputs_dir(self):
        from proof.smoke_test import PinFixture
        with PinFixture() as fixture:
            with patch.dict(os.environ):
                os.environ.pop("IYI_PROOF_INPUTS_DIR", None)
                pin = write_pin(
                    fixture.report,
                    fixture.p,
                    fixture.w,
                    fixture.compiler,
                    DRIVERS_29,
                    inputs_dir=None,
                    target_platform="darwin",
                )
                self.assertIsNone(pin.get("inputs_dir"))
                self.assertIsNone(pin.get("inputs_digest"))
                check_identity(pin)


class TestArtifactLegsCompareR1(unittest.TestCase):
    def test_compare_r1_invokes_frames_script_on_linux(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = os.path.join(tmpdir, "repo")
            bench_dir = os.path.join(repo_root, "bench")
            os.makedirs(bench_dir)
            frames_script = os.path.join(bench_dir, "frames_equivalent.py")
            with open(frames_script, "w") as f:
                f.write("import sys\nraise SystemExit(0)\n")

            with patch("platform.system", return_value="Linux"):
                ok, msg = artifact_legs.compare_r1(
                    name="case",
                    status_a=0,
                    status_b=0,
                    stdout_a=b"out",
                    stderr_a=b"err_a",
                    stdout_b=b"out",
                    stderr_b=b"err_b",
                    repo_root=repo_root,
                    row_dir=tmpdir,
                    tag="test",
                )
                self.assertTrue(ok)
                self.assertIn("stderr frames equivalent", msg)

    def test_compare_r1_fails_closed_when_frames_script_returns_1_on_linux(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = os.path.join(tmpdir, "repo")
            bench_dir = os.path.join(repo_root, "bench")
            os.makedirs(bench_dir)
            frames_script = os.path.join(bench_dir, "frames_equivalent.py")
            with open(frames_script, "w") as f:
                f.write("import sys\nsys.stdout.write('mismatched frames\\n')\nraise SystemExit(1)\n")

            with patch("platform.system", return_value="Linux"):
                ok, msg = artifact_legs.compare_r1(
                    name="case",
                    status_a=0,
                    status_b=0,
                    stdout_a=b"out",
                    stderr_a=b"err_a",
                    stdout_b=b"out",
                    stderr_b=b"err_b",
                    repo_root=repo_root,
                    row_dir=tmpdir,
                    tag="test",
                )
                self.assertFalse(ok)
                self.assertIn("stderr frames equivalence failed", msg)


class TestPrivateTmpInvariance(unittest.TestCase):
    def test_preserves_private_tmp_requirement(self):
        # Must accept /private/tmp/iyp-12345678
        valid_dir = "/private/tmp/iyp-12345678"
        with patch("os.path.realpath", return_value=valid_dir), patch("os.path.exists", return_value=False):
            res = _validated_report_dir(valid_dir, require_empty=True, chain_id="12345678" + "0"*24)
            self.assertEqual(res, valid_dir)

    def test_rejects_loosened_tmp_path(self):
        # Must reject /tmp/iyp-12345678 when not resolving to /private/tmp
        invalid_dir = "/tmp/iyp-12345678"
        with patch("os.path.realpath", return_value=invalid_dir):
            with self.assertRaises(IdentityError) as ctx:
                _validated_report_dir(invalid_dir, require_empty=True)
            self.assertEqual(ctx.exception.reason, "REPORT-DIR-NAME")


class TestOriginRecordsAdversarialHardlink(unittest.TestCase):
    def test_adversarial_unexecuted_hardlink_remains_rejected_after_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            attempt_dir = os.path.join(tmpdir, "attempt")
            os.makedirs(attempt_dir)
            source_file = os.path.join(tmpdir, "source.bin")
            with open(source_file, "wb") as f:
                f.write(b"binary_payload\n")
            hardlink_ref = os.path.join(tmpdir, "unexec_link.bin")
            os.link(source_file, hardlink_ref)

            st = os.stat(hardlink_ref)
            mtime_ns = st.st_mtime_ns
            os.utime(hardlink_ref, ns=(mtime_ns, mtime_ns))

            stat_target = (0, {"out_ino": st.st_ino, "out_mtime_ns": mtime_ns}, hardlink_ref)
            stat_result = (0, {"out_ino": st.st_ino, "out_mtime_ns": mtime_ns}, hardlink_ref, os.stat(hardlink_ref))

            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            origin_path = write_origin_records(
                attempt_dir,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                stat_targets=[stat_target],
                stat_results=[stat_result],
            )
            initial_sha = sha256_file(origin_path)
            receipt = {
                "schema": "iyi-sealed-origin-receipt-v1",
                "chain_id": "0" * 32,
                "attempt": 1,
                "driver": "demo",
                "origin_records_sha256": initial_sha,
                "ledger_sha256": hashlib.sha256(b"{}\n").hexdigest(),
            }

            # Initial verification fails because atime was not advanced during execution
            ok, reasons = verify_origin_records(
                origin_path,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                expected_indices=[0],
                receipt_data=receipt,
            )
            self.assertFalse(ok)
            self.assertTrue(any("did not advance atime" in r for r in reasons))

            # Adversary / archive collector reads the hardlink file, advancing its atime
            with open(hardlink_ref, "rb") as f:
                _ = f.read()
            os.utime(hardlink_ref, ns=(mtime_ns + 10_000_000, mtime_ns))
            self.assertGreater(os.stat(hardlink_ref).st_atime_ns, mtime_ns)

            # Re-verification against the immutable origin record REMAINS REJECTED!
            ok_after, reasons_after = verify_origin_records(
                origin_path,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                expected_indices=[0],
                receipt_data=receipt,
            )
            self.assertFalse(ok_after)
            self.assertTrue(any("did not advance atime" in r for r in reasons_after))

            # Tampered origin records (adversary modifying origin_records.json) fails receipt check
            with open(origin_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            doc["entries"][0]["atime_advanced"] = True
            doc["overall_status"] = "PASS"
            with open(origin_path, "w", encoding="utf-8") as f:
                json.dump(doc, f)

            ok_tampered, reasons_tampered = verify_origin_records(
                origin_path,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                expected_indices=[0],
                receipt_data=receipt,
            )
            self.assertFalse(ok_tampered)
            self.assertTrue(any("receipt origin_records_sha256 mismatch" in r for r in reasons_tampered))

    def test_real_run3_archive_read_final_transition(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)

            source_file = os.path.join(report_dir, "source.bin")
            with open(source_file, "wb") as f:
                f.write(b"payload\n")
            hardlink_ref = os.path.join(report_dir, "unexec.bin")
            os.link(source_file, hardlink_ref)

            st = os.stat(hardlink_ref)
            mtime_ns = st.st_mtime_ns
            os.utime(hardlink_ref, ns=(mtime_ns, mtime_ns))

            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write('{"v":1,"kind":"header","driver":"demo","attempt":1,"chain_id":"00000000000000000000000000000000"}\n')

            stat_target = (0, {"out_ino": st.st_ino, "out_mtime_ns": mtime_ns}, hardlink_ref)
            stat_result = (0, {"out_ino": st.st_ino, "out_mtime_ns": mtime_ns}, hardlink_ref, os.stat(hardlink_ref))

            origin_path = write_origin_records(
                attempt_dir,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                stat_targets=[stat_target],
                stat_results=[stat_result],
            )
            initial_sha = sha256_file(origin_path)

            receipts_dir = os.path.join(report_dir, "sealed-receipts")
            os.makedirs(receipts_dir)
            receipt_path = os.path.join(receipts_dir, "receipt-run3-demo-a1.json")
            receipt = {
                "schema": "iyi-sealed-origin-receipt-v1",
                "chain_id": "0" * 32,
                "attempt": 1,
                "driver": "demo",
                "origin_records_sha256": initial_sha,
                "ledger_sha256": sha256_file(ledger_file),
                "receipt_status": "NOT-EXECUTED",
            }
            with open(receipt_path, "w") as f:
                json.dump(receipt, f)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1,
                    "chain_id": "0" * 32,
                    "unit": "run3/demo",
                    "attempt": 1,
                    "status": "PASS",
                    "reasons": [],
                    "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000,
                    "ended_ns": 2000,
                    "survivors": [],
                }, f)

            pin = {
                "report_dir": report_dir,
                "chain_id": "0" * 32,
            }

            unit_info, earlier, reasons = _collect_final_unit(
                pin,
                run3_dir,
                "run3/demo",
                "run3",
                sealed_receipts_dir=receipts_dir,
            )
            self.assertEqual(unit_info["status"], "FAIL")
            self.assertTrue(any("did not advance atime" in r for r in reasons))

            # Simulate archive collector reading the hardlink payload (advancing atime on disk)
            with open(hardlink_ref, "rb") as f:
                _ = f.read()
            os.utime(hardlink_ref, ns=(mtime_ns + 50_000_000, mtime_ns))
            self.assertGreater(os.stat(hardlink_ref).st_atime_ns, mtime_ns)

            # Re-collecting final unit after archive read REMAINS FAIL!
            unit_info_after, _, reasons_after = _collect_final_unit(
                pin,
                run3_dir,
                "run3/demo",
                "run3",
                sealed_receipts_dir=receipts_dir,
            )
            self.assertEqual(unit_info_after["status"], "FAIL")
            self.assertTrue(any("did not advance atime" in r for r in reasons_after))

    def test_write_origin_records_rejects_adversarial_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            attempt_dir = os.path.join(tmpdir, "attempt")
            os.makedirs(attempt_dir)
            target = os.path.join(tmpdir, "external_target")
            with open(target, "w") as f:
                f.write("target\n")
            origin_symlink = os.path.join(attempt_dir, "origin_records.json")
            os.symlink(target, origin_symlink)

            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            with self.assertRaises(IdentityError) as ctx:
                write_origin_records(
                    attempt_dir,
                    driver="demo",
                    attempt=1,
                    chain_id="0" * 32,
                    ledger_path=ledger_file,
                    stat_targets=[],
                    stat_results=[],
                )
            self.assertEqual(ctx.exception.reason, "ORIGIN-RECORDS-SYMLINK")

    def test_write_origin_records_non_overwriting_under_preexisting_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            attempt_dir = os.path.join(tmpdir, "attempt")
            os.makedirs(attempt_dir)
            origin_path = os.path.join(attempt_dir, "origin_records.json")
            with open(origin_path, "w") as f:
                f.write('{"initial":"preexisting"}\n')

            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            res_path = write_origin_records(
                attempt_dir,
                driver="demo",
                attempt=1,
                chain_id="0" * 32,
                ledger_path=ledger_file,
                stat_targets=[],
                stat_results=[],
            )
            self.assertEqual(res_path, origin_path)
            with open(origin_path, "r") as f:
                content = f.read()
            self.assertEqual(content, '{"initial":"preexisting"}\n')

    def test_final_acceptance_rejects_missing_origin_records_on_linux(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1,
                    "chain_id": "0" * 32,
                    "unit": "run3/demo",
                    "attempt": 1,
                    "status": "PASS",
                    "reasons": [],
                    "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000,
                    "ended_ns": 2000,
                    "survivors": [],
                }, f)

            pin = {"report_dir": report_dir, "chain_id": "0" * 32}

            with patch("platform.system", return_value="Linux"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "FAIL")
                self.assertTrue(any("origin_records.json is missing" in r for r in reasons))

    def test_final_acceptance_rejects_directory_and_symlink_origin_records(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1,
                    "chain_id": "0" * 32,
                    "unit": "run3/demo",
                    "attempt": 1,
                    "status": "PASS",
                    "reasons": [],
                    "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000,
                    "ended_ns": 2000,
                    "survivors": [],
                }, f)

            pin = {"report_dir": report_dir, "chain_id": "0" * 32}

            origin_dir = os.path.join(attempt_dir, "origin_records.json")
            os.makedirs(origin_dir)
            with patch("platform.system", return_value="Linux"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "FAIL")
                self.assertTrue(any("is not a regular file" in r for r in reasons))
            os.rmdir(origin_dir)

            dummy_target = os.path.join(report_dir, "dummy.json")
            with open(dummy_target, "w") as f:
                f.write("{}\n")
            os.symlink(dummy_target, origin_dir)
            with patch("platform.system", return_value="Linux"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "FAIL")
                self.assertTrue(any("is a forbidden symlink" in r for r in reasons))

    def test_final_acceptance_rejects_missing_receipt_on_linux(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)
            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            origin_path = os.path.join(attempt_dir, "origin_records.json")
            with open(origin_path, "w") as f:
                json.dump({
                    "v": 1, "kind": "origin_records", "driver": "demo", "attempt": 1,
                    "chain_id": "0" * 32, "ledger_path": os.path.realpath(ledger_file),
                    "ledger_sha256": sha256_file(ledger_file),
                    "timestamp_ns": 1000, "entries": [], "overall_status": "PASS",
                }, f)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1, "chain_id": "0" * 32, "unit": "run3/demo", "attempt": 1, "status": "PASS",
                    "reasons": [], "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000, "ended_ns": 2000, "survivors": [],
                }, f)

            pin = {"report_dir": report_dir, "chain_id": "0" * 32}

            with patch("platform.system", return_value="Linux"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "UNFAITHFUL")
                self.assertTrue(any("missing required host sealed receipt" in r for r in reasons))

    def test_final_acceptance_rejects_payload_forged_report_receipt_on_linux(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)
            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            origin_path = os.path.join(attempt_dir, "origin_records.json")
            with open(origin_path, "w") as f:
                json.dump({
                    "v": 1, "kind": "origin_records", "driver": "demo", "attempt": 1,
                    "chain_id": "0" * 32, "ledger_path": os.path.realpath(ledger_file),
                    "ledger_sha256": sha256_file(ledger_file),
                    "timestamp_ns": 1000, "entries": [], "overall_status": "PASS",
                }, f)
            forged_dir = os.path.join(report_dir, "sealed-receipts")
            os.makedirs(forged_dir)
            with open(os.path.join(forged_dir, "receipt-run3-demo-a1.json"), "w") as f:
                json.dump({"schema": "iyi-sealed-origin-receipt-v1", "forged": True}, f)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1, "chain_id": "0" * 32, "unit": "run3/demo", "attempt": 1, "status": "PASS",
                    "reasons": [], "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000, "ended_ns": 2000, "survivors": [],
                }, f)

            pin = {"report_dir": report_dir, "chain_id": "0" * 32}

            with patch("platform.system", return_value="Linux"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "UNFAITHFUL")
                self.assertTrue(any("missing required host sealed receipt" in r for r in reasons))

    def test_final_acceptance_darwin_no_receipt_behavior(self):
        from proof.run_proof import _collect_final_unit
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            attempt_dir = os.path.join(run3_dir, "a1")
            os.makedirs(attempt_dir)

            ledger_file = os.path.join(attempt_dir, "ledger.jsonl")
            with open(ledger_file, "w") as f:
                f.write("{}\n")

            origin_path = os.path.join(attempt_dir, "origin_records.json")
            with open(origin_path, "w") as f:
                json.dump({
                    "v": 1, "kind": "origin_records", "driver": "demo", "attempt": 1,
                    "chain_id": "0" * 32, "ledger_path": os.path.realpath(ledger_file),
                    "ledger_sha256": sha256_file(ledger_file),
                    "timestamp_ns": 1000,
                    "entries": [
                        {"index": 0, "out_ref": "/bin", "expected_ino": 1, "expected_mtime_ns": 100,
                         "st_dev": 1, "st_ino": 1, "st_nlink": 1, "st_mode": 0o755, "st_size": 10,
                         "st_mtime_ns": 100, "st_atime_ns": 100, "st_ctime_ns": 100, "atime_advanced": False}
                    ],
                    "overall_status": "NOT-EXECUTED",
                }, f)

            result_file = os.path.join(attempt_dir, "result.json")
            with open(result_file, "w") as f:
                json.dump({
                    "v": 1, "chain_id": "0" * 32, "unit": "run3/demo", "attempt": 1, "status": "PASS",
                    "reasons": [], "checks": {"exit": "PASS", "sentinel": "PASS", "no-refused": "PASS", "skips": "PASS", "ledger": "PASS"},
                    "started_ns": 1000, "ended_ns": 2000, "survivors": [],
                }, f)

            pin = {"report_dir": report_dir, "chain_id": "0" * 32}

            with patch("platform.system", return_value="Darwin"):
                unit_info, _, reasons = _collect_final_unit(pin, run3_dir, "run3/demo", "run3")
                self.assertEqual(unit_info["status"], "FAIL")
                self.assertTrue(any("did not advance atime" in r for r in reasons))

    def test_run3_execute_only_fails_closed_pending(self):
        from proof.run_proof import _run_one_driver
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            pin = {
                "report_dir": report_dir,
                "chain_id": "0" * 32,
                "w_path": report_dir,
                "compiler_path": "/bin/true",
                "canonical_roots": [],
                "platform_tmp": None,
                "python_path": sys.executable,
                "p_source_sha": "0" * 40,
                "w_head": "0" * 40,
                "compiler_sha256": "0" * 64,
                "compiler_size": 0,
                "compiler_mtime_ns": 0,
                "compiler_inode": 0,
                "compiler_version_line": "iyi 0.1.0 [0000000]",
                "compiler_stamp": "0000000",
                "env_path": "/bin",
                "env_home": "/home",
                "python_version": "3.10",
                "timeout_path": "/bin/timeout",
                "timeout_version": "1.0",
                "nm_path": "/bin/nm",
                "nm_version": "1.0",
                "census_sha256": {"demo": "0" * 64},
            }
            census_dir = os.path.join(report_dir, "proof", "census")
            os.makedirs(census_dir)
            script_path = os.path.join(report_dir, "bench", "std_demo_exercise.sh")
            os.makedirs(os.path.dirname(script_path))
            with open(script_path, "w") as f:
                f.write("#!/bin/sh\necho PASS\nexit 0\n")
            os.chmod(script_path, 0o755)
            census = {
                "census_version": 1,
                "driver": "demo",
                "script": "bench/std_demo_exercise.sh",
                "script_sha256": "0" * 64,
                "sites": [],
                "non_invocations": [],
                "skips": [],
                "not_skips": [],
                "pass_sentinel": {"line": 2, "regex": "^PASS$", "text": "echo PASS"},
                "exec_evidence": [],
            }
            with open(os.path.join(census_dir, "demo.json"), "w") as f:
                json.dump(census, f)

            with patch("proof.run_proof.validate_census", return_value=[]), \
                 patch("proof.run_proof._check_stage_identity", return_value=True), \
                 patch("proof.run_proof.run_logged", return_value=(MagicMock(returncode=0, timed_out=False, survivors=(), interrupted_signal=None), b"PASS\n")):
                record = _run_one_driver(
                    report_dir,
                    pin,
                    "demo",
                    baseline=set(),
                    driver_limit_sec=10.0,
                    grace_sec=1.0,
                    disk_min_gb=0.1,
                    stat_fn=os.stat,
                    execute_only=True,
                )
                self.assertEqual(record["status"], "PENDING")
                self.assertEqual(record["checks"]["ledger"], "PENDING")
                self.assertTrue(any("deferred to trusted host observer" in r for r in record["reasons"]))

    def test_run3_accepts_trusted_nonce(self):
        from proof.run_proof import _run_one_driver
        with tempfile.TemporaryDirectory() as report_dir:
            run3_dir = os.path.join(report_dir, "run3", "demo")
            pin = {
                "report_dir": report_dir,
                "chain_id": "0" * 32,
                "w_path": report_dir,
                "compiler_path": "/bin/true",
                "canonical_roots": [],
                "platform_tmp": None,
                "python_path": sys.executable,
                "p_source_sha": "0" * 40,
                "w_head": "0" * 40,
                "compiler_sha256": "0" * 64,
                "compiler_size": 0,
                "compiler_mtime_ns": 0,
                "compiler_inode": 0,
                "compiler_version_line": "iyi 0.1.0 [0000000]",
                "compiler_stamp": "0000000",
                "env_path": "/bin",
                "env_home": "/home",
                "python_version": "3.10",
                "timeout_path": "/bin/timeout",
                "timeout_version": "1.0",
                "nm_path": "/bin/nm",
                "nm_version": "1.0",
                "census_sha256": {"demo": "0" * 64},
            }
            census_dir = os.path.join(report_dir, "proof", "census")
            os.makedirs(census_dir)
            script_path = os.path.join(report_dir, "bench", "std_demo_exercise.sh")
            os.makedirs(os.path.dirname(script_path))
            with open(script_path, "w") as f:
                f.write("#!/bin/sh\necho PASS\nexit 0\n")
            os.chmod(script_path, 0o755)
            census = {
                "census_version": 1,
                "driver": "demo",
                "script": "bench/std_demo_exercise.sh",
                "script_sha256": "0" * 64,
                "sites": [],
                "non_invocations": [],
                "skips": [],
                "not_skips": [],
                "pass_sentinel": {"line": 2, "regex": "^PASS$", "text": "echo PASS"},
                "exec_evidence": [],
            }
            with open(os.path.join(census_dir, "demo.json"), "w") as f:
                json.dump(census, f)

            with patch("proof.run_proof.validate_census", return_value=[]), \
                 patch("proof.run_proof._check_stage_identity", return_value=True), \
                 patch("proof.run_proof.run_logged", return_value=(MagicMock(returncode=0, timed_out=False, survivors=(), interrupted_signal=None), b"PASS\n")):
                record = _run_one_driver(
                    report_dir,
                    pin,
                    "demo",
                    baseline=set(),
                    driver_limit_sec=10.0,
                    grace_sec=1.0,
                    disk_min_gb=0.1,
                    stat_fn=os.stat,
                    execute_only=True,
                    nonce="trustednonce1234",
                )
                attempt_dir = os.path.join(run3_dir, f"a{record['attempt']}")
                with open(os.path.join(attempt_dir, "shim.json"), "r") as f:
                    shim_cfg = json.load(f)
                self.assertEqual(shim_cfg.get("nonce"), "trustednonce1234")
                with open(os.path.join(attempt_dir, "ledger.jsonl"), "r") as f:
                    header = json.loads(f.readline())
                self.assertEqual(header.get("nonce"), "trustednonce1234")


class TestHttpOmissionSkips(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        census_path = os.path.join(self.repo_root, "proof", "census", "http.json")
        with open(census_path) as f:
            self.census = json.load(f)
        self.script_path = os.path.join(self.repo_root, self.census["script"])
        with open(self.script_path, "rb") as f:
            self.script_bytes = f.read()

    def test_all_four_forms_classify_driver_skips(self):
        from proof.run_proof import _classify_driver_skips
        # 1. Neither (ordinary run) -> PASS
        neither_log = (
            "  requests on one connection, a chunked one, a megabyte, gzip whole and streamed, multipart, and stop; "
            "zstd whole as Python's compression.zstd reads it, and by curl --compressed\n"
        )
        status, reasons = _classify_driver_skips(self.census, neither_log, baseline=set())
        self.assertEqual(status, "PASS")
        self.assertEqual(reasons, [])

        # 2. Python only -> ENV-BLOCKED with python zstd reason
        py_only_log = (
            "  requests on one connection, a chunked one, a megabyte, gzip whole and streamed, multipart, and stop; "
            "zstd unchecked: no compression.zstd in this Python, and by curl --compressed\n"
        )
        status, reasons = _classify_driver_skips(self.census, py_only_log, baseline=set())
        self.assertEqual(status, "ENV-BLOCKED")
        self.assertEqual(reasons, ["tool skip http: python zstd"])

        # 3. Curl only -> ENV-BLOCKED with curl zstd reason
        curl_only_log = (
            "  requests on one connection, a chunked one, a megabyte, gzip whole and streamed, multipart, and stop; "
            "zstd whole as Python's compression.zstd reads it; curl --compressed unchecked: its build lists no zstd\n"
        )
        status, reasons = _classify_driver_skips(self.census, curl_only_log, baseline=set())
        self.assertEqual(status, "ENV-BLOCKED")
        self.assertEqual(reasons, ["tool skip http: curl zstd"])

        # 4. Both -> ENV-BLOCKED with both reasons
        both_log = (
            "  requests on one connection, a chunked one, a megabyte, gzip whole and streamed, multipart, and stop; "
            "zstd unchecked: no compression.zstd in this Python; curl --compressed unchecked: its build lists no zstd\n"
        )
        status, reasons = _classify_driver_skips(self.census, both_log, baseline=set())
        self.assertEqual(status, "ENV-BLOCKED")
        self.assertEqual(sorted(reasons), ["tool skip http: curl zstd", "tool skip http: python zstd"])

    def test_baseline_inventory_captures_tool_skips(self):
        from proof.run_proof import _baseline_skip_hits
        baseline_log = (
            "-- running sibling: std_http_exercise.sh\n"
            "  requests on one connection, a chunked one, a megabyte, gzip whole and streamed, multipart, and stop; "
            "zstd unchecked: no compression.zstd in this Python; curl --compressed unchecked: its build lists no zstd\n"
        )
        hits = _baseline_skip_hits(self.repo_root, baseline_log)
        self.assertEqual(len(hits), 2)
        whats = {hit["what"] for hit in hits}
        self.assertEqual(whats, {"python zstd", "curl zstd"})
        self.assertTrue(all(hit["class"] == "tool" for hit in hits))
        self.assertTrue(all(hit["driver"] == "http" for hit in hits))
    def test_census_grounding_and_source_drift_rejection(self):
        # Validate that http.json passes grounding against bench/std_http_exercise.sh
        violations = validate_census(self.census, self.script_bytes, self.census["script"], target_platform="linux")
        self.assertEqual(violations, [])

        # Test source drift rejection: modifying a skip line causes validate_census to fail
        lines = self.script_bytes.decode("utf-8").splitlines()
        tampered_lines = list(lines)
        skip = next(item for item in self.census["skips"] if item["text"] == 'said = "zstd unchecked: no compression.zstd in this Python"')
        skip_line = skip["line"]
        tampered_lines[skip_line - 1] = 'said = "modified line without skip"'
        tampered_bytes = "\n".join(tampered_lines).encode("utf-8")
        drift_violations = validate_census(self.census, tampered_bytes, self.census["script"], target_platform="linux")
        self.assertTrue(any(v[0] == "C5.0-schema" and v[1] == skip_line and "text is not the cited source line" in v[2] for v in drift_violations))
        self.assertTrue(any(v[0] == "C5.4-skip-regex" and v[1] == skip_line for v in drift_violations))

        # Test unlisted skip rejection: adding an unlisted python assignment with skip vocab triggers C5.4-unlisted-skip-line
        tampered_lines2 = list(lines)
        tampered_lines2.insert(355, 'unlisted = "zstd unchecked: rogue skip vocab"')
        tampered_bytes2 = "\n".join(tampered_lines2).encode("utf-8")
        drift_violations2 = validate_census(self.census, tampered_bytes2, self.census["script"], target_platform="linux")
        self.assertTrue(any(v[0] == "C5.4-unlisted-skip-line" for v in drift_violations2))

        for source in (
            r'unlisted = "\x75nchecked: no oracle"',
            r"unlisted = 'unchecked: can\'t run the oracle'",
            r'unlisted = "unchecked: C:\\missing"',
        ):
            with self.subTest(source=source):
                modified = list(lines)
                modified.insert(355, source)
                violations = validate_census(
                    self.census, "\n".join(modified).encode("utf-8"),
                    self.census["script"], target_platform="linux",
                )
                self.assertTrue(any(
                    v[0] == "C5.4-unlisted-skip-line" and v[1] == 356
                    for v in violations
                ))

if __name__ == "__main__":
    unittest.main()
