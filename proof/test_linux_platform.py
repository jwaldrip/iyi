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
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from proof.proofkit import (
    IdentityError,
    base_env,
    compute_inputs_bundle_digest,
    inspect_pin_inputs,
    probe_atime_observable,
    _process_group_members,
    _validate_census_schema,
    validate_census,
    verify_ledger,
    check_identity,
    _validated_report_dir,
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
            "verdict": {},
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
            "pass_sentinel": {"line": 100, "token": "PASS"},
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
        self.assertTrue(any(v[0] == "C5.0-schema" and "closed keys" in v[2] for v in violations))

    def test_darwin_old_census_without_linux_supported_on_darwin(self):
        census = self._make_census([self._make_variant(darwin="required", linux=None)])
        violations = []
        _validate_census_schema(census, violations, target_platform="darwin")
        self.assertEqual(violations, [])

    def test_linux_fails_closed_when_linux_field_missing(self):
        census = self._make_census([self._make_variant(darwin="required", linux=None)])
        violations = []
        _validate_census_schema(census, violations, target_platform="linux")
        self.assertTrue(any(v[0] == "C5.0-schema" and "invalid fields" in v[2] for v in violations))

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
                            {"id": "v_unclass", "kind": "positive", "darwin": "required"}
                            # Missing 'linux' field!
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
                            # On Linux this is platform-excluded: should NOT trigger NOT-EXERCISED
                            {"id": "v_darwin_only", "kind": "positive", "darwin": "required", "linux": "platform-excluded"},
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
                            # On Darwin this is required: missing record must trigger NOT-EXERCISED
                            {"id": "v_darwin_req", "kind": "positive", "darwin": "required", "linux": "platform-excluded"},
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
    def test_compute_inputs_bundle_digest_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = os.path.join(tmpdir, "bundle.sha256")
            with open(manifest_file, "w") as f:
                f.write("test manifest data\n")
            digest = compute_inputs_bundle_digest(tmpdir)
            expected = hashlib.sha256(b"test manifest data\n").hexdigest()
            self.assertEqual(digest, expected)

    def test_compute_inputs_bundle_digest_directory_tree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sub = os.path.join(tmpdir, "sub")
            os.makedirs(sub)
            with open(os.path.join(sub, "f1.txt"), "w") as f:
                f.write("content1\n")
            with open(os.path.join(tmpdir, "f2.txt"), "w") as f:
                f.write("content2\n")
            digest1 = compute_inputs_bundle_digest(tmpdir)
            digest2 = compute_inputs_bundle_digest(tmpdir)
            self.assertEqual(digest1, digest2)
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", digest1))

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
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = os.path.join(tmpdir, "bundle.sha256")
            with open(manifest_file, "w") as f:
                f.write("initial\n")
            digest = compute_inputs_bundle_digest(tmpdir)
            pin = {
                "p_path": "/p",
                "w_path": "/w",
                "compiler_path": "/c",
                "report_dir": "/private/tmp/iyp-01234567",
                "chain_id": "01234567" + "0"*24,
                "inputs_dir": tmpdir,
                "inputs_digest": digest,
            }
            # Modify the manifest file
            with open(manifest_file, "w") as f:
                f.write("tampered\n")
            with self.assertRaises(IdentityError) as ctx:
                check_identity(pin)
            self.assertEqual(ctx.exception.reason, "INPUTS-DIGEST-CHANGED")


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


if __name__ == "__main__":
    unittest.main()
