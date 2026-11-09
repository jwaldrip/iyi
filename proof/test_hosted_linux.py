#!/usr/bin/env python3
"""
Unit and integration tests for GitHub-Hosted Linux Strict Proof Controller.
Tests manifest validation, fail-closed authorization, mount policy & anti-aliasing,
staging interface consumption, descriptor-safe evidence collection, workflow
command sanitization, and sequential lifecycle state machine.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from proof.hosted_linux import (
    AUTH_COMMENT_PREFIX,
    AUTH_REFUSED_EXIT_CODE,
    BACKEND_NAME,
    DEFAULT_ENVIRONMENT_ID,
    DEFAULT_REVIEWER_ID,
    DRIVER_LIMIT_SEC,
    GRACE_SEC,
    DescriptorSafeEvidenceCollector,
    EvidenceCollectionError,
    LineageValidationError,
    MountBinding,
    MountPolicyError,
    ProofManifest,
    SequentialLifecycleController,
    StagingError,
    StrictAuthorizationRefused,
    build_mount_bindings,
    canonical_json_bytes,
    check_driver_admission,
    compute_inventory_sha256,
    create_checkpoint_archive,
    sanitize_workflow_output,
    sha256_bytes,
    stage_and_verify_inputs,
    validate_manifest_dict,
    verify_container_mount_table,
    verify_git_lineage,
    verify_strict_authorization,
)


def make_valid_manifest_dict(report_path: str = "/private/tmp/iyp-abcd1234") -> dict:
    return {
        "schema": "iyi-hosted-linux-proof-v1",
        "backend": BACKEND_NAME,
        "repository": "jwaldrip/iyi",
        "c_sha": "a" * 40,
        "p_sha": "b" * 40,
        "w_sha": "c" * 40,
        "workflow_path": ".github/workflows/pr147-linux-strict.yml",
        "workflow_blob": "d" * 40,
        "run_id": "123456789",
        "run_attempt": 1,
        "job_id": "987654321",
        "job_key": "strict-proof",
        "image": "ghcr.io/jwaldrip/iyi-proof-linux:latest",
        "image_digest": "sha256:" + "e" * 64,
        "lock_path": "proof/hosted_sources.lock.json",
        "lock_sha256": "f" * 64,
        "expected_bundle_sha256": "1" * 64,
        "report_path": report_path,
        "environment": "strict-proof",
        "environment_id": DEFAULT_ENVIRONMENT_ID,
        "resource_policy": {
            "driver_limit_sec": DRIVER_LIMIT_SEC,
            "grace_sec": GRACE_SEC,
            "payload_budget_sec": 19800.0,
            "host_job_limit_sec": 21600.0,
            "min_disk_gib": 20.0,
        },
        "independent_review": {
            "review_path": "proof/review_linux.json",
            "verdict": "GO",
        },
    }


class TestProofManifest(unittest.TestCase):
    def test_canonical_manifest_bytes_and_digest(self):
        data = make_valid_manifest_dict()
        manifest = validate_manifest_dict(data)
        canonical = manifest.canonical_bytes()
        self.assertTrue(canonical.endswith(b"\n"))
        digest = manifest.digest()
        self.assertEqual(len(digest), 64)
        # Determinism
        manifest2 = validate_manifest_dict(data)
        self.assertEqual(manifest2.digest(), digest)

    def test_compute_inventory_sha256_canonical_format(self):
        files_dict = {
            "vectors/b.json": {"sha256": "2" * 64, "size": 200},
            "vectors/a.json": {"sha256": "1" * 64, "size": 100},
        }
        expected_raw = f"{'1' * 64}  vectors/a.json\n{'2' * 64}  vectors/b.json\n"
        expected_hash = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
        self.assertEqual(compute_inventory_sha256(files_dict), expected_hash)

    def test_validate_manifest_rejects_missing_keys(self):
        data = make_valid_manifest_dict()
        del data["p_sha"]
        with self.assertRaises(StrictAuthorizationRefused) as ctx:
            validate_manifest_dict(data)
        self.assertIn("p_sha", str(ctx.exception))

    def test_validate_manifest_rejects_invalid_shas(self):
        data = make_valid_manifest_dict()
        data["c_sha"] = "not-a-40-hex-sha"
        with self.assertRaises(StrictAuthorizationRefused):
            validate_manifest_dict(data)

    def test_validate_manifest_rejects_invalid_digest(self):
        data = make_valid_manifest_dict()
        data["lock_sha256"] = "short-hash"
        with self.assertRaises(StrictAuthorizationRefused):
            validate_manifest_dict(data)

    def test_validate_manifest_rejects_bad_report_path(self):
        for bad_path in ("/tmp/foo", "/private/tmp/iyp-ABCDEF12", "/private/tmp/iyp-12345", "/var/tmp/iyp-12345678"):
            data = make_valid_manifest_dict(report_path=bad_path)
            with self.assertRaises(StrictAuthorizationRefused):
                validate_manifest_dict(data)
    def test_validate_manifest_rejects_invalid_image_digest(self):
        for bad in ("", "sha256:short", "not-a-digest", "sha256:" + "g" * 64):
            data = make_valid_manifest_dict()
            data["image_digest"] = bad
            with self.assertRaises(StrictAuthorizationRefused):
                validate_manifest_dict(data)

    def test_validate_manifest_rejects_wrong_backend(self):
        data = make_valid_manifest_dict()
        data["backend"] = "local-quiet-darwin"
        with self.assertRaises(StrictAuthorizationRefused):
            validate_manifest_dict(data)


class TestAuthorizationVerification(unittest.TestCase):
    def setUp(self):
        self.manifest = validate_manifest_dict(make_valid_manifest_dict())
        self.digest = self.manifest.digest()
        self.expected_comment = f"{AUTH_COMMENT_PREFIX}{self.digest}"

    def test_valid_authorization_passes(self):
        approvals = [
            {
                "state": "approved",
                "user": {"id": int(DEFAULT_REVIEWER_ID), "login": "jwaldrip"},
                "environments": [{"id": int(DEFAULT_ENVIRONMENT_ID), "name": "strict-proof"}],
                "comment": self.expected_comment,
            }
        ]
        # Should not raise
        verify_strict_authorization(self.manifest, approvals)

    def test_rejects_empty_approvals(self):
        with self.assertRaises(StrictAuthorizationRefused):
            verify_strict_authorization(self.manifest, [])

    def test_rejects_wrong_reviewer_id(self):
        approvals = [
            {
                "state": "approved",
                "user": {"id": 999999, "login": "someone_else"},
                "environments": [{"id": int(DEFAULT_ENVIRONMENT_ID), "name": "strict-proof"}],
                "comment": self.expected_comment,
            }
        ]
        with self.assertRaises(StrictAuthorizationRefused):
            verify_strict_authorization(self.manifest, approvals)

    def test_rejects_wrong_environment_id(self):
        approvals = [
            {
                "state": "approved",
                "user": {"id": int(DEFAULT_REVIEWER_ID), "login": "jwaldrip"},
                "environments": [{"id": 11111111, "name": "other-env"}],
                "comment": self.expected_comment,
            }
        ]
        with self.assertRaises(StrictAuthorizationRefused):
            verify_strict_authorization(self.manifest, approvals)

    def test_rejects_mismatched_digest_comment(self):
        approvals = [
            {
                "state": "approved",
                "user": {"id": int(DEFAULT_REVIEWER_ID), "login": "jwaldrip"},
                "environments": [{"id": int(DEFAULT_ENVIRONMENT_ID), "name": "strict-proof"}],
                "comment": f"{AUTH_COMMENT_PREFIX}{'0' * 64}",
            }
        ]
        with self.assertRaises(StrictAuthorizationRefused):
            verify_strict_authorization(self.manifest, approvals)

    def test_rejects_local_quiet_darwin_comment(self):
        approvals = [
            {
                "state": "approved",
                "user": {"id": int(DEFAULT_REVIEWER_ID), "login": "jwaldrip"},
                "environments": [{"id": int(DEFAULT_ENVIRONMENT_ID), "name": "strict-proof"}],
                "comment": f"iyi-strict-authorization-v2 sha256:{self.digest}",
            }
        ]
        with self.assertRaises(StrictAuthorizationRefused):
            verify_strict_authorization(self.manifest, approvals)

    def test_rejects_non_approved_state(self):
        for state in ("rejected", "pending", "commented"):
            approvals = [
                {
                    "state": state,
                    "user": {"id": int(DEFAULT_REVIEWER_ID), "login": "jwaldrip"},
                    "environments": [{"id": int(DEFAULT_ENVIRONMENT_ID), "name": "strict-proof"}],
                    "comment": self.expected_comment,
                }
            ]
            with self.assertRaises(StrictAuthorizationRefused):
                verify_strict_authorization(self.manifest, approvals)


class TestMountPolicyAndAntiAlias(unittest.TestCase):
    def test_mount_bindings_construction(self):
        bindings = build_mount_bindings(
            p_dir="/host/p",
            p_build_dir="/host/p-build",
            w_dir="/host/w",
            inputs_dir="/host/inputs",
            private_tmp_dir="/host/private_tmp",
            scratch_dir="/host/scratch",
            home_proof_dir="/host/home",
            phase="build",
        )
        binding_by_dest = {b.container_path: b for b in bindings}
        self.assertEqual(binding_by_dest["/P"].access, "ro")
        self.assertEqual(binding_by_dest["/P/.build"].access, "rw")
        self.assertEqual(binding_by_dest["/W"].access, "ro")
        self.assertEqual(binding_by_dest["/inputs"].access, "ro")
        self.assertEqual(binding_by_dest["/private/tmp"].access, "rw")
        self.assertEqual(binding_by_dest["/tmp"].mount_type, "tmpfs")
        self.assertEqual(binding_by_dest["/dev/shm"].mount_type, "tmpfs")

        # In proof phase, /P/.build must be ro
        proof_bindings = build_mount_bindings(
            p_dir="/host/p",
            p_build_dir="/host/p-build",
            w_dir="/host/w",
            inputs_dir="/host/inputs",
            private_tmp_dir="/host/private_tmp",
            scratch_dir="/host/scratch",
            home_proof_dir="/host/home",
            phase="proof",
        )
        proof_map = {b.container_path: b for b in proof_bindings}
        self.assertEqual(proof_map["/P/.build"].access, "ro")

    def test_verify_container_mounts_valid(self):
        inspect_data = {
            "Mounts": [
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/P/.build", "Source": "/host/p-build", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
                {"Destination": "/private/tmp", "Source": "/host/priv_tmp", "RW": True},
                {"Destination": "/scratch", "Source": "/host/scratch", "RW": True},
                {"Destination": "/home/proof", "Source": "/host/home", "RW": True},
                {"Destination": "/tmp", "RW": True},
                {"Destination": "/dev/shm", "RW": True},
            ]
        }
        # Passes for proof phase
        verify_container_mount_table(inspect_data, expected_phase="proof")

    def test_verify_container_mounts_rejects_docker_sock(self):
        inspect_data = {
            "Mounts": [
                {"Destination": "/var/run/docker.sock", "Source": "/var/run/docker.sock", "RW": True},
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
            ]
        }
        with self.assertRaises(MountPolicyError):
            verify_container_mount_table(inspect_data)

    def test_verify_container_mounts_rejects_host_proc(self):
        inspect_data = {
            "Mounts": [
                {"Destination": "/host_proc", "Source": "/proc", "RW": False},
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
            ]
        }
        with self.assertRaises(MountPolicyError):
            verify_container_mount_table(inspect_data)

    def test_verify_container_mounts_rejects_writable_p_or_w_or_inputs(self):
        for target in ("/P", "/W", "/inputs"):
            inspect_data = {
                "Mounts": [
                    {"Destination": "/P", "Source": "/host/p", "RW": target != "/P"},
                    {"Destination": "/W", "Source": "/host/w", "RW": target != "/W"},
                    {"Destination": "/inputs", "Source": "/host/inputs", "RW": target != "/inputs"},
                ]
            }
            with self.assertRaises(MountPolicyError):
                verify_container_mount_table(inspect_data)

    def test_verify_container_mounts_rejects_writable_p_build_in_proof(self):
        inspect_data = {
            "Mounts": [
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/P/.build", "Source": "/host/p-build", "RW": True},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
            ]
        }
        with self.assertRaises(MountPolicyError):
            verify_container_mount_table(inspect_data, expected_phase="proof")

    def test_verify_container_mounts_final_phase_receipts(self):
        inspect_data = {
            "Mounts": [
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/P/.build", "Source": "/host/p-build", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
                {"Destination": "/receipts", "Source": "/host/receipts", "RW": False},
            ]
        }
        # Passes when /receipts is present and read-only
        verify_container_mount_table(inspect_data, expected_phase="final")

        # Fails when /receipts is writable
        inspect_writable = {
            "Mounts": [
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
                {"Destination": "/receipts", "Source": "/host/receipts", "RW": True},
            ]
        }
        with self.assertRaises(MountPolicyError):
            verify_container_mount_table(inspect_writable, expected_phase="final")

        # Fails when /receipts is missing in final phase
        inspect_missing = {
            "Mounts": [
                {"Destination": "/P", "Source": "/host/p", "RW": False},
                {"Destination": "/W", "Source": "/host/w", "RW": False},
                {"Destination": "/inputs", "Source": "/host/inputs", "RW": False},
            ]
        }
        with self.assertRaises(MountPolicyError):
            verify_container_mount_table(inspect_missing, expected_phase="final")


class TestEvidenceCollectionAndSanitization(unittest.TestCase):
    def test_workflow_command_sanitization(self):
        raw = (
            "Normal output line\n"
            "::set-output name=leak::payload\n"
            "::error::malicious error injection\n"
            "::warning::fake warning\n"
            "Another normal line\n"
            "  ::debug::indented command\n"
        )
        sanitized = sanitize_workflow_output(raw)
        # Verify that no line can be parsed as a GitHub Actions workflow command
        for line in sanitized.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), f"Line still has workflow command prefix: {line}")
        self.assertNotIn("::set-output", sanitized)
        self.assertIn("[payload-log]: set-output", sanitized)
        self.assertIn("[payload-log]: error::malicious error injection", sanitized)
        self.assertIn("Normal output line", sanitized)
        self.assertIn("Another normal line", sanitized)
    def test_descriptor_safe_walk_preserves_symlinks_as_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            reg_file = os.path.join(td, "hello.txt")
            with open(reg_file, "w") as f:
                f.write("hello content")

            sym_file = os.path.join(td, "link_to_nonexistent")
            os.symlink("/etc/fake_target", sym_file)

            archive_path = os.path.join(td, "test.tar.gz")
            manifest: list[dict] = []
            with open(archive_path, "wb") as f_out:
                import tarfile
                with tarfile.open(fileobj=f_out, mode="w:gz") as tar:
                    with DescriptorSafeEvidenceCollector(td) as collector:
                        collector.walk_and_collect(tar, arc_prefix="test", manifest=manifest)

            sym_entries = [m for m in manifest if m["type"] == "symlink"]
            self.assertEqual(len(sym_entries), 1)
            self.assertEqual(sym_entries[0]["target"], "/etc/fake_target")
            self.assertEqual(sym_entries[0]["path"], "test/link_to_nonexistent")

    def test_checkpoint_archive_creation(self):
        with tempfile.TemporaryDirectory() as td:
            src_dir = os.path.join(td, "source")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "result.json"), "w") as f:
                f.write('{"status": "PASS"}')

            archive_path = os.path.join(td, "checkpoint.tar.gz")
            desc = {"stage": "run1", "status": "PASS", "attempt": 1}
            digest = create_checkpoint_archive(src_dir, archive_path, desc)
            self.assertEqual(len(digest), 64)
            self.assertTrue(os.path.isfile(archive_path))

    def test_checkpoint_archive_rejects_system_tempdir(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "checkpoint.tar.gz")
            desc = {"stage": "plan", "status": "PASS", "attempt": 1}
            with self.assertRaises(EvidenceCollectionError):
                create_checkpoint_archive(tempfile.gettempdir(), archive_path, desc)

    def test_checkpoint_archive_with_none_checkpoint_dir(self):
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "checkpoint.tar.gz")
            desc = {"stage": "plan", "status": "PASS", "attempt": 1}
            digest = create_checkpoint_archive(None, archive_path, desc)
            self.assertEqual(len(digest), 64)
            self.assertTrue(os.path.isfile(archive_path))

    def test_sealed_origin_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = validate_manifest_dict(make_valid_manifest_dict(report_path="/private/tmp/iyp-11223344"))
            controller = SequentialLifecycleController(
                manifest=manifest,
                p_dir=os.path.join(td, "p"),
                w_dir=os.path.join(td, "w"),
                inputs_dir=os.path.join(td, "inputs"),
                artifacts_dir=os.path.join(td, "artifacts"),
                job_start_time=1000.0,
                runner_temp_dir=td,
            )
            controller.chain_id = "test-chain-12345"

            # Create attempt dir with origin_records.json and ledger.jsonl
            attempt_dir = os.path.join(controller.private_tmp_dir, "iyp-11223344", "run3", "acme", "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            origin_records_path = os.path.join(attempt_dir, "origin_records.json")
            ledger_path = os.path.join(attempt_dir, "ledger.jsonl")

            with open(origin_records_path, "w") as f:
                json.dump({"v": 1, "kind": "origin_records", "overall_status": "PASS"}, f)
            with open(ledger_path, "w") as f:
                f.write('{"event": "start"}\n')

            receipt = controller.seal_origin_receipt("run3-acme", attempt=1, driver="acme")
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["schema"], "iyi-sealed-origin-receipt-v1")
            self.assertEqual(receipt["chain_id"], "test-chain-12345")
            self.assertEqual(receipt["driver"], "acme")
            self.assertEqual(receipt["attempt"], 1)
            self.assertEqual(receipt["receipt_status"], "PASS")

            # Check that file exists on disk outside payload mounts
            receipt_disk = os.path.join(controller.artifacts_dir, "sealed-receipts", "receipt-run3-acme-a1.json")
            self.assertTrue(os.path.isfile(receipt_disk))


class TestSequentialLifecycle(unittest.TestCase):
    def test_driver_admission_budget(self):
        # DRIVER_LIMIT_SEC=2100, GRACE_SEC=30. Minimum required = 2130
        self.assertTrue(check_driver_admission(2130.0))
        self.assertTrue(check_driver_admission(3000.0))
        self.assertFalse(check_driver_admission(2129.9))
        self.assertFalse(check_driver_admission(100.0))

    def test_sticky_failure_tracks_and_finalizes_terminal(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = validate_manifest_dict(make_valid_manifest_dict())
            controller = SequentialLifecycleController(
                manifest=manifest,
                p_dir=os.path.join(td, "p"),
                w_dir=os.path.join(td, "w"),
                inputs_dir=os.path.join(td, "inputs"),
                artifacts_dir=os.path.join(td, "artifacts"),
                job_start_time=1000.0,
                runner_temp_dir=td,
            )
            controller.mark_failure("Deliberate test failure", critical=False)
            self.assertTrue(controller.sticky_failed)

            envelope_path = controller.finalize_terminal_envelope()
            self.assertTrue(os.path.isfile(envelope_path))
            with open(envelope_path, "r") as f:
                env_data = json.load(f)
            self.assertEqual(env_data["summary"]["status"], "FAIL")
            self.assertIn("Deliberate test failure", env_data["summary"]["failures"])


if __name__ == "__main__":
    unittest.main()
