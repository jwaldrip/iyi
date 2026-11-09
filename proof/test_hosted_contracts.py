#!/usr/bin/env python3
"""
proof/test_hosted_contracts.py: Comprehensive test suite for proof/hosted_contracts.py.
Validates PlanControllerRepairs Sections 3.1-3.6 and ReviewControllerReadiness:
- Canonical duplicate-rejecting JSON with compact formatting and newline termination.
- Non-finite numbers (NaN, Inf, overflow exponents) rejection.
- Booleans strictly rejected as numeric types.
- Deep immutability and closed schemas:
  * ResourcePolicy (13 stage limits)
  * CagePolicy (12 isolation dimensions)
  * EvidencePolicy (15 evidence budget dimensions)
  * QualificationRequirements (exact 144/144, 0 exclusions/failures, 142+2, 117 siblings, Run2 28/116/144, frames, --crystal)
- Validation in __post_init__ preventing constructor bypass.
- Cryptographic referential integrity across ProofManifest records.
- Optional artifact_digest handling in ValidationRef.
- Unconditional holds and refusal enforcements.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import unittest

from proof.hosted_contracts import (
    AUTH_COMMENT_PREFIX,
    BACKEND_NAME,
    SCHEMA_MANIFEST_V2,
    CagePolicy,
    CheckpointDescriptor,
    ContractError,
    DuplicateKeyError,
    EvidencePolicy,
    ExecutionContext,
    ExecutionSubject,
    NonFiniteNumberError,
    ProofManifest,
    QualificationRequirements,
    ReferenceIntegrityError,
    ResourcePolicy,
    ReviewReferenceMismatch,
    ReviewUnauthenticatedError,
    SourceGroundingAuthority,
    StrictHaltRefusal,
    StructuralIndependentReviewRef,
    TypeValidationError,
    UnknownFieldError,
    UnsupportedSchemaError,
    ValidationRef,
    ValidationReferenceMismatch,
    build_grounded_qualification_requirements,
    build_production_cage_policy,
    build_production_resource_policy,
    canonical_json_bytes,
    compute_manifest_digest,
    enforce_independent_review_refusal,
    enforce_origin_transport_refusal,
    parse_strict_json,
    parse_utc_iso_timestamp,
    require_ascii_str,
    require_bool,
    require_dict,
    require_float,
    require_int,
    require_iso_timestamp,
    require_positive_ascii_id,
    require_sha1_or_commit,
    require_sha256,
    require_str,
    sha256_bytes,
    validate_checkpoint_to_context,
    validate_execution_context_to_manifest,
    validate_production_cage_policy,
    validate_production_resource_policy,
    validate_qualification_ground_truth,
    validate_strict_pairs_map,
    validate_timestamp_and_epoch,
    validate_validation_ref_to_subject,
)


def sample_resource_policy_dict() -> dict:
    return {
        "driver_limit_sec": 2100,
        "grace_sec": 30,
        "payload_budget_sec": 19800,
        "host_job_limit_sec": 21600,
        "finalization_alloc_sec": 1800,
        "min_disk_gib": 20.0,
        "stage_build_limit_sec": 1200,
        "stage_version_limit_sec": 60,
        "stage_plan_limit_sec": 600,
        "stage_pin_limit_sec": 600,
        "stage_run1_limit_sec": 1800,
        "stage_run2_limit_sec": 3600,
        "stage_final_limit_sec": 1200,
    }


def sample_cage_policy_dict() -> dict:
    return {
        "uid": 65534,
        "gid": 65534,
        "network": "none",
        "read_only_root": True,
        "drop_capabilities": "ALL",
        "no_new_privileges": True,
        "private_pid_namespace": True,
        "default_confined_seccomp": True,
        "init_process": True,
        "pids_limit": 128,
        "tmpfs_tmp_size": "2g",
        "tmpfs_dev_shm_size": "1g",
    }


def sample_evidence_policy_dict() -> dict:
    return {
        "max_file_bytes": 10000000,
        "max_aggregate_unique_inode_bytes": 50000000,
        "max_archive_emitted_bytes": 100000000,
        "max_directory_entries": 10000,
        "max_directory_depth": 16,
        "max_path_bytes": 1024,
        "max_aliases": 1024,
        "max_json_bytes": 16000000,
        "max_ledger_line_bytes": 65536,
        "max_ledger_line_count": 10000,
        "max_structured_records": 10000,
        "max_witness_events": 50000,
        "max_held_descriptors": 128,
        "max_helper_memory_bytes": 67108864,
        "collection_deadline_sec": 300,
    }


def sample_qualification_dict() -> dict:
    return {
        "rg2_evaluated": 144,
        "rg2_passed": 144,
        "rg2_exclusions": 0,
        "rg2_failures": 0,
        "rg2a_evaluated": 144,
        "rg2a_passed": 144,
        "rg2a_exclusions": 0,
        "rg2a_failures": 0,
        "selectors_142_digest": "1" * 64,
        "additions_2_digest": "2" * 64,
        "corpus_144_selectors_digest": "3" * 64,
        "rg9_programs_total": 144,
        "siblings_117_manifest_digest": "4" * 64,
        "run2_samples": 28,
        "run2_std_exercises": 116,
        "run2_total_corpus": 144,
        "run2_failures": 0,
        "run2_exclusions": 0,
        "run3_inventory_manifest_digest": "5" * 64,
        "named_frames_required": True,
        "crystal_flag_intact": True,
    }


def sample_subject_dict() -> dict:
    return {
        "repository": "jwaldrip/iyi",
        "c_sha": "a" * 40,
        "p_sha": "b" * 40,
        "w_sha": "c" * 40,
        "workflow_path": ".github/workflows/pr147-linux-strict.yml",
        "workflow_blob": "d" * 40,
        "run_id": "12345",
        "run_attempt": 1,
        "job_key": "strict-proof",
        "report_path": "/private/tmp/iyp-abcd1234",
        "image": "ghcr.io/jwaldrip/iyi-proof-linux",
        "image_digest": "sha256:" + "e" * 64,
        "lock_path": "proof/hosted_sources.lock.json",
        "lock_sha256": "f" * 64,
        "expected_bundle_sha256": "1" * 64,
        "resource_policy": sample_resource_policy_dict(),
        "cage_policy": sample_cage_policy_dict(),
        "evidence_policy": sample_evidence_policy_dict(),
        "w_interface_version": "v1",
        "census_digest": "2" * 64,
        "logical_slot_manifest_digest": "3" * 64,
        "qualification_requirements": sample_qualification_dict(),
    }


def sample_validation_dict(subject_digest: str, artifact_digest: str | None = "4" * 64) -> dict:
    return {
        "subject_digest": subject_digest,
        "validation_repository": "jwaldrip/iyi",
        "validation_workflow": ".github/workflows/pr147-linux-strict.yml",
        "validation_c_sha": "a" * 40,
        "run_id": "12345",
        "run_attempt": 1,
        "job_id": "999888",
        "artifact_id": "777666",
        "artifact_digest": artifact_digest,
        "evidence_member_size": 2048,
        "evidence_member_sha256": "5" * 64,
    }


def sample_review_dict(subject_digest: str, validation_ref_digest: str) -> dict:
    return {
        "subject_digest": subject_digest,
        "validation_ref_digest": validation_ref_digest,
        "attestation_digest": "6" * 64,
        "reviewer_identity": "independent-evaluator",
        "verification_evidence": {"signature_valid": "true"},
        "decision": "GO",
    }


class TestCanonicalJSON(unittest.TestCase):
    def test_canonical_json_bytes_formatting(self):
        data = {"b": 2, "a": 1}
        raw = canonical_json_bytes(data)
        self.assertEqual(raw, b'{"a":1,"b":2}\n')
        self.assertEqual(sha256_bytes(raw), hashlib.sha256(raw).hexdigest())

    def test_canonical_json_rejects_non_finite_numbers(self):
        with self.assertRaises(NonFiniteNumberError):
            canonical_json_bytes({"val": float("nan")})
        with self.assertRaises(NonFiniteNumberError):
            canonical_json_bytes({"val": float("inf")})
        with self.assertRaises(NonFiniteNumberError):
            canonical_json_bytes({"val": float("-inf")})

    def test_parse_strict_json_rejects_duplicate_keys(self):
        json_dup = '{"a": 1, "b": 2, "a": 3}'
        with self.assertRaises(DuplicateKeyError) as ctx:
            parse_strict_json(json_dup)
        self.assertIn("Duplicate key", str(ctx.exception))

    def test_parse_strict_json_rejects_non_finite_constants_and_overflow(self):
        for bad_constant in ('{"val": NaN}', '{"val": Infinity}', '{"val": -Infinity}'):
            with self.assertRaises(NonFiniteNumberError):
                parse_strict_json(bad_constant)
        # Exponent overflow
        with self.assertRaises(NonFiniteNumberError):
            parse_strict_json('{"val": 1.0e9999}')

    def test_parse_strict_json_rejects_unknown_fields(self):
        json_text = '{"a": 1, "extra": 2}'
        with self.assertRaises(UnknownFieldError):
            parse_strict_json(json_text, allowed_keys={"a"})

    def test_require_helpers_reject_booleans_as_numeric(self):
        with self.assertRaises(TypeValidationError):
            require_int(True, "flag")
        with self.assertRaises(TypeValidationError):
            require_int(False, "flag")
        with self.assertRaises(TypeValidationError):
            require_positive_ascii_id(True, "id")
        with self.assertRaises(TypeValidationError):
            require_float(True, "float_val")

    def test_require_positive_ascii_id(self):
        self.assertEqual(require_positive_ascii_id("12345", "id"), "12345")
        self.assertEqual(require_positive_ascii_id(12345, "id"), "12345")
        for bad_id in ("0", "-1", "0123", "abc", "", None, False, True):
            with self.assertRaises(TypeValidationError):
                require_positive_ascii_id(bad_id, "id")

    def test_require_iso_timestamp(self):
        self.assertEqual(require_iso_timestamp("2026-11-09T00:00:00Z", "ts"), "2026-11-09T00:00:00Z")
        self.assertEqual(require_iso_timestamp("2026-11-09T00:00:00.123456Z", "ts"), "2026-11-09T00:00:00.123456Z")
        for bad_ts in ("2026-11-09 00:00:00", "2026-11-09T00:00:00", "invalid", "", None):
            with self.assertRaises(TypeValidationError):
                require_iso_timestamp(bad_ts, "ts")


class TestClosedPolicies(unittest.TestCase):
    def test_resource_policy_closed_and_immutable(self):
        rp = ResourcePolicy.from_dict(sample_resource_policy_dict())
        self.assertEqual(rp.driver_limit_sec, 2100)
        self.assertEqual(rp.stage_build_limit_sec, 1200)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rp.driver_limit_sec = 100  # type: ignore

        # Reject unknown fields
        bad_dict = sample_resource_policy_dict()
        bad_dict["extra_key"] = 123
        with self.assertRaises(UnknownFieldError):
            ResourcePolicy.from_dict(bad_dict)

        # Direct constructor validation
        with self.assertRaises(TypeValidationError):
            ResourcePolicy(
                driver_limit_sec=0,  # Invalid <= 0
                grace_sec=30,
                payload_budget_sec=19800,
                host_job_limit_sec=21600,
                finalization_alloc_sec=1800,
                min_disk_gib=20.0,
                stage_build_limit_sec=1200,
                stage_version_limit_sec=60,
                stage_plan_limit_sec=600,
                stage_pin_limit_sec=600,
                stage_run1_limit_sec=1800,
                stage_run2_limit_sec=3600,
                stage_final_limit_sec=1200,
            )

    def test_cage_policy_closed_and_immutable(self):
        cp = CagePolicy.from_dict(sample_cage_policy_dict())
        self.assertEqual(cp.uid, 65534)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cp.uid = 0  # type: ignore

        # Direct constructor rejects non-none network
        with self.assertRaises(TypeValidationError):
            CagePolicy(
                uid=65534,
                gid=65534,
                network="host",  # Invalid
                read_only_root=True,
                drop_capabilities="ALL",
                no_new_privileges=True,
                private_pid_namespace=True,
                default_confined_seccomp=True,
                init_process=True,
                pids_limit=128,
                tmpfs_tmp_size="2g",
                tmpfs_dev_shm_size="1g",
            )

    def test_evidence_policy_closed_and_immutable(self):
        ep = EvidencePolicy.from_dict(sample_evidence_policy_dict())
        self.assertEqual(ep.max_directory_depth, 16)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ep.max_directory_depth = 32  # type: ignore

        # Direct constructor rejects invalid limits
        with self.assertRaises(TypeValidationError):
            EvidencePolicy(
                max_file_bytes=0,  # Invalid
                max_aggregate_unique_inode_bytes=50000000,
                max_archive_emitted_bytes=100000000,
                max_directory_entries=10000,
                max_directory_depth=16,
                max_path_bytes=1024,
                max_aliases=1024,
                max_json_bytes=16000000,
                max_ledger_line_bytes=65536,
                max_ledger_line_count=10000,
                max_structured_records=10000,
                max_witness_events=50000,
                max_held_descriptors=128,
                max_helper_memory_bytes=67108864,
                collection_deadline_sec=300,
            )

    def test_qualification_requirements_enforces_exact_144_117(self):
        qr = QualificationRequirements.from_dict(sample_qualification_dict())
        self.assertEqual(qr.rg2_evaluated, 144)
        self.assertEqual(qr.run2_total_corpus, 144)
        self.assertEqual(qr.run2_samples, 28)
        self.assertEqual(qr.run2_std_exercises, 116)

        # Fails if historical 142 count supplied in dict
        bad_dict = sample_qualification_dict()
        bad_dict["rg2_evaluated"] = 142
        with self.assertRaises(TypeValidationError):
            QualificationRequirements.from_dict(bad_dict)

        # Direct constructor call enforces validation in __post_init__
        with self.assertRaises(TypeValidationError):
            QualificationRequirements(
                rg2_evaluated=142,  # Invalid != 144
                rg2_passed=144,
                rg2_exclusions=0,
                rg2_failures=0,
                rg2a_evaluated=144,
                rg2a_passed=144,
                rg2a_exclusions=0,
                rg2a_failures=0,
                selectors_142_digest="1" * 64,
                additions_2_digest="2" * 64,
                corpus_144_selectors_digest="3" * 64,
                rg9_programs_total=144,
                siblings_117_manifest_digest="4" * 64,
                run2_samples=28,
                run2_std_exercises=116,
                run2_total_corpus=144,
                run2_failures=0,
                run2_exclusions=0,
                run3_inventory_manifest_digest="5" * 64,
                named_frames_required=True,
                crystal_flag_intact=True,
            )

class TestDataModels(unittest.TestCase):
    def test_execution_subject_lifecycle(self):
        s_dict = sample_subject_dict()
        subj = ExecutionSubject.from_dict(s_dict)
        self.assertEqual(subj.run_attempt, 1)
        self.assertEqual(len(subj.digest()), 64)
        self.assertTrue(isinstance(subj.resource_policy, ResourcePolicy))
        self.assertTrue(isinstance(subj.qualification_requirements, QualificationRequirements))

        # Deep immutability
        with self.assertRaises(dataclasses.FrozenInstanceError):
            subj.run_attempt = 2  # type: ignore

        # Direct constructor validation rejects non-hex SHA
        with self.assertRaises(TypeValidationError):
            ExecutionSubject(
                repository="jwaldrip/iyi",
                c_sha="not-a-40-hex-sha",
                p_sha="b" * 40,
                w_sha="c" * 40,
                workflow_path=".github/workflows/pr147-linux-strict.yml",
                workflow_blob="d" * 40,
                run_id="12345",
                run_attempt=1,
                job_key="strict-proof",
                report_path="/private/tmp/iyp-abcd1234",
                image="ghcr.io/jwaldrip/iyi-proof-linux",
                image_digest="sha256:" + "e" * 64,
                lock_path="proof/hosted_sources.lock.json",
                lock_sha256="f" * 64,
                expected_bundle_sha256="1" * 64,
                resource_policy=subj.resource_policy,
                cage_policy=subj.cage_policy,
                evidence_policy=subj.evidence_policy,
                w_interface_version="v1",
                census_digest="2" * 64,
                logical_slot_manifest_digest="3" * 64,
                qualification_requirements=subj.qualification_requirements,
            )

    def test_validation_ref_optional_artifact_digest(self):
        # When platform supplies artifact_digest
        v_dict_with_digest = sample_validation_dict("a" * 64, "4" * 64)
        v_ref = ValidationRef.from_dict(v_dict_with_digest)
        self.assertEqual(v_ref.artifact_digest, "4" * 64)

        # When platform does not supply container digest (optional platform digest)
        v_dict_none_digest = sample_validation_dict("a" * 64, None)
        v_ref_none = ValidationRef.from_dict(v_dict_none_digest)
        self.assertIsNone(v_ref_none.artifact_digest)
        self.assertEqual(v_ref_none.evidence_member_sha256, "5" * 64)

    def test_structural_independent_review_ref(self):
        r_dict = sample_review_dict("a" * 64, "b" * 64)
        r_ref = StructuralIndependentReviewRef.from_dict(r_dict)
        self.assertEqual(r_ref.decision, "GO")
        self.assertEqual(len(r_ref.digest()), 64)

        r_dict_bad = sample_review_dict("a" * 64, "b" * 64)
        r_dict_bad["decision"] = "HOLD"
        with self.assertRaises(TypeValidationError):
            StructuralIndependentReviewRef.from_dict(r_dict_bad)

    def test_proof_manifest_v2_referential_integrity(self):
        s_dict = sample_subject_dict()
        subj = ExecutionSubject.from_dict(s_dict)
        subj_digest = subj.digest()

        v_dict = sample_validation_dict(subj_digest)
        v_ref = ValidationRef.from_dict(v_dict)
        val_digest = v_ref.digest()

        r_dict = sample_review_dict(subj_digest, val_digest)
        r_ref = StructuralIndependentReviewRef.from_dict(r_dict)

        manifest = ProofManifest(
            schema=SCHEMA_MANIFEST_V2,
            subject=subj,
            validation=v_ref,
            review=r_ref,
        )
        self.assertEqual(manifest.schema, SCHEMA_MANIFEST_V2)
        self.assertEqual(len(manifest.digest()), 64)

    def test_proof_manifest_v2_rejects_subject_validation_mismatch(self):
        s_dict = sample_subject_dict()
        subj = ExecutionSubject.from_dict(s_dict)
        v_dict = sample_validation_dict("0" * 64)  # Mismatched subject digest
        v_ref = ValidationRef.from_dict(v_dict)
        r_dict = sample_review_dict(subj.digest(), v_ref.digest())
        r_ref = StructuralIndependentReviewRef.from_dict(r_dict)

        with self.assertRaises(ValidationReferenceMismatch):
            ProofManifest(
                schema=SCHEMA_MANIFEST_V2,
                subject=subj,
                validation=v_ref,
                review=r_ref,
            )

    def test_proof_manifest_v2_rejects_review_validation_mismatch(self):
        s_dict = sample_subject_dict()
        subj = ExecutionSubject.from_dict(s_dict)
        subj_digest = subj.digest()
        v_dict = sample_validation_dict(subj_digest)
        v_ref = ValidationRef.from_dict(v_dict)
        r_dict = sample_review_dict(subj_digest, "0" * 64)  # Mismatched validation digest
        r_ref = StructuralIndependentReviewRef.from_dict(r_dict)

        with self.assertRaises(ReviewReferenceMismatch):
            ProofManifest(
                schema=SCHEMA_MANIFEST_V2,
                subject=subj,
                validation=v_ref,
                review=r_ref,
            )

    def test_execution_context_lifecycle(self):
        ctx_data = {
            "manifest_digest": "a" * 64,
            "subject_digest": "b" * 64,
            "repository": "jwaldrip/iyi",
            "run_id": "12345",
            "run_attempt": 1,
            "job_key": "strict-proof",
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        self.assertEqual(ctx.job_id, "999888")
        self.assertEqual(len(ctx.digest()), 64)

    def test_checkpoint_descriptor_lifecycle(self):
        desc_data = {
            "manifest_digest": "a" * 64,
            "subject_digest": "b" * 64,
            "execution_context_digest": "c" * 64,
            "launch_id": "launch-001",
            "stage": "run1",
            "attempt": 1,
            "command": ["python3", "-I", "-B", "proof/run_proof.py"],
            "exit_code": 0,
            "outcome": "PASS",
            "chain_id": "chain-123",
            "compiler_sha256": "d" * 64,
            "effective_policy": {"timeout": 2100},
            "teardown_disposition": {"stopped": True, "removed": True},
            "evidence_digests": {"report.tar.gz": "e" * 64},
            "timestamp": "2026-11-09T00:01:00Z",
        }
        desc = CheckpointDescriptor.from_dict(desc_data)
        self.assertEqual(desc.outcome, "PASS")
        self.assertEqual(len(desc.digest()), 64)


class TestRefusalPolicies(unittest.TestCase):
    def test_enforce_independent_review_refusal(self):
        with self.assertRaises(ReviewUnauthenticatedError) as ctx:
            enforce_independent_review_refusal()
        self.assertIn("INDEPENDENT-REVIEW-UNATTESTED", str(ctx.exception))

    def test_enforce_origin_transport_refusal(self):
        with self.assertRaises(StrictHaltRefusal) as ctx:
            enforce_origin_transport_refusal()
        self.assertIn("STRICT-EXECUTION-HALTED", str(ctx.exception))

    def test_auth_comment_prefix_preserves_v1(self):
        self.assertEqual(AUTH_COMMENT_PREFIX, "iyi-strict-linux-authorization-v1 sha256:")



class TestQualificationGroundTruth(unittest.TestCase):
    def setUp(self):
        self.orig_142 = tuple(f"selector_{i:03d}" for i in range(142))
        self.adds_2 = ("add_001", "add_002")
        self.corpus_144 = tuple(sorted(self.orig_142 + self.adds_2))
        self.sibs_117 = tuple(f"sibling_{i:03d}" for i in range(117))
        self.run3_inv = tuple(f"run3_driver_{i:03d}" for i in range(30))
        self.authority = SourceGroundingAuthority(
            baseline_commit="a" * 40,
            expected_142_selectors=self.orig_142,
            expected_2_additions=self.adds_2,
            expected_117_siblings=self.sibs_117,
            expected_run3_inventory=self.run3_inv,
        )

    def test_build_and_validate_ground_truth_success(self):
        qr = build_grounded_qualification_requirements(self.authority)
        self.assertEqual(qr.rg2_evaluated, 144)
        self.assertEqual(qr.run2_samples, 28)
        self.assertEqual(qr.run2_std_exercises, 116)
        self.assertEqual(qr.run2_total_corpus, 144)
        validate_qualification_ground_truth(
            qr,
            authority=self.authority,
            candidate_original_142_selectors=self.orig_142,
            candidate_additions_2_selectors=self.adds_2,
            candidate_complete_144_corpus=self.corpus_144,
            candidate_siblings_117_manifest=self.sibs_117,
            candidate_run3_inventory_manifest=self.run3_inv,
        )

    def test_authority_rejects_duplicate_in_original_selectors(self):
        bad_orig = self.orig_142[:-1] + (self.orig_142[0],)
        with self.assertRaises(DuplicateKeyError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=bad_orig,
                expected_2_additions=self.adds_2,
                expected_117_siblings=self.sibs_117,
                expected_run3_inventory=self.run3_inv,
            )

    def test_authority_rejects_duplicate_in_additions(self):
        bad_adds = ("add_001", "add_001")
        with self.assertRaises(DuplicateKeyError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=self.orig_142,
                expected_2_additions=bad_adds,
                expected_117_siblings=self.sibs_117,
                expected_run3_inventory=self.run3_inv,
            )

    def test_authority_rejects_wrong_original_count(self):
        bad_orig = self.orig_142[:-1]  # 141
        with self.assertRaises(TypeValidationError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=bad_orig,
                expected_2_additions=self.adds_2,
                expected_117_siblings=self.sibs_117,
                expected_run3_inventory=self.run3_inv,
            )

    def test_authority_rejects_overlap_between_originals_and_additions(self):
        bad_adds = (self.orig_142[0], "new_add_002")
        with self.assertRaises(ReferenceIntegrityError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=self.orig_142,
                expected_2_additions=bad_adds,
                expected_117_siblings=self.sibs_117,
                expected_run3_inventory=self.run3_inv,
            )

    def test_authority_rejects_wrong_sibling_count(self):
        bad_sibs = self.sibs_117[:-1]  # 116
        with self.assertRaises(TypeValidationError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=self.orig_142,
                expected_2_additions=self.adds_2,
                expected_117_siblings=bad_sibs,
                expected_run3_inventory=self.run3_inv,
            )

    def test_authority_rejects_run3_inventory_below_minimum(self):
        bad_run3 = tuple(f"driver_{i}" for i in range(28))  # < 29
        with self.assertRaises(TypeValidationError):
            SourceGroundingAuthority(
                baseline_commit="a" * 40,
                expected_142_selectors=self.orig_142,
                expected_2_additions=self.adds_2,
                expected_117_siblings=self.sibs_117,
                expected_run3_inventory=bad_run3,
            )

    def test_run3_inventory_exact_match_rejects_omitted_required_driver(self):
        qr = build_grounded_qualification_requirements(self.authority)
        tampered_run3 = self.run3_inv[:-1] + ("foreign_extra_driver",)
        with self.assertRaises(ReferenceIntegrityError):
            validate_qualification_ground_truth(
                qr,
                authority=self.authority,
                candidate_run3_inventory_manifest=tampered_run3,
            )

    def test_run3_inventory_exact_match_rejects_extra_driver(self):
        qr = build_grounded_qualification_requirements(self.authority)
        extra_run3 = self.run3_inv + ("foreign_extra_driver",)
        with self.assertRaises(ReferenceIntegrityError):
            validate_qualification_ground_truth(
                qr,
                authority=self.authority,
                candidate_run3_inventory_manifest=extra_run3,
            )

    def test_validate_rejects_tampered_original_selectors(self):
        qr = build_grounded_qualification_requirements(self.authority)
        tampered_orig = ("foreign_sel",) + self.orig_142[1:]
        with self.assertRaises(ReferenceIntegrityError):
            validate_qualification_ground_truth(
                qr,
                authority=self.authority,
                candidate_original_142_selectors=tampered_orig,
            )

    def test_validate_rejects_digest_mismatch(self):
        qr = build_grounded_qualification_requirements(self.authority)
        other_authority = SourceGroundingAuthority(
            baseline_commit="b" * 40,
            expected_142_selectors=tuple(f"other_{i:03d}" for i in range(142)),
            expected_2_additions=self.adds_2,
            expected_117_siblings=self.sibs_117,
            expected_run3_inventory=self.run3_inv,
        )
        with self.assertRaises(ReferenceIntegrityError):
            validate_qualification_ground_truth(
                qr,
                authority=other_authority,
            )

class TestCrossRecordBindingValidators(unittest.TestCase):
    def setUp(self):
        self.s_dict = sample_subject_dict()
        self.subject = ExecutionSubject.from_dict(self.s_dict)
        self.subj_digest = self.subject.digest()
        self.v_dict = sample_validation_dict(self.subj_digest)
        self.val_ref = ValidationRef.from_dict(self.v_dict)
        self.r_dict = sample_review_dict(self.subj_digest, self.val_ref.digest())
        self.rev_ref = StructuralIndependentReviewRef.from_dict(self.r_dict)
        self.manifest = ProofManifest(
            schema=SCHEMA_MANIFEST_V2,
            subject=self.subject,
            validation=self.val_ref,
            review=self.rev_ref,
        )

    def test_validation_ref_to_subject_success(self):
        validate_validation_ref_to_subject(self.val_ref, self.subject)

    def test_validation_ref_rejects_mismatched_c_sha(self):
        bad_v_dict = sample_validation_dict(self.subj_digest)
        bad_v_dict["validation_c_sha"] = "0" * 40
        bad_v = ValidationRef.from_dict(bad_v_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            validate_validation_ref_to_subject(bad_v, self.subject)

    def test_validation_ref_rejects_mismatched_repository(self):
        bad_v_dict = sample_validation_dict(self.subj_digest)
        bad_v_dict["validation_repository"] = "other/repo"
        bad_v = ValidationRef.from_dict(bad_v_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            validate_validation_ref_to_subject(bad_v, self.subject)

    def test_proof_manifest_rejects_tampered_validation_c_sha(self):
        bad_v_dict = sample_validation_dict(self.subj_digest)
        bad_v_dict["validation_c_sha"] = "0" * 40
        bad_v = ValidationRef.from_dict(bad_v_dict)
        r_dict = sample_review_dict(self.subj_digest, bad_v.digest())
        bad_r = StructuralIndependentReviewRef.from_dict(r_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            ProofManifest(
                schema=SCHEMA_MANIFEST_V2,
                subject=self.subject,
                validation=bad_v,
                review=bad_r,
            )

    def test_execution_context_to_manifest_success(self):
        ctx_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "repository": self.subject.repository,
            "run_id": self.subject.run_id,
            "run_attempt": self.subject.run_attempt,
            "job_key": self.subject.job_key,
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        validate_execution_context_to_manifest(ctx, self.manifest)

    def test_execution_context_rejects_mismatched_run_id(self):
        ctx_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "repository": self.subject.repository,
            "run_id": "99999",  # Mismatch
            "run_attempt": self.subject.run_attempt,
            "job_key": self.subject.job_key,
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        with self.assertRaises(ReferenceIntegrityError):
            validate_execution_context_to_manifest(ctx, self.manifest)

    def test_checkpoint_to_context_success(self):
        ctx_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "repository": self.subject.repository,
            "run_id": self.subject.run_id,
            "run_attempt": self.subject.run_attempt,
            "job_key": self.subject.job_key,
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        desc_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "execution_context_digest": ctx.digest(),
            "launch_id": "launch-001",
            "stage": "run1",
            "attempt": 1,
            "command": ["python3", "-I", "-B", "proof/run_proof.py"],
            "exit_code": 0,
            "outcome": "PASS",
            "chain_id": "chain-123",
            "compiler_sha256": "d" * 64,
            "effective_policy": {"timeout": 2100},
            "teardown_disposition": {"stopped": True, "removed": True},
            "evidence_digests": {"report.tar.gz": "e" * 64},
            "timestamp": "2026-11-09T00:01:00Z",
        }
        desc = CheckpointDescriptor.from_dict(desc_data)
        validate_checkpoint_to_context(desc, ctx, self.manifest)

    def test_validation_ref_rejects_mismatched_run_id(self):
        bad_v_dict = sample_validation_dict(self.subj_digest)
        bad_v_dict["run_id"] = "99999"
        bad_v = ValidationRef.from_dict(bad_v_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            validate_validation_ref_to_subject(bad_v, self.subject)

    def test_validation_ref_rejects_mismatched_run_attempt(self):
        bad_v_dict = sample_validation_dict(self.subj_digest)
        bad_v_dict["run_attempt"] = 2
        bad_v = ValidationRef.from_dict(bad_v_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            validate_validation_ref_to_subject(bad_v, self.subject)

    def test_checkpoint_to_context_rejects_unremoved_container_on_pass(self):
        ctx_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "repository": self.subject.repository,
            "run_id": self.subject.run_id,
            "run_attempt": self.subject.run_attempt,
            "job_key": self.subject.job_key,
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        desc_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "execution_context_digest": ctx.digest(),
            "launch_id": "launch-001",
            "stage": "run1",
            "attempt": 1,
            "command": ["python3", "-I", "-B", "proof/run_proof.py"],
            "exit_code": 0,
            "outcome": "PASS",
            "chain_id": "chain-123",
            "compiler_sha256": "d" * 64,
            "effective_policy": {"timeout": 2100},
            "teardown_disposition": {"stopped": True, "removed": False},
            "evidence_digests": {"report.tar.gz": "e" * 64},
            "timestamp": "2026-11-09T00:01:00Z",
        }
        desc = CheckpointDescriptor.from_dict(desc_data)
        with self.assertRaises(ReferenceIntegrityError):
            validate_checkpoint_to_context(desc, ctx, self.manifest)

    def test_checkpoint_to_context_rejects_nonzero_exit_code_on_pass(self):
        ctx_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "repository": self.subject.repository,
            "run_id": self.subject.run_id,
            "run_attempt": self.subject.run_attempt,
            "job_key": self.subject.job_key,
            "job_id": "999888",
            "runner_identity": "ubuntu-24.04-runner-01",
            "job_started_at_iso": "2026-11-09T00:00:00Z",
            "job_started_at_epoch": 1794182400.0,
            "platform_response_digests": {"approvals": "c" * 64},
        }
        ctx = ExecutionContext.from_dict(ctx_data)
        desc_data = {
            "manifest_digest": self.manifest.digest(),
            "subject_digest": self.subject.digest(),
            "execution_context_digest": ctx.digest(),
            "launch_id": "launch-001",
            "stage": "run1",
            "attempt": 1,
            "command": ["python3", "-I", "-B", "proof/run_proof.py"],
            "exit_code": 1,
            "outcome": "PASS",
            "chain_id": "chain-123",
            "compiler_sha256": "d" * 64,
            "effective_policy": {"timeout": 2100},
            "teardown_disposition": {"stopped": True, "removed": True},
            "evidence_digests": {"report.tar.gz": "e" * 64},
            "timestamp": "2026-11-09T00:01:00Z",
        }
        desc = CheckpointDescriptor.from_dict(desc_data)
        with self.assertRaises(ReferenceIntegrityError):
            validate_checkpoint_to_context(desc, ctx, self.manifest)


class TestStrictPairsMapAndCheckpointImmutability(unittest.TestCase):
    def test_validate_strict_pairs_map_rejects_duplicates(self):
        pairs = [("key1", "val1"), ("key1", "val2")]
        with self.assertRaises(DuplicateKeyError):
            validate_strict_pairs_map(pairs, "test_map")

    def test_validate_strict_pairs_map_rejects_mutable_containers(self):
        with self.assertRaises(TypeValidationError):
            validate_strict_pairs_map({"key1": {"nested": "dict"}}, "test_map")
        with self.assertRaises(TypeValidationError):
            validate_strict_pairs_map({"key1": ["nested", "list"]}, "test_map")

    def test_validate_strict_pairs_map_rejects_non_finite_float(self):
        with self.assertRaises(NonFiniteNumberError):
            validate_strict_pairs_map({"key1": float("nan")}, "test_map")
        with self.assertRaises(NonFiniteNumberError):
            validate_strict_pairs_map({"key1": float("inf")}, "test_map")

    def test_checkpoint_direct_constructor_rejects_nested_mutable(self):
        with self.assertRaises(TypeValidationError):
            CheckpointDescriptor(
                manifest_digest="a" * 64,
                subject_digest="b" * 64,
                execution_context_digest="c" * 64,
                launch_id="1",
                stage="run1",
                attempt=1,
                command=("echo", "test"),
                exit_code=0,
                outcome="PASS",
                chain_id=None,
                compiler_sha256=None,
                effective_policy=(("policy_dict", {"mutable": True}),),  # Invalid nested dict
                teardown_disposition=(),
                evidence_digests=(),
                timestamp="2026-11-09T00:01:00Z",
            )

    def test_checkpoint_direct_constructor_rejects_non_sha_evidence(self):
        with self.assertRaises(TypeValidationError):
            CheckpointDescriptor(
                manifest_digest="a" * 64,
                subject_digest="b" * 64,
                execution_context_digest="c" * 64,
                launch_id="1",
                stage="run1",
                attempt=1,
                command=("echo", "test"),
                exit_code=0,
                outcome="PASS",
                chain_id=None,
                compiler_sha256=None,
                effective_policy=(),
                teardown_disposition=(),
                evidence_digests=(("report", "not_a_sha256"),),  # Invalid SHA
                timestamp="2026-11-09T00:01:00Z",
            )

    def test_teardown_disposition_preserves_bool_types(self):
        desc = CheckpointDescriptor(
            manifest_digest="a" * 64,
            subject_digest="b" * 64,
            execution_context_digest="c" * 64,
            launch_id="1",
            stage="run1",
            attempt=1,
            command=("echo", "test"),
            exit_code=0,
            outcome="PASS",
            chain_id=None,
            compiler_sha256=None,
            effective_policy=(),
            teardown_disposition=(("containers_removed", True), ("exit_code", 0)),
            evidence_digests=(),
            timestamp="2026-11-09T00:01:00Z",
        )
        d = desc.to_dict()
        self.assertIs(d["teardown_disposition"]["containers_removed"], True)
        self.assertEqual(d["teardown_disposition"]["exit_code"], 0)


class TestStrictBoolRejection(unittest.TestCase):
    def test_require_bool_rejects_non_booleans(self):
        for val in ("false", "true", "0", "1", 0, 1, None, [], {}, 1.0):
            with self.assertRaises(TypeValidationError):
                require_bool(val, "flag")

    def test_require_bool_enforces_expected(self):
        self.assertTrue(require_bool(True, "flag", expected=True))
        with self.assertRaises(TypeValidationError):
            require_bool(False, "flag", expected=True)

    def test_cage_policy_from_dict_rejects_string_and_int_flags(self):
        d = sample_cage_policy_dict()
        d["read_only_root"] = "false"
        with self.assertRaises(TypeValidationError):
            CagePolicy.from_dict(d)

        d2 = sample_cage_policy_dict()
        d2["no_new_privileges"] = 1
        with self.assertRaises(TypeValidationError):
            CagePolicy.from_dict(d2)

    def test_qualification_from_dict_rejects_string_flags(self):
        d = sample_qualification_dict()
        d["named_frames_required"] = "true"
        with self.assertRaises(TypeValidationError):
            QualificationRequirements.from_dict(d)


class TestTimestampAndEpoch(unittest.TestCase):
    def test_parse_utc_iso_timestamp_valid(self):
        dt = parse_utc_iso_timestamp("2026-11-09T12:30:45Z", "ts")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 11)
        self.assertEqual(dt.day, 9)

    def test_parse_utc_iso_timestamp_rejects_calendar_errors(self):
        bad_dates = [
            "2026-99-99T99:99:99Z",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-04-31T00:00:00Z",
        ]
        for b in bad_dates:
            with self.assertRaises(TypeValidationError):
                parse_utc_iso_timestamp(b, "ts")

    def test_validate_timestamp_and_epoch_agreement(self):
        iso = "2026-11-09T00:00:00Z"
        epoch = 1794182400.0
        validated = validate_timestamp_and_epoch(iso, epoch, "start_time")
        self.assertAlmostEqual(validated, epoch)

        # Rejects drift > 1.0s
        with self.assertRaises(TypeValidationError):
            validate_timestamp_and_epoch(iso, epoch + 5.0, "start_time")

        # Rejects negative epoch
        with self.assertRaises(TypeValidationError):
            validate_timestamp_and_epoch(iso, -100.0, "start_time")


class TestProductionPolicyBinding(unittest.TestCase):
    def test_production_resource_policy_exact(self):
        rp = build_production_resource_policy()
        self.assertEqual(rp.driver_limit_sec, 2100)
        self.assertEqual(rp.grace_sec, 30)
        self.assertEqual(rp.host_job_limit_sec, 21600)
        self.assertEqual(rp.payload_budget_sec, 19800)
        self.assertEqual(rp.finalization_alloc_sec, 1800)
        self.assertEqual(rp.min_disk_gib, 20.0)
        validate_production_resource_policy(rp)

    def test_production_resource_policy_rejects_alterations(self):
        bad_rp = ResourcePolicy(
            driver_limit_sec=2100,
            grace_sec=1,  # Altered != 30
            payload_budget_sec=19800,
            host_job_limit_sec=21600,
            finalization_alloc_sec=1800,
            min_disk_gib=20.0,
            stage_build_limit_sec=1200,
            stage_version_limit_sec=60,
            stage_plan_limit_sec=600,
            stage_pin_limit_sec=600,
            stage_run1_limit_sec=1800,
            stage_run2_limit_sec=3600,
            stage_final_limit_sec=1200,
        )
        with self.assertRaises(ReferenceIntegrityError):
            validate_production_resource_policy(bad_rp)

    def test_production_cage_policy_exact(self):
        cp = build_production_cage_policy()
        self.assertEqual(cp.uid, 65534)
        self.assertEqual(cp.gid, 65534)
        self.assertEqual(cp.network, "none")
        self.assertEqual(cp.pids_limit, 128)
        self.assertEqual(cp.tmpfs_tmp_size, "2g")
        self.assertEqual(cp.tmpfs_dev_shm_size, "1g")
        validate_production_cage_policy(cp)

    def test_production_cage_policy_rejects_alterations(self):
        bad_cp = CagePolicy(
            uid=1000,  # Altered != 65534
            gid=65534,
            network="none",
            read_only_root=True,
            drop_capabilities="ALL",
            no_new_privileges=True,
            private_pid_namespace=True,
            default_confined_seccomp=True,
            init_process=True,
            pids_limit=128,
            tmpfs_tmp_size="2g",
            tmpfs_dev_shm_size="1g",
        )
        with self.assertRaises(ReferenceIntegrityError):
            validate_production_cage_policy(bad_cp)


class TestCanonicalNormalization(unittest.TestCase):
    def test_resource_policy_normalizes_int_disk_to_float(self):
        rp_int = ResourcePolicy(
            driver_limit_sec=2100,
            grace_sec=30,
            payload_budget_sec=19800,
            host_job_limit_sec=21600,
            finalization_alloc_sec=1800,
            min_disk_gib=20,  # int
            stage_build_limit_sec=1200,
            stage_version_limit_sec=60,
            stage_plan_limit_sec=600,
            stage_pin_limit_sec=600,
            stage_run1_limit_sec=1800,
            stage_run2_limit_sec=3600,
            stage_final_limit_sec=1200,
        )
        rp_float = ResourcePolicy(
            driver_limit_sec=2100,
            grace_sec=30,
            payload_budget_sec=19800,
            host_job_limit_sec=21600,
            finalization_alloc_sec=1800,
            min_disk_gib=20.0,  # float
            stage_build_limit_sec=1200,
            stage_version_limit_sec=60,
            stage_plan_limit_sec=600,
            stage_pin_limit_sec=600,
            stage_run1_limit_sec=1800,
            stage_run2_limit_sec=3600,
            stage_final_limit_sec=1200,
        )
        self.assertIsInstance(rp_int.min_disk_gib, float)
        self.assertEqual(rp_int.canonical_bytes(), rp_float.canonical_bytes())
        self.assertEqual(rp_int.digest(), rp_float.digest())

    def test_execution_subject_normalizes_int_run_id_to_str(self):
        d1 = sample_subject_dict()
        d1["run_id"] = 12345  # int
        s1 = ExecutionSubject.from_dict(d1)

        d2 = sample_subject_dict()
        d2["run_id"] = "12345"  # str
        s2 = ExecutionSubject.from_dict(d2)

        self.assertIsInstance(s1.run_id, str)
        self.assertEqual(s1.run_id, "12345")
        self.assertEqual(s1.canonical_bytes(), s2.canonical_bytes())
        self.assertEqual(s1.digest(), s2.digest())

if __name__ == "__main__":
    unittest.main()
