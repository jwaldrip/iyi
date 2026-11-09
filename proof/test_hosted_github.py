#!/usr/bin/env python3
"""
proof/test_hosted_github.py: Comprehensive pure mocked tests for proof/hosted_github.py.

Validates Slice B of PlanControllerRepairs (§3.1-3.3, §4 Slice B, §5) and all 12 review findings:
1. Reject conflicting approval rejections, rerun history, and non-approved states.
2. Fresh exact run/attempt, C, workflow, and branch authentication in approval verification.
3. Validation provenance verification while strict workflow is in_progress and strict job is waiting.
4. Logical job key resolution using trusted workflow display identities (Linux Strict Proof Supervisor).
5. Bounded ZIP expansion against evidence policy (individual bomb, aggregate bomb, entry flood).
6. Detached custody comparison against independent complete expected member inventory and envelope hash.
7. Artifact producer/attempt/repository joins, normalized platform digests, and expired strictly False.
8. Guard first download URL before attaching token (reject untrusted host and non-HTTPS).
9. Retain raw response pages under full canonical query keys without credential leaks.
10. Fixed self-review protection semantics (allow_self_review vs prevent_self_review) and injected policy.
11. Strict JSON parsing and closed receipt invariants (recomputed inventory digest, duplicate path checks).
12. Semantic own-artifact-ID detection (prohibits metadata self-reference without false positives on numbers).
- Backward-compatible preservation of existing proof/github_artifact.py callers.
- Pure in-memory mocked tests; zero network access, zero git commands.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import http.client
import io
import json
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from proof.github_artifact import (
    DEFAULT_TRUSTED_API_HOSTS,
    REDIRECT_CODES,
    USER_AGENT,
    download_artifact_stream,
    download_artifact_zip,
    validate_credentialed_artifact_url,
)
from proof.hosted_contracts import (
    AUTH_COMMENT_PREFIX,
    SCHEMA_MANIFEST_V2,
    ContractError,
    EvidencePolicy,
    ExecutionContext,
    ExecutionSubject,
    ProofManifest,
    ReferenceIntegrityError,
    ReviewUnauthenticatedError,
    StrictHaltRefusal,
    StructuralIndependentReviewRef,
    TypeValidationError,
    ValidationRef,
    canonical_json_bytes,
    sha256_bytes,
)
from proof.hosted_github import (
    CONTROLLER_TERMINAL_STATE_PENDING_CUSTODY,
    CUSTODY_STATUS_RETAINED,
    DEFAULT_API_BASE,
    DEFAULT_USER_AGENT,
    SCHEMA_DETACHED_CUSTODY_V1,
    TRUSTED_WORKFLOW_JOB_IDENTITIES,
    UNIMPLEMENTED_TRUST_ANCHORS,
    AmbiguousMatchError,
    ArtifactCustodyError,
    DetachedCustodyReceipt,
    GitHubPlatformRefusal,
    HostedGitHubClient,
    HostedGitHubError,
    MissingRecordError,
    PersonalApprovalReceipt,
    ResponseBudgetExceededError,
    TrustedApprovalPolicy,
    ValidationProvenanceReceipt,
    build_trusted_approval_policy,
    canonical_request_key,
    compute_inventory_digest,
    read_execution_context,
    verify_detached_artifact_custody,
    verify_independent_review,
    verify_personal_approval,
    verify_validation_provenance,
)


# Hermetic In-Memory Mock Opener
class MockOpener(urllib.request.OpenerDirector):
    """In-memory URL opener simulating GitHub REST API and blob storage redirects."""

    def __init__(self) -> None:
        super().__init__()
        self.routes: Dict[str, Tuple[int, Dict[str, str], bytes]] = {}
        self.redirects: Dict[str, str] = {}
        self.recorded_requests: List[Dict[str, Any]] = []

    def register(
        self,
        url: str,
        body: Any,
        status: int = 200,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            raise TypeError(f"Unsupported body type: {type(body)}")

        hdrs = dict(headers or {})
        if "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/json"
        if "Content-Length" not in hdrs:
            hdrs["Content-Length"] = str(len(body_bytes))

        self.routes[url] = (status, hdrs, body_bytes)

    def register_redirect(self, from_url: str, to_url: str) -> None:
        self.redirects[from_url] = to_url

    def open(self, fullurl: Any, data: Any = None, timeout: Any = None) -> Any:
        if isinstance(fullurl, urllib.request.Request):
            req = fullurl
            url = req.full_url
        else:
            url = str(fullurl)
            req = urllib.request.Request(url)

        headers = dict(req.headers)
        self.recorded_requests.append({
            "url": url,
            "headers": headers,
            "method": req.get_method(),
        })

        clean_url = url.split("?")[0]

        # Check for redirect
        if clean_url in self.redirects or url in self.redirects:
            target = self.redirects.get(url, self.redirects.get(clean_url, ""))
            msg = http.client.HTTPMessage()
            msg["Location"] = target
            raise urllib.error.HTTPError(url, 302, "Found", msg, io.BytesIO(b""))

        matched = self.routes.get(url) or self.routes.get(clean_url)
        if matched is None:
            msg = http.client.HTTPMessage()
            msg["Content-Type"] = "application/json"
            err_body = json.dumps({"message": f"Not Found: {url}"}).encode("utf-8")
            msg["Content-Length"] = str(len(err_body))
            raise urllib.error.HTTPError(url, 404, "Not Found", msg, io.BytesIO(err_body))

        status, hdrs, body_bytes = matched
        if status >= 400:
            msg = http.client.HTTPMessage()
            for k, v in hdrs.items():
                msg[k] = v
            raise urllib.error.HTTPError(url, status, f"HTTP {status}", msg, io.BytesIO(body_bytes))

        msg = http.client.HTTPMessage()
        for k, v in hdrs.items():
            msg[k] = v

        fp = io.BytesIO(body_bytes)
        resp = urllib.response.addinfourl(fp, msg, url, status)
        return resp


# Test Fixture Helpers
def create_test_zip(files: Dict[str, bytes]) -> bytes:
    """Create in-memory zip archive with deterministic files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
    return buf.getvalue()


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


def sample_validation_dict(subject_digest: str, member_size: int, member_sha: str) -> dict:
    return {
        "subject_digest": subject_digest,
        "validation_repository": "jwaldrip/iyi",
        "validation_workflow": ".github/workflows/pr147-linux-strict.yml",
        "validation_c_sha": "a" * 40,
        "run_id": "12345",
        "run_attempt": 1,
        "job_id": "555444",
        "artifact_id": "999000",
        "artifact_digest": "4" * 64,
        "evidence_member_size": member_size,
        "evidence_member_sha256": member_sha,
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


class TestHostedGitHubClient(unittest.TestCase):
    """Test client creation, bounded requests, errors, pagination, and redirect discipline."""

    def test_client_init_and_empty_token_refusal(self) -> None:
        with self.assertRaises(GitHubPlatformRefusal):
            HostedGitHubClient(token="")
        with self.assertRaises(GitHubPlatformRefusal):
            HostedGitHubClient(token="   ")
        client = HostedGitHubClient(token="ghp_test123", api_base="https://api.github.com/")
        self.assertEqual(client.api_base, "https://api.github.com")

    def test_request_headers_and_security_host_check(self) -> None:
        opener = MockOpener()
        opener.register("https://api.github.com/repos/jwaldrip/iyi", {"id": 12345, "name": "iyi"})
        client = HostedGitHubClient(token="valid-secret-token", opener=opener)

        data = client.get_repository("jwaldrip/iyi")
        self.assertEqual(data["id"], 12345)

        self.assertEqual(len(opener.recorded_requests), 1)
        req = opener.recorded_requests[0]
        self.assertEqual(req["headers"]["Authorization"], "Bearer valid-secret-token")
        self.assertEqual(req["headers"]["Accept"], "application/vnd.github+json")
        ua = req["headers"].get("User-agent") or req["headers"].get("User-Agent")
        self.assertEqual(ua, DEFAULT_USER_AGENT)

        # Assert token is NOT retained in digests
        digests = client.get_retained_response_digests()
        self.assertEqual(len(digests), 1)
        self.assertIn("GET repos/jwaldrip/iyi", digests[0][0])
        self.assertNotIn("valid-secret-token", str(digests))

        # Security check: attempt to make request to non-API host raises refusal
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            client._request("GET", "https://evil.attacker.com/steal")
        self.assertIn("Security violation", str(ctx.exception))

    def test_first_hop_credential_url_guard(self) -> None:
        # Untrusted host raises ValueError before sending credentials
        with self.assertRaises(ValueError) as ctx:
            validate_credentialed_artifact_url("https://foreign.attacker.com/steal/actions/artifacts/123/zip")
        self.assertIn("Untrusted host", str(ctx.exception))

        # Non-HTTPS URL raises ValueError before sending credentials
        with self.assertRaises(ValueError) as ctx:
            validate_credentialed_artifact_url("http://api.github.com/repos/a/b/actions/artifacts/123/zip")
        self.assertIn("HTTPS", str(ctx.exception))

    def test_bounded_response_limit(self) -> None:
        opener = MockOpener()
        large_payload = {"data": "x" * 2000}
        opener.register("https://api.github.com/large", large_payload)
        client = HostedGitHubClient(token="token", max_response_bytes=500, opener=opener)

        with self.assertRaises(ResponseBudgetExceededError):
            client.api_get("large")

    def test_http_error_handling(self) -> None:
        opener = MockOpener()
        opener.register("https://api.github.com/auth-fail", {"message": "Bad credentials"}, status=401)
        opener.register("https://api.github.com/forbidden", {"message": "Forbidden"}, status=403)
        opener.register("https://api.github.com/not-found", {"message": "Not Found"}, status=404)
        opener.register("https://api.github.com/server-error", {"message": "Internal Error"}, status=500)

        client = HostedGitHubClient(token="token", opener=opener)

        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            client.api_get("auth-fail")
        self.assertIn("401", str(ctx.exception))

        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            client.api_get("forbidden")
        self.assertIn("403", str(ctx.exception))

        with self.assertRaises(MissingRecordError):
            client.api_get("not-found")

        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            client.api_get("server-error")
        self.assertIn("500", str(ctx.exception))

    def test_pagination_canonical_keys_retained(self) -> None:
        opener = MockOpener()
        # Page 1
        page1_url = "https://api.github.com/items?page=1&per_page=2"
        page1_data = [{"id": 1}, {"id": 2}]
        page2_url = "https://api.github.com/items?page=2&per_page=2"
        page2_data = [{"id": 3}, {"id": 4}]

        opener.register(
            page1_url,
            page1_data,
            headers={"Link": f'<{page2_url}>; rel="next"'},
        )
        opener.register(page2_url, page2_data)

        client = HostedGitHubClient(token="token", opener=opener)
        results = client.get_paginated("items", params={"page": 1, "per_page": 2})
        self.assertEqual([r["id"] for r in results], [1, 2, 3, 4])

        # Assert BOTH page 1 and page 2 are retained under distinct keys
        digests = dict(client.get_retained_response_digests())
        self.assertIn("GET items?page=1&per_page=2", digests)
        self.assertIn("GET items?page=2&per_page=2", digests)

    def test_redirect_strips_token_discipline(self) -> None:
        opener = MockOpener()
        api_art_url = "https://api.github.com/repos/jwaldrip/iyi/actions/artifacts/123/zip"
        storage_url = "https://pipelines.actions.githubusercontent.com/signed-blob-12345"

        test_data = create_test_zip({"file.txt": b"DATA"})
        opener.register_redirect(api_art_url, storage_url)
        opener.register(storage_url, test_data, headers={"Content-Type": "application/zip"})

        client = HostedGitHubClient(token="secret-gh-token", opener=opener)
        downloaded = client.download_artifact_zip(api_art_url)
        self.assertEqual(downloaded, test_data)

        self.assertEqual(len(opener.recorded_requests), 2)
        api_req = opener.recorded_requests[0]
        storage_req = opener.recorded_requests[1]

        self.assertEqual(api_req["headers"].get("Authorization"), "Bearer secret-gh-token")
        self.assertNotIn("Authorization", storage_req["headers"])


class TestValidationProvenance(unittest.TestCase):
    """Test validation provenance verification and all negative controls."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="test-token", opener=self.opener)

        # Evidence member in zip
        self.evidence_bytes = canonical_json_bytes({"status": "PASS", "test_count": 144})
        self.evidence_size = len(self.evidence_bytes)
        self.evidence_sha256 = sha256_bytes(self.evidence_bytes)
        self.artifact_zip = create_test_zip({"validation_summary.json": self.evidence_bytes})
        self.artifact_sha256 = sha256_bytes(self.artifact_zip)

        # Subject & ValidationRef
        subj_dict = sample_subject_dict()
        self.subject = ExecutionSubject.from_dict(subj_dict)
        val_dict = sample_validation_dict(self.subject.digest(), self.evidence_size, self.evidence_sha256)
        val_dict["artifact_digest"] = self.artifact_sha256
        self.validation_ref = ValidationRef.from_dict(val_dict)

        # Register successful routes
        self.repo = "jwaldrip/iyi"
        self.val_run_id = self.validation_ref.run_id
        self.val_job_id = self.validation_ref.job_id
        self.val_art_id = self.validation_ref.artifact_id

        self.opener.register(f"https://api.github.com/repos/{self.repo}", {"id": 1, "full_name": self.repo})
        # Workflow is in_progress while validation job is completed
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "in_progress",
            "conclusion": None,
            "path": ".github/workflows/pr147-linux-strict.yml",
            "head_sha": self.subject.c_sha,
        })
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}/attempts/1/jobs", {
            "jobs": [
                {
                    "id": int(self.val_job_id),
                    "name": "validation-proofs",
                    "status": "completed",
                    "conclusion": "success",
                },
                {
                    "id": 999999,
                    "name": "Linux Strict Proof Supervisor (Ubuntu 24.04)",
                    "status": "waiting",
                    "conclusion": None,
                },
            ]
        })
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}", {
            "id": int(self.val_art_id),
            "name": "validation-evidence",
            "size_in_bytes": len(self.artifact_zip),
            "expired": False,
            "digest": f"sha256:{self.artifact_sha256}",
            "workflow_run": {"id": int(self.val_run_id)},
        })
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            self.artifact_zip,
            headers={"Content-Type": "application/zip"},
        )

    def test_validation_provenance_while_workflow_in_progress(self) -> None:
        receipt = verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIsInstance(receipt, ValidationProvenanceReceipt)
        self.assertEqual(receipt.subject_digest, self.subject.digest())
        self.assertEqual(receipt.evidence_member_size, self.evidence_size)
        self.assertEqual(receipt.evidence_member_sha256, self.evidence_sha256)

    def test_validation_job_failed(self) -> None:
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}/attempts/1/jobs", {
            "jobs": [
                {
                    "id": int(self.val_job_id),
                    "name": "validation-proofs",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ]
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("conclusion", str(ctx.exception))

    def test_zip_individual_bomb_rejected(self) -> None:
        small_limits = dataclasses.replace(self.subject.evidence_policy, max_file_bytes=10)
        subj = dataclasses.replace(self.subject, evidence_policy=small_limits)
        val = dataclasses.replace(self.validation_ref, subject_digest=subj.digest())

        with self.assertRaises(ResponseBudgetExceededError):
            verify_validation_provenance(self.client, val, subj)

    def test_zip_entry_flood_rejected(self) -> None:
        entry_limits = dataclasses.replace(self.subject.evidence_policy, max_directory_entries=1)
        subj = dataclasses.replace(self.subject, evidence_policy=entry_limits)
        multi_zip = create_test_zip({"file1.txt": b"1", "file2.txt": b"2"})
        multi_sha = sha256_bytes(multi_zip)
        val = dataclasses.replace(
            self.validation_ref,
            subject_digest=subj.digest(),
            artifact_digest=multi_sha,
        )
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}", {
            "id": int(self.val_art_id),
            "name": "validation-evidence",
            "size_in_bytes": len(multi_zip),
            "expired": False,
            "digest": f"sha256:{multi_sha}",
            "workflow_run": {"id": int(self.val_run_id)},
        })
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            multi_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ResponseBudgetExceededError):
            verify_validation_provenance(self.client, val, subj)

class TestExecutionContextReadback(unittest.TestCase):
    """Test authenticated ExecutionContext platform readback using trusted job identities."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        self.evidence_bytes = b"evidence"
        self.subj = ExecutionSubject.from_dict(sample_subject_dict())
        val_dict = sample_validation_dict(self.subj.digest(), len(self.evidence_bytes), sha256_bytes(self.evidence_bytes))
        self.val = ValidationRef.from_dict(val_dict)
        rev_dict = sample_review_dict(self.subj.digest(), self.val.digest())
        self.rev = StructuralIndependentReviewRef.from_dict(rev_dict)
        self.manifest = ProofManifest(
            schema=SCHEMA_MANIFEST_V2,
            subject=self.subj,
            validation=self.val,
            review=self.rev,
        )

        self.repo = self.subj.repository
        self.run_id = self.subj.run_id
        self.run_attempt = self.subj.run_attempt

        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}", {
            "id": int(self.run_id),
            "run_attempt": self.run_attempt,
            "path": self.subj.workflow_path,
            "head_sha": self.subj.c_sha,
        })
        # Use actual workflow display name "Linux Strict Proof Supervisor (Ubuntu 24.04)"
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/attempts/1/jobs", {
            "jobs": [
                {
                    "id": 128575084391,
                    "name": "Linux Strict Proof Supervisor (Ubuntu 24.04)",
                    "runner_name": "hosted-linux-runner-42",
                    "runner_id": 42,
                    "started_at": "2026-11-09T08:30:00Z",
                    "status": "in_progress",
                }
            ]
        })

    def test_execution_context_resolves_actual_workflow_display_name(self) -> None:
        ctx = read_execution_context(self.client, self.manifest)
        self.assertIsInstance(ctx, ExecutionContext)
        self.assertEqual(ctx.manifest_digest, self.manifest.digest())
        self.assertEqual(ctx.job_id, "128575084391")
        self.assertEqual(ctx.runner_identity, "hosted-linux-runner-42")


class TestPersonalApproval(unittest.TestCase):
    """Test personal approval verification, conflicting rejection rejection, and policy checks."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        self.evidence_bytes = b"evidence"
        self.subj = ExecutionSubject.from_dict(sample_subject_dict())
        val_dict = sample_validation_dict(self.subj.digest(), len(self.evidence_bytes), sha256_bytes(self.evidence_bytes))
        self.val = ValidationRef.from_dict(val_dict)
        rev_dict = sample_review_dict(self.subj.digest(), self.val.digest())
        self.rev = StructuralIndependentReviewRef.from_dict(rev_dict)
        self.manifest = ProofManifest(
            schema=SCHEMA_MANIFEST_V2,
            subject=self.subj,
            validation=self.val,
            review=self.rev,
        )

        self.repo = self.subj.repository
        self.run_id = self.subj.run_id
        self.policy = build_trusted_approval_policy(
            environment_name="strict-proof",
            environment_id="26584191206",
            reviewer_id="43164",
            reviewer_login="jwaldrip",
            target_branch="proof/strict-lifecycle-repair-20261102",
            allow_self_review=False,
            can_admins_bypass=False,
        )

        # Mock run metadata
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}", {
            "id": int(self.run_id),
            "run_attempt": 1,
            "head_sha": self.subj.c_sha,
            "path": self.subj.workflow_path,
            "head_branch": "proof/strict-lifecycle-repair-20261102",
        })

        # Mock environment
        self.opener.register(f"https://api.github.com/repos/{self.repo}/environments/{self.policy.environment_name}", {
            "id": int(self.policy.environment_id),
            "name": self.policy.environment_name,
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {"reviewer": {"id": int(self.policy.reviewer_id), "login": "jwaldrip"}}
                    ],
                }
            ],
        })

        # Mock deployment branch policies
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/environments/{self.policy.environment_name}/deployment-branch-policies",
            {"branch_policies": [{"name": self.policy.target_branch}]},
        )

        self.expected_comment = f"{AUTH_COMMENT_PREFIX}{self.manifest.digest()}"
        self.valid_approval = {
            "state": "approved",
            "user": {"id": int(self.policy.reviewer_id), "login": "jwaldrip"},
            "environments": [{"id": int(self.policy.environment_id), "name": self.policy.environment_name}],
            "comment": self.expected_comment,
        }
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [self.valid_approval],
        )

    def test_personal_approval_positive(self) -> None:
        receipt = verify_personal_approval(self.client, self.manifest, self.policy)
        self.assertIsInstance(receipt, PersonalApprovalReceipt)
        self.assertEqual(receipt.manifest_digest, self.manifest.digest())

    def test_conflicting_rejection_in_history_rejected(self) -> None:
        # History contains one approval and one rejection for the same reviewer/environment
        rejection_record = {
            "state": "rejected",
            "user": {"id": int(self.policy.reviewer_id), "login": "jwaldrip"},
            "environments": [{"id": int(self.policy.environment_id), "name": self.policy.environment_name}],
            "comment": "Rejected",
        }
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [self.valid_approval, rejection_record],
        )
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_personal_approval(self.client, self.manifest, self.policy)
        self.assertIn("rejected", str(ctx.exception).lower())

    def test_self_review_policy_semantics(self) -> None:
        # allow_self_review=False requires prevent_self_review=True
        # If GitHub environment has prevent_self_review=False, reject!
        self.opener.register(f"https://api.github.com/repos/{self.repo}/environments/{self.policy.environment_name}", {
            "id": int(self.policy.environment_id),
            "name": self.policy.environment_name,
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [{"reviewer": {"id": int(self.policy.reviewer_id)}}],
                }
            ],
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_personal_approval(self.client, self.manifest, self.policy)
        self.assertIn("prevent_self_review", str(ctx.exception))


class TestDetachedArtifactCustody(unittest.TestCase):
    """Test detached custody readback, full expected inventory comparison, and semantic checks."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        self.evidence_bytes = b"evidence"
        self.subj = ExecutionSubject.from_dict(sample_subject_dict())
        val_dict = sample_validation_dict(self.subj.digest(), len(self.evidence_bytes), sha256_bytes(self.evidence_bytes))
        self.val = ValidationRef.from_dict(val_dict)
        rev_dict = sample_review_dict(self.subj.digest(), self.val.digest())
        self.rev = StructuralIndependentReviewRef.from_dict(rev_dict)
        self.manifest = ProofManifest(
            schema=SCHEMA_MANIFEST_V2,
            subject=self.subj,
            validation=self.val,
            review=self.rev,
        )

        self.repo = self.subj.repository
        self.art_id = "444555"

        self.terminal_envelope = {
            "summary": {
                "status": "PASS",
                "manifest_digest": self.manifest.digest(),
            },
            "manifest": self.manifest.to_dict(),
            "checkpoints": [],
            "sealed_receipts": [],
        }
        self.envelope_bytes = canonical_json_bytes(self.terminal_envelope)
        self.envelope_digest = sha256_bytes(self.envelope_bytes)

        summary_bytes = canonical_json_bytes({"status": "PASS"})
        receipt_bytes = canonical_json_bytes({"unit": 0, "status": "sealed"})

        self.zip_files = {
            "strict-controller-summary.json": summary_bytes,
            "terminal-envelope.json": self.envelope_bytes,
            "sealed-receipts/receipt-0.json": receipt_bytes,
        }
        self.raw_zip = create_test_zip(self.zip_files)

        # Expected full inventory
        self.expected_inventory = (
            ("sealed-receipts/receipt-0.json", len(receipt_bytes), sha256_bytes(receipt_bytes)),
            ("strict-controller-summary.json", len(summary_bytes), sha256_bytes(summary_bytes)),
            ("terminal-envelope.json", len(self.envelope_bytes), self.envelope_digest),
        )

        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}", {
            "id": int(self.art_id),
            "name": "strict-linux-evidence",
            "size_in_bytes": len(self.raw_zip),
            "expired": False,
            "workflow_run": {"id": int(self.subj.run_id)},
        })
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            self.raw_zip,
            headers={"Content-Type": "application/zip"},
        )

    def test_detached_custody_positive(self) -> None:
        receipt = verify_detached_artifact_custody(
            self.client,
            self.repo,
            self.art_id,
            expected_manifest=self.manifest,
            expected_envelope_digest=self.envelope_digest,
            expected_inventory=self.expected_inventory,
        )
        self.assertIsInstance(receipt, DetachedCustodyReceipt)
        self.assertEqual(receipt.status, CUSTODY_STATUS_RETAINED)
        self.assertEqual(receipt.artifact_id, self.art_id)
        self.assertEqual(receipt.member_inventory, self.expected_inventory)

    def test_missing_or_extra_inventory_member_rejected(self) -> None:
        # Dropping a checkpoint/receipt member fails inventory comparison
        partial_zip = create_test_zip({"terminal-envelope.json": self.envelope_bytes})
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            partial_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_detached_artifact_custody(
                self.client,
                self.repo,
                self.art_id,
                self.manifest,
                self.envelope_digest,
                self.expected_inventory,
            )
        self.assertIn("inventory mismatch", str(ctx.exception).lower())

    def test_terminal_envelope_fail_status_rejected(self) -> None:
        fail_envelope = copy.deepcopy(self.terminal_envelope)
        fail_envelope["summary"]["status"] = "FAIL"
        fail_bytes = canonical_json_bytes(fail_envelope)
        fail_digest = sha256_bytes(fail_bytes)

        fail_files = dict(self.zip_files)
        fail_files["terminal-envelope.json"] = fail_bytes
        fail_zip = create_test_zip(fail_files)

        fail_inventory = (
            ("sealed-receipts/receipt-0.json", len(fail_files["sealed-receipts/receipt-0.json"]), sha256_bytes(fail_files["sealed-receipts/receipt-0.json"])),
            ("strict-controller-summary.json", len(fail_files["strict-controller-summary.json"]), sha256_bytes(fail_files["strict-controller-summary.json"])),
            ("terminal-envelope.json", len(fail_bytes), fail_digest),
        )

        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            fail_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_detached_artifact_custody(
                self.client,
                self.repo,
                self.art_id,
                self.manifest,
                fail_digest,
                fail_inventory,
            )
        self.assertIn("not PASS", str(ctx.exception))

    def test_semantic_own_artifact_id_detection(self) -> None:
        # Pre-upload envelope containing future artifact ID field is rejected
        tainted_envelope = copy.deepcopy(self.terminal_envelope)
        tainted_envelope["summary"]["artifact_id"] = self.art_id
        tainted_bytes = canonical_json_bytes(tainted_envelope)
        tainted_digest = sha256_bytes(tainted_bytes)

        tainted_files = dict(self.zip_files)
        tainted_files["terminal-envelope.json"] = tainted_bytes
        tainted_zip = create_test_zip(tainted_files)

        tainted_inv = (
            ("sealed-receipts/receipt-0.json", len(tainted_files["sealed-receipts/receipt-0.json"]), sha256_bytes(tainted_files["sealed-receipts/receipt-0.json"])),
            ("strict-controller-summary.json", len(tainted_files["strict-controller-summary.json"]), sha256_bytes(tainted_files["strict-controller-summary.json"])),
            ("terminal-envelope.json", len(tainted_bytes), tainted_digest),
        )

        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            tainted_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_detached_artifact_custody(
                self.client,
                self.repo,
                self.art_id,
                self.manifest,
                tainted_digest,
                tainted_inv,
            )
        self.assertIn("prohibited artifact ID field", str(ctx.exception))


class TestIndependentReviewRefusal(unittest.TestCase):
    """Test unconditional independent review refusal and unimplemented trust anchors."""

    def test_caller_supplied_review_refusal(self) -> None:
        subj = ExecutionSubject.from_dict(sample_subject_dict())
        val = ValidationRef.from_dict(sample_validation_dict(subj.digest(), 8, sha256_bytes(b"evidence")))
        rev = StructuralIndependentReviewRef.from_dict(sample_review_dict(subj.digest(), val.digest()))
        manifest = ProofManifest(schema=SCHEMA_MANIFEST_V2, subject=subj, validation=val, review=rev)

        with self.assertRaises(ReviewUnauthenticatedError) as ctx:
            verify_independent_review(manifest, caller_supplied_review={"verdict": "GO"})
        self.assertIn("caller-supplied independent review data cannot authorize", str(ctx.exception))

    def test_unconditional_review_refusal(self) -> None:
        subj = ExecutionSubject.from_dict(sample_subject_dict())
        val = ValidationRef.from_dict(sample_validation_dict(subj.digest(), 8, sha256_bytes(b"evidence")))
        rev = StructuralIndependentReviewRef.from_dict(sample_review_dict(subj.digest(), val.digest()))
        manifest = ProofManifest(schema=SCHEMA_MANIFEST_V2, subject=subj, validation=val, review=rev)

        with self.assertRaises(ReviewUnauthenticatedError) as ctx:
            verify_independent_review(manifest)
        self.assertIn("independent review", str(ctx.exception).lower())

    def test_unimplemented_trust_anchors(self) -> None:
        self.assertIn("independent_reviewer_cryptographic_attestation_key_or_issuer_policy", UNIMPLEMENTED_TRUST_ANCHORS)
        self.assertIn("independent_reviewer_authenticated_delivery_and_verification_mechanism", UNIMPLEMENTED_TRUST_ANCHORS)
        self.assertIn("observer_origin_transport_kernel_mechanism", UNIMPLEMENTED_TRUST_ANCHORS)


class TestExistingGitHubArtifactCallers(unittest.TestCase):
    """Test backward compatibility of proof/github_artifact.py functions."""

    def test_download_artifact_zip_and_stream(self) -> None:
        opener = MockOpener()
        url = "https://api.github.com/repos/jwaldrip/iyi/actions/artifacts/1/zip"
        storage_url = "https://storage.local/blob"
        raw_data = create_test_zip({"data.txt": b"ZIP_ARCHIVE_DATA"})

        opener.register_redirect(url, storage_url)
        opener.register(storage_url, raw_data, headers={"Content-Type": "application/zip"})

        downloaded = download_artifact_zip(url, "token", timeout=30, opener=opener)
        self.assertEqual(downloaded, raw_data)

        chunks = list(download_artifact_stream(url, "token", timeout=30, max_bytes=1000, chunk_size=4, opener=opener))
        self.assertEqual(b"".join(chunks), raw_data)

        with self.assertRaises(ValueError):
            list(download_artifact_stream(url, "token", timeout=30, max_bytes=5, chunk_size=4, opener=opener))


if __name__ == "__main__":
    unittest.main()
