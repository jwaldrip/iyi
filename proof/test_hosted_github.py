#!/usr/bin/env python3
"""
proof/test_hosted_github.py: Comprehensive pure mocked tests for proof/hosted_github.py.

Validates Slice B of PlanControllerRepairs (§3.1-3.3, §4 Slice B, §5):
- Bounded authenticated platform reads (repo, run, attempt, job, artifact).
- Bounded pagination over Link headers and page params; enforces max_pages ceilings.
- Storage redirect discipline: token is stripped on redirect, never sent to storage.
- Verification of subject-bound validation provenance and evidence member integrity.
- Authenticated execution context readback resolving concrete job ID, runner identity, and timestamps.
- Personal approval verification using injected trusted policy and exact manifest digest.
- Strict refusal of caller-supplied local approvals JSON or review JSON.
- Detached artifact custody readback by exact immutable artifact ID.
- Invariant enforcement: No artifact contains its own future artifact ID.
- Unconditional independent review refusal.
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
    REDIRECT_CODES,
    USER_AGENT,
    download_artifact_stream,
    download_artifact_zip,
)
from proof.hosted_contracts import (
    AUTH_COMMENT_PREFIX,
    SCHEMA_MANIFEST_V2,
    ContractError,
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
    build_production_approval_policy,
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
        resp.code = status
        resp.status = status
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
        "run_id": "888123",
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

        # Assert Authorization header was sent to API host
        self.assertEqual(len(opener.recorded_requests), 1)
        req = opener.recorded_requests[0]
        self.assertEqual(req["headers"]["Authorization"], "Bearer valid-secret-token")
        self.assertEqual(req["headers"]["Accept"], "application/vnd.github+json")
        self.assertEqual(req["headers"]["User-Agent"], DEFAULT_USER_AGENT)

        # Assert token is NOT retained in digests
        digests = client.get_retained_response_digests()
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests[0][0], "repos/jwaldrip/iyi")
        self.assertNotIn("valid-secret-token", str(digests))

        # Security check: attempt to make request to non-API host raises refusal
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            client._request("GET", "https://evil.attacker.com/steal")
        self.assertIn("Security violation", str(ctx.exception))

    def test_bounded_response_limit(self) -> None:
        opener = MockOpener()
        large_payload = {"data": "x" * 2000}
        opener.register("https://api.github.com/large", large_payload)
        # Limit client to 500 bytes
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

    def test_pagination_with_link_headers(self) -> None:
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

    def test_pagination_max_pages_ceiling(self) -> None:
        opener = MockOpener()
        # Create endless link loop
        url1 = "https://api.github.com/infinite?page=1&per_page=1"
        url2 = "https://api.github.com/infinite?page=2&per_page=1"
        opener.register(url1, [{"id": 1}], headers={"Link": f'<{url2}>; rel="next"'})
        opener.register(url2, [{"id": 2}], headers={"Link": f'<{url1}>; rel="next"'})

        client = HostedGitHubClient(token="token", opener=opener)
        with self.assertRaises(ResponseBudgetExceededError) as ctx:
            client.get_paginated("infinite", params={"page": 1, "per_page": 1}, max_pages=3)
        self.assertIn("Pagination limit exceeded", str(ctx.exception))

    def test_redirect_strips_token_discipline(self) -> None:
        opener = MockOpener()
        api_art_url = "https://api.github.com/repos/jwaldrip/iyi/actions/artifacts/123/zip"
        storage_url = "https://pipelines.actions.githubusercontent.com/signed-blob-12345"

        test_data = b"ZIP_ARCHIVE_DATA_SAMPLE"
        opener.register_redirect(api_art_url, storage_url)
        opener.register(storage_url, test_data, headers={"Content-Type": "application/zip"})

        client = HostedGitHubClient(token="secret-gh-token", opener=opener)
        downloaded = client.download_artifact_zip(api_art_url)
        self.assertEqual(downloaded, test_data)

        # Inspect requests:
        # First request to api_art_url MUST have Bearer token
        # Second request to storage_url MUST NOT have Bearer token
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
        self.evidence_bytes = b'{"status": "PASS", "test_count": 144}'
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
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
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
                }
            ]
        })
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}", {
            "id": int(self.val_art_id),
            "name": "validation-evidence",
            "size_in_bytes": len(self.artifact_zip),
            "expired": False,
            "digest": self.artifact_sha256,
            "workflow_run": {"id": int(self.val_run_id)},
            "archive_download_url": f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
        })
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            self.artifact_zip,
            headers={"Content-Type": "application/zip"},
        )

    def test_validation_provenance_positive(self) -> None:
        receipt = verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIsInstance(receipt, ValidationProvenanceReceipt)
        self.assertEqual(receipt.subject_digest, self.subject.digest())
        self.assertEqual(receipt.validation_ref_digest, self.validation_ref.digest())
        self.assertEqual(receipt.evidence_member_size, self.evidence_size)
        self.assertEqual(receipt.evidence_member_sha256, self.evidence_sha256)
        self.assertEqual(receipt.evidence_member_name, "validation_summary.json")

    def test_validation_ref_mismatch_with_subject(self) -> None:
        # Alter subject C sha
        alt_subj_dict = sample_subject_dict()
        alt_subj_dict["c_sha"] = "0" * 40
        alt_subject = ExecutionSubject.from_dict(alt_subj_dict)
        with self.assertRaises(ValidationReferenceMismatch):
            verify_validation_provenance(self.client, self.validation_ref, alt_subject)

    def test_validation_run_incomplete_or_failed(self) -> None:
        # Status in_progress
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "in_progress",
            "conclusion": None,
            "path": ".github/workflows/pr147-linux-strict.yml",
            "head_sha": self.subject.c_sha,
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("status", str(ctx.exception))

        # Conclusion failure
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
            "path": ".github/workflows/pr147-linux-strict.yml",
            "head_sha": self.subject.c_sha,
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("conclusion", str(ctx.exception))

    def test_validation_run_workflow_or_head_sha_mismatch(self) -> None:
        # Wrong workflow path
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/unrelated.yml",
            "head_sha": self.subject.c_sha,
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("workflow path mismatch", str(ctx.exception))

        # Wrong head_sha
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}", {
            "id": int(self.val_run_id),
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/pr147-linux-strict.yml",
            "head_sha": "0" * 40,
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("head_sha mismatch", str(ctx.exception))

    def test_validation_job_missing_or_failed(self) -> None:
        # Missing job ID
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}/attempts/1/jobs", {
            "jobs": [{"id": 111111, "name": "other-job", "conclusion": "success"}]
        })
        with self.assertRaises(MissingRecordError):
            verify_validation_provenance(self.client, self.validation_ref, self.subject)

        # Job conclusion failure
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.val_run_id}/attempts/1/jobs", {
            "jobs": [{"id": int(self.val_job_id), "name": "validation-proofs", "conclusion": "failure"}]
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("conclusion", str(ctx.exception))

    def test_validation_artifact_expired_or_run_mismatch(self) -> None:
        # Expired
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}", {
            "id": int(self.val_art_id),
            "name": "validation-evidence",
            "expired": True,
            "workflow_run": {"id": int(self.val_run_id)},
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("expired", str(ctx.exception))

        # Workflow run mismatch
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}", {
            "id": int(self.val_art_id),
            "name": "validation-evidence",
            "expired": False,
            "workflow_run": {"id": 99999999},
        })
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("run ID mismatch", str(ctx.exception))

    def test_evidence_member_tampered_or_missing(self) -> None:
        # Tampered content in zip
        bad_zip = create_test_zip({"validation_summary.json": b"altered content"})
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            bad_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError):
            verify_validation_provenance(self.client, self.validation_ref, self.subject)

    def test_zip_duplicate_member_names_rejected(self) -> None:
        # Create zip with duplicate members
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("member.txt", b"one")
            zf.writestr("member.txt", b"two")
        dup_zip = buf.getvalue()

        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            dup_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("Duplicate member", str(ctx.exception))

    def test_zip_path_traversal_rejected(self) -> None:
        # Create zip with traversal
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../escape.json", self.evidence_bytes)
        trav_zip = buf.getvalue()

        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.val_art_id}/zip",
            trav_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_validation_provenance(self.client, self.validation_ref, self.subject)
        self.assertIn("traversal", str(ctx.exception))


class TestExecutionContextReadback(unittest.TestCase):
    """Test authenticated ExecutionContext platform readback and validation."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        # Subject, ValidationRef, ReviewRef, Manifest
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

        # Mock run and jobs
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}", {
            "id": int(self.run_id),
            "run_attempt": self.run_attempt,
            "path": self.subj.workflow_path,
            "head_sha": self.subj.c_sha,
        })
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/attempts/1/jobs", {
            "jobs": [
                {
                    "id": 128575084391,
                    "name": "strict-proof",
                    "runner_name": "hosted-linux-runner-42",
                    "runner_id": 42,
                    "started_at": "2026-11-09T08:30:00Z",
                    "status": "in_progress",
                }
            ]
        })

    def test_execution_context_readback_by_logical_key(self) -> None:
        ctx = read_execution_context(self.client, self.manifest)
        self.assertIsInstance(ctx, ExecutionContext)
        self.assertEqual(ctx.manifest_digest, self.manifest.digest())
        self.assertEqual(ctx.subject_digest, self.subj.digest())
        self.assertEqual(ctx.job_id, "128575084391")
        self.assertEqual(ctx.runner_identity, "hosted-linux-runner-42")
        self.assertEqual(ctx.job_started_at_iso, "2026-11-09T08:30:00Z")
        self.assertGreater(ctx.job_started_at_epoch, 0.0)

    def test_execution_context_readback_by_concrete_job_id(self) -> None:
        ctx = read_execution_context(self.client, self.manifest, concrete_job_id="128575084391")
        self.assertEqual(ctx.job_id, "128575084391")

    def test_concrete_job_name_mismatch(self) -> None:
        # Job ID exists but its name does not match job_key
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/attempts/1/jobs", {
            "jobs": [
                {
                    "id": 128575084391,
                    "name": "wrong-job-name",
                    "runner_name": "runner-1",
                    "started_at": "2026-11-09T08:30:00Z",
                }
            ]
        })
        with self.assertRaises(ReferenceIntegrityError):
            read_execution_context(self.client, self.manifest, concrete_job_id="128575084391")

    def test_ambiguous_jobs_matching_logical_key(self) -> None:
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/attempts/1/jobs", {
            "jobs": [
                {"id": 101, "name": "strict-proof", "runner_name": "r1", "started_at": "2026-11-09T08:30:00Z"},
                {"id": 102, "name": "strict-proof", "runner_name": "r2", "started_at": "2026-11-09T08:31:00Z"},
            ]
        })
        with self.assertRaises(AmbiguousMatchError):
            read_execution_context(self.client, self.manifest)

    def test_missing_runner_identity(self) -> None:
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/attempts/1/jobs", {
            "jobs": [
                {"id": 128575084391, "name": "strict-proof", "runner_name": "", "started_at": "2026-11-09T08:30:00Z"}
            ]
        })
        with self.assertRaises(GitHubPlatformRefusal) as c:
            read_execution_context(self.client, self.manifest)
        self.assertIn("runner identity", str(c.exception))


class TestPersonalApproval(unittest.TestCase):
    """Test personal approval verification using injected policy and manifest digest."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        # Subject, Manifest
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
        self.policy = build_production_approval_policy()

        # Mock environment
        self.opener.register(f"https://api.github.com/repos/{self.repo}/environments/{self.policy.environment_name}", {
            "id": int(self.policy.environment_id),
            "name": self.policy.environment_name,
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
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

        # Mock approvals endpoint
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
        self.assertEqual(receipt.reviewer_id, self.policy.reviewer_id)
        self.assertEqual(receipt.environment_id, self.policy.environment_id)
        self.assertEqual(receipt.comment, self.expected_comment)

    def test_caller_supplied_approvals_refusal(self) -> None:
        with self.assertRaises(GitHubPlatformRefusal) as ctx:
            verify_personal_approval(
                self.client,
                self.manifest,
                self.policy,
                caller_supplied_approvals=[{"fake": "approval"}],
            )
        self.assertIn("caller-supplied local approvals JSON cannot authorize", str(ctx.exception))

    def test_wrong_reviewer_id_or_login(self) -> None:
        bad_approval = copy.deepcopy(self.valid_approval)
        bad_approval["user"]["id"] = 999999
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [bad_approval],
        )
        with self.assertRaises(GitHubPlatformRefusal):
            verify_personal_approval(self.client, self.manifest, self.policy)

    def test_wrong_comment_or_digest(self) -> None:
        bad_approval = copy.deepcopy(self.valid_approval)
        bad_approval["comment"] = f"{AUTH_COMMENT_PREFIX}{'0' * 64}"
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [bad_approval],
        )
        with self.assertRaises(GitHubPlatformRefusal):
            verify_personal_approval(self.client, self.manifest, self.policy)

    def test_approval_state_not_approved(self) -> None:
        bad_approval = copy.deepcopy(self.valid_approval)
        bad_approval["state"] = "pending"
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [bad_approval],
        )
        with self.assertRaises(GitHubPlatformRefusal):
            verify_personal_approval(self.client, self.manifest, self.policy)

    def test_ambiguous_multiple_matching_approvals(self) -> None:
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/runs/{self.run_id}/approvals",
            [self.valid_approval, self.valid_approval],
        )
        with self.assertRaises(AmbiguousMatchError):
            verify_personal_approval(self.client, self.manifest, self.policy)

    def test_environment_policy_violations(self) -> None:
        # can_admins_bypass is True
        self.opener.register(f"https://api.github.com/repos/{self.repo}/environments/{self.policy.environment_name}", {
            "id": int(self.policy.environment_id),
            "name": self.policy.environment_name,
            "can_admins_bypass": True,
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
        self.assertIn("can_admins_bypass", str(ctx.exception))


class TestDetachedArtifactCustody(unittest.TestCase):
    """Test detached custody readback, member inventory, and envelope binding."""

    def setUp(self) -> None:
        self.opener = MockOpener()
        self.client = HostedGitHubClient(token="token", opener=self.opener)

        # Subject, Manifest
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

        # Terminal envelope
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

        # Evidence files in zip
        self.zip_files = {
            "strict-controller-summary.json": canonical_json_bytes({"status": "PASS"}),
            "terminal-envelope.json": self.envelope_bytes,
            "sealed-receipts/receipt-0.json": b'{"unit": 0, "status": "sealed"}',
        }
        self.raw_zip = create_test_zip(self.zip_files)

        # Register artifact metadata and download
        self.opener.register(f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}", {
            "id": int(self.art_id),
            "name": "strict-linux-evidence",
            "size_in_bytes": len(self.raw_zip),
            "expired": False,
            "workflow_run": {"id": int(self.subj.run_id)},
            "archive_download_url": f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
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
        )
        self.assertIsInstance(receipt, DetachedCustodyReceipt)
        self.assertEqual(receipt.status, CUSTODY_STATUS_RETAINED)
        self.assertEqual(receipt.artifact_id, self.art_id)
        self.assertEqual(receipt.manifest_digest, self.manifest.digest())
        self.assertEqual(receipt.terminal_envelope_digest, self.envelope_digest)
        self.assertEqual(len(receipt.member_inventory), 3)

    def test_artifact_contains_its_own_id_rejected(self) -> None:
        # Security violation: artifact contains its own future artifact_id
        tainted_envelope = copy.deepcopy(self.terminal_envelope)
        tainted_envelope["summary"]["future_artifact_id"] = self.art_id
        tainted_envelope_bytes = canonical_json_bytes(tainted_envelope)

        tainted_zip_files = dict(self.zip_files)
        tainted_zip_files["terminal-envelope.json"] = tainted_envelope_bytes
        tainted_zip = create_test_zip(tainted_zip_files)

        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            tainted_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_detached_artifact_custody(self.client, self.repo, self.art_id, self.manifest)
        self.assertIn("contains its own future artifact_id", str(ctx.exception))

    def test_terminal_envelope_missing(self) -> None:
        missing_env_zip = create_test_zip({"other.txt": b"content"})
        self.opener.register(
            f"https://api.github.com/repos/{self.repo}/actions/artifacts/{self.art_id}/zip",
            missing_env_zip,
            headers={"Content-Type": "application/zip"},
        )
        with self.assertRaises(ArtifactCustodyError) as ctx:
            verify_detached_artifact_custody(self.client, self.repo, self.art_id, self.manifest)
        self.assertIn("terminal-envelope.json missing", str(ctx.exception))

    def test_terminal_envelope_manifest_digest_mismatch(self) -> None:
        alt_subj = ExecutionSubject.from_dict(sample_subject_dict())
        alt_val = ValidationRef.from_dict(sample_validation_dict(alt_subj.digest(), 8, sha256_bytes(b"evidence")))
        alt_rev = StructuralIndependentReviewRef.from_dict(sample_review_dict(alt_subj.digest(), alt_val.digest()))
        alt_manifest = ProofManifest(schema=SCHEMA_MANIFEST_V2, subject=alt_subj, validation=alt_val, review=alt_rev)

        with self.assertRaises(ReferenceIntegrityError):
            verify_detached_artifact_custody(self.client, self.repo, self.art_id, expected_manifest=alt_manifest)


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

        with self.assertRaises(StrictHaltRefusal) as ctx:
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
        url = "https://api.github.com/artifact/1/zip"
        storage_url = "https://storage.local/blob"
        raw_data = b"ZIP_ARCHIVE_DATA"

        opener.register_redirect(url, storage_url)
        opener.register(storage_url, raw_data, headers={"Content-Type": "application/zip"})

        # Backward compatible download_artifact_zip
        downloaded = download_artifact_zip(url, "token", timeout=30, opener=opener)
        self.assertEqual(downloaded, raw_data)

        # Streaming interface with max_bytes
        chunks = list(download_artifact_stream(url, "token", timeout=30, max_bytes=1000, chunk_size=4, opener=opener))
        self.assertEqual(b"".join(chunks), raw_data)

        # Exceeding max_bytes raises ValueError
        with self.assertRaises(ValueError):
            list(download_artifact_stream(url, "token", timeout=30, max_bytes=5, chunk_size=4, opener=opener))


if __name__ == "__main__":
    unittest.main()
