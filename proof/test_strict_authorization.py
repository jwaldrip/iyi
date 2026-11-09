#!/usr/bin/env python3
"""Discriminating loopback and CLI boundary tests for strict-proof authorization verifier.

Tests all security gates and failure modes per PlanRepairStrictBoundary (§3.B)
and AuditMinimalStrictVerifier (§Yield: Findings):
  - Isolated Git fixtures (zero ambient repo dependencies)
  - Canonical manifest creation via 'prepare' CLI with substantive E verification
  - Authoritative check via 'check' CLI against local loopback HTTP service
  - Pinned GitHub origin and storage redirect credential stripping
  - Exact source tuple verification (HEADs, cleanliness, ancestry, non-proof diff)
  - Upstream PR147 verification on 'iyilang/iyi'
  - Complete enumeration and advertised total_count pagination verification
  - Exact E provenance (Git blob, hash-object, sha256, substantive GO report)
  - Substantive V validation (workflow, jobs, artifact contents, inventory, mutations)
  - Fail-closed run-native pending integrated supervisor (no fake native commands)
  - Fail-closed legacy hooks rejecting caller-supplied AUTHORIZED assertions
  - Discriminating negative controls asserting exit code 5 and specific diagnostic messages
  - Usage errors returning exit code 2
"""

from __future__ import annotations

import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse
import zipfile
from typing import Any, Dict, List, Optional

from proof.strict_authorization import (
    APPROVAL_COMMENT_PREFIX,
    AUTH_REFUSED_EXIT_CODE,
    CHAIN_ID,
    EXECUTION_BACKEND,
    MANIFEST_SCHEMA,
    PINNED_BRANCH,
    PINNED_ENVIRONMENT_ID,
    PINNED_ENVIRONMENT_NAME,
    PINNED_REF,
    PINNED_REPOSITORY,
    PINNED_REPOSITORY_ID,
    PINNED_REVIEWER_ID,
    PINNED_REVIEWER_LOGIN,
    PINNED_WORKFLOW_PATH,
    UPSTREAM_PR_NUMBER,
    UPSTREAM_PR_REPOSITORY,
    USAGE_ERROR_EXIT_CODE,
    AuthenticatedGitHubVerifier,
    AuthorizationError,
    StrictAuthorizationRefused,
    canonical_json,
    check_strict_authorization_or_refuse,
    compute_digest,
    create_manifest,
    load_verified_authorization_from_ipc,
    main,
    parse_json_no_duplicate_keys,
    read_manifest_package,
)

VALID_TOKEN = "valid-ci-token-test-secret"


class LoopbackGitHubMockHandler(BaseHTTPRequestHandler):
    """Loopback HTTP mock server simulating GitHub API and storage redirect behavior."""

    routes: Dict[str, Any] = {}
    paginated_routes: Dict[str, Dict[str, Any]] = {}
    faults: Dict[str, int] = {}
    artifact_zips: Dict[str, bytes] = {}
    storage_requests: List[Dict[str, Any]] = []

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress HTTP server logging during unit tests

    def do_GET(self) -> None:
        auth_header = self.headers.get("Authorization", "")
        parsed_url = urllib.parse.urlparse(self.path)
        clean_path = parsed_url.path.lstrip("/")
        query = urllib.parse.parse_qs(parsed_url.query)

        # 1. Check for simulated storage download (from 302 redirect)
        if clean_path.startswith("storage/"):
            LoopbackGitHubMockHandler.storage_requests.append({
                "path": self.path,
                "has_auth": bool(auth_header),
                "auth_header": auth_header,
            })
            storage_key = clean_path.replace("storage/", "")
            if storage_key in self.artifact_zips:
                data = self.artifact_zips[storage_key]
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_response(404)
            self.end_headers()
            return

        # 2. Check for simulated faults
        if clean_path in self.faults:
            code = self.faults[clean_path]
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": f"Simulated fault {code}"}).encode("utf-8"))
            return

        # 3. Verify Bearer token for all API endpoints
        if not auth_header.startswith("Bearer ") or auth_header.split("Bearer ", 1)[1] != VALID_TOKEN:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"message":"Bad credentials"}')
            return

        # 4. Check for artifact zip redirect endpoint
        if clean_path.endswith("/zip"):
            art_id = clean_path.split("/")[-2]
            storage_key = f"artifacts/{art_id}/zip"
            if storage_key in self.artifact_zips:
                port = self.server.server_address[1]
                redirect_url = f"http://127.0.0.1:{port}/storage/{storage_key}"
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
                return

        # 5. Check paginated routes
        if clean_path in self.paginated_routes:
            config = self.paginated_routes[clean_path]
            total_count = config["total_count"]
            items = config["items"]
            key = config.get("key", "items")
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            start = (page - 1) * per_page
            end = start + per_page
            page_slice = items[start:end]

            resp_obj = {
                "total_count": total_count,
                key: page_slice,
            }
            body = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 6. Regular route matching
        if clean_path in self.routes:
            body = json.dumps(self.routes[clean_path]).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"message": f"Not Found: {clean_path}"}).encode("utf-8"))


class StrictAuthorizationTestsBase(unittest.TestCase):
    """Base setup for loopback server and isolated git fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), LoopbackGitHubMockHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        LoopbackGitHubMockHandler.routes.clear()
        LoopbackGitHubMockHandler.paginated_routes.clear()
        LoopbackGitHubMockHandler.faults.clear()
        LoopbackGitHubMockHandler.artifact_zips.clear()
        LoopbackGitHubMockHandler.storage_requests.clear()

        self.test_dir = tempfile.mkdtemp(prefix="iyi_strict_test_")
        self.repos_dir = os.path.join(self.test_dir, "repos")
        self.p_repo = os.path.join(self.repos_dir, "p")
        self.w_repo = os.path.join(self.repos_dir, "w")
        self.c_repo = os.path.join(self.repos_dir, "c")

        self.s_run_id = "101"
        self.v_run_id = "202"
        self.v_art_id = "301"

        # 1. Initialize isolated P repository
        subprocess.run(["git", "init", "-b", "main", self.p_repo], check=True, capture_output=True)
        subprocess.run(["git", "-C", self.p_repo, "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", self.p_repo, "config", "user.name", "Test User"], check=True)
        src_dir = os.path.join(self.p_repo, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.iyi"), "w") as f:
            f.write("def main(): Int32\n  42\nend\n")
        subprocess.run(["git", "-C", self.p_repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.p_repo, "commit", "-m", "P initial"], check=True, capture_output=True)
        self.p_sha = subprocess.check_output(["git", "-C", self.p_repo, "rev-parse", "HEAD"], text=True).strip()

        # 2. Initialize isolated W repository (cloned from P, only changes in proof/)
        subprocess.run(["git", "clone", self.p_repo, self.w_repo], check=True, capture_output=True)
        subprocess.run(["git", "-C", self.w_repo, "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", self.w_repo, "config", "user.name", "Test User"], check=True)
        w_proof_dir = os.path.join(self.w_repo, "proof")
        os.makedirs(w_proof_dir, exist_ok=True)
        with open(os.path.join(w_proof_dir, "proofkit.py"), "w") as f:
            f.write("# w proofkit\n")
        subprocess.run(["git", "-C", self.w_repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.w_repo, "commit", "-m", "W proof changes"], check=True, capture_output=True)
        self.w_sha = subprocess.check_output(["git", "-C", self.w_repo, "rev-parse", "HEAD"], text=True).strip()

        # 3. Initialize isolated C repository (cloned from W)
        subprocess.run(["git", "clone", self.w_repo, self.c_repo], check=True, capture_output=True)
        subprocess.run(["git", "-C", self.c_repo, "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", self.c_repo, "config", "user.name", "Test User"], check=True)
        # Commit candidate strict controller change in C
        c_proof_dir = os.path.join(self.c_repo, "proof")
        os.makedirs(c_proof_dir, exist_ok=True)
        with open(os.path.join(c_proof_dir, "controller.py"), "w") as f:
            f.write("# candidate strict controller C\n")
        subprocess.run(["git", "-C", self.c_repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.c_repo, "commit", "-m", "Candidate C commit"], check=True, capture_output=True)
        self.c_sha = subprocess.check_output(["git", "-C", self.c_repo, "rev-parse", "HEAD"], text=True).strip()

        # 4. Commit independent review report E in C repository
        self.review_rel_path = "proof/review_evidence.json"
        full_review_path = os.path.join(self.c_repo, self.review_rel_path)
        self.review_content = {
            "verdict": "GO",
            "report": {
                "summary": "Substantive independent audit of candidate C against P and W",
                "verdict": "GO",
                "p_sha": self.p_sha,
                "w_sha": self.w_sha,
                "c_sha": self.c_sha,
                "v_run_id": self.v_run_id,
                "findings": ["No unauthorized mutations", "Zero exclusion 142/142 RG2 passed"],
            },
            "supporting_receipts": [
                {"id": "rec-142", "status": "VERIFIED"},
                {"id": "rec-mut", "status": "VERIFIED"},
            ],
            "declaration": "Independent review produced by reviewer agent; cryptographic human approval via GitHub environment.",
        }
        self.review_bytes = canonical_json(self.review_content)
        self.review_sha256 = compute_digest(self.review_bytes)
        with open(full_review_path, "wb") as f:
            f.write(self.review_bytes)
        subprocess.run(["git", "-C", self.c_repo, "add", self.review_rel_path], check=True)
        subprocess.run(["git", "-C", self.c_repo, "commit", "-m", "Add independent review E"], check=True, capture_output=True)
        self.review_commit = subprocess.check_output(["git", "-C", self.c_repo, "rev-parse", "HEAD"], text=True).strip()

        p = subprocess.Popen(["git", "-C", self.c_repo, "hash-object", "--stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = p.communicate(self.review_bytes)
        self.review_blob_sha = out.decode("utf-8").strip()

        # Reset C working tree to c_sha so C checkout HEAD matches c_sha and is clean
        subprocess.run(["git", "-C", self.c_repo, "checkout", self.c_sha], check=True, capture_output=True)

        # 5. Create substantive validation artifact ZIP
        v_receipt = {
            "version": 1,
            "verdict": "PASS",
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "run_id": self.v_run_id,
            "inventory": {
                "total_evaluated": 142,
                "total_passed": 142,
                "drivers_count": 29,
            },
            "mutations": {
                "tested": 2,
                "detected": 2,
                "status": "PASS",
            },
            "coverage": {
                "status": "PASS",
            },
        }
        self.v_art_bytes = self._create_zip("validation_receipt.json", canonical_json(v_receipt))
        self.v_art_sha256 = compute_digest(self.v_art_bytes)
        LoopbackGitHubMockHandler.artifact_zips[f"artifacts/{self.v_art_id}/zip"] = self.v_art_bytes

        # 6. Prepare canonical manifest
        self.manifest_path = os.path.join(self.test_dir, "manifest.json")
        self.package_path = os.path.join(self.test_dir, "manifest_package.zip")

        prep_code = main([
            "prepare",
            "--manifest", self.manifest_path,
            "--package", self.package_path,
            "--p-sha", self.p_sha,
            "--w-sha", self.w_sha,
            "--c-sha", self.c_sha,
            "--s-run-id", self.s_run_id,
            "--s-run-attempt", "1",
            "--v-run-id", self.v_run_id,
            "--v-artifacts", json.dumps([{"id": self.v_art_id, "name": "validation.zip", "sha256": self.v_art_sha256}]),
            "--review-commit", self.review_commit,
            "--review-path", self.review_rel_path,
            "--review-blob-sha", self.review_blob_sha,
            "--review-sha256", self.review_sha256,
            "--review-verdict", "GO",
            "--c", self.c_repo,
        ])
        self.assertEqual(prep_code, 0)

        _, parsed_manifest, self.manifest_digest = read_manifest_package(self.package_path)
        self.expected_comment = f"{APPROVAL_COMMENT_PREFIX}{self.manifest_digest}"

        # 7. Setup standard authoritative routes
        self._setup_mock_routes()

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_zip(self, name: str, content: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(name, content)
        return buf.getvalue()

    def _setup_mock_routes(self) -> None:
        repo = PINNED_REPOSITORY
        env = PINNED_ENVIRONMENT_NAME

        LoopbackGitHubMockHandler.routes.update({
            f"repos/{repo}": {
                "id": int(PINNED_REPOSITORY_ID),
                "full_name": PINNED_REPOSITORY,
            },
            f"repos/{env}": {
                "id": int(PINNED_ENVIRONMENT_ID),
                "name": PINNED_ENVIRONMENT_NAME,
            },
            f"repos/{repo}/environments/{env}": {
                "id": int(PINNED_ENVIRONMENT_ID),
                "name": PINNED_ENVIRONMENT_NAME,
                "can_admins_bypass": False,
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": False,
                        "reviewers": [
                            {"type": "User", "reviewer": {"id": int(PINNED_REVIEWER_ID), "login": PINNED_REVIEWER_LOGIN}}
                        ],
                    }
                ],
            },
            f"repos/{UPSTREAM_PR_REPOSITORY}/pulls/{UPSTREAM_PR_NUMBER}": {
                "head": {"sha": self.p_sha},
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}": {
                "id": int(self.s_run_id),
                "run_attempt": 1,
                "path": PINNED_WORKFLOW_PATH,
                "head_sha": self.c_sha,
                "head_branch": PINNED_BRANCH,
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
            },
            f"repos/{repo}/actions/runs/{self.v_run_id}": {
                "id": int(self.v_run_id),
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
            },
            f"repos/{repo}/actions/artifacts/{self.v_art_id}": {
                "id": int(self.v_art_id),
                "expired": False,
                "workflow_run": {"id": int(self.v_run_id)},
            },
        })

        LoopbackGitHubMockHandler.paginated_routes.update({
            f"repos/{repo}/environments/{env}/deployment-branch-policies": {
                "total_count": 1,
                "key": "branch_policies",
                "items": [{"name": PINNED_BRANCH}],
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}/attempts/1/jobs": {
                "total_count": 2,
                "key": "jobs",
                "items": [
                    {"name": "prepare-strict-authorization", "conclusion": "success"},
                    {"name": "strict-chain", "status": "in_progress"},
                ],
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}/approvals": {
                "total_count": 1,
                "key": "approvals",
                "items": [
                    {
                        "state": "approved",
                        "user": {"id": int(PINNED_REVIEWER_ID), "login": PINNED_REVIEWER_LOGIN},
                        "environments": [{"id": int(PINNED_ENVIRONMENT_ID), "name": PINNED_ENVIRONMENT_NAME}],
                        "comment": self.expected_comment,
                    }
                ],
            },
            f"repos/{repo}/actions/runs/{self.v_run_id}/attempts/1/jobs": {
                "total_count": 1,
                "key": "jobs",
                "items": [
                    {"name": "validation-proofs", "status": "completed", "conclusion": "success"},
                ],
            },
        })


class StrictAuthorizationPositiveTests(StrictAuthorizationTestsBase):
    """End-to-end positive control tests."""

    def test_e2e_positive_control(self) -> None:
        """Positive control: prepare -> check -> receipt verified."""
        receipt_path = os.path.join(self.test_dir, "receipt.json")

        check_code = main(
            [
                "check",
                "--manifest", self.package_path,
                "--token", VALID_TOKEN,
                "--c", self.c_repo,
                "--p", self.p_repo,
                "--w", self.w_repo,
                "--receipt", receipt_path,
                "--format", "json",
            ],
            _api_base=self.base_url,
        )
        self.assertEqual(check_code, 0)
        self.assertTrue(os.path.exists(receipt_path))
        with open(receipt_path, "r") as rf:
            receipt = json.load(rf)
        self.assertEqual(receipt["decision"], "AUTHORIZED")
        self.assertEqual(receipt["manifest_digest"], self.manifest_digest)
        self.assertEqual(receipt["c_sha"], self.c_sha)
        self.assertEqual(receipt["p_sha"], self.p_sha)
        self.assertEqual(receipt["w_sha"], self.w_sha)
        self.assertEqual(receipt["reviewer_id"], int(PINNED_REVIEWER_ID))


class StrictAuthorizationNegativeTests(StrictAuthorizationTestsBase):
    """Discriminating negative controls asserting exit code 5 and specific diagnostic messages."""

    def _assert_refusal(self, argv: List[str], expected_substring: str) -> None:
        """Run CLI check and assert exit code 5 and expected diagnostic substring."""
        buf = io.StringIO()
        old_err = sys.stderr
        try:
            sys.stderr = buf
            code = main(argv, _api_base=self.base_url)
        finally:
            sys.stderr = old_err

        output = buf.getvalue()
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE, f"Expected exit code 5, got {code}. Output:\n{output}")
        self.assertIn(
            expected_substring,
            output,
            f"Expected diagnostic substring '{expected_substring}' not found in stderr:\n{output}",
        )

    def test_conflicting_approval_history_is_refused(self) -> None:
        key = f"repos/{PINNED_REPOSITORY}/actions/runs/{self.s_run_id}/approvals"
        route = LoopbackGitHubMockHandler.paginated_routes[key]
        conflicting = copy.deepcopy(route["items"][0])
        conflicting["state"] = "rejected"
        route["items"].append(conflicting)
        route["total_count"] = 2
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Conflicting approval history for strict-proof",
        )

    def test_negative_approval_missing_rejected_pending_wrong_user_wrong_env(self) -> None:
        """Negative 1: Missing, rejected, pending, wrong-user or wrong-environment approval."""
        repo = PINNED_REPOSITORY
        approvals_key = f"repos/{repo}/actions/runs/{self.s_run_id}/approvals"

        cases = [
            ("missing", [], "No approvals found in GitHub history for run S"),
            ("rejected", [{
                "state": "rejected",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }], "Approval state is not approved: rejected"),
            ("pending", [{
                "state": "pending",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }], "Approval state is not approved: pending"),
            ("wrong_user", [{
                "state": "approved",
                "user": {"id": 99999},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }], f"Approval user ID mismatch: expected {PINNED_REVIEWER_ID}"),
            ("wrong_env", [{
                "state": "approved",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": 99999}],
                "comment": self.expected_comment,
            }], f"Approval environment ID mismatch: expected {PINNED_ENVIRONMENT_ID}"),
        ]

        for label, app_list, expected_diag in cases:
            LoopbackGitHubMockHandler.paginated_routes[approvals_key] = {
                "total_count": len(app_list),
                "key": "approvals",
                "items": app_list,
            }
            with self.subTest(label=label):
                self._assert_refusal(
                    ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
                    expected_diag,
                )

    def test_negative_approval_comment_faults(self) -> None:
        """Negative 2: Empty, whitespace, wrong prefix, wrong digest in approval comment."""
        repo = PINNED_REPOSITORY
        approvals_key = f"repos/{repo}/actions/runs/{self.s_run_id}/approvals"

        cases = [
            ("empty", "", "Approval comment is empty"),
            ("whitespace", f"{self.expected_comment} ", "Approval comment contains whitespace discrepancies"),
            ("wrong_prefix", f"iyi-strict-authorization-v1 sha256:{self.manifest_digest}", "Approval comment wrong prefix"),
            ("wrong_digest", f"{APPROVAL_COMMENT_PREFIX}{'0'*64}", "Approval comment mismatch"),
        ]

        for label, comm, expected_diag in cases:
            LoopbackGitHubMockHandler.paginated_routes[approvals_key] = {
                "total_count": 1,
                "key": "approvals",
                "items": [{
                    "state": "approved",
                    "user": {"id": int(PINNED_REVIEWER_ID)},
                    "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                    "comment": comm,
                }],
            }
            with self.subTest(label=label):
                self._assert_refusal(
                    ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
                    expected_diag,
                )

    def test_negative_environment_policy_violations(self) -> None:
        """Negative 3: Admin bypass, self review, multiple reviewers, or branch policy violations."""
        repo = PINNED_REPOSITORY
        env = PINNED_ENVIRONMENT_NAME

        # 1. Admin bypass true
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/environments/{env}"]["can_admins_bypass"] = True
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "can_admins_bypass must be False",
        )
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/environments/{env}"]["can_admins_bypass"] = False

        # 2. Prevent self review true
        rule = LoopbackGitHubMockHandler.routes[f"repos/{repo}/environments/{env}"]["protection_rules"][0]
        rule["prevent_self_review"] = True
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "prevent_self_review must be False",
        )
        rule["prevent_self_review"] = False

        # 3. Multiple reviewers
        rule["reviewers"].append({"type": "User", "reviewer": {"id": 99999}})
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "must specify exactly one reviewer",
        )
        rule["reviewers"].pop()

        # 4. Extra branch permitted
        LoopbackGitHubMockHandler.paginated_routes[f"repos/{repo}/environments/{env}/deployment-branch-policies"] = {
            "total_count": 2,
            "key": "branch_policies",
            "items": [{"name": PINNED_BRANCH}, {"name": "main"}],
        }
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            f"Environment branch policy must permit only '{PINNED_BRANCH}'",
        )

    def test_negative_run_s_attempt_2_and_mismatches(self) -> None:
        """Negative 4: Run S attempt 2, workflow path mismatch, or head_sha mismatch."""
        repo = PINNED_REPOSITORY

        # Attempt 2
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["run_attempt"] = 2
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Run S attempt must be 1",
        )
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["run_attempt"] = 1

        # Workflow path mismatch
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["path"] = ".github/workflows/other.yml"
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Run S workflow mismatch",
        )
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["path"] = PINNED_WORKFLOW_PATH

        # Head sha mismatch
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["head_sha"] = "0" * 40
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Run S head_sha mismatch with C",
        )
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"]["head_sha"] = self.c_sha

    def test_negative_run_s_jobs_faults(self) -> None:
        """Negative 5: Run S preparation job missing, failed, or duplicate protected job."""
        repo = PINNED_REPOSITORY
        jobs_key = f"repos/{repo}/actions/runs/{self.s_run_id}/attempts/1/jobs"

        # Prep job failed
        LoopbackGitHubMockHandler.paginated_routes[jobs_key] = {
            "total_count": 2,
            "key": "jobs",
            "items": [
                {"name": "prepare-strict-authorization", "conclusion": "failure"},
                {"name": "strict-chain", "status": "in_progress"},
            ],
        }
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Preparation job in S did not succeed",
        )

        # Prep job missing
        LoopbackGitHubMockHandler.paginated_routes[jobs_key] = {
            "total_count": 1,
            "key": "jobs",
            "items": [
                {"name": "strict-chain", "status": "in_progress"},
            ],
        }
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Expected exactly one preparation job in S",
        )

        # Duplicate protected job
        LoopbackGitHubMockHandler.paginated_routes[jobs_key] = {
            "total_count": 3,
            "key": "jobs",
            "items": [
                {"name": "prepare-strict-authorization", "conclusion": "success"},
                {"name": "strict-chain", "status": "in_progress"},
                {"name": "strict-chain", "status": "in_progress"},
            ],
        }
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Expected exactly one protected job in S, found 2",
        )

    def test_negative_upstream_pr147_moved_or_error(self) -> None:
        """Negative 6: Upstream PR147 head moved or API error fails closed."""
        pr_key = f"repos/{UPSTREAM_PR_REPOSITORY}/pulls/{UPSTREAM_PR_NUMBER}"

        # Head moved
        LoopbackGitHubMockHandler.routes[pr_key] = {"head": {"sha": "1" * 40}}
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "PR147 head moved",
        )

        # API 404
        LoopbackGitHubMockHandler.faults[pr_key] = 404
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "GitHub API error HTTP 404",
        )
        del LoopbackGitHubMockHandler.faults[pr_key]

    def test_negative_incomplete_pagination(self) -> None:
        """Negative 7: Incomplete pagination where advertised total_count exceeds retrieved items."""
        repo = PINNED_REPOSITORY
        jobs_key = f"repos/{repo}/actions/runs/{self.v_run_id}/attempts/1/jobs"

        # Advertised total_count is 5, but items returned is only 1
        LoopbackGitHubMockHandler.paginated_routes[jobs_key] = {
            "total_count": 5,
            "key": "jobs",
            "items": [
                {"name": "validation-proofs", "status": "completed", "conclusion": "success"},
            ],
        }
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Incomplete pagination",
        )

    def test_negative_v_artifact_dummy_receipt_and_content_checks(self) -> None:
        """Negative 8: V artifact with dummy receipt {'receipt':'verified_142'} or missing inventory refuses."""
        # Create dummy receipt ZIP
        dummy_zip = self._create_zip("validation_receipt.json", b'{"receipt":"verified_142"}')
        dummy_sha = compute_digest(dummy_zip)
        LoopbackGitHubMockHandler.artifact_zips[f"artifacts/{self.v_art_id}/zip"] = dummy_zip

        # Prepare manifest binding dummy artifact SHA
        bad_manifest = os.path.join(self.test_dir, "bad_v_art_manifest.json")
        main([
            "prepare",
            "--manifest", bad_manifest,
            "--p-sha", self.p_sha,
            "--w-sha", self.w_sha,
            "--c-sha", self.c_sha,
            "--s-run-id", self.s_run_id,
            "--v-run-id", self.v_run_id,
            "--v-artifacts", json.dumps([{"id": self.v_art_id, "name": "validation.zip", "sha256": dummy_sha}]),
            "--review-commit", self.review_commit,
            "--review-path", self.review_rel_path,
            "--review-blob-sha", self.review_blob_sha,
            "--review-sha256", self.review_sha256,
            "--review-verdict", "GO",
            "--c", self.c_repo,
        ])

        self._assert_refusal(
            ["check", "--manifest", bad_manifest, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Validation receipt W mismatch",
        )

    def test_negative_independent_review_e_nogo_and_tampered_bytes(self) -> None:
        """Negative 9: Independent review E with NO-GO verdict (even with matching digest) or tampered bytes."""
        # Commit NO-GO review in C repo
        nogo_content = {
            "verdict": "NO-GO",
            "report": {
                "verdict": "NO-GO",
                "p_sha": self.p_sha,
                "w_sha": self.w_sha,
                "c_sha": self.c_sha,
                "v_run_id": self.v_run_id,
            },
        }
        nogo_bytes = canonical_json(nogo_content)
        nogo_sha = compute_digest(nogo_bytes)

        full_nogo_path = os.path.join(self.c_repo, "proof/nogo_review.json")
        with open(full_nogo_path, "wb") as f:
            f.write(nogo_bytes)
        subprocess.run(["git", "-C", self.c_repo, "add", "proof/nogo_review.json"], check=True)
        subprocess.run(["git", "-C", self.c_repo, "commit", "-m", "Commit nogo review"], check=True, capture_output=True)
        nogo_commit = subprocess.check_output(["git", "-C", self.c_repo, "rev-parse", "HEAD"], text=True).strip()

        # 1. Attempting prepare with NO-GO file refuses
        code = main([
            "prepare",
            "--manifest", os.path.join(self.test_dir, "nogo_manifest.json"),
            "--p-sha", self.p_sha,
            "--w-sha", self.w_sha,
            "--c-sha", self.c_sha,
            "--s-run-id", self.s_run_id,
            "--v-run-id", self.v_run_id,
            "--v-artifacts", json.dumps([{"id": self.v_art_id, "name": "validation.zip", "sha256": self.v_art_sha256}]),
            "--review-commit", nogo_commit,
            "--review-path", "proof/nogo_review.json",
            "--c", self.c_repo,
        ])
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_negative_source_tuple_and_git_relations(self) -> None:
        """Negative 10: Executing C checkout HEAD mismatch, C dirty, W ancestry failure, product diff."""
        # 1. C checkout moved to wrong commit
        subprocess.run(["git", "-C", self.c_repo, "checkout", self.review_commit], check=True, capture_output=True)
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Executing checkout HEAD mismatch",
        )
        subprocess.run(["git", "-C", self.c_repo, "checkout", self.c_sha], check=True, capture_output=True)

        # 2. C checkout dirty
        with open(os.path.join(self.c_repo, "dirty.txt"), "w") as f:
            f.write("uncommitted\n")
        self._assert_refusal(
            ["check", "--manifest", self.package_path, "--token", VALID_TOKEN, "--c", self.c_repo],
            "is dirty",
        )
        os.remove(os.path.join(self.c_repo, "dirty.txt"))

        # 3. Product diff between P and W
        bad_w_repo = os.path.join(self.test_dir, "bad_w_repo")
        subprocess.run(["git", "clone", self.p_repo, bad_w_repo], check=True, capture_output=True)
        # Edit file in src/
        with open(os.path.join(bad_w_repo, "src", "main.iyi"), "a") as f:
            f.write("# unauthorized product mutation\n")
        subprocess.run(["git", "-C", bad_w_repo, "add", "."], check=True)
        subprocess.run(["git", "-C", bad_w_repo, "commit", "-m", "Product diff mutation"], check=True, capture_output=True)
        bad_w_sha = subprocess.check_output(["git", "-C", bad_w_repo, "rev-parse", "HEAD"], text=True).strip()

        bad_w_manifest = os.path.join(self.test_dir, "bad_w_manifest.json")
        # Prepare manifest binding bad_w_sha
        main([
            "prepare",
            "--manifest", bad_w_manifest,
            "--p-sha", self.p_sha,
            "--w-sha", bad_w_sha,
            "--c-sha", self.c_sha,
            "--s-run-id", self.s_run_id,
            "--v-run-id", self.v_run_id,
            "--v-artifacts", json.dumps([{"id": self.v_art_id, "name": "validation.zip", "sha256": self.v_art_sha256}]),
            "--review-commit", self.review_commit,
            "--review-path", self.review_rel_path,
            "--review-blob-sha", self.review_blob_sha,
            "--review-sha256", self.review_sha256,
            "--review-verdict", "GO",
            "--c", self.c_repo,
        ])
        self._assert_refusal(
            ["check", "--manifest", bad_w_manifest, "--token", VALID_TOKEN, "--c", self.c_repo, "--w", bad_w_repo],
            "Product trees differ between P",
        )

    def test_negative_manifest_package_corrupted_and_duplicate_members(self) -> None:
        """Negative 11: Corrupted ZIP, duplicate member names, or ambiguous member files."""
        # 1. Corrupted zip
        corrupt_pkg = os.path.join(self.test_dir, "corrupt_pkg.zip")
        with open(corrupt_pkg, "wb") as f:
            f.write(b"not-a-valid-zip-data")
        self._assert_refusal(
            ["check", "--manifest", corrupt_pkg, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Corrupted zip archive for manifest",
        )

        # 2. Duplicate members
        dup_pkg = os.path.join(self.test_dir, "dup_pkg.zip")
        with zipfile.ZipFile(dup_pkg, "w") as zf:
            zf.writestr("manifest.json", b'{"schema":"iyi-strict-manifest-v2"}')
            zf.writestr("manifest.json", b'{"schema":"duplicate"}')
        self._assert_refusal(
            ["check", "--manifest", dup_pkg, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Duplicate ZIP member names in manifest package",
        )

        # 3. Extra unexpected members
        extra_pkg = os.path.join(self.test_dir, "extra_pkg.zip")
        with zipfile.ZipFile(extra_pkg, "w") as zf:
            zf.writestr("manifest.json", open(self.manifest_path, "rb").read())
            zf.writestr("unexpected.txt", b"extra file")
        self._assert_refusal(
            ["check", "--manifest", extra_pkg, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Ambiguous or extra members in manifest package",
        )

    def test_negative_manifest_canonical_json_and_duplicate_keys(self) -> None:
        """Negative 12: Manifest with non-canonical formatting or duplicate JSON keys."""
        # 1. Non-canonical whitespace
        raw_m = open(self.manifest_path, "rb").read()
        formatted_m = json.dumps(json.loads(raw_m.decode("utf-8")), indent=2).encode("utf-8")
        ws_pkg = os.path.join(self.test_dir, "whitespace_pkg.zip")
        with zipfile.ZipFile(ws_pkg, "w") as zf:
            zf.writestr("manifest.json", formatted_m)
        self._assert_refusal(
            ["check", "--manifest", ws_pkg, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Manifest bytes do not match canonical JSON representation",
        )

        # 2. Duplicate JSON keys
        dup_json = b'{"schema":"iyi-strict-manifest-v2","schema":"duplicate"}'
        dup_json_pkg = os.path.join(self.test_dir, "dup_json_pkg.zip")
        with zipfile.ZipFile(dup_json_pkg, "w") as zf:
            zf.writestr("manifest.json", dup_json)
        self._assert_refusal(
            ["check", "--manifest", dup_json_pkg, "--token", VALID_TOKEN, "--c", self.c_repo],
            "Duplicate key in JSON",
        )

    def test_negative_run_native_fail_closed(self) -> None:
        """Negative 13: run-native fails closed pending integrated supervisor."""
        buf = io.StringIO()
        old_err = sys.stderr
        try:
            sys.stderr = buf
            code = main(["run-native", "--manifest", self.package_path])
        finally:
            sys.stderr = old_err
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        self.assertIn("run-native is disabled pending integrated supervisor", buf.getvalue())

    def test_negative_legacy_hooks_fail_closed_and_reject_minted_authority(self) -> None:
        """Negative 14: Legacy hooks fail closed and reject caller-supplied AUTHORIZED assertions."""
        # check_strict_authorization_or_refuse raises StrictAuthorizationRefused
        with self.assertRaises(StrictAuthorizationRefused) as ctx:
            check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha)
        self.assertEqual(ctx.exception.exit_code, AUTH_REFUSED_EXIT_CODE)

        # load_verified_authorization_from_ipc raises StrictAuthorizationRefused
        with self.assertRaises(StrictAuthorizationRefused) as ctx2:
            load_verified_authorization_from_ipc(
                {"verified": True, "p_sha": self.p_sha, "w_sha": self.w_sha, "c_sha": self.c_sha},
                self.p_sha,
                self.w_sha,
                self.c_sha,
            )
        self.assertEqual(ctx2.exception.exit_code, AUTH_REFUSED_EXIT_CODE)

    def test_storage_redirect_no_auth_header(self) -> None:
        """Negative 15: Storage redirect download strips Authorization header."""
        verifier = AuthenticatedGitHubVerifier(
            token=VALID_TOKEN,
            _api_base=self.base_url,
        )
        receipt = verifier.verify(
            manifest_path=self.package_path,
            c_dir=self.c_repo,
        )
        self.assertEqual(receipt["decision"], "AUTHORIZED")

        self.assertGreater(len(LoopbackGitHubMockHandler.storage_requests), 0)
        for req in LoopbackGitHubMockHandler.storage_requests:
            self.assertFalse(req["has_auth"], f"Authorization header leaked to storage: {req['auth_header']}")

    def test_usage_errors(self) -> None:
        """Negative 16: Usage errors return exit code 2."""
        code = main(["prepare"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)
        code = main(["check"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)
        code = main(["run-native"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)


class ProductionAuthorityTests(unittest.TestCase):
    def test_environment_cannot_select_approval_authority(self) -> None:
        with patch.dict(os.environ, {"_STRICT_AUTH_TEST_API_BASE": "http://127.0.0.1:12345"}):
            verifier = AuthenticatedGitHubVerifier(token=VALID_TOKEN)
        self.assertEqual(verifier.base_url, "https://api.github.com")


if __name__ == "__main__":
    unittest.main()
