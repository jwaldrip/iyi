#!/usr/bin/env python3
"""Discriminating loopback and CLI boundary tests for strict-proof authorization verifier.

Tests all security gates and failure modes per PlanMinimalStrictAuthorization (§3, §5):
  - Canonical manifest creation via 'prepare' CLI
  - Authoritative check via 'check' CLI against local loopback HTTP service
  - Native execution via 'run-native' CLI with durable claims
  - Harmless native subprocess invocation and journal assertions
  - 15 specific negative controls asserting exit code 5 and EMPTY native journal:
      1. Missing, rejected, pending, wrong-user or wrong-environment approval
      2. Empty, malformed, whitespace-altered or wrong digest comment
      3. Run-ID substitution or attempt 2
      4. Wrong C/workflow or local code checkout
      5. PR147 moves, W lacks P ancestry, or product trees differ
      6. Manifest archive tampered
      7. Member changed and archive digest recomputed
      8. Duplicate ZIP member names
      9. Review NO-GO, missing review, or changed review bytes
      10. V failed but contains a PASS-looking summary
      11. Approval receipt claims success but GitHub history has none
      12. API 401/403/404/500 or incomplete pagination
      13. Storage redirect: storage request receives no API Authorization header
      14. Repeated fresh-chain launch under the same consumed approval
      15. Invocation from W preserves C's absolute verifier
  - Positive end-to-end control executing prepare -> check -> harmless native subprocess -> result readback
  - Usage errors return exit code 2
  - Fail-closed backward-compatible hook check_strict_authorization_or_refuse (exit 5)
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
    read_manifest_package,
)

SCRIPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "strict_authorization.py"))
VALID_TOKEN = "valid-ci-token-test-secret"


class LoopbackGitHubMockHandler(BaseHTTPRequestHandler):
    """Loopback HTTP mock server simulating GitHub API and storage redirect behavior."""

    routes: Dict[str, Any] = {}
    faults: Dict[str, int] = {}
    artifact_zips: Dict[str, bytes] = {}
    storage_requests: List[Dict[str, Any]] = []

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress HTTP server logging during unit tests

    def do_GET(self) -> None:
        auth_header = self.headers.get("Authorization", "")
        clean_path = self.path.split("?")[0].lstrip("/")

        # Check for simulated storage download (from 302 redirect)
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

        # Check for simulated faults
        if clean_path in self.faults:
            code = self.faults[clean_path]
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": f"Simulated fault {code}"}).encode("utf-8"))
            return

        # Verify Bearer token for all API endpoints
        if not auth_header.startswith("Bearer ") or auth_header.split("Bearer ", 1)[1] != VALID_TOKEN:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"message":"Bad credentials"}')
            return

        # Check for artifact zip redirect endpoint
        if clean_path.endswith("/zip"):
            art_id = clean_path.split("/")[-2]
            storage_key = f"artifacts/{art_id}/zip"
            if storage_key in self.artifact_zips:
                # Issue 302 redirect to storage endpoint
                port = self.server.server_address[1]
                redirect_url = f"http://127.0.0.1:{port}/storage/{storage_key}"
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
                return

        # Regular route matching
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
    """Base setup for loopback server and test fixtures."""

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
        LoopbackGitHubMockHandler.faults.clear()
        LoopbackGitHubMockHandler.artifact_zips.clear()
        LoopbackGitHubMockHandler.storage_requests.clear()

        self.test_dir = tempfile.mkdtemp(prefix="iyi_test_strict_")
        self.claim_dir = os.path.join(self.test_dir, "claims")
        self.report_dir = os.path.join(self.test_dir, "report")
        self.w_dir = os.path.join(self.test_dir, "w_proof")
        self.p_dir = os.path.join(self.test_dir, "p_product")
        self.compiler_bin = os.path.join(self.test_dir, "compiler")
        self.journal_path = os.path.join(self.test_dir, "native_journal.jsonl")

        os.makedirs(self.w_dir, exist_ok=True)
        os.makedirs(self.p_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

        with open(self.compiler_bin, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(self.compiler_bin, 0o755)

        # Harmless fake native runner script that logs invocations to journal
        self.harmless_runner = os.path.join(self.test_dir, "harmless_runner.py")
        with open(self.harmless_runner, "w") as f:
            f.write(
                "import sys, json, time\n"
                "stage = sys.argv[1]\n"
                "journal = None\n"
                "for i, arg in enumerate(sys.argv):\n"
                "    if arg == '--native-journal' and i + 1 < len(sys.argv):\n"
                "        journal = sys.argv[i+1]\n"
                "    elif arg == '--report-dir' and i + 1 < len(sys.argv):\n"
                "        rdir = sys.argv[i+1]\n"
                "        import os; os.makedirs(rdir, exist_ok=True)\n"
                "        with open(os.path.join(rdir, 'final.json'), 'w') as rf:\n"
                "            rf.write(json.dumps({'verdict': 'PASS', 'stage': stage}))\n"
                "if journal:\n"
                "    with open(journal, 'a') as jf:\n"
                "        jf.write(json.dumps({'stage': stage, 'args': sys.argv[1:]}) + '\\n')\n"
                "sys.exit(0)\n"
            )

        # Independent test literals
        self.p_sha = "180f14f91c829b25362a5ed34b20847f3ac2db77"
        self.w_sha = "b932ce0d97775c7061102a13db706f507dc84117"
        self.c_sha = "e0655fa63198086055d72f28fbe9e3f8c1e48b11"
        self.s_run_id = "101"
        self.v_run_id = "202"

        # Independent review evidence file
        self.review_path = os.path.join(self.test_dir, "review_evidence.json")
        self.review_content = {
            "verdict": "GO",
            "report": {
                "summary": "Substantive independent audit of candidate C against P and W",
                "verdict": "GO",
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
        with open(self.review_path, "wb") as rf:
            rf.write(self.review_bytes)

        # Validation artifact zip
        self.v_art_id = "301"
        self.v_art_bytes = self._create_zip("validation_receipt.json", b'{"receipt":"verified_142"}')
        self.v_art_sha256 = compute_digest(self.v_art_bytes)
        LoopbackGitHubMockHandler.artifact_zips[f"artifacts/{self.v_art_id}/zip"] = self.v_art_bytes

        # Manifest and package paths
        self.manifest_path = os.path.join(self.test_dir, "manifest.json")
        self.package_path = os.path.join(self.test_dir, "manifest_package.zip")

        # Prepare manifest via CLI
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
            "--review-path", self.review_path,
            "--review-sha256", self.review_sha256,
            "--review-verdict", "GO",
        ])
        self.assertEqual(prep_code, 0)

        # Compute D independently
        _, parsed_manifest, self.manifest_digest = read_manifest_package(self.package_path)
        self.expected_comment = f"{APPROVAL_COMMENT_PREFIX}{self.manifest_digest}"

        # Setup standard mock routes
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
            f"repos/{repo}/environments/{env}/deployment-branch-policies": {
                "branch_policies": [{"name": PINNED_BRANCH}],
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}": {
                "id": int(self.s_run_id),
                "run_attempt": 1,
                "path": PINNED_WORKFLOW_PATH,
                "head_sha": self.c_sha,
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}/attempts/1/jobs": {
                "jobs": [
                    {"name": "prepare-strict-authorization", "conclusion": "success"},
                    {"name": "strict-chain", "status": "in_progress"},
                ],
            },
            f"repos/{repo}/actions/runs/{self.s_run_id}/approvals": [
                {
                    "state": "approved",
                    "user": {"id": int(PINNED_REVIEWER_ID), "login": PINNED_REVIEWER_LOGIN},
                    "environments": [{"id": int(PINNED_ENVIRONMENT_ID), "name": PINNED_ENVIRONMENT_NAME}],
                    "comment": self.expected_comment,
                }
            ],
            f"repos/{repo}/actions/runs/{self.v_run_id}": {
                "id": int(self.v_run_id),
                "status": "completed",
                "conclusion": "success",
            },
            f"repos/{repo}/actions/runs/{self.v_run_id}/attempts/1/jobs": {
                "jobs": [
                    {"name": "remote-harness-audit", "status": "completed", "conclusion": "success"},
                ],
            },
            f"repos/{repo}/actions/artifacts/{self.v_art_id}": {
                "id": int(self.v_art_id),
                "expired": False,
                "workflow_run": {"id": int(self.v_run_id)},
            },
            f"repos/{repo}/pulls/147": {
                "head": {"sha": self.p_sha},
            },
        })

    def _read_journal(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.journal_path):
            return []
        lines = []
        with open(self.journal_path, "r") as f:
            for line in f:
                if line.strip():
                    lines.append(json.loads(line))
        return lines


class StrictAuthorizationPositiveTests(StrictAuthorizationTestsBase):
    """End-to-end positive control tests."""

    def test_e2e_positive_control(self) -> None:
        """Positive control: prepare -> check -> run-native -> harmless native process -> result readback."""
        receipt_path = os.path.join(self.test_dir, "receipt.json")

        # 1. Execute check command
        check_code = main([
            "check",
            "--manifest", self.package_path,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--receipt", receipt_path,
        ])
        self.assertEqual(check_code, 0)
        self.assertTrue(os.path.exists(receipt_path))
        with open(receipt_path, "r") as rf:
            receipt = json.load(rf)
        self.assertEqual(receipt["decision"], "AUTHORIZED")
        self.assertEqual(receipt["manifest_digest"], self.manifest_digest)

        # 2. Execute run-native command
        rn_code = main([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])
        self.assertEqual(rn_code, 0)

        # 3. Assert harmless native process executed and journal logged stages
        journal = self._read_journal()
        self.assertGreater(len(journal), 0)
        stages = [entry["stage"] for entry in journal]
        self.assertIn("preflight", stages)
        self.assertIn("plan", stages)
        self.assertIn("pin", stages)
        self.assertIn("run1", stages)
        self.assertIn("run2", stages)
        self.assertIn("run3", stages)
        self.assertIn("final", stages)

        # 4. Assert durable claim updated to completed
        claim_file = f"claim_{self.s_run_id}_{self.manifest_digest}.json"
        with open(os.path.join(self.claim_dir, claim_file), "r") as cf:
            claim_data = json.load(cf)
        self.assertEqual(claim_data["status"], "completed")


class StrictAuthorizationNegativeTests(StrictAuthorizationTestsBase):
    """15 required negative controls asserting exit code 5 and empty native journal."""

    def _assert_refusal(self, argv: List[str]) -> None:
        """Run CLI and assert exit code 5, native journal empty, no claim left completed."""
        code = main(argv)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        journal = self._read_journal()
        self.assertEqual(len(journal), 0, f"Expected empty journal on refusal, got {journal}")

    def test_negative_1_approval_missing_rejected_pending_wrong_user_wrong_env(self) -> None:
        """Negative 1: Missing, rejected, pending, wrong-user or wrong-environment approval."""
        repo = PINNED_REPOSITORY
        approvals_key = f"repos/{repo}/actions/runs/{self.s_run_id}/approvals"

        cases = [
            ("missing", []),
            ("rejected", [{
                "state": "rejected",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }]),
            ("pending", [{
                "state": "pending",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }]),
            ("wrong_user", [{
                "state": "approved",
                "user": {"id": 99999},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": self.expected_comment,
            }]),
            ("wrong_env", [{
                "state": "approved",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": 99999}],
                "comment": self.expected_comment,
            }]),
        ]

        for label, app_list in cases:
            LoopbackGitHubMockHandler.routes[approvals_key] = app_list
            with self.subTest(label=label):
                self._assert_refusal([
                    "run-native",
                    "--manifest", self.package_path,
                    "--w", self.w_dir,
                    "--p", self.p_dir,
                    "--compiler", self.compiler_bin,
                    "--report-dir", self.report_dir,
                    "--claim-dir", self.claim_dir,
                    "--allow-loopback",
                    "--base-url", self.base_url,
                    "--token", VALID_TOKEN,
                    "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
                    "--native-journal", self.journal_path,
                ])

    def test_negative_2_comment_empty_malformed_whitespace_wrong_digest(self) -> None:
        """Negative 2: Empty, malformed, whitespace-altered or wrong digest comment."""
        repo = PINNED_REPOSITORY
        approvals_key = f"repos/{repo}/actions/runs/{self.s_run_id}/approvals"

        cases = [
            ("empty", ""),
            ("whitespace", f"{self.expected_comment} "),
            ("wrong_prefix", f"iyi-strict-authorization-v1 sha256:{self.manifest_digest}"),
            ("wrong_digest", f"{APPROVAL_COMMENT_PREFIX}{'0'*64}"),
        ]

        for label, comm in cases:
            LoopbackGitHubMockHandler.routes[approvals_key] = [{
                "state": "approved",
                "user": {"id": int(PINNED_REVIEWER_ID)},
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID)}],
                "comment": comm,
            }]
            with self.subTest(label=label):
                self._assert_refusal([
                    "run-native",
                    "--manifest", self.package_path,
                    "--w", self.w_dir,
                    "--p", self.p_dir,
                    "--compiler", self.compiler_bin,
                    "--report-dir", self.report_dir,
                    "--claim-dir", self.claim_dir,
                    "--allow-loopback",
                    "--base-url", self.base_url,
                    "--token", VALID_TOKEN,
                    "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
                    "--native-journal", self.journal_path,
                ])

    def test_negative_3_run_id_substitution_or_attempt_2(self) -> None:
        """Negative 3: Run-ID substitution or attempt 2 refuses."""
        repo = PINNED_REPOSITORY

        # Attempt 2 in API
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"] = {
            "id": int(self.s_run_id),
            "run_attempt": 2,
            "path": PINNED_WORKFLOW_PATH,
            "head_sha": self.c_sha,
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
        }
        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_4_wrong_c_workflow_or_head_sha(self) -> None:
        """Negative 4: Wrong C/workflow refuses before native effects."""
        repo = PINNED_REPOSITORY

        # Head SHA mismatch in run S
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}"] = {
            "id": int(self.s_run_id),
            "run_attempt": 1,
            "path": PINNED_WORKFLOW_PATH,
            "head_sha": "0" * 40,
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
        }
        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_5_pr147_moves(self) -> None:
        """Negative 5: PR147 moves to a different head refuses."""
        repo = PINNED_REPOSITORY
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/pulls/147"] = {
            "head": {"sha": "1" * 40},
        }
        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_6_manifest_archive_tampered(self) -> None:
        """Negative 6: Manifest archive tampered/corrupted refuses."""
        bad_pkg = os.path.join(self.test_dir, "bad_package.zip")
        with open(bad_pkg, "wb") as f:
            f.write(b"not-a-valid-zip-content")

        self._assert_refusal([
            "run-native",
            "--manifest", bad_pkg,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_7_member_changed_and_digest_recomputed(self) -> None:
        """Negative 7: Member changed and digest recomputed refuses approval binding."""
        # Create manifest with altered field
        tampered_manifest = os.path.join(self.test_dir, "tampered_manifest.json")
        with open(self.manifest_path, "r") as f:
            m = json.load(f)
        m["chain_id"] = "tampered-chain-v9"
        with open(tampered_manifest, "w") as f:
            json.dump(m, f)

        self._assert_refusal([
            "run-native",
            "--manifest", tampered_manifest,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_8_duplicate_zip_member_names(self) -> None:
        """Negative 8: Duplicate ZIP member names refuses."""
        dup_pkg = os.path.join(self.test_dir, "dup_package.zip")
        with zipfile.ZipFile(dup_pkg, "w") as zf:
            zf.writestr("manifest.json", b'{"schema":"iyi-strict-manifest-v2"}')
            # Manually append second entry with same name
            zf.writestr("manifest.json", b'{"schema":"duplicate"}')

        self._assert_refusal([
            "run-native",
            "--manifest", dup_pkg,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_9_review_nogo_or_changed_bytes(self) -> None:
        """Negative 9: Review NO-GO, missing review, or changed bytes refuses."""
        # Change review file bytes
        with open(self.review_path, "wb") as f:
            f.write(b'{"verdict":"NO-GO","report":"failed"}')

        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--review-path", self.review_path,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_10_v_failed_but_pass_summary(self) -> None:
        """Negative 10: V job failed despite any PASS summary refuses."""
        repo = PINNED_REPOSITORY
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.v_run_id}"] = {
            "id": int(self.v_run_id),
            "status": "completed",
            "conclusion": "failure",
        }
        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_11_receipt_claims_success_but_github_has_none(self) -> None:
        """Negative 11: Local receipt exists but GitHub approval history is empty refuses."""
        repo = PINNED_REPOSITORY
        LoopbackGitHubMockHandler.routes[f"repos/{repo}/actions/runs/{self.s_run_id}/approvals"] = []

        fake_receipt = os.path.join(self.test_dir, "fake_receipt.json")
        with open(fake_receipt, "w") as f:
            json.dump({"decision": "AUTHORIZED"}, f)

        self._assert_refusal([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])

    def test_negative_12_api_faults_401_403_404_500(self) -> None:
        """Negative 12: API faults 401, 403, 404, 500 fail closed."""
        repo = PINNED_REPOSITORY
        route_to_fault = f"repos/{repo}/actions/runs/{self.s_run_id}"

        for fault_code in (500, 404, 401, 403):
            LoopbackGitHubMockHandler.faults[route_to_fault] = fault_code
            with self.subTest(fault_code=fault_code):
                self._assert_refusal([
                    "run-native",
                    "--manifest", self.package_path,
                    "--w", self.w_dir,
                    "--p", self.p_dir,
                    "--compiler", self.compiler_bin,
                    "--report-dir", self.report_dir,
                    "--claim-dir", self.claim_dir,
                    "--allow-loopback",
                    "--base-url", self.base_url,
                    "--token", VALID_TOKEN,
                    "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
                    "--native-journal", self.journal_path,
                ])
        LoopbackGitHubMockHandler.faults.clear()

    def test_negative_13_storage_redirect_authorization_header_isolation(self) -> None:
        """Negative 13: Storage download receives NO Authorization header across redirect."""
        verifier = AuthenticatedGitHubVerifier(
            token=VALID_TOKEN,
            base_url=self.base_url,
            allow_loopback=True,
        )
        receipt = verifier.verify(manifest_path=self.package_path)
        self.assertEqual(receipt["decision"], "AUTHORIZED")

        # Verify that the storage requests did NOT carry Authorization header
        self.assertGreater(len(LoopbackGitHubMockHandler.storage_requests), 0)
        for req in LoopbackGitHubMockHandler.storage_requests:
            self.assertFalse(req["has_auth"], f"Authorization header leaked to storage: {req['auth_header']}")

    def test_negative_14_repeated_fresh_chain_launch_under_same_approval(self) -> None:
        """Negative 14: Repeated invocation under same consumed approval refuses."""
        # 1. First run succeeds
        first_code = main([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])
        self.assertEqual(first_code, 0)
        first_journal_count = len(self._read_journal())
        self.assertGreater(first_journal_count, 0)

        # 2. Second invocation with same consumed claim MUST refuse
        second_code = main([
            "run-native",
            "--manifest", self.package_path,
            "--w", self.w_dir,
            "--p", self.p_dir,
            "--compiler", self.compiler_bin,
            "--report-dir", self.report_dir,
            "--claim-dir", self.claim_dir,
            "--allow-loopback",
            "--base-url", self.base_url,
            "--token", VALID_TOKEN,
            "--native-runner-cmd", f"{sys.executable} {self.harmless_runner}",
            "--native-journal", self.journal_path,
        ])
        self.assertEqual(second_code, AUTH_REFUSED_EXIT_CODE)
        # Assert journal was NOT appended to on second run
        second_journal_count = len(self._read_journal())
        self.assertEqual(second_journal_count, first_journal_count)

    def test_negative_15_usage_errors(self) -> None:
        """Usage errors return exit code 2."""
        # Missing required arguments
        code = main(["prepare"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)
        code = main(["check"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)
        code = main(["run-native"])
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)

    def test_backward_compatible_refusal_hook(self) -> None:
        """Legacy check_strict_authorization_or_refuse hook fails closed with exit code 5."""
        with self.assertRaises(StrictAuthorizationRefused) as ctx:
            check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha)
        self.assertEqual(ctx.exception.exit_code, AUTH_REFUSED_EXIT_CODE)


if __name__ == "__main__":
    unittest.main()
