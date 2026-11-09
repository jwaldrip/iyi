"""Discriminating tests for authenticated GitHub environment strict-proof authorization verifier.

Tests all security gates and failure modes:
  - Exact individual check isolation: every check ID (RNR-1..6, REP-1, RUN-1, JOB-1..3,
    ENV-1..2, BRN-1..2, SRC-1..3, BUN-1, HAR-1..6, VAL-1..4, AUD-1..3, MAN-1..3, APR-1)
    has a positive test showing it passes on valid fixtures, and a dedicated negative test
    that breaks only that check and verifies the refusal names that exact check ID.
  - Comprehensive CLI execution through main(api_factory) with loopback server and real fixtures.
  - Full loopback HTTP server verifying Bearer token on API requests, 302 redirect handling,
    and storage host that strictly rejects any request carrying an Authorization header.
  - Canonical JSON parser tests verifying duplicate key and non-canonical rejection.
  - StrictManifestBinding verification over file descriptors with exact error guarantees.
  - Subcommands: prepare, authorize, rehearse, inspect, check-bundle, check-w-tree, publish, rail-summary, verify-run.
"""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
import urllib.parse
import zipfile

from proof.fixtures.github_api import (
    canonical as fixture_canonical,
    digest as fixture_digest,
    get_approval_fixture,
    get_audit_files_fixture,
    get_blob_95962d09_fixture,
    get_branch_deploy_fixture,
    get_branch_policies_fixture,
    get_check_run_deployment_fixture,
    get_compare_pw_fixture,
    get_compare_wh_fixture,
    get_contents_harness_audit_zip_fixture,
    get_deployment_fixture,
    get_evidence_branch_fixture,
    get_environment_fixture,
    get_manifest_artifact_fixture,
    get_pull_147_fixture,
    get_repo_fixture,
    get_rules_branch_deploy_fixture,
    get_strict_run_in_progress_fixture,
    get_val_artifacts_fixture,
    get_val_jobs_fixture,
    git_blob_id as fixture_git_blob_id,
    load_fixture,
)
from proof.strict_authorization import (
    APPROVAL_COMMENT_PREFIX,
    ATTESTATION_SCOPE,
    ARTIFACT_NAME_MANIFEST,
    ARTIFACT_NAME_RAIL_SUMMARY,
    ARTIFACT_NAME_REHEARSAL_REPORT,
    ARTIFACT_NAME_VERIFICATION,
    AUTH_REFUSED_EXIT_CODE,
    AuthorizationError,
    GitHubAPIClient,
    HARNESS_ARTIFACT_DIGEST,
    HARNESS_ARTIFACT_ID,
    HARNESS_ARTIFACT_NAME,
    HARNESS_CONCLUSION,
    HARNESS_EVENT,
    HARNESS_HEAD_BRANCH,
    HARNESS_JOB_ID,
    HARNESS_JOB_NAME,
    HARNESS_PRESERVED_BLOB,
    HARNESS_PRESERVED_COMMIT,
    HARNESS_PRESERVED_PATH,
    HARNESS_RUN_ATTEMPT,
    HARNESS_RUN_ID,
    HARNESS_SUMMARY_MEMBER,
    HARNESS_SUMMARY_MEMBER_SHA256,
    HARNESS_WORKFLOW_ID,
    HARNESS_WORKFLOW_PATH,
    JOB_KEY_PREPARE,
    JOB_KEY_REHEARSAL,
    JOB_KEY_STRICT,
    JOB_NAME_PREPARE,
    JOB_NAME_REHEARSAL,
    JOB_NAME_STRICT,
    PINNED_ACTIONS,
    PINNED_API_BASE,
    PINNED_DEPLOY_BRANCH,
    PINNED_ENVIRONMENT_ID,
    PINNED_ENVIRONMENT_NAME,
    PINNED_H_ADDED_PATHS,
    PINNED_H_MERGE_BASE,
    PINNED_H_SHA,
    PINNED_P_HEAD_REF,
    PINNED_P_HEAD_REPO_ID,
    PINNED_P_PR_NUMBER,
    PINNED_P_PR_REPOSITORY,
    PINNED_P_PR_STATE,
    PINNED_P_SHA,
    PINNED_REF,
    PINNED_REFUSAL_CONTROLS,
    PINNED_REPOSITORY,
    PINNED_REPOSITORY_ID,
    PINNED_REVIEWER_ID,
    PINNED_REVIEWER_LOGIN,
    PINNED_W_ADDED_COUNT,
    PINNED_W_ADDED_PATHS_SHA256,
    PINNED_W_AHEAD_BY,
    PINNED_W_BEHIND_BY,
    PINNED_W_MERGE_BASE,
    PINNED_W_SHA,
    PINNED_WORKFLOW_ID,
    PINNED_WORKFLOW_NAME,
    PINNED_WORKFLOW_PATH,
    SCHEMA_AUDIT,
    SCHEMA_MANIFEST,
    SCHEMA_RAIL_SUMMARY,
    SCHEMA_REHEARSAL,
    SCHEMA_REFUSAL_REPORT,
    SCHEMA_REHEARSAL_MANIFEST,
    SCHEMA_VERIFICATION,
    StrictManifestBinding,
    USAGE_ERROR_EXIT_CODE,
    WORKFLOW_REF,
    build_manifest_v2,
    canonical,
    check_apr_1,
    check_aud_1,
    check_aud_2,
    check_aud_3,
    check_brn_1,
    check_brn_2,
    check_bun_1,
    check_env_1,
    check_env_2,
    check_har_1_2,
    check_har_3,
    check_har_4,
    check_har_5,
    check_har_6,
    check_job_1,
    check_job_2,
    check_job_3,
    check_man_1,
    check_man_2,
    check_man_3,
    check_rep_1,
    check_rnr_1,
    check_rnr_2,
    check_rnr_3,
    check_rnr_4,
    check_rnr_5,
    check_rnr_6,
    check_run_1,
    check_src_1,
    check_src_2,
    check_src_3,
    check_val_1,
    check_val_1b,
    check_val_2,
    check_val_3,
    check_val_4,
    digest,
    git_blob_id,
    main,
    parse,
    read_strict_manifest_binding,
)


class CanonicalJsonParserTests(unittest.TestCase):
    """Test canonical UTF-8 JSON parsing and strict rejection."""

    def test_canonical_roundtrip(self):
        data = {"b": 2, "a": 1, "c": [3, 4]}
        raw = canonical(data)
        self.assertEqual(raw, b'{"a":1,"b":2,"c":[3,4]}')
        parsed = parse(raw)
        self.assertEqual(parsed, {"a": 1, "b": 2, "c": [3, 4]})

    def test_reject_duplicate_keys(self):
        raw = b'{"a":1,"a":2}'
        with self.assertRaises(AuthorizationError) as ctx:
            parse(raw)
        self.assertIn("duplicate JSON key", str(ctx.exception))

    def test_reject_noncanonical_spacing(self):
        raw = b'{"a": 1, "b": 2}'
        with self.assertRaises(AuthorizationError) as ctx:
            parse(raw)
        self.assertIn("noncanonical JSON", str(ctx.exception))

    def test_reject_noncanonical_key_sorting(self):
        raw = b'{"b":1,"a":2}'
        with self.assertRaises(AuthorizationError) as ctx:
            parse(raw)
        self.assertIn("noncanonical JSON", str(ctx.exception))


class CheckIsolationTests(unittest.TestCase):
    """Verify that every check ID isolates its failure mode and names the check ID."""

    # RNR-1
    def test_rnr_1_positive(self):
        env = {"GITHUB_REPOSITORY": PINNED_REPOSITORY, "GITHUB_REPOSITORY_ID": PINNED_REPOSITORY_ID}
        res = check_rnr_1(env)
        self.assertEqual(res["repository"], PINNED_REPOSITORY)
        self.assertEqual(res["repository_id"], PINNED_REPOSITORY_ID)

    def test_rnr_1_repository_mismatch(self):
        env = {"GITHUB_REPOSITORY": "wrong/repo", "GITHUB_REPOSITORY_ID": PINNED_REPOSITORY_ID}
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_1(env)
        self.assertIn("RNR-1", str(ctx.exception))

    def test_rnr_1_repo_id_mismatch(self):
        env = {"GITHUB_REPOSITORY": PINNED_REPOSITORY, "GITHUB_REPOSITORY_ID": "999999"}
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_1(env)
        self.assertIn("RNR-1", str(ctx.exception))

    # RNR-2
    def test_rnr_2_positive(self):
        env = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": "c" * 40,
            "GITHUB_SHA": "c" * 40,
        }
        res = check_rnr_2(env)
        self.assertEqual(res["event"], "workflow_dispatch")

    def test_rnr_2_event_mismatch(self):
        env = {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": "c" * 40,
            "GITHUB_SHA": "c" * 40,
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_2(env)
        self.assertIn("RNR-2", str(ctx.exception))

    def test_rnr_2_ref_mismatch(self):
        env = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/master",
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": "c" * 40,
            "GITHUB_SHA": "c" * 40,
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_2(env)
        self.assertIn("RNR-2", str(ctx.exception))

    def test_rnr_2_workflow_ref_mismatch(self):
        env = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": "wrong-workflow-ref",
            "GITHUB_WORKFLOW_SHA": "c" * 40,
            "GITHUB_SHA": "c" * 40,
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_2(env)
        self.assertIn("RNR-2", str(ctx.exception))

    def test_rnr_2_workflow_sha_mismatch(self):
        env = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_SHA": "b" * 40,
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_2(env)
        self.assertIn("RNR-2", str(ctx.exception))

    # RNR-3
    def test_rnr_3_positive(self):
        self.assertEqual(check_rnr_3({"GITHUB_RUN_ATTEMPT": "1"}), "1")

    def test_rnr_3_attempt_mismatch(self):
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_3({"GITHUB_RUN_ATTEMPT": "2"})
        self.assertIn("RNR-3", str(ctx.exception))

    # RNR-4
    def test_rnr_4_positive(self):
        env = {
            "GITHUB_JOB": JOB_KEY_PREPARE,
            "RUNNER_ENVIRONMENT": "github-hosted",
            "JOB_CHECK_RUN_ID": "12345",
        }
        res = check_rnr_4(env, JOB_KEY_PREPARE)
        self.assertEqual(res["job"], JOB_KEY_PREPARE)

    def test_rnr_4_job_key_mismatch(self):
        env = {
            "GITHUB_JOB": "wrong-job",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "JOB_CHECK_RUN_ID": "12345",
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_4(env, JOB_KEY_PREPARE)
        self.assertIn("RNR-4", str(ctx.exception))

    def test_rnr_4_runner_environment_mismatch(self):
        env = {
            "GITHUB_JOB": JOB_KEY_PREPARE,
            "RUNNER_ENVIRONMENT": "self-hosted",
            "JOB_CHECK_RUN_ID": "12345",
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_4(env, JOB_KEY_PREPARE)
        self.assertIn("RNR-4", str(ctx.exception))

    def test_rnr_4_job_check_run_id_not_decimal(self):
        env = {
            "GITHUB_JOB": JOB_KEY_PREPARE,
            "RUNNER_ENVIRONMENT": "github-hosted",
            "JOB_CHECK_RUN_ID": "0abc",
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_4(env, JOB_KEY_PREPARE)
        self.assertIn("RNR-4", str(ctx.exception))

    # RNR-5
    def test_rnr_5_positive(self):
        payload = {"inputs": {"mode": "strict-chain", "evidence_commit": "a" * 40}}
        res = check_rnr_5(payload)
        self.assertEqual(res["mode"], "strict-chain")
        self.assertEqual(res["evidence_commit"], "a" * 40)

    def test_rnr_5_mode_mismatch(self):
        payload = {"inputs": {"mode": "synthetic", "evidence_commit": "a" * 40}}
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_5(payload)
        self.assertIn("RNR-5", str(ctx.exception))

    def test_rnr_5_evidence_commit_invalid(self):
        payload = {"inputs": {"mode": "strict-chain", "evidence_commit": "not-a-sha"}}
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_5(payload)
        self.assertIn("RNR-5", str(ctx.exception))

    # RNR-6
    def test_rnr_6_positive(self):
        head = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("ascii").strip()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=head, stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            res = check_rnr_6({"GITHUB_SHA": head})
            self.assertEqual(res["head_sha"], head)

    def test_rnr_6_sha_mismatch(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="a" * 40, stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            with self.assertRaises(AuthorizationError) as ctx:
                check_rnr_6({"GITHUB_SHA": "b" * 40})
            self.assertIn("RNR-6", str(ctx.exception))

    def test_rnr_6_dirty_tree(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="a" * 40, stderr=""),
                MagicMock(returncode=0, stdout=" M dirty_file.txt\n", stderr=""),
            ]
            with self.assertRaises(AuthorizationError) as ctx:
                check_rnr_6({"GITHUB_SHA": "a" * 40})
            self.assertIn("RNR-6", str(ctx.exception))

    # REP-1
    def test_rep_1_positive(self):
        repo = get_repo_fixture()
        res = check_rep_1(repo)
        self.assertEqual(res["full_name"], PINNED_REPOSITORY)
        self.assertEqual(res["id"], PINNED_REPOSITORY_ID)

    def test_rep_1_private_repo(self):
        repo = get_repo_fixture()
        repo["private"] = True
        with self.assertRaises(AuthorizationError) as ctx:
            check_rep_1(repo)
        self.assertIn("REP-1", str(ctx.exception))

    def test_rep_1_visibility_not_public(self):
        repo = get_repo_fixture()
        repo["visibility"] = "internal"
        with self.assertRaises(AuthorizationError) as ctx:
            check_rep_1(repo)
        self.assertIn("REP-1", str(ctx.exception))

    # RUN-1
    def test_run_1_positive(self):
        run = get_strict_run_in_progress_fixture(head_sha="c" * 40)
        res = check_run_1(run, "c" * 40, expected_event="workflow_dispatch")
        self.assertEqual(res["head_sha"], "c" * 40)

    def test_run_1_not_in_progress(self):
        run = get_strict_run_in_progress_fixture(head_sha="c" * 40)
        run["status"] = "completed"
        with self.assertRaises(AuthorizationError) as ctx:
            check_run_1(run, "c" * 40)
        self.assertIn("RUN-1", str(ctx.exception))

    def test_run_1_workflow_mismatch(self):
        run = get_strict_run_in_progress_fixture(head_sha="c" * 40)
        run["workflow_id"] = 999999
        with self.assertRaises(AuthorizationError) as ctx:
            check_run_1(run, "c" * 40)
        self.assertIn("RUN-1", str(ctx.exception))

    # JOB-1
    def test_job_1_positive(self):
        job = deepcopy(load_fixture("job_128575084391.json"))
        job["workflow_name"] = PINNED_WORKFLOW_NAME
        job["name"] = JOB_NAME_STRICT
        job["run_id"] = "100"
        job["head_sha"] = "c" * 40
        job["status"] = "in_progress"
        job["runner_name"] = "GitHub Actions 1"
        res = check_job_1(job, "100", JOB_NAME_STRICT, "c" * 40, runner_name="GitHub Actions 1")
        self.assertEqual(res["name"], JOB_NAME_STRICT)

    def test_job_1_missing_runner_name(self):
        job = deepcopy(load_fixture("job_128575084391.json"))
        job["workflow_name"] = PINNED_WORKFLOW_NAME
        job["name"] = JOB_NAME_STRICT
        job["run_id"] = "100"
        job["head_sha"] = "c" * 40
        job["status"] = "in_progress"
        job["runner_name"] = ""
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_1(job, "100", JOB_NAME_STRICT, "c" * 40, runner_name="GitHub Actions 1")
        self.assertIn("JOB-1", str(ctx.exception))

    def test_job_1_runner_name_mismatch(self):
        job = deepcopy(load_fixture("job_128575084391.json"))
        job["workflow_name"] = PINNED_WORKFLOW_NAME
        job["name"] = JOB_NAME_STRICT
        job["run_id"] = "100"
        job["head_sha"] = "c" * 40
        job["status"] = "in_progress"
        job["runner_name"] = "GitHub Actions 1"
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_1(job, "100", JOB_NAME_STRICT, "c" * 40, runner_name="GitHub Actions 2")
        self.assertIn("JOB-1", str(ctx.exception))

    # JOB-2
    def test_job_2_positive(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        dep = get_deployment_fixture(6086087299, "c" * 40)
        res = check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertEqual(res["environment"], PINNED_ENVIRONMENT_NAME)

    def test_job_2_missing_deployment(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        check_run["deployment"] = None
        dep = get_deployment_fixture(6086087299, "c" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_deployment_environment_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        dep = get_deployment_fixture(6086087299, "c" * 40, env_name="production")
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))
    def test_job_2_app_slug_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        check_run["app"]["slug"] = "unauthorized-app"
        dep = get_deployment_fixture(6086087299, "c" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_head_sha_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        check_run["head_sha"] = "0" * 40
        dep = get_deployment_fixture(6086087299, "c" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_details_url_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        check_run["details_url"] = "https://github.com/other/run/1"
        dep = get_deployment_fixture(6086087299, "c" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_deployment_app_slug_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        dep = get_deployment_fixture(6086087299, "c" * 40)
        dep["performed_via_github_app"] = {"slug": "other-app"}
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_deployment_sha_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        dep = get_deployment_fixture(6086087299, "0" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_2_deployment_ref_mismatch(self):
        check_run = get_check_run_deployment_fixture(128575084399, 42086795082, "c" * 40, deployment_id=6086087299)
        dep = get_deployment_fixture(6086087299, "c" * 40)
        dep["ref"] = "refs/heads/wrong"
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "42086795082", "128575084399", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    # JOB-3
    def test_job_3_positive(self):
        jobs = [
            {"id": "1", "name": JOB_NAME_PREPARE, "status": "completed", "conclusion": "success"},
            {"id": "2", "name": JOB_NAME_STRICT, "status": "in_progress", "conclusion": None},
            {"id": "3", "name": "Ownership recovery (case1)", "status": "completed", "conclusion": "skipped"},
        ]
        check_job_3(jobs, "1", "2")

    def test_job_3_unskipped_extra_job(self):
        jobs = [
            {"id": "1", "name": JOB_NAME_PREPARE, "status": "completed", "conclusion": "success"},
            {"id": "2", "name": JOB_NAME_STRICT, "status": "in_progress", "conclusion": None},
            {"id": "3", "name": "Extra Job", "status": "completed", "conclusion": "success"},
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_3(jobs, "1", "2")
        self.assertIn("JOB-3", str(ctx.exception))

    # ENV-1 & ENV-2
    def test_env_1_positive(self):
        env = get_environment_fixture()
        res = check_env_1(env)
        self.assertEqual(res["name"], PINNED_ENVIRONMENT_NAME)

    def test_env_1_admin_bypass_true(self):
        env = get_environment_fixture()
        env["can_admins_bypass"] = True
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_1(env)
        self.assertIn("ENV-1", str(ctx.exception))
    def test_env_1_custom_branch_policy_false(self):
        env = get_environment_fixture()
        env["deployment_branch_policy"] = {"protected_branches": True, "custom_branch_policies": False}
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_1(env)
        self.assertIn("ENV-1", str(ctx.exception))

    def test_env_1_protection_rules_mismatch(self):
        env = get_environment_fixture()
        env["protection_rules"] = env["protection_rules"][:1]
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_1(env)
        self.assertIn("ENV-1", str(ctx.exception))

    def test_env_2_positive(self):
        policies = get_branch_policies_fixture()
        res = check_env_2(policies)
        self.assertEqual(res[0]["name"], PINNED_DEPLOY_BRANCH)

    def test_env_2_wrong_branch_policy(self):
        policies = [{"type": "branch", "name": "wrong-branch"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_2(policies)
        self.assertIn("ENV-2", str(ctx.exception))
    def test_env_2_policy_type_not_branch(self):
        policies = [{"type": "tag", "name": PINNED_DEPLOY_BRANCH}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_2(policies)
        self.assertIn("ENV-2", str(ctx.exception))

    def test_env_2_multiple_policies_rejected(self):
        policies = [
            {"type": "branch", "name": PINNED_DEPLOY_BRANCH},
            {"type": "branch", "name": "other-branch"},
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_2(policies)
        self.assertIn("ENV-2", str(ctx.exception))

    # BRN-1 & BRN-2
    def test_brn_1_positive(self):
        branch = get_branch_deploy_fixture()
        head = branch["commit"]["sha"]
        res = check_brn_1(branch, head)
        self.assertEqual(res["head_sha"], head)

    def test_brn_1_wrong_head(self):
        branch = get_branch_deploy_fixture()
        with self.assertRaises(AuthorizationError) as ctx:
            check_brn_1(branch, "0" * 40)
        self.assertIn("BRN-1", str(ctx.exception))

    def test_brn_2_positive_active(self):
        rules = get_rules_branch_deploy_fixture(active=True)
        res = check_brn_2(rules, require_active=True)
        self.assertEqual(len(res), 3)

    def test_brn_2_negative_missing_rules(self):
        rules = get_rules_branch_deploy_fixture(active=False)
        with self.assertRaises(AuthorizationError) as ctx:
            check_brn_2(rules, require_active=True)
        self.assertIn("BRN-2", str(ctx.exception))

    def test_brn_2_negative_update_allows_merge(self):
        rules = get_rules_branch_deploy_fixture(active=True)
        for r in rules:
            if r["type"] == "update":
                r["parameters"] = {"update_allows_fetch_and_merge": True}
        with self.assertRaises(AuthorizationError) as ctx:
            check_brn_2(rules, require_active=True)
        self.assertIn("BRN-2", str(ctx.exception))

    # SRC-1, SRC-2, SRC-3
    def test_src_1_positive(self):
        pr = get_pull_147_fixture()
        res = check_src_1(pr)
        self.assertEqual(res["sha"], PINNED_P_SHA)

    def test_src_1_closed_pr(self):
        pr = get_pull_147_fixture()
        pr["state"] = "closed"
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_1(pr)
        self.assertIn("SRC-1", str(ctx.exception))
    def test_src_1_head_repo_id_mismatch(self):
        pr = deepcopy(get_pull_147_fixture())
        pr["head"]["repo"]["id"] = 9999999
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_1(pr)
        self.assertIn("SRC-1", str(ctx.exception))

    def test_src_1_head_ref_mismatch(self):
        pr = deepcopy(get_pull_147_fixture())
        pr["head"]["ref"] = "wrong-ref"
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_1(pr)
        self.assertIn("SRC-1", str(ctx.exception))

    def test_src_1_head_sha_mismatch(self):
        pr = deepcopy(get_pull_147_fixture())
        pr["head"]["sha"] = "0" * 40
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_1(pr)
        self.assertIn("SRC-1", str(ctx.exception))

    def test_src_2_positive(self):
        compare = get_compare_pw_fixture()
        res = check_src_2(compare)
        self.assertEqual(res["sha"], PINNED_W_SHA)
        self.assertEqual(res["added_count"], PINNED_W_ADDED_COUNT)

    def test_src_2_pw_count_mismatch(self):
        compare = deepcopy(get_compare_pw_fixture())
        compare["files"] = compare["files"][:10]
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_2(compare)
        self.assertIn("SRC-2", str(ctx.exception))
    def test_src_2_ahead_by_mismatch(self):
        compare = deepcopy(get_compare_pw_fixture())
        compare["ahead_by"] = 999
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_2(compare)
        self.assertIn("SRC-2", str(ctx.exception))

    def test_src_2_behind_by_mismatch(self):
        compare = deepcopy(get_compare_pw_fixture())
        compare["behind_by"] = 999
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_2(compare)
        self.assertIn("SRC-2", str(ctx.exception))

    def test_src_2_status_not_ahead(self):
        compare = deepcopy(get_compare_pw_fixture())
        compare["status"] = "diverged"
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_2(compare)
        self.assertIn("SRC-2", str(ctx.exception))

    def test_src_3_positive(self):
        compare = get_compare_wh_fixture()
        res = check_src_3(compare)
        self.assertEqual(res["sha"], PINNED_H_SHA)

    def test_src_3_wh_merge_base_mismatch(self):
        compare = deepcopy(get_compare_wh_fixture())
        compare["merge_base_commit"] = {"sha": "0" * 40}
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_3(compare)
        self.assertIn("SRC-3", str(ctx.exception))
    def test_src_3_added_paths_mismatch(self):
        compare = deepcopy(get_compare_wh_fixture())
        compare["files"][0]["filename"] = "proof/wrong.py"
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_3(compare)
        self.assertIn("SRC-3", str(ctx.exception))

    def test_src_3_file_count_not_two(self):
        compare = deepcopy(get_compare_wh_fixture())
        compare["files"] = compare["files"][:1]
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_3(compare)
        self.assertIn("SRC-3", str(ctx.exception))

    # BUN-1
    def test_bun_1_positive(self):
        bundle = check_bun_1()
        self.assertIn("index.js", bundle)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", h) for h in bundle.values()))

    # HAR-1..6
    def test_har_1_2_positive(self):
        run = load_fixture("run_42429518284.json")
        job = load_fixture("job_128575084391.json")
        check_har_1_2(run, job)

    def test_har_1_conclusion_failure(self):
        run = deepcopy(load_fixture("run_42429518284.json"))
        job = deepcopy(load_fixture("job_128575084391.json"))
        run["conclusion"] = "failure"
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_1_2(run, job)
        self.assertIn("HAR-1", str(ctx.exception))

    def test_har_3_positive(self):
        art = load_fixture("artifact_13600255503.json")
        exp, is_exp = check_har_3(art)
        self.assertEqual(exp, art["expires_at"])
        self.assertFalse(is_exp)

    def test_har_3_expired_passes(self):
        art = deepcopy(load_fixture("artifact_13600255503.json"))
        art["expired"] = True
        exp, is_exp = check_har_3(art)
        self.assertEqual(exp, art["expires_at"])
        self.assertTrue(is_exp)
        check_har_5(None, b"preserved", is_expired=True)

    def test_har_3_digest_mismatch(self):
        art = deepcopy(load_fixture("artifact_13600255503.json"))
        art["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_3(art)
        self.assertIn("HAR-3", str(ctx.exception))
    def test_har_3_bare_digest_passes(self):
        art = deepcopy(load_fixture("artifact_13600255503.json"))
        art["digest"] = HARNESS_ARTIFACT_DIGEST[7:]
        exp, is_exp = check_har_3(art)
        self.assertEqual(exp, art["expires_at"])
        self.assertFalse(is_exp)

    def test_har_4_positive(self):
        contents = load_fixture("contents_harness_audit_zip.json")
        blob = load_fixture("blob_95962d09.json")
        zip_bytes = check_har_4(contents, blob)
        self.assertTrue(len(zip_bytes) > 0)

    def test_har_4_blob_sha_mismatch(self):
        contents = deepcopy(load_fixture("contents_harness_audit_zip.json"))
        blob = deepcopy(load_fixture("blob_95962d09.json"))
        contents["sha"] = "wrong_sha"
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_4(contents, blob)
        self.assertIn("HAR-4", str(ctx.exception))

    def test_har_5_positive(self):
        check_har_5(b"bytes", b"bytes", False)

    def test_har_5_missing_download(self):
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_5(None, b"bytes", False)
        self.assertIn("HAR-5", str(ctx.exception))

    def test_har_6_positive(self):
        blob = load_fixture("blob_95962d09.json")
        import base64
        zip_bytes = base64.b64decode(blob["content"].replace("\n", ""))
        res = check_har_6(zip_bytes)
        self.assertEqual(res["status"], "PASS")

    def test_har_6_summary_status_mismatch(self):
        # Create a zip where raw JSON matches digest logic when tampered
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(HARNESS_SUMMARY_MEMBER, b'{"status":"FAIL","w_sha":"5a3770e96fb12099c4ce9dc3b21895de07dd4cd8","p1_sha":"180f14f91c829b25362a5ed34b20847f3ac2db77"}')
        with patch("proof.strict_authorization.HARNESS_SUMMARY_MEMBER_SHA256", digest(b'{"status":"FAIL","w_sha":"5a3770e96fb12099c4ce9dc3b21895de07dd4cd8","p1_sha":"180f14f91c829b25362a5ed34b20847f3ac2db77"}')):
            with self.assertRaises(AuthorizationError) as ctx:
                check_har_6(buf.getvalue())
            self.assertIn("HAR-6", str(ctx.exception))
            self.assertIn("status", str(ctx.exception))

    # VAL-1..4
    def test_val_1_positive(self):
        run = get_strict_run_in_progress_fixture(head_sha="c" * 40, run_id=42086795082)
        run["event"] = "push"
        run["status"] = "completed"
        run["conclusion"] = "success"
        run["workflow_id"] = PINNED_WORKFLOW_ID
        res = check_val_1([run], "c" * 40)
        self.assertEqual(res["id"], 42086795082)

    def test_val_1_run_not_success(self):
        run = get_strict_run_in_progress_fixture(head_sha="c" * 40, run_id=42086795082)
        run["event"] = "push"
        run["status"] = "completed"
        run["conclusion"] = "failure"
        run["workflow_id"] = PINNED_WORKFLOW_ID
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1([run], "c" * 40)
        self.assertIn("VAL-1", str(ctx.exception))

    def test_val_1b_positive(self):
        mock_client = MagicMock()
        mock_client.get_paginated.return_value = [
            {"name": "Controller synthetic and validation proofs (macOS 15)", "status": "completed", "conclusion": "success"}
        ]
        runs = [{"id": 100, "run_attempt": 1, "status": "completed", "conclusion": "success"}]
        check_val_1b(mock_client, runs)

    def test_val_1b_failure(self):
        mock_client = MagicMock()
        mock_client.get_paginated.return_value = [
            {"name": "Controller synthetic and validation proofs (macOS 15)", "status": "completed", "conclusion": "failure"}
        ]
        runs = [{"id": 100, "run_attempt": 1, "status": "completed", "conclusion": "failure"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1b(mock_client, runs)
        self.assertIn("VAL-1b", str(ctx.exception))

    def test_val_1b_attempt1_failed_attempt2_passed_refuses(self):
        mock_client = MagicMock()
        def get_jobs_side_effect(endpoint):
            if "attempts/1/jobs" in endpoint:
                return [{"name": "Controller synthetic and validation proofs (macOS 15)", "status": "completed", "conclusion": "failure"}]
            elif "attempts/2/jobs" in endpoint:
                return [{"name": "Controller synthetic and validation proofs (macOS 15)", "status": "completed", "conclusion": "success"}]
            return []
        mock_client.get_paginated.side_effect = get_jobs_side_effect
        runs = [{"id": 100, "run_attempt": 2, "status": "completed", "conclusion": "success"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1b(mock_client, runs)
        self.assertIn("VAL-1b", str(ctx.exception))

    def test_val_1b_skipped_controller_passes(self):
        mock_client = MagicMock()
        mock_client.get_paginated.return_value = [
            {"name": "Controller synthetic and validation proofs (macOS 15)", "status": "completed", "conclusion": "skipped"}
        ]
        runs = [{"id": 100, "run_attempt": 1, "status": "completed", "conclusion": "success"}]
        check_val_1b(mock_client, runs)
    def test_val_2_positive(self):
        jobs = get_val_jobs_fixture(42086795082, "c" * 40)
        check_val_2(jobs)

    def test_val_2_job_set_missing(self):
        jobs = [
            {"id": 1, "name": "Generate supervisor bundle", "status": "completed", "conclusion": "success"}
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_2(jobs)
        self.assertIn("VAL-2", str(ctx.exception))

    def test_val_2_extra_job(self):
        jobs = get_val_jobs_fixture(42086795082, "c" * 40)
        jobs.append({"id": 99, "name": "Unexpected extra job", "status": "completed", "conclusion": "success"})
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_2(jobs)
        self.assertIn("VAL-2", str(ctx.exception))

    def test_val_3_positive(self):
        arts = get_val_artifacts_fixture(42086795082, "c" * 40, "sha256:" + "1" * 64, "sha256:" + "2" * 64)
        res = check_val_3(arts, "c" * 40)
        self.assertIn(f"supervisor-bundle-{'c' * 40}", res)

    def test_val_3_artifact_count_not_62(self):
        arts = get_val_artifacts_fixture(42086795082, "c" * 40, "sha256:" + "1" * 64, "sha256:" + "2" * 64)
        arts = arts[:61]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_3(arts, "c" * 40)
        self.assertIn("VAL-3", str(ctx.exception))
    def test_val_3_bare_digest_passes(self):
        arts = get_val_artifacts_fixture(42086795082, "c" * 40, "1" * 64, "2" * 64)
        for a in arts:
            if a.get("digest", "").startswith("sha256:"):
                a["digest"] = a["digest"][7:]
        res = check_val_3(arts, "c" * 40)
        self.assertIn(f"supervisor-bundle-{'c' * 40}", res)

    def _make_rehearsal_report(self, c_sha: str = "c" * 40, run_id: str = "100") -> bytes:
        reh_m = {
            "schema": SCHEMA_REHEARSAL_MANIFEST,
            "c_sha": c_sha,
            "run_id": str(run_id),
            "checks": [],
            "approvals_observed": [],
        }
        reh_m_raw = canonical(reh_m)
        return canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": c_sha,
            "run_id": str(run_id),
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": digest(reh_m_raw),
            "rehearsal_manifest": reh_m,
        })

    def test_val_4_positive(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = self._make_rehearsal_report("c" * 40, "100")
        s_sha, r_sha = check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertEqual(s_sha, digest(summary_raw))

    def test_val_4_summary_dist_mismatch(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": {"file1": "0" * 64},
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = self._make_rehearsal_report("c" * 40, "100")
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_missing_workflow_structure_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "FAIL",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = self._make_rehearsal_report("c" * 40, "100")
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_missing_controller_suite_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "FAIL",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = self._make_rehearsal_report("c" * 40, "100")
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_strict_refusal_controls_mismatch_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": ["wrong_control"],
        })
        rehearsal_raw = self._make_rehearsal_report("c" * 40, "100")
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_missing_rehearsal_manifest_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": "0" * 64,
        })
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_rehearsal_manifest_schema_mismatch_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        bad_reh_m = {
            "schema": "wrong.schema",
            "c_sha": "c" * 40,
            "run_id": "100",
        }
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": digest(canonical(bad_reh_m)),
            "rehearsal_manifest": bad_reh_m,
        })
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))

    def test_val_4_rehearsal_manifest_sha_mismatch_refuses(self):
        bundle_map = check_bun_1()
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        })
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": "wrong_sha" * 5,
            "rehearsal_manifest": {
                "schema": SCHEMA_REHEARSAL_MANIFEST,
                "c_sha": "c" * 40,
                "run_id": "100",
                "checks": [],
                "approvals_observed": [],
            },
        })
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertIn("VAL-4", str(ctx.exception))
    # AUD-1..3
    def test_aud_1_positive(self):
        commit = {"parents": [{"sha": HARNESS_PRESERVED_COMMIT}]}
        check_aud_1(commit, "c" * 40)

    def test_aud_1_missing_commit_parent(self):
        commit = {"parents": [{"sha": "wrong_parent"}]}
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_1(commit, "c" * 40)
        self.assertIn("AUD-1", str(ctx.exception))

    def test_aud_1_multiple_parents_rejected(self):
        commit = {"parents": [{"sha": HARNESS_PRESERVED_COMMIT}, {"sha": "merge_parent"}]}
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_1(commit, "c" * 40)
        self.assertIn("AUD-1", str(ctx.exception))
    def test_aud_1_parent_commit_mismatch(self):
        commit = {"parents": [{"sha": "0" * 40}]}
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_1(commit, "c" * 40)
        self.assertIn("AUD-1", str(ctx.exception))

    def test_aud_2_positive(self):
        files_raw, _, _ = get_audit_files_fixture("c" * 40, "100", {})
        res = check_aud_2(files_raw)
        self.assertIn("audit.json", res)

    def test_aud_2_blob_sha_mismatch(self):
        files_raw, _, _ = get_audit_files_fixture("c" * 40, "100", {})
        files_raw["audit.json"] = (files_raw["audit.json"][0], "wrong_blob_sha")
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_2(files_raw)
        self.assertIn("AUD-2", str(ctx.exception))
    def test_aud_2_missing_file_refuses(self):
        files_raw, _, _ = get_audit_files_fixture("c" * 40, "100", {})
        del files_raw["census-review.md"]
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_2(files_raw)
        self.assertIn("AUD-2", str(ctx.exception))

    def test_aud_2_extra_file_refuses(self):
        files_raw, _, _ = get_audit_files_fixture("c" * 40, "100", {})
        files_raw["extra.txt"] = (b"extra", "0" * 40)
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_2(files_raw)
        self.assertIn("AUD-2", str(ctx.exception))

    def test_aud_3_positive(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        check_aud_3(
            audit_dict,
            "c" * 40,
            "100",
            {},
            files_map["audit.md"]["sha256"],
            files_map["census-review.md"]["sha256"],
        )

    def test_aud_3_non_go_verdict(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["verdict"] = "NO-GO"
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(
                audit_dict,
                "c" * 40,
                "100",
                {},
                files_map["audit.md"]["sha256"],
                files_map["census-review.md"]["sha256"],
            )
        self.assertIn("AUD-3", str(ctx.exception))
    def test_aud_3_schema_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["schema"] = "wrong.schema"
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_repository_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["repository_id"] = "999"
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_c_sha_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["c_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_p_sha_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["p_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_w_sha_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["w_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_h_sha_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["h_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_validation_run_id_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {})
        audit_dict["validation"]["run_id"] = "999"
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    def test_aud_3_validation_artifact_digest_mismatch(self):
        files_raw, files_map, audit_dict = get_audit_files_fixture("c" * 40, "100", {"art1": {"digest": "sha256:" + "1" * 64}})
        audit_dict["validation"]["artifacts"]["art1"] = "sha256:" + "0" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_dict, "c" * 40, "100", {"art1": {"digest": "sha256:" + "1" * 64}}, files_map["audit.md"]["sha256"], files_map["census-review.md"]["sha256"])
        self.assertIn("AUD-3", str(ctx.exception))

    # MAN-1..3
    def test_man_1_positive(self):
        art = {
            "id": "10",
            "name": ARTIFACT_NAME_MANIFEST,
            "workflow_run": {"id": "100", "head_sha": "c" * 40},
            "expired": False,
            "digest": "sha256:" + "a" * 64,
            "created_at": "2026-11-06T00:25:00Z",
        }
        res = check_man_1([art], "10", "100", "c" * 40, "2026-11-06T00:20:00Z", "2026-11-06T00:30:00Z")
        self.assertEqual(res["id"], "10")

    def test_man_1_created_at_outside_window(self):
        art = {
            "id": "10",
            "name": ARTIFACT_NAME_MANIFEST,
            "workflow_run": {"id": "100", "head_sha": "c" * 40},
            "expired": False,
            "digest": "sha256:" + "a" * 64,
            "created_at": "2026-11-06T00:10:00Z",
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_1([art], "10", "100", "c" * 40, "2026-11-06T00:20:00Z", "2026-11-06T00:30:00Z")
        self.assertIn("MAN-1", str(ctx.exception))
    def test_man_1_bare_digest_passes(self):
        art = {
            "id": "10",
            "name": ARTIFACT_NAME_MANIFEST,
            "workflow_run": {"id": "100", "head_sha": "c" * 40},
            "expired": False,
            "digest": "a" * 64,
            "created_at": "2026-11-06T00:25:00Z",
        }
        res = check_man_1([art], "10", "100", "c" * 40, "2026-11-06T00:20:00Z", "2026-11-06T00:30:00Z")
        self.assertEqual(res["id"], "10")

    def test_man_1_missing_timestamps(self):
        art = {
            "id": "10",
            "name": ARTIFACT_NAME_MANIFEST,
            "workflow_run": {"id": "100", "head_sha": "c" * 40},
            "expired": False,
            "digest": "sha256:" + "a" * 64,
            "created_at": "",
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_1([art], "10", "100", "c" * 40, "", "")
        self.assertIn("MAN-1", str(ctx.exception))

    def test_man_2_positive(self):
        content = b'{"hello":"world"}'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", content)
        zip_bytes = buf.getvalue()
        zip_dig = f"sha256:{digest(zip_bytes)}"
        member_sha = digest(content)
        res = check_man_2(zip_bytes, zip_dig, member_sha)
        self.assertEqual(res, content)

    def test_man_2_positive_without_expected_manifest_sha(self):
        content = b'{"hello":"world"}'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", content)
        zip_bytes = buf.getvalue()
        zip_dig = f"sha256:{digest(zip_bytes)}"
        res = check_man_2(zip_bytes, zip_dig, expected_manifest_sha256=None)
        self.assertEqual(res, content)
    def test_man_2_bare_digest_passes(self):
        content = b'{"hello":"world"}'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", content)
        zip_bytes = buf.getvalue()
        bare_zip_dig = digest(zip_bytes)
        member_sha = digest(content)
        res = check_man_2(zip_bytes, bare_zip_dig, member_sha)
        self.assertEqual(res, content)

    def test_man_2_digest_mismatch(self):
        zip_bytes = b"fake-zip"
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_2(zip_bytes, "sha256:" + "0" * 64, "0" * 64)
        self.assertIn("MAN-2", str(ctx.exception))

    def test_man_3_positive(self):
        m1 = {"schema": SCHEMA_MANIFEST, "sources": {"c_sha": "a" * 40}}
        m2 = deepcopy(m1)
        check_man_3(m1, m2)

    def test_man_3_tampering(self):
        base_manifest = {
            "schema": SCHEMA_MANIFEST,
            "approval": {"reviewer_login": "jwaldrip"},
            "repository": {"full_name": PINNED_REPOSITORY},
            "sources": {"c_sha": "a" * 40, "p": {"sha": PINNED_P_SHA}},
        }
        tamper_cases = [
            ("schema", "wrong.schema"),
            ("sources.c_sha", "b" * 40),
            ("approval.reviewer_login", "attacker"),
            ("repository.full_name", "attacker/repo"),
            ("sources.p.sha", "0" * 40),
        ]
        for field_path, bad_val in tamper_cases:
            tampered = deepcopy(base_manifest)
            keys = field_path.split(".")
            d = tampered
            for k in keys[:-1]:
                d = d[k]
            d[keys[-1]] = bad_val
            with self.assertRaises(AuthorizationError) as ctx:
                check_man_3(base_manifest, tampered)
            self.assertIn("MAN-3", str(ctx.exception))

    # APR-1
    def test_apr_1_positive(self):
        apprs = get_approval_fixture("0" * 64)
        res = check_apr_1(apprs, "0" * 64)
        self.assertEqual(res["state"], "approved")

    def test_apr_1_wrong_comment(self):
        apprs = get_approval_fixture("0" * 64)
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "1" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_empty_records(self):
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1([], "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_multiple_records(self):
        apprs = get_approval_fixture("0" * 64)
        apprs.append(deepcopy(apprs[0]))
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_pending_state(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["state"] = "pending"
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_rejected_state(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["state"] = "rejected"
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_wrong_user_id(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["user"]["id"] = 99999
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_wrong_user_login(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["user"]["login"] = "otheruser"
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_wrong_user_type(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["user"]["type"] = "Bot"
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_wrong_env_id(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["environments"][0]["id"] = 99999
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_wrong_env_name(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["environments"][0]["name"] = "production"
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_multiple_environments(self):
        apprs = get_approval_fixture("0" * 64)
        apprs[0]["environments"].append({"id": 1, "name": "other"})
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))

    def test_apr_1_comment_extra_whitespace(self):
        for bad_comment in [
            f" {APPROVAL_COMMENT_PREFIX}{'0' * 64}",
            f"{APPROVAL_COMMENT_PREFIX}{'0' * 64} ",
            f"iyi-strict-authorization-v2  sha256:{'0' * 64}",
            f"{APPROVAL_COMMENT_PREFIX}{'0' * 64}\n",
        ]:
            apprs = get_approval_fixture("0" * 64)
            apprs[0]["comment"] = bad_comment
            with self.assertRaises(AuthorizationError) as ctx:
                check_apr_1(apprs, "0" * 64)
            self.assertIn("APR-1", str(ctx.exception))


class StrictManifestBindingTests(unittest.TestCase):
    """Test StrictManifestBinding read and error handling."""

    def setUp(self):
        self.manifest_data = {
            "schema": SCHEMA_MANIFEST,
            "repository": {"id": PINNED_REPOSITORY_ID, "full_name": PINNED_REPOSITORY},
            "strict_run": {"id": "42086795082", "attempt": "1"},
            "sources": {
                "c_sha": "c" * 40,
                "p": {"sha": PINNED_P_SHA},
                "w": {"sha": PINNED_W_SHA},
            },
        }
        self.manifest_raw = canonical(self.manifest_data)
        self.manifest_sha = digest(self.manifest_raw)

    def test_binding_success(self):
        r, w = os.pipe()
        os.write(w, self.manifest_raw)
        os.close(w)

        binding = read_strict_manifest_binding(
            r,
            self.manifest_sha,
            repository=PINNED_REPOSITORY,
            run_id="42086795082",
            run_attempt="1",
            p_sha=PINNED_P_SHA,
            w_sha=PINNED_W_SHA,
            c_sha="c" * 40,
        )
        self.assertEqual(binding.manifest_sha256, self.manifest_sha)
        self.assertEqual(binding.strict_run_id, "42086795082")
        self.assertEqual(binding.strict_run_attempt, "1")
        self.assertEqual(binding.p_sha, PINNED_P_SHA)
        self.assertEqual(binding.w_sha, PINNED_W_SHA)
        self.assertEqual(binding.c_sha, "c" * 40)

    def test_binding_closed_fd_raises_authorization_error(self):
        r, w = os.pipe()
        os.close(w)
        os.close(r)
        with self.assertRaises(AuthorizationError):
            read_strict_manifest_binding(
                r,
                self.manifest_sha,
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )

    def test_binding_none_fd_raises_authorization_error(self):
        with self.assertRaises(AuthorizationError):
            read_strict_manifest_binding(
                None,
                self.manifest_sha,
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )

    def test_binding_invalid_expected_sha_raises_authorization_error(self):
        r, w = os.pipe()
        os.write(w, self.manifest_raw)
        os.close(w)
        with self.assertRaises(AuthorizationError):
            read_strict_manifest_binding(
                r,
                "not-a-sha256",
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )

    def test_binding_digest_mismatch(self):
        r, w = os.pipe()
        os.write(w, self.manifest_raw)
        os.close(w)

        with self.assertRaises(AuthorizationError) as ctx:
            read_strict_manifest_binding(
                r,
                "0" * 64,
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )
        self.assertIn("manifest digest mismatch", str(ctx.exception))

    def test_binding_p_sha_mismatch(self):
        r, w = os.pipe()
        os.write(w, self.manifest_raw)
        os.close(w)

        with self.assertRaises(AuthorizationError) as ctx:
            read_strict_manifest_binding(
                r,
                self.manifest_sha,
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha="wrong_p" * 5,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )
        self.assertIn("p_sha", str(ctx.exception))

    def test_binding_non_object_repository(self):
        m_data = deepcopy(self.manifest_data)
        m_data["repository"] = None
        raw = canonical(m_data)
        r, w = os.pipe()
        os.write(w, raw)
        os.close(w)
        with self.assertRaises(AuthorizationError) as ctx:
            read_strict_manifest_binding(
                r,
                digest(raw),
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )
        self.assertIn("manifest repository must be an object", str(ctx.exception))

    def test_binding_non_object_strict_run(self):
        m_data = deepcopy(self.manifest_data)
        m_data["strict_run"] = "not-an-object"
        raw = canonical(m_data)
        r, w = os.pipe()
        os.write(w, raw)
        os.close(w)
        with self.assertRaises(AuthorizationError) as ctx:
            read_strict_manifest_binding(
                r,
                digest(raw),
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )
        self.assertIn("manifest strict_run must be an object", str(ctx.exception))

    def test_binding_non_object_sources(self):
        m_data = deepcopy(self.manifest_data)
        m_data["sources"] = None
        raw = canonical(m_data)
        r, w = os.pipe()
        os.write(w, raw)
        os.close(w)
        with self.assertRaises(AuthorizationError) as ctx:
            read_strict_manifest_binding(
                r,
                digest(raw),
                repository=PINNED_REPOSITORY,
                run_id="42086795082",
                run_attempt="1",
                p_sha=PINNED_P_SHA,
                w_sha=PINNED_W_SHA,
                c_sha="c" * 40,
            )
        self.assertIn("manifest sources must be an object", str(ctx.exception))

    def test_binding_non_object_p_or_w(self):
        for sub in ("p", "w"):
            m_data = deepcopy(self.manifest_data)
            m_data["sources"][sub] = None
            raw = canonical(m_data)
            r, w = os.pipe()
            os.write(w, raw)
            os.close(w)
            with self.assertRaises(AuthorizationError) as ctx:
                read_strict_manifest_binding(
                    r,
                    digest(raw),
                    repository=PINNED_REPOSITORY,
                    run_id="42086795082",
                    run_attempt="1",
                    p_sha=PINNED_P_SHA,
                    w_sha=PINNED_W_SHA,
                    c_sha="c" * 40,
                )
            self.assertIn(f"manifest sources.{sub} must be an object", str(ctx.exception))


class IndependentManifestV2Tests(unittest.TestCase):
    """Independent verification of §3.5 manifest v2 structure and keys."""

    def test_independent_manifest_v2_exact_schema_and_keys(self):
        c_sha = "c" * 40
        bundle_map = check_bun_1()
        expected = {
            "schema": SCHEMA_MANIFEST,
            "approval": {
                "comment_format": f"{APPROVAL_COMMENT_PREFIX}<sha256 of these manifest bytes>",
                "environment_id": str(PINNED_ENVIRONMENT_ID),
                "environment_name": PINNED_ENVIRONMENT_NAME,
                "reviewer_user_id": str(PINNED_REVIEWER_ID),
                "reviewer_login": PINNED_REVIEWER_LOGIN,
                "attestation_scope": ATTESTATION_SCOPE,
            },
            "repository": {
                "id": str(PINNED_REPOSITORY_ID),
                "full_name": PINNED_REPOSITORY,
                "visibility": "public",
            },
            "strict_run": {
                "id": "50000000001",
                "attempt": "1",
                "workflow_id": str(PINNED_WORKFLOW_ID),
                "workflow_path": PINNED_WORKFLOW_PATH,
                "workflow_ref": WORKFLOW_REF,
                "event": "workflow_dispatch",
                "head_branch": PINNED_DEPLOY_BRANCH,
                "head_sha": c_sha,
                "html_url": "https://github.com/jwaldrip/iyi/actions/runs/50000000001",
                "actor_id": "43164",
                "triggering_actor_id": "43164",
                "created_at": "2026-11-06T00:20:00Z",
            },
            "prepare_job": {
                "id": "50000000011",
                "name": JOB_NAME_PREPARE,
                "started_at": "2026-11-06T00:20:00Z",
            },
            "inputs": {
                "mode": "strict-chain",
                "evidence_commit": "e" * 40,
            },
            "sources": {
                "c_sha": c_sha,
                "p": {
                    "sha": PINNED_P_SHA,
                    "pr_repository": PINNED_P_PR_REPOSITORY,
                    "pr_number": PINNED_P_PR_NUMBER,
                    "pr_state": PINNED_P_PR_STATE,
                    "head_ref": PINNED_P_HEAD_REF,
                    "head_repo_id": PINNED_P_HEAD_REPO_ID,
                },
                "w": {
                    "sha": PINNED_W_SHA,
                    "merge_base": PINNED_W_MERGE_BASE,
                    "ahead_by": PINNED_W_AHEAD_BY,
                    "behind_by": PINNED_W_BEHIND_BY,
                    "added_count": PINNED_W_ADDED_COUNT,
                    "added_paths_sha256": PINNED_W_ADDED_PATHS_SHA256,
                },
                "h": {
                    "sha": PINNED_H_SHA,
                    "merge_base": PINNED_H_MERGE_BASE,
                    "added_paths": sorted(list(PINNED_H_ADDED_PATHS)),
                },
            },
            "environment": {
                "id": str(PINNED_ENVIRONMENT_ID),
                "name": PINNED_ENVIRONMENT_NAME,
                "can_admins_bypass": False,
                "required_reviewers": [{"type": "User", "id": str(PINNED_REVIEWER_ID)}],
                "prevent_self_review": False,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
                "branch_policies": [{"type": "branch", "name": PINNED_DEPLOY_BRANCH}],
            },
            "deploy_branch": {
                "name": PINNED_DEPLOY_BRANCH,
                "head_sha": c_sha,
                "rules": [
                    {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "deletion"},
                    {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "non_fast_forward"},
                    {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "update"},
                ],
            },
            "actions": PINNED_ACTIONS,
            "bundle": bundle_map,
            "evidence": {
                "validation": {
                    "run_id": "42086795082",
                    "run_attempt": "1",
                    "workflow_id": str(PINNED_WORKFLOW_ID),
                    "event": "push",
                    "head_branch": PINNED_DEPLOY_BRANCH,
                    "head_sha": c_sha,
                    "conclusion": "success",
                    "html_url": "https://github.com/jwaldrip/iyi/actions/runs/42086795082",
                    "artifacts": {
                        "remote-strict-validation-evidence": {"id": "2001", "digest": "sha256:" + "a" * 64},
                        f"supervisor-bundle-{c_sha}": {"id": "2002", "digest": "sha256:" + "b" * 64},
                        ARTIFACT_NAME_RAIL_SUMMARY: {"id": "2003", "digest": "sha256:" + "c" * 64},
                        ARTIFACT_NAME_REHEARSAL_REPORT: {"id": "2004", "digest": "sha256:" + "d" * 64},
                    },
                    "summary_member_sha256": "1" * 64,
                    "rehearsal_member_sha256": "2" * 64,
                },
                "harness": {
                    "run_id": HARNESS_RUN_ID,
                    "run_attempt": HARNESS_RUN_ATTEMPT,
                    "workflow_id": HARNESS_WORKFLOW_ID,
                    "workflow_path": HARNESS_WORKFLOW_PATH,
                    "event": HARNESS_EVENT,
                    "head_branch": HARNESS_HEAD_BRANCH,
                    "head_sha": PINNED_H_SHA,
                    "job_id": HARNESS_JOB_ID,
                    "artifact_id": HARNESS_ARTIFACT_ID,
                    "artifact_name": HARNESS_ARTIFACT_NAME,
                    "artifact_digest": HARNESS_ARTIFACT_DIGEST,
                    "artifact_expires_at": "2026-11-22T02:02:58Z",
                    "preserved_commit": HARNESS_PRESERVED_COMMIT,
                    "preserved_path": HARNESS_PRESERVED_PATH,
                    "preserved_blob": HARNESS_PRESERVED_BLOB,
                    "summary_member": HARNESS_SUMMARY_MEMBER,
                    "summary_member_sha256": HARNESS_SUMMARY_MEMBER_SHA256,
                },
                "audit": {
                    "commit": "e" * 40,
                    "dir": f"proof/strict-audit/{c_sha}",
                    "files": {
                        "audit.json": {"blob": "b1" + "0" * 38, "sha256": "s1" + "0" * 62},
                        "audit.md": {"blob": "b2" + "0" * 38, "sha256": "s2" + "0" * 62},
                        "census-review.md": {"blob": "b3" + "0" * 38, "sha256": "s3" + "0" * 62},
                    },
                    "verdict": "GO",
                    "self_declared": {
                        "reviewer": "independent-agent",
                        "model": "anthropic/claude-opus-5-5",
                        "did_not_implement": True,
                    },
                },
            },
        }

        # Verify top-level keys
        self.assertEqual(
            set(expected.keys()),
            {"schema", "approval", "repository", "strict_run", "prepare_job", "inputs", "sources", "environment", "deploy_branch", "actions", "bundle", "evidence"},
        )
        # Verify approval keys
        self.assertEqual(
            set(expected["approval"].keys()),
            {"comment_format", "environment_id", "environment_name", "reviewer_user_id", "reviewer_login", "attestation_scope"},
        )
        # Verify sources keys
        self.assertEqual(
            set(expected["sources"].keys()),
            {"c_sha", "p", "w", "h"},
        )
        self.assertEqual(
            set(expected["sources"]["p"].keys()),
            {"sha", "pr_repository", "pr_number", "pr_state", "head_ref", "head_repo_id"},
        )
        self.assertEqual(
            set(expected["sources"]["w"].keys()),
            {"sha", "merge_base", "ahead_by", "behind_by", "added_count", "added_paths_sha256"},
        )
        self.assertEqual(
            set(expected["sources"]["h"].keys()),
            {"sha", "merge_base", "added_paths"},
        )
        # Verify evidence keys
        self.assertEqual(
            set(expected["evidence"].keys()),
            {"validation", "harness", "audit"},
        )
        self.assertEqual(
            set(expected["evidence"]["validation"].keys()),
            {"run_id", "run_attempt", "workflow_id", "event", "head_branch", "head_sha", "conclusion", "html_url", "artifacts", "summary_member_sha256", "rehearsal_member_sha256"},
        )
        self.assertEqual(
            set(expected["evidence"]["harness"].keys()),
            {"run_id", "run_attempt", "workflow_id", "workflow_path", "event", "head_branch", "head_sha", "job_id", "artifact_id", "artifact_name", "artifact_digest", "artifact_expires_at", "preserved_commit", "preserved_path", "preserved_blob", "summary_member", "summary_member_sha256"},
        )
        self.assertEqual(
            set(expected["evidence"]["audit"].keys()),
            {"commit", "dir", "files", "verdict", "self_declared"},
        )

        built = build_manifest_v2(
            c_sha=c_sha,
            strict_run=expected["strict_run"],
            prepare_job=expected["prepare_job"],
            inputs=expected["inputs"],
            environment=expected["environment"],
            branch_policies=expected["environment"]["branch_policies"],
            deploy_branch={"name": PINNED_DEPLOY_BRANCH, "head_sha": c_sha},
            branch_rules=expected["deploy_branch"]["rules"],
            bundle_map=bundle_map,
            validation_run={
                "id": 42086795082,
                "workflow_id": int(PINNED_WORKFLOW_ID),
                "html_url": "https://github.com/jwaldrip/iyi/actions/runs/42086795082",
            },
            validation_artifacts=expected["evidence"]["validation"]["artifacts"],
            summary_member_sha256="1" * 64,
            rehearsal_member_sha256="2" * 64,
            evidence_commit="e" * 40,
            audit_files=expected["evidence"]["audit"]["files"],
            audit_json={"self_declared": expected["evidence"]["audit"]["self_declared"]},
            harness_expires_at="2026-11-22T02:02:58Z",
        )
        self.assertEqual(built, expected)


class MockGitHubAPIServer:
    """In-process HTTP mock serving GitHub API fixtures and storage with redirect stripping checks."""

    def __init__(self, c_sha: str = "72c3c7d026369e5f59553d0c6cb208233f545d24"):
        self.c_sha = c_sha
        self.token = "secret-token-test-123"
        self.storage_payloads: Dict[str, bytes] = {}
        self.api_responses: Dict[str, Any] = {}
        self._init_default_data()

        # Build Storage Server
        parent = self
        class StorageHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization"):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Authorization header forbidden on storage endpoint")
                    return
                key = self.path.lstrip("/storage/")
                payload = parent.storage_payloads.get(key)
                if payload is not None:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {parent.token}":
                    self.send_response(401)
                    self.end_headers()
                    return

                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path.lstrip("/")
                query = parsed.query
                full_endpoint = f"{path}?{query}" if query else path

                # Artifact download zip redirect (exact pattern match)
                m_zip = re.match(r"^repos/[^/]+/[^/]+/actions/artifacts/(\d+)/zip$", path)
                if m_zip:
                    art_id = m_zip.group(1)
                    if art_id in parent.storage_payloads:
                        storage_url = f"http://127.0.0.1:{parent.storage_port}/storage/{art_id}"
                        self.send_response(302)
                        self.send_header("Location", storage_url)
                        self.end_headers()
                        return
                    else:
                        self.send_response(404)
                        self.end_headers()
                        return
                # Exact route lookup
                resp = parent.api_responses.get(full_endpoint)
                if resp is None and query:
                    # Match parsed query params
                    qs = urllib.parse.parse_qs(query)
                    for registered_ep, val in parent.api_responses.items():
                        reg_parsed = urllib.parse.urlsplit(registered_ep)
                        if reg_parsed.path == path:
                            reg_qs = urllib.parse.parse_qs(reg_parsed.query)
                            if reg_qs == qs:
                                resp = val
                                break
                elif resp is None and not query:
                    resp = parent.api_responses.get(path)

                if resp is not None:
                    headers = {}
                    body_data = resp
                    if isinstance(resp, tuple) and len(resp) == 2 and isinstance(resp[1], dict):
                        body_data, headers = resp
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    for hk, hv in headers.items():
                        self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.write(canonical(body_data))
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        self.storage_server = HTTPServer(("127.0.0.1", 0), StorageHandler)
        self.storage_port = self.storage_server.server_port
        self.storage_thread = threading.Thread(target=self.storage_server.serve_forever, daemon=True)
        self.storage_thread.start()

        self.api_server = HTTPServer(("127.0.0.1", 0), APIHandler)
        self.api_port = self.api_server.server_port
        self.api_thread = threading.Thread(target=self.api_server.serve_forever, daemon=True)
        self.api_thread.start()

    def _init_default_data(self):
        c_sha = self.c_sha
        strict_run_id = 50000000001
        val_run_id = 42086795082
        prep_job_id = 50000000011
        strict_job_id = 50000000012
        val_rehearsal_job_id = 1007
        bundle_map = check_bun_1()

        # Build summary and rehearsal zips
        summary_dict = {
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": c_sha,
            "run_id": str(val_run_id),
            "run_attempt": "1",
            "dist": bundle_map,
            "actions": PINNED_ACTIONS,
            "workflow_structure": "PASS",
            "controller_suite": "PASS",
            "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
        }
        summary_raw = canonical(summary_dict)
        sbuf = io.BytesIO()
        with zipfile.ZipFile(sbuf, "w") as zf:
            zf.writestr("rail-validation-summary.json", summary_raw)
        summary_zip_bytes = sbuf.getvalue()
        summary_zip_dig = f"sha256:{digest(summary_zip_bytes)}"

        rehearsal_manifest_dict = {
            "schema": SCHEMA_REHEARSAL_MANIFEST,
            "c_sha": c_sha,
            "run_id": str(val_run_id),
            "event": "push",
            "branch": PINNED_DEPLOY_BRANCH,
            "sources": {
                "c_sha": c_sha,
                "p_sha": PINNED_P_SHA,
                "w_sha": PINNED_W_SHA,
                "h_sha": PINNED_H_SHA,
            },
            "bundle": bundle_map,
            "actions": PINNED_ACTIONS,
            "branch_rules": [
                {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "deletion"},
                {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "non_fast_forward"},
                {"ruleset_id": "65877824", "ruleset_source": "jwaldrip/iyi", "ruleset_source_type": "Repository", "type": "update"},
            ],
            "harness": {
                "run_id": HARNESS_RUN_ID,
                "artifact_id": HARNESS_ARTIFACT_ID,
                "digest": HARNESS_ARTIFACT_DIGEST,
                "expires_at": "2026-11-22T02:02:58Z",
            },
        }
        rehearsal_manifest_raw = canonical(rehearsal_manifest_dict)
        rehearsal_manifest_sha = digest(rehearsal_manifest_raw)

        rehearsal_dict = {
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": c_sha,
            "run_id": str(val_run_id),
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": rehearsal_manifest_sha,
            "rehearsal_manifest": rehearsal_manifest_dict,
        }
        rehearsal_raw = canonical(rehearsal_dict)
        rbuf = io.BytesIO()
        with zipfile.ZipFile(rbuf, "w") as zf:
            zf.writestr("rail-rehearsal-report.json", rehearsal_raw)
        rehearsal_zip_bytes = rbuf.getvalue()
        rehearsal_zip_dig = f"sha256:{digest(rehearsal_zip_bytes)}"

        # Bundle zip
        bbuf = io.BytesIO()
        with zipfile.ZipFile(bbuf, "w") as zf:
            for k, v in bundle_map.items():
                zf.writestr(k, b"bundle-content")
        bundle_zip_bytes = bbuf.getvalue()
        bundle_zip_dig = f"sha256:{digest(bundle_zip_bytes)}"

        # Storage payloads
        import base64
        harness_zip_bytes = base64.b64decode(load_fixture("blob_95962d09.json")["content"].replace("\n", ""))
        self.storage_payloads["13600255503"] = harness_zip_bytes
        self.storage_payloads["2002"] = bundle_zip_bytes
        self.storage_payloads["2003"] = summary_zip_bytes
        self.storage_payloads["2004"] = rehearsal_zip_bytes

        val_arts = get_val_artifacts_fixture(val_run_id, c_sha, summary_zip_dig, rehearsal_zip_dig, bundle_digest=bundle_zip_dig)
        val_artifacts_map = {
            "remote-strict-validation-evidence": {"id": "2001", "digest": "sha256:" + "a" * 64},
            f"supervisor-bundle-{c_sha}": {"id": "2002", "digest": bundle_zip_dig},
            ARTIFACT_NAME_RAIL_SUMMARY: {"id": "2003", "digest": summary_zip_dig},
            ARTIFACT_NAME_REHEARSAL_REPORT: {"id": "2004", "digest": rehearsal_zip_dig},
        }

        # Audit files
        evidence_commit = "e" * 40
        files_raw, files_map, audit_dict = get_audit_files_fixture(c_sha, str(val_run_id), val_artifacts_map)

        # Reconstructed manifest for prepare/authorize
        strict_run = get_strict_run_in_progress_fixture(head_sha=c_sha, run_id=strict_run_id)
        prep_job = {
            "id": prep_job_id,
            "name": JOB_NAME_PREPARE,
            "started_at": "2026-11-06T00:20:00Z",
            "completed_at": "2026-11-06T00:24:00Z",
            "runner_name": "GitHub Actions 1",
            "status": "completed",
            "conclusion": "success",
            "head_sha": c_sha,
            "run_id": strict_run_id,
            "run_attempt": 1,
            "workflow_name": PINNED_WORKFLOW_NAME,
        }
        strict_job = {
            "id": strict_job_id,
            "name": JOB_NAME_STRICT,
            "status": "in_progress",
            "conclusion": None,
            "runner_name": "GitHub Actions 1",
            "head_sha": c_sha,
            "run_id": strict_run_id,
            "run_attempt": 1,
            "workflow_name": PINNED_WORKFLOW_NAME,
        }
        val_rehearsal_job = {
            "id": val_rehearsal_job_id,
            "name": JOB_NAME_REHEARSAL,
            "workflow_name": PINNED_WORKFLOW_NAME,
            "head_sha": c_sha,
            "status": "in_progress",
            "conclusion": None,
            "runner_name": "GitHub Actions 7",
            "run_id": val_run_id,
            "run_attempt": 1,
        }
        env_data = get_environment_fixture()
        branch_policies = check_env_2(get_branch_policies_fixture()["branch_policies"])
        branch_data = get_branch_deploy_fixture()
        branch_data["commit"]["sha"] = c_sha
        branch_rules = check_brn_2(get_rules_branch_deploy_fixture(active=True), require_active=True)
        run_info = check_run_1(strict_run, c_sha)
        prep_job_info = check_job_1(prep_job, strict_run_id, JOB_NAME_PREPARE, c_sha, runner_name="GitHub Actions 1")
        val_run = {
            "id": val_run_id,
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "path": PINNED_WORKFLOW_PATH,
            "head_branch": PINNED_DEPLOY_BRANCH,
            "head_sha": c_sha,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "html_url": f"https://github.com/{PINNED_REPOSITORY}/actions/runs/{val_run_id}",
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
            "head_repository": {"id": int(PINNED_REPOSITORY_ID)},
        }

        manifest_dict = build_manifest_v2(
            c_sha=c_sha,
            strict_run=run_info,
            prepare_job=prep_job_info,
            inputs={"mode": "strict-chain", "evidence_commit": evidence_commit},
            environment=env_data,
            branch_policies=branch_policies,
            deploy_branch=branch_data,
            branch_rules=branch_rules,
            bundle_map=bundle_map,
            validation_run=val_run,
            validation_artifacts=val_artifacts_map,
            summary_member_sha256=digest(summary_raw),
            rehearsal_member_sha256=digest(rehearsal_raw),
            evidence_commit=evidence_commit,
            audit_files=files_map,
            audit_json=audit_dict,
            harness_expires_at="2026-11-22T02:02:58Z",
        )
        manifest_raw = canonical(manifest_dict)
        self.manifest_sha = digest(manifest_raw)
        self.manifest_dict = manifest_dict

        # Manifest zip artifact
        mbuf = io.BytesIO()
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", manifest_raw)
        manifest_zip_bytes = mbuf.getvalue()
        self.storage_payloads["13600255999"] = manifest_zip_bytes
        self.manifest_zip_digest = f"sha256:{digest(manifest_zip_bytes)}"

        # Wire API endpoints with exact routes & query parameters
        self.api_responses = {
            f"repos/{PINNED_REPOSITORY}": get_repo_fixture(),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}": strict_run,
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}": val_run,
            f"repos/{PINNED_REPOSITORY}/actions/runs?head_sha={c_sha}": {
                "workflow_runs": [val_run]
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}/attempts/1/jobs": {
                "jobs": [
                    prep_job,
                    strict_job,
                    {
                        "id": 50000000013,
                        "name": JOB_NAME_REHEARSAL,
                        "status": "completed",
                        "conclusion": "skipped",
                        "runner_name": "GitHub Actions 1",
                        "head_sha": c_sha,
                        "run_id": strict_run_id,
                        "run_attempt": 1,
                        "workflow_name": PINNED_WORKFLOW_NAME,
                    },
                ]
            },
            f"repos/{PINNED_REPOSITORY}/actions/jobs/{prep_job_id}": prep_job,
            f"repos/{PINNED_REPOSITORY}/actions/jobs/{strict_job_id}": strict_job,
            f"repos/{PINNED_REPOSITORY}/actions/jobs/{val_rehearsal_job_id}": val_rehearsal_job,
            f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}": env_data,
            f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies": {"branch_policies": branch_policies},
            f"repos/{PINNED_REPOSITORY}/branches/{PINNED_DEPLOY_BRANCH}": branch_data,
            f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}": get_rules_branch_deploy_fixture(active=True),
            f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}": get_pull_147_fixture(),
            f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}": get_compare_pw_fixture(),
            f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}": get_compare_wh_fixture(),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}": load_fixture("run_42429518284.json"),
            f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}": load_fixture("job_128575084391.json"),
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}": load_fixture("artifact_13600255503.json"),
            f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}?ref={HARNESS_PRESERVED_COMMIT}": load_fixture("contents_harness_audit_zip.json"),
            f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}": load_fixture("blob_95962d09.json"),
            f"repos/{PINNED_REPOSITORY}/actions/workflows/{PINNED_WORKFLOW_ID}/runs?head_sha={c_sha}&branch={PINNED_DEPLOY_BRANCH}": {
                "workflow_runs": [val_run]
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/attempts/1/jobs": {
                "jobs": get_val_jobs_fixture(val_run_id, c_sha)
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/artifacts": {
                "artifacts": val_arts
            },
            f"repos/{PINNED_REPOSITORY}/branches/proof/strict-evidence-{c_sha[:12]}-20261107": get_evidence_branch_fixture(c_sha, evidence_commit),
            f"repos/{PINNED_REPOSITORY}/commits/{evidence_commit}": {
                "sha": evidence_commit,
                "parents": [{"sha": HARNESS_PRESERVED_COMMIT}],
            },
            f"repos/{PINNED_REPOSITORY}/contents/proof/strict-audit/{c_sha}?ref={evidence_commit}": [
                {"name": "audit.json", "sha": files_map["audit.json"]["blob"]},
                {"name": "audit.md", "sha": files_map["audit.md"]["blob"]},
                {"name": "census-review.md", "sha": files_map["census-review.md"]["blob"]},
            ],
            f"repos/{PINNED_REPOSITORY}/contents/proof/strict-audit/{c_sha}/audit.json": {
                "name": "audit.json",
                "sha": files_map["audit.json"]["blob"],
            },
            f"repos/{PINNED_REPOSITORY}/contents/proof/strict-audit/{c_sha}/audit.md": {
                "name": "audit.md",
                "sha": files_map["audit.md"]["blob"],
            },
            f"repos/{PINNED_REPOSITORY}/contents/proof/strict-audit/{c_sha}/census-review.md": {
                "name": "census-review.md",
                "sha": files_map["census-review.md"]["blob"],
            },
            f"repos/{PINNED_REPOSITORY}/git/blobs/{files_map['audit.json']['blob']}": {
                "sha": files_map["audit.json"]["blob"],
                "content": base64.b64encode(files_raw["audit.json"][0]).decode("ascii"),
            },
            f"repos/{PINNED_REPOSITORY}/git/blobs/{files_map['audit.md']['blob']}": {
                "sha": files_map["audit.md"]["blob"],
                "content": base64.b64encode(files_raw["audit.md"][0]).decode("ascii"),
            },
            f"repos/{PINNED_REPOSITORY}/git/blobs/{files_map['census-review.md']['blob']}": {
                "sha": files_map["census-review.md"]["blob"],
                "content": base64.b64encode(files_raw["census-review.md"][0]).decode("ascii"),
            },
            f"repos/{PINNED_REPOSITORY}/check-runs/{strict_job_id}": get_check_run_deployment_fixture(
                strict_job_id, strict_run_id, c_sha, deployment_id=6086087299
            ),
            f"repos/{PINNED_REPOSITORY}/check-runs/{val_rehearsal_job_id}": {
                "id": val_rehearsal_job_id,
                "deployment": None,
            },
            f"repos/{PINNED_REPOSITORY}/deployments/6086087299": get_deployment_fixture(6086087299, c_sha),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}/artifacts": {
                "artifacts": [
                    get_manifest_artifact_fixture(13600255999, strict_run_id, c_sha, digest(manifest_zip_bytes), created_at="2026-11-06T00:22:00Z")
                ]
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}/approvals": get_approval_fixture(self.manifest_sha),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/approvals": [],
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}/pending_deployments": [
                {
                    "environment": {"id": PINNED_ENVIRONMENT_ID, "name": PINNED_ENVIRONMENT_NAME},
                    "reviewers": [{"type": "User", "reviewer": {"id": PINNED_REVIEWER_ID}}],
                }
            ],
        }

    def client(self) -> GitHubAPIClient:
        return GitHubAPIClient(token=self.token, base_url=f"http://127.0.0.1:{self.api_port}")

    def shutdown(self):
        self.api_server.shutdown()
        self.storage_server.shutdown()


class FullLoopbackSubcommandCLITests(unittest.TestCase):
    """Test actual CLI subcommands using the full loopback GitHub API server."""

    @classmethod
    def setUpClass(cls):
        cls.c_sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("ascii").strip()
        cls.mock_server = MockGitHubAPIServer(c_sha=cls.c_sha)

    @classmethod
    def tearDownClass(cls):
        cls.mock_server.shutdown()

    def setUp(self):
        self.api_factory = lambda token: self.mock_server.client()
        self.td = tempfile.mkdtemp()
        self.event_path = os.path.join(self.td, "event.json")
        with open(self.event_path, "w", encoding="utf-8") as f:
            json.dump({"inputs": {"mode": "strict-chain", "evidence_commit": "e" * 40}}, f)

        self.common_env = {
            "GITHUB_REPOSITORY": PINNED_REPOSITORY,
            "GITHUB_REPOSITORY_ID": PINNED_REPOSITORY_ID,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": self.c_sha,
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "50000000001",
            "JOB_CHECK_RUN_ID": "50000000011",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_NAME": "GitHub Actions 1",
            "GITHUB_EVENT_PATH": self.event_path,
        }

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def test_cmd_prepare_positive(self):
        env = dict(self.common_env)
        env["GITHUB_JOB"] = JOB_KEY_PREPARE
        out_dir = os.path.join(self.td, "prepare_out")
        code = main(
            ["prepare", "--out-dir", out_dir],
            environ=env,
            api_factory=self.api_factory,
        )
        self.assertEqual(code, 0)
        manifest_file = os.path.join(out_dir, "manifest.json")
        self.assertTrue(os.path.isfile(manifest_file))
        with open(manifest_file, "rb") as f:
            m = parse(f.read())
        self.assertEqual(m["schema"], SCHEMA_MANIFEST)

    def test_cmd_authorize_positive(self):
        env = dict(self.common_env)
        env["GITHUB_JOB"] = JOB_KEY_STRICT
        env["JOB_CHECK_RUN_ID"] = "50000000012"
        env["PREPARE_JOB_ID"] = "50000000011"
        env["PREPARE_ARTIFACT_ID"] = "13600255999"
        env["PREPARE_MANIFEST_SHA256"] = self.mock_server.manifest_sha

        out_dir = os.path.join(self.td, "auth_out")
        code = main(
            ["authorize", "--out-dir", out_dir],
            environ=env,
            api_factory=self.api_factory,
        )
        self.assertEqual(code, 0)
        ver_file = os.path.join(out_dir, "verification.json")
        self.assertTrue(os.path.isfile(ver_file))
        with open(ver_file, "rb") as f:
            v = parse(f.read())
        self.assertEqual(v["decision"], "AUTHORIZED")
        self.assertEqual(v["manifest_sha256"], self.mock_server.manifest_sha)
        self.assertTrue(len(v["checks"]) > 0)

    def test_cmd_authorize_refusal_leaves_durable_verification_record(self):
        env = dict(self.common_env)
        env["GITHUB_JOB"] = JOB_KEY_STRICT
        env["JOB_CHECK_RUN_ID"] = "50000000012"
        env["PREPARE_JOB_ID"] = "50000000011"
        env["PREPARE_ARTIFACT_ID"] = "13600255999"
        env["PREPARE_MANIFEST_SHA256"] = "wrong" * 12 + "0000"

        out_dir = os.path.join(self.td, "auth_refuse_out")
        code = main(
            ["authorize", "--out-dir", out_dir],
            environ=env,
            api_factory=self.api_factory,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        ver_file = os.path.join(out_dir, "verification.json")
        self.assertTrue(os.path.isfile(ver_file))
        with open(ver_file, "rb") as f:
            v = parse(f.read())
        self.assertEqual(v["decision"], "REFUSED")
        self.assertEqual(v["failed_check"], "MAN-2")

    def test_cmd_publish_positive(self):
        manifest_file = os.path.join(self.td, "pub_manifest.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":1}')
        dig = digest(b'{"test":1}')

        summary_file = os.path.join(self.td, "summary.md")
        # ARTIFACT_DIGEST is the bare 64-hex string emitted by upload-artifact@v4
        bare_digest = "f" * 64
        env = {
            "MANIFEST_SHA256": dig,
            "ARTIFACT_ID": "12345",
            "ARTIFACT_URL": "https://github.com/.../artifacts/12345",
            "ARTIFACT_DIGEST": bare_digest,
            "GITHUB_STEP_SUMMARY": summary_file,
        }
        code = main(["publish", "--manifest", manifest_file], environ=env)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(summary_file))
        with open(summary_file, "r", encoding="utf-8") as f:
            s_content = f.read()
        self.assertIn(dig, s_content)
        self.assertIn("12345", s_content)
        self.assertIn(f"sha256:{bare_digest}", s_content)

    def test_cmd_publish_positive_prefixed(self):
        manifest_file = os.path.join(self.td, "pub_manifest_p.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":2}')
        dig = digest(b'{"test":2}')

        summary_file = os.path.join(self.td, "summary_p.md")
        zip_digest = "sha256:" + "e" * 64
        env = {
            "MANIFEST_SHA256": dig,
            "ARTIFACT_ID": "12346",
            "ARTIFACT_URL": "https://github.com/.../artifacts/12346",
            "ARTIFACT_DIGEST": zip_digest,
            "GITHUB_STEP_SUMMARY": summary_file,
        }
        code = main(["publish", "--manifest", manifest_file], environ=env)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(summary_file))
        with open(summary_file, "r", encoding="utf-8") as f:
            s_content = f.read()
        self.assertIn(dig, s_content)
        self.assertIn(zip_digest, s_content)

    def test_cmd_publish_invalid_digest_format_refuses(self):
        manifest_file = os.path.join(self.td, "pub_manifest.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":1}')
        dig = digest(b'{"test":1}')

        env = {
            "MANIFEST_SHA256": dig,
            "ARTIFACT_ID": "12345",
            "ARTIFACT_URL": "https://github.com/.../artifacts/12345",
            "ARTIFACT_DIGEST": "invalid-not-sha256",
        }
        code = main(["publish", "--manifest", manifest_file], environ=env)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_publish_missing_env_refuses(self):
        manifest_file = os.path.join(self.td, "pub_manifest.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":1}')
        code = main(["publish", "--manifest", manifest_file], environ={})
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_publish_summary_write_error_refuses(self):
        manifest_file = os.path.join(self.td, "pub_manifest_err.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":3}')
        dig = digest(b'{"test":3}')
        env = {
            "MANIFEST_SHA256": dig,
            "ARTIFACT_ID": "12347",
            "ARTIFACT_URL": "https://github.com/.../artifacts/12347",
            "ARTIFACT_DIGEST": "a" * 64,
            "GITHUB_STEP_SUMMARY": self.td,  # Directory, writing raises OSError
        }
        code = main(["publish", "--manifest", manifest_file], environ=env)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_prepare_then_authorize_end_to_end(self):
        # 1. Run prepare
        env_prep = dict(self.common_env)
        env_prep["GITHUB_JOB"] = JOB_KEY_PREPARE
        prep_out = os.path.join(self.td, "prep_e2e_out")
        code_prep = main(["prepare", "--out-dir", prep_out], environ=env_prep, api_factory=self.api_factory)
        self.assertEqual(code_prep, 0)

        manifest_file = os.path.join(prep_out, "manifest.json")
        self.assertTrue(os.path.isfile(manifest_file))
        with open(manifest_file, "rb") as f:
            manifest_bytes = f.read()
        manifest_d = digest(manifest_bytes)

        # 2. Package manifest into zip and update mock server storage
        art_id = "555555"
        mbuf = io.BytesIO()
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", manifest_bytes)
        zip_bytes = mbuf.getvalue()
        zip_dig = f"sha256:{digest(zip_bytes)}"

        self.mock_server.storage_payloads[art_id] = zip_bytes
        self.mock_server.api_responses[f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/artifacts"] = {
            "artifacts": [
                get_manifest_artifact_fixture(int(art_id), 50000000001, self.c_sha, digest(zip_bytes), created_at="2026-11-06T00:22:00Z")
            ]
        }
        self.mock_server.api_responses[f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/approvals"] = get_approval_fixture(manifest_d)

        # 3. Run authorize consuming this exact manifest
        env_auth = dict(self.common_env)
        env_auth["GITHUB_JOB"] = JOB_KEY_STRICT
        env_auth["JOB_CHECK_RUN_ID"] = "50000000012"
        env_auth["PREPARE_JOB_ID"] = "50000000011"
        env_auth["PREPARE_ARTIFACT_ID"] = art_id
        env_auth["PREPARE_MANIFEST_SHA256"] = manifest_d

        auth_out = os.path.join(self.td, "auth_e2e_out")
        code_auth = main(["authorize", "--out-dir", auth_out], environ=env_auth, api_factory=self.api_factory)
        self.assertEqual(code_auth, 0)

        ver_file = os.path.join(auth_out, "verification.json")
        self.assertTrue(os.path.isfile(ver_file))
        with open(ver_file, "rb") as f:
            ver = parse(f.read())
        self.assertEqual(ver["decision"], "AUTHORIZED")
        self.assertEqual(ver["manifest_sha256"], manifest_d)

    def test_cmd_rail_summary(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)

        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)

        refusal_path = os.path.join(self.td, "refusal.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            refusal_report_data = {
                "schema": SCHEMA_REFUSAL_REPORT,
                "status": "PASS",
                "controller_suite": "PASS",
                "c_sha": self.c_sha,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {
                        "status": "REFUSED",
                        "exit_code": AUTH_REFUSED_EXIT_CODE,
                        "diagnostic": "missing required manifest fd 5",
                    },
                    "manifest_digest_mismatch": {
                        "status": "REFUSED",
                        "exit_code": AUTH_REFUSED_EXIT_CODE,
                        "diagnostic": "manifest digest mismatch: expected sha256:000, got sha256:111",
                    },
                    "strict_run_id_mismatch": {
                        "status": "REFUSED",
                        "exit_code": AUTH_REFUSED_EXIT_CODE,
                        "diagnostic": "strict run id mismatch: expected 42086795082, got 999",
                    },
                    "invalid_p_sha": {
                        "status": "REFUSED",
                        "exit_code": AUTH_REFUSED_EXIT_CODE,
                        "diagnostic": "invalid P commit SHA: expected 180f14f91c829b25362a5ed34b20847f3ac2db77, got 0000000000000000000000000000000000000000",
                    },
                },
            }
            json.dump(refusal_report_data, f)

        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            [
                "rail-summary",
                "--out", out_path,
                "--pins-report", pins_path,
                "--structure-report", struct_path,
                "--refusal-report", refusal_path,
            ],
            environ=env,
        )
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(out_path))
        with open(out_path, "rb") as f:
            s_raw = f.read()
            s = parse(s_raw)
        self.assertEqual(s["status"], "PASS")
        self.assertEqual(s["workflow_structure"], "PASS")
        self.assertEqual(s["controller_suite"], "PASS")
        self.assertEqual(s["strict_refusal_controls"], PINNED_REFUSAL_CONTROLS)

        # Feed rail-summary output directly into check_val_4 to prove compatibility
        bundle_map = check_bun_1()
        reh_m = {
            "schema": SCHEMA_REHEARSAL_MANIFEST,
            "c_sha": self.c_sha,
            "run_id": "42086795082",
            "checks": [],
            "approvals_observed": [],
        }
        reh_m_raw = canonical(reh_m)
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": self.c_sha,
            "run_id": "42086795082",
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": digest(reh_m_raw),
            "rehearsal_manifest": reh_m,
        })
        s_sha, r_sha = check_val_4(s_raw, rehearsal_raw, bundle_map, "42086795082", self.c_sha)
        self.assertEqual(s_sha, digest(s_raw))

    def test_cmd_rail_summary_missing_refusal_report_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path],
            environ=env,
        )
        self.assertEqual(code, USAGE_ERROR_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_failed_status_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_failed.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "FAIL",
                "controller_suite": "FAIL",
                "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
    def test_cmd_rail_summary_refusal_report_contradictory_status_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_contradictory.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "FAIL",
                "c_sha": self.c_sha,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "manifest_digest_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "strict_run_id_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "invalid_p_sha": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                },
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_missing_case_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_missing_case.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "c_sha": self.c_sha,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "manifest_digest_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "strict_run_id_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    # invalid_p_sha missing!
                },
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_c_sha_mismatch_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_c_sha_mismatch.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "c_sha": "0" * 40,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "manifest_digest_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "strict_run_id_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "invalid_p_sha": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                },
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_unrefused_case_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_unrefused.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "c_sha": self.c_sha,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "manifest_digest_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "strict_run_id_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "invalid_p_sha": {"status": "UNREFUSED", "exit_code": 0, "diagnostic": "succeeded unexpectedly"},
                },
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_missing_diagnostic_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_no_diag.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "c_sha": self.c_sha,
                "run_id": "42086795082",
                "run_attempt": "1",
                "cases": {
                    "missing_manifest_fd": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "manifest_digest_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "strict_run_id_mismatch": {"status": "REFUSED", "exit_code": 5, "diagnostic": "err"},
                    "invalid_p_sha": {"status": "REFUSED", "exit_code": 5, "diagnostic": ""},
                },
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_refusal_report_controls_mismatch_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
        refusal_path = os.path.join(self.td, "refusal_bad_ctrl.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "strict_refusal_controls": ["wrong-control"],
            }, f)
        out_path = os.path.join(self.td, "rail_summary.json")
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        code = main(
            ["rail-summary", "--out", out_path, "--pins-report", pins_path, "--structure-report", struct_path, "--refusal-report", refusal_path],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary_missing_run_attempt_refuses(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)

        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)

        refusal_path = os.path.join(self.td, "refusal_missing_attempt.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PASS",
                "controller_suite": "PASS",
                "strict_refusal_controls": PINNED_REFUSAL_CONTROLS,
            }, f)

        out_path = os.path.join(self.td, "rail_summary.json")
        # Missing GITHUB_RUN_ATTEMPT
        env = {
            "GITHUB_SHA": self.c_sha,
            "GITHUB_RUN_ID": "42086795082",
        }
        code = main(
            [
                "rail-summary",
                "--out", out_path,
                "--pins-report", pins_path,
                "--structure-report", struct_path,
                "--refusal-report", refusal_path,
            ],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
    def test_cmd_rehearse_push_positive(self):
        val_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/42086795082"
        orig_val_status = self.mock_server.api_responses[val_ep]["status"]
        self.mock_server.api_responses[val_ep]["status"] = "in_progress"

        try:
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
            env["GITHUB_EVENT_NAME"] = "push"
            env["GITHUB_RUN_ID"] = "42086795082"
            env["JOB_CHECK_RUN_ID"] = "1007"
            env["RUNNER_NAME"] = "GitHub Actions 7"
            env["GITHUB_REF_NAME"] = PINNED_DEPLOY_BRANCH
            report_file = os.path.join(self.td, "rehearsal_report.json")

            code = main(
                ["rehearse", "--report", report_file],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(report_file))
            with open(report_file, "rb") as f:
                r = parse(f.read())
            self.assertEqual(r["status"], "REHEARSAL_PASS")
            self.assertTrue(len(r["checks"]) > 0)
            self.assertIn("rehearsal_manifest", r)
            self.assertTrue(os.path.isfile(os.path.join(self.td, "rehearsal-manifest.json")))
        finally:
            self.mock_server.api_responses[val_ep]["status"] = orig_val_status

    def test_cmd_rehearse_dispatch_validation_only(self):
        val_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/42086795082"
        orig_val_status = self.mock_server.api_responses[val_ep]["status"]
        orig_val_event = self.mock_server.api_responses[val_ep]["event"]
        self.mock_server.api_responses[val_ep]["status"] = "in_progress"
        self.mock_server.api_responses[val_ep]["event"] = "workflow_dispatch"

        try:
            dispatch_event = os.path.join(self.td, "dispatch_event.json")
            with open(dispatch_event, "w", encoding="utf-8") as f:
                json.dump({"inputs": {"mode": "validation-only"}}, f)

            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
            env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
            env["GITHUB_RUN_ID"] = "42086795082"
            env["JOB_CHECK_RUN_ID"] = "1007"
            env["RUNNER_NAME"] = "GitHub Actions 7"
            env["GITHUB_REF_NAME"] = PINNED_DEPLOY_BRANCH
            env["GITHUB_EVENT_PATH"] = dispatch_event
            report_file = os.path.join(self.td, "rehearsal_report_dispatch.json")

            code = main(
                ["rehearse", "--report", report_file],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(report_file))
        finally:
            self.mock_server.api_responses[val_ep]["status"] = orig_val_status
            self.mock_server.api_responses[val_ep]["event"] = orig_val_event

    def test_cmd_rehearse_dispatch_invalid_mode_refuses(self):
        val_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/42086795082"
        orig_val_status = self.mock_server.api_responses[val_ep]["status"]
        orig_val_event = self.mock_server.api_responses[val_ep]["event"]
        self.mock_server.api_responses[val_ep]["status"] = "in_progress"
        self.mock_server.api_responses[val_ep]["event"] = "workflow_dispatch"

        try:
            dispatch_event = os.path.join(self.td, "dispatch_event_bad.json")
            with open(dispatch_event, "w", encoding="utf-8") as f:
                json.dump({"inputs": {"mode": "invalid-mode"}}, f)

            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
            env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
            env["GITHUB_RUN_ID"] = "42086795082"
            env["JOB_CHECK_RUN_ID"] = "1007"
            env["RUNNER_NAME"] = "GitHub Actions 7"
            env["GITHUB_REF_NAME"] = PINNED_DEPLOY_BRANCH
            env["GITHUB_EVENT_PATH"] = dispatch_event
            report_file = os.path.join(self.td, "rehearsal_report_bad_mode.json")

            code = main(
                ["rehearse", "--report", report_file],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[val_ep]["status"] = orig_val_status
            self.mock_server.api_responses[val_ep]["event"] = orig_val_event

    def test_cmd_rehearse_event_name_mismatch_refuses(self):
        val_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/42086795082"
        orig_val_status = self.mock_server.api_responses[val_ep]["status"]
        orig_val_event = self.mock_server.api_responses[val_ep]["event"]
        self.mock_server.api_responses[val_ep]["status"] = "in_progress"
        self.mock_server.api_responses[val_ep]["event"] = "workflow_dispatch"

        try:
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
            env["GITHUB_EVENT_NAME"] = "push"  # Mismatch with run API event (workflow_dispatch)
            env["GITHUB_RUN_ID"] = "42086795082"
            env["JOB_CHECK_RUN_ID"] = "1007"
            env["RUNNER_NAME"] = "GitHub Actions 7"
            env["GITHUB_REF_NAME"] = PINNED_DEPLOY_BRANCH
            report_file = os.path.join(self.td, "rehearsal_report_mismatch.json")

            code = main(
                ["rehearse", "--report", report_file],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[val_ep]["status"] = orig_val_status
            self.mock_server.api_responses[val_ep]["event"] = orig_val_event
    def test_cmd_rehearse_missing_ref_name_refuses(self):
        env = dict(self.common_env)
        env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
        env["GITHUB_EVENT_NAME"] = "push"
        env["GITHUB_RUN_ID"] = "42086795082"
        env["JOB_CHECK_RUN_ID"] = "1007"
        env["RUNNER_NAME"] = "GitHub Actions 7"
        env.pop("GITHUB_REF_NAME", None)
        report_file = os.path.join(self.td, "rehearsal_report_noref.json")

        code = main(
            ["rehearse", "--report", report_file],
            environ=env,
            api_factory=self.api_factory,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rehearse_status_completed_refuses(self):
        val_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/42086795082"
        orig_val_status = self.mock_server.api_responses[val_ep]["status"]
        self.mock_server.api_responses[val_ep]["status"] = "completed"

        try:
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
            env["GITHUB_EVENT_NAME"] = "push"
            env["GITHUB_RUN_ID"] = "42086795082"
            env["JOB_CHECK_RUN_ID"] = "1007"
            env["RUNNER_NAME"] = "GitHub Actions 7"
            env["GITHUB_REF_NAME"] = PINNED_DEPLOY_BRANCH
            report_file = os.path.join(self.td, "rehearsal_report_compl.json")

            code = main(
                ["rehearse", "--report", report_file],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[val_ep]["status"] = orig_val_status

    def test_cmd_inspect_positive(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        try:
            code = main(
                ["inspect", "--run-id", "50000000001"],
                environ=self.common_env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, 0)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status

    def test_cmd_inspect_status_in_progress_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "in_progress"

        try:
            code = main(
                ["inspect", "--run-id", "50000000001"],
                environ=self.common_env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status

    def test_cmd_inspect_missing_pending_deployment_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        dep_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/pending_deployments"
        orig_deps = self.mock_server.api_responses[dep_ep]
        self.mock_server.api_responses[dep_ep] = []

        try:
            code = main(
                ["inspect", "--run-id", "50000000001"],
                environ=self.common_env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.api_responses[dep_ep] = orig_deps

    def test_cmd_inspect_wrong_reviewer_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        dep_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/pending_deployments"
        orig_deps = self.mock_server.api_responses[dep_ep]
        self.mock_server.api_responses[dep_ep] = [
            {
                "environment": {"id": PINNED_ENVIRONMENT_ID, "name": PINNED_ENVIRONMENT_NAME},
                "reviewers": [{"type": "User", "reviewer": {"id": "99999"}}],
            }
        ]

        try:
            code = main(
                ["inspect", "--run-id", "50000000001"],
                environ=self.common_env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.api_responses[dep_ep] = orig_deps

    def test_cmd_inspect_tampered_manifest_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        # Tamper manifest zip payload
        orig_payload = self.mock_server.storage_payloads["13600255999"]
        mbuf = io.BytesIO()
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", b'{"tampered":true}')
        self.mock_server.storage_payloads["13600255999"] = mbuf.getvalue()

        try:
            code = main(
                ["inspect", "--run-id", "50000000001"],
                environ=self.common_env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.storage_payloads["13600255999"] = orig_payload

    def test_cmd_inspect_local_head_mismatch_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        orig_run = subprocess.run
        def mock_subp_run(cmd, *a, **kw):
            if isinstance(cmd, list) and cmd == ["git", "rev-parse", "HEAD"]:
                cp = MagicMock()
                cp.returncode = 0
                cp.stdout = "0" * 40
                cp.stderr = ""
                return cp
            return orig_run(cmd, *a, **kw)

        try:
            with patch("subprocess.run", side_effect=mock_subp_run):
                code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
                self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status

    def test_cmd_inspect_dirty_working_tree_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        orig_run = subprocess.run
        def mock_subp_run(cmd, *a, **kw):
            if isinstance(cmd, list) and cmd == ["git", "status", "--porcelain"]:
                cp = MagicMock()
                cp.returncode = 0
                cp.stdout = " M file.txt\n"
                cp.stderr = ""
                return cp
            return orig_run(cmd, *a, **kw)

        try:
            with patch("subprocess.run", side_effect=mock_subp_run):
                code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
                self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status

    def test_cmd_inspect_missing_evidence_branch_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        ev_branch_ep = f"repos/{PINNED_REPOSITORY}/branches/proof/strict-evidence-{self.c_sha[:12]}-20261107"
        orig_ev = self.mock_server.api_responses.pop(ev_branch_ep, None)

        try:
            code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            if orig_ev is not None:
                self.mock_server.api_responses[ev_branch_ep] = orig_ev

    def test_cmd_inspect_evidence_commit_mismatch_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        ev_branch_ep = f"repos/{PINNED_REPOSITORY}/branches/proof/strict-evidence-{self.c_sha[:12]}-20261107"
        orig_ev = deepcopy(self.mock_server.api_responses[ev_branch_ep])
        self.mock_server.api_responses[ev_branch_ep]["commit"]["sha"] = "f" * 40

        try:
            code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.api_responses[ev_branch_ep] = orig_ev

    def test_cmd_inspect_duplicate_prepare_job_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        jobs_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/attempts/1/jobs"
        orig_jobs = deepcopy(self.mock_server.api_responses[jobs_ep])
        prep2 = deepcopy(self.mock_server.api_responses[jobs_ep]["jobs"][0])
        prep2["id"] = 50000000099
        self.mock_server.api_responses[jobs_ep]["jobs"].append(prep2)

        try:
            code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.api_responses[jobs_ep] = orig_jobs

    def test_cmd_inspect_two_member_manifest_zip_refuses(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        orig_payload = self.mock_server.storage_payloads["13600255999"]
        mbuf = io.BytesIO()
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", b'{"test":1}')
            zf.writestr("extra.txt", b'extra')
        two_mem_zip = mbuf.getvalue()
        self.mock_server.storage_payloads["13600255999"] = two_mem_zip

        art_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/artifacts"
        orig_arts = deepcopy(self.mock_server.api_responses[art_ep])
        self.mock_server.api_responses[art_ep]["artifacts"][0]["digest"] = f"sha256:{digest(two_mem_zip)}"

        try:
            code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.storage_payloads["13600255999"] = orig_payload
            self.mock_server.api_responses[art_ep] = orig_arts

    def test_cmd_inspect_tampered_manifest_matching_zip_digest_reaches_man_3(self):
        run_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"
        orig_status = self.mock_server.api_responses[run_ep]["status"]
        self.mock_server.api_responses[run_ep]["status"] = "waiting"

        orig_payload = self.mock_server.storage_payloads["13600255999"]
        mbuf = io.BytesIO()
        tampered_manifest = deepcopy(self.mock_server.manifest_dict)
        # Keep all valid prior fields (inputs.evidence_commit, repository, etc.)
        # and tamper one field so check_man_3 ([MAN-3]) is specifically reached
        tampered_manifest["sources"]["c_sha"] = "0" * 40
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", canonical(tampered_manifest))
        tampered_zip = mbuf.getvalue()
        self.mock_server.storage_payloads["13600255999"] = tampered_zip

        art_ep = f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001/artifacts"
        orig_arts = deepcopy(self.mock_server.api_responses[art_ep])
        self.mock_server.api_responses[art_ep]["artifacts"][0]["digest"] = f"sha256:{digest(tampered_zip)}"

        try:
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main(["inspect", "--run-id", "50000000001"], environ=self.common_env, api_factory=self.api_factory)
                self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
                self.assertIn("[MAN-3]", mock_err.getvalue())
        finally:
            self.mock_server.api_responses[run_ep]["status"] = orig_status
            self.mock_server.storage_payloads["13600255999"] = orig_payload
            self.mock_server.api_responses[art_ep] = orig_arts
    def test_har_expired_artifact_positive(self):
        art_ep = f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}"
        orig_art = deepcopy(self.mock_server.api_responses[art_ep])
        self.mock_server.api_responses[art_ep]["expired"] = True

        try:
            # Prepare should succeed without downloading expired harness zip
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_PREPARE
            out_dir = os.path.join(self.td, "prep_expired")
            code = main(
                ["prepare", "--out-dir", out_dir],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, 0)
        finally:
            self.mock_server.api_responses[art_ep] = orig_art

    def test_har_expired_artifact_tampered_blob_refuses(self):
        art_ep = f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}"
        orig_art = deepcopy(self.mock_server.api_responses[art_ep])
        self.mock_server.api_responses[art_ep]["expired"] = True

        blob_ep = f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}"
        orig_blob = deepcopy(self.mock_server.api_responses[blob_ep])
        self.mock_server.api_responses[blob_ep]["content"] = "dGFtcGVyZWQ="

        try:
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_PREPARE
            out_dir = os.path.join(self.td, "prep_expired_badblob")
            code = main(
                ["prepare", "--out-dir", out_dir],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[art_ep] = orig_art
            self.mock_server.api_responses[blob_ep] = orig_blob

    def test_val_1b_candidate_run_failure_refuses(self):
        runs_ep = f"repos/{PINNED_REPOSITORY}/actions/runs?head_sha={self.c_sha}"
        orig_runs = deepcopy(self.mock_server.api_responses[runs_ep])

        failing_candidate_run = {
            "id": 9999901,
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "head_sha": self.c_sha,
            "head_branch": "proof/strict-workflow-activation-20261107",
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
        }
        self.mock_server.api_responses[runs_ep]["workflow_runs"].append(failing_candidate_run)
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9999901/attempts/1/jobs"] = {
            "jobs": [
                {
                    "name": "Controller synthetic and validation proofs (macOS 15)",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ]
        }

        try:
            env = dict(self.common_env)
            env["GITHUB_JOB"] = JOB_KEY_PREPARE
            out_dir = os.path.join(self.td, "prep_val1b_fail")
            code = main(
                ["prepare", "--out-dir", out_dir],
                environ=env,
                api_factory=self.api_factory,
            )
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
        finally:
            self.mock_server.api_responses[runs_ep] = orig_runs

    def test_verify_run_positive(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "999"
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_run_id": "999",
                    "strict_job_id": "128575084399",
                    "approval": {
                        "state": "approved",
                        "user_id": str(PINNED_REVIEWER_ID),
                        "environment_id": str(PINNED_ENVIRONMENT_ID),
                        "comment": f"{APPROVAL_COMMENT_PREFIX}{manifest_sha}",
                    },
                    "checks": [{"id": "REP-1", "status": "PASS"}, {"id": "APR-1", "status": "PASS"}],
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99999"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/999"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/999/artifacts"] = {
            "artifacts": [
                {"id": 99999, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "999"], api_factory=self.api_factory)
        self.assertEqual(code, 0)

    def test_verify_run_positive_bare_digest(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "9991"
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_run_id": "9991",
                    "strict_job_id": "128575084399",
                    "approval": {
                        "state": "approved",
                        "user_id": str(PINNED_REVIEWER_ID),
                        "environment_id": str(PINNED_ENVIRONMENT_ID),
                        "comment": f"{APPROVAL_COMMENT_PREFIX}{manifest_sha}",
                    },
                    "checks": [{"id": "REP-1", "status": "PASS"}, {"id": "APR-1", "status": "PASS"}],
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        bare_zip_dig = digest(v_bytes)
        self.mock_server.storage_payloads["99991"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9991"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9991/artifacts"] = {
            "artifacts": [
                {"id": 99991, "name": ARTIFACT_NAME_VERIFICATION, "digest": bare_zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9991"], api_factory=self.api_factory)
        self.assertEqual(code, 0)

    def test_verify_run_duplicate_member_refuses(self):
        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr("verification.json", b'{"test":1}')
            zf.writestr("manifest.json", b'{"test":2}')
            zf.writestr("verification.json", b'{"test":3}')
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99992"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9992"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9992/artifacts"] = {
            "artifacts": [
                {"id": 99992, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9992"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_missing_strict_run_id_refuses(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "9993"
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_job_id": "128575084399",
                    "approval": {
                        "state": "approved",
                        "user_id": str(PINNED_REVIEWER_ID),
                        "environment_id": str(PINNED_ENVIRONMENT_ID),
                        "comment": f"{APPROVAL_COMMENT_PREFIX}{manifest_sha}",
                    },
                    "checks": [{"id": "REP-1", "status": "PASS"}],
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99993"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9993"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9993/artifacts"] = {
            "artifacts": [
                {"id": 99993, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9993"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_missing_approval_refuses(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "9994"
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_run_id": "9994",
                    "strict_job_id": "128575084399",
                    "checks": [{"id": "REP-1", "status": "PASS"}],
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99994"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9994"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9994/artifacts"] = {
            "artifacts": [
                {"id": 99994, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9994"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_missing_manifest_sources_refuses(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "9995"
        del manifest_doc["sources"]
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_run_id": "9995",
                    "strict_job_id": "128575084399",
                    "approval": {
                        "state": "approved",
                        "user_id": str(PINNED_REVIEWER_ID),
                        "environment_id": str(PINNED_ENVIRONMENT_ID),
                        "comment": f"{APPROVAL_COMMENT_PREFIX}{manifest_sha}",
                    },
                    "checks": [{"id": "REP-1", "status": "PASS"}],
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99995"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9995"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9995/artifacts"] = {
            "artifacts": [
                {"id": 99995, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9995"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_missing_checks_refuses(self):
        manifest_doc = deepcopy(self.mock_server.manifest_dict)
        manifest_doc["strict_run"]["id"] = "9996"
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                    "strict_run_id": "9996",
                    "strict_job_id": "128575084399",
                    "approval": {
                        "state": "approved",
                        "user_id": str(PINNED_REVIEWER_ID),
                        "environment_id": str(PINNED_ENVIRONMENT_ID),
                        "comment": f"{APPROVAL_COMMENT_PREFIX}{manifest_sha}",
                    },
                    "checks": [],  # empty checks!
                    "verified_at": "2026-11-06T00:30:00Z",
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99996"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9996"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/9996/artifacts"] = {
            "artifacts": [
                {"id": 99996, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "9996"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)
    def test_verify_run_failed_run_refuses(self):
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/998"] = {
            "status": "completed",
            "conclusion": "failure",
        }
        code = main(["verify-run", "--run-id", "998"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_missing_verification_artifact_refuses(self):
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/997"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/997/artifacts"] = {
            "artifacts": []
        }
        code = main(["verify-run", "--run-id", "997"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_zip_digest_mismatch_refuses(self):
        manifest_doc = {
            "schema": SCHEMA_MANIFEST,
            "strict_run": {"id": "995"},
            "sources": {"c_sha": self.c_sha},
        }
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        self.mock_server.storage_payloads["99995"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/995"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/995/artifacts"] = {
            "artifacts": [
                {"id": 99995, "name": ARTIFACT_NAME_VERIFICATION, "digest": "sha256:" + "0" * 64}
            ]
        }
        code = main(["verify-run", "--run-id", "995"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_single_member_refuses(self):
        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": "0" * 64,
                }),
            )
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99994"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/994"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/994/artifacts"] = {
            "artifacts": [
                {"id": 99994, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "994"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_manifest_digest_mismatch_refuses(self):
        manifest_doc = {
            "schema": SCHEMA_MANIFEST,
            "strict_run": {"id": "993"},
            "sources": {"c_sha": self.c_sha},
        }
        manifest_raw = canonical(manifest_doc)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "AUTHORIZED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": "1" * 64,  # Mismatches actual manifest digest
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99993"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/993"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/993/artifacts"] = {
            "artifacts": [
                {"id": 99993, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "993"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_verify_run_refused_decision_refuses(self):
        manifest_doc = {
            "schema": SCHEMA_MANIFEST,
            "strict_run": {"id": "996"},
            "sources": {"c_sha": self.c_sha},
        }
        manifest_raw = canonical(manifest_doc)
        manifest_sha = digest(manifest_raw)

        vbuf = io.BytesIO()
        with zipfile.ZipFile(vbuf, "w") as zf:
            zf.writestr(
                "verification.json",
                canonical({
                    "schema": SCHEMA_VERIFICATION,
                    "decision": "REFUSED",
                    "c_sha": self.c_sha,
                    "manifest_sha256": manifest_sha,
                }),
            )
            zf.writestr("manifest.json", manifest_raw)
        v_bytes = vbuf.getvalue()
        zip_dig = f"sha256:{digest(v_bytes)}"
        self.mock_server.storage_payloads["99996"] = v_bytes

        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/996"] = {
            "status": "completed",
            "conclusion": "success",
            "workflow_id": int(PINNED_WORKFLOW_ID),
            "run_attempt": 1,
            "head_sha": self.c_sha,
        }
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/996/artifacts"] = {
            "artifacts": [
                {"id": 99996, "name": ARTIFACT_NAME_VERIFICATION, "digest": zip_dig}
            ]
        }
        code = main(["verify-run", "--run-id", "996"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_get_paginated_multi_page(self):
        page1_url = "repos/jwaldrip/iyi/paginated_test"
        page2_url = f"http://127.0.0.1:{self.mock_server.api_port}/repos/jwaldrip/iyi/paginated_test?page=2"

        self.mock_server.api_responses[page1_url] = (
            {"items": [{"id": 1}, {"id": 2}]},
            {"Link": f'<{page2_url}>; rel="next"'},
        )
        self.mock_server.api_responses["repos/jwaldrip/iyi/paginated_test?page=2"] = (
            {"items": [{"id": 3}, {"id": 4}]},
            {},
        )

        client = self.mock_server.client()
        res = client.get_paginated(page1_url, list_key="items")
        self.assertEqual(res, [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}])


class SubprocessCLITests(unittest.TestCase):
    """Test CLI exit codes (0, 5, 2) when executed as child process."""

    def test_subprocess_unknown_subcommand_exit_2(self):
        res = subprocess.run(
            [sys.executable, "-B", "-m", "proof.strict_authorization", "unknown-command"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, USAGE_ERROR_EXIT_CODE)

    def test_subprocess_missing_args_exit_2(self):
        res = subprocess.run(
            [sys.executable, "-B", "-m", "proof.strict_authorization", "prepare"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, USAGE_ERROR_EXIT_CODE)

    def test_subprocess_refusal_exit_5(self):
        res = subprocess.run(
            [sys.executable, "-B", "-m", "proof.strict_authorization", "publish", "--manifest", "/nonexistent/manifest.json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, AUTH_REFUSED_EXIT_CODE)

    def test_subprocess_check_bundle_tampered_exit_5(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b'{"test":1}')
            mpath = f.name
        try:
            res = subprocess.run(
                [sys.executable, "-B", "-m", "proof.strict_authorization", "check-bundle", "--manifest", mpath, "--expect-sha256", "0" * 64],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, AUTH_REFUSED_EXIT_CODE)
        finally:
            os.unlink(mpath)

    def test_subprocess_check_bundle_exit_0(self):
        manifest_path = os.path.join(tempfile.gettempdir(), f"sub_bundle_{os.getpid()}.json")
        bundle_map = check_bun_1()
        m_bytes = canonical({"schema": SCHEMA_MANIFEST, "bundle": bundle_map})
        with open(manifest_path, "wb") as f:
            f.write(m_bytes)
        d = digest(m_bytes)
        try:
            res = subprocess.run(
                [sys.executable, "-B", "-m", "proof.strict_authorization", "check-bundle", "--manifest", manifest_path, "--expect-sha256", d],
                capture_output=True,
                text=True,
                env=dict(os.environ, PYTHONPATH="."),
            )
            self.assertEqual(res.returncode, 0)
        finally:
            if os.path.exists(manifest_path):
                os.unlink(manifest_path)

    def test_subprocess_rail_summary_exit_0(self):
        td = tempfile.mkdtemp()
        try:
            pins_path = os.path.join(td, "sub_pins.json")
            with open(pins_path, "w", encoding="utf-8") as f:
                json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)
            struct_path = os.path.join(td, "sub_struct.json")
            with open(struct_path, "w", encoding="utf-8") as f:
                json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)
            c_sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("ascii").strip()
            refusal_path = os.path.join(td, "sub_refusal.json")
            with open(refusal_path, "w", encoding="utf-8") as f:
                json.dump({
                    "schema": SCHEMA_REFUSAL_REPORT,
                    "status": "PASS",
                    "controller_suite": "PASS",
                    "c_sha": c_sha,
                    "run_id": "42086795082",
                    "run_attempt": "1",
                    "cases": {
                        "missing_manifest_fd": {
                            "status": "REFUSED",
                            "exit_code": AUTH_REFUSED_EXIT_CODE,
                            "diagnostic": "missing required manifest fd 5",
                        },
                        "manifest_digest_mismatch": {
                            "status": "REFUSED",
                            "exit_code": AUTH_REFUSED_EXIT_CODE,
                            "diagnostic": "manifest digest mismatch: expected sha256:000, got sha256:111",
                        },
                        "strict_run_id_mismatch": {
                            "status": "REFUSED",
                            "exit_code": AUTH_REFUSED_EXIT_CODE,
                            "diagnostic": "strict run id mismatch: expected 42086795082, got 999",
                        },
                        "invalid_p_sha": {
                            "status": "REFUSED",
                            "exit_code": AUTH_REFUSED_EXIT_CODE,
                            "diagnostic": "invalid P commit SHA: expected 180f14f91c829b25362a5ed34b20847f3ac2db77, got 0000000000000000000000000000000000000000",
                        },
                    },
                }, f)
            out_path = os.path.join(td, "sub_rail_summary.json")
            env = dict(
                os.environ,
                PYTHONPATH=".",
                GITHUB_SHA=c_sha,
                GITHUB_RUN_ID="42086795082",
                GITHUB_RUN_ATTEMPT="1",
            )
            res = subprocess.run(
                [
                    sys.executable, "-B", "-m", "proof.strict_authorization", "rail-summary",
                    "--out", out_path,
                    "--pins-report", pins_path,
                    "--structure-report", struct_path,
                    "--refusal-report", refusal_path,
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res.returncode, 0)
        finally:
            shutil.rmtree(td, ignore_errors=True)


class BundleAndWTreeTests(unittest.TestCase):
    """Test check-bundle and check-w-tree verification commands."""

    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def test_check_bundle_positive(self):
        manifest_path = os.path.join(self.td, "manifest.json")
        bundle_map = check_bun_1()
        raw = canonical({"schema": SCHEMA_MANIFEST, "bundle": bundle_map})
        with open(manifest_path, "wb") as f:
            f.write(raw)
        code = main(["check-bundle", "--manifest", manifest_path, "--expect-sha256", digest(raw)])
        self.assertEqual(code, 0)

    def test_check_bundle_tampered_digest_refuses(self):
        manifest_path = os.path.join(self.td, "manifest.json")
        with open(manifest_path, "wb") as f:
            f.write(b'{"test":1}')
        code = main(["check-bundle", "--manifest", manifest_path, "--expect-sha256", "0" * 64])
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def _prepare_w_repo(self, w_dir: str):
        res_cat = subprocess.run(["git", "cat-file", "-e", PINNED_W_SHA], capture_output=True)
        if res_cat.returncode == 0:
            subprocess.run(["git", "clone", "--shared", ".", w_dir], check=True, capture_output=True)
            subprocess.run(["git", "-C", w_dir, "checkout", PINNED_W_SHA], check=True, capture_output=True)
            return None
        else:
            subprocess.run(["git", "init", w_dir], check=True, capture_output=True)
            subprocess.run(["git", "-C", w_dir, "config", "user.name", "Test"], check=True, capture_output=True)
            subprocess.run(["git", "-C", w_dir, "config", "user.email", "test@example.com"], check=True, capture_output=True)
            dummy_file = os.path.join(w_dir, "src", "file.txt")
            os.makedirs(os.path.dirname(dummy_file), exist_ok=True)
            with open(dummy_file, "w") as f:
                f.write("initial")
            subprocess.run(["git", "-C", w_dir, "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", w_dir, "commit", "-m", "commit P"], check=True, capture_output=True)
            p_sha = subprocess.check_output(["git", "-C", w_dir, "rev-parse", "HEAD"]).decode("ascii").strip()

            pw_fixture = get_compare_pw_fixture()
            census_paths = [f["filename"] for f in pw_fixture["files"]]
            for p in census_paths:
                fpath = os.path.join(w_dir, p)
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, "wb") as f:
                    f.write(b"content")

            subprocess.run(["git", "-C", w_dir, "add", "proof"], check=True, capture_output=True)
            subprocess.run(["git", "-C", w_dir, "commit", "-m", "commit W"], check=True, capture_output=True)
            w_sha = subprocess.check_output(["git", "-C", w_dir, "rev-parse", "HEAD"]).decode("ascii").strip()
            return (p_sha, w_sha)

    def test_check_w_tree_verified(self):
        w_dir = os.path.join(self.td, "real_w_repo")
        shas = self._prepare_w_repo(w_dir)
        if shas:
            with patch("proof.strict_authorization.PINNED_P_SHA", shas[0]), \
                 patch("proof.strict_authorization.PINNED_W_SHA", shas[1]):
                code = main(["check-w-tree", "--w-dir", w_dir])
        else:
            code = main(["check-w-tree", "--w-dir", w_dir])
        self.assertEqual(code, 0)

    def test_check_w_tree_dirty_refuses(self):
        w_dir = os.path.join(self.td, "dirty_w_repo")
        shas = self._prepare_w_repo(w_dir)
        with open(os.path.join(w_dir, "dirty.txt"), "w") as f:
            f.write("dirty")
        if shas:
            with patch("proof.strict_authorization.PINNED_P_SHA", shas[0]), \
                 patch("proof.strict_authorization.PINNED_W_SHA", shas[1]):
                code = main(["check-w-tree", "--w-dir", w_dir])
        else:
            code = main(["check-w-tree", "--w-dir", w_dir])
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_check_w_tree_wrong_head_refuses(self):
        w_dir = os.path.join(self.td, "wrong_head_w_repo")
        shas = self._prepare_w_repo(w_dir)
        if shas:
            subprocess.run(["git", "-C", w_dir, "checkout", shas[0]], check=True, capture_output=True)
            with patch("proof.strict_authorization.PINNED_P_SHA", shas[0]), \
                 patch("proof.strict_authorization.PINNED_W_SHA", shas[1]):
                code = main(["check-w-tree", "--w-dir", w_dir])
        else:
            subprocess.run(["git", "-C", w_dir, "checkout", PINNED_P_SHA], check=True, capture_output=True)
            code = main(["check-w-tree", "--w-dir", w_dir])
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_check_w_tree_subprocess_exit_0(self):
        w_dir = os.path.join(self.td, "subp_w_repo")
        shas = self._prepare_w_repo(w_dir)
        if shas:
            py_code = f"import sys, proof.strict_authorization as sa; sa.PINNED_P_SHA='{shas[0]}'; sa.PINNED_W_SHA='{shas[1]}'; sys.exit(sa.main(['check-w-tree', '--w-dir', '{w_dir}']))"
            res = subprocess.run(
                [sys.executable, "-B", "-c", py_code],
                capture_output=True,
                text=True,
                env=dict(os.environ, PYTHONPATH="."),
            )
        else:
            res = subprocess.run(
                [sys.executable, "-B", "-m", "proof.strict_authorization", "check-w-tree", "--w-dir", w_dir],
                capture_output=True,
                text=True,
                env=dict(os.environ, PYTHONPATH="."),
            )
        self.assertEqual(res.returncode, 0)

if __name__ == "__main__":
    unittest.main()
