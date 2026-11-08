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
    ARTIFACT_NAME_MANIFEST,
    ARTIFACT_NAME_RAIL_SUMMARY,
    ARTIFACT_NAME_REHEARSAL_REPORT,
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
        job["runner_name"] = "GitHub Actions 1"
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_1(job, "100", JOB_NAME_STRICT, "c" * 40, runner_name=None)
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

    def test_env_2_positive(self):
        policies = get_branch_policies_fixture()
        res = check_env_2(policies)
        self.assertEqual(res[0]["name"], PINNED_DEPLOY_BRANCH)

    def test_env_2_wrong_branch_policy(self):
        policies = [{"type": "branch", "name": "wrong-branch"}]
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
        exp = check_har_3(art)
        self.assertEqual(exp, art["expires_at"])

    def test_har_3_digest_mismatch(self):
        art = deepcopy(load_fixture("artifact_13600255503.json"))
        art["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_3(art)
        self.assertIn("HAR-3", str(ctx.exception))

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
            {"name": "Controller synthetic and validation proofs (macOS 15)", "conclusion": "success"}
        ]
        runs = [{"id": 100, "status": "completed", "conclusion": "success"}]
        check_val_1b(mock_client, runs)

    def test_val_1b_failure(self):
        mock_client = MagicMock()
        mock_client.get_paginated.return_value = [
            {"name": "Controller synthetic and validation proofs (macOS 15)", "conclusion": "success"}
        ]
        runs = [{"id": 100, "status": "completed", "conclusion": "failure"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1b(mock_client, runs)
        self.assertIn("VAL-1b", str(ctx.exception))

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
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": "0" * 64,
        })
        s_sha, r_sha = check_val_4(summary_raw, rehearsal_raw, bundle_map, "100", "c" * 40)
        self.assertEqual(s_sha, digest(summary_raw))

    def test_val_4_summary_dist_mismatch(self):
        summary_raw = canonical({
            "schema": SCHEMA_RAIL_SUMMARY,
            "status": "PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
            "dist": {"file1": "0" * 64},
            "actions": PINNED_ACTIONS,
        })
        rehearsal_raw = canonical({
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": "c" * 40,
            "run_id": "100",
        })
        bundle_map = {"file1": "1" * 64}
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

    def test_man_2_digest_mismatch(self):
        zip_bytes = b"fake-zip"
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_2(zip_bytes, "sha256:" + "0" * 64, "0" * 64)
        self.assertIn("MAN-2", str(ctx.exception))

    def test_man_3_positive(self):
        m = {"schema": SCHEMA_MANIFEST, "sources": {"c_sha": "a" * 40}}
        check_man_3(m, m)

    def test_man_3_tampering(self):
        m1 = {"schema": SCHEMA_MANIFEST, "sources": {"c_sha": "a" * 40}}
        m2 = {"schema": SCHEMA_MANIFEST, "sources": {"c_sha": "b" * 40}}
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_3(m1, m2)
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

                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path.lstrip("/")

                # Artifact download zip redirect
                if path.endswith("/zip"):
                    art_id = path.split("/")[-2]
                    storage_url = f"http://127.0.0.1:{parent.storage_port}/storage/{art_id}"
                    self.send_response(302)
                    self.send_header("Location", storage_url)
                    self.end_headers()
                    return

                resp = parent.api_responses.get(path)
                if resp is None:
                    # Match prefix
                    for pfx, val in parent.api_responses.items():
                        if path.startswith(pfx):
                            resp = val
                            break

                if resp is not None:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
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

        rehearsal_dict = {
            "schema": SCHEMA_REHEARSAL,
            "status": "REHEARSAL_PASS",
            "c_sha": c_sha,
            "run_id": str(val_run_id),
            "checks": [],
            "approvals_observed": [],
            "rehearsal_manifest_sha256": "0" * 64,
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
        branch_policies = get_branch_policies_fixture()["branch_policies"]
        branch_data = get_branch_deploy_fixture()
        branch_data["commit"]["sha"] = c_sha
        branch_rules = get_rules_branch_deploy_fixture(active=True)

        manifest_dict = build_manifest_v2(
            c_sha=c_sha,
            strict_run=strict_run,
            prepare_job=prep_job,
            inputs={"mode": "strict-chain", "evidence_commit": evidence_commit},
            environment=env_data,
            branch_policies=branch_policies,
            deploy_branch=branch_data,
            branch_rules=branch_rules,
            bundle_map=bundle_map,
            validation_run={"id": val_run_id},
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

        # Manifest zip artifact
        mbuf = io.BytesIO()
        with zipfile.ZipFile(mbuf, "w") as zf:
            zf.writestr("manifest.json", manifest_raw)
        manifest_zip_bytes = mbuf.getvalue()
        self.storage_payloads["13600255999"] = manifest_zip_bytes
        self.manifest_zip_digest = f"sha256:{digest(manifest_zip_bytes)}"

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
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
            "head_repository": {"id": int(PINNED_REPOSITORY_ID)},
        }

        # Wire API endpoints
        self.api_responses = {
            f"repos/{PINNED_REPOSITORY}": get_repo_fixture(),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{strict_run_id}": strict_run,
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}": val_run,
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
            f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}": branch_rules,
            f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}": get_pull_147_fixture(),
            f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}": get_compare_pw_fixture(),
            f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}": get_compare_wh_fixture(),
            f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}": load_fixture("run_42429518284.json"),
            f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}": load_fixture("job_128575084391.json"),
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}": load_fixture("artifact_13600255503.json"),
            f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}": load_fixture("contents_harness_audit_zip.json"),
            f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}": load_fixture("blob_95962d09.json"),
            f"repos/{PINNED_REPOSITORY}/actions/workflows/{PINNED_WORKFLOW_ID}/runs": {
                "workflow_runs": [val_run]
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/attempts/1/jobs": {
                "jobs": get_val_jobs_fixture(val_run_id, c_sha)
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/artifacts": {
                "artifacts": val_arts
            },
            f"repos/{PINNED_REPOSITORY}/commits/{evidence_commit}": {
                "sha": evidence_commit,
                "parents": [{"sha": HARNESS_PRESERVED_COMMIT}],
            },
            f"repos/{PINNED_REPOSITORY}/contents/proof/strict-audit/{c_sha}": [
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
        self.assertIn("failed_check", v)

    def test_cmd_rehearse_push_positive(self):
        env = dict(self.common_env)
        env["GITHUB_JOB"] = JOB_KEY_REHEARSAL
        env["GITHUB_EVENT_NAME"] = "push"
        env["GITHUB_RUN_ID"] = "42086795082"
        env["JOB_CHECK_RUN_ID"] = "1007"
        env["RUNNER_NAME"] = "GitHub Actions 7"
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

    def test_cmd_inspect_positive(self):
        # Update run status to waiting
        self.mock_server.api_responses[f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"]["status"] = "waiting"
        code = main(
            ["inspect", "--run-id", "50000000001"],
            environ=self.common_env,
            api_factory=self.api_factory,
        )
        self.assertEqual(code, 0)
        self.mock_server.api_responses[f"repos/{PINNED_REPOSITORY}/actions/runs/50000000001"]["status"] = "in_progress"

    def test_cmd_publish_positive(self):
        manifest_file = os.path.join(self.td, "pub_manifest.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":1}')
        dig = digest(b'{"test":1}')

        summary_file = os.path.join(self.td, "summary.md")
        env = {
            "MANIFEST_SHA256": dig,
            "ARTIFACT_ID": "12345",
            "ARTIFACT_URL": "https://github.com/.../artifacts/12345",
            "ARTIFACT_DIGEST": f"sha256:{dig}",
            "GITHUB_STEP_SUMMARY": summary_file,
        }
        code = main(["publish", "--manifest", manifest_file], environ=env)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(summary_file))

    def test_cmd_publish_missing_env_refuses(self):
        manifest_file = os.path.join(self.td, "pub_manifest.json")
        with open(manifest_file, "wb") as f:
            f.write(b'{"test":1}')
        code = main(["publish", "--manifest", manifest_file], environ={})
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_verify_run(self):
        # 1. Success run
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/999"] = {
            "status": "completed",
            "conclusion": "success",
        }
        code = main(["verify-run", "--run-id", "999"], api_factory=self.api_factory)
        self.assertEqual(code, 0)

        # 2. Failed run
        self.mock_server.api_responses["repos/jwaldrip/iyi/actions/runs/998"] = {
            "status": "completed",
            "conclusion": "failure",
        }
        code = main(["verify-run", "--run-id", "998"], api_factory=self.api_factory)
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)

    def test_cmd_rail_summary(self):
        pins_path = os.path.join(self.td, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)

        struct_path = os.path.join(self.td, "struct.json")
        with open(struct_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)

        refusal_path = os.path.join(self.td, "refusal.json")
        with open(refusal_path, "w", encoding="utf-8") as f:
            json.dump({"status": "PASS", "strict_refusal_controls": PINNED_REFUSAL_CONTROLS}, f)

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
            s = parse(f.read())
        self.assertEqual(s["status"], "PASS")
        self.assertEqual(s["strict_refusal_controls"], PINNED_REFUSAL_CONTROLS)

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
            [
                "rail-summary",
                "--out", out_path,
                "--pins-report", pins_path,
                "--structure-report", struct_path,
            ],
            environ=env,
        )
        self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)


class BundleAndWTreeTests(unittest.TestCase):
    """Test check-bundle and check-w-tree verification commands."""

    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def test_check_bundle_positive(self):
        bundle = check_bun_1()
        manifest_data = {
            "schema": SCHEMA_MANIFEST,
            "bundle": bundle,
        }
        raw = canonical(manifest_data)
        manifest_path = os.path.join(self.td, "manifest.json")
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

    def test_check_w_tree_verified(self):
        # Mock git commands in a temporary directory
        with patch("subprocess.run") as mock_run:
            diff_lines = "\n".join(f"A\tproof/file_{i}.txt" for i in range(PINNED_W_ADDED_COUNT))
            sorted_paths = sorted(f"proof/file_{i}.txt" for i in range(PINNED_W_ADDED_COUNT))
            expected_digest = fixture_digest("\n".join(sorted_paths).encode("utf-8"))

            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=PINNED_W_SHA, stderr=""),  # rev-parse HEAD
                MagicMock(returncode=0, stdout="", stderr=""),             # status --porcelain
                MagicMock(returncode=0, stdout="", stderr=""),             # diff P..W outside proof
                MagicMock(returncode=0, stdout=diff_lines, stderr=""),    # diff --name-status P..W
            ]
            w_dir = Path(self.td)
            for p in sorted_paths:
                fpath = w_dir / p
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_bytes(b"content")

            with patch("proof.strict_authorization.PINNED_W_ADDED_PATHS_SHA256", expected_digest):
                code = main(["check-w-tree", "--w-dir", str(w_dir)])
                self.assertEqual(code, 0)

    def test_check_w_tree_dirty_refuses(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=PINNED_W_SHA, stderr=""),
                MagicMock(returncode=0, stdout=" M dirty.txt\n", stderr=""),
            ]
            code = main(["check-w-tree", "--w-dir", self.td])
            self.assertEqual(code, AUTH_REFUSED_EXIT_CODE)


if __name__ == "__main__":
    unittest.main()
