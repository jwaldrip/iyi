"""Discriminating tests for authenticated GitHub environment strict-proof authorization verifier.

Tests all security gates and failure modes:
  - Exact individual check isolation: every check ID (RNR-1..6, REP-1, RUN-1, JOB-1..3,
    ENV-1..2, BRN-1..2, SRC-1..3, BUN-1, HAR-1..6, VAL-1..4, AUD-1..3, MAN-1..3, APR-1)
    has a dedicated negative test that breaks only that check and verifies the refusal
    names that exact check ID.
  - Test environments are constructed independently of the manifest.
  - Subprocess tests verifying exit code 5 on bad environment and exit code 2 on usage error.
  - Loopback server verifying exact Bearer token on API requests, 302 redirect handling,
    and storage host that strictly rejects any request carrying an Authorization header.
  - Canonical JSON parser tests verifying duplicate key and non-canonical rejection.
  - StrictManifestBinding verification over file descriptors with exact revision and pin checks.
"""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from proof.fixtures.github_api import (
    get_manifest_artifact_fixture,
    get_branch_deploy_fixture,
    get_branch_policies_fixture,
    get_check_run_deployment_fixture,
    get_compare_pw_fixture,
    get_compare_wh_fixture,
    get_contents_harness_audit_zip_fixture,
    get_deployment_fixture,
    get_environment_fixture,
    get_pull_147_fixture,
    get_repo_fixture,
    get_rules_branch_deploy_fixture,
    get_strict_run_in_progress_fixture,
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


class CheckIsolationTests(unittest.TestCase):
    """Verify that every check ID isolates its failure mode and names the check ID."""

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

    def test_rnr_2_ref_mismatch(self):
        env = {
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
            "GITHUB_REF": PINNED_REF,
            "GITHUB_WORKFLOW_REF": "wrong-workflow-ref",
            "GITHUB_WORKFLOW_SHA": "c" * 40,
            "GITHUB_SHA": "c" * 40,
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_2(env)
        self.assertIn("RNR-2", str(ctx.exception))

    def test_rnr_3_attempt_mismatch(self):
        env = {"GITHUB_RUN_ATTEMPT": "2"}
        with self.assertRaises(AuthorizationError) as ctx:
            check_rnr_3(env)
        self.assertIn("RNR-3", str(ctx.exception))

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

    def test_rep_1_private_repo(self):
        repo = get_repo_fixture()
        repo["private"] = True
        with self.assertRaises(AuthorizationError) as ctx:
            check_rep_1(repo)
        self.assertIn("REP-1", str(ctx.exception))

    def test_run_1_not_in_progress(self):
        run = get_strict_run_in_progress_fixture()
        run["status"] = "completed"
        with self.assertRaises(AuthorizationError) as ctx:
            check_run_1(run, run["head_sha"])
        self.assertIn("RUN-1", str(ctx.exception))

    def test_job_1_workflow_name_mismatch(self):
        job = deepcopy(load_fixture("job_128575084391.json"))
        job["workflow_name"] = "Wrong Workflow Name"
        job["run_id"] = "100"
        job["run_attempt"] = "1"
        job["name"] = JOB_NAME_STRICT
        job["head_sha"] = "c" * 40
        job["status"] = "in_progress"
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_1(job, "100", JOB_NAME_STRICT, "c" * 40)
        self.assertIn("JOB-1", str(ctx.exception))

    def test_job_2_missing_deployment(self):
        check_run = deepcopy(load_fixture("check_run_97854822865.json"))
        check_run["deployment"] = None
        dep = deepcopy(load_fixture("deployment_6086087244.json"))
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_2(check_run, dep, "100", "200", "c" * 40)
        self.assertIn("JOB-2", str(ctx.exception))

    def test_job_3_unskipped_extra_job(self):
        jobs = [
            {"id": 1, "name": JOB_NAME_PREPARE, "status": "completed", "conclusion": "success"},
            {"id": 2, "name": JOB_NAME_STRICT, "status": "in_progress", "conclusion": None},
            {"id": 3, "name": "Extra Job", "status": "completed", "conclusion": "success"},
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_job_3(jobs, "1", "2")
        self.assertIn("JOB-3", str(ctx.exception))

    def test_env_1_admin_bypass_true(self):
        env = get_environment_fixture()
        env["can_admins_bypass"] = True
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_1(env)
        self.assertIn("ENV-1", str(ctx.exception))

    def test_env_2_wrong_branch_policy(self):
        policies = [{"type": "branch", "name": "wrong-branch"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_env_2(policies)
        self.assertIn("ENV-2", str(ctx.exception))

    def test_brn_1_wrong_head(self):
        branch = get_branch_deploy_fixture()
        with self.assertRaises(AuthorizationError) as ctx:
            check_brn_1(branch, "wrong_sha" * 4)
        self.assertIn("BRN-1", str(ctx.exception))

    def test_brn_2_missing_rules(self):
        rules = [{"type": "deletion", "ruleset_source_type": "Repository", "ruleset_source": PINNED_REPOSITORY, "ruleset_id": "1"}]
        with self.assertRaises(AuthorizationError) as ctx:
            check_brn_2(rules, require_active=True)
        self.assertIn("BRN-2", str(ctx.exception))

    def test_src_1_closed_pr(self):
        pr = get_pull_147_fixture()
        pr["state"] = "closed"
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_1(pr)
        self.assertIn("SRC-1", str(ctx.exception))

    def test_src_2_pw_count_mismatch(self):
        compare = deepcopy(get_compare_pw_fixture())
        compare["files"] = compare["files"][:10]
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_2(compare)
        self.assertIn("SRC-2", str(ctx.exception))

    def test_src_3_wh_files_mismatch(self):
        compare = deepcopy(get_compare_wh_fixture())
        compare["files"].append({"filename": "extra_file.py", "status": "added"})
        with self.assertRaises(AuthorizationError) as ctx:
            check_src_3(compare)
        self.assertIn("SRC-3", str(ctx.exception))

    def test_har_1_harness_conclusion(self):
        run = deepcopy(load_fixture("run_42429518284.json"))
        job = deepcopy(load_fixture("job_128575084391.json"))
        run["conclusion"] = "failure"
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_1_2(run, job)
        self.assertIn("HAR-1", str(ctx.exception))

    def test_har_3_artifact_digest(self):
        art = deepcopy(load_fixture("artifact_13600255503.json"))
        art["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_3(art)
        self.assertIn("HAR-3", str(ctx.exception))

    def test_har_4_blob_sha(self):
        contents = deepcopy(load_fixture("contents_harness_audit_zip.json"))
        blob = deepcopy(load_fixture("blob_95962d09.json"))
        contents["sha"] = "wrong_sha"
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_4(contents, blob)
        self.assertIn("HAR-4", str(ctx.exception))

    def test_har_5_download_mismatch(self):
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_5(b"wrong bytes", b"preserved bytes", False)
        self.assertIn("HAR-5", str(ctx.exception))

    def test_har_6_summary_status(self):
        # Create a zip with tampered summary member
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(HARNESS_SUMMARY_MEMBER, b'{"status":"FAIL","w_sha":"5a3770e96fb12099c4ce9dc3b21895de07dd4cd8","p1_sha":"180f14f91c829b25362a5ed34b20847f3ac2db77"}')
        with self.assertRaises(AuthorizationError) as ctx:
            check_har_6(buf.getvalue())
        self.assertIn("HAR-6", str(ctx.exception))

    def test_val_1_run_not_success(self):
        run = deepcopy(load_fixture("run_42086795082.json"))
        run["workflow_id"] = PINNED_WORKFLOW_ID
        run["head_branch"] = PINNED_DEPLOY_BRANCH
        run["head_sha"] = "c" * 40
        run["event"] = "push"
        run["conclusion"] = "failure"
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1([run], "c" * 40)
        self.assertIn("VAL-1", str(ctx.exception))

    def test_val_1b_unskipped_job_failed(self):
        runs = [
            {
                "id": "1",
                "status": "completed",
                "conclusion": "failure",
                "_controller_proof_job": {"name": "Controller synthetic and validation proofs (macOS 15)", "conclusion": "failure"},
            }
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_1b(runs)
        self.assertIn("VAL-1b", str(ctx.exception))

    def test_val_2_job_set_missing(self):
        jobs = [
            {"name": "Bootstrap strict supervisor bundle", "status": "completed", "conclusion": "success"}
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_2(jobs)
        self.assertIn("VAL-2", str(ctx.exception))

    def test_val_3_artifact_missing(self):
        arts = [
            {"id": "1", "name": "remote-strict-validation-evidence", "digest": "sha256:" + "a" * 64, "expired": False}
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_val_3(arts)
        self.assertIn("VAL-3", str(ctx.exception))

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

    def test_aud_1_missing_commit_parent(self):
        commit = {"parents": [{"sha": "wrong_parent"}]}
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_1(commit, "c" * 40)
        self.assertIn("AUD-1", str(ctx.exception))

    def test_aud_2_missing_file(self):
        files = {"audit.json": b"{}", "audit.md": b"md"}
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_2(files)
        self.assertIn("AUD-2", str(ctx.exception))

    def test_aud_3_non_go_verdict(self):
        audit_json = {
            "schema": SCHEMA_AUDIT,
            "verdict": "NO-GO",
            "repository_id": PINNED_REPOSITORY_ID,
            "c_sha": "c" * 40,
            "p_sha": PINNED_P_SHA,
            "w_sha": PINNED_W_SHA,
            "h_sha": PINNED_H_SHA,
            "validation": {"run_id": "100", "artifacts": {}},
            "harness": {"run_id": HARNESS_RUN_ID, "artifact_id": HARNESS_ARTIFACT_ID, "digest": HARNESS_ARTIFACT_DIGEST},
            "report_sha256": "0" * 64,
            "census_review_sha256": "0" * 64,
            "open_blocking_findings": [],
            "s6_signing_ruling": "audited",
            "self_declared": {"did_not_implement": True},
        }
        with self.assertRaises(AuthorizationError) as ctx:
            check_aud_3(audit_json, "c" * 40, "100", {}, "0" * 64, "0" * 64)
        self.assertIn("AUD-3", str(ctx.exception))

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

    def test_man_2_digest_mismatch(self):
        zip_bytes = b"fake-zip"
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_2(zip_bytes, "sha256:" + "0" * 64, "0" * 64)
        self.assertIn("MAN-2", str(ctx.exception))

    def test_man_3_field_tampering(self):
        m = {"schema": SCHEMA_MANIFEST, "sources": {"c_sha": "a" * 40}}
        live = {"sources.c_sha": "b" * 40}
        with self.assertRaises(AuthorizationError) as ctx:
            check_man_3(m, live)
        self.assertIn("MAN-3", str(ctx.exception))

    def test_apr_1_wrong_comment(self):
        apprs = [
            {
                "state": "approved",
                "user": {"id": 43164, "login": "jwaldrip", "type": "User"},
                "environments": [{"id": 26584191206, "name": "strict-proof"}],
                "comment": "wrong comment",
            }
        ]
        with self.assertRaises(AuthorizationError) as ctx:
            check_apr_1(apprs, "0" * 64)
        self.assertIn("APR-1", str(ctx.exception))


class CanonicalJSONTests(unittest.TestCase):
    def test_canonical_roundtrip(self):
        data = {"b": 2, "a": 1, "c": [3, 4]}
        raw = canonical(data)
        self.assertEqual(raw, b'{"a":1,"b":2,"c":[3,4]}')
        parsed = parse(raw)
        self.assertEqual(parsed, data)

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


class StrictManifestBindingTests(unittest.TestCase):
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
        self.assertEqual(binding.c_sha, "c" * 40)
        self.assertEqual(binding.p_sha, PINNED_P_SHA)
        self.assertEqual(binding.w_sha, PINNED_W_SHA)

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


class LoopbackServerTests(unittest.TestCase):
    """Test actual loopback HTTP servers verifying Bearer token and redirect stripping."""

    @classmethod
    def setUpClass(cls):
        cls.expected_token = "secret-test-token-12345"
        cls.test_zip_payload = b"PK\x03\x04test-zip-payload-bytes"

        # Storage server handler: must return 401 if Authorization header is present
        class StorageHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization"):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Authorization header forbidden on storage endpoint")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.end_headers()
                self.wfile.write(cls.test_zip_payload)

            def log_message(self, format, *args):
                pass

        # API server handler: requires Bearer token, returns 302 to storage
        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {cls.expected_token}":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Unauthorized API call")
                    return

                if self.path.endswith("/zip"):
                    storage_url = f"http://127.0.0.1:{cls.storage_port}/storage/artifact.zip"
                    self.send_response(302)
                    self.send_header("Location", storage_url)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, format, *args):
                pass

        cls.storage_server = HTTPServer(("127.0.0.1", 0), StorageHandler)
        cls.storage_port = cls.storage_server.server_port
        cls.storage_thread = threading.Thread(target=cls.storage_server.serve_forever, daemon=True)
        cls.storage_thread.start()

        cls.api_server = HTTPServer(("127.0.0.1", 0), APIHandler)
        cls.api_port = cls.api_server.server_port
        cls.api_thread = threading.Thread(target=cls.api_server.serve_forever, daemon=True)
        cls.api_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.api_server.shutdown()
        cls.storage_server.shutdown()

    def test_loopback_download_zip_strips_auth_header(self):
        client = GitHubAPIClient(
            token=self.expected_token,
            base_url=f"http://127.0.0.1:{self.api_port}",
        )
        content = client.download_artifact_zip("test_artifact_id")
        self.assertEqual(content, self.test_zip_payload)

    def test_loopback_api_requires_token(self):
        bad_client = GitHubAPIClient(
            token="wrong-token",
            base_url=f"http://127.0.0.1:{self.api_port}",
        )
        with self.assertRaises(AuthorizationError) as ctx:
            bad_client.get_json("repos/jwaldrip/iyi")
        self.assertIn("HTTP 401", str(ctx.exception))


class SubprocessCLITests(unittest.TestCase):
    """Subprocess tests verifying exit code 5 on bad environment and exit code 2 on usage error."""

    def test_exit_5_on_bad_environment(self):
        # Run in isolated environment missing GITHUB_REPOSITORY
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": os.getcwd(),
            "GITHUB_REPOSITORY": "invalid/repository",
            "GITHUB_REPOSITORY_ID": PINNED_REPOSITORY_ID,
            "GITHUB_JOB": JOB_KEY_STRICT,
            "RUNNER_ENVIRONMENT": "github-hosted",
            "JOB_CHECK_RUN_ID": "12345",
            "GITHUB_REF": PINNED_REF,
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "c" * 40,
        }
        res = subprocess.run(
            [sys.executable, "-B", "-m", "proof.strict_authorization", "authorize", "--out-dir", "/tmp"],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, AUTH_REFUSED_EXIT_CODE)
        self.assertIn("STRICT_AUTHORIZATION_REFUSED", res.stderr)
        self.assertIn("RNR-1", res.stderr)

    def test_exit_2_on_usage_error(self):
        res = subprocess.run(
            [sys.executable, "-B", "-m", "proof.strict_authorization", "authorize"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, USAGE_ERROR_EXIT_CODE)


class UtilityCLITests(unittest.TestCase):
    def test_rail_summary_generation(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            pins_path = td_path / "pins.json"
            struct_path = td_path / "struct.json"
            out_path = td_path / "rail-validation-summary.json"

            with open(pins_path, "w", encoding="utf-8") as f:
                json.dump({"status": "PASS", "actions": PINNED_ACTIONS}, f)

            with open(struct_path, "w", encoding="utf-8") as f:
                json.dump({"status": "PASS", "workflow_structure": "PASS"}, f)

            env = {
                "GITHUB_SHA": "c" * 40,
                "GITHUB_RUN_ID": "1001",
                "GITHUB_RUN_ATTEMPT": "1",
            }
            code = main(
                ["rail-summary", "--out", str(out_path), "--pins-report", str(pins_path), "--structure-report", str(struct_path)],
                environ=env,
            )
            self.assertEqual(code, 0)
            self.assertTrue(out_path.is_file())

            with open(out_path, "rb") as f:
                data = json.load(f)
            self.assertEqual(data["schema"], SCHEMA_RAIL_SUMMARY)
            self.assertEqual(data["status"], "PASS")
            self.assertEqual(data["c_sha"], "c" * 40)
            self.assertEqual(data["run_id"], "1001")
            self.assertEqual(data["actions"], PINNED_ACTIONS)
            self.assertEqual(data["strict_refusal_controls"], PINNED_REFUSAL_CONTROLS)


if __name__ == "__main__":
    unittest.main()
