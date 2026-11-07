"""Discriminating unit and hosted mirror tests for strict-proof authorization verifier.

Tests all security gates and failure modes:
  - Exact immutable VerifiedAuthorization invariants and tamper-proofing
  - Anchored P SHA (PR #147 head required, stale P1 rejected)
  - Environment policy, reviewer 43164, branch policy, bypass prevention
  - Replay prevention, strict run attempt == 1, in_progress status
  - Run ID isolation across strict, harness, and audit contexts
  - Evidence artifact content validation, verdicts (PASS / GO)
  - Producer independence and untrusted producer rejection
  - Payload tampering, digest mismatches, noncanonical JSON
  - Bundle fingerprint drift
  - Authenticated inherited IPC handoff and verification
  - Harmless visible effect receipt execution and refusal
  - Production refusal hook fail-closed behavior (exit 5)
  - Real loopback HTTP mirror tests exercising API faults (500, 404, 401),
    malicious/corrupted zip downloads, and end-to-end authenticated verification
"""

import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile

from proof.strict_authorization import (
    APPROVAL_COMMENT_PREFIX,
    AUDIT_SCHEMA,
    AUTH_REFUSED_EXIT_CODE,
    HARNESS_SCHEMA,
    HARMLESS_EFFECT_SCHEMA,
    MANIFEST_SCHEMA,
    PINNED_BRANCH,
    PINNED_ENVIRONMENT_ID,
    PINNED_ENVIRONMENT_NAME,
    PINNED_P_SHA,
    PINNED_REF,
    PINNED_REPOSITORY,
    PINNED_REPOSITORY_ID,
    PINNED_REVIEWER_ID,
    PINNED_W_SHA,
    PINNED_WORKFLOW_PATH,
    AuthenticatedGitHubVerifier,
    AuthorizationError,
    StrictAuthorizationRefused,
    VerifiedAuthorization,
    canonical,
    check_strict_authorization_or_refuse,
    digest,
    execute_harmless_effect_if_authorized,
    load_verified_authorization_from_ipc,
    verify_candidate,
)


class AuthorizationCandidateTests(unittest.TestCase):
    def setUp(self):
        self.p_sha = PINNED_P_SHA
        self.w_sha = PINNED_W_SHA
        self.c_sha = "c" * 40

        # Embedded harness validation evidence
        self.harness_dict = {
            "schema": HARNESS_SCHEMA,
            "verdict": "PASS",
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "run_id": "24",
            "run_attempt": "1",
            "workflow_id": "20",
            "producer": {
                "type": "workflow",
                "identity": "iyi-strict-harness-gate",
                "run_id": "24",
                "workflow_id": "20",
                "job_id": "101",
            },
        }
        self.harness_bytes = canonical(self.harness_dict)

        # Embedded independent audit evidence (produced by independent reviewer/auditor)
        self.audit_dict = {
            "schema": AUDIT_SCHEMA,
            "verdict": "GO",
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "harness_sha256": digest(self.harness_bytes),
            "harness_run_id": "24",
            "harness_run_attempt": "1",
            "harness_workflow_id": "20",
            "model_disclosure": {
                "model_involved": True,
                "implemented_change": False,
                "declaration": "Independent agent reviewer audit; cryptographic human approval via GitHub environment deployment approval.",
            },
            "report": {
                "summary": "Independent review of candidate C against P and W",
                "verdict": "GO",
                "findings": ["No unauthorized mutations observed", "Harness validation verified"],
            },
            "supporting_receipts": [
                {"receipt_id": "rec-001", "type": "p_w_c_tuple_proof", "status": "VERIFIED"},
                {"receipt_id": "rec-002", "type": "negative_controls_proof", "status": "VERIFIED"},
            ],
            "producer": {
                "type": "reviewer-agent",
                "identity": "independent-security-reviewer-agent",
                "run_id": "26",
                "workflow_id": "27",
                "job_id": "201",
            },
        }
        self.audit_bytes = canonical(self.audit_dict)

        self.manifest = {
            "schema": MANIFEST_SCHEMA,
            "repository": PINNED_REPOSITORY,
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "workflow_path": PINNED_WORKFLOW_PATH,
            "workflow_id": "20",
            "strict_run_id": "21",
            "strict_run_attempt": "1",
            "strict_ref": PINNED_REF,
            "environment_id": PINNED_ENVIRONMENT_ID,
            "bundle_sha256": "d" * 64,
            "harness": {
                "artifact_id": "23",
                "member": "validation.json",
                "sha256": digest(self.harness_bytes),
                "run_id": "24",
                "run_attempt": "1",
                "workflow_id": "20",
            },
            "audit": {
                "artifact_id": "25",
                "member": "audit.json",
                "sha256": digest(self.audit_bytes),
                "run_id": "26",
                "run_attempt": "1",
                "workflow_id": "27",
            },
        }

        self.obs = {
            "context": {
                k: self.manifest[k]
                for k in (
                    "repository",
                    "repository_id",
                    "p_sha",
                    "w_sha",
                    "c_sha",
                    "workflow_path",
                    "workflow_id",
                    "strict_run_id",
                    "strict_run_attempt",
                    "strict_ref",
                    "environment_id",
                    "bundle_sha256",
                )
            },
            "repository": {
                "id": int(PINNED_REPOSITORY_ID),
                "full_name": PINNED_REPOSITORY,
                "private": False,
            },
            "environment": {
                "id": int(PINNED_ENVIRONMENT_ID),
                "name": PINNED_ENVIRONMENT_NAME,
                "can_admins_bypass": False,
                "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": False,
                        "reviewers": [{"type": "User", "reviewer": {"id": int(PINNED_REVIEWER_ID)}}],
                    },
                    {"type": "branch_policy"},
                ],
            },
            "strict_run": self.run_record("21", "20", status="in_progress"),
            "harness_run": self.run_record("24", "20", status="completed", conclusion="success"),
            "audit_run": self.run_record("26", "27", status="completed", conclusion="success"),
            "approvals": [],
            "environment_job_count": 1,
            "selected_branch_policies": [{"name": PINNED_BRANCH, "type": "branch", "id": 65877824}],
            "artifact_bindings": {
                "harness": {
                    "artifact_id": "23",
                    "run_id": "24",
                    "head_sha": self.c_sha,
                    "expired": False,
                },
                "audit": {
                    "artifact_id": "25",
                    "run_id": "26",
                    "head_sha": self.c_sha,
                    "expired": False,
                },
            },
        }
        self.obs["context"]["workflow_sha"] = self.manifest["c_sha"]
        self.approve()

    def run_record(self, run_id, workflow_id, status="completed", conclusion="success"):
        return {
            "id": int(run_id),
            "run_attempt": 1,
            "workflow_id": int(workflow_id),
            "head_sha": self.manifest["c_sha"],
            "head_branch": PINNED_BRANCH,
            "path": PINNED_WORKFLOW_PATH,
            "event": "workflow_dispatch",
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
            "status": status,
            "conclusion": conclusion,
        }

    def approve(self):
        self.obs["approvals"] = [
            {
                "state": "approved",
                "user": {"id": int(PINNED_REVIEWER_ID), "type": "User"},
                "comment": APPROVAL_COMMENT_PREFIX + digest(canonical(self.manifest)),
                "environments": [{"id": int(PINNED_ENVIRONMENT_ID), "name": PINNED_ENVIRONMENT_NAME}],
            }
        ]

    def check(self):
        return verify_candidate(canonical(self.manifest), self.harness_bytes, self.audit_bytes, self.obs)

    def test_valid_candidate_returns_verified_authorization(self):
        auth = self.check()
        self.assertIsInstance(auth, VerifiedAuthorization)
        self.assertTrue(auth.is_authorized)
        self.assertEqual(auth.manifest_digest, digest(canonical(self.manifest)))
        self.assertEqual(auth.environment_id, PINNED_ENVIRONMENT_ID)
        self.assertEqual(auth.reviewer_id, PINNED_REVIEWER_ID)
        self.assertEqual(auth.strict_ref, PINNED_REF)
        self.assertEqual(auth.p_sha, PINNED_P_SHA)
        self.assertEqual(auth.w_sha, PINNED_W_SHA)

    def test_verified_authorization_is_frozen_and_immutable(self):
        auth = self.check()
        with self.assertRaises(AttributeError):
            auth.is_authorized = False  # type: ignore
        with self.assertRaises(AttributeError):
            auth.p_sha = "0" * 40  # type: ignore
        with self.assertRaises(AttributeError):
            auth.manifest_digest = "tampered"  # type: ignore

    def test_rejects_stale_p1_sha(self):
        # Old P1: 626463375298d357ffcb3223059f4d3adce6fb10 must be strictly refused
        stale_p = "626463375298d357ffcb3223059f4d3adce6fb10"
        self.manifest["p_sha"] = stale_p
        self.obs["context"]["p_sha"] = stale_p
        self.approve()
        with self.assertRaises(AuthorizationError) as ctx:
            self.check()
        self.assertIn("PR #147 head required", str(ctx.exception))

    def test_environment_and_reviewer_negative_controls(self):
        changes = [
            ("bypass enabled", lambda o: o["environment"].update(can_admins_bypass=True)),
            ("bypass missing", lambda o: o["environment"].pop("can_admins_bypass")),
            ("wrong reviewer", lambda o: o["environment"]["protection_rules"][0]["reviewers"][0]["reviewer"].update(id=1)),
            ("self review forbidden", lambda o: o["environment"]["protection_rules"][0].update(prevent_self_review=True)),
            ("unprotected environment", lambda o: o["environment"].update(protection_rules=[])),
            ("wrong environment id", lambda o: o["environment"].update(id=1)),
            ("wrong environment name", lambda o: o["environment"].update(name="wrong-env")),
            ("wrong approval identity", lambda o: o["approvals"][0]["user"].update(id=1)),
            ("wrong account type", lambda o: o["approvals"][0]["user"].update(type="Bot")),
            ("wrong approval digest", lambda o: o["approvals"][0].update(comment=APPROVAL_COMMENT_PREFIX + "0" * 64)),
            ("empty approval comment", lambda o: o["approvals"][0].update(comment="")),
            ("empty approval", lambda o: o.update(approvals=[])),
            ("ambiguous reviews", lambda o: o["approvals"].append(copy.deepcopy(o["approvals"][0]))),
            ("rejection", lambda o: o["approvals"][0].update(state="rejected")),
            ("wrong approval environment id", lambda o: o["approvals"][0]["environments"][0].update(id=1)),
            ("wrong approval environment name", lambda o: o["approvals"][0]["environments"][0].update(name="other")),
            ("extra environment job", lambda o: o.update(environment_job_count=2)),
            ("zero environment jobs", lambda o: o.update(environment_job_count=0)),
            ("private repo", lambda o: o["repository"].update(private=True)),
            ("wrong repo id", lambda o: o["repository"].update(id=999)),
            ("wrong branch policy", lambda o: o["selected_branch_policies"][0].update(name="*")),
            ("tag policy", lambda o: o["selected_branch_policies"][0].update(type="tag")),
            ("missing policy type", lambda o: o["selected_branch_policies"][0].pop("type")),
            ("missing branch rule", lambda o: o["environment"]["protection_rules"].pop()),
            ("duplicate reviewer rule", lambda o: o["environment"]["protection_rules"].__setitem__(1, copy.deepcopy(o["environment"]["protection_rules"][0]))),
            ("unknown rule", lambda o: o["environment"]["protection_rules"].append({"type": "wait_timer"})),
            ("extra policy", lambda o: o["selected_branch_policies"].append({"name": "*", "type": "branch"})),
            ("protected branches only", lambda o: o["environment"].update(deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False})),
        ]
        baseline = copy.deepcopy(self.obs)
        for label, mutate in changes:
            with self.subTest(label=label):
                self.obs = copy.deepcopy(baseline)
                mutate(self.obs)
                with self.assertRaises(AuthorizationError):
                    self.check()

    def test_strict_run_replay_prevention_controls(self):
        # Strict run must be in_progress on attempt 1, matching workflow_dispatch and pinned branch
        replays = [
            ("completed run replay", lambda o: o["strict_run"].update(status="completed")),
            ("wrong attempt", lambda o: o["strict_run"].update(run_attempt=2)),
            ("wrong head branch", lambda o: o["strict_run"].update(head_branch="master")),
            ("wrong event", lambda o: o["strict_run"].update(event="push")),
            ("wrong path", lambda o: o["strict_run"].update(path=".github/workflows/other.yml")),
            ("wrong head sha", lambda o: o["strict_run"].update(head_sha="0" * 40)),
        ]
        baseline = copy.deepcopy(self.obs)
        for label, mutate in replays:
            with self.subTest(label=label):
                self.obs = copy.deepcopy(baseline)
                mutate(self.obs)
                with self.assertRaises(AuthorizationError):
                    self.check()

    def test_run_id_isolation_controls(self):
        # Audit run ID cannot match harness run ID
        self.manifest["audit"]["run_id"] = self.manifest["harness"]["run_id"]
        self.approve()
        with self.assertRaises(AuthorizationError) as ctx:
            self.check()
        self.assertIn("distinct", str(ctx.exception))

        # Harness run ID cannot match strict run ID
        self.setUp()
        self.manifest["harness"]["run_id"] = self.manifest["strict_run_id"]
        self.approve()
        with self.assertRaises(AuthorizationError) as ctx:
            self.check()
        self.assertIn("distinct", str(ctx.exception))

        # Audit run ID cannot match strict run ID
        self.setUp()
        self.manifest["audit"]["run_id"] = self.manifest["strict_run_id"]
        self.approve()
        with self.assertRaises(AuthorizationError) as ctx:
            self.check()
        self.assertIn("distinct", str(ctx.exception))

    def test_bundle_drift_rejected(self):
        # Manifest bundle_sha256 mismatch with actual runtime context
        self.obs["context"]["bundle_sha256"] = "e" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            self.check()
        self.assertIn("bundle_sha256", str(ctx.exception))

    def test_artifact_provenance_binding_controls(self):
        # 1. Expired harness artifact rejected
        self.obs["artifact_bindings"]["harness"]["expired"] = True
        with self.assertRaises(AuthorizationError):
            self.check()
        self.obs["artifact_bindings"]["harness"]["expired"] = False

        # 2. Expired audit artifact rejected
        self.obs["artifact_bindings"]["audit"]["expired"] = True
        with self.assertRaises(AuthorizationError):
            self.check()
        self.obs["artifact_bindings"]["audit"]["expired"] = False

        # 3. Artifact associated with wrong run ID
        self.obs["artifact_bindings"]["harness"]["run_id"] = "999"
        with self.assertRaises(AuthorizationError):
            self.check()
        self.obs["artifact_bindings"]["harness"]["run_id"] = "24"

        # 4. Artifact associated with wrong commit SHA
        self.obs["artifact_bindings"]["audit"]["head_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError):
            self.check()

    def test_producer_independence_and_malicious_producer_controls(self):
        # 1. Audit producer identical to harness producer
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["producer"] = copy.deepcopy(self.harness_dict["producer"])
        bad_audit_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_audit_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError) as ctx:
            verify_candidate(canonical(m), self.harness_bytes, bad_audit_bytes, self.obs)
        self.assertIn("independent", str(ctx.exception))

        # 2. Audit producer run ID same as harness producer run ID
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["producer"]["run_id"] = self.harness_dict["producer"]["run_id"]
        bad_audit_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_audit_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError) as ctx:
            verify_candidate(canonical(m), self.harness_bytes, bad_audit_bytes, self.obs)
        self.assertIn("independent", str(ctx.exception))

        # 3. Malicious / untrusted producer type
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["producer"]["type"] = "self-attested-actor"
        bad_audit_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_audit_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError) as ctx:
            verify_candidate(canonical(m), self.harness_bytes, bad_audit_bytes, self.obs)
        self.assertIn("untrusted audit producer type", str(ctx.exception))

        # 4. Harness verdict not strictly PASS (rejects SUCCESS, GO, etc.)
        for bad_verdict in ("SUCCESS", "GO", "OK", "FAIL"):
            harness_copy = copy.deepcopy(self.harness_dict)
            harness_copy["verdict"] = bad_verdict
            bad_harness_bytes = canonical(harness_copy)
            m = copy.deepcopy(self.manifest)
            m["harness"]["sha256"] = digest(bad_harness_bytes)
            self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
            with self.assertRaises(AuthorizationError):
                verify_candidate(canonical(m), bad_harness_bytes, self.audit_bytes, self.obs)

        # 5. Audit verdict not strictly GO (rejects PASS, SUCCESS, NO-GO)
        for bad_verdict in ("PASS", "SUCCESS", "NO-GO", "FAIL"):
            audit_copy = copy.deepcopy(self.audit_dict)
            audit_copy["verdict"] = bad_verdict
            bad_audit_bytes = canonical(audit_copy)
            m = copy.deepcopy(self.manifest)
            m["audit"]["sha256"] = digest(bad_audit_bytes)
            self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
            with self.assertRaises(AuthorizationError):
                verify_candidate(canonical(m), self.harness_bytes, bad_audit_bytes, self.obs)

    def test_audit_implemented_change_rejected(self):
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["model_disclosure"]["implemented_change"] = True
        bad_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError) as ctx:
            verify_candidate(canonical(m), self.harness_bytes, bad_bytes, self.obs)
        self.assertIn("must not have implemented the change", str(ctx.exception))

    def test_audit_missing_model_disclosure_rejected(self):
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["model_disclosure"]["model_involved"] = False
        bad_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError) as ctx:
            verify_candidate(canonical(m), self.harness_bytes, bad_bytes, self.obs)
        self.assertIn("disclose model involvement", str(ctx.exception))

    def test_audit_report_and_supporting_receipts_controls(self):
        # 1. Missing report
        audit_copy = copy.deepcopy(self.audit_dict)
        del audit_copy["report"]
        bad_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(m), self.harness_bytes, bad_bytes, self.obs)

        # 2. Non-GO report verdict
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["report"]["verdict"] = "NO-GO"
        bad_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(m), self.harness_bytes, bad_bytes, self.obs)

        # 3. Empty supporting receipts
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["supporting_receipts"] = []
        bad_bytes = canonical(audit_copy)
        m = copy.deepcopy(self.manifest)
        m["audit"]["sha256"] = digest(bad_bytes)
        self.obs["approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + digest(canonical(m))
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(m), self.harness_bytes, bad_bytes, self.obs)

    def test_ipc_ack_tampered_digest_rejected(self):
        valid_ack = {
            "protocol_version": 1,
            "event": "authorization-ack",
            "request_id": "auth-req-1",
            "invocation_id": "strict-21-1",
            "verified": True,
            "manifest_raw": canonical(self.manifest).decode("utf-8"),
            "manifest_digest": digest(canonical(self.manifest)),
            "harness_raw": self.harness_bytes.decode("utf-8"),
            "audit_raw": self.audit_bytes.decode("utf-8"),
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
        }
        # Tampered manifest digest
        tampered_ack = copy.deepcopy(valid_ack)
        tampered_ack["manifest_digest"] = "0" * 64
        with self.assertRaises(AuthorizationError) as ctx:
            load_verified_authorization_from_ipc(tampered_ack, self.p_sha, self.w_sha, self.c_sha)
        self.assertIn("manifest digest mismatch", str(ctx.exception))

        # Tampered harness raw bytes
        tampered_harness_ack = copy.deepcopy(valid_ack)
        tampered_harness_ack["harness_raw"] = '{"tampered": true}'
        with self.assertRaises(AuthorizationError) as ctx:
            load_verified_authorization_from_ipc(tampered_harness_ack, self.p_sha, self.w_sha, self.c_sha)
        self.assertIn("harness bytes digest mismatch", str(ctx.exception))

    def test_ipc_handoff_and_reconstruction(self):
        auth = self.check()
        valid_ack = {
            "protocol_version": 1,
            "event": "authorization-ack",
            "request_id": "auth-req-1",
            "invocation_id": "strict-21-1",
            "verified": True,
            "manifest_raw": canonical(self.manifest).decode("utf-8"),
            "manifest_digest": digest(canonical(self.manifest)),
            "harness_raw": self.harness_bytes.decode("utf-8"),
            "audit_raw": self.audit_bytes.decode("utf-8"),
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
        }

        reconstructed = load_verified_authorization_from_ipc(valid_ack, self.p_sha, self.w_sha, self.c_sha)
        self.assertIsInstance(reconstructed, VerifiedAuthorization)
        self.assertTrue(reconstructed.is_authorized)
        self.assertEqual(reconstructed.manifest_digest, auth.manifest_digest)

        # Refusal ACK fails closed
        refused_ack = {
            "protocol_version": 1,
            "event": "authorization-ack",
            "verified": False,
            "error": "STRICT_MODE_AUTH_REFUSED",
        }
        with self.assertRaises(AuthorizationError):
            load_verified_authorization_from_ipc(refused_ack, self.p_sha, self.w_sha, self.c_sha)

        # Revision mismatch in ACK fails closed
        bad_ack = copy.deepcopy(valid_ack)
        bad_ack["p_sha"] = "0" * 40
        with self.assertRaises(AuthorizationError):
            load_verified_authorization_from_ipc(bad_ack, self.p_sha, self.w_sha, self.c_sha)

    def test_harmless_effect_execution_and_refusal(self):
        auth = self.check()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            receipt = execute_harmless_effect_if_authorized(auth, output_path=temp_path)
            self.assertEqual(receipt["schema"], HARMLESS_EFFECT_SCHEMA)
            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["manifest_digest"], auth.manifest_digest)
            self.assertEqual(receipt["p_sha"], auth.p_sha)
            self.assertEqual(receipt["w_sha"], auth.w_sha)
            self.assertEqual(receipt["c_sha"], auth.c_sha)
            self.assertTrue(os.path.exists(temp_path))

            with open(temp_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["status"], "PASS")

            # Refusal when auth is None or invalid
            with self.assertRaises(StrictAuthorizationRefused):
                execute_harmless_effect_if_authorized(None)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_check_strict_authorization_or_refuse_fails_closed_in_production(self):
        # In real execution without authentic verified_auth, check_strict_authorization_or_refuse MUST raise
        with self.assertRaises(StrictAuthorizationRefused) as ctx:
            check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha)
        msg = str(ctx.exception)
        self.assertIn("STRICT_MODE_AUTH_REFUSED", msg)
        self.assertIn("strict-proof", msg)
        self.assertIn(PINNED_REVIEWER_ID, msg)
        self.assertIn(str(AUTH_REFUSED_EXIT_CODE), msg)

        # With authentic verified_auth, valid tuple succeeds
        auth = self.check()
        self.assertIsNone(check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha, verified_auth=auth))

        # Tuple mismatch with verified_auth raises AuthorizationError
        with self.assertRaises(AuthorizationError):
            check_strict_authorization_or_refuse(self.p_sha, self.w_sha, "0" * 40, verified_auth=auth)


class LoopbackGitHubMockHandler(BaseHTTPRequestHandler):
    """Real HTTP handler serving simulated GitHub API endpoints and artifact zip streams."""

    routes = {}
    artifact_zips = {}
    faults = {}

    def log_message(self, format, *args):
        pass  # Suppress HTTP server stderr logs in test runs

    def do_GET(self):
        path = self.path.split("?")[0].lstrip("/")
        auth_header = self.headers.get("Authorization", "")

        # Verify Bearer token is provided
        if not auth_header.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"message":"Bad credentials"}')
            return

        # Check for simulated fault injection
        if path in self.faults:
            code, body = self.faults[path]
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8") if isinstance(body, str) else body)
            return

        if path in self.artifact_zips:
            zip_bytes = self.artifact_zips[path]
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(zip_bytes)))
            self.end_headers()
            self.wfile.write(zip_bytes)
            return

        if path in self.routes:
            data = self.routes[path]
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message":"Not Found"}')


class AuthenticatedGitHubVerifierLoopbackTests(unittest.TestCase):
    """Hosted mirror tests for AuthenticatedGitHubVerifier using real loopback HTTP socket server.

    Exercises actual HTTP wire requests, header authentication, status codes,
    zip archive download/decompression, and error fail-closed handling.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), LoopbackGitHubMockHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        LoopbackGitHubMockHandler.routes.clear()
        LoopbackGitHubMockHandler.artifact_zips.clear()
        LoopbackGitHubMockHandler.faults.clear()

        self.token = "valid-ci-token-test-secret"
        self.verifier = AuthenticatedGitHubVerifier(
            token=self.token,
            base_url=self.base_url,
            repository=PINNED_REPOSITORY,
            allow_loopback=True,
        )

        self.p_sha = PINNED_P_SHA
        self.w_sha = PINNED_W_SHA
        self.c_sha = "c" * 40

        self.harness_dict = {
            "schema": HARNESS_SCHEMA,
            "verdict": "PASS",
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "run_id": "24",
            "run_attempt": "1",
            "workflow_id": "20",
            "producer": {
                "type": "workflow",
                "identity": "iyi-strict-harness-gate",
                "run_id": "24",
                "workflow_id": "20",
                "job_id": "101",
            },
        }
        self.harness_bytes = canonical(self.harness_dict)

        # Embedded independent audit evidence (produced by independent reviewer/auditor)
        self.audit_dict = {
            "schema": AUDIT_SCHEMA,
            "verdict": "GO",
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "harness_sha256": digest(self.harness_bytes),
            "harness_run_id": "24",
            "harness_run_attempt": "1",
            "harness_workflow_id": "20",
            "model_disclosure": {
                "model_involved": True,
                "implemented_change": False,
                "declaration": "Independent agent reviewer audit; cryptographic human approval via GitHub environment deployment approval.",
            },
            "report": {
                "summary": "Independent review of candidate C against P and W",
                "verdict": "GO",
                "findings": ["No unauthorized mutations observed", "Harness validation verified"],
            },
            "supporting_receipts": [
                {"receipt_id": "rec-001", "type": "p_w_c_tuple_proof", "status": "VERIFIED"},
                {"receipt_id": "rec-002", "type": "negative_controls_proof", "status": "VERIFIED"},
            ],
            "producer": {
                "type": "reviewer-agent",
                "identity": "independent-security-reviewer-agent",
                "run_id": "26",
                "workflow_id": "27",
                "job_id": "201",
            },
        }
        self.audit_bytes = canonical(self.audit_dict)

        # Build real ZIP archives for artifacts
        self.harness_zip = self._create_zip("validation.json", self.harness_bytes)
        self.audit_zip = self._create_zip("audit.json", self.audit_bytes)

        self.manifest = {
            "schema": MANIFEST_SCHEMA,
            "repository": PINNED_REPOSITORY,
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "c_sha": self.c_sha,
            "workflow_path": PINNED_WORKFLOW_PATH,
            "workflow_id": "20",
            "strict_run_id": "21",
            "strict_run_attempt": "1",
            "strict_ref": PINNED_REF,
            "environment_id": PINNED_ENVIRONMENT_ID,
            "bundle_sha256": "d" * 64,
            "harness": {
                "artifact_id": "23",
                "member": "validation.json",
                "sha256": digest(self.harness_bytes),
                "run_id": "24",
                "run_attempt": "1",
                "workflow_id": "20",
            },
            "audit": {
                "artifact_id": "25",
                "member": "audit.json",
                "sha256": digest(self.audit_bytes),
                "run_id": "26",
                "run_attempt": "1",
                "workflow_id": "27",
            },
        }
        self.manifest_bytes = canonical(self.manifest)

        self.runtime_context = {
            k: self.manifest[k]
            for k in (
                "repository",
                "repository_id",
                "p_sha",
                "w_sha",
                "c_sha",
                "workflow_path",
                "workflow_id",
                "strict_run_id",
                "strict_run_attempt",
                "strict_ref",
                "environment_id",
                "bundle_sha256",
            )
        }
        self.runtime_context["workflow_sha"] = self.c_sha

        # Configure mock API routes
        LoopbackGitHubMockHandler.routes.update({
            f"repos/{PINNED_REPOSITORY}": {
                "id": int(PINNED_REPOSITORY_ID),
                "full_name": PINNED_REPOSITORY,
                "private": False,
            },
            f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}": {
                "id": int(PINNED_ENVIRONMENT_ID),
                "name": PINNED_ENVIRONMENT_NAME,
                "can_admins_bypass": False,
                "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": False,
                        "reviewers": [{"type": "User", "reviewer": {"id": int(PINNED_REVIEWER_ID)}}],
                    },
                    {"type": "branch_policy"},
                ],
            },
            f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies": {
                "total_count": 1,
                "branch_policies": [{"name": PINNED_BRANCH, "type": "branch", "id": 65877824}],
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/21": {
                "id": 21,
                "run_attempt": 1,
                "workflow_id": 20,
                "head_sha": self.c_sha,
                "head_branch": PINNED_BRANCH,
                "path": PINNED_WORKFLOW_PATH,
                "event": "workflow_dispatch",
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
                "status": "in_progress",
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/24": {
                "id": 24,
                "run_attempt": 1,
                "workflow_id": 20,
                "head_sha": self.c_sha,
                "head_branch": PINNED_BRANCH,
                "path": PINNED_WORKFLOW_PATH,
                "event": "workflow_dispatch",
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
                "status": "completed",
                "conclusion": "success",
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/26": {
                "id": 26,
                "run_attempt": 1,
                "workflow_id": 27,
                "head_sha": self.c_sha,
                "head_branch": PINNED_BRANCH,
                "path": PINNED_WORKFLOW_PATH,
                "event": "workflow_dispatch",
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
                "status": "completed",
                "conclusion": "success",
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/21/approvals": [
                {
                    "state": "approved",
                    "user": {"id": int(PINNED_REVIEWER_ID), "type": "User"},
                    "comment": APPROVAL_COMMENT_PREFIX + digest(self.manifest_bytes),
                    "environments": [{"id": int(PINNED_ENVIRONMENT_ID), "name": PINNED_ENVIRONMENT_NAME}],
                }
            ],
            f"repos/{PINNED_REPOSITORY}/actions/runs/21/attempts/1/jobs": {
                "total_count": 1,
                "jobs": [{"id": 301, "name": "strict-chain", "status": "in_progress"}],
            },
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/23": {
                "id": 23,
                "name": "harness-evidence",
                "expired": False,
                "workflow_run": {"id": 24, "head_sha": self.c_sha},
            },
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/25": {
                "id": 25,
                "name": "audit-evidence",
                "expired": False,
                "workflow_run": {"id": 26, "head_sha": self.c_sha},
            },
        })

        LoopbackGitHubMockHandler.artifact_zips.update({
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/23/zip": self.harness_zip,
            f"repos/{PINNED_REPOSITORY}/actions/artifacts/25/zip": self.audit_zip,
        })

    def _create_zip(self, filename: str, content: bytes) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(filename, content)
        return bio.getvalue()

    def test_loopback_e2e_verification_and_artifact_download(self):
        # End-to-end verification over real HTTP socket
        auth = self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIsInstance(auth, VerifiedAuthorization)
        self.assertTrue(auth.is_authorized)
        self.assertEqual(auth.manifest_digest, digest(self.manifest_bytes))
        self.assertEqual(auth.p_sha, PINNED_P_SHA)
        self.assertEqual(auth.w_sha, PINNED_W_SHA)

    def test_loopback_api_fault_http_500_fails_closed(self):
        LoopbackGitHubMockHandler.faults[f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}"] = (
            500,
            '{"message": "Internal Server Error"}',
        )
        with self.assertRaises(AuthorizationError) as ctx:
            self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("HTTP 500", str(ctx.exception))

    def test_loopback_api_fault_http_404_fails_closed(self):
        LoopbackGitHubMockHandler.faults[f"repos/{PINNED_REPOSITORY}/actions/runs/21/approvals"] = (
            404,
            '{"message": "Not Found"}',
        )
        with self.assertRaises(AuthorizationError) as ctx:
            self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("HTTP 404", str(ctx.exception))

    def test_loopback_api_fault_http_401_fails_closed(self):
        # Missing or bad token triggers 401
        bad_verifier = AuthenticatedGitHubVerifier(
            token="unrecognized-bad-token",
            base_url=self.base_url,
            repository=PINNED_REPOSITORY,
            allow_loopback=True,
        )
        # Handler responds 401 if header does not start with Bearer valid
        LoopbackGitHubMockHandler.faults[f"repos/{PINNED_REPOSITORY}"] = (401, '{"message": "Unauthorized"}')
        with self.assertRaises(AuthorizationError) as ctx:
            bad_verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("HTTP 401", str(ctx.exception))

    def test_loopback_corrupted_zip_payload_fails_closed(self):
        LoopbackGitHubMockHandler.artifact_zips[f"repos/{PINNED_REPOSITORY}/actions/artifacts/23/zip"] = b"not-a-valid-zip-archive"
        with self.assertRaises(AuthorizationError) as ctx:
            self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("Corrupted zip archive", str(ctx.exception))

    def test_loopback_expired_artifact_metadata_fails_closed(self):
        LoopbackGitHubMockHandler.routes[f"repos/{PINNED_REPOSITORY}/actions/artifacts/23"]["expired"] = True
        with self.assertRaises(AuthorizationError) as ctx:
            self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("expired", str(ctx.exception))

    def test_loopback_missing_zip_member_fails_closed(self):
        empty_zip = self._create_zip("wrong_filename.json", b"{}")
        LoopbackGitHubMockHandler.artifact_zips[f"repos/{PINNED_REPOSITORY}/actions/artifacts/23/zip"] = empty_zip
        with self.assertRaises(AuthorizationError) as ctx:
            self.verifier.verify(self.manifest_bytes, runtime_context=self.runtime_context)
        self.assertIn("not found in artifact", str(ctx.exception))

    def test_untrusted_api_base_url_rejected(self):
        with self.assertRaises(AuthorizationError) as ctx:
            AuthenticatedGitHubVerifier(token="token", base_url="https://evil-attacker-site.com")
        self.assertIn("Untrusted API base URL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
