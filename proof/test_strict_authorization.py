import copy
import json
import unittest

from proof.strict_authorization import (
    APPROVAL_COMMENT_PREFIX,
    AUDIT_SCHEMA,
    HARNESS_SCHEMA,
    MANIFEST_SCHEMA,
    PINNED_BRANCH,
    PINNED_ENVIRONMENT_ID,
    PINNED_ENVIRONMENT_NAME,
    PINNED_REF,
    PINNED_REPOSITORY,
    PINNED_REPOSITORY_ID,
    PINNED_REVIEWER_ID,
    PINNED_WORKFLOW_PATH,
    AuthenticatedGitHubVerifier,
    AuthorizationError,
    StrictAuthorizationRefused,
    VerifiedAuthorization,
    canonical,
    check_strict_authorization_or_refuse,
    digest,
    execute_harmless_effect_if_authorized,
    verify_candidate,
)


class AuthorizationCandidateTests(unittest.TestCase):
    def setUp(self):
        self.p_sha = "a" * 40
        self.w_sha = "b" * 40
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
            "producer": {"type": "workflow", "run_id": "24", "workflow_id": "20", "job_id": "101"},
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
            "producer": {"type": "reviewer", "identity": "independent-audit-runner", "run_id": "26", "workflow_id": "27"},
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
            "repository": {"id": int(PINNED_REPOSITORY_ID), "full_name": PINNED_REPOSITORY, "private": False},
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
            "strict_run": self.run_record("21", "20"),
            "harness_run": self.run_record("24", "20"),
            "audit_run": self.run_record("26", "27"),
            "approvals": [],
            "environment_job_count": 1,
            "selected_branch_policies": [{"name": PINNED_BRANCH, "type": "branch", "id": 31}],
            "artifact_bindings": {
                "harness": copy.deepcopy(self.manifest["harness"]),
                "audit": copy.deepcopy(self.manifest["audit"]),
            },
        }
        self.obs["context"]["workflow_sha"] = self.manifest["c_sha"]
        self.approve()

    def run_record(self, run_id, workflow_id):
        return {
            "id": int(run_id),
            "run_attempt": 1,
            "workflow_id": int(workflow_id),
            "head_sha": self.manifest["c_sha"],
            "repository": {"id": int(PINNED_REPOSITORY_ID)},
            "status": "completed",
            "conclusion": "success",
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

    def test_protection_rule_order_is_irrelevant(self):
        self.obs["environment"]["protection_rules"].reverse()
        auth = self.check()
        self.assertIsInstance(auth, VerifiedAuthorization)

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

    def test_context_and_evidence_substitution(self):
        for field in ("p_sha", "w_sha", "c_sha", "workflow_sha", "bundle_sha256", "workflow_id", "strict_run_id", "strict_ref", "environment_id"):
            with self.subTest(field=field):
                original = self.obs["context"][field]
                self.obs["context"][field] = "substituted"
                with self.assertRaises(AuthorizationError):
                    self.check()
                self.obs["context"][field] = original
        for run in ("strict_run", "harness_run", "audit_run"):
            with self.subTest(run=run):
                self.obs[run]["head_sha"] = "f" * 40
                with self.assertRaises(AuthorizationError):
                    self.check()
                self.obs[run]["head_sha"] = self.manifest["c_sha"]
        self.obs["artifact_bindings"]["harness"]["artifact_id"] = "99"
        with self.assertRaises(AuthorizationError):
            self.check()
        self.obs["artifact_bindings"]["harness"]["artifact_id"] = "23"
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(self.manifest), b"altered", self.audit_bytes, self.obs)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(self.manifest), self.harness_bytes, b"altered", self.obs)

    def test_rerun_refused_even_if_review_is_rebound(self):
        self.manifest["strict_run_attempt"] = "2"
        self.obs["context"]["strict_run_attempt"] = "2"
        self.obs["strict_run"]["run_attempt"] = 2
        self.approve()
        with self.assertRaises(AuthorizationError):
            self.check()

    def test_embedded_artifact_content_controls(self):
        # 1. Harness artifact: embedded run_attempt must be 1
        harness_copy = copy.deepcopy(self.harness_dict)
        harness_copy["run_attempt"] = "2"
        bad_harness_bytes = canonical(harness_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["harness"]["sha256"] = digest(bad_harness_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), bad_harness_bytes, self.audit_bytes, self.obs)

        # 2. Harness artifact: embedded c_sha mismatch
        harness_copy = copy.deepcopy(self.harness_dict)
        harness_copy["c_sha"] = "0" * 40
        bad_harness_bytes = canonical(harness_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["harness"]["sha256"] = digest(bad_harness_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), bad_harness_bytes, self.audit_bytes, self.obs)

        # 3. Harness artifact: verdict not PASS
        harness_copy = copy.deepcopy(self.harness_dict)
        harness_copy["verdict"] = "FAIL"
        bad_harness_bytes = canonical(harness_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["harness"]["sha256"] = digest(bad_harness_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), bad_harness_bytes, self.audit_bytes, self.obs)

        # 4. Audit artifact: verdict not GO
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["verdict"] = "NO-GO"
        bad_audit_bytes = canonical(audit_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["audit"]["sha256"] = digest(bad_audit_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), self.harness_bytes, bad_audit_bytes, self.obs)

        # 5. Audit artifact: producer same as harness producer (not independent)
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["producer"] = copy.deepcopy(self.harness_dict["producer"])
        bad_audit_bytes = canonical(audit_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["audit"]["sha256"] = digest(bad_audit_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), self.harness_bytes, bad_audit_bytes, self.obs)

        # 6. Audit artifact: untrusted producer type
        audit_copy = copy.deepcopy(self.audit_dict)
        audit_copy["producer"]["type"] = "self-attested"
        bad_audit_bytes = canonical(audit_copy)
        manifest_copy = copy.deepcopy(self.manifest)
        manifest_copy["audit"]["sha256"] = digest(bad_audit_bytes)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(manifest_copy), self.harness_bytes, bad_audit_bytes, self.obs)

    def test_duplicate_noncanonical_or_unknown_fields_refused(self):
        raw = canonical(self.manifest)
        with self.assertRaises(AuthorizationError):
            verify_candidate(raw[:-1] + b',"schema":"iyi.strict-authorization.v1"}', self.harness_bytes, self.audit_bytes, self.obs)
        with self.assertRaises(AuthorizationError):
            verify_candidate(raw + b"\n", self.harness_bytes, self.audit_bytes, self.obs)
        self.manifest["extra"] = True
        self.approve()
        with self.assertRaises(AuthorizationError):
            self.check()

    def test_non_native_harmless_effect(self):
        auth = self.check()
        receipt = execute_harmless_effect_if_authorized(auth)
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["manifest_digest"], auth.manifest_digest)
        self.assertEqual(receipt["environment_id"], PINNED_ENVIRONMENT_ID)
        self.assertEqual(receipt["effect"], "harmless-non-native-synthetic-proof-receipt")

        # Refusal when auth is not verified or None
        with self.assertRaises(StrictAuthorizationRefused):
            execute_harmless_effect_if_authorized(None)

    def test_check_strict_authorization_or_refuse_fails_closed(self):
        # In real execution without authentic verified_auth, check_strict_authorization_or_refuse MUST raise
        with self.assertRaises(StrictAuthorizationRefused) as ctx:
            check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha)
        self.assertIn("STRICT_MODE_AUTH_REFUSED", str(ctx.exception))
        self.assertIn("strict-proof", str(ctx.exception))
        self.assertIn(PINNED_REVIEWER_ID, str(ctx.exception))

        # With verified_auth, matching tuple succeeds
        auth = self.check()
        self.assertIsNone(check_strict_authorization_or_refuse(self.p_sha, self.w_sha, self.c_sha, verified_auth=auth))

        # Tuple mismatch with verified_auth raises
        with self.assertRaises(AuthorizationError):
            check_strict_authorization_or_refuse("wrong" * 8, self.w_sha, self.c_sha, verified_auth=auth)


class AuthenticatedGitHubVerifierTests(unittest.TestCase):
    """Synthetic mirror tests for AuthenticatedGitHubVerifier simulating GitHub REST responses."""

    def setUp(self):
        self.verifier = AuthenticatedGitHubVerifier(token="dummy-test-token", repository=PINNED_REPOSITORY)
        self.p_sha = "a" * 40
        self.w_sha = "b" * 40
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
            "producer": {"type": "workflow", "run_id": "24", "workflow_id": "20", "job_id": "101"},
        }
        self.harness_bytes = canonical(self.harness_dict)

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
            "producer": {"type": "reviewer", "identity": "independent-auditor", "run_id": "26", "workflow_id": "27"},
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

        # Simulated GitHub API responses
        self.simulated_api = {
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
                "repository": {"id": int(PINNED_REPOSITORY_ID)},
                "status": "in_progress",
            },
            f"repos/{PINNED_REPOSITORY}/actions/runs/24": {
                "id": 24,
                "run_attempt": 1,
                "workflow_id": 20,
                "head_sha": self.c_sha,
                "head_branch": PINNED_BRANCH,
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
        }
        self.verifier._api_get = self._mock_api_get

    def _mock_api_get(self, endpoint):
        key = endpoint.lstrip("/")
        if key in self.simulated_api:
            return copy.deepcopy(self.simulated_api[key])
        raise AuthorizationError(f"Simulated API 404 for {endpoint}")

    def test_authenticated_verifier_success(self):
        auth = self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)
        self.assertIsInstance(auth, VerifiedAuthorization)
        self.assertTrue(auth.is_authorized)
        self.assertEqual(auth.manifest_digest, digest(self.manifest_bytes))

    def test_authenticated_verifier_rejects_missing_approval(self):
        self.simulated_api[f"repos/{PINNED_REPOSITORY}/actions/runs/21/approvals"] = []
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)

    def test_authenticated_verifier_rejects_bypass_enabled(self):
        self.simulated_api[f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}"]["can_admins_bypass"] = True
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)

    def test_authenticated_verifier_rejects_wrong_reviewer(self):
        self.simulated_api[f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}"]["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 12345
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)

    def test_authenticated_verifier_rejects_wrong_branch_policy(self):
        self.simulated_api[f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies"]["branch_policies"][0]["name"] = "wrong-branch"
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)

    def test_authenticated_verifier_rejects_wrong_comment_digest(self):
        self.simulated_api[f"repos/{PINNED_REPOSITORY}/actions/runs/21/approvals"][0]["comment"] = APPROVAL_COMMENT_PREFIX + "0" * 64
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(self.manifest_bytes, self.harness_bytes, self.audit_bytes, self.runtime_context)


if __name__ == "__main__":
    unittest.main()
