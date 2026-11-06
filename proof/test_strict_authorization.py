import copy
import unittest

from proof.strict_authorization import AuthorizationError, canonical, digest, verify_candidate


class AuthorizationCandidateTests(unittest.TestCase):
    def setUp(self):
        self.harness = b"exact retained validation evidence\n"
        self.manifest = {
            "schema": "iyi.strict-authorization.v1", "repository": "jwaldrip/iyi",
            "repository_id": "1340355933", "p_sha": "a" * 40, "w_sha": "b" * 40,
            "c_sha": "c" * 40, "workflow_path": ".github/workflows/remote-strict-proof.yml",
            "workflow_id": "20", "strict_run_id": "21", "strict_run_attempt": "1",
            "strict_ref": "refs/heads/proof/trusted", "environment_id": "22",
            "bundle_sha256": "d" * 64,
            "harness": {"artifact_id": "23", "member": "validation.json", "sha256": digest(self.harness),
                        "run_id": "24", "run_attempt": "1", "workflow_id": "20"},
            "audit": {"artifact_id": "25", "member": "audit.json", "sha256": "e" * 64,
                      "run_id": "26", "run_attempt": "1", "workflow_id": "27"},
        }
        self.audit = canonical({"schema": "iyi.strict-independent-audit.v1", "verdict": "GO",
                                "repository_id": self.manifest["repository_id"],
                                "p_sha": self.manifest["p_sha"], "w_sha": self.manifest["w_sha"],
                                "c_sha": self.manifest["c_sha"], "harness_sha256": digest(self.harness),
                                "harness_run_id": "24", "harness_run_attempt": "1", "harness_workflow_id": "20"})
        self.manifest["audit"]["sha256"] = digest(self.audit)
        self.obs = {
            "context": {k: self.manifest[k] for k in ("repository", "repository_id", "p_sha", "w_sha", "c_sha", "workflow_path", "workflow_id", "strict_run_id", "strict_run_attempt", "strict_ref", "environment_id", "bundle_sha256")},
            "repository": {"id": 1340355933, "full_name": "jwaldrip/iyi", "private": False},
            "environment": {"id": 22, "name": "strict-proof", "can_admins_bypass": False,
                            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                                  "reviewers": [{"type": "User", "reviewer": {"id": 43164}}]},
                                                 {"type": "branch_policy"}]},
            "strict_run": self.run_record("21", "20"),
            "harness_run": self.run_record("24", "20"),
            "audit_run": self.run_record("26", "27"),
            "approvals": [], "environment_job_count": 1, "selected_branch_policies": [{"name": "proof/trusted", "type": "branch", "id": 31}],
            "artifact_bindings": {"harness": copy.deepcopy(self.manifest["harness"]), "audit": copy.deepcopy(self.manifest["audit"])},
        }
        self.obs["context"]["workflow_sha"] = self.manifest["c_sha"]
        self.approve()

    def run_record(self, run_id, workflow_id):
        return {"id": int(run_id), "run_attempt": 1, "workflow_id": int(workflow_id),
                "head_sha": self.manifest["c_sha"], "repository": {"id": 1340355933},
                "status": "completed", "conclusion": "success"}

    def approve(self):
        self.obs["approvals"] = [{"state": "approved", "user": {"id": 43164, "type": "User"},
                                  "comment": "iyi-strict-authorization-v1 sha256:" + digest(canonical(self.manifest)),
                                  "environments": [{"id": 22, "name": "strict-proof"}]}]

    def check(self):
        return verify_candidate(canonical(self.manifest), self.harness, self.audit, self.obs)

    def test_valid_candidate_is_not_authority(self):
        self.assertIsNone(self.check())

    def test_protection_rule_order_is_irrelevant(self):
        self.obs["environment"]["protection_rules"].reverse()
        self.assertIsNone(self.check())

    def test_environment_and_reviewer_negative_controls(self):
        changes = [
            ("bypass enabled", lambda o: o["environment"].update(can_admins_bypass=True)),
            ("bypass missing", lambda o: o["environment"].pop("can_admins_bypass")),
            ("wrong reviewer", lambda o: o["environment"]["protection_rules"][0]["reviewers"][0]["reviewer"].update(id=1)),
            ("self review forbidden", lambda o: o["environment"]["protection_rules"][0].update(prevent_self_review=True)),
            ("unprotected environment", lambda o: o["environment"].update(protection_rules=[])),
            ("wrong environment id", lambda o: o["environment"].update(id=1)),
            ("wrong approval identity", lambda o: o["approvals"][0]["user"].update(id=1)),
            ("wrong account type", lambda o: o["approvals"][0]["user"].update(type="Bot")),
            ("wrong approval digest", lambda o: o["approvals"][0].update(comment="iyi-strict-authorization-v1 sha256:" + "0" * 64)),
            ("empty approval", lambda o: o.update(approvals=[])),
            ("ambiguous reviews", lambda o: o["approvals"].append(copy.deepcopy(o["approvals"][0]))),
            ("rejection", lambda o: o["approvals"][0].update(state="rejected")),
            ("wrong approval environment", lambda o: o["approvals"][0]["environments"][0].update(id=1)),
            ("extra environment job", lambda o: o.update(environment_job_count=2)),
            ("private repo", lambda o: o["repository"].update(private=True)),
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
            verify_candidate(canonical(self.manifest), b"altered", self.audit, self.obs)
        with self.assertRaises(AuthorizationError):
            verify_candidate(canonical(self.manifest), self.harness, self.audit + b" ", self.obs)

    def test_rerun_refused_even_if_review_is_rebound(self):
        self.manifest["strict_run_attempt"] = "2"
        self.obs["context"]["strict_run_attempt"] = "2"
        self.obs["strict_run"]["run_attempt"] = 2
        self.approve()
        with self.assertRaises(AuthorizationError):
            self.check()

    def test_duplicate_noncanonical_or_unknown_fields_refused(self):
        raw = canonical(self.manifest)
        with self.assertRaises(AuthorizationError):
            verify_candidate(raw[:-1] + b',"schema":"iyi.strict-authorization.v1"}', self.harness, self.audit, self.obs)
        with self.assertRaises(AuthorizationError):
            verify_candidate(raw + b"\n", self.harness, self.audit, self.obs)
        self.manifest["extra"] = True
        self.approve()
        with self.assertRaises(AuthorizationError):
            self.check()

    def test_stale_or_non_go_audit_refused(self):
        for mutation in ({"verdict": "NO-GO"}, {"c_sha": "f" * 40}, {"harness_run_id": "99"}):
            import json
            value = json.loads(self.audit)
            value.update(mutation)
            self.audit = canonical(value)
            self.manifest["audit"]["sha256"] = digest(self.audit)
            self.obs["artifact_bindings"]["audit"]["sha256"] = digest(self.audit)
            self.approve()
            with self.assertRaises(AuthorizationError):
                self.check()
            self.setUp()


if __name__ == "__main__":
    unittest.main()
