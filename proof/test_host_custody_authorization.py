import copy
import unittest

from host_custody_authorization import (ApprovalBinding, AuthorizationRefused,
                                        approval_claim_matches, authorize_runtime)
from test_host_custody_contract import subject_record


class AuthorizationTests(unittest.TestCase):
    def test_matching_fixture_is_never_authority(self):
        subject = subject_record()
        binding = ApprovalBinding.from_subject(subject)
        run = {k: subject[k] for k in ("repository", "source_revision", "workflow_path", "workflow_blob",
                                        "run", "attempt", "job", "branch")}
        decision = {"environment_id": "10", "reviewer_id": "20", "reviewer_login": "jason",
                    "state": "approved", "comment": binding.approval_comment}
        policy = dict(environment_id="10", reviewer_id="20", reviewer_login="jason")
        self.assertTrue(approval_claim_matches(binding, run, decision, **policy))
        with self.assertRaises(AuthorizationRefused):
            authorize_runtime(subject)
        for key, value in (("attempt", 2), ("branch", None), ("source_revision", "other"),
                           ("workflow_blob", "other"), ("job", "other")):
            candidate = copy.deepcopy(run)
            candidate[key] = value
            self.assertFalse(approval_claim_matches(binding, candidate, decision, **policy))
        for key, value in (("reviewer_id", "21"), ("reviewer_login", "other"),
                           ("environment_id", "11"), ("state", "rejected"),
                           ("comment", "host-custody-v1:" + "0" * 64)):
            candidate = copy.deepcopy(decision)
            candidate[key] = value
            self.assertFalse(approval_claim_matches(binding, run, candidate, **policy))
        changed = copy.deepcopy(subject)
        changed["attempt"] = 2
        self.assertFalse(approval_claim_matches(ApprovalBinding.from_subject(changed), run, decision, **policy))

    def test_malformed_or_missing_limits_refuse_and_no_bypass_arguments(self):
        subject = subject_record()
        del subject["limits"]["staging_deadline_ms"]
        with self.assertRaises(AuthorizationRefused):
            authorize_runtime(subject)
        with self.assertRaises(TypeError):
            authorize_runtime(subject_record(), approved=True)
