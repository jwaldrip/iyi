"""Held custody authorization. No supplied record is an authenticated platform read.

The matching helpers are offline diagnostics only. Runtime authorization cannot
succeed until an independently authenticated reviewer channel, personal approval
and platform qualification are implemented and reviewed.
"""
from dataclasses import dataclass

from host_custody_contract import subject_digest


class AuthorizationRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class ApprovalBinding:
    repository: str
    source_revision: str
    workflow_path: str
    workflow_blob: str
    run: int
    attempt: int
    job: str
    branch: str
    subject_digest: str

    @classmethod
    def from_subject(cls, subject):
        return cls(*(subject[k] for k in ("repository", "source_revision", "workflow_path",
                                           "workflow_blob", "run", "attempt", "job", "branch")),
                   subject_digest(subject))

    @property
    def approval_comment(self):
        return "host-custody-v1:" + self.subject_digest


def approval_claim_matches(binding, run, decision, *, environment_id, reviewer_id, reviewer_login):
    """Compare untrusted fixture claims, never verify authentication or issue a receipt.

    Production must instead use fresh authenticated platform reads, enforce the
    environment's reviewer and branch policies, reject conflicting decisions and
    independently verify review and platform qualification. This comparison is
    deliberately incapable of authorizing runtime.
    """
    if not isinstance(binding, ApprovalBinding) or type(run) is not dict or type(decision) is not dict:
        return False
    if not all(type(x) is str and x for x in (environment_id, reviewer_id, reviewer_login)):
        return False
    expected = {"repository": binding.repository, "source_revision": binding.source_revision,
                "workflow_path": binding.workflow_path, "workflow_blob": binding.workflow_blob,
                "run": binding.run, "attempt": binding.attempt, "job": binding.job,
                "branch": binding.branch}
    if any(type(run.get(k)) is not type(v) or run.get(k) != v for k, v in expected.items()):
        return False
    return (decision.get("environment_id") == environment_id and
            decision.get("reviewer_id") == reviewer_id and
            decision.get("reviewer_login") == reviewer_login and
            decision.get("state") == "approved" and
            decision.get("comment") == binding.approval_comment)


def authorize_runtime(subject):
    """Fail closed before privileged work, including for structurally valid claims.

    No caller-supplied issuer, approval, policy, test provider or flag is accepted.
    """
    try:
        subject_digest(subject)
    except (TypeError, ValueError) as exc:
        raise AuthorizationRefused("Invalid custody subject or mandatory limits") from exc
    raise AuthorizationRefused(
        "Independent review issuer, key policy and authenticated delivery are unavailable; "
        "personal exact-subject approval and platform qualification are not implemented."
    )
