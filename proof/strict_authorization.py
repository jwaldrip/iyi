"""Fail-closed checks for a prospective strict-proof authorization.

This module does not enable native execution. Its caller must obtain every
observation independently from authenticated GitHub APIs and immutable artifact
IDs. In particular, accepting caller-provided dictionaries is not an API or
trust boundary. The production controller retains its unconditional refusal.

Canonical JSON is UTF-8, sorted keys, compact separators, ASCII escapes, no
trailing newline, duplicate keys or non-finite numbers. Evidence hashes cover
the exact downloaded artifact member bytes, not an extracted JSON value.
"""

import hashlib
import json
import re


class AuthorizationError(ValueError):
    pass


def reject(message):
    raise AuthorizationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: reject("invalid JSON constant"))
        if canonical(value) != raw:
            reject("noncanonical JSON")
        return value
    except (ValueError, UnicodeError, TypeError) as exc:
        raise AuthorizationError("invalid canonical JSON") from exc


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        reject("unexpected object schema")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(value, length):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        reject("invalid digest")


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        reject("invalid decimal identifier")


def verify_candidate(manifest_bytes, harness_bytes, audit_bytes, observations):
    """Validate observations, returning no authority to execute strict mode.

    The independent audit bytes are canonical JSON of the exact schema checked
    below. A GO is a machine-readable audit verdict, never human approval.
    Observations must be authenticated API results plus immutable, independently
    resolved local checkout and artifact identities. Callers cannot use this
    function alone to establish their provenance or independence.
    """
    m = parse(manifest_bytes)
    keys(m, {"schema", "repository", "repository_id", "p_sha", "w_sha", "c_sha",
             "workflow_path", "workflow_id", "strict_run_id", "strict_run_attempt",
             "strict_ref", "environment_id", "harness", "audit", "bundle_sha256"})
    if m["schema"] != "iyi.strict-authorization.v1":
        reject("wrong schema")
    for field in ("p_sha", "w_sha", "c_sha"):
        sha(m[field], 40)
    sha(m["bundle_sha256"], 64)
    for field in ("repository_id", "workflow_id", "strict_run_id", "strict_run_attempt", "environment_id"):
        decimal(m[field])
    if m["repository"] != "jwaldrip/iyi" or m["repository_id"] != "1340355933":
        reject("wrong repository")
    if m["strict_run_attempt"] != "1":
        reject("reruns cannot be authorized")
    if not isinstance(m["strict_ref"], str) or not m["strict_ref"].startswith("refs/heads/"):
        reject("strict ref must be a branch ref")
    if m["workflow_path"] != ".github/workflows/remote-strict-proof.yml":
        reject("wrong workflow")
    for field in ("harness", "audit"):
        keys(m[field], {"artifact_id", "member", "sha256", "run_id", "run_attempt", "workflow_id"})
        for key in ("artifact_id", "run_id", "run_attempt", "workflow_id"):
            decimal(m[field][key])
        sha(m[field]["sha256"], 64)
        if not isinstance(m[field]["member"], str) or not m[field]["member"] or "/" in m[field]["member"] or m[field]["member"] in (".", ".."):
            reject("invalid evidence member")
    if digest(harness_bytes) != m["harness"]["sha256"] or digest(audit_bytes) != m["audit"]["sha256"]:
        reject("evidence digest mismatch")
    audit = parse(audit_bytes)
    keys(audit, {"schema", "verdict", "repository_id", "p_sha", "w_sha", "c_sha", "harness_sha256", "harness_run_id", "harness_run_attempt", "harness_workflow_id"})
    if audit != {"schema": "iyi.strict-independent-audit.v1", "verdict": "GO",
                 "repository_id": m["repository_id"], "p_sha": m["p_sha"],
                 "w_sha": m["w_sha"], "c_sha": m["c_sha"],
                 "harness_sha256": m["harness"]["sha256"],
                 "harness_run_id": m["harness"]["run_id"],
                 "harness_run_attempt": m["harness"]["run_attempt"],
                 "harness_workflow_id": m["harness"]["workflow_id"]}:
        reject("independent audit does not bind this tuple and harness")

    # Exact equality to independently established trusted context is required.
    keys(observations, {"context", "environment", "repository", "strict_run", "harness_run", "audit_run", "approvals", "artifact_bindings", "environment_job_count", "selected_branch_policies"})
    ctx = observations["context"]
    keys(ctx, {"repository", "repository_id", "p_sha", "w_sha", "c_sha", "workflow_sha", "workflow_path", "workflow_id", "strict_run_id", "strict_run_attempt", "strict_ref", "environment_id", "bundle_sha256"})
    for key in ctx:
        expected = m["c_sha"] if key == "workflow_sha" else m[key]
        if ctx[key] != expected:
            reject("trusted context mismatch: " + key)
    repo = observations["repository"]
    if not isinstance(repo, dict) or str(repo.get("id")) != m["repository_id"] or repo.get("full_name") != m["repository"] or repo.get("private") is not False:
        reject("repository visibility or identity mismatch")
    env = observations["environment"]
    if not isinstance(env, dict) or str(env.get("id")) != m["environment_id"] or env.get("name") != "strict-proof" or env.get("can_admins_bypass") is not False:
        reject("environment identity or bypass mismatch")
    rules = env.get("protection_rules")
    if not isinstance(rules, list) or len(rules) != 2 or any(not isinstance(item, dict) for item in rules):
        reject("environment requires reviewer and branch policy rules")
    by_type = {item.get("type"): item for item in rules if isinstance(item.get("type"), str)}
    if set(by_type) != {"required_reviewers", "branch_policy"}:
        reject("unexpected environment protection rules")
    rule = by_type["required_reviewers"]
    reviewers = rule.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1 or reviewers[0].get("type") != "User" or str(reviewers[0].get("reviewer", {}).get("id")) != "43164" or rule.get("prevent_self_review") is not False:
        reject("reviewer rule mismatch")
    if env.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        reject("ref policy not explicitly restricted")
    policies = observations["selected_branch_policies"]
    if not isinstance(policies, list) or len(policies) != 1 or not isinstance(policies[0], dict) or policies[0].get("type") != "branch" or policies[0].get("name") != m["strict_ref"].removeprefix("refs/heads/"):
        reject("unexpected branch policy")
    if observations["environment_job_count"] != 1:
        reject("ambiguous environment job")
    for field, section in (("strict_run", None), ("harness_run", "harness"), ("audit_run", "audit")):
        run = observations[field]
        expected_id = m["strict_run_id"] if section is None else m[section]["run_id"]
        expected_attempt = m["strict_run_attempt"] if section is None else m[section]["run_attempt"]
        expected_workflow = m["workflow_id"] if section is None else m[section]["workflow_id"]
        if not isinstance(run, dict) or str(run.get("id")) != expected_id or str(run.get("run_attempt")) != expected_attempt or str(run.get("workflow_id")) != expected_workflow or run.get("head_sha") != m["c_sha"] or str(run.get("repository", {}).get("id")) != m["repository_id"]:
            reject(field + " identity mismatch")
        if section is not None and (run.get("status") != "completed" or run.get("conclusion") != "success"):
            reject(field + " not successful")
    if observations["artifact_bindings"] != {"harness": m["harness"], "audit": m["audit"]}:
        reject("artifact provenance mismatch")
    approvals = observations["approvals"]
    if not isinstance(approvals, list) or len(approvals) != 1:
        reject("approval absent or ambiguous")
    review = approvals[0]
    if not isinstance(review, dict) or review.get("state") != "approved" or not isinstance(review.get("user"), dict) or review["user"].get("type") != "User" or str(review["user"].get("id")) != "43164" or review.get("comment") != "iyi-strict-authorization-v1 sha256:" + digest(manifest_bytes):
        reject("authenticated approval mismatch")
    environments = review.get("environments")
    if not isinstance(environments, list) or len(environments) != 1 or str(environments[0].get("id")) != m["environment_id"] or environments[0].get("name") != "strict-proof":
        reject("approval environment mismatch")
    # Deliberately no boolean or authorization capability is returned.
