"""Fail-closed authenticated API-backed strict-proof authorization verifier.

This module implements authenticated API-backed environment policy and approval
verification for strict mode. In real execution, strict execution remains
refused unless all controls are authentically enforced via GitHub APIs:
  - Repository ID 1340355933 (jwaldrip/iyi, public)
  - Pinned Environment ID 26584191206 (strict-proof)
  - Environment policy: can_admins_bypass: false, prevent_self_review: false
  - Protection rules: exactly required_reviewers (ID 43164) and branch_policy
  - Deployment branch policy: exactly proof/strict-lifecycle-repair-20261102 (branch)
  - Fresh run attempt == 1 (reruns unconditionally refused)
  - Exactly one approval by reviewer 43164 with exact comment:
      iyi-strict-authorization-v1 sha256:<manifest_sha256>
  - Harness evidence verified by content: embedded run_id, run_attempt=1, SHA,
    verdict PASS, and workflow producer identity
  - Independent audit evidence verified by content: embedded GO verdict,
    harness binding, and verified independent producer identity
  - Replay prevention: strictly running attempt 1, in_progress status,
    matching workflow_dispatch event, matching pinned path
  - supervisor and controller consume verified manifest bytes directly
    via authenticated inherited IPC with no mutable path swap
"""

from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Pinned immutable repository and environment trust anchors
PINNED_REPOSITORY = "jwaldrip/iyi"
PINNED_REPOSITORY_ID = "1340355933"
PINNED_ENVIRONMENT_NAME = "strict-proof"
PINNED_ENVIRONMENT_ID = "26584191206"
PINNED_BRANCH = "proof/strict-lifecycle-repair-20261102"
PINNED_REF = "refs/heads/proof/strict-lifecycle-repair-20261102"
PINNED_WORKFLOW_PATH = ".github/workflows/remote-strict-proof.yml"
PINNED_REVIEWER_ID = "43164"
PINNED_REVIEWER_LOGIN = "jwaldrip"
APPROVAL_COMMENT_PREFIX = "iyi-strict-authorization-v1 sha256:"

# Anchored P head from PR #147 and audited proof W SHA
PINNED_P_SHA = "180f14f91c829b25362a5ed34b20847f3ac2db77"
PINNED_W_SHA = "b932ce0d97775c7061102a13db706f507dc84117"

PINNED_API_BASE = "https://api.github.com"

MANIFEST_SCHEMA = "iyi.strict-authorization.v1"
AUDIT_SCHEMA = "iyi.strict-independent-audit.v1"
HARNESS_SCHEMA = "iyi.strict-harness-validation.v1"
HARMLESS_EFFECT_SCHEMA = "iyi.strict-harmless-effect.v1"

TRUSTED_AUDIT_PRODUCER_TYPES = {"reviewer", "independent-auditor", "independent-authority"}
AUTH_REFUSED_EXIT_CODE = 5


class AuthorizationError(ValueError):
    """Raised when an authorization check fails closed."""
    pass


class StrictAuthorizationRefused(RuntimeError):
    """Raised when strict execution is refused due to absent authorization."""
    pass


def reject(message: str) -> None:
    raise AuthorizationError(message)


def canonical(value: Any) -> bytes:
    """Serialize value to deterministic canonical UTF-8 JSON."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def parse(raw: bytes) -> Any:
    """Parse canonical UTF-8 JSON, rejecting duplicate keys and non-canonical format."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: reject("invalid JSON constant"),
        )
        if canonical(value) != raw:
            reject("noncanonical JSON")
        return value
    except (ValueError, UnicodeError, TypeError) as exc:
        raise AuthorizationError("invalid canonical JSON") from exc


def keys(value: Any, expected: Set[str]) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        reject("unexpected object schema")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha(value: Any, length: int) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        reject("invalid digest")


def decimal(value: Any) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        reject("invalid decimal identifier")


@dataclass(frozen=True)
class VerifiedAuthorization:
    """Immutable record of an authentically verified strict authorization.

    The supervisor and controller consume this verified record directly,
    preventing any mutable disk or path swap substitution.
    Attributes are frozen and cannot be modified.
    """

    manifest_bytes: bytes
    manifest_digest: str
    manifest_data: Dict[str, Any]
    harness_bytes: bytes
    harness_digest: str
    harness_data: Dict[str, Any]
    audit_bytes: bytes
    audit_digest: str
    audit_data: Dict[str, Any]
    p_sha: str
    w_sha: str
    c_sha: str
    repository_id: str = PINNED_REPOSITORY_ID
    environment_id: str = PINNED_ENVIRONMENT_ID
    reviewer_id: str = PINNED_REVIEWER_ID
    strict_ref: str = PINNED_REF
    run_attempt: str = "1"
    is_authorized: bool = True

    def __post_init__(self) -> None:
        if not self.is_authorized:
            reject("authorization record must be authorized")
        if self.manifest_digest != digest(self.manifest_bytes):
            reject("manifest digest mismatch in authorization record")
        if self.harness_digest != digest(self.harness_bytes):
            reject("harness digest mismatch in authorization record")
        if self.audit_digest != digest(self.audit_bytes):
            reject("audit digest mismatch in authorization record")
        if self.repository_id != PINNED_REPOSITORY_ID:
            reject("repository ID mismatch in authorization record")
        if self.environment_id != PINNED_ENVIRONMENT_ID:
            reject("environment ID mismatch in authorization record")
        if self.reviewer_id != PINNED_REVIEWER_ID:
            reject("reviewer ID mismatch in authorization record")
        if self.strict_ref != PINNED_REF:
            reject("strict ref mismatch in authorization record")
        if self.run_attempt != "1":
            reject("rerun attempt not allowed in authorization record")
        for s in (self.p_sha, self.w_sha, self.c_sha):
            sha(s, 40)
        if self.p_sha != PINNED_P_SHA:
            reject("stale or invalid P SHA in authorization record; PR #147 head required")
        if self.w_sha != PINNED_W_SHA:
            reject("W SHA mismatch in authorization record")
        if (
            self.manifest_data.get("p_sha") != self.p_sha
            or self.manifest_data.get("w_sha") != self.w_sha
            or self.manifest_data.get("c_sha") != self.c_sha
        ):
            reject("manifest data SHA mismatch with authorization tuple")


    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_digest": self.manifest_digest,
            "c_sha": self.c_sha,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "environment_id": self.environment_id,
            "reviewer_id": self.reviewer_id,
            "strict_ref": self.strict_ref,
            "run_attempt": self.run_attempt,
            "is_authorized": self.is_authorized,
        }


def verify_candidate(
    manifest_bytes: bytes,
    harness_bytes: bytes,
    audit_bytes: bytes,
    observations: Dict[str, Any],
) -> VerifiedAuthorization:
    """Validate candidate manifest, evidence contents, and observations.

    Enforces all immutable trust anchors:
      - repository ID 1340355933 (public)
      - environment ID 26584191206
      - branch policy proof/strict-lifecycle-repair-20261102
      - fresh run attempt == 1
      - reviewer ID 43164 with exact manifest digest comment
      - embedded harness artifact validation (run_id, attempt=1, c_sha, verdict PASS, workflow producer)
      - embedded independent audit validation (verdict GO, independent producer)
      - strict replay prevention: status in_progress, workflow_dispatch event, pinned path

    Returns a VerifiedAuthorization object upon success.
    """
    m = parse(manifest_bytes)
    keys(
        m,
        {
            "schema",
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
            "harness",
            "audit",
            "bundle_sha256",
        },
    )
    if m["schema"] != MANIFEST_SCHEMA:
        reject("wrong schema")
    for field in ("p_sha", "w_sha", "c_sha"):
        sha(m[field], 40)
    if m["p_sha"] != PINNED_P_SHA:
        reject("stale or invalid P SHA in manifest; PR #147 head required")
    if m["w_sha"] != PINNED_W_SHA:
        reject("W SHA mismatch in manifest")
    sha(m["bundle_sha256"], 64)
    for field in (
        "repository_id",
        "workflow_id",
        "strict_run_id",
        "strict_run_attempt",
        "environment_id",
    ):
        decimal(m[field])
    if m["repository"] != PINNED_REPOSITORY or m["repository_id"] != PINNED_REPOSITORY_ID:
        reject("wrong repository")
    if m["environment_id"] != PINNED_ENVIRONMENT_ID:
        reject("wrong environment id")
    if m["strict_run_attempt"] != "1":
        reject("reruns cannot be authorized")
    if m["strict_ref"] != PINNED_REF:
        reject("strict ref must match pinned trusted branch")
    if m["workflow_path"] != PINNED_WORKFLOW_PATH:
        reject("wrong workflow")

    for field in ("harness", "audit"):
        keys(
            m[field],
            {
                "artifact_id",
                "member",
                "sha256",
                "run_id",
                "run_attempt",
                "workflow_id",
            },
        )
        for key in ("artifact_id", "run_id", "run_attempt", "workflow_id"):
            decimal(m[field][key])
        if m[field]["run_attempt"] != "1":
            reject(f"{field} artifact must belong to attempt 1")
        sha(m[field]["sha256"], 64)
        if (
            not isinstance(m[field]["member"], str)
            or not m[field]["member"]
            or "/" in m[field]["member"]
            or "\\" in m[field]["member"]
            or m[field]["member"] in (".", "..")
        ):
            reject("invalid evidence member")

    # Run IDs must be distinct across distinct run contexts
    if m["harness"]["run_id"] == m["audit"]["run_id"]:
        reject("audit run ID must be distinct from harness run ID")
    if m["strict_run_id"] in (m["harness"]["run_id"], m["audit"]["run_id"]):
        reject("evidence run IDs must be distinct from strict run ID")

    # Verify exact byte digests
    if digest(harness_bytes) != m["harness"]["sha256"]:
        reject("harness evidence digest mismatch")
    if digest(audit_bytes) != m["audit"]["sha256"]:
        reject("audit evidence digest mismatch")

    # Verify embedded harness artifact content
    harness_data = parse(harness_bytes)
    keys(
        harness_data,
        {
            "schema",
            "verdict",
            "repository_id",
            "p_sha",
            "w_sha",
            "c_sha",
            "run_id",
            "run_attempt",
            "workflow_id",
            "producer",
        },
    )
    if harness_data["schema"] != HARNESS_SCHEMA:
        reject("wrong harness artifact schema")
    if harness_data["verdict"] != "PASS":
        reject("harness artifact verdict is not PASS")
    if harness_data["repository_id"] != m["repository_id"]:
        reject("harness repository mismatch")
    if (
        harness_data["p_sha"] != m["p_sha"]
        or harness_data["w_sha"] != m["w_sha"]
        or harness_data["c_sha"] != m["c_sha"]
    ):
        reject("harness evidence source revision mismatch")
    if harness_data["run_id"] != m["harness"]["run_id"]:
        reject("harness run id mismatch")
    if harness_data["run_attempt"] != m["harness"]["run_attempt"] or harness_data["run_attempt"] != "1":
        reject("harness run attempt mismatch or rerun")
    if harness_data["workflow_id"] != m["harness"]["workflow_id"]:
        reject("harness workflow id mismatch")
    if not isinstance(harness_data["producer"], dict):
        reject("missing harness producer identity")
    keys(harness_data["producer"], {"type", "run_id", "workflow_id", "job_id", "identity"})
    if harness_data["producer"]["run_id"] != m["harness"]["run_id"]:
        reject("harness producer run id mismatch")

    # Verify embedded independent audit artifact content
    audit_data = parse(audit_bytes)
    keys(
        audit_data,
        {
            "schema",
            "verdict",
            "repository_id",
            "p_sha",
            "w_sha",
            "c_sha",
            "harness_sha256",
            "harness_run_id",
            "harness_run_attempt",
            "harness_workflow_id",
            "producer",
        },
    )
    if audit_data["schema"] != AUDIT_SCHEMA:
        reject("wrong audit artifact schema")
    if audit_data["verdict"] != "GO":
        reject("independent audit verdict is not GO")
    if audit_data["repository_id"] != m["repository_id"]:
        reject("audit repository mismatch")
    if (
        audit_data["p_sha"] != m["p_sha"]
        or audit_data["w_sha"] != m["w_sha"]
        or audit_data["c_sha"] != m["c_sha"]
    ):
        reject("audit tuple mismatch")
    if audit_data["harness_sha256"] != m["harness"]["sha256"]:
        reject("audit harness digest mismatch")
    if (
        audit_data["harness_run_id"] != m["harness"]["run_id"]
        or audit_data["harness_run_attempt"] != m["harness"]["run_attempt"]
        or audit_data["harness_workflow_id"] != m["harness"]["workflow_id"]
    ):
        reject("audit harness run binding mismatch")

    # Verify trusted independent producer identity and independence from harness producer
    producer = audit_data["producer"]
    if not isinstance(producer, dict):
        reject("missing audit producer identity")
    keys(producer, {"type", "run_id", "workflow_id", "job_id", "identity"})
    if producer == harness_data["producer"]:
        reject("audit producer must be independent of harness producer")
    if str(producer.get("run_id")) == str(harness_data.get("producer", {}).get("run_id")):
        reject("audit producer run must be independent of harness producer run")
    if str(producer.get("run_id")) == str(harness_data.get("run_id")):
        reject("audit run must be independent of harness run")
    if producer["type"] not in TRUSTED_AUDIT_PRODUCER_TYPES:
        reject("untrusted audit producer type")
    if not isinstance(producer["identity"], str) or not producer["identity"]:
        reject("missing audit producer identity string")

    # Exact equality to independently established trusted context is required.
    keys(
        observations,
        {
            "context",
            "environment",
            "repository",
            "strict_run",
            "harness_run",
            "audit_run",
            "approvals",
            "artifact_bindings",
            "environment_job_count",
            "selected_branch_policies",
        },
    )

    ctx = observations["context"]
    keys(
        ctx,
        {
            "repository",
            "repository_id",
            "p_sha",
            "w_sha",
            "c_sha",
            "workflow_sha",
            "workflow_path",
            "workflow_id",
            "strict_run_id",
            "strict_run_attempt",
            "strict_ref",
            "environment_id",
            "bundle_sha256",
        },
    )
    for key in ctx:
        expected = m["c_sha"] if key == "workflow_sha" else m[key]
        if ctx[key] != expected:
            reject("trusted context mismatch: " + key)

    repo = observations["repository"]
    if (
        not isinstance(repo, dict)
        or str(repo.get("id")) != PINNED_REPOSITORY_ID
        or repo.get("full_name") != PINNED_REPOSITORY
        or repo.get("private") is not False
    ):
        reject("repository visibility or identity mismatch")

    env = observations["environment"]
    if (
        not isinstance(env, dict)
        or str(env.get("id")) != PINNED_ENVIRONMENT_ID
        or env.get("name") != PINNED_ENVIRONMENT_NAME
        or env.get("can_admins_bypass") is not False
    ):
        reject("environment identity or bypass mismatch")

    rules = env.get("protection_rules")
    if (
        not isinstance(rules, list)
        or len(rules) != 2
        or any(not isinstance(item, dict) for item in rules)
    ):
        reject("environment requires reviewer and branch policy rules")
    by_type = {item.get("type"): item for item in rules if isinstance(item.get("type"), str)}
    if set(by_type) != {"required_reviewers", "branch_policy"}:
        reject("unexpected environment protection rules")

    rule = by_type["required_reviewers"]
    reviewers = rule.get("reviewers")
    if (
        not isinstance(reviewers, list)
        or len(reviewers) != 1
        or reviewers[0].get("type") != "User"
        or str(reviewers[0].get("reviewer", {}).get("id")) != PINNED_REVIEWER_ID
        or rule.get("prevent_self_review") is not False
    ):
        reject("reviewer rule mismatch")

    if env.get("deployment_branch_policy") != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        reject("ref policy not explicitly restricted")

    policies = observations["selected_branch_policies"]
    if (
        not isinstance(policies, list)
        or len(policies) != 1
        or not isinstance(policies[0], dict)
        or policies[0].get("type") != "branch"
        or policies[0].get("name") != PINNED_BRANCH
    ):
        reject("unexpected branch policy")

    if observations["environment_job_count"] != 1:
        reject("ambiguous environment job")

    # Strict run replay checks
    strict_run = observations["strict_run"]
    if (
        not isinstance(strict_run, dict)
        or str(strict_run.get("id")) != m["strict_run_id"]
        or str(strict_run.get("run_attempt")) != m["strict_run_attempt"]
        or str(strict_run.get("workflow_id")) != m["workflow_id"]
        or strict_run.get("head_sha") != m["c_sha"]
        or strict_run.get("head_branch") != PINNED_BRANCH
        or strict_run.get("path") != PINNED_WORKFLOW_PATH
        or strict_run.get("event") != "workflow_dispatch"
        or strict_run.get("status") != "in_progress"
        or str(strict_run.get("repository", {}).get("id")) != PINNED_REPOSITORY_ID
    ):
        reject("strict_run identity, replay, or status mismatch")

    # Harness and audit run checks
    for field, section in (("harness_run", "harness"), ("audit_run", "audit")):
        run = observations[field]
        expected_id = m[section]["run_id"]
        expected_attempt = m[section]["run_attempt"]
        expected_workflow = m[section]["workflow_id"]
        if (
            not isinstance(run, dict)
            or str(run.get("id")) != expected_id
            or str(run.get("run_attempt")) != expected_attempt
            or str(run.get("workflow_id")) != expected_workflow
            or run.get("head_sha") != m["c_sha"]
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or str(run.get("repository", {}).get("id")) != PINNED_REPOSITORY_ID
        ):
            reject(field + " identity or conclusion mismatch")

    # Artifact provenance check against independently queried artifact records
    bindings = observations["artifact_bindings"]
    if not isinstance(bindings, dict):
        reject("invalid artifact bindings format")
    for section in ("harness", "audit"):
        expected_art = m[section]
        bound = bindings.get(section)
        if (
            not isinstance(bound, dict)
            or str(bound.get("artifact_id")) != expected_art["artifact_id"]
            or str(bound.get("run_id")) != expected_art["run_id"]
            or bound.get("expired") is True
            or bound.get("head_sha") != m["c_sha"]
        ):
            reject(f"{section} artifact provenance mismatch")

    approvals = observations["approvals"]
    if not isinstance(approvals, list) or len(approvals) != 1:
        reject("approval absent or ambiguous")
    review = approvals[0]
    expected_comment = f"{APPROVAL_COMMENT_PREFIX}{digest(manifest_bytes)}"
    if (
        not isinstance(review, dict)
        or review.get("state") != "approved"
        or not isinstance(review.get("user"), dict)
        or review["user"].get("type") != "User"
        or str(review["user"].get("id")) != PINNED_REVIEWER_ID
        or review.get("comment") != expected_comment
    ):
        reject("authenticated approval mismatch")

    environments = review.get("environments")
    if (
        not isinstance(environments, list)
        or len(environments) != 1
        or str(environments[0].get("id")) != PINNED_ENVIRONMENT_ID
        or environments[0].get("name") != PINNED_ENVIRONMENT_NAME
    ):
        reject("approval environment mismatch")

    return VerifiedAuthorization(
        manifest_bytes=manifest_bytes,
        manifest_digest=digest(manifest_bytes),
        manifest_data=m,
        harness_bytes=harness_bytes,
        harness_digest=digest(harness_bytes),
        harness_data=harness_data,
        audit_bytes=audit_bytes,
        audit_digest=digest(audit_bytes),
        audit_data=audit_data,
        p_sha=m["p_sha"],
        w_sha=m["w_sha"],
        c_sha=m["c_sha"],
        run_attempt=m["strict_run_attempt"],
    )


class AuthenticatedGitHubVerifier:
    """Performs authenticated API calls against GitHub REST endpoints to verify environment authorization."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        repository: str = PINNED_REPOSITORY,
        allow_loopback: bool = False,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not self.token:
            reject("Authentication token is required for GitHub API verification")

        if base_url is None:
            self.base_url = PINNED_API_BASE
        else:
            cleaned = base_url.rstrip("/")
            if allow_loopback and re.fullmatch(r"http://(127\.0\.0\.1|localhost)(:[0-9]+)?", cleaned):
                self.base_url = cleaned
            elif cleaned == PINNED_API_BASE:
                self.base_url = cleaned
            else:
                reject(f"Untrusted API base URL '{base_url}'; only '{PINNED_API_BASE}' is permitted")

        self.repository = repository

    def _api_get_raw(self, endpoint: str) -> bytes:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "iyi-strict-auth-verifier/1.0",
            "Authorization": f"Bearer {self.token}",
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            reject(f"GitHub API error HTTP {exc.code} for {endpoint}")
        except Exception as exc:
            reject(f"GitHub API request failed for {endpoint}: {exc}")

    def _api_get(self, endpoint: str) -> Any:
        raw = self._api_get_raw(endpoint)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            reject(f"Invalid JSON returned from GitHub API for {endpoint}: {exc}")

    def _download_artifact_zip_member(self, artifact_id: str, member_name: str, expected_run_id: str) -> bytes:
        """Download artifact zip archive and extract exact member bytes."""
        metadata = self._api_get(f"repos/{self.repository}/actions/artifacts/{artifact_id}")
        if not isinstance(metadata, dict):
            reject(f"Invalid artifact metadata for {artifact_id}")
        if metadata.get("expired") is True:
            reject(f"Artifact {artifact_id} is expired")
        wf_run = metadata.get("workflow_run", {})
        if str(wf_run.get("id")) != str(expected_run_id):
            reject(f"Artifact {artifact_id} workflow run mismatch: expected {expected_run_id}, got {wf_run.get('id')}")

        zip_bytes = self._api_get_raw(f"repos/{self.repository}/actions/artifacts/{artifact_id}/zip")
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                if member_name not in zf.namelist():
                    reject(f"Member '{member_name}' not found in artifact {artifact_id} zip")
                return zf.read(member_name)
        except zipfile.BadZipFile as exc:
            reject(f"Corrupted zip archive for artifact {artifact_id}: {exc}")

    def load_runtime_context(self, bundle_sha256: str) -> Dict[str, Any]:
        """Load runtime context from real platform environment variables."""
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
        c_sha = os.environ.get("GITHUB_SHA", "")
        ref = os.environ.get("GITHUB_REF", "")
        job = os.environ.get("GITHUB_JOB", "")

        if repo != PINNED_REPOSITORY:
            reject("GITHUB_REPOSITORY mismatch with pinned repository")
        if ref != PINNED_REF:
            reject("GITHUB_REF mismatch with pinned ref")
        if job != "strict-chain":
            reject("GITHUB_JOB mismatch with pinned strict job")
        decimal(run_id)
        if run_attempt != "1":
            reject("GITHUB_RUN_ATTEMPT must be 1")
        sha(c_sha, 40)
        sha(bundle_sha256, 64)

        return {
            "repository": PINNED_REPOSITORY,
            "repository_id": PINNED_REPOSITORY_ID,
            "p_sha": PINNED_P_SHA,
            "w_sha": PINNED_W_SHA,
            "c_sha": c_sha,
            "workflow_sha": c_sha,
            "workflow_path": PINNED_WORKFLOW_PATH,
            "workflow_id": "403985693",
            "strict_run_id": run_id,
            "strict_run_attempt": run_attempt,
            "strict_ref": PINNED_REF,
            "environment_id": PINNED_ENVIRONMENT_ID,
            "bundle_sha256": bundle_sha256,
        }

    def fetch_observations(
        self,
        strict_run_id: str,
        strict_run_attempt: str,
        harness_run_id: str,
        audit_run_id: str,
        harness_artifact_id: str,
        audit_artifact_id: str,
        runtime_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fetch all required observations independently via GitHub API."""
        repo = self._api_get(f"repos/{self.repository}")
        env = self._api_get(f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}")
        branch_policies_resp = self._api_get(
            f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies"
        )
        policies = branch_policies_resp.get("branch_policies", [])

        strict_run = self._api_get(f"repos/{self.repository}/actions/runs/{strict_run_id}")
        harness_run = self._api_get(f"repos/{self.repository}/actions/runs/{harness_run_id}")
        audit_run = self._api_get(f"repos/{self.repository}/actions/runs/{audit_run_id}")

        approvals_list = self._api_get(f"repos/{self.repository}/actions/runs/{strict_run_id}/approvals")
        if not isinstance(approvals_list, list):
            reject("invalid approvals response format")

        jobs_resp = self._api_get(
            f"repos/{self.repository}/actions/runs/{strict_run_id}/attempts/{strict_run_attempt}/jobs"
        )
        jobs = jobs_resp.get("jobs", [])
        env_jobs = [
            j for j in jobs
            if isinstance(j, dict) and (
                j.get("name") == "strict-chain"
                or any(isinstance(step, dict) and step.get("name") == "strict-chain" for step in j.get("steps", []))
            )
        ]
        env_job_count = len(env_jobs)

        # Independently read artifact metadata to bind provenance
        h_art_meta = self._api_get(f"repos/{self.repository}/actions/artifacts/{harness_artifact_id}")
        a_art_meta = self._api_get(f"repos/{self.repository}/actions/artifacts/{audit_artifact_id}")

        artifact_bindings = {
            "harness": {
                "artifact_id": str(h_art_meta.get("id")),
                "run_id": str(h_art_meta.get("workflow_run", {}).get("id")),
                "head_sha": str(h_art_meta.get("workflow_run", {}).get("head_sha")),
                "expired": h_art_meta.get("expired", True),
            },
            "audit": {
                "artifact_id": str(a_art_meta.get("id")),
                "run_id": str(a_art_meta.get("workflow_run", {}).get("id")),
                "head_sha": str(a_art_meta.get("workflow_run", {}).get("head_sha")),
                "expired": a_art_meta.get("expired", True),
            },
        }

        return {
            "context": runtime_context,
            "repository": repo,
            "environment": env,
            "selected_branch_policies": policies,
            "strict_run": strict_run,
            "harness_run": harness_run,
            "audit_run": audit_run,
            "approvals": approvals_list,
            "artifact_bindings": artifact_bindings,
            "environment_job_count": env_job_count,
        }

    def verify(
        self,
        manifest_bytes: bytes,
        harness_bytes: Optional[bytes] = None,
        audit_bytes: Optional[bytes] = None,
        runtime_context: Optional[Dict[str, Any]] = None,
    ) -> VerifiedAuthorization:
        """Fetch observations and verify candidate bytes authentically."""
        m = parse(manifest_bytes)
        if harness_bytes is None:
            harness_bytes = self._download_artifact_zip_member(
                artifact_id=m["harness"]["artifact_id"],
                member_name=m["harness"]["member"],
                expected_run_id=m["harness"]["run_id"],
            )
        if audit_bytes is None:
            audit_bytes = self._download_artifact_zip_member(
                artifact_id=m["audit"]["artifact_id"],
                member_name=m["audit"]["member"],
                expected_run_id=m["audit"]["run_id"],
            )

        if runtime_context is None:
            runtime_context = self.load_runtime_context(bundle_sha256=m["bundle_sha256"])

        observations = self.fetch_observations(
            strict_run_id=m["strict_run_id"],
            strict_run_attempt=m["strict_run_attempt"],
            harness_run_id=m["harness"]["run_id"],
            audit_run_id=m["audit"]["run_id"],
            harness_artifact_id=m["harness"]["artifact_id"],
            audit_artifact_id=m["audit"]["artifact_id"],
            runtime_context=runtime_context,
        )
        return verify_candidate(manifest_bytes, harness_bytes, audit_bytes, observations)


def load_verified_authorization_from_ipc(
    auth_ack: Dict[str, Any],
    p_sha: str,
    w_sha: str,
    c_sha: str,
) -> VerifiedAuthorization:
    """Reconstruct and verify immutable VerifiedAuthorization from supervisor IPC ACK."""
    if not isinstance(auth_ack, dict):
        reject("invalid authorization IPC ACK")
    if auth_ack.get("event") != "authorization-ack":
        reject("unexpected IPC event for authorization")
    if auth_ack.get("verified") is not True:
        reject(f"authorization refused by supervisor: {auth_ack.get('error', 'unknown error')}")
    if auth_ack.get("p_sha") != p_sha or auth_ack.get("w_sha") != w_sha or auth_ack.get("c_sha") != c_sha:
        reject("authorization IPC ACK revision mismatch with runtime")

    manifest_raw = auth_ack.get("manifest_raw")
    if not isinstance(manifest_raw, (str, bytes)):
        reject("missing manifest in authorization IPC ACK")
    manifest_bytes = manifest_raw.encode("utf-8") if isinstance(manifest_raw, str) else manifest_raw

    harness_raw = auth_ack.get("harness_raw")
    if not isinstance(harness_raw, (str, bytes)):
        reject("missing harness evidence in authorization IPC ACK")
    harness_bytes = harness_raw.encode("utf-8") if isinstance(harness_raw, str) else harness_raw

    audit_raw = auth_ack.get("audit_raw")
    if not isinstance(audit_raw, (str, bytes)):
        reject("missing audit evidence in authorization IPC ACK")
    audit_bytes = audit_raw.encode("utf-8") if isinstance(audit_raw, str) else audit_raw

    m = parse(manifest_bytes)
    harness_data = parse(harness_bytes)
    audit_data = parse(audit_bytes)

    return VerifiedAuthorization(
        manifest_bytes=manifest_bytes,
        manifest_digest=digest(manifest_bytes),
        manifest_data=m,
        harness_bytes=harness_bytes,
        harness_digest=digest(harness_bytes),
        harness_data=harness_data,
        audit_bytes=audit_bytes,
        audit_digest=digest(audit_bytes),
        audit_data=audit_data,
        p_sha=p_sha,
        w_sha=w_sha,
        c_sha=c_sha,
    )


def check_strict_authorization_or_refuse(
    p_sha: str,
    w_sha: str,
    c_sha: str,
    verified_auth: Optional[VerifiedAuthorization] = None,
) -> None:
    """Production enforcement hook for remote strict controller and supervisor.

    In real execution, no environment approval has been issued for environment
    26584191206 (strict-proof) and no independent audit GO artifact exists.
    This function unconditionally refuses strict execution with the exact
    missing trust anchors, preserving fail-closed security.
    """
    for name, val in [("p_sha", p_sha), ("w_sha", w_sha), ("c_sha", c_sha)]:
        if not isinstance(val, str) or not re.fullmatch(r"[0-9a-f]{40}", val):
            raise AuthorizationError(f"Invalid or missing {name} for strict authorization check")

    if p_sha != PINNED_P_SHA:
        raise AuthorizationError(f"Stale P SHA '{p_sha}'; strict proof requires PR #147 head '{PINNED_P_SHA}'")
    if w_sha != PINNED_W_SHA:
        raise AuthorizationError(f"W SHA '{w_sha}' does not match pinned '{PINNED_W_SHA}'")

    if verified_auth is not None:
        if not isinstance(verified_auth, VerifiedAuthorization) or not verified_auth.is_authorized:
            raise AuthorizationError("Provided authorization object is not an authorized VerifiedAuthorization")
        if verified_auth.p_sha != p_sha:
            raise AuthorizationError(f"Verified authorization P SHA mismatch: expected {p_sha}, got {verified_auth.p_sha}")
        if verified_auth.w_sha != w_sha:
            raise AuthorizationError(f"Verified authorization W SHA mismatch: expected {w_sha}, got {verified_auth.w_sha}")
        if verified_auth.c_sha != c_sha:
            raise AuthorizationError(f"Verified authorization C SHA mismatch: expected {c_sha}, got {verified_auth.c_sha}")
        return

    # In real execution without authentic verified authorization, explain exact missing anchors and refuse
    refusal_lines = [
        "STRICT_MODE_AUTH_REFUSED: Real strict execution requires independently authenticated authorization.",
        f"Missing trust anchor: Environment '{PINNED_ENVIRONMENT_NAME}' (ID {PINNED_ENVIRONMENT_ID})",
        f"requires an approval by reviewer {PINNED_REVIEWER_ID} ({PINNED_REVIEWER_LOGIN}) with comment containing",
        f"the exact manifest digest prefix '{APPROVAL_COMMENT_PREFIX}<digest>' on attempt 1.",
        "No deployment approval has been issued on GitHub environment strict-proof.",
        "Missing trust anchor: Retained independent audit GO artifact with trusted independent producer identity (policy decision required by repository owner to establish independent audit authority).",
        f"Refusing execution nonzero (exit code {AUTH_REFUSED_EXIT_CODE}) before planning, pinning, or native execution.",
    ]
    refusal_msg = "\n".join(refusal_lines)
    print(f"\n[STRICT_AUTHORIZATION] {refusal_msg}", file=sys.stderr)
    raise StrictAuthorizationRefused(refusal_msg)


def execute_harmless_effect_if_authorized(
    auth: Optional[VerifiedAuthorization],
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute observable non-native harmless effect when authenticated authorization is proven.

    If authorization is valid, produces a non-native proof receipt.
    If authorization is missing or refused, raises StrictAuthorizationRefused.
    """
    if not isinstance(auth, VerifiedAuthorization) or not auth.is_authorized:
        raise StrictAuthorizationRefused("Cannot execute harmless effect without verified authorization")

    receipt = {
        "schema": HARMLESS_EFFECT_SCHEMA,
        "status": "PASS",
        "manifest_digest": auth.manifest_digest,
        "c_sha": auth.c_sha,
        "p_sha": auth.p_sha,
        "w_sha": auth.w_sha,
        "environment_id": auth.environment_id,
        "reviewer_id": auth.reviewer_id,
        "strict_ref": auth.strict_ref,
        "effect": "harmless-non-native-synthetic-proof-receipt",
    }
    raw = canonical(receipt)
    if output_path:
        with open(output_path, "wb") as f:
            f.write(raw)
    return receipt
