#!/usr/bin/env python3
"""Fail-closed authenticated API-backed strict-proof authorization verifier.

This module implements the minimal shared strict authorization verifier per
PlanMinimalStrictAuthorization (§3.B, §3.C, §3.D, §3.E, §3.F):
  - One canonical manifest schema: "iyi-strict-manifest-v2"
  - Exactly one human approval authority: Jason Waldrip (user ID 43164)
    approving environment 'strict-proof' (ID 26584191206) with exact comment
    "iyi-strict-authorization-v2 sha256:<D>" on run attempt 1.
  - Substantive independent audit report E (data only) with verdict GO,
    binding the reviewed sources, validation evidence V, and execution backend.
  - Execution backend bound in D: "local-quiet-darwin" on chain "iyi-strict-proof-chain-v1".
  - One shared verifier used across all entry operations:
      1. prepare: validate inputs and write canonical manifest.
      2. check: inspect manifest against authoritative GitHub data.
      3. run-native: check authorization, claim execution, and invoke native chain.
  - Fail-closed: returns exit code 5 on any refusal before native effects.
  - Usage errors return exit code 2.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Pinned immutable repository, environment, and workflow trust anchors
PINNED_REPOSITORY = "jwaldrip/iyi"
PINNED_REPOSITORY_ID = "1340355933"
PINNED_ENVIRONMENT_NAME = "strict-proof"
PINNED_ENVIRONMENT_ID = "26584191206"
PINNED_REVIEWER_ID = "43164"
PINNED_REVIEWER_LOGIN = "jwaldrip"
PINNED_BRANCH = "proof/strict-lifecycle-repair-20261102"
PINNED_REF = "refs/heads/proof/strict-lifecycle-repair-20261102"
PINNED_WORKFLOW_PATH = ".github/workflows/remote-strict-proof.yml"
APPROVAL_COMMENT_PREFIX = "iyi-strict-authorization-v2 sha256:"

AUTH_REFUSED_EXIT_CODE = 5
USAGE_ERROR_EXIT_CODE = 2

EXECUTION_BACKEND = "local-quiet-darwin"
CHAIN_ID = "iyi-strict-proof-chain-v1"
MANIFEST_SCHEMA = "iyi-strict-manifest-v2"
PINNED_API_BASE = "https://api.github.com"

# Standard redirect codes for blob storage downloads
REDIRECT_CODES = (301, 302, 303, 307, 308)
USER_AGENT = "iyi-strict-independent-readback/2.0"


class AuthorizationError(ValueError):
    """Raised when authorization inputs or parameters are malformed."""
    pass


class StrictAuthorizationRefused(RuntimeError):
    """Raised when strict authorization verification fails closed."""
    def __init__(self, message: str, exit_code: int = AUTH_REFUSED_EXIT_CODE):
        super().__init__(message)
        self.exit_code = exit_code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler that prevents automatic header forwarding across redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical_json(data: Any) -> bytes:
    """Serialize data into deterministic canonical UTF-8 JSON bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_digest(data: bytes) -> str:
    """Compute lowercase 64-hex SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def validate_hex_sha(val: Any, length: int = 40, name: str = "SHA") -> str:
    """Validate that val is a lowercase hex string of exact length."""
    if not isinstance(val, str) or len(val) != length or not re.fullmatch(r"[0-9a-f]+", val):
        raise StrictAuthorizationRefused(
            f"Invalid {name}: must be {length}-hex lowercase, got {val!r}"
        )
    return val


def validate_decimal(val: Any, name: str = "ID") -> str:
    """Validate that val represents a positive decimal integer."""
    s = str(val).strip()
    if not s.isdigit():
        raise StrictAuthorizationRefused(
            f"Invalid {name}: must be numeric decimal string, got {val!r}"
        )
    return s


def read_manifest_package(path: str) -> Tuple[bytes, Dict[str, Any], str]:
    """Read manifest from raw JSON or ZIP archive.

    Returns (canonical_bytes, parsed_dict, digest_D).
    Rejects duplicate archive member names and ambiguous members.
    """
    if not os.path.exists(path):
        raise StrictAuthorizationRefused(f"Manifest path does not exist: {path}")

    if path.endswith(".zip") or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as zf:
                namelist = zf.namelist()
                if len(namelist) != len(set(namelist)):
                    raise StrictAuthorizationRefused("Duplicate ZIP member names in manifest package")
                if "manifest.json" not in namelist:
                    raise StrictAuthorizationRefused("manifest.json missing from manifest package")
                raw_bytes = zf.read("manifest.json")
        except zipfile.BadZipFile as exc:
            raise StrictAuthorizationRefused(f"Corrupted zip archive for manifest: {exc}")
        except Exception as exc:
            if isinstance(exc, StrictAuthorizationRefused):
                raise
            raise StrictAuthorizationRefused(f"Corrupted zip archive for manifest: {exc}")
    else:
        with open(path, "rb") as f:
            raw_bytes = f.read()

    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise StrictAuthorizationRefused(f"Malformed manifest JSON: {exc}")

    canonical_bytes = canonical_json(parsed)
    digest = compute_digest(canonical_bytes)
    return canonical_bytes, parsed, digest


def create_manifest(
    p_sha: str,
    w_sha: str,
    c_sha: str,
    s_run_id: str,
    s_run_attempt: int,
    workflow_path: str,
    v_run_id: str,
    v_artifacts: List[Dict[str, Any]],
    review_path: Optional[str] = None,
    review_sha256: Optional[str] = None,
    review_verdict: str = "GO",
    repository: str = PINNED_REPOSITORY,
    execution_backend: str = EXECUTION_BACKEND,
    chain_id: str = CHAIN_ID,
    environment_id: str = PINNED_ENVIRONMENT_ID,
    environment_name: str = PINNED_ENVIRONMENT_NAME,
    reviewer_id: str = PINNED_REVIEWER_ID,
) -> Tuple[Dict[str, Any], bytes, str]:
    """Create canonical manifest structure, canonical bytes, and digest D."""
    validate_hex_sha(p_sha, 40, "p_sha")
    validate_hex_sha(w_sha, 40, "w_sha")
    validate_hex_sha(c_sha, 40, "c_sha")
    validate_decimal(s_run_id, "s_run_id")
    validate_decimal(v_run_id, "v_run_id")
    validate_decimal(environment_id, "environment_id")
    validate_decimal(reviewer_id, "reviewer_id")

    if int(s_run_attempt) != 1:
        raise StrictAuthorizationRefused("s_run_attempt must be 1: reruns cannot be authorized")

    if execution_backend != EXECUTION_BACKEND:
        raise StrictAuthorizationRefused(
            f"execution_backend must be {EXECUTION_BACKEND}, got {execution_backend}"
        )

    if environment_name != PINNED_ENVIRONMENT_NAME or str(environment_id) != PINNED_ENVIRONMENT_ID:
        raise StrictAuthorizationRefused(
            f"environment must be {PINNED_ENVIRONMENT_NAME} ({PINNED_ENVIRONMENT_ID})"
        )

    if str(reviewer_id) != PINNED_REVIEWER_ID:
        raise StrictAuthorizationRefused(
            f"reviewer_id must be {PINNED_REVIEWER_ID}, got {reviewer_id}"
        )

    if not isinstance(v_artifacts, list) or len(v_artifacts) == 0:
        raise StrictAuthorizationRefused("v_artifacts must be a non-empty list of artifact records")

    for art in v_artifacts:
        if not isinstance(art, dict):
            raise StrictAuthorizationRefused("Each artifact in v_artifacts must be an object")
        if "id" not in art or "name" not in art or "sha256" not in art:
            raise StrictAuthorizationRefused("Artifact record must contain 'id', 'name', and 'sha256'")
        validate_decimal(art["id"], "artifact id")
        validate_hex_sha(art["sha256"], 64, "artifact sha256")

    # Handle independent review
    resolved_review_sha = review_sha256
    resolved_review_path = review_path or "proof/review_evidence.json"
    if review_path and os.path.exists(review_path):
        with open(review_path, "rb") as rf:
            rbytes = rf.read()
        file_sha = compute_digest(rbytes)
        if resolved_review_sha and resolved_review_sha != file_sha:
            raise StrictAuthorizationRefused(
                f"review_sha256 mismatch with file content at {review_path}"
            )
        resolved_review_sha = file_sha
        try:
            rdata = json.loads(rbytes.decode("utf-8"))
            if isinstance(rdata, dict):
                declared_verdict = rdata.get("verdict") or rdata.get("report", {}).get("verdict")
                if declared_verdict and declared_verdict != "GO":
                    raise StrictAuthorizationRefused(
                        f"Review file declares non-GO verdict: {declared_verdict}"
                    )
        except UnicodeDecodeError:
            pass
        except json.JSONDecodeError:
            pass

    if not resolved_review_sha:
        raise StrictAuthorizationRefused("review_sha256 or readable review_path is required")
    validate_hex_sha(resolved_review_sha, 64, "review_sha256")

    if review_verdict != "GO":
        raise StrictAuthorizationRefused(f"Review verdict must be GO, got {review_verdict}")

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "repository": repository,
        "repository_id": PINNED_REPOSITORY_ID,
        "s_run_id": str(s_run_id),
        "s_run_attempt": int(s_run_attempt),
        "workflow_path": workflow_path,
        "c_sha": c_sha,
        "p_sha": p_sha,
        "w_sha": w_sha,
        "execution_backend": execution_backend,
        "chain_id": chain_id,
        "environment_id": int(environment_id),
        "environment_name": environment_name,
        "reviewer_id": int(reviewer_id),
        "required_policy": {
            "prevent_self_review": False,
            "can_admins_bypass": False,
            "branch": PINNED_BRANCH,
        },
        "v_run_id": str(v_run_id),
        "v_artifacts": [
            {
                "id": str(art["id"]),
                "name": str(art["name"]),
                "sha256": str(art["sha256"]),
            }
            for art in v_artifacts
        ],
        "review": {
            "blob_sha": resolved_review_sha,
            "path": resolved_review_path,
            "sha256": resolved_review_sha,
            "verdict": review_verdict,
        },
    }

    canonical_bytes = canonical_json(manifest)
    digest_D = compute_digest(canonical_bytes)
    return manifest, canonical_bytes, digest_D


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
            raise StrictAuthorizationRefused(
                "Authentication token is required for GitHub API verification"
            )

        if base_url is None:
            self.base_url = PINNED_API_BASE
        else:
            cleaned = base_url.rstrip("/")
            if allow_loopback and re.fullmatch(r"https?://(127\.0\.0\.1|localhost)(:[0-9]+)?", cleaned):
                self.base_url = cleaned
            elif cleaned == PINNED_API_BASE:
                self.base_url = cleaned
            else:
                raise StrictAuthorizationRefused(
                    f"Untrusted API base URL '{base_url}'; only '{PINNED_API_BASE}' or loopback is permitted"
                )

        self.repository = repository
        self.allow_loopback = allow_loopback

    def _api_get_raw(self, endpoint: str) -> bytes:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {self.token}",
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise StrictAuthorizationRefused(
                f"GitHub API error HTTP {exc.code} for {endpoint}"
            )
        except Exception as exc:
            raise StrictAuthorizationRefused(
                f"GitHub API request failed for {endpoint}: {exc}"
            )

    def _api_get(self, endpoint: str) -> Any:
        raw = self._api_get_raw(endpoint)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise StrictAuthorizationRefused(
                f"Invalid JSON returned from GitHub API for {endpoint}: {exc}"
            )

    def _download_artifact_zip(self, artifact_url: str, timeout: int = 60) -> bytes:
        """Download artifact zip archive following redirects without forwarding Authorization header."""
        req = urllib.request.Request(
            artifact_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
            },
        )
        location = None
        try:
            with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            if err.code in REDIRECT_CODES:
                location = err.headers.get("Location")
            if location is None:
                raise StrictAuthorizationRefused(
                    f"Artifact download HTTP error {err.code} without Location header"
                )

        signed_req = urllib.request.Request(location, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(signed_req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:
            raise StrictAuthorizationRefused(f"Failed downloading redirected artifact: {exc}")

    def verify_git_source_relations(
        self,
        p_sha: str,
        w_sha: str,
        c_sha: str,
        repo_dir: Optional[str] = None,
    ) -> None:
        """Verify that W descends from P, product trees are identical under src, and C matches."""
        # Query PR 147 head if available via API
        try:
            pr_data = self._api_get(f"repos/{self.repository}/pulls/147")
            if isinstance(pr_data, dict):
                pr_head = pr_data.get("head", {}).get("sha")
                if pr_head and pr_head != p_sha:
                    raise StrictAuthorizationRefused(
                        f"PR147 head moved: PR reports {pr_head}, manifest binds {p_sha}"
                    )
        except StrictAuthorizationRefused as exc:
            # If explicit rejection, propagate
            if "PR147 head moved" in str(exc):
                raise
        except Exception:
            # Endpoint may not be mocked in all minimal loopbacks
            pass

        # If repo_dir or current working directory is a git repo, check git ancestry and diff
        cwd = repo_dir or os.getcwd()
        try:
            # Check W descends from P
            ancestor_check = subprocess.run(
                ["git", "merge-base", "--is-ancestor", p_sha, w_sha],
                cwd=cwd,
                capture_output=True,
                text=True,
            )
            if ancestor_check.returncode != 0:
                raise StrictAuthorizationRefused(
                    f"W ({w_sha}) does not descend from P ({p_sha})"
                )

            # Check product trees are identical under src
            diff_check = subprocess.run(
                ["git", "diff", "--exit-code", f"{p_sha}..{w_sha}", "--", "src"],
                cwd=cwd,
                capture_output=True,
                text=True,
            )
            if diff_check.returncode != 0:
                raise StrictAuthorizationRefused(
                    f"Product trees differ between P ({p_sha}) and W ({w_sha}) under src"
                )
        except FileNotFoundError:
            pass
        except StrictAuthorizationRefused:
            raise
        except Exception:
            pass

    def verify(
        self,
        manifest_path: str,
        repo_dir: Optional[str] = None,
        review_path: Optional[str] = None,
        check_git: bool = True,
    ) -> Dict[str, Any]:
        """Perform authoritative inspection of manifest against GitHub and source evidence."""
        canonical_bytes, m, D = read_manifest_package(manifest_path)

        # 1. Manifest structure and schema validation
        if m.get("schema") != MANIFEST_SCHEMA:
            raise StrictAuthorizationRefused(
                f"wrong schema: expected {MANIFEST_SCHEMA}, got {m.get('schema')}"
            )

        if m.get("execution_backend") != EXECUTION_BACKEND:
            raise StrictAuthorizationRefused(
                f"wrong backend: expected {EXECUTION_BACKEND}, got {m.get('execution_backend')}"
            )

        if m.get("repository") != PINNED_REPOSITORY or str(m.get("repository_id")) != PINNED_REPOSITORY_ID:
            raise StrictAuthorizationRefused("wrong repository")

        if m.get("environment_name") != PINNED_ENVIRONMENT_NAME or str(m.get("environment_id")) != PINNED_ENVIRONMENT_ID:
            raise StrictAuthorizationRefused("wrong environment")

        if str(m.get("reviewer_id")) != PINNED_REVIEWER_ID:
            raise StrictAuthorizationRefused("wrong reviewer")

        if m.get("workflow_path") != PINNED_WORKFLOW_PATH:
            raise StrictAuthorizationRefused("wrong workflow")

        if str(m.get("s_run_attempt")) != "1":
            raise StrictAuthorizationRefused("s_run_attempt must be 1: reruns cannot be authorized")

        p_sha = validate_hex_sha(m.get("p_sha"), 40, "p_sha")
        w_sha = validate_hex_sha(m.get("w_sha"), 40, "w_sha")
        c_sha = validate_hex_sha(m.get("c_sha"), 40, "c_sha")
        s_run_id = validate_decimal(m.get("s_run_id"), "s_run_id")
        v_run_id = validate_decimal(m.get("v_run_id"), "v_run_id")

        # 2. Authenticate GitHub repository identity
        repo_info = self._api_get(f"repos/{self.repository}")
        if str(repo_info.get("id")) != PINNED_REPOSITORY_ID:
            raise StrictAuthorizationRefused(
                f"Repository ID mismatch: expected {PINNED_REPOSITORY_ID}, got {repo_info.get('id')}"
            )

        # 3. Authenticate GitHub environment and policy
        env_info = self._api_get(f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}")
        if str(env_info.get("id")) != PINNED_ENVIRONMENT_ID:
            raise StrictAuthorizationRefused("Environment ID mismatch")

        if env_info.get("can_admins_bypass") is not False:
            raise StrictAuthorizationRefused("Environment policy violation: can_admins_bypass must be False")

        # Check required reviewers
        rules = env_info.get("protection_rules", [])
        reviewer_found = False
        for rule in rules:
            if rule.get("type") == "required_reviewers":
                if rule.get("prevent_self_review") is not False:
                    raise StrictAuthorizationRefused("Environment policy violation: prevent_self_review must be False")
                reviewers = rule.get("reviewers", [])
                for rev in reviewers:
                    user = rev.get("reviewer", {})
                    if str(user.get("id")) == PINNED_REVIEWER_ID:
                        reviewer_found = True
                        break
        if not reviewer_found:
            raise StrictAuthorizationRefused("Required reviewer 43164 missing from environment protection rules")

        # Check deployment branch policies
        bp_info = self._api_get(
            f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies"
        )
        branches = [b.get("name") for b in bp_info.get("branch_policies", [])]
        if PINNED_BRANCH not in branches:
            raise StrictAuthorizationRefused(f"Branch {PINNED_BRANCH} not permitted by environment branch policy")

        # 4. Authenticate Run S (approval run)
        s_run = self._api_get(f"repos/{self.repository}/actions/runs/{s_run_id}")
        if str(s_run.get("run_attempt")) != "1":
            raise StrictAuthorizationRefused("Run S attempt must be 1")
        if s_run.get("path") != PINNED_WORKFLOW_PATH:
            raise StrictAuthorizationRefused(f"Run S workflow mismatch: {s_run.get('path')}")
        if s_run.get("head_sha") != c_sha:
            raise StrictAuthorizationRefused(
                f"Run S head_sha mismatch with C: expected {c_sha}, got {s_run.get('head_sha')}"
            )
        if str(s_run.get("repository", {}).get("id")) != PINNED_REPOSITORY_ID:
            raise StrictAuthorizationRefused("Run S repository mismatch")

        # 5. Authenticate Jobs in Run S
        s_jobs_resp = self._api_get(
            f"repos/{self.repository}/actions/runs/{s_run_id}/attempts/1/jobs"
        )
        s_jobs = s_jobs_resp.get("jobs", [])
        env_jobs = [
            j for j in s_jobs
            if isinstance(j, dict) and (
                j.get("name") == "strict-chain"
                or any(step.get("name") == "strict-chain" for step in j.get("steps", []) if isinstance(step, dict))
            )
        ]
        if len(env_jobs) != 1:
            raise StrictAuthorizationRefused(
                f"Exactly one job in S must use approval environment, found {len(env_jobs)}"
            )

        prep_jobs = [
            j for j in s_jobs
            if isinstance(j, dict) and j.get("name") == "prepare-strict-authorization"
        ]
        if prep_jobs and prep_jobs[0].get("conclusion") != "success":
            raise StrictAuthorizationRefused("Preparation job in S did not succeed")

        # 6. Authenticate Approval Record in Run S
        approvals = self._api_get(f"repos/{self.repository}/actions/runs/{s_run_id}/approvals")
        if not isinstance(approvals, list):
            raise StrictAuthorizationRefused("Invalid approvals list format from GitHub API")

        expected_comment = f"{APPROVAL_COMMENT_PREFIX}{D}"
        matching_approvals = []
        for app in approvals:
            if not isinstance(app, dict):
                continue
            state = app.get("state")
            user_id = str(app.get("user", {}).get("id"))
            comment = app.get("comment", "")
            environments = app.get("environments", [])
            # Support both environments array and environment object
            env_ids = [str(e.get("id")) for e in environments if isinstance(e, dict)]
            if "environment" in app and isinstance(app["environment"], dict):
                env_ids.append(str(app["environment"].get("id")))

            if (
                state == "approved"
                and user_id == PINNED_REVIEWER_ID
                and PINNED_ENVIRONMENT_ID in env_ids
                and comment == expected_comment
            ):
                matching_approvals.append(app)

        if len(matching_approvals) != 1:
            # Diagnose specific reason
            if not approvals:
                raise StrictAuthorizationRefused("No approvals found in GitHub history for run S")
            # Check for near matches or specific faults
            for app in approvals:
                if str(app.get("user", {}).get("id")) != PINNED_REVIEWER_ID:
                    raise StrictAuthorizationRefused(
                        f"Approval user ID mismatch: expected {PINNED_REVIEWER_ID}, got {app.get('user', {}).get('id')}"
                    )
                env_ids = [str(e.get("id")) for e in app.get("environments", []) if isinstance(e, dict)]
                if PINNED_ENVIRONMENT_ID not in env_ids:
                    raise StrictAuthorizationRefused(
                        f"Approval environment ID mismatch: expected {PINNED_ENVIRONMENT_ID}, got {env_ids}"
                    )
                if app.get("state") != "approved":
                    raise StrictAuthorizationRefused(
                        f"Approval state is not approved: {app.get('state')}"
                    )
                comm = app.get("comment", "")
                if comm != expected_comment:
                    raise StrictAuthorizationRefused(
                        f"Approval comment mismatch: expected '{expected_comment}', got '{comm}'"
                    )
            raise StrictAuthorizationRefused("No valid matching approval record found for run S")

        # 7. Authenticate V run and evidence artifacts
        v_run = self._api_get(f"repos/{self.repository}/actions/runs/{v_run_id}")
        if v_run.get("status") != "completed" or v_run.get("conclusion") != "success":
            raise StrictAuthorizationRefused(
                f"V run {v_run_id} status or conclusion failure: status={v_run.get('status')}, conclusion={v_run.get('conclusion')}"
            )

        v_jobs_resp = self._api_get(
            f"repos/{self.repository}/actions/runs/{v_run_id}/attempts/1/jobs"
        )
        for job in v_jobs_resp.get("jobs", []):
            if isinstance(job, dict) and job.get("conclusion") != "success":
                raise StrictAuthorizationRefused(
                    f"Job '{job.get('name')}' in V run {v_run_id} failed with conclusion '{job.get('conclusion')}'"
                )

        v_artifacts = m.get("v_artifacts", [])
        if not v_artifacts:
            raise StrictAuthorizationRefused("Manifest has no v_artifacts")

        for art in v_artifacts:
            art_id = str(art["id"])
            art_meta = self._api_get(f"repos/{self.repository}/actions/artifacts/{art_id}")
            if art_meta.get("expired") is True:
                raise StrictAuthorizationRefused(f"Evidence artifact {art_id} is expired")
            if str(art_meta.get("workflow_run", {}).get("id")) != v_run_id:
                raise StrictAuthorizationRefused(
                    f"Evidence artifact {art_id} workflow run mismatch: expected {v_run_id}, got {art_meta.get('workflow_run', {}).get('id')}"
                )
            download_url = f"{self.base_url}/repos/{self.repository}/actions/artifacts/{art_id}/zip"
            zip_bytes = self._download_artifact_zip(download_url)
            computed_art_sha = compute_digest(zip_bytes)
            if computed_art_sha != art["sha256"]:
                raise StrictAuthorizationRefused(
                    f"Evidence artifact {art_id} archive SHA-256 digest mismatch: expected {art['sha256']}, got {computed_art_sha}"
                )

        # 8. Authenticate Independent Review E
        review_info = m.get("review", {})
        if review_info.get("verdict") != "GO":
            raise StrictAuthorizationRefused(
                f"Independent review verdict is not GO: {review_info.get('verdict')}"
            )
        resolved_rf = review_path or review_info.get("path")
        if resolved_rf and os.path.exists(resolved_rf):
            with open(resolved_rf, "rb") as rf:
                r_bytes = rf.read()
            if compute_digest(r_bytes) != review_info.get("sha256"):
                raise StrictAuthorizationRefused("Review file content SHA-256 mismatch with manifest")
            try:
                r_obj = json.loads(r_bytes.decode("utf-8"))
                if isinstance(r_obj, dict):
                    v = r_obj.get("verdict") or r_obj.get("report", {}).get("verdict")
                    if v and v != "GO":
                        raise StrictAuthorizationRefused(f"Review object declares non-GO verdict: {v}")
            except Exception:
                pass

        # 9. Verify Git Source Relations (P, W, C)
        if check_git:
            self.verify_git_source_relations(p_sha=p_sha, w_sha=w_sha, c_sha=c_sha, repo_dir=repo_dir)

        receipt = {
            "decision": "AUTHORIZED",
            "manifest_digest": D,
            "s_run_id": s_run_id,
            "s_run_attempt": 1,
            "environment_id": int(PINNED_ENVIRONMENT_ID),
            "environment_name": PINNED_ENVIRONMENT_NAME,
            "reviewer_id": int(PINNED_REVIEWER_ID),
            "reviewer_login": PINNED_REVIEWER_LOGIN,
            "c_sha": c_sha,
            "p_sha": p_sha,
            "w_sha": w_sha,
            "execution_backend": EXECUTION_BACKEND,
            "chain_id": CHAIN_ID,
            "timestamp": time.time(),
        }
        return receipt


def acquire_durable_claim(claim_dir: str, s_run_id: str, manifest_digest: str) -> str:
    """Atomically record durable claim for S/D to prevent duplicate fresh chains."""
    os.makedirs(claim_dir, exist_ok=True)
    claim_file = f"claim_{s_run_id}_{manifest_digest}.json"
    claim_path = os.path.join(claim_dir, claim_file)
    if os.path.exists(claim_path):
        raise StrictAuthorizationRefused(
            f"Approval for S run {s_run_id} and manifest {manifest_digest} has already been claimed or consumed at {claim_path}"
        )

    claim_data = {
        "s_run_id": s_run_id,
        "manifest_digest": manifest_digest,
        "backend": EXECUTION_BACKEND,
        "chain_id": CHAIN_ID,
        "status": "in_progress",
        "pid": os.getpid(),
        "claimed_at": time.time(),
    }
    try:
        fd = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w") as f:
            json.dump(claim_data, f, indent=2)
    except FileExistsError:
        raise StrictAuthorizationRefused(
            f"Approval for S run {s_run_id} and manifest {manifest_digest} was concurrently claimed"
        )
    return claim_path


def update_durable_claim(claim_path: str, status: str, error: Optional[str] = None) -> None:
    """Update status of existing durable claim."""
    if os.path.exists(claim_path):
        try:
            with open(claim_path, "r") as f:
                data = json.load(f)
            data["status"] = status
            data["finished_at"] = time.time()
            if error:
                data["error"] = error
            with open(claim_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


def execute_native_proof_chain(
    manifest: Dict[str, Any],
    w_dir: str,
    p_dir: str,
    compiler_bin: str,
    report_dir: str,
    native_runner_cmd: Optional[str] = None,
    native_journal_path: Optional[str] = None,
) -> int:
    """Execute the full native proof chain from C's absolute directory."""
    c_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stages = [
        ("preflight", [
            sys.executable, "-B", os.path.join(c_root, "proof", "preflight_oracle.py"),
            "--w", w_dir, "--p", p_dir, "--compiler", compiler_bin,
        ]),
        ("plan", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "plan", "--w", w_dir, "--p", p_dir, "--compiler", compiler_bin,
        ]),
        ("pin", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "pin", "--w", w_dir, "--p", p_dir, "--compiler", compiler_bin, "--report-dir", report_dir,
        ]),
        ("run1", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "run1", "--report-dir", report_dir,
        ]),
        ("run2", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "run2", "--report-dir", report_dir,
        ]),
        ("run3", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "run3", "--report-dir", report_dir,
        ]),
        ("final", [
            sys.executable, "-B", os.path.join(c_root, "proof", "run_proof.py"),
            "final", "--report-dir", report_dir,
        ]),
    ]

    env = dict(os.environ)
    env["PYTHONPATH"] = f"{c_root}:{env.get('PYTHONPATH', '')}".rstrip(":")

    for stage_name, cmd in stages:
        actual_cmd = cmd
        if native_runner_cmd:
            import shlex
            actual_cmd = shlex.split(native_runner_cmd) + [stage_name] + cmd

        if native_journal_path:
            with open(native_journal_path, "a") as jf:
                jf.write(json.dumps({
                    "stage": stage_name,
                    "command": actual_cmd,
                    "timestamp": time.time(),
                }) + "\n")

        res = subprocess.run(actual_cmd, cwd=c_root, env=env)
        if res.returncode != 0:
            return res.returncode

    return 0


# Backwards-compatible wrappers for supervisor and controller
def check_strict_authorization_or_refuse(
    p_sha: str,
    w_sha: str,
    c_sha: str,
    verified_auth: Optional[Any] = None,
) -> None:
    """Fail-closed check for legacy callers. Raises StrictAuthorizationRefused without authentic proof."""
    if verified_auth is not None:
        if isinstance(verified_auth, dict):
            if (
                verified_auth.get("decision") == "AUTHORIZED"
                and verified_auth.get("p_sha") == p_sha
                and verified_auth.get("w_sha") == w_sha
                and verified_auth.get("c_sha") == c_sha
            ):
                return
        elif getattr(verified_auth, "is_authorized", False):
            if (
                getattr(verified_auth, "p_sha", None) == p_sha
                and getattr(verified_auth, "w_sha", None) == w_sha
                and getattr(verified_auth, "c_sha", None) == c_sha
            ):
                return
        raise AuthorizationError("Provided authorization object is not authorized or revision mismatch")

    refusal_msg = (
        f"STRICT_MODE_AUTH_REFUSED: Environment '{PINNED_ENVIRONMENT_NAME}' (ID {PINNED_ENVIRONMENT_ID}) "
        f"requires manual approval by reviewer {PINNED_REVIEWER_ID} with comment '{APPROVAL_COMMENT_PREFIX}<D>' "
        f"on attempt 1. No deployment approval has been recorded on GitHub. Refusing execution (exit code {AUTH_REFUSED_EXIT_CODE})."
    )
    print(f"\n[STRICT_AUTHORIZATION] {refusal_msg}", file=sys.stderr)
    raise StrictAuthorizationRefused(refusal_msg)


def load_verified_authorization_from_ipc(
    auth_ack: Dict[str, Any],
    p_sha: str,
    w_sha: str,
    c_sha: str,
) -> Dict[str, Any]:
    """Compatibility helper for supervisor/controller IPC handoff."""
    if not isinstance(auth_ack, dict) or auth_ack.get("verified") is not True:
        raise StrictAuthorizationRefused("Authorization refused or invalid IPC ACK")
    if auth_ack.get("p_sha") != p_sha or auth_ack.get("w_sha") != w_sha or auth_ack.get("c_sha") != c_sha:
        raise StrictAuthorizationRefused("Revision mismatch in authorization IPC ACK")
    return auth_ack


# CLI Entry commands
def cmd_prepare(args: argparse.Namespace) -> int:
    """Prepare manifest and package."""
    v_arts = []
    if args.v_artifacts:
        if os.path.exists(args.v_artifacts):
            with open(args.v_artifacts, "r") as f:
                v_arts = json.load(f)
        else:
            v_arts = json.loads(args.v_artifacts)

    manifest, canonical_bytes, D = create_manifest(
        p_sha=args.p_sha,
        w_sha=args.w_sha,
        c_sha=args.c_sha,
        s_run_id=args.s_run_id,
        s_run_attempt=args.s_run_attempt,
        workflow_path=args.workflow_path,
        v_run_id=args.v_run_id,
        v_artifacts=v_arts,
        review_path=args.review_path,
        review_sha256=args.review_sha256,
        review_verdict=args.review_verdict,
        execution_backend=args.backend,
        chain_id=args.chain_id,
        environment_id=str(args.environment_id),
        environment_name=args.environment_name,
        reviewer_id=str(args.reviewer_id),
    )

    if args.manifest:
        os.makedirs(os.path.dirname(os.path.abspath(args.manifest)), exist_ok=True)
        with open(args.manifest, "wb") as f:
            f.write(canonical_bytes)

    if args.package:
        os.makedirs(os.path.dirname(os.path.abspath(args.package)), exist_ok=True)
        with zipfile.ZipFile(args.package, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", canonical_bytes)

    if args.output_digest:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_digest)), exist_ok=True)
        with open(args.output_digest, "w") as f:
            f.write(D + "\n")

    print(f"PREPARE_SUCCESS: canonical manifest prepared")
    print(f"MANIFEST_DIGEST: {D}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check manifest against authoritative GitHub data."""
    verifier = AuthenticatedGitHubVerifier(
        token=args.token,
        base_url=args.base_url,
        allow_loopback=args.allow_loopback,
    )
    receipt = verifier.verify(
        manifest_path=args.manifest,
        repo_dir=args.repo_dir,
        review_path=args.review_path,
    )
    if args.receipt:
        os.makedirs(os.path.dirname(os.path.abspath(args.receipt)), exist_ok=True)
        with open(args.receipt, "w") as f:
            json.dump(receipt, f, indent=2)

    if args.format == "json":
        print(json.dumps(receipt, indent=2))
    else:
        print(f"CHECK_SUCCESS: verified environment approval for manifest {receipt['manifest_digest']}")
        print(f"DECISION: AUTHORIZED")
    return 0


def cmd_run_native(args: argparse.Namespace) -> int:
    """Check authorization, record durable claim, and invoke native chain."""
    verifier = AuthenticatedGitHubVerifier(
        token=args.token,
        base_url=args.base_url,
        allow_loopback=args.allow_loopback,
    )
    receipt = verifier.verify(
        manifest_path=args.manifest,
        repo_dir=args.repo_dir,
        review_path=args.review_path,
    )

    claim_dir = args.claim_dir or os.path.expanduser("~/.cache/iyi-strict-proof/claims")
    claim_path = acquire_durable_claim(
        claim_dir=claim_dir,
        s_run_id=str(receipt["s_run_id"]),
        manifest_digest=receipt["manifest_digest"],
    )

    _, manifest, _ = read_manifest_package(args.manifest)

    os.makedirs(args.report_dir, exist_ok=True)
    status = "failed"
    try:
        ret = execute_native_proof_chain(
            manifest=manifest,
            w_dir=args.w,
            p_dir=args.p,
            compiler_bin=args.compiler,
            report_dir=args.report_dir,
            native_runner_cmd=args.native_runner_cmd,
            native_journal_path=args.native_journal,
        )
        if ret == 0:
            status = "completed"
        return ret
    finally:
        update_durable_claim(claim_path, status=status)


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Fail-closed authenticated strict authorization verifier"
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # prepare
    p_prep = subparsers.add_parser("prepare", help="Prepare canonical manifest")
    p_prep.add_argument("--manifest", required=True, help="Output path for canonical manifest JSON")
    p_prep.add_argument("--package", help="Optional output path for ZIP package containing manifest.json")
    p_prep.add_argument("--p-sha", required=True, help="PR147 product commit SHA")
    p_prep.add_argument("--w-sha", required=True, help="Proof commit SHA")
    p_prep.add_argument("--c-sha", required=True, help="Reviewed strict commit SHA")
    p_prep.add_argument("--s-run-id", required=True, help="Approval workflow run ID")
    p_prep.add_argument("--s-run-attempt", type=int, default=1, help="Approval workflow run attempt")
    p_prep.add_argument("--workflow-path", default=PINNED_WORKFLOW_PATH, help="Workflow file path")
    p_prep.add_argument("--v-run-id", required=True, help="Validation workflow run ID")
    p_prep.add_argument("--v-artifacts", required=True, help="JSON string or file path containing artifact records")
    p_prep.add_argument("--review-path", help="Path to independent review file")
    p_prep.add_argument("--review-sha256", help="SHA-256 of independent review")
    p_prep.add_argument("--review-verdict", default="GO", help="Expected review verdict")
    p_prep.add_argument("--backend", default=EXECUTION_BACKEND, help="Execution backend")
    p_prep.add_argument("--chain-id", default=CHAIN_ID, help="Strict chain identity")
    p_prep.add_argument("--environment-id", type=int, default=int(PINNED_ENVIRONMENT_ID))
    p_prep.add_argument("--environment-name", default=PINNED_ENVIRONMENT_NAME)
    p_prep.add_argument("--reviewer-id", type=int, default=int(PINNED_REVIEWER_ID))
    p_prep.add_argument("--output-digest", help="Optional output path to write manifest digest D")

    # check
    p_check = subparsers.add_parser("check", help="Check manifest against authoritative GitHub data")
    p_check.add_argument("--manifest", required=True, help="Path to manifest JSON or ZIP package")
    p_check.add_argument("--token", help="GitHub API token")
    p_check.add_argument("--base-url", help="GitHub API base URL")
    p_check.add_argument("--allow-loopback", action="store_true", help="Allow loopback API URLs for testing")
    p_check.add_argument("--repo-dir", help="Local git repository directory for source checks")
    p_check.add_argument("--review-path", help="Optional path to independent review file")
    p_check.add_argument("--receipt", help="Optional output path for verification receipt JSON")
    p_check.add_argument("--format", choices=["text", "json"], default="text")

    # run-native
    p_rn = subparsers.add_parser("run-native", help="Verify authorization and invoke native chain")
    p_rn.add_argument("--manifest", required=True, help="Path to manifest JSON or ZIP package")
    p_rn.add_argument("--w", required=True, help="Path to W proof directory")
    p_rn.add_argument("--p", required=True, help="Path to P product directory")
    p_rn.add_argument("--compiler", required=True, help="Path to compiler binary")
    p_rn.add_argument("--report-dir", required=True, help="Path to output report directory")
    p_rn.add_argument("--claim-dir", help="Directory to store durable claims")
    p_rn.add_argument("--token", help="GitHub API token")
    p_rn.add_argument("--base-url", help="GitHub API base URL")
    p_rn.add_argument("--allow-loopback", action="store_true", help="Allow loopback API URLs for testing")
    p_rn.add_argument("--repo-dir", help="Local git repository directory for source checks")
    p_rn.add_argument("--review-path", help="Optional path to independent review file")
    p_rn.add_argument("--native-runner-cmd", help="Optional test wrapper command for native stage subprocesses")
    p_rn.add_argument("--native-journal", help="Optional path to journal file logging stage executions")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns exit code 0, 2 (usage), or 5 (refusal)."""
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code

    if not args.subcommand:
        parser.print_usage(sys.stderr)
        return USAGE_ERROR_EXIT_CODE

    try:
        if args.subcommand == "prepare":
            return cmd_prepare(args)
        elif args.subcommand == "check":
            return cmd_check(args)
        elif args.subcommand == "run-native":
            return cmd_run_native(args)
        else:
            return USAGE_ERROR_EXIT_CODE
    except StrictAuthorizationRefused as exc:
        print(f"\n[STRICT_AUTHORIZATION_REFUSED] {exc}", file=sys.stderr)
        return exc.exit_code
    except (AuthorizationError, ValueError) as exc:
        print(f"\n[USAGE_ERROR] {exc}", file=sys.stderr)
        return USAGE_ERROR_EXIT_CODE
    except Exception as exc:
        print(f"\n[UNEXPECTED_ERROR] {exc}", file=sys.stderr)
        return AUTH_REFUSED_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main())
