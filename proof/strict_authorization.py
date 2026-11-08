"""Authenticated API-backed GitHub environment strict-proof authorization verifier.

This module implements manifest preparation, environment policy validation,
and authenticated approval verification for strict mode under GitHub protected
environment attestation policy:
  - Evidence chain binding: The verifier binds the audited repository state,
    action pins, supervisor bundle, validation artifacts, preserved harness copy,
    and independent audit commit into an immutable canonical manifest.
  - Platform attestation: GitHub records that account 43164 (jwaldrip) approved
    environment 'strict-proof' (ID 26584191206) for this run attempt 1 with exactly
    the comment 'iyi-strict-authorization-v2 sha256:<D>'. It does not record who
    operated the account or which credential was used. Reviewer independence and audit
    soundness are attested by the approver; no system authenticates the reviewer.
  - Fail-closed execution: All checks must pass against GitHub API before authorization
    is granted. Any verification failure, tampering, or API fault exits 5.
"""

import argparse
import base64
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request
import zipfile

# Pinned immutable repository and environment trust anchors
PINNED_REPOSITORY = "jwaldrip/iyi"
PINNED_REPOSITORY_ID = "1340355933"
PINNED_WORKFLOW_ID = "403985693"
PINNED_WORKFLOW_PATH = ".github/workflows/remote-strict-proof.yml"
PINNED_WORKFLOW_NAME = "Remote Strict Proof Chain (macOS 15)"
PINNED_DEPLOY_BRANCH = "proof/strict-lifecycle-repair-20261102"
PINNED_REF = "refs/heads/proof/strict-lifecycle-repair-20261102"
WORKFLOW_REF = "jwaldrip/iyi/.github/workflows/remote-strict-proof.yml@refs/heads/proof/strict-lifecycle-repair-20261102"
PINNED_ENVIRONMENT_NAME = "strict-proof"
PINNED_ENVIRONMENT_ID = "26584191206"
PINNED_REVIEWER_ID = "43164"
PINNED_REVIEWER_LOGIN = "jwaldrip"

JOB_KEY_PREPARE = "prepare-strict-authorization"
JOB_NAME_PREPARE = "Prepare strict authorization manifest"
JOB_KEY_STRICT = "strict-chain"
JOB_NAME_STRICT = "Sequential strict-chain attempt (macOS 15)"
JOB_KEY_REHEARSAL = "authorization-rehearsal"
JOB_NAME_REHEARSAL = "Authorization rehearsal against GitHub API"

# Anchored P head from PR #147 and audited proof W SHA
PINNED_P_SHA = "180f14f91c829b25362a5ed34b20847f3ac2db77"
PINNED_P_PR_REPOSITORY = "iyilang/iyi"
PINNED_P_PR_NUMBER = "147"
PINNED_P_PR_STATE = "open"
PINNED_P_HEAD_REF = "plan/native-stale-testing"
PINNED_P_HEAD_REPO_ID = "1340355933"

PINNED_W_SHA = "5a3770e96fb12099c4ce9dc3b21895de07dd4cd8"
PINNED_W_MERGE_BASE = PINNED_P_SHA
PINNED_W_AHEAD_BY = 2
PINNED_W_BEHIND_BY = 0
PINNED_W_ADDED_COUNT = 34
PINNED_W_ADDED_PATHS_SHA256 = "0f4a92668eeba752d74a3d4deab401d6ca023d69ab3e013d92d943bad84fed3c"

PINNED_H_SHA = "48ffd47caaf45ff9580c35e6f2b0e3c285144bcc"
PINNED_H_MERGE_BASE = PINNED_W_SHA
PINNED_H_ADDED_PATHS = [
    ".github/workflows/remote-harness-audit.yml",
    "proof/remote_harness_audit.py",
]

HARNESS_RUN_ID = "42429518284"
HARNESS_RUN_ATTEMPT = "1"
HARNESS_WORKFLOW_ID = "403962866"
HARNESS_WORKFLOW_PATH = ".github/workflows/remote-harness-audit.yml"
HARNESS_EVENT = "push"
HARNESS_HEAD_BRANCH = "proof/remote-harness-audit-pr147-refresh-20261107"
HARNESS_CONCLUSION = "success"
HARNESS_JOB_ID = "128575084391"
HARNESS_JOB_NAME = "macOS-15 Remote Harness CI Gate and H'' Audit (Plan §2-§3)"
HARNESS_ARTIFACT_ID = "13600255503"
HARNESS_ARTIFACT_NAME = "remote-harness-audit-evidence"
HARNESS_ARTIFACT_DIGEST = "sha256:3eb033b6e255cec4cc137d4c6379b1ca97a4c43712ac5171e57a48cf24fb3862"
HARNESS_PRESERVED_COMMIT = "83ffe98b6dccd267f8f677ac40e7056535fb0d0b"
HARNESS_PRESERVED_PATH = "proof/recovery-180f14f-current/remote-harness-audit-42429518284.zip"
HARNESS_PRESERVED_BLOB = "95962d09b72f54bb53a334404b381ab630e44ceb"
HARNESS_SUMMARY_MEMBER = "audit_summary.json"
HARNESS_SUMMARY_MEMBER_SHA256 = "6d11eba8c63bd25995cd17705c17c2e16d48bb626e8b934cd0a6c2980b7f3f18"

SCHEMA_MANIFEST = "iyi.strict-authorization-manifest.v2"
APPROVAL_COMMENT_PREFIX = "iyi-strict-authorization-v2 sha256:"
SCHEMA_VERIFICATION = "iyi.strict-authorization-verification.v2"
SCHEMA_AUDIT = "iyi.strict-independent-audit.v2"
SCHEMA_RAIL_SUMMARY = "iyi.strict-rail-validation-summary.v1"
SCHEMA_REHEARSAL = "iyi.strict-authorization-rehearsal.v1"
SCHEMA_REHEARSAL_MANIFEST = "iyi.strict-authorization-rehearsal-manifest.v2"

ARTIFACT_NAME_MANIFEST = "strict-authorization-manifest"
ARTIFACT_NAME_VERIFICATION = "strict-authorization-verification"
ARTIFACT_NAME_RAIL_SUMMARY = "rail-validation-summary"
ARTIFACT_NAME_REHEARSAL_REPORT = "rail-rehearsal-report"

ATTESTATION_SCOPE = (
    "GitHub records that account 43164 approved environment 26584191206 for this run with this comment. "
    "It does not record who operated the account or which credential was used. "
    "Reviewer independence and audit soundness are attested by the approver; no system authenticates the reviewer."
)

PINNED_ACTIONS = {
    "actions/checkout": {"tag": "v7.0.1", "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1"},
    "actions/setup-python": {"tag": "v7.1.0", "sha": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"},
    "actions/setup-go": {"tag": "v7.0.0", "sha": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"},
    "actions/cache": {"tag": "v6.1.0", "sha": "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"},
    "actions/setup-node": {"tag": "v7.1.0", "sha": "949feb2413d6458794dcd2491c4babbbce0c15c1"},
    "actions/upload-artifact": {"tag": "v7.0.2", "sha": "cf430e030ddbb5b0abf93d22962f4752f3646cd9"},
}

PINNED_REFUSAL_CONTROLS = [
    "missing_manifest_fd",
    "manifest_digest_mismatch",
    "strict_run_id_mismatch",
    "invalid_p_sha",
]

PINNED_API_BASE = "https://api.github.com"
AUTH_REFUSED_EXIT_CODE = 5
USAGE_ERROR_EXIT_CODE = 2
REDIRECT_CODES = (301, 302, 303, 307, 308)


class AuthorizationError(ValueError):
    """Raised when an authorization check fails closed."""
    def __init__(self, message: str, check_id: Optional[str] = None):
        super().__init__(message)
        self.check_id = check_id


class StrictAuthorizationRefused(RuntimeError):
    """Raised when strict execution is refused."""
    pass


def canonical(value: Any) -> bytes:
    """Serialize value to deterministic canonical UTF-8 JSON without trailing newline."""
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
        for key, val in pairs:
            if key in result:
                raise AuthorizationError(f"duplicate JSON key: {key}")
            result[key] = val
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda c: (_ for _ in ()).throw(AuthorizationError(f"invalid JSON constant: {c}")),
        )
        if canonical(value) != raw:
            raise AuthorizationError("noncanonical JSON")
        return value
    except AuthorizationError:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise AuthorizationError("invalid canonical JSON") from exc


def digest(raw: bytes) -> str:
    """Return lowercase hex SHA-256 digest."""
    return hashlib.sha256(raw).hexdigest()


def git_blob_id(data: bytes) -> str:
    """Compute git object SHA-1 for a blob."""
    header = f"blob {len(data)}\0".encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


@dataclass(frozen=True)
class StrictManifestBinding:
    """Immutable binding established by controller reading supervisor fd 5."""
    manifest_sha256: str
    strict_run_id: str
    strict_run_attempt: str
    c_sha: str
    p_sha: str
    w_sha: str


def read_strict_manifest_binding(
    fd: int,
    expected_sha256: str,
    *,
    repository: str,
    run_id: str,
    run_attempt: str,
    p_sha: str,
    w_sha: str,
    c_sha: str,
) -> StrictManifestBinding:
    """Read up to 64 KiB from fd to EOF, close fd, verify digest and parse canonical manifest.

    Checks repository, run_id, run_attempt ('1'), and sources C/P/W matching rev-parse/pins.
    Guarantees raising only AuthorizationError on any refusal condition.
    """
    try:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise AuthorizationError("expected_sha256 must be a 64-hex lowercase string")

        if fd is None or not isinstance(fd, int) or fd < 0:
            raise AuthorizationError("invalid file descriptor")

        chunks = []
        total = 0
        max_bytes = 65536
        while True:
            try:
                chunk = os.read(fd, max_bytes - total + 1)
            except OSError as exc:
                raise AuthorizationError(f"error reading manifest fd: {exc}") from exc
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise AuthorizationError("manifest on fd exceeds 64 KiB limit")
    except AuthorizationError:
        raise
    except Exception as exc:
        raise AuthorizationError(f"error processing manifest binding: {exc}") from exc
    finally:
        if fd is not None and isinstance(fd, int) and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    raw_bytes = b"".join(chunks)
    if len(raw_bytes) == 0:
        raise AuthorizationError("empty manifest on fd")

    actual_digest = digest(raw_bytes)
    if actual_digest != expected_sha256:
        raise AuthorizationError(f"manifest digest mismatch: expected {expected_sha256}, got {actual_digest}")

    m = parse(raw_bytes)
    if not isinstance(m, dict):
        raise AuthorizationError("manifest must be a JSON object")
    if m.get("schema") != SCHEMA_MANIFEST:
        raise AuthorizationError(f"manifest schema mismatch: expected {SCHEMA_MANIFEST}, got {m.get('schema')}")

    repo_obj = m.get("repository", {})
    if repo_obj.get("full_name") != repository:
        raise AuthorizationError(f"repository mismatch: expected {repository}, got {repo_obj.get('full_name')}")
    if str(repo_obj.get("id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"repository id mismatch: expected {PINNED_REPOSITORY_ID}, got {repo_obj.get('id')}")

    strict_run = m.get("strict_run", {})
    if str(strict_run.get("id")) != str(run_id):
        raise AuthorizationError(f"strict run id mismatch: expected {run_id}, got {strict_run.get('id')}")
    if str(strict_run.get("attempt")) != "1":
        raise AuthorizationError(f"strict run attempt in manifest must be '1', got {strict_run.get('attempt')}")
    if str(run_attempt) != "1":
        raise AuthorizationError(f"strict run attempt must be '1', got {run_attempt}")

    sources = m.get("sources", {})
    if sources.get("c_sha") != c_sha:
        raise AuthorizationError(f"c_sha mismatch: expected {c_sha}, got {sources.get('c_sha')}")

    p_obj = sources.get("p", {})
    if p_obj.get("sha") != p_sha:
        raise AuthorizationError(f"p_sha mismatch: expected {p_sha}, got {p_obj.get('sha')}")
    if p_sha != PINNED_P_SHA:
        raise AuthorizationError(f"p_sha does not match pinned {PINNED_P_SHA}: got {p_sha}")

    w_obj = sources.get("w", {})
    if w_obj.get("sha") != w_sha:
        raise AuthorizationError(f"w_sha mismatch: expected {w_sha}, got {w_obj.get('sha')}")
    if w_sha != PINNED_W_SHA:
        raise AuthorizationError(f"w_sha does not match pinned {PINNED_W_SHA}: got {w_sha}")

    return StrictManifestBinding(
        manifest_sha256=expected_sha256,
        strict_run_id=str(run_id),
        strict_run_attempt=str(run_attempt),
        c_sha=c_sha,
        p_sha=p_sha,
        w_sha=w_sha,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent automatic redirect so the token is not forwarded across domains."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubAPIClient:
    """Authenticated GitHub REST API client with retry and redirect isolation."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = PINNED_API_BASE,
        timeout: int = 30,
        max_attempts: int = 3,
    ) -> None:
        self.token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_attempts = max_attempts

    def _request(
        self,
        endpoint_or_url: str,
        params: Optional[Dict[str, Any]] = None,
        include_auth: bool = True,
        follow_redirect: bool = False,
    ) -> Tuple[int, bytes, Dict[str, str]]:
        if endpoint_or_url.startswith("http://") or endpoint_or_url.startswith("https://"):
            url = endpoint_or_url
        else:
            url = f"{self.base_url}/{endpoint_or_url.lstrip('/')}"

        if params:
            query = urllib.parse.urlencode(params)
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{query}"

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "iyi-strict-authorization-core",
        }
        if include_auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, headers=headers)
        opener = urllib.request.build_opener(_NoRedirect)

        for attempt in range(1, self.max_attempts + 1):
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    return resp.status, resp.read(), resp_headers
            except urllib.error.HTTPError as exc:
                resp_headers = {k.lower(): v for k, v in exc.headers.items()}
                if exc.code in REDIRECT_CODES and not follow_redirect:
                    return exc.code, exc.read(), resp_headers
                # Retry only on 5xx or 429
                if (exc.code >= 500 or exc.code == 429) and attempt < self.max_attempts:
                    time.sleep(0.5 * attempt)
                    continue
                return exc.code, exc.read(), resp_headers
            except urllib.error.URLError as exc:
                if attempt < self.max_attempts:
                    time.sleep(0.5 * attempt)
                    continue
                raise AuthorizationError(f"GitHub API connection failure: {exc}") from exc

        raise AuthorizationError("GitHub API request exhausted retries")

    def get_raw(self, endpoint_or_url: str, params: Optional[Dict[str, Any]] = None) -> bytes:
        status, body, _ = self._request(endpoint_or_url, params=params, include_auth=True)
        if status != 200:
            raise AuthorizationError(f"GitHub API error HTTP {status} for {endpoint_or_url}")
        return body

    def get_json(self, endpoint_or_url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        raw = self.get_raw(endpoint_or_url, params=params)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise AuthorizationError(f"Invalid JSON returned from GitHub API for {endpoint_or_url}") from exc

    def get_paginated(
        self,
        endpoint_or_url: str,
        params: Optional[Dict[str, Any]] = None,
        list_key: Optional[str] = None,
    ) -> List[Any]:
        """Fetch all pages for a list endpoint."""
        results: List[Any] = []
        next_url: Optional[str] = endpoint_or_url
        current_params = dict(params or {})

        while next_url:
            status, body, headers = self._request(
                next_url,
                params=current_params if next_url == endpoint_or_url else None,
                include_auth=True,
            )
            if status != 200:
                raise AuthorizationError(f"GitHub API error HTTP {status} on paginated request")

            try:
                page_data = json.loads(body.decode("utf-8"))
            except Exception as exc:
                raise AuthorizationError(f"Invalid JSON on paginated request: {exc}") from exc

            if isinstance(page_data, list):
                results.extend(page_data)
            elif isinstance(page_data, dict):
                if list_key and list_key in page_data:
                    results.extend(page_data[list_key])
                else:
                    for candidate in ("jobs", "artifacts", "branch_policies", "check_runs", "workflow_runs", "rules"):
                        if candidate in page_data and isinstance(page_data[candidate], list):
                            results.extend(page_data[candidate])
                            break
                    else:
                        raise AuthorizationError(f"Cannot identify list key in paginated response: {list(page_data.keys())}")
            else:
                raise AuthorizationError("Unexpected paginated response type")

            link_header = headers.get("link", "")
            next_url = None
            if link_header:
                for part in link_header.split(","):
                    match = re.search(r'<([^>]+)>;\s*rel="next"', part.strip())
                    if match:
                        next_url = match.group(1)
                        break

        return results

    def download_artifact_zip(self, artifact_id: str) -> bytes:
        """Download artifact archive zip following 302 redirect WITHOUT Authorization header."""
        endpoint = f"repos/{PINNED_REPOSITORY}/actions/artifacts/{artifact_id}/zip"
        status, body, headers = self._request(endpoint, include_auth=True, follow_redirect=False)

        if status in REDIRECT_CODES:
            location = headers.get("location")
            if not location:
                raise AuthorizationError(f"Redirect HTTP {status} without Location header for artifact {artifact_id}")
            # Follow redirect WITHOUT Authorization header
            status2, body2, _ = self._request(location, include_auth=False, follow_redirect=True)
            if status2 != 200:
                raise AuthorizationError(f"Storage download error HTTP {status2} for artifact {artifact_id}")
            return body2
        elif status == 200:
            return body
        else:
            raise AuthorizationError(f"Failed to initiate artifact {artifact_id} download: HTTP {status}")


# ---------------------------------------------------------------------------
# Individual check implementations (§3.7)
# ---------------------------------------------------------------------------

def check_rnr_1(environ: Dict[str, str]) -> Dict[str, Any]:
    repo = environ.get("GITHUB_REPOSITORY", "")
    repo_id = environ.get("GITHUB_REPOSITORY_ID", "")
    if repo != PINNED_REPOSITORY:
        raise AuthorizationError(f"[RNR-1] GITHUB_REPOSITORY mismatch: expected {PINNED_REPOSITORY}, got {repo}", check_id="RNR-1")
    if repo_id != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[RNR-1] GITHUB_REPOSITORY_ID mismatch: expected {PINNED_REPOSITORY_ID}, got {repo_id}", check_id="RNR-1")
    return {"repository": repo, "repository_id": repo_id}


def check_rnr_2(environ: Dict[str, str], deploy_branch: str = PINNED_DEPLOY_BRANCH, expected_event: str = "workflow_dispatch") -> Dict[str, Any]:
    event = environ.get("GITHUB_EVENT_NAME", "")
    if event != expected_event:
        raise AuthorizationError(f"[RNR-2] GITHUB_EVENT_NAME mismatch: expected {expected_event}, got {event}", check_id="RNR-2")
    ref = environ.get("GITHUB_REF", "")
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    workflow_sha = environ.get("GITHUB_WORKFLOW_SHA", "")
    sha = environ.get("GITHUB_SHA", "")

    expected_ref = f"refs/heads/{deploy_branch}"
    if ref != expected_ref:
        raise AuthorizationError(f"[RNR-2] GITHUB_REF mismatch: expected {expected_ref}, got {ref}", check_id="RNR-2")
    if workflow_ref != WORKFLOW_REF:
        raise AuthorizationError(f"[RNR-2] GITHUB_WORKFLOW_REF mismatch: expected {WORKFLOW_REF}, got {workflow_ref}", check_id="RNR-2")
    if workflow_sha != sha:
        raise AuthorizationError(f"[RNR-2] GITHUB_WORKFLOW_SHA must equal GITHUB_SHA: {workflow_sha} != {sha}", check_id="RNR-2")

    return {"event": event, "ref": ref, "workflow_ref": workflow_ref, "workflow_sha": workflow_sha}


def check_rnr_3(environ: Dict[str, str]) -> str:
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if attempt != "1":
        raise AuthorizationError(f"[RNR-3] GITHUB_RUN_ATTEMPT must be '1', got {attempt}", check_id="RNR-3")
    return attempt


def check_rnr_4(environ: Dict[str, str], expected_job_key: str) -> Dict[str, Any]:
    job = environ.get("GITHUB_JOB", "")
    runner_env = environ.get("RUNNER_ENVIRONMENT", "")
    job_check_run_id = environ.get("JOB_CHECK_RUN_ID", "")

    if job != expected_job_key:
        raise AuthorizationError(f"[RNR-4] GITHUB_JOB mismatch: expected {expected_job_key}, got {job}", check_id="RNR-4")
    if runner_env != "github-hosted":
        raise AuthorizationError(f"[RNR-4] RUNNER_ENVIRONMENT must be 'github-hosted', got {runner_env}", check_id="RNR-4")
    if not re.fullmatch(r"[1-9][0-9]*", job_check_run_id):
        raise AuthorizationError(f"[RNR-4] JOB_CHECK_RUN_ID must be a decimal string: {job_check_run_id}", check_id="RNR-4")

    return {"job": job, "runner_environment": runner_env, "job_check_run_id": job_check_run_id}


def check_rnr_5(event_payload: Dict[str, Any]) -> Dict[str, Any]:
    inputs = event_payload.get("inputs", {})
    mode = inputs.get("mode")
    evidence_commit = inputs.get("evidence_commit")

    if mode != "strict-chain":
        raise AuthorizationError(f"[RNR-5] event inputs.mode must be 'strict-chain', got {mode}", check_id="RNR-5")
    if not isinstance(evidence_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", evidence_commit):
        raise AuthorizationError(f"[RNR-5] event inputs.evidence_commit must be a 40-hex commit SHA, got {evidence_commit}", check_id="RNR-5")

    return {"mode": mode, "evidence_commit": evidence_commit}


def check_rnr_6(environ: Dict[str, str], repo_root: Optional[str] = None) -> Dict[str, Any]:
    expected_sha = environ.get("GITHUB_SHA", "")
    if not expected_sha or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise AuthorizationError("[RNR-6] GITHUB_SHA must be a valid 40-hex SHA", check_id="RNR-6")
    cwd = repo_root or os.getcwd()

    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorizationError(f"[RNR-6] git rev-parse HEAD failed: {res.stderr}", check_id="RNR-6")
    actual_head = res.stdout.strip()
    if actual_head != expected_sha:
        raise AuthorizationError(f"[RNR-6] local HEAD does not match GITHUB_SHA: {actual_head} != {expected_sha}", check_id="RNR-6")

    res = subprocess.run(["git", "status", "--porcelain"], cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorizationError(f"[RNR-6] git status --porcelain failed: {res.stderr}", check_id="RNR-6")
    porcelain = res.stdout.strip()
    if porcelain:
        raise AuthorizationError(f"[RNR-6] working tree is dirty; git status --porcelain must be empty: {porcelain}", check_id="RNR-6")

    return {"head_sha": actual_head}


def check_rep_1(repo: Dict[str, Any]) -> Dict[str, Any]:
    if str(repo.get("id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[REP-1] repository id mismatch: expected {PINNED_REPOSITORY_ID}, got {repo.get('id')}", check_id="REP-1")
    if repo.get("full_name") != PINNED_REPOSITORY:
        raise AuthorizationError(f"[REP-1] repository full_name mismatch: expected {PINNED_REPOSITORY}, got {repo.get('full_name')}", check_id="REP-1")
    if repo.get("private") is not False:
        raise AuthorizationError("[REP-1] repository private must be false", check_id="REP-1")
    if repo.get("visibility") != "public":
        raise AuthorizationError(f"[REP-1] repository visibility must be 'public', got {repo.get('visibility')}", check_id="REP-1")

    return {
        "id": str(repo["id"]),
        "full_name": repo["full_name"],
        "visibility": repo["visibility"],
    }

def check_run_1(
    run: Dict[str, Any],
    expected_head_sha: str,
    expected_event: str = "workflow_dispatch",
    expected_branch: Optional[str] = None,
    allow_completed: bool = False,
) -> Dict[str, Any]:
    branch = expected_branch or PINNED_DEPLOY_BRANCH
    if str(run.get("run_attempt")) != "1":
        raise AuthorizationError(f"[RUN-1] run_attempt must be 1, got {run.get('run_attempt')}", check_id="RUN-1")
    if str(run.get("workflow_id")) != PINNED_WORKFLOW_ID:
        raise AuthorizationError(f"[RUN-1] workflow_id mismatch: expected {PINNED_WORKFLOW_ID}, got {run.get('workflow_id')}", check_id="RUN-1")
    if run.get("path") != PINNED_WORKFLOW_PATH:
        raise AuthorizationError(f"[RUN-1] workflow path mismatch: expected {PINNED_WORKFLOW_PATH}, got {run.get('path')}", check_id="RUN-1")
    if run.get("head_sha") != expected_head_sha:
        raise AuthorizationError(f"[RUN-1] head_sha mismatch: expected {expected_head_sha}, got {run.get('head_sha')}", check_id="RUN-1")
    if run.get("head_branch") != branch:
        raise AuthorizationError(f"[RUN-1] head_branch mismatch: expected {branch}, got {run.get('head_branch')}", check_id="RUN-1")
    if str(run.get("repository", {}).get("id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[RUN-1] repository id mismatch in run: {run.get('repository', {}).get('id')}", check_id="RUN-1")
    if str(run.get("head_repository", {}).get("id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[RUN-1] head_repository id mismatch in run: {run.get('head_repository', {}).get('id')}", check_id="RUN-1")
    if run.get("event") != expected_event:
        raise AuthorizationError(f"[RUN-1] run event mismatch: expected {expected_event}, got {run.get('event')}", check_id="RUN-1")
    allowed_statuses = ("in_progress", "waiting") if not allow_completed else ("in_progress", "waiting", "completed")
    if run.get("status") not in allowed_statuses:
        raise AuthorizationError(f"[RUN-1] run status must be in {allowed_statuses}, got {run.get('status')}", check_id="RUN-1")

    actor_id = str(run.get("actor_id") or run.get("actor", {}).get("id", ""))
    triggering_actor_id = str(run.get("triggering_actor_id") or run.get("triggering_actor", {}).get("id", ""))

    return {
        "id": str(run["id"]),
        "attempt": "1",
        "workflow_id": str(run["workflow_id"]),
        "workflow_path": run["path"],
        "workflow_ref": WORKFLOW_REF,
        "event": run["event"],
        "head_branch": run["head_branch"],
        "head_sha": run["head_sha"],
        "html_url": run.get("html_url", ""),
        "actor_id": actor_id,
        "triggering_actor_id": triggering_actor_id,
        "created_at": run.get("created_at", ""),
    }
def check_job_1(
    job: Dict[str, Any],
    expected_run_id: str,
    expected_job_name: str,
    expected_head_sha: str,
    runner_name: Optional[str] = None,
) -> Dict[str, Any]:
    if str(job.get("run_id")) != str(expected_run_id):
        raise AuthorizationError(f"[JOB-1] job run_id mismatch: expected {expected_run_id}, got {job.get('run_id')}", check_id="JOB-1")
    if str(job.get("run_attempt")) != "1":
        raise AuthorizationError(f"[JOB-1] job run_attempt must be 1, got {job.get('run_attempt')}", check_id="JOB-1")
    if job.get("name") != expected_job_name:
        raise AuthorizationError(f"[JOB-1] job name mismatch: expected {expected_job_name}, got {job.get('name')}", check_id="JOB-1")
    if job.get("workflow_name") != PINNED_WORKFLOW_NAME:
        raise AuthorizationError(f"[JOB-1] job workflow_name mismatch: expected {PINNED_WORKFLOW_NAME}, got {job.get('workflow_name')}", check_id="JOB-1")
    if job.get("head_sha") != expected_head_sha:
        raise AuthorizationError(f"[JOB-1] job head_sha mismatch: expected {expected_head_sha}, got {job.get('head_sha')}", check_id="JOB-1")
    if job.get("status") not in ("in_progress", "completed"):
        raise AuthorizationError(f"[JOB-1] job status must be 'in_progress' or 'completed', got {job.get('status')}", check_id="JOB-1")
    if not runner_name:
        raise AuthorizationError("[JOB-1] RUNNER_NAME is required", check_id="JOB-1")
    if job.get("runner_name") != runner_name:
        raise AuthorizationError(f"[JOB-1] job runner_name mismatch: expected {runner_name}, got {job.get('runner_name')}", check_id="JOB-1")

    return {
        "id": str(job["id"]),
        "name": job["name"],
        "started_at": job.get("started_at", ""),
    }


def check_job_2(
    check_run: Dict[str, Any],
    deployment: Dict[str, Any],
    expected_run_id: str,
    expected_job_id: str,
    expected_head_sha: str,
) -> Dict[str, Any]:
    if check_run.get("app", {}).get("slug") != "github-actions":
        raise AuthorizationError(f"[JOB-2] check run app.slug must be 'github-actions', got {check_run.get('app', {}).get('slug')}", check_id="JOB-2")
    if check_run.get("head_sha") != expected_head_sha:
        raise AuthorizationError(f"[JOB-2] check run head_sha mismatch: expected {expected_head_sha}, got {check_run.get('head_sha')}", check_id="JOB-2")

    expected_details = f"https://github.com/{PINNED_REPOSITORY}/actions/runs/{expected_run_id}/job/{expected_job_id}"
    if check_run.get("details_url") != expected_details:
        raise AuthorizationError(f"[JOB-2] check run details_url mismatch: expected {expected_details}, got {check_run.get('details_url')}", check_id="JOB-2")

    dep = check_run.get("deployment")
    if not isinstance(dep, dict):
        raise AuthorizationError("[JOB-2] check run missing deployment object", check_id="JOB-2")
    if dep.get("environment") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"[JOB-2] check run deployment.environment must be '{PINNED_ENVIRONMENT_NAME}', got {dep.get('environment')}", check_id="JOB-2")
    if dep.get("original_environment") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"[JOB-2] check run deployment.original_environment must be '{PINNED_ENVIRONMENT_NAME}', got {dep.get('original_environment')}", check_id="JOB-2")
    if dep.get("task") != "deploy":
        raise AuthorizationError(f"[JOB-2] check run deployment.task must be 'deploy', got {dep.get('task')}", check_id="JOB-2")

    if deployment.get("sha") != expected_head_sha:
        raise AuthorizationError(f"[JOB-2] deployment sha mismatch: expected {expected_head_sha}, got {deployment.get('sha')}", check_id="JOB-2")
    if deployment.get("ref") != PINNED_DEPLOY_BRANCH:
        raise AuthorizationError(f"[JOB-2] deployment ref mismatch: expected {PINNED_DEPLOY_BRANCH}, got {deployment.get('ref')}", check_id="JOB-2")
    if deployment.get("environment") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"[JOB-2] deployment environment mismatch: expected {PINNED_ENVIRONMENT_NAME}, got {deployment.get('environment')}", check_id="JOB-2")
    if deployment.get("performed_via_github_app", {}).get("slug") != "github-actions":
        raise AuthorizationError(f"[JOB-2] deployment performed_via_github_app.slug must be 'github-actions', got {deployment.get('performed_via_github_app', {}).get('slug')}", check_id="JOB-2")

    return {
        "check_run_id": str(check_run["id"]),
        "deployment_id": str(deployment["id"]),
        "environment": PINNED_ENVIRONMENT_NAME,
    }


def check_job_3(jobs_list: List[Dict[str, Any]], prepare_job_id: str, strict_job_id: str) -> None:
    prepare_matches = []
    strict_matches = []

    for job in jobs_list:
        name = job.get("name", "")
        jid = str(job.get("id"))
        if name == JOB_NAME_PREPARE:
            prepare_matches.append(job)
            if jid != str(prepare_job_id):
                raise AuthorizationError(f"[JOB-3] prepare job id mismatch: expected {prepare_job_id}, got {jid}", check_id="JOB-3")
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise AuthorizationError(f"[JOB-3] prepare job must be completed/success, got status={job.get('status')}, conclusion={job.get('conclusion')}", check_id="JOB-3")
        elif name == JOB_NAME_STRICT:
            strict_matches.append(job)
            if jid != str(strict_job_id):
                raise AuthorizationError(f"[JOB-3] strict job id mismatch: expected {strict_job_id}, got {jid}", check_id="JOB-3")
        else:
            conclusion = job.get("conclusion")
            if conclusion != "skipped":
                raise AuthorizationError(f"[JOB-3] job '{name}' (id {jid}) must have conclusion 'skipped', got {conclusion}", check_id="JOB-3")

    if len(prepare_matches) != 1:
        raise AuthorizationError(f"[JOB-3] expected exactly one prepare job, found {len(prepare_matches)}", check_id="JOB-3")
    if len(strict_matches) != 1:
        raise AuthorizationError(f"[JOB-3] expected exactly one strict job, found {len(strict_matches)}", check_id="JOB-3")


def check_env_1(env: Dict[str, Any]) -> Dict[str, Any]:
    if str(env.get("id")) != PINNED_ENVIRONMENT_ID:
        raise AuthorizationError(f"[ENV-1] environment id mismatch: expected {PINNED_ENVIRONMENT_ID}, got {env.get('id')}", check_id="ENV-1")
    if env.get("name") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"[ENV-1] environment name mismatch: expected {PINNED_ENVIRONMENT_NAME}, got {env.get('name')}", check_id="ENV-1")
    if env.get("can_admins_bypass") is not False:
        raise AuthorizationError("[ENV-1] environment can_admins_bypass must be false", check_id="ENV-1")

    rules = env.get("protection_rules", [])
    if not isinstance(rules, list) or len(rules) != 2:
        raise AuthorizationError(f"[ENV-1] environment must have exactly 2 protection rules, got {len(rules)}", check_id="ENV-1")

    by_type = {r.get("type"): r for r in rules if isinstance(r, dict)}
    if set(by_type.keys()) != {"required_reviewers", "branch_policy"}:
        raise AuthorizationError(f"[ENV-1] protection rule types mismatch: expected required_reviewers and branch_policy, got {set(by_type.keys())}", check_id="ENV-1")

    rev_rule = by_type["required_reviewers"]
    if rev_rule.get("prevent_self_review") is not False:
        raise AuthorizationError("[ENV-1] prevent_self_review must be false", check_id="ENV-1")

    reviewers = rev_rule.get("reviewers", [])
    if len(reviewers) != 1:
        raise AuthorizationError(f"[ENV-1] expected exactly 1 reviewer in protection rule, got {len(reviewers)}", check_id="ENV-1")
    rev = reviewers[0]
    if rev.get("type") != "User" or str(rev.get("reviewer", {}).get("id")) != PINNED_REVIEWER_ID:
        raise AuthorizationError(f"[ENV-1] reviewer mismatch: expected User {PINNED_REVIEWER_ID}, got {rev}", check_id="ENV-1")

    dep_policy = env.get("deployment_branch_policy")
    if dep_policy != {"protected_branches": False, "custom_branch_policies": True}:
        raise AuthorizationError(f"[ENV-1] deployment_branch_policy mismatch: expected {{'protected_branches': False, 'custom_branch_policies': True}}, got {dep_policy}", check_id="ENV-1")

    return {
        "id": str(env["id"]),
        "name": env["name"],
        "can_admins_bypass": False,
        "required_reviewers": [{"type": "User", "id": PINNED_REVIEWER_ID}],
        "prevent_self_review": False,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def check_env_2(policies_resp: Any) -> List[Dict[str, Any]]:
    if isinstance(policies_resp, dict):
        policies = policies_resp.get("branch_policies", [])
    elif isinstance(policies_resp, list):
        policies = policies_resp
    else:
        raise AuthorizationError("[ENV-2] invalid branch policies response format", check_id="ENV-2")

    if len(policies) != 1:
        raise AuthorizationError(f"[ENV-2] expected exactly 1 branch policy, got {len(policies)}", check_id="ENV-2")
    pol = policies[0]
    if pol.get("type") != "branch" or pol.get("name") != PINNED_DEPLOY_BRANCH:
        raise AuthorizationError(f"[ENV-2] branch policy mismatch: expected branch '{PINNED_DEPLOY_BRANCH}', got {pol}", check_id="ENV-2")

    return [{"type": "branch", "name": PINNED_DEPLOY_BRANCH}]


def check_brn_1(branch: Dict[str, Any], expected_head_sha: str) -> Dict[str, Any]:
    head = branch.get("commit", {}).get("sha")
    if head != expected_head_sha:
        raise AuthorizationError(f"[BRN-1] branch head mismatch: expected {expected_head_sha}, got {head}", check_id="BRN-1")
    return {"name": PINNED_DEPLOY_BRANCH, "head_sha": head}

def check_brn_2(rules: List[Dict[str, Any]], require_active: bool = True) -> List[Dict[str, Any]]:
    extracted = []
    types_found = set()

    for r in rules:
        rtype = r.get("type")
        stype = r.get("ruleset_source_type")
        source = r.get("ruleset_source")
        if stype == "Repository" and source == PINNED_REPOSITORY:
            types_found.add(rtype)
            if rtype == "update":
                params = r.get("parameters") or {}
                if params.get("update_allows_fetch_and_merge") is not False:
                    if require_active:
                        raise AuthorizationError("[BRN-2] branch rule 'update' must have update_allows_fetch_and_merge: false", check_id="BRN-2")
            extracted.append({
                "type": rtype,
                "ruleset_id": str(r.get("ruleset_id", "")),
                "ruleset_source_type": stype,
                "ruleset_source": source,
            })

    if require_active:
        for req in ("deletion", "non_fast_forward", "update"):
            if req not in types_found:
                raise AuthorizationError(f"[BRN-2] missing required branch rule: {req}", check_id="BRN-2")

    extracted.sort(key=lambda x: (x["type"], x["ruleset_id"]))
    return extracted


def check_src_1(pull: Dict[str, Any]) -> Dict[str, Any]:
    state = pull.get("state")
    if state != PINNED_P_PR_STATE:
        raise AuthorizationError(f"[SRC-1] PR #147 state must be '{PINNED_P_PR_STATE}', got {state}", check_id="SRC-1")
    head_sha = pull.get("head", {}).get("sha")
    if head_sha != PINNED_P_SHA:
        raise AuthorizationError(f"[SRC-1] PR #147 head.sha mismatch: expected {PINNED_P_SHA}, got {head_sha}", check_id="SRC-1")
    head_repo_id = str(pull.get("head", {}).get("repo", {}).get("id"))
    if head_repo_id != PINNED_P_HEAD_REPO_ID:
        raise AuthorizationError(f"[SRC-1] PR #147 head.repo.id mismatch: expected {PINNED_P_HEAD_REPO_ID}, got {head_repo_id}", check_id="SRC-1")
    head_ref = pull.get("head", {}).get("ref")
    if head_ref != PINNED_P_HEAD_REF:
        raise AuthorizationError(f"[SRC-1] PR #147 head.ref mismatch: expected {PINNED_P_HEAD_REF}, got {head_ref}", check_id="SRC-1")

    return {
        "sha": PINNED_P_SHA,
        "pr_repository": PINNED_P_PR_REPOSITORY,
        "pr_number": PINNED_P_PR_NUMBER,
        "pr_state": PINNED_P_PR_STATE,
        "head_ref": PINNED_P_HEAD_REF,
        "head_repo_id": PINNED_P_HEAD_REPO_ID,
    }


def check_src_2(compare: Dict[str, Any]) -> Dict[str, Any]:
    status = compare.get("status")
    ahead_by = compare.get("ahead_by")
    behind_by = compare.get("behind_by")
    merge_base = compare.get("merge_base_commit", {}).get("sha")

    if status != "ahead":
        raise AuthorizationError(f"[SRC-2] compare P...W status must be 'ahead', got {status}", check_id="SRC-2")
    if ahead_by != PINNED_W_AHEAD_BY:
        raise AuthorizationError(f"[SRC-2] compare P...W ahead_by mismatch: expected {PINNED_W_AHEAD_BY}, got {ahead_by}", check_id="SRC-2")
    if behind_by != PINNED_W_BEHIND_BY:
        raise AuthorizationError(f"[SRC-2] compare P...W behind_by mismatch: expected {PINNED_W_BEHIND_BY}, got {behind_by}", check_id="SRC-2")
    if merge_base != PINNED_W_MERGE_BASE:
        raise AuthorizationError(f"[SRC-2] compare P...W merge_base mismatch: expected {PINNED_W_MERGE_BASE}, got {merge_base}", check_id="SRC-2")

    files = compare.get("files", [])
    added_paths = []
    for f in files:
        fname = f.get("filename", "")
        fstatus = f.get("status")
        if fstatus != "added" or not fname.startswith("proof/"):
            raise AuthorizationError(f"[SRC-2] compare P...W file {fname} status must be 'added' under proof/, got {fstatus}", check_id="SRC-2")
        added_paths.append(fname)

    if len(added_paths) != PINNED_W_ADDED_COUNT:
        raise AuthorizationError(f"[SRC-2] compare P...W added count mismatch: expected {PINNED_W_ADDED_COUNT}, got {len(added_paths)}", check_id="SRC-2")

    sorted_paths = sorted(added_paths)
    joined_paths = "\n".join(sorted_paths).encode("utf-8")
    actual_digest = digest(joined_paths)
    if actual_digest != PINNED_W_ADDED_PATHS_SHA256:
        raise AuthorizationError(f"[SRC-2] compare P...W added paths digest mismatch: expected {PINNED_W_ADDED_PATHS_SHA256}, got {actual_digest}", check_id="SRC-2")

    return {
        "sha": PINNED_W_SHA,
        "merge_base": PINNED_W_MERGE_BASE,
        "ahead_by": PINNED_W_AHEAD_BY,
        "behind_by": PINNED_W_BEHIND_BY,
        "added_count": PINNED_W_ADDED_COUNT,
        "added_paths_sha256": PINNED_W_ADDED_PATHS_SHA256,
    }


def check_src_3(compare: Dict[str, Any]) -> Dict[str, Any]:
    merge_base = compare.get("merge_base_commit", {}).get("sha")
    if merge_base != PINNED_H_MERGE_BASE:
        raise AuthorizationError(f"[SRC-3] compare W...H merge_base mismatch: expected {PINNED_H_MERGE_BASE}, got {merge_base}", check_id="SRC-3")

    files = compare.get("files", [])
    if len(files) != 2:
        raise AuthorizationError(f"[SRC-3] compare W...H must have exactly 2 files, got {len(files)}", check_id="SRC-3")
    added = {f.get("filename"): f.get("status") for f in files}
    expected_set = set(PINNED_H_ADDED_PATHS)
    if set(added.keys()) != expected_set:
        raise AuthorizationError(f"[SRC-3] compare W...H added files mismatch: expected {expected_set}, got {set(added.keys())}", check_id="SRC-3")
    for fname, st in added.items():
        if st != "added":
            raise AuthorizationError(f"[SRC-3] compare W...H file {fname} status must be 'added', got {st}", check_id="SRC-3")

    return {
        "sha": PINNED_H_SHA,
        "merge_base": PINNED_H_MERGE_BASE,
        "added_paths": sorted(list(PINNED_H_ADDED_PATHS)),
    }


def check_bun_1(repo_root: Optional[str] = None) -> Dict[str, str]:
    root = Path(repo_root or os.getcwd())
    dist_dir = root / ".github" / "actions" / "strict-supervisor" / "dist"
    if not dist_dir.is_dir():
        raise AuthorizationError(f"[BUN-1] supervisor dist directory not found: {dist_dir}", check_id="BUN-1")

    bundle: Dict[str, str] = {}
    for path in sorted(dist_dir.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(dist_dir))
            with open(path, "rb") as f:
                content = f.read()
            bundle[rel] = digest(content)

    if not bundle:
        raise AuthorizationError("[BUN-1] supervisor dist directory contains no files", check_id="BUN-1")

    return bundle


def check_har_1_2(run: Dict[str, Any], job: Dict[str, Any]) -> None:
    if str(run.get("id")) != HARNESS_RUN_ID:
        raise AuthorizationError(f"[HAR-1] harness run id mismatch: expected {HARNESS_RUN_ID}, got {run.get('id')}", check_id="HAR-1")
    if str(run.get("run_attempt")) != HARNESS_RUN_ATTEMPT:
        raise AuthorizationError(f"[HAR-1] harness run_attempt mismatch: expected {HARNESS_RUN_ATTEMPT}, got {run.get('run_attempt')}", check_id="HAR-1")
    if str(run.get("workflow_id")) != HARNESS_WORKFLOW_ID:
        raise AuthorizationError(f"[HAR-1] harness workflow_id mismatch: expected {HARNESS_WORKFLOW_ID}, got {run.get('workflow_id')}", check_id="HAR-1")
    if run.get("path") != HARNESS_WORKFLOW_PATH:
        raise AuthorizationError(f"[HAR-1] harness workflow path mismatch: expected {HARNESS_WORKFLOW_PATH}, got {run.get('path')}", check_id="HAR-1")
    if run.get("event") != HARNESS_EVENT:
        raise AuthorizationError(f"[HAR-1] harness event mismatch: expected {HARNESS_EVENT}, got {run.get('event')}", check_id="HAR-1")
    if run.get("head_branch") != HARNESS_HEAD_BRANCH:
        raise AuthorizationError(f"[HAR-1] harness head_branch mismatch: expected {HARNESS_HEAD_BRANCH}, got {run.get('head_branch')}", check_id="HAR-1")
    if run.get("head_sha") != PINNED_H_SHA:
        raise AuthorizationError(f"[HAR-1] harness head_sha mismatch: expected {PINNED_H_SHA}, got {run.get('head_sha')}", check_id="HAR-1")
    if run.get("conclusion") != HARNESS_CONCLUSION:
        raise AuthorizationError(f"[HAR-1] harness conclusion mismatch: expected {HARNESS_CONCLUSION}, got {run.get('conclusion')}", check_id="HAR-1")

    if str(job.get("id")) != HARNESS_JOB_ID:
        raise AuthorizationError(f"[HAR-2] harness job id mismatch: expected {HARNESS_JOB_ID}, got {job.get('id')}", check_id="HAR-2")
    if job.get("name") != HARNESS_JOB_NAME:
        raise AuthorizationError(f"[HAR-2] harness job name mismatch: expected {HARNESS_JOB_NAME}, got {job.get('name')}", check_id="HAR-2")
    if str(job.get("run_id")) != HARNESS_RUN_ID:
        raise AuthorizationError(f"[HAR-2] harness job run_id mismatch: expected {HARNESS_RUN_ID}, got {job.get('run_id')}", check_id="HAR-2")
    if str(job.get("run_attempt")) != HARNESS_RUN_ATTEMPT:
        raise AuthorizationError(f"[HAR-2] harness job run_attempt mismatch: expected {HARNESS_RUN_ATTEMPT}, got {job.get('run_attempt')}", check_id="HAR-2")
    if job.get("head_sha") != PINNED_H_SHA:
        raise AuthorizationError(f"[HAR-2] harness job head_sha mismatch: expected {PINNED_H_SHA}, got {job.get('head_sha')}", check_id="HAR-2")
    if job.get("status") != "completed":
        raise AuthorizationError(f"[HAR-2] harness job status must be 'completed', got {job.get('status')}", check_id="HAR-2")
    if job.get("conclusion") != "success":
        raise AuthorizationError(f"[HAR-2] harness job conclusion must be 'success', got {job.get('conclusion')}", check_id="HAR-2")


def check_har_3(art: Dict[str, Any]) -> str:
    if str(art.get("id")) != HARNESS_ARTIFACT_ID:
        raise AuthorizationError(f"[HAR-3] harness artifact id mismatch: expected {HARNESS_ARTIFACT_ID}, got {art.get('id')}", check_id="HAR-3")
    if art.get("name") != HARNESS_ARTIFACT_NAME:
        raise AuthorizationError(f"[HAR-3] harness artifact name mismatch: expected {HARNESS_ARTIFACT_NAME}, got {art.get('name')}", check_id="HAR-3")
    wf_run = art.get("workflow_run", {})
    if str(wf_run.get("id")) != HARNESS_RUN_ID:
        raise AuthorizationError(f"[HAR-3] harness artifact workflow_run.id mismatch: expected {HARNESS_RUN_ID}, got {wf_run.get('id')}", check_id="HAR-3")
    if wf_run.get("head_sha") != PINNED_H_SHA:
        raise AuthorizationError(f"[HAR-3] harness artifact workflow_run.head_sha mismatch: expected {PINNED_H_SHA}, got {wf_run.get('head_sha')}", check_id="HAR-3")
    if wf_run.get("head_branch") != HARNESS_HEAD_BRANCH:
        raise AuthorizationError(f"[HAR-3] harness artifact workflow_run.head_branch mismatch: expected {HARNESS_HEAD_BRANCH}, got {wf_run.get('head_branch')}", check_id="HAR-3")
    if str(wf_run.get("repository_id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[HAR-3] harness artifact workflow_run.repository_id mismatch: expected {PINNED_REPOSITORY_ID}, got {wf_run.get('repository_id')}", check_id="HAR-3")
    if art.get("digest") != HARNESS_ARTIFACT_DIGEST:
        raise AuthorizationError(f"[HAR-3] harness artifact digest mismatch: expected {HARNESS_ARTIFACT_DIGEST}, got {art.get('digest')}", check_id="HAR-3")
    if art.get("expired") is not False:
        raise AuthorizationError("[HAR-3] harness artifact must not be expired", check_id="HAR-3")
    expires_at = art.get("expires_at")
    if not expires_at:
        raise AuthorizationError("[HAR-3] missing expires_at on harness artifact", check_id="HAR-3")
    return expires_at


def check_har_4(contents: Dict[str, Any], blob: Dict[str, Any]) -> bytes:
    if contents.get("sha") != HARNESS_PRESERVED_BLOB:
        raise AuthorizationError(f"[HAR-4] preserved content blob mismatch: expected {HARNESS_PRESERVED_BLOB}, got {contents.get('sha')}", check_id="HAR-4")

    raw_b64 = blob.get("content", "").replace("\n", "")
    zip_bytes = base64.b64decode(raw_b64)
    computed_blob_id = git_blob_id(zip_bytes)
    if computed_blob_id != HARNESS_PRESERVED_BLOB:
        raise AuthorizationError(f"[HAR-4] computed blob SHA mismatch: expected {HARNESS_PRESERVED_BLOB}, got {computed_blob_id}", check_id="HAR-4")

    actual_digest = f"sha256:{digest(zip_bytes)}"
    if actual_digest != HARNESS_ARTIFACT_DIGEST:
        raise AuthorizationError(f"[HAR-4] preserved zip digest mismatch: expected {HARNESS_ARTIFACT_DIGEST}, got {actual_digest}", check_id="HAR-4")

    return zip_bytes


def check_har_5(downloaded_zip: Optional[bytes], preserved_zip: bytes, is_expired: bool) -> None:
    if is_expired:
        return
    if downloaded_zip is None:
        raise AuthorizationError("[HAR-5] harness artifact download is required when artifact is not expired", check_id="HAR-5")
    if downloaded_zip != preserved_zip:
        raise AuthorizationError("[HAR-5] downloaded harness zip does not match preserved copy", check_id="HAR-5")


def check_har_6(zip_bytes: bytes) -> Dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            if HARNESS_SUMMARY_MEMBER not in zf.namelist():
                raise AuthorizationError(f"[HAR-6] harness zip missing {HARNESS_SUMMARY_MEMBER}", check_id="HAR-6")
            raw = zf.read(HARNESS_SUMMARY_MEMBER)
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[HAR-6] corrupted harness zip: {exc}", check_id="HAR-6") from exc

    actual_member_digest = digest(raw)
    if actual_member_digest != HARNESS_SUMMARY_MEMBER_SHA256:
        raise AuthorizationError(f"[HAR-6] harness summary member digest mismatch: expected {HARNESS_SUMMARY_MEMBER_SHA256}, got {actual_member_digest}", check_id="HAR-6")

    try:
        summary = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AuthorizationError(f"[HAR-6] invalid JSON in harness summary: {exc}", check_id="HAR-6") from exc

    if not isinstance(summary, dict):
        raise AuthorizationError("[HAR-6] harness summary must be a JSON object", check_id="HAR-6")
    if summary.get("status") != "PASS":
        raise AuthorizationError(f"[HAR-6] harness summary status must be 'PASS', got {summary.get('status')}", check_id="HAR-6")
    if summary.get("w_sha") != PINNED_W_SHA:
        raise AuthorizationError(f"[HAR-6] harness summary w_sha mismatch: expected {PINNED_W_SHA}, got {summary.get('w_sha')}", check_id="HAR-6")
    if summary.get("p1_sha") != PINNED_P_SHA:
        raise AuthorizationError(f"[HAR-6] harness summary p1_sha mismatch: expected {PINNED_P_SHA}, got {summary.get('p1_sha')}", check_id="HAR-6")

    return {
        "status": "PASS",
        "w_sha": PINNED_W_SHA,
        "p1_sha": PINNED_P_SHA,
        "digest": actual_member_digest,
    }


def check_val_1(runs: List[Dict[str, Any]], expected_head_sha: str) -> Dict[str, Any]:
    matching = []
    for r in runs:
        if (
            str(r.get("workflow_id")) == str(PINNED_WORKFLOW_ID)
            and r.get("head_branch") == PINNED_DEPLOY_BRANCH
            and r.get("head_sha") == expected_head_sha
            and r.get("event") == "push"
        ):
            matching.append(r)

    if len(matching) != 1:
        raise AuthorizationError(f"[VAL-1] expected exactly 1 push run of workflow {PINNED_WORKFLOW_ID} at {expected_head_sha}, got {len(matching)}", check_id="VAL-1")

    v = matching[0]
    if str(v.get("run_attempt")) != "1":
        raise AuthorizationError(f"[VAL-1] validation run attempt must be 1, got {v.get('run_attempt')}", check_id="VAL-1")
    if v.get("status") != "completed":
        raise AuthorizationError(f"[VAL-1] validation run status must be 'completed', got {v.get('status')}", check_id="VAL-1")
    if v.get("conclusion") != "success":
        raise AuthorizationError(f"[VAL-1] validation run conclusion must be 'success', got {v.get('conclusion')}", check_id="VAL-1")

    return v


def check_val_1b(client: GitHubAPIClient, all_runs_at_head: List[Dict[str, Any]]) -> None:
    target_job_name = "Controller synthetic and validation proofs (macOS 15)"
    for run in all_runs_at_head:
        run_id = str(run.get("id"))
        attempt = str(run.get("run_attempt", "1"))
        jobs = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs")
        ctrl_job = next((j for j in jobs if j.get("name") == target_job_name), None)
        if ctrl_job is not None:
            conclusion = ctrl_job.get("conclusion")
            if conclusion != "skipped":
                if run.get("status") != "completed" or run.get("conclusion") != "success":
                    raise AuthorizationError(
                        f"[VAL-1b] run {run_id} executed controller proofs (conclusion={conclusion}) but run status is {run.get('status')}/{run.get('conclusion')}",
                        check_id="VAL-1b",
                    )


def check_val_2(jobs: List[Dict[str, Any]]) -> None:
    exact_names = {
        "Generate supervisor bundle",
        "Controller synthetic and validation proofs (macOS 15)",
        "Verify complete hosted evidence inventory",
        JOB_NAME_REHEARSAL,
    }
    seen_exact = set()
    ownership_count = 0

    for job in jobs:
        name = job.get("name", "")
        jid = str(job.get("id"))
        if name in exact_names:
            if name in seen_exact:
                raise AuthorizationError(f"[VAL-2] duplicate validation job '{name}' (id {jid})", check_id="VAL-2")
            seen_exact.add(name)
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise AuthorizationError(f"[VAL-2] validation job '{name}' must be completed/success, got {job.get('status')}/{job.get('conclusion')}", check_id="VAL-2")
        elif re.match(r"^Ownership recovery \([^\)]+\)$", name):
            ownership_count += 1
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise AuthorizationError(f"[VAL-2] ownership recovery job '{name}' must be completed/success, got {job.get('status')}/{job.get('conclusion')}", check_id="VAL-2")
        elif name in (JOB_NAME_PREPARE, JOB_NAME_STRICT):
            if job.get("conclusion") != "skipped":
                raise AuthorizationError(f"[VAL-2] job '{name}' on validation run must be skipped, got {job.get('conclusion')}", check_id="VAL-2")
        else:
            raise AuthorizationError(f"[VAL-2] unexpected extra job on validation run: '{name}' (id {jid})", check_id="VAL-2")

    if seen_exact != exact_names:
        missing = exact_names - seen_exact
        raise AuthorizationError(f"[VAL-2] validation run missing required jobs: {missing}", check_id="VAL-2")
    if ownership_count != 3:
        raise AuthorizationError(f"[VAL-2] validation run must have exactly 3 Ownership recovery jobs, got {ownership_count}", check_id="VAL-2")


def check_val_3(artifacts: List[Dict[str, Any]], expected_head_sha: str) -> Dict[str, Dict[str, str]]:
    if len(artifacts) != 62:
        raise AuthorizationError(f"[VAL-3] validation run must have exactly 62 artifacts, got {len(artifacts)}", check_id="VAL-3")

    bundle_name = f"supervisor-bundle-{expected_head_sha}"
    expected_names = {
        "remote-strict-validation-evidence",
        bundle_name,
        ARTIFACT_NAME_RAIL_SUMMARY,
        ARTIFACT_NAME_REHEARSAL_REPORT,
    }

    found: Dict[str, Dict[str, str]] = {}
    for art in artifacts:
        name = art.get("name", "")
        if name in expected_names:
            if name in found:
                raise AuthorizationError(f"[VAL-3] duplicate artifact '{name}' found on validation run", check_id="VAL-3")
            if art.get("expired") is True:
                raise AuthorizationError(f"[VAL-3] artifact '{name}' is expired", check_id="VAL-3")
            dig = art.get("digest")
            if not isinstance(dig, str) or not dig.startswith("sha256:"):
                raise AuthorizationError(f"[VAL-3] artifact '{name}' missing sha256 digest", check_id="VAL-3")
            found[name] = {"id": str(art["id"]), "digest": dig}

    if set(found.keys()) != expected_names:
        missing = expected_names - set(found.keys())
        raise AuthorizationError(f"[VAL-3] validation run missing expected artifacts: {missing}", check_id="VAL-3")

    return found


def check_val_4(
    summary_member_raw: bytes,
    rehearsal_member_raw: bytes,
    bundle_map: Dict[str, str],
    val_run_id: str,
    expected_head_sha: str,
) -> Tuple[str, str]:
    try:
        summary = parse(summary_member_raw)
    except Exception as exc:
        raise AuthorizationError(f"[VAL-4] rail summary member is not canonical JSON: {exc}", check_id="VAL-4") from exc
    if summary.get("schema") != SCHEMA_RAIL_SUMMARY:
        raise AuthorizationError(f"[VAL-4] summary member schema mismatch: expected {SCHEMA_RAIL_SUMMARY}, got {summary.get('schema')}", check_id="VAL-4")
    if summary.get("status") != "PASS":
        raise AuthorizationError(f"[VAL-4] summary member status must be 'PASS', got {summary.get('status')}", check_id="VAL-4")
    if summary.get("c_sha") != expected_head_sha:
        raise AuthorizationError(f"[VAL-4] summary member c_sha mismatch: expected {expected_head_sha}, got {summary.get('c_sha')}", check_id="VAL-4")
    if str(summary.get("run_id")) != str(val_run_id):
        raise AuthorizationError(f"[VAL-4] summary member run_id mismatch: expected {val_run_id}, got {summary.get('run_id')}", check_id="VAL-4")
    if summary.get("dist") != bundle_map:
        raise AuthorizationError("[VAL-4] summary member dist map does not match BUN-1 supervisor dist", check_id="VAL-4")
    if summary.get("actions") != PINNED_ACTIONS:
        raise AuthorizationError("[VAL-4] summary member actions map does not match PINNED_ACTIONS §3.2", check_id="VAL-4")

    try:
        rehearsal = parse(rehearsal_member_raw)
    except Exception as exc:
        raise AuthorizationError(f"[VAL-4] rehearsal report member is not canonical JSON: {exc}", check_id="VAL-4") from exc
    if rehearsal.get("schema") != SCHEMA_REHEARSAL:
        raise AuthorizationError(f"[VAL-4] rehearsal member schema mismatch: expected {SCHEMA_REHEARSAL}, got {rehearsal.get('schema')}", check_id="VAL-4")
    if rehearsal.get("status") != "REHEARSAL_PASS":
        raise AuthorizationError(f"[VAL-4] rehearsal member status must be 'REHEARSAL_PASS', got {rehearsal.get('status')}", check_id="VAL-4")
    if rehearsal.get("c_sha") != expected_head_sha:
        raise AuthorizationError(f"[VAL-4] rehearsal member c_sha mismatch: expected {expected_head_sha}, got {rehearsal.get('c_sha')}", check_id="VAL-4")
    if str(rehearsal.get("run_id")) != str(val_run_id):
        raise AuthorizationError(f"[VAL-4] rehearsal member run_id mismatch: expected {val_run_id}, got {rehearsal.get('run_id')}", check_id="VAL-4")

    return digest(summary_member_raw), digest(rehearsal_member_raw)


def check_aud_1(commit: Dict[str, Any], expected_c_sha: str) -> None:
    parents = commit.get("parents", [])
    if len(parents) != 1 or str(parents[0].get("sha")) != HARNESS_PRESERVED_COMMIT:
        raise AuthorizationError(f"[AUD-1] evidence commit must have exactly one parent equal to preserved harness commit {HARNESS_PRESERVED_COMMIT}", check_id="AUD-1")


def check_aud_2(files_dict: Dict[str, Tuple[bytes, str]]) -> Dict[str, Dict[str, str]]:
    expected_files = {"audit.json", "audit.md", "census-review.md"}
    if set(files_dict.keys()) != expected_files:
        raise AuthorizationError(f"[AUD-2] evidence directory files mismatch: expected {expected_files}, got {set(files_dict.keys())}", check_id="AUD-2")

    result: Dict[str, Dict[str, str]] = {}
    for name, (content, api_sha) in files_dict.items():
        computed_blob = git_blob_id(content)
        if computed_blob != api_sha:
            raise AuthorizationError(f"[AUD-2] blob id mismatch for {name}: computed {computed_blob} != API sha {api_sha}", check_id="AUD-2")
        result[name] = {
            "blob": computed_blob,
            "sha256": digest(content),
        }
    return result


def check_aud_3(
    audit_json: Dict[str, Any],
    expected_head_sha: str,
    val_run_id: str,
    val_artifacts: Dict[str, Dict[str, str]],
    audit_md_sha256: str,
    census_review_sha256: str,
) -> None:
    if audit_json.get("schema") != SCHEMA_AUDIT:
        raise AuthorizationError(f"[AUD-3] audit.json schema mismatch: expected {SCHEMA_AUDIT}, got {audit_json.get('schema')}", check_id="AUD-3")
    if audit_json.get("verdict") != "GO":
        raise AuthorizationError(f"[AUD-3] audit.json verdict must be 'GO', got {audit_json.get('verdict')}", check_id="AUD-3")
    if str(audit_json.get("repository_id")) != PINNED_REPOSITORY_ID:
        raise AuthorizationError(f"[AUD-3] audit.json repository_id mismatch: expected {PINNED_REPOSITORY_ID}, got {audit_json.get('repository_id')}", check_id="AUD-3")
    if audit_json.get("c_sha") != expected_head_sha:
        raise AuthorizationError(f"[AUD-3] audit.json c_sha mismatch: expected {expected_head_sha}, got {audit_json.get('c_sha')}", check_id="AUD-3")
    if audit_json.get("p_sha") != PINNED_P_SHA:
        raise AuthorizationError(f"[AUD-3] audit.json p_sha mismatch: expected {PINNED_P_SHA}, got {audit_json.get('p_sha')}", check_id="AUD-3")
    if audit_json.get("w_sha") != PINNED_W_SHA:
        raise AuthorizationError(f"[AUD-3] audit.json w_sha mismatch: expected {PINNED_W_SHA}, got {audit_json.get('w_sha')}", check_id="AUD-3")
    if audit_json.get("h_sha") != PINNED_H_SHA:
        raise AuthorizationError(f"[AUD-3] audit.json h_sha mismatch: expected {PINNED_H_SHA}, got {audit_json.get('h_sha')}", check_id="AUD-3")

    val_section = audit_json.get("validation", {})
    if str(val_section.get("run_id")) != str(val_run_id):
        raise AuthorizationError(f"[AUD-3] audit.json validation.run_id mismatch: expected {val_run_id}, got {val_section.get('run_id')}", check_id="AUD-3")

    art_digests = val_section.get("artifacts", {})
    for art_name, art_info in val_artifacts.items():
        if art_digests.get(art_name) != art_info["digest"]:
            raise AuthorizationError(f"[AUD-3] audit.json validation artifact digest mismatch for {art_name}: expected {art_info['digest']}, got {art_digests.get(art_name)}", check_id="AUD-3")

    harness_section = audit_json.get("harness", {})
    if str(harness_section.get("run_id")) != HARNESS_RUN_ID:
        raise AuthorizationError(f"[AUD-3] audit.json harness.run_id mismatch: expected {HARNESS_RUN_ID}, got {harness_section.get('run_id')}", check_id="AUD-3")
    if str(harness_section.get("artifact_id")) != HARNESS_ARTIFACT_ID:
        raise AuthorizationError(f"[AUD-3] audit.json harness.artifact_id mismatch: expected {HARNESS_ARTIFACT_ID}, got {harness_section.get('artifact_id')}", check_id="AUD-3")
    if harness_section.get("digest") != HARNESS_ARTIFACT_DIGEST:
        raise AuthorizationError(f"[AUD-3] audit.json harness.digest mismatch: expected {HARNESS_ARTIFACT_DIGEST}, got {harness_section.get('digest')}", check_id="AUD-3")

    if audit_json.get("report_sha256") != audit_md_sha256:
        raise AuthorizationError(f"[AUD-3] audit.json report_sha256 mismatch: expected {audit_md_sha256}, got {audit_json.get('report_sha256')}", check_id="AUD-3")
    if audit_json.get("census_review_sha256") != census_review_sha256:
        raise AuthorizationError(f"[AUD-3] audit.json census_review_sha256 mismatch: expected {census_review_sha256}, got {audit_json.get('census_review_sha256')}", check_id="AUD-3")

    if audit_json.get("open_blocking_findings") != []:
        raise AuthorizationError(f"[AUD-3] audit.json open_blocking_findings must be empty list, got {audit_json.get('open_blocking_findings')}", check_id="AUD-3")

    ruling = audit_json.get("s6_signing_ruling")
    if not isinstance(ruling, str) or not ruling.strip():
        raise AuthorizationError("[AUD-3] audit.json s6_signing_ruling must be a non-empty string", check_id="AUD-3")

    self_decl = audit_json.get("self_declared", {})
    if self_decl.get("did_not_implement") is not True:
        raise AuthorizationError("[AUD-3] audit.json self_declared.did_not_implement must be true", check_id="AUD-3")


def check_man_1(
    artifacts: List[Dict[str, Any]],
    prepare_art_id: str,
    strict_run_id: str,
    expected_head_sha: str,
    prepare_started_at: str,
    prepare_completed_at: str,
) -> Dict[str, Any]:
    if len(artifacts) != 1:
        raise AuthorizationError(f"[MAN-1] strict run must have exactly 1 artifact before native steps, got {len(artifacts)}", check_id="MAN-1")

    art = artifacts[0]
    if str(art.get("id")) != str(prepare_art_id):
        raise AuthorizationError(f"[MAN-1] artifact id mismatch: expected {prepare_art_id}, got {art.get('id')}", check_id="MAN-1")
    if art.get("name") != ARTIFACT_NAME_MANIFEST:
        raise AuthorizationError(f"[MAN-1] artifact name must be '{ARTIFACT_NAME_MANIFEST}', got {art.get('name')}", check_id="MAN-1")
    if str(art.get("workflow_run", {}).get("id")) != str(strict_run_id):
        raise AuthorizationError(f"[MAN-1] artifact workflow_run.id mismatch: expected {strict_run_id}, got {art.get('workflow_run', {}).get('id')}", check_id="MAN-1")
    if art.get("workflow_run", {}).get("head_sha") != expected_head_sha:
        raise AuthorizationError(f"[MAN-1] artifact workflow_run.head_sha mismatch: expected {expected_head_sha}, got {art.get('workflow_run', {}).get('head_sha')}", check_id="MAN-1")
    if art.get("expired") is True:
        raise AuthorizationError("[MAN-1] manifest artifact is expired", check_id="MAN-1")

    dig = art.get("digest")
    if not isinstance(dig, str) or not dig.startswith("sha256:"):
        raise AuthorizationError("[MAN-1] manifest artifact missing sha256 digest", check_id="MAN-1")

    created = art.get("created_at", "")
    if not (prepare_started_at and prepare_completed_at and created):
        raise AuthorizationError("[MAN-1] missing required timestamps for prepare job window check", check_id="MAN-1")
    if created < prepare_started_at or created > prepare_completed_at:
        raise AuthorizationError(f"[MAN-1] manifest artifact created_at ({created}) outside prepare job window ({prepare_started_at} .. {prepare_completed_at})", check_id="MAN-1")

    return art


def check_man_2(zip_bytes: bytes, expected_digest: str, expected_manifest_sha256: str) -> bytes:
    actual_zip_digest = f"sha256:{digest(zip_bytes)}"
    if actual_zip_digest != expected_digest:
        raise AuthorizationError(f"[MAN-2] manifest zip digest mismatch: expected {expected_digest}, got {actual_zip_digest}", check_id="MAN-2")

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            if len(names) != 1 or names[0] != "manifest.json":
                raise AuthorizationError(f"[MAN-2] manifest zip must contain exactly one member 'manifest.json', got {names}", check_id="MAN-2")
            member_bytes = zf.read("manifest.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[MAN-2] corrupted manifest zip archive: {exc}", check_id="MAN-2") from exc

    if len(member_bytes) > 65536:
        raise AuthorizationError(f"[MAN-2] manifest.json exceeds 64 KiB ceiling: {len(member_bytes)} bytes", check_id="MAN-2")

    member_sha = digest(member_bytes)
    if member_sha != expected_manifest_sha256:
        raise AuthorizationError(f"[MAN-2] manifest member sha256 mismatch: expected {expected_manifest_sha256}, got {member_sha}", check_id="MAN-2")

    return member_bytes

def check_man_3(manifest: Dict[str, Any], expected_manifest: Dict[str, Any]) -> None:
    if manifest.get("schema") != SCHEMA_MANIFEST:
        raise AuthorizationError(f"[MAN-3] manifest schema mismatch: expected {SCHEMA_MANIFEST}, got {manifest.get('schema')}", check_id="MAN-3")
    if canonical(manifest) != canonical(expected_manifest):
        diffs = [k for k in sorted(set(manifest.keys()) | set(expected_manifest.keys())) if manifest.get(k) != expected_manifest.get(k)]
        raise AuthorizationError(f"[MAN-3] live state does not match prepared manifest (differing keys: {diffs})", check_id="MAN-3")


def check_apr_1(approvals: List[Dict[str, Any]], expected_manifest_sha256: str) -> Dict[str, Any]:
    if len(approvals) != 1:
        raise AuthorizationError(f"[APR-1] expected exactly 1 approval record, got {len(approvals)}", check_id="APR-1")

    appr = approvals[0]
    if appr.get("state") != "approved":
        raise AuthorizationError(f"[APR-1] approval state must be 'approved', got {appr.get('state')}", check_id="APR-1")

    user = appr.get("user", {})
    if str(user.get("id")) != PINNED_REVIEWER_ID:
        raise AuthorizationError(f"[APR-1] approval reviewer user.id mismatch: expected {PINNED_REVIEWER_ID}, got {user.get('id')}", check_id="APR-1")
    if user.get("login") != PINNED_REVIEWER_LOGIN:
        raise AuthorizationError(f"[APR-1] approval reviewer user.login mismatch: expected {PINNED_REVIEWER_LOGIN}, got {user.get('login')}", check_id="APR-1")
    if user.get("type") != "User":
        raise AuthorizationError(f"[APR-1] approval reviewer user.type must be 'User', got {user.get('type')}", check_id="APR-1")

    envs = appr.get("environments", [])
    if len(envs) != 1:
        raise AuthorizationError(f"[APR-1] approval must specify exactly 1 environment, got {len(envs)}", check_id="APR-1")
    env0 = envs[0]
    if str(env0.get("id")) != PINNED_ENVIRONMENT_ID or env0.get("name") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"[APR-1] approval environment mismatch: expected {PINNED_ENVIRONMENT_ID}/{PINNED_ENVIRONMENT_NAME}, got {env0}", check_id="APR-1")

    expected_comment = f"{APPROVAL_COMMENT_PREFIX}{expected_manifest_sha256}"
    actual_comment = appr.get("comment", "")
    if actual_comment != expected_comment:
        raise AuthorizationError(f"[APR-1] approval comment mismatch: expected '{expected_comment}', got '{actual_comment}'", check_id="APR-1")

    return appr


# ---------------------------------------------------------------------------
# Manifest builder (§3.5)
# ---------------------------------------------------------------------------

def build_manifest_v2(
    *,
    c_sha: str,
    strict_run: Dict[str, Any],
    prepare_job: Dict[str, Any],
    inputs: Dict[str, Any],
    environment: Dict[str, Any],
    branch_policies: List[Dict[str, Any]],
    deploy_branch: Dict[str, Any],
    branch_rules: List[Dict[str, Any]],
    bundle_map: Dict[str, str],
    validation_run: Dict[str, Any],
    validation_artifacts: Dict[str, Dict[str, str]],
    summary_member_sha256: str,
    rehearsal_member_sha256: str,
    evidence_commit: str,
    audit_files: Dict[str, Dict[str, str]],
    audit_json: Dict[str, Any],
    harness_expires_at: str,
) -> Dict[str, Any]:
    """Assemble manifest v2 matching §3.5 schema and keys."""
    manifest = {
        "schema": SCHEMA_MANIFEST,
        "approval": {
            "comment_format": f"{APPROVAL_COMMENT_PREFIX}<sha256 of these manifest bytes>",
            "environment_id": str(PINNED_ENVIRONMENT_ID),
            "environment_name": PINNED_ENVIRONMENT_NAME,
            "reviewer_user_id": str(PINNED_REVIEWER_ID),
            "reviewer_login": PINNED_REVIEWER_LOGIN,
            "attestation_scope": ATTESTATION_SCOPE,
        },
        "repository": {
            "id": str(PINNED_REPOSITORY_ID),
            "full_name": PINNED_REPOSITORY,
            "visibility": "public",
        },
        "strict_run": {
            "id": str(strict_run["id"]),
            "attempt": "1",
            "workflow_id": str(PINNED_WORKFLOW_ID),
            "workflow_path": PINNED_WORKFLOW_PATH,
            "workflow_ref": WORKFLOW_REF,
            "event": "workflow_dispatch",
            "head_branch": PINNED_DEPLOY_BRANCH,
            "head_sha": c_sha,
            "html_url": strict_run.get("html_url", ""),
            "actor_id": str(strict_run.get("actor_id") or strict_run.get("actor", {}).get("id", "")),
            "triggering_actor_id": str(strict_run.get("triggering_actor_id") or strict_run.get("triggering_actor", {}).get("id", "")),
            "created_at": strict_run.get("created_at", ""),
        },
        "prepare_job": {
            "id": str(prepare_job["id"]),
            "name": JOB_NAME_PREPARE,
            "started_at": prepare_job.get("started_at", ""),
        },
        "inputs": {
            "mode": "strict-chain",
            "evidence_commit": evidence_commit,
        },
        "sources": {
            "c_sha": c_sha,
            "p": {
                "sha": PINNED_P_SHA,
                "pr_repository": PINNED_P_PR_REPOSITORY,
                "pr_number": PINNED_P_PR_NUMBER,
                "pr_state": PINNED_P_PR_STATE,
                "head_ref": PINNED_P_HEAD_REF,
                "head_repo_id": PINNED_P_HEAD_REPO_ID,
            },
            "w": {
                "sha": PINNED_W_SHA,
                "merge_base": PINNED_W_MERGE_BASE,
                "ahead_by": PINNED_W_AHEAD_BY,
                "behind_by": PINNED_W_BEHIND_BY,
                "added_count": PINNED_W_ADDED_COUNT,
                "added_paths_sha256": PINNED_W_ADDED_PATHS_SHA256,
            },
            "h": {
                "sha": PINNED_H_SHA,
                "merge_base": PINNED_H_MERGE_BASE,
                "added_paths": sorted(list(PINNED_H_ADDED_PATHS)),
            },
        },
        "environment": {
            "id": str(PINNED_ENVIRONMENT_ID),
            "name": PINNED_ENVIRONMENT_NAME,
            "can_admins_bypass": False,
            "required_reviewers": [
                {
                    "type": "User",
                    "id": str(PINNED_REVIEWER_ID),
                }
            ],
            "prevent_self_review": False,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "branch_policies": branch_policies,
        },
        "deploy_branch": {
            "name": PINNED_DEPLOY_BRANCH,
            "head_sha": c_sha,
            "rules": branch_rules,
        },
        "actions": PINNED_ACTIONS,
        "bundle": bundle_map,
        "evidence": {
            "validation": {
                "run_id": str(validation_run["id"]),
                "run_attempt": "1",
                "workflow_id": str(PINNED_WORKFLOW_ID),
                "event": "push",
                "head_branch": PINNED_DEPLOY_BRANCH,
                "head_sha": c_sha,
                "conclusion": "success",
                "html_url": validation_run.get("html_url", ""),
                "artifacts": validation_artifacts,
                "summary_member_sha256": summary_member_sha256,
                "rehearsal_member_sha256": rehearsal_member_sha256,
            },
            "harness": {
                "run_id": HARNESS_RUN_ID,
                "run_attempt": HARNESS_RUN_ATTEMPT,
                "workflow_id": HARNESS_WORKFLOW_ID,
                "workflow_path": HARNESS_WORKFLOW_PATH,
                "event": HARNESS_EVENT,
                "head_branch": HARNESS_HEAD_BRANCH,
                "head_sha": PINNED_H_SHA,
                "job_id": HARNESS_JOB_ID,
                "artifact_id": HARNESS_ARTIFACT_ID,
                "artifact_name": HARNESS_ARTIFACT_NAME,
                "artifact_digest": HARNESS_ARTIFACT_DIGEST,
                "artifact_expires_at": harness_expires_at,
                "preserved_commit": HARNESS_PRESERVED_COMMIT,
                "preserved_path": HARNESS_PRESERVED_PATH,
                "preserved_blob": HARNESS_PRESERVED_BLOB,
                "summary_member": HARNESS_SUMMARY_MEMBER,
                "summary_member_sha256": HARNESS_SUMMARY_MEMBER_SHA256,
            },
            "audit": {
                "commit": evidence_commit,
                "dir": f"proof/strict-audit/{c_sha}",
                "files": audit_files,
                "verdict": "GO",
                "self_declared": audit_json.get("self_declared", {}),
            },
        },
    }
    return manifest


def set_github_output(name: str, value: str, environ: Dict[str, str]) -> None:
    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")


# ---------------------------------------------------------------------------
# Subcommand implementations (§3.8)
# ---------------------------------------------------------------------------

def _fetch_common_prepare_audit_data(
    client: GitHubAPIClient,
    c_sha: str,
    evidence_commit: str,
    val_run_id: str,
    val_artifacts_map: Dict[str, Dict[str, str]],
) -> Tuple[Dict[str, Tuple[bytes, str]], Dict[str, Dict[str, str]], Dict[str, Any]]:
    commit_data = client.get_json(f"repos/{PINNED_REPOSITORY}/commits/{evidence_commit}")
    check_aud_1(commit_data, c_sha)

    audit_dir_path = f"proof/strict-audit/{c_sha}"
    dir_contents = client.get_json(f"repos/{PINNED_REPOSITORY}/contents/{audit_dir_path}?ref={evidence_commit}")
    if not isinstance(dir_contents, list):
        raise AuthorizationError(f"[AUD-2] {audit_dir_path} must be a directory", check_id="AUD-2")

    files_in_dir = {f.get("name"): f for f in dir_contents if isinstance(f, dict)}
    if set(files_in_dir.keys()) != {"audit.json", "audit.md", "census-review.md"}:
        raise AuthorizationError(f"[AUD-2] unexpected files in audit directory: {set(files_in_dir.keys())}", check_id="AUD-2")

    audit_files_raw: Dict[str, Tuple[bytes, str]] = {}
    for fname in ("audit.json", "audit.md", "census-review.md"):
        finfo = files_in_dir[fname]
        api_blob_sha = finfo.get("sha", "")
        binfo = client.get_json(f"repos/{PINNED_REPOSITORY}/git/blobs/{api_blob_sha}")
        content_bytes = base64.b64decode(binfo["content"].replace("\n", ""))
        audit_files_raw[fname] = (content_bytes, api_blob_sha)

    audit_files_map = check_aud_2(audit_files_raw)
    try:
        audit_json = parse(audit_files_raw["audit.json"][0])
    except Exception as exc:
        raise AuthorizationError(f"[AUD-3] audit.json is not canonical JSON: {exc}", check_id="AUD-3") from exc

    check_aud_3(
        audit_json,
        c_sha,
        val_run_id,
        val_artifacts_map,
        audit_files_map["audit.md"]["sha256"],
        audit_files_map["census-review.md"]["sha256"],
    )
    return audit_files_raw, audit_files_map, audit_json


def cmd_prepare(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """prepare --out-dir: run checks RNR-1..6, REP, RUN, JOB-1, ENV, BRN, SRC, BUN, HAR, VAL, AUD. Write manifest."""
    check_rnr_1(environ)
    check_rnr_2(environ)
    check_rnr_3(environ)
    check_rnr_4(environ, JOB_KEY_PREPARE)

    event_path = environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.isfile(event_path):
        raise AuthorizationError("[RNR-5] missing GITHUB_EVENT_PATH", check_id="RNR-5")
    with open(event_path, "rb") as f:
        event_payload = json.loads(f.read().decode("utf-8"))
    inputs_info = check_rnr_5(event_payload)
    evidence_commit = inputs_info["evidence_commit"]

    check_rnr_6(environ)
    c_sha = environ["GITHUB_SHA"]
    run_id = environ["GITHUB_RUN_ID"]
    check_run_id = environ["JOB_CHECK_RUN_ID"]

    # GitHub API checks
    repo_data = client.get_json(f"repos/{PINNED_REPOSITORY}")
    check_rep_1(repo_data)

    strict_run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}")
    run_info = check_run_1(strict_run_data, c_sha, expected_event="workflow_dispatch")

    job_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{check_run_id}")
    runner_name = environ.get("RUNNER_NAME")
    job_info = check_job_1(job_data, run_id, JOB_NAME_PREPARE, c_sha, runner_name=runner_name)

    env_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}")
    check_env_1(env_data)

    policies_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies")
    branch_policies = check_env_2(policies_data)

    branch_data = client.get_json(f"repos/{PINNED_REPOSITORY}/branches/{PINNED_DEPLOY_BRANCH}")
    check_brn_1(branch_data, c_sha)

    rules_data = client.get_paginated(f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}")
    branch_rules = check_brn_2(rules_data, require_active=True)

    pull_data = client.get_json(f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}")
    check_src_1(pull_data)

    compare_pw = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}")
    check_src_2(compare_pw)

    compare_wh = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}")
    check_src_3(compare_wh)

    bundle_map = check_bun_1()

    harness_run = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}")
    harness_job = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}")
    check_har_1_2(harness_run, harness_job)

    harness_art = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}")
    har_expires_at = check_har_3(harness_art)

    contents_data = client.get_json(f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}?ref={HARNESS_PRESERVED_COMMIT}")
    blob_data = client.get_json(f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}")
    preserved_zip = check_har_4(contents_data, blob_data)

    downloaded_harness_zip = None
    if not harness_art.get("expired"):
        downloaded_harness_zip = client.download_artifact_zip(HARNESS_ARTIFACT_ID)
    check_har_5(downloaded_harness_zip, preserved_zip, harness_art.get("expired", False))

    check_har_6(preserved_zip)

    # Validation run checks
    val_runs = client.get_paginated(
        f"repos/{PINNED_REPOSITORY}/actions/workflows/{PINNED_WORKFLOW_ID}/runs",
        params={"head_sha": c_sha, "branch": PINNED_DEPLOY_BRANCH},
    )
    val_run = check_val_1(val_runs, c_sha)
    check_val_1b(client, val_runs)
    val_run_id = str(val_run["id"])

    val_jobs = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/attempts/1/jobs")
    check_val_2(val_jobs)

    val_arts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/artifacts")
    val_artifacts_map = check_val_3(val_arts, c_sha)

    # VAL-4 zip downloads and digest verification
    summary_art = val_artifacts_map[ARTIFACT_NAME_RAIL_SUMMARY]
    summary_zip = client.download_artifact_zip(summary_art["id"])
    if f"sha256:{digest(summary_zip)}" != summary_art["digest"]:
        raise AuthorizationError(f"[VAL-4] summary zip digest mismatch: expected {summary_art['digest']}, got sha256:{digest(summary_zip)}", check_id="VAL-4")
    try:
        with zipfile.ZipFile(io.BytesIO(summary_zip)) as zf:
            names = zf.namelist()
            if len(names) != 1 or names[0] != "rail-validation-summary.json":
                raise AuthorizationError(f"[VAL-4] summary zip must contain exactly 'rail-validation-summary.json', got {names}", check_id="VAL-4")
            summary_raw = zf.read("rail-validation-summary.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[VAL-4] corrupted summary zip archive: {exc}", check_id="VAL-4") from exc

    rehearsal_art = val_artifacts_map[ARTIFACT_NAME_REHEARSAL_REPORT]
    rehearsal_zip = client.download_artifact_zip(rehearsal_art["id"])
    if f"sha256:{digest(rehearsal_zip)}" != rehearsal_art["digest"]:
        raise AuthorizationError(f"[VAL-4] rehearsal zip digest mismatch: expected {rehearsal_art['digest']}, got sha256:{digest(rehearsal_zip)}", check_id="VAL-4")
    try:
        with zipfile.ZipFile(io.BytesIO(rehearsal_zip)) as zf:
            names = zf.namelist()
            if len(names) != 1 or names[0] != "rail-rehearsal-report.json":
                raise AuthorizationError(f"[VAL-4] rehearsal zip must contain exactly 'rail-rehearsal-report.json', got {names}", check_id="VAL-4")
            rehearsal_raw = zf.read("rail-rehearsal-report.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[VAL-4] corrupted rehearsal zip archive: {exc}", check_id="VAL-4") from exc

    sum_sha, reh_sha = check_val_4(summary_raw, rehearsal_raw, bundle_map, val_run_id, c_sha)

    # Audit checks
    _, audit_files_map, audit_json = _fetch_common_prepare_audit_data(
        client, c_sha, evidence_commit, val_run_id, val_artifacts_map
    )

    manifest_dict = build_manifest_v2(
        c_sha=c_sha,
        strict_run=run_info,
        prepare_job=job_info,
        inputs=inputs_info,
        environment=env_data,
        branch_policies=branch_policies,
        deploy_branch=branch_data,
        branch_rules=branch_rules,
        bundle_map=bundle_map,
        validation_run=val_run,
        validation_artifacts=val_artifacts_map,
        summary_member_sha256=sum_sha,
        rehearsal_member_sha256=reh_sha,
        evidence_commit=evidence_commit,
        audit_files=audit_files_map,
        audit_json=audit_json,
        harness_expires_at=har_expires_at,
    )

    manifest_bytes = canonical(manifest_dict)
    manifest_sha256 = digest(manifest_bytes)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)

    set_github_output("manifest_sha256", manifest_sha256, environ)
    set_github_output("job_id", check_run_id, environ)
    print(f"Prepared strict manifest {manifest_sha256} written to {manifest_path}")
    return 0


def cmd_publish(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """publish --manifest: emit summary notice and verify artifact outputs."""
    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        raise AuthorizationError(f"Manifest file not found: {manifest_path}")

    with open(manifest_path, "rb") as f:
        content = f.read()

    manifest_sha = digest(content)
    expected_sha = environ.get("MANIFEST_SHA256")
    if not expected_sha or manifest_sha != expected_sha:
        raise AuthorizationError(f"MANIFEST_SHA256 mismatch: expected {expected_sha}, got {manifest_sha}")

    artifact_id = environ.get("ARTIFACT_ID")
    artifact_url = environ.get("ARTIFACT_URL")
    artifact_digest = environ.get("ARTIFACT_DIGEST")

    if not artifact_id or not artifact_url or not artifact_digest:
        raise AuthorizationError("Missing required ARTIFACT_ID, ARTIFACT_URL, or ARTIFACT_DIGEST in environment")

    expected_digest_prefix = f"sha256:{manifest_sha}"
    if artifact_digest != expected_digest_prefix:
        raise AuthorizationError(f"ARTIFACT_DIGEST mismatch: expected {expected_digest_prefix}, got {artifact_digest}")

    summary_content = (
        f"### Strict Authorization Manifest Prepared\n\n"
        f"- **Manifest SHA-256 (D):** `{manifest_sha}`\n"
        f"- **Artifact ID:** `{artifact_id}`\n"
        f"- **Artifact URL:** {artifact_url}\n\n"
        f"To approve this deployment, submit review comment on environment `strict-proof`:\n"
        f"```text\n{APPROVAL_COMMENT_PREFIX}{manifest_sha}\n```\n"
    )

    summary_file = environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write(summary_content)
        except OSError:
            pass

    print(f"Published manifest artifact {artifact_id} with SHA-256 {manifest_sha}")
    return 0


def cmd_authorize(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """authorize --out-dir: verify full strict authorization chain and approval. Writes manifest & verification."""
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    c_sha = environ.get("GITHUB_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    check_run_id = environ.get("JOB_CHECK_RUN_ID", "")
    prepare_job_id = environ.get("PREPARE_JOB_ID", "")
    prepare_art_id = environ.get("PREPARE_ARTIFACT_ID", "")
    prepare_manifest_sha = environ.get("PREPARE_MANIFEST_SHA256", "")

    recorded_checks: List[Dict[str, Any]] = []

    def record(check_id: str, status: str, observed: Any) -> None:
        recorded_checks.append({"id": check_id, "status": status, "observed": observed})

    try:
        if not prepare_job_id or not prepare_art_id or not prepare_manifest_sha:
            raise AuthorizationError("Missing required PREPARE_* outputs in environment for authorize")

        # RNR-1..4
        rnr1 = check_rnr_1(environ)
        record("RNR-1", "PASS", rnr1)
        rnr2 = check_rnr_2(environ)
        record("RNR-2", "PASS", rnr2)
        rnr3 = check_rnr_3(environ)
        record("RNR-3", "PASS", rnr3)
        rnr4 = check_rnr_4(environ, JOB_KEY_STRICT)
        record("RNR-4", "PASS", rnr4)

        # RNR-5
        event_path = environ.get("GITHUB_EVENT_PATH")
        if not event_path or not os.path.isfile(event_path):
            raise AuthorizationError("[RNR-5] missing GITHUB_EVENT_PATH", check_id="RNR-5")
        with open(event_path, "rb") as f:
            event_payload = json.loads(f.read().decode("utf-8"))
        inputs_info = check_rnr_5(event_payload)
        record("RNR-5", "PASS", inputs_info)
        evidence_commit = inputs_info["evidence_commit"]

        # RNR-6
        rnr6 = check_rnr_6(environ)
        record("RNR-6", "PASS", rnr6)

        # REP-1
        repo_data = client.get_json(f"repos/{PINNED_REPOSITORY}")
        rep1 = check_rep_1(repo_data)
        record("REP-1", "PASS", rep1)

        # RUN-1
        strict_run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}")
        run_info = check_run_1(strict_run_data, c_sha, expected_event="workflow_dispatch")
        record("RUN-1", "PASS", run_info)

        # JOB-1
        job_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{check_run_id}")
        runner_name = environ.get("RUNNER_NAME")
        job_info = check_job_1(job_data, run_id, JOB_NAME_STRICT, c_sha, runner_name=runner_name)
        record("JOB-1", "PASS", job_info)

        # JOB-2
        check_run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/check-runs/{check_run_id}")
        dep_obj = check_run_data.get("deployment")
        if not isinstance(dep_obj, dict) or not dep_obj.get("id"):
            raise AuthorizationError("[JOB-2] check run not linked to deployment", check_id="JOB-2")
        deployment_data = client.get_json(f"repos/{PINNED_REPOSITORY}/deployments/{dep_obj['id']}")
        job2 = check_job_2(check_run_data, deployment_data, run_id, check_run_id, c_sha)
        record("JOB-2", "PASS", job2)

        # JOB-3
        jobs_list = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs")
        check_job_3(jobs_list, prepare_job_id, check_run_id)
        record("JOB-3", "PASS", {"prepare_job_id": prepare_job_id, "strict_job_id": check_run_id})

        # ENV-1 & ENV-2
        env_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}")
        env1 = check_env_1(env_data)
        record("ENV-1", "PASS", env1)

        policies_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies")
        branch_policies = check_env_2(policies_data)
        record("ENV-2", "PASS", branch_policies)

        # BRN-1 & BRN-2
        branch_data = client.get_json(f"repos/{PINNED_REPOSITORY}/branches/{PINNED_DEPLOY_BRANCH}")
        brn1 = check_brn_1(branch_data, c_sha)
        record("BRN-1", "PASS", brn1)

        rules_data = client.get_paginated(f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}")
        branch_rules = check_brn_2(rules_data, require_active=True)
        record("BRN-2", "PASS", branch_rules)

        # SRC-1, SRC-2, SRC-3
        pull_data = client.get_json(f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}")
        src1 = check_src_1(pull_data)
        record("SRC-1", "PASS", src1)

        compare_pw = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}")
        src2 = check_src_2(compare_pw)
        record("SRC-2", "PASS", src2)

        compare_wh = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}")
        src3 = check_src_3(compare_wh)
        record("SRC-3", "PASS", src3)

        # BUN-1
        bundle_map = check_bun_1()
        record("BUN-1", "PASS", bundle_map)

        # HAR-1..6
        harness_run = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}")
        harness_job = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}")
        check_har_1_2(harness_run, harness_job)
        record("HAR-1..2", "PASS", {"run_id": HARNESS_RUN_ID, "job_id": HARNESS_JOB_ID})

        harness_art = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}")
        har_expires_at = check_har_3(harness_art)
        record("HAR-3", "PASS", {"artifact_id": HARNESS_ARTIFACT_ID, "expires_at": har_expires_at})

        contents_data = client.get_json(f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}?ref={HARNESS_PRESERVED_COMMIT}")
        blob_data = client.get_json(f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}")
        preserved_zip = check_har_4(contents_data, blob_data)
        record("HAR-4", "PASS", {"preserved_blob": HARNESS_PRESERVED_BLOB})

        downloaded_harness_zip = None
        if not harness_art.get("expired"):
            downloaded_harness_zip = client.download_artifact_zip(HARNESS_ARTIFACT_ID)
        check_har_5(downloaded_harness_zip, preserved_zip, harness_art.get("expired", False))
        record("HAR-5", "PASS", {"downloaded": downloaded_harness_zip is not None})

        har6 = check_har_6(preserved_zip)
        record("HAR-6", "PASS", har6)

        # VAL-1..4
        val_runs = client.get_paginated(
            f"repos/{PINNED_REPOSITORY}/actions/workflows/{PINNED_WORKFLOW_ID}/runs",
            params={"head_sha": c_sha, "branch": PINNED_DEPLOY_BRANCH},
        )
        val_run = check_val_1(val_runs, c_sha)
        record("VAL-1", "PASS", {"run_id": val_run["id"]})

        check_val_1b(client, val_runs)
        record("VAL-1b", "PASS", {"verified_runs_count": len(val_runs)})

        val_run_id = str(val_run["id"])
        val_jobs = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/attempts/1/jobs")
        check_val_2(val_jobs)
        record("VAL-2", "PASS", {"jobs_count": len(val_jobs)})

        val_arts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/artifacts")
        val_artifacts_map = check_val_3(val_arts, c_sha)
        record("VAL-3", "PASS", val_artifacts_map)

        summary_art = val_artifacts_map[ARTIFACT_NAME_RAIL_SUMMARY]
        summary_zip = client.download_artifact_zip(summary_art["id"])
        if f"sha256:{digest(summary_zip)}" != summary_art["digest"]:
            raise AuthorizationError(f"[VAL-4] summary zip digest mismatch: expected {summary_art['digest']}, got sha256:{digest(summary_zip)}", check_id="VAL-4")
        try:
            with zipfile.ZipFile(io.BytesIO(summary_zip)) as zf:
                names = zf.namelist()
                if len(names) != 1 or names[0] != "rail-validation-summary.json":
                    raise AuthorizationError(f"[VAL-4] summary zip must contain exactly 'rail-validation-summary.json', got {names}", check_id="VAL-4")
                summary_raw = zf.read("rail-validation-summary.json")
        except zipfile.BadZipFile as exc:
            raise AuthorizationError(f"[VAL-4] corrupted summary zip archive: {exc}", check_id="VAL-4") from exc

        rehearsal_art = val_artifacts_map[ARTIFACT_NAME_REHEARSAL_REPORT]
        rehearsal_zip = client.download_artifact_zip(rehearsal_art["id"])
        if f"sha256:{digest(rehearsal_zip)}" != rehearsal_art["digest"]:
            raise AuthorizationError(f"[VAL-4] rehearsal zip digest mismatch: expected {rehearsal_art['digest']}, got sha256:{digest(rehearsal_zip)}", check_id="VAL-4")
        try:
            with zipfile.ZipFile(io.BytesIO(rehearsal_zip)) as zf:
                names = zf.namelist()
                if len(names) != 1 or names[0] != "rail-rehearsal-report.json":
                    raise AuthorizationError(f"[VAL-4] rehearsal zip must contain exactly 'rail-rehearsal-report.json', got {names}", check_id="VAL-4")
                rehearsal_raw = zf.read("rail-rehearsal-report.json")
        except zipfile.BadZipFile as exc:
            raise AuthorizationError(f"[VAL-4] corrupted rehearsal zip archive: {exc}", check_id="VAL-4") from exc

        sum_sha, reh_sha = check_val_4(summary_raw, rehearsal_raw, bundle_map, val_run_id, c_sha)
        record("VAL-4", "PASS", {"summary_sha256": sum_sha, "rehearsal_sha256": reh_sha})

        # AUD-1..3
        _, audit_files_map, audit_json = _fetch_common_prepare_audit_data(
            client, c_sha, evidence_commit, val_run_id, val_artifacts_map
        )
        record("AUD-1..3", "PASS", {"evidence_commit": evidence_commit, "verdict": "GO"})

        # MAN-1
        artifacts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/artifacts")
        prep_job = next(j for j in jobs_list if str(j["id"]) == str(prepare_job_id))
        art_meta = check_man_1(
            artifacts,
            prepare_art_id,
            run_id,
            c_sha,
            prep_job.get("started_at", ""),
            prep_job.get("completed_at", ""),
        )
        record("MAN-1", "PASS", art_meta)

        # MAN-2
        zip_bytes = client.download_artifact_zip(prepare_art_id)
        manifest_bytes = check_man_2(zip_bytes, art_meta["digest"], prepare_manifest_sha)
        manifest = parse(manifest_bytes)
        record("MAN-2", "PASS", {"manifest_sha256": prepare_manifest_sha})

        prep_job_info = check_job_1(prep_job, run_id, JOB_NAME_PREPARE, c_sha, runner_name=prep_job.get("runner_name"))
        expected_live_manifest = build_manifest_v2(
            c_sha=c_sha,
            strict_run=run_info,
            prepare_job=prep_job_info,
            inputs=inputs_info,
            environment=env_data,
            branch_policies=branch_policies,
            deploy_branch=branch_data,
            branch_rules=branch_rules,
            bundle_map=bundle_map,
            validation_run=val_run,
            validation_artifacts=val_artifacts_map,
            summary_member_sha256=sum_sha,
            rehearsal_member_sha256=reh_sha,
            evidence_commit=evidence_commit,
            audit_files=audit_files_map,
            audit_json=audit_json,
            harness_expires_at=har_expires_at,
        )
        check_man_3(manifest, expected_live_manifest)
        record("MAN-3", "PASS", {"matches_live_rebuild": True})

        # APR-1
        approvals = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/approvals")
        appr_record = check_apr_1(approvals, prepare_manifest_sha)
        record("APR-1", "PASS", appr_record)

        # All checks passed! Write manifest and verification
        manifest_path = out_dir / "manifest.json"
        with open(manifest_path, "wb") as f:
            f.write(manifest_bytes)

        verification_data = {
            "schema": SCHEMA_VERIFICATION,
            "decision": "AUTHORIZED",
            "manifest_sha256": prepare_manifest_sha,
            "c_sha": c_sha,
            "strict_run_id": run_id,
            "strict_job_id": check_run_id,
            "approval": appr_record,
            "checks": recorded_checks,
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        verification_path = out_dir / "verification.json"
        with open(verification_path, "wb") as f:
            f.write(canonical(verification_data))

        manifest_b64 = base64.b64encode(manifest_bytes).decode("ascii")
        set_github_output("manifest_sha256", prepare_manifest_sha, environ)
        set_github_output("manifest_b64", manifest_b64, environ)
        set_github_output("job_id", check_run_id, environ)
        set_github_output("job_started_at", job_info.get("started_at", ""), environ)
        set_github_output("decision", "AUTHORIZED", environ)

        print(f"Strict authorization verified. Manifest SHA-256: {prepare_manifest_sha}")
        return 0

    except Exception as exc:
        failed_id = getattr(exc, "check_id", None)
        if not failed_id:
            m = re.search(r"\[([A-Z0-9\.\-]+)\]", str(exc))
            if m:
                failed_id = m.group(1)

        refusal_data = {
            "schema": SCHEMA_VERIFICATION,
            "decision": "REFUSED",
            "reason": str(exc),
            "failed_check": failed_id,
            "c_sha": c_sha,
            "strict_run_id": run_id,
            "strict_job_id": check_run_id,
            "checks": recorded_checks,
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            with open(out_dir / "verification.json", "wb") as f:
                f.write(canonical(refusal_data))
        except OSError:
            pass
        raise


def cmd_check_bundle(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """check-bundle --manifest <path> --expect-sha256 <hex>: verify supervisor dist hashes."""
    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        raise AuthorizationError(f"Manifest file not found: {manifest_path}", check_id="BUN-MANIFEST")

    with open(manifest_path, "rb") as f:
        content = f.read()

    actual_sha = digest(content)
    if actual_sha != args.expect_sha256:
        raise AuthorizationError(f"Manifest SHA-256 mismatch: expected {args.expect_sha256}, got {actual_sha}", check_id="BUN-DIGEST")

    m = parse(content)
    expected_bundle = m.get("bundle", {})
    actual_bundle = check_bun_1()

    if actual_bundle != expected_bundle:
        raise AuthorizationError("Supervisor dist files do not match manifest bundle map", check_id="BUN-MATCH")

    print(f"Bundle verified against manifest ({len(actual_bundle)} files).")
    return 0


def cmd_check_w_tree(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """check-w-tree --w-dir <path>: verify W checkout added paths and digest."""
    w_dir = Path(args.w_dir)
    if not w_dir.is_dir():
        raise AuthorizationError(f"W directory not found: {w_dir}", check_id="W-DIR")

    # 1. Verify W checkout HEAD == PINNED_W_SHA
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(w_dir), capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorizationError(f"[W-TREE] git rev-parse HEAD failed in {w_dir}: {res.stderr}", check_id="W-HEAD")
    actual_w_sha = res.stdout.strip()
    if actual_w_sha != PINNED_W_SHA:
        raise AuthorizationError(f"[W-TREE] W checkout HEAD mismatch: expected {PINNED_W_SHA}, got {actual_w_sha}", check_id="W-HEAD")

    # 2. Verify clean tree
    res = subprocess.run(["git", "status", "--porcelain"], cwd=str(w_dir), capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorizationError(f"[W-TREE] git status --porcelain failed in {w_dir}: {res.stderr}", check_id="W-STATUS")
    if res.stdout.strip():
        raise AuthorizationError(f"[W-TREE] W checkout is dirty: {res.stdout.strip()}", check_id="W-STATUS")

    # 3. Verify non-proof product equality between P and W
    res = subprocess.run(
        ["git", "diff", "--name-only", PINNED_P_SHA, PINNED_W_SHA, "--", ".", ":(exclude)proof"],
        cwd=str(w_dir),
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise AuthorizationError(f"[W-TREE] git diff P..W outside proof failed in {w_dir}: {res.stderr}", check_id="W-DIFF")
    if res.stdout.strip():
        raise AuthorizationError(f"[W-TREE] non-proof product diff found between P and W: {res.stdout.strip()}", check_id="W-DIFF")

    # 4. Verify 34 added files between P and W
    res = subprocess.run(
        ["git", "diff", "--name-status", PINNED_P_SHA, PINNED_W_SHA],
        cwd=str(w_dir),
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise AuthorizationError(f"[W-TREE] git diff --name-status P..W failed in {w_dir}: {res.stderr}", check_id="W-DIFF")

    added_files = []
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            raise AuthorizationError(f"[W-TREE] unexpected diff line: {line}", check_id="W-DIFF")
        st, path = parts
        if st != "A" or not path.startswith("proof/"):
            raise AuthorizationError(f"[W-TREE] file {path} has status {st}; expected added under proof/", check_id="W-DIFF")
        added_files.append(path)

    if len(added_files) != PINNED_W_ADDED_COUNT:
        raise AuthorizationError(f"[W-TREE] W added files count mismatch: expected {PINNED_W_ADDED_COUNT}, got {len(added_files)}", check_id="W-COUNT")

    sorted_paths = sorted(added_files)
    digest_bytes = "\n".join(sorted_paths).encode("utf-8")
    actual_digest = digest(digest_bytes)
    if actual_digest != PINNED_W_ADDED_PATHS_SHA256:
        raise AuthorizationError(f"[W-TREE] W added paths digest mismatch: expected {PINNED_W_ADDED_PATHS_SHA256}, got {actual_digest}", check_id="W-DIGEST")

    # 5. Verify every added file exists on disk
    for path in sorted_paths:
        if not (w_dir / path).is_file():
            raise AuthorizationError(f"[W-TREE] added file missing on disk: {path}", check_id="W-DISK")

    print(f"W tree verified: HEAD={actual_w_sha}, clean, product equal, {len(added_files)} files match digest {actual_digest}")
    return 0


def cmd_rehearse(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """rehearse --report <path>: execute rehearsal against GitHub API and emit report."""
    check_rnr_1(environ)
    check_rnr_3(environ)
    check_rnr_4(environ, JOB_KEY_REHEARSAL)
    check_rnr_6(environ)

    c_sha = environ["GITHUB_SHA"]
    run_id = environ["GITHUB_RUN_ID"]
    check_run_id = environ["JOB_CHECK_RUN_ID"]
    ref_name = environ.get("GITHUB_REF_NAME", PINNED_DEPLOY_BRANCH)

    repo_data = client.get_json(f"repos/{PINNED_REPOSITORY}")
    check_rep_1(repo_data)

    run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}")
    event = run_data.get("event")
    if event == "push":
        check_run_1(run_data, c_sha, expected_event="push", expected_branch=ref_name, allow_completed=True)
    elif event == "workflow_dispatch":
        check_run_1(run_data, c_sha, expected_event="workflow_dispatch", expected_branch=ref_name, allow_completed=True)
        event_path = environ.get("GITHUB_EVENT_PATH")
        if event_path and os.path.isfile(event_path):
            with open(event_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            mode = payload.get("inputs", {}).get("mode")
            if mode not in ("validation-only", "strict-chain"):
                raise AuthorizationError(f"[RNR-5] invalid workflow_dispatch mode for rehearsal: {mode}", check_id="RNR-5")
    else:
        raise AuthorizationError(f"[RUN-1] rehearsal unsupported event: {event}", check_id="RUN-1")

    job_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{check_run_id}")
    runner_name = environ.get("RUNNER_NAME")
    check_job_1(job_data, run_id, JOB_NAME_REHEARSAL, c_sha, runner_name=runner_name)

    check_run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/check-runs/{check_run_id}")
    if check_run_data.get("deployment") is not None:
        raise AuthorizationError("[JOB-2-NEG] rehearsal check run must have no deployment object", check_id="JOB-2-NEG")

    env_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}")
    check_env_1(env_data)

    policies_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies")
    check_env_2(policies_data)

    rules_data = client.get_paginated(f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}")
    branch_rules = check_brn_2(rules_data, require_active=False)

    pull_data = client.get_json(f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}")
    check_src_1(pull_data)

    compare_pw = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}")
    check_src_2(compare_pw)

    compare_wh = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}")
    check_src_3(compare_wh)

    approvals = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/approvals")
    if approvals != []:
        raise AuthorizationError(f"[APR-NEG] rehearsal run approvals must equal [], got {len(approvals)}", check_id="APR-NEG")

    bundle_map = check_bun_1()

    # HAR-1..6 checks
    harness_run = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}")
    harness_job = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}")
    check_har_1_2(harness_run, harness_job)

    harness_art = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}")
    har_expires_at = check_har_3(harness_art)

    contents_data = client.get_json(f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}?ref={HARNESS_PRESERVED_COMMIT}")
    blob_data = client.get_json(f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}")
    preserved_zip = check_har_4(contents_data, blob_data)

    downloaded_harness_zip = None
    if not harness_art.get("expired"):
        downloaded_harness_zip = client.download_artifact_zip(HARNESS_ARTIFACT_ID)
    check_har_5(downloaded_harness_zip, preserved_zip, harness_art.get("expired", False))

    check_har_6(preserved_zip)

    # Redirect-safe round trip of the bundle artifact
    arts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/artifacts")
    bundle_name = f"supervisor-bundle-{c_sha}"
    bundle_art = next((a for a in arts if a.get("name") == bundle_name), None)
    if not bundle_art:
        raise AuthorizationError(f"[BUN-RT] supervisor bundle artifact '{bundle_name}' not found on run {run_id}", check_id="BUN-RT")

    zip_bytes = client.download_artifact_zip(str(bundle_art["id"]))
    actual_digest = f"sha256:{digest(zip_bytes)}"
    if actual_digest != bundle_art.get("digest"):
        raise AuthorizationError(f"[BUN-RT] rehearsal bundle artifact digest mismatch: expected {bundle_art.get('digest')}, got {actual_digest}", check_id="BUN-RT")

    rehearsal_manifest = {
        "schema": SCHEMA_REHEARSAL_MANIFEST,
        "c_sha": c_sha,
        "run_id": str(run_id),
        "event": event,
        "branch": ref_name,
        "sources": {
            "c_sha": c_sha,
            "p_sha": PINNED_P_SHA,
            "w_sha": PINNED_W_SHA,
            "h_sha": PINNED_H_SHA,
        },
        "bundle": bundle_map,
        "actions": PINNED_ACTIONS,
        "branch_rules": branch_rules,
        "harness": {
            "run_id": HARNESS_RUN_ID,
            "artifact_id": HARNESS_ARTIFACT_ID,
            "digest": HARNESS_ARTIFACT_DIGEST,
            "expires_at": har_expires_at,
        },
    }
    rehearsal_manifest_bytes = canonical(rehearsal_manifest)
    rehearsal_manifest_sha = digest(rehearsal_manifest_bytes)

    rehearsal_report = {
        "schema": SCHEMA_REHEARSAL,
        "status": "REHEARSAL_PASS",
        "c_sha": c_sha,
        "run_id": str(run_id),
        "checks": [
            {"id": "RNR-1", "status": "PASS", "detail": "Repository identity verified"},
            {"id": "RNR-3", "status": "PASS", "detail": "Run attempt verified as 1"},
            {"id": "RNR-4", "status": "PASS", "detail": "Runner environment verified"},
            {"id": "RNR-6", "status": "PASS", "detail": "HEAD commit and clean tree verified"},
            {"id": "REP-1", "status": "PASS", "detail": "Repository public and id verified"},
            {"id": "RUN-1", "status": "PASS", "detail": f"Run metadata {event} profile verified"},
            {"id": "JOB-1", "status": "PASS", "detail": "Rehearsal job verified"},
            {"id": "JOB-2-NEG", "status": "PASS", "detail": "No deployment object on check run"},
            {"id": "ENV-1", "status": "PASS", "detail": "Environment protection rules verified"},
            {"id": "ENV-2", "status": "PASS", "detail": "Deployment branch policies verified"},
            {"id": "BRN-2", "status": "PASS", "detail": f"Observed branch rulesets ({len(branch_rules)})"},
            {"id": "SRC-1", "status": "PASS", "detail": "PR 147 open state and head P verified"},
            {"id": "SRC-2", "status": "PASS", "detail": "P...W 34 added files and digest verified"},
            {"id": "SRC-3", "status": "PASS", "detail": "W...H exactly 2 files and merge base verified"},
            {"id": "BUN-1", "status": "PASS", "detail": "Supervisor bundle files verified"},
            {"id": "HAR-1..6", "status": "PASS", "detail": "Preserved harness run, artifact, and summary member verified"},
            {"id": "APR-NEG", "status": "PASS", "detail": "Approvals equal empty list"},
            {"id": "BUN-RT", "status": "PASS", "detail": "Supervisor bundle artifact round-trip verified without Authorization"},
        ],
        "approvals_observed": [],
        "rehearsal_manifest_sha256": rehearsal_manifest_sha,
    }

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "wb") as f:
        f.write(canonical(rehearsal_report))

    print(f"Rehearsal passed. Report written to {report_path}")
    return 0


def cmd_rail_summary(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """rail-summary --out <path> --pins-report <path> --structure-report <path> [--refusal-report <path>]"""
    c_sha = environ.get("GITHUB_SHA")
    if not c_sha or not re.fullmatch(r"[0-9a-f]{40}", c_sha):
        raise AuthorizationError("[rail-summary] missing or invalid GITHUB_SHA", check_id="RAIL-SHA")

    run_id = environ.get("GITHUB_RUN_ID")
    if not run_id or not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise AuthorizationError("[rail-summary] missing or invalid GITHUB_RUN_ID", check_id="RAIL-RUN-ID")

    run_attempt = environ.get("GITHUB_RUN_ATTEMPT", "1")
    if run_attempt != "1":
        raise AuthorizationError("[rail-summary] GITHUB_RUN_ATTEMPT must be '1'", check_id="RAIL-ATTEMPT")

    pins_path = Path(args.pins_report)
    if not pins_path.is_file():
        raise AuthorizationError(f"Pins report file not found: {pins_path}", check_id="RAIL-PINS")
    with open(pins_path, "r", encoding="utf-8") as f:
        pins_data = json.load(f)

    if isinstance(pins_data, dict) and pins_data.get("status") != "PASS":
        raise AuthorizationError(f"[rail-summary] pins report status is not PASS: {pins_data.get('status')}", check_id="RAIL-PINS")

    if isinstance(pins_data, dict) and "actions" in pins_data:
        actions_dict = pins_data["actions"]
    elif isinstance(pins_data, dict):
        actions_dict = pins_data
    else:
        raise AuthorizationError("Invalid pins report format", check_id="RAIL-PINS")

    if actions_dict != PINNED_ACTIONS:
        raise AuthorizationError("[rail-summary] pins report actions do not match PINNED_ACTIONS §3.2", check_id="RAIL-PINS")

    struct_path = Path(args.structure_report)
    if not struct_path.is_file():
        raise AuthorizationError(f"Structure report file not found: {struct_path}", check_id="RAIL-STRUCT")
    with open(struct_path, "r", encoding="utf-8") as f:
        struct_data = json.load(f)

    struct_status = struct_data.get("status") or struct_data.get("workflow_structure")
    if struct_status != "PASS":
        raise AuthorizationError(f"[rail-summary] Workflow structure check did not pass: {struct_status}", check_id="RAIL-STRUCT")

    refusal_report_arg = getattr(args, "refusal_report", None)
    if not refusal_report_arg or not os.path.isfile(refusal_report_arg):
        raise AuthorizationError("[rail-summary] missing required refusal controls evidence report (--refusal-report)", check_id="RAIL-REFUSAL")

    with open(refusal_report_arg, "r", encoding="utf-8") as f:
        ref_data = json.load(f)

    ref_status = ref_data.get("status") or ref_data.get("controller_suite")
    if ref_status != "PASS":
        raise AuthorizationError(f"[rail-summary] controller refusal suite did not pass: {ref_status}", check_id="RAIL-REFUSAL")

    reported_controls = ref_data.get("strict_refusal_controls") or ref_data.get("controls") or []
    if set(reported_controls) != set(PINNED_REFUSAL_CONTROLS):
        raise AuthorizationError(f"[rail-summary] refusal controls do not match PINNED_REFUSAL_CONTROLS: {reported_controls}", check_id="RAIL-REFUSAL")

    bundle_map = check_bun_1()

    summary = {
        "schema": SCHEMA_RAIL_SUMMARY,
        "status": "PASS",
        "c_sha": c_sha,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "dist": bundle_map,
        "actions": actions_dict,
        "workflow_structure": "PASS",
        "strict_refusal_controls": [c for c in PINNED_REFUSAL_CONTROLS if c in reported_controls],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(canonical(summary))

    print(f"Rail validation summary written to {out_path}")
    return 0


def cmd_inspect(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """inspect --run-id: verify run is waiting on strict-proof, recompute D from live records, and print approval prompt."""
    run_id = args.run_id
    run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}")
    status = run_data.get("status")
    if status not in ("waiting", "in_progress"):
        raise AuthorizationError(f"Run {run_id} status must be 'waiting' or 'in_progress', got '{status}'", check_id="INSPECT-STATUS")

    pending_deps = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/pending_deployments")
    if not isinstance(pending_deps, list) or len(pending_deps) != 1:
        raise AuthorizationError(f"Run {run_id} expected exactly 1 pending deployment, got {pending_deps}", check_id="INSPECT-DEPLOY")

    dep = pending_deps[0]
    env = dep.get("environment", {})
    if str(env.get("id")) != PINNED_ENVIRONMENT_ID or env.get("name") != PINNED_ENVIRONMENT_NAME:
        raise AuthorizationError(f"Pending deployment environment mismatch: expected {PINNED_ENVIRONMENT_NAME}, got {env}", check_id="INSPECT-DEPLOY")

    reviewers = dep.get("reviewers", [])
    if len(reviewers) != 1:
        raise AuthorizationError(f"Pending deployment expected 1 reviewer, got {reviewers}", check_id="INSPECT-DEPLOY")
    rev = reviewers[0]
    if rev.get("type") != "User" or str(rev.get("reviewer", {}).get("id")) != PINNED_REVIEWER_ID:
        raise AuthorizationError(f"Pending deployment reviewer mismatch: expected User {PINNED_REVIEWER_ID}, got {rev}", check_id="INSPECT-DEPLOY")

    c_sha = run_data.get("head_sha", "")
    run_info = check_run_1(run_data, c_sha, expected_event="workflow_dispatch")

    # Fetch jobs to verify prepare-strict-authorization
    jobs_list = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs")
    prep_job = next((j for j in jobs_list if j.get("name") == JOB_NAME_PREPARE), None)
    if not prep_job:
        raise AuthorizationError(f"Prepare job '{JOB_NAME_PREPARE}' not found on run {run_id}", check_id="INSPECT-PREP")
    if prep_job.get("status") != "completed" or prep_job.get("conclusion") != "success":
        raise AuthorizationError(f"Prepare job must be completed/success, got status={prep_job.get('status')}, conclusion={prep_job.get('conclusion')}", check_id="INSPECT-PREP")

    # Check artifacts for manifest
    artifacts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}/artifacts")
    prep_art_match = next((a for a in artifacts if a.get("name") == ARTIFACT_NAME_MANIFEST), None)
    if not prep_art_match:
        raise AuthorizationError(f"Artifact '{ARTIFACT_NAME_MANIFEST}' not found on run {run_id}", check_id="INSPECT-ART")

    prep_art_id = str(prep_art_match["id"])
    art_meta = check_man_1(
        artifacts,
        prep_art_id,
        run_id,
        c_sha,
        prep_job.get("started_at", ""),
        prep_job.get("completed_at", ""),
    )

    zip_bytes = client.download_artifact_zip(prep_art_id)
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            if "manifest.json" not in zf.namelist():
                raise AuthorizationError("Manifest zip missing 'manifest.json'", check_id="INSPECT-MAN")
            manifest_bytes = zf.read("manifest.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"Corrupted manifest zip: {exc}", check_id="INSPECT-MAN") from exc

    downloaded_d = digest(manifest_bytes)
    downloaded_manifest = parse(manifest_bytes)
    evidence_commit = downloaded_manifest.get("inputs", {}).get("evidence_commit", "")

    # Re-verify live evidence chain independently
    repo_data = client.get_json(f"repos/{PINNED_REPOSITORY}")
    check_rep_1(repo_data)

    job_info = check_job_1(prep_job, run_id, JOB_NAME_PREPARE, c_sha, runner_name=prep_job.get("runner_name"))

    env_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}")
    check_env_1(env_data)

    policies_data = client.get_json(f"repos/{PINNED_REPOSITORY}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies")
    branch_policies = check_env_2(policies_data)

    branch_data = client.get_json(f"repos/{PINNED_REPOSITORY}/branches/{PINNED_DEPLOY_BRANCH}")
    check_brn_1(branch_data, c_sha)

    rules_data = client.get_paginated(f"repos/{PINNED_REPOSITORY}/rules/branches/{PINNED_DEPLOY_BRANCH}")
    branch_rules = check_brn_2(rules_data, require_active=True)

    pull_data = client.get_json(f"repos/{PINNED_P_PR_REPOSITORY}/pulls/{PINNED_P_PR_NUMBER}")
    check_src_1(pull_data)

    compare_pw = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_P_SHA}...{PINNED_W_SHA}")
    check_src_2(compare_pw)

    compare_wh = client.get_json(f"repos/{PINNED_REPOSITORY}/compare/{PINNED_W_SHA}...{PINNED_H_SHA}")
    check_src_3(compare_wh)

    bundle_map = check_bun_1()

    harness_run = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{HARNESS_RUN_ID}")
    harness_job = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/jobs/{HARNESS_JOB_ID}")
    check_har_1_2(harness_run, harness_job)

    harness_art = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/artifacts/{HARNESS_ARTIFACT_ID}")
    har_expires_at = check_har_3(harness_art)

    contents_data = client.get_json(f"repos/{PINNED_REPOSITORY}/contents/{HARNESS_PRESERVED_PATH}?ref={HARNESS_PRESERVED_COMMIT}")
    blob_data = client.get_json(f"repos/{PINNED_REPOSITORY}/git/blobs/{HARNESS_PRESERVED_BLOB}")
    preserved_zip = check_har_4(contents_data, blob_data)

    downloaded_harness_zip = None
    if not harness_art.get("expired"):
        downloaded_harness_zip = client.download_artifact_zip(HARNESS_ARTIFACT_ID)
    check_har_5(downloaded_harness_zip, preserved_zip, harness_art.get("expired", False))

    check_har_6(preserved_zip)

    val_runs = client.get_paginated(
        f"repos/{PINNED_REPOSITORY}/actions/workflows/{PINNED_WORKFLOW_ID}/runs",
        params={"head_sha": c_sha, "branch": PINNED_DEPLOY_BRANCH},
    )
    val_run = check_val_1(val_runs, c_sha)
    check_val_1b(client, val_runs)
    val_run_id = str(val_run["id"])

    val_jobs = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/attempts/1/jobs")
    check_val_2(val_jobs)

    val_arts = client.get_paginated(f"repos/{PINNED_REPOSITORY}/actions/runs/{val_run_id}/artifacts")
    val_artifacts_map = check_val_3(val_arts, c_sha)

    summary_art = val_artifacts_map[ARTIFACT_NAME_RAIL_SUMMARY]
    summary_zip = client.download_artifact_zip(summary_art["id"])
    if f"sha256:{digest(summary_zip)}" != summary_art["digest"]:
        raise AuthorizationError(f"[VAL-4] summary zip digest mismatch: expected {summary_art['digest']}, got sha256:{digest(summary_zip)}", check_id="VAL-4")
    try:
        with zipfile.ZipFile(io.BytesIO(summary_zip)) as zf:
            summary_raw = zf.read("rail-validation-summary.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[VAL-4] corrupted summary zip archive: {exc}", check_id="VAL-4") from exc

    rehearsal_art = val_artifacts_map[ARTIFACT_NAME_REHEARSAL_REPORT]
    rehearsal_zip = client.download_artifact_zip(rehearsal_art["id"])
    if f"sha256:{digest(rehearsal_zip)}" != rehearsal_art["digest"]:
        raise AuthorizationError(f"[VAL-4] rehearsal zip digest mismatch: expected {rehearsal_art['digest']}, got sha256:{digest(rehearsal_zip)}", check_id="VAL-4")
    try:
        with zipfile.ZipFile(io.BytesIO(rehearsal_zip)) as zf:
            rehearsal_raw = zf.read("rail-rehearsal-report.json")
    except zipfile.BadZipFile as exc:
        raise AuthorizationError(f"[VAL-4] corrupted rehearsal zip archive: {exc}", check_id="VAL-4") from exc

    sum_sha, reh_sha = check_val_4(summary_raw, rehearsal_raw, bundle_map, val_run_id, c_sha)

    _, audit_files_map, audit_json = _fetch_common_prepare_audit_data(
        client, c_sha, evidence_commit, val_run_id, val_artifacts_map
    )

    reconstructed_manifest = build_manifest_v2(
        c_sha=c_sha,
        strict_run=run_info,
        prepare_job=job_info,
        inputs={"mode": "strict-chain", "evidence_commit": evidence_commit},
        environment=env_data,
        branch_policies=branch_policies,
        deploy_branch=branch_data,
        branch_rules=branch_rules,
        bundle_map=bundle_map,
        validation_run=val_run,
        validation_artifacts=val_artifacts_map,
        summary_member_sha256=sum_sha,
        rehearsal_member_sha256=reh_sha,
        evidence_commit=evidence_commit,
        audit_files=audit_files_map,
        audit_json=audit_json,
        harness_expires_at=har_expires_at,
    )
    check_man_3(downloaded_manifest, reconstructed_manifest)

    recomputed_d = digest(canonical(reconstructed_manifest))
    if recomputed_d != downloaded_d:
        raise AuthorizationError(f"[INSPECT-D] recomputed D mismatch: expected {downloaded_d}, got {recomputed_d}", check_id="INSPECT-D")

    art_url = f"https://github.com/{PINNED_REPOSITORY}/actions/runs/{run_id}/artifacts/{prep_art_id}"
    print(f"D: {recomputed_d}")
    print(f"Strict run S is waiting for your approval: https://github.com/{PINNED_REPOSITORY}/actions/runs/{run_id}")
    print(f"- Manifest: {art_url}. SHA-256 of manifest.json: {recomputed_d}")
    print("To approve: open the run, choose Review deployments, tick strict-proof, paste exactly:")
    print(f"{APPROVAL_COMMENT_PREFIX}{recomputed_d}")
    print("and choose Approve and deploy.")
    return 0


def cmd_verify_run(args: argparse.Namespace, environ: Dict[str, str], client: GitHubAPIClient) -> int:
    """verify-run --run-id: check completed run succeeded."""
    run_id = args.run_id
    run_data = client.get_json(f"repos/{PINNED_REPOSITORY}/actions/runs/{run_id}")
    status = run_data.get("status")
    conclusion = run_data.get("conclusion")
    if status != "completed" or conclusion != "success":
        raise AuthorizationError(f"Run {run_id} failed verification: status={status}, conclusion={conclusion}", check_id="VERIFY-RUN")
    print(f"Run {run_id} verified: status={status}, conclusion={conclusion}")
    return 0


# ---------------------------------------------------------------------------
# CLI Parser & Main Entrypoint (§3.8)
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strict_authorization",
        description="GitHub Actions strict-proof authorization verifier",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # prepare --out-dir
    p_prep = subparsers.add_parser("prepare")
    p_prep.add_argument("--out-dir", required=True, help="Directory to write manifest.json")

    # publish --manifest
    p_pub = subparsers.add_parser("publish")
    p_pub.add_argument("--manifest", required=True, help="Path to manifest.json")

    # authorize --out-dir
    p_auth = subparsers.add_parser("authorize")
    p_auth.add_argument("--out-dir", required=True, help="Directory to write manifest.json and verification.json")

    # check-bundle --manifest <path> --expect-sha256 <hex>
    p_cb = subparsers.add_parser("check-bundle")
    p_cb.add_argument("--manifest", required=True, help="Path to manifest.json")
    p_cb.add_argument("--expect-sha256", required=True, help="Expected manifest sha256")

    # check-w-tree --w-dir <path>
    p_cwt = subparsers.add_parser("check-w-tree")
    p_cwt.add_argument("--w-dir", required=True, help="Path to W checkout root")

    # rehearse --report <path>
    p_reh = subparsers.add_parser("rehearse")
    p_reh.add_argument("--report", required=True, help="Path to write rail-rehearsal-report.json")

    # rail-summary --out <path> --pins-report <path> --structure-report <path> [--refusal-report <path>]
    p_rs = subparsers.add_parser("rail-summary")
    p_rs.add_argument("--out", required=True, help="Path to write rail-validation-summary.json")
    p_rs.add_argument("--pins-report", required=True, help="Path to pins report JSON")
    p_rs.add_argument("--structure-report", required=True, help="Path to structure report JSON")
    p_rs.add_argument("--refusal-report", required=False, help="Path to refusal controls report JSON")

    # inspect --run-id <id>
    p_insp = subparsers.add_parser("inspect")
    p_insp.add_argument("--run-id", required=True, help="Strict workflow run ID")

    # verify-run --run-id <id>
    p_vr = subparsers.add_parser("verify-run")
    p_vr.add_argument("--run-id", required=True, help="Workflow run ID")

    return parser


def main(
    argv: Optional[List[str]] = None,
    environ: Optional[Dict[str, str]] = None,
    api_factory: Optional[Callable[[str], GitHubAPIClient]] = None,
) -> int:
    env = dict(environ if environ is not None else os.environ)
    parser = build_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return USAGE_ERROR_EXIT_CODE if exc.code != 0 else 0

    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN") or ""
    if api_factory is not None:
        client = api_factory(token)
    else:
        client = GitHubAPIClient(token=token, base_url=PINNED_API_BASE)

    handlers = {
        "prepare": cmd_prepare,
        "publish": cmd_publish,
        "authorize": cmd_authorize,
        "check-bundle": cmd_check_bundle,
        "check-w-tree": cmd_check_w_tree,
        "rehearse": cmd_rehearse,
        "rail-summary": cmd_rail_summary,
        "inspect": cmd_inspect,
        "verify-run": cmd_verify_run,
    }

    handler = handlers.get(args.subcommand)
    if not handler:
        sys.stderr.write(f"Unknown subcommand: {args.subcommand}\n")
        return USAGE_ERROR_EXIT_CODE

    try:
        return handler(args, env, client)
    except AuthorizationError as exc:
        sys.stderr.write(f"STRICT_AUTHORIZATION_REFUSED: {exc}\n")
        return AUTH_REFUSED_EXIT_CODE
    except Exception as exc:
        sys.stderr.write(f"STRICT_AUTHORIZATION_ERROR: {exc}\n")
        return AUTH_REFUSED_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
