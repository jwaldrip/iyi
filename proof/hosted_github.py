#!/usr/bin/env python3
"""
proof/hosted_github.py: Bounded authenticated GitHub platform reads and artifact custody.

Implements Slice B of PlanControllerRepairs (§3.1-3.3, §4 Slice B, §5):
- Bounded authenticated platform reads for exact repository, run, attempt, job, and artifact.
- Bounded pagination traversing Link headers and page parameters with max_pages ceilings.
- Token-free storage redirect handling reusing proof/github_artifact.py discipline.
- Retains raw platform response bodies and SHA-256 digests without saving credentials.
- Subject-bound validation provenance verification.
- Authenticated execution context readback resolving concrete positive job ID, runner identity,
  and platform job start timestamp.
- Personal approval verification using injected trusted approval policy and exact manifest digest.
- Strict refusal of caller-supplied local approval or review JSON.
- Detached artifact custody readback by exact immutable artifact ID, establishing completed
  retention and binding approved subject, terminal envelope, member inventory, and digests.
- Enforces that no artifact contains its own future artifact ID.
- Unconditionally preserves independent review refusal; never contacts live network.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import io
import json
import re
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from proof.github_artifact import (
    REDIRECT_CODES,
    USER_AGENT,
    _NoRedirect,
    download_artifact_stream,
    download_artifact_zip,
)
from proof.hosted_contracts import (
    AUTH_COMMENT_PREFIX,
    AUTH_REFUSED_EXIT_CODE,
    SCHEMA_MANIFEST_V2,
    ContractError,
    ExecutionContext,
    ExecutionSubject,
    ProofManifest,
    ReferenceIntegrityError,
    ReviewReferenceMismatch,
    ReviewUnauthenticatedError,
    StrictHaltRefusal,
    StructuralIndependentReviewRef,
    TypeValidationError,
    UnknownFieldError,
    UnsupportedSchemaError,
    ValidationRef,
    ValidationReferenceMismatch,
    canonical_json_bytes,
    enforce_independent_review_refusal,
    enforce_origin_transport_refusal,
    parse_strict_json,
    parse_utc_iso_timestamp,
    require_ascii_str,
    require_bool,
    require_dict,
    require_float,
    require_int,
    require_iso_timestamp,
    require_positive_ascii_id,
    require_sha1_or_commit,
    require_sha256,
    require_str,
    sha256_bytes,
    validate_execution_context_to_manifest,
    validate_strict_pairs_map,
    validate_timestamp_and_epoch,
    validate_validation_ref_to_subject,
)

# Configuration Defaults
DEFAULT_API_BASE: str = "https://api.github.com"
DEFAULT_USER_AGENT: str = USER_AGENT
DEFAULT_TIMEOUT_SEC: int = 60
DEFAULT_MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024   # 10 MiB per API JSON payload
DEFAULT_MAX_ARTIFACT_BYTES: int = 500 * 1024 * 1024  # 500 MiB per evidence zip archive
DEFAULT_MAX_PAGE_COUNT: int = 50
DEFAULT_PER_PAGE: int = 100

CONTROLLER_TERMINAL_STATE_PENDING_CUSTODY: str = "NATIVE_COMPLETE_PENDING_CUSTODY"
CUSTODY_STATUS_RETAINED: str = "RETAINED"
SCHEMA_DETACHED_CUSTODY_V1: str = "iyi-hosted-artifact-custody-v1"


# Slice B Specific Error Hierarchy
class HostedGitHubError(ContractError):
    """Base exception for hosted GitHub platform operations."""


class GitHubPlatformRefusal(HostedGitHubError):
    """Raised when platform validation fails closed."""


class ArtifactCustodyError(HostedGitHubError):
    """Raised when artifact custody readback or integrity check fails."""


class AmbiguousMatchError(GitHubPlatformRefusal):
    """Raised when an API query produces multiple matches when exactly one is expected."""


class MissingRecordError(GitHubPlatformRefusal):
    """Raised when an expected platform record is missing."""


class ResponseBudgetExceededError(GitHubPlatformRefusal):
    """Raised when an API response or artifact exceeds configured size limits."""


# Injected Policy for Human Personal Approval
@dataclasses.dataclass(frozen=True)
class TrustedApprovalPolicy:
    """Injected policy governing acceptance of human personal approvals."""
    environment_name: str
    environment_id: str
    reviewer_id: str
    reviewer_login: Optional[str] = None
    required_comment_prefix: str = AUTH_COMMENT_PREFIX
    enforce_environment_rules: bool = True
    enforce_branch_policy: bool = True
    target_branch: Optional[str] = None
    allow_self_review: bool = False
    can_admins_bypass: bool = False

    def __post_init__(self) -> None:
        require_ascii_str(self.environment_name, "environment_name")
        object.__setattr__(self, "environment_id", require_positive_ascii_id(self.environment_id, "environment_id"))
        object.__setattr__(self, "reviewer_id", require_positive_ascii_id(self.reviewer_id, "reviewer_id"))
        if self.reviewer_login is not None:
            require_ascii_str(self.reviewer_login, "reviewer_login")
        require_str(self.required_comment_prefix, "required_comment_prefix")
        require_bool(self.enforce_environment_rules, "enforce_environment_rules")
        require_bool(self.enforce_branch_policy, "enforce_branch_policy")
        if self.target_branch is not None:
            require_ascii_str(self.target_branch, "target_branch")
        require_bool(self.allow_self_review, "allow_self_review")
        require_bool(self.can_admins_bypass, "can_admins_bypass")


def build_production_approval_policy(branch: Optional[str] = None) -> TrustedApprovalPolicy:
    """Construct the canonical production approval policy per PlanControllerRepairs 3.3."""
    return TrustedApprovalPolicy(
        environment_name="strict-proof",
        environment_id="26584191206",
        reviewer_id="43164",
        reviewer_login="jwaldrip",
        required_comment_prefix=AUTH_COMMENT_PREFIX,
        enforce_environment_rules=True,
        enforce_branch_policy=True,
        target_branch=branch or "proof/strict-lifecycle-repair-20261102",
        allow_self_review=False,
        can_admins_bypass=False,
    )


# Receipt Records
@dataclasses.dataclass(frozen=True)
class ValidationProvenanceReceipt:
    """Authenticated provenance record for the validation proof run and artifact."""
    subject_digest: str
    validation_ref_digest: str
    repository: str
    run_id: str
    run_attempt: int
    job_id: str
    artifact_id: str
    artifact_name: str
    artifact_size: int
    archive_sha256: str
    evidence_member_name: str
    evidence_member_size: int
    evidence_member_sha256: str
    platform_response_digests: Tuple[Tuple[str, str], ...]
    verified_at: str

    def __post_init__(self) -> None:
        require_sha256(self.subject_digest, "subject_digest")
        require_sha256(self.validation_ref_digest, "validation_ref_digest")
        require_ascii_str(self.repository, "repository")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        object.__setattr__(self, "job_id", require_positive_ascii_id(self.job_id, "job_id"))
        object.__setattr__(self, "artifact_id", require_positive_ascii_id(self.artifact_id, "artifact_id"))
        require_ascii_str(self.artifact_name, "artifact_name")
        require_int(self.artifact_size, "artifact_size", min_val=1)
        require_sha256(self.archive_sha256, "archive_sha256")
        require_ascii_str(self.evidence_member_name, "evidence_member_name")
        require_int(self.evidence_member_size, "evidence_member_size", min_val=1)
        require_sha256(self.evidence_member_sha256, "evidence_member_sha256")
        prd = validate_strict_pairs_map(
            self.platform_response_digests,
            "platform_response_digests",
            allowed_value_types=(str,),
            value_validator=require_sha256,
        )
        object.__setattr__(self, "platform_response_digests", prd)
        require_iso_timestamp(self.verified_at, "verified_at")

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["platform_response_digests"] = dict(self.platform_response_digests)
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclasses.dataclass(frozen=True)
class PersonalApprovalReceipt:
    """Authenticated record of verified personal approval retrieved from GitHub API."""
    manifest_digest: str
    repository: str
    run_id: str
    run_attempt: int
    environment_name: str
    environment_id: str
    reviewer_id: str
    reviewer_login: Optional[str]
    comment: str
    approval_record_digest: str
    platform_response_digests: Tuple[Tuple[str, str], ...]
    verified_at: str

    def __post_init__(self) -> None:
        require_sha256(self.manifest_digest, "manifest_digest")
        require_ascii_str(self.repository, "repository")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        require_ascii_str(self.environment_name, "environment_name")
        object.__setattr__(self, "environment_id", require_positive_ascii_id(self.environment_id, "environment_id"))
        object.__setattr__(self, "reviewer_id", require_positive_ascii_id(self.reviewer_id, "reviewer_id"))
        if self.reviewer_login is not None:
            require_ascii_str(self.reviewer_login, "reviewer_login")
        require_str(self.comment, "comment")
        require_sha256(self.approval_record_digest, "approval_record_digest")
        prd = validate_strict_pairs_map(
            self.platform_response_digests,
            "platform_response_digests",
            allowed_value_types=(str,),
            value_validator=require_sha256,
        )
        object.__setattr__(self, "platform_response_digests", prd)
        require_iso_timestamp(self.verified_at, "verified_at")

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["platform_response_digests"] = dict(self.platform_response_digests)
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


def compute_inventory_digest(members: Sequence[Tuple[str, int, str]]) -> str:
    """Compute deterministic SHA-256 digest over sorted member inventory per Plan 3.7."""
    sorted_items = sorted(members, key=lambda x: x[0])
    lines = [f"{sha256}  {path}\n" for path, _size, sha256 in sorted_items]
    return sha256_bytes("".join(lines).encode("utf-8"))


@dataclasses.dataclass(frozen=True)
class DetachedCustodyReceipt:
    """Detached custody readback establishing completed retention of evidence."""
    schema: str
    status: str
    subject_digest: str
    manifest_digest: str
    terminal_envelope_digest: str
    repository: str
    run_id: str
    run_attempt: int
    artifact_id: str
    artifact_name: str
    artifact_size_bytes: int
    archive_sha256: str
    member_inventory: Tuple[Tuple[str, int, str], ...]
    inventory_digest: str
    platform_response_digests: Tuple[Tuple[str, str], ...]
    verified_at: str

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_DETACHED_CUSTODY_V1:
            raise UnsupportedSchemaError(
                f"Unsupported custody schema: {self.schema!r}, expected {SCHEMA_DETACHED_CUSTODY_V1!r}"
            )
        require_ascii_str(self.status, "status")
        require_sha256(self.subject_digest, "subject_digest")
        require_sha256(self.manifest_digest, "manifest_digest")
        require_sha256(self.terminal_envelope_digest, "terminal_envelope_digest")
        require_ascii_str(self.repository, "repository")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        object.__setattr__(self, "artifact_id", require_positive_ascii_id(self.artifact_id, "artifact_id"))
        require_ascii_str(self.artifact_name, "artifact_name")
        require_int(self.artifact_size_bytes, "artifact_size_bytes", min_val=1)
        require_sha256(self.archive_sha256, "archive_sha256")
        require_sha256(self.inventory_digest, "inventory_digest")

        cleaned_members: List[Tuple[str, int, str]] = []
        for item in self.member_inventory:
            if not isinstance(item, (tuple, list)) or len(item) != 3:
                raise TypeValidationError("member_inventory elements must be (path, size, sha256) 3-tuples")
            p = require_ascii_str(item[0], "member path")
            sz = require_int(item[1], "member size", min_val=0)
            sh = require_sha256(item[2], "member sha256")
            cleaned_members.append((p, sz, sh))
        sorted_members = tuple(sorted(cleaned_members, key=lambda x: x[0]))
        object.__setattr__(self, "member_inventory", sorted_members)

        prd = validate_strict_pairs_map(
            self.platform_response_digests,
            "platform_response_digests",
            allowed_value_types=(str,),
            value_validator=require_sha256,
        )
        object.__setattr__(self, "platform_response_digests", prd)
        require_iso_timestamp(self.verified_at, "verified_at")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "status": self.status,
            "subject_digest": self.subject_digest,
            "manifest_digest": self.manifest_digest,
            "terminal_envelope_digest": self.terminal_envelope_digest,
            "repository": self.repository,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "artifact_size_bytes": self.artifact_size_bytes,
            "archive_sha256": self.archive_sha256,
            "member_inventory": [
                {"path": p, "size": sz, "sha256": s}
                for p, sz, s in self.member_inventory
            ],
            "inventory_digest": self.inventory_digest,
            "platform_response_digests": dict(self.platform_response_digests),
            "verified_at": self.verified_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


# Bounded Authenticated GitHub Client
class HostedGitHubClient:
    """Authenticated, bounded GitHub REST client with pagination and redirect discipline."""

    def __init__(
        self,
        token: str,
        api_base: str = DEFAULT_API_BASE,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        user_agent: str = DEFAULT_USER_AGENT,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ):
        if not isinstance(token, str) or not token.strip():
            raise GitHubPlatformRefusal("API token must be a non-empty string")
        self.token = token.strip()
        self.api_base = api_base.rstrip("/")
        self.timeout_sec = int(timeout_sec)
        self.max_response_bytes = int(max_response_bytes)
        self.max_artifact_bytes = int(max_artifact_bytes)
        self.user_agent = user_agent
        self.opener = opener
        # Retains raw platform response bytes and SHA-256 digests
        # Maps relative endpoint or canonical path -> (raw_bytes, sha256)
        self._retained_responses: Dict[str, Tuple[bytes, str]] = {}

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_bytes: Optional[int] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Perform bounded authenticated request to GitHub API.

        Credentials are sent ONLY to endpoints under self.api_base.
        Raw response bodies are bounded by max_bytes.
        Response SHA-256 digests are retained in self._retained_responses.
        """
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            url = endpoint
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(self.api_base)
            if (parsed_url.scheme, parsed_url.netloc) != (parsed_base.scheme, parsed_base.netloc):
                raise GitHubPlatformRefusal(
                    f"Security violation: attempt to send API credentials to non-API host {parsed_url.netloc!r}"
                )
            rel_key = parsed_url.path.lstrip("/")
        else:
            rel_key = endpoint.lstrip("/")
            url = f"{self.api_base}/{rel_key}"

        if params:
            query = urllib.parse.urlencode(sorted(params.items()))
            url = f"{url}?{query}" if "?" not in url else f"{url}&{query}"

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }

        req = urllib.request.Request(url, headers=headers, method=method)
        http_opener = self.opener or urllib.request.build_opener(_NoRedirect)
        limit = max_bytes or self.max_response_bytes

        try:
            with http_opener.open(req, timeout=self.timeout_sec) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 200))
                resp_headers = dict(resp.headers)
                body = bytearray()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > limit:
                        raise ResponseBudgetExceededError(
                            f"Response for {rel_key} exceeded limit of {limit} bytes (read {len(body)})"
                        )
                raw_bytes = bytes(body)
        except urllib.error.HTTPError as err:
            status = err.code
            resp_headers = dict(err.headers) if hasattr(err, "headers") else {}
            err_body = err.read(limit) if hasattr(err, "read") else b""
            raw_bytes = bytes(err_body)
            digest = sha256_bytes(raw_bytes)
            self._retained_responses[rel_key] = (raw_bytes, digest)

            if status in (401, 403):
                raise GitHubPlatformRefusal(
                    f"GitHub API authorization error {status} for {rel_key}: {raw_bytes[:200].decode('utf-8', errors='replace')}"
                )
            if status == 404:
                raise MissingRecordError(f"GitHub record not found (404) at {rel_key}")
            raise GitHubPlatformRefusal(
                f"GitHub API HTTP error {status} for {rel_key}: {raw_bytes[:200].decode('utf-8', errors='replace')}"
            )
        except urllib.error.URLError as err:
            raise GitHubPlatformRefusal(f"GitHub API network connection error for {rel_key}: {err.reason}")

        digest = sha256_bytes(raw_bytes)
        self._retained_responses[rel_key] = (raw_bytes, digest)
        return status, resp_headers, raw_bytes

    def api_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Perform authenticated GET request and parse strict JSON."""
        _status, _headers, raw_bytes = self._request("GET", endpoint, params)
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise GitHubPlatformRefusal(f"Malformed JSON response from {endpoint}: {exc}")

    def get_retained_response_digests(self) -> Tuple[Tuple[str, str], ...]:
        """Return sorted (endpoint, sha256) pairs of retained platform responses."""
        return tuple(
            sorted(
                [(k, digest) for k, (_body, digest) in self._retained_responses.items()],
                key=lambda x: x[0],
            )
        )

    def get_paginated(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        list_key: Optional[str] = None,
        max_pages: int = DEFAULT_MAX_PAGE_COUNT,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> List[Any]:
        """Fetch all items from a paginated GitHub API endpoint within bounded limits.

        Follows 'Link: <...>; rel="next"' headers and explicit page parameters.
        Enforces max_pages bound.
        """
        all_items: List[Any] = []
        current_params = dict(params or {})
        current_params.setdefault("per_page", per_page)
        current_params.setdefault("page", 1)

        page_count = 0
        current_url = endpoint

        while True:
            page_count += 1
            if page_count > max_pages:
                raise ResponseBudgetExceededError(
                    f"Pagination limit exceeded: more than {max_pages} pages for {endpoint}"
                )

            status, headers, raw_bytes = self._request("GET", current_url, current_params)
            try:
                data = json.loads(raw_bytes.decode("utf-8"))
            except Exception as exc:
                raise GitHubPlatformRefusal(f"Malformed JSON on page {page_count} of {endpoint}: {exc}")

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                if list_key:
                    items = data.get(list_key, [])
                else:
                    list_values = [v for v in data.values() if isinstance(v, list)]
                    if len(list_values) == 1:
                        items = list_values[0]
                    else:
                        raise GitHubPlatformRefusal(
                            f"Ambiguous response object for pagination on {endpoint}, list_key required"
                        )
            else:
                raise GitHubPlatformRefusal(f"Unexpected response type {type(data).__name__} for {endpoint}")

            if not isinstance(items, list):
                raise GitHubPlatformRefusal(f"Extracted paginated items is not a list: {type(items).__name__}")

            all_items.extend(items)

            link_header = headers.get("link") or headers.get("Link", "")
            next_url = None
            if link_header:
                links = [l.strip() for l in link_header.split(",")]
                for link in links:
                    parts = link.split(";")
                    if len(parts) >= 2 and any(
                        'rel="next"' in p.strip() or "rel='next'" in p.strip() for p in parts[1:]
                    ):
                        url_part = parts[0].strip().strip("<>")
                        next_url = url_part
                        break

            if next_url:
                current_url = next_url
                current_params = {}
            else:
                effective_per_page = int(current_params.get("per_page", per_page))
                if len(items) < effective_per_page or len(items) == 0:
                    break
                current_params["page"] = int(current_params.get("page", 1)) + 1

        return all_items

    def download_artifact_zip(
        self,
        artifact_url: str,
        max_bytes: Optional[int] = None,
    ) -> bytes:
        """Download artifact archive bytes following redirects without forwarding API credentials."""
        limit = max_bytes or self.max_artifact_bytes
        try:
            raw_bytes = download_artifact_zip(
                artifact_url=artifact_url,
                token=self.token,
                timeout=self.timeout_sec,
                max_bytes=limit,
                opener=self.opener,
            )
        except ValueError as err:
            raise ResponseBudgetExceededError(str(err))
        except Exception as exc:
            raise ArtifactCustodyError(f"Failed to download artifact from {artifact_url}: {exc}")

        digest = sha256_bytes(raw_bytes)
        parsed_url = urllib.parse.urlparse(artifact_url)
        clean_key = parsed_url.path.lstrip("/")
        self._retained_responses[clean_key] = (b"", digest)
        return raw_bytes

    # Exact Platform Reads
    def get_repository(self, repo: str) -> Dict[str, Any]:
        """Fetch repository record by exact name (e.g. 'jwaldrip/iyi')."""
        clean_repo = require_ascii_str(repo, "repository")
        data = self.api_get(f"repos/{clean_repo}")
        if not isinstance(data, dict):
            raise GitHubPlatformRefusal(f"Repository {clean_repo} did not return a JSON object")
        return data

    def get_workflow_run(self, repo: str, run_id: str) -> Dict[str, Any]:
        """Fetch workflow run record by exact ID."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_run_id = require_positive_ascii_id(run_id, "run_id")
        data = self.api_get(f"repos/{clean_repo}/actions/runs/{clean_run_id}")
        if not isinstance(data, dict):
            raise GitHubPlatformRefusal(f"Run {clean_run_id} did not return a JSON object")
        return data

    def get_run_attempt(self, repo: str, run_id: str, attempt: int) -> Dict[str, Any]:
        """Fetch workflow run attempt record by exact run ID and attempt number."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_run_id = require_positive_ascii_id(run_id, "run_id")
        clean_attempt = require_int(attempt, "attempt", min_val=1)
        data = self.api_get(f"repos/{clean_repo}/actions/runs/{clean_run_id}/attempts/{clean_attempt}")
        if not isinstance(data, dict):
            raise GitHubPlatformRefusal(f"Run attempt {clean_run_id}/{clean_attempt} did not return a JSON object")
        return data

    def get_run_jobs(
        self,
        repo: str,
        run_id: str,
        attempt: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all jobs for a run attempt via bounded pagination."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_run_id = require_positive_ascii_id(run_id, "run_id")
        if attempt is not None:
            clean_attempt = require_int(attempt, "attempt", min_val=1)
            endpoint = f"repos/{clean_repo}/actions/runs/{clean_run_id}/attempts/{clean_attempt}/jobs"
        else:
            endpoint = f"repos/{clean_repo}/actions/runs/{clean_run_id}/jobs"
        return self.get_paginated(endpoint, list_key="jobs")

    def get_job(self, repo: str, job_id: str) -> Dict[str, Any]:
        """Fetch individual job record by exact ID."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_job_id = require_positive_ascii_id(job_id, "job_id")
        data = self.api_get(f"repos/{clean_repo}/actions/jobs/{clean_job_id}")
        if not isinstance(data, dict):
            raise GitHubPlatformRefusal(f"Job {clean_job_id} did not return a JSON object")
        return data

    def get_artifact(self, repo: str, artifact_id: str) -> Dict[str, Any]:
        """Fetch individual artifact metadata by exact immutable ID."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_art_id = require_positive_ascii_id(artifact_id, "artifact_id")
        data = self.api_get(f"repos/{clean_repo}/actions/artifacts/{clean_art_id}")
        if not isinstance(data, dict):
            raise GitHubPlatformRefusal(f"Artifact {clean_art_id} did not return a JSON object")
        return data

    def list_run_artifacts(self, repo: str, run_id: str) -> List[Dict[str, Any]]:
        """List all artifacts for a run via bounded pagination."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_run_id = require_positive_ascii_id(run_id, "run_id")
        return self.get_paginated(f"repos/{clean_repo}/actions/runs/{clean_run_id}/artifacts", list_key="artifacts")

    def get_run_approvals(self, repo: str, run_id: str) -> List[Dict[str, Any]]:
        """Fetch approvals history for a run via bounded pagination."""
        clean_repo = require_ascii_str(repo, "repository")
        clean_run_id = require_positive_ascii_id(run_id, "run_id")
        return self.get_paginated(f"repos/{clean_repo}/actions/runs/{clean_run_id}/approvals")


# Validation Provenance Verifier
def verify_validation_provenance(
    client: HostedGitHubClient,
    validation_ref: ValidationRef,
    subject: ExecutionSubject,
    expected_member_name: Optional[str] = None,
) -> ValidationProvenanceReceipt:
    """Verify validation run provenance, concrete job, and evidence member.

    Validates:
    1. ValidationRef referential integrity to ExecutionSubject.
    2. GitHub repository matches validation_repository.
    3. Workflow run matches validation_run_id, run_attempt, c_sha, and workflow path.
    4. Workflow run and concrete validation job status is completed and conclusion is success.
    5. No failing jobs in the validation run attempt.
    6. Artifact exists, is not expired, and belongs to the validation run.
    7. Evidence member exists in downloaded artifact zip, matches exact size and SHA-256.
    """
    validate_validation_ref_to_subject(validation_ref, subject)

    repo_data = client.get_repository(validation_ref.validation_repository)
    if repo_data.get("full_name") != validation_ref.validation_repository:
        raise GitHubPlatformRefusal(
            f"Validation repository mismatch: expected {validation_ref.validation_repository}, got {repo_data.get('full_name')}"
        )

    run_data = client.get_workflow_run(validation_ref.validation_repository, validation_ref.run_id)
    if str(run_data.get("run_attempt")) != str(validation_ref.run_attempt):
        raise GitHubPlatformRefusal(
            f"Validation run attempt mismatch: expected {validation_ref.run_attempt}, got {run_data.get('run_attempt')}"
        )
    if run_data.get("status") != "completed":
        raise GitHubPlatformRefusal(
            f"Validation run status is {run_data.get('status')!r}, expected 'completed'"
        )
    if run_data.get("conclusion") != "success":
        raise GitHubPlatformRefusal(
            f"Validation run conclusion is {run_data.get('conclusion')!r}, expected 'success'"
        )
    if run_data.get("path") != validation_ref.validation_workflow:
        raise GitHubPlatformRefusal(
            f"Validation workflow path mismatch: expected {validation_ref.validation_workflow}, got {run_data.get('path')}"
        )
    if run_data.get("head_sha") != validation_ref.validation_c_sha:
        raise GitHubPlatformRefusal(
            f"Validation head_sha mismatch: expected {validation_ref.validation_c_sha}, got {run_data.get('head_sha')}"
        )
    if run_data.get("head_sha") != subject.c_sha:
        raise GitHubPlatformRefusal(
            f"Validation head_sha mismatch with subject C: expected {subject.c_sha}, got {run_data.get('head_sha')}"
        )

    jobs = client.get_run_jobs(
        validation_ref.validation_repository,
        validation_ref.run_id,
        validation_ref.run_attempt,
    )
    matching_jobs = [j for j in jobs if str(j.get("id")) == validation_ref.job_id]
    if len(matching_jobs) == 0:
        raise MissingRecordError(
            f"Validation job ID {validation_ref.job_id} not found in run {validation_ref.run_id}"
        )
    val_job = matching_jobs[0]
    if val_job.get("conclusion") != "success":
        raise GitHubPlatformRefusal(
            f"Validation job {validation_ref.job_id} conclusion is {val_job.get('conclusion')!r}, expected 'success'"
        )

    for other_job in jobs:
        if isinstance(other_job, dict) and other_job.get("conclusion") not in ("success", "skipped"):
            raise GitHubPlatformRefusal(
                f"Validation run {validation_ref.run_id} contains non-successful job: {other_job.get('name')!r} ({other_job.get('conclusion')})"
            )

    artifact_meta = client.get_artifact(validation_ref.validation_repository, validation_ref.artifact_id)
    if artifact_meta.get("expired") is True:
        raise GitHubPlatformRefusal(f"Validation artifact {validation_ref.artifact_id} is expired")
    if str(artifact_meta.get("workflow_run", {}).get("id")) != validation_ref.run_id:
        raise GitHubPlatformRefusal(
            f"Validation artifact run ID mismatch: expected {validation_ref.run_id}, got {artifact_meta.get('workflow_run', {}).get('id')}"
        )
    if validation_ref.artifact_digest is not None and "digest" in artifact_meta:
        if artifact_meta["digest"] != validation_ref.artifact_digest:
            raise ReferenceIntegrityError(
                f"Validation artifact platform digest mismatch: expected {validation_ref.artifact_digest}, got {artifact_meta['digest']}"
            )

    archive_url = artifact_meta.get("archive_download_url") or f"{client.api_base}/repos/{validation_ref.validation_repository}/actions/artifacts/{validation_ref.artifact_id}/zip"
    archive_bytes = client.download_artifact_zip(archive_url)
    archive_sha256 = sha256_bytes(archive_bytes)

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            namelist = zf.namelist()
            if len(namelist) != len(set(namelist)):
                raise ArtifactCustodyError("Duplicate member names in validation artifact archive")
            for name in namelist:
                if name.startswith("/") or ".." in name.split("/"):
                    raise ArtifactCustodyError(f"Illegal path traversal in validation artifact member: {name}")

            matching_members: List[Tuple[str, int, str]] = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                m_bytes = zf.read(info.filename)
                m_sha = sha256_bytes(m_bytes)
                if info.file_size == validation_ref.evidence_member_size and m_sha == validation_ref.evidence_member_sha256:
                    if expected_member_name is None or info.filename == expected_member_name:
                        matching_members.append((info.filename, info.file_size, m_sha))

            if len(matching_members) == 0:
                raise ArtifactCustodyError(
                    f"Evidence member not found: expected size={validation_ref.evidence_member_size}, sha256={validation_ref.evidence_member_sha256}"
                )
            if len(matching_members) > 1 and expected_member_name is None:
                raise AmbiguousMatchError(
                    f"Ambiguous evidence member: multiple files match expected size and sha256: {[m[0] for m in matching_members]}"
                )

            matched_name, matched_size, matched_sha = matching_members[0]
    except zipfile.BadZipFile as exc:
        raise ArtifactCustodyError(f"Corrupted validation artifact archive: {exc}")

    return ValidationProvenanceReceipt(
        subject_digest=subject.digest(),
        validation_ref_digest=validation_ref.digest(),
        repository=validation_ref.validation_repository,
        run_id=validation_ref.run_id,
        run_attempt=validation_ref.run_attempt,
        job_id=validation_ref.job_id,
        artifact_id=validation_ref.artifact_id,
        artifact_name=str(artifact_meta.get("name", "")),
        artifact_size=len(archive_bytes),
        archive_sha256=archive_sha256,
        evidence_member_name=matched_name,
        evidence_member_size=matched_size,
        evidence_member_sha256=matched_sha,
        platform_response_digests=client.get_retained_response_digests(),
        verified_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# Authenticated Execution Context Readback
def read_execution_context(
    client: HostedGitHubClient,
    manifest: ProofManifest,
    concrete_job_id: Optional[str] = None,
) -> ExecutionContext:
    """Resolve authenticated ExecutionContext from GitHub platform reads.

    Validates:
    1. Workflow run matches manifest subject repository, run_id, run_attempt, workflow_path, and c_sha.
    2. Concrete job ID is positive integer decimal and reconciles to logical job_key.
    3. Rejects ambiguous multiple matching jobs or missing jobs.
    4. Runner identity is present and valid ASCII.
    5. Platform started_at timestamp is valid ISO UTC and produces float epoch.
    6. Verifies context against manifest via validate_execution_context_to_manifest.
    """
    repo = manifest.subject.repository
    run_id = manifest.subject.run_id
    run_attempt = manifest.subject.run_attempt

    run_data = client.get_workflow_run(repo, run_id)
    if str(run_data.get("run_attempt")) != str(run_attempt):
        raise GitHubPlatformRefusal(
            f"Strict run attempt mismatch: expected {run_attempt}, got {run_data.get('run_attempt')}"
        )
    if run_data.get("path") != manifest.subject.workflow_path:
        raise GitHubPlatformRefusal(
            f"Strict workflow path mismatch: expected {manifest.subject.workflow_path}, got {run_data.get('path')}"
        )
    if run_data.get("head_sha") != manifest.subject.c_sha:
        raise GitHubPlatformRefusal(
            f"Strict head_sha mismatch with subject C: expected {manifest.subject.c_sha}, got {run_data.get('head_sha')}"
        )

    jobs = client.get_run_jobs(repo, run_id, run_attempt)
    if concrete_job_id is not None:
        clean_job_id = require_positive_ascii_id(concrete_job_id, "concrete_job_id")
        matching = [j for j in jobs if str(j.get("id")) == clean_job_id]
        if len(matching) == 0:
            raise MissingRecordError(f"Concrete job ID {clean_job_id} not found in run {run_id}")
        selected_job = matching[0]
        # Ensure job matches logical key
        if selected_job.get("name") != manifest.subject.job_key and not any(
            s.get("name") == manifest.subject.job_key for s in selected_job.get("steps", [])
        ):
            raise ReferenceIntegrityError(
                f"Concrete job ID {clean_job_id} name {selected_job.get('name')!r} does not match logical job_key {manifest.subject.job_key!r}"
            )
    else:
        matching = [
            j for j in jobs
            if j.get("name") == manifest.subject.job_key
            or any(s.get("name") == manifest.subject.job_key for s in j.get("steps", []))
        ]
        if len(matching) == 0:
            raise MissingRecordError(f"No job matching logical key {manifest.subject.job_key!r} found in run {run_id}")
        if len(matching) > 1:
            raise AmbiguousMatchError(
                f"Ambiguous jobs matching logical key {manifest.subject.job_key!r}: {[j.get('id') for j in matching]}"
            )
        selected_job = matching[0]

    job_id_str = require_positive_ascii_id(selected_job.get("id"), "job_id")
    runner_identity = selected_job.get("runner_name") or (
        f"runner-{selected_job.get('runner_id')}" if selected_job.get("runner_id") else selected_job.get("runner_group_name")
    )
    if not runner_identity or not str(runner_identity).strip():
        raise GitHubPlatformRefusal(f"Platform job {job_id_str} has missing or empty runner identity")
    runner_identity_str = require_ascii_str(str(runner_identity).strip(), "runner_identity")

    started_at_raw = selected_job.get("started_at")
    if not started_at_raw:
        raise GitHubPlatformRefusal(f"Platform job {job_id_str} has no started_at timestamp")

    dt = parse_utc_iso_timestamp(started_at_raw, "job_started_at")
    epoch = float(dt.timestamp())
    iso_z = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    platform_digests = client.get_retained_response_digests()

    context = ExecutionContext(
        manifest_digest=manifest.digest(),
        subject_digest=manifest.subject.digest(),
        repository=repo,
        run_id=run_id,
        run_attempt=run_attempt,
        job_key=manifest.subject.job_key,
        job_id=job_id_str,
        runner_identity=runner_identity_str,
        job_started_at_iso=iso_z,
        job_started_at_epoch=epoch,
        platform_response_digests=platform_digests,
    )

    validate_execution_context_to_manifest(context, manifest)
    return context


# Personal Approval Verifier
def verify_personal_approval(
    client: HostedGitHubClient,
    manifest: ProofManifest,
    policy: TrustedApprovalPolicy,
    caller_supplied_approvals: Optional[Any] = None,
) -> PersonalApprovalReceipt:
    """Verify Jason's personal approval of exact manifest digest via authenticated GitHub API.

    Refuses:
    - Caller-supplied local approvals JSON (production approvals must be retrieved from API).
    - Unauthenticated, missing, rejected, or pending approvals.
    - Wrong reviewer ID, wrong environment ID, or wrong digest comment.
    - Ambiguous multiple approvals.
    - Environment rule or branch policy mismatches when enabled in policy.
    """
    if caller_supplied_approvals is not None:
        raise GitHubPlatformRefusal(
            "Security refusal: caller-supplied local approvals JSON cannot authorize execution; "
            "approvals must be retrieved from authenticated GitHub API."
        )

    repo = manifest.subject.repository
    run_id = manifest.subject.run_id

    if policy.enforce_environment_rules:
        env_data = client.api_get(f"repos/{repo}/environments/{policy.environment_name}")
        if str(env_data.get("id")) != policy.environment_id:
            raise GitHubPlatformRefusal(
                f"Environment ID mismatch: expected {policy.environment_id}, got {env_data.get('id')}"
            )
        if not policy.can_admins_bypass and env_data.get("can_admins_bypass") is not False:
            raise GitHubPlatformRefusal("Environment policy violation: can_admins_bypass must be False")

        rules = env_data.get("protection_rules", [])
        found_reviewer = False
        for rule in rules:
            if rule.get("type") == "required_reviewers":
                if not policy.allow_self_review and rule.get("prevent_self_review") is not False:
                    raise GitHubPlatformRefusal("Environment policy violation: prevent_self_review must be False")
                for rev in rule.get("reviewers", []):
                    if str(rev.get("reviewer", {}).get("id")) == policy.reviewer_id:
                        found_reviewer = True
                        break
        if not found_reviewer:
            raise GitHubPlatformRefusal(
                f"Required reviewer {policy.reviewer_id} missing from environment protection rules"
            )

    if policy.enforce_branch_policy and policy.target_branch:
        bp_data = client.api_get(f"repos/{repo}/environments/{policy.environment_name}/deployment-branch-policies")
        branches = [b.get("name") for b in bp_data.get("branch_policies", []) if isinstance(b, dict)]
        if policy.target_branch not in branches:
            raise GitHubPlatformRefusal(
                f"Branch {policy.target_branch!r} not permitted by environment deployment branch policy"
            )

    approvals = client.get_run_approvals(repo, run_id)
    expected_comment = f"{policy.required_comment_prefix}{manifest.digest()}"
    matching: List[Dict[str, Any]] = []

    for app in approvals:
        if not isinstance(app, dict):
            continue
        if app.get("state") != "approved":
            continue
        user = app.get("user", {})
        if str(user.get("id")) != policy.reviewer_id:
            continue
        if policy.reviewer_login and user.get("login") != policy.reviewer_login:
            continue

        env_ids = [str(e.get("id")) for e in app.get("environments", []) if isinstance(e, dict)]
        if "environment" in app and isinstance(app["environment"], dict):
            env_ids.append(str(app["environment"].get("id")))
        if policy.environment_id not in env_ids:
            continue

        if app.get("comment", "") != expected_comment:
            continue

        matching.append(app)

    if len(matching) == 0:
        raise GitHubPlatformRefusal(
            f"No matching personal approval found for manifest digest {manifest.digest()} in run {run_id}"
        )
    if len(matching) > 1:
        raise AmbiguousMatchError(
            f"Multiple matching approval records found ({len(matching)}) for run {run_id}"
        )

    matched = matching[0]
    app_digest = sha256_bytes(canonical_json_bytes(matched))

    return PersonalApprovalReceipt(
        manifest_digest=manifest.digest(),
        repository=repo,
        run_id=run_id,
        run_attempt=manifest.subject.run_attempt,
        environment_name=policy.environment_name,
        environment_id=policy.environment_id,
        reviewer_id=policy.reviewer_id,
        reviewer_login=policy.reviewer_login,
        comment=expected_comment,
        approval_record_digest=app_digest,
        platform_response_digests=client.get_retained_response_digests(),
        verified_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# Detached Artifact Custody Readback
def verify_detached_artifact_custody(
    client: HostedGitHubClient,
    repository: str,
    artifact_id: str,
    expected_manifest: ProofManifest,
    expected_envelope_digest: Optional[str] = None,
    max_bytes: Optional[int] = None,
) -> DetachedCustodyReceipt:
    """Readback and establish detached custody of evidence artifact by exact immutable ID.

    Validates:
    1. Artifact metadata belongs to expected run and is not expired.
    2. Downloads archive bytes following redirects without forwarding API credentials.
    3. Verifies zip integrity, absence of duplicate member names or path traversal.
    4. Computes deterministic sorted member inventory and inventory digest.
    5. Reads terminal-envelope.json and verifies envelope digest and reference to manifest digest.
    6. Enforces invariant: No artifact contains its own future artifact ID.
    7. Produces DetachedCustodyReceipt.
    """
    clean_repo = require_ascii_str(repository, "repository")
    clean_art_id = require_positive_ascii_id(artifact_id, "artifact_id")

    meta = client.get_artifact(clean_repo, clean_art_id)
    if meta.get("expired") is True:
        raise ArtifactCustodyError(f"Evidence artifact {clean_art_id} is expired")

    run_id_meta = str(meta.get("workflow_run", {}).get("id"))
    if run_id_meta != expected_manifest.subject.run_id:
        raise ArtifactCustodyError(
            f"Artifact workflow run ID mismatch: expected {expected_manifest.subject.run_id}, got {run_id_meta}"
        )

    art_name = str(meta.get("name", ""))
    download_url = meta.get("archive_download_url") or f"{client.api_base}/repos/{clean_repo}/actions/artifacts/{clean_art_id}/zip"
    archive_bytes = client.download_artifact_zip(download_url, max_bytes=max_bytes)
    archive_sha256 = sha256_bytes(archive_bytes)

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            namelist = zf.namelist()
            if len(namelist) != len(set(namelist)):
                raise ArtifactCustodyError("Duplicate member names in custody artifact archive")
            for name in namelist:
                if name.startswith("/") or ".." in name.split("/"):
                    raise ArtifactCustodyError(f"Illegal path traversal in custody artifact member: {name}")

            inventory: List[Tuple[str, int, str]] = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                m_bytes = zf.read(info.filename)
                m_sha = sha256_bytes(m_bytes)
                inventory.append((info.filename, info.file_size, m_sha))

            sorted_inventory = tuple(sorted(inventory, key=lambda x: x[0]))
            inv_digest = compute_inventory_digest(sorted_inventory)

            if "terminal-envelope.json" not in namelist:
                raise ArtifactCustodyError("terminal-envelope.json missing from evidence artifact archive")

            envelope_bytes = zf.read("terminal-envelope.json")
            env_digest = sha256_bytes(envelope_bytes)
            if expected_envelope_digest and env_digest != expected_envelope_digest:
                raise ReferenceIntegrityError(
                    f"Terminal envelope digest mismatch: expected {expected_envelope_digest}, got {env_digest}"
                )

            try:
                env_data = json.loads(envelope_bytes.decode("utf-8"))
            except Exception as exc:
                raise ArtifactCustodyError(f"Malformed JSON in terminal-envelope.json: {exc}")

            env_man = env_data.get("manifest", {})
            env_man_digest = sha256_bytes(canonical_json_bytes(env_man))
            expected_man_digest = expected_manifest.digest()
            if env_man_digest != expected_man_digest:
                raise ReferenceIntegrityError(
                    f"Terminal envelope manifest digest mismatch: expected {expected_man_digest}, got {env_man_digest}"
                )

            # Security Invariant: No artifact contains its own ID
            if clean_art_id in json.dumps(env_data):
                raise ArtifactCustodyError(
                    f"Security violation: artifact contains its own future artifact_id {clean_art_id}"
                )

    except zipfile.BadZipFile as exc:
        raise ArtifactCustodyError(f"Corrupted evidence artifact zip archive: {exc}")

    return DetachedCustodyReceipt(
        schema=SCHEMA_DETACHED_CUSTODY_V1,
        status=CUSTODY_STATUS_RETAINED,
        subject_digest=expected_manifest.subject.digest(),
        manifest_digest=expected_manifest.digest(),
        terminal_envelope_digest=env_digest,
        repository=clean_repo,
        run_id=expected_manifest.subject.run_id,
        run_attempt=expected_manifest.subject.run_attempt,
        artifact_id=clean_art_id,
        artifact_name=art_name,
        artifact_size_bytes=len(archive_bytes),
        archive_sha256=archive_sha256,
        member_inventory=sorted_inventory,
        inventory_digest=inv_digest,
        platform_response_digests=client.get_retained_response_digests(),
        verified_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# Unconditional Independent Review Refusal
def verify_independent_review(
    manifest: ProofManifest,
    caller_supplied_review: Optional[Any] = None,
) -> None:
    """Unconditionally refuse independent review verification per PlanControllerRepairs 3.1 & 3.3.

    The required cryptographic attestation identity, issuer policy, and authenticated
    transport mechanism are explicitly unimplemented and held.
    Caller-supplied review JSON is strictly refused.
    """
    if caller_supplied_review is not None:
        raise ReviewUnauthenticatedError(
            "Security refusal: caller-supplied independent review data cannot authorize execution; "
            "independent review cryptographic attestation is explicitly held and unimplemented."
        )
    enforce_independent_review_refusal()


# Explicitly Unimplemented Trust Anchors
UNIMPLEMENTED_TRUST_ANCHORS: Tuple[str, ...] = (
    "independent_reviewer_cryptographic_attestation_key_or_issuer_policy",
    "independent_reviewer_authenticated_delivery_and_verification_mechanism",
    "observer_origin_transport_kernel_mechanism",
)

# Integration API for Main Orchestrator
INTEGRATION_API: Dict[str, Any] = {
    "client_cls": HostedGitHubClient,
    "approval_policy_cls": TrustedApprovalPolicy,
    "build_production_approval_policy": build_production_approval_policy,
    "verify_validation_provenance": verify_validation_provenance,
    "read_execution_context": read_execution_context,
    "verify_personal_approval": verify_personal_approval,
    "verify_detached_artifact_custody": verify_detached_artifact_custody,
    "verify_independent_review": verify_independent_review,
    "enforce_independent_review_refusal": enforce_independent_review_refusal,
    "unimplemented_trust_anchors": UNIMPLEMENTED_TRUST_ANCHORS,
    "terminal_pending_state": CONTROLLER_TERMINAL_STATE_PENDING_CUSTODY,
    "custody_receipt_cls": DetachedCustodyReceipt,
    "validation_receipt_cls": ValidationProvenanceReceipt,
    "personal_approval_receipt_cls": PersonalApprovalReceipt,
}
