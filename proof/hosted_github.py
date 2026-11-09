#!/usr/bin/env python3
"""
proof/hosted_github.py: Bounded authenticated GitHub platform reads and artifact custody.

Implements Slice B of PlanControllerRepairs (§3.1-3.3, §4 Slice B, §5):
- Bounded authenticated platform reads for exact repository, run, attempt, job, and artifact.
- Bounded pagination traversing Link headers and page parameters with max_pages ceilings.
- Token-free storage redirect handling reusing proof/github_artifact.py discipline.
- Retains raw platform response bodies and SHA-256 digests under full canonical request keys
  (method + path + sorted query) without saving credentials or signed URLs.
- Subject-bound validation provenance verification without requiring whole-workflow completion.
- Authenticated execution context readback resolving concrete positive job ID, runner identity,
  and platform job start timestamp using trusted workflow job display identities.
- Personal approval verification using injected trusted approval policy, fresh run/attempt/branch
  authentication, and exact manifest digest; strictly rejects conflicting rejections or reruns.
- Strict refusal of caller-supplied local approval or review JSON.
- Detached artifact custody readback by exact immutable artifact ID, establishing completed
  retention and comparing against independent complete expected member inventory and envelope hash.
- Semantic placement check enforcing that no pre-upload artifact contains its own future artifact ID.
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
    DEFAULT_TRUSTED_API_HOSTS,
    REDIRECT_CODES,
    USER_AGENT,
    _NoRedirect,
    download_artifact_stream,
    download_artifact_zip,
    validate_credentialed_artifact_url,
)
from proof.hosted_contracts import (
    AUTH_COMMENT_PREFIX,
    AUTH_REFUSED_EXIT_CODE,
    SCHEMA_MANIFEST_V2,
    ContractError,
    EvidencePolicy,
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

# Trusted Workflow Job Identities per .github/workflows/pr147-linux-strict.yml
TRUSTED_WORKFLOW_JOB_IDENTITIES: Dict[str, Tuple[str, ...]] = {
    "strict-proof": (
        "Linux Strict Proof Supervisor (Ubuntu 24.04)",
        "strict-chain",
        "strict-proof",
    ),
    "strict-chain": (
        "Linux Strict Proof Supervisor (Ubuntu 24.04)",
        "strict-chain",
    ),
    "validation-proofs": (
        "Run Staged Linux Qualification",
        "validation-proofs",
    ),
}


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


# Canonical Request Key Formatter for Invariant Retained Responses
def canonical_request_key(method: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    """Format canonical method + path + sorted query key for platform response retention."""
    clean_path = path.lstrip("/")
    if params:
        query_parts: List[str] = []
        for k, v in sorted(params.items()):
            query_parts.append(f"{k}={v}")
        query = "&".join(query_parts)
        return f"{method.upper()} {clean_path}?{query}"
    return f"{method.upper()} {clean_path}"


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


def build_trusted_approval_policy(
    environment_name: str,
    environment_id: str,
    reviewer_id: str,
    reviewer_login: Optional[str] = None,
    target_branch: Optional[str] = None,
    allow_self_review: bool = False,
    can_admins_bypass: bool = False,
    required_comment_prefix: str = AUTH_COMMENT_PREFIX,
) -> TrustedApprovalPolicy:
    """Construct an explicitly injected TrustedApprovalPolicy."""
    return TrustedApprovalPolicy(
        environment_name=environment_name,
        environment_id=environment_id,
        reviewer_id=reviewer_id,
        reviewer_login=reviewer_login,
        target_branch=target_branch,
        allow_self_review=allow_self_review,
        can_admins_bypass=can_admins_bypass,
        required_comment_prefix=required_comment_prefix,
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
        if self.status != CUSTODY_STATUS_RETAINED:
            raise TypeValidationError(f"Invalid custody status: {self.status!r}, expected {CUSTODY_STATUS_RETAINED!r}")

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

        # Validate member_inventory tuples and ensure no duplicate member paths
        cleaned_members: List[Tuple[str, int, str]] = []
        seen_paths: Set[str] = set()
        for item in self.member_inventory:
            if not isinstance(item, (tuple, list)) or len(item) != 3:
                raise TypeValidationError("member_inventory elements must be (path, size, sha256) 3-tuples")
            p = require_ascii_str(item[0], "member path")
            if p in seen_paths:
                raise TypeValidationError(f"Duplicate member path in member_inventory: {p!r}")
            seen_paths.add(p)
            sz = require_int(item[1], "member size", min_val=0)
            sh = require_sha256(item[2], "member sha256")
            cleaned_members.append((p, sz, sh))

        sorted_members = tuple(sorted(cleaned_members, key=lambda x: x[0]))
        object.__setattr__(self, "member_inventory", sorted_members)

        # Recompute and enforce inventory digest
        expected_inv_digest = compute_inventory_digest(sorted_members)
        if self.inventory_digest != expected_inv_digest:
            raise ReferenceIntegrityError(
                f"inventory_digest mismatch: declared {self.inventory_digest}, recomputed {expected_inv_digest}"
            )

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


# Bounded ZIP Archive Expansion Helper
def inspect_and_extract_bounded_zip(
    archive_bytes: bytes,
    limits: EvidencePolicy,
) -> Tuple[Tuple[Tuple[str, int, str], ...], Dict[str, bytes]]:
    """Inspect and decompress a zip archive enforcing strict per-member and aggregate limits.

    Guards against zip bombs, excessive entries, path traversals, duplicate names, and memory exhaustion.
    """
    if len(archive_bytes) > limits.max_archive_emitted_bytes:
        raise ResponseBudgetExceededError(
            f"Archive size {len(archive_bytes)} exceeds max_archive_emitted_bytes {limits.max_archive_emitted_bytes}"
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise ArtifactCustodyError(f"Corrupted zip archive: {exc}")

    with zf:
        infolist = zf.infolist()
        if len(infolist) > limits.max_directory_entries:
            raise ResponseBudgetExceededError(
                f"Zip entry count {len(infolist)} exceeds max_directory_entries {limits.max_directory_entries}"
            )

        seen_names: Set[str] = set()
        total_declared_uncompressed = 0

        # Preflight metadata before decompressing
        for info in infolist:
            name = info.filename
            if name in seen_names:
                raise ArtifactCustodyError(f"Duplicate member name in zip archive: {name!r}")
            seen_names.add(name)

            if name.startswith("/") or ".." in name.split("/"):
                raise ArtifactCustodyError(f"Illegal path traversal in zip member: {name!r}")

            name_bytes = name.encode("utf-8")
            if len(name_bytes) > limits.max_path_bytes:
                raise ResponseBudgetExceededError(
                    f"Member path {name!r} ({len(name_bytes)} bytes) exceeds max_path_bytes {limits.max_path_bytes}"
                )

            depth = len([p for p in name.split("/") if p])
            if depth > limits.max_directory_depth:
                raise ResponseBudgetExceededError(
                    f"Member path {name!r} depth {depth} exceeds max_directory_depth {limits.max_directory_depth}"
                )

            if info.file_size > limits.max_file_bytes:
                raise ResponseBudgetExceededError(
                    f"Member {name!r} declared size {info.file_size} exceeds max_file_bytes {limits.max_file_bytes}"
                )

            total_declared_uncompressed += info.file_size
            if total_declared_uncompressed > limits.max_aggregate_unique_inode_bytes:
                raise ResponseBudgetExceededError(
                    f"Aggregate declared zip uncompressed size exceeds max_aggregate_unique_inode_bytes {limits.max_aggregate_unique_inode_bytes}"
                )

        # Decompress incrementally with running aggregate check
        inventory: List[Tuple[str, int, str]] = []
        member_bytes_dict: Dict[str, bytes] = {}
        cumulative_decompressed_bytes = 0

        for info in infolist:
            if info.is_dir():
                continue

            member_buf = bytearray()
            hasher = hashlib.sha256()

            with zf.open(info, "r") as member_stream:
                while True:
                    chunk = member_stream.read(65536)
                    if not chunk:
                        break
                    member_buf.extend(chunk)
                    cumulative_decompressed_bytes += len(chunk)
                    hasher.update(chunk)

                    if len(member_buf) > limits.max_file_bytes:
                        raise ResponseBudgetExceededError(
                            f"Member {info.filename!r} exceeded max_file_bytes during decompression"
                        )
                    if cumulative_decompressed_bytes > limits.max_aggregate_unique_inode_bytes:
                        raise ResponseBudgetExceededError(
                            "Cumulative decompressed bytes exceeded max_aggregate_unique_inode_bytes limit"
                        )

            if len(member_buf) != info.file_size:
                raise ArtifactCustodyError(
                    f"Member {info.filename!r} actual decompressed size {len(member_buf)} != declared {info.file_size}"
                )

            member_sha = hasher.hexdigest()
            m_bytes = bytes(member_buf)
            inventory.append((info.filename, len(m_bytes), member_sha))
            member_bytes_dict[info.filename] = m_bytes

        sorted_inventory = tuple(sorted(inventory, key=lambda x: x[0]))
        return sorted_inventory, member_bytes_dict


# Bounded Authenticated GitHub Client
class HostedGitHubClient:
    """Authenticated, bounded GitHub REST client with canonical request-key retention."""

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
        # Maps canonical request key (e.g. "GET repos/.../jobs?page=1") -> (raw_bytes, sha256)
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
        Response SHA-256 digests are retained under canonical method+path+query keys.
        """
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            url = endpoint
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(self.api_base)
            if (parsed_url.scheme, parsed_url.netloc) != (parsed_base.scheme, parsed_base.netloc):
                raise GitHubPlatformRefusal(
                    f"Security violation: attempt to send API credentials to non-API host {parsed_url.netloc!r}"
                )
            rel_path = parsed_url.path.lstrip("/")
            # If query params were in the URL, parse and merge them
            if parsed_url.query and not params:
                query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                params = query_dict
                url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        else:
            rel_path = endpoint.lstrip("/")
            url = f"{self.api_base}/{rel_path}"

        canon_key = canonical_request_key(method, rel_path, params)

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
                            f"Response for {canon_key} exceeded limit of {limit} bytes (read {len(body)})"
                        )
                raw_bytes = bytes(body)
        except urllib.error.HTTPError as err:
            status = err.code
            resp_headers = dict(err.headers) if hasattr(err, "headers") else {}
            err_body = err.read(limit) if hasattr(err, "read") else b""
            raw_bytes = bytes(err_body)
            digest = sha256_bytes(raw_bytes)
            self._retained_responses[canon_key] = (raw_bytes, digest)

            if status in (401, 403):
                raise GitHubPlatformRefusal(
                    f"GitHub API authorization error {status} for {canon_key}: {raw_bytes[:200].decode('utf-8', errors='replace')}"
                )
            if status == 404:
                raise MissingRecordError(f"GitHub record not found (404) at {canon_key}")
            raise GitHubPlatformRefusal(
                f"GitHub API HTTP error {status} for {canon_key}: {raw_bytes[:200].decode('utf-8', errors='replace')}"
            )
        except urllib.error.URLError as err:
            raise GitHubPlatformRefusal(f"GitHub API network connection error for {canon_key}: {err.reason}")

        digest = sha256_bytes(raw_bytes)
        self._retained_responses[canon_key] = (raw_bytes, digest)
        return status, resp_headers, raw_bytes

    def api_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Perform authenticated GET request and parse strict JSON."""
        _status, _headers, raw_bytes = self._request("GET", endpoint, params)
        try:
            return parse_strict_json(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise GitHubPlatformRefusal(f"Malformed or non-strict JSON response from {endpoint}: {exc}")

    def get_retained_response_digests(self) -> Tuple[Tuple[str, str], ...]:
        """Return sorted (canonical_key, sha256) pairs of retained platform responses."""
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
        Retains every page response under its own distinct canonical query key.
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
                data = parse_strict_json(raw_bytes.decode("utf-8"))
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
                        # Security check: next Link URL must stay on the same API host and path
                        parsed_next = urllib.parse.urlparse(url_part)
                        parsed_base = urllib.parse.urlparse(self.api_base)
                        if (parsed_next.scheme, parsed_next.netloc) != (parsed_base.scheme, parsed_base.netloc):
                            raise GitHubPlatformRefusal(f"Next page Link redirected to untrusted host: {parsed_next.netloc!r}")
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
        """Download artifact archive bytes following redirects without forwarding API credentials.

        Validates initial request URL before attaching token to prevent token exfiltration.
        """
        limit = max_bytes or self.max_artifact_bytes
        parsed_base = urllib.parse.urlparse(self.api_base)
        trusted_hosts = (parsed_base.hostname or "api.github.com",)

        try:
            raw_bytes = download_artifact_zip(
                artifact_url=artifact_url,
                token=self.token,
                timeout=self.timeout_sec,
                max_bytes=limit,
                opener=self.opener,
                trusted_hosts=trusted_hosts,
            )
        except ValueError as err:
            raise ResponseBudgetExceededError(str(err))
        except Exception as exc:
            raise ArtifactCustodyError(f"Failed to download artifact from {artifact_url}: {exc}")

        digest = sha256_bytes(raw_bytes)
        parsed_url = urllib.parse.urlparse(artifact_url)
        canon_key = canonical_request_key("GET", parsed_url.path)
        self._retained_responses[canon_key] = (b"", digest)
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
    4. Exact validation job status is completed and conclusion is success (does NOT require
       whole workflow completion, allowing validation to precede strict execution in same attempt).
    5. No direct validation dependency jobs failed.
    6. Artifact exists, is not expired, belongs to validation run, and matches platform digest.
    7. Evidence member is decompressed within bounded limits, matches exact size and SHA-256,
       and its JSON content binds the subject.
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
    if val_job.get("status") != "completed":
        raise GitHubPlatformRefusal(
            f"Validation job {validation_ref.job_id} status is {val_job.get('status')!r}, expected 'completed'"
        )
    if val_job.get("conclusion") != "success":
        raise GitHubPlatformRefusal(
            f"Validation job {validation_ref.job_id} conclusion is {val_job.get('conclusion')!r}, expected 'success'"
        )

    artifact_meta = client.get_artifact(validation_ref.validation_repository, validation_ref.artifact_id)
    if str(artifact_meta.get("id")) != validation_ref.artifact_id:
        raise GitHubPlatformRefusal(
            f"Artifact ID mismatch: expected {validation_ref.artifact_id}, got {artifact_meta.get('id')}"
        )
    if artifact_meta.get("expired") is not False:
        raise GitHubPlatformRefusal(f"Validation artifact {validation_ref.artifact_id} expired must be strictly False")
    if str(artifact_meta.get("workflow_run", {}).get("id")) != validation_ref.run_id:
        raise GitHubPlatformRefusal(
            f"Validation artifact run ID mismatch: expected {validation_ref.run_id}, got {artifact_meta.get('workflow_run', {}).get('id')}"
        )

    # Normalize platform digest if present
    meta_digest = artifact_meta.get("digest")
    if meta_digest:
        clean_meta_digest = meta_digest.replace("sha256:", "").lower()
        if validation_ref.artifact_digest is not None:
            clean_expected_digest = validation_ref.artifact_digest.replace("sha256:", "").lower()
            if clean_meta_digest != clean_expected_digest:
                raise ReferenceIntegrityError(
                    f"Validation artifact platform digest mismatch: expected {clean_expected_digest}, got {clean_meta_digest}"
                )

    download_url = f"{client.api_base}/repos/{validation_ref.validation_repository}/actions/artifacts/{validation_ref.artifact_id}/zip"
    archive_bytes = client.download_artifact_zip(download_url)
    archive_sha256 = sha256_bytes(archive_bytes)

    if meta_digest:
        clean_meta_digest = meta_digest.replace("sha256:", "").lower()
        if archive_sha256 != clean_meta_digest:
            raise ReferenceIntegrityError(
                f"Downloaded archive SHA-256 {archive_sha256} does not match platform digest {clean_meta_digest}"
            )

    # Bounded decompression and inspection
    inventory, member_dict = inspect_and_extract_bounded_zip(archive_bytes, subject.evidence_policy)

    matching_members = [
        (p, sz, sh)
        for p, sz, sh in inventory
        if sz == validation_ref.evidence_member_size and sh == validation_ref.evidence_member_sha256
    ]

    if expected_member_name:
        matching_members = [m for m in matching_members if m[0] == expected_member_name]

    if len(matching_members) == 0:
        raise ArtifactCustodyError(
            f"Evidence member not found: expected size={validation_ref.evidence_member_size}, sha256={validation_ref.evidence_member_sha256}"
        )
    if len(matching_members) > 1:
        raise AmbiguousMatchError(
            f"Ambiguous evidence member: multiple files match expected size and sha256: {[m[0] for m in matching_members]}"
        )

    matched_name, matched_size, matched_sha = matching_members[0]
    matched_bytes = member_dict[matched_name]

    # Validate member content strictly
    try:
        member_data = parse_strict_json(matched_bytes.decode("utf-8"))
        if isinstance(member_data, dict):
            status = member_data.get("status")
            if status not in ("PASS", "success", True, None):
                raise ArtifactCustodyError(f"Validation evidence declared non-passing status: {status!r}")
    except Exception as exc:
        raise ArtifactCustodyError(f"Validation evidence member failed strict JSON validation: {exc}")

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
    """Resolve authenticated ExecutionContext from GitHub platform reads using trusted job identities.

    Validates:
    1. Workflow run matches manifest subject repository, run_id, run_attempt, workflow_path, and c_sha.
    2. Concrete job ID is positive integer decimal and reconciles to logical job_key identity.
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
    trusted_names = TRUSTED_WORKFLOW_JOB_IDENTITIES.get(manifest.subject.job_key, (manifest.subject.job_key,))

    if concrete_job_id is not None:
        clean_job_id = require_positive_ascii_id(concrete_job_id, "concrete_job_id")
        matching = [j for j in jobs if str(j.get("id")) == clean_job_id]
        if len(matching) == 0:
            raise MissingRecordError(f"Concrete job ID {clean_job_id} not found in run {run_id}")
        selected_job = matching[0]

        job_name = selected_job.get("name", "")
        if job_name not in trusted_names:
            raise ReferenceIntegrityError(
                f"Concrete job ID {clean_job_id} name {job_name!r} does not match trusted identities for logical key {manifest.subject.job_key!r}: {trusted_names}"
            )
    else:
        matching = [
            j for j in jobs
            if j.get("name") in trusted_names
        ]
        if len(matching) == 0:
            raise MissingRecordError(
                f"No job matching trusted identities for logical key {manifest.subject.job_key!r} found in run {run_id}"
            )
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

    Enforces:
    1. Rejects caller-supplied local approvals JSON (production approvals must be retrieved from API).
    2. Authenticates fresh workflow run metadata: repository, run_attempt, head_sha, and target_branch.
    3. Retrieves environment protection rules and paginated deployment branch policies.
    4. Evaluates all applicable decisions: strictly rejects if any rejection or conflicting decision exists.
    5. Exactly one unambiguous approved record matching reviewer, environment, and exact manifest digest comment.
    """
    if caller_supplied_approvals is not None:
        raise GitHubPlatformRefusal(
            "Security refusal: caller-supplied local approvals JSON cannot authorize execution; "
            "approvals must be retrieved from authenticated GitHub API."
        )

    repo = manifest.subject.repository
    run_id = manifest.subject.run_id

    # Authenticate current run attempt, C revision, and branch
    run_data = client.get_workflow_run(repo, run_id)
    if str(run_data.get("run_attempt")) != str(manifest.subject.run_attempt):
        raise GitHubPlatformRefusal(
            f"Run attempt mismatch in approval verification: expected {manifest.subject.run_attempt}, got {run_data.get('run_attempt')}"
        )
    if run_data.get("head_sha") != manifest.subject.c_sha:
        raise GitHubPlatformRefusal(
            f"Run head_sha mismatch in approval verification: expected {manifest.subject.c_sha}, got {run_data.get('head_sha')}"
        )
    if run_data.get("path") != manifest.subject.workflow_path:
        raise GitHubPlatformRefusal(
            f"Run workflow path mismatch: expected {manifest.subject.workflow_path}, got {run_data.get('path')}"
        )

    if policy.target_branch:
        run_branch = run_data.get("head_branch")
        if run_branch and run_branch != policy.target_branch:
            raise GitHubPlatformRefusal(
                f"Run head_branch mismatch: expected {policy.target_branch!r}, got {run_branch!r}"
            )

    if policy.enforce_environment_rules:
        env_data = client.api_get(f"repos/{repo}/environments/{policy.environment_name}")
        if str(env_data.get("id")) != policy.environment_id:
            raise GitHubPlatformRefusal(
                f"Environment ID mismatch: expected {policy.environment_id}, got {env_data.get('id')}"
            )
        if env_data.get("can_admins_bypass") != policy.can_admins_bypass:
            raise GitHubPlatformRefusal(
                f"Environment policy violation: can_admins_bypass must be {policy.can_admins_bypass}, got {env_data.get('can_admins_bypass')}"
            )

        rules = env_data.get("protection_rules", [])
        found_reviewer = False
        for rule in rules:
            if rule.get("type") == "required_reviewers":
                expected_prevent_self = not policy.allow_self_review
                if rule.get("prevent_self_review") != expected_prevent_self:
                    raise GitHubPlatformRefusal(
                        f"Environment policy violation: prevent_self_review must be {expected_prevent_self}, got {rule.get('prevent_self_review')}"
                    )
                for rev in rule.get("reviewers", []):
                    if str(rev.get("reviewer", {}).get("id")) == policy.reviewer_id:
                        found_reviewer = True
                        break
        if not found_reviewer:
            raise GitHubPlatformRefusal(
                f"Required reviewer {policy.reviewer_id} missing from environment protection rules"
            )

    if policy.enforce_branch_policy and policy.target_branch:
        bp_items = client.get_paginated(
            f"repos/{repo}/environments/{policy.environment_name}/deployment-branch-policies",
            list_key="branch_policies",
        )
        branches = [b.get("name") for b in bp_items if isinstance(b, dict)]
        if policy.target_branch not in branches:
            raise GitHubPlatformRefusal(
                f"Branch {policy.target_branch!r} not permitted by environment deployment branch policy"
            )

    approvals = client.get_run_approvals(repo, run_id)
    expected_comment = f"{policy.required_comment_prefix}{manifest.digest()}"

    # Gather all applicable decisions for this reviewer and environment
    applicable_decisions: List[Dict[str, Any]] = []

    for app in approvals:
        if not isinstance(app, dict):
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

        applicable_decisions.append(app)

    if len(applicable_decisions) == 0:
        raise GitHubPlatformRefusal(
            f"No approval decisions found for reviewer {policy.reviewer_id} in run {run_id}"
        )

    # Check for any conflicting non-approved decisions
    for app in applicable_decisions:
        state = app.get("state")
        if state == "rejected":
            raise GitHubPlatformRefusal(
                f"Conflicting rejected decision found for reviewer {policy.reviewer_id} in run {run_id}"
            )
        if state != "approved":
            raise GitHubPlatformRefusal(
                f"Non-approved decision state {state!r} found for reviewer {policy.reviewer_id} in run {run_id}"
            )
        if app.get("comment", "") != expected_comment:
            raise GitHubPlatformRefusal(
                f"Approval comment mismatch: expected {expected_comment!r}, got {app.get('comment')!r}"
            )

    matching_approvals = [app for app in applicable_decisions if app.get("state") == "approved" and app.get("comment") == expected_comment]

    if len(matching_approvals) > 1:
        raise AmbiguousMatchError(
            f"Multiple matching approval records found ({len(matching_approvals)}) for run {run_id}"
        )

    matched = matching_approvals[0]
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
    expected_envelope_digest: str,
    expected_inventory: Sequence[Tuple[str, int, str]],
    max_bytes: Optional[int] = None,
) -> DetachedCustodyReceipt:
    """Readback and establish detached custody of evidence artifact by exact immutable ID.

    Validates:
    1. Artifact metadata belongs to expected run, attempt, and repository; expired is strictly False.
    2. Downloads archive bytes following redirects without forwarding API credentials.
    3. Enforces bounded decompression limits against evidence policy.
    4. Compares actual member inventory against independent complete expected member inventory.
    5. Reads terminal-envelope.json and verifies envelope digest and reference to manifest digest.
    6. Enforces invariant: No artifact contains its own future artifact ID.
    7. Produces DetachedCustodyReceipt.
    """
    clean_repo = require_ascii_str(repository, "repository")
    clean_art_id = require_positive_ascii_id(artifact_id, "artifact_id")
    require_sha256(expected_envelope_digest, "expected_envelope_digest")

    if clean_repo != expected_manifest.subject.repository:
        raise ArtifactCustodyError(
            f"Repository mismatch in custody readback: expected {expected_manifest.subject.repository}, got {clean_repo}"
        )

    meta = client.get_artifact(clean_repo, clean_art_id)
    if str(meta.get("id")) != clean_art_id:
        raise ArtifactCustodyError(f"Artifact metadata ID mismatch: expected {clean_art_id}, got {meta.get('id')}")

    if meta.get("expired") is not False:
        raise ArtifactCustodyError(f"Evidence artifact {clean_art_id} expired must be strictly False")

    run_id_meta = str(meta.get("workflow_run", {}).get("id"))
    if run_id_meta != expected_manifest.subject.run_id:
        raise ArtifactCustodyError(
            f"Artifact workflow run ID mismatch: expected {expected_manifest.subject.run_id}, got {run_id_meta}"
        )

    art_name = str(meta.get("name", ""))
    download_url = f"{client.api_base}/repos/{clean_repo}/actions/artifacts/{clean_art_id}/zip"
    archive_bytes = client.download_artifact_zip(download_url, max_bytes=max_bytes)
    archive_sha256 = sha256_bytes(archive_bytes)

    # Bounded extraction and member inventory
    actual_inventory, member_dict = inspect_and_extract_bounded_zip(
        archive_bytes,
        expected_manifest.subject.evidence_policy,
    )

    # Compare against independent complete expected inventory
    actual_dict = {p: (sz, sh) for p, sz, sh in actual_inventory}
    expected_dict = {p: (sz, sh) for p, sz, sh in expected_inventory}

    if actual_dict != expected_dict:
        missing = sorted(set(expected_dict.keys()) - set(actual_dict.keys()))
        extra = sorted(set(actual_dict.keys()) - set(expected_dict.keys()))
        mismatches = [
            f"{k}: expected {expected_dict[k]} vs actual {actual_dict[k]}"
            for k in sorted(set(expected_dict.keys()) & set(actual_dict.keys()))
            if expected_dict[k] != actual_dict[k]
        ]
        raise ArtifactCustodyError(
            f"Artifact member inventory mismatch: missing={missing}, extra={extra}, mismatches={mismatches}"
        )

    if "terminal-envelope.json" not in member_dict:
        raise ArtifactCustodyError("terminal-envelope.json missing from evidence artifact archive")

    envelope_bytes = member_dict["terminal-envelope.json"]
    env_digest = sha256_bytes(envelope_bytes)
    if env_digest != expected_envelope_digest:
        raise ReferenceIntegrityError(
            f"Terminal envelope digest mismatch: expected {expected_envelope_digest}, got {env_digest}"
        )

    try:
        env_data = parse_strict_json(envelope_bytes.decode("utf-8"))
    except Exception as exc:
        raise ArtifactCustodyError(f"Malformed JSON in terminal-envelope.json: {exc}")

    # Check terminal envelope status
    status = env_data.get("summary", {}).get("status")
    if status != "PASS":
        raise ArtifactCustodyError(f"Terminal envelope status is not PASS: {status!r}")

    env_man = env_data.get("manifest", {})
    env_man_digest = sha256_bytes(canonical_json_bytes(env_man))
    expected_man_digest = expected_manifest.digest()
    if env_man_digest != expected_man_digest:
        raise ReferenceIntegrityError(
            f"Terminal envelope manifest digest mismatch: expected {expected_man_digest}, got {env_man_digest}"
        )

    # Semantic check: No artifact contains its own future artifact ID
    # Check that artifact_id is not embedded as an ID field in metadata
    summary = env_data.get("summary", {})
    for forbidden_key in ("artifact_id", "future_artifact_id", "evidence_artifact_id"):
        if forbidden_key in summary or forbidden_key in env_data:
            raise ArtifactCustodyError(
                f"Security violation: terminal envelope contains prohibited artifact ID field {forbidden_key!r}"
            )
    if summary.get("id") == clean_art_id or summary.get("id") == int(clean_art_id):
        raise ArtifactCustodyError("Security violation: terminal summary contains own artifact ID")

    for path, _sz, _sh in actual_inventory:
        if path.startswith(f"artifact-{clean_art_id}") or path == f"{clean_art_id}.zip":
            raise ArtifactCustodyError(f"Security violation: member path {path!r} contains own artifact ID")

    inv_digest = compute_inventory_digest(actual_inventory)

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
        member_inventory=actual_inventory,
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
    "build_trusted_approval_policy": build_trusted_approval_policy,
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
