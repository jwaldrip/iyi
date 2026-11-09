#!/usr/bin/env python3
"""Fail-closed authenticated API-backed strict-proof authorization verifier.

This module implements the minimal shared strict authorization verifier per
PlanRepairStrictBoundary (§3.A, §3.B) addressing all auditor P1/P2 findings:
  - Canonical manifest schema: "iyi-strict-manifest-v2"
  - Exactly one human approval authority: Jason Waldrip (user ID 43164)
    approving environment 'strict-proof' (ID 26584191206) with exact comment
    "iyi-strict-authorization-v2 sha256:<D>" on run attempt 1.
  - Substantive independent audit report E (regular Git blob) with verdict GO,
    binding reviewed sources P, W, C and validation evidence V.
  - Complete pagination enumeration with advertised total_count verification.
  - Pinned official GitHub origin; artifact storage redirects followed without
    token leakage.
  - Live upstream PR147 check on 'iyilang/iyi' repository (fails closed on error).
  - Exact source tuple verification: HEAD commits, working tree cleanliness,
    W ancestry from P, and full non-proof tree equality.
  - Fail-closed: returns exit code 5 on any refusal before native effects.
  - No fake native runner commands or caller-supplied AUTHORIZED bypasses.
  - run-native is left fail-closed pending integrated supervisor local backend.
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
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Pinned immutable repository, environment, and workflow trust anchors
PINNED_REPOSITORY = "jwaldrip/iyi"
PINNED_REPOSITORY_ID = "1340355933"
UPSTREAM_PR_REPOSITORY = "iyilang/iyi"
UPSTREAM_PR_NUMBER = 147
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
USER_AGENT = "iyi-strict-independent-readback/2.0"


class AuthorizationError(ValueError):
    """Raised when authorization inputs or parameters are malformed."""
    pass


class StrictAuthorizationRefused(RuntimeError):
    """Raised when strict authorization verification fails closed."""
    def __init__(self, message: str, exit_code: int = AUTH_REFUSED_EXIT_CODE):
        super().__init__(message)
        self.exit_code = exit_code


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


def parse_json_no_duplicate_keys(raw: bytes | str) -> Any:
    """Parse JSON bytes or string, rejecting duplicate keys at any depth."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw

    def _dict_no_duplicates(pairs):
        res = {}
        for key, value in pairs:
            if key in res:
                raise StrictAuthorizationRefused(f"Duplicate key in JSON: {key!r}")
            res[key] = value
        return res

    try:
        return json.loads(text, object_pairs_hook=_dict_no_duplicates)
    except StrictAuthorizationRefused:
        raise
    except Exception as exc:
        raise StrictAuthorizationRefused(f"Malformed JSON: {exc}")


def git_cmd(args: List[str], cwd: Optional[str] = None) -> str:
    """Run git command and return stripped stdout or raise StrictAuthorizationRefused."""
    cmd = ["git"] + args
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    except FileNotFoundError:
        raise StrictAuthorizationRefused("git command not found on system")
    except Exception as exc:
        raise StrictAuthorizationRefused(f"Failed to execute git command: {exc}")
    if res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise StrictAuthorizationRefused(f"Git command failed: {' '.join(cmd)}: {err}")
    return res.stdout.strip()


def git_cmd_bytes(args: List[str], cwd: Optional[str] = None) -> bytes:
    """Run git command and return raw stdout bytes or raise StrictAuthorizationRefused."""
    cmd = ["git"] + args
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True)
    except FileNotFoundError:
        raise StrictAuthorizationRefused("git command not found on system")
    except Exception as exc:
        raise StrictAuthorizationRefused(f"Failed to execute git command: {exc}")
    if res.returncode != 0:
        err = res.stderr.decode("utf-8", errors="replace").strip()
        raise StrictAuthorizationRefused(f"Git command failed: {' '.join(cmd)}: {err}")
    return res.stdout


def git_rev_parse(ref: str, cwd: Optional[str] = None) -> str:
    return git_cmd(["rev-parse", ref], cwd=cwd)


def git_is_clean(cwd: Optional[str] = None) -> bool:
    out = git_cmd(["status", "--porcelain"], cwd=cwd)
    return len(out.strip()) == 0


def git_is_ancestor(ancestor: str, descendant: str, cwd: Optional[str] = None) -> bool:
    try:
        res = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise StrictAuthorizationRefused("git command not found on system")
    return res.returncode == 0


def git_diff_non_proof_clean(p_sha: str, w_sha: str, cwd: Optional[str] = None) -> bool:
    """Check that all differences between P and W are within proof/."""
    try:
        res_names = subprocess.run(
            ["git", "diff", "--name-only", f"{p_sha}..{w_sha}"],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise StrictAuthorizationRefused("git command not found on system")
    if res_names.returncode != 0:
        err = res_names.stderr.strip()
        raise StrictAuthorizationRefused(f"Git diff failed between P ({p_sha}) and W ({w_sha}): {err}")
    diff_files = [line.strip() for line in res_names.stdout.splitlines() if line.strip()]
    non_proof = [f for f in diff_files if not f.startswith("proof/")]
    if non_proof:
        raise StrictAuthorizationRefused(f"Product trees differ between P ({p_sha}) and W ({w_sha}): non-proof paths={non_proof}")
    res_quiet = subprocess.run(
        ["git", "diff", "--exit-code", p_sha, w_sha, "--", ".", ":(exclude)proof"],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if res_quiet.returncode != 0:
        raise StrictAuthorizationRefused(f"Product trees differ between P ({p_sha}) and W ({w_sha}) outside proof/")
    return True


def read_manifest_package(path: str) -> Tuple[bytes, Dict[str, Any], str]:
    """Read manifest from raw JSON or ZIP archive.

    Returns (exact_manifest_bytes, parsed_dict, digest_D).
    Enforces:
    - In ZIP package: exactly one member 'manifest.json', no duplicate member names,
      no directory traversal or absolute member paths.
    - No duplicate JSON keys.
    - Exact bytes match canonical JSON serialization.
    - D is SHA-256 of exact bytes.
    """
    if not os.path.exists(path):
        raise StrictAuthorizationRefused(f"Manifest path does not exist: {path}")

    if path.endswith(".zip") or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as zf:
                infolist = zf.infolist()
                namelist = [info.filename for info in infolist]
                if len(namelist) != len(set(namelist)):
                    raise StrictAuthorizationRefused("Duplicate ZIP member names in manifest package")
                for name in namelist:
                    if name.startswith("/") or name.startswith("\\"):
                        raise StrictAuthorizationRefused(f"Absolute path in ZIP member: {name}")
                    parts = name.replace("\\", "/").split("/")
                    if any(p in (".", "..") for p in parts):
                        raise StrictAuthorizationRefused(f"Path traversal in ZIP member: {name}")
                if "manifest.json" not in namelist:
                    raise StrictAuthorizationRefused("manifest.json missing from manifest package")
                if len(namelist) != 1 or namelist != ["manifest.json"]:
                    raise StrictAuthorizationRefused(f"Ambiguous or extra members in manifest package: {namelist}")
                raw_bytes = zf.read("manifest.json")
        except zipfile.BadZipFile as exc:
            raise StrictAuthorizationRefused(f"Corrupted zip archive for manifest: {exc}")
        except StrictAuthorizationRefused:
            raise
        except Exception as exc:
            raise StrictAuthorizationRefused(f"Corrupted zip archive for manifest: {exc}")
    else:
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read()
        except Exception as exc:
            raise StrictAuthorizationRefused(f"Failed to read manifest file: {exc}")

    parsed = parse_json_no_duplicate_keys(raw_bytes)
    if not isinstance(parsed, dict):
        raise StrictAuthorizationRefused("Manifest JSON must be an object")

    canonical_bytes = canonical_json(parsed)
    if raw_bytes != canonical_bytes:
        raise StrictAuthorizationRefused(
            "Manifest bytes do not match canonical JSON representation (non-canonical whitespace or formatting)"
        )

    digest = compute_digest(raw_bytes)
    return raw_bytes, parsed, digest


def validate_substantive_review_report(
    report_data: Any,
    p_sha: str,
    w_sha: str,
    c_sha: str,
    v_run_id: str,
) -> None:
    """Validate that review report E is a substantive GO verdict binding P, W, C, and V."""
    if not isinstance(report_data, dict):
        raise StrictAuthorizationRefused("Review report must be a JSON object")

    verdict = report_data.get("verdict")
    if not verdict and isinstance(report_data.get("report"), dict):
        verdict = report_data["report"].get("verdict")

    if verdict != "GO":
        raise StrictAuthorizationRefused(f"Independent review verdict must be GO, got: {verdict!r}")

    # Ensure no contradictory NO-GO verdict exists in the report
    report_str = json.dumps(report_data)
    if '"NO-GO"' in report_str or '"REJECTED"' in report_str:
        raise StrictAuthorizationRefused("Independent review contains contradictory NO-GO verdict")

    # Verify substantive references to P, W, C, and V
    if p_sha not in report_str:
        raise StrictAuthorizationRefused(f"Independent review report does not reference P ({p_sha})")
    if w_sha not in report_str:
        raise StrictAuthorizationRefused(f"Independent review report does not reference W ({w_sha})")
    if c_sha not in report_str:
        raise StrictAuthorizationRefused(f"Independent review report does not reference C ({c_sha})")
    if str(v_run_id) not in report_str:
        raise StrictAuthorizationRefused(f"Independent review report does not reference V run {v_run_id}")


def create_manifest(
    p_sha: str,
    w_sha: str,
    c_sha: str,
    s_run_id: str,
    s_run_attempt: int,
    workflow_path: str,
    v_run_id: str,
    v_artifacts: List[Dict[str, Any]],
    review_commit: str,
    review_path: str = "proof/review_evidence.json",
    review_blob_sha: Optional[str] = None,
    review_sha256: Optional[str] = None,
    review_verdict: str = "GO",
    repository: str = PINNED_REPOSITORY,
    upstream_pr_repo: str = UPSTREAM_PR_REPOSITORY,
    upstream_pr_number: int = UPSTREAM_PR_NUMBER,
    execution_backend: str = EXECUTION_BACKEND,
    chain_id: str = CHAIN_ID,
    environment_id: str = PINNED_ENVIRONMENT_ID,
    environment_name: str = PINNED_ENVIRONMENT_NAME,
    reviewer_id: str = PINNED_REVIEWER_ID,
    c_dir: Optional[str] = None,
) -> Tuple[Dict[str, Any], bytes, str]:
    """Create canonical manifest structure, canonical bytes, and digest D."""
    validate_hex_sha(p_sha, 40, "p_sha")
    validate_hex_sha(w_sha, 40, "w_sha")
    validate_hex_sha(c_sha, 40, "c_sha")
    validate_decimal(s_run_id, "s_run_id")
    validate_decimal(v_run_id, "v_run_id")
    validate_decimal(environment_id, "environment_id")
    validate_decimal(reviewer_id, "reviewer_id")
    validate_hex_sha(review_commit, 40, "review_commit")

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

    # Read and validate substantive review report E
    repo_cwd = c_dir or os.getcwd()
    r_bytes = None
    candidate_file = os.path.join(repo_cwd, review_path) if not os.path.isabs(review_path) else review_path
    if os.path.exists(candidate_file):
        with open(candidate_file, "rb") as f:
            r_bytes = f.read()
    elif review_blob_sha:
        try:
            r_bytes = git_cmd_bytes(["cat-file", "-p", review_blob_sha], cwd=repo_cwd)
        except Exception:
            pass
    if r_bytes is None:
        try:
            r_bytes = git_cmd_bytes(["cat-file", "-p", f"{review_commit}:{review_path}"], cwd=repo_cwd)
        except Exception:
            pass

    if r_bytes is None:
        raise StrictAuthorizationRefused(f"Independent review report not found at {review_path} or commit {review_commit}")

    # Parse and validate substantive review report
    r_parsed = parse_json_no_duplicate_keys(r_bytes)
    validate_substantive_review_report(r_parsed, p_sha=p_sha, w_sha=w_sha, c_sha=c_sha, v_run_id=v_run_id)

    actual_sha256 = compute_digest(r_bytes)
    if review_sha256 and review_sha256 != actual_sha256:
        raise StrictAuthorizationRefused(
            f"review_sha256 mismatch: declared {review_sha256}, actual {actual_sha256}"
        )

    # Compute actual git blob sha
    p = subprocess.Popen(["git", "hash-object", "--stdin"], cwd=repo_cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdo, stde = p.communicate(r_bytes)
    if p.returncode != 0:
        raise StrictAuthorizationRefused(f"git hash-object failed for review file: {stde.decode('utf-8', errors='replace')}")
    actual_blob_sha = stdo.decode("utf-8").strip()

    if review_blob_sha and review_blob_sha != actual_blob_sha:
        raise StrictAuthorizationRefused(
            f"review_blob_sha mismatch: declared {review_blob_sha}, actual {actual_blob_sha}"
        )

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "repository": repository,
        "repository_id": PINNED_REPOSITORY_ID,
        "upstream_pr": {
            "repository": upstream_pr_repo,
            "number": int(upstream_pr_number),
        },
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
            "commit": review_commit,
            "path": review_path,
            "blob_sha": actual_blob_sha,
            "sha256": actual_sha256,
            "verdict": review_verdict,
        },
    }

    canonical_bytes = canonical_json(manifest)
    digest_D = compute_digest(canonical_bytes)
    return manifest, canonical_bytes, digest_D


class AuthenticatedGitHubVerifier:
    """Authoritative API-backed verifier for GitHub environment approval and source evidence."""

    def __init__(
        self,
        token: Optional[str] = None,
        repository: str = PINNED_REPOSITORY,
        _api_base: Optional[str] = None,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not self.token:
            raise StrictAuthorizationRefused(
                "Authentication token is required for GitHub API verification"
            )

        candidate_base = _api_base
        if candidate_base is None:
            self.base_url = PINNED_API_BASE
        else:
            cleaned = candidate_base.rstrip("/")
            if re.fullmatch(r"https?://(127\.0\.0\.1|localhost)(:[0-9]+)?", cleaned) or cleaned == PINNED_API_BASE:
                self.base_url = cleaned
            else:
                raise StrictAuthorizationRefused(
                    f"Untrusted API base URL '{candidate_base}'; only '{PINNED_API_BASE}' or loopback is permitted"
                )

        self.repository = repository

    def _api_get(self, endpoint: str) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {self.token}",
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise StrictAuthorizationRefused(
                f"GitHub API error HTTP {exc.code} for {endpoint}"
            )
        except Exception as exc:
            raise StrictAuthorizationRefused(
                f"GitHub API request failed for {endpoint}: {exc}"
            )

        return parse_json_no_duplicate_keys(raw)

    def _api_get_paginated(self, endpoint: str, list_key: Optional[str] = None) -> List[Any]:
        """Fetch all pages of a paginated resource and verify total_count completeness."""
        items: List[Any] = []
        page = 1
        per_page = 100
        expected_total = None

        while True:
            sep = "&" if "?" in endpoint else "?"
            paged_url = f"{endpoint}{sep}per_page={per_page}&page={page}"
            data = self._api_get(paged_url)

            if isinstance(data, list):
                page_items = data
            elif isinstance(data, dict):
                if list_key and list_key in data and isinstance(data[list_key], list):
                    page_items = data[list_key]
                else:
                    for k in ("jobs", "branch_policies", "branches", "approvals"):
                        if k in data and isinstance(data[k], list):
                            page_items = data[k]
                            break
                    else:
                        raise StrictAuthorizationRefused(f"No list found in paginated response for {endpoint}")
                if expected_total is None and "total_count" in data:
                    expected_total = int(data["total_count"])
            else:
                raise StrictAuthorizationRefused(f"Unexpected response type for {endpoint}")

            if not page_items:
                break

            items.extend(page_items)
            if len(page_items) < per_page:
                break
            page += 1

        if expected_total is not None and len(items) != expected_total:
            raise StrictAuthorizationRefused(
                f"Incomplete pagination for {endpoint}: advertised total_count={expected_total}, retrieved={len(items)}"
            )
        return items

    def _download_artifact_zip(self, artifact_url: str, timeout: int = 60) -> bytes:
        """Download artifact zip archive following redirects without forwarding Authorization header."""
        from proof.github_artifact import download_artifact_zip
        try:
            return download_artifact_zip(artifact_url, self.token, timeout=timeout)
        except Exception as exc:
            raise StrictAuthorizationRefused(f"Failed to download artifact: {exc}")

    def verify_source_tuple(
        self,
        c_sha: str,
        p_sha: str,
        w_sha: str,
        c_dir: Optional[str] = None,
        p_dir: Optional[str] = None,
        w_dir: Optional[str] = None,
    ) -> None:
        """Verify the exact C/P/W source tuple: HEADs, cleanliness, ancestry, and non-proof equality."""
        c_real = os.path.abspath(c_dir or os.getcwd())
        c_head = git_rev_parse("HEAD", cwd=c_real)
        if c_head != c_sha:
            raise StrictAuthorizationRefused(
                f"Executing checkout HEAD mismatch: expected {c_sha}, got {c_head}"
            )
        if not git_is_clean(c_real):
            raise StrictAuthorizationRefused(f"Executing checkout at {c_real} is dirty")

        if p_dir:
            p_real = os.path.abspath(p_dir)
            p_head = git_rev_parse("HEAD", cwd=p_real)
            if p_head != p_sha:
                raise StrictAuthorizationRefused(
                    f"P checkout HEAD mismatch: expected {p_sha}, got {p_head}"
                )
            if not git_is_clean(p_real):
                raise StrictAuthorizationRefused(f"P checkout at {p_real} is dirty")

        if w_dir:
            w_real = os.path.abspath(w_dir)
            w_head = git_rev_parse("HEAD", cwd=w_real)
            if w_head != w_sha:
                raise StrictAuthorizationRefused(
                    f"W checkout HEAD mismatch: expected {w_sha}, got {w_head}"
                )
            if not git_is_clean(w_real):
                raise StrictAuthorizationRefused(f"W checkout at {w_real} is dirty")

        git_root = (os.path.abspath(w_dir) if w_dir else c_real)
        if not git_is_ancestor(p_sha, w_sha, cwd=git_root):
            raise StrictAuthorizationRefused(
                f"W ({w_sha}) does not descend from P ({p_sha})"
            )

        git_diff_non_proof_clean(p_sha, w_sha, cwd=git_root)

    def verify(
        self,
        manifest_path: str,
        c_dir: Optional[str] = None,
        p_dir: Optional[str] = None,
        w_dir: Optional[str] = None,
        require_completed_jobs: bool = False,
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

        # 2. Query upstream PR147 on iyilang/iyi (fail closed!)
        pr_data = self._api_get(f"repos/{UPSTREAM_PR_REPOSITORY}/pulls/{UPSTREAM_PR_NUMBER}")
        if not isinstance(pr_data, dict):
            raise StrictAuthorizationRefused(f"Invalid PR147 data from {UPSTREAM_PR_REPOSITORY}")
        pr_head = pr_data.get("head", {}).get("sha")
        if not pr_head:
            raise StrictAuthorizationRefused("PR147 head SHA missing from response")
        if pr_head != p_sha:
            raise StrictAuthorizationRefused(
                f"PR147 head moved: PR reports {pr_head}, manifest binds {p_sha}"
            )

        # 3. Authenticate GitHub repository identity
        repo_info = self._api_get(f"repos/{self.repository}")
        if str(repo_info.get("id")) != PINNED_REPOSITORY_ID:
            raise StrictAuthorizationRefused(
                f"Repository ID mismatch: expected {PINNED_REPOSITORY_ID}, got {repo_info.get('id')}"
            )

        # 4. Authenticate GitHub environment and exact policy
        env_info = self._api_get(f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}")
        if str(env_info.get("id")) != PINNED_ENVIRONMENT_ID:
            raise StrictAuthorizationRefused("Environment ID mismatch")

        if env_info.get("can_admins_bypass") is not False:
            raise StrictAuthorizationRefused("Environment policy violation: can_admins_bypass must be False")

        # Check required reviewers: exactly one reviewer, prevent_self_review must be False, reviewer_id must be PINNED_REVIEWER_ID
        rules = env_info.get("protection_rules", [])
        rev_rule = None
        for rule in rules:
            if rule.get("type") == "required_reviewers":
                rev_rule = rule
                break
        if not rev_rule:
            raise StrictAuthorizationRefused("Required reviewers rule missing from environment protection rules")

        if rev_rule.get("prevent_self_review") is not False:
            raise StrictAuthorizationRefused("Environment policy violation: prevent_self_review must be False")

        reviewers = rev_rule.get("reviewers", [])
        if len(reviewers) != 1:
            raise StrictAuthorizationRefused(f"Environment policy must specify exactly one reviewer, found {len(reviewers)}")

        rev_user = reviewers[0].get("reviewer", {})
        if str(rev_user.get("id")) != PINNED_REVIEWER_ID:
            raise StrictAuthorizationRefused(
                f"Required reviewer ID mismatch: expected {PINNED_REVIEWER_ID}, got {rev_user.get('id')}"
            )

        # Check deployment branch policies: exactly PINNED_BRANCH
        bp_list = self._api_get_paginated(
            f"repos/{self.repository}/environments/{PINNED_ENVIRONMENT_NAME}/deployment-branch-policies",
            list_key="branch_policies",
        )
        if not bp_list:
            raise StrictAuthorizationRefused("No deployment branch policies configured for environment")
        branch_names = [b.get("name") for b in bp_list if isinstance(b, dict)]
        if set(branch_names) != {PINNED_BRANCH}:
            raise StrictAuthorizationRefused(
                f"Environment branch policy must permit only '{PINNED_BRANCH}', got {branch_names}"
            )

        # 5. Authenticate Run S (approval run)
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
        if s_run.get("head_branch") != PINNED_BRANCH:
            raise StrictAuthorizationRefused(
                f"Run S head_branch mismatch: expected {PINNED_BRANCH}, got {s_run.get('head_branch')}"
            )

        # 6. Authenticate Jobs in Run S (complete enumeration)
        s_jobs = self._api_get_paginated(
            f"repos/{self.repository}/actions/runs/{s_run_id}/attempts/1/jobs",
            list_key="jobs",
        )
        if not s_jobs:
            raise StrictAuthorizationRefused("Run S has empty jobs list")

        prep_jobs = [
            j for j in s_jobs
            if isinstance(j, dict) and j.get("name") in ("prepare-strict-authorization", "Prepare strict authorization manifest")
        ]
        if len(prep_jobs) != 1:
            raise StrictAuthorizationRefused(
                f"Expected exactly one preparation job in S, found {len(prep_jobs)}"
            )
        if prep_jobs[0].get("conclusion") != "success":
            raise StrictAuthorizationRefused("Preparation job in S did not succeed")

        prot_jobs = [
            j for j in s_jobs
            if isinstance(j, dict) and j.get("name") in ("strict-chain", "Sequential strict-chain gate (strict-proof)")
        ]
        if len(prot_jobs) != 1:
            raise StrictAuthorizationRefused(
                f"Expected exactly one protected job in S, found {len(prot_jobs)}"
            )
        prot_job = prot_jobs[0]
        if require_completed_jobs:
            if prot_job.get("status") != "completed" or prot_job.get("conclusion") != "success":
                raise StrictAuthorizationRefused("Protected job in S has not completed successfully")
            if s_run.get("status") != "completed" or s_run.get("conclusion") != "success":
                raise StrictAuthorizationRefused("Run S has not completed successfully")
        else:
            if prot_job.get("status") not in ("in_progress", "completed"):
                raise StrictAuthorizationRefused(f"Protected job in S has invalid status: {prot_job.get('status')}")
            if prot_job.get("status") == "completed" and prot_job.get("conclusion") != "success":
                raise StrictAuthorizationRefused(f"Protected job in S completed with failure: {prot_job.get('conclusion')}")

        # 7. Authenticate Approval Record in Run S
        approvals = self._api_get_paginated(
            f"repos/{self.repository}/actions/runs/{s_run_id}/approvals",
            list_key="approvals",
        )
        expected_comment = f"{APPROVAL_COMMENT_PREFIX}{D}"
        matching_approvals = []
        for app in approvals:
            if not isinstance(app, dict):
                continue
            state = app.get("state")
            user_id = str(app.get("user", {}).get("id"))
            comment = app.get("comment", "")
            environments = app.get("environments", [])
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
            if not approvals:
                raise StrictAuthorizationRefused("No approvals found in GitHub history for run S")
            for app in approvals:
                if app.get("state") != "approved":
                    raise StrictAuthorizationRefused(f"Approval state is not approved: {app.get('state')}")
                if str(app.get("user", {}).get("id")) != PINNED_REVIEWER_ID:
                    raise StrictAuthorizationRefused(
                        f"Approval user ID mismatch: expected {PINNED_REVIEWER_ID}, got {app.get('user', {}).get('id')}"
                    )
                env_ids = [str(e.get("id")) for e in app.get("environments", []) if isinstance(e, dict)]
                if PINNED_ENVIRONMENT_ID not in env_ids:
                    raise StrictAuthorizationRefused(
                        f"Approval environment ID mismatch: expected {PINNED_ENVIRONMENT_ID}, got {env_ids}"
                    )
                comm = app.get("comment", "")
                if comm != expected_comment:
                    if not comm:
                        raise StrictAuthorizationRefused("Approval comment is empty")
                    if comm.strip() == expected_comment and comm != expected_comment:
                        raise StrictAuthorizationRefused("Approval comment contains whitespace discrepancies")
                    if not comm.startswith(APPROVAL_COMMENT_PREFIX):
                        raise StrictAuthorizationRefused(f"Approval comment wrong prefix: {comm!r}")
                    raise StrictAuthorizationRefused(
                        f"Approval comment mismatch: expected '{expected_comment}', got '{comm}'"
                    )
            raise StrictAuthorizationRefused("No valid matching approval record found for run S")

        # 8. Authenticate V run, jobs, and substantive evidence artifacts
        v_run = self._api_get(f"repos/{self.repository}/actions/runs/{v_run_id}")
        if str(v_run.get("repository", {}).get("id")) != PINNED_REPOSITORY_ID:
            raise StrictAuthorizationRefused("V run repository mismatch")
        if str(v_run.get("run_attempt")) != "1":
            raise StrictAuthorizationRefused("V run attempt must be 1")
        if v_run.get("status") != "completed" or v_run.get("conclusion") != "success":
            raise StrictAuthorizationRefused(
                f"V run {v_run_id} status or conclusion failure: status={v_run.get('status')}, conclusion={v_run.get('conclusion')}"
            )

        v_jobs = self._api_get_paginated(
            f"repos/{self.repository}/actions/runs/{v_run_id}/attempts/1/jobs",
            list_key="jobs",
        )
        if not v_jobs:
            raise StrictAuthorizationRefused("V run has empty jobs list")

        for job in v_jobs:
            if isinstance(job, dict) and job.get("conclusion") != "success":
                raise StrictAuthorizationRefused(
                    f"Job '{job.get('name')}' in V run {v_run_id} failed with conclusion '{job.get('conclusion')}'"
                )

        has_validation_job = any(
            isinstance(j, dict) and any(term in j.get("name", "").lower() for term in ("validation", "synthetic", "supervisor", "proofs"))
            for j in v_jobs
        )
        if not has_validation_job:
            raise StrictAuthorizationRefused("V run missing required validation proofs job")

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

            # Inspect artifact contents
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                    z_names = zf.namelist()
                    if len(z_names) != len(set(z_names)):
                        raise StrictAuthorizationRefused("Duplicate member names in validation artifact")
                    for name in z_names:
                        if name.startswith("/") or ".." in name.split("/"):
                            raise StrictAuthorizationRefused("Unsafe member name in validation artifact")
                    receipt_names = [n for n in z_names if n in ("validation_receipt.json", "validation-receipt.json", "receipt.json", "evidence-manifest.json")]
                    if not receipt_names:
                        raise StrictAuthorizationRefused("Validation artifact contains no recognized receipt or evidence manifest")
                    receipt_data = parse_json_no_duplicate_keys(zf.read(receipt_names[0]))
            except zipfile.BadZipFile as exc:
                raise StrictAuthorizationRefused(f"Corrupted validation artifact zip: {exc}")

            if not isinstance(receipt_data, dict):
                raise StrictAuthorizationRefused("Validation receipt must be a JSON object")

            # Verify substantive receipt binding
            if receipt_data.get("w_sha") != w_sha:
                raise StrictAuthorizationRefused(
                    f"Validation receipt W mismatch: expected {w_sha}, got {receipt_data.get('w_sha')}"
                )
            if receipt_data.get("p_sha") != p_sha:
                raise StrictAuthorizationRefused(
                    f"Validation receipt P mismatch: expected {p_sha}, got {receipt_data.get('p_sha')}"
                )
            if receipt_data.get("c_sha") != c_sha:
                raise StrictAuthorizationRefused(
                    f"Validation receipt C mismatch: expected {c_sha}, got {receipt_data.get('c_sha')}"
                )

            inventory = receipt_data.get("inventory") or receipt_data.get("executed_inventory")
            if not inventory:
                raise StrictAuthorizationRefused("Validation receipt lacks substantive executed inventory")

            mutations = receipt_data.get("mutations") or receipt_data.get("mutation_evidence")
            if not mutations or (isinstance(mutations, dict) and mutations.get("status") not in ("PASS", "VERIFIED")):
                raise StrictAuthorizationRefused("Validation receipt lacks passing mutation evidence")

            v_verdict = receipt_data.get("verdict") or receipt_data.get("status")
            if v_verdict not in ("PASS", "SUCCESS", "VERIFIED"):
                raise StrictAuthorizationRefused(f"Validation receipt non-passing verdict: {v_verdict}")

        # 9. Authenticate Independent Review E from immutable Git blob
        review_info = m.get("review", {})
        if not isinstance(review_info, dict):
            raise StrictAuthorizationRefused("Manifest review section missing or not an object")
        if review_info.get("verdict") != "GO":
            raise StrictAuthorizationRefused(
                f"Independent review verdict is not GO: {review_info.get('verdict')}"
            )
        r_commit = validate_hex_sha(review_info.get("commit"), 40, "review.commit")
        r_path = review_info.get("path", "proof/review_evidence.json")
        r_blob = validate_hex_sha(review_info.get("blob_sha"), 40, "review.blob_sha")
        r_sha256 = validate_hex_sha(review_info.get("sha256"), 64, "review.sha256")

        repo_cwd = os.path.abspath(c_dir or os.getcwd())
        blob_bytes = git_cmd_bytes(["cat-file", "-p", r_blob], cwd=repo_cwd)
        if compute_digest(blob_bytes) != r_sha256:
            raise StrictAuthorizationRefused("Review Git blob SHA-256 digest mismatch")

        p = subprocess.Popen(["git", "hash-object", "--stdin"], cwd=repo_cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdo, _ = p.communicate(blob_bytes)
        if stdo.decode("utf-8").strip() != r_blob:
            raise StrictAuthorizationRefused("Review Git blob object SHA mismatch")

        resolved_blob = git_cmd(["rev-parse", f"{r_commit}:{r_path}"], cwd=repo_cwd)
        if resolved_blob != r_blob:
            raise StrictAuthorizationRefused(
                f"Review path '{r_path}' in commit {r_commit} resolves to blob {resolved_blob}, expected {r_blob}"
            )

        r_obj = parse_json_no_duplicate_keys(blob_bytes)
        validate_substantive_review_report(r_obj, p_sha=p_sha, w_sha=w_sha, c_sha=c_sha, v_run_id=v_run_id)

        # 10. Verify Git Source Relations (P, W, C)
        self.verify_source_tuple(
            c_sha=c_sha,
            p_sha=p_sha,
            w_sha=w_sha,
            c_dir=c_dir,
            p_dir=p_dir,
            w_dir=w_dir,
        )

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


# Fail-closed legacy hooks: no caller-minted authorization
def check_strict_authorization_or_refuse(
    p_sha: str,
    w_sha: str,
    c_sha: str,
) -> None:
    """Fail-closed check for legacy callers. Raises StrictAuthorizationRefused unconditionally.

    Self-certified authorization assertions (such as caller-supplied dicts or ACK objects)
    are prohibited. Authentic authorization requires GitHub environment approval verified
    by the shared verifier.
    """
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
    """Compatibility helper. Fails closed: caller-minted authorization ACKs are prohibited."""
    raise StrictAuthorizationRefused(
        "Self-certified authorization IPC ACK is prohibited. Authoritative verification required."
    )


# CLI Entry commands
def cmd_prepare(args: argparse.Namespace) -> int:
    """Prepare canonical manifest and package."""
    v_arts = []
    if args.v_artifacts:
        if os.path.exists(args.v_artifacts):
            with open(args.v_artifacts, "rb") as f:
                v_arts = parse_json_no_duplicate_keys(f.read())
        else:
            v_arts = parse_json_no_duplicate_keys(args.v_artifacts)

    manifest, canonical_bytes, D = create_manifest(
        p_sha=args.p_sha,
        w_sha=args.w_sha,
        c_sha=args.c_sha,
        s_run_id=args.s_run_id,
        s_run_attempt=args.s_run_attempt,
        workflow_path=args.workflow_path,
        v_run_id=args.v_run_id,
        v_artifacts=v_arts,
        review_commit=args.review_commit,
        review_path=args.review_path,
        review_blob_sha=args.review_blob_sha,
        review_sha256=args.review_sha256,
        review_verdict=args.review_verdict,
        execution_backend=args.backend,
        chain_id=args.chain_id,
        environment_id=str(args.environment_id),
        environment_name=args.environment_name,
        reviewer_id=str(args.reviewer_id),
        c_dir=args.c,
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

    print("PREPARE_SUCCESS: canonical manifest prepared")
    print(f"MANIFEST_DIGEST: {D}")
    return 0


def cmd_check(args: argparse.Namespace, _api_base: Optional[str] = None) -> int:
    """Check manifest against authoritative GitHub data and local source tuple."""
    verifier = AuthenticatedGitHubVerifier(
        token=args.token,
        _api_base=_api_base,
    )
    receipt = verifier.verify(
        manifest_path=args.manifest,
        c_dir=args.c,
        p_dir=args.p,
        w_dir=args.w,
    )
    if args.receipt:
        os.makedirs(os.path.dirname(os.path.abspath(args.receipt)), exist_ok=True)
        with open(args.receipt, "w") as f:
            json.dump(receipt, f, indent=2)

    if args.format == "json":
        print(json.dumps(receipt, indent=2))
    else:
        print(f"CHECK_SUCCESS: verified environment approval for manifest {receipt['manifest_digest']}")
        print("DECISION: AUTHORIZED")
    return 0


def cmd_run_native(args: argparse.Namespace) -> int:
    """Fail closed: direct execution from strict_authorization is prohibited."""
    refusal_msg = (
        "run-native is disabled pending integrated supervisor: "
        "native execution must route through the supported supervisor local backend"
    )
    print(f"\n[STRICT_AUTHORIZATION_REFUSED] {refusal_msg}", file=sys.stderr)
    raise StrictAuthorizationRefused(refusal_msg)


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
    p_prep.add_argument("--review-commit", required=True, help="Git commit SHA containing independent review E")
    p_prep.add_argument("--review-path", default="proof/review_evidence.json", help="Repository-relative path to review file")
    p_prep.add_argument("--review-blob-sha", help="Optional Git blob SHA of independent review E")
    p_prep.add_argument("--review-sha256", help="Optional SHA-256 of independent review E")
    p_prep.add_argument("--review-verdict", default="GO", help="Expected review verdict")
    p_prep.add_argument("--backend", default=EXECUTION_BACKEND, help="Execution backend")
    p_prep.add_argument("--chain-id", default=CHAIN_ID, help="Strict chain identity")
    p_prep.add_argument("--environment-id", type=int, default=int(PINNED_ENVIRONMENT_ID))
    p_prep.add_argument("--environment-name", default=PINNED_ENVIRONMENT_NAME)
    p_prep.add_argument("--reviewer-id", type=int, default=int(PINNED_REVIEWER_ID))
    p_prep.add_argument("--output-digest", help="Optional output path to write manifest digest D")
    p_prep.add_argument("--c", help="Directory of C repository for Git resolution")

    # check
    p_check = subparsers.add_parser("check", help="Check manifest against authoritative GitHub data")
    p_check.add_argument("--manifest", required=True, help="Path to manifest JSON or ZIP package")
    p_check.add_argument("--token", help="GitHub API token")
    p_check.add_argument("--c", help="Directory of C repository (default cwd)")
    p_check.add_argument("--p", help="Directory of P repository (optional)")
    p_check.add_argument("--w", help="Directory of W repository (optional)")
    p_check.add_argument("--receipt", help="Optional output path for verification receipt JSON")
    p_check.add_argument("--format", choices=["text", "json"], default="text")

    # run-native
    p_rn = subparsers.add_parser("run-native", help="Verify authorization and invoke native chain")
    p_rn.add_argument("--manifest", required=True, help="Path to manifest JSON or ZIP package")
    p_rn.add_argument("--w", help="Path to W proof directory")
    p_rn.add_argument("--p", help="Path to P product directory")
    p_rn.add_argument("--compiler", help="Path to compiler binary")
    p_rn.add_argument("--report-dir", help="Path to output report directory")

    return parser


def main(argv: Optional[List[str]] = None, _api_base: Optional[str] = None) -> int:
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
            return cmd_check(args, _api_base=_api_base)
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
