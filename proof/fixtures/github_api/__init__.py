"""GitHub API read-only and derived test fixtures.

This package provides genuine read-only responses captured from GitHub API
and explicitly documented derived fixtures for testing strict-proof authorization.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FIXTURES_DIR = Path(__file__).resolve().parent


def load_fixture(name: str) -> Any:
    """Load a fixture JSON file by filename."""
    path = FIXTURES_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"Fixture not found: {name}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def git_blob_id(data: bytes) -> str:
    """Compute git object SHA-1 for a blob."""
    header = f"blob {len(data)}\0".encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


def digest(raw: bytes) -> str:
    """Return lowercase hex SHA-256 digest."""
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    """Serialize value to deterministic canonical UTF-8 JSON without trailing newline."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def get_repo_fixture() -> Dict[str, Any]:
    return load_fixture("repo_jwaldrip_iyi.json")


def get_environment_fixture() -> Dict[str, Any]:
    return load_fixture("environment_strict_proof.json")


def get_branch_policies_fixture() -> Dict[str, Any]:
    return load_fixture("branch_policies_strict_proof.json")


def get_pull_147_fixture() -> Dict[str, Any]:
    return load_fixture("pull_147.json")


def get_compare_pw_fixture() -> Dict[str, Any]:
    return load_fixture("compare_p_w.json")


def get_compare_wh_fixture() -> Dict[str, Any]:
    return load_fixture("compare_w_h.json")


def get_contents_harness_audit_zip_fixture() -> Dict[str, Any]:
    return load_fixture("contents_harness_audit_zip.json")


def get_blob_95962d09_fixture() -> Dict[str, Any]:
    return load_fixture("blob_95962d09.json")


def get_branch_deploy_fixture() -> Dict[str, Any]:
    return load_fixture("branch_deploy.json")


def get_rules_branch_deploy_fixture(active: bool = False) -> List[Dict[str, Any]]:
    if active:
        return load_fixture("rules_branch_deploy_active.json")
    return load_fixture("rules_branch_deploy.json")


def get_strict_run_in_progress_fixture(
    head_sha: str = "72c3c7d026369e5f59553d0c6cb208233f545d24",
    run_id: int = 42086795082,
) -> Dict[str, Any]:
    """Derived fixture: in-progress workflow_dispatch strict run.

    Base fixture: run_42086795082.json
    Substituted fields:
      - status: "in_progress"
      - conclusion: None
      - event: "workflow_dispatch"
      - head_sha: head_sha
      - run_attempt: 1
      - id: run_id
    """
    base = deepcopy(load_fixture("run_42086795082.json"))
    base["status"] = "in_progress"
    base["conclusion"] = None
    base["event"] = "workflow_dispatch"
    base["head_sha"] = head_sha
    base["run_attempt"] = 1
    base["id"] = run_id
    base["_derived_from"] = {
        "base_fixture": "run_42086795082.json",
        "substitutions": ["status", "conclusion", "event", "head_sha", "run_attempt", "id"],
    }
    return base


def get_approval_fixture(
    manifest_digest: str,
    reviewer_id: int = 43164,
    reviewer_login: str = "jwaldrip",
    env_id: int = 26584191206,
    env_name: str = "strict-proof",
) -> List[Dict[str, Any]]:
    """Derived fixture: environment approval record.

    Base fixture: approvals_empty.json
    Substituted fields:
      - single approval entry with state="approved"
      - user: reviewer_id, reviewer_login, type="User"
      - environments: [{"id": env_id, "name": env_name}]
      - comment: "iyi-strict-authorization-v2 sha256:" + manifest_digest
    """
    record = {
        "state": "approved",
        "user": {
            "id": reviewer_id,
            "login": reviewer_login,
            "type": "User",
        },
        "environments": [
            {
                "id": env_id,
                "name": env_name,
            }
        ],
        "comment": f"iyi-strict-authorization-v2 sha256:{manifest_digest}",
        "_derived_from": {
            "base_fixture": "approvals_empty.json",
            "substitutions": ["state", "user", "environments", "comment"],
        },
    }
    return [record]


def get_check_run_deployment_fixture(
    check_run_id: int,
    run_id: int,
    head_sha: str,
    deployment_id: int = 6086087299,
    env_name: str = "strict-proof",
) -> Dict[str, Any]:
    """Derived fixture: check run linked to environment deployment.

    Base fixture: check_run_97854822865.json
    Substituted fields:
      - id: check_run_id
      - head_sha: head_sha
      - app: {"slug": "github-actions"}
      - details_url: f"https://github.com/jwaldrip/iyi/actions/runs/{run_id}/job/{check_run_id}"
      - deployment: {"id": deployment_id, "environment": env_name, "original_environment": env_name, "task": "deploy"}
    """
    base = deepcopy(load_fixture("check_run_97854822865.json"))
    base["id"] = check_run_id
    base["head_sha"] = head_sha
    base["app"] = {"slug": "github-actions"}
    base["details_url"] = f"https://github.com/jwaldrip/iyi/actions/runs/{run_id}/job/{check_run_id}"
    base["deployment"] = {
        "id": deployment_id,
        "environment": env_name,
        "original_environment": env_name,
        "task": "deploy",
    }
    base["_derived_from"] = {
        "base_fixture": "check_run_97854822865.json",
        "substitutions": ["id", "head_sha", "app", "details_url", "deployment"],
    }
    return base


def get_deployment_fixture(
    deployment_id: int,
    head_sha: str,
    ref: str = "proof/strict-lifecycle-repair-20261102",
    env_name: str = "strict-proof",
) -> Dict[str, Any]:
    """Derived fixture: deployment record performed via github-actions app.

    Base fixture: deployment_6086087244.json
    Substituted fields:
      - id: deployment_id
      - sha: head_sha
      - ref: ref
      - environment: env_name
      - original_environment: env_name
      - performed_via_github_app: {"slug": "github-actions"}
    """
    base = deepcopy(load_fixture("deployment_6086087244.json"))
    base["id"] = deployment_id
    base["sha"] = head_sha
    base["ref"] = ref
    base["environment"] = env_name
    base["original_environment"] = env_name
    base["performed_via_github_app"] = {"slug": "github-actions"}
    base["_derived_from"] = {
        "base_fixture": "deployment_6086087244.json",
        "substitutions": ["id", "sha", "ref", "environment", "original_environment", "performed_via_github_app"],
    }
    return base


def get_manifest_artifact_fixture(
    artifact_id: int,
    run_id: int,
    head_sha: str,
    manifest_zip_sha256: str,
    created_at: str = "2026-11-06T00:20:00Z",
) -> Dict[str, Any]:
    """Derived fixture: manifest artifact metadata.

    Base fixture: artifact_13600255503.json
    Substituted fields:
      - id: artifact_id
      - name: "strict-authorization-manifest"
      - digest: f"sha256:{manifest_zip_sha256}"
      - expired: False
      - created_at: created_at
      - workflow_run: {"id": run_id, "repository_id": 1340355933, "head_sha": head_sha, "head_branch": "proof/strict-lifecycle-repair-20261102"}
    """
    base = deepcopy(load_fixture("artifact_13600255503.json"))
    base["id"] = artifact_id
    base["name"] = "strict-authorization-manifest"
    base["digest"] = f"sha256:{manifest_zip_sha256}"
    base["expired"] = False
    base["created_at"] = created_at
    base["workflow_run"] = {
        "id": run_id,
        "repository_id": 1340355933,
        "head_sha": head_sha,
        "head_branch": "proof/strict-lifecycle-repair-20261102",
    }
    base["_derived_from"] = {
        "base_fixture": "artifact_13600255503.json",
        "substitutions": ["id", "name", "digest", "expired", "created_at", "workflow_run"],
    }
    return base


def get_val_jobs_fixture(val_run_id: int, head_sha: str) -> List[Dict[str, Any]]:
    """Generate exact 7 validation/rehearsal jobs (all success) plus skipped prepare/strict."""
    jobs = [
        {
            "id": 1001,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Generate supervisor bundle",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 1",
            "started_at": "2026-11-06T00:01:00Z",
            "completed_at": "2026-11-06T00:03:00Z",
        },
        {
            "id": 1002,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Controller synthetic and validation proofs (macOS 15)",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 2",
            "started_at": "2026-11-06T00:03:00Z",
            "completed_at": "2026-11-06T00:10:00Z",
        },
        {
            "id": 1003,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Ownership recovery (clean-success)",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 3",
            "started_at": "2026-11-06T00:10:00Z",
            "completed_at": "2026-11-06T00:12:00Z",
        },
        {
            "id": 1004,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Ownership recovery (divergence-retry)",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 4",
            "started_at": "2026-11-06T00:10:00Z",
            "completed_at": "2026-11-06T00:12:00Z",
        },
        {
            "id": 1005,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Ownership recovery (run1-outage)",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 5",
            "started_at": "2026-11-06T00:10:00Z",
            "completed_at": "2026-11-06T00:12:00Z",
        },
        {
            "id": 1006,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Verify complete hosted evidence inventory",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 6",
            "started_at": "2026-11-06T00:12:00Z",
            "completed_at": "2026-11-06T00:14:00Z",
        },
        {
            "id": 1007,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Authorization rehearsal against GitHub API",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "runner_name": "GitHub Actions 7",
            "started_at": "2026-11-06T00:14:00Z",
            "completed_at": "2026-11-06T00:16:00Z",
        },
        {
            "id": 1008,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Prepare strict authorization manifest",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "skipped",
        },
        {
            "id": 1009,
            "run_id": val_run_id,
            "run_attempt": 1,
            "name": "Sequential strict-chain attempt (macOS 15)",
            "workflow_name": "Remote Strict Proof Chain (macOS 15)",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "skipped",
        },
    ]
    return jobs


def get_val_artifacts_fixture(
    val_run_id: int,
    head_sha: str,
    summary_digest: str,
    rehearsal_digest: str,
    bundle_digest: str = "sha256:" + "b" * 64,
) -> List[Dict[str, Any]]:
    """Generate exact 62 artifacts for validation run, including the 4 named artifacts."""
    named = [
        {
            "id": 2001,
            "name": "remote-strict-validation-evidence",
            "digest": "sha256:" + "a" * 64,
            "expired": False,
            "created_at": "2026-11-06T00:15:00Z",
            "workflow_run": {"id": val_run_id, "head_sha": head_sha},
        },
        {
            "id": 2002,
            "name": f"supervisor-bundle-{head_sha}",
            "digest": bundle_digest,
            "expired": False,
            "created_at": "2026-11-06T00:15:00Z",
            "workflow_run": {"id": val_run_id, "head_sha": head_sha},
        },
        {
            "id": 2003,
            "name": "rail-validation-summary",
            "digest": summary_digest,
            "expired": False,
            "created_at": "2026-11-06T00:15:00Z",
            "workflow_run": {"id": val_run_id, "head_sha": head_sha},
        },
        {
            "id": 2004,
            "name": "rail-rehearsal-report",
            "digest": rehearsal_digest,
            "expired": False,
            "created_at": "2026-11-06T00:15:00Z",
            "workflow_run": {"id": val_run_id, "head_sha": head_sha},
        },
    ]

    other = []
    for i in range(5, 63):
        other.append({
            "id": 2000 + i,
            "name": f"evidence-artifact-{i:02d}",
            "digest": f"sha256:{digest(f'art-{i}'.encode('utf-8'))}",
            "expired": False,
            "created_at": "2026-11-06T00:15:00Z",
            "workflow_run": {"id": val_run_id, "head_sha": head_sha},
        })

    return named + other


def get_audit_files_fixture(
    c_sha: str,
    val_run_id: str,
    val_artifacts: Dict[str, Dict[str, str]],
    harness_run_id: str = "42429518284",
    harness_artifact_id: str = "13600255503",
    harness_digest: str = "sha256:3eb033b6e255cec4cc137d4c6379b1ca97a4c43712ac5171e57a48cf24fb3862",
    p_sha: str = "180f14f91c829b25362a5ed34b20847f3ac2db77",
    w_sha: str = "5a3770e96fb12099c4ce9dc3b21895de07dd4cd8",
    h_sha: str = "48ffd47caaf45ff9580c35e6f2b0e3c285144bcc",
    repo_id: str = "1340355933",
) -> Tuple[Dict[str, Tuple[bytes, str]], Dict[str, Dict[str, str]], Dict[str, Any]]:
    """Generate genuine audit.json, audit.md, census-review.md with verified blob SHAs."""
    audit_md_bytes = b"# Independent Security Audit Report\n\nVerified independent review for strict proof.\n"
    census_review_bytes = b"# Census Review\n\nPreserved census review for refreshed proof.\n"

    audit_md_blob = git_blob_id(audit_md_bytes)
    census_blob = git_blob_id(census_review_bytes)

    audit_dict = {
        "schema": "iyi.strict-independent-audit.v2",
        "verdict": "GO",
        "repository_id": str(repo_id),
        "c_sha": c_sha,
        "p_sha": p_sha,
        "w_sha": w_sha,
        "h_sha": h_sha,
        "validation": {
            "run_id": str(val_run_id),
            "artifacts": {k: v["digest"] for k, v in val_artifacts.items()},
        },
        "harness": {
            "run_id": harness_run_id,
            "artifact_id": harness_artifact_id,
            "digest": harness_digest,
        },
        "report_sha256": digest(audit_md_bytes),
        "census_review_sha256": digest(census_review_bytes),
        "open_blocking_findings": [],
        "s6_signing_ruling": "S6 verified: independent audit ruling GO",
        "self_declared": {
            "reviewer": "independent-agent",
            "model": "anthropic/claude-opus-5-5",
            "did_not_implement": True,
        },
    }
    audit_json_bytes = canonical(audit_dict)
    audit_json_blob = git_blob_id(audit_json_bytes)

    files_raw = {
        "audit.json": (audit_json_bytes, audit_json_blob),
        "audit.md": (audit_md_bytes, audit_md_blob),
        "census-review.md": (census_review_bytes, census_blob),
    }

    files_map = {
        "audit.json": {"blob": audit_json_blob, "sha256": digest(audit_json_bytes)},
        "audit.md": {"blob": audit_md_blob, "sha256": digest(audit_md_bytes)},
        "census-review.md": {"blob": census_blob, "sha256": digest(census_review_bytes)},
    }

    return files_raw, files_map, audit_dict
