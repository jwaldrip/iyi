"""GitHub API read-only and derived test fixtures.

This package provides genuine read-only responses captured from GitHub API
and explicitly documented derived fixtures for testing strict-proof authorization.
"""

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

FIXTURES_DIR = Path(__file__).resolve().parent


def load_fixture(name: str) -> Any:
    """Load a fixture JSON file by filename."""
    path = FIXTURES_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"Fixture not found: {name}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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


def get_rules_branch_deploy_fixture() -> List[Dict[str, Any]]:
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
