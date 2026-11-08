#!/usr/bin/env python3
"""Verify remote-strict-proof.yml structural assertions per Plan §3.4 and §4.C."""

import json
import os
import re
import sys
from typing import Dict, List, Optional
import yaml

try:
    from proof.check_action_pins import PINNED_ACTIONS
except ImportError:
    # Handle direct script invocation from repo root or proof directory
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from proof.check_action_pins import PINNED_ACTIONS

EXPECTED_PUSH_BRANCHES = [
    "proof/strict-controller-integration-20261101",
    "proof/strict-lifecycle-repair-20261102",
    "proof/strict-authorization-activation-20261107",
]

EXPECTED_JOB_NAMES = {
    "bootstrap-supervisor-bundle": "Generate supervisor bundle",
    "validation-proofs": "Controller synthetic and validation proofs (macOS 15)",
    "ownership-recovery": "Ownership recovery (${{ matrix.case }})",
    "authorization-rehearsal": "Authorization rehearsal against GitHub API",
    "ownership-inventory": "Verify complete hosted evidence inventory",
    "prepare-strict-authorization": "Prepare strict authorization manifest",
    "strict-chain": "Sequential strict-chain attempt (macOS 15)",
}


def check_strict_workflow(
    workflow_path: Optional[str] = None,
    out_path: Optional[str] = None,
) -> Dict[str, str]:
    if workflow_path is None:
        workflow_path = ".github/workflows/remote-strict-proof.yml"

    with open(workflow_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    wf = yaml.safe_load(raw_text)
    if not isinstance(wf, dict):
        raise ValueError(f"Workflow {workflow_path} did not parse as a dictionary")

    errors: List[str] = []

    # 1. Triggers and permissions
    on_clause = wf.get("on") or wf.get(True)  # yaml can parse 'on' as True
    if not isinstance(on_clause, dict):
        errors.append("Missing or invalid 'on:' trigger section")
    else:
        # Check push
        push = on_clause.get("push")
        if not isinstance(push, dict) or "branches" not in push:
            errors.append("Missing 'on.push.branches'")
        else:
            actual_branches = push["branches"]
            if sorted(actual_branches) != sorted(EXPECTED_PUSH_BRANCHES):
                errors.append(
                    f"on.push.branches mismatch: expected {EXPECTED_PUSH_BRANCHES}, got {actual_branches}"
                )

        # Check workflow_dispatch
        dispatch = on_clause.get("workflow_dispatch")
        if not isinstance(dispatch, dict):
            errors.append("Missing 'on.workflow_dispatch'")
        else:
            inputs = dispatch.get("inputs", {})
            if "mode" not in inputs:
                errors.append("Missing 'inputs.mode' in workflow_dispatch")
            else:
                mode = inputs["mode"]
                if mode.get("type") != "choice" or sorted(mode.get("options", [])) != [
                    "strict-chain",
                    "validation-only",
                ]:
                    errors.append(
                        f"inputs.mode must be choice with options ['validation-only', 'strict-chain'], got {mode}"
                    )
            if "evidence_commit" not in inputs:
                errors.append("Missing 'inputs.evidence_commit' in workflow_dispatch")
            elif inputs["evidence_commit"].get("required") is True:
                errors.append("inputs.evidence_commit should be optional (required: false)")

        allowed_triggers = {"push", "workflow_dispatch"}
        extra_triggers = set(on_clause.keys()) - allowed_triggers
        if extra_triggers:
            errors.append(f"Unexpected extra triggers in 'on:': {extra_triggers}")

    # Top-level permissions
    top_perms = wf.get("permissions")
    if top_perms != {"contents": "read", "actions": "read"}:
        errors.append(
            f"Top-level permissions must be {{contents: read, actions: read}}, got {top_perms}"
        )

    # Check for write permissions and forbidden secrets across all jobs
    jobs = wf.get("jobs", {})
    if not isinstance(jobs, dict):
        errors.append("Missing or invalid 'jobs:' dictionary")
        jobs = {}

    for job_key, job_data in jobs.items():
        job_perms = job_data.get("permissions")
        if isinstance(job_perms, dict):
            for scope, val in job_perms.items():
                if val == "write" or val is True:
                    errors.append(
                        f"Job '{job_key}' has write permission on scope '{scope}': {val}"
                    )
        elif job_perms == "write-all":
            errors.append(f"Job '{job_key}' has write-all permissions")

    # Secrets scan in raw text
    secret_refs = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", raw_text)
    for ref in secret_refs:
        if ref != "GITHUB_TOKEN":
            errors.append(f"Disallowed secret reference 'secrets.{ref}' found in workflow")

    # 2. Exactly one environment job, using the literal 'strict-proof'
    env_jobs = [
        (k, v.get("environment")) for k, v in jobs.items() if "environment" in v
    ]
    if len(env_jobs) != 1:
        errors.append(
            f"Expected exactly 1 job with environment, found {len(env_jobs)}: {env_jobs}"
        )
    else:
        env_job_key, env_val = env_jobs[0]
        if env_job_key != "strict-chain":
            errors.append(
                f"Expected environment on 'strict-chain', got it on '{env_job_key}'"
            )
        if env_val != "strict-proof":
            errors.append(
                f"Environment value must be literal 'strict-proof', got {env_val!r}"
            )

    # 3. Strict job first steps
    strict_job = jobs.get("strict-chain", {})
    strict_steps = strict_job.get("steps", [])
    if len(strict_steps) < 4:
        errors.append(f"strict-chain has only {len(strict_steps)} steps; expected at least 4")
    else:
        # Step 0: checkout C
        s0 = strict_steps[0]
        s0_uses = s0.get("uses", "")
        if not s0_uses.startswith("actions/checkout@"):
            errors.append(f"strict-chain step 0 must use actions/checkout, got {s0_uses}")
        if s0.get("with", {}).get("persist-credentials") is not False:
            errors.append("strict-chain step 0 must have persist-credentials: false")
        if str(s0.get("with", {}).get("fetch-depth")) != "0":
            errors.append("strict-chain step 0 must have fetch-depth: 0")

        # Step 1: setup-python 3.14
        s1 = strict_steps[1]
        s1_uses = s1.get("uses", "")
        if not s1_uses.startswith("actions/setup-python@"):
            errors.append(f"strict-chain step 1 must use actions/setup-python, got {s1_uses}")
        if str(s1.get("with", {}).get("python-version")) != "3.14":
            errors.append("strict-chain step 1 must have python-version: '3.14'")

        # Step 2: authorize
        s2 = strict_steps[2]
        if s2.get("id") != "authorize":
            errors.append(f"strict-chain step 2 id must be 'authorize', got {s2.get('id')}")
        s2_run = s2.get("run", "")
        if "proof.strict_authorization authorize" not in s2_run:
            errors.append(
                "strict-chain step 2 run must invoke 'proof.strict_authorization authorize'"
            )
        s2_env = s2.get("env", {})
        required_env = {
            "JOB_CHECK_RUN_ID",
            "PREPARE_JOB_ID",
            "PREPARE_ARTIFACT_ID",
            "PREPARE_MANIFEST_SHA256",
        }
        missing_env = required_env - set(s2_env.keys())
        if missing_env:
            errors.append(f"strict-chain step 2 missing env variables: {missing_env}")

        # Step 3: upload-verification
        s3 = strict_steps[3]
        if s3.get("id") != "upload-verification":
            errors.append(
                f"strict-chain step 3 id must be 'upload-verification', got {s3.get('id')}"
            )
        if s3.get("if") != "${{ always() }}":
            errors.append(
                f"strict-chain step 3 if must be '${{{{ always() }}}}', got {s3.get('if')!r}"
            )
        s3_uses = s3.get("uses", "")
        if not s3_uses.startswith("actions/upload-artifact@"):
            errors.append(
                f"strict-chain step 3 must use actions/upload-artifact, got {s3_uses}"
            )
        if s3.get("with", {}).get("name") != "strict-authorization-verification":
            errors.append(
                "strict-chain step 3 artifact name must be 'strict-authorization-verification'"
            )
        if str(s3.get("with", {}).get("retention-days")) != "90":
            errors.append("strict-chain step 3 retention-days must be 90")

    # 4. No other if: or continue-on-error in the strict job
    for idx, step in enumerate(strict_steps):
        step_name = step.get("name", f"step_{idx}")
        if idx != 3 and "if" in step:
            errors.append(
                f"strict-chain {step_name} (index {idx}) has forbidden 'if:' condition: {step['if']}"
            )
        if step.get("continue-on-error") is True or "continue-on-error" in step:
            errors.append(
                f"strict-chain {step_name} (index {idx}) has forbidden 'continue-on-error'"
            )

    # 5. Supervisor with: wiring
    supervisor_step = None
    for step in strict_steps:
        if step.get("uses") == "./.github/actions/strict-supervisor":
            supervisor_step = step
            break

    if not supervisor_step:
        errors.append("strict-chain missing step using './.github/actions/strict-supervisor'")
    else:
        s_with = supervisor_step.get("with", {})
        expected_with = {
            "strict_manifest_b64": "${{ steps.authorize.outputs.manifest_b64 }}",
            "strict_manifest_sha256": "${{ steps.authorize.outputs.manifest_sha256 }}",
            "job_id": "${{ steps.authorize.outputs.job_id }}",
            "job_start_time": "${{ steps.authorize.outputs.job_started_at }}",
            "job_key": "strict-chain",
        }
        for k, v in expected_with.items():
            if s_with.get(k) != v:
                errors.append(
                    f"strict-chain supervisor input '{k}' mismatch: expected {v!r}, got {s_with.get(k)!r}"
                )

    # 6. Job names equal constants
    for job_key, expected_name in EXPECTED_JOB_NAMES.items():
        job_data = jobs.get(job_key)
        if not job_data:
            errors.append(f"Workflow missing required job '{job_key}'")
        elif job_data.get("name") != expected_name:
            errors.append(
                f"Job '{job_key}' name mismatch: expected {expected_name!r}, got {job_data.get('name')!r}"
            )

    # 8. Every uses: is local or matches §3.2
    for job_key, job_data in jobs.items():
        for idx, step in enumerate(job_data.get("steps", [])):
            uses = step.get("uses")
            if not uses:
                continue

            # Strip comments or whitespace
            clean_uses = uses.split("#")[0].strip()
            if clean_uses.startswith("./"):
                continue
            if "@" not in clean_uses:
                errors.append(f"Job '{job_key}' step {idx} unpinned action: {uses}")
                continue
            action_name, action_ref = clean_uses.split("@", 1)
            action_name = action_name.strip()
            action_ref = action_ref.strip()

            if action_name not in PINNED_ACTIONS:
                errors.append(
                    f"Job '{job_key}' step {idx} uses unapproved action: {action_name}"
                )
            else:
                expected_sha = PINNED_ACTIONS[action_name]["sha"]
                if action_ref != expected_sha:
                    errors.append(
                        f"Job '{job_key}' step {idx} action '{action_name}' commit pin mismatch: "
                        f"expected {expected_sha}, got {action_ref}"
                    )

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        raise RuntimeError(
            f"Strict workflow validation failed with {len(errors)} error(s):\n"
            + "\n".join(errors)
        )

    report = {
        "status": "PASS",
        "workflow_structure": "PASS",
    }

    if out_path:
        out_dir = os.path.dirname(out_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")

    return report


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify strict workflow structure")
    parser.add_argument(
        "--workflow",
        "-w",
        default=".github/workflows/remote-strict-proof.yml",
        help="Path to remote-strict-proof.yml",
    )
    parser.add_argument(
        "--out", "-o", dest="out_path", help="Path to write JSON structure report"
    )
    args = parser.parse_args(argv)

    try:
        report = check_strict_workflow(workflow_path=args.workflow, out_path=args.out_path)
        print("Strict workflow structure PASSED: all §3.4 and §4.C rules satisfied")
        return 0
    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
