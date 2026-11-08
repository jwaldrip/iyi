#!/usr/bin/env python3
"""Unit tests for check_strict_workflow."""

import tempfile
import unittest
from pathlib import Path
import yaml
from proof.check_action_pins import PINNED_ACTIONS
from proof.check_strict_workflow import check_strict_workflow


def build_valid_workflow_dict():
    checkout_sha = PINNED_ACTIONS["actions/checkout"]["sha"]
    python_sha = PINNED_ACTIONS["actions/setup-python"]["sha"]
    upload_sha = PINNED_ACTIONS["actions/upload-artifact"]["sha"]
    node_sha = PINNED_ACTIONS["actions/setup-node"]["sha"]

    return {
        "name": "Remote Strict Proof Chain (macOS 15)",
        "on": {
            "push": {
                "branches": [
                    "proof/strict-controller-integration-20261101",
                    "proof/strict-lifecycle-repair-20261102",
                    "proof/strict-authorization-activation-20261107",
                ]
            },
            "workflow_dispatch": {
                "inputs": {
                    "mode": {
                        "type": "choice",
                        "options": ["validation-only", "strict-chain"],
                        "default": "validation-only",
                    },
                    "evidence_commit": {
                        "type": "string",
                        "required": False,
                        "default": "",
                    },
                }
            },
        },
        "permissions": {
            "contents": "read",
            "actions": "read",
        },
        "jobs": {
            "bootstrap-supervisor-bundle": {
                "name": "Generate supervisor bundle",
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": f"actions/checkout@{checkout_sha}"},
                    {"uses": f"actions/setup-node@{node_sha}"},
                    {"uses": f"actions/upload-artifact@{upload_sha}"},
                ],
            },
            "validation-proofs": {
                "name": "Controller synthetic and validation proofs (macOS 15)",
                "runs-on": "macos-15",
                "steps": [
                    {"uses": f"actions/checkout@{checkout_sha}"},
                    {"uses": f"actions/setup-python@{python_sha}"},
                    {"uses": f"actions/upload-artifact@{upload_sha}"},
                ],
            },
            "ownership-recovery": {
                "name": "Ownership recovery (${{ matrix.case }})",
                "runs-on": "macos-15",
                "steps": [
                    {"uses": f"actions/checkout@{checkout_sha}"},
                    {"uses": f"actions/setup-python@{python_sha}"},
                    {"uses": f"actions/upload-artifact@{upload_sha}"},
                ],
            },
            "authorization-rehearsal": {
                "name": "Authorization rehearsal against GitHub API",
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {"uses": f"actions/checkout@{checkout_sha}"},
                    {"uses": f"actions/setup-python@{python_sha}"},
                    {"uses": f"actions/upload-artifact@{upload_sha}"},
                ],
            },
            "ownership-inventory": {
                "name": "Verify complete hosted evidence inventory",
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo OK"},
                ],
            },
            "prepare-strict-authorization": {
                "name": "Prepare strict authorization manifest",
                "runs-on": "ubuntu-24.04",
                "steps": [
                    {"uses": f"actions/checkout@{checkout_sha}"},
                    {"uses": f"actions/setup-python@{python_sha}"},
                    {"uses": f"actions/upload-artifact@{upload_sha}"},
                ],
            },
            "strict-chain": {
                "name": "Sequential strict-chain attempt (macOS 15)",
                "runs-on": "macos-15",
                "environment": "strict-proof",
                "steps": [
                    {
                        "uses": f"actions/checkout@{checkout_sha}",
                        "with": {"persist-credentials": False, "fetch-depth": 0},
                    },
                    {
                        "uses": f"actions/setup-python@{python_sha}",
                        "with": {"python-version": "3.14"},
                    },
                    {
                        "id": "authorize",
                        "run": "python3 -B -m proof.strict_authorization authorize --out-dir /tmp",
                        "env": {
                            "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
                            "JOB_CHECK_RUN_ID": "123",
                            "PREPARE_JOB_ID": "456",
                            "PREPARE_ARTIFACT_ID": "789",
                            "PREPARE_MANIFEST_SHA256": "abc",
                        },
                    },
                    {
                        "id": "upload-verification",
                        "if": "${{ always() }}",
                        "uses": f"actions/upload-artifact@{upload_sha}",
                        "with": {
                            "name": "strict-authorization-verification",
                            "retention-days": 90,
                        },
                    },
                    {
                        "name": "Launch Strict Proof Supervisor",
                        "uses": "./.github/actions/strict-supervisor",
                        "with": {
                            "strict_manifest_b64": "${{ steps.authorize.outputs.manifest_b64 }}",
                            "strict_manifest_sha256": "${{ steps.authorize.outputs.manifest_sha256 }}",
                            "job_id": "${{ steps.authorize.outputs.job_id }}",
                            "job_start_time": "${{ steps.authorize.outputs.job_started_at }}",
                            "job_key": "strict-chain",
                        },
                    },
                ],
            },
        },
    }


class TestCheckStrictWorkflow(unittest.TestCase):
    def test_valid_workflow_passes(self):
        wf = build_valid_workflow_dict()
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            out_file = Path(tmpdir) / "structure-report.json"
            report = check_strict_workflow(str(wf_file), str(out_file))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["workflow_structure"], "PASS")
            self.assertTrue(out_file.is_file())

    def test_missing_push_branch_fails(self):
        wf = build_valid_workflow_dict()
        wf["on"]["push"]["branches"].pop()
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("on.push.branches mismatch", str(ctx.exception))

    def test_write_permission_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["strict-chain"]["permissions"] = {"contents": "write"}
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("write permission", str(ctx.exception))

    def test_disallowed_secret_fails(self):
        wf = build_valid_workflow_dict()
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            content = yaml.dump(wf) + "\n# ${{ secrets.SUPER_SECRET }}"
            wf_file.write_text(content)
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("Disallowed secret reference", str(ctx.exception))

    def test_multiple_environment_jobs_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["validation-proofs"]["environment"] = "strict-proof"
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("Expected exactly 1 job with environment", str(ctx.exception))

    def test_strict_job_unexpected_if_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["strict-chain"]["steps"][0]["if"] = "success()"
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("forbidden 'if:'", str(ctx.exception))

    def test_strict_job_continue_on_error_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["strict-chain"]["steps"][0]["continue-on-error"] = True
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("forbidden 'continue-on-error'", str(ctx.exception))

    def test_supervisor_wiring_mismatch_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["strict-chain"]["steps"][4]["with"]["job_key"] = "wrong-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("supervisor input 'job_key' mismatch", str(ctx.exception))

    def test_unpinned_action_fails(self):
        wf = build_valid_workflow_dict()
        wf["jobs"]["bootstrap-supervisor-bundle"]["steps"][0]["uses"] = "actions/checkout@v4"
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_file = Path(tmpdir) / "wf.yml"
            wf_file.write_text(yaml.dump(wf))
            with self.assertRaises(RuntimeError) as ctx:
                check_strict_workflow(str(wf_file))
            self.assertIn("commit pin mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
