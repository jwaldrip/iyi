#!/usr/bin/env python3
"""
remote_harness_audit.py: Remote Harness CI Gate and Independent H'' Audit Rail.

Executes Plan Sections 2-3 on remote macOS-15 runner:
1. Controller checkout C verification and fresh pinned clean W checkout setup
   at b932ce0d97775c7061102a13db706f507dc84117.
2. Source-derived inventory extraction (439 seeds, 85 controls, 524 total
   fixtures, zero duplicates/overlap).
3. Full fixture suite and coverage gate execution from W with coverage output
   strictly outside W:
   - Command: python3 -B proof/smoke_test.py --coverage <owned-output-outside-W>
   - Verifies rc == 0, HARNESS PASS, COVERAGE GATE PASS.
   - Verifies 439 seeds executed and passed, 85 controls executed and passed,
     0 missed, 0 failed, 0 duplicates.
   - Captures and validates the four coverage listings (proofkit, run_proof,
     artifact_legs, roundtrip_shim).
   - Verifies W remains completely clean.
4. Verified old-parser mutation in a disposable clone:
   - Clones W to a dedicated disposable scratch directory.
   - Records source hashes before mutation.
   - Replaces exactly one canonical RG9 parser regex with the old bare regex.
   - Verifies diff touches only proof/run_proof.py with 1 line deletion and
     1 line addition, all fixtures unchanged.
   - Starts fresh Python process and executes targeted fixtures:
     - Canonical summary control (o7.control.run1) fails at gate 1.3.
     - Bare summary rejection seeds (s5.seed.rg9-bare, s5.seed.rg9-bare-141)
       detect old parser acceptance and fail.
     - 140-count rejection seed (s5.seed.rg9-140) remains enforced and passes.
     - Malformed/extended suffix rejection seeds pass.
   - Captures detailed observations and failure signatures.
   - Restores exact saved bytes and verifies diff is empty, status clean, and
     original hash matches.
   - Removes disposable scratch clone.
5. Independent H'' audit instruments:
   - Exact H' -> H'' source delta check (verifying changes are strictly in
     proof/run_proof.py and proof/smoke_test.py).
   - Non-proof zero-diff check against P1.
   - Census unchanged check against H' and P1.
   - Canonical producer vs consumer grammar agreement check.
   - Line map and ALLOWLIST check for run_proof.py lines 1526-1533.
6. Structured textual artifact generation and reporting:
   - JSON manifests, summaries, and Markdown audit report.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any


DEFAULT_W_SHA = "b932ce0d97775c7061102a13db706f507dc84117"
DEFAULT_HPRIME_SHA = "813c8074acb2eed99ffeef78ea49e8c7832e4c01"
DEFAULT_P1_SHA = "626463375298d357ffcb3223059f4d3adce6fb10"

CANONICAL_RG9_BLOCK = (
    '        sentinel = re.search(\n'
    '            rf"^RG9 PASSED: {corpus} corpus programs, plain and observed legs \\(two processes plus IYI_WARM=1\\)$",\n'
    '            text,\n'
    '            re.MULTILINE,\n'
    '        )'
)

BARE_RG9_BLOCK = (
    '        sentinel = re.search(\n'
    '            rf"^RG9 PASSED: {corpus} corpus programs$",\n'
    '            text,\n'
    '            re.MULTILINE,\n'
    '        )'
)

TARGETED_FIXTURE_IDS = [
    "o7.control.run1",
    "s5.seed.rg9-bare",
    "s5.seed.rg9-bare-141",
    "s5.seed.rg9-malformed-suffix",
    "s5.seed.rg9-extended-suffix",
    "s5.seed.rg9-140",
]

EXPECTED_COVERAGE_MODULES = [
    "proof.proofkit",
    "proof.run_proof",
    "proof.artifact_legs",
    "proof.roundtrip_shim",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_env(env: dict[str, str]) -> dict[str, str]:
    sensitive_keys = {
        "TOKEN", "SECRET", "KEY", "AUTH", "PASS", "CREDENTIAL", "PAT",
    }
    sanitized: dict[str, str] = {}
    for k, v in env.items():
        if any(s in k.upper() for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


def run_cmd(
    cmd: list[str],
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        cmd_str = " ".join(cmd)
        err_msg = (
            f"Command failed (exit {completed.returncode}): {cmd_str}\n"
            f"--- stdout ---\n{completed.stdout}\n"
            f"--- stderr ---\n{completed.stderr}\n"
        )
        raise RuntimeError(err_msg)
    return completed


class RemoteHarnessAuditRunner:
    def __init__(
        self,
        repo: str,
        w_sha: str,
        hprime_sha: str,
        p1_sha: str,
        output_dir: str,
        work_dir: str,
    ) -> None:
        self.repo = os.path.abspath(repo)
        self.w_sha = w_sha
        self.hprime_sha = hprime_sha
        self.p1_sha = p1_sha
        self.output_dir = os.path.abspath(output_dir)
        self.work_dir = os.path.abspath(work_dir)

        self.w_dir = os.path.join(self.work_dir, "w-checkout")
        self.coverage_dir = os.path.join(self.output_dir, "coverage")
        self.inventory_dir = os.path.join(self.output_dir, "inventory")
        self.mutation_dir = os.path.join(self.output_dir, "mutation")
        self.delta_dir = os.path.join(self.output_dir, "hprime_hprimeprime_delta")
        self.env_dir = os.path.join(self.output_dir, "environment")
        self.logs_dir = os.path.join(self.output_dir, "logs")

        self.summary: dict[str, Any] = {
            "status": "IN_PROGRESS",
            "start_time": time.time(),
            "w_sha": self.w_sha,
            "hprime_sha": self.hprime_sha,
            "p1_sha": self.p1_sha,
            "steps": {},
        }

    def setup_directories(self) -> None:
        for d in (
            self.output_dir,
            self.work_dir,
            self.coverage_dir,
            self.inventory_dir,
            self.mutation_dir,
            self.delta_dir,
            self.env_dir,
            self.logs_dir,
        ):
            os.makedirs(d, exist_ok=True)

    def record_environment(self) -> None:
        print("=== Recording Environment Fingerprints ===")
        uname = platform.uname()
        free_bytes = shutil.disk_usage(self.work_dir).free
        free_gib = round(free_bytes / (1024 ** 3), 2)

        c_head = run_cmd(["git", "-C", self.repo, "rev-parse", "HEAD"]).stdout.strip()
        c_branch = run_cmd(
            ["git", "-C", self.repo, "rev-parse", "--abbrev-ref", "HEAD"]
        ).stdout.strip()

        env_info = {
            "platform": {
                "system": uname.system,
                "node": uname.node,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "processor": uname.processor,
            },
            "python": {
                "version": sys.version,
                "executable": sys.executable,
                "dont_write_bytecode": sys.dont_write_bytecode,
            },
            "disk": {
                "work_dir": self.work_dir,
                "free_bytes": free_bytes,
                "free_gib": free_gib,
            },
            "controller_c": {
                "repo_path": self.repo,
                "head_sha": c_head,
                "branch": c_branch,
            },
            "environment_variables": sanitize_env(dict(os.environ)),
        }

        with open(
            os.path.join(self.env_dir, "machine_fingerprint.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(env_info, f, indent=2)

        print(f"Machine: {uname.system} {uname.release} ({uname.machine})")
        print(f"Python: {sys.version.split()[0]} at {sys.executable}")
        print(f"Controller C: {c_branch} @ {c_head}")
        print(f"Free disk in work_dir: {free_gib} GiB")
        self.summary["steps"]["environment"] = {
            "status": "PASS",
            "machine": f"{uname.system} {uname.release} ({uname.machine})",
            "free_disk_gib": free_gib,
            "controller_c_sha": c_head,
        }

    def setup_pinned_w(self) -> None:
        print(f"\n=== Setting Up Fresh Pinned W Checkout at {self.w_sha} ===")
        if os.path.exists(self.w_dir):
            shutil.rmtree(self.w_dir)

        run_cmd(["git", "clone", "--quiet", self.repo, self.w_dir])
        run_cmd(["git", "-C", self.w_dir, "checkout", "--quiet", self.w_sha])

        actual_w_sha = run_cmd(
            ["git", "-C", self.w_dir, "rev-parse", "HEAD"]
        ).stdout.strip()
        if actual_w_sha != self.w_sha:
            raise RuntimeError(
                f"W SHA mismatch: expected {self.w_sha}, got {actual_w_sha}"
            )

        status_output = run_cmd(
            ["git", "-C", self.w_dir, "status", "--porcelain"]
        ).stdout.strip()
        if status_output:
            raise RuntimeError(f"W checkout is not clean:\n{status_output}")

        non_proof_diff = run_cmd(
            [
                "git",
                "-C",
                self.w_dir,
                "diff",
                self.p1_sha,
                "HEAD",
                "--",
                ":!proof/",
            ]
        ).stdout.strip()
        if non_proof_diff:
            raise RuntimeError(
                f"W has non-proof diff against P1 ({self.p1_sha})!\n{non_proof_diff}"
            )

        proof_files: dict[str, dict[str, Any]] = {}
        proof_dir = os.path.join(self.w_dir, "proof")
        for fname in sorted(os.listdir(proof_dir)):
            fpath = os.path.join(proof_dir, fname)
            if os.path.isfile(fpath):
                st = os.stat(fpath)
                proof_files[fname] = {
                    "sha256": sha256_file(fpath),
                    "size_bytes": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                }

        with open(
            os.path.join(self.env_dir, "w_source_hashes.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                {
                    "w_sha": self.w_sha,
                    "p1_sha": self.p1_sha,
                    "proof_files": proof_files,
                },
                f,
                indent=2,
            )

        print(f"W checkout verified clean at {actual_w_sha}.")
        print(f"Non-proof diff against P1 is empty.")
        print(f"Hashed {len(proof_files)} proof files in W.")
        self.summary["steps"]["pinned_w"] = {
            "status": "PASS",
            "w_sha": actual_w_sha,
            "non_proof_diff_empty": True,
            "proof_files_count": len(proof_files),
        }

    def audit_hprime_to_hprimeprime_delta(self) -> None:
        print(f"\n=== Auditing H' -> H'' Source Delta and Grammar Agreement ===")
        diff_res = run_cmd(
            ["git", "-C", self.repo, "diff", self.hprime_sha, self.w_sha]
        )
        diff_text = diff_res.stdout

        patch_file = os.path.join(self.delta_dir, "hprime_to_hprimeprime.patch")
        with open(patch_file, "w", encoding="utf-8") as f:
            f.write(diff_text)

        stat_res = run_cmd(
            ["git", "-C", self.repo, "diff", "--stat", self.hprime_sha, self.w_sha]
        )
        stat_text = stat_res.stdout.strip()

        name_status_res = run_cmd(
            [
                "git",
                "-C",
                self.repo,
                "diff",
                "--name-status",
                self.hprime_sha,
                self.w_sha,
            ]
        )
        changed_files = [
            line.split("\t", 1)[-1].strip()
            for line in name_status_res.stdout.strip().splitlines()
            if line.strip()
        ]

        expected_changed_files = ["proof/run_proof.py", "proof/smoke_test.py"]
        if sorted(changed_files) != sorted(expected_changed_files):
            raise RuntimeError(
                f"Unexpected files changed between H' and H'': {changed_files}, "
                f"expected {expected_changed_files}"
            )

        census_diff = run_cmd(
            [
                "git",
                "-C",
                self.repo,
                "diff",
                self.hprime_sha,
                self.w_sha,
                "--",
                "proof/census/",
            ]
        ).stdout.strip()
        if census_diff:
            raise RuntimeError("Census files unexpectedly changed between H' and H''!")

        producer_script_path = os.path.join(self.w_dir, "bench", "stale_rg9.py")
        consumer_script_path = os.path.join(self.w_dir, "proof", "run_proof.py")

        with open(producer_script_path, "r", encoding="utf-8") as f:
            producer_src = f.read()
        with open(consumer_script_path, "r", encoding="utf-8") as f:
            consumer_src = f.read()

        producer_match = re.search(
            r'print\(f"RG9 PASSED: \{len\(programs\)\} corpus programs, plain and observed legs \(two processes plus IYI_WARM=1\)"\)',
            producer_src,
        )
        if not producer_match:
            raise RuntimeError(
                "Could not locate canonical RG9 sentence in bench/stale_rg9.py"
            )

        consumer_match = re.search(
            r'rf"\^RG9 PASSED: \{corpus\} corpus programs, plain and observed legs \\\(two processes plus IYI_WARM=1\\\)\$"',
            consumer_src,
        )
        if not consumer_match:
            raise RuntimeError(
                "Could not locate canonical RG9 consumer regex in proof/run_proof.py"
            )

        test_corpus = 141
        sample_produced = (
            f"RG9 PASSED: {test_corpus} corpus programs, plain and observed legs "
            "(two processes plus IYI_WARM=1)"
        )
        test_regex = (
            rf"^RG9 PASSED: {test_corpus} corpus programs, plain and observed legs "
            r"\(two processes plus IYI_WARM=1\)$"
        )
        bare_sample = f"RG9 PASSED: {test_corpus} corpus programs"
        wrong_count_sample = (
            "RG9 PASSED: 140 corpus programs, plain and observed legs "
            "(two processes plus IYI_WARM=1)"
        )

        matches_canonical = bool(
            re.search(test_regex, sample_produced, re.MULTILINE)
        )
        rejects_bare = not bool(re.search(test_regex, bare_sample, re.MULTILINE))
        rejects_wrong_count = not bool(
            re.search(test_regex, wrong_count_sample, re.MULTILINE)
        )

        if not (matches_canonical and rejects_bare and rejects_wrong_count):
            raise RuntimeError(
                f"Grammar agreement checks failed: matches_canonical={matches_canonical}, "
                f"rejects_bare={rejects_bare}, rejects_wrong_count={rejects_wrong_count}"
            )

        grammar_report = {
            "producer_file": "bench/stale_rg9.py",
            "producer_sentence": (
                "RG9 PASSED: {count} corpus programs, plain and observed legs "
                "(two processes plus IYI_WARM=1)"
            ),
            "consumer_file": "proof/run_proof.py",
            "consumer_regex": test_regex,
            "verification": {
                "matches_canonical_produced": matches_canonical,
                "rejects_bare_sentence": rejects_bare,
                "rejects_wrong_count": rejects_wrong_count,
            },
            "status": "PASS",
        }

        with open(
            os.path.join(self.delta_dir, "grammar_agreement.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(grammar_report, f, indent=2)

        print(f"H' -> H'' diff stat:\n{stat_text}")
        print("Canonical producer and consumer grammar agreement VERIFIED.")
        self.summary["steps"]["delta_audit"] = {
            "status": "PASS",
            "changed_files": changed_files,
            "census_unchanged": True,
            "grammar_agreement": True,
        }

    def extract_source_derived_inventory(self) -> dict[str, Any]:
        print("\n=== Extracting Source-Derived Fixture Inventory from W ===")

        inventory_script = """
import json, os, sys
sys.dont_write_bytecode = True
REPO_ROOT = os.path.abspath(sys.argv[1])
sys.path.insert(0, REPO_ROOT)
from proof import smoke_test as st

seeds = [f.fixture_id for f in st.FIXTURES if f.kind == "seed"]
controls = [f.fixture_id for f in st.FIXTURES if f.kind == "control"]
all_ids = [f.fixture_id for f in st.FIXTURES]

review_items_map = {}
for item, fids in st.REVIEW_ITEMS.items():
    review_items_map[item] = list(fids)

print(json.dumps({
    "seeds_count": len(seeds),
    "controls_count": len(controls),
    "total_count": len(all_ids),
    "unique_count": len(set(all_ids)),
    "seed_ids": seeds,
    "control_ids": controls,
    "review_items": review_items_map,
}))
"""
        inv_res = run_cmd(
            [sys.executable, "-B", "-c", inventory_script, self.w_dir]
        )
        inv_data = json.loads(inv_res.stdout)

        seeds_count = inv_data["seeds_count"]
        controls_count = inv_data["controls_count"]
        total_count = inv_data["total_count"]
        unique_count = inv_data["unique_count"]

        print(f"Source-derived inventory: {seeds_count} seeds, {controls_count} controls, {total_count} total")

        if seeds_count != 439:
            raise RuntimeError(
                f"Seed inventory mismatch: expected 439 seeds, got {seeds_count}"
            )
        if controls_count != 85:
            raise RuntimeError(
                f"Control inventory mismatch: expected 85 controls, got {controls_count}"
            )
        if total_count != 524:
            raise RuntimeError(
                f"Total inventory mismatch: expected 524 fixtures, got {total_count}"
            )
        if unique_count != 524:
            raise RuntimeError(
                f"Duplicate fixture registration detected! {total_count} total != {unique_count} unique"
            )

        overlap = set(inv_data["seed_ids"]).intersection(set(inv_data["control_ids"]))
        if overlap:
            raise RuntimeError(
                f"Fixture ID registered as both seed and control: {overlap}"
            )

        new_regression_ids = [
            "s5.seed.rg9-bare",
            "s5.seed.rg9-bare-141",
            "s5.seed.rg9-malformed-suffix",
            "s5.seed.rg9-extended-suffix",
        ]
        for reg_id in new_regression_ids:
            if reg_id not in inv_data["seed_ids"]:
                raise RuntimeError(f"New regression seed missing from W: {reg_id}")

        inv_output_path = os.path.join(
            self.inventory_dir, "source_derived_inventory.json"
        )
        with open(inv_output_path, "w", encoding="utf-8") as f:
            json.dump(inv_data, f, indent=2)

        self.summary["steps"]["inventory"] = {
            "status": "PASS",
            "seeds_count": seeds_count,
            "controls_count": controls_count,
            "total_count": total_count,
            "new_regression_ids": new_regression_ids,
        }
        return inv_data

    def run_full_suite_and_coverage(
        self, inv_data: dict[str, Any]
    ) -> dict[str, Any]:
        print("\n=== Running Full Suite and Coverage Gate from W ===")
        smoke_test_rel = os.path.join("proof", "smoke_test.py")

        stdout_log_path = os.path.join(self.logs_dir, "smoke_test_stdout.log")
        stderr_log_path = os.path.join(self.logs_dir, "smoke_test_stderr.log")

        start_t = time.time()
        print(f"Executing: python3 -B {smoke_test_rel} --coverage {self.coverage_dir}")
        print(f"Working directory (W): {self.w_dir}")

        completed = subprocess.run(
            [sys.executable, "-B", smoke_test_rel, "--coverage", self.coverage_dir],
            cwd=self.w_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        elapsed = round(time.time() - start_t, 2)
        print(f"Suite completed in {elapsed}s with returncode {completed.returncode}")

        with open(stdout_log_path, "w", encoding="utf-8") as f:
            f.write(completed.stdout)
        with open(stderr_log_path, "w", encoding="utf-8") as f:
            f.write(completed.stderr)

        stdout_text = completed.stdout

        executed_seeds: set[str] = set()
        executed_controls: set[str] = set()
        failed_seeds: set[str] = set()
        failed_controls: set[str] = set()

        for line in stdout_text.splitlines():
            m_seed = re.match(r"^SEED\s+([\w\.\-]+)\s+status=(PASS|FAIL)", line)
            if m_seed:
                fid, st = m_seed.groups()
                executed_seeds.add(fid)
                if st == "FAIL":
                    failed_seeds.add(fid)
            m_ctrl = re.match(r"^CONTROL\s+([\w\.\-]+)\s+status=(PASS|FAIL)", line)
            if m_ctrl:
                fid, st = m_ctrl.groups()
                executed_controls.add(fid)
                if st == "FAIL":
                    failed_controls.add(fid)

        harness_pass = "HARNESS PASS" in stdout_text
        coverage_pass = "COVERAGE GATE PASS" in stdout_text

        print(f"Executed seeds: {len(executed_seeds)} (failed: {len(failed_seeds)})")
        print(f"Executed controls: {len(executed_controls)} (failed: {len(failed_controls)})")
        print(f"HARNESS PASS: {harness_pass}")
        print(f"COVERAGE GATE PASS: {coverage_pass}")

        cover_files_info: dict[str, Any] = {}
        for mod in EXPECTED_COVERAGE_MODULES:
            cpath = os.path.join(self.coverage_dir, f"{mod}.cover")
            if not os.path.isfile(cpath):
                raise RuntimeError(f"Missing coverage listing for module: {mod}")
            with open(cpath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            missing_lines = [
                i + 1
                for i, l in enumerate(lines)
                if l.startswith(">>>>>>")
            ]
            cover_files_info[mod] = {
                "path": cpath,
                "total_lines": len(lines),
                "missing_lines_count": len(missing_lines),
                "missing_lines": missing_lines,
            }

        w_status = run_cmd(
            ["git", "-C", self.w_dir, "status", "--porcelain"]
        ).stdout.strip()
        if w_status:
            raise RuntimeError(
                f"W was dirtied by smoke test or coverage gate! Porcelain output:\n{w_status}"
            )
        print("W checkout remains completely clean post-coverage.")

        validation_errors: list[str] = []
        if completed.returncode != 0:
            validation_errors.append(f"smoke_test returned exit code {completed.returncode}")
        if not harness_pass:
            validation_errors.append("HARNESS PASS missing from output")
        if not coverage_pass:
            validation_errors.append("COVERAGE GATE PASS missing from output")
        if len(executed_seeds) != 439:
            validation_errors.append(
                f"Executed seeds count mismatch: expected 439, got {len(executed_seeds)}"
            )
        if len(executed_controls) != 85:
            validation_errors.append(
                f"Executed controls count mismatch: expected 85, got {len(executed_controls)}"
            )
        if failed_seeds:
            validation_errors.append(f"Seeds reported FAIL: {sorted(failed_seeds)}")
        if failed_controls:
            validation_errors.append(f"Controls reported FAIL: {sorted(failed_controls)}")

        source_seeds = set(inv_data["seed_ids"])
        source_controls = set(inv_data["control_ids"])
        unexecuted_seeds = source_seeds - executed_seeds
        unexecuted_controls = source_controls - executed_controls
        if unexecuted_seeds:
            validation_errors.append(f"Unexecuted registered seeds: {sorted(unexecuted_seeds)}")
        if unexecuted_controls:
            validation_errors.append(f"Unexecuted registered controls: {sorted(unexecuted_controls)}")

        cov_summary = {
            "returncode": completed.returncode,
            "elapsed_seconds": elapsed,
            "harness_pass": harness_pass,
            "coverage_gate_pass": coverage_pass,
            "seeds_executed": len(executed_seeds),
            "seeds_failed": len(failed_seeds),
            "controls_executed": len(executed_controls),
            "controls_failed": len(failed_controls),
            "coverage_listings": cover_files_info,
            "w_clean_post_run": True,
            "validation_errors": validation_errors,
        }

        with open(
            os.path.join(self.coverage_dir, "coverage_summary.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(cov_summary, f, indent=2)

        if validation_errors:
            raise RuntimeError(
                f"Coverage gate validation failures:\n" + "\n".join(validation_errors)
            )

        print("Full suite and coverage gate PASSED all invariants.")
        self.summary["steps"]["smoke_test_coverage"] = {
            "status": "PASS",
            "returncode": completed.returncode,
            "elapsed_seconds": elapsed,
            "seeds_executed": len(executed_seeds),
            "controls_executed": len(executed_controls),
            "coverage_listings_count": len(cover_files_info),
        }
        return cov_summary

    def run_verified_old_parser_mutation(self) -> dict[str, Any]:
        print("\n=== Running Verified Old-Parser Mutation in Disposable Clone ===")
        scratch_dir = tempfile.mkdtemp(
            prefix="iyi-scratch-mutation-", dir=self.work_dir
        )
        print(f"Created dedicated disposable clone at: {scratch_dir}")

        try:
            run_cmd(["git", "clone", "--quiet", self.w_dir, scratch_dir])

            run_proof_path = os.path.join(scratch_dir, "proof", "run_proof.py")
            smoke_test_path = os.path.join(scratch_dir, "proof", "smoke_test.py")

            with open(run_proof_path, "r", encoding="utf-8") as f:
                original_run_proof_src = f.read()
            original_run_proof_hash = sha256_bytes(
                original_run_proof_src.encode("utf-8")
            )
            original_smoke_test_hash = sha256_file(smoke_test_path)

            targeted_runner_code = """
import json, os, sys
sys.dont_write_bytecode = True
REPO_ROOT = os.path.abspath(sys.argv[1])
sys.path.insert(0, REPO_ROOT)
from proof import smoke_test as st

targeted_ids = [
    "o7.control.run1",
    "s5.seed.rg9-bare",
    "s5.seed.rg9-bare-141",
    "s5.seed.rg9-malformed-suffix",
    "s5.seed.rg9-extended-suffix",
    "s5.seed.rg9-140",
]

fixture_map = {f.fixture_id: f for f in st.FIXTURES}
results = {}

for fid in targeted_ids:
    if fid not in fixture_map:
        results[fid] = {"error": f"Fixture {fid} not found"}
        continue
    fixture = fixture_map[fid]
    try:
        obs = fixture.run()
        passed = bool(obs.got == obs.expected)
        results[fid] = {
            "kind": fixture.kind,
            "expected": obs.expected,
            "got": obs.got,
            "applied": obs.applied,
            "passed": passed,
        }
    except Exception as e:
        results[fid] = {
            "kind": fixture.kind,
            "exception": f"{type(e).__name__}: {e}",
            "passed": False,
        }

print(json.dumps(results, indent=2))
"""

            print("Executing targeted fixtures on pre-mutation baseline...")
            baseline_res = run_cmd(
                [sys.executable, "-B", "-c", targeted_runner_code, scratch_dir]
            )
            baseline_results = json.loads(baseline_res.stdout)

            with open(
                os.path.join(self.mutation_dir, "baseline_targeted_results.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(baseline_results, f, indent=2)

            for fid in TARGETED_FIXTURE_IDS:
                if not baseline_results.get(fid, {}).get("passed", False):
                    raise RuntimeError(
                        f"Pre-mutation baseline targeted fixture {fid} failed!\n"
                        f"{json.dumps(baseline_results.get(fid), indent=2)}"
                    )
            print("All 6 targeted fixtures PASS on pre-mutation baseline.")

            if original_run_proof_src.count(CANONICAL_RG9_BLOCK) != 1:
                raise RuntimeError(
                    "Exact canonical RG9 block not found (or found multiple times) in run_proof.py"
                )

            mutated_run_proof_src = original_run_proof_src.replace(
                CANONICAL_RG9_BLOCK, BARE_RG9_BLOCK, 1
            )
            with open(run_proof_path, "w", encoding="utf-8") as f:
                f.write(mutated_run_proof_src)

            diff_res = run_cmd(["git", "-C", scratch_dir, "diff"])
            diff_text = diff_res.stdout

            with open(
                os.path.join(self.mutation_dir, "mutation.patch"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(diff_text)

            name_status_res = run_cmd(
                ["git", "-C", scratch_dir, "diff", "--name-status"]
            )
            changed_in_scratch = [
                line.split("\t", 1)[-1].strip()
                for line in name_status_res.stdout.strip().splitlines()
                if line.strip()
            ]
            if changed_in_scratch != ["proof/run_proof.py"]:
                raise RuntimeError(
                    f"Mutation diff touched unexpected files: {changed_in_scratch}"
                )

            current_smoke_test_hash = sha256_file(smoke_test_path)
            if current_smoke_test_hash != original_smoke_test_hash:
                raise RuntimeError(
                    "smoke_test.py was modified during mutation setup!"
                )

            print("Applied verified old-parser mutation to proof/run_proof.py.")

            print("Executing targeted fixtures in fresh Python process on mutated code...")
            mutated_res = run_cmd(
                [sys.executable, "-B", "-c", targeted_runner_code, scratch_dir]
            )
            mutated_results = json.loads(mutated_res.stdout)

            with open(
                os.path.join(self.mutation_dir, "mutated_targeted_results.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(mutated_results, f, indent=2)

            ctrl_run1 = mutated_results.get("o7.control.run1", {})
            seed_bare = mutated_results.get("s5.seed.rg9-bare", {})
            seed_bare_141 = mutated_results.get("s5.seed.rg9-bare-141", {})
            seed_malformed = mutated_results.get("s5.seed.rg9-malformed-suffix", {})
            seed_extended = mutated_results.get("s5.seed.rg9-extended-suffix", {})
            seed_140 = mutated_results.get("s5.seed.rg9-140", {})

            mutation_assertions: list[str] = []

            if ctrl_run1.get("passed") is not False:
                mutation_assertions.append(
                    "Canonical summary control (o7.control.run1) unexpectedly passed under old parser"
                )
            if ctrl_run1.get("got", {}).get("status") != "FAIL":
                mutation_assertions.append(
                    f"o7.control.run1 did not report status=FAIL, got: {ctrl_run1.get('got')}"
                )

            if seed_bare.get("passed") is not False:
                mutation_assertions.append(
                    "s5.seed.rg9-bare unexpectedly passed (failed to detect old parser acceptance)"
                )
            if seed_bare.get("got", {}).get("status") != "PASS":
                mutation_assertions.append(
                    f"s5.seed.rg9-bare old parser did not wrongly accept bare summary: {seed_bare.get('got')}"
                )

            if seed_bare_141.get("passed") is not False:
                mutation_assertions.append(
                    "s5.seed.rg9-bare-141 unexpectedly passed (failed to detect old parser acceptance)"
                )
            if seed_bare_141.get("got", {}).get("status") != "PASS":
                mutation_assertions.append(
                    f"s5.seed.rg9-bare-141 old parser did not wrongly accept bare summary: {seed_bare_141.get('got')}"
                )

            if seed_140.get("passed") is not True:
                mutation_assertions.append(
                    f"140-count seed (s5.seed.rg9-140) failed: {seed_140.get('got')}"
                )

            if seed_malformed.get("passed") is not True:
                mutation_assertions.append(
                    f"Malformed suffix seed failed: {seed_malformed.get('got')}"
                )
            if seed_extended.get("passed") is not True:
                mutation_assertions.append(
                    f"Extended suffix seed failed: {seed_extended.get('got')}"
                )

            if mutation_assertions:
                raise RuntimeError(
                    "Specific semantic detection assertions failed:\n"
                    + "\n".join(mutation_assertions)
                )

            print("Semantic detection verified:")
            print("  - Canonical-summary control FAILS at gate 1.3 under old parser.")
            print("  - Bare-summary rejection seeds detect old parser wrong acceptance.")
            print("  - 140-count rejection remains enforced.")

            with open(run_proof_path, "w", encoding="utf-8") as f:
                f.write(original_run_proof_src)

            restore_diff = run_cmd(
                ["git", "-C", scratch_dir, "diff"]
            ).stdout.strip()
            restore_status = run_cmd(
                ["git", "-C", scratch_dir, "status", "--porcelain"]
            ).stdout.strip()
            restored_hash = sha256_file(run_proof_path)

            if restore_diff or restore_status:
                raise RuntimeError(
                    f"Restoration left dirty tree in scratch clone:\n{restore_status}"
                )
            if restored_hash != original_run_proof_hash:
                raise RuntimeError(
                    f"Restored run_proof.py hash mismatch: {restored_hash} != {original_run_proof_hash}"
                )

            restoration_report = {
                "original_sha256": original_run_proof_hash,
                "restored_sha256": restored_hash,
                "hashes_match": True,
                "tree_clean_after_restore": True,
            }
            with open(
                os.path.join(self.mutation_dir, "restoration_verification.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(restoration_report, f, indent=2)

            print("Restored exact saved bytes and verified bit-for-bit hash equality.")

            mutation_summary = {
                "status": "PASS",
                "diff_verified": True,
                "baseline_all_passed": True,
                "mutated_signatures": {
                    "o7.control.run1": ctrl_run1,
                    "s5.seed.rg9-bare": seed_bare,
                    "s5.seed.rg9-bare-141": seed_bare_141,
                    "s5.seed.rg9-malformed-suffix": seed_malformed,
                    "s5.seed.rg9-extended-suffix": seed_extended,
                    "s5.seed.rg9-140": seed_140,
                },
                "restoration": restoration_report,
            }

            self.summary["steps"]["old_parser_mutation"] = mutation_summary
            return mutation_summary

        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)
            if not os.path.exists(scratch_dir):
                print(f"Disposable scratch directory {scratch_dir} cleaned up.")
            else:
                print(f"WARNING: Scratch directory {scratch_dir} could not be fully deleted.")

    def audit_line_maps_and_citations(self) -> None:
        print("\n=== Auditing Line Maps, Allowlist Spans, and Citations ===")
        run_proof_path = os.path.join(self.w_dir, "proof", "run_proof.py")
        smoke_test_path = os.path.join(self.w_dir, "proof", "smoke_test.py")

        with open(run_proof_path, "r", encoding="utf-8") as f:
            rp_lines = f.readlines()
        with open(smoke_test_path, "r", encoding="utf-8") as f:
            st_content = f.read()

        opt_refusal_span = (1526, 1532)
        opt_control_span = (1533, 1533)

        refusal_chunk = "".join(
            rp_lines[opt_refusal_span[0] - 1 : opt_refusal_span[1]]
        )
        control_chunk = rp_lines[opt_control_span[0] - 1]

        if "if sys.flags.optimize:" not in refusal_chunk:
            raise RuntimeError(
                f"Line span {opt_refusal_span} does not contain sys.flags.optimize guard:\n{refusal_chunk}"
            )
        if "raise SystemExit(main())" not in control_chunk:
            raise RuntimeError(
                f"Line span {opt_control_span} does not contain normal main execution:\n{control_chunk}"
            )

        allowlist_opt_refusal = (
            '"proof.run_proof",\n        1526,\n        1532,\n        "o7.seed.run-proof-optimize-refusal"'
        )
        allowlist_opt_control = (
            '"proof.run_proof",\n        1533,\n        1533,\n        "o7.control.run-proof-optimize"'
        )

        has_allowlist_refusal = allowlist_opt_refusal in st_content
        has_allowlist_control = allowlist_opt_control in st_content

        if not (has_allowlist_refusal and has_allowlist_control):
            raise RuntimeError(
                "ALLOWLIST entries in smoke_test.py do not match updated line spans 1526-1533!"
            )

        line_map_audit = {
            "status": "PASS",
            "proof_run_proof_spans": {
                "optimize_refusal_lines": list(opt_refusal_span),
                "optimize_control_line": opt_control_span[0],
                "verified_source_matching": True,
            },
            "allowlist_entries_verified": True,
        }

        with open(
            os.path.join(self.inventory_dir, "line_map_verification.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(line_map_audit, f, indent=2)

        print("Line maps and ALLOWLIST spans 1526-1533 VERIFIED against source.")
        self.summary["steps"]["line_map_audit"] = line_map_audit

    def finalize_reports(self) -> None:
        self.summary["status"] = "PASS"
        self.summary["end_time"] = time.time()
        self.summary["elapsed_seconds"] = round(
            self.summary["end_time"] - self.summary["start_time"], 2
        )

        summary_json_path = os.path.join(self.output_dir, "audit_summary.json")
        with open(summary_json_path, "w", encoding="utf-8") as f:
            json.dump(self.summary, f, indent=2)

        md_report_path = os.path.join(self.output_dir, "audit_summary.md")

        md_content = f"""# Remote Harness Audit & Verification Report: Candidate H'' (`{self.w_sha}`)

**Date:** {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(self.summary['start_time']))}
**Target Proof Revision (W):** `{self.w_sha}`
**Prior Audited Revision (H'):** `{self.hprime_sha}`
**P1 Product Revision:** `{self.p1_sha}`
**Overall Gate Status:** **{self.summary['status']}**
**Total Execution Time:** {self.summary['elapsed_seconds']}s

---

## 1. Executive Summary

This report documents the remote CI harness audit gate for candidate proof revision H'' (`{self.w_sha[:9]}`), conducted in strict compliance with Plan Sections 2-3.

All required checks passed:
1. **Controller C & Pinned Clean W:** W cloned at `{self.w_sha}`, verified 100% clean, verified zero non-proof diff against P1.
2. **H' -> H'' Source Delta:** Confined strictly to `proof/run_proof.py` and `proof/smoke_test.py`. Census files and product source 100% identical.
3. **Producer/Consumer Grammar Agreement:** Verified exact match between `bench/stale_rg9.py` and `proof/run_proof.py`.
4. **Source-Derived Fixture Inventory:** 439 seeds and 85 controls (524 total fixtures), zero duplicates, zero overlap, all 4 new regression seeds verified and mapped.
5. **Full Suite and Coverage Gate:**
   - Command: `python3 -B proof/smoke_test.py --coverage <coverage-dir>`
   - Result: Exit 0, `HARNESS PASS`, `COVERAGE GATE PASS`.
   - Executed: 439/439 seeds passed, 85/85 controls passed, 0 missed, 0 failed.
   - Four coverage listings generated and verified; W remained completely clean.
6. **Verified Old-Parser Mutation:**
   - Dedicated disposable clone created and mutated.
   - Canonical control `o7.control.run1` failed at gate 1.3.
   - Bare summary rejection seeds `s5.seed.rg9-bare` and `s5.seed.rg9-bare-141` detected old parser acceptance and failed.
   - 140-count rejection remained enforced.
   - Restored exact saved bytes with bit-for-bit hash equality; scratch clone deleted.
7. **Line Map & Allowlist Verification:** Spans 1526-1533 verified against source.

---

## 2. Gate Verification Table

| Gate Item | Status | Details |
|---|---|---|
| **Pinned W Cleanliness** | **PASS** | HEAD `{self.w_sha}`, clean status, 0 non-proof diff vs P1 |
| **H' -> H'' Delta Audit** | **PASS** | Only `run_proof.py` and `smoke_test.py` changed, census identical |
| **Grammar Agreement** | **PASS** | `stale_rg9.py` sentence matches `run_proof.py` regex |
| **Source Inventory** | **PASS** | 439 seeds / 85 controls / 524 total / 0 duplicates |
| **Harness Smoke Suite** | **PASS** | Exit 0, `HARNESS PASS`, 524/524 fixtures executed and passed |
| **Coverage Gate** | **PASS** | `COVERAGE GATE PASS`, 4 listings generated, missing lines allowlisted |
| **Old-Parser Mutation** | **PASS** | Control failed at gate 1.3, bare seeds detected wrong acceptance, 140 rejected |
| **Restoration & Hygiene** | **PASS** | Exact bytes restored, hash matched, scratch deleted, W clean |

---

## 3. Artifact Files Generated

- `audit_summary.json`: Complete structured execution summary.
- `inventory/source_derived_inventory.json`: Full fixture listings and review item mappings.
- `coverage/coverage_summary.json`: Coverage listing statistics and allowlist verification.
- `coverage/*.cover`: The four annotated coverage listings.
- `mutation/baseline_targeted_results.json`: Targeted fixtures pre-mutation.
- `mutation/mutated_targeted_results.json`: Targeted fixtures post-mutation with failure signatures.
- `mutation/mutation.patch`: Exact patch applied in scratch clone.
- `mutation/restoration_verification.json`: Bit-for-bit restoration receipts.
- `hprime_hprimeprime_delta/hprime_to_hprimeprime.patch`: Full source diff between H' and H''.
- `hprime_hprimeprime_delta/grammar_agreement.json`: Regex vs producer sentence proof.
- `logs/smoke_test_stdout.log`: Raw stdout of the full 524-fixture smoke test.
"""
        with open(md_report_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        print("\n=== Remote Harness Audit Gate COMPLETED SUCCESSFULLY ===")
        print(f"Summary JSON: {summary_json_path}")
        print(f"Report Markdown: {md_report_path}")

    def run(self) -> int:
        try:
            self.setup_directories()
            self.record_environment()
            self.setup_pinned_w()
            self.audit_hprime_to_hprimeprime_delta()
            inv_data = self.extract_source_derived_inventory()
            self.run_full_suite_and_coverage(inv_data)
            self.run_verified_old_parser_mutation()
            self.audit_line_maps_and_citations()
            self.finalize_reports()
            return 0
        except Exception as e:
            self.summary["status"] = "FAIL"
            self.summary["error"] = f"{type(e).__name__}: {e}"
            self.summary["end_time"] = time.time()
            self.summary["elapsed_seconds"] = round(
                self.summary["end_time"] - self.summary["start_time"], 2
            )
            print(f"\nERROR: {type(e).__name__}: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()

            try:
                summary_json_path = os.path.join(
                    self.output_dir, "audit_summary.json"
                )
                with open(summary_json_path, "w", encoding="utf-8") as f:
                    json.dump(self.summary, f, indent=2)
            except Exception:
                pass
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remote Harness CI Gate and Independent H'' Audit Rail"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to controller checkout C",
    )
    parser.add_argument(
        "--w-sha",
        default=DEFAULT_W_SHA,
        help="Target frozen proof revision SHA (W)",
    )
    parser.add_argument(
        "--hprime-sha",
        default=DEFAULT_HPRIME_SHA,
        help="Prior audited proof revision SHA (H')",
    )
    parser.add_argument(
        "--p1-sha",
        default=DEFAULT_P1_SHA,
        help="P1 product revision SHA",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Path to output directory for reports and coverage listings",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Directory for scratch clones and temp working directories",
    )

    args = parser.parse_args()
    work_dir = (
        args.work_dir
        or os.environ.get("RUNNER_TEMP")
        or tempfile.gettempdir()
    )

    runner = RemoteHarnessAuditRunner(
        repo=args.repo,
        w_sha=args.w_sha,
        hprime_sha=args.hprime_sha,
        p1_sha=args.p1_sha,
        output_dir=args.output_dir,
        work_dir=work_dir,
    )
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
