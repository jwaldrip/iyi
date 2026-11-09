#!/usr/bin/env python3
"""
remote_harness_audit.py: Remote Harness CI Gate and Independent Audit Rail for PR147.

Executes Plan S3 on remote macOS-15 runner:
1. Controller checkout C verification and fresh pinned clean W checkout setup
   at 0a353e31a0a79c8b5ee36f9b627c8eb5079ed5ea (Wnew).
2. Source-derived inventory extraction:
   - 463 seeds, 86 controls, 549 total fixtures, 0 duplicates, 0 overlap.
3. Full fixture suite and coverage gate execution from W with coverage output
   strictly outside W:
   - Command: python3 -B proof/smoke_test.py --coverage <owned-output-outside-W>
   - Verifies rc == 0, HARNESS PASS, COVERAGE GATE PASS.
   - Verifies 463 seeds executed and passed, 86 controls executed and passed,
     0 missed, 0 failed, 0 duplicates.
   - Captures and validates the four coverage listings (proofkit, run_proof,
     artifact_legs, roundtrip_shim).
   - Verifies W remains completely clean.
4. Two verified mutations in a disposable clone, each with exact bit-for-bit restore:
   Mutation 1: Restore the samples-only rule in proof/run_proof.py.
     - Expect s5.seed.std-exclusion and s5.seed.rg2a-std-exclusion to fail detection.
     - Expect s5.seed.sample-exclusion to stay detected (pass).
     - Expect unrelated control o7.control.run1 to pass.
   Mutation 2: Drop the count rule in proof/run_proof.py.
     - Expect s5.seed.rg2-count-omitted, s5.seed.rg2-count-excess, and
       s5.seed.rg2-passed-short to fail detection.
     - Expect unrelated control o7.control.run1 to pass.
   - Both mutations require exact byte restoration and hash equality check.
   - If one mutation doesn't detect bug, stop not soften.
5. Independent audit instruments:
   - Exact old W (4f02007f) -> W' (5f92d9e) source delta check (verifying changes
     are strictly in proof/run_proof.py and proof/smoke_test.py).
   - Non-proof zero-diff check against P1 (e4e7e5ed).
   - Census unchanged check against old W and P1.
   - Canonical producer vs consumer grammar agreement check:
     - Render P's bench/stale_equivalence.sh RG2 and RG2a summary and exclusion format
       strings, fullmatching them with consumer regexes.
     - Verify RG9 producer sentence vs consumer regex.
   - Line map and ALLOWLIST check for run_proof.py lines 1794-1801.
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


DEFAULT_W_SHA = "0a353e31a0a79c8b5ee36f9b627c8eb5079ed5ea"
DEFAULT_OLD_W_SHA = "4f02007f07ce5a80f6779432c519f4b7a292b0a7"
DEFAULT_HPRIME_SHA = "4f02007f07ce5a80f6779432c519f4b7a292b0a7"
DEFAULT_P1_SHA = "e4e7e5ed543690cafad11d0b5c1452a710b26d54"

# Mutation 1: Restore samples-only rule in proof/run_proof.py
M1_CANONICAL_BLOCK = (
    '                    if valid_entry:\n'
    '                        reasons.append(\n'
    '                            f"CALIBRATION-EXCLUSION: {family} {prog} ({reason_text})"\n'
    '                        )'
)

M1_MUTATED_BLOCK = (
    '                    if valid_entry and prog.startswith("samples/"):\n'
    '                        reasons.append(\n'
    '                            f"CALIBRATION-EXCLUSION: {family} {prog} ({reason_text})"\n'
    '                        )'
)

M1_TARGETED_IDS = [
    "s5.seed.std-exclusion",
    "s5.seed.rg2a-std-exclusion",
    "s5.seed.sample-exclusion",
    "o7.control.run1",
]

# Mutation 2: Drop count rule in proof/run_proof.py
M2_CANONICAL_BLOCK = (
    '                if (evaluated, passed, excluded, failures) != (corpus, corpus, 0, 0):\n'
    '                    reasons.append(\n'
    '                        f"RG2-COUNT: {family} evaluated={evaluated} "\n'
    '                        f"passed={passed} excluded={excluded} "\n'
    '                        f"failures={failures} "\n'
    '                        f"expected={corpus}/{corpus}/0/0"\n'
    '                    )'
)

M2_MUTATED_BLOCK = (
    '                if False and (evaluated, passed, excluded, failures) != (corpus, corpus, 0, 0):\n'
    '                    reasons.append(\n'
    '                        f"RG2-COUNT: {family} evaluated={evaluated} "\n'
    '                        f"passed={passed} excluded={excluded} "\n'
    '                        f"failures={failures} "\n'
    '                        f"expected={corpus}/{corpus}/0/0"\n'
    '                    )'
)

M2_TARGETED_IDS = [
    "s5.seed.rg2-count-omitted",
    "s5.seed.rg2-count-excess",
    "s5.seed.rg2-passed-short",
    "o7.control.run1",
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
        old_w_sha: str = DEFAULT_OLD_W_SHA,
    ) -> None:
        self.repo = os.path.abspath(repo)
        self.w_sha = w_sha
        self.hprime_sha = hprime_sha
        self.p1_sha = p1_sha
        self.old_w_sha = old_w_sha
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
            "old_w_sha": self.old_w_sha,
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

        # Ensure isolated task-owned directory for GNU timeout symlink
        # NEVER add blanket gnubin, which shadows BSD mktemp with GNU mktemp!
        gtimeout_candidates = [
            "/opt/homebrew/bin/gtimeout",
            "/usr/local/bin/gtimeout",
        ]
        gtimeout_path = None
        for cand in gtimeout_candidates:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                gtimeout_path = cand
                break
        if not gtimeout_path:
            gtimeout_which = shutil.which("gtimeout")
            if gtimeout_which:
                gtimeout_path = gtimeout_which

        isolated_bin = os.path.join(self.work_dir, "isolated-bin")
        os.makedirs(isolated_bin, exist_ok=True)
        isolated_timeout = os.path.join(isolated_bin, "timeout")

        if gtimeout_path and not os.path.exists(isolated_timeout):
            try:
                os.symlink(gtimeout_path, isolated_timeout)
            except OSError:
                pass

        if os.path.isdir(isolated_bin) and isolated_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{isolated_bin}:{os.environ.get('PATH', '')}"

        # Verify mktemp is genuine BSD /usr/bin/mktemp
        mktemp_path = shutil.which("mktemp")
        if mktemp_path != "/usr/bin/mktemp":
            raise RuntimeError(
                f"mktemp does not resolve to system BSD /usr/bin/mktemp! Resolved to: {mktemp_path}"
            )

        # Verify Darwin temp-root invariant with bare mktemp -d probe
        getconf_path = shutil.which("getconf")
        if not getconf_path:
            raise RuntimeError("getconf does not resolve on PATH!")
        getconf_res = run_cmd([getconf_path, "DARWIN_USER_TEMP_DIR"])
        darwin_tmp_raw = getconf_res.stdout.strip()
        darwin_tmp_real = os.path.realpath(darwin_tmp_raw)

        clean_env = dict(os.environ)
        clean_env.pop("TMPDIR", None)
        probe_res = run_cmd([mktemp_path, "-d"], env=clean_env)
        probe_dir = probe_res.stdout.strip()
        probe_parent = os.path.realpath(os.path.dirname(probe_dir))
        try:
            shutil.rmtree(probe_dir, ignore_errors=True)
        except OSError:
            pass

        if probe_parent != darwin_tmp_real:
            raise RuntimeError(
                f"Bare mktemp probe parent {probe_parent!r} != Darwin temp {darwin_tmp_real!r}"
            )
        print(f"Verified system BSD mktemp: {mktemp_path} (parent {probe_parent} == {darwin_tmp_real})")

        timeout_path = shutil.which("timeout")
        if not timeout_path:
            raise RuntimeError(
                "timeout binary does not resolve on PATH! Isolated GNU coreutils gtimeout symlink required."
            )
        timeout_ver_res = run_cmd(["timeout", "--version"])
        timeout_first_line = (
            timeout_ver_res.stdout.splitlines()[0] if timeout_ver_res.stdout else ""
        )
        if "coreutils" not in timeout_first_line.lower():
            raise RuntimeError(
                f"timeout binary at {timeout_path} is not GNU coreutils: {timeout_first_line}"
            )
        print(f"Verified isolated timeout binary: {timeout_path} ({timeout_first_line})")

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
            "tools": {
                "mktemp_path": mktemp_path,
                "timeout_path": timeout_path,
                "timeout_version": timeout_first_line,
                "darwin_user_temp_real": darwin_tmp_real,
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
            "mktemp_path": mktemp_path,
            "timeout_path": timeout_path,
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

        is_ancestor = run_cmd(
            ["git", "-C", self.w_dir, "merge-base", "--is-ancestor", self.p1_sha, "HEAD"],
            check=False,
        ).returncode == 0
        if not is_ancestor:
            raise RuntimeError(
                f"W ({self.w_sha}) does not descend from P1 ({self.p1_sha})!"
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
        print("Non-proof diff against P1 is empty.")
        print(f"Hashed {len(proof_files)} proof files in W.")
        self.summary["steps"]["pinned_w"] = {
            "status": "PASS",
            "w_sha": actual_w_sha,
            "non_proof_diff_empty": True,
            "proof_files_count": len(proof_files),
        }

    def audit_hprime_to_hprimeprime_delta(self) -> None:
        print(f"\n=== Auditing Old W ({self.old_w_sha[:9]}) -> W' ({self.w_sha[:9]}) Delta and Grammar Agreement ===")
        # 1. Audit old W -> W' delta (Plan §3, S3)
        diff_res = run_cmd(
            ["git", "-C", self.repo, "diff", self.old_w_sha, self.w_sha, "--", "proof/"]
        )
        diff_text = diff_res.stdout

        patch_file = os.path.join(self.delta_dir, "hprime_to_hprimeprime.patch")
        with open(patch_file, "w", encoding="utf-8") as f:
            f.write(diff_text)

        stat_res = run_cmd(
            ["git", "-C", self.repo, "diff", "--stat", self.old_w_sha, self.w_sha, "--", "proof/"]
        )
        stat_text = stat_res.stdout.strip()

        name_status_res = run_cmd(
            [
                "git",
                "-C",
                self.repo,
                "diff",
                "--name-status",
                self.old_w_sha,
                self.w_sha,
                "--",
                "proof/",
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
                f"Unexpected files changed between old W and W': {changed_files}, "
                f"expected {expected_changed_files}"
            )

        census_diff = run_cmd(
            [
                "git",
                "-C",
                self.repo,
                "diff",
                self.old_w_sha,
                self.w_sha,
                "--",
                "proof/census/",
            ]
        ).stdout.strip()
        if census_diff:
            raise RuntimeError("Census files unexpectedly changed between old W and W'!")

        non_proof_delta = run_cmd(
            [
                "git",
                "-C",
                self.repo,
                "diff",
                self.p1_sha,
                self.w_sha,
                "--",
                ":!proof/",
            ]
        ).stdout.strip()
        if non_proof_delta:
            raise RuntimeError(f"Non-proof delta between P1 and W' is non-empty:\n{non_proof_delta}")

        # 2. Grammar agreement:
        # Render P's bench/stale_equivalence.sh RG2 and RG2a summary and exclusion format strings,
        # then fullmatch them with consumer regexes in proof/run_proof.py.
        equiv_script_path = os.path.join(self.w_dir, "bench", "stale_equivalence.sh")
        run_proof_path = os.path.join(self.w_dir, "proof", "run_proof.py")
        rg9_script_path = os.path.join(self.w_dir, "bench", "stale_rg9.py")

        with open(equiv_script_path, "r", encoding="utf-8") as f:
            equiv_src = f.read()
        with open(run_proof_path, "r", encoding="utf-8") as f:
            rp_src = f.read()
        with open(rg9_script_path, "r", encoding="utf-8") as f:
            rg9_src = f.read()

        # Producer patterns in bench/stale_equivalence.sh
        if "RG2: %d evaluated, %d passed, %d still excluded with reason, %d failures" not in equiv_src:
            raise RuntimeError("Could not locate RG2 summary format string in bench/stale_equivalence.sh")
        if "RG2a: %d evaluated, %d passed, %d still excluded with reason, %d failures" not in equiv_src:
            raise RuntimeError("Could not locate RG2a summary format string in bench/stale_equivalence.sh")
        if "  [excluded after calibration] %s: %s" not in equiv_src:
            raise RuntimeError("Could not locate exclusion format string in bench/stale_equivalence.sh")

        # Consumer regex patterns in proof/run_proof.py extracted via AST
        tree = ast.parse(rp_src)
        consumer_summary_pattern_raw = None
        consumer_excl_pattern_raw = None
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "_RG2_SUMMARY_PATTERN":
                            arg = node.value.args[0]
                            if isinstance(arg, ast.Constant):
                                consumer_summary_pattern_raw = arg.value
                        elif target.id == "_RG2_EXCLUSION_PATTERN":
                            arg = node.value.args[0]
                            if isinstance(arg, ast.Constant):
                                consumer_excl_pattern_raw = arg.value

        if not consumer_summary_pattern_raw:
            raise RuntimeError("Could not locate _RG2_SUMMARY_PATTERN in proof/run_proof.py")
        if not consumer_excl_pattern_raw:
            raise RuntimeError("Could not locate _RG2_EXCLUSION_PATTERN in proof/run_proof.py")

        consumer_summary_re = re.compile(consumer_summary_pattern_raw)
        consumer_excl_re = re.compile(consumer_excl_pattern_raw)

        # Render format strings as produced by stale_equivalence.sh
        rg2_passing = "RG2: %d evaluated, %d passed, %d still excluded with reason, %d failures" % (142, 142, 0, 0)
        rg2_excluded = "RG2: %d evaluated, %d passed, %d still excluded with reason, %d failures" % (141, 141, 1, 0)
        rg2a_passing = "RG2a: %d evaluated, %d passed, %d still excluded with reason, %d failures" % (142, 142, 0, 0)
        rg2a_excluded = "RG2a: %d evaluated, %d passed, %d still excluded with reason, %d failures" % (141, 141, 1, 0)

        excl_sample = "  [excluded after calibration] %s: %s" % ("samples/iyi/hello.iyi", "fixture sample")
        excl_std = "  [excluded after calibration] %s: %s" % ("bench/std_regex_exercise.iyi", "divergence on negative match")

        # Fullmatch evaluations
        m_rg2_pass = bool(consumer_summary_re.fullmatch(rg2_passing))
        m_rg2_excl = bool(consumer_summary_re.fullmatch(rg2_excluded))
        m_rg2a_pass = bool(consumer_summary_re.fullmatch(rg2a_passing))
        m_rg2a_excl = bool(consumer_summary_re.fullmatch(rg2a_excluded))
        m_excl_sample = bool(consumer_excl_re.fullmatch(excl_sample))
        m_excl_std = bool(consumer_excl_re.fullmatch(excl_std))

        # Negative / discriminating checks
        neg_missing_family = not bool(consumer_summary_re.fullmatch("142 evaluated, 142 passed, 0 still excluded with reason, 0 failures"))
        neg_wrong_family = not bool(consumer_summary_re.fullmatch("RG3: 142 evaluated, 142 passed, 0 still excluded with reason, 0 failures"))
        neg_leading_zero = not bool(consumer_summary_re.fullmatch("RG2: 0142 evaluated, 142 passed, 0 still excluded with reason, 0 failures"))
        neg_excl_no_indent = not bool(consumer_excl_re.fullmatch("[excluded after calibration] samples/iyi/hello.iyi: test"))
        neg_excl_no_space = not bool(consumer_excl_re.fullmatch("  [excluded after calibration] samples/iyi/hello.iyi:test"))

        grammar_failures: list[str] = []
        if not m_rg2_pass:
            grammar_failures.append("RG2 passing summary did not fullmatch consumer regex")
        if not m_rg2_excl:
            grammar_failures.append("RG2 excluded summary did not fullmatch consumer regex")
        if not m_rg2a_pass:
            grammar_failures.append("RG2a passing summary did not fullmatch consumer regex")
        if not m_rg2a_excl:
            grammar_failures.append("RG2a excluded summary did not fullmatch consumer regex")
        if not m_excl_sample:
            grammar_failures.append("Sample exclusion format did not fullmatch consumer regex")
        if not m_excl_std:
            grammar_failures.append("Std exclusion format did not fullmatch consumer regex")
        if not (neg_missing_family and neg_wrong_family and neg_leading_zero and neg_excl_no_indent and neg_excl_no_space):
            grammar_failures.append("Grammar discriminating negative tests failed")

        # RG9 producer vs consumer check
        rg9_producer_match = "print(f\"RG9 PASSED: {len(programs)} corpus programs, plain and observed legs (two processes plus IYI_WARM=1)\")" in rg9_src
        rg9_consumer_match = "rf\"^RG9 PASSED: {corpus} corpus programs, plain and observed legs \\(two processes plus IYI_WARM=1\\)$\"" in rp_src
        if not (rg9_producer_match and rg9_consumer_match):
            grammar_failures.append("RG9 producer or consumer pattern missing")

        if grammar_failures:
            raise RuntimeError(f"Grammar agreement checks failed:\n" + "\n".join(grammar_failures))

        grammar_report = {
            "producer_file": "bench/stale_equivalence.sh",
            "consumer_file": "proof/run_proof.py",
            "summary_pattern": consumer_summary_pattern_raw,
            "exclusion_pattern": consumer_excl_pattern_raw,
            "verification": {
                "rg2_passing_fullmatch": m_rg2_pass,
                "rg2_excluded_fullmatch": m_rg2_excl,
                "rg2a_passing_fullmatch": m_rg2a_pass,
                "rg2a_excluded_fullmatch": m_rg2a_excl,
                "sample_exclusion_fullmatch": m_excl_sample,
                "std_exclusion_fullmatch": m_excl_std,
                "discriminating_negatives_passed": True,
                "rg9_agreement_passed": True,
            },
            "status": "PASS",
        }

        with open(
            os.path.join(self.delta_dir, "grammar_agreement.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(grammar_report, f, indent=2)

        print(f"Old W -> W' diff stat:\n{stat_text}")
        print("Canonical producer and consumer grammar agreement VERIFIED.")
        self.summary["steps"]["delta_audit"] = {
            "status": "PASS",
            "changed_files": changed_files,
            "census_unchanged": True,
            "grammar_agreement": True,
        }

    def validate_adapted_censuses(self) -> None:
        print("\n=== Validating Adapted and All 29 Driver Censuses ===")
        sys.path.insert(0, self.w_dir)
        try:
            import proof.proofkit as pk
        finally:
            if sys.path and sys.path[0] == self.w_dir:
                sys.path.pop(0)

        DRIVERS_29 = (
            "acme", "autocert", "bzip2", "compress", "cookie", "dns", "file",
            "file_utils", "fileserver", "fuzz", "hpke", "http", "math", "mlkem",
            "png", "regex", "router", "secure_dns", "shlex", "signal", "smtp",
            "sse", "tar", "term", "tls", "websocket", "xz", "zip", "zstd",
        )
        adapted_drivers = ("http", "regex", "tls", "websocket")
        results = {}
        for d in DRIVERS_29:
            cpath = os.path.join(self.w_dir, "proof", "census", f"{d}.json")
            with open(cpath, "r", encoding="utf-8") as f:
                census = json.load(f)
            relpath = census.get("script")
            with open(os.path.join(self.w_dir, relpath), "rb") as f:
                sbytes = f.read()
            violations = pk.validate_census(census, sbytes, relpath)
            sha = hashlib.sha256(sbytes).hexdigest()
            results[d] = {
                "sha256": sha,
                "recorded_sha256": census.get("script_sha256"),
                "violations_count": len(violations),
                "violations": [list(v) for v in violations],
            }
            if violations:
                print(f"ERROR: Driver {d} has {len(violations)} violations!")
                for v in violations:
                    print(f"  {v}")
            else:
                if d in adapted_drivers:
                    print(f"Driver {d} (ADAPTED): PASS (sha256={sha[:12]}..., 0 violations)")

        failed_drivers = [d for d, r in results.items() if r["violations_count"] > 0]
        if failed_drivers:
            raise RuntimeError(f"Censuses failed validation for: {failed_drivers}")

        print("All 29 driver censuses validated cleanly with zero violations.")
        census_report_dir = os.path.join(self.output_dir, "census")
        os.makedirs(census_report_dir, exist_ok=True)
        with open(os.path.join(census_report_dir, "census_validation_report.json"), "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        self.summary["steps"]["census_validation"] = {
            "status": "PASS",
            "total_drivers": len(DRIVERS_29),
            "adapted_drivers": list(adapted_drivers),
            "zero_violations": True,
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

        if seeds_count != 463:
            raise RuntimeError(
                f"Seed inventory mismatch: expected 463 seeds, got {seeds_count}"
            )
        if controls_count != 86:
            raise RuntimeError(
                f"Control inventory mismatch: expected 86 controls, got {controls_count}"
            )
        if total_count != 549:
            raise RuntimeError(
                f"Total inventory mismatch: expected 549 fixtures, got {total_count}"
            )
        if unique_count != 549:
            raise RuntimeError(
                f"Duplicate fixture registration detected! {total_count} total != {unique_count} unique"
            )

        overlap = set(inv_data["seed_ids"]).intersection(set(inv_data["control_ids"]))
        if overlap:
            raise RuntimeError(
                f"Fixture ID registered as both seed and control: {overlap}"
            )

        required_regression_ids = [
            "s5.seed.sample-exclusion",
            "s5.seed.std-exclusion",
            "s5.seed.rg2a-std-exclusion",
            "s5.seed.rg2-malformed-exclusion",
            "s5.seed.rg2-truncated-log",
            "s5.seed.rg2-invalid-selector",
            "s5.seed.rg2-duplicate-exclusion",
            "s5.seed.rg2-count-omitted",
            "s5.seed.rg2-count-excess",
            "s5.seed.rg2-passed-short",
            "s5.seed.rg2-log-mismatch-missing-line",
            "s5.seed.rg2-log-mismatch-extra-line",
            "s5.seed.rg2-summary-missing",
            "s5.seed.rg2-summary-duplicate",
            "s5.seed.rg2-summary-malformed",
            "s5.seed.rg2-sentinel-missing",
            "s5.seed.rg2-sentinel-duplicate",
            "s5.seed.rg2-sentinel-order",
            "s5.seed.rg2-unattributed-exclusion",
            "o7.seed.run1-rg2-log-missing",
            "o7.seed.final-no-run1-attempt",
            "o7.seed.final-rg2-evidence-missing",
            "o7.seed.final-rg2-log-tampered",
            "o7.seed.final-rg2-summary-tampered",
        ]
        for reg_id in required_regression_ids:
            if reg_id not in inv_data["seed_ids"]:
                raise RuntimeError(f"Required regression seed missing from W: {reg_id}")

        if "s5.control.rg2-corpus-evidence" not in inv_data["control_ids"]:
            raise RuntimeError("Required control s5.control.rg2-corpus-evidence missing from W!")

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
            "required_regression_ids": required_regression_ids,
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
        passed_controls: set[str] = set()
        failed_controls: set[str] = set()
        totals: dict[str, int] = {}

        for line in stdout_text.splitlines():
            line_str = line.strip()
            if line_str.startswith("SEED "):
                parts = line_str.split(maxsplit=2)
                if len(parts) >= 2:
                    executed_seeds.add(parts[1])
            m_ctrl = re.match(r"^CONTROL\s+([\w\.\-]+)\s+(PASS|FAIL)", line_str)
            if m_ctrl:
                fid, st = m_ctrl.groups()
                executed_controls.add(fid)
                if st == "PASS":
                    passed_controls.add(fid)
                else:
                    failed_controls.add(fid)
            m_total = re.match(
                r"^TOTAL\s+seeds_executed=(\d+)\s+seeds_passed=(\d+)\s+seeds_missed=(\d+)\s+seeds_missing=(\d+)\s+"
                r"controls_executed=(\d+)\s+controls_failed=(\d+)\s+controls_missing=(\d+)",
                line_str,
            )
            if m_total:
                totals = {
                    "seeds_executed": int(m_total.group(1)),
                    "seeds_passed": int(m_total.group(2)),
                    "seeds_missed": int(m_total.group(3)),
                    "seeds_missing": int(m_total.group(4)),
                    "controls_executed": int(m_total.group(5)),
                    "controls_failed": int(m_total.group(6)),
                    "controls_missing": int(m_total.group(7)),
                }

        harness_pass = "HARNESS PASS" in stdout_text
        coverage_pass = "COVERAGE GATE PASS" in stdout_text

        print(f"Executed seeds: {len(executed_seeds)} (totals line: {totals.get('seeds_executed')})")
        print(f"Executed controls: {len(executed_controls)} (totals line: {totals.get('controls_executed')})")
        print(f"Controls passed: {len(passed_controls)}, failed: {len(failed_controls)}")
        print(f"Totals breakdown: {totals}")
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
        if not totals:
            validation_errors.append("TOTAL summary line missing from output")
        else:
            if totals.get("seeds_executed") != 463:
                validation_errors.append(
                    f"Totals seeds_executed mismatch: expected 463, got {totals.get('seeds_executed')}"
                )
            if totals.get("seeds_passed") != 463:
                validation_errors.append(
                    f"Totals seeds_passed mismatch: expected 463, got {totals.get('seeds_passed')}"
                )
            if totals.get("seeds_missed") != 0:
                validation_errors.append(
                    f"Totals seeds_missed non-zero: {totals.get('seeds_missed')}"
                )
            if totals.get("seeds_missing") != 0:
                validation_errors.append(
                    f"Totals seeds_missing non-zero: {totals.get('seeds_missing')}"
                )
            if totals.get("controls_executed") != 86:
                validation_errors.append(
                    f"Totals controls_executed mismatch: expected 86, got {totals.get('controls_executed')}"
                )
            if totals.get("controls_failed") != 0:
                validation_errors.append(
                    f"Totals controls_failed non-zero: {totals.get('controls_failed')}"
                )
            if totals.get("controls_missing") != 0:
                validation_errors.append(
                    f"Totals controls_missing non-zero: {totals.get('controls_missing')}"
                )

        if len(executed_seeds) != 463:
            validation_errors.append(
                f"Parsed executed seeds count mismatch: expected 463, got {len(executed_seeds)}"
            )
        if len(executed_controls) != 86:
            validation_errors.append(
                f"Parsed executed controls count mismatch: expected 86, got {len(executed_controls)}"
            )
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
            "totals": totals,
            "seeds_executed": len(executed_seeds),
            "controls_executed": len(executed_controls),
            "controls_passed": len(passed_controls),
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
                "Coverage gate validation failures:\n" + "\n".join(validation_errors)
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

    def verify_targeted_stdout(
        self, stdout_text: str, targeted_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        parsed: dict[str, dict[str, Any]] = {}
        ctrl_re = re.compile(r"^CONTROL\s+([\w\.\-]+)\s+(PASS|FAIL)(.*)$")
        seed_re = re.compile(
            r"^SEED\s+([\w\.\-]+)\s+expect=(.+?)\s+got=(.+?)\s+applied=(.+)$"
        )

        for line in stdout_text.splitlines():
            line_str = line.strip()
            m_ctrl = ctrl_re.match(line_str)
            if m_ctrl:
                fid = m_ctrl.group(1)
                st = m_ctrl.group(2)
                rest = m_ctrl.group(3).strip()
                if fid in targeted_ids:
                    if fid in parsed:
                        raise RuntimeError(f"Duplicate control line in stdout: {fid}")
                    if st == "PASS":
                        parsed[fid] = {"kind": "control", "status": "PASS"}
                    else:  # FAIL
                        m_exp = re.search(r"expect=(.+?)\s+got=(.+)$", rest)
                        if not m_exp:
                            raise RuntimeError(
                                f"Malformed CONTROL FAIL line missing expect/got: {line_str}"
                            )
                        try:
                            exp_val = json.loads(m_exp.group(1))
                            got_val = json.loads(m_exp.group(2))
                        except json.JSONDecodeError as err:
                            raise RuntimeError(
                                f"CONTROL FAIL line contains malformed JSON: {line_str}\nError: {err}"
                            )
                        parsed[fid] = {
                            "kind": "control",
                            "status": "FAIL",
                            "expected": exp_val,
                            "got": got_val,
                        }

            m_seed = seed_re.match(line_str)
            if m_seed:
                fid = m_seed.group(1)
                if fid in targeted_ids:
                    if fid in parsed:
                        raise RuntimeError(f"Duplicate seed line in stdout: {fid}")
                    try:
                        exp_val = json.loads(m_seed.group(2))
                        got_val = json.loads(m_seed.group(3))
                    except json.JSONDecodeError as err:
                        raise RuntimeError(
                            f"SEED line contains malformed JSON: {line_str}\nError: {err}"
                        )
                    applied_raw = m_seed.group(4).strip()
                    try:
                        applied_val = json.loads(applied_raw)
                    except Exception:
                        applied_val = applied_raw
                    if not applied_val or applied_val == "MISSING":
                        raise RuntimeError(
                            f"SEED line has missing or invalid applied evidence: {line_str}"
                        )
                    parsed[fid] = {
                        "kind": "seed",
                        "expected": exp_val,
                        "got": got_val,
                        "applied": applied_val,
                        "passed": bool(exp_val == got_val),
                    }

        missing = [fid for fid in targeted_ids if fid not in parsed]
        if missing:
            raise RuntimeError(
                f"Targeted stdout missing output lines for fixtures: {missing}\n"
                f"--- full stdout ---\n{stdout_text}"
            )
        return parsed

    def _execute_single_mutation(
        self,
        mutation_name: str,
        canonical_block: str,
        mutated_block: str,
        targeted_ids: list[str],
        verify_fn: Any,
    ) -> dict[str, Any]:
        print(f"\n=== Executing Verified Mutation: {mutation_name} ===")
        scratch_dir = tempfile.mkdtemp(
            prefix=f"iyi-mutation-{mutation_name}-", dir=self.work_dir
        )
        sub_mut_dir = os.path.join(self.mutation_dir, mutation_name)
        os.makedirs(sub_mut_dir, exist_ok=True)
        print(f"Created dedicated disposable clone at: {scratch_dir}")

        targeted_runner_code = """
import json, os, sys
sys.dont_write_bytecode = True
REPO_ROOT = os.path.abspath(sys.argv[1])
OUTPUT_JSON_PATH = os.path.abspath(sys.argv[2])
TARGETED_IDS = [x.strip() for x in sys.argv[3].split(",") if x.strip()]
sys.path.insert(0, REPO_ROOT)
from proof import smoke_test as st

def _normalize(value: object) -> object:
    if isinstance(value, (set, frozenset)):
        members = [_normalize(item) for item in value]
        members.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return {"__audit_type__": type(value).__name__, "items": members}
    if isinstance(value, tuple):
        return {"__audit_type__": "tuple", "items": [_normalize(item) for item in value]}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("Audit object keys must be strings")
        return {key: _normalize(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Cannot serialize {type(value).__name__}")

def _render(value: object) -> str:
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"))

fixture_map = {f.fixture_id: f for f in st.FIXTURES}
results = {}

for fid in TARGETED_IDS:
    if fid not in fixture_map:
        results[fid] = {"error": f"Fixture {fid} not found"}
        continue
    fixture = fixture_map[fid]
    try:
        obs = fixture.run()
        if not isinstance(obs, st.Observation):
            raise TypeError(
                f"fixture returned {type(obs).__name__}, not Observation"
            )
    except Exception as e:
        obs = st.Observation(
            expected="fixture completes",
            got=f"{type(e).__name__}: {e}",
            applied=f"fixture_exception={type(e).__name__}",
        )

    if fixture.kind == "seed":
        if not obs.applied:
            obs = st.Observation(
                expected={
                    "observation": obs.expected,
                    "harness": "applied evidence present",
                },
                got={
                    "observation": obs.got,
                    "harness": "missing applied evidence",
                },
                applied="MISSING",
            )
        passed = bool(obs.got == obs.expected)
        results[fid] = {
            "kind": fixture.kind,
            "expected": obs.expected,
            "got": obs.got,
            "applied": obs.applied,
            "passed": passed,
        }
        print(
            f"SEED {fixture.fixture_id} "
            f"expect={_render(obs.expected)} "
            f"got={_render(obs.got)} "
            f"applied={_render(obs.applied)}"
        )
    elif fixture.kind == "control":
        passed = bool(obs.got == obs.expected)
        results[fid] = {
            "kind": fixture.kind,
            "expected": obs.expected,
            "got": obs.got,
            "applied": getattr(obs, "applied", ""),
            "passed": passed,
        }
        if passed:
            print(f"CONTROL {fixture.fixture_id} PASS")
        else:
            print(
                f"CONTROL {fixture.fixture_id} FAIL "
                f"expect={_render(obs.expected)} "
                f"got={_render(obs.got)}"
            )

with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
    json.dump(_normalize(results), f, indent=2, sort_keys=True)
"""

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

            # 1. Baseline check (pre-mutation)
            baseline_json_path = os.path.join(
                sub_mut_dir, "baseline_targeted_results.json"
            )
            print(f"Executing targeted fixtures on pre-mutation baseline for {mutation_name}...")
            baseline_start = time.time()
            baseline_res = run_cmd(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    targeted_runner_code,
                    scratch_dir,
                    baseline_json_path,
                    ",".join(targeted_ids),
                ],
                cwd=scratch_dir,
                check=False,
            )
            baseline_elapsed = round(time.time() - baseline_start, 2)

            with open(
                os.path.join(sub_mut_dir, "baseline_raw_stdout.log"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(baseline_res.stdout)
            with open(
                os.path.join(sub_mut_dir, "baseline_raw_stderr.log"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(baseline_res.stderr)

            baseline_exec_info = {
                "returncode": baseline_res.returncode,
                "elapsed_seconds": baseline_elapsed,
                "stdout_bytes": len(baseline_res.stdout.encode("utf-8")),
                "stderr_bytes": len(baseline_res.stderr.encode("utf-8")),
            }
            with open(
                os.path.join(sub_mut_dir, "baseline_execution.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(baseline_exec_info, f, indent=2)

            if baseline_res.returncode != 0:
                raise RuntimeError(
                    f"Baseline targeted runner failed with returncode {baseline_res.returncode}\n"
                    f"--- stdout ---\n{baseline_res.stdout}\n"
                    f"--- stderr ---\n{baseline_res.stderr}"
                )

            with open(baseline_json_path, "r", encoding="utf-8") as f:
                baseline_results = json.load(f)

            baseline_stdout_parsed = self.verify_targeted_stdout(
                baseline_res.stdout, targeted_ids
            )

            for fid in targeted_ids:
                if not baseline_results.get(fid, {}).get("passed", False):
                    raise RuntimeError(
                        f"Pre-mutation baseline fixture {fid} failed!\n"
                        f"{json.dumps(baseline_results.get(fid), indent=2)}"
                    )
            print(f"All {len(targeted_ids)} targeted fixtures PASS on pre-mutation baseline.")

            # 2. Apply mutation
            if original_run_proof_src.count(canonical_block) != 1:
                raise RuntimeError(
                    f"Exact canonical block for {mutation_name} count={original_run_proof_src.count(canonical_block)} != 1 in run_proof.py"
                )

            mutated_run_proof_src = original_run_proof_src.replace(
                canonical_block, mutated_block, 1
            )
            with open(run_proof_path, "w", encoding="utf-8") as f:
                f.write(mutated_run_proof_src)

            diff_res = run_cmd(["git", "-C", scratch_dir, "diff"])
            diff_text = diff_res.stdout
            if not diff_text.strip():
                raise RuntimeError(f"Mutation diff is empty in scratch clone for {mutation_name}!")

            with open(
                os.path.join(sub_mut_dir, "mutation.patch"),
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

            print(f"Applied verified mutation {mutation_name} to proof/run_proof.py.")

            # 3. Execute mutated targeted fixtures in fresh Python process
            print(f"Executing targeted fixtures in fresh Python process on mutated code ({mutation_name})...")
            mutated_json_path = os.path.join(
                sub_mut_dir, "mutated_targeted_results.json"
            )
            mutated_start = time.time()
            mutated_res = run_cmd(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    targeted_runner_code,
                    scratch_dir,
                    mutated_json_path,
                    ",".join(targeted_ids),
                ],
                cwd=scratch_dir,
                check=False,
            )
            mutated_elapsed = round(time.time() - mutated_start, 2)

            with open(
                os.path.join(sub_mut_dir, "mutated_raw_stdout.log"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(mutated_res.stdout)
            with open(
                os.path.join(sub_mut_dir, "mutated_raw_stderr.log"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(mutated_res.stderr)

            mutated_exec_info = {
                "returncode": mutated_res.returncode,
                "elapsed_seconds": mutated_elapsed,
                "stdout_bytes": len(mutated_res.stdout.encode("utf-8")),
                "stderr_bytes": len(mutated_res.stderr.encode("utf-8")),
            }
            with open(
                os.path.join(sub_mut_dir, "mutated_execution.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(mutated_exec_info, f, indent=2)

            if mutated_res.returncode != 0:
                raise RuntimeError(
                    f"Mutated targeted runner failed with returncode {mutated_res.returncode}\n"
                    f"--- stdout ---\n{mutated_res.stdout}\n"
                    f"--- stderr ---\n{mutated_res.stderr}"
                )

            with open(mutated_json_path, "r", encoding="utf-8") as f:
                mutated_results = json.load(f)

            mutated_stdout_parsed = self.verify_targeted_stdout(
                mutated_res.stdout, targeted_ids
            )

            # 4. Semantic detection assertions (caller-provided verify_fn)
            verify_fn(mutated_results)

            # 5. Exact byte restoration
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
                    f"Restoration left dirty tree in scratch clone for {mutation_name}:\n{restore_status}"
                )
            if restored_hash != original_run_proof_hash:
                raise RuntimeError(
                    f"Restored run_proof.py hash mismatch in {mutation_name}: {restored_hash} != {original_run_proof_hash}"
                )

            restoration_report = {
                "original_sha256": original_run_proof_hash,
                "restored_sha256": restored_hash,
                "hashes_match": True,
                "tree_clean_after_restore": True,
            }
            with open(
                os.path.join(sub_mut_dir, "restoration_verification.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(restoration_report, f, indent=2)

            print(f"Restored exact saved bytes for {mutation_name} and verified bit-for-bit hash equality.")

            return {
                "status": "PASS",
                "diff_verified": True,
                "baseline_all_passed": True,
                "baseline_execution": baseline_exec_info,
                "mutated_execution": mutated_exec_info,
                "mutated_results": mutated_results,
                "restoration": restoration_report,
            }

        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)
            if not os.path.exists(scratch_dir):
                print(f"Disposable scratch clone {scratch_dir} cleaned up.")

    def run_verified_mutations(self) -> dict[str, Any]:
        print("\n=== Running Verified Mutations (Plan §3 S3) ===")

        # Mutation 1: Restore the samples-only rule
        # Expect s5.seed.std-exclusion and s5.seed.rg2a-std-exclusion to fail detection
        # while s5.seed.sample-exclusion stays detected (passes) and o7.control.run1 passes.
        def verify_m1(mutated_results: dict[str, Any]) -> None:
            assertions: list[str] = []
            seed_std = mutated_results.get("s5.seed.std-exclusion", {})
            seed_rg2a = mutated_results.get("s5.seed.rg2a-std-exclusion", {})
            seed_sample = mutated_results.get("s5.seed.sample-exclusion", {})
            ctrl = mutated_results.get("o7.control.run1", {})

            if seed_std.get("passed") is not False:
                assertions.append("s5.seed.std-exclusion unexpectedly passed under samples-only mutation")
            if seed_rg2a.get("passed") is not False:
                assertions.append("s5.seed.rg2a-std-exclusion unexpectedly passed under samples-only mutation")
            if seed_sample.get("passed") is not True:
                assertions.append(f"s5.seed.sample-exclusion failed under samples-only mutation: {seed_sample}")
            if ctrl.get("passed") is not True:
                assertions.append(f"Unrelated control o7.control.run1 failed under samples-only mutation: {ctrl}")

            if assertions:
                raise RuntimeError(
                    "Mutation 1 (samples-only rule) semantic verification failed:\n"
                    + "\n".join(assertions)
                )
            print("Mutation 1 semantic detection VERIFIED:")
            print("  - s5.seed.std-exclusion FAILED detection as expected.")
            print("  - s5.seed.rg2a-std-exclusion FAILED detection as expected.")
            print("  - s5.seed.sample-exclusion STAYED DETECTED (passed) as expected.")
            print("  - Unrelated control o7.control.run1 PASSED as expected.")

        m1_summary = self._execute_single_mutation(
            mutation_name="samples_only_rule",
            canonical_block=M1_CANONICAL_BLOCK,
            mutated_block=M1_MUTATED_BLOCK,
            targeted_ids=M1_TARGETED_IDS,
            verify_fn=verify_m1,
        )

        # Mutation 2: Drop the count rule
        # Expect s5.seed.rg2-count-omitted, s5.seed.rg2-count-excess, and
        # s5.seed.rg2-passed-short to fail detection while o7.control.run1 passes.
        def verify_m2(mutated_results: dict[str, Any]) -> None:
            assertions: list[str] = []
            seed_omitted = mutated_results.get("s5.seed.rg2-count-omitted", {})
            seed_excess = mutated_results.get("s5.seed.rg2-count-excess", {})
            seed_short = mutated_results.get("s5.seed.rg2-passed-short", {})
            ctrl = mutated_results.get("o7.control.run1", {})

            if seed_omitted.get("passed") is not False:
                assertions.append("s5.seed.rg2-count-omitted unexpectedly passed when count rule dropped")
            if seed_excess.get("passed") is not False:
                assertions.append("s5.seed.rg2-count-excess unexpectedly passed when count rule dropped")
            if seed_short.get("passed") is not False:
                assertions.append("s5.seed.rg2-passed-short unexpectedly passed when count rule dropped")
            if ctrl.get("passed") is not True:
                assertions.append(f"Unrelated control o7.control.run1 failed when count rule dropped: {ctrl}")

            if assertions:
                raise RuntimeError(
                    "Mutation 2 (drop count rule) semantic verification failed:\n"
                    + "\n".join(assertions)
                )
            print("Mutation 2 semantic detection VERIFIED:")
            print("  - s5.seed.rg2-count-omitted FAILED detection as expected.")
            print("  - s5.seed.rg2-count-excess FAILED detection as expected.")
            print("  - s5.seed.rg2-passed-short FAILED detection as expected.")
            print("  - Unrelated control o7.control.run1 PASSED as expected.")

        m2_summary = self._execute_single_mutation(
            mutation_name="drop_count_rule",
            canonical_block=M2_CANONICAL_BLOCK,
            mutated_block=M2_MUTATED_BLOCK,
            targeted_ids=M2_TARGETED_IDS,
            verify_fn=verify_m2,
        )

        mutations_overall = {
            "status": "PASS",
            "both_mutations_caught": True,
            "mutation_1_samples_only": m1_summary,
            "mutation_2_drop_count": m2_summary,
        }

        with open(
            os.path.join(self.mutation_dir, "mutation_summary.json"),
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(mutations_overall, f, indent=2)

        self.summary["steps"]["mutations"] = mutations_overall
        return mutations_overall

    def audit_line_maps_and_citations(self) -> None:
        print("\n=== Auditing Line Maps, Allowlist Spans, and Citations ===")
        run_proof_path = os.path.join(self.w_dir, "proof", "run_proof.py")
        smoke_test_path = os.path.join(self.w_dir, "proof", "smoke_test.py")

        with open(run_proof_path, "r", encoding="utf-8") as f:
            rp_lines = f.readlines()
        with open(smoke_test_path, "r", encoding="utf-8") as f:
            st_content = f.read()

        opt_refusal_span = (1794, 1800)
        opt_control_span = (1801, 1801)

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
            '"proof.run_proof",\n        1794,\n        1800,\n        "o7.seed.run-proof-optimize-refusal"'
        )
        allowlist_opt_control = (
            '"proof.run_proof",\n        1801,\n        1801,\n        "o7.control.run-proof-optimize"'
        )

        has_allowlist_refusal = allowlist_opt_refusal in st_content
        has_allowlist_control = allowlist_opt_control in st_content

        if not (has_allowlist_refusal and has_allowlist_control):
            raise RuntimeError(
                "ALLOWLIST entries in smoke_test.py do not match updated line spans 1794-1801!"
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

        print("Line maps and ALLOWLIST spans 1794-1801 VERIFIED against source.")
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

        md_content = f"""# Remote Harness Audit & Verification Report: Dedicated Controller C for W' (`{self.w_sha}`)

**Date:** {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(self.summary['start_time']))}
**Target Proof Revision (W'):** `{self.w_sha}`
**Prior Audited Revision (old W):** `{self.old_w_sha}`
**P1 Product Revision:** `{self.p1_sha}`
**Overall Gate Status:** **{self.summary['status']}**
**Total Execution Time:** {self.summary['elapsed_seconds']}s

---

## 1. Executive Summary

This report documents the remote CI harness audit gate for candidate proof revision W' (`{self.w_sha[:9]}`), conducted in strict compliance with Plan Section 4 S3 and the user-ratified zero-exclusion amendment.

All required checks passed:
1. **Controller C & Pinned Clean W':** W cloned at `{self.w_sha}`, verified 100% clean, verified zero non-proof diff against P1 (`{self.p1_sha}`).
2. **Old W -> W' Source Delta:** Confined strictly to `proof/run_proof.py` and `proof/smoke_test.py`. Census files and product source 100% identical.
3. **Producer/Consumer Grammar Agreement:** Verified exact match between `bench/stale_equivalence.sh` (RG2 & RG2a format strings) and `proof/run_proof.py` consumer regexes, as well as `bench/stale_rg9.py` RG9 agreement.
4. **Source-Derived Fixture Inventory:** 463 seeds and 86 controls (549 total fixtures), zero duplicates, zero overlap, all required zero-exclusion regression seeds verified and mapped.
5. **Full Suite and Coverage Gate:**
   - Command: `python3 -B proof/smoke_test.py --coverage <coverage-dir>`
   - Result: Exit 0, `HARNESS PASS`, `COVERAGE GATE PASS`.
   - Executed: 463/463 seeds passed, 86/86 controls passed, 0 missed, 0 failed.
   - Four coverage listings generated and verified; W remained completely clean.
6. **Two Verified Runtime Gate Mutations:**
   - **Mutation 1 (Restore samples-only rule):**
     - Target: `proof/run_proof.py` `CALIBRATION-EXCLUSION` block restricted to `samples/`.
     - `s5.seed.std-exclusion` and `s5.seed.rg2a-std-exclusion` failed detection.
     - `s5.seed.sample-exclusion` stayed detected (passed).
     - Unrelated control `o7.control.run1` passed.
     - Exact bit-for-bit bytes restored and verified.
   - **Mutation 2 (Drop count rule):**
     - Target: `proof/run_proof.py` `RG2-COUNT` block disabled.
     - `s5.seed.rg2-count-omitted`, `s5.seed.rg2-count-excess`, and `s5.seed.rg2-passed-short` failed detection.
     - Unrelated control `o7.control.run1` passed.
     - Exact bit-for-bit bytes restored and verified.
7. **Line Map & Allowlist Verification:** Spans 1794-1801 verified against source.

---

## 2. Gate Verification Table

| Gate Item | Status | Details |
|---|---|---|
| **Pinned W Cleanliness** | **PASS** | HEAD `{self.w_sha}`, clean status, 0 non-proof diff vs P1 |
| **Old W -> W' Delta Audit** | **PASS** | Only `run_proof.py` and `smoke_test.py` changed, census identical |
| **Grammar Agreement** | **PASS** | `stale_equivalence.sh` RG2/RG2a format strings match `run_proof.py` regexes |
| **Source Inventory** | **PASS** | 463 seeds / 86 controls / 549 total / 0 duplicates |
| **Harness Smoke Suite** | **PASS** | Exit 0, `HARNESS PASS`, 549/549 fixtures executed and passed |
| **Coverage Gate** | **PASS** | `COVERAGE GATE PASS`, 4 listings generated, missing lines allowlisted |
| **Mutation 1 (Samples-Only)** | **PASS** | Both std seeds failed detection, sample seed stayed detected, control passed |
| **Mutation 2 (Drop Count)** | **PASS** | All 3 count seeds failed detection, control passed |
| **Restoration & Hygiene** | **PASS** | Exact bytes restored for both mutations, hash matched, scratch deleted, W clean |
| **Line Maps & Allowlist** | **PASS** | Spans 1794-1800 (refusal) and 1801 (control) verified |

---

## 3. Artifact Files Generated

- `audit_summary.json`: Complete structured execution summary.
- `inventory/source_derived_inventory.json`: Full fixture listings and review item mappings.
- `inventory/line_map_verification.json`: Line map and allowlist verification.
- `coverage/coverage_summary.json`: Coverage listing statistics and allowlist verification.
- `coverage/*.cover`: The four annotated coverage listings.
- `mutation/mutation_summary.json`: Top-level summary of both mutations.
- `mutation/samples_only_rule/`: Mutation 1 patch, logs, results, restoration receipts.
- `mutation/drop_count_rule/`: Mutation 2 patch, logs, results, restoration receipts.
- `hprime_hprimeprime_delta/hprime_to_hprimeprime.patch`: Full source diff between old W and W'.
- `hprime_hprimeprime_delta/grammar_agreement.json`: Regex vs producer format string proofs.
- `logs/smoke_test_stdout.log`: Raw stdout of the full 549-fixture smoke test.
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
            self.validate_adapted_censuses()
            inv_data = self.extract_source_derived_inventory()
            self.run_full_suite_and_coverage(inv_data)
            self.run_verified_mutations()
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
        description="Remote Harness CI Gate and Independent Audit Rail for PR147"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to controller checkout C",
    )
    parser.add_argument(
        "--w-sha",
        default=DEFAULT_W_SHA,
        help="Target frozen proof revision SHA (W')",
    )
    parser.add_argument(
        "--old-w-sha",
        default=DEFAULT_OLD_W_SHA,
        help="Prior vetted proof revision SHA (old W)",
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
        old_w_sha=args.old_w_sha,
    )
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
