#!/usr/bin/env python3
"""Bounded YAML foldcopy mutation diagnostic driver.

Slice B: Evidence-only bounded YAML diagnostic.
Captures complete raw termination, return code, stdout, and stderr for the
foldcopy mutation and its unmodified control under the pinned P1 compiler.

Contract:
    diagnose_foldcopy.py --pin PIN --repo ISOLATED_SOURCE --report-dir NEW_OWNED_DIR

Limitations and Caveats:
    - Fresh diagnostic caches: Uses freshly initialized temporary and cache
      directories; cannot reconstruct the deleted cache state of the failed attempt.
    - Relocated source paths: Uses the specified isolated source repository;
      compilation paths and cache keys reflect this isolated repository path.
    - Evidence-only diagnostic: Runs outside the canonical bench scripts and
      does not count as a strict-chain PASS.
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any, Sequence

# Pinned constants from H' / P1 specification
P1_SOURCE_SHA = "626463375298d357ffcb3223059f4d3adce6fb10"
EXPECTED_COMPILER_SHA256 = (
    "b8afdb5f55b03754b8194978e320cbca3c0816661cadcbd3083f0872a64ca418"
)

# Expected assertion for negative proof
EXPECTED_ASSERTION = (
    "ASSERTION FAILED: quoted scalars of 20,000 lines read in under a second"
)

# Mutation anchor and replacement in src/std/yaml.iyi
MUTATION_ANCHOR = (
    "    count = @buffer.size\n"
    "    while count > floor"
)
MUTATION_REPLACEMENT = (
    "    text = @buffer.to_s\n"
    "    count = text.bytesize\n"
    "    @buffer.clear\n"
    "    @buffer.append(text.to_unsafe, count)\n"
    "    while count > floor"
)

# Environment allowlist for serialization (never serialize secrets)
ALLOWED_ENV_KEYS = {
    "HOME",
    "PATH",
    "TMPDIR",
    "IYI_CACHE_DIR",
    "IYI_PATH",
    "LIBRARY_PATH",
    "PKG_CONFIG_PATH",
    "PYTHONDONTWRITEBYTECODE",
    "LANG",
    "LC_ALL",
    "TERM",
    "USER",
    "LOGNAME",
    "SHELL",
}

# Standard time bounds
COMMAND_TIMEOUT_SEC = 60.0
CLEANUP_GRACE_SEC = 5.0


class DiagnosticValidationError(Exception):
    """Raised when pin, compiler, or source parity validation fails."""


def sha256_file(path: str | Path) -> str:
    """Compute hex SHA-256 of file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def load_pin_data(pin_arg: str | Path) -> tuple[dict[str, Any], str]:
    """Load pin.json from file or directory containing pin.json."""
    pin_path = Path(pin_arg).resolve()
    if pin_path.is_dir():
        candidate = pin_path / "pin.json"
        if not candidate.is_file():
            raise DiagnosticValidationError(f"pin.json not found in directory: {pin_path}")
        pin_file = candidate
    elif pin_path.is_file():
        pin_file = pin_path
    else:
        raise DiagnosticValidationError(f"PIN path does not exist: {pin_path}")

    try:
        with open(pin_file, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (json.JSONDecodeError, OSError) as error:
        raise DiagnosticValidationError(f"Failed to read pin file {pin_file}: {error}") from error

    required_keys = (
        "p_source_sha",
        "compiler_path",
        "compiler_sha256",
        "timeout_path",
        "env_path",
        "env_home",
    )
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise DiagnosticValidationError(f"Pin missing required keys: {missing}")

    return data, str(pin_file)


def validate_p1_and_compiler(pin: dict[str, Any]) -> dict[str, Any]:
    """Validate P1 identity, compiler hash, and timeout utility."""
    p_source_sha = pin["p_source_sha"]
    if p_source_sha != P1_SOURCE_SHA:
        raise DiagnosticValidationError(
            f"Pin p_source_sha mismatch: expected {P1_SOURCE_SHA}, got {p_source_sha}"
        )

    compiler_sha256_pin = pin["compiler_sha256"]
    if compiler_sha256_pin != EXPECTED_COMPILER_SHA256:
        raise DiagnosticValidationError(
            f"Pin compiler_sha256 mismatch: expected {EXPECTED_COMPILER_SHA256}, got {compiler_sha256_pin}"
        )

    compiler_path = Path(pin["compiler_path"]).resolve()
    if not compiler_path.is_file():
        raise DiagnosticValidationError(f"Compiler binary missing: {compiler_path}")
    if not os.access(compiler_path, os.X_OK):
        raise DiagnosticValidationError(f"Compiler binary not executable: {compiler_path}")

    actual_compiler_sha256 = sha256_file(compiler_path)
    if actual_compiler_sha256 != EXPECTED_COMPILER_SHA256:
        raise DiagnosticValidationError(
            f"Compiler binary hash mismatch: expected {EXPECTED_COMPILER_SHA256}, got {actual_compiler_sha256}"
        )

    timeout_path = Path(pin["timeout_path"]).resolve()
    if not timeout_path.is_file():
        raise DiagnosticValidationError(f"Timeout binary missing: {timeout_path}")
    if not os.access(timeout_path, os.X_OK):
        raise DiagnosticValidationError(f"Timeout binary not executable: {timeout_path}")

    p_clean: bool | None = None
    p_head: str | None = None
    p_path = pin.get("p_path")
    if p_path and Path(p_path).is_dir():
        try:
            head_proc = subprocess.run(
                ["git", "-C", str(p_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if head_proc.returncode == 0:
                p_head = head_proc.stdout.strip()
                if p_head != p_source_sha:
                    raise DiagnosticValidationError(
                        f"p_path HEAD mismatch: expected {p_source_sha}, got {p_head}"
                    )
            status_proc = subprocess.run(
                ["git", "-C", str(p_path), "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=False,
            )
            if status_proc.returncode == 0:
                p_clean = len(status_proc.stdout.strip()) == 0
                if not p_clean:
                    raise DiagnosticValidationError(f"p_path is dirty: {p_path}")
        except OSError as error:
            raise DiagnosticValidationError(f"Git inspection of p_path failed: {error}") from error

    return {
        "p_source_sha": p_source_sha,
        "compiler_path": str(compiler_path),
        "compiler_sha256": actual_compiler_sha256,
        "compiler_sha256_verified": True,
        "timeout_path": str(timeout_path),
        "p_path": p_path,
        "p_head": p_head,
        "p_clean": p_clean,
    }


def validate_source_parity(repo_path: str | Path, p1_sha: str = P1_SOURCE_SHA) -> dict[str, Any]:
    """Verify that isolated source repository's non-proof/ content matches P1."""
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise DiagnosticValidationError(f"Isolated source repo directory missing: {repo}")

    # Verify repo is a valid git worktree / repository
    root_proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if root_proc.returncode != 0:
        raise DiagnosticValidationError(f"Not a git repository: {repo}")

    # Check committed non-proof diff from P1
    diff_cmd = [
        "git",
        "-C",
        str(repo),
        "diff",
        "--name-only",
        p1_sha,
        "HEAD",
        "--",
        ".",
        ":(exclude)proof",
    ]
    diff_proc = subprocess.run(diff_cmd, capture_output=True, text=True, check=False)
    if diff_proc.returncode != 0:
        raise DiagnosticValidationError(
            f"Git diff against P1 failed: {diff_proc.stderr.strip()}"
        )
    committed_non_proof = [
        line.strip() for line in diff_proc.stdout.splitlines() if line.strip()
    ]
    if committed_non_proof:
        raise DiagnosticValidationError(
            f"Committed non-proof content differs from P1: {committed_non_proof}"
        )

    # Check uncommitted working tree / index non-proof diff from P1
    wt_diff_cmd = [
        "git",
        "-C",
        str(repo),
        "diff",
        "--name-only",
        p1_sha,
        "--",
        ".",
        ":(exclude)proof",
    ]
    wt_proc = subprocess.run(wt_diff_cmd, capture_output=True, text=True, check=False)
    wt_non_proof = [
        line.strip() for line in wt_proc.stdout.splitlines() if line.strip()
    ]
    if wt_non_proof:
        raise DiagnosticValidationError(
            f"Working tree non-proof content differs from P1: {wt_non_proof}"
        )

    # Check untracked non-proof files
    status_cmd = [
        "git",
        "-C",
        str(repo),
        "status",
        "--porcelain",
        "--",
        ".",
        ":(exclude)proof",
    ]
    status_proc = subprocess.run(status_cmd, capture_output=True, text=True, check=False)
    untracked_non_proof = [
        line.strip() for line in status_proc.stdout.splitlines() if line.strip()
    ]
    if untracked_non_proof:
        raise DiagnosticValidationError(
            f"Untracked or modified non-proof files in isolated source repo: {untracked_non_proof}"
        )

    # Verify YAML source file exists
    yaml_src = repo / "src" / "std" / "yaml.iyi"
    if not yaml_src.is_file():
        raise DiagnosticValidationError(f"Missing required source file: {yaml_src}")

    # Verify YAML benchmark program exists
    yaml_bench = repo / "bench" / "std_yaml_exercise.iyi"
    if not yaml_bench.is_file():
        raise DiagnosticValidationError(f"Missing required benchmark program: {yaml_bench}")

    return {
        "repo": str(repo),
        "p1_sha": p1_sha,
        "source_parity_p1": True,
        "yaml_src_sha256": sha256_file(yaml_src),
        "yaml_bench_sha256": sha256_file(yaml_bench),
    }


def create_foldcopy_overlay(repo_path: str | Path, report_dir: str | Path) -> dict[str, Any]:
    """Copy src/std/yaml.iyi into an owned overlay, apply foldcopy mutation, and record diff."""
    repo = Path(repo_path).resolve()
    report = Path(report_dir).resolve()
    src_file = repo / "src" / "std" / "yaml.iyi"
    source_text = src_file.read_text(encoding="utf-8")

    occurrences = source_text.count(MUTATION_ANCHOR)
    if occurrences != 1:
        raise DiagnosticValidationError(
            f"Mutation anchor must occur exactly once, found {occurrences}"
        )

    mutated_text = source_text.replace(MUTATION_ANCHOR, MUTATION_REPLACEMENT, 1)

    overlay_dir = report / "overlay"
    overlay_std = overlay_dir / "std"
    overlay_std.mkdir(parents=True, exist_ok=True)

    dest_file = overlay_std / "yaml.iyi"
    dest_file.write_text(mutated_text, encoding="utf-8")

    # Generate unified diff
    src_lines = source_text.splitlines(keepends=True)
    mut_lines = mutated_text.splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            src_lines,
            mut_lines,
            fromfile="a/src/std/yaml.iyi",
            tofile="b/src/std/yaml.iyi",
        )
    )
    diff_text = "".join(diff_lines)
    diff_path = report / "mutation.diff"
    diff_path.write_text(diff_text, encoding="utf-8")

    return {
        "source_file": str(src_file),
        "source_sha256": sha256_file(src_file),
        "overlay_dir": str(overlay_dir),
        "overlay_file": str(dest_file),
        "overlay_sha256": sha256_file(dest_file),
        "diff_path": str(diff_path),
        "diff_sha256": sha256_file(diff_path),
        "diff_text": diff_text,
        "anchor_occurrences": occurrences,
    }


def make_base_env(pin: dict[str, Any], stage_extra: dict[str, str] | None = None) -> dict[str, str]:
    """Derive clean base environment according to C2 + Amendment A specification."""
    env = os.environ.copy()

    for k in list(env.keys()):
        if k.startswith("IYI_") or k.startswith("CRYSTAL_"):
            env.pop(k, None)

    for k in [
        "PYTHONOPTIMIZE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "ROUTE_A_DRIVERS",
        "STD_SIBLINGS",
        "SIBLING_MINUTES",
    ]:
        env.pop(k, None)

    env["LIBRARY_PATH"] = "/opt/homebrew/opt/bdw-gc/lib"
    env["PKG_CONFIG_PATH"] = "/opt/homebrew/opt/openssl@3/lib/pkgconfig"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    if pin:
        env["PATH"] = pin["env_path"]
        env["HOME"] = pin["env_home"]

    if stage_extra:
        env.update(stage_extra)

    return env


def filter_env_allowlist(env: dict[str, str]) -> dict[str, str]:
    """Filter environment to allowed non-secret keys."""
    return {k: env[k] for k in sorted(env) if k in ALLOWED_ENV_KEYS}


def run_supervised_command(
    cmd: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_sec: float = COMMAND_TIMEOUT_SEC,
    grace_sec: float = CLEANUP_GRACE_SEC,
) -> dict[str, Any]:
    """Run command with own process group, bounded cutoff, and complete capture."""
    started_ns = time.time_ns()
    started_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    timed_out = False
    interrupted_signal: int | None = None
    teardown_used = False
    teardown_signal: str | None = None

    # Open separate stdout and stderr files
    with open(stdout_path, "wb") as stdout_f, open(stderr_path, "wb") as stderr_f:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout_f,
            stderr=stderr_f,
            start_new_session=True,  # Fresh session leader and process group
        )
        pgid = proc.pid
        leader_pid = proc.pid

        # Handle signals to supervisor: forward teardown to owned process group
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def supervisor_signal_handler(signum: int, _frame: Any) -> None:
            nonlocal interrupted_signal
            interrupted_signal = signum
            try:
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        signal.signal(signal.SIGINT, supervisor_signal_handler)
        signal.signal(signal.SIGTERM, supervisor_signal_handler)

        try:
            # Enforce 60-second command cutoff with grace window for process group teardown
            proc.wait(timeout=timeout_sec + grace_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            teardown_used = True
            teardown_signal = "SIGTERM"
            try:
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=grace_sec)
            except subprocess.TimeoutExpired:
                teardown_signal = "SIGKILL"
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()
        finally:
            # Restore original signal handlers
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)
            # Ensure leader is terminated
            if proc.poll() is None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()

    ended_ns = time.time_ns()
    ended_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    duration_sec = (ended_ns - started_ns) / 1_000_000_000.0

    raw_returncode = proc.returncode

    # Retain the 60-second command cutoff; cleanup grace must not become additional accepted execution time
    if duration_sec >= timeout_sec or raw_returncode == 124:
        timed_out = True

    # Read captured raw bytes
    stdout_bytes = stdout_path.read_bytes()
    stderr_bytes = stderr_path.read_bytes()
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    combined_text = stdout_text + "\n" + stderr_text

    assertion_found = EXPECTED_ASSERTION in combined_text
    panic_found = "panic" in combined_text.lower()

    return {
        "argv": list(cmd),
        "cwd": cwd,
        "started_ns": started_ns,
        "ended_ns": ended_ns,
        "started_iso": started_iso,
        "ended_iso": ended_iso,
        "duration_sec": duration_sec,
        "returncode": raw_returncode,
        "raw_returncode": raw_returncode,
        "timed_out": timed_out,
        "interrupted_signal": interrupted_signal,
        "supervisor_termination": {
            "leader_pid": leader_pid,
            "pgid": pgid,
            "teardown_used": teardown_used,
            "teardown_signal": teardown_signal,
            "timeout_sec_cutoff": timeout_sec,
            "grace_sec": grace_sec,
        },
        "env_allowlist": filter_env_allowlist(env),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_bytes_len": len(stdout_bytes),
        "stderr_bytes_len": len(stderr_bytes),
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "assertion_expected": EXPECTED_ASSERTION,
        "assertion_found": assertion_found,
        "panic_found": panic_found,
    }


def execute_diagnostic(
    pin_arg: str | Path,
    repo_arg: str | Path,
    report_dir_arg: str | Path,
) -> tuple[dict[str, Any], int]:
    """Execute complete foldcopy diagnostic and write artifacts."""
    overall_start_ns = time.time_ns()
    overall_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    pin_data, pin_file_path = load_pin_data(pin_arg)
    repo = Path(repo_arg).resolve()
    report_dir = Path(report_dir_arg).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    # 1. Pre-validation
    pre_validation = validate_p1_and_compiler(pin_data)
    pre_parity = validate_source_parity(repo, pin_data["p_source_sha"])

    # 2. Build owned overlay with foldcopy mutation
    mutation_info = create_foldcopy_overlay(repo, report_dir)

    # Prepare command and paths
    yaml_bench_program = str(repo / "bench" / "std_yaml_exercise.iyi")
    cmd = [
        pin_data["timeout_path"],
        "60",
        pin_data["compiler_path"],
        "run",
        yaml_bench_program,
    ]

    psep = os.pathsep

    # 3. Run unmodified control sequentially
    control_tmp = report_dir / "control.tmp"
    control_cache = report_dir / "control.cache"
    control_tmp.mkdir(parents=True, exist_ok=True)
    control_cache.mkdir(parents=True, exist_ok=True)

    control_iyi_path = psep.join([str(repo / "src"), str(repo / "samples" / "iyi")])
    control_env_additions = {
        "TMPDIR": str(control_tmp),
        "IYI_CACHE_DIR": str(control_cache),
        "IYI_PATH": control_iyi_path,
    }
    control_env = make_base_env(pin_data, control_env_additions)
    control_stdout = report_dir / "control.stdout"
    control_stderr = report_dir / "control.stderr"

    control_result = run_supervised_command(
        cmd,
        cwd=str(repo),
        env=control_env,
        stdout_path=control_stdout,
        stderr_path=control_stderr,
        timeout_sec=COMMAND_TIMEOUT_SEC,
        grace_sec=CLEANUP_GRACE_SEC,
    )

    # 4. Run foldcopy mutant sequentially
    mutant_tmp = report_dir / "mutant.tmp"
    mutant_cache = report_dir / "mutant.cache"
    mutant_tmp.mkdir(parents=True, exist_ok=True)
    mutant_cache.mkdir(parents=True, exist_ok=True)

    overlay_dir = mutation_info["overlay_dir"]
    mutant_iyi_path = psep.join([str(overlay_dir), str(repo / "src"), str(repo / "samples" / "iyi")])
    mutant_env_additions = {
        "TMPDIR": str(mutant_tmp),
        "IYI_CACHE_DIR": str(mutant_cache),
        "IYI_PATH": mutant_iyi_path,
    }
    mutant_env = make_base_env(pin_data, mutant_env_additions)
    mutant_stdout = report_dir / "mutant.stdout"
    mutant_stderr = report_dir / "mutant.stderr"

    mutant_result = run_supervised_command(
        cmd,
        cwd=str(repo),
        env=mutant_env,
        stdout_path=mutant_stdout,
        stderr_path=mutant_stderr,
        timeout_sec=COMMAND_TIMEOUT_SEC,
        grace_sec=CLEANUP_GRACE_SEC,
    )

    # 5. Post-validation: ensure compiler hash and repo non-proof parity are untouched
    post_validation = validate_p1_and_compiler(pin_data)
    post_parity = validate_source_parity(repo, pin_data["p_source_sha"])

    overall_end_ns = time.time_ns()
    overall_end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Determine mechanical verdict per planner Section 4:
    # - Control fails: returncode != 0
    # - Mutant exits zero: negative proof failed
    # - Mutant exits nonzero with required assertion: isolated negative proof holds
    # - Mutant exits nonzero without required assertion: retain FAIL, unproven cause
    control_pass = control_result["returncode"] == 0
    mutant_rc = mutant_result["returncode"]
    mutant_assertion_found = mutant_result["assertion_found"]

    if not control_pass:
        verdict = "CONTROL_FAILED"
        exit_code = 3
    elif mutant_rc == 0:
        verdict = "MUTANT_PASSED_NEGATIVE_PROOF_FAILED"
        exit_code = 4
    elif mutant_assertion_found:
        verdict = "MUTANT_CAUGHT_NEGATIVE_PROOF_HOLDS"
        exit_code = 0
    else:
        verdict = "MUTANT_FAILED_WITHOUT_REQUIRED_ASSERTION"
        exit_code = 5

    report_payload: dict[str, Any] = {
        "v": 1,
        "diagnostic": "diagnose_foldcopy",
        "verdict": verdict,
        "exit_code": exit_code,
        "started_ns": overall_start_ns,
        "ended_ns": overall_end_ns,
        "started_iso": overall_start_iso,
        "ended_iso": overall_end_iso,
        "limitations": [
            "fresh diagnostic caches: uses freshly initialized temporary and cache directories; cannot reconstruct the deleted cache state of the failed Run1 attempt",
            "relocated source paths: uses the specified isolated source repository; compilation paths and cache keys reflect this isolated repository path",
            "evidence-only diagnostic: not a strict-chain run or substitute for full corpus verification",
        ],
        "pin_file": pin_file_path,
        "pin_summary": {
            "chain_id": pin_data.get("chain_id"),
            "p_source_sha": pin_data.get("p_source_sha"),
            "compiler_path": pin_data.get("compiler_path"),
            "compiler_sha256": pin_data.get("compiler_sha256"),
            "timeout_path": pin_data.get("timeout_path"),
        },
        "pre_validation": {
            "identity": pre_validation,
            "source_parity": pre_parity,
        },
        "post_validation": {
            "identity": post_validation,
            "source_parity": post_parity,
        },
        "mutation": {
            "source_file": mutation_info["source_file"],
            "source_sha256": mutation_info["source_sha256"],
            "overlay_file": mutation_info["overlay_file"],
            "overlay_sha256": mutation_info["overlay_sha256"],
            "diff_path": mutation_info["diff_path"],
            "diff_sha256": mutation_info["diff_sha256"],
            "anchor": MUTATION_ANCHOR,
            "replacement": MUTATION_REPLACEMENT,
        },
        "control": control_result,
        "mutant": mutant_result,
        "evidence_files": {
            "control_stdout": str(control_stdout),
            "control_stderr": str(control_stderr),
            "mutant_stdout": str(mutant_stdout),
            "mutant_stderr": str(mutant_stderr),
            "mutation_diff": str(mutation_info["diff_path"]),
            "overlay_yaml": str(mutation_info["overlay_file"]),
        },
    }

    # Write report.json and results.json
    report_path = report_dir / "report.json"
    results_path = report_dir / "results.json"
    report_json_str = json.dumps(report_payload, indent=2, sort_keys=True) + "\n"
    report_path.write_text(report_json_str, encoding="utf-8")

    results_summary = [
        {
            "case": "control",
            "rc": control_result["returncode"],
            "timed_out": control_result["timed_out"],
            "duration_sec": control_result["duration_sec"],
        },
        {
            "case": "mutant",
            "rc": mutant_result["returncode"],
            "timed_out": mutant_result["timed_out"],
            "duration_sec": mutant_result["duration_sec"],
            "assertion_found": mutant_result["assertion_found"],
        },
    ]
    results_path.write_text(
        json.dumps(results_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return report_payload, exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Diagnose YAML foldcopy mutation failure and capture complete raw output."
    )
    parser.add_argument(
        "--pin",
        required=True,
        help="Path to pin.json or report directory containing pin.json",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to isolated source repository worktree",
    )
    parser.add_argument(
        "--report-dir",
        required=True,
        help="Path to new owned report directory for evidence and logs",
    )

    args = parser.parse_args(argv)

    try:
        report, exit_code = execute_diagnostic(
            pin_arg=args.pin,
            repo_arg=args.repo,
            report_dir_arg=args.report_dir,
        )
    except DiagnosticValidationError as error:
        print(f"DIAGNOSTIC-VALIDATION-ERROR: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"DIAGNOSTIC-ERROR: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "verdict": report["verdict"],
                "exit_code": report["exit_code"],
                "control_rc": report["control"]["returncode"],
                "control_timed_out": report["control"]["timed_out"],
                "mutant_rc": report["mutant"]["returncode"],
                "mutant_timed_out": report["mutant"]["timed_out"],
                "mutant_assertion_found": report["mutant"]["assertion_found"],
                "report_dir": args.report_dir,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
