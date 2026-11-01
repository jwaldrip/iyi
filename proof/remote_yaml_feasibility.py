#!/usr/bin/env python3
"""Bounded remote YAML foldcopy feasibility checkpoint runner for P1 on macOS.

Executes exactly two independent standalone YAML exercise attempts with freshly
owned caches and the complete original shell sequence, preserving:
- Both 20,000-line scalar inputs
- The original combined one-second performance assertion (<1000ms)
- The exact foldcopy mutation in std/yaml.iyi
- The inner 60s timeout around iyi run
- The exact assertion comparison (ASSERTION FAILED: quoted scalars of 20,000 lines read in under a second)
- The outer 2100s bound per attempt
- Evidence-only instrumentation with byte-for-byte verified mechanical reversal

Reference: agent://PlanQuietCorpusFailures (Smallest sound path for frozen P1)
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Sequence

# Pinned constants from P1 and H' specification
P1_SOURCE_SHA = "626463375298d357ffcb3223059f4d3adce6fb10"
EXPECTED_SCRIPT_SHA256 = (
    "befa5fb2d84c074ce584e9f4401a3909dd9cf3a8ee4db5f4aff2b6bd687fc3da"
)

# Expected assertion for negative proof
EXPECTED_ASSERTION = (
    "ASSERTION FAILED: quoted scalars of 20,000 lines read in under a second"
)

# Safe path variables allowlist (values recorded: unset vs empty vs path value)
SAFE_PATH_VARS = (
    "TMPDIR",
    "IYI_CACHE_DIR",
    "CRYSTAL_CACHE_DIR",
    "XDG_CACHE_HOME",
    "PATH",
    "HOME",
    "LIBRARY_PATH",
    "PKG_CONFIG_PATH",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
)

# Sensitive / startup variable names (never record raw values; record presence and SHA-256)
SENSITIVE_STARTUP_VARS = (
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "HISTFILE",
    "INPUTRC",
)

# Standard outer supervisor timeout (35 minutes matching bench/std_siblings.sh)
DEFAULT_OUTER_TIMEOUT_SEC = 2100
DEFAULT_MIN_DISK_GIB = 20.0


class DiagnosticValidationError(Exception):
    """Raised when pin, compiler, source parity, or anchor checks fail."""


class DiagnosticBlockerError(Exception):
    """Raised when an environmental, disk, or cache blocker prevents valid execution."""


def sha256_file(path: str | Path) -> str:
    """Compute hex SHA-256 of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def record_machine_fingerprints(report_dir: Path) -> dict[str, Any]:
    """Capture machine architecture, CPU, memory, and disk fingerprints safely."""
    def run_cmd(cmd: list[str]) -> str:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return res.stdout.strip() if res.returncode == 0 else ""
        except Exception:
            return ""

    disk_info = shutil.disk_usage("/")
    fingerprints = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "uname_all": run_cmd(["uname", "-a"]),
        "cpu_brand": run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "logical_cpus": run_cmd(["sysctl", "-n", "hw.ncpu"]),
        "physical_cpus": run_cmd(["sysctl", "-n", "hw.physicalcpu"]),
        "memory_bytes": run_cmd(["sysctl", "-n", "hw.memsize"]),
        "disk_free_gib": round(disk_info.free / (1024 ** 3), 2),
        "disk_total_gib": round(disk_info.total / (1024 ** 3), 2),
        "disk_used_gib": round(disk_info.used / (1024 ** 3), 2),
    }

    out_file = report_dir / "machine_fingerprints.json"
    out_file.write_text(json.dumps(fingerprints, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return fingerprints


def verify_disk_space(target_path: str | Path, min_gib: float = DEFAULT_MIN_DISK_GIB) -> dict[str, Any]:
    """Verify available disk space meets or exceeds declared floor."""
    path = Path(target_path).resolve()
    usage = shutil.disk_usage(str(path))
    free_gib = usage.free / (1024 ** 3)
    total_gib = usage.total / (1024 ** 3)
    used_gib = usage.used / (1024 ** 3)

    if free_gib < min_gib:
        raise DiagnosticBlockerError(
            f"Available disk space {free_gib:.2f} GiB at '{path}' is less than required minimum {min_gib:.2f} GiB."
        )

    return {
        "target_path": str(path),
        "free_gib": round(free_gib, 2),
        "total_gib": round(total_gib, 2),
        "used_gib": round(used_gib, 2),
        "min_required_gib": min_gib,
        "sufficient": True,
    }


def validate_base_parity(repo_path: str | Path, p1_sha: str = P1_SOURCE_SHA) -> dict[str, Any]:
    """Verify that repository product content matches P1 and is clean."""
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise DiagnosticValidationError(f"Integration repository directory missing: {repo}")

    # Verify git worktree / repository
    root_proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if root_proc.returncode != 0:
        raise DiagnosticValidationError(f"Not a git repository: {repo}")

    head_proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    head_sha = head_proc.stdout.strip() if head_proc.returncode == 0 else "unknown"

    # Check committed non-proof and non-workflow diff from P1
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
        ":(exclude).github",
    ]
    diff_proc = subprocess.run(diff_cmd, capture_output=True, text=True, check=False)
    if diff_proc.returncode != 0:
        raise DiagnosticValidationError(f"Git diff against P1 failed: {diff_proc.stderr.strip()}")
    committed_non_proof = [
        line.strip() for line in diff_proc.stdout.splitlines() if line.strip()
    ]
    if committed_non_proof:
        raise DiagnosticValidationError(
            f"Repository has non-proof differences from P1 ({p1_sha}): {committed_non_proof}"
        )

    # Check uncommitted tracked or untracked changes
    status_proc = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if status_proc.returncode != 0:
        raise DiagnosticValidationError(f"Git status failed on repo: {status_proc.stderr.strip()}")
    dirty_lines = [
        line.strip() for line in status_proc.stdout.splitlines() if line.strip()
    ]
    # Filter out proof-only, workflow-only, artifact-only, and build-only untracked items
    allowed_untracked = (
        "proof/",
        ".github/",
        "p1-source/",
        "remote-yaml-feasibility-artifacts/",
    )
    dirty_non_proof = [
        line for line in dirty_lines
        if not (len(line) > 3 and any(line[3:].startswith(p) for p in allowed_untracked))
    ]
    if dirty_non_proof:
        raise DiagnosticValidationError(
            f"Repository has dirty non-proof files: {dirty_non_proof}"
        )

    return {
        "repo_path": str(repo),
        "head_sha": head_sha,
        "p1_sha": p1_sha,
        "non_proof_diff": committed_non_proof,
        "dirty_non_proof": dirty_non_proof,
        "clean": len(dirty_non_proof) == 0 and len(committed_non_proof) == 0,
    }


def validate_compiler(compiler_path: str | Path, expected_sha256: str | None = None) -> dict[str, Any]:
    """Validate compiler binary existence, executability, version string, and SHA-256."""
    c_path = Path(compiler_path).resolve()
    if not c_path.is_file():
        raise DiagnosticValidationError(f"Compiler binary missing: {c_path}")
    if not os.access(c_path, os.X_OK):
        raise DiagnosticValidationError(f"Compiler binary not executable: {c_path}")

    actual_hash = sha256_file(c_path)
    if expected_sha256 and actual_hash != expected_sha256:
        raise DiagnosticValidationError(
            f"Compiler binary SHA-256 mismatch: expected {expected_sha256}, got {actual_hash}"
        )

    # Run compiler --version
    ver_proc = subprocess.run([str(c_path), "--version"], capture_output=True, text=True, check=False)
    version_output = ver_proc.stdout.strip() if ver_proc.returncode == 0 else ""

    return {
        "compiler_path": str(c_path),
        "compiler_sha256": actual_hash,
        "compiler_version": version_output,
        "verified": True,
    }


def validate_integration_script(script_path: str | Path, expected_sha256: str | None = EXPECTED_SCRIPT_SHA256) -> dict[str, Any]:
    """Validate integration bench script existence and hash."""
    s_path = Path(script_path).resolve()
    if not s_path.is_file():
        raise DiagnosticValidationError(f"Integration bench script missing: {s_path}")

    actual_hash = sha256_file(s_path)
    if expected_sha256 and actual_hash != expected_sha256:
        raise DiagnosticValidationError(
            f"Integration bench script SHA-256 mismatch: expected {expected_sha256}, got {actual_hash}"
        )

    return {
        "script_path": str(s_path),
        "script_sha256": actual_hash,
        "verified": True,
    }


# Patch anchors and exact replacements
ANCHOR_1_ORIGINAL = """WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT"""

ANCHOR_1_REPLACEMENT = """WORK="$(mktemp -d)"
# === BEGIN INSTRUMENTATION: ANCHOR 1 (EVIDENCE RETENTION & ENTRY CAPTURE) ===
if [ -n "${CAPTURE_DIR:-}" ]; then
  printf "%s\\n" "$WORK" > "$CAPTURE_DIR/work_path.txt"
  if [ -f "$CAPTURE_DIR/capture_env.sh" ]; then
    . "$CAPTURE_DIR/capture_env.sh"
    __iyi_diag_capture "entry"
  fi
fi
trap 'if [ -n "${CAPTURE_DIR:-}" ]; then printf "%s\\n" "$WORK" > "$CAPTURE_DIR/work_path_exit.txt"; fi' EXIT
# === END INSTRUMENTATION: ANCHOR 1 ==="""

ANCHOR_2A_ORIGINAL = """prove_caught() {
  local name="$1" what="$2" message="$3" old="$4" new="$5\""""

ANCHOR_2A_REPLACEMENT = """prove_caught() {
  local name="$1" what="$2" message="$3" old="$4" new="$5"
  local __capture_rc=0 __capture_start_ns=0 __capture_end_ns=0"""

ANCHOR_2B_ORIGINAL = """  elif IYI_PATH="$WORK/patched_$name${PSEP}$REPO/src${PSEP}$REPO/samples/iyi" timeout 60 "$IYI" run "$REPO/bench/std_yaml_exercise.iyi" >"$WORK/$name.out" 2>&1; then"""

ANCHOR_2B_REPLACEMENT = """  elif {
    if [ "$name" = foldcopy ] && [ -n "${CAPTURE_DIR:-}" ]; then
      if command -v __iyi_diag_capture >/dev/null 2>&1; then
        __iyi_diag_capture "pre_foldcopy"
      fi
    fi
    __capture_start_ns=$(python3 -c 'import time; print(time.time_ns())' 2>/dev/null || date +%s%N 2>/dev/null || echo 0)
    IYI_PATH="$WORK/patched_$name${PSEP}$REPO/src${PSEP}$REPO/samples/iyi" timeout 60 "$IYI" run "$REPO/bench/std_yaml_exercise.iyi" >"$WORK/$name.out" 2>&1
    __capture_rc=$?
    __capture_end_ns=$(python3 -c 'import time; print(time.time_ns())' 2>/dev/null || date +%s%N 2>/dev/null || echo 0)

    if [ "$name" = foldcopy ] && [ -n "${CAPTURE_DIR:-}" ]; then
      printf "%s\\n" "$__capture_rc" > "$CAPTURE_DIR/foldcopy_rc.txt"
      printf "%s\\n" "$__capture_start_ns" > "$CAPTURE_DIR/foldcopy_start_ns.txt"
      printf "%s\\n" "$__capture_end_ns" > "$CAPTURE_DIR/foldcopy_end_ns.txt"
      printf "%s\\n" "$WORK/patched_$name${PSEP}$REPO/src${PSEP}$REPO/samples/iyi" > "$CAPTURE_DIR/foldcopy_iyi_path.txt"
      if [ -f "$WORK/$name.out" ]; then
        cp "$WORK/$name.out" "$CAPTURE_DIR/foldcopy.out"
      fi
      if [ -f "$WORK/patched_$name/std/yaml.iyi" ]; then
        mkdir -p "$CAPTURE_DIR/patched_foldcopy/std"
        cp "$WORK/patched_$name/std/yaml.iyi" "$CAPTURE_DIR/patched_foldcopy/std/yaml.iyi"
      fi
    fi

    [ "$__capture_rc" -eq 0 ]
  }; then"""

PATCH_SPEC = [
    ("anchor_1_trap_and_entry", ANCHOR_1_ORIGINAL, ANCHOR_1_REPLACEMENT),
    ("anchor_2a_prove_caught_vars", ANCHOR_2A_ORIGINAL, ANCHOR_2A_REPLACEMENT),
    ("anchor_2b_prove_caught_timed_cmd", ANCHOR_2B_ORIGINAL, ANCHOR_2B_REPLACEMENT),
]


def build_instrumented_body(original_text: str) -> tuple[str, list[dict[str, Any]]]:
    """Apply single-occurrence patch anchors to construct the instrumented shell body."""
    text = original_text
    applied = []
    for name, original_pattern, replacement in PATCH_SPEC:
        count = text.count(original_pattern)
        if count != 1:
            raise DiagnosticValidationError(
                f"Patch anchor '{name}' count mismatch: expected 1, found {count}"
            )
        text = text.replace(original_pattern, replacement, 1)
        applied.append({
            "name": name,
            "anchor_count": count,
            "original_len": len(original_pattern),
            "replacement_len": len(replacement),
        })
    return text, applied


def reverse_instrumented_body(instrumented_text: str) -> tuple[str, list[dict[str, Any]]]:
    """Mechanically reverse patch anchors in reverse order."""
    text = instrumented_text
    reversed_records = []
    for name, original_pattern, replacement in reversed(PATCH_SPEC):
        count = text.count(replacement)
        if count != 1:
            raise DiagnosticValidationError(
                f"Reverse patch anchor '{name}' count mismatch: expected 1, found {count}"
            )
        text = text.replace(replacement, original_pattern, 1)
        reversed_records.append({
            "name": name,
            "replacement_count": count,
        })
    return text, reversed_records


def verify_syntax_and_reversal(original_text: str, instrumented_text: str) -> dict[str, Any]:
    """Verify mechanical reversal byte equality and clean bash syntax."""
    orig_bytes = original_text.encode("utf-8")
    reversed_text, _ = reverse_instrumented_body(instrumented_text)
    reversed_bytes = reversed_text.encode("utf-8")

    if reversed_bytes != orig_bytes:
        raise DiagnosticValidationError(
            f"Inverse-patch byte equality verification failed: "
            f"orig_len={len(orig_bytes)}, reversed_len={len(reversed_bytes)}"
        )

    # Bash syntax check
    syntax_proc = subprocess.run(
        ["bash", "-n"],
        input=instrumented_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if syntax_proc.returncode != 0:
        raise DiagnosticValidationError(
            f"Instrumented script failed bash syntax check (bash -n): {syntax_proc.stderr.strip()}"
        )

    return {
        "byte_equality_verified": True,
        "original_byte_count": len(orig_bytes),
        "instrumented_byte_count": len(instrumented_text.encode("utf-8")),
        "bash_syntax_clean": True,
    }


def resolve_cache_directory(env: dict[str, str]) -> tuple[Path, bool, str]:
    """Resolve cache directory according to iyi codegen rules."""
    home = env.get("HOME")
    iyi_cache = env.get("IYI_CACHE_DIR")
    crystal_cache = env.get("CRYSTAL_CACHE_DIR")
    xdg_cache = env.get("XDG_CACHE_HOME")

    if iyi_cache and iyi_cache.strip():
        cache_path = Path(iyi_cache.strip()).resolve()
        source = "IYI_CACHE_DIR"
    elif crystal_cache and crystal_cache.strip():
        cache_path = Path(crystal_cache.strip()).resolve()
        source = "CRYSTAL_CACHE_DIR"
    elif xdg_cache and xdg_cache.strip():
        cache_path = Path(xdg_cache.strip(), "iyi").resolve()
        source = "XDG_CACHE_HOME/iyi"
    elif home and home.strip():
        cache_path = Path(home.strip(), ".cache", "iyi").resolve()
        source = "HOME/.cache/iyi"
    else:
        cache_path = Path(".iyi").resolve()
        source = "default .iyi"

    is_shared = False
    if home and home.strip():
        home_path = Path(home.strip()).resolve()
        if (
            cache_path == home_path / ".cache" / "iyi"
            or cache_path == home_path / ".iyi"
            or str(cache_path).startswith(str(home_path / ".cache"))
        ):
            is_shared = True

    return cache_path, is_shared, source


def write_capture_helpers(report_dir: Path) -> tuple[Path, Path]:
    """Write shell and python helper scripts into report_dir to safely record metadata."""
    env_helper_py = report_dir / "capture_env.py"
    env_helper_py_content = """#!/usr/bin/env python3
import hashlib
import json
import os
import sys

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    stage = sys.argv[1]
    capture_dir = os.environ.get("CAPTURE_DIR", ".")

    safe_vars = [
        "TMPDIR", "IYI_CACHE_DIR", "CRYSTAL_CACHE_DIR", "XDG_CACHE_HOME",
        "PATH", "HOME", "LIBRARY_PATH", "PKG_CONFIG_PATH",
        "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"
    ]
    sensitive_exact = ["BASH_ENV", "ENV", "PROMPT_COMMAND", "HISTFILE", "INPUTRC"]

    safe_result = {}
    for k in safe_vars:
        if k not in os.environ:
            safe_result[k] = {"state": "unset"}
        elif os.environ[k] == "":
            safe_result[k] = {"state": "empty"}
        else:
            safe_result[k] = {"state": "set", "value": os.environ[k]}

    sensitive_result = {}
    for k, v in os.environ.items():
        is_sensitive = False
        if (k.startswith("IYI_") or k.startswith("CRYSTAL_")) and k not in safe_vars and k not in ("IYI", "IYI_PATH"):
            is_sensitive = True
        elif k in sensitive_exact:
            is_sensitive = True

        if is_sensitive:
            sensitive_result[k] = {
                "state": "empty" if v == "" else "set",
                "sha256": hashlib.sha256(v.encode("utf-8")).hexdigest(),
                "len": len(v)
            }

    out_file = os.path.join(capture_dir, f"env_{stage}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "stage": stage,
            "safe_path_variables": safe_result,
            "sensitive_variables_presence_and_hashes": sensitive_result
        }, f, indent=2, sort_keys=True)

if __name__ == "__main__":
    main()
"""
    env_helper_py.write_text(env_helper_py_content, encoding="utf-8")
    os.chmod(env_helper_py, 0o755)

    env_helper_sh = report_dir / "capture_env.sh"
    env_helper_sh_content = """# Helper functions sourced by instrumented shell body
__iyi_diag_capture() {
  local stage="$1"
  [ -z "${CAPTURE_DIR:-}" ] && return 0

  # 1. Shell state
  {
    printf "stage=%s\\n" "$stage"
    printf "timestamp_iso=%s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
    printf "timestamp_ns=%s\\n" "$(python3 -c 'import time; print(time.time_ns())' 2>/dev/null || date +%s%N 2>/dev/null || echo 0)"
    printf "bash_version=%s\\n" "${BASH_VERSION:-}"
    printf "dash_options=%s\\n" "$-"
    printf "bashopts=%s\\n" "${BASHOPTS:-}"
    printf "shellopts=%s\\n" "${SHELLOPTS:-}"
    printf "cwd=%s\\n" "$(pwd)"
    printf "repo=%s\\n" "${REPO:-}"
    printf "work=%s\\n" "${WORK:-}"
    printf "iyi=%s\\n" "${IYI:-}"
    printf "psep=%s\\n" "${PSEP:-}"
  } > "$CAPTURE_DIR/shell_state_${stage}.txt" 2>/dev/null || true

  # 2. Resource limits
  ulimit -a > "$CAPTURE_DIR/ulimit_${stage}.txt" 2>/dev/null || true

  # 3. Functions (names and SHA-256 hashes of definitions)
  {
    while IFS= read -r fn_entry; do
      fn_name="${fn_entry##* }"
      [ -z "$fn_name" ] && continue
      fn_hash=$(type "$fn_name" 2>/dev/null | python3 -c 'import sys, hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())' 2>/dev/null || echo "error")
      printf "%s %s\\n" "$fn_name" "$fn_hash"
    done < <(declare -F 2>/dev/null || true)
  } > "$CAPTURE_DIR/functions_${stage}.txt" 2>/dev/null || true

  # 4. Commands resolution and hashes
  python3 -c '
import json, os, subprocess, hashlib, sys
cmds = ["timeout", "grep", "python3", "python"]
results = {}
for cmd in cmds:
    t_proc = subprocess.run(["bash", "-c", f"type -t {cmd}"], capture_output=True, text=True)
    cmd_type = t_proc.stdout.strip() if t_proc.returncode == 0 else "not_found"
    p_proc = subprocess.run(["bash", "-c", f"type -p {cmd}"], capture_output=True, text=True)
    cmd_path = p_proc.stdout.strip() if p_proc.returncode == 0 else ""
    cmd_hash = None
    if cmd_path and os.path.isfile(cmd_path):
        try:
            with open(cmd_path, "rb") as f:
                cmd_hash = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            pass
    results[cmd] = {
        "command_type": cmd_type,
        "path": cmd_path,
        "sha256": cmd_hash,
    }
iyi_path = os.environ.get("IYI", "")
iyi_hash = None
if iyi_path and os.path.isfile(iyi_path):
    try:
        with open(iyi_path, "rb") as f:
            iyi_hash = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        pass
results["iyi"] = {
    "path": iyi_path,
    "sha256": iyi_hash,
}
with open(os.path.join(sys.argv[1], f"commands_{sys.argv[2]}.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, sort_keys=True)
' "$CAPTURE_DIR" "$stage" 2>/dev/null || true

  # 5. Environment classification
  if [ -f "$CAPTURE_DIR/capture_env.py" ]; then
    python3 "$CAPTURE_DIR/capture_env.py" "$stage" 2>/dev/null || true
  fi
}
"""
    env_helper_sh.write_text(env_helper_sh_content, encoding="utf-8")
    return env_helper_py, env_helper_sh


def execute_single_attempt(
    attempt_num: int,
    repo_path: Path,
    compiler_path: Path,
    attempt_dir: Path,
    instrumented_text: str,
    cache_dir: Path,
    outer_timeout_sec: int = DEFAULT_OUTER_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Execute a single standalone attempt of the YAML exercise under full instrumentation."""
    attempt_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    write_capture_helpers(attempt_dir)

    run_env = os.environ.copy()
    run_env["CAPTURE_DIR"] = str(attempt_dir)
    run_env["IYI"] = str(compiler_path)
    run_env["IYI_CACHE_DIR"] = str(cache_dir.resolve())

    # Verify cache isolation
    resolved_cache, is_shared, cache_source = resolve_cache_directory(run_env)
    if is_shared:
        raise DiagnosticBlockerError(
            f"Attempt {attempt_num} cache resolves to shared location '{resolved_cache}'. "
            f"Refusing to run without an isolated owned cache directory."
        )

    outer_stdout_path = attempt_dir / "outer.stdout"
    outer_stderr_path = attempt_dir / "outer.stderr"

    # bash -c BODY bench/std_yaml_exercise.sh
    cmd = ["bash", "-c", instrumented_text, "bench/std_yaml_exercise.sh"]

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_ns = time.time_ns()
    timed_out = False
    returncode = -1

    with open(outer_stdout_path, "wb") as out_f, open(outer_stderr_path, "wb") as err_f:
        proc = subprocess.Popen(
            cmd,
            cwd=str(repo_path),
            env=run_env,
            stdout=out_f,
            stderr=err_f,
        )
        try:
            returncode = proc.wait(timeout=outer_timeout_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            returncode = 124

    end_ns = time.time_ns()
    end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    duration_sec = (end_ns - start_ns) / 1e9

    # Retained WORK directory check
    work_path_file = attempt_dir / "work_path.txt"
    work_path = work_path_file.read_text(encoding="utf-8").strip() if work_path_file.is_file() else None
    work_exists = Path(work_path).is_dir() if work_path else False

    # Foldcopy raw evidence
    foldcopy_rc_file = attempt_dir / "foldcopy_rc.txt"
    foldcopy_rc = int(foldcopy_rc_file.read_text(encoding="utf-8").strip()) if foldcopy_rc_file.is_file() else None

    foldcopy_start_ns_file = attempt_dir / "foldcopy_start_ns.txt"
    foldcopy_start_ns = int(foldcopy_start_ns_file.read_text(encoding="utf-8").strip()) if foldcopy_start_ns_file.is_file() else None

    foldcopy_end_ns_file = attempt_dir / "foldcopy_end_ns.txt"
    foldcopy_end_ns = int(foldcopy_end_ns_file.read_text(encoding="utf-8").strip()) if foldcopy_end_ns_file.is_file() else None

    foldcopy_duration_sec = None
    if foldcopy_start_ns and foldcopy_end_ns and foldcopy_end_ns >= foldcopy_start_ns:
        foldcopy_duration_sec = (foldcopy_end_ns - foldcopy_start_ns) / 1e9

    foldcopy_out_path = attempt_dir / "foldcopy.out"
    foldcopy_out_exists = foldcopy_out_path.is_file()
    foldcopy_out_bytes = foldcopy_out_path.stat().st_size if foldcopy_out_exists else 0
    foldcopy_out_sha256 = sha256_file(foldcopy_out_path) if foldcopy_out_exists else None

    foldcopy_out_content = foldcopy_out_path.read_text(encoding="utf-8", errors="replace") if foldcopy_out_exists else ""
    assertion_found = EXPECTED_ASSERTION in foldcopy_out_content
    panic_found = "panic:" in foldcopy_out_content or "ASSERTION FAILED:" in foldcopy_out_content

    # Patched YAML and diff against original
    patched_yaml_path = attempt_dir / "patched_foldcopy" / "std" / "yaml.iyi"
    patched_yaml_exists = patched_yaml_path.is_file()
    patched_yaml_sha256 = sha256_file(patched_yaml_path) if patched_yaml_exists else None

    orig_yaml_path = repo_path / "src" / "std" / "yaml.iyi"
    mutation_diff_path = attempt_dir / "mutation.diff"
    if patched_yaml_exists and orig_yaml_path.is_file():
        orig_yaml_lines = orig_yaml_path.read_text(encoding="utf-8").splitlines(keepends=True)
        patched_yaml_lines = patched_yaml_path.read_text(encoding="utf-8").splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(
            orig_yaml_lines,
            patched_yaml_lines,
            fromfile=str(orig_yaml_path),
            tofile=str(patched_yaml_path),
        ))
        mutation_diff_path.write_text("".join(diff_lines), encoding="utf-8")

    # Classification
    if foldcopy_rc == 124:
        classification = "TIMEOUT_EXHAUSTED_60S"
    elif foldcopy_rc == 1 and assertion_found:
        classification = "EXPECTED_ASSERTION_PRODUCED"
    elif foldcopy_rc == 1 and not assertion_found:
        classification = "UNEXPECTED_FAILURE_WITHOUT_ASSERTION"
    elif foldcopy_rc == 0:
        classification = "MUTANT_UNEXPECTEDLY_PASSED_ZERO_RC"
    elif foldcopy_rc in (137, 139):
        classification = f"TERMINATED_BY_SIGNAL_{foldcopy_rc}"
    elif foldcopy_rc is not None:
        classification = f"NONZERO_EXIT_{foldcopy_rc}"
    else:
        classification = "FOLDCOPY_NOT_REACHED_OR_CAPTURE_EMPTY"

    # Evaluated attempt pass criteria:
    # 1. Whole shell sequence completed and exited zero (outer_returncode == 0)
    # 2. foldcopy raw return code was 1
    # 3. Required performance assertion was produced
    # 4. Classification is EXPECTED_ASSERTION_PRODUCED
    attempt_passed = (
        returncode == 0
        and foldcopy_rc == 1
        and assertion_found is True
        and classification == "EXPECTED_ASSERTION_PRODUCED"
    )

    result = {
        "attempt_number": attempt_num,
        "passed": attempt_passed,
        "classification": classification,
        "execution": {
            "outer_returncode": returncode,
            "outer_timed_out": timed_out,
            "started_iso": start_iso,
            "ended_iso": end_iso,
            "duration_sec": duration_sec,
            "outer_stdout_path": str(outer_stdout_path),
            "outer_stdout_bytes": outer_stdout_path.stat().st_size,
            "outer_stderr_path": str(outer_stderr_path),
            "outer_stderr_bytes": outer_stderr_path.stat().st_size,
        },
        "cache": {
            "resolved_path": str(resolved_cache),
            "is_shared": is_shared,
            "source": cache_source,
        },
        "work": {
            "work_path": work_path,
            "work_exists": work_exists,
            "cleaned_by_script": False,
        },
        "foldcopy": {
            "raw_returncode": foldcopy_rc,
            "start_ns": foldcopy_start_ns,
            "end_ns": foldcopy_end_ns,
            "duration_sec": foldcopy_duration_sec,
            "foldcopy_out_path": str(foldcopy_out_path) if foldcopy_out_exists else None,
            "foldcopy_out_bytes": foldcopy_out_bytes,
            "foldcopy_out_sha256": foldcopy_out_sha256,
            "assertion_expected": EXPECTED_ASSERTION,
            "assertion_found": assertion_found,
            "panic_found": panic_found,
            "patched_yaml_path": str(patched_yaml_path) if patched_yaml_exists else None,
            "patched_yaml_sha256": patched_yaml_sha256,
            "mutation_diff_path": str(mutation_diff_path) if mutation_diff_path.is_file() else None,
            "classification": classification,
        },
    }

    report_path = attempt_dir / "report.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    receipt = {
        "attempt_number": attempt_num,
        "passed": attempt_passed,
        "classification": classification,
        "outer_returncode": returncode,
        "foldcopy_raw_rc": foldcopy_rc,
        "foldcopy_duration_sec": foldcopy_duration_sec,
        "assertion_found": assertion_found,
        "panic_found": panic_found,
        "work_path": work_path,
        "work_exists": work_exists,
        "attempt_dir": str(attempt_dir),
    }
    receipt_path = attempt_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return result


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for remote YAML foldcopy feasibility checkpoint."""
    parser = argparse.ArgumentParser(
        description="Run two-attempt remote macOS feasibility checkpoint for P1 YAML foldcopy negative proof."
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to repository under test (default: current directory)",
    )
    parser.add_argument(
        "--compiler",
        required=True,
        help="Path to compiled P1 compiler binary",
    )
    parser.add_argument(
        "--compiler-sha256",
        default=None,
        help="Expected SHA-256 of compiler binary (if known/provided)",
    )
    parser.add_argument(
        "--p1-sha",
        default=P1_SOURCE_SHA,
        help=f"Expected P1 commit SHA (default: {P1_SOURCE_SHA})",
    )
    parser.add_argument(
        "--script-sha256",
        default=EXPECTED_SCRIPT_SHA256,
        help=f"Expected integration script SHA-256 (default: {EXPECTED_SCRIPT_SHA256})",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to save diagnostic reports, receipts, and artifacts",
    )
    parser.add_argument(
        "--outer-timeout",
        type=int,
        default=DEFAULT_OUTER_TIMEOUT_SEC,
        help=f"Outer supervisor timeout in seconds per attempt (default: {DEFAULT_OUTER_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--min-disk-gib",
        type=float,
        default=DEFAULT_MIN_DISK_GIB,
        help=f"Minimum free disk space required in GiB (default: {DEFAULT_MIN_DISK_GIB})",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate environment, disk space, base parity, compiler, and anchor reversal without running attempts",
    )

    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("REMOTE YAML FOLDCOPY FEASIBILITY CHECKPOINT (P1)")
    print(f"Time: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("================================================================================")

    try:
        # 1. Record Machine Fingerprints
        print("Recording machine fingerprints...")
        machine_fp = record_machine_fingerprints(output_dir)
        print(f"  System: {machine_fp['system']} {machine_fp['release']} ({machine_fp['machine']})")
        print(f"  CPU: {machine_fp['cpu_brand']} (logical: {machine_fp['logical_cpus']}, physical: {machine_fp['physical_cpus']})")
        print(f"  Free disk: {machine_fp['disk_free_gib']} GiB")

        # 2. Verify Disk Space
        print(f"Verifying disk space (>= {args.min_disk_gib} GiB)...")
        disk_val = verify_disk_space(output_dir, min_gib=args.min_disk_gib)
        print(f"  Disk check PASSED: {disk_val['free_gib']} GiB free")

        # 3. Base Parity Validation against P1
        print("Validating base parity against P1...")
        repo_path = Path(args.repo).resolve()
        repo_val = validate_base_parity(repo_path, p1_sha=args.p1_sha)
        print(f"  Repo HEAD: {repo_val['head_sha']}, target P1: {repo_val['p1_sha']} (clean={repo_val['clean']})")

        # 4. Compiler Validation
        print("Validating compiler binary...")
        compiler_path = Path(args.compiler).resolve()
        compiler_val = validate_compiler(compiler_path, expected_sha256=args.compiler_sha256)
        print(f"  Compiler: {compiler_val['compiler_path']}")
        print(f"  Compiler SHA-256: {compiler_val['compiler_sha256']}")
        print(f"  Version: {compiler_val['compiler_version']}")

        # 5. Integration Script Validation
        print("Validating integration script...")
        script_path = repo_path / "bench" / "std_yaml_exercise.sh"
        script_val = validate_integration_script(script_path, expected_sha256=args.script_sha256)
        print(f"  Script: {script_val['script_path']}")
        print(f"  Script SHA-256: {script_val['script_sha256']}")

        # 6. Build Instrumented Shell Body and Verify Reversal + Syntax
        print("Building instrumented shell body and verifying mechanical reversal...")
        original_text = script_path.read_text(encoding="utf-8")
        instrumented_text, applied_patches = build_instrumented_body(original_text)
        reversal_val = verify_syntax_and_reversal(original_text, instrumented_text)
        print(f"  Reversal byte equality: {reversal_val['byte_equality_verified']}")
        print(f"  Bash syntax check: {reversal_val['bash_syntax_clean']}")

        # Save original and instrumented scripts + diff
        (output_dir / "original.sh").write_text(original_text, encoding="utf-8")
        (output_dir / "instrumented.sh").write_text(instrumented_text, encoding="utf-8")
        diff_lines = list(difflib.unified_diff(
            original_text.splitlines(keepends=True),
            instrumented_text.splitlines(keepends=True),
            fromfile=str(script_path),
            tofile=str(output_dir / "instrumented.sh"),
        ))
        (output_dir / "instrumentation.diff").write_text("".join(diff_lines), encoding="utf-8")
        if args.validate_only:
            val_summary = {
                "status": "VALIDATED_ONLY",
                "machine": machine_fp,
                "disk": disk_val,
                "base_parity": repo_val,
                "compiler": compiler_val,
                "script": script_val,
                "reversal_and_syntax": reversal_val,
            }
            (output_dir / "validation.json").write_text(
                json.dumps(val_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print("\nVALIDATION SUCCESS: Base parity, compiler, script, anchor reversal, and bash syntax verified.")
            print(json.dumps(val_summary, indent=2, sort_keys=True))
            return 0


        # Prepare owned cache root
        cache_root = Path(tempfile.mkdtemp(prefix="iyi_cache_root_")).resolve()

        # 7. Execute Attempt 1
        print("\n--------------------------------------------------------------------------------")
        print("STARTING ATTEMPT 1 (of 2 predeclared attempts)")
        print("--------------------------------------------------------------------------------")
        cache_dir_1 = cache_root / "attempt1_cache"
        attempt1_dir = output_dir / "attempt1"
        attempt1_result = execute_single_attempt(
            attempt_num=1,
            repo_path=repo_path,
            compiler_path=compiler_path,
            attempt_dir=attempt1_dir,
            instrumented_text=instrumented_text,
            cache_dir=cache_dir_1,
            outer_timeout_sec=args.outer_timeout,
        )
        print(f"Attempt 1 Outcome: classification={attempt1_result['classification']}, "
              f"foldcopy_rc={attempt1_result['foldcopy']['raw_returncode']}, "
              f"duration={attempt1_result['foldcopy']['duration_sec']}s, "
              f"passed={attempt1_result['passed']}")

        # 8. Execute Attempt 2 (independently, regardless of Attempt 1 outcome)
        print("\n--------------------------------------------------------------------------------")
        print("STARTING ATTEMPT 2 (of 2 predeclared attempts)")
        print("--------------------------------------------------------------------------------")
        cache_dir_2 = cache_root / "attempt2_cache"
        attempt2_dir = output_dir / "attempt2"
        attempt2_result = execute_single_attempt(
            attempt_num=2,
            repo_path=repo_path,
            compiler_path=compiler_path,
            attempt_dir=attempt2_dir,
            instrumented_text=instrumented_text,
            cache_dir=cache_dir_2,
            outer_timeout_sec=args.outer_timeout,
        )
        print(f"Attempt 2 Outcome: classification={attempt2_result['classification']}, "
              f"foldcopy_rc={attempt2_result['foldcopy']['raw_returncode']}, "
              f"duration={attempt2_result['foldcopy']['duration_sec']}s, "
              f"passed={attempt2_result['passed']}")

        # 9. Verify completeness of receipts
        def check_attempt_receipts(att_dir: Path) -> bool:
            req_files = [
                att_dir / "receipt.json",
                att_dir / "report.json",
                att_dir / "outer.stdout",
                att_dir / "outer.stderr",
                att_dir / "foldcopy_rc.txt",
                att_dir / "work_path.txt",
            ]
            return all(f.is_file() for f in req_files)

        receipts_complete = check_attempt_receipts(attempt1_dir) and check_attempt_receipts(attempt2_dir)

        # 10. Overall Checkpoint Verdict
        both_attempts_passed = attempt1_result["passed"] and attempt2_result["passed"]

        if not receipts_complete:
            overall_verdict = "INCOMPLETE_RECEIPT"
            overall_status = "FAIL"
        elif both_attempts_passed:
            overall_verdict = "FEASIBLE"
            overall_status = "PASS"
        else:
            overall_verdict = "FEASIBILITY_CHECKPOINT_FAILED"
            overall_status = "FAIL"

        summary = {
            "overall_verdict": overall_verdict,
            "overall_status": overall_status,
            "p1_source_sha": P1_SOURCE_SHA,
            "compiler": compiler_val,
            "integration_script": script_val,
            "machine_fingerprints": machine_fp,
            "disk_verification": disk_val,
            "attempt1": {
                "passed": attempt1_result["passed"],
                "classification": attempt1_result["classification"],
                "outer_returncode": attempt1_result["execution"]["outer_returncode"],
                "foldcopy_raw_rc": attempt1_result["foldcopy"]["raw_returncode"],
                "foldcopy_duration_sec": attempt1_result["foldcopy"]["duration_sec"],
                "assertion_found": attempt1_result["foldcopy"]["assertion_found"],
            },
            "attempt2": {
                "passed": attempt2_result["passed"],
                "classification": attempt2_result["classification"],
                "outer_returncode": attempt2_result["execution"]["outer_returncode"],
                "foldcopy_raw_rc": attempt2_result["foldcopy"]["raw_returncode"],
                "foldcopy_duration_sec": attempt2_result["foldcopy"]["duration_sec"],
                "assertion_found": attempt2_result["foldcopy"]["assertion_found"],
            },
            "receipts_complete": receipts_complete,
            "bounds": {
                "inner_timeout_sec": 60,
                "outer_timeout_sec": args.outer_timeout,
                "combined_assertion": EXPECTED_ASSERTION,
                "scalar_input_lines": 20000,
                "attempts_predeclared": 2,
            },
        }

        (output_dir / "checkpoint_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / "checkpoint_receipt.json").write_text(
            json.dumps({
                "verdict": overall_verdict,
                "status": overall_status,
                "attempt1_classification": attempt1_result["classification"],
                "attempt2_classification": attempt2_result["classification"],
                "attempt1_passed": attempt1_result["passed"],
                "attempt2_passed": attempt2_result["passed"],
                "receipts_complete": receipts_complete,
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        print("\n================================================================================")
        print(f"CHECKPOINT SUMMARY: {overall_verdict} (status={overall_status})")
        print(f"Attempt 1: {attempt1_result['classification']} (passed={attempt1_result['passed']})")
        print(f"Attempt 2: {attempt2_result['classification']} (passed={attempt2_result['passed']})")
        print(f"Receipts Complete: {receipts_complete}")
        print("================================================================================")
        print(json.dumps(summary, indent=2, sort_keys=True))

        return 0 if overall_status == "PASS" else 1

    except DiagnosticValidationError as err:
        print(f"\nDIAGNOSTIC-VALIDATION-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "DiagnosticValidationError", "detail": str(err)}
        (output_dir / "setup_error.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 2

    except DiagnosticBlockerError as err:
        print(f"\nDIAGNOSTIC-BLOCKER-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "DiagnosticBlockerError", "detail": str(err)}
        (output_dir / "setup_blocker.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 3

    except Exception as err:
        print(f"\nDIAGNOSTIC-UNEXPECTED-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "UnexpectedError", "detail": str(err)}
        (output_dir / "setup_error.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 1


if __name__ == "__main__":
    sys.exit(main())
