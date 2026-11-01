#!/usr/bin/env python3
"""Bounded YAML parent shell capture diagnostic driver.

Preserves the complete original YAML shell exercise sequence, bare `timeout`
resolution, 60-second limit, merged stdout/stderr redirection, and diagnostic
comparisons while capturing raw return codes, unfiltered output, actual mutated
YAML sources, environment metadata, and retained work scratch.

Reference: agent://PlanQuietCorpusFailures (Ordered diagnostic plan sections 1-4)
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Sequence

# Pinned constants from H' / P1 specification
P1_SOURCE_SHA = "626463375298d357ffcb3223059f4d3adce6fb10"
EXPECTED_COMPILER_SHA256 = (
    "b8afdb5f55b03754b8194978e320cbca3c0816661cadcbd3083f0872a64ca418"
)
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


class DiagnosticValidationError(Exception):
    """Raised when pin, compiler, source parity, or anchor checks fail."""


class DiagnosticBlockerError(Exception):
    """Raised when an environmental or cache blocker prevents valid execution."""


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


def validate_base_parity(repo_path: str | Path, p1_sha: str = P1_SOURCE_SHA) -> dict[str, Any]:
    """Verify that integration repository's non-proof content matches P1 and is clean."""
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
    # Filter out proof-only untracked items if any
    dirty_non_proof = [
        line for line in dirty_lines if not (len(line) > 3 and line[3:].startswith("proof/"))
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


def validate_compiler(compiler_path: str | Path, expected_sha256: str = EXPECTED_COMPILER_SHA256) -> dict[str, Any]:
    """Validate compiler binary existence, executability, and pinned SHA-256."""
    c_path = Path(compiler_path).resolve()
    if not c_path.is_file():
        raise DiagnosticValidationError(f"Compiler binary missing: {c_path}")
    if not os.access(c_path, os.X_OK):
        raise DiagnosticValidationError(f"Compiler binary not executable: {c_path}")

    actual_hash = sha256_file(c_path)
    if actual_hash != expected_sha256:
        raise DiagnosticValidationError(
            f"Compiler binary SHA-256 mismatch: expected {expected_sha256}, got {actual_hash}"
        )

    return {
        "compiler_path": str(c_path),
        "compiler_sha256": actual_hash,
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
    """
    Apply single-occurrence patch anchors to construct the instrumented shell body.
    Requires each patch anchor to occur exactly once.
    """
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
    """
    Mechanically reverse patch anchors in reverse order.
    Requires each replacement anchor to occur exactly once.
    """
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
    """
    Verify:
      1. Mechanical reversal produces byte-for-byte identical content to original.
      2. Instrumented script passes bash syntax check (`bash -n`).
    """
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
    """
    Resolve which cache directory will be selected by `iyi`, whether it is a shared
    or global user directory, and the resolution source.

    Resolution order from src/compiler/iyi/codegen/cache_dir.cr:158-176:
      1. Config.env("CACHE_DIR") (IYI_CACHE_DIR, then CRYSTAL_CACHE_DIR)
      2. XDG_CACHE_HOME/iyi
      3. HOME/.cache/iyi
      4. HOME/.iyi
      5. .iyi
    """
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

    # Identify shared caches
    is_shared = False
    if home and home.strip():
        home_path = Path(home.strip()).resolve()
        # Any directory inside ~/.cache or directly ~/.iyi is a user global shared cache
        if (
            cache_path == home_path / ".cache" / "iyi"
            or cache_path == home_path / ".iyi"
            or str(cache_path).startswith(str(home_path / ".cache"))
        ):
            is_shared = True

    return cache_path, is_shared, source


def write_capture_helpers(report_dir: Path) -> tuple[Path, Path]:
    """
    Write shell and python helper scripts into report_dir to safely record
    environment metadata, functions, and commands without dumping secrets or bodies.
    """
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

  # 1. Shell state (options, version, cwd, REPO, WORK, IYI)
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

  # 3. Functions (names and SHA-256 hashes of definitions, without dumping bodies)
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


def execute_capture(
    repo_path: Path,
    compiler_path: Path,
    report_dir: Path,
    instrumented_text: str,
    cache_dir: Path | None = None,
    allow_shared_cache: bool = False,
    outer_timeout_sec: int = DEFAULT_OUTER_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Execute the instrumented YAML shell body and capture complete evidence."""
    # Build execution environment preserving inherited variables
    run_env = os.environ.copy()
    run_env["CAPTURE_DIR"] = str(report_dir)
    run_env["IYI"] = str(compiler_path)

    if cache_dir is not None:
        cache_dir_resolved = cache_dir.resolve()
        cache_dir_resolved.mkdir(parents=True, exist_ok=True)
        run_env["IYI_CACHE_DIR"] = str(cache_dir_resolved)

    # Check cache resolution
    resolved_cache, is_shared, cache_source = resolve_cache_directory(run_env)
    if is_shared and not allow_shared_cache:
        raise DiagnosticBlockerError(
            f"Inherited cache resolves to shared location '{resolved_cache}' ({cache_source}). "
            f"Refusing to use or mutate shared cache without an owned cache directory. "
            f"Stop with explicit blocker rather than claiming exact comparison. "
            f"Provide an owned cache via --cache-dir or set IYI_CACHE_DIR, or pass --allow-shared-cache."
        )

    # Prepare outer output streams
    outer_stdout_path = report_dir / "outer.stdout"
    outer_stderr_path = report_dir / "outer.stderr"

    # Shell invocation preserving original relative $0
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

    # Inspect retained WORK directory
    work_path_file = report_dir / "work_path.txt"
    work_path = work_path_file.read_text(encoding="utf-8").strip() if work_path_file.is_file() else None
    work_exists = Path(work_path).is_dir() if work_path else False

    # Inspect foldcopy captured evidence
    foldcopy_rc_file = report_dir / "foldcopy_rc.txt"
    foldcopy_rc = int(foldcopy_rc_file.read_text(encoding="utf-8").strip()) if foldcopy_rc_file.is_file() else None

    foldcopy_start_ns_file = report_dir / "foldcopy_start_ns.txt"
    foldcopy_start_ns = int(foldcopy_start_ns_file.read_text(encoding="utf-8").strip()) if foldcopy_start_ns_file.is_file() else None

    foldcopy_end_ns_file = report_dir / "foldcopy_end_ns.txt"
    foldcopy_end_ns = int(foldcopy_end_ns_file.read_text(encoding="utf-8").strip()) if foldcopy_end_ns_file.is_file() else None

    foldcopy_duration_sec = None
    if foldcopy_start_ns and foldcopy_end_ns and foldcopy_end_ns >= foldcopy_start_ns:
        foldcopy_duration_sec = (foldcopy_end_ns - foldcopy_start_ns) / 1e9

    foldcopy_out_path = report_dir / "foldcopy.out"
    foldcopy_out_exists = foldcopy_out_path.is_file()
    foldcopy_out_bytes = foldcopy_out_path.stat().st_size if foldcopy_out_exists else 0
    foldcopy_out_sha256 = sha256_file(foldcopy_out_path) if foldcopy_out_exists else None

    foldcopy_out_content = foldcopy_out_path.read_text(encoding="utf-8", errors="replace") if foldcopy_out_exists else ""
    assertion_found = EXPECTED_ASSERTION in foldcopy_out_content
    panic_found = "panic:" in foldcopy_out_content or "ASSERTION FAILED:" in foldcopy_out_content

    # Inspect patched YAML and diff against original
    patched_yaml_path = report_dir / "patched_foldcopy" / "std" / "yaml.iyi"
    patched_yaml_exists = patched_yaml_path.is_file()
    patched_yaml_sha256 = sha256_file(patched_yaml_path) if patched_yaml_exists else None

    orig_yaml_path = repo_path / "src" / "std" / "yaml.iyi"
    mutation_diff_path = report_dir / "mutation.diff"
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

    return {
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
            "allow_shared_cache": allow_shared_cache,
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


def record_diagnostic_differences() -> dict[str, Any]:
    """Document known architectural and environmental differences between all runs."""
    return {
        "execution_form": {
            "isolated_diagnostic": "Direct Python subprocess running absolute gtimeout binary for mutant only",
            "standalone_shell": "Direct bash execution of bench/std_yaml_exercise.sh under outer timeout piped to tee",
            "parent_capture": "bash -c BODY bench/std_yaml_exercise.sh preserving relative $0, full sequence, and separated outer stdout/stderr",
        },
        "environment": {
            "isolated_diagnostic": "Sanitized base_env(pin, additions) removing IYI_*/CRYSTAL_*",
            "standalone_shell": "Inherited unrecorded parent shell environment with 3 overrides (PATH, HOME, IYI)",
            "parent_capture": "Inherited parent shell environment preserved verbatim; safe paths, presence, and hashes recorded at entry and pre-foldcopy",
        },
        "cache_directory": {
            "isolated_diagnostic": "Fresh isolated owned scratch directories control.cache and mutant.cache",
            "standalone_shell": "Unrecorded default user cache directory (~/.cache/iyi)",
            "parent_capture": "Cache directory resolved and gated against mutating shared cache; blocker raised if shared",
        },
        "timeout_resolution": {
            "isolated_diagnostic": "Absolute pinned /opt/homebrew/Cellar/coreutils/9.11/bin/gtimeout",
            "standalone_shell": "Bare timeout resolved dynamically by Bash",
            "parent_capture": "Bare timeout resolved dynamically by Bash; command type, executable path, and SHA-256 recorded",
        },
        "preceding_cases": {
            "isolated_diagnostic": "Pre-validation -> Control (1.96s) -> Mutant (44.06s)",
            "standalone_shell": "Full preceding YAML suite: build/run, refusals, alias expansion, 11 prove_caught cases",
            "parent_capture": "Full preceding YAML suite preserved unchanged before foldcopy",
        },
        "status_and_output_capture": {
            "isolated_diagnostic": "Direct Python capture of inner exit status and separate stdout/stderr",
            "standalone_shell": "Merged foldcopy.out deleted by EXIT trap; exit status unrecorded; wrong-diagnostic banner",
            "parent_capture": "Inner return code and unfiltered foldcopy.out captured before evaluation; EXIT trap retains WORK",
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for YAML parent capture diagnostic driver."""
    parser = argparse.ArgumentParser(
        description="Preserve parent context and capture raw foldcopy exit status and evidence."
    )
    parser.add_argument(
        "--repo",
        default="/Users/jwaldrip/dev/worktrees/iyi-run1-integration-20261101",
        help="Path to integration repository worktree (default: iyi-run1-integration-20261101)",
    )
    parser.add_argument(
        "--compiler",
        default=os.environ.get("IYI", "/Users/jwaldrip/dev/worktrees/iyi-stale-integration-repair/.build/iyi"),
        help="Path to compiler binary (default: $IYI or iyi-stale-integration-repair/.build/iyi)",
    )
    parser.add_argument(
        "--report-dir",
        required=True,
        help="Path to report directory for captured evidence and receipts",
    )
    parser.add_argument(
        "--pin",
        default=None,
        help="Optional path to pin.json or report directory containing pin.json",
    )
    parser.add_argument(
        "--p1-sha",
        default=P1_SOURCE_SHA,
        help="Expected P1 commit SHA (default: 626463375298d357ffcb3223059f4d3adce6fb10)",
    )
    parser.add_argument(
        "--compiler-sha256",
        default=EXPECTED_COMPILER_SHA256,
        help=f"Expected compiler binary SHA-256 (default: {EXPECTED_COMPILER_SHA256})",
    )
    parser.add_argument(
        "--script-sha256",
        default=EXPECTED_SCRIPT_SHA256,
        help=f"Expected integration script SHA-256 (default: {EXPECTED_SCRIPT_SHA256})",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Optional explicit owned cache directory for IYI_CACHE_DIR",
    )
    parser.add_argument(
        "--allow-shared-cache",
        action="store_true",
        help="Explicitly permit using inherited shared cache without raising blocker",
    )
    parser.add_argument(
        "--outer-timeout",
        type=int,
        default=DEFAULT_OUTER_TIMEOUT_SEC,
        help=f"Outer supervisor timeout in seconds (default: {DEFAULT_OUTER_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate parity, hashes, anchor reversal, and syntax without executing shell body",
    )

    args = parser.parse_args(argv)

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    driver_path = Path(__file__).resolve()
    driver_sha256 = sha256_file(driver_path)

    try:
        # 1. Validation of base repo, compiler, and integration script
        repo_val = validate_base_parity(args.repo, p1_sha=args.p1_sha)
        compiler_val = validate_compiler(args.compiler, expected_sha256=args.compiler_sha256)

        script_path = Path(args.repo) / "bench" / "std_yaml_exercise.sh"
        script_val = validate_integration_script(script_path, expected_sha256=args.script_sha256)

        # 2. Build instrumented shell body and verify reverse byte equality + bash syntax
        original_text = script_path.read_text(encoding="utf-8")
        instrumented_text, applied_patches = build_instrumented_body(original_text)
        reversal_val = verify_syntax_and_reversal(original_text, instrumented_text)

        # Save original, instrumented, and diff
        orig_save_path = report_dir / "original.sh"
        orig_save_path.write_text(original_text, encoding="utf-8")

        inst_save_path = report_dir / "instrumented.sh"
        inst_save_path.write_text(instrumented_text, encoding="utf-8")

        diff_lines = list(difflib.unified_diff(
            original_text.splitlines(keepends=True),
            instrumented_text.splitlines(keepends=True),
            fromfile=str(script_path),
            tofile=str(report_dir / "instrumented.sh"),
        ))
        diff_save_path = report_dir / "instrumentation.diff"
        diff_save_path.write_text("".join(diff_lines), encoding="utf-8")

        # Write capture helper scripts into report_dir
        write_capture_helpers(report_dir)

        # Check cache resolution
        cache_dir_arg = Path(args.cache_dir) if args.cache_dir else None
        candidate_env = os.environ.copy()
        if cache_dir_arg:
            candidate_env["IYI_CACHE_DIR"] = str(cache_dir_arg.resolve())
        resolved_cache, is_shared, cache_source = resolve_cache_directory(candidate_env)

        validation_receipt = {
            "driver": {
                "path": str(driver_path),
                "sha256": driver_sha256,
            },
            "validation": {
                "base_parity": repo_val,
                "compiler": compiler_val,
                "integration_script": script_val,
                "applied_patches": applied_patches,
                "reversal_and_syntax": reversal_val,
            },
            "cache": {
                "resolved_path": str(resolved_cache),
                "is_shared": is_shared,
                "source": cache_source,
                "allow_shared_cache": args.allow_shared_cache,
            },
            "saved_artifacts": {
                "original_script": str(orig_save_path),
                "original_sha256": sha256_file(orig_save_path),
                "instrumented_script": str(inst_save_path),
                "instrumented_sha256": sha256_file(inst_save_path),
                "instrumentation_diff": str(diff_save_path),
                "instrumentation_diff_sha256": sha256_file(diff_save_path),
            },
            "diagnostic_differences": record_diagnostic_differences(),
        }

        if args.validate_only:
            val_path = report_dir / "validation.json"
            val_path.write_text(json.dumps(validation_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print("VALIDATION SUCCESS: Base parity, compiler hash, anchor reversal, and bash syntax verified.")
            print(json.dumps({
                "status": "VALIDATED_ONLY",
                "report_dir": str(report_dir),
                "script_sha256": script_val["script_sha256"],
                "compiler_sha256": compiler_val["compiler_sha256"],
                "p1_sha": repo_val["p1_sha"],
                "cache_resolved": str(resolved_cache),
                "cache_is_shared": is_shared,
            }, indent=2, sort_keys=True))
            return 0

        # 3. Execution under parent context
        exec_results = execute_capture(
            repo_path=Path(args.repo),
            compiler_path=Path(args.compiler),
            report_dir=report_dir,
            instrumented_text=instrumented_text,
            cache_dir=cache_dir_arg,
            allow_shared_cache=args.allow_shared_cache,
            outer_timeout_sec=args.outer_timeout,
        )

        full_report = {
            **validation_receipt,
            **exec_results,
            "verdict": exec_results["foldcopy"]["classification"],
        }

        report_path = report_dir / "report.json"
        report_path.write_text(json.dumps(full_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        receipt_path = report_dir / "receipt.json"
        receipt = {
            "verdict": full_report["verdict"],
            "outer_returncode": full_report["execution"]["outer_returncode"],
            "foldcopy_raw_rc": full_report["foldcopy"]["raw_returncode"],
            "foldcopy_duration_sec": full_report["foldcopy"]["duration_sec"],
            "assertion_found": full_report["foldcopy"]["assertion_found"],
            "panic_found": full_report["foldcopy"]["panic_found"],
            "work_path": full_report["work"]["work_path"],
            "work_exists": full_report["work"]["work_exists"],
            "report_dir": str(report_dir),
        }
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0

    except DiagnosticValidationError as err:
        print(f"DIAGNOSTIC-VALIDATION-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "DiagnosticValidationError", "detail": str(err)}
        (report_dir / "error.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 2

    except DiagnosticBlockerError as err:
        print(f"DIAGNOSTIC-BLOCKER-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "DiagnosticBlockerError", "detail": str(err)}
        (report_dir / "blocker.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 3

    except Exception as err:
        print(f"DIAGNOSTIC-UNEXPECTED-ERROR: {err}", file=sys.stderr)
        err_report = {"error_type": "UnexpectedError", "detail": str(err)}
        (report_dir / "error.json").write_text(json.dumps(err_report, indent=2) + "\n", encoding="utf-8")
        return 1


if __name__ == "__main__":
    sys.exit(main())
