#!/usr/bin/env python3
"""
Verify Route B ledger output against required invariants:
1. Must contain at least one successful roundtrip (exit 0) of the driver's own exercise.
2. Every patched invocation (observed-source / observed-run) must trace to an actual
   mutation-proof source / section in the driver script, not a canonical test.
3. Summary of all modes recorded in the ledger.
"""

from __future__ import annotations

import argparse
import os
import re
import sys


KNOWN_MUTATION_PATTERNS = [
    re.compile(r"mut(?:ant|\.out|\.log|\.build|-\d+)", re.IGNORECASE),
    re.compile(r"patched", re.IGNORECASE),
    re.compile(r"broken", re.IGNORECASE),
    re.compile(r"tlsbreak|latencybreak", re.IGNORECASE),
    re.compile(r"software", re.IGNORECASE),
    re.compile(r"small(?:\.bin|\.log)", re.IGNORECASE),
    re.compile(r"bare(?:\.log)?", re.IGNORECASE),
    re.compile(r"refuse(?:\.out|\.iyi)?", re.IGNORECASE),
    re.compile(r"stale-sandbox", re.IGNORECASE),
]


def is_mutation_proof_invocation(args: str, roots: str, driver_script_content: str) -> bool:
    # 1. Check if args or roots contain known mutation keywords
    combined = f"{roots} {args}"
    for pat in KNOWN_MUTATION_PATTERNS:
        if pat.search(combined):
            return True

    # 2. Check if the target file in args appears in a mutation section of the driver
    # Extract filename from args
    match = re.search(r"(\S+\.iyi)", args)
    if match:
        target_iyi = os.path.basename(match.group(1))
        # Search for lines in driver script where this target is invoked alongside IYI_PATH
        for line in driver_script_content.splitlines():
            if target_iyi in line and "IYI_PATH=" in line:
                return True

    return False


def verify_ledger(ledger_path: str, driver: str, repo_root: str = ".") -> dict[str, int]:
    if not os.path.exists(ledger_path):
        raise RuntimeError(f"Ledger file not found: {ledger_path}")

    driver_script = os.path.join(repo_root, f"bench/std_{driver}_exercise.sh")
    driver_script_content = ""
    if os.path.exists(driver_script):
        with open(driver_script, "r", encoding="utf-8") as f:
            driver_script_content = f.read()

    counts: dict[str, int] = {
        "roundtrip": 0,
        "observed-passthrough": 0,
        "observed-source": 0,
        "observed-run": 0,
        "unchanged": 0,
    }

    found_own_roundtrip = False
    target_substr = f"std_{driver}_exercise.iyi"

    with open(ledger_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        raise RuntimeError(f"Ledger file is empty: {ledger_path}")

    for line_idx, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            raise RuntimeError(f"Malformed ledger line {line_idx} in {ledger_path}: {line}")

        ts, mode, exit_code, cwd, roots, args = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

        counts[mode] = counts.get(mode, 0) + 1

        if mode == "roundtrip":
            # Check if this line built/ran the driver's own exercise and succeeded
            if target_substr in args and exit_code == "0":
                found_own_roundtrip = True

        if mode in ("observed-source", "observed-run"):
            # Guard A: Patched builds must have non-canonical roots
            if roots in ("none", "default", "empty"):
                raise RuntimeError(
                    f"Line {line_idx}: mode {mode} recorded with canonical roots '{roots}' (misclassified canonical invocation): {args}"
                )

            # Guard B: Must trace to an actual mutation-proof source/section in the driver
            if not is_mutation_proof_invocation(args, roots, driver_script_content):
                raise RuntimeError(
                    f"Line {line_idx}: mode {mode} does not trace to a verified mutation proof in std_{driver}_exercise.sh: roots='{roots}' args='{args}'"
                )

    if not found_own_roundtrip:
        raise RuntimeError(
            f"NOT-ROUNDTRIPPED: No successful roundtrip (exit 0) found for own exercise '{target_substr}' in {ledger_path}"
        )

    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Route B driver ledger")
    parser.add_argument("--ledger", required=True, help="Path to TSV ledger file")
    parser.add_argument("--driver", required=True, help="Driver short name (e.g. cookie, tls)")
    parser.add_argument("--repo", default=".", help="Path to repo/worktree root")
    args = parser.parse_args()

    try:
        counts = verify_ledger(args.ledger, args.driver, args.repo)
        summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"[LEDGER OK] driver={args.driver} {summary}")
    except RuntimeError as ex:
        print(f"[LEDGER FAIL] {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
