#!/usr/bin/env python3
"""Verify action commit pins against git ls-remote tags per Plan §3.2."""

import json
import os
import subprocess
import sys
from typing import Callable, Dict, Optional, Tuple

PINNED_ACTIONS: Dict[str, Dict[str, str]] = {
    "actions/checkout": {
        "tag": "v7.0.1",
        "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    },
    "actions/setup-python": {
        "tag": "v7.1.0",
        "sha": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
    },
    "actions/setup-go": {
        "tag": "v7.0.0",
        "sha": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
    },
    "actions/cache": {
        "tag": "v6.1.0",
        "sha": "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
    },
    "actions/setup-node": {
        "tag": "v7.1.0",
        "sha": "949feb2413d6458794dcd2491c4babbbce0c15c1",
    },
    "actions/upload-artifact": {
        "tag": "v7.0.2",
        "sha": "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    },
}


def default_ls_remote(action: str, tag: str) -> str:
    """Run git ls-remote to query the remote tag commit and peeled tag commit."""
    url = f"https://github.com/{action}.git"
    ref_tag = f"refs/tags/{tag}"
    ref_peeled = f"refs/tags/{tag}^{{}}"
    cmd = ["git", "ls-remote", "--tags", url, ref_tag, ref_peeled]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"git ls-remote failed for {action} {tag}: {res.stderr.strip()}")
    return res.stdout


def resolve_tag_sha(output: str, tag: str) -> str:
    """Resolve tag SHA from git ls-remote output, preferring peeled tag if present."""
    target_tag = f"refs/tags/{tag}"
    target_peeled = f"refs/tags/{tag}^{{}}"
    tag_sha: Optional[str] = None
    peeled_sha: Optional[str] = None

    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            sha, ref = parts[0], parts[1]
            if ref == target_peeled:
                peeled_sha = sha
            elif ref == target_tag:
                tag_sha = sha

    resolved = peeled_sha or tag_sha
    if not resolved:
        raise ValueError(f"Tag {tag} not found in ls-remote output:\n{output}")
    return resolved


def check_action_pins(
    out_path: Optional[str] = None,
    ls_remote_fn: Optional[Callable[[str, str], str]] = None,
) -> Dict[str, object]:
    """Check all pinned actions against their remote git tags."""
    if ls_remote_fn is None:
        ls_remote_fn = default_ls_remote

    verified_actions: Dict[str, Dict[str, str]] = {}
    mismatches = []

    for action, expected in sorted(PINNED_ACTIONS.items()):
        tag = expected["tag"]
        expected_sha = expected["sha"]
        try:
            raw_output = ls_remote_fn(action, tag)
            resolved_sha = resolve_tag_sha(raw_output, tag)
        except Exception as e:
            mismatches.append(f"{action} @ {tag}: resolution error: {e}")
            continue

        if resolved_sha != expected_sha:
            mismatches.append(
                f"{action} @ {tag}: expected commit {expected_sha}, got {resolved_sha}"
            )
        else:
            verified_actions[action] = {
                "tag": tag,
                "sha": resolved_sha,
            }

    if mismatches:
        for err in mismatches:
            print(f"ERROR: {err}", file=sys.stderr)
        raise RuntimeError(f"Action pin verification failed with {len(mismatches)} error(s)")

    report = {
        "status": "PASS",
        "actions": verified_actions,
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

    parser = argparse.ArgumentParser(description="Verify action pins against git ls-remote")
    parser.add_argument("--out", "-o", dest="out_path", help="Path to write JSON pins report")
    args = parser.parse_args(argv)

    try:
        report = check_action_pins(out_path=args.out_path)
        print("Action pin verification PASSED: all 6 actions match §3.2")
        for action, data in sorted(report["actions"].items()):
            print(f"  {action} {data['tag']} -> {data['sha']}")
        return 0
    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
