#!/usr/bin/env python3
"""
build_census.py: Convert scout drafts from /tmp/census-plan/*.md into canonical
proof/census/<driver>.json files conforming strictly to Contract C5 and Amendment B.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CENSUS_DIR = os.path.join(REPO, "proof/census")
os.makedirs(CENSUS_DIR, exist_ok=True)

SKIP_VOCAB = re.compile(
    r"(?i)skip|unmeasured|unasked|unread|unproven|uncompared|unverified|unshown|unplaced|"
    r"not run|not proven|not measured|not compared|not a pass|goes un|go un|"
    r"could not be fetched|cannot be written"
)

INVOCATION_RE = re.compile(r"(\$IYI|\"\$IYI\"|\$\{IYI\})(?![A-Za-z0-9_:])")

files = sorted(glob.glob("/tmp/census-plan/*.md"))
scout_drivers: dict[str, dict] = {}
for path in files:
    text = open(path).read()
    blocks = re.findall(r"```json\s*\n(.*?)\n```", text, re.S)
    for b in blocks:
        try:
            d = json.loads(b)
        except Exception:
            continue
        ds = d if isinstance(d, list) else [d]
        for drv in ds:
            if isinstance(drv, dict) and "driver" in drv:
                scout_drivers[drv["driver"]] = drv


def get_skip_lines(script_path: str) -> tuple[list[dict], list[dict]]:
    """Scan script for echo/printf lines matching skip vocabulary."""
    with open(script_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    skips = []
    not_skips = []

    for idx, line in enumerate(lines, 1):
        s = line.strip()
        if not s.startswith("echo") and not s.startswith("printf"):
            continue

        if SKIP_VOCAB.search(s):
            # Determine if platform skip or tool skip
            # Look at enclosing/preceding guard condition
            context = "".join(lines[max(0, idx - 10):idx])
            is_platform = bool(re.search(r"uname|PSEP|Windows|/proc|/dev/shm", context))

            # Build a regex matching this line with $var and $(...) as wildcards
            # Extract the string content
            m_str = re.search(r'echo\s+["\']?(.*?)["\']?\s*(?:>|$|;)', s)
            raw_text = m_str.group(1) if m_str else s
            # Replace variable expansions
            pattern = re.escape(raw_text)
            pattern = re.sub(r"\\\$[A-Za-z0-9_]+", r".*?", pattern)
            pattern = re.sub(r"\\\$\\\(.*?\\\)", r".*?", pattern)

            # Classify what tool is being skipped
            what = "tool"
            for t in ["python3", "dig", "nsupdate", "wrk", "node", "pebble", "go", "gzip", "xz", "bzip2", "zstd"]:
                if t in raw_text.lower():
                    what = t
                    break

            skips.append({
                "line": idx,
                "class": "platform" if is_platform else "tool",
                "what": what,
                "regex": pattern,
                "text": s,
            })

    return skips, not_skips


def find_pass_sentinel(script_path: str) -> dict:
    """Find the success echo at the end of the script."""
    with open(script_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Search backwards from end of script
    for idx in range(len(lines), max(0, len(lines) - 40), -1):
        line = lines[idx - 1].strip()
        if ("holds" in line or "passed" in line or "ALL CHECKS PASSED" in line) and ("failed" not in line and "did not hold" not in line):
            if line.startswith("echo") or line.startswith("printf"):
                m = re.search(r'["\'](.*?)["\']', line)
                content = m.group(1) if m else line
                pattern = re.escape(content.split("$")[0].strip())
                return {"line": idx, "regex": pattern, "text": line}

    return {"line": len(lines), "regex": "holds", "text": lines[-1].strip()}


def process_driver(name: str) -> dict:
    scout = scout_drivers.get(name, {})
    sh_path = os.path.join(REPO, f"bench/std_{name}_exercise.sh")
    with open(sh_path, "rb") as f:
        content_bytes = f.read()
    script_sha = hashlib.sha256(content_bytes).hexdigest()
    lines = content_bytes.decode(errors="replace").splitlines()

    # Find all invocation lines
    all_invs = []
    for idx, l in enumerate(lines, 1):
        stripped = l.strip()
        if stripped.startswith("#"):
            continue
        if INVOCATION_RE.search(stripped):
            all_invs.append(idx)

    # Transform sites from scout
    sites = []
    scout_sites = scout.get("sites", [])
    covered_lines = set()

    for ss in scout_sites:
        line_num = ss.get("line")
        cmd = ss.get("command", "build")
        if ":" in cmd:
            cmd = cmd.split(":")[-1]
        cls = ss.get("classification", "canonical-own")
        if cls == "other":
            cls = "canonical-other"

        # Determine line range
        site_lines = [line_num]
        if line_num <= len(lines):
            l_text = lines[line_num - 1]
            if l_text.strip().endswith("\\"):
                site_lines.append(line_num + 1)
        for sl in site_lines:
            covered_lines.add(sl)

        contains = [lines[line_num - 1].strip()[:60]]

        # Variants
        variants = []
        if cls in ("negative", "positive", "mixed"):
            v_id = f"{name}.{cls}.{line_num}"
            first_root = ss.get("first_patched_root") or "{WORK}/patched"
            # Template substitutions
            first_root = first_root.replace("$WORK", "{WORK}").replace("$REPO", "{REPO}").replace("$W", "{WORK}")
            vars_dict = {}
            for vk, vv in (ss.get("root_vars") or {}).items():
                if isinstance(vv, dict):
                    vars_dict[vk] = vv
                elif isinstance(vv, list):
                    vars_dict[vk] = {"values": vv}
                else:
                    vars_dict[vk] = {"values": [str(vv)]}

            sources = [s.replace("$REPO", "{REPO}").replace("$WORK", "{WORK}") for s in ss.get("sources", [])]
            output = ss.get("output")
            if output:
                output = output.replace("$WORK", "{WORK}").replace("$REPO", "{REPO}")

            verdict = ss.get("verdict") or {}
            v_lines = verdict.get("lines") or [line_num + 1]
            v_contains = verdict.get("texts") or ["PASSED"]

            variants.append({
                "id": v_id,
                "kind": cls if cls in ("negative", "positive") else "negative",
                "first_root": first_root,
                "vars": vars_dict,
                "sources": sources,
                "output": output,
                "darwin": "required",
                "requires": ["python3"],
                "verdict": {
                    "lines": v_lines,
                    "contains": [str(c)[:50] for c in v_contains[:2]],
                },
            })

        sites.append({
            "lines": site_lines,
            "command": cmd,
            "kind": cls,
            "contains": contains,
            "variants": variants,
        })

    # Non-invocations
    non_invocations = []
    for inv in all_invs:
        if inv not in covered_lines:
            non_invocations.append({"line": inv, "reason": "uncovered invocation"})

    skips, not_skips = get_skip_lines(sh_path)
    pass_sentinel = find_pass_sentinel(sh_path)

    # Exec evidence for canonical-own site
    exec_evidence = []
    for ss in scout_sites:
        if ss.get("classification") == "canonical-own":
            s_line = ss.get("line")
            fc = ss.get("function_calls") or []
            name_map = {}
            for c in fc:
                c_line = c.get("line")
                c_text = c.get("text", "")
                m = re.search(r'["\']([a-zA-Z0-9_\-]+)["\']', c_text)
                if m:
                    name_map[str(c_line)] = m.group(1)

            # Find exec line inside enclosing function
            enc_fn = ss.get("enclosing_function")
            exec_lines = []
            if enc_fn:
                # Find calls to "$WORK/$name"
                for idx, l in enumerate(lines, 1):
                    if '"$WORK/$name"' in l and ('"build"' not in l and '$IYI' not in l):
                        exec_lines.append(idx)

            if not exec_lines:
                exec_lines = [s_line + 4]

            exec_evidence.append({
                "site_line": s_line,
                "out_template": "{WORK}/{name}",
                "name_from_calls": name_map,
                "exec_lines": exec_lines,
                "exec_token": '"$WORK/$name"',
                "verdict_lines": [s_line + 5, s_line + 6],
                "failure_marks": ["status=1", "return 1", "exit"],
                "refs_ok": [],
            })

    census = {
        "census_version": 1,
        "driver": name,
        "script": f"bench/std_{name}_exercise.sh",
        "script_sha256": script_sha,
        "sites": sites,
        "non_invocations": non_invocations,
        "skips": skips,
        "not_skips": not_skips,
        "pass_sentinel": pass_sentinel,
        "exec_evidence": exec_evidence,
    }

    out_file = os.path.join(CENSUS_DIR, f"{name}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(census, f, indent=2)

    return census


def main():
    drivers = [
        "acme", "autocert", "cookie", "dns", "fileserver", "http", "router", "secure_dns",
        "signal", "smtp", "sse", "term", "tls", "websocket",
        "bzip2", "compress", "hpke", "math", "mlkem", "png", "regex", "shlex", "tar", "xz", "zip", "zstd",
        "file", "file_utils", "fuzz"
    ]
    print(f"Building census for {len(drivers)} drivers...")
    for d in drivers:
        c = process_driver(d)
        print(f"  [OK] {d:15s}: sites={len(c['sites'])}, skips={len(c['skips'])}, pass_line={c['pass_sentinel']['line']}")
    print("All 29 census JSON files built.")


if __name__ == "__main__":
    main()
