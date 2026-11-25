#!/usr/bin/env python3
"""Probe: which environment variables does the compiler read, cold and warm?

RG9's inputs check builds one program twice against one cache directory: the
first build (cold: the cache is empty) with `--stale-key`, the second (warm:
the first one's cache) with `--stale-key --stale-inputs`. On Windows their
`cenv` differs for every program, and on Linux and macOS it does not. This
builds the same program in the four ways that separate the two causes:

    cold-plain   empty cache, --stale-key
    warm-plain   that cache again, --stale-key
    cold-stale   another empty cache, --stale-key --stale-inputs
    warm-stale   that cache again, --stale-key --stale-inputs

with IYI_STALE_CENV_DUMP naming every variable each build's fingerprint was
made of, and prints which names each pair of builds disagrees on.

    python3 bench/stale_win_probe.py REPO COMPILER WORK [PROGRAM]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stale_rg9 as rg9  # noqa: E402


def parse_dump(text: str) -> dict:
    """The last block of a dump: header, counted names, uncounted names, quiet names."""
    blocks = []
    for line in text.splitlines():
        if line.startswith("build file="):
            blocks.append({"header": line, "counted": {}, "uncounted": {}, "quiet": {}})
        elif blocks and line[:2] in ("* ", "  ", "~ "):
            name, _, value = line[2:].partition("=")
            key = {"*": "counted", " ": "uncounted", "~": "quiet"}[line[0]]
            blocks[-1][key][name] = value
    return blocks[-1] if blocks else {"header": "(no dump)", "counted": {}, "uncounted": {}, "quiet": {}}


def leg(repo: str, compiler: str, work: str, program: str, name: str, cache: str, with_inputs: bool) -> dict:
    key = os.path.join(work, name + ".key")
    out = os.path.join(work, name + ".bin")
    dump = os.path.join(work, name + ".dump")
    record = os.path.join(work, name + ".inputs.json")
    for path in (key, out, dump, record):
        if os.path.exists(path):
            os.remove(path)
    env = rg9.env_for(repo, cache, False)
    env["IYI_STALE_CENV_DUMP"] = dump
    cmd = [compiler, "build", "--stale-key", key]
    if with_inputs:
        cmd += ["--stale-inputs", record]
    cmd += ["-o", out, program]
    proc = subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True)
    if proc.returncode:
        sys.exit(f"{name}: build exited {proc.returncode}\n{proc.stdout[-1500:]}\n{proc.stderr[-1500:]}")
    local = json.load(open(key, encoding="utf-8"))["local"]
    text = open(dump, encoding="utf-8").read() if os.path.exists(dump) else ""
    block = parse_dump(text)
    block["parts"] = local
    block["builds_in_dump"] = text.count("build file=")
    return block


def main() -> None:
    repo, compiler, work = (os.path.abspath(a) for a in sys.argv[1:4])
    program = os.path.join(repo, "samples", "iyi", sys.argv[4] if len(sys.argv) > 4 else "hello.iyi")
    os.makedirs(work, exist_ok=True)
    legs = {}
    plain_cache = os.path.join(work, "cache-plain")
    stale_cache = os.path.join(work, "cache-stale")
    legs["cold-plain"] = leg(repo, compiler, work, program, "cold-plain", plain_cache, False)
    legs["warm-plain"] = leg(repo, compiler, work, program, "warm-plain", plain_cache, False)
    legs["cold-stale"] = leg(repo, compiler, work, program, "cold-stale", stale_cache, True)
    legs["warm-stale"] = leg(repo, compiler, work, program, "warm-stale", stale_cache, True)

    print(f"program: {os.path.relpath(program, repo)}")
    for name, block in legs.items():
        parts = block["parts"]
        print(f"\n== {name}: {block['header']} (dump blocks: {block['builds_in_dump']})")
        print(f"   cenv {parts['cenv'][:16]}  build {parts['build'][:16]}  counted {len(block['counted'])}  uncounted {len(block['uncounted'])}  quiet-only {len(block['quiet'])}")
        for name_, value in sorted(block["counted"].items()):
            print(f"   * {name_}={value[:120]}")
        if block["quiet"]:
            print("   quiet-only (read, but kept out of the fingerprint): " + ", ".join(sorted(block["quiet"])))

    def compare(a: str, b: str) -> None:
        left, right = legs[a], legs[b]
        same = left["parts"]["cenv"] == right["parts"]["cenv"]
        print(f"\n== {a} vs {b}: cenv {'EQUAL' if same else 'DIFFERENT'}")
        names = set(left["counted"]) | set(right["counted"])
        for name_ in sorted(names):
            in_left, in_right = name_ in left["counted"], name_ in right["counted"]
            if in_left != in_right:
                print(f"   only in {a if in_left else b}: {name_}={(left if in_left else right)['counted'][name_][:120]}")
            elif left["counted"][name_] != right["counted"][name_]:
                print(f"   value differs: {name_}: {left['counted'][name_][:80]!r} vs {right['counted'][name_][:80]!r}")
        for name_ in sorted(set(left["uncounted"]) ^ set(right["uncounted"])):
            side = a if name_ in left["uncounted"] else b
            print(f"   uncounted, only in {side}: {name_}")
        for name_ in sorted(set(left["quiet"]) ^ set(right["quiet"])):
            side = a if name_ in left["quiet"] else b
            print(f"   quiet, only in {side}: {name_}")

    compare("cold-plain", "warm-plain")
    compare("cold-stale", "warm-stale")
    compare("cold-plain", "cold-stale")
    compare("warm-plain", "warm-stale")
    compare("cold-plain", "warm-stale")  # RG9's own pair


if __name__ == "__main__":
    main()
