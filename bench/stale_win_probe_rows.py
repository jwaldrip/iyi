#!/usr/bin/env python3
"""Probe: why do rows 26, 28, 50 and 55 of bench/stale_tests.sh fail on Windows?

Each scenario repeats what a row does, spelled as the row spells it (paths with
forward slashes, a work directory under the 8.3 temp directory, MSYS bash for the
`cd` and the exported variable), with IYI_STALE_CENV_DUMP naming, for every build
the runner starts, the variables its `cenv` was made of and the compatibility
layer the build saw, and for the runner itself the layer and the job limits it
read. After every step it prints the decision, those views and the receipts in the
store with the key parts each one holds, so a miss names the part that moved.

    python3 bench/stale_win_probe_rows.py COMPILER WORK

COMPILER and WORK are absolute and forward-slashed, as bench/stale_tests.sh gives
them. A probe, not a gate: it exits 0.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
JOB_RUN = os.path.join(HERE, "stale_win_job_run.py")

COMPILER = WORK = CACHE = ""
STEP = 0


def p(*parts: str) -> str:
    return "/".join(parts)


def say(text: str = "") -> None:
    print(text, flush=True)


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def read_dump(path: str) -> list[dict]:
    blocks: list[dict] = []
    if not os.path.exists(path):
        return blocks
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        if line.startswith("build file="):
            blocks.append({"kind": "build", "header": line, "counted": {}, "uncounted": {}, "quiet": {}, "info": ""})
        elif line.startswith("runner "):
            blocks.append({"kind": "runner", "header": line})
        elif blocks and blocks[-1]["kind"] == "build":
            block = blocks[-1]
            if line.startswith("info "):
                block["info"] = line[5:]
            elif line[:2] in ("* ", "  ", "~ "):
                name, _, value = line[2:].partition("=")
                block[{"*": "counted", " ": "uncounted", "~": "quiet"}[line[0]]][name] = value
    return blocks


def receipts() -> list[dict]:
    found = []
    for path in glob.glob(p(CACHE, "tests-v1", "records", "*", "*.json")):
        try:
            record = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        found.append(record)
    found.sort(key=lambda record: record.get("seq") or 0)
    return found


def show_receipts() -> None:
    previous = None
    for record in receipts():
        build, profile = record.get("build", {}), record.get("profile", {})
        parts = " ".join("%s=%s" % (key, (build.get(key) or "")[:8]) for key in ("build", "toolchain", "behavior", "cenv", "link", "callpath"))
        say("   receipt seq=%s %s %s profile=%s rlimits=%s" % (record.get("seq"), record.get("mode"), parts, (profile.get("fp") or "")[:8], profile.get("rlimits")))
        explain = record.get("explain") or {}
        if previous is not None:
            moved = sorted(key for key in set(explain) | set(previous) if explain.get(key) != previous.get(key))
            if moved:
                say("      explain differs from the receipt before in: " + ", ".join(moved))
        previous = explain


def show_dump(path: str) -> None:
    blocks = read_dump(path)
    for block in blocks:
        if block["kind"] == "runner":
            say("   dump " + block["header"])
        else:
            say("   dump %s counted=%d %s" % (block["header"].replace(WORK, "<work>"), len(block["counted"]), block["info"]))
    builds = [block for block in blocks if block["kind"] == "build"]
    for left, right in zip(builds, builds[1:]):
        names = sorted(set(left["counted"]) | set(right["counted"]))
        for name in names:
            if left["counted"].get(name) != right["counted"].get(name):
                say("   dump counted differs between consecutive builds: %s: %r vs %r" % (name, left["counted"].get(name), right["counted"].get(name)))


def env_for(dump: str) -> dict:
    env = os.environ.copy()
    env["IYI_CACHE_DIR"] = CACHE
    env["IYI_STALE_FAST_AUDIT"] = "1"
    env["IYI_STALE_CENV_DUMP"] = dump
    env.pop("__COMPAT_LAYER", None)
    env.pop("IYI_DAEMON_SOCKET", None)
    env.pop("CRYSTAL_DAEMON_SOCKET", None)
    return env


def run_test(label: str, cwd: str, file: str, layer: str | None = None, job: int | None = None) -> dict:
    """One `iyi test --cached --json --explain FILE` the way a row runs it."""
    global STEP
    STEP += 1
    dump = p(WORK, "dump-%02d.txt" % STEP)
    env = env_for(dump)
    core = [COMPILER, "test", "--cached", "--json", "--explain", file]
    kwargs = {"env": env, "capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace"}
    if job is not None:
        # The row's own shape for a limit: a python wrapper with the directory as its cwd.
        command = [sys.executable, JOB_RUN, str(job)] + core
        kwargs["cwd"] = cwd
    else:
        # The row's own shape otherwise: a subshell of MSYS bash that `cd`s, and exports the variables.
        export = 'export __COMPAT_LAYER="$1" IYI_DAEMON_SOCKET="$2" CRYSTAL_DAEMON_SOCKET="$2"; ' if layer is not None else ""
        script = export + 'cd "$3" && shift 3 && exec "$@"'
        command = ["bash", "-c", script, "_", layer or "", p(WORK, "no.sock"), cwd] + core
    proc = subprocess.run(command, **kwargs)
    lines = proc.stdout.splitlines()
    say("")
    say("-- step %d: %s (layer=%r job=%r) exit %d" % (STEP, label, layer, job, proc.returncode))
    result: dict = {}
    if lines and lines[-1].startswith("{"):
        try:
            doc = json.loads(lines[-1])
            test = doc["tests"][0] if doc.get("tests") else {}
            result = {"cached": doc.get("cached"), "failed": doc.get("failed"), "test": test}
            say("   cached=%s failed=%s reuse=%s check=%s check_reason=%s reason=%s" % (
                doc.get("cached"), doc.get("failed"), test.get("reuse"), test.get("check"), test.get("check_reason"), test.get("reason")))
        except (ValueError, KeyError) as problem:
            say("   unparsed json: %s" % problem)
        for line in lines[:-1]:
            say("   decision: " + line)
    else:
        say("   stdout: " + proc.stdout[-800:])
    if proc.stderr.strip():
        say("   stderr: " + proc.stderr.strip()[-800:])
    show_dump(dump)
    show_receipts()
    return result


def key_build(label: str, cwd: str, file: str, job: int | None = None, layer: str | None = None) -> dict:
    """One `iyi build --stale-key` the way the runner's build runs, and the key parts."""
    global STEP
    STEP += 1
    dump = p(WORK, "dump-%02d.txt" % STEP)
    env = env_for(dump)
    if layer is not None:
        env["__COMPAT_LAYER"] = layer
    key = p(WORK, "key-%02d.json" % STEP)
    record = p(WORK, "inputs-%02d.json" % STEP)
    out = p(WORK, "out-%02d.exe" % STEP)
    core = [COMPILER, "build", file, "-o", out, "-Diyi_observe", "--stale-key", key, "--stale-inputs", record]
    command = ([sys.executable, JOB_RUN, str(job)] + core) if job is not None else core
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    say("")
    say("-- step %d: key build %s (layer=%r job=%r) exit %d" % (STEP, label, layer, job, proc.returncode))
    if proc.returncode:
        say("   output: " + (proc.stdout + proc.stderr)[-800:])
        return {}
    data = json.load(open(key, encoding="utf-8"))["local"]
    say("   " + " ".join("%s=%s" % (part, data[part][:8]) for part in ("build", "toolchain", "behavior", "cenv", "link", "callpath")))
    show_dump(dump)
    return data


def compare_keys(a: dict, b: dict, label: str) -> None:
    if not a or not b:
        return
    moved = [part for part in ("toolchain", "behavior", "cenv", "link", "callpath", "build") if a.get(part) != b.get(part)]
    say("   >> %s: parts that differ: %s" % (label, ", ".join(moved) or "none"))
    explain_a, explain_b = a.get("explain") or {}, b.get("explain") or {}
    differ = sorted(key for key in set(explain_a) | set(explain_b) if explain_a.get(key) != explain_b.get(key))
    if differ:
        say("   >> %s: explain entries that differ: %s" % (label, ", ".join(differ)))


def scenario_layer_view() -> None:
    say("")
    say("== what a process sees of __COMPAT_LAYER")
    snippet = "import os; print(repr(os.environ.get('__COMPAT_LAYER')))"
    for layer in ("RunAsInvoker", "RunAsInvoker 256Color", "256Color"):
        via_bash = subprocess.run(["bash", "-c", 'export __COMPAT_LAYER="$1"; python3 -c "%s"; env | grep -i compat_layer' % snippet, "_", layer],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace")
        say("   bash export %r -> python sees: %s | stderr: %s" % (layer, via_bash.stdout.strip().replace("\n", " ; "), via_bash.stderr.strip()[:200]))
        env = os.environ.copy()
        env["__COMPAT_LAYER"] = layer
        direct = subprocess.run([sys.executable, "-c", snippet], env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        say("   python env=%r -> python sees: %s" % (layer, direct.stdout.strip()))


LOADER_TEST = """import std/env::{ENV}

assert Program.env("LD_PRELOAD") == nil
assert Program.env("LD_LIBRARY_PATH") == nil
assert Program.env("GLIBC_TUNABLES") == nil
assert Program.env("DYLD_INSERT_LIBRARIES") == nil
assert Program.env("DYLD_LIBRARY_PATH") == nil
assert Program.env("__COMPAT_LAYER") == nil
assert Program.env("IYI_DAEMON_SOCKET") == nil
assert Program.env("CRYSTAL_DAEMON_SOCKET") == nil
names = ENV.keys
assert !names.includes?("LD_PRELOAD")
assert !names.includes?("DYLD_LIBRARY_PATH")
assert !names.includes?("__COMPAT_LAYER")
assert !names.includes?("IYI_DAEMON_SOCKET")
assert !names.includes?("CRYSTAL_DAEMON_SOCKET")
"""


def scenario_loader() -> None:
    say("")
    say("== row 28: the loader variable and a job limit")
    warm = p(WORK, "warm")
    write(p(warm, "other_test.iyi"), "assert 1 + 1 == 2\n")
    run_test("warm the compiler cache", warm, "other_test.iyi")
    d = p(WORK, "r28")
    write(p(d, "loader_test.iyi"), LOADER_TEST)
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    limit = 16 * 1024**3
    run_test("run 1: RunAsInvoker, records", d, "loader_test.iyi", layer="RunAsInvoker")
    run_test("run 2: the same loader (expect a hit)", d, "loader_test.iyi", layer="RunAsInvoker")
    run_test("run 3: RunAsInvoker 256Color (expect a miss, link changed)", d, "loader_test.iyi", layer="RunAsInvoker 256Color")
    run_test("run 4: RunAsInvoker 256Color again (expect a hit)", d, "loader_test.iyi", layer="RunAsInvoker 256Color")
    run_test("run 5: ambient, no layer (expect a miss)", d, "loader_test.iyi")
    run_test("run 6: ambient, inside a job with a 16 GiB job memory limit (expect profile changed)", d, "loader_test.iyi", job=limit)
    run_test("run 7: the same limit again (expect a hit)", d, "loader_test.iyi", job=limit)

    say("")
    say("== row 28: the key's parts under a layer and under a job")
    plain_1 = key_build("ambient", d, "loader_test.iyi")
    plain_2 = key_build("ambient again", d, "loader_test.iyi")
    compare_keys(plain_1, plain_2, "ambient vs ambient")
    jobbed = key_build("ambient, job limit", d, "loader_test.iyi", job=limit)
    compare_keys(plain_2, jobbed, "ambient vs job limit")
    layered = key_build("layer RunAsInvoker", d, "loader_test.iyi", layer="RunAsInvoker")
    layered_2 = key_build("layer RunAsInvoker 256Color", d, "loader_test.iyi", layer="RunAsInvoker 256Color")
    compare_keys(plain_2, layered, "ambient vs RunAsInvoker")
    compare_keys(layered, layered_2, "RunAsInvoker vs RunAsInvoker 256Color")


def scenario_macro_run() -> None:
    say("")
    say("== rows 50 and 55: a macro run helper compiled cold")
    d = p(WORK, "macro-run")
    write(p(d, "helper.iyi"), 'puts "41 + 1"\n')
    write(p(d, "run_test.iyi"), 'raise "macro run lost" unless ({{ run("./helper") }}) == 42\n')
    shutil.rmtree(CACHE, ignore_errors=True)
    run_test("row 50 run 1: empty cache, records", d, "run_test.iyi")
    run_test("row 50 run 2: the checked run", d, "run_test.iyi")
    run_test("row 50 run 3", d, "run_test.iyi")
    d55 = p(WORK, "r55")
    write(p(d55, "helper.iyi"), 'puts "41 + 1"\n')
    write(p(d55, "run_test.iyi"), 'raise "macro run lost" unless ({{ run("./helper") }}) == 42\n')
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    run_test("row 55 run 1: warm compiler cache, cold helper, records", d55, "run_test.iyi")
    run_test("row 55 run 2: the checked run", d55, "run_test.iyi")


def main() -> None:
    global COMPILER, WORK, CACHE
    COMPILER, WORK = sys.argv[1], sys.argv[2]
    CACHE = p(WORK, "cache")
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    for scenario in (scenario_layer_view, scenario_loader, scenario_macro_run):
        try:
            scenario()
        except Exception:  # noqa: BLE001 - a probe reports and goes on
            say("   scenario %s raised:\n%s" % (scenario.__name__, traceback.format_exc()))


if __name__ == "__main__":
    main()
