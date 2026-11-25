#!/usr/bin/env python3
"""Probe: why do rows 26, 28, 50, 55 and 58 of bench/stale_tests.sh fail on Windows?

Each scenario repeats what a row does, spelled as the row spells it (paths with
forward slashes, a work directory under the 8.3 temp directory, Git's bash for the
`cd` and the exported variable, the environment inherited as it is: python's
`os.environ` would spell every name in upper case, and the runner compares names as
spelled), with IYI_STALE_CENV_DUMP naming, for every build the runner starts, the
variables its `cenv` was made of and the compatibility layer the build saw, and for
the runner itself the layer and the job limits it read. After every step it prints
the decision, those views and the receipts in the store with the key parts each one
holds, so a miss names the part that moved.

    PROBE_BASH=C:/Program Files/Git/usr/bin/bash.exe \\
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
BASH = os.environ.get("PROBE_BASH", "bash")

COMPILER = WORK = CACHE = DUMP = ""
DUMP_OFFSET = 0
PREVIOUS_COUNTED: dict | None = None
STEP = 0


def p(*parts: str) -> str:
    return "/".join(parts)


def say(text: str = "") -> None:
    print(text, flush=True)


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def long_path(path: str) -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(1024)
    size = ctypes.windll.kernel32.GetLongPathNameW(path.replace("/", "\\"), buffer, 1024)
    return buffer.value if 0 < size < 1024 else path


def new_dump_blocks() -> list[dict]:
    """What the compiler and the runner appended to the dump since the last call."""
    global DUMP_OFFSET
    blocks: list[dict] = []
    if not os.path.exists(DUMP):
        return blocks
    with open(DUMP, "rb") as handle:
        handle.seek(DUMP_OFFSET)
        data = handle.read()
    DUMP_OFFSET += len(data)
    for line in data.decode("utf-8", errors="replace").splitlines():
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
    previous: dict[str, dict] = {}
    for record in receipts():
        build, profile = record.get("build", {}), record.get("profile", {})
        test = record.get("test") or {}
        name = "%s/%s" % (test.get("root"), test.get("path"))
        parts = " ".join("%s=%s" % (key, (build.get(key) or "")[:8]) for key in ("build", "toolchain", "behavior", "cenv", "link", "callpath"))
        say("   receipt seq=%s %s %s %s profile=%s rlimits=%s" % (record.get("seq"), record.get("mode"), name, parts, (profile.get("fp") or "")[:8], profile.get("rlimits")))
        explain = record.get("explain") or {}
        before = previous.get(name)
        if before is not None:
            moved = sorted(key for key in set(explain) | set(before) if explain.get(key) != before.get(key))
            if moved:
                say("      explain differs from this test's receipt before in: " + ", ".join(moved))
        previous[name] = explain


def show_dump() -> None:
    global PREVIOUS_COUNTED
    for block in new_dump_blocks():
        if block["kind"] == "runner":
            say("   dump " + block["header"])
            continue
        say("   dump %s counted=%d %s" % (block["header"].replace(WORK, "<work>"), len(block["counted"]), block["info"]))
        before, PREVIOUS_COUNTED = PREVIOUS_COUNTED, block["counted"]
        if before is not None:
            for name in sorted(set(before) | set(block["counted"])):
                if before.get(name) != block["counted"].get(name):
                    say("   dump counted differs from the build before: %s: %r vs %r" % (name, before.get(name), block["counted"].get(name)))


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", **kwargs)


def in_bash(layer: str | None, cwd: str, command: list[str]) -> list[str]:
    """The row's shape: a subshell of Git's bash that exports the variables, `cd`s and execs."""
    export = 'export __COMPAT_LAYER="$1" IYI_DAEMON_SOCKET="$2" CRYSTAL_DAEMON_SOCKET="$2"; ' if layer is not None else ""
    script = export + 'cd "$3" && shift 3 && exec "$@"'
    return [BASH, "-c", script, "_", layer or "", p(WORK, "no.sock"), cwd] + command


def launch(core: list[str], cwd: str, mode: str, layer: str | None = None, job: int | None = None) -> subprocess.CompletedProcess:
    if job is not None:
        # The row's own shape for a limit: a python wrapper with the directory as its cwd.
        return run([sys.executable, JOB_RUN, str(job)] + core, cwd=cwd)
    if mode == "py":
        return run(core, cwd=cwd)
    if mode == "long":
        return run(core, cwd=long_path(cwd))
    return run(in_bash(layer, cwd, core))


def run_test(label: str, cwd: str, args: list[str], layer: str | None = None, job: int | None = None, mode: str = "bash") -> dict:
    """One `iyi test ARGS` the way a row runs it."""
    global STEP
    STEP += 1
    proc = launch([COMPILER, "test"] + args, cwd, mode, layer, job)
    lines = proc.stdout.splitlines()
    say("")
    say("-- step %d: %s (%s layer=%r job=%r) exit %d" % (STEP, label, mode, layer, job, proc.returncode))
    result: dict = {}
    if lines and lines[-1].startswith("{"):
        try:
            doc = json.loads(lines[-1])
            result = doc
            say("   cached=%s failed=%s" % (doc.get("cached"), doc.get("failed")))
            for test in doc.get("tests", []):
                say("   %s: reuse=%s check=%s check_reason=%s reason=%s" % (
                    os.path.basename(test.get("file", "?")), test.get("reuse"), test.get("check"), test.get("check_reason"), test.get("reason")))
        except ValueError as problem:
            say("   unparsed json: %s" % problem)
        for line in lines[:-1]:
            say("   decision: " + line)
    else:
        say("   stdout: " + proc.stdout[-800:])
    if proc.stderr.strip():
        say("   stderr: " + proc.stderr.strip()[-800:])
    show_dump()
    show_receipts()
    return result


def key_build(label: str, cwd: str, file: str, job: int | None = None, layer: str | None = None, mode: str = "bash", elements: bool = False) -> tuple[dict, dict]:
    """One `iyi build --stale-key` the way the runner's build runs: the key parts, and the call path's elements."""
    global STEP
    STEP += 1
    key = p(WORK, "key-%02d.json" % STEP)
    record = p(WORK, "inputs-%02d.json" % STEP)
    out = p(WORK, "out-%02d.exe" % STEP)
    dump = p(WORK, "elements-%02d.jsonl" % STEP)
    core = [COMPILER, "build", file, "-o", out, "-Diyi_observe", "--stale-key", key, "--stale-inputs", record]
    if elements:
        core += ["--stale-dump-elements", dump]
    proc = launch(core, cwd, mode, layer, job)
    say("")
    say("-- step %d: key build %s (%s layer=%r job=%r) exit %d" % (STEP, label, mode, layer, job, proc.returncode))
    if proc.returncode:
        say("   output: " + (proc.stdout + proc.stderr)[-800:])
        return {}, {}
    data = json.load(open(key, encoding="utf-8"))["local"]
    say("   " + " ".join("%s=%s" % (part, data[part][:8]) for part in ("build", "toolchain", "behavior", "cenv", "link", "callpath")))
    show_dump()
    rows: dict = {}
    if elements and os.path.exists(dump):
        for line in open(dump, encoding="utf-8"):
            if line.strip():
                row = json.loads(line)
                rows["%s|%s" % (row.get("kind"), row.get("key"))] = row
    return data, rows


def compare_keys(a: dict, b: dict, label: str, rows_a: dict | None = None, rows_b: dict | None = None) -> None:
    if not a or not b:
        return
    moved = [part for part in ("toolchain", "behavior", "cenv", "link", "callpath", "build") if a.get(part) != b.get(part)]
    say("   >> %s: parts that differ: %s" % (label, ", ".join(moved) or "none"))
    explain_a, explain_b = a.get("explain") or {}, b.get("explain") or {}
    differ = sorted(key for key in set(explain_a) | set(explain_b) if explain_a.get(key) != explain_b.get(key))
    if differ:
        say("   >> %s: explain entries that differ: %s" % (label, ", ".join(differ)))
    if rows_a and rows_b:
        keys = sorted(key for key in set(rows_a) | set(rows_b) if (rows_a.get(key) or {}).get("digest") != (rows_b.get(key) or {}).get("digest"))
        say("   >> %s: %d of %d call path elements differ" % (label, len(keys), len(set(rows_a) | set(rows_b))))
        for key in keys[:30]:
            left, right = rows_a.get(key), rows_b.get(key)
            row = left or right
            say("      %s [%s:%s mapped=%s] %s vs %s" % (
                key[:140], os.path.basename(str(row.get("file"))), row.get("line"), row.get("mapped"),
                (left or {}).get("digest", "absent")[:8], (right or {}).get("digest", "absent")[:8]))


CANDIDATES = (
    "RunAsInvoker",
    "RunAsInvoker 256Color",
    "256Color RunAsInvoker",
    "256Color",
    "IyiRowLayer",
    "RunAsInvoker IyiRowLayer",
    "IyiRowLayer RunAsInvoker",
    "DisableThemes",
    "RunAsInvoker DisableThemes",
    "HighDpiAware",
    "RunAsInvoker HighDpiAware",
)


def scenario_layer_view() -> None:
    say("")
    say("== what a process starting with __COMPAT_LAYER set sees of it afterwards")
    snippet = "import os; print(repr(os.environ.get('__COMPAT_LAYER')))"
    for layer in CANDIDATES:
        env = os.environ.copy()
        env["__COMPAT_LAYER"] = layer
        direct = run([sys.executable, "-c", snippet], env=env)
        through_bash = run([BASH, "-c", 'export __COMPAT_LAYER="$1"; "$2" -c "$3"', "_", layer, sys.executable.replace("\\", "/"), snippet])
        say("   exported %-30r python started by python sees %-28s python started by bash sees %s" % (layer, direct.stdout.strip(), through_bash.stdout.strip() or through_bash.stderr.strip()[:80]))


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

CHECKED = ["--cached", "--json", "--explain"]


def scenario_loader() -> None:
    say("")
    say("== row 28: the loader variable")
    warm = p(WORK, "warm")
    write(p(warm, "other_test.iyi"), "assert 1 + 1 == 2\n")
    run_test("warm the compiler cache", warm, CHECKED + ["other_test.iyi"])
    d = p(WORK, "r28")
    write(p(d, "loader_test.iyi"), LOADER_TEST)
    t = CHECKED + ["loader_test.iyi"]
    for second in ("RunAsInvoker 256Color", "RunAsInvoker HighDpiAware", "256Color"):
        say("")
        say("== row 28 with %r as the changed layer" % second)
        shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
        run_test("run 1: RunAsInvoker, records", d, t, layer="RunAsInvoker")
        run_test("run 2: the same loader (expect a hit)", d, t, layer="RunAsInvoker")
        run_test("run 3: %r (expect a miss, link changed)" % second, d, t, layer=second)
        run_test("run 4: %r again (expect a hit)" % second, d, t, layer=second)
        run_test("run 5: ambient, no layer (expect a miss)", d, t)


def scenario_job() -> None:
    say("")
    say("== row 28: a job limit")
    d = p(WORK, "r28")
    write(p(d, "loader_test.iyi"), LOADER_TEST)
    t = CHECKED + ["loader_test.iyi"]
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    limit = 16 * 1024**3
    run_test("run 1: ambient, records", d, t)
    run_test("run 2: ambient (expect a hit)", d, t)
    run_test("run 3: ambient, inside a job with a 16 GiB job memory limit (expect profile changed)", d, t, job=limit)
    run_test("run 4: the same limit again (expect a hit)", d, t, job=limit)
    run_test("run 5: ambient again (expect a hit)", d, t)
    run_test("run 6: ambient, python's cwd and no job (the wrapper's spelling of the directory)", d, t, mode="py")

    say("")
    say("== row 28: the key's parts under a job")
    plain_1, rows_1 = key_build("ambient, bash cd", d, "loader_test.iyi", elements=True)
    plain_2, rows_2 = key_build("ambient again, bash cd", d, "loader_test.iyi", elements=True)
    compare_keys(plain_1, plain_2, "bash cd vs bash cd", rows_1, rows_2)
    jobbed, rows_j = key_build("ambient, job limit (python's cwd)", d, "loader_test.iyi", job=limit, elements=True)
    compare_keys(plain_2, jobbed, "bash cd vs job limit", rows_2, rows_j)
    py, rows_p = key_build("ambient, python's cwd", d, "loader_test.iyi", mode="py", elements=True)
    compare_keys(plain_2, py, "bash cd vs python's cwd", rows_2, rows_p)
    long_, rows_l = key_build("ambient, python's cwd as a long path", d, "loader_test.iyi", mode="long", elements=True)
    compare_keys(plain_2, long_, "bash cd vs python's cwd as a long path", rows_2, rows_l)


def scenario_macro_run() -> None:
    say("")
    say("== rows 50 and 55: a macro run helper compiled cold")
    d = p(WORK, "macro-run")
    write(p(d, "helper.iyi"), 'puts "41 + 1"\n')
    write(p(d, "run_test.iyi"), 'raise "macro run lost" unless ({{ run("./helper") }}) == 42\n')
    t = CHECKED + ["run_test.iyi"]
    shutil.rmtree(CACHE, ignore_errors=True)
    run_test("row 50 run 1: empty cache, records", d, t)
    run_test("row 50 run 2: the checked run", d, t)
    run_test("row 50 run 3", d, t)
    d55 = p(WORK, "r55")
    write(p(d55, "helper.iyi"), 'puts "41 + 1"\n')
    write(p(d55, "run_test.iyi"), 'raise "macro run lost" unless ({{ run("./helper") }}) == 42\n')
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    run_test("row 55 run 1: warm compiler cache, cold helper, records", d55, t)
    run_test("row 55 run 2: the checked run", d55, t)


def scenario_interrupt_shape() -> None:
    say("")
    say("== row 58: the interrupted run's shape, without the interrupt")
    d = p(WORK, "r58")
    for name in ("quick_a", "quick_b"):
        write(p(d, name + "_test.iyi"), "assert 1 + 1 == 2\n")
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    run_test("run 1: python's cwd, --fresh -p 4 (the interrupted run)", d, ["--fresh", "--json", "--explain", "-p", "4", "."], mode="py")
    run_test("run 2: bash cd, --cached -p 4 (the rerun; expect two hits)", d, CHECKED + ["-p", "4", "."])
    run_test("run 3: bash cd again (expect two hits)", d, CHECKED + ["-p", "4", "."])
    shutil.rmtree(p(CACHE, "tests-v1"), ignore_errors=True)
    run_test("run 4: bash cd, --fresh -p 4", d, ["--fresh", "--json", "--explain", "-p", "4", "."])
    run_test("run 5: bash cd, --cached -p 4 (expect two hits)", d, CHECKED + ["-p", "4", "."])
    file = "quick_a_test.iyi"
    a, rows_a = key_build("bash cd", d, file, elements=True)
    b, rows_b = key_build("python's cwd", d, file, mode="py", elements=True)
    compare_keys(a, b, "bash cd vs python's cwd", rows_a, rows_b)


def main() -> None:
    global COMPILER, WORK, CACHE, DUMP
    COMPILER, WORK = sys.argv[1], sys.argv[2]
    CACHE = p(WORK, "cache")
    DUMP = p(WORK, "dump.txt")
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    # Set in this process, so every child inherits the block as it is, with the names it has.
    os.environ["IYI_CACHE_DIR"] = CACHE
    os.environ["IYI_STALE_FAST_AUDIT"] = "1"
    os.environ["IYI_STALE_CENV_DUMP"] = DUMP
    for name in ("__COMPAT_LAYER", "IYI_DAEMON_SOCKET", "CRYSTAL_DAEMON_SOCKET"):
        os.environ.pop(name, None)
    say("bash: %s" % BASH)
    scenarios = (scenario_layer_view, scenario_interrupt_shape, scenario_macro_run, scenario_job, scenario_loader)
    only = os.environ.get("PROBE_ONLY")
    for scenario in scenarios:
        if only and only not in scenario.__name__:
            continue
        try:
            scenario()
        except Exception:  # noqa: BLE001 - a probe reports and goes on
            say("   scenario %s raised:\n%s" % (scenario.__name__, traceback.format_exc()))


if __name__ == "__main__":
    main()
