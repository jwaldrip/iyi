#!/usr/bin/env python3
"""Probe for the observed chmod program that "overflowed its stack" on Windows.

A probe, not a gate (see .github/workflows/stale-win-probe.yml). The cause it
establishes: the program was built with an overlay whose prelude copy reached
the runtime by a relative path, so the scheduler was compiled as library code
and `IyiScheduler.state` carried a preemption check, which recursed through
`IyiWorkers.preempted` for as long as the monitor's word stayed raised. The
probe builds three layouts of the same programs and counts the failures:

  mis    the overlay as it was: prelude copy, runtime reached by a relative path
  fixed  the overlay as bench/stale_chmod_failure.sh makes it now: the whole
         `src/iyi` beside the prelude copy
  none   no overlay at all

and two programs: the chmod regression's, and the same with a loop ahead of the
chmod that keeps the task on its worker for longer than the monitor's quantum.

Usage: stale_win_probe_chmod.py REPO IYI WORK
"""
import collections
import os
from pathlib import Path
import shutil
import subprocess
import sys

repo = Path(sys.argv[1])
iyi = sys.argv[2]
work = Path(sys.argv[3])
work.mkdir(parents=True, exist_ok=True)

RUNS = int(os.environ.get("CHMOD_PROBE_RUNS", "100"))


def say(text=""):
    print(text, flush=True)


def clip(text, limit=6000):
    text = text.replace("\r", "")
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "\n... omitted ...\n" + text[-limit // 2:]


project = work / "project"
project.mkdir(exist_ok=True)
scratch = work / "scratch"
scratch.mkdir(exist_ok=True)
target = project / "absent"

CHMOD_TEST = '''import std/file::{File}
path = Program.env("IYI_CHMOD_FAILURE_PATH") || raise "missing path"
group do |g|
  task = g.spawn do
    File.chmod(path, 0o600)
    0
  end
  assert task.value.is_a?(Panicked)
end
'''

# The same, after a loop that holds the task's worker for longer than the
# monitor's quantum (5 to 10 ms), so the worker's preemption word is raised
# by the time the loop's back-edge looks at it.
BUSY_TEST = '''import std/file::{File}
path = Program.env("IYI_CHMOD_FAILURE_PATH") || raise "missing path"
group do |g|
  task = g.spawn do
    total = 0_u64
    i = 0_u64
    while i < 300_000_000_u64
      total = total &+ (i ^ 5_u64)
      i = i &+ 1_u64
    end
    File.chmod(path, 0o600) if total != 1_u64
    0
  end
  assert task.value.is_a?(Panicked)
end
'''


def make_overlay(name, full):
    """The overlay stale_chmod_failure.sh makes: the old one, or with the whole runtime beside the prelude."""
    overlay = work / name
    if overlay.exists():
        shutil.rmtree(overlay)
    observer = overlay / "std" / "observe.iyi"
    observer.parent.mkdir(parents=True)
    original = (repo / "src" / "std" / "observe.iyi").read_text(encoding="utf-8")
    scheduler = (repo / "src" / "iyi" / "concurrency.iyi").read_text(encoding="utf-8").splitlines()
    matches = [line for line, text in enumerate(scheduler, 1) if "def self.resolved : Int32" in text]
    if len(matches) != 1:
        raise AssertionError("scheduler resolved fixture no longer applies")
    site = f"iyi/concurrency.iyi:{matches[0]}"
    before = 'pub def __iyi_observe_process(site : String) : Nil\n  not_reusable(36_u8, site)\nend'
    after = ('pub def __iyi_observe_process(site : String) : Nil\n'
             f'  not_reusable(36_u8, site) unless site.includes?("{site}")\nend')
    if original.count(before) != 1:
        raise AssertionError("scheduler process observer fixture no longer applies")
    observer.write_text(original.replace(before, after), encoding="utf-8")
    prelude = overlay / "iyi" / "prelude.iyi"
    if full:
        shutil.copytree(repo / "src" / "iyi", overlay / "iyi")
        return overlay
    prelude.parent.mkdir(parents=True)
    source = (repo / "src" / "iyi" / "prelude.iyi").read_text(encoding="utf-8")
    runtime_path = os.path.relpath(repo / "src" / "iyi", prelude.parent).replace("\\", "/")
    prelude.write_text(source.replace('require "./', f'require "{runtime_path}/'), encoding="utf-8")
    return overlay


def environment(overlay):
    env = os.environ.copy()
    env["IYI_CACHE_DIR"] = str(work / "cache")
    base_path = env.get("IYI_PATH") or os.pathsep.join((str(repo / "src"), str(repo / "samples" / "iyi")))
    env["IYI_PATH"] = os.pathsep.join((str(overlay), base_path)) if overlay else base_path
    env["IYI_LIBRARY_PATH"] = str(repo / "lib")
    env["IYI_CHMOD_FAILURE_PATH"] = str(target)
    return env


def observed(env, trace):
    out = env.copy()
    out.update({"TMPDIR": str(scratch), "TEMP": str(scratch), "TMP": str(scratch), "IYI_OBSERVE": str(trace)})
    return out


def build(label, overlay, source):
    test = project / f"{label}.iyi"
    test.write_text(source, encoding="utf-8")
    exe = work / f"{label}.exe"
    env = environment(overlay)
    result = subprocess.run([iyi, "build", "-Diyi_observe", "-o", str(exe), str(test)], cwd=project, env=env,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    if result.returncode:
        say(f"== {label}: build failed, exit {result.returncode}\n{clip(result.stdout)}\n{clip(result.stderr)}")
        return None, env
    return exe, env


def runs(label, exe, env, count):
    tally = collections.Counter()
    for index in range(count):
        trace = work / f"{label}-{index}.trace"
        trace.unlink(missing_ok=True)
        result = subprocess.run([str(exe)], cwd=project, env=observed(env, trace), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        head = (result.stderr.strip().splitlines() or [""])[0]
        if "Cannot chmod" in head:
            head = "the caught chmod panic"
        tally[(result.returncode, head[:100])] += 1
    for (code, head), count_ in sorted(tally.items(), key=lambda item: -item[1]):
        say(f"   {label}: {count_} of {count} x exit {code}: {head}")


def find_cdb():
    for root in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if root:
            candidate = Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"
            if candidate.exists():
                return candidate
    return None


def disassemble(label, exe, env, function):
    """What the compiler made of one function of the runtime, from the debugger."""
    cdb = find_cdb()
    if cdb is None:
        return
    module = exe.stem.replace("-", "_")
    result = subprocess.run([str(cdb), "-G", "-c", f"uf {module}!{function}; q", "-y", str(work), str(exe)],
                            cwd=project, env=observed(env, work / "disassemble.trace"), capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=120)
    lines = [line for line in result.stdout.replace("\r", "").splitlines()
             if "call" in line or line.startswith(module + "!") or "Flow analysis" in line]
    say(f"   {label}: {function} makes {sum('__iyi_preempt' in line for line in lines)} call(s) to __iyi_preempt")
    say("\n".join("      " + line for line in lines[:14]))


say(f"== probe host: {os.environ.get('OS')}, cdb: {find_cdb()}")
layouts = (("mis", make_overlay("overlay-mis", full=False)), ("fixed", make_overlay("overlay-fixed", full=True)),
           ("none", None))
for layout, overlay in layouts:
    say(f"== {layout}")
    for program, source, count in (("chmod", CHMOD_TEST, RUNS), ("busy", BUSY_TEST, 20)):
        exe, env = build(f"{layout}-{program}", overlay, source)
        if exe:
            runs(f"{layout}-{program}", exe, env, count)
            if program == "busy":
                disassemble(f"{layout}-busy", exe, env, "state")
