#!/usr/bin/env python3
"""Every gate in `bench/` is run by something.

    python3 bench/gates_reachable.py

A gate that nothing runs is a gate that passes on the machine that wrote it
and nowhere else. This repository has been bitten by that three times in one
release: `format_exercise`, `io_exercise` and `socket_exercise` all existed,
all held, and were named in the workflow by nothing — nine seconds for the
three of them, which is what an unrun gate was saving. `bench/panics.sh` was
the fourth, in a narrower form: it ran on Linux and darwin and the sentence
it asserts is Windows' own, so the one platform it was about was the one
platform nothing checked it on.

So this is that lesson, made a check, over every script and program directly
under bench/ (`.sh`, `.py` and `.iyi`). A file counts as run when something
that is itself run *runs* it, starting from the workflow's jobs and the
Makefiles:

  * a line of code that runs a command names it - `bash`, `python3`, `"$PY"`,
    `"$IYI" build`, `source` or `.`, pwsh's `&`, `subprocess` and
    `sys.executable` in Python, or a shell function whose body does one of
    those - at the command's place in the line, not inside a message;
  * or it is bound to a variable or a loop - `for s in bench/std_*_exercise.sh`,
    `TEST=".../std_${MODULE}_test.iyi"`, pwsh's `foreach` - that such a line
    uses. `*`, `${VAR}` and `$VAR` in a name stand for any.

It counted a mention until this: a name in a comment, in a docstring, in a
message or in a list of strings was a run. Thirteen measurement scripts were
"reached" that way, through `measured_numbers.py`'s list of what it cannot
re-measure and through each other's prose, and so was every tool below,
through this file's own list of them. A program was not looked at at all.

What is left is either a gate nobody runs — the thing to fix — or a *tool*,
which is a different kind of file: it takes an argument and answers a
question a person asked, rather than passing or failing. Those are listed
below with what they are for, and the list is short on purpose: a file that
is neither run nor explained is what this exists to name.

Exits non-zero if anything is unreached and unexplained.
"""
import fnmatch
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ci_plan  # noqa: E402  the planner's reading of names, globs and comments

# A tool, not a gate: it takes a path and prints a measurement, so there is
# nothing for a job to pass or fail. Each says where its answer is used,
# because "not a gate" is a claim and this is where it is written down.
TOOLS = {
    # `python3 bench/migrate_count.py <src dir>` counts the shapes a
    # file-per-module language has to answer for in a Crystal tree. Its
    # numbers on one 8,079-line application are read in SPEC.md III.6,
    # "What a migration would need, measured"; the application is not in
    # this repository, so there is no tree here to point it at.
    "migrate_count.py",
    # `bash bench/ct_timing.sh` times std's secret paths dudect-style and
    # fails loudly past |t| = 10. Run by hand on a quiet machine: on a
    # shared CI runner other jobs' load reaches |t| = 10 with nothing
    # leaking, so no workflow runs it.
    "ct_timing.sh",
    # `python3 bench/sibling_times.py LOG...` reads the seconds each std
    # sibling took from a run's std-siblings shard logs. Its numbers are the
    # WEIGHTS `bench/std_siblings.sh` deals its shards by; the logs are a
    # run's, downloaded, so there is nothing in a checkout to point it at.
    "sibling_times.py",
    # `python3 bench/machine_probe.py` prints the machine a timing came from
    # and three figures that tell a slower machine from slower code. The
    # README and BENCHMARKS.md point a reader at it before they re-take a
    # published number; on a CI runner it would describe the runner.
    "machine_probe.py",
    # `sh bench/native_llvm_matrix.sh` round-trips the LLVM IR of every
    # sample, std exercise and compile fixture through `iyi-ir` for five
    # targets and prints a table of verdicts: a measurement of how much of
    # what the hosted compiler emits the IR carries, not a pass or a fail.
    # It takes the better part of an hour, and its inventory is the corpus
    # half of bench/fixtures/llvm_roundtrip/COVERAGE.md. The gate beside
    # it, `native_llvm_roundtrip_exercise.sh`, is what a job runs.
    "native_llvm_matrix.sh",
    # `python3 bench/macro_method_usage.py` counts how often the prelude, std
    # and the port's own source call each macro method, and lists the hosted
    # compiler's macro methods by the type that defines them. Its count is
    # the order the macro port is filled in, recorded in
    # src/compiler/macros/PORT_STATUS.md, which says to regenerate from it.
    "macro_method_usage.py",
    # `bash bench/selfhost_semantic_calls_census.sh` asks the port's call
    # lookup every call site the hosted pass typed in the compiler's own
    # source and the prelude, and prints how many answers are identical and
    # the ranked reasons for the rest: the order the call lookup is filled
    # in. It takes minutes per file and has no floor; the gate beside it,
    # `selfhost_semantic_calls_exercise.sh`, is what a job runs.
    "selfhost_semantic_calls_census.sh",
    # `bash bench/selfhost_semantic_new_census.sh` asks the port for every
    # `new` call the hosted pass typed in the compiler's own source and the
    # prelude, holds each file's identical count against
    # bench/selfhost_semantic_new.floor, and ranks the misses by reason: the
    # order `new` is filled in. It builds an oracle and analyses every file
    # of the compiler and the prelude, one process each; the gate beside it,
    # `selfhost_semantic_new_exercise.sh`, is what a job runs.
    "selfhost_semantic_new_census.sh",
    # The judge of the typed pipeline. `bash bench/pipeline_judge.sh` builds
    # the hosted IR and the port's tool from one commit and prints, for
    # samples/iyi/hello.iyi and the compiler's own root, how many functions
    # the hosted compiler defines that the port lowers clean under the same
    # name; the three scripts under it print that line
    # (`pipeline_coverage.py`), the refusals ranked by the hosted functions
    # hidden behind each (`pipeline_frontier.py`) and the missing names by
    # owner (`pipeline_breakdown.py`). It is a measurement that orders the
    # work, read in src/compiler/PIPELINE.md, not a pass or a fail, and the
    # compiler's root takes the port's tool minutes and gigabytes; the gate
    # beside it, `selfhost_pipeline_exercise.sh`, is what a job runs.
    "pipeline_judge.sh",
    "pipeline_coverage.py",
    "pipeline_frontier.py",
    "pipeline_breakdown.py",
    # The instruments: each measures seconds or megabytes with a release
    # compiler, and most against Go or the compatibility binary beside it,
    # which a shared runner can neither build nor time - the same binary
    # read 0.048 s and 0.109 s minutes apart on one. SPEC.md and the README
    # quote what they print, and `measured_numbers.py`, in the docs job,
    # holds those quotes to the rows, columns and parameters the instrument
    # still produces; it lists each, with what it needs, in UNCHECKABLE.
    # Run by hand.
    "alloc_scaling.py",
    "artifact_speed.py",
    "bind_speed.py",
    "build_speed.py",
    "daemon_full_build.py",
    "edit_loop.py",
    "gc_default.py",
    "incremental.py",
    "macro_cost.py",
    "resident_probe.py",
    "runtime.py",
    "web_cores.py",
}

# A command's place in a line: its start, after `;`, `&&`, `|`, `$(`, a
# backtick, `{`, `run:`, a shell keyword or `!`, past `VAR=value` and a
# `timeout 60`-like prefix. A word anywhere else is prose.
COMMAND = (r"(?:^|[;&|(`{]|\$\(|\brun:|\b(?:do|then|else|elif|if|while|until)\b)\s*(?:!\s*)?"
           r"(?:[A-Za-z_]\w*=\S*\s+)*(?:(?:timeout|env|nice|command|exec|time)\s+(?:-\S+\s+)*(?:\d\S*\s+)?)*")
SH_RUNNER = (COMMAND + r"(?:bash|sh|python3?|pwsh|powershell|node|go|wasmtime|source|\.|"
             r"\"?\$\{?(?:PY|PYTHON|IYI|iyi|exe|python)\}?\"?|"
             r"(?:\S*[/\\])?iyi(?:\.exe|\.bat)?|&\s*\S+)(?=\s)")
PY_RUNNER = r"sys\.executable|subprocess|Popen|check_output|check_call|os\.system|runpy"

SH_BIND = re.compile(r"^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_]\w*)=(.*)$")
PY_BIND = re.compile(r"^\s*([A-Za-z_]\w*)\s*=(?!=)(.*)$")
FOR = re.compile(r"^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.*?)(?:;\s*do)?\s*$")
FOREACH = re.compile(r"foreach\s*\(\s*\$(\w+)\s+in\s+(.*)\)", re.I)
FUNCTION = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\)\s*\{?\s*$|^\s*function\s+([A-Za-z_][\w-]*)")


def names_in(line, names):
    """The files of *names* a line names, as the planner reads a name."""
    found = set()
    for prefix, written in ci_plan.FILE_NAME.findall(line):
        pattern = ci_plan.VARIABLE.sub("*", written)
        if not pattern.rsplit(".", 1)[0].strip("*") and not prefix:
            continue
        found.update(fnmatch.filter(names, pattern))
    return found


# A quoted text with a space in it is a message, and a command named inside
# one runs nothing: `echo "then bash bench/x.sh by hand"`. A quoted word -
# `"$PY"`, `"$REPO/bench/x.sh"` - is still a word of the command, and so is
# everything in a `$( )` inside quotes: `scan="$("$PY" bench/x.py)"` runs
# x.py. The quotes are paired left to right, as the shell pairs them: a
# pattern found `" "` between two quoted words and took it for a message.
def commands(line):
    """*line* with its messages blanked, for asking where a command is."""
    out = []
    held = []
    stack = []  # the open quotes and command substitutions, innermost last

    def close_text(closing):
        text = "".join(held)
        held.clear()
        out.append(("" if any(char.isspace() for char in text) else text) + closing)

    at = 0
    while at < len(line):
        char = line[at]
        inner = stack[-1] if stack else None
        if inner == "'":
            if char == "'":
                close_text("'")
                stack.pop()
            else:
                held.append(char)
        elif inner == '"':
            if char == "\\" and at + 1 < len(line):
                held.append(line[at:at + 2])
                at += 1
            elif char == '"':
                close_text('"')
                stack.pop()
            elif line.startswith("$(", at):
                close_text("$(")
                stack.append("(")
                at += 1
            else:
                held.append(char)
        elif char in "\"'":
            out.append(char)
            stack.append(char)
        elif line.startswith("$(", at):
            out.append("$(")
            stack.append("(")
            at += 1
        elif char == ")" and inner == "(":
            out.append(char)
            stack.pop()
        else:
            out.append(char)
        at += 1
    if stack and stack[-1] in "\"'":
        # Open at the end of the line: a quoted text that goes on to the next.
        close_text("")
    return "".join(out)


def runs(text, names, python=False):
    """The files of *names* that *text*'s code runs: named on a line that runs
    a command, or bound to a variable or a loop that such a line uses."""
    lines = ci_plan.code(text).splitlines()
    runner = re.compile(PY_RUNNER if python else SH_RUNNER + "|" + PY_RUNNER, re.I)
    if not python:
        # A function whose body runs something runs it when it is called.
        functions = set()
        current = None
        for line in lines:
            defined = FUNCTION.match(line)
            if defined:
                current = defined.group(1) or defined.group(2)
            elif current and runner.search(commands(line)):
                functions.add(current)
            if line.startswith("}"):
                current = None
        if functions:
            called = COMMAND + "(?:" + "|".join(map(re.escape, sorted(functions))) + r")\b"
            runner = re.compile(SH_RUNNER + "|" + PY_RUNNER + "|" + called, re.I)

    ran = set()
    bound = {}
    for line in lines:
        for binding in (FOR, FOREACH, PY_BIND if python else SH_BIND):
            found = binding.search(line)
            if found:
                bound.setdefault(found.group(1), set()).update(names_in(found.group(2), names))
        if runner.search(commands(line)):
            ran |= names_in(line, names)
    running = [line for line in lines if runner.search(commands(line))]
    for variable, files in bound.items():
        if not files:
            continue
        if python:
            used = re.compile(rf"\b{re.escape(variable)}\b")
        else:
            used = re.compile(rf"\$\{{?{re.escape(variable)}\b", re.I)
        if any(used.search(line) for line in running):
            ran |= files
    return ran


def reached(bench):
    """Every file under bench/ something runs, from the jobs and the
    Makefiles down through the scripts they run."""
    names = list(bench)
    jobs = ci_plan.parse_jobs(ci_plan.WORKFLOW.read_text(encoding="utf-8"))
    roots = set()
    for name, job in jobs.items():
        roots |= runs(job["text"], names)
    for makefile in ("Makefile", "Makefile.win"):
        path = ROOT / makefile
        if path.is_file():
            roots |= runs(path.read_text(encoding="utf-8", errors="ignore"), names)
    edges = {name: runs(text, names, name.endswith(".py")) - {name}
             for name, text in bench.items() if name.endswith(ci_plan.CALLER_SUFFIXES)}
    found = set(roots)
    pending = list(roots)
    while pending:
        for callee in edges.get(pending.pop(), ()):
            if callee not in found:
                found.add(callee)
                pending.append(callee)
    return found


def main():
    bench = ci_plan.bench_texts()
    every = {name for name in bench if name.endswith((".sh", ".py", ".iyi"))}
    run = reached(bench) & every
    unreached = sorted(every - run)
    # A gate named `*.wip.sh` does not pass yet: the slice that owns it renames it
    # to `*_exercise.sh` when it does, and a job's glob runs it from then on.
    unexplained = [name for name in unreached if name not in TOOLS and ".wip." not in name]

    print(f"{len(every)} scripts and programs under bench/, {len(run)} of them run")
    for name in unreached:
        why = "a tool, not a gate" if name in TOOLS else ("a gate that does not pass yet" if ".wip." in name else "RUN BY NOTHING")
        print(f"  {name:34s} {why}")

    missing_tools = sorted(TOOLS - every)
    if missing_tools:
        print()
        print("TOOLS names a file that is not there: " + ", ".join(missing_tools))
        print("Remove it from the list, in the same commit as the file.")
        return 1

    named_tools = sorted(TOOLS & run)
    if named_tools:
        print()
        print("TOOLS names a file something runs: " + ", ".join(named_tools))
        print("It is a gate then, so take it off the list — the list is for")
        print("files nothing runs, and an entry that is run hides the next one.")
        return 1

    if unexplained:
        print()
        print("A gate nothing runs passes on the machine that wrote it:")
        for name in unexplained:
            print(f"    bench/{name}")
        print()
        print("Run it in a workflow job — the job whose platform the gate is")
        print("about — or, if it is a tool rather than a gate, add it to TOOLS")
        print("in this script with what its answer is for, in the same commit.")
        return 1

    print()
    print("every gate under bench/ is run by something that runs it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
