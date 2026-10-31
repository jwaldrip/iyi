"""Compile-only counterfactual for the artifact_legs signature layout.

Never imports or executes proof modules and never writes files. Compares:
  * 3ef292791 (pre-wrap layout), read with `git show`;
  * H (current W2 file);
  * the proposed single-line layout, built in memory from H.
"""

import ast
import dis
import subprocess
import trace
import types

W2 = "/Users/jwaldrip/dev/worktrees/iyi-audit-deadlines-seams-20261030"
PATH = f"{W2}/proof/artifact_legs.py"

KW = (
    "build_timeout: float = BUILD_TIMEOUT, "
    "run_default_timeout: float = RUN_DEFAULT_TIMEOUT, "
    "run_heavy_timeout: float = RUN_HEAVY_TIMEOUT, "
    "disk_min_gb: float = DISK_MIN_GB"
)
KW_LINES = (
    "    build_timeout: float = BUILD_TIMEOUT,\n"
    "    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,\n"
    "    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,\n"
    "    disk_min_gb: float = DISK_MIN_GB,\n"
)
ROW_PARAMS = (
    "    source: str,\n"
    "    *,\n"
    "    repo: str,\n"
    "    compiler: str,\n"
    "    work_root: str,\n"
    "    nm_bin: str,\n"
)
REPLACEMENTS = (
    (
        "def run_timeout_for(\n"
        "    relpath: str,\n"
        "    *,\n"
        "    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,\n"
        "    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,\n"
        ") -> float:\n",
        "def run_timeout_for(relpath: str, *, run_default_timeout: float = RUN_DEFAULT_TIMEOUT, "
        "run_heavy_timeout: float = RUN_HEAVY_TIMEOUT) -> float:\n",
    ),
    (
        "def _run_row(\n" + ROW_PARAMS + KW_LINES + ") -> dict:\n",
        "def _run_row(source: str, *, repo: str, compiler: str, work_root: str, nm_bin: str, "
        + KW + ") -> dict:\n",
    ),
    (
        "def run_row(\n" + ROW_PARAMS + KW_LINES + ") -> dict:\n",
        "def run_row(source: str, *, repo: str, compiler: str, work_root: str, nm_bin: str, "
        + KW + ") -> dict:\n",
    ),
    (
        "def run_rows(\n"
        "    sources: Sequence[str],\n"
        "    *,\n"
        "    repo: str,\n"
        "    compiler: str,\n"
        "    work_root: str,\n"
        "    nm_bin: str,\n"
        "    workers: int,\n" + KW_LINES + ") -> list[dict]:\n",
        "def run_rows(sources: Sequence[str], *, repo: str, compiler: str, work_root: str, "
        "nm_bin: str, workers: int, " + KW + ") -> list[dict]:\n",
    ),
    (
        "def main(\n"
        "    argv: Sequence[str] | None = None,\n"
        "    *,\n" + KW_LINES + ") -> int:\n",
        "def main(argv: Sequence[str] | None = None, *, " + KW + ") -> int:\n",
    ),
)


def walk(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from walk(const)


def annotate_only(source, label):
    code = compile(source, label, "exec")
    owners = {}
    for item in walk(code):
        for _offset, lineno in dis.findlinestarts(item):
            if lineno is not None:
                owners.setdefault(lineno, set()).add(item.co_name)
    return sorted(line for line, names in owners.items() if names == {"__annotate__"}), len(owners)


def report(label, source):
    only, executable = annotate_only(source, label)
    lines = source.splitlines()
    guard = [i for i, line in enumerate(lines, 1) if line == 'if __name__ == "__main__":']
    print(
        f"[{label}] lines={len(lines)} executable_linestarts={executable} "
        f"annotate_only={only} main_guard={guard} "
        f"guard_body={lines[guard[0]] if guard else None!r} "
        f"longest={max(len(line) for line in lines)}"
    )


with open(PATH, encoding="utf-8") as handle:
    current = handle.read()
old = subprocess.run(
    ["git", "-C", W2, "show", "3ef292791:proof/artifact_legs.py"],
    check=True,
    capture_output=True,
    text=True,
).stdout

proposed = current
for before, after in REPLACEMENTS:
    count = proposed.count(before)
    assert count == 1, (before.splitlines()[0], count)
    proposed = proposed.replace(before, after)

report("3ef292791", old)
report("H-451420109", current)
report("proposed", proposed)
print("ast_equal_H_vs_proposed", ast.dump(ast.parse(current)) == ast.dump(ast.parse(proposed)))
print("trace_executable_H", len(trace._find_executable_linenos(PATH)))
for index, line in enumerate(proposed.splitlines(), 1):
    if line.startswith("def ") and any(
        line.startswith(f"def {name}(")
        for name in ("run_timeout_for", "_run_row", "run_row", "run_rows", "main")
    ):
        print("proposed_def", index, len(line), line[:60])
