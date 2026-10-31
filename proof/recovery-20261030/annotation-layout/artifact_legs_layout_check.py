"""Static, compile-only check for the artifact_legs signature-layout repair.

Usage (venv python, from any cwd):
  python3 -B -I artifact_legs_layout_check.py ROOT BASE_REV [CAND_REV]
      Compare CAND_REV (default HEAD) of the repo at ROOT against BASE_REV.
      Exit 0 only when every check passes.
  python3 -B -I artifact_legs_layout_check.py --self-test ROOT BASE_REV
      Build candidate variants in memory from BASE_REV and prove each check
      passes on the intended repair and fails, alone, on its own mutant.

Never imports or executes proof modules and never writes files. Sources are
read with `git show REV:path`, so the working tree state does not matter.

Checks:
  C1  no line in the four covered modules has bytecode only inside a
      PEP 649/749 `__annotate__` code object (trace counts such lines as
      executable, and nothing in proof/ ever calls `__annotate__`);
  C2  proof/artifact_legs.py parses to the same AST as BASE (layout-only);
  C3  ALLOWLIST keeps exactly the BASE entries, except that the artifact_legs
      entry's first/last equal the candidate's top-level __main__ guard span;
  C4  proof/smoke_test.py parses to the same AST as BASE once the ALLOWLIST
      value is blanked;
  C5  proofkit.py, run_proof.py and roundtrip_shim.py are byte-identical to BASE.
"""

import ast
import dis
import subprocess
import sys
import types

COVERED = ("proofkit", "run_proof", "artifact_legs", "roundtrip_shim")
UNCHANGED = ("proofkit", "run_proof", "roundtrip_shim")
LEGS = "proof.artifact_legs"


def git_show(root, rev, path):
    return subprocess.run(
        ["git", "-C", root, "show", f"{rev}:{path}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def load(root, rev):
    sources = {name: git_show(root, rev, f"proof/{name}.py") for name in COVERED}
    sources["smoke_test"] = git_show(root, rev, "proof/smoke_test.py")
    return sources


def walk(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from walk(const)


def annotate_only(source, label):
    owners = {}
    for item in walk(compile(source, label, "exec")):
        for _offset, lineno in dis.findlinestarts(item):
            if lineno is not None:
                owners.setdefault(lineno, set()).add(item.co_name)
    return sorted(line for line, names in owners.items() if names == {"__annotate__"})


def main_guard_span(source):
    spans = []
    for node in ast.parse(source).body:
        test = getattr(node, "test", None)
        if (
            isinstance(node, ast.If)
            and isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
        ):
            spans.append((node.lineno, node.end_lineno))
    if len(spans) != 1:
        raise ValueError(f"expected one top-level __main__ guard, found {spans}")
    return spans[0]


def allowlist_node(tree):
    found = [
        node
        for node in tree.body
        if isinstance(node, (ast.AnnAssign, ast.Assign))
        and any(
            isinstance(target, ast.Name) and target.id == "ALLOWLIST"
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
    ]
    if len(found) != 1:
        raise ValueError(f"expected one ALLOWLIST assignment, found {len(found)}")
    return found[0]


def allowlist(source):
    return ast.literal_eval(allowlist_node(ast.parse(source)).value)


def blanked_dump(source):
    tree = ast.parse(source)
    allowlist_node(tree).value = ast.Constant(value=None)
    return ast.dump(tree)


def check(base, cand):
    failures = {}
    annotate = {
        name: annotate_only(cand[name], f"proof/{name}.py") for name in COVERED
    }
    if any(annotate.values()):
        failures["C1"] = {name: lines for name, lines in annotate.items() if lines}
    if ast.dump(ast.parse(base["artifact_legs"])) != ast.dump(ast.parse(cand["artifact_legs"])):
        failures["C2"] = "artifact_legs AST differs from BASE"
    base_entries = allowlist(base["smoke_test"])
    cand_entries = allowlist(cand["smoke_test"])
    span = main_guard_span(cand["artifact_legs"])
    expected_entries = tuple(
        (entry[0], span[0], span[1], entry[3], entry[4]) if entry[0] == LEGS else entry
        for entry in base_entries
    )
    if len(base_entries) != 7 or sum(entry[0] == LEGS for entry in base_entries) != 1:
        failures["C3"] = f"BASE ALLOWLIST shape unexpected: {len(base_entries)} entries"
    elif cand_entries != expected_entries:
        failures["C3"] = {
            "candidate_legs_entry": [entry[:3] for entry in cand_entries if entry[0] == LEGS],
            "guard_span": span,
            "same_count": len(cand_entries) == len(base_entries),
        }
    if blanked_dump(base["smoke_test"]) != blanked_dump(cand["smoke_test"]):
        failures["C4"] = "smoke_test AST differs from BASE outside the ALLOWLIST value"
    changed = [name for name in UNCHANGED if base[name] != cand[name]]
    if changed:
        failures["C5"] = changed
    return failures


KW_LINES = (
    "    build_timeout: float = BUILD_TIMEOUT,\n"
    "    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,\n"
    "    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,\n"
    "    disk_min_gb: float = DISK_MIN_GB,\n"
)
KW = (
    "build_timeout: float = BUILD_TIMEOUT, run_default_timeout: float = RUN_DEFAULT_TIMEOUT, "
    "run_heavy_timeout: float = RUN_HEAVY_TIMEOUT, disk_min_gb: float = DISK_MIN_GB"
)
ROW_LINES = (
    "    source: str,\n    *,\n    repo: str,\n    compiler: str,\n"
    "    work_root: str,\n    nm_bin: str,\n"
)
ROW = "source: str, *, repo: str, compiler: str, work_root: str, nm_bin: str, "
SIGNATURES = {
    "run_timeout_for": (
        "def run_timeout_for(\n    relpath: str,\n    *,\n"
        "    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,\n"
        "    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,\n) -> float:\n",
        "def run_timeout_for(relpath: str, *, run_default_timeout: float = RUN_DEFAULT_TIMEOUT, "
        "run_heavy_timeout: float = RUN_HEAVY_TIMEOUT) -> float:\n",
    ),
    "_run_row": (
        "def _run_row(\n" + ROW_LINES + KW_LINES + ") -> dict:\n",
        "def _run_row(" + ROW + KW + ") -> dict:\n",
    ),
    "run_row": (
        "def run_row(\n" + ROW_LINES + KW_LINES + ") -> dict:\n",
        "def run_row(" + ROW + KW + ") -> dict:\n",
    ),
    "run_rows": (
        "def run_rows(\n    sources: Sequence[str],\n    *,\n    repo: str,\n    compiler: str,\n"
        "    work_root: str,\n    nm_bin: str,\n    workers: int,\n" + KW_LINES + ") -> list[dict]:\n",
        "def run_rows(sources: Sequence[str], *, repo: str, compiler: str, work_root: str, "
        "nm_bin: str, workers: int, " + KW + ") -> list[dict]:\n",
    ),
    "main": (
        "def main(\n    argv: Sequence[str] | None = None,\n    *,\n" + KW_LINES + ") -> int:\n",
        "def main(argv: Sequence[str] | None = None, *, " + KW + ") -> int:\n",
    ),
}


def replace_once(text, before, after):
    count = text.count(before)
    if count != 1:
        raise ValueError(f"anchor matched {count} times: {before.splitlines()[0]!r}")
    return text.replace(before, after)


def collapse(legs, names):
    for name in names:
        legs = replace_once(legs, *SIGNATURES[name])
    return legs


def renumber(smoke, legs):
    first, last = main_guard_span(legs)
    return replace_once(
        smoke,
        '        "proof.artifact_legs",\n        857,\n        858,\n',
        f'        "proof.artifact_legs",\n        {first},\n        {last},\n',
    )


def self_test(root, base_rev):
    base = load(root, base_rev)
    fixed_legs = collapse(base["artifact_legs"], SIGNATURES)
    all_but_main = collapse(base["artifact_legs"], [name for name in SIGNATURES if name != "main"])
    swapped = replace_once(
        fixed_legs,
        "    return run_heavy_timeout if relpath in HEAVY else run_default_timeout\n",
        "    return run_default_timeout if relpath in HEAVY else run_heavy_timeout\n",
    )
    variants = {
        "repair": ({"artifact_legs": fixed_legs, "smoke_test": renumber(base["smoke_test"], fixed_legs)}, set()),
        "unfixed-base": ({}, {"C1"}),
        "stale-allowlist": ({"artifact_legs": fixed_legs}, {"C3"}),
        "one-signature-left-wrapped": (
            {"artifact_legs": all_but_main, "smoke_test": renumber(base["smoke_test"], all_but_main)},
            {"C1"},
        ),
        "semantic-edit": (
            {"artifact_legs": swapped, "smoke_test": renumber(base["smoke_test"], swapped)},
            {"C2"},
        ),
        "extra-smoke-edit": (
            {
                "artifact_legs": fixed_legs,
                "smoke_test": replace_once(
                    renumber(base["smoke_test"], fixed_legs),
                    'prefix="iyi-o6-heavy-timeout-"',
                    'prefix="iyi-o6-heavy-timeout-x"',
                ),
            },
            {"C4"},
        ),
        "other-module-edit": (
            {
                "artifact_legs": fixed_legs,
                "smoke_test": renumber(base["smoke_test"], fixed_legs),
                "proofkit": base["proofkit"] + "\n",
            },
            {"C5"},
        ),
    }
    mismatches = 0
    for name, (overrides, expected) in variants.items():
        candidate = dict(base)
        candidate.update(overrides)
        failures = check(base, candidate)
        got = set(failures)
        status = "ok" if got == expected else "MISMATCH"
        mismatches += got != expected
        print(f"SELFTEST {name} expected={sorted(expected)} got={sorted(got)} {status}")
        if name == "repair":
            print(f"SELFTEST repair guard_span={main_guard_span(fixed_legs)} lines={len(fixed_legs.splitlines())}")
        if name == "unfixed-base":
            print(f"SELFTEST unfixed-base C1={failures.get('C1')}")
    print("SELFTEST PASS" if mismatches == 0 else f"SELFTEST FAIL mismatches={mismatches}")
    return 0 if mismatches == 0 else 1


def main(argv):
    if argv[:1] == ["--self-test"] and len(argv) == 3:
        return self_test(argv[1], argv[2])
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    root, base_rev = argv[0], argv[1]
    cand_rev = argv[2] if len(argv) == 3 else "HEAD"
    failures = check(load(root, base_rev), load(root, cand_rev))
    for key in ("C1", "C2", "C3", "C4", "C5"):
        print(f"CHECK {key} {'FAIL ' + repr(failures[key]) if key in failures else 'PASS'}")
    print(f"LAYOUT CHECK {'FAIL' if failures else 'PASS'} base={base_rev} candidate={cand_rev}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
