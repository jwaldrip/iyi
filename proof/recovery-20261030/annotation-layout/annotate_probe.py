"""Compile-only probe: which trace-executable lines live only in __annotate__ code.

Never imports or executes the probed modules. Reads source, compiles it, walks
code objects, and compares against trace._find_executable_linenos and the
annotated .cover listings from the parent's coverage run.
"""

import dis
import os
import sys
import trace
import types

W2 = "/Users/jwaldrip/dev/worktrees/iyi-audit-deadlines-seams-20261030"
COV = "/private/tmp/iyi-parent-evidence-451420109/cov"
MODULES = ("artifact_legs", "proofkit", "run_proof", "roundtrip_shim")


def walk(code, parents=()):
    yield code, parents
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from walk(const, parents + (code.co_name,))


def missed(module):
    path = os.path.join(COV, f"proof.{module}.cover")
    with open(path, encoding="utf-8") as handle:
        return {
            number
            for number, line in enumerate(handle.read().splitlines(), 1)
            if line.startswith(">>>>>>")
        }


print("python", sys.version.replace("\n", " "))
for module in MODULES:
    path = os.path.join(W2, "proof", f"{module}.py")
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    code = compile(source, path, "exec")
    owners = {}
    for item, _parents in walk(code):
        for _offset, lineno in dis.findlinestarts(item):
            if lineno is not None:
                owners.setdefault(lineno, set()).add(item.co_name)
    executable = set(trace._find_executable_linenos(path))
    annotate_only = {
        line for line, names in owners.items() if names == {"__annotate__"}
    }
    annotate_any = {line for line, names in owners.items() if "__annotate__" in names}
    misses = missed(module)
    annotate_codes = sum(1 for item, _ in walk(code) if item.co_name == "__annotate__")
    print(
        f"[{module}] executable={len(executable)} annotate_codes={annotate_codes} "
        f"annotate_only={sorted(annotate_only)}"
    )
    print(f"[{module}] misses={sorted(misses)}")
    print(f"[{module}] misses_annotate_only={sorted(misses & annotate_only)}")
    print(f"[{module}] misses_not_annotate_only={sorted(misses - annotate_only)}")
    print(f"[{module}] annotate_only_but_hit={sorted(annotate_only - misses)}")
    print(f"[{module}] annotate_only_subset_of_executable={annotate_only <= executable}")
    print(f"[{module}] annotate_any_count={len(annotate_any)}")

# Bytecode detail for one representative signature (module scope + its __annotate__).
path = os.path.join(W2, "proof", "artifact_legs.py")
with open(path, encoding="utf-8") as handle:
    code = compile(handle.read(), path, "exec")
print("--- module-scope instructions on lines 56..62")
for instruction in dis.get_instructions(code):
    lineno = instruction.positions.lineno if instruction.positions else None
    if lineno is not None and 56 <= lineno <= 62:
        print(lineno, instruction.opname, instruction.argrepr, "starts_line" if instruction.starts_line else "")
for item, parents in walk(code):
    if item.co_name == "__annotate__" and 56 <= item.co_firstlineno <= 62:
        print("--- __annotate__ for def at", item.co_firstlineno, "parents", parents)
        for instruction in dis.get_instructions(item):
            lineno = instruction.positions.lineno if instruction.positions else None
            print(lineno, instruction.opname, instruction.argrepr, "starts_line" if instruction.starts_line else "")
