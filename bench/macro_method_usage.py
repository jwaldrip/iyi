#!/usr/bin/env python3
"""Counts how often the prelude, std and the port's own source call each macro
method inside {% %} and {{ }}, and lists the hosted compiler's macro methods by
the AST type they are defined on.

The hosted compiler defines its macro methods in src/compiler/iyi/macros/methods.cr
as `class <Type>` blocks holding `def <name>` lines. The count is what sets the
order in which the macro port fills in methods: most used first.

    python3 bench/macro_method_usage.py            # table, most used first
    python3 bench/macro_method_usage.py --names    # bare method names, one per line
    python3 bench/macro_method_usage.py --status   # table with the port's status (PORT_STATUS.md)
"""
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HOSTED = os.path.join(REPO, "src/compiler/iyi/macros/methods.cr")
ROOTS = [
    os.path.join(REPO, "src/iyi"),
    os.path.join(REPO, "src/std"),
    os.path.join(REPO, "src/compiler"),
]
MACRO_BLOCK = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
CLASS_LINE = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)")
WHEN_LINE = re.compile(r"^\s*when\s+(.*)$")
QUOTED = re.compile(r'"([^"\n]+)"')
# Hosted plumbing that dispatches but is not a macro method a template can call.
PLUMBING = {"interpret", "interpret_compare", "to_macro_id", "truthy?", "to_string", "interpret_check_args"}
# Words that are macro-language keywords or hosted helpers, never macro methods.
NOT_METHODS = {"flag?", "host_flag?", "skip_file", "system", "run", "env", "raise",
               "debug", "puts", "p", "pp", "print"}


def hosted_methods():
    """Return {type name: [method names]} from the hosted methods.cr.

    A macro method is a quoted name on a `when` line of a type's `interpret`
    dispatch. Lines outside a type's `class` block, and names that are plumbing
    rather than macro methods, are not counted.
    """
    table = {}
    current = None
    with open(HOSTED, encoding="utf-8") as f:
        for line in f:
            m = CLASS_LINE.match(line)
            if m and line.startswith("  class "):
                current = m.group(1)
                table.setdefault(current, [])
                continue
            if line.startswith("  end"):
                current = None
                continue
            if current is None:
                continue
            w = WHEN_LINE.match(line)
            if not w:
                continue
            for name in QUOTED.findall(w.group(1)):
                if name in PLUMBING or name in table[current]:
                    continue
                table[current].append(name)
    return table


def macro_sources():
    """The prelude and std (.iyi and .cr), and the port's own source (.iyi only:
    the hosted compiler under src/compiler/iyi is the oracle, not a caller)."""
    for root in ROOTS:
        for dirpath, _, files in os.walk(root):
            if os.sep + "compiler" + os.sep + "iyi" in dirpath + os.sep:
                continue
            for name in files:
                exts = (".iyi",) if root.endswith("compiler") else (".iyi", ".cr")
                if name.endswith(exts):
                    yield os.path.join(dirpath, name)


def port_names():
    """Names the port's macro dispatch answers, from its `when "name"` lines."""
    names = set()
    port_dir = os.path.join(REPO, "src/compiler/macros")
    for name in os.listdir(port_dir):
        if not name.endswith(".iyi"):
            continue
        with open(os.path.join(port_dir, name), encoding="utf-8") as f:
            for line in f:
                w = WHEN_LINE.match(line)
                if w:
                    names.update(QUOTED.findall(w.group(1)))
    return names


def usage_counts(names):
    counts = {n: 0 for n in names}
    pats = {n: re.compile(r"\.(?:" + re.escape(n) + r")(?![A-Za-z0-9_?!])") for n in names}
    for path in macro_sources():
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        for block in MACRO_BLOCK.findall(text):
            for n, pat in pats.items():
                counts[n] += len(pat.findall(block))
    return counts


def main():
    table = hosted_methods()
    types_of = {}
    for typ, ms in table.items():
        for n in ms:
            types_of.setdefault(n, []).append(typ)
    counts = usage_counts(sorted(types_of))
    if "--names" in sys.argv:
        for n in sorted(types_of, key=lambda n: (-counts[n], n)):
            if counts[n] > 0:
                print(n)
        return
    if "--status" in sys.argv:
        port = port_names()
        print("| uses | method | hosted on | port |")
        print("|---:|---|---|---|")
        for n in sorted(types_of, key=lambda n: (-counts[n], n)):
            status = "named" if n in port else "not yet"
            print(f"| {counts[n]} | `{n}` | {', '.join(sorted(types_of[n]))} | {status} |")
        return
    print("| uses | method | hosted on |")
    print("|---:|---|---|")
    for n in sorted(types_of, key=lambda n: (-counts[n], n)):
        print(f"| {counts[n]} | `{n}` | {', '.join(sorted(types_of[n]))} |")


if __name__ == "__main__":
    main()
