#!/usr/bin/env python3
"""Compares the own-source lowering blocks of the hosted oracle and the port, type by type.

  lower_types_compare.py <oracle output> <port output>

Each output holds one block per type a file declares, opened by a `== <name>` line (see
bench/selfhost_lower_types_oracle.cr, `own_text`). The script prints one line:

  declared identical oracle_failed missing differs

A type is identical when the port prints the same block. A type the oracle could not lower (its
block is an `ERROR:` line) is counted as oracle_failed, not as a difference: the hosted side has no
answer to compare with. A type the port did not print is missing. Anything else differs.

Then one `REASON <count> <text>` line for each reason a type differs, ranked by count: the first
field whose line differs (or `block` when the blocks differ before any field), and for the
oracle-failed types the first line of the hosted error. The gate prints these as the ranked list.
"""
import sys


def blocks(path):
    order = []
    found = {}
    name = None
    buf = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("== "):
                if name is not None:
                    found[name] = "".join(buf)
                name = line[3:].rstrip("\n")
                order.append(name)
                buf = [line]
            elif name is not None:
                buf.append(line)
    if name is not None:
        found[name] = "".join(buf)
    return order, found


def first_difference(a, b):
    """The field name of the first line that differs, or `block` when the lines match in order."""
    al = a.split("\n")
    bl = b.split("\n")
    for i in range(max(len(al), len(bl))):
        x = al[i] if i < len(al) else "<end>"
        y = bl[i] if i < len(bl) else "<end>"
        if x != y:
            field = x.split(":", 1)[0] if ":" in x else "block"
            return field
    return "block"


def main():
    oracle_order, oracle = blocks(sys.argv[1])
    _, port = blocks(sys.argv[2])
    declared = len(oracle_order)
    identical = failed = missing = differs = 0
    reasons = {}
    for name in oracle_order:
        ob = oracle[name]
        if "\nERROR: " in ob:
            failed += 1
            first = ob.split("\nERROR: ", 1)[1].split("\n", 1)[0]
            key = "oracle: " + first[:120]
            reasons[key] = reasons.get(key, 0) + 1
            continue
        if name not in port:
            missing += 1
            reasons["port: no block"] = reasons.get("port: no block", 0) + 1
            continue
        if port[name] == ob:
            identical += 1
        else:
            differs += 1
            key = "differs in " + first_difference(ob, port[name])
            reasons[key] = reasons.get(key, 0) + 1
    print(declared, identical, failed, missing, differs)
    for key, count in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0])):
        print("REASON", count, key)


if __name__ == "__main__":
    main()
