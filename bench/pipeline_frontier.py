#!/usr/bin/env python3
# The worklist behind the coverage line (SPEC 2.1, S3): which refusals stop the port from lowering the hosted functions,
# and how many hosted functions each one hides. Read after bench/pipeline_coverage.py on the same output.
#
#   python3 bench/pipeline_frontier.py <hosted.ll> <port.names> <port.refusals> <root> [top N]
#
# <hosted.ll> is the hosted compiler's IR for the root (`./bin/iyi build --no-debug --emit llvm-ir -o <dir>/hosted <root>`).
# <port.names> is the tool's `<output>.names` under --keep-going; <port.refusals> its `<output>.refusals` sidecar: one
# tab-separated line per refused site or reached def, `<phase>\t<def label>\t<slice owner>\t<reason first line>`.
#
# Prints, all prefixed `breakdown:` or `frontier:` with the root:
#   breakdown: the missing names (hosted, not clean in the port) by cause, then by owner, three examples each.
#   frontier: the status of each missing name (refused, name-differs, not-reached); then the refusals ranked by the
#     hosted functions behind them: a function the port never reached is credited to the nearest refused caller (walking
#     up the hosted call graph) with that caller's first refusal reason. A clean caller that never asked for the callee is
#     listed apart. Counts are not exclusive; read the ranking, not the sum.
import collections
import re
import sys

DEFINE = re.compile(r'^define\b[^@]*@("(?:[^"\\]|\\.)*"|[^\s(]+)')
FILE_PREFIX = re.compile(r'^\*(?:/[^:]*\.iyi)::')
CALL = re.compile(r'(?:call|invoke)\b[^@\n]*@("(?:[^"\\]|\\.)*"|[^\s(,]+)\(')

# The slice word the tool writes (typed_owner in lower/program.iyi) -> the live agent that owns it (OWNERS.md).
SLICE_OWNER = {
    "bodies": "agent://S1d15Bodies",
    "declarations": "agent://S1b19Declarations",
    "calls": "agent://S1c10Calls",
    "macros": "agent://S1bInlineMacros12",
    "lowering core": "agent://S2a14Core",
    "lowering": "agent://S2a14Core",
    "unassigned": "unassigned (no rule in typed_owner)",
}
STRUCTURAL = {
    "entry": "agent://S3lPipeline (program assembly)",
    "proc": "agent://S2a14Core (closures)",
    "const": "globals lane (no live owner)",
    "generic": "agent://S2a14Core (mangled_name: ^Generic(T) segment)",
    "shim": "agent://S2a14Core (runtime shims)",
}


def norm(name):
    """A hosted function name without its quotes, with the file part of a top-level def dropped."""
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return FILE_PREFIX.sub("*", name)


def hosted_defines(path):
    """The hosted functions the IR defines, and the call edges between them: (names, callers-of)."""
    defined = []
    graph = collections.defaultdict(set)
    current = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("define"):
                m = DEFINE.match(line)
                current = norm(m.group(1)) if m else None
                if current:
                    defined.append(current)
            elif line.startswith("}"):
                current = None
            elif current and ("call" in line or "invoke" in line):
                for m in CALL.finditer(line):
                    graph[current].add(norm(m.group(1)))
    return set(defined), graph


def hosted_names(path):
    names, _graph = hosted_defines(path)
    return names


def port_names(path):
    with open(path, encoding="utf-8") as f:
        return {line.rstrip("\n") for line in f if line.strip()}


def cause_of(name):
    bare = name.lstrip("*")
    if bare in ("__crystal_main", "__iyi_main", "main") or bare.endswith("::__iyi_main"):
        return "entry"
    if "~proc" in name:
        return "proc"
    if "const_init" in name or name.startswith("*~"):
        return "const"
    if "^" in name:
        return "generic"
    if re.search(r"(^|::|\*)__iyi_|(^|::)(memcpy|memmove|memset|bzero)$", name):
        return "shim"
    return "method"


def label_of(name):
    """A hosted name to the table's def label: `*Owner(args)^Gen#meth<Args>:Ret` -> `Owner(args)#meth`;
    `*Point::new<Args>:Ret` -> `Point.class#new`; a top-level `*name<Args>:Ret` -> `name`."""
    s = name.lstrip("*")
    m = re.search(r"(?<!:):(?!:)[^:]*$", s)  # the return type: the last single colon
    if m:
        s = s[:m.start()]
    m = re.search(r"<[^<>]*>$", s)  # the argument list
    if m:
        s = s[:m.start()]
    if "#" in s:
        owner, meth = s.split("#", 1)
        owner = owner.split("^", 1)[0]
        return f"{owner}#{meth}"
    if "::" in s:
        owner, meth = s.rsplit("::", 1)
        return f"{owner}.class#{meth}"
    return s


def load_refusals(path):
    """Refusal owners by def label, the reached def labels, and every refusal reason by label (owner, reason)."""
    by_label = collections.defaultdict(collections.Counter)
    reached = set()
    full = collections.defaultdict(list)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            phase, label, owner, reason = parts[0], parts[1], parts[2], parts[3]
            if phase == "reached":
                reached.add(label)
                continue
            by_label[label][owner] += 1
            if owner != "-":
                full[label].append((owner, reason))
    return by_label, reached, full


def breakdown(root, hosted, port, by_label, reached):
    missing = sorted(hosted - port)
    causes = collections.Counter()
    owners = collections.defaultdict(list)
    counts = collections.Counter()
    for name in missing:
        cause = cause_of(name)
        causes[cause] += 1
        if cause in STRUCTURAL:
            owner = STRUCTURAL[cause]
        else:
            label = label_of(name)
            hits = by_label.get(label)
            if hits:
                word = hits.most_common(1)[0][0]
                owner = SLICE_OWNER.get(word, f"slice {word}")
            elif label in reached:
                owner = "reached, no refusal, lowered under another name (naming or clean)"
            else:
                owner = "not reached by the port (no instance under this def label)"
        counts[owner] += 1
        owners[owner].append(name)
    print(f"breakdown: {root} hosted={len(hosted)} port-clean={len(port)} missing={len(missing)}")
    print(f"breakdown: {root} by name shape (the hosted name's form, not a naming defect): " + ", ".join(f"{c} {n}" for c, n in causes.most_common()))
    for owner, n in counts.most_common():
        print(f"breakdown: {root} {n:6d} {owner}")
        for ex in owners[owner][:3]:
            print(f"breakdown: {root}        e.g. {ex}")


def statuses(dset, clean, by_label, reached):
    """Each missing hosted function's status: refused (its label has a refusal), name-differs (the port lowered its label under another name) or not-reached."""
    status = {}
    for n in dset - clean:
        lab = label_of(n)
        status[n] = "refused" if lab in by_label else ("name-differs" if lab in reached else "not-reached")
    return status


def status_line(root, dset, clean, status):
    count = collections.Counter(status.values())
    return (f"frontier: {root} hosted={len(dset)} clean={len(clean)} missing={len(status)} refused={count['refused']} "
            f"name-differs={count['name-differs']} not-reached={count['not-reached']}")


def frontier(root, hosted_ll, names_path, refusals_path, topn):
    dset, graph = hosted_defines(hosted_ll)
    clean = hosted_names(hosted_ll) & port_names(names_path)
    by_label, reached, full = load_refusals(refusals_path)
    missing = dset - clean
    status = statuses(dset, clean, by_label, reached)
    print(status_line(root, dset, clean, status))
    callers = collections.defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            if callee in dset:
                callers[callee].add(caller)
    blame = collections.Counter()
    orphan = 0
    for n in missing:
        if status[n] != "not-reached":
            continue
        seen = {n}
        front = [n]
        found = set()
        while front and not found:
            nxt = []
            for x in front:
                for cl in callers.get(x, ()):
                    if cl in seen:
                        continue
                    seen.add(cl)
                    if cl in missing and status[cl] == "refused":
                        found.add(cl)
                    elif cl in clean:
                        found.add(("CLEAN", cl))
                    else:
                        nxt.append(cl)
            front = nxt
        if not found:
            orphan += 1
        for cl in found:
            blame[cl] += 1
    print(f"frontier: {root} not-reached with no reached caller in the hosted call graph "
          f"(entry points, calls through pointers): {orphan}")
    reason = collections.Counter()
    example = {}
    for cl, k in blame.items():
        if isinstance(cl, tuple):
            continue
        owner, why = (full.get(label_of(cl)) or [("?", "?")])[0]
        reason[(owner, why)] += k
        example.setdefault((owner, why), cl)
    print(f"frontier: {root} refusals ranked by the hosted functions behind them")
    for (owner, why), k in reason.most_common(topn):
        print(f"frontier: {root} {k:6d} owner={owner} reason={why[:140]} example={example[(owner, why)][:120]}")
    clean_callers = sorted(((k, x[1]) for x, k in blame.items() if isinstance(x, tuple)), reverse=True)
    print(f"frontier: {root} clean callers that never asked for a hosted callee: {len(clean_callers)}")
    for k, x in clean_callers[:10]:
        print(f"frontier: {root} {k:6d} clean-caller={x[:140]}")


def main(argv):
    if len(argv) < 5:
        print(__doc__)
        return 2
    hosted_ll, names_path, refusals_path, root = argv[1:5]
    topn = int(argv[5]) if len(argv) > 5 else 12
    hosted = hosted_names(hosted_ll)
    port = port_names(names_path)
    by_label, reached, _full = load_refusals(refusals_path)
    breakdown(root, hosted, port, by_label, reached)
    frontier(root, hosted_ll, names_path, refusals_path, topn)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
