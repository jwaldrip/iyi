#!/usr/bin/env python3
"""What a Crystal source tree needs to become iyi modules, counted by shape.

Textual, one pass, no compiler: the parts the compiler answers (R-2
signatures, ivar types) come from `crystal tool bind -e Root entry.cr`,
which classifies every public method as written / machine-writable /
needs a human; this counts the rest - the shapes a file-per-module
language has to do something about. Read beside SPEC.md III.6, "What a
migration would need, measured", where the counts of one 8,079-line
application are interpreted.

    python3 bench/migrate_count.py <src dir>
"""
import os, re, sys, collections

src = sys.argv[1]
files = sorted(os.path.join(d, f) for d, _, fs in os.walk(src) for f in fs if f.endswith(".cr"))

TYPE_RE = re.compile(r"^(\s*)(?:private\s+)?(?:abstract\s+)?(class|struct|module|enum|lib|annotation)\s+([A-Z][\w:]*)")
DEF_RE = re.compile(r"^(\s*)(?:private\s+|protected\s+)?def\s+(self\.)?([\w?!=<>+\-*/%\[\]]+)")
MACRO_RE = re.compile(r"^\s*macro\s+\w+")
INCLUDE_RE = re.compile(r"^\s*(include|extend)\s+[A-Z]")
IVAR_ASSIGN_RE = re.compile(r"^\s*@(\w+)\s*(?:\|\|)?=[^=]")
IVAR_DECL_RE = re.compile(r"^\s*@(\w+)\s*:\s*\S")
REQUIRE_RE = re.compile(r'^\s*require\s+"([^"]+)"')
DSL_RE = re.compile(r'^(get|post|put|patch|delete|options|head|ws|before_all|after_all|error)\s')
RESCUE_RE = re.compile(r"^\s*(rescue|raise)\b")
NOTNIL_RE = re.compile(r"\.not_nil!")

defined_in = collections.defaultdict(set)     # full type name -> files
opened_in = collections.defaultdict(list)     # full type name -> files (every opening)
per_file = {}
totals = collections.Counter()

for path in files:
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    totals["lines"] += len(lines)
    stack = []  # (indent, name)
    counts = collections.Counter()
    ivar_decl = collections.defaultdict(set)
    ivar_assign = collections.defaultdict(set)
    top_level_code = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        while stack and indent <= stack[-1][0] and re.match(r"^\s*end\b", line):
            stack.pop()
            break
        m = TYPE_RE.match(line)
        if m:
            name = m.group(3)
            full = "::".join([s[1] for s in stack] + [name]) if not name.startswith("::") else name
            # a nested name that already contains :: is absolute enough
            key = name if "::" in name else full
            opened_in[key].append(path)
            stack.append((indent, name))
            counts["type openings"] += 1
            continue
        if MACRO_RE.match(line):
            counts["macro definitions"] += 1
        if INCLUDE_RE.match(line) and stack:
            counts["include/extend in a type"] += 1
        m = REQUIRE_RE.match(line)
        if m:
            counts["require relative" if m.group(1).startswith(".") else "require shard/stdlib"] += 1
            continue
        if DEF_RE.match(line):
            counts["defs"] += 1
            if not stack:
                counts["top-level defs"] += 1
            continue
        d = IVAR_DECL_RE.match(line)
        if d and stack:
            ivar_decl[stack[-1][1]].add(d.group(1))
        a = IVAR_ASSIGN_RE.match(line)
        if a and stack:
            ivar_assign[stack[-1][1]].add(a.group(1))
        if RESCUE_RE.match(line):
            counts["rescue/raise lines"] += 1
        if NOTNIL_RE.search(line):
            counts["not_nil! uses"] += len(NOTNIL_RE.findall(line))
        if not stack and DSL_RE.match(stripped):
            counts["top-level DSL calls (routes, filters)"] += 1
        elif not stack and not re.match(r"^\s*(end|else|elsif|when|in|rescue|ensure|\}|\{%|\{\{|%\}|\)|\])", line) and not stripped.startswith(("require", "def ", "private def", "macro", "class", "module", "struct", "enum", "abstract", "lib ", "annotation", "@[")):
            top_level_code += 1
    undeclared = sum(len(ivar_assign[t] - ivar_decl[t]) for t in ivar_assign)
    counts["ivars assigned without a declaration"] += undeclared
    counts["other top-level statements"] += top_level_code
    per_file[path] = counts
    totals.update(counts)

# R-3: a type opened in more than one file of the tree, and types whose
# first opening is not this tree's (reopened foreign types).
own_reopened = {t: fs for t, fs in opened_in.items() if len(set(fs)) > 1}
foreign_roots = ("Log", "HTTP", "String", "Array", "Hash", "Int", "Float", "Time", "JSON", "DB", "PG", "Object", "Exception", "File", "IO", "Nil", "Bool", "Char", "Symbol", "Number", "Enumerable", "Iterator", "Process", "Random", "Regex", "Struct", "Class", "Value", "Reference", "Pointer", "Tuple", "NamedTuple", "Proc", "Set", "Deque", "Slice", "Bytes", "URI", "Base64", "Crypto", "OpenSSL", "Socket", "Path", "Dir", "Env", "ENV", "Log::Metadata")
foreign_reopened = {t: fs for t, fs in opened_in.items() if t.split("::")[0] in foreign_roots or t in foreign_roots}

print(f"{len(files)} files, {totals['lines']:,} lines")
for key in ["defs", "top-level defs", "top-level DSL calls (routes, filters)", "other top-level statements", "type openings",
            "require relative", "require shard/stdlib", "macro definitions", "include/extend in a type",
            "ivars assigned without a declaration", "rescue/raise lines", "not_nil! uses"]:
    print(f"  {key:<42} {totals[key]:>5}")
print(f"  {'types opened in more than one file (R-3)':<42} {len(own_reopened):>5}   in {sum(len(set(f)) for f in own_reopened.values())} openings")
for t, fs in sorted(own_reopened.items(), key=lambda kv: -len(set(kv[1])))[:8]:
    print(f"      {t:<40} {len(set(fs))} files")
print(f"  {'foreign types reopened (R-3, blocker)':<42} {len(foreign_reopened):>5}")
for t, fs in sorted(foreign_reopened.items()):
    print(f"      {t:<40} {len(fs)} opening(s): {', '.join(sorted(set(os.path.relpath(f, src) for f in fs)))[:80]}")
