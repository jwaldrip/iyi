#!/usr/bin/env python3
"""Direct per-function census for the typed pipeline against the hosted IR.

Subcommands:
  names <hosted.ll> [-o <out>]
      Extract in-scope hosted function names (one per line) and print the
      out-of-scope count.

  run <tool> <root> <names> <outdir> [--chunk N] [--hosted <hosted.ll>]
      Run <tool> on <root> with --pipeline typed --prelude --probe-phase
      --keep-going --census <chunk_file> sequentially in chunks of N names
      (default 200), measuring memory and wall time per chunk, and merge
      the resulting .names and .refusals sidecars into <outdir>.

  report <outdir> [--hosted <hosted.ll>] [--write-dir <dir>]
      Print the census summary line, scaffold failures by reason, and
      the ranked refusal-shape table. Optionally write census.txt,
      shapes.tsv, and by_function.tsv to --write-dir.
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

DEFINE = re.compile(r'^define\b[^@]*@("(?:[^"\\]|\\.)*"|[^\s(]+)')
FILE_PREFIX = re.compile(r'^\*(?:/[^:]*\.iyi)::')


def norm_hosted_name(name: str) -> str:
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return FILE_PREFIX.sub("*", name)


def has_return_colon(s: str) -> bool:
    dp = 0
    db = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0:
            if c == ":" and i + 1 < len(s) and s[i + 1] == ":":
                i += 2
                continue
            elif c == ":":
                return True
        i += 1
    return False


def is_in_scope_hosted_name(name: str) -> bool:
    if not name.startswith("*"):
        return False
    if name.startswith("*~"):
        return False
    if not has_return_colon(name[1:]):
        return False
    return True


def extract_hosted_defines(ll_path: str) -> tuple[list[str], list[str]]:
    seen: set[str] = set()
    in_scope: list[str] = []
    out_scope: list[str] = []
    with open(ll_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("define"):
                continue
            m = DEFINE.match(line)
            if not m:
                continue
            name = norm_hosted_name(m.group(1))
            if name in seen:
                continue
            seen.add(name)
            if is_in_scope_hosted_name(name):
                in_scope.append(name)
            else:
                out_scope.append(name)
    in_scope.sort()
    out_scope.sort()
    return in_scope, out_scope


def strip_caret(owner: str) -> str:
    if "^" not in owner:
        return owner
    dp = 0
    db = 0
    for i, c in enumerate(owner):
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0 and c == "^":
            return owner[:i]
    return owner


def label_of(full: str) -> str:
    """Convert a hosted name into the port's def label (`Owner#meth`, `Owner.class#meth`, `name`)."""
    s = full.lstrip("*")
    dp = 0
    db = 0
    ret_colon = -1
    i = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0:
            if c == ":" and i + 1 < len(s) and s[i + 1] == ":":
                i += 2
                continue
            elif c == ":":
                ret_colon = i
                break
        i += 1
    head = s[:ret_colon] if ret_colon >= 0 else s

    if head.endswith(">"):
        dp = 0
        db = 0
        open_lt = -1
        j = len(head) - 2
        while j >= 0:
            c = head[j]
            if c == ")":
                dp += 1
            elif c == "(":
                dp -= 1
            elif c == "}":
                db += 1
            elif c == "{":
                db -= 1
            elif dp == 0 and db == 0:
                if c == "<":
                    open_lt = j
                    break
                elif c == "#":
                    break
            j -= 1
        if open_lt >= 0 and head[open_lt:] != "<=>":
            head = head[:open_lt]

    dp = 0
    db = 0
    hash_idx = -1
    last_dbl = -1
    i = 0
    while i < len(head):
        c = head[i]
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0:
            if c == "#":
                hash_idx = i
                break
            elif c == ":" and i + 1 < len(head) and head[i + 1] == ":":
                last_dbl = i
                i += 2
                continue
        i += 1

    if hash_idx >= 0:
        owner = strip_caret(head[:hash_idx])
        meth = head[hash_idx + 1 :]
        return f"{owner}#{meth}"
    if last_dbl >= 0:
        owner = strip_caret(head[:last_dbl])
        meth = head[last_dbl + 2 :]
        return f"{owner}.class#{meth}"
    return head

def parse_name_parts(full: str) -> tuple[str, str, bool, str, str, str]:
    """Return (kind, owner, has_caret, meth, args_str, ret) for a mangled function name."""
    s = full.lstrip("*")
    dp = 0
    db = 0
    ret_colon = -1
    i = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0:
            if c == ":" and i + 1 < len(s) and s[i + 1] == ":":
                i += 2
                continue
            elif c == ":":
                ret_colon = i
                break
        i += 1
    head = s[:ret_colon] if ret_colon >= 0 else s
    ret = s[ret_colon + 1 :] if ret_colon >= 0 else ""

    args_str = ""
    if head.endswith(">"):
        dp = 0
        db = 0
        open_lt = -1
        j = len(head) - 2
        while j >= 0:
            c = head[j]
            if c == ")":
                dp += 1
            elif c == "(":
                dp -= 1
            elif c == "}":
                db += 1
            elif c == "{":
                db -= 1
            elif dp == 0 and db == 0:
                if c == "<":
                    open_lt = j
                    break
                elif c == "#":
                    break
            j -= 1
        if open_lt >= 0 and head[open_lt:] != "<=>":
            args_str = head[open_lt + 1 : -1]
            head = head[:open_lt]

    dp = 0
    db = 0
    hash_idx = -1
    last_dbl = -1
    i = 0
    while i < len(head):
        c = head[i]
        if c == "(":
            dp += 1
        elif c == ")":
            dp -= 1
        elif c == "{":
            db += 1
        elif c == "}":
            db -= 1
        elif dp == 0 and db == 0:
            if c == "#":
                hash_idx = i
                break
            elif c == ":" and i + 1 < len(head) and head[i + 1] == ":":
                last_dbl = i
                i += 2
                continue
        i += 1

    if hash_idx >= 0:
        raw_owner = head[:hash_idx]
        owner = strip_caret(raw_owner)
        return ("instance", owner, "^" in raw_owner, head[hash_idx + 1 :], args_str, ret)
    if last_dbl >= 0:
        raw_owner = head[:last_dbl]
        owner = strip_caret(raw_owner)
        return ("class", owner, "^" in raw_owner, head[last_dbl + 2 :], args_str, ret)
    return ("top", "", False, head, args_str, ret)


def classify_naming_diff(hosted: str, port: str) -> str:
    """Classify how `port` differs from `hosted`."""
    hk, ho, hcaret, hm, ha, hret = parse_name_parts(hosted)
    pk, po, pcaret, pm, pa, pret = parse_name_parts(port)
    diffs: list[str] = []
    if hcaret and not pcaret:
        diffs.append("^Owner(T) segment")
    elif pcaret and not hcaret:
        diffs.append("extra ^Owner(T) segment")
    if (".class#" in port and "::" in hosted) or (".class#" in hosted and "::" in port) or (hk != pk):
        diffs.append(".class# vs ::")
    if ha and not pa:
        diffs.append("missing <Args>")
    elif ha != pa:
        diffs.append("different <Args>")
    if hret and not pret:
        diffs.append("missing :Ret")
    elif hret != pret:
        diffs.append("different :Ret")
    if not diffs:
        diffs.append("other")
    return " + ".join(diffs)


def pick_port_match(hosted: str, candidates: list[str], extra_set: set[str]) -> str:
    """Pick the best matching port name among candidates sharing `label_of`."""
    _, _, _, _, ha, hret = parse_name_parts(hosted)
    def score(pn: str) -> tuple[int, int, int, str]:
        _, _, _, _, pa, pret = parse_name_parts(pn)
        return (
            0 if pn in extra_set else 1,
            0 if pa == ha else 1,
            0 if pret == hret else 1,
            pn,
        )
    return min(candidates, key=score)


def normalize_reason(reason: str) -> str:
    """Normalize a raw refusal reason into a shape by replacing quoted names, type names, and counts."""
    s = reason.strip()

    # Replace single-quoted names (`'foo'`, `'String.interpolation'`), avoiding English possessives (`union's`).
    s = re.sub(r"(?<![A-Za-z0-9_])'[^']*'", "'<name>'", s)

    # Specific recurring messages whose structure names a type or identifier without quotes:
    s = re.sub(r"\bundefined constant \S+", "undefined constant <Const>", s)
    s = re.sub(
        r"the body of \S+ \(hosted codegen_fun: return type\)",
        "the body of <name> (hosted codegen_fun: return type)",
        s,
    )
    s = re.sub(r"\bexpected argument #\d+", "expected argument #<n>", s)
    s = re.sub(r"\(given \d+, expected [^)]+\)", "(given <n>, expected <n>)", s)
    s = re.sub(r"(the call to )\S+( has no )", r"\1<name>\2", s)
    s = re.sub(r"(lower: visit\(a restriction that converts argument )\d+ of \S+", r"\1<n> of <name>", s)
    s = re.sub(r"(a function or global named )\S+( already exists)", r"\1<name>\2", s)
    s = re.sub(r"(pointerof of )\S+( is not ported yet)", r"\1<name> is not ported yet", s)
    s = re.sub(r"(lower: visit\(allocate of class )\S+(:)", r"\1<Type>\2", s)
    s = re.sub(r"(lower: visit\(a call to )\S+( with no receiver)", r"\1<name>\2", s)
    s = re.sub(r"(lower: visit\(a call to )\S+( inherited from a superclass of )\S+", r"\1<name>\2<Type>", s)
    s = re.sub(r"(create_llvm_type for )\S+( is not ported)", r"\1<Type>\2", s)
    s = re.sub(r"(llvm_struct_type of (?:generic instance )?)(.+?)( is not ported)", r"\1<Type>\3", s)
    s = re.sub(r"^BUG: .+?( has no type id \(not reachable)", r"BUG: <Type>\1", s)
    s = re.sub(r"^(lower: )\S+( is declared )(.+?)( and assigned )(.+?)(: the hosted upcast)", r"\1<name>\2<Type>\4<Type>\6", s)
    s = re.sub(r"^(lower: visit\(assign )\S+( to )\S+( \(hosted assign_distinct)", r"\1<Type>\2<Type>\3", s)
    s = re.sub(
        r"(lower: visit\((?:pointer_get|pointer_set) of )([^()]+(?:\([^)]*\))?)( \(hosted)",
        r"\1<Type>\3",
        s,
    )
    s = re.sub(
        r"(lower: visit\(binary \S+ on )(\S+) and (\S+)( \(mixed operands)",
        r"\1<Type> and <Type>\4",
        s,
    )
    s = re.sub(r"(class var @@\S+ initializer of )(\S+)", r"\1<Type>", s)
    s = re.sub(r"(class variable @@\S+)", "class variable @@<name>", s)
    s = re.sub(r"(at /[^\s:]+):\d+(?::\d+)*", r"\1:<line>", s)
    s = re.sub(r"at /[^\s:]+:<line>", "at <file>:<line>", s)

    if s.startswith("unsupported node:"):
        return s

    # Replace balanced parenthesized unions `(A | B)`
    res = []
    i = 0
    while i < len(s):
        if s[i] == "(" and "|" in s[i:]:
            depth = 0
            j = i
            has_bar = False
            while j < len(s):
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif s[j] == "|" and depth == 1:
                    has_bar = True
                j += 1
            if has_bar and depth == 0 and (i == 0 or s[i - 1] in " ,("):
                res.append("<Type>")
                i = j + 1
                continue
        res.append(s[i])
        i += 1
    s = "".join(res)

    # Replace qualified types (`A::B::C`), generic types (`Foo(...)`), and capitalized type names after prepositions.
    s = re.sub(r"\b(?:[A-Z][A-Za-z0-9_]*::)+[A-Z][A-Za-z0-9_]*\+?(?:\.class)?", "<Type>", s)
    while True:
        nxt = re.sub(r"\b[A-Z][A-Za-z0-9_]*\([^()]*\)\+?(?:\.class)?", "<Type>", s)
        if nxt == s:
            break
        s = nxt

    def replace_cap_type(m: re.Match[str]) -> str:
        prefix = m.group(1)
        tok = m.group(2)
        if tok.startswith("<"):
            return prefix + tok
        return prefix + "<Type>"

    for prep in (
        r"(compile-time type is )",
        r"( must be )",
        r"(, not )",
        r"(, got )",
        r"(: expected )",
        r"( to be )",
        r"('<name>' for )",
        r"( of )",
        r"(Cast from )",
        r"( to )",
    ):
        s = re.sub(prep + r"([A-Z][A-Za-z0-9_]*\+?(?:\.class)?)", replace_cap_type, s)

    s = re.sub(r"<Type>\s*(?:\|\s*<Type>\s*)+", "<Type>", s)
    return s


def cmd_names(args: argparse.Namespace) -> int:
    in_scope, out_scope = extract_hosted_defines(args.hosted_ll)
    total = len(in_scope) + len(out_scope)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            for n in in_scope:
                f.write(n + "\n")
        print(f"names: hosted={total} asked={len(in_scope)} out-of-scope={len(out_scope)} out={args.out}")
    else:
        for n in in_scope:
            print(n)
        print(
            f"names: hosted={total} asked={len(in_scope)} out-of-scope={len(out_scope)}",
            file=sys.stderr,
        )
    return 0


def parse_max_rss_bytes(stderr_text: str) -> int:
    m = re.search(r"^\s*(\d+)\s+maximum resident set size\b", stderr_text, re.MULTILINE)
    if m:
        return int(m.group(1))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    with open(args.names, encoding="utf-8") as f:
        names = [line.rstrip("\n") for line in f if line.strip()]

    (outdir / "root.txt").write_text(args.root + "\n", encoding="utf-8")
    (outdir / "names.txt").write_text("\n".join(names) + ("\n" if names else ""), encoding="utf-8")
    if args.hosted:
        in_scope, out_scope = extract_hosted_defines(args.hosted)
        (outdir / "hosted_count.txt").write_text(
            f"{len(in_scope) + len(out_scope)}\t{len(in_scope)}\t{len(out_scope)}\n",
            encoding="utf-8",
        )
        (outdir / "hosted.names").write_text(
            "\n".join(in_scope + out_scope) + "\n", encoding="utf-8"
        )

    if args.chunk < 1:
        raise ValueError("--chunk must be positive")
    chunks = collections.deque(
        names[i : i + args.chunk] for i in range(0, len(names), args.chunk)
    )
    if not chunks:
        chunks.append([])

    repo_root = str(Path(__file__).resolve().parent.parent)
    env = os.environ.copy()
    env.setdefault("IYI_PATH", os.path.join(repo_root, "src"))

    merged_names: set[str] = set()
    merged_refusals: list[str] = []
    seen_refusals: set[str] = set()
    stats_lines = ["chunk\tcount\twall_s\tmax_rss_mb\trc"]
    durations: list[float] = []
    idx = 0
    runaway_rows: list[str] = []
    # Leave headroom for allocations between RSS samples.
    watchdog_limit_kib = 3 * 1024 * 1024
    # A conservative initial bound until a successful chunk supplies a median.
    initial_timeout = 3600.0
    (outdir / "merged.names").unlink(missing_ok=True)
    (outdir / "merged.refusals").unlink(missing_ok=True)

    while chunks:
        chunk = chunks.popleft()
        prefix = outdir / f"chunk_{idx:04d}"
        chunk_file = outdir / f"chunk_{idx:04d}.in"
        chunk_file.write_text("\n".join(chunk) + ("\n" if chunk else ""), encoding="utf-8")
        out_bin = str(prefix)
        cmd = [
            args.tool,
            args.root,
            "-o",
            out_bin,
            "--pipeline",
            "typed",
            "--prelude",
            "--probe-phase",
            "--keep-going",
            "--census",
            str(chunk_file),
        ]
        names_sidecar = Path(out_bin + ".names")
        refusals_sidecar = Path(out_bin + ".refusals")
        names_sidecar.unlink(missing_ok=True)
        refusals_sidecar.unlink(missing_ok=True)
        t0 = time.monotonic()
        deadline = 10 * statistics.median(durations) if durations else initial_timeout
        peak_kib = 0
        stopped = ""
        probe_path = outdir / f"chunk_{idx:04d}.probe"
        err_path = outdir / f"chunk_{idx:04d}.err"
        sampler: subprocess.Popen | None = None
        sample_path = outdir / f"chunk_{idx:04d}.sample"
        with probe_path.open("w", encoding="utf-8") as probe, err_path.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen(cmd, env=env, stdout=probe, stderr=err)
            while proc.poll() is None:
                try:
                    rss = subprocess.run(
                        ["ps", "-o", "rss=", "-p", str(proc.pid)],
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    value = rss.stdout.strip()
                    if value:
                        peak_kib = max(peak_kib, int(value))
                    if peak_kib >= 1 * 1024 * 1024 and sampler is None:
                        with sample_path.open("w", encoding="utf-8") as sample_log:
                            sampler = subprocess.Popen(
                                ["sample", str(proc.pid), "5"],
                                stdout=sample_log, stderr=subprocess.STDOUT,
                            )
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    stopped = "watchdog: cannot measure rss"
                if peak_kib > watchdog_limit_kib:
                    stopped = "runaway: rss > 3 GiB safety threshold"
                elif time.monotonic() - t0 > deadline:
                    stopped = "timeout"
                if stopped:
                    proc.kill()
                    break
                time.sleep(0.25)
            proc.wait()
        if sampler is not None:
            try:
                sampler.wait(timeout=8)
            except subprocess.TimeoutExpired:
                sampler.kill()
                sampler.wait()
        dt = time.monotonic() - t0
        rss_mb = peak_kib / 1024.0
        stats_lines.append(f"{idx}\t{len(chunk)}\t{dt:.2f}\t{rss_mb:.1f}\t{proc.returncode}\t{stopped}")
        print(f"chunk {idx}: count={len(chunk)} wall={dt:.2f}s max_sampled_rss={rss_mb:.1f}MB rc={proc.returncode} {stopped}", flush=True)
        idx += 1
        if stopped:
            if stopped.startswith("watchdog:"):
                print(stopped, file=sys.stderr)
                return 1
            if len(chunk) > 1:
                mid = len(chunk) // 2
                chunks.appendleft(chunk[mid:])
                chunks.appendleft(chunk[:mid])
            elif chunk:
                runaway_rows.append(f"census\t{chunk[0]}\tcensus\t{stopped}")
            else:
                print(f"Root alone exceeded watchdog: {stopped}", file=sys.stderr)
                return 1
            continue
        durations.append(dt)

        names_sidecar = Path(out_bin + ".names")
        refusals_sidecar = Path(out_bin + ".refusals")
        if not names_sidecar.exists() or not refusals_sidecar.exists():
            print(
                f"ERROR: chunk {idx + 1}/{len(chunks)} did not write both sidecars; census is incomplete",
                file=sys.stderr,
                flush=True,
            )
            return 1
        if names_sidecar.exists():
            for line in names_sidecar.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s:
                    merged_names.add(s)
        if refusals_sidecar.exists():
            for line in refusals_sidecar.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.rstrip("\n")
                if not s:
                    continue
                if s not in seen_refusals:
                    seen_refusals.add(s)
                    merged_refusals.append(s)
    for row in runaway_rows:
        if row not in seen_refusals:
            merged_refusals.append(row)

    (outdir / "merged.names").write_text(
        "\n".join(sorted(merged_names)) + ("\n" if merged_names else ""),
        encoding="utf-8",
    )
    (outdir / "merged.refusals").write_text(
        "\n".join(merged_refusals) + ("\n" if merged_refusals else ""),
        encoding="utf-8",
    )
    (outdir / "stats.tsv").write_text("\n".join(stats_lines) + "\n", encoding="utf-8")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    root = (outdir / "root.txt").read_text(encoding="utf-8").strip() if (outdir / "root.txt").exists() else "?"
    asked = [
        line.strip()
        for line in (outdir / "names.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    asked_set = set(asked)

    if args.hosted:
        in_scope, out_scope = extract_hosted_defines(args.hosted)
        hosted_total = len(in_scope) + len(out_scope)
        hosted_set = set(in_scope) | set(out_scope)
    elif (outdir / "hosted_count.txt").exists():
        hosted_total = int((outdir / "hosted_count.txt").read_text(encoding="utf-8").split()[0])
        hosted_set = set((outdir / "hosted.names").read_text(encoding="utf-8").splitlines())
    else:
        hosted_total = len(asked)
        hosted_set = asked_set

    port_clean_all = {
        line.strip()
        for line in (outdir / "merged.names").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    census_failures: dict[str, str] = {}
    instance_clean: dict[str, str] = {}
    instance_silent: dict[str, str] = {}
    refusals_by_instance: dict[str, list[tuple[str, str, str]]] = collections.defaultdict(list)

    for line in (outdir / "merged.refusals").read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        phase, label, owner, reason = parts[0], parts[1], parts[2], parts[3]
        if phase == "census":
            if label not in census_failures:
                census_failures[label] = reason
        elif phase == "instance-clean":
            instance_clean[label] = reason
        elif phase == "instance-silent":
            instance_silent[label] = reason
        elif phase in ("instance-body", "instance-lowering"):
            refusals_by_instance[label].append((phase, owner, reason))
    accounted = set(census_failures) | set(instance_clean) | set(instance_silent) | set(refusals_by_instance)
    missing_records = asked_set - accounted
    if missing_records:
        print(f"ERROR: {len(missing_records)} asked names lack direct instance records; report is incomplete", file=sys.stderr)
        return 1
    clean_asked = {h for h, actual in instance_clean.items()
                   if actual == h and h not in refusals_by_instance and h not in census_failures}
    extra_clean = sorted(port_clean_all - hosted_set)

    scaffold_failed: list[tuple[str, str]] = []
    naming_pairs: list[tuple[str, str, str]] = []
    silent_funcs: list[str] = []
    refused_count = 0
    by_fn_rows: list[str] = ["hosted_name\tstatus\tfirst_shape"]

    shape_funcs: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    shape_examples: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    shape_verbatim: dict[tuple[str, str], str] = {}
    func_shapes: dict[str, set[tuple[str, str]]] = {}

    superset_collisions = 0
    for h in asked:
        if h in clean_asked:
            if h in census_failures:
                superset_collisions += 1
            by_fn_rows.append(f"{h}\tclean\t")
            continue
        if h in census_failures:
            reason = census_failures[h]
            scaffold_failed.append((h, reason))
            by_fn_rows.append(f"{h}\tscaffold\t{normalize_reason(reason)}")
            continue

        rows = refusals_by_instance.get(h, [])
        if rows:
            refused_count += 1
            fshapes: set[tuple[str, str]] = set()
            first_shape = ""
            for _phase, owner, raw_reason in rows:
                shp = normalize_reason(raw_reason)
                if not first_shape:
                    first_shape = shp
                sk = (shp, owner)
                fshapes.add(sk)
                shape_funcs[sk].add(h)
                if h not in shape_examples[sk] and len(shape_examples[sk]) < 3:
                    shape_examples[sk].append(h)
                shape_verbatim.setdefault(sk, raw_reason)
            func_shapes[h] = fshapes
            by_fn_rows.append(f"{h}\trefused\t{first_shape}")
        elif h in instance_clean:
            pn = instance_clean[h]
            if pn != h:
                diff_cls = classify_naming_diff(h, pn)
                naming_pairs.append((h, pn, diff_cls))
                shp = f"NAMING: {diff_cls}"
                sk = (shp, "lowering")
                func_shapes[h] = {sk}
                shape_funcs[sk].add(h)
                if len(shape_examples[sk]) < 3:
                    shape_examples[sk].append(h)
                shape_verbatim.setdefault(sk, f"{h} -> {pn}")
                by_fn_rows.append(f"{h}\tnaming\t{diff_cls}: {pn}")
            else:
                raise RuntimeError(f"unclassified exact direct result: {h}")
        else:
            silent_funcs.append(h)
            shp = "SILENT: no direct clean name or refusal"
            sk = (shp, "lowering")
            func_shapes[h] = {sk}
            shape_funcs[sk].add(h)
            if len(shape_examples[sk]) < 3:
                shape_examples[sk].append(h)
            shape_verbatim.setdefault(sk, instance_silent.get(h, "no direct instance result"))
            by_fn_rows.append(f"{h}\tsilent\t{shp}")

    only_counts: collections.Counter[tuple[str, str]] = collections.Counter()
    for _h, sks in func_shapes.items():
        if len(sks) == 1:
            only_sk = next(iter(sks))
            only_counts[only_sk] += 1

    ranked_shapes = sorted(
        shape_funcs.keys(),
        key=lambda sk: (-len(shape_funcs[sk]), -only_counts[sk], sk[0], sk[1]),
    )

    lines: list[str] = []
    summary = (
        f"census: {root} hosted={hosted_total} asked={len(asked)} "
        f"scaffold-failed={len(scaffold_failed)} clean={len(clean_asked)}"
    )
    lines.append(summary)
    lines.append(
        f"refused={refused_count} naming={len(naming_pairs)} silent={len(silent_funcs)} "
        f"extra-port-names={len(extra_clean)} superset-collisions={superset_collisions}"
    )

    if scaffold_failed:
        lines.append("")
        lines.append("== Scaffold failures by reason ==")
        sc_groups: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for h, r in scaffold_failed:
            sc_groups[normalize_reason(r)].append((h, r))
        for rshape, items in sorted(sc_groups.items(), key=lambda kv: -len(kv[1])):
            ex_h, ex_raw = items[0]
            lines.append(f"  {len(items):5d}  shape={rshape}")
            lines.append(f"         e.g. {ex_h}")
            lines.append(f"         raw: {ex_raw}")

    lines.append("")
    lines.append("== Refusal shapes ranked by hosted functions stopped ==")
    shape_tsv = ["rank\tstopped\tonly_shape\towner\tshape\texample_1\texample_2\texample_3\tverbatim_reason"]
    for idx, sk in enumerate(ranked_shapes, start=1):
        shp, owner = sk
        stopped = len(shape_funcs[sk])
        only_n = only_counts[sk]
        exs = shape_examples[sk]
        verb = shape_verbatim[sk]
        ex_pad = exs + [""] * (3 - len(exs))
        shape_tsv.append(
            f"{idx}\t{stopped}\t{only_n}\t{owner}\t{shp}\t{ex_pad[0]}\t{ex_pad[1]}\t{ex_pad[2]}\t{verb}"
        )
        lines.append(f"  #{idx:<3d} stopped={stopped:5d} only={only_n:5d} owner={owner} shape={shp}")
        for ex in exs:
            lines.append(f"         e.g. {ex}")
        lines.append(f"         verbatim: {verb}")

    if naming_pairs:
        lines.append("")
        lines.append(f"== (a) NAMING: lowered clean under another name ({len(naming_pairs)}) ==")
        by_cls: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for h, pn, diff_cls in naming_pairs:
            by_cls[diff_cls].append((h, pn))
        for diff_cls, pairs in sorted(by_cls.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            lines.append(f"  class={diff_cls} count={len(pairs)}")
            for h, pn in pairs:
                lines.append(f"    {h} -> {pn}")

    if silent_funcs:
        lines.append("")
        lines.append(f"== (b) SILENT: reached, no refusal row, no clean name ({len(silent_funcs)}) ==")
        for h in silent_funcs[:20]:
            lines.append(f"  {h}")
        if len(silent_funcs) > 20:
            lines.append(f"  ... ({len(silent_funcs) - 20} more)")

    if extra_clean:
        lines.append("")
        lines.append(f"== Clean port names not in hosted names ({len(extra_clean)}) ==")
        for ex in extra_clean[:5]:
            lines.append(f"  {ex}")

    report_text = "\n".join(lines) + "\n"
    print(report_text, end="")

    if args.write_dir:
        wdir = Path(args.write_dir)
        wdir.mkdir(parents=True, exist_ok=True)
        (wdir / "census.txt").write_text(report_text, encoding="utf-8")
        (wdir / "shapes.tsv").write_text("\n".join(shape_tsv) + "\n", encoding="utf-8")
        (wdir / "by_function.tsv").write_text("\n".join(by_fn_rows) + "\n", encoding="utf-8")
        print(f"wrote {wdir}/census.txt, shapes.tsv, by_function.tsv", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Direct per-function census driver")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_names = sub.add_parser("names", help="Extract in-scope hosted function names from .ll")
    p_names.add_argument("hosted_ll")
    p_names.add_argument("-o", "--out", default=None)

    p_run = sub.add_parser("run", help="Run tool in chunks and merge sidecars")
    p_run.add_argument("tool")
    p_run.add_argument("root")
    p_run.add_argument("names")
    p_run.add_argument("outdir")
    p_run.add_argument("--chunk", type=int, default=200)
    p_run.add_argument("--hosted", default=None)

    p_rep = sub.add_parser("report", help="Print census report and optionally write TSV outputs")
    p_rep.add_argument("outdir")
    p_rep.add_argument("--hosted", default=None)
    p_rep.add_argument("--write-dir", default=None)

    args = ap.parse_args(argv[1:])
    if args.cmd == "names":
        return cmd_names(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "report":
        return cmd_report(args)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
