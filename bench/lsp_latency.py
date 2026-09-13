#!/usr/bin/env python3
"""Measures what `iyi lsp` claims: that a real compile per question fits
an editor's budget. The corpus is this repository's own samples — the
calc language, the kemal port, the app/std modules — opened in one
session, then asked the questions a person asks: a keystroke's verdict,
a hover, a completion, references. Wall time is measured from request
to answer, percentiles are printed, and a p95 over budget names its
verb and exits 1. `bench/lsp_session.py` is the correctness gate; this
is the speed half of the same claim.

Budgets are deliberately loose (CI machines are not laptops); the point
they hold is architectural: no question is allowed to cost a rebuild of
the world, because R-1 made the module the unit.
"""

import glob
import os
import re
import sys
import time

from lsp_session import Client

CORPUS_ROOT = os.path.join(os.path.dirname(__file__), "..", "samples", "iyi")

# p95 budgets, seconds.
BUDGETS = {
    "didChange": 2.0,
    "hover": 2.0,
    "completion": 2.0,
    # Workspace-wide, one compile per entry whose imports reach the
    # declaring module. Every entry compiled instead: 4.6 s on this
    # corpus with an unoptimised compiler, which is what the budget is
    # set under, so "ask everybody" cannot come back unnoticed.
    #
    # Kept as a backstop rather than the check. An absolute second count
    # measures the machine as much as the code: the same commit measures
    # 0.97 s on an M-series laptop, 1.72 s in an x86-64 container under
    # emulation, and 3.10 s on a CI runner, so a 3.0 s line fails on the
    # slowest machine while nothing regressed. The ratio below is what
    # actually holds the claim.
    "references": 6.0,
}

# What `references` may cost relative to a single-module compile measured in
# the same run, which is the same machine, the same build and the same minute.
# It is ~6x on all three machines above. The regression this gate exists to
# catch, compiling every entry rather than the ones whose imports reach the
# declaring module, is a multiple of that rather than a few percent, so a
# ceiling of twelve catches it and machine speed cancels out.
REFERENCES_OVER_DIDCHANGE = 12.0


def percentile(samples, p):
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, round(p / 100 * len(ordered)) - 1))
    return ordered[index]


def main():
    root = os.path.abspath(CORPUS_ROOT)
    files = sorted(
        f for f in glob.glob(os.path.join(root, "**", "*.iyi"), recursive=True)
    )
    if not files:
        sys.exit(f"no corpus under {root}")

    c = Client()
    started = time.monotonic()
    c.send("initialize", {"rootUri": "file://" + root, "capabilities": {}})
    c.send("initialized", {}, wait=False)
    startup = time.monotonic() - started

    texts = {}
    for path in files:
        with open(path) as f:
            texts[path] = f.read()
        c.send("textDocument/didOpen",
               {"textDocument": {"uri": "file://" + path, "languageId": "iyi",
                                 "version": 1, "text": texts[path]}},
               wait=False)
        c.diagnostics("file://" + path)

    timings = {verb: [] for verb in BUDGETS}

    def timed(verb, thunk):
        t0 = time.monotonic()
        thunk()
        timings[verb].append(time.monotonic() - t0)

    # A probe position per file: the first def's name.
    probes = {}
    for path in files:
        m = re.search(r"^(?:pub )?def (\w+)", texts[path], re.M)
        if m:
            line = texts[path][:m.start()].count("\n")
            col = texts[path].splitlines()[line].index(m.group(1))
            probes[path] = (line, col + 1)

    for round_no in range(2):
        for path in files:
            uri = "file://" + path
            # 1. the keystroke: a comment toggled at the end, full
            #    verdict awaited. Round two returns to the original, so
            #    the corpus is left as found.
            text = texts[path] + "# t\n" if round_no == 0 else texts[path]
            timed("didChange", lambda: (
                c.send("textDocument/didChange",
                       {"textDocument": {"uri": uri, "version": 2 + round_no},
                        "contentChanges": [{"text": text}]}, wait=False),
                c.diagnostics(uri)))

            if path not in probes:
                continue
            line, col = probes[path]
            timed("hover", lambda: c.send(
                "textDocument/hover",
                {"textDocument": {"uri": uri},
                 "position": {"line": line, "character": col}}))
            timed("completion", lambda: c.send(
                "textDocument/completion",
                {"textDocument": {"uri": uri},
                 "position": {"line": line, "character": col}}))

    # References are workspace-wide — every module compiles — so a few
    # samples say what there is to say.
    for path in list(probes)[:5]:
        uri = "file://" + path
        line, col = probes[path]
        timed("references", lambda: c.send(
            "textDocument/references",
            {"textDocument": {"uri": uri},
             "position": {"line": line, "character": col},
             "context": {"includeDeclaration": True}}))

    c.send("shutdown", {})
    c.send("exit", {}, wait=False)

    print(f"corpus: {len(files)} modules under samples/iyi, "
          f"startup {startup * 1000:.0f} ms")
    print(f"{'verb':<12}{'n':>5}{'p50':>9}{'p95':>9}{'max':>9}")
    over = []
    p95s = {}
    for verb, samples in timings.items():
        p50 = percentile(samples, 50)
        p95 = percentile(samples, 95)
        p95s[verb] = p95
        print(f"{verb:<12}{len(samples):>5}"
              f"{p50 * 1000:>7.0f}ms{p95 * 1000:>7.0f}ms"
              f"{max(samples) * 1000:>7.0f}ms")
        if p95 > BUDGETS[verb]:
            over.append(f"{verb}: p95 {p95 * 1000:.0f}ms > "
                        f"{BUDGETS[verb] * 1000:.0f}ms")

    keystroke = p95s.get("didChange", 0.0)
    references = p95s.get("references", 0.0)
    if keystroke > 0:
        ratio = references / keystroke
        print(f"\nreferences costs {ratio:.1f} keystroke compiles on this "
              f"machine; the ceiling is {REFERENCES_OVER_DIDCHANGE:.0f}")
        if ratio > REFERENCES_OVER_DIDCHANGE:
            over.append(
                f"references: {ratio:.1f}x a keystroke compile, over "
                f"{REFERENCES_OVER_DIDCHANGE:.0f}x. That is the shape of "
                f"compiling every entry rather than the ones whose imports "
                f"reach the declaring module")

    if over:
        print("\nOVER BUDGET")
        for line in over:
            print(f"  {line}")
        sys.exit(1)
    print("\nlsp latency: every verb inside its budget")


if __name__ == "__main__":
    main()
