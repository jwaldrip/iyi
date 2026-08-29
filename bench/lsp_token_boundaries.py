#!/usr/bin/env python3
"""Sweeps every sample module's semantic tokens and refuses a token
that colors part of a word. The bug this gate exists for was literal:
the lexer reuses one Token and leaves `raw` dirty between kinds, so an
ident could inherit the previous number's *length* — and every editor
showed `t`otal, the first letter colored, the rest plain. A wordy
token must start and end on word boundaries; 8,000+ tokens across the
samples say so on every push, so the world's best highlighting cannot
quietly become the world's strangest.
"""

import glob
import os
import sys

from lsp_session import Client

TYPES = ["keyword", "string", "number", "comment", "type", "function",
         "variable", "property", "operator", "regexp", "macro",
         "enumMember", "parameter"]
WORDY = {"keyword", "type", "function", "variable", "parameter", "number"}


def name_char(ch):
    return ch.isalnum() or ch == "_"


def main():
    root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "samples", "iyi"))
    files = sorted(glob.glob(root + "/**/*.iyi", recursive=True))
    if not files:
        sys.exit(f"no corpus under {root}")

    c = Client()
    c.send("initialize", {"rootUri": "file://" + root, "capabilities": {}})
    c.send("initialized", {}, wait=False)

    total = 0
    bad = []
    for path in files:
        with open(path) as f:
            text = f.read()
        lines = text.split("\n")
        uri = "file://" + path
        c.send("textDocument/didOpen",
               {"textDocument": {"uri": uri, "languageId": "iyi",
                                 "version": 1, "text": text}}, wait=False)
        reply = c.send("textDocument/semanticTokens/full",
                       {"textDocument": {"uri": uri}})
        data = reply["result"]["data"]
        line = start = 0
        for i in range(0, len(data), 5):
            dl, ds, ln, tt, _ = data[i:i + 5]
            line += dl
            start = (start + ds) if dl == 0 else ds
            total += 1
            kind = TYPES[tt]
            if kind not in WORDY:
                continue
            src = lines[line] if line < len(lines) else ""
            before = src[start - 1] if start > 0 else " "
            last = src[start + ln - 1] if start + ln - 1 < len(src) else " "
            after = src[start + ln] if start + ln < len(src) else " "
            starts_mid = name_char(before) and kind != "number"
            ends_mid = name_char(after) and name_char(last)
            if starts_mid or ends_mid:
                bad.append(f"{os.path.relpath(path, root)}:{line + 1}:{start}"
                           f" {kind} {src[start:start + ln]!r}"
                           f" in {src.strip()!r}")
    c.send("shutdown", {})
    c.send("exit", {}, wait=False)

    if bad:
        print(f"{len(bad)} of {total} tokens color part of a word:")
        for entry in bad[:20]:
            print(f"  {entry}")
        sys.exit(1)
    print(f"token boundaries: {total} tokens across "
          f"{len(files)} modules, every word whole")


if __name__ == "__main__":
    main()
