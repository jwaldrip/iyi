#!/usr/bin/env python3
"""Fails when Crystal's name stands in for iyi's own.

iyi is a permanent fork. Crystal is the language it came from, not its
identity, so the name is allowed only where it genuinely denotes Crystal: the
standard library a `--crystal` program compiles against, the licence and
provenance, the compatibility binary, and upstream's documentation kept beside
ours. Everywhere else it is leakage, and leakage is what this refuses.

    python3 bench/identity_floor.py            # check
    python3 bench/identity_floor.py --list     # every unallowed occurrence

Two layers, because either alone is fooled. PATHS catches a whole tree that
should have been renamed. LINES catches a name inside a file that was otherwise
cut over, which is the shape a skipped hunk leaves behind.

A new match is not automatically wrong. It is a claim that this occurrence
denotes Crystal rather than iyi, and the way to make that claim is to add it
here, in the same commit, with the reason. What this refuses is the version
where the name creeps back and nobody notices.

This is written in Python rather than shell on purpose: the first draft used
`grep -P`, the `grep` on the PATH inside a script has no `-P`, and every
allowlist test errored and failed OPEN. A gate that cannot fail is worse than
no gate, so the matching is done here where the semantics are exact.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Trees and files that are Crystal's, not iyi's. Each carries its reason.
ALLOWED_PATHS: list[tuple[str, str]] = [
    # Crystal's standard library. A `--crystal` program compiles against it,
    # and so does the compiler, which is a Crystal program (SPEC.md B.2).
    (r"^src/(?!compiler/|iyi/)", "Crystal's standard library"),
    (r"^spec/std/", "that library's own specs"),
    # Drives the compatibility binary by the name a user types.
    (r"^spec/compiler-cli/", "compatibility binary's CLI specs"),
    # Provenance, licence, copyright.
    (r"^README\.crystal\.md$", "upstream's README, kept"),
    (r"^LICENSE", "Crystal's licence"),
    (r"^NOTICE\.md$", "Crystal's copyright"),
    # The compatibility binary, shipped so `.cr` sources still build.
    (r"^bin/crystal", "the compatibility binary"),
    (r"^samples/crystal/", "programs that exist to use Crystal's library"),
    # Upstream's manual pages, artwork, and editor integration keyed on
    # Crystal's own type names.
    (r"^doc/man/crystal", "upstream's manual pages"),
    (r"^doc/assets/", "upstream's artwork"),
    (r"^etc/", "debugger and editor integration"),
    # Bootstrap toolchain lookup.
    (r"^Makefile\.win$", "bootstrap toolchain lookup"),
    (r"^shell\.nix$", "bootstrap toolchain lookup"),
    (r"^\.gitattributes$", "language detection for the .cr tree"),
]

# Lines that name Crystal legitimately inside a file that is otherwise iyi's.
ALLOWED_LINES: list[tuple[str, str]] = [
    (r"--crystal", "the compatibility mode's own flag"),
    (r"crystal_front", "the front-end bench binary"),
    (r"CRYSTAL_ONLY", "the list of commands that belong to Crystal"),
    (r"Crystal 1\.", "the upstream version this forked from"),
    (r"fork of Crystal", "provenance"),
    (r"README\.crystal", "provenance"),
    (r"Manas Technology", "copyright holder"),
    (r"crystal-lang\.org", "upstream's site"),
    (r"github\.com/crystal-lang", "upstream's repository"),
    (r"[Cc]opyright.*Crystal", "copyright"),
    (
        r"Crystal's (own|library|licence|license|compiler|semantics|stdlib|"
        r"standard|prelude|codegen|cache|interpreter|fibers|ecosystem|list|"
        r"requirements|answer|version|numbers|README)",
        "a sentence about the other language",
    ),
    (
        r"the Crystal (project|language|compiler|standard|library|ecosystem|"
        r"binary|bootstrap|stdlib)",
        "a sentence about the other language",
    ),
    (r"as Crystal\b", "a comparison with the other language"),
    (r"than Crystal\b", "a comparison with the other language"),
    (r"Crystal\b.*(shard|Kemal|ecosystem)", "the ecosystem it borrows"),
]

PATH_RES = [(re.compile(p), why) for p, why in ALLOWED_PATHS]
LINE_RES = [(re.compile(p), why) for p, why in ALLOWED_LINES]
NEEDLE = re.compile("crystal", re.IGNORECASE)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return out.splitlines()


def path_allowed(rel: str) -> str | None:
    for rx, why in PATH_RES:
        if rx.search(rel):
            return why
    return None


def line_allowed(line: str) -> str | None:
    for rx, why in LINE_RES:
        if rx.search(line):
            return why
    return None


def main() -> int:
    show_all = "--list" in sys.argv
    path_hits: list[str] = []
    line_hits: list[tuple[str, int, str]] = []

    for rel in tracked_files():
        if path_allowed(rel):
            continue

        if NEEDLE.search(rel):
            path_hits.append(rel)

        fp = REPO / rel
        try:
            text = fp.read_text()
        except (UnicodeDecodeError, OSError, IsADirectoryError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if NEEDLE.search(line) and not line_allowed(line):
                line_hits.append((rel, n, line.strip()[:120]))

    if not path_hits and not line_hits:
        print("iyi owns its name")
        return 0

    print("CRYSTAL'S NAME IS STANDING IN FOR IYI'S")
    print()
    limit = None if show_all else 30
    for rel in path_hits[:limit]:
        print(f"PATH  {rel}")
    if limit and len(path_hits) > limit:
        print(f"      ... and {len(path_hits) - limit} more paths")
    print()
    for rel, n, line in line_hits[:limit]:
        print(f"LINE  {rel}:{n}  {line}")
    if limit and len(line_hits) > limit:
        print(f"      ... and {len(line_hits) - limit} more lines")

    by_file: dict[str, int] = {}
    for rel, _, _ in line_hits:
        by_file[rel] = by_file.get(rel, 0) + 1
    print()
    print(f"paths: {len(path_hits)}    lines: {len(line_hits)}    files: {len(by_file)}")
    if by_file and not show_all:
        print()
        print("worst files:")
        for rel, n in sorted(by_file.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  {n:6}  {rel}")
    print()
    print("Each is a place iyi is called Crystal. If an occurrence genuinely")
    print("denotes the other language, add it to ALLOWED_PATHS or ALLOWED_LINES")
    print("in this script, in the same commit, and say why.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
