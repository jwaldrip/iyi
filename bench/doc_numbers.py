#!/usr/bin/env python3
"""Fails when a number the docs state as current has drifted from the tree.

The docs quote sizes as facts a reader can check, and the convention is
`wc -l` (README says so where it first quotes one). Three times now a number
has gone stale without anyone noticing: PR #3 corrected a batch, the 0.2.0
merge left the prelude at 1,184 lines when it was 1,989, and the same figure
was repeated in eleven places across four files.

    python3 bench/doc_numbers.py          # check
    python3 bench/doc_numbers.py --list   # every occurrence found

Only CURRENT claims are checked. A release note saying "0.1.0 had a
1,184-line prelude" is a statement about the past and stays; the check looks
for the phrasings the docs use to describe the tree as it is now.

What this does NOT check is whether a sentence is true, only whether a number
matches what the tree measures. `bench/identity_floor.py` is the same idea for
a different kind of claim.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent


def wc(paths) -> int:
    return sum(len(p.read_text().splitlines()) for p in paths)


def measured() -> dict[str, int]:
    """The numbers, measured the way the docs say they are measured."""
    return {
        "prelude": wc(sorted((REPO / "src/iyi").glob("*.iyi"))),
        "samples_std": wc(sorted((REPO / "samples/iyi/std").glob("*.iyi"))),
        "compiler": wc(sorted((REPO / "src/compiler").rglob("*.cr"))),
        "samples": len(sorted((REPO / "samples/iyi").glob("*.iyi"))),
    }

# Each entry: the measured key, the pattern that quotes it as current, the file,
# and how many times that pattern is expected to appear there. The count is
# load-bearing: two sites in one file shared a pattern, and dropping one of them
# left the other matching, so the check went on passing while a sentence it was
# meant to cover had gone. A pattern must capture the number in group 1.
CLAIMS: list[tuple[str, str, str, int]] = [
    ("prelude", r"iyi's own library is ([\d,]+) lines", "README.md", 2),
    ("prelude", r"iyi's own library, ([\d,]+) lines", "README.md", 1),
    ("prelude", r"standard library instead of ([\d,]+)", "README.md", 1),
    ("prelude", r"iyi's own prelude \| ([\d,]+) lines", "SPEC.md", 1),
    ("prelude", r"still true of iyi's own ([\d,]+) lines", "SPEC.md", 1),
    ("prelude", r"Done: ([\d,]+) lines", "SPEC.md", 1),
    ("prelude", r"\| ([\d,]+)-line own prelude", "SPEC.md", 1),
    ("prelude", r"against iyi's own ([\d,]+)-line prelude", "SPEC.md", 1),
    ("prelude", r"against iyi's own ([\d,]+)-line library", "CHANGELOG.md", 1),
    ("prelude", r"against iyi's own ([\d,]+)-line", "samples/iyi/calc.iyi", 1),
    ("samples_std", r"own prelude \+ ([\d,]+) in samples", "SPEC.md", 1),
    ("compiler", r"\| ([\d,]+) lines, Crystal, forked", "SPEC.md", 1),
]


def main() -> int:
    show_all = "--list" in sys.argv
    truth = measured()
    wrong: list[str] = []
    found: list[str] = []

    for key, pattern, rel, expected in CLAIMS:
        fp = REPO / rel
        text = fp.read_text()
        hits = list(re.finditer(pattern, text))
        if len(hits) != expected:
            wrong.append(
                f"{rel}: /{pattern}/ appears {len(hits)} time(s), expected "
                f"{expected}. A sentence this was written to cover was reworded "
                f"or removed, so the check stopped checking it"
            )
            if not hits:
                continue
        for m in hits:
            stated = int(m.group(1).replace(",", ""))
            line = text[: m.start()].count("\n") + 1
            ok = stated == truth[key]
            found.append(f"{'ok  ' if ok else 'WRONG'}  {rel}:{line}  {key}={stated}")
            if not ok:
                wrong.append(
                    f"{rel}:{line}  says {key} is {stated:,}, tree measures {truth[key]:,}"
                )

    if show_all:
        for f in found:
            print(f)
        print()

    print("measured:", ", ".join(f"{k}={v:,}" for k, v in sorted(truth.items())))

    if not wrong:
        print("the numbers the docs state are the numbers the tree has")
        return 0

    print("\nA NUMBER THE DOCS STATE AS CURRENT HAS DRIFTED\n")
    for w in wrong:
        print(f"  {w}")
    print(
        "\nUpdate the sentence, or update this script if what it measures is no "
        "longer what the sentence means. Counts are `wc -l`, which is the "
        "convention README states where it first quotes one."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
