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


def bang_names() -> int:
    """Distinct method names ending in `!` in Crystal's standard library.

    README says `!` propagates an error in iyi, so a Crystal method whose name
    ends in one cannot be called from a `.iyi` file, and quotes how many such
    names there are. `src/compiler/` is excluded because the compiler is not the
    standard library, and `__crystal_pseudo_!` is excluded because it is a
    compiler intrinsic rather than a name a person calls.
    """
    names: set[str] = set()
    for p in (REPO / "src").rglob("*.cr"):
        if "/compiler/" in str(p):
            continue
        try:
            text = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for m in re.finditer(r"^\s*def\s+([a-z_][A-Za-z0-9_]*!)", text, re.M):
            names.add(m.group(1))
    names.discard("__crystal_pseudo_!")
    return len(names)


def generated_project_lines() -> int:
    """What `bench/incremental/generate_project.py` writes, as iyi.

    The edit-loop numbers are about a generated 30-module project and the docs
    quote its size. The generator is the authority, so it is asked rather than
    remembered: two places said 7,208 while it emitted 7,207.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as work:
        subprocess.run(
            [sys.executable, "bench/incremental/generate_project.py", work],
            cwd=REPO, capture_output=True, text=True, check=True,
        )
        return wc(sorted((pathlib.Path(work) / "iyi").rglob("*.iyi")))


def measured() -> dict[str, int]:
    """The numbers, measured the way the docs say they are measured."""
    return {
        "prelude": wc(sorted((REPO / "src/iyi").glob("*.iyi"))),
        "samples_std": wc(sorted((REPO / "samples/iyi/std").glob("*.iyi"))),
        "compiler": wc(sorted((REPO / "src/compiler").rglob("*.cr"))),
        "samples": len(sorted((REPO / "samples/iyi").glob("*.iyi"))),
        # Bytes on disk, not lines: the docs quote the library's size as a
        # download, which is what a person unpacking the tarball sees.
        "prelude_kb": round(
            sum(p.stat().st_size for p in sorted((REPO / "src/iyi").glob("*.iyi"))) / 1024
        ),
        "bang_names": bang_names(),
        "generated": generated_project_lines(),
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
    ("prelude_kb", r"library is ([\d,]+) KB on disk", "README.md", 1),
    ("prelude_kb", r"carries both libraries: iyi's own ([\d,]+) KB", "README.md", 1),
    ("prelude_kb", r"beside `bin/iyi` is ([\d,]+) KB", "Makefile", 1),
    ("prelude_kb", r"ships only iyi's own ([\d,]+) KB", "Makefile", 1),
    ("prelude_kb", r"its own, and it is ([\d,]+) KB", "Makefile", 1),
    ("bang_names", r"standard library has \*\*([\d,]+) such names\*\*", "README.md", 1),
    ("generated", r"edit one module in a ([\d,]+)-line project", "README.md", 1),
    ("generated", r"on the same ([\d,]+) lines", "README.md", 1),
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
