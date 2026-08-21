#!/usr/bin/env python3
"""What iyi's own library costs at run time, against Crystal's.

The README says the word "Performance", and the compile-time half of that is
measured to death (`build_speed.py`, `incremental.py`) while the run-time half
was not measured at all. It is worth asking, because the two libraries are not
the same code: iyi's own library is 2,368 lines, Crystal's is 8,161.

**Two columns, and the second one is why this file is not a victory lap.** The
first reading said string building was twenty times faster. With
`GC_DONT_GC=1` it was slower: every bit of that twenty was the collector,
which scans a program's roots and has far fewer of them in a small binary
than in a large one. A later run no longer shows the twenty; as they run,
string building is within noise, and the collector is masking a slower
builder. The columns separate two different claims (what the library's code
costs, and what carrying a standard library costs) and only the first is
about `Array` and `String` at all. The numbers live in the README; this file
is how to re-measure them.

Each program is written once and compiled twice, under `--crystal` and under
iyi's own prelude, and both must print the same thing or the row is refused.
The backend is shared: same LLVM, same GC, same GC settings.

    python3 bench/runtime.py

Release builds, best of five, seconds. Run it on an idle machine.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
IYI = ROOT / "bin" / "iyi"

RUNS = 5

# Each program is one workload, written so that both libraries can run it. What
# they may use is the intersection: iyi's library is the smaller of the two, so
# every line here is in both.
PROGRAMS = {
    "arithmetic": """
      total = 0_i64
      i = 0
      while i < 60_000_000
        total = total + (i % 7)
        i = i + 1
      end
      puts total
    """,
    "array append and read": """
      items = [] of Int32
      i = 0
      while i < 8_000_000
        items << i
        i = i + 1
      end
      sum = 0_i64
      index = 0
      while index < items.size
        sum = sum + items[index]
        index = index + 1
      end
      puts sum
    """,
    "hash insert and read": """
      counts = {} of Int32 => Int32
      i = 0
      while i < 1_500_000
        counts[i] = i
        i = i + 1
      end
      sum = 0_i64
      key = 0
      while key < 1_500_000
        sum = sum + counts[key]
        key = key + 1
      end
      puts sum
    """,
    "string building": """
      text = ""
      i = 0
      while i < 40_000
        text = text + "x"
        i = i + 1
      end
      puts text.size
    """,
}


def build(source: pathlib.Path, output: pathlib.Path, crystal_library: bool) -> None:
    command = [str(IYI), "build", "--release", "-o", str(output), str(source)]
    if crystal_library:
        command.insert(2, "--crystal")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"build failed for {source.name}:\n{result.stderr[:800]}")


def best(binary: pathlib.Path, collect: bool = True) -> tuple[float, str]:
    # `GC_DONT_GC=1` is libgc's own switch and it is the whole second column:
    # allocation still happens, nothing is ever collected, so what is left is
    # the library's code.
    environment = dict(os.environ)
    if not collect:
        environment["GC_DONT_GC"] = "1"

    fastest = None
    answer = None
    for _ in range(RUNS):
        start = time.perf_counter()
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                env=environment)
        elapsed = time.perf_counter() - start
        if result.returncode != 0:
            raise SystemExit(f"{binary.name} exited {result.returncode}")
        answer = result.stdout.strip()
        fastest = elapsed if fastest is None else min(fastest, elapsed)
    return fastest, answer


def main() -> int:
    if not IYI.exists():
        raise SystemExit("build the compiler first: make iyi release=1")

    print("run time, best of %d, seconds. The same program under two libraries." % RUNS)
    print()
    print("  %-24s %17s   %17s" % ("", "as it runs", "with the collector off"))
    print("  %-24s %8s %8s   %8s %8s   %s" %
          ("program", "iyi", "crystal", "iyi", "crystal", "library"))
    print("  " + "-" * 74)

    refused = 0
    with tempfile.TemporaryDirectory() as work:
        directory = pathlib.Path(work)
        for name, body in PROGRAMS.items():
            source = directory / (name.replace(" ", "_") + ".iyi")
            lines = [line[6:] if line.startswith("      ") else line
                     for line in body.strip("\n").split("\n")]
            source.write_text("module bench\n\n" + "\n".join(lines) + "\n")

            own = directory / (source.stem + "-iyi")
            theirs = directory / (source.stem + "-crystal")
            build(source, own, crystal_library=False)
            build(source, theirs, crystal_library=True)

            own_time, own_answer = best(own)
            their_time, their_answer = best(theirs)
            own_bare, _ = best(own, collect=False)
            their_bare, _ = best(theirs, collect=False)

            # Both libraries have to compute the same thing, or the row is a
            # comparison of two different programs.
            if own_answer != their_answer:
                print("  %-24s refused: %s vs %s" % (name, own_answer, their_answer))
                refused += 1
                continue

            ratio = own_bare / their_bare if their_bare else 0.0
            print("  %-24s %8.3f %8.3f   %8.3f %8.3f   %.2fx" %
                  (name, own_time, their_time, own_bare, their_bare, ratio))

    print()
    print("  The last column is the honest one: under 1.00 is iyi's library being")
    print("  faster with the collector out of the way. The difference between the")
    print("  two pairs is what carrying a standard library costs at collection")
    print("  time, which is a real cost and a different claim.")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
