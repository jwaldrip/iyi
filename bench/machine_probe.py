#!/usr/bin/env python3
"""Three figures that separate "the code got slower" from "the machine did".

Run it twice under the two states worth comparing (on battery and plugged in,
or before and after whatever changed) and read the ratios. The point is which
of the three moves together:

* the loop is pure CPU and nothing else,
* startup is the compiler linking libLLVM and doing no work,
* the front end is the figure the release gate is decided on.

`build_speed.py` divides by startup, and startup is mostly the loader. If the
front end moves and startup does not, the gate is measuring a machine it
cannot see, and it says NOT MET where it means UNDECIDED.
"""
import subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRYSTAL = ROOT / ".build" / "crystal-release"
HELLO = ROOT / "samples" / "iyi" / "hello.iyi"
ENV = {"IYI_PATH": f"lib:{ROOT / 'src'}", "PATH": "/usr/bin:/bin"}


def loop(rounds=5):
    best = None
    for _ in range(rounds):
        start = time.perf_counter()
        total = 0
        for i in range(3_000_000):
            total += i * i
        best = min(best or 1e9, time.perf_counter() - start)
    return best


def timed(argv, rounds=7):
    best = None
    for _ in range(rounds):
        start = time.perf_counter()
        subprocess.run(argv, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        best = min(best or 1e9, time.perf_counter() - start)
    return best


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "unlabelled"
    if not CRYSTAL.exists():
        print(f"needs {CRYSTAL} (make crystal release=1, then cp it there)")
        return 1
    cpu = loop()
    startup = timed([str(CRYSTAL), "--version"])
    front = timed([str(CRYSTAL), "build", "--no-codegen", str(HELLO)])
    print(f"{label:>16}  cpu loop {cpu:.3f} s   startup {startup:.3f} s   "
          f"front end {front:.3f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
