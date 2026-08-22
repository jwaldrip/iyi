#!/usr/bin/env python3
"""What a consumer pays for a shard, from its source and from its boundary.

    make -B iyi release=1
    python3 bench/bind_speed.py

SPEC.md Part V item 12e measured what Crystal's *library* would be worth as an
artifact and answered with a generated module. This asks the same question of
the thing a boundary is actually for — a **shard**, a library the consumer does
not otherwise have — and it asks it end to end: `crystal tool bind` writes the
declarations, an ordinary build of the keep file puts the per-type units in the
artifact, and a program is built against it and run.

The shard is generated rather than borrowed, and the reason is not convenience.
`Kemal` cannot be bound today: its object code numbers
`Array(Radix::Node(...))`, a generic instance from another shard, and a generic
travels as bodies rather than as declarations (IV.2). So a real shard would
measure that gap instead of this question. What is generated here is the shape
the question needs — ordinary types with ordinary methods — and its size is
stated rather than hidden: twenty types of twenty-five methods, 1,627 lines.

Cold and warm are the two numbers that matter and they answer different things.
Cold is what a consumer pays the first time, or on a machine that has never
seen the shard, and it is where an artifact should win: the source arm compiles
the shard, the artifact arm reads declarations and links objects somebody else
compiled. Warm is what it pays on a rebuild, where Crystal's own cache has
already done most of that work — an artifact cannot beat a cache at being a
cache, and saying so is the point of measuring both.

Each build edits the consumer first, because a build of an unedited program
skips codegen and would measure neither arm. The arms alternate, so a clock
step lands on both.
"""

import os
import pathlib
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
IYI = ROOT / ".build" / "iyi"
CRYSTAL = ROOT / ".build" / "crystal"

TYPES, METHODS = 20, 25
PAIRS = 5

# The sweep, because the first answer this produced was "nothing" and the
# useful question under it is *how big a shard has to be* before its boundary
# pays. Both arms compile Crystal's library, so a small shard is noise beside
# it; 12e's own measurement was of a 103,002-line library.
SIZES = ((20, 25), (60, 40), (120, 60))


def check_release(binary: pathlib.Path) -> None:
    if not binary.exists():
        sys.exit(f"needs {binary} (make -B iyi crystal release=1)")
    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True).stdout
    if "not built in release mode" in out:
        sys.exit(f"{binary} is not an optimised build. Force it:\n  make -B iyi crystal release=1")


def write_shard(directory: pathlib.Path, types: int, methods: int) -> None:
    TYPES, METHODS = types, methods
    lines = ["module Shard", "  extend self", ""]
    for part in range(TYPES):
        lines += [f"  class Part{part}", "    @seed : Int32", "",
                  "    def initialize(@seed : Int32)", "    end", ""]
        for step in range(METHODS):
            lines += [f"    def step{step}(n : Int32) : Int32",
                      f"      (n + @seed + {step}) % 1000", "    end", ""]
        lines += ["  end", ""]
    lines += ["  def make(seed : Int32) : Part0", "    Part0.new(seed)", "  end", "end"]
    (directory / "shard.cr").write_text("\n".join(lines) + "\n")
    (directory / "entry.cr").write_text('require "./shard"\n')


def write_consumer(directory: pathlib.Path, arm: str, run: int,
                   types: int, methods: int) -> pathlib.Path:
    """The same program either way, differing only in how it reaches the shard.

    It calls *all* of the shard, and the first version of this called one method
    — which measured nothing. Codegen is demand-driven: a consumer that reaches
    one method has the compiler emit one, so a 30,000-line shard cost the same
    as a 2,000-line one and the boundary had nothing to save. What a boundary
    saves is compiling the code somebody uses, so a benchmark that uses none of
    it is measuring its own consumer.
    """
    reach = 'require "./shard"' if arm == "source" else "import shard"
    lines = [f"module main", "", reach, "", f"total = {run % 97}"]
    for part in range(types):
        lines.append(f"p{part} = Shard::Part{part}.new(total)")
        for step in range(methods):
            lines.append(f"total = p{part}.step{step}(total)")
    lines.append("puts total")
    path = directory / f"app_{arm}.iyi"
    path.write_text("\n".join(lines) + "\n")
    return path


def environment(directory: pathlib.Path, cache: pathlib.Path) -> dict:
    return {**os.environ,
            "CRYSTAL_PATH": str(ROOT / "src"),
            "CRYSTAL_CACHE_DIR": str(cache)}


def build(directory: pathlib.Path, arm: str, run: int, cache: pathlib.Path,
          types: int, methods: int) -> float:
    source = write_consumer(directory, arm, run, types, methods)
    command = [str(IYI), "build", "--crystal"]
    if arm == "artifact":
        command += ["--use-iyimod", "mods"]
    command += ["-o", f"out_{arm}", str(source.name)]

    start = time.monotonic()
    result = subprocess.run(command, cwd=directory, env=environment(directory, cache),
                            capture_output=True, text=True)
    elapsed = time.monotonic() - start
    if result.returncode != 0:
        sys.exit(f"{arm} build failed:\n{result.stdout}\n{result.stderr}")
    return elapsed


def bind(directory: pathlib.Path, cache: pathlib.Path) -> None:
    mods = directory / "mods"
    mods.mkdir(exist_ok=True)
    env = environment(directory, cache)

    result = subprocess.run(
        [str(CRYSTAL), "tool", "bind", "-e", "Shard", "--emit-bind", "mods", "entry.cr"],
        cwd=directory, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"bind failed:\n{result.stdout}\n{result.stderr}")

    # An ordinary build of the keep file: that is where the per-type units are,
    # and `--emit-bind` puts the ones this namespace owns into the artifact.
    result = subprocess.run(
        [str(CRYSTAL), "build", "--iyi-keep", "Shard", "--emit-bind", ".",
         "-o", "keepbin", "shard_keep.cr"],
        cwd=mods, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"filling the artifact failed:\n{result.stdout}\n{result.stderr}")
    print("  " + result.stdout.strip().splitlines()[-1])


def measure(directory: pathlib.Path, cold: bool, types: int, methods: int) -> dict:
    cache = directory / "cache"
    timings = {"source": [], "artifact": []}
    for pair in range(PAIRS):
        for arm in ("source", "artifact"):  # alternating, so a clock step hits both
            if cold:
                shutil.rmtree(cache, ignore_errors=True)
            cache.mkdir(exist_ok=True)
            timings[arm].append(build(directory, arm, pair * 2 + 1, cache, types, methods))

    return timings


def report(title: str, timings: dict) -> None:
    print()
    print(f"  {title}")
    for arm in ("source", "artifact"):
        runs = timings[arm]
        print(f"    {arm:<9} min {min(runs):6.2f} s   median {statistics.median(runs):6.2f} s")
    saved = min(timings["source"]) - min(timings["artifact"])
    share = saved / min(timings["source"]) * 100
    print(f"    on the minimum, the boundary {'saves' if saved > 0 else 'costs'} "
          f"{abs(saved):.2f} s ({abs(share):.0f}%)")


def main() -> int:
    check_release(IYI)
    check_release(CRYSTAL)

    with tempfile.TemporaryDirectory(prefix="bind-speed-") as raw:
        for types, methods in SIZES:
            directory = pathlib.Path(raw) / f"s{types}x{methods}"
            directory.mkdir()
            write_shard(directory, types, methods)
            lines = len((directory / "shard.cr").read_text().splitlines())
            print()
            print(f"=== {types} types x {methods} methods, {lines} lines ===")
            (directory / "cache").mkdir()
            bind(directory, directory / "cache")
            cold = measure(directory, cold=True, types=types, methods=methods)
            report("cold", cold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
