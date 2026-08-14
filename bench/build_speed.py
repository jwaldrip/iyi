#!/usr/bin/env python3
"""Build speed — the number SPEC.md's 0.1.0 section exists to produce.

    python3 bench/build_speed.py

The claim iyi is built around is compile speed against Go, and it is the one
claim the project had no committed harness for. This is that harness, and it is
also the release gate: it exits non-zero while the front-end target is unmet,
so "0.1.0 is ready" is a command that passes rather than a judgement.

What is measured
----------------

* **front end** — `crystal build --no-codegen`. Parse and semantic analysis,
  no LLVM. This is the number `.iyimod` (Part IV) and prelude-skipping passes
  (IV.1d) move, and the one the target is set on.
* **end to end** — `crystal build`. Reported even though LLVM and the linker
  dominate it, so the claim cannot quietly become a front-end-only claim.
* **go build** — the same program in Go, timed here rather than quoted. This
  document is not entitled to a Go number it did not measure.

Cold and warm mean an empty and a reused compiler cache. Both compilers are
pointed at a temporary cache directory, so neither the user's `~/.cache/crystal`
nor their `GOCACHE` is touched or warmed by this.

Each figure is the **best** of N runs, not the mean: build time has a floor and
noise only ever adds, so the minimum is the better estimate of the floor.

Limits, stated because they bound the result
--------------------------------------------

* **The compiler is timed as a binary**, not through `bin/crystal`. See the
  comment on `CRYSTAL` below for why, and subtract nothing: the earlier runs
  recorded in SPEC.md were timed through the wrapper and carry its 30 ms.
* **The corpus is one program.** `hello` is the only pair where "the equivalent
  Go program" is unambiguous, and iyi has no larger program to offer: its
  samples explain rules rather than do work. `webapp.iyi` is timed too, but
  for iyi alone — its Kemal-shaped router against Go's `net/http` would compare
  three small files with a large precompiled stdlib package, which is not a
  like-for-like build.
* A `hello` comparison measures the fixed cost of a build and nothing about how
  either compiler scales. That is deliberate: IV.1d found user code stays nearly
  free until a program is large, so the fixed cost *is* what small frequent
  builds pay, and it is where build-speed complaints come from.
* Wall clock on one machine. Nothing here is portable between machines; the
  point is the ratio in one column against another, measured together.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The compiler binary, not `bin/crystal`.
#
# `bin/crystal` is development scaffolding: a POSIX-sh script that resolves
# symlinks with recursive shell functions, shells out to `uname` and `readlink`,
# warns which compiler it found, and then `exec`s this binary. It costs **30 ms**
# — half of what the front end costs now — and no released compiler would ship
# it. `go build` is timed as a bare binary, so timing iyi through a shell
# wrapper measures this repository's ergonomics against Go's compiler.
#
# It was worth timing while the front end cost 1.3 s and the wrapper was 2% of
# it. At 0.03 s it is not.
CRYSTAL = ROOT / ".build" / "crystal"
WRAPPER = ROOT / "bin" / "crystal"

# SPEC.md 0.1.0, "Done is a number": IV.1a already ran a front end that never
# walks the prelude at 0.049 s and emitted an object with an identical symbol
# table. The target is to make that configuration the ordinary one.
FRONT_END_TARGET = 0.05

RUNS = 3


def compiler_env():
    """The environment `bin/crystal` would have set, asked for once.

    The wrapper is what knows where this checkout's sources and its `libgc`
    are. Asking it once and passing the answer to the binary is the same build
    the wrapper would have run, without paying for the shell on every one.
    """
    result = subprocess.run(
        [str(WRAPPER), "env", "CRYSTAL_PATH", "CRYSTAL_LIBRARY_PATH"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return {"CRYSTAL_PATH": f"lib:{ROOT / 'src'}"}

    lines = result.stdout.decode().split()
    env = {}
    if len(lines) > 0:
        env["CRYSTAL_PATH"] = lines[0]
    if len(lines) > 1:
        env["CRYSTAL_LIBRARY_PATH"] = lines[1]
    return env


CRYSTAL_ENV = {}


def best(runs, fn):
    """Best of `runs`, or None if the command failed."""
    times = []
    for _ in range(runs):
        started = time.monotonic()
        ok = fn()
        elapsed = time.monotonic() - started
        if not ok:
            return None
        times.append(elapsed)
    return min(times)


def run(argv, env=None, cwd=None):
    full = dict(os.environ)
    full.update(env or {})
    result = subprocess.run(
        argv, env=full, cwd=cwd,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
    return result.returncode == 0


def time_crystal(source, out_dir, codegen, cold):
    """Time one `crystal build`, in a cache directory this bench owns."""
    cache = out_dir / ("cache_cold" if cold else "cache_warm")

    def once():
        if cold and cache.exists():
            shutil.rmtree(cache)
        cache.mkdir(parents=True, exist_ok=True)
        argv = [str(CRYSTAL), "build", "-o", str(out_dir / "out")]
        if not codegen:
            argv.append("--no-codegen")
        argv.append(str(source))
        env = dict(CRYSTAL_ENV)
        env["CRYSTAL_CACHE_DIR"] = str(cache)
        return run(argv, env=env)

    if not cold:
        # Warm means the second build onward, so pay for the first here.
        cache.mkdir(parents=True, exist_ok=True)
        once()
    return best(RUNS, once)


def time_go(source, out_dir, cold):
    if shutil.which("go") is None:
        return None
    cache = out_dir / ("gocache_cold" if cold else "gocache_warm")

    def once():
        if cold and cache.exists():
            shutil.rmtree(cache)
        cache.mkdir(parents=True, exist_ok=True)
        return run(
            ["go", "build", "-o", str(out_dir / "hello_go"), source.name],
            env={"GOCACHE": str(cache), "GOFLAGS": "-mod=mod"},
            cwd=str(source.parent),
        )

    if not cold:
        cache.mkdir(parents=True, exist_ok=True)
        once()
    return best(RUNS, once)


def show(value):
    return "     —" if value is None else f"{value:6.2f}"


def main():
    if not CRYSTAL.exists():
        sys.exit(f"no compiler at {CRYSTAL} — run `make crystal` first")

    CRYSTAL_ENV.update(compiler_env())

    hello_iyi = ROOT / "samples" / "iyi" / "hello.iyi"
    webapp_iyi = ROOT / "samples" / "iyi" / "webapp.iyi"
    hello_go = ROOT / "bench" / "build_speed" / "hello.go"

    with tempfile.TemporaryDirectory(prefix="iyi-build-speed-") as tmp:
        out = pathlib.Path(tmp)

        front_hello = time_crystal(hello_iyi, out, codegen=False, cold=True)
        front_webapp = time_crystal(webapp_iyi, out, codegen=False, cold=True)
        e2e_cold = time_crystal(hello_iyi, out, codegen=True, cold=True)
        e2e_warm = time_crystal(hello_iyi, out, codegen=True, cold=False)
        go_cold = time_go(hello_go, out, cold=True)
        go_warm = time_go(hello_go, out, cold=False)

    print()
    print("build speed — best of", RUNS, "runs, seconds")
    print()
    print("  program        stage                        cold    warm")
    print("  " + "-" * 56)
    print(f"  hello.iyi      front end (--no-codegen)   {show(front_hello)}       —")
    print(f"  hello.iyi      end to end                 {show(e2e_cold)}  {show(e2e_warm)}")
    print(f"  hello.go       go build                   {show(go_cold)}  {show(go_warm)}")
    print("  " + "-" * 56)
    print(f"  webapp.iyi     front end (iyi only)       {show(front_webapp)}       —")
    print()

    if go_cold is None:
        print("  go was not found, so there is no head-to-head in this run.")
        print()

    if front_hello is None:
        sys.exit("front end did not build; nothing to check against the target")

    print(f"  front-end target (SPEC.md 0.1.0): {FRONT_END_TARGET:.3f} s")
    print(f"  measured:                         {front_hello:.3f} s")
    if front_hello <= FRONT_END_TARGET:
        print("  MET.")
        print()
        return 0

    print(f"  NOT MET — {front_hello / FRONT_END_TARGET:.1f}x over.")
    print()
    print("  The prelude is iyi's own now (0.1.0 item 3), which is what took")
    print("  this from 26x over to here. What is left is that its 833 lines are")
    print("  still analysed from source on every build: `.iyimod` carries a")
    print("  module's declarations and the prelude is now a module small enough")
    print("  to be one (item 1), and the passes that re-walk it are item 2.")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
