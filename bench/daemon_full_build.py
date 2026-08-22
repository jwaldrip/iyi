#!/usr/bin/env python3
"""What the daemon takes off a *whole* build, link included.

    make -B iyi iyi-daemon release=1
    python3 bench/daemon_full_build.py

SPEC.md IV.1d publishes the daemon's effect on the front end and says of the
rest: "Full-build timings on this machine were too noisy to publish." This is
the harness that sentence was missing. It exists so the claim is a command
somebody can run rather than a thing somebody remembers measuring.

Three corrections IV.1d had to make are built in here, because each of them
flattered the daemon and none was about the compiler:

* **A release compiler.** An unoptimised one spends about three times as long
  in prelude analysis, which is the term the daemon removes, so every saving
  measured through one is about three times too large. This refuses to run
  unless both binaries say they are optimised.
* **An edit before every build.** Crystal caches generated objects per program,
  so building the same unedited file twice skips codegen from the second run
  on — leaving the front end as most of what is measured, which is exactly what
  the daemon accelerates. Every build here edits a module first.
* **Alternating arms.** A block of measurements of one arm can sit inside a
  clock step and come out uniformly wrong; alternating is what makes a step hit
  both. The arms alternate, and the pairs are reported as well as the totals so
  a step is visible rather than averaged away.

What is *not* controlled for is the machine being otherwise busy. The figure
reported is the minimum of the runs, which is the usual answer to that: build
time has a floor and noise only ever adds.
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
DAEMON = ROOT / ".build" / "iyi-daemon"

MODULES = 12
PAIRS = 8


def check_release(binary: pathlib.Path) -> None:
    if not binary.exists():
        sys.exit(f"needs {binary} (make -B iyi iyi-daemon release=1)")
    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True).stdout
    if "not built in release mode" in out:
        sys.exit(
            f"{binary} is not an optimised build, and an unoptimised one spends about\n"
            f"three times as long in the term the daemon removes. Force it:\n"
            f"  make -B iyi iyi-daemon release=1"
        )


def write_project(directory: pathlib.Path) -> pathlib.Path:
    """Twelve modules and a main that calls into every one of them."""
    parts = directory / "parts"
    parts.mkdir(parents=True, exist_ok=True)
    for index in range(MODULES):
        (parts / f"mod{index}.iyi").write_text(
            f"module parts/mod{index}\n"
            f"\n"
            f"pub def value{index}(n : Int32) : Int32\n"
            f"  n + {index}\n"
            f"end\n"
        )

    lines = ["module app", ""]
    lines += [f"import parts/mod{index}" for index in range(MODULES)]
    lines.append("")
    lines.append("total = 0")
    for index in range(MODULES):
        lines.append(f"total = total + Parts::Mod{index}.value{index}(total)")
    lines.append("puts total")
    main = directory / "app.iyi"
    main.write_text("\n".join(lines) + "\n")
    return main


def edit(directory: pathlib.Path, run: int) -> None:
    """A change in one module, so codegen is not skipped."""
    index = run % MODULES
    (directory / "parts" / f"mod{index}.iyi").write_text(
        f"module parts/mod{index}\n"
        f"\n"
        f"pub def value{index}(n : Int32) : Int32\n"
        f"  n + {index} + 0  # edit {run}\n"
        f"end\n"
    )


def build(main: pathlib.Path, directory: pathlib.Path, output: pathlib.Path,
          socket: str | None) -> float:
    environment = dict(os.environ)
    environment["CRYSTAL_PATH"] = f"lib:{ROOT / 'src'}"
    if socket:
        environment["CRYSTAL_DAEMON_SOCKET"] = socket
    else:
        environment.pop("CRYSTAL_DAEMON_SOCKET", None)

    start = time.monotonic()
    result = subprocess.run(
        [str(IYI), "build", "--crystal", "-o", str(output), str(main)],
        cwd=directory, env=environment, capture_output=True, text=True,
    )
    elapsed = time.monotonic() - start
    if result.returncode != 0:
        sys.exit(f"build failed:\n{result.stdout}\n{result.stderr}")
    return elapsed


def main() -> int:
    check_release(IYI)
    check_release(DAEMON)

    with tempfile.TemporaryDirectory(prefix="daemon-full-build-") as raw:
        directory = pathlib.Path(raw)
        main_file = write_project(directory)
        socket = str(directory / "daemon.sock")

        server = subprocess.Popen(
            [str(DAEMON), "daemon", "start", "--socket", socket],
            cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "CRYSTAL_PATH": f"lib:{ROOT / 'src'}"},
        )
        try:
            for _ in range(100):
                if pathlib.Path(socket).exists():
                    break
                time.sleep(0.1)
            else:
                sys.exit("the daemon never created its socket")

            # One build through each arm before timing, so neither is paying for
            # a cold object cache the other already warmed.
            edit(directory, 0)
            build(main_file, directory, directory / "warm", None)
            build(main_file, directory, directory / "warm", socket)

            plain, served = [], []
            for pair in range(PAIRS):
                edit(directory, pair * 2 + 1)
                plain.append(build(main_file, directory, directory / "out", None))
                edit(directory, pair * 2 + 2)
                served.append(build(main_file, directory, directory / "out", socket))
                print(f"  pair {pair + 1:>2}   normal {plain[-1]:5.2f} s   "
                      f"daemon {served[-1]:5.2f} s")
        finally:
            server.terminate()
            server.wait(timeout=10)

    print()
    print(f"  {MODULES} modules, --crystal, full build with codegen and link")
    print(f"  {PAIRS} alternating pairs, a module edited before every build")
    print()
    for name, runs in (("normal", plain), ("daemon", served)):
        print(f"  {name:<7} min {min(runs):5.2f} s   median {statistics.median(runs):5.2f} s   "
              f"max {max(runs):5.2f} s")
    print()
    print(f"  on the minimum, the daemon takes off {min(plain) - min(served):.2f} s "
          f"({(1 - min(served) / min(plain)) * 100:.0f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
