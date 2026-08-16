#!/usr/bin/env python3
"""What editing one module costs, in iyi and in Go.

`build_speed.py` times builds of a whole program. That is the number a first
release is judged on and it is not the number this language exists for. R-1
says a module compiles against its imports' *declarations*: the payoff is not
the first build, it is the second one, after you change a line.

Go is the column to stand next to, because Go answers the same question with
packages and answers it well. Both projects here come out of one generator
(`bench/incremental/generate_project.py`) and print the same number, checked
before anything is timed and again after the edits.

Three columns, because two of the comparisons matter and they are different
questions. **Go** is the language that does this well and the one to stand next
to. **Crystal** is the language this is a fork of, compiled here by the same
binary: it has no unit of compilation smaller than the program, because a class
is open until the last line of the last file, and that is the thing SPEC.md's
rules exist to make untrue.

What is measured, for each language:

* **cold**       nothing cached anywhere. iyi gets a fresh `CRYSTAL_CACHE_DIR`,
                 Go a fresh `GOCACHE`.
* **warm**       the same build again, nothing edited.
* **one module** a constant inside one module's method body changes, and the
                 program is built again. This is the loop a person is actually
                 in, and the one R-1 is about.
* **main only**  the entry file changes and no module does.

The iyi rebuild is `--use-iyimod DIR --emit-iyimod DIR`: read every module's
artifact, compile the ones whose source moved, write their artifacts back.
That is what SPEC.md IV.3 calls the incremental loop, and this is the first
thing in this repository to put a number on it.

Run it after `make crystal release=1`; a debug compiler is about 1.5x and only
one of the two columns pays it.

    python3 bench/incremental.py
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "incremental"))
from generate_project import write_project  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRYSTAL = ROOT / ".build" / "crystal"
WRAPPER = ROOT / "bin" / "crystal"

# Enough to find a floor without the run costing a coffee: each sample is a
# whole build, and the edited-module ones are the point of the exercise.
RUNS = 7

# What the edited line is set to, cycled so that every sample is a real change
# rather than a rewrite of the same bytes. A build that rewrote identical text
# would measure nothing, which is a mistake this bench has already made once.
# The generator puts one `edit_point` in each module for this to land on, and
# nothing else in the file looks like it.
CONSTANTS = [3, 4, 5, 6, 7, 8]


def compiler_env():
    """The environment `bin/crystal` would have set, asked for once."""
    result = subprocess.run(
        [str(WRAPPER), "env", "CRYSTAL_PATH", "CRYSTAL_LIBRARY_PATH"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    env = {}
    if result.returncode == 0:
        lines = result.stdout.decode().split()
        if len(lines) > 0:
            env["CRYSTAL_PATH"] = lines[0]
        if len(lines) > 1:
            env["CRYSTAL_LIBRARY_PATH"] = lines[1]
    else:
        env["CRYSTAL_PATH"] = f"lib:{ROOT / 'src'}"
    return env


CRYSTAL_ENV = compiler_env()


def run(argv, cwd, env=None):
    full = dict(os.environ)
    full.update(env or {})
    return subprocess.run(argv, cwd=cwd, env=full,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def timed(argv, cwd, env=None, before=None):
    """Seconds for one build, with *before* run outside the clock."""
    if before:
        before()
    start = time.perf_counter()
    result = run(argv, cwd, env)
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        print(result.stdout.decode()[-2000:])
        raise SystemExit(f"build failed: {' '.join(argv)}")
    return elapsed


def best(samples):
    return min(samples) if samples else None


def show(value):
    return "   —" if value is None else f"{value:6.2f}"


class Iyi:
    name = "iyi"

    def __init__(self, root, cache):
        self.root, self.cache = root, cache
        self.main = root / "main.iyi"
        self.part = root / "parts" / "mod0.iyi"
        self.mods = root / "mods"

    def env(self):
        return dict(CRYSTAL_ENV, CRYSTAL_CACHE_DIR=str(self.cache))

    def full(self):
        return [str(CRYSTAL), "build", "--emit-iyimod", str(self.mods),
                "-o", "out", "main.iyi"]

    def incremental(self):
        return [str(CRYSTAL), "build", "--use-iyimod", str(self.mods),
                "--emit-iyimod", str(self.mods), "-o", "out", "main.iyi"]

    def clear_cache(self):
        shutil.rmtree(self.cache, ignore_errors=True)
        shutil.rmtree(self.mods, ignore_errors=True)

    def edit_module(self, constant):
        text = re.sub(r"edit_point = \d+", f"edit_point = {constant}",
                      self.part.read_text(), count=1)
        self.part.write_text(text)

    def edit_main(self, index):
        text = self.main.read_text()
        marker = "# edit "
        text = "\n".join(line for line in text.splitlines() if not line.startswith(marker))
        self.main.write_text(text + f"\n{marker}{index}\n")

    def output(self):
        return run(["./out"], self.root).stdout.decode().strip()


class Crystal:
    """The same program as Crystal compiles it, with the same binary.

    This is the comparison the fork is actually about. Crystal has no unit of
    compilation smaller than the program: every build reads every file and
    analyses all of it, because a class is open until the last line of the last
    file. The rules in SPEC.md exist to make that untrue, and this column is
    what they are worth.
    """

    name = "crystal"

    def __init__(self, root, cache):
        self.root, self.cache = root, cache
        self.main = root / "main.cr"
        self.part = root / "parts" / "mod0.cr"

    def env(self):
        return dict(CRYSTAL_ENV, CRYSTAL_CACHE_DIR=str(self.cache))

    def full(self):
        return [str(CRYSTAL), "build", "-o", "out", "main.cr"]

    incremental = full

    def clear_cache(self):
        shutil.rmtree(self.cache, ignore_errors=True)

    def edit_module(self, constant):
        text = re.sub(r"edit_point = \d+", f"edit_point = {constant}",
                      self.part.read_text(), count=1)
        self.part.write_text(text)

    def edit_main(self, index):
        text = self.main.read_text()
        marker = "# edit "
        text = "\n".join(line for line in text.splitlines() if not line.startswith(marker))
        self.main.write_text(text + f"\n{marker}{index}\n")

    def output(self):
        return run(["./out"], self.root).stdout.decode().strip()


class Go:
    name = "go build"

    def __init__(self, root, cache):
        self.root, self.cache = root, cache
        self.main = root / "main.go"
        self.part = root / "parts" / "mod0" / "mod0.go"

    def env(self):
        return {"GOCACHE": str(self.cache), "GOFLAGS": "-mod=mod"}

    def full(self):
        return ["go", "build", "-o", "out", "."]

    incremental = full

    def clear_cache(self):
        shutil.rmtree(self.cache, ignore_errors=True)

    def edit_module(self, constant):
        text = re.sub(r"var editPoint int32 = \d+",
                      f"var editPoint int32 = {constant}",
                      self.part.read_text(), count=1)
        self.part.write_text(text)

    def edit_main(self, index):
        text = self.main.read_text()
        marker = "// edit "
        text = "\n".join(line for line in text.splitlines() if not line.startswith(marker))
        self.main.write_text(text + f"\n{marker}{index}\n")

    def output(self):
        return run(["./out"], self.root).stdout.decode().strip()


def measure(lang):
    """Cold, warm, one edited module, edited main. Seconds, best of RUNS."""
    figures = {}

    lang.clear_cache()
    figures["cold"] = timed(lang.full(), lang.root, lang.env())
    figures["warm"] = best([timed(lang.incremental(), lang.root, lang.env())
                            for _ in range(RUNS)])

    samples = []
    for index in range(RUNS):
        constant = CONSTANTS[index % len(CONSTANTS)]
        samples.append(timed(lang.incremental(), lang.root, lang.env(),
                             before=lambda c=constant: lang.edit_module(c)))
    figures["module"] = best(samples)

    samples = []
    for index in range(RUNS):
        samples.append(timed(lang.incremental(), lang.root, lang.env(),
                             before=lambda i=index: lang.edit_main(i)))
    figures["main"] = best(samples)

    # iyi only, and the row the artifact is for: the same edit, built the way a
    # build with no artifacts has to build it — every module's source read and
    # analysed again. The difference between this and the row above is what R-1
    # buys on the loop, rather than on a cold build.
    if isinstance(lang, Iyi):
        samples = []
        for index in range(RUNS):
            constant = CONSTANTS[index % len(CONSTANTS)]
            samples.append(timed(lang.full(), lang.root, lang.env(),
                                 before=lambda c=constant: lang.edit_module(c)))
        figures["module_from_source"] = best(samples)
    return figures


def main():
    if not CRYSTAL.exists():
        print(f"needs {CRYSTAL}: run `make crystal release=1` first")
        return 1
    if shutil.which("go") is None:
        print("needs `go` on PATH: this bench is a comparison, not a figure")
        return 1

    work = pathlib.Path(tempfile.mkdtemp(prefix="iyi-incremental-"))
    iyi_root, go_root, crystal_root = write_project(work)
    iyi = Iyi(iyi_root, work / "cache")
    crystal = Crystal(crystal_root, work / "crystal-cache")
    go = Go(go_root, work / "gocache")
    languages = (iyi, crystal, go)

    # One program, or nothing here means anything.
    for lang in languages:
        lang.clear_cache()
        timed(lang.full(), lang.root, lang.env())
    printed = {lang.name: lang.output() for lang in languages}
    if len(set(printed.values())) != 1:
        print(f"the programs printed {printed}")
        return 1
    agreed = printed[iyi.name]

    figures = {lang.name: measure(lang) for lang in languages}

    # All three were edited the same way; they still have to agree.
    for lang in languages:
        lang.edit_module(3)
        timed(lang.incremental(), lang.root, lang.env())
    same_after = len({lang.output() for lang in languages}) == 1

    lines = sum(len(p.read_text().splitlines()) for p in iyi_root.rglob("*.iyi"))
    print()
    print(f"the edit loop — best of {RUNS}, seconds")
    print()
    print(f"  30 modules, 300 types, {lines} lines, all three printing {agreed}")
    print(f"  after the same edit, all three print the same thing: "
          f"{'yes' if same_after else 'NO — nothing below counts'}")
    print()
    print("  what changed                        iyi    crystal   go build")
    print("  " + "-" * 58)
    for key, label in (("cold", "nothing cached anywhere"),
                       ("warm", "nothing at all"),
                       ("module", "one module's body"),
                       ("main", "the entry file only")):
        print(f"  {label:32}{show(figures['iyi'][key])}"
              f"     {show(figures['crystal'][key])}     {show(figures['go build'][key])}")
    print("  " + "-" * 58)
    print(f"  {'the same edit, no artifacts':32}"
          f"{show(figures['iyi']['module_from_source'])}          —          —")
    print("  (what R-1 buys on the loop is the difference between that row and")
    print("   `one module's body`: every other module read as declarations")
    print("   instead of source)")
    print()
    print(f"  workdir {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
