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

* **cold**       nothing cached anywhere. iyi gets a fresh `IYI_CACHE_DIR`,
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
# iyi: asked for paths, so it has to be the surface that knows them by the
# names below — `crystal env IYI_PATH` prints an empty line and exits 0.
WRAPPER = ROOT / "bin" / "iyi"

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
    """The environment the `iyi` wrapper would have set, asked for once.

    The answer is checked rather than the exit status. `env` prints an empty
    line for a name it does not know and exits 0, so asking the other command
    surface — which answers in `CRYSTAL_*` — returned "" twice and left the
    compiler with no search path at all. Every build here then failed with
    `can't find file 'iyi/prelude'`, which is the whole bench.
    """
    result = subprocess.run(
        [str(WRAPPER), "env", "IYI_PATH", "IYI_LIBRARY_PATH"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    lines = result.stdout.decode().split() if result.returncode == 0 else []

    if not lines or not lines[0]:
        fallback = f"lib:{ROOT / 'src'}"
        print(f"  note: {WRAPPER.name} did not answer IYI_PATH; using {fallback}",
              file=sys.stderr)
        return {"IYI_PATH": fallback}

    env = {"IYI_PATH": lines[0]}
    if len(lines) > 1 and lines[1]:
        env["IYI_LIBRARY_PATH"] = lines[1]
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
        return dict(CRYSTAL_ENV, IYI_CACHE_DIR=str(self.cache))

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
        return dict(CRYSTAL_ENV, IYI_CACHE_DIR=str(self.cache))

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


# What starting the compiler and doing nothing costs on the machine the
# published figures were measured on. `build_speed.py` divides by the same
# number and refuses to decide its target when the machine is more than 15%
# off it; this bench compares three columns that all pay the machine equally,
# so a slow session does not invalidate the comparison — only the seconds.
# It says which it is rather than leaving a reader to assume.
STARTUP_BASELINE = 0.018
SLOW = 1.15


def startup_cost(rounds = 5):
    best = None
    for _ in range(rounds):
        start = time.perf_counter()
        subprocess.run([str(CRYSTAL), "--version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        best = min(best or 1e9, time.perf_counter() - start)
    return best


def compiler_build():
    """The compiler's version line, and whether it was built in release mode.

    `build_speed.py` asks this because its figure decides a release gate. This
    one asks because a debug compiler reads this table as iyi 0.26 s against
    Crystal's 4.27 s, where a release one reads 0.17 s against 1.24 s: both
    columns are the same binary, so a debug build flatters iyi by a factor it
    did not earn. Which is a mistake made here once, with the numbers already
    written down somewhere else.
    """
    result = subprocess.run([str(CRYSTAL), "--version"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    text = result.stdout.decode("utf-8", "replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return (lines[0] if lines else "unknown"), "not built in release mode" not in text


# The same run, drawn as what it feels like: three builds starting together and
# finishing when they finish. Real time, so the bar that crawls is crawling at
# the speed a person waits at. Written by `--svg`, and the only thing here
# that is not measured is the terminal around it.
def write_svg_animated(path, figures, names, lines):
    row = "module"
    runs = [(name, figures[name][row]) for name in names if figures[name].get(row)]
    if not runs:
        return
    # The commands as the bench runs them, with iyi's artifact flags elided
    # rather than dropped: `…` is `--use-iyimod mods --emit-iyimod mods`, and a
    # picture that hid them would be claiming an ergonomics this does not have.
    shown = {"iyi": ("iyi build … -o app main.iyi", "#3fb950"),
             "crystal": ("crystal build -o app main.cr", "#d29922"),
             "go build": ("go build -o app .", "#58a6ff")}
    slowest = max(seconds for _, seconds in runs)
    start, hold, loop = 0.45, 1.15, 0.45 + max(seconds for _, seconds in runs) + 1.15
    left, top, step, bar_left, bar_max, height = 26, 76, 34, 400, 250, 15
    width, tall = bar_left + bar_max + 92, top + step * len(runs) + 26

    css, body = [], []
    for index, (name, seconds) in enumerate(runs):
        label, colour = shown.get(name, (name, "#8c959f"))
        y = top + index * step
        length = max(8, round(bar_max * seconds / slowest))
        pct_start = 100 * start / loop
        pct_done = 100 * (start + seconds) / loop
        css.append(f"""
    @keyframes fill{index} {{
      0%, {pct_start:.2f}% {{ transform: scaleX(0); }}
      {pct_done:.2f}%, 100% {{ transform: scaleX(1); }}
    }}
    @keyframes show{index} {{
      0%, {pct_done:.2f}% {{ opacity: 0; }}
      {min(pct_done + 1, 100):.2f}%, 100% {{ opacity: 1; }}
    }}
    .bar{index} {{ transform-origin: {bar_left}px 0; animation: fill{index} {loop:.2f}s linear infinite; }}
    .time{index} {{ animation: show{index} {loop:.2f}s linear infinite; }}""")
        body.append(
            f'<text x="{left}" y="{y + 12}" class="cmd"><tspan class="prompt">$ </tspan>{label}</text>'
            f'<rect x="{bar_left}" y="{y}" width="{bar_max}" height="{height}" rx="3" class="track"/>'
            f'<rect x="{bar_left}" y="{y}" width="{length}" height="{height}" rx="3" fill="{colour}" class="bar{index}"/>'
            f'<text x="{bar_left + length + 10}" y="{y + 12}" class="time time{index}" fill="{colour}">{seconds:.2f} s</text>')

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {tall}" width="{width}" height="{tall}" role="img" aria-label="{', '.join(f'{n} {v:.2f} seconds' for n, v in runs)} to rebuild after one edit">
  <style>
    :root {{ --fg: #1f2328; --dim: #656d76; --bg: #ffffff; --track: #eaeef2; }}
    @media (prefers-color-scheme: dark) {{
      :root {{ --fg: #e6edf3; --dim: #8d96a0; --bg: #0d1117; --track: #21262d; }}
    }}
    text {{ font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 13px; }}
    .head {{ font-size: 13px; fill: var(--dim); }}
    .cmd {{ fill: var(--fg); }}
    .prompt {{ fill: var(--dim); }}
    .time {{ font-weight: 600; }}
    .track {{ fill: var(--track); }}{''.join(css)}
  </style>
  <rect width="{width}" height="{tall}" rx="8" fill="var(--bg)"/>
  <circle cx="22" cy="24" r="5" fill="#ff5f57"/><circle cx="40" cy="24" r="5" fill="#febc2e"/><circle cx="58" cy="24" r="5" fill="#28c840"/>
  <text x="76" y="28" class="head">one line changed in one of 30 modules, {lines:,} lines</text>
  <text x="{left}" y="58" class="head">rebuilt three ways, at the speed you wait at</text>
  {''.join(body)}
</svg>
"""
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(svg)
    print(f"  wrote {path}")


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

    version, release = compiler_build()
    if not release:
        print()
        print(f"  {version}, and it is a DEBUG build.")
        print()
        print("  Nothing is timed. A debug compiler is about 1.5x on iyi's own")
        print("  column and about 3x on Crystal's, so the table would read as a")
        print("  claim about this language and be a claim about how the binary")
        print("  was built. Build it and run this again:")
        print()
        print("    rm -f .build/crystal && make crystal release=1")
        print()
        return 1

    work = pathlib.Path(tempfile.mkdtemp(prefix="iyi-incremental-"))
    iyi_root, go_root, crystal_root = write_project(work)
    iyi = Iyi(iyi_root, work / "cache")
    crystal = Crystal(crystal_root, work / "crystal-cache")
    go = Go(go_root, work / "gocache")
    languages = [iyi, crystal, go]

    # No daemon column. It was measured — one module edited, 0.18–0.28 s built
    # normally against 0.20–0.24 s through it — and it buys nothing now that
    # the prelude it existed to hold is 1,053 lines (SPEC.md IV.1d).

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
    startup = startup_cost()
    factor = startup / STARTUP_BASELINE
    print(f"  compiler: {version}, release build")
    print(f"  startup:  {startup:.3f} s doing nothing, against a "
          f"{STARTUP_BASELINE:.3f} s baseline — {factor:.2f}x")
    print(f"  30 modules, 300 types, {lines} lines, all three printing {agreed}")
    print(f"  after the same edit, all three print the same thing: "
          f"{'yes' if same_after else 'NO — nothing below counts'}")
    print()
    names = [lang.name for lang in languages]
    header = "  what changed                  " + "".join(f"{name:>14}" for name in names)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for key, label in (("cold", "nothing cached anywhere"),
                       ("warm", "nothing at all"),
                       ("module", "one module's body"),
                       ("main", "the entry file only")):
        row = "".join(f"{show(figures[name][key]):>14}" for name in names)
        print(f"  {label:28}{row}")
    print("  " + "-" * (len(header) - 2))
    blank = "".join(f"{'—':>14}" for _ in names[1:])
    print(f"  {'the same edit, no artifacts':28}"
          f"{show(figures['iyi']['module_from_source']):>14}{blank}")
    print("  (what R-1 buys on the loop is the difference between that row and")
    print("   `one module's body`: every other module read as declarations")
    print("   instead of source)")
    if factor > SLOW:
        print()
        print(f"  This machine starts the compiler {factor:.2f}x slower than the one the")
        print("  published figures came from, so read the columns against each other")
        print("  rather than the seconds against a number somebody else wrote down.")
        print("  All three columns pay the same machine.")
    if "--svg" in sys.argv:
        write_svg_animated(sys.argv[sys.argv.index("--svg") + 1], figures, names, lines)

    print()
    print(f"  workdir {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
