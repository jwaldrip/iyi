#!/usr/bin/env python3
"""What macros cost at compile time — the measurement behind SPEC.md II.10.

    python3 bench/macro_cost.py

Three questions, because "macro cost" turns out to be three different numbers:

  (a) template   — a macro whose body is a `for` that emits a template
  (b) computing  — a macro that does string building and a branch per item
  (c) macro_run  — `{{ run("...") }}`, which compiles and runs another program

Each of (a) and (b) is compared against a hand-written program that is
**identical after expansion**, with every generated method actually called. That
last part is what an earlier attempt at this got wrong: methods nobody calls are
never typed, so the macro was measured producing dead code.

Two things about the method, both learned the hard way:

  * `--prelude=empty`. Against the real prelude the fixed ~1.4 s tax is larger
    than the effect, and the delta is indistinguishable from run-to-run noise.
  * A fresh `CRYSTAL_CACHE_DIR` for (c). Crystal caches the compiled `run`
    script, so every build after the first reuses the binary and reports ~0.
"""
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CRYSTAL = Path(__file__).resolve().parent.parent / "bin" / "crystal"
OUT = Path(tempfile.mkdtemp(prefix="macro_cost."))
RUNS = 9
COLD_RUNS = 3


def build(path, prelude_empty=True, cold=False):
    cmd = [str(CRYSTAL), "build", "--no-codegen"]
    if prelude_empty:
        cmd.append("--prelude=empty")
    cmd.append(str(path))

    if cold:
        cache = tempfile.TemporaryDirectory()
        env = dict(os.environ, CRYSTAL_CACHE_DIR=cache.name)
    else:
        cache, env = None, None

    start = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(OUT))
    elapsed = time.perf_counter() - start
    if cache:
        cache.cleanup()
    if r.returncode != 0:
        sys.exit(f"FAILED {path}:\n{r.stdout}\n{r.stderr}")
    return elapsed


def calls(n):
    # A bare call is enough to type the method, and needs nothing from a prelude.
    return "".join(f"m{i}\n" for i in range(n))


def template_macro(n):
    return (
        "macro gen\n"
        f"  {{% for i in 0...{n} %}}\n"
        "    def m{{i}} : Int32\n"
        "      {{i}}\n"
        "    end\n"
        "  {% end %}\n"
        "end\n\ngen\n\n" + calls(n)
    )


def template_hand(n):
    return "".join(f"def m{i} : Int32\n  {i}\nend\n\n" for i in range(n)) + calls(n)


def computing_macro(n):
    return (
        "macro gen\n"
        f"  {{% for i in 0...{n} %}}\n"
        '    {% name = "m" + i.stringify %}\n'
        "    {% if i % 2 == 0 %}\n"
        "      def {{name.id}} : Int32\n        {{i}}\n      end\n"
        "    {% else %}\n"
        "      def {{name.id}} : Int32\n        {{i * 2}}\n      end\n"
        "    {% end %}\n"
        "  {% end %}\n"
        "end\n\ngen\n\n" + calls(n)
    )


def computing_hand(n):
    body = "".join(
        f"def m{i} : Int32\n  {i if i % 2 == 0 else i * 2}\nend\n\n" for i in range(n)
    )
    return body + calls(n)


def compare(title, make_macro, make_hand, sizes):
    print(f"\n{title}")
    print(f"{'N':>6} {'macro (s)':>11} {'hand (s)':>10} {'ratio':>8} {'delta/method':>14}")
    print("-" * 54)
    for n in sizes:
        mp, hp = OUT / f"m_{n}.cr", OUT / f"h_{n}.cr"
        mp.write_text(make_macro(n))
        hp.write_text(make_hand(n))
        ms, hs = [], []
        for _ in range(RUNS):          # interleaved, so machine drift hits both
            ms.append(build(mp))
            hs.append(build(hp))
        m, h = statistics.median(ms), statistics.median(hs)
        per = ((m - h) / n * 1e6) if n else 0.0
        print(f"{n:>6} {m:>11.4f} {h:>10.4f} {m / h:>8.2f} {per:>11.1f} us")
        print(f"       spread {min(ms):.4f}-{max(ms):.4f}      {min(hs):.4f}-{max(hs):.4f}")


def macro_run():
    print("\n(c) macro_run, cold cache — one full nested compile per distinct script")
    (OUT / "gen_a.cr").write_text('puts "def gen_a : Int32\\n  1\\nend"\n')
    (OUT / "gen_b.cr").write_text('puts "def gen_b : Int32\\n  2\\nend"\n')

    cases = {
        "no macro_run": "def gen_a : Int32\n  1\nend\ndef gen_b : Int32\n  2\nend\ngen_a\ngen_b\n",
        "one script": '{{ run("./gen_a.cr").stringify.id }}\ndef gen_b : Int32\n  2\nend\ngen_a\ngen_b\n',
        "two scripts": '{{ run("./gen_a.cr").stringify.id }}\n{{ run("./gen_b.cr").stringify.id }}\ngen_a\ngen_b\n',
        "same script twice": '{{ run("./gen_a.cr").stringify.id }}\n{{ run("./gen_a.cr").stringify.id }}\ngen_a\n',
    }
    for label, src in cases.items():
        path = OUT / (label.replace(" ", "_") + ".cr")
        path.write_text(src)
        ts = [build(path, prelude_empty=False, cold=True) for _ in range(COLD_RUNS)]
        print(f"  {label:<20} {statistics.median(ts):>6.2f} s   "
              f"runs {[f'{v:.2f}' for v in ts]}")


if __name__ == "__main__":
    compare("(a) a macro that emits a template",
            template_macro, template_hand, (0, 250, 500, 1000, 2000, 4000))
    compare("(b) a macro that computes per item",
            computing_macro, computing_hand, (250, 1000, 4000))
    macro_run()
    print(f"\nworkspace: {OUT}")
