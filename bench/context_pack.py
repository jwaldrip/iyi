#!/usr/bin/env python3
"""AI_FIRST.md §5 — the gate the plan wrote before the work.

Two arms. The token arm is hermetic and runs in CI: for each target below,
the surface pack (`iyi mod context FILE`) must be smaller than the raw
grounding it replaces — the sources of the target's import closure, which
is what an agent reads when no pack exists — and must carry no body. The
rounds arm needs a model, so it is pluggable: `--agent 'CMD'` names a
command that reads a prompt on stdin and writes a program on stdout, and
the same task is run twice, pack-grounded and raw-grounded, counting
rounds until the build is green.

Until both arms pass, AI_FIRST.md's own rule holds: no AI-first sentence
is quoted anywhere as fact. The token arm's threshold is written from the
first measurement (webapp 57%, calc 43% of raw) with headroom, not
ambition: the pack must stay under 70% of raw, and any regression past
that is this script exiting 1.

    python3 bench/context_pack.py            # token arm
    python3 bench/context_pack.py --agent 'claude -p'   # both arms
"""

import argparse
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
IYI = REPO / "bin" / "iyi"

# {entry file: its import closure's sources — what raw grounding costs}
TARGETS = {
    "samples/iyi/webapp.iyi": [
        "samples/iyi/kemal/dsl.iyi",
        "samples/iyi/kemal/router.iyi",
    ],
    "samples/iyi/calc.iyi": [
        "samples/iyi/calc/lexer.iyi",
        "samples/iyi/calc/parser.iyi",
        "samples/iyi/calc/ast.iyi",
    ],
}

# A line that lives in a body in each closure. The pack carrying one is the
# pack carrying bodies, whatever its size says.
BODY_MARKERS = {
    "samples/iyi/webapp.iyi": "join_paths",
    "samples/iyi/calc.iyi": "evaluate(scope)!",
}

THRESHOLD = 0.70


def pack_for(entry: str) -> str:
    result = subprocess.run(
        [str(IYI), "mod", "context", entry],
        capture_output=True, text=True, cwd=REPO,
    )
    if result.returncode != 0:
        sys.exit(f"mod context failed for {entry}:\n{result.stderr}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", help="command reading a prompt on stdin, writing a program on stdout")
    arguments = parser.parse_args()

    failures = []
    print(f"{'target':<28} {'pack':>7} {'raw':>7} {'ratio':>6}")
    for entry, closure in TARGETS.items():
        pack = pack_for(entry)
        raw = sum(len((REPO / source).read_text().encode()) for source in closure)
        size = len(pack.encode())
        ratio = size / raw
        print(f"{pathlib.Path(entry).name:<28} {size:>7} {raw:>7} {ratio:>6.0%}")

        if ratio > THRESHOLD:
            failures.append(f"{entry}: the pack is {ratio:.0%} of raw, over the {THRESHOLD:.0%} line")
        marker = BODY_MARKERS[entry]
        closure_text = "".join((REPO / source).read_text() for source in closure)
        if marker not in closure_text:
            failures.append(f"{entry}: marker '{marker}' is gone from the sources; the check checks nothing")
        if marker in pack:
            failures.append(f"{entry}: a body reached the pack ('{marker}')")

    if arguments.agent:
        failures.extend(rounds_arm(arguments.agent))
    else:
        print("\nrounds arm: skipped (no --agent). AI_FIRST.md §5 needs both arms")
        print("before any AI-first sentence is quoted as fact.")

    if failures:
        print()
        for failure in failures:
            print(f"FAIL  {failure}")
        return 1
    print("\nthe pack pays for itself" + ("" if arguments.agent else " on the token arm"))
    return 0


TASK = """Write a complete iyi program, file name main.iyi, that uses the kemal
modules to serve two routes: GET / answering "home" and GET /sum/:a/:b
answering the sum of the two integer path parameters. Use only what the
grounding below shows. Answer with the file content only, no fences.

Grounding:
"""


def rounds_arm(agent: str) -> list[str]:
    failures = []
    for grounding_name, grounding in (
        ("pack", pack_for("samples/iyi/webapp.iyi")),
        ("raw", "".join((REPO / s).read_text() for s in TARGETS["samples/iyi/webapp.iyi"])),
    ):
        rounds, tokens = run_task(agent, grounding)
        print(f"rounds arm [{grounding_name}]: rounds={rounds} prompt_bytes={tokens}")
        if rounds is None:
            failures.append(f"rounds arm [{grounding_name}]: never went green")
    return failures


def run_task(agent: str, grounding: str):
    prompt = TASK + grounding
    sent = 0
    with tempfile.TemporaryDirectory() as work:
        workdir = pathlib.Path(work)
        # The imports resolve the way the sample's own do.
        for source in TARGETS["samples/iyi/webapp.iyi"]:
            target = workdir / "kemal" / pathlib.Path(source).name
            target.parent.mkdir(exist_ok=True)
            target.write_text((REPO / source).read_text())
        for attempt in range(1, 7):
            sent += len(prompt.encode())
            answer = subprocess.run(
                agent, shell=True, input=prompt, capture_output=True, text=True,
            ).stdout
            # Models fence despite instructions; the task is the program,
            # not the etiquette.
            if "```" in answer:
                lines = answer.splitlines()
                inside = [i for i, l in enumerate(lines) if l.strip().startswith("```")]
                if len(inside) >= 2:
                    answer = "\n".join(lines[inside[0] + 1:inside[-1]]) + "\n"
            (workdir / "main.iyi").write_text(answer)
            build = subprocess.run(
                [str(IYI), "build", "--no-codegen", "main.iyi", "-o", "out"],
                capture_output=True, text=True, cwd=workdir,
            )
            if build.returncode == 0:
                return attempt, sent
            prompt = (
                "The program you wrote does not compile. Fix it and answer with "
                "the whole corrected file only.\n\nErrors:\n" + build.stderr +
                "\n\nYour program:\n" + answer
            )
    return None, sent


if __name__ == "__main__":
    sys.exit(main())
