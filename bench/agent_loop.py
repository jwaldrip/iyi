#!/usr/bin/env python3
"""Drives the agent's whole loop through the verbs built for it and
asserts on every answer. This is the gate for the agentic wave: each
claim the release makes — check's verdict-as-data, suggested_edit,
fix's convergence, --affected's exact selection, the MCP server, the
budget ladder — is a step here, and a step that fails names itself and
exits 1.

The loop is the one an agent actually runs:
    ground -> edit -> check -> fix -> test (only what the edit reaches)
and the server underneath it (mcp) speaking the same answers.

`run --sandbox` is asserted only when a wasi toolchain is present: the
sandbox refusing to fall back to native is its own contract, so a
machine without wasmtime skips the step loudly rather than faking it.
"""

import json
import os
import subprocess
import sys
import tempfile

IYI = os.path.abspath(os.environ.get("IYI", "./bin/iyi"))

passed = 0


def step(name, ok, detail=""):
    global passed
    mark = "ok" if ok else "FAIL"
    print(f"step {passed + 1} {name}: {mark}  {detail}")
    if not ok:
        sys.exit(1)
    passed += 1


def run(*args, cwd=None):
    proc = subprocess.run([IYI, *args], capture_output=True, text=True, cwd=cwd)
    return proc


def main():
    work = tempfile.mkdtemp(prefix="iyi-agent-loop")
    os.makedirs(os.path.join(work, "calc"))

    def write(rel, text):
        with open(os.path.join(work, rel), "w") as f:
            f.write(text)

    write("calc/add.iyi", (
        "module calc/add\n\n"
        "# Adds two integers.\n"
        "pub def add(a : Int32, b : Int32) : Int32\n  a + b\nend\n"
    ))
    write("calc/mul.iyi", (
        "module calc/mul\n\n"
        "# Multiplies two integers.\n"
        "pub def mul(a : Int32, b : Int32) : Int32\n  a * b\nend\n"
    ))
    write("app.iyi", (
        "module app\n\n"
        "pub def shout(n : Int32) : Int32\n  n * 2\nend\n\n"
        "pub def go() : Int32\n  shoutt(3)\nend\n\n"
        "go()\n"
    ))
    write("add_test.iyi", (
        "import calc/add\nusing calc/add::{add}\n\n"
        "if add(2, 2) != 4\n  puts \"add broke\"\nend\n"
    ))
    write("mul_test.iyi", (
        "import calc/mul\nusing calc/mul::{mul}\n\n"
        "if mul(2, 3) != 6\n  puts \"mul broke\"\nend\n"
    ))

    # 1. ground: the context pack names every import, docs included
    proc = run("mod", "context", "--json", "add_test.iyi", cwd=work)
    pack = json.loads(proc.stdout)
    names = [i["import"] for i in pack["imports"]]
    step("context grounds the test", names == ["calc/add"], f"imports {names}")

    write("ground.iyi", "import calc/add\nimport calc/mul\n\nputs 1\n")
    # 2. the budget ladder: a huge budget keeps the docs, a tight one
    # still names every import, and --json refuses the flag
    proc = run("mod", "context", "--budget", "10000", "ground.iyi", cwd=work)
    step("a huge budget keeps the docs",
         "# Adds two integers." in proc.stdout and "# pack:" in proc.stdout, "")
    proc = run("mod", "context", "--budget", "20", "ground.iyi", cwd=work)
    step("a tight budget still names every import",
         "calc/add" in proc.stdout and "calc/mul" in proc.stdout
         and "elided" in proc.stdout, "")
    step("--json with --budget is refused",
         run("mod", "context", "--json", "--budget", "10", "ground.iyi", cwd=work).returncode != 0,
         "budget shapes text; json is data")

    # 3. check: the verdict is data, and it carries the edit
    proc = run("check", "-f", "json", "app.iyi", cwd=work)
    step("check exits 1 on the broken file", proc.returncode == 1, "")
    errors = json.loads(proc.stderr)
    edit = next((e["suggested_edit"] for e in errors if "suggested_edit" in e), None)
    step("the error carries suggested_edit",
         edit is not None and edit["replacement"] == "shout" and edit["size"] == 6,
         f"edit {edit}")

    # 4. fix: applies exactly that edit and converges
    proc = run("fix", "--json", "app.iyi", cwd=work)
    fixed = json.loads(proc.stdout)
    step("fix applies the compiler's own edit",
         fixed["clean"] and [(a["from"], a["to"]) for a in fixed["applied"]] == [("shoutt", "shout")],
         f"applied {fixed['applied']}")
    proc = run("check", "app.iyi", cwd=work)
    step("check confirms clean", proc.returncode == 0, "")

    # 4b. the blind spot, closed: an uncalled body is typed against its
    # declared signature (R-2's dividend); --shallow gives the build's
    # lazy answer; fix converges to check's verdict, not the build's
    write("uncalled.iyi", (
        "module app\n\n"
        "pub def go() : Int32\n  shoutt(3)\nend\n\n"
        "pub def shout(n : Int32) : Int32\n  n * 2\nend\n"
    ))
    proc = run("check", "uncalled.iyi", cwd=work)
    step("check types the body nobody calls", proc.returncode == 1,
         "R-2's declared types stand in for the caller")
    proc = run("check", "--shallow", "uncalled.iyi", cwd=work)
    step("--shallow is the build's lazy answer", proc.returncode == 0, "")
    proc = run("fix", "--json", "uncalled.iyi", cwd=work)
    fixed = json.loads(proc.stdout)
    step("fix converges to check's verdict",
         fixed["clean"] and [(a["from"], a["to"]) for a in fixed["applied"]] == [("shoutt", "shout")],
         f"applied {fixed['applied']}")
    step("and check agrees", run("check", "uncalled.iyi", cwd=work).returncode == 0, "")

    # 4c. the suggestion pool includes `using`-imported names — the miss
    # that motivated it: `addd` went unsuggested while `add` sat one
    # edit away in the file's own using line
    write("uses.iyi", (
        "import calc/add\nusing calc/add::{add}\n\n"
        "if addd(2, 2) != 4\n    puts \"broke\"\nend\n"
    ))
    proc = run("fix", "--json", "uses.iyi", cwd=work)
    fixed = json.loads(proc.stdout)
    step("a using-imported name is suggested and fixed",
         fixed["clean"] and [(a["from"], a["to"]) for a in fixed["applied"]] == [("addd", "add")],
         f"applied {fixed['applied']}")

    # 5. test --affected: the exact selection, both directions
    proc = run("test", "--json", "--affected", "calc/add.iyi", cwd=work)
    report = json.loads(proc.stdout)
    files = sorted(t["file"] for t in report["tests"])
    step("an edit to add runs only add's test",
         files == ["./add_test.iyi"] and report["skipped"] == 1,
         f"ran {files}, skipped {report['skipped']}")
    proc = run("test", "--json", "--affected", "app.iyi", cwd=work)
    report = json.loads(proc.stdout)
    step("an edit nothing imports runs nothing",
         report["tests"] == [] and report["skipped"] == 2,
         f"skipped {report['skipped']}")

    # 5b. check --affected: the ripple — a surface break names exactly
    # the consumer it reaches, and a clean tree answers "all compile"
    write("consumer.iyi", (
        "import calc/add\nusing calc/add::{add}\n\n"
        "puts add(1, 1)\n"
    ))
    proc = run("check", "--affected", "calc/add.iyi", cwd=work)
    step("a clean ripple compiles everyone",
         proc.returncode == 0 and "all compile" in proc.stdout, proc.stdout.strip())
    write("calc/add.iyi", (
        "module calc/add\n\n"
        "# Adds three integers now.\n"
        "pub def add(a : Int32, b : Int32, c : Int32) : Int32\n  a + b + c\nend\n"
    ))
    proc = run("check", "--affected", "calc/add.iyi", cwd=work)
    step("a surface break names its consumers",
         proc.returncode == 1 and "broke" in proc.stdout, proc.stdout.splitlines()[-1])
    write("calc/add.iyi", (
        "module calc/add\n\n"
        "# Adds two integers.\n"
        "pub def add(a : Int32, b : Int32) : Int32\n  a + b\nend\n"
    ))
    step("and the repair closes it",
         run("check", "--affected", "calc/add.iyi", cwd=work).returncode == 0, "")

    # 5c. the loop is around a language that can do work now: a pure-iyi
    # tool reads its args, its environment, and the disk — no --crystal
    write("nameplate.iyi", (
        "module nameplate\n\n"
        "pub def run() : Nil\n"
        "  args = Program.args\n"
        "  puts \"args: #{args.size}\"\n"
        "  home = Program.env(\"HOME\")\n"
        "  puts \"HOME present: #{home.is_a?(String)}\"\n"
        "  File.write(\"note.txt\", \"from a pure iyi tool\")\n"
        "  puts File.read(\"note.txt\")\n"
        "  File.delete(\"note.txt\")\n"
        "end\n\n"
        "run()\n"
    ))
    binary = os.path.join(work, "nameplate")
    proc = run("build", "nameplate.iyi", "-o", binary, cwd=work)
    step("the nameplate tool builds", proc.returncode == 0, proc.stderr.strip()[:80])
    out = subprocess.run([binary, "a", "b", "c"], capture_output=True, text=True, cwd=work)
    step("args, env and the disk answer",
         out.stdout == "args: 3\nHOME present: true\nfrom a pure iyi tool\n",
         repr(out.stdout))

    # 6. mcp: the same answers, over the wire
    server = subprocess.Popen([IYI, "mcp"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True, cwd=work)

    def rpc(method, params=None, id=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if id is not None:
            msg["id"] = id
        if params is not None:
            msg["params"] = params
        server.stdin.write(json.dumps(msg) + "\n")
        server.stdin.flush()
        if id is not None:
            return json.loads(server.stdout.readline())

    reply = rpc("initialize", {"protocolVersion": "2025-06-18"}, 1)
    step("mcp initialize names the server",
         reply["result"]["serverInfo"]["name"] == "iyi", "")
    rpc("notifications/initialized")
    tools = [t["name"] for t in rpc("tools/list", None, 2)["result"]["tools"]]
    step("mcp lists the loop's tools",
         tools == ["check", "fix", "context", "test"], f"{tools}")
    reply = rpc("tools/call", {"name": "check", "arguments": {"file": "app.iyi"}}, 3)
    step("mcp check answers [] on the clean file",
         json.loads(reply["result"]["content"][0]["text"]) == [], "")
    reply = rpc("tools/call", {"name": "test",
                               "arguments": {"affected": ["calc/mul.iyi"]}}, 4)
    report = json.loads(reply["result"]["content"][0]["text"])
    step("mcp test honours affected",
         [t["file"] for t in report["tests"]] == ["./mul_test.iyi"], "")
    rpc("exit")
    server.wait(timeout=10)
    step("mcp exits on exit", server.returncode == 0, "")

    # 7. the sandbox, where the toolchain exists
    wasi_cc = os.environ.get("IYI_WASI_CC") or next(
        (p for p in ["/opt/wasi-sdk/bin/clang",
                     os.path.expanduser("~/.local/opt/wasi-sdk/bin/clang")]
         if os.path.exists(p)), None)
    wasmtime = os.environ.get("IYI_WASMTIME") or next(
        (p for p in [os.path.expanduser("~/.wasmtime/bin/wasmtime")]
         if os.path.exists(p)), None) or subprocess.run(
        ["which", "wasmtime"], capture_output=True).returncode == 0
    if wasi_cc and wasmtime:
        write("honest.iyi", "module honest\n\npub def work() : Int32\n  55\nend\n\nputs work()\n")
        proc = run("run", "--sandbox", "honest.iyi", cwd=work)
        step("sandbox runs the honest program",
             proc.returncode == 0 and proc.stdout.strip() == "55", "")
        write("theft.iyi", "module theft\n\nf = File.open(\"/etc/passwd\")\nputs f\n")
        proc = run("run", "--sandbox", "theft.iyi", cwd=work)
        step("sandbox refuses the theft, leaks nothing",
             proc.returncode != 0 and "root:" not in proc.stdout,
             "refused at the compile fence")
    else:
        print("step - sandbox: skipped (no wasi-sdk/wasmtime on this machine) — the CI wasi job runs it")

    print("agent loop gate: every step held")


if __name__ == "__main__":
    main()
