#!/usr/bin/env python3
"""Parent-owned diagnostic, not a production seam or coverage fixture.

Run the real run_bounded in isolated interpreters. A source-line observer sends
one real SIGINT after its first handler registration and before proc.wait.
Compare the repaired implementation with one relocation-only mutant.
"""
from __future__ import annotations
import argparse
import ast
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading


def emit(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def locate(source: str):
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_bounded"]
    if len(functions) != 1:
        raise RuntimeError("run_bounded must occur exactly once")
    fn = functions[0]
    catches = [n for n in ast.walk(fn) if isinstance(n, ast.Try) and any(
        isinstance(h.type, ast.Name) and h.type.id == "_BoundedSignal" for h in n.handlers
    )]
    if len(catches) != 1:
        raise RuntimeError("expected exactly one _BoundedSignal catch")
    inner = catches[0]
    registrations = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name)
                     and n.func.value.id == "signal" and n.func.attr == "signal"
                     and len(n.args) == 2 and isinstance(n.args[1], ast.Name)
                     and n.args[1].id == "interrupt_handler"]
    if len(registrations) != 1:
        raise RuntimeError("handler registration anchor must match exactly once")
    registration = registrations[0]
    blocks = [n for n in ast.walk(fn) if isinstance(n, ast.If)
              and n.lineno <= registration.lineno <= n.end_lineno
              and "threading.current_thread" in ast.unparse(n.test)]
    if len(blocks) != 1:
        raise RuntimeError("registration condition anchor must match exactly once")
    return fn, inner, registration, blocks[0]


def relocated_mutant(source: str):
    fn, inner, registration, block = locate(source)
    if block not in inner.body:
        raise RuntimeError("repaired registration must be directly inside catch scope")
    if not (inner.lineno < block.lineno <= block.end_lineno < inner.end_lineno):
        raise RuntimeError("registration range is outside protected try")
    lines = source.splitlines(keepends=True)
    insertion, start, end = inner.lineno - 1, block.lineno - 1, block.end_lineno
    indent_from = len(lines[start]) - len(lines[start].lstrip())
    indent_to = len(lines[insertion]) - len(lines[insertion].lstrip())
    if indent_from - indent_to != 4:
        raise RuntimeError("expected one indentation level between try and registration")
    moved = [line[4:] if line.strip() else line for line in lines[start:end]]
    mutated = "".join(lines[:insertion] + moved + lines[insertion:start] + lines[end:])
    _, mutant_inner, _, mutant_block = locate(mutated)
    if mutant_block in mutant_inner.body:
        raise RuntimeError("mutant did not relocate registration outside catch")
    # Remove the one relocated block in both ASTs, then require exact AST equality.
    base_tree, mutant_tree = ast.parse(source), ast.parse(mutated)
    def strip_registration(tree):
        class Strip(ast.NodeTransformer):
            removed = 0
            def visit_If(self, node):
                if "threading.current_thread" in ast.unparse(node.test) and any(
                    isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "signal"
                    and n.func.attr == "signal" and len(n.args) == 2
                    and isinstance(n.args[1], ast.Name) and n.args[1].id == "interrupt_handler"
                    for n in ast.walk(node)
                ):
                    self.removed += 1
                    return None
                return self.generic_visit(node)
        strip = Strip()
        result = strip.visit(tree)
        if strip.removed != 1:
            raise RuntimeError("semantic relocation must remove exactly one block")
        return ast.dump(result, include_attributes=False)
    if strip_registration(base_tree) != strip_registration(mutant_tree):
        raise RuntimeError("mutant changes more than registration placement")
    return mutated, {"anchor_matches": 1, "registration_in_catch_before": True,
                     "registration_in_catch_after": False, "semantic_change": "one registration block relocation"}


def child_case(source_path: Path, output: Path, name: str) -> int:
    spec = importlib.util.spec_from_file_location("registration_diagnostic_" + name, source_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load isolated proof module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _, _, registration, _ = locate(source_path.read_text())
    originals = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    observed = {"case": name, "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "observer_fired": False, "signal_sent": False, "escaped": None, "result": None}
    resources = {}
    def trace(frame, event, arg):
        if event != "line" or frame.f_code is not module.run_bounded.__code__ or observed["observer_fired"]:
            return trace
        handler = signal.getsignal(signal.SIGINT)
        # First line event after the real SIGINT registration, before any wait.
        if getattr(handler, "__name__", None) != "interrupt_handler":
            return trace
        registered = list(frame.f_locals.get("previous_handlers", {}))
        if registered != [signal.SIGINT]:
            raise RuntimeError(f"observer missed first-registration interval: {registered}")
        proc = frame.f_locals.get("proc")
        if proc is None:
            raise RuntimeError("observer has no owned Popen")
        if os.getpgid(proc.pid) != proc.pid or os.getsid(proc.pid) != proc.pid:
            raise RuntimeError("owned leader is not its fresh process group/session")
        resources.update({"proc": proc, "sampler": frame.f_locals.get("sampler"),
                          "stop": frame.f_locals.get("stop_sampler")})
        observed.update({"observer_fired": True, "observer_line": frame.f_lineno,
                         "registration_line": registration.lineno,
                         "leader_pid": proc.pid, "pgid": proc.pid, "sid": proc.pid,
                         "registered_signals": registered,
                         "signal_sent": True, "wait_not_reached": True})
        emit(output / (name + "-before-signal.json"), observed)
        os.kill(os.getpid(), signal.SIGINT)
        return trace
    result = None
    try:
        sys.settrace(trace)
        try:
            result = module.run_bounded(["/bin/sh", "-c", "sleep 30"], str(output), os.environ.copy(),
                                        str(output / (name + ".log")), str(output / (name + ".times")), 5.0, 0.1)
            observed["result"] = {"returncode": result.returncode, "timed_out": result.timed_out,
                                  "interrupted_signal": result.interrupted_signal,
                                  "survivors": list(result.survivors)}
        except module._BoundedSignal as error:
            observed["escaped"] = {"type": type(error).__name__, "signum": error.signum}
        finally:
            sys.settrace(None)
        if not observed["observer_fired"]:
            raise RuntimeError("source-line observer never fired")
        pid = resources["proc"].pid
        observed["group_members_before_fixture_teardown"] = list(module._process_group_members(pid))
        sampler = resources.get("sampler")
        observed["sampler_joined_before_fixture_teardown"] = sampler is not None and not sampler.is_alive()
        observed["handlers_restored_before_fixture_teardown"] = all(signal.getsignal(sig) is old for sig, old in originals.items())
        emit(output / (name + "-observation.json"), observed)
    finally:
        # Observe first; only then clean this diagnostic's exact owned resources.
        sys.settrace(None)
        proc = resources.get("proc")
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise RuntimeError("owned diagnostic leader survived cleanup")
        stop = resources.get("stop")
        if stop is not None:
            stop.set()
        sampler = resources.get("sampler")
        if sampler is not None and sampler.ident is not None:
            sampler.join(timeout=5)
            if sampler.is_alive():
                raise RuntimeError("owned diagnostic sampler survived cleanup")
        for sig, old in originals.items():
            signal.signal(sig, old)
    if name == "fixed":
        ok = (observed["escaped"] is None and result is not None
              and result.interrupted_signal == signal.SIGINT and not result.timed_out
              and not observed["group_members_before_fixture_teardown"]
              and observed["sampler_joined_before_fixture_teardown"]
              and observed["handlers_restored_before_fixture_teardown"])
    else:
        ok = observed["escaped"] == {"type": "_BoundedSignal", "signum": signal.SIGINT}
    print(json.dumps({"case": name, "diagnostic_pass": ok, "observation": observed}, sort_keys=True))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=("fixed", "mutant"))
    args = parser.parse_args()
    if args.case:
        return child_case(args.source, args.output, args.case)
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.source.read_text()
    mutant, evidence = relocated_mutant(source)
    fixed_path, mutant_path = args.output / "proofkit-fixed.py", args.output / "proofkit-mutant.py"
    fixed_path.write_text(source)
    mutant_path.write_text(mutant)
    (args.output / "registration.diff").write_text("".join(difflib.unified_diff(
        source.splitlines(keepends=True), mutant.splitlines(keepends=True), fromfile="fixed", tofile="mutant")))
    emit(args.output / "mutation.json", evidence)
    outcomes = []
    for name, path in (("fixed", fixed_path), ("mutant", mutant_path)):
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--source", str(path),
                   "--output", str(args.output), "--case", name]
        result = subprocess.run(command, capture_output=True)
        (args.output / (name + ".stdout")).write_bytes(result.stdout)
        (args.output / (name + ".stderr")).write_bytes(result.stderr)
        outcomes.append({"case": name, "argv": command, "rc": result.returncode})
        print(name, "rc", result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
    emit(args.output / "results.json", outcomes)
    return 0 if all(item["rc"] == 0 for item in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
