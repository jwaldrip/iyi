#!/usr/bin/env python3
"""Measure native/hosted pairs and apply the native speed ceiling."""

import argparse
import csv
import filecmp
import json
import math
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from decimal import Decimal, ROUND_CEILING


DEFAULT_CEILING = Path(__file__).resolve().parent.parent / "native_speed.ceiling"
TSV_COLUMNS = (
    "workload", "mode", "metric", "native", "hosted", "ratio", "ceiling", "noise", "scale",
    "spread_native", "spread_hosted", "verdict", "native_result", "hosted_result",
    "native_footprint_mb", "hosted_footprint_mb",
)


class GateError(Exception):
    pass


def number(value, label, *, zero=False):
    if isinstance(value, bool):
        raise GateError("invalid " + label)
    try:
        value = float(value)
    except (ValueError, TypeError):
        raise GateError("invalid " + label)
    if not math.isfinite(value) or value < 0 or (value == 0 and not zero):
        raise GateError("invalid " + label)
    return value


def parse_ceiling(text):
    noise = {}
    ceilings = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if fields[0] == "noise" and len(fields) == 3:
            if fields[1] in noise:
                raise GateError("duplicate noise " + fields[1])
            noise[fields[1]] = number(fields[2], "noise", zero=True)
        elif len(fields) == 4:
            key = tuple(fields[:3])
            if key in ceilings:
                raise GateError("duplicate ceiling " + " ".join(key))
            ceilings[key] = number(fields[3], "ceiling")
        else:
            raise GateError("invalid ceiling line: " + line)
    return noise, ceilings


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def measurements(data):
    if isinstance(data, dict) and "measurements" in data:
        data = data["measurements"]
    if not isinstance(data, dict) or not isinstance(data.get("rows"), list) or not data["rows"]:
        raise GateError("measurements contain no rows")
    return data


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def same(left, right):
    if left == right:
        return True
    try:
        a, b = float(left), float(right)
    except (ValueError, TypeError):
        return False
    return math.isfinite(a) and math.isfinite(b) and abs(a - b) <= 1e-6 * max(abs(a), abs(b))


def wait_timed(command, timeout, require_result=True, allow_failure=False):
    start = time.perf_counter()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(["/usr/bin/time", "-l"] + command, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
        except OSError as exc:
            raise GateError("cannot start %s: %s" % (command[0], exc))
        def timed_out(_signum, _frame):
            raise TimeoutError()

        previous_handler = signal.signal(signal.SIGALRM, timed_out)
        deadline = start + timeout
        try:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, deadline - time.perf_counter()))
            _, status, usage = os.wait4(process.pid, 0)
        except TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.wait4(process.pid, 0)
            raise GateError("timeout after %s seconds: %s" % (timeout, command[0]))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.wait4(process.pid, 0)
            except ChildProcessError:
                pass
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
        wall = time.perf_counter() - start
        process.returncode = os.waitstatus_to_exitcode(status)
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read().decode("utf-8", "replace")
        report = stderr.read().decode("utf-8", "replace")
    if process.returncode != 0:
        if allow_failure:
            return {"returncode": process.returncode, "stdout": output, "stderr": report}
        raise GateError("%s exited %s: %s" % (command[0], process.returncode, (output + report)[-4000:]))

    def counter(label, required=False):
        found = re.search(r"(?m)^\s*(\d+)\s+" + re.escape(label) + r"\s*$", report)
        if found:
            return int(found.group(1))
        if required:
            raise GateError("time report lacks " + label + ": " + report[-2000:])
        return 0

    result = None
    if require_result:
        found = re.findall(r"(?m)^result=(.*)$", output)
        if len(found) != 1 or not found[0].strip():
            raise GateError("%s printed %s result lines" % (command[0], len(found)))
        result = found[0].strip()
    return {
        "wall": wall, "cpu": usage.ru_utime + usage.ru_stime,
        "cycles": counter("cycles elapsed"), "instructions": counter("instructions retired"),
        "footprint": counter("peak memory footprint", required=True), "result": result,
    }


def metric_of(row):
    if "metric" in row:
        return row["metric"]
    samples = row["hosted"] + row["native"]
    return "cycles" if all(number(s.get("cycles", 0), "cycles", zero=True) > 0 for s in samples) else "cpu"


def values(row, metric):
    result = {}
    for arm in ("native", "hosted"):
        samples = row.get(arm)
        if not isinstance(samples, list) or not samples:
            raise GateError("missing %s samples" % arm)
        nums = [number(sample.get(metric), arm + " " + metric) for sample in samples]
        least = min(nums)
        result[arm] = least
        result["spread_" + arm] = statistics.median(nums) / least
    result["ratio"] = result["native"] / result["hosted"]
    return result


def needs_retry(row, noise):
    metric = metric_of(row)
    if metric not in noise:
        raise GateError("missing noise for " + metric)
    v = values(row, metric)
    return max(v["spread_native"], v["spread_hosted"]) > 1 + 2 * noise[metric]


def runtime_rounds(hosted, native, count, timeout):
    runs = {"hosted": [], "native": []}
    for turn in range(count):
        order = (("hosted", hosted), ("native", native))
        if turn % 2:
            order = tuple(reversed(order))
        for arm, exe in order:
            runs[arm].append(wait_timed([exe], timeout))
    return runs


def measure(args):
    if args.runs < 1 or args.timeout <= 0:
        raise GateError("runs and timeout must be positive")
    noise, _ = parse_ceiling(DEFAULT_CEILING.read_text(encoding="utf-8"))
    pairs = []
    seen = set()
    with open(args.pairs, newline="", encoding="utf-8") as src:
        for fields in csv.reader(src, delimiter="\t"):
            if len(fields) != 4 or not all(fields):
                raise GateError("each pair needs workload, mode, hosted and native")
            key = tuple(fields[:2])
            if key in seen:
                raise GateError("duplicate pair: " + " ".join(key))
            seen.add(key)
            pairs.append(fields)
    if not pairs:
        raise GateError("no executable pairs")
    native_paths = {(workload, mode): native for workload, mode, _, native in pairs}
    rows = []
    for workload, mode, hosted, native in pairs:
        row = {"workload": workload, "mode": mode}
        row.update(runtime_rounds(hosted, native, args.runs, args.timeout))
        if needs_retry(row, noise):
            row.update(runtime_rounds(hosted, native, args.runs * 2, args.timeout))
            row["remeasured"] = True
        default = native_paths.get((workload, "default"))
        row["cosmetic"] = bool(mode == "release" and default and default != native
                               and filecmp.cmp(default, native, shallow=False))
        rows.append(row)
    write_json(args.out, {"rows": rows})


def compile_rounds(old, new, source, count, directory, timeout):
    runs = {"hosted": [], "native": []}
    for arm in runs:
        (directory / arm).mkdir(parents=True, exist_ok=True)
    for turn in range(count):
        order = (("hosted", old), ("native", new))
        if turn % 2:
            order = tuple(reversed(order))
        for arm, compiler in order:
            output = directory / arm / "iyi"
            while True:
                if output.exists():
                    output.unlink()
                command = [compiler, "build"]
                if release[arm]:
                    command.append("--release")
                command += ["-o", str(output), source]
                sample = wait_timed(command, timeout, require_result=False, allow_failure=True)
                if "returncode" not in sample:
                    if not output.is_file():
                        raise GateError("compiler did not create " + str(output))
                    runs[arm].append(sample)
                    break
                diagnostic = sample["stdout"] + "\n" + sample["stderr"]
                raise GateError("compiler exited %s: %s" % (sample["returncode"], diagnostic[-4000:]))
            if not output.is_file():
                raise GateError("compiler did not create " + str(output))
            runs[arm].append(sample)
    return runs


def latency(args):
    if args.runs < 1:
        raise GateError("runs must be positive")
    timeout = number(args.timeout, "latency timeout")
    noise, _ = parse_ceiling(DEFAULT_CEILING.read_text(encoding="utf-8"))
    directory = Path(args.out).resolve().parent / "lat"
    runs = compile_rounds(args.old, args.new, args.source, args.runs, directory, timeout)
    rows = [dict({"workload": "latency", "mode": "selfbuild", "metric": metric}, **runs)
            for metric in ("wall", "cpu", "footprint")]
    if any(needs_retry(row, noise) for row in rows):
        runs = compile_rounds(args.old, args.new, args.source, args.runs * 2, directory, timeout)
        rows = [dict({"workload": "latency", "mode": "selfbuild", "metric": metric,
                      "remeasured": True}, **runs) for metric in ("wall", "cpu", "footprint")]
    write_json(args.out, {"rows": rows})


def evaluate(data, noise, ceilings, scale, target=False, lowering=False):
    scale = number(scale, "tolerance scale")
    if target:
        scale = 1.0
    rows = measurements(data)["rows"]
    references = {}
    mismatch = set()
    keys = set()
    for row in rows:
        if row.get("workload") == "latency":
            continue
        name = row["workload"]
        for arm in ("hosted", "native"):
            for sample in row.get(arm, []):
                result = sample.get("result")
                if not isinstance(result, str) or not result:
                    raise GateError("missing result for " + name)
                if name in references and not same(references[name], result):
                    mismatch.add(name)
                else:
                    references.setdefault(name, result)
    evaluated = []
    for row in rows:
        metric = metric_of(row)
        key = (row["workload"], row["mode"], metric)
        if key in keys:
            raise GateError("duplicate measurement " + " ".join(key))
        keys.add(key)
        if metric not in noise:
            raise GateError("missing noise for " + metric)
        stats = values(row, metric)
        ratio = stats["ratio"]
        ceiling = 1.0 if target else ceilings.get(key)
        bound = None if ceiling is None else ceiling * (1 + scale * noise[metric])
        verdict = "PASS"
        if ceiling is None:
            verdict = "NO CEILING"
        else:
            if ratio > bound:
                verdict = "FAIL"
        if max(stats["spread_native"], stats["spread_hosted"]) > 1 + 2 * noise[metric]:
            verdict = "NOISY"
        if row.get("cosmetic", False):
            verdict = "COSMETIC"
        if key[0] in mismatch:
            verdict = "RESULT"
        failure = verdict != "PASS" and not (verdict == "NO CEILING" and lowering)
        evaluated.append(dict(row= row, key=key, metric=metric, noise=noise[metric], scale=scale,
                              ceiling=ceiling, bound=bound, verdict=verdict, failure=failure, **stats))
    return evaluated


def upward(value):
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_CEILING)


def report(rows, tsv=None, target=False):
    records = []
    for item in rows:
        row = item["row"]
        ceiling = "-" if item["ceiling"] is None else "%.2f" % item["ceiling"]
        bound = "-" if item["bound"] is None else "%.3f" % item["bound"]
        extra = ""
        if (not target and item["verdict"] == "PASS" and item["ceiling"] is not None
                and item["ratio"] < item["ceiling"] / (1 + item["noise"])):
            extra = " IMPROVED (NATIVE_SPEED_LOWER=1: %s)" % upward(item["ratio"])
        print("  %s %s %s native=%.6g hosted=%.6g ratio=%.4f ceiling=%s bound=%s spread=%.3f/%.3f %s%s" % (
            row["workload"], row["mode"], item["metric"], item["native"], item["hosted"], item["ratio"],
            ceiling, bound, item["spread_native"], item["spread_hosted"], item["verdict"], extra))
        def result(arm):
            return row[arm][0].get("result") or ""
        def footprint(arm):
            return max(number(s.get("footprint"), "footprint") for s in row[arm]) / (1024 * 1024)
        records.append((row["workload"], row["mode"], item["metric"], item["native"], item["hosted"],
                        item["ratio"], ceiling, item["noise"], item["scale"], item["spread_native"],
                        item["spread_hosted"], item["verdict"], result("native"), result("hosted"),
                        footprint("native"), footprint("hosted")))
    if tsv:
        with open(tsv, "w", newline="", encoding="utf-8") as dst:
            writer = csv.writer(dst, delimiter="\t", lineterminator="\n")
            writer.writerow(TSV_COLUMNS)
            writer.writerows(records)
    if target and any(item["failure"] for item in rows):
        print("the target is not met:")
        for item in rows:
            if item["failure"]:
                print("  %s %s %s %s ratio=%.4f" % (*item["key"], item["verdict"], item["ratio"]))


def judge(args):
    if args.fixture:
        fixture = read_json(args.fixture)
        noise, ceilings = parse_ceiling(fixture["ceiling"])
        rows = evaluate(fixture["measurements"], noise, ceilings, fixture["scale"], fixture["target"])
        report(rows, target=fixture["target"])
        expected = fixture["expect"]
        matched = any(item["verdict"] == expected for item in rows)
        if expected == "PASS":
            matched = all(item["verdict"] == "PASS" for item in rows)
        if not matched:
            print("fixture expected %s, got %s" % (expected, ", ".join(item["verdict"] for item in rows)))
            return 1
        return 0
    if not args.ceiling or not args.measurements or args.scale is None:
        raise GateError("judge needs --ceiling, --measurements and --scale")
    noise, ceilings = parse_ceiling(Path(args.ceiling).read_text(encoding="utf-8"))
    rows = evaluate(read_json(args.measurements), noise, ceilings, args.scale, args.target,
                    lowering=os.environ.get("NATIVE_SPEED_LOWER") == "1" and not args.target)
    report(rows, tsv=args.tsv, target=args.target)
    return 1 if any(item["failure"] for item in rows) else 0


def lower(args):
    text = Path(args.ceiling).read_text(encoding="utf-8")
    noise, ceilings = parse_ceiling(text)
    rows = evaluate(read_json(args.measurements), noise, ceilings, 1, lowering=True)
    if any(item["verdict"] in ("RESULT", "NOISY", "COSMETIC") for item in rows):
        raise GateError("cannot lower a ceiling from invalid or noisy measurements")
    updates = {item["key"]: upward(item["ratio"]) for item in rows}
    output = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 4 and not fields[0].startswith("#") and tuple(fields[:3]) in updates:
            key = tuple(fields[:3])
            old = Decimal(fields[3])
            measured = updates.pop(key)
            kept = min(old, measured)
            output.append("%s %s" % (" ".join(key), format(kept, ".2f")))
        else:
            output.append(line)
    for key, measured in updates.items():
        output.append("%s %s" % (" ".join(key), format(measured, ".2f")))
    Path(args.write).write_text("\n".join(output) + "\n", encoding="utf-8")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    m = commands.add_parser("measure")
    m.add_argument("--pairs", required=True)
    m.add_argument("--runs", required=True, type=int)
    m.add_argument("--timeout", required=True, type=float)
    m.add_argument("--out", required=True)
    j = commands.add_parser("judge")
    j.add_argument("--ceiling")
    j.add_argument("--measurements")
    j.add_argument("--scale", type=float)
    j.add_argument("--target", action="store_true")
    j.add_argument("--fixture")
    j.add_argument("--tsv")
    lo = commands.add_parser("lower")
    lo.add_argument("--ceiling", required=True)
    lo.add_argument("--measurements", required=True)
    lo.add_argument("--write", required=True)
    lat = commands.add_parser("latency")
    lat.add_argument("--old", required=True)
    lat.add_argument("--new", required=True)
    lat.add_argument("--source", required=True)
    lat.add_argument("--runs", required=True, type=int)
    lat.add_argument("--timeout", type=float, default=1800,
                     help="per-compile timeout in seconds (default: %(default)s)")
    lat.add_argument("--out", required=True)
    return p


def main():
    args = parser().parse_args()
    try:
        if args.command == "measure":
            measure(args)
        elif args.command == "judge":
            return judge(args)
        elif args.command == "lower":
            lower(args)
        elif args.command == "latency":
            latency(args)
        return 0
    except (GateError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("native speed: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
