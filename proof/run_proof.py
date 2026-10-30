#!/usr/bin/env python3
"""Run the observed-corpus proof chain.

Commands and arguments:
  plan --p P --w W --compiler C
      Validate pin inputs without writing a report.
  pin --report-dir R --p P --w W --compiler C
      Create the immutable pin for a new chain.
  run1 --report-dir R
      Run gates 1.1 through 1.4, exclusions, and baseline skip capture.
  run2 --report-dir R
      Run all artifact legs with the pinned compiler and nm.
  run3 --report-dir R [--driver DRIVER]
      Run every required observed driver, or one required driver.
  final --report-dir R
      Recompute every latest result and publish final.json.
  all --report-dir R
      Run run1, run2, run3, and final in dependency order.

Stage statuses are PASS, FAIL, STOP, PARTIAL, ENV-BLOCKED,
NOT-ROUNDTRIPPED, MISCLASSIFIED, DIVERGENCE, UNFAITHFUL,
NOT-EXERCISED, TIMEOUT, INVALID, CENSUS-MISSING, NOT-EXECUTED,
OUT-MODIFIED, and STALE. Exit 0 means PASS, exit 1 means a recorded
non-PASS status, and exit 2 means usage or configuration refusal.

R has pin.json; run1/a<N>/ and run2/a<N>/; run3/required.json;
run3/<driver>/a<N>/; and final.json. Every attempt ends with an atomic
result.json. Attempt numbers are append-only. final uses the numerically
highest attempt, recomputes its status from required checks, re-derives the
required drivers from the latest Run 1 and Run 2, and requires every Run 3
attempt to be newer than both. It verifies chain, unit, attempt and pinned
identity, and lists every earlier failure. A chain is bound to the
report-directory suffix and pin identity. On Darwin the pin records and
probes the real platform temp root used by bare mktemp.
INVALID recovery requires a new pin and report directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
import time
from collections.abc import Sequence

# Ensure the repository root is importable when this file is executed directly.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from proof.proofkit import (
    DISK_MIN_GB,
    DRIVER_LIMIT_SEC,
    DRIVERS_29,
    GRACE_SEC,
    RG2R_MIN,
    RUN1_CORPUS,
    RUN1_SIBLINGS,
    RUN1_STD_EXERCISES,
    RUN2_COUNTS,
    IdentityError,
    base_env,
    check_disk_space,
    check_identity,
    inspect_pin_inputs,
    load_pin,
    load_result,
    recompute_status,
    run_bounded,
    probe_atime_observable,
    validate_census,
    verify_ledger,
    write_pin,
    write_result,
)


_FINAL_LIMITS = [
    "the platform skips",
    (
        "under helpers, observed-source binaries run only in the drivers' "
        "own artifact blocks (acme, autocert, compress, png, regex, shlex, "
        "tls, websocket, xz, zip) and in negative mutation proofs; every "
        "other canonical or positive build runs its artifact consumer; RG2 "
        "proves observed source bare for all 141"
    ),
]


def _attempt_entries(parent_dir: str) -> list[tuple[int, str]]:
    try:
        names = os.listdir(parent_dir)
    except FileNotFoundError:
        return []
    entries: list[tuple[int, str]] = []
    for name in names:
        match = re.fullmatch(r"a([1-9][0-9]*)", name)
        path = os.path.join(parent_dir, name)
        if match and os.path.isdir(path):
            entries.append((int(match.group(1)), path))
    return sorted(entries)


def next_attempt_dir(parent_dir: str) -> str:
    os.makedirs(parent_dir, exist_ok=True)
    entries = _attempt_entries(parent_dir)
    attempt = entries[-1][0] + 1 if entries else 1
    path = os.path.join(parent_dir, f"a{attempt}")
    os.makedirs(path, exist_ok=False)
    return path


def latest_attempt_dir(parent_dir: str) -> str | None:
    entries = _attempt_entries(parent_dir)
    return entries[-1][1] if entries else None


def _attempt_number(path: str) -> int:
    match = re.fullmatch(r"a([1-9][0-9]*)", os.path.basename(path))
    if not match:
        raise ValueError(f"not an attempt directory: {path}")
    return int(match.group(1))


def _write_json_atomic(path: str, value: object) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temporary = os.path.join(
        parent,
        f".{os.path.basename(path)}.{os.getpid()}.{secrets.token_hex(8)}.tmp",
    )
    try:
        with open(temporary, "x", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_json(path: str) -> object:
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def read_log(log_path: str) -> bytes:
    with open(log_path, "rb") as log_file:
        return log_file.read()


def fresh_stage_env(pin: dict, attempt_dir: str, stage_name: str, additions: dict[str, str] | None = None) -> dict[str, str]:
    tmp_dir = os.path.join(attempt_dir, f"{stage_name}.tmp")
    cache_dir = os.path.join(attempt_dir, f"{stage_name}.cache")
    os.makedirs(tmp_dir, exist_ok=False)
    os.makedirs(cache_dir, exist_ok=False)
    stage_additions = {
        "TMPDIR": tmp_dir,
        "IYI_CACHE_DIR": cache_dir,
    }
    if additions:
        stage_additions.update(additions)
    return base_env(pin, stage_additions)


def run_logged(cmd: list[str], *, cwd: str, env: dict[str, str], log_path: str, times_path: str, limit_sec: float | None, grace_sec: float = GRACE_SEC):
    result = run_bounded(
        cmd,
        cwd,
        env,
        log_path,
        times_path,
        limit_sec,
        grace_sec,
    )
    return result, read_log(log_path)


def _new_result(pin: dict, unit: str, attempt: int, checks: dict[str, str], reasons: list[str], started_ns: int, survivors: Sequence[int]) -> dict:
    kind = unit.split("/", 1)[0]
    record = {
        "v": 1,
        "chain_id": pin["chain_id"],
        "unit": unit,
        "attempt": attempt,
        "status": "FAIL",
        "reasons": list(reasons),
        "checks": dict(checks),
        "started_ns": started_ns,
        "ended_ns": time.time_ns(),
        "survivors": sorted(set(int(pid) for pid in survivors)),
    }
    record["status"] = recompute_status(record, kind)
    return record


def _finish_attempt(attempt_dir: str, pin: dict, unit: str, checks: dict[str, str], reasons: list[str], started_ns: int, survivors: Sequence[int]) -> dict:
    record = _new_result(
        pin,
        unit,
        _attempt_number(attempt_dir),
        checks,
        reasons,
        started_ns,
        survivors,
    )
    write_result(os.path.join(attempt_dir, "result.json"), record)
    return record


def _check_stage_identity(pin: dict, checks: dict[str, str], reasons: list[str]) -> bool:
    try:
        check_identity(pin)
    except IdentityError as error:
        checks["identity"] = "INVALID"
        reasons.append(f"identity {error.reason}: {error.detail}")
        return False
    if checks.get("identity") != "INVALID":
        checks["identity"] = "PASS"
    return True


def _check_stage_disk(path: str, minimum_gb: float, checks: dict[str, str], reasons: list[str], *, check_name: str, low_status: str) -> bool:
    try:
        check_disk_space(path, minimum_gb)
    except (OSError, RuntimeError) as error:
        checks[check_name] = low_status
        reasons.append(str(error))
        return False
    checks[check_name] = "PASS"
    return True


def _run_gate(command: list[str], *, pin: dict, attempt_dir: str, stage_name: str, additions: dict[str, str], cwd: str):
    env = fresh_stage_env(pin, attempt_dir, stage_name, additions)
    log_path = os.path.join(attempt_dir, f"{stage_name}.log")
    times_path = os.path.join(attempt_dir, f"{stage_name}.times")
    return run_logged(command, cwd=cwd, env=env, log_path=log_path, times_path=times_path, limit_sec=None)


def _exclusions(log_text: str) -> list[dict[str, str]]:
    pattern = re.compile(
        r"^  \[excluded after calibration\] (\S+): (.*)$",
        re.MULTILINE,
    )
    return [
        {"program": match.group(1), "reason": match.group(2)}
        for match in pattern.finditer(log_text)
    ]


def _skip_hits(census: dict, text: str) -> list[dict[str, str]]:
    lines = text.splitlines()
    hits: list[dict[str, str]] = []
    for entry in census.get("skips", []):
        if not isinstance(entry, dict):
            continue
        regex = entry.get("regex")
        if not isinstance(regex, str):
            continue
        try:
            matched = any(re.search(regex, line) for line in lines)
        except re.error:
            matched = False
        if matched:
            hits.append(
                {
                    "driver": str(census.get("driver", "")),
                    "class": str(entry.get("class", "")),
                    "what": str(entry.get("what", "")),
                    "regex": regex,
                }
            )
    unique = {tuple(sorted(hit.items())): hit for hit in hits}
    return sorted(
        unique.values(),
        key=lambda hit: (
            hit["driver"],
            hit["class"],
            hit["what"],
            hit["regex"],
        ),
    )


def _baseline_skip_hits(w_path: str, log_text: str) -> list[dict[str, str]]:
    header = re.compile(
        r"^-- running sibling: std_([A-Za-z0-9_]+)_exercise\.sh\s*$",
        re.MULTILINE,
    )
    matches = list(header.finditer(log_text))
    hits: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        driver = match.group(1)
        section_end = matches[index + 1].start() if index + 1 < len(matches) else len(log_text)
        section = log_text[match.end():section_end]
        census_path = os.path.join(w_path, "proof", "census", f"{driver}.json")
        if not os.path.isfile(census_path):
            continue
        census = _load_json(census_path)
        if not isinstance(census, dict):
            raise ValueError(f"census is not an object: {census_path}")
        hits.extend(_skip_hits(census, section))
    unique = {tuple(sorted(hit.items())): hit for hit in hits}
    return sorted(
        unique.values(),
        key=lambda hit: (
            hit["driver"],
            hit["class"],
            hit["what"],
            hit["regex"],
        ),
    )


def cmd_plan(args, *, drivers: Sequence[str] = DRIVERS_29) -> int:
    facts = inspect_pin_inputs(args.p, args.w, args.compiler, drivers)
    with tempfile.TemporaryDirectory(
        prefix="iyi-plan-atime-",
        dir="/private/tmp",
    ) as probe_dir:
        probe = probe_atime_observable(probe_dir)
    print("Observed Corpus Proof Plan")
    print(f"  P Path:    {facts['p_path']}")
    print(f"  W Path:    {facts['w_path']}")
    print(f"  Compiler:  {facts['compiler_path']}")
    print(f"  P SHA:     {facts['p_source_sha']}")
    print(f"  W HEAD:    {facts['w_head']}")
    print(f"  Version:   {facts['compiler_version_line']}")
    print(f"  BIN SHA:   {facts['compiler_sha256']}")
    print(f"  Timeout:   {facts['timeout_path']} ({facts['timeout_version']})")
    print(f"  Platform:  {facts['platform_tmp']}")
    print(
        "  Probe:     "
        f"sha256={probe['sha256']} inode={probe['inode']} "
        f"atime={probe['atime_after_exec_ns']}"
    )
    print(f"  Censuses:  {len(facts['census_sha256'])} validated")
    return 0


def cmd_pin(args, *, drivers: Sequence[str] = DRIVERS_29) -> int:
    pin = write_pin(args.report_dir, args.p, args.w, args.compiler, drivers)
    print(f"Pin successfully written to {os.path.join(args.report_dir, 'pin.json')}")
    print(f"  Chain ID:  {pin['chain_id']}")
    print(f"  P SHA:     {pin['p_source_sha']}")
    print(f"  W HEAD:    {pin['w_head']}")
    print(f"  Compiler:  {pin['compiler_sha256']}")
    print(f"  Platform:  {pin['platform_tmp']}")
    return 0


def cmd_run1(args, *, std_exercises: int = RUN1_STD_EXERCISES, siblings: int = RUN1_SIBLINGS, corpus: int = RUN1_CORPUS, rg2r_min: int = RG2R_MIN, disk_min_gb: float = DISK_MIN_GB, baseline_w_path: str | None = None, rg9_work_path: str | None = None) -> int:
    pin = load_pin(args.report_dir)
    attempt_dir = next_attempt_dir(os.path.join(args.report_dir, "run1"))
    started_ns = time.time_ns()
    checks: dict[str, str] = {}
    reasons: list[str] = []
    survivors: list[int] = []
    w_path = pin["w_path"]
    compiler = pin["compiler_path"]

    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if not _check_stage_disk(
        args.report_dir,
        disk_min_gb,
        checks,
        reasons,
        check_name="identity",
        low_status="STOP",
    ):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    gate_1_1_text = ""
    gate_1_4_text = ""

    try:
        result, output = _run_gate(
            ["bash", "bench/stale_equivalence.sh", "all"],
            pin=pin,
            attempt_dir=attempt_dir,
            stage_name="run1_1",
            additions={"IYI": compiler},
            cwd=w_path,
        )
        survivors.extend(result.survivors)
        gate_1_1_text = output.decode("utf-8", errors="replace")
        if result.interrupted_signal is not None:
            checks["gate-1.1"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        else:
            required = (
                r"^RG2 PASSED: ",
                r"^RG2a PASSED: ",
                r"^RG5 trace half PASSED: ",
            )
            missing = [
                pattern
                for pattern in required
                if not re.search(pattern, gate_1_1_text, re.MULTILINE)
            ]
            if result.returncode != 0 or result.timed_out or missing:
                checks["gate-1.1"] = "FAIL"
                reasons.append(
                    f"gate 1.1 exit={result.returncode} missing={missing}"
                )
            else:
                checks["gate-1.1"] = "PASS"
        rg2r = re.search(
            r"^RG2r PASSED: all ([0-9]+) probes",
            gate_1_1_text,
            re.MULTILINE,
        )
        if rg2r and int(rg2r.group(1)) >= rg2r_min:
            checks["rg2r-count"] = "PASS"
        else:
            checks["rg2r-count"] = "FAIL"
            reasons.append(
                f"RG2r count is {rg2r.group(1) if rg2r else 'missing'}, expected at least {rg2r_min}"
            )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks["gate-1.1"] = "FAIL"
        checks["rg2r-count"] = "FAIL"
        reasons.append(f"gate 1.1 error: {error}")
    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if any(reason.startswith("interrupted by signal ") for reason in reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    try:
        result, output = _run_gate(
            ["bash", "bench/std_observe_exercise.sh"],
            pin=pin,
            attempt_dir=attempt_dir,
            stage_name="run1_2",
            additions={"IYI": compiler},
            cwd=w_path,
        )
        survivors.extend(result.survivors)
        text = output.decode("utf-8", errors="replace")
        if result.interrupted_signal is not None:
            checks["gate-1.2"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        elif (
            result.returncode == 0
            and not result.timed_out
            and "OK: bench/std_observe_exercise.sh passed all checks" in text
        ):
            checks["gate-1.2"] = "PASS"
        else:
            checks["gate-1.2"] = "FAIL"
            reasons.append(f"gate 1.2 exit={result.returncode} or sentinel missing")
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks["gate-1.2"] = "FAIL"
        reasons.append(f"gate 1.2 error: {error}")
    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if any(reason.startswith("interrupted by signal ") for reason in reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    rg9_work = rg9_work_path or os.path.join(attempt_dir, "rg9_work")
    try:
        os.makedirs(rg9_work, exist_ok=False)
        result, output = _run_gate(
            [
                pin["python_path"],
                "bench/stale_rg9.py",
                "--repo",
                w_path,
                "--compiler",
                compiler,
                "--work",
                rg9_work,
            ],
            pin=pin,
            attempt_dir=attempt_dir,
            stage_name="run1_3",
            additions={"IYI": compiler},
            cwd=w_path,
        )
        survivors.extend(result.survivors)
        text = output.decode("utf-8", errors="replace")
        sentinel = re.search(
            rf"^RG9 PASSED: {corpus} corpus programs$",
            text,
            re.MULTILINE,
        )
        if result.interrupted_signal is not None:
            checks["gate-1.3"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        elif result.returncode == 0 and not result.timed_out and sentinel:
            checks["gate-1.3"] = "PASS"
        else:
            checks["gate-1.3"] = "FAIL"
            reasons.append(
                f"gate 1.3 exit={result.returncode}; expected RG9 count {corpus}"
            )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks["gate-1.3"] = "FAIL"
        reasons.append(f"gate 1.3 error: {error}")
    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if any(reason.startswith("interrupted by signal ") for reason in reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    try:
        result, output = _run_gate(
            ["bash", "bench/std_exercise.sh"],
            pin=pin,
            attempt_dir=attempt_dir,
            stage_name="run1_4",
            additions={"IYI": compiler, "STD_SIBLINGS": "1"},
            cwd=w_path,
        )
        survivors.extend(result.survivors)
        gate_1_4_text = output.decode("utf-8", errors="replace")
        phrases = (
            "Standard library foundation: traits, cmp, enumerable",
            f"all {std_exercises} exercises answer the same from source and from artifacts",
            f"== shard 1 of 1: {siblings} of {siblings} sibling exercises",
        )
        header_count = len(
            re.findall(r"^-- running sibling: ", gate_1_4_text, re.MULTILINE)
        )
        if result.interrupted_signal is not None:
            checks["gate-1.4"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        elif (
            result.returncode == 0
            and not result.timed_out
            and all(phrase in gate_1_4_text for phrase in phrases)
            and header_count == siblings
        ):
            checks["gate-1.4"] = "PASS"
        else:
            checks["gate-1.4"] = "FAIL"
            reasons.append(
                f"gate 1.4 exit={result.returncode}; sibling headers={header_count}, expected={siblings}"
            )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks["gate-1.4"] = "FAIL"
        reasons.append(f"gate 1.4 error: {error}")
    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if any(reason.startswith("interrupted by signal ") for reason in reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    exclusions = _exclusions(gate_1_1_text)
    sample_exclusions = [
        entry for entry in exclusions if entry["program"].startswith("samples/")
    ]
    if sample_exclusions:
        checks["exclusions"] = "FAIL"
        reasons.extend(
            "UNEXPLAINED-SAMPLE-EXCLUSION: "
            f"{entry['program']} ({entry['reason']})"
            for entry in sample_exclusions
        )
    else:
        checks["exclusions"] = "PASS"
    _write_json_atomic(os.path.join(attempt_dir, "exclusions.json"), exclusions)

    try:
        baseline = _baseline_skip_hits(
            baseline_w_path or w_path,
            gate_1_4_text,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        baseline = []
        checks["baseline-skips"] = "FAIL"
        reasons.append(f"baseline skip capture failed: {error}")
    else:
        checks["baseline-skips"] = "PASS"
    _write_json_atomic(
        os.path.join(attempt_dir, "baseline_skips.json"),
        baseline,
    )

    record = _finish_attempt(
        attempt_dir, pin, "run1", checks, reasons, started_ns, survivors
    )
    print(f"Run 1 {record['status']}: {attempt_dir}")
    return 0 if record["status"] == "PASS" else 1


def _read_run2_rows(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid run2 row {number}: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"run2 row {number} is not an object")
            rows.append(row)
    return rows


def cmd_run2(args, *, expected_counts: tuple[int, int, int] = RUN2_COUNTS, disk_min_gb: float = DISK_MIN_GB) -> int:
    pin = load_pin(args.report_dir)
    attempt_dir = next_attempt_dir(os.path.join(args.report_dir, "run2"))
    started_ns = time.time_ns()
    checks: dict[str, str] = {}
    reasons: list[str] = []
    survivors: list[int] = []

    if not _check_stage_identity(pin, checks, reasons):
        record = _finish_attempt(
            attempt_dir, pin, "run2", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1
    if not _check_stage_disk(
        args.report_dir,
        disk_min_gb,
        checks,
        reasons,
        check_name="identity",
        low_status="STOP",
    ):
        record = _finish_attempt(
            attempt_dir, pin, "run2", checks, reasons, started_ns, survivors
        )
        return 0 if record["status"] == "PASS" else 1

    samples, std, total = expected_counts
    report_path = os.path.join(attempt_dir, "run2.jsonl")
    work_root = os.path.join(attempt_dir, "scratch")
    os.makedirs(work_root, exist_ok=False)
    env = fresh_stage_env(pin, attempt_dir, "run2")
    command = [
        pin["python_path"],
        "-B",
        os.path.join(pin["w_path"], "proof", "artifact_legs.py"),
        "--repo",
        pin["w_path"],
        "--compiler",
        pin["compiler_path"],
        "--work",
        work_root,
        "--report",
        report_path,
        "--workers",
        "2",
        "--nm",
        pin["nm_path"],
        "--expect-samples",
        str(samples),
        "--expect-std",
        str(std),
        "--expect-total",
        str(total),
    ]
    try:
        result, _output = run_logged(
            command,
            cwd=pin["w_path"],
            env=env,
            log_path=os.path.join(attempt_dir, "run2.log"),
            times_path=os.path.join(attempt_dir, "run2.times"),
            limit_sec=None,
        )
        survivors.extend(result.survivors)
        if result.interrupted_signal is not None:
            checks["legs"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        else:
            rows = _read_run2_rows(report_path)
            statuses = [str(row.get("status", "FAIL")) for row in rows]
            if "STOP" in statuses:
                checks["legs"] = "STOP"
            elif result.returncode == 0 and statuses and all(
                status == "PASS" for status in statuses
            ):
                checks["legs"] = "PASS"
            else:
                checks["legs"] = "FAIL"
            if checks["legs"] != "PASS":
                reasons.append(
                    f"artifact legs exit={result.returncode}; statuses={statuses}"
                )
            sample_count = sum(row.get("kind") == "sample" for row in rows)
            std_count = sum(row.get("kind") == "std" for row in rows)
            actual = (sample_count, std_count, len(rows))
            if actual == expected_counts:
                checks["counts"] = "PASS"
            else:
                checks["counts"] = "FAIL"
                reasons.append(
                    f"artifact counts={actual}, expected={expected_counts}"
                )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks["legs"] = "FAIL"
        checks["counts"] = "FAIL"
        reasons.append(f"artifact legs error: {error}")

    _check_stage_identity(pin, checks, reasons)
    record = _finish_attempt(
        attempt_dir, pin, "run2", checks, reasons, started_ns, survivors
    )
    print(f"Run 2 {record['status']}: {attempt_dir}")
    return 0 if record["status"] == "PASS" else 1


def _driver_from_program(program: str) -> str | None:
    base = os.path.basename(program)
    match = re.fullmatch(r"std_(.+)_exercise\.iyi", base)
    return match.group(1) if match else None


def _compute_required_drivers(drivers: Sequence[str], exclusions_path: str, run2_path: str) -> list[str]:
    required = list(dict.fromkeys(drivers))
    exclusions = _load_json(exclusions_path)
    if not isinstance(exclusions, list):
        raise ValueError("exclusions.json is not a list")
    additions: set[str] = set()
    for entry in exclusions:
        if not isinstance(entry, dict):
            raise ValueError("exclusions.json contains a non-object")
        program = entry.get("program")
        if not isinstance(program, str):
            raise ValueError("exclusion has no string program")
        if program.startswith("bench/std_"):
            driver = _driver_from_program(program)
            if driver:
                additions.add(driver)
    for row in _read_run2_rows(run2_path):
        if row.get("p_nonzero") is True:
            base = row.get("base")
            name = row.get("name")
            candidate = base if isinstance(base, str) else name
            if not isinstance(candidate, str):
                raise ValueError("p_nonzero row has no base or name")
            driver = _driver_from_program(candidate)
            if driver is None:
                driver = re.sub(r"^std_", "", os.path.basename(candidate))
                driver = re.sub(r"_exercise(?:\.iyi)?$", "", driver)
            if driver:
                additions.add(driver)
    for driver in sorted(additions):
        if driver not in required:
            required.append(driver)
    return required


def _run3_prerequisites(report_dir: str) -> tuple[str, str, str] | None:
    run1_attempt = latest_attempt_dir(os.path.join(report_dir, "run1"))
    run2_attempt = latest_attempt_dir(os.path.join(report_dir, "run2"))
    if run1_attempt is None or run2_attempt is None:
        return None
    exclusions = os.path.join(run1_attempt, "exclusions.json")
    baseline = os.path.join(run1_attempt, "baseline_skips.json")
    run2 = os.path.join(run2_attempt, "run2.jsonl")
    if not all(os.path.isfile(path) for path in (exclusions, baseline, run2)):
        return None
    return exclusions, baseline, run2


def _empty_run3_checks(status: str, check_name: str) -> dict[str, str]:
    return {check_name: status}


def _record_run3_configuration_failure(report_dir: str, pin: dict, selected: Sequence[str], status: str, reason: str) -> None:
    for driver in selected:
        attempt_dir = next_attempt_dir(
            os.path.join(report_dir, "run3", driver)
        )
        _finish_attempt(
            attempt_dir,
            pin,
            f"run3/{driver}",
            _empty_run3_checks(status, "census"),
            [reason],
            time.time_ns(),
            (),
        )


def _baseline_keys(value: object) -> set[tuple[str, str, str, str]]:
    if not isinstance(value, list):
        raise ValueError("baseline_skips.json is not a list")
    keys: set[tuple[str, str, str, str]] = set()
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError("baseline skip is not an object")
        keys.add(
            (
                str(entry.get("driver", "")),
                str(entry.get("class", "")),
                str(entry.get("what", "")),
                str(entry.get("regex", "")),
            )
        )
    return keys


def _classify_driver_skips(census: dict, log_text: str, baseline: set[tuple[str, str, str, str]]) -> tuple[str, list[str]]:
    hits = _skip_hits(census, log_text)
    hit_keys = {
        (hit["driver"], hit["class"], hit["what"], hit["regex"])
        for hit in hits
    }
    tool_hits = [hit for hit in hits if hit["class"] == "tool"]
    missing = sorted(hit_keys - baseline)
    reasons = [
        f"platform limit {hit['driver']}: {hit['what']}"
        for hit in hits
        if hit["class"] == "platform"
    ]
    if tool_hits:
        reasons.extend(
            f"tool skip {hit['driver']}: {hit['what']}" for hit in tool_hits
        )
        return "ENV-BLOCKED", reasons
    if missing:
        reasons.append(f"skip hits absent from baseline: {missing}")
        return "PARTIAL", reasons
    return "PASS", reasons


def _launcher_text(pin: dict, shim_config_path: str) -> str:
    return (
        "#!/bin/bash\nexec "
        f"{shlex.quote(pin['python_path'])} -B "
        f"{shlex.quote(os.path.join(pin['w_path'], 'proof', 'roundtrip_shim.py'))} "
        f"--config {shlex.quote(shim_config_path)} -- \"$@\"\n"
    )


def _run_one_driver(report_dir: str, pin: dict, driver: str, baseline: set[tuple[str, str, str, str]], *, driver_limit_sec: float, grace_sec: float, disk_min_gb: float, stat_fn, setup_base: str | None = None, driver_log_path: str | None = None) -> dict:
    attempt_dir = next_attempt_dir(
        os.path.join(report_dir, "run3", driver)
    )
    attempt = _attempt_number(attempt_dir)
    started_ns = time.time_ns()
    checks: dict[str, str] = {}
    reasons: list[str] = []
    survivors: list[int] = []
    unit = f"run3/{driver}"
    w_path = pin["w_path"]
    census_path = os.path.join(w_path, "proof", "census", f"{driver}.json")

    if not os.path.isfile(census_path):
        checks["census"] = "CENSUS-MISSING"
        reasons.append(f"CENSUS-MISSING: {census_path}")
        return _finish_attempt(
            attempt_dir, pin, unit, checks, reasons, started_ns, survivors
        )
    try:
        census_value = _load_json(census_path)
        if not isinstance(census_value, dict):
            raise ValueError("census is not an object")
        census = census_value
        script_relpath = census.get("script")
        if not isinstance(script_relpath, str):
            raise ValueError("census script is not a string")
        driver_script = os.path.join(w_path, script_relpath)
        if not os.path.isfile(driver_script):
            checks["census"] = "PASS"
            checks["exit"] = "FAIL"
            reasons.append(f"driver script missing: {driver_script}")
            return _finish_attempt(
                attempt_dir, pin, unit, checks, reasons, started_ns, survivors
            )
        with open(driver_script, "rb") as script_file:
            script_bytes = script_file.read()
        violations = validate_census(census, script_bytes, script_relpath)
        if violations:
            checks["census"] = "FAIL"
            reasons.append(
                f"census invalid: {json.dumps(violations, sort_keys=True)}"
            )
            return _finish_attempt(
                attempt_dir, pin, unit, checks, reasons, started_ns, survivors
            )
        checks["census"] = "PASS"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        checks["census"] = "FAIL"
        reasons.append(f"census error: {error}")
        return _finish_attempt(
            attempt_dir, pin, unit, checks, reasons, started_ns, survivors
        )

    if not _check_stage_identity(pin, checks, reasons):
        return _finish_attempt(
            attempt_dir, pin, unit, checks, reasons, started_ns, survivors
        )
    if not _check_stage_disk(
        report_dir,
        disk_min_gb,
        checks,
        reasons,
        check_name="disk",
        low_status="STOP",
    ):
        return _finish_attempt(
            attempt_dir, pin, unit, checks, reasons, started_ns, survivors
        )

    try:
        layout_base = setup_base or attempt_dir
        t_dir = os.path.realpath(os.path.join(layout_base, "t"))
        c_dir = os.path.realpath(os.path.join(layout_base, "c"))
        s_dir = os.path.realpath(os.path.join(layout_base, "s"))
        bin_dir = os.path.realpath(os.path.join(layout_base, "bin"))
        for directory in (t_dir, c_dir, s_dir, bin_dir):
            os.makedirs(directory, exist_ok=False)
        launcher_path = os.path.join(bin_dir, "iyi")
        config_path = os.path.join(attempt_dir, "shim.json")
        ledger_path = os.path.join(attempt_dir, "ledger.jsonl")
        nonce = secrets.token_hex(16)
        config = {
            "real": os.path.realpath(pin["compiler_path"]),
            "census": os.path.realpath(census_path),
            "ledger": ledger_path,
            "nonce": nonce,
            "driver": driver,
            "work_tmp": t_dir,
            "scratch": s_dir,
            "repo": os.path.realpath(w_path),
            "canonical_roots": pin["canonical_roots"],
            "platform_tmp": pin["platform_tmp"],
        }
        _write_json_atomic(config_path, config)
        with open(launcher_path, "x", encoding="utf-8") as launcher:
            launcher.write(_launcher_text(pin, config_path))
        os.chmod(launcher_path, 0o755)
        with open(ledger_path, "x", encoding="utf-8") as ledger:
            ledger.write(
                json.dumps(
                    {
                        "v": 1,
                        "kind": "header",
                        "nonce": nonce,
                        "driver": driver,
                        "attempt": attempt,
                        "chain_id": pin["chain_id"],
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
        env = base_env(
            pin,
            {
                "IYI": launcher_path,
                "TMPDIR": t_dir,
                "IYI_CACHE_DIR": c_dir,
            },
        )
    except (OSError, TypeError, ValueError) as error:
        checks["exit"] = "FAIL"
        reasons.append(f"driver setup error: {error}")
        return _finish_attempt(
            attempt_dir, pin, unit, checks, reasons, started_ns, survivors
        )
    try:
        result, output = run_logged(
            ["bash", script_relpath],
            cwd=w_path,
            env=env,
            log_path=driver_log_path or os.path.join(attempt_dir, "driver.log"),
            times_path=os.path.join(attempt_dir, "driver.times"),
            limit_sec=driver_limit_sec,
            grace_sec=grace_sec,
        )
        survivors.extend(result.survivors)
        log_text = output.decode("utf-8", errors="replace")
        if result.interrupted_signal is not None:
            checks["exit"] = "FAIL"
            reasons.append(f"interrupted by signal {result.interrupted_signal}")
        elif result.timed_out:
            checks["exit"] = "TIMEOUT"
            reasons.append(f"driver exceeded {driver_limit_sec} seconds")
        elif result.returncode != 0:
            checks["exit"] = "FAIL"
            reasons.append(f"driver exit {result.returncode}")
        else:
            checks["exit"] = "PASS"

        sentinel_regex = census.get("pass_sentinel", {}).get("regex")
        if isinstance(sentinel_regex, str) and re.search(
            sentinel_regex, log_text, re.MULTILINE
        ):
            checks["sentinel"] = "PASS"
        else:
            checks["sentinel"] = "FAIL"
            reasons.append("driver pass sentinel missing")

        if "observed-roundtrip-shim: REFUSED" in log_text:
            checks["no-refused"] = "MISCLASSIFIED"
            reasons.append("driver log contains a shim REFUSED line")
        else:
            checks["no-refused"] = "PASS"

        skip_status, skip_reasons = _classify_driver_skips(
            census,
            log_text,
            baseline,
        )
        checks["skips"] = skip_status
        reasons.extend(skip_reasons)

        verdict = verify_ledger(
            ledger_path,
            census=census,
            driver=driver,
            nonce=nonce,
            attempt=attempt,
            chain_id=pin["chain_id"],
            work_tmp=t_dir,
            repo=w_path,
            platform_tmp=pin["platform_tmp"],
            stat_fn=stat_fn,
        )
        statuses = sorted(verdict.statuses)
        checks["ledger"] = statuses[0] if statuses else "PASS"
        reasons.extend(f"ledger {status}" for status in statuses)
        reasons.extend(f"ledger: {reason}" for reason in verdict.reasons)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        checks.setdefault("exit", "FAIL")
        checks.setdefault("sentinel", "FAIL")
        checks.setdefault("no-refused", "FAIL")
        checks.setdefault("skips", "FAIL")
        checks.setdefault("ledger", "UNFAITHFUL")
        reasons.append(f"driver execution error: {error}")

    _check_stage_identity(pin, checks, reasons)
    return _finish_attempt(
        attempt_dir, pin, unit, checks, reasons, started_ns, survivors
    )


def cmd_run3(args, *, drivers: Sequence[str] = DRIVERS_29, driver_limit_sec: float = DRIVER_LIMIT_SEC, grace_sec: float = GRACE_SEC, disk_min_gb: float = DISK_MIN_GB, stat_fn=os.stat) -> int:
    pin = load_pin(args.report_dir)
    requested_driver = getattr(args, "driver", "")
    prerequisites = _run3_prerequisites(args.report_dir)
    if prerequisites is None:
        print(
            "REFUSED run3 requires latest run1 exclusions.json and "
            "baseline_skips.json plus latest run2 run2.jsonl",
            file=sys.stderr,
        )
        return 2
    exclusions_path, baseline_path, run2_path = prerequisites
    try:
        required = _compute_required_drivers(
            drivers,
            exclusions_path,
            run2_path,
        )
        baseline = _baseline_keys(_load_json(baseline_path))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"REFUSED invalid run3 prerequisite: {error}", file=sys.stderr)
        return 2

    run3_dir = os.path.join(args.report_dir, "run3")
    os.makedirs(run3_dir, exist_ok=True)
    required_path = os.path.join(run3_dir, "required.json")
    if os.path.exists(required_path):
        try:
            frozen = _load_json(required_path)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            frozen = None
            mismatch_reason = f"required.json unreadable: {error}"
        else:
            mismatch_reason = (
                f"required.json mismatch: frozen={frozen!r}, recomputed={required!r}"
            )
        if frozen != required:
            frozen_drivers = (
                [
                    driver
                    for driver in frozen
                    if isinstance(driver, str)
                ]
                if isinstance(frozen, list)
                else []
            )
            selected = frozen_drivers or required
            _record_run3_configuration_failure(
                args.report_dir,
                pin,
                selected,
                "INVALID",
                mismatch_reason,
            )
            print(f"Run 3 INVALID: {mismatch_reason}", file=sys.stderr)
            return 1
    else:
        _write_json_atomic(required_path, required)

    if requested_driver and requested_driver not in required:
        print(
            f"REFUSED driver {requested_driver!r} is not in required.json",
            file=sys.stderr,
        )
        return 2
    selected = [requested_driver] if requested_driver else required
    failed = False
    for driver in selected:
        record = _run_one_driver(
            args.report_dir,
            pin,
            driver,
            baseline,
            driver_limit_sec=driver_limit_sec,
            grace_sec=grace_sec,
            disk_min_gb=disk_min_gb,
            stat_fn=stat_fn,
        )
        print(f"Run 3 {driver}: {record['status']}")
        if record["status"] != "PASS":
            failed = True
        if record["status"] in ("INVALID", "STOP"):
            break
        if any(
            isinstance(reason, str)
            and reason.startswith("interrupted by signal ")
            for reason in record.get("reasons", [])
        ):
            break
    return 1 if failed else 0


def _validate_record(record: dict | None, *, pin: dict, unit: str, attempt: int, kind: str) -> tuple[str, list[str]]:
    if record is None:
        return "FAIL", [f"{unit} attempt {attempt} result is missing or unreadable"]
    reasons: list[str] = []
    shape_ok = (
        record.get("v") == 1
        and isinstance(record.get("reasons"), list)
        and isinstance(record.get("checks"), dict)
        and isinstance(record.get("started_ns"), int)
        and isinstance(record.get("ended_ns"), int)
        and isinstance(record.get("survivors"), list)
    )
    if not shape_ok:
        reasons.append(f"{unit} attempt {attempt} has an invalid result shape")
    if record.get("chain_id") != pin["chain_id"]:
        reasons.append(f"{unit} attempt {attempt} chain_id mismatch")
    if record.get("unit") != unit:
        reasons.append(f"{unit} attempt {attempt} unit mismatch")
    if record.get("attempt") != attempt:
        reasons.append(f"{unit} attempt {attempt} path/result attempt mismatch")
    computed = recompute_status(record, kind)
    if record.get("status") != computed:
        reasons.append(
            f"{unit} attempt {attempt} forged status "
            f"stored={record.get('status')!r} recomputed={computed!r}"
        )
    if reasons:
        return "FAIL", reasons
    return computed, []


def _collect_final_unit(pin: dict, parent_dir: str, unit: str, kind: str) -> tuple[dict[str, int | str], list[dict[str, int | str]], list[str]]:
    entries = _attempt_entries(parent_dir)
    if not entries:
        return (
            {"attempt": 0, "status": "FAIL"},
            [],
            [f"{unit} has no attempt"],
        )
    earlier: list[dict[str, int | str]] = []
    reasons: list[str] = []
    for attempt, path in entries[:-1]:
        record = load_result(os.path.join(path, "result.json"))
        status, _earlier_reasons = _validate_record(
            record,
            pin=pin,
            unit=unit,
            attempt=attempt,
            kind=kind,
        )
        if status != "PASS":
            earlier.append(
                {"unit": unit, "attempt": attempt, "status": status}
            )
    attempt, path = entries[-1]
    record = load_result(os.path.join(path, "result.json"))
    status, invalid_reasons = _validate_record(
        record,
        pin=pin,
        unit=unit,
        attempt=attempt,
        kind=kind,
    )
    reasons.extend(invalid_reasons)
    if status != "PASS" and isinstance(record, dict):
        recorded_reasons = record.get("reasons")
        if isinstance(recorded_reasons, list):
            reasons.extend(
                f"{unit} attempt {attempt}: {reason}"
                for reason in recorded_reasons
                if isinstance(reason, str)
            )
    if status != "PASS" and not reasons:
        reasons.append(f"{unit} attempt {attempt} status is {status}")
    return {"attempt": attempt, "status": status}, earlier, reasons


def cmd_final(args, *, drivers: Sequence[str] = DRIVERS_29) -> int:
    pin = load_pin(args.report_dir)
    units: dict[str, dict[str, int | str]] = {}
    earlier_failures: list[dict[str, int | str]] = []
    reasons: list[str] = []

    run1, earlier, unit_reasons = _collect_final_unit(
        pin,
        os.path.join(args.report_dir, "run1"),
        "run1",
        "run1",
    )
    units["run1"] = run1
    earlier_failures.extend(earlier)
    reasons.extend(unit_reasons)

    run2, earlier, unit_reasons = _collect_final_unit(
        pin,
        os.path.join(args.report_dir, "run2"),
        "run2",
        "run2",
    )
    units["run2"] = run2
    earlier_failures.extend(earlier)
    reasons.extend(unit_reasons)

    required_path = os.path.join(args.report_dir, "run3", "required.json")
    try:
        required_value = _load_json(required_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        required_value = []
        reasons.append(f"run3 required.json is missing or unreadable: {error}")
    if not isinstance(required_value, list) or not all(
        isinstance(driver, str) for driver in required_value
    ):
        reasons.append("run3 required.json is not a list of drivers")
        required: list[str] = []
    else:
        required = list(required_value)

    prerequisites = _run3_prerequisites(args.report_dir)
    recomputed_required: list[str] = []
    if prerequisites is None:
        reasons.append(
            "latest run1 exclusions/baseline or run2 rows are unavailable"
        )
    else:
        exclusions_path, _baseline_path, run2_path = prerequisites
        try:
            recomputed_required = _compute_required_drivers(
                drivers,
                exclusions_path,
                run2_path,
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            reasons.append(f"run3 required set cannot be recomputed: {error}")
    if required != recomputed_required:
        reasons.append(
            "run3 required.json mismatch: "
            f"frozen={required!r}, recomputed={recomputed_required!r}"
        )

    run1_record = _latest_record(args.report_dir, "run1")
    run2_record = _latest_record(args.report_dir, "run2")
    prerequisite_ends = (
        run1_record.get("ended_ns") if isinstance(run1_record, dict) else None,
        run2_record.get("ended_ns") if isinstance(run2_record, dict) else None,
    )
    latest_prerequisite_end = (
        max(prerequisite_ends)
        if all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in prerequisite_ends
        )
        else None
    )
    if latest_prerequisite_end is None:
        reasons.append("latest run1/run2 results have no valid ended_ns")

    drivers_to_check = list(
        dict.fromkeys([*required, *recomputed_required])
    )
    for driver in drivers_to_check:
        unit = f"run3/{driver}"
        latest, earlier, unit_reasons = _collect_final_unit(
            pin,
            os.path.join(args.report_dir, "run3", driver),
            unit,
            "run3",
        )
        units[unit] = latest
        earlier_failures.extend(earlier)
        reasons.extend(unit_reasons)
        record = _latest_record(args.report_dir, unit)
        started_ns = (
            record.get("started_ns")
            if isinstance(record, dict)
            else None
        )
        if (
            latest_prerequisite_end is not None
            and (
                not isinstance(started_ns, int)
                or isinstance(started_ns, bool)
                or started_ns <= latest_prerequisite_end
            )
        ):
            reasons.append(
                f"{unit} latest attempt is not newer than latest run1/run2"
            )

    identity: dict[str, str] = {
        "status": "PASS",
        "p_source_sha": pin["p_source_sha"],
        "w_head": pin["w_head"],
        "compiler_sha256": pin["compiler_sha256"],
    }
    try:
        check_identity(pin)
    except IdentityError as error:
        identity["status"] = "INVALID"
        reasons.append(f"identity {error.reason}: {error.detail}")

    statuses = [entry["status"] for entry in units.values()]
    if identity["status"] != "PASS":
        status = "INVALID"
    elif reasons or not required or any(value != "PASS" for value in statuses):
        status = "FAIL"
    else:
        status = "PASS"
    final_record = {
        "v": 1,
        "chain_id": pin["chain_id"],
        "status": status,
        "units": units,
        "earlier_failures": sorted(
            earlier_failures,
            key=lambda entry: (str(entry["unit"]), int(entry["attempt"])),
        ),
        "reasons": reasons,
        "limits": list(_FINAL_LIMITS),
        "identity": identity,
    }
    _write_json_atomic(os.path.join(args.report_dir, "final.json"), final_record)
    print(f"Final proof status: {status}")
    return 0 if status == "PASS" else 1


def _latest_record(report_dir: str, unit: str) -> dict | None:
    parent = os.path.join(report_dir, unit)
    attempt = latest_attempt_dir(parent)
    if attempt is None:
        return None
    return load_result(os.path.join(attempt, "result.json"))


def _latest_status(report_dir: str, unit: str) -> str | None:
    record = _latest_record(report_dir, unit)
    return record.get("status") if isinstance(record, dict) else None


def _latest_was_interrupted(report_dir: str, unit: str) -> bool:
    record = _latest_record(report_dir, unit)
    if not isinstance(record, dict):
        return False
    return any(
        isinstance(reason, str)
        and reason.startswith("interrupted by signal ")
        for reason in record.get("reasons", [])
    )


def cmd_all(args, *, drivers: Sequence[str] = DRIVERS_29, std_exercises: int = RUN1_STD_EXERCISES, siblings: int = RUN1_SIBLINGS, corpus: int = RUN1_CORPUS, rg2r_min: int = RG2R_MIN, expected_counts: tuple[int, int, int] = RUN2_COUNTS, driver_limit_sec: float = DRIVER_LIMIT_SEC, grace_sec: float = GRACE_SEC, disk_min_gb: float = DISK_MIN_GB, stat_fn=os.stat, required_path: str | None = None, run3_disk_min_gb: float | None = None) -> int:
    cmd_run1(
        args,
        std_exercises=std_exercises,
        siblings=siblings,
        corpus=corpus,
        rg2r_min=rg2r_min,
        disk_min_gb=disk_min_gb,
    )
    if (
        _latest_status(args.report_dir, "run1") in ("STOP", "INVALID")
        or _latest_was_interrupted(args.report_dir, "run1")
    ):
        return 1
    cmd_run2(
        args,
        expected_counts=expected_counts,
        disk_min_gb=disk_min_gb,
    )
    if (
        _latest_status(args.report_dir, "run2") in ("STOP", "INVALID")
        or _latest_was_interrupted(args.report_dir, "run2")
    ):
        return 1
    run3_return = cmd_run3(
        args,
        drivers=drivers,
        driver_limit_sec=driver_limit_sec,
        grace_sec=grace_sec,
        disk_min_gb=(
            disk_min_gb
            if run3_disk_min_gb is None
            else run3_disk_min_gb
        ),
        stat_fn=stat_fn,
    )
    if run3_return == 2:
        return 2
    required_path = required_path or os.path.join(args.report_dir, "run3", "required.json")
    try:
        required = _load_json(required_path)
    except (OSError, UnicodeError, json.JSONDecodeError):
        required = []
    if isinstance(required, list):
        for driver in required:
            if not isinstance(driver, str):
                continue
            unit = os.path.join("run3", driver)
            status = _latest_status(args.report_dir, unit)
            if (
                status in ("STOP", "INVALID")
                or _latest_was_interrupted(args.report_dir, unit)
            ):
                return 1
    return cmd_final(args, drivers=drivers)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Observed Corpus Proof Runner")
    subparsers = parser.add_subparsers(dest="subcmd", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--p", required=True)
    plan.add_argument("--w", required=True)
    plan.add_argument("--compiler", required=True)

    pin = subparsers.add_parser("pin")
    pin.add_argument("--report-dir", required=True)
    pin.add_argument("--p", required=True)
    pin.add_argument("--w", required=True)
    pin.add_argument("--compiler", required=True)

    for command in ("run1", "run2", "final", "all"):
        stage = subparsers.add_parser(command)
        stage.add_argument("--report-dir", required=True)

    run3 = subparsers.add_parser("run3")
    run3.add_argument("--report-dir", required=True)
    run3.add_argument("--driver", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if os.environ.get("ROUTE_A_DRIVERS"):
        print(
            "run_proof: ROUTE_A_DRIVERS is removed and prohibited; all "
            "drivers must use Route B",
            file=sys.stderr,
        )
        return 2
    args = _parser().parse_args(argv)
    handlers = {
        "plan": cmd_plan,
        "pin": cmd_pin,
        "run1": cmd_run1,
        "run2": cmd_run2,
        "run3": cmd_run3,
        "final": cmd_final,
        "all": cmd_all,
    }
    try:
        return handlers[args.subcmd](args)
    except IdentityError as error:
        print(f"REFUSED {error.reason}: {error.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if sys.flags.optimize:
        print(
            "run_proof: refusing to run under python -O / PYTHONOPTIMIZE",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raise SystemExit(main())
