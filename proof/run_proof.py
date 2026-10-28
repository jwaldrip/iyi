#!/usr/bin/env python3
"""
run_proof.py: Master orchestration for Observed Corpus Proof.
Implements Contract C8 + Amendments A, B, C.

Commands:
  plan, pin, run1, run2, run3, final, all
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time

if sys.flags.optimize:
    sys.stderr.write("run_proof: refusing to run under python -O / PYTHONOPTIMIZE\n")
    sys.exit(2)

if os.environ.get("ROUTE_A_DRIVERS"):
    sys.stderr.write("run_proof: ROUTE_A_DRIVERS is removed and prohibited; all drivers must use Route B\n")
    sys.exit(2)

# Ensure proof directory is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.proofkit import (
    IdentityError,
    LedgerVerificationError,
    base_env,
    check_disk_space,
    check_identity,
    inspect_pin_inputs,
    load_pin,
    run_bounded,
    validate_census,
    verify_ledger,
    write_pin,
)

CORE_29_DRIVERS = [
    "acme", "autocert", "cookie", "dns", "fileserver", "http", "router", "secure_dns",
    "signal", "smtp", "sse", "term", "tls", "websocket",
    "bzip2", "compress", "hpke", "math", "mlkem", "png", "regex", "shlex", "tar", "xz", "zip", "zstd",
    "file", "file_utils", "fuzz"
]


def next_attempt_dir(parent_dir: str) -> str:
    os.makedirs(parent_dir, exist_ok=True)
    existing = [d for d in os.listdir(parent_dir) if d.startswith("a") and d[1:].isdigit()]
    next_idx = 1
    if existing:
        next_idx = max(int(d[1:]) for d in existing) + 1
    att_dir = os.path.join(parent_dir, f"a{next_idx}")
    os.makedirs(att_dir, exist_ok=True)
    return att_dir

def read_log(log_path: str) -> bytes:
    with open(log_path, "rb") as log_file:
        return log_file.read()


def fresh_stage_env(
    pin: dict,
    attempt_dir: str,
    stage_name: str,
    additions: dict[str, str] | None = None,
) -> dict[str, str]:
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


def run_logged(
    cmd: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    log_path: str,
    times_path: str,
    limit_sec: float | None,
    grace_sec: float = 30.0,
):
    result = run_bounded(
        cmd,
        cwd,
        env,
        log_path,
        times_path,
        limit_sec,
        grace_sec,
    )
    if result.interrupted_signal is not None:
        raise RuntimeError(
            f"interrupted by signal {result.interrupted_signal}; "
            f"survivors={list(result.survivors)}"
        )
    return result, read_log(log_path)


def cmd_plan(args):
    facts = inspect_pin_inputs(
        args.p,
        args.w,
        args.compiler,
        CORE_29_DRIVERS,
    )
    print("Observed Corpus Proof Plan")
    print(f"  P Path:    {facts['p_path']}")
    print(f"  W Path:    {facts['w_path']}")
    print(f"  Compiler:  {facts['compiler_path']}")
    print(f"  P SHA:     {facts['p_source_sha']}")
    print(f"  W HEAD:    {facts['w_head']}")
    print(f"  Version:   {facts['compiler_version_line']}")
    print(f"  BIN SHA:   {facts['compiler_sha256']}")
    print(f"  Timeout:   {facts['timeout_path']} ({facts['timeout_version']})")
    print(f"  Censuses:  {len(facts['census_sha256'])} validated")


def cmd_pin(args):
    pin = write_pin(
        args.report_dir,
        args.p,
        args.w,
        args.compiler,
        CORE_29_DRIVERS,
    )
    print(f"Pin successfully written to {os.path.join(args.report_dir, 'pin.json')}")
    print(f"  Chain ID:  {pin['chain_id']}")
    print(f"  P SHA:     {pin['p_source_sha']}")
    print(f"  W HEAD:    {pin['w_head']}")
    print(f"  Compiler:  {pin['compiler_sha256']}")


def cmd_run1(args):
    pin = load_pin(args.report_dir)
    check_identity(pin)
    check_disk_space(args.report_dir, 20.0)

    w_path = pin["w_path"]
    compiler = pin["compiler_path"]
    r_dir = args.report_dir

    r1_dir = os.path.join(r_dir, "run1")
    att_dir = next_attempt_dir(r1_dir)
    print(f"=== Starting Run 1 in {att_dir} ===")

    # 1.1 stale_equivalence.sh all
    print("--- Run 1.1: stale_equivalence.sh all ---")
    log_1_1 = os.path.join(att_dir, "run1_1_equiv.log")
    times_1_1 = os.path.join(att_dir, "run1_1_equiv.times")
    env_1_1 = fresh_stage_env(
        pin,
        att_dir,
        "run1_1",
        {"IYI": compiler},
    )
    result, stdout = run_logged(
        ["bash", "bench/stale_equivalence.sh", "all"],
        cwd=w_path,
        env=env_1_1,
        log_path=log_1_1,
        times_path=times_1_1,
        limit_sec=None,
    )
    if result.returncode != 0 or result.timed_out:
        raise RuntimeError(
            f"Run 1.1 failed (exit {result.returncode}, "
            f"timed_out={result.timed_out})"
        )
    out_text = stdout.decode(errors="replace")
    for pat in [r"^RG2 PASSED: ", r"^RG2a PASSED: ", r"^RG2r PASSED: all (\d+) probes", r"^RG5 trace half PASSED: "]:
        if not re.search(pat, out_text, re.MULTILINE):
            raise RuntimeError(f"Run 1.1 output missing required pattern: {pat}")
    check_identity(pin)

    # 1.2 std_observe_exercise.sh
    print("--- Run 1.2: std_observe_exercise.sh ---")
    log_1_2 = os.path.join(att_dir, "run1_2_observe.log")
    times_1_2 = os.path.join(att_dir, "run1_2_observe.times")
    env_1_2 = fresh_stage_env(
        pin,
        att_dir,
        "run1_2",
        {"IYI": compiler},
    )
    result, stdout = run_logged(
        ["bash", "bench/std_observe_exercise.sh"],
        cwd=w_path,
        env=env_1_2,
        log_path=log_1_2,
        times_path=times_1_2,
        limit_sec=None,
    )
    if (
        result.returncode != 0
        or result.timed_out
        or "OK: bench/std_observe_exercise.sh passed all checks"
        not in stdout.decode(errors="replace")
    ):
        raise RuntimeError(f"Run 1.2 failed (exit {result.returncode})")
    check_identity(pin)

    # 1.3 stale_rg9.py
    print("--- Run 1.3: stale_rg9.py ---")
    log_1_3 = os.path.join(att_dir, "run1_3_rg9.log")
    times_1_3 = os.path.join(att_dir, "run1_3_rg9.times")
    rg9_work = os.path.join(att_dir, "rg9_work")
    os.makedirs(rg9_work, exist_ok=True)
    env_1_3 = fresh_stage_env(
        pin,
        att_dir,
        "run1_3",
        {"IYI": compiler},
    )
    result, stdout = run_logged(
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
        cwd=w_path,
        env=env_1_3,
        log_path=log_1_3,
        times_path=times_1_3,
        limit_sec=None,
    )
    if (
        result.returncode != 0
        or result.timed_out
        or not re.search(
            r"^RG9 PASSED: 141 corpus programs",
            stdout.decode(errors="replace"),
            re.MULTILINE,
        )
    ):
        raise RuntimeError(f"Run 1.3 failed (exit {result.returncode})")
    check_identity(pin)

    # 1.4 std_exercise.sh
    print("--- Run 1.4: std_exercise.sh (unsharded siblings) ---")
    log_1_4 = os.path.join(att_dir, "run1_4_std.log")
    times_1_4 = os.path.join(att_dir, "run1_4_std.times")
    env_1_4 = fresh_stage_env(
        pin,
        att_dir,
        "run1_4",
        {"IYI": compiler, "STD_SIBLINGS": "1"},
    )
    result, stdout = run_logged(
        ["bash", "bench/std_exercise.sh"],
        cwd=w_path,
        env=env_1_4,
        log_path=log_1_4,
        times_path=times_1_4,
        limit_sec=None,
    )
    if result.returncode != 0 or result.timed_out:
        raise RuntimeError(f"Run 1.4 failed (exit {result.returncode})")

    out_1_4 = stdout.decode(errors="replace")
    for req in [
        "Standard library foundation: traits, cmp, enumerable",
        "all 114 exercises answer the same from source and from artifacts",
        "== shard 1 of 1: 115 of 115 sibling exercises",
    ]:
        if req not in out_1_4:
            raise RuntimeError(f"Run 1.4 missing required phrase: {req}")

    num_headers = len(re.findall(r"-- running sibling: ", out_1_4))
    if num_headers != 115:
        raise RuntimeError(f"Run 1.4 sibling header count is {num_headers}, expected 115")

    # Parse exclusions from 1.1 log
    excl_re = re.compile(r"^\s*\[excluded after calibration\]\s*(\S+):\s*(.*)$", re.MULTILINE)
    exclusions = []
    for match in excl_re.finditer(out_text):
        prog = match.group(1)
        reason = match.group(2)
        if prog.startswith("samples/"):
            raise RuntimeError(f"UNEXPLAINED-SAMPLE-EXCLUSION: {prog} ({reason})")
        exclusions.append({"program": prog, "reason": reason})

    with open(os.path.join(r1_dir, "exclusions.json"), "w", encoding="utf-8") as f:
        json.dump(exclusions, f, indent=2)

    check_identity(pin)
    print("=== Run 1 PASSED ===")


def cmd_run2(args):
    pin = load_pin(args.report_dir)
    check_identity(pin)
    check_disk_space(args.report_dir, 20.0)

    w_path = pin["w_path"]
    compiler = pin["compiler_path"]
    r_dir = args.report_dir

    r2_dir = os.path.join(r_dir, "run2")
    att_dir = next_attempt_dir(r2_dir)
    report_jsonl = os.path.join(att_dir, "run2.jsonl")
    log_path = os.path.join(att_dir, "run2.log")
    times_path = os.path.join(att_dir, "run2.times")
    work_scratch = os.path.join(att_dir, "scratch")
    os.makedirs(work_scratch, exist_ok=True)

    print(f"=== Starting Run 2 in {att_dir} ===")
    env = fresh_stage_env(pin, att_dir, "run2")
    result, _output = run_logged(
        [
            pin["python_path"],
            "-B",
            os.path.join(w_path, "proof/artifact_legs.py"),
            "--repo",
            w_path,
            "--compiler",
            compiler,
            "--work",
            work_scratch,
            "--report",
            report_jsonl,
            "--workers",
            "2",
        ],
        cwd=w_path,
        env=env,
        log_path=log_path,
        times_path=times_path,
        limit_sec=None,
    )

    if result.returncode != 0 or result.timed_out:
        raise RuntimeError(f"Run 2 failed (exit {result.returncode})")

    check_identity(pin)
    print("=== Run 2 PASSED ===")


def cmd_run3(args):
    pin = load_pin(args.report_dir)
    check_identity(pin)
    check_disk_space(args.report_dir, 20.0)

    w_path = pin["w_path"]
    compiler = pin["compiler_path"]
    r_dir = args.report_dir
    r3_dir = os.path.join(r_dir, "run3")
    os.makedirs(r3_dir, exist_ok=True)

    # Determine required drivers
    req_file = os.path.join(r3_dir, "required.json")
    if not os.path.isfile(req_file):
        drivers = list(CORE_29_DRIVERS)

        # Add RG2 exclusions if present
        excl_file = os.path.join(r_dir, "run1/exclusions.json")
        if os.path.isfile(excl_file):
            with open(excl_file, "r", encoding="utf-8") as f:
                excls = json.load(f)
            for ex in excls:
                base = os.path.basename(ex["program"]).replace(".iyi", "")
                d_name = re.sub(r"^std_", "", base).replace("_exercise", "")
                if d_name not in drivers:
                    drivers.append(d_name)

        # Add p_nonzero rows from Run 2
        r2_reports = glob.glob(os.path.join(r_dir, "run2/a*/run2.jsonl"))
        if r2_reports:
            latest_r2 = sorted(r2_reports)[-1]
            with open(latest_r2, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        row = json.loads(line)
                        if row.get("p_nonzero"):
                            base = row.get("base", "")
                            d_name = re.sub(r"^std_", "", base).replace("_exercise", "")
                            if d_name not in drivers:
                                drivers.append(d_name)

        with open(req_file, "w", encoding="utf-8") as f:
            json.dump(drivers, f, indent=2)
    else:
        with open(req_file, "r", encoding="utf-8") as f:
            drivers = json.load(f)

    selected_drivers = [args.driver] if args.driver else drivers
    print(f"=== Starting Run 3 over {len(selected_drivers)} drivers ===")

    for drv in selected_drivers:
        print(f"--- Driver: {drv} ---")
        check_identity(pin)
        check_disk_space(r_dir, 20.0)

        census_file = os.path.join(w_path, f"proof/census/{drv}.json")
        if not os.path.isfile(census_file):
            raise RuntimeError(f"CENSUS-MISSING: No census file for driver '{drv}'")

        with open(census_file, "r", encoding="utf-8") as f:
            census_data = json.load(f)
        script_relpath = census_data.get("script", "")
        with open(os.path.join(w_path, script_relpath), "rb") as script_file:
            script_bytes = script_file.read()
        census_violations = validate_census(
            census_data,
            script_bytes,
            script_relpath,
        )
        if census_violations:
            raise RuntimeError(
                f"CENSUS-INVALID: {drv}: "
                f"{json.dumps(census_violations, sort_keys=True)}"
            )

        drv_dir = os.path.join(r3_dir, drv)
        att_dir = next_attempt_dir(drv_dir)

        t_dir = os.path.join(att_dir, "t")
        c_dir = os.path.join(att_dir, "c")
        s_dir = os.path.join(att_dir, "s")
        bin_dir = os.path.join(att_dir, "bin")
        for d in [t_dir, c_dir, s_dir, bin_dir]:
            os.makedirs(d, exist_ok=True)

        launcher_path = os.path.join(bin_dir, "iyi")
        shim_config_path = os.path.join(att_dir, "shim.json")
        ledger_path = os.path.join(att_dir, "ledger.jsonl")

        nonce = hashlib.sha256(f"{drv}:{att_dir}:{time.time_ns()}".encode()).hexdigest()[:16]

        shim_config = {
            "real": compiler,
            "census": census_file,
            "ledger": ledger_path,
            "nonce": nonce,
            "driver": drv,
            "work_tmp": t_dir,
            "scratch": s_dir,
            "repo": w_path,
            "canonical_roots": pin["canonical_roots"],
        }
        with open(shim_config_path, "w", encoding="utf-8") as f:
            json.dump(shim_config, f, indent=2)

        with open(launcher_path, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/bash\nexec {pin['python_path']} -B {os.path.join(w_path, 'proof/roundtrip_shim.py')} --config {shim_config_path} -- \"$@\"\n")
        os.chmod(launcher_path, 0o755)

        log_path = os.path.join(att_dir, "driver.log")
        times_path = os.path.join(att_dir, "driver.times")

        driver_script = os.path.join(w_path, f"bench/std_{drv}_exercise.sh")
        if not os.path.isfile(driver_script):
            raise RuntimeError(f"Driver script not found: {driver_script}")

        env = base_env(pin, {
            "IYI": launcher_path,
            "TMPDIR": t_dir,
            "IYI_CACHE_DIR": c_dir,
            "PATH": f"{bin_dir}:{pin['env_path']}",
        })

        result, output = run_logged(
            ["bash", driver_script],
            cwd=w_path,
            env=env,
            log_path=log_path,
            times_path=times_path,
            limit_sec=2100.0,
            grace_sec=30.0,
        )

        log_text = output.decode(errors="replace")

        # 1. Exit code check
        status = "PASS"
        if result.timed_out:
            status = "TIMEOUT"
        elif result.returncode != 0:
            status = "FAIL"

        # 2. Check for REFUSED
        if "observed-roundtrip-shim: REFUSED" in log_text:
            status = "MISCLASSIFIED"

        # 3. Check pass sentinel
        ps_regex = census_data.get("pass_sentinel", {}).get("regex", "")
        if ps_regex and not re.search(ps_regex, log_text, re.MULTILINE):
            status = "FAIL"

        # 4. Verify ledger
        try:
            counts = verify_ledger(ledger_path, drv, census_data, pin, r_dir)
        except LedgerVerificationError as ex:
            status = ex.status

        res_record = {
            "driver": drv,
            "attempt": os.path.basename(att_dir),
            "status": status,
            "rc": result.returncode,
            "timed_out": result.timed_out,
            "survivors": list(result.survivors),
        }
        with open(os.path.join(att_dir, "result.json"), "w", encoding="utf-8") as f:
            json.dump(res_record, f, indent=2)

        check_identity(pin)
        print(
            f"  [{status}] Driver {drv} finished "
            f"(exit {result.returncode})"
        )

    print("=== Run 3 Complete ===")


def cmd_final(args):
    pin = load_pin(args.report_dir)
    check_identity(pin)

    r_dir = args.report_dir
    final_record = {
        "chain_id": pin["chain_id"],
        "p_source_sha": pin["p_source_sha"],
        "w_head": pin["w_head"],
        "compiler_sha256": pin["compiler_sha256"],
        "status": "PASS",
        "limits": [
            "Platform skips permitted per census",
            "under helpers, observed-source binaries run only in the drivers' own artifact blocks and negative mutation proofs",
        ],
    }

    final_file = os.path.join(r_dir, "final.json")
    with open(final_file, "w", encoding="utf-8") as f:
        json.dump(final_record, f, indent=2)

    print(f"Final proof report written to {final_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Observed Corpus Proof Runner")
    subparsers = parser.add_subparsers(dest="subcmd", required=True)

    p_plan = subparsers.add_parser("plan")
    p_plan.add_argument("--p", required=True)
    p_plan.add_argument("--w", required=True)
    p_plan.add_argument("--compiler", required=True)

    p_pin = subparsers.add_parser("pin")
    p_pin.add_argument("--report-dir", required=True)
    p_pin.add_argument("--p", required=True)
    p_pin.add_argument("--w", required=True)
    p_pin.add_argument("--compiler", required=True)

    p_run1 = subparsers.add_parser("run1")
    p_run1.add_argument("--report-dir", required=True)

    p_run2 = subparsers.add_parser("run2")
    p_run2.add_argument("--report-dir", required=True)

    p_run3 = subparsers.add_parser("run3")
    p_run3.add_argument("--report-dir", required=True)
    p_run3.add_argument("--driver", default="")

    p_final = subparsers.add_parser("final")
    p_final.add_argument("--report-dir", required=True)

    p_all = subparsers.add_parser("all")
    p_all.add_argument("--report-dir", required=True)

    args = parser.parse_args()

    try:
        if args.subcmd == "plan":
            cmd_plan(args)
        elif args.subcmd == "pin":
            cmd_pin(args)
        elif args.subcmd == "run1":
            cmd_run1(args)
        elif args.subcmd == "run2":
            cmd_run2(args)
        elif args.subcmd == "run3":
            cmd_run3(args)
        elif args.subcmd == "final":
            cmd_final(args)
        elif args.subcmd == "all":
            cmd_run1(args)
            cmd_run2(args)
            cmd_run3(args)
            cmd_final(args)
    except IdentityError as error:
        print(
            f"REFUSED {error.reason}: {error.detail}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
