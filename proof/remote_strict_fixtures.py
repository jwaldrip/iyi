#!/usr/bin/env python3
"""
Shared test and validation fixtures for Remote Strict Controller.

Provisions canonical modules under W and emits native-shaped stage and final records.
Used by deterministic controller test suites and hosted validation harnesses.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import time
from typing import Any, Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

CANONICAL_MODULES: tuple[str, ...] = ("proofkit.py", "run_proof.py")

FINAL_LIMITS: tuple[str, ...] = (
    "the platform skips",
    (
        "under helpers, observed-source binaries run only in the drivers' "
        "own artifact blocks (acme, autocert, compress, png, regex, shlex, "
        "tls, websocket, xz, zip) and in negative mutation proofs; every "
        "other canonical or positive build runs its artifact consumer; RG2 "
        "proves observed source bare for all 141"
    ),
)


def provision_canonical_w(w_path: str, source_proof_dir: str | None = None) -> dict[str, str]:
    """
    Provision regular-file copies of canonical proof modules under w_path/proof.
    Returns a dictionary of {module_name: sha256_hex}.
    """
    w_real = os.path.realpath(w_path)
    target_proof_dir = os.path.join(w_real, "proof")
    os.makedirs(target_proof_dir, exist_ok=True)

    if source_proof_dir is None:
        source_proof_dir = os.path.dirname(os.path.abspath(__file__))

    hashes: dict[str, str] = {}
    for mod_name in CANONICAL_MODULES:
        src = os.path.join(source_proof_dir, mod_name)
        if not os.path.isfile(src):
            raise FileNotFoundError(f"Canonical source module not found: {src}")

        with open(src, "rb") as f:
            content = f.read()

        mod_sha = hashlib.sha256(content).hexdigest()
        hashes[mod_name] = mod_sha

        dst = os.path.join(target_proof_dir, mod_name)
        with open(dst, "wb") as f:
            f.write(content)
        os.chmod(dst, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    return hashes


def generate_pin(
    chain_id: str,
    *,
    report_dir: str,
    p_source_sha: str,
    w_head: str,
    compiler_sha256: str,
    c_sha: str,
    compiler_path: str,
    created_ns: int | None = None,
) -> dict[str, Any]:
    """Emit canonical pin.json structure matching run_proof.py."""
    return {
        "chain_id": chain_id,
        "report_dir": report_dir,
        "p_source_sha": p_source_sha,
        "w_head": w_head,
        "c_sha": c_sha,
        "compiler_path": compiler_path,
        "compiler_sha256": compiler_sha256,
        "created_ns": created_ns if created_ns is not None else time.time_ns(),
    }


def generate_stage_record(
    unit: str,
    attempt: int,
    *,
    chain_id: str,
    status: str = "PASS",
    started_ns: int | None = None,
    ended_ns: int | None = None,
    checks: dict[str, str] | None = None,
    reasons: list[str] | None = None,
    survivors: list[int] | None = None,
) -> dict[str, Any]:
    """Emit canonical stage result record matching run_proof._validate_record."""
    now_ns = time.time_ns()
    s_ns = started_ns if started_ns is not None else now_ns - 10_000_000
    e_ns = ended_ns if ended_ns is not None else now_ns

    if checks is None:
        if unit == "run1":
            checks = {
                "identity": status,
                "gate-1.1": status,
                "gate-1.2": status,
                "gate-1.3": status,
                "gate-1.4": status,
                "rg2r-count": status,
                "exclusions": status,
                "baseline-skips": status,
            }
        elif unit == "run2":
            checks = {
                "identity": status,
                "legs": status,
                "counts": status,
            }
        else:
            checks = {
                "census": status,
                "identity": status,
                "disk": status,
                "exit": status,
                "sentinel": status,
                "no-refused": status,
                "skips": status,
                "ledger": status,
            }

    return {
        "v": 1,
        "chain_id": chain_id,
        "unit": unit,
        "attempt": attempt,
        "status": status,
        "reasons": reasons if reasons is not None else ([] if status == "PASS" else [f"{unit} check failure"]),
        "checks": checks,
        "started_ns": s_ns,
        "ended_ns": e_ns,
        "survivors": survivors if survivors is not None else [],
    }


def generate_final_record(
    pin: dict[str, Any],
    required_drivers: Sequence[str],
    *,
    status: str = "PASS",
    units: dict[str, dict[str, Any]] | None = None,
    earlier_failures: list[dict[str, Any]] | None = None,
    reasons: list[str] | None = None,
    identity_status: str = "PASS",
) -> dict[str, Any]:
    """Emit canonical final.json structure matching run_proof.py:1358-1389."""
    if units is None:
        units = {
            "run1": {"attempt": 1, "status": "PASS"},
            "run2": {"attempt": 1, "status": "PASS"},
        }
        for d in required_drivers:
            units[f"run3/{d}"] = {"attempt": 1, "status": "PASS"}

    identity = {
        "status": identity_status,
        "p_source_sha": pin["p_source_sha"],
        "w_head": pin["w_head"],
        "compiler_sha256": pin["compiler_sha256"],
    }

    return {
        "v": 1,
        "chain_id": pin.get("chain_id", ""),
        "status": status,
        "units": units,
        "earlier_failures": sorted(
            earlier_failures or [],
            key=lambda entry: (str(entry.get("unit", "")), int(entry.get("attempt", 0))),
        ),
        "reasons": reasons if reasons is not None else ([] if status == "PASS" else ["Final verification rejected"]),
        "limits": list(FINAL_LIMITS),
        "identity": identity,
    }


FAKE_STAGE_EMITTER_SOURCE = """#!/usr/bin/env python3
import json
import hashlib
import subprocess
import os
import signal
import sys
import time

def main():
    config_path = os.environ.get("FAKE_STAGE_CONFIG", "")
    config = {}
    if config_path and os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

    args = sys.argv[1:]
    if not args:
        sys.exit(1)
    subcmd = args[0]

    def get_arg(name):
        if name in args:
            idx = args.index(name)
            if idx + 1 < len(args):
                return args[idx + 1]
        return None

    report_dir = get_arg("--report-dir")
    driver = get_arg("--driver") or ""

    stage_cfg = config.get(subcmd, {})
    if subcmd == "run3" and driver:
        stage_cfg = config.get(f"run3/{driver}", stage_cfg)

    # Signal & sleep simulation
    sleep_sec = float(stage_cfg.get("sleep", 0.0))
    flush_delay = float(stage_cfg.get("flush_delay", 0.0))
    term_exit_code = int(stage_cfg.get("term_exit_code", 0))
    completion_marker = stage_cfg.get("completion_marker", "")
    ready_file = stage_cfg.get("ready_file", "")
    interrupted = False

    def term_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        if flush_delay > 0:
            time.sleep(flush_delay)
        if completion_marker:
            with open(completion_marker, "w", encoding="utf-8") as cm:
                cm.write("completed_term_flush\\n")
        if stage_cfg.get("exit_on_term", True):
            sys.exit(term_exit_code)

    signal.signal(signal.SIGTERM, term_handler)

    if stage_cfg.get("ignore_sigterm"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

    # Spawn nested grandchild in separate session if requested
    if stage_cfg.get("spawn_nested"):
        pid_file = stage_cfg.get("pid_file")
        c_pid = os.fork()
        if c_pid == 0:
            os.setsid()
            my_pid = os.getpid()
            if pid_file:
                with open(pid_file, "a", encoding="utf-8") as pf:
                    pf.write(f"child:{my_pid}\\n")
            gc_pid = os.fork()
            if gc_pid == 0:
                os.setsid()
                my_gc_pid = os.getpid()
                if pid_file:
                    with open(pid_file, "a", encoding="utf-8") as pf:
                        pf.write(f"grandchild:{my_gc_pid}\\n")
                if ready_file:
                    with open(ready_file, "w", encoding="utf-8") as rf:
                        rf.write("ready\\n")
                while True:
                    time.sleep(0.5)
                sys.exit(0)
            while True:
                time.sleep(0.5)
            sys.exit(0)
        else:
            # Parent process waits a moment to ensure grandchild fork completed
            time.sleep(0.2)

    if ready_file and not stage_cfg.get("spawn_nested"):
        with open(ready_file, "w", encoding="utf-8") as rf:
            rf.write("ready\\n")

    if sleep_sec > 0:
        deadline = time.time() + sleep_sec
        while time.time() < deadline:
            if interrupted and not flush_delay:
                break
            time.sleep(0.05)
        if interrupted and report_dir and stage_cfg.get("write_interrupted_result"):
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            res = {
                "v": 1,
                "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
                "unit": subcmd if subcmd != "run3" else f"run3/{driver}",
                "attempt": 1,
                "status": "FAIL",
                "reasons": ["interrupted by signal 15"],
                "checks": {"exit": "FAIL"},
                "started_ns": time.time_ns() - 1000000,
                "ended_ns": time.time_ns(),
                "survivors": [],
            }
            with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as rf:
                json.dump(res, rf)
            sys.exit(1)

    exit_code = int(stage_cfg.get("exit_code", 0))

    if subcmd == "plan":
        sys.exit(exit_code)

    elif subcmd == "pin":
        if stage_cfg.get("omit_pin"):
            print("synthetic pin failed before establishment", file=sys.stderr)
            sys.exit(exit_code or 1)
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
            pin_data = {
                "chain_id": config.get("chain_id", "0123456789abcdef0123456789abcdef"),
                "report_dir": report_dir,
                "p_source_sha": subprocess.check_output(["git", "-C", get_arg("--p"), "rev-parse", "HEAD"], text=True).strip(),
                "w_head": subprocess.check_output(["git", "-C", get_arg("--w"), "rev-parse", "HEAD"], text=True).strip(),
                "c_sha": config["c_sha"],
                "compiler_path": os.path.realpath(get_arg("--compiler")),
                "compiler_sha256": hashlib.sha256(open(get_arg("--compiler"), "rb").read()).hexdigest(),
                "created_ns": time.time_ns(),
            }
            with open(os.path.join(report_dir, "pin.json"), "w", encoding="utf-8") as f:
                json.dump(pin_data, f)
        sys.exit(exit_code)

    elif subcmd == "run1":
        if report_dir:
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            with open(os.path.join(attempt_dir, f"{subcmd}.log"), "w", encoding="utf-8") as f:
                f.write(f"log for {subcmd}\\n")
            with open(os.path.join(attempt_dir, f"{subcmd}.times"), "w", encoding="utf-8") as f:
                f.write("0.1 0.2 0.3\\n")
            with open(os.path.join(attempt_dir, "exclusions.json"), "w", encoding="utf-8") as f:
                json.dump([], f)
            with open(os.path.join(attempt_dir, "baseline_skips.json"), "w", encoding="utf-8") as f:
                json.dump([], f)

            # Eligible scratch: rg9_work
            if stage_cfg.get("inject_eligible_symlink"):
                target = stage_cfg.get("symlink_target", "/tmp")
                os.symlink(target, os.path.join(attempt_dir, "rg9_work"))
            else:
                scratch_dir = os.path.join(attempt_dir, "rg9_work")
                os.makedirs(scratch_dir, exist_ok=True)
                with open(os.path.join(scratch_dir, "temp.bin"), "w", encoding="utf-8") as f:
                    f.write("scratch data")

            # Temporary scratch
            tmp_dir = os.path.join(attempt_dir, "g01.tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            with open(os.path.join(tmp_dir, "tmp.txt"), "w", encoding="utf-8") as f:
                f.write("tmp data")

            if not stage_cfg.get("skip_result"):
                if stage_cfg.get("malformed_result"):
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        f.write("{invalid json syntax")
                else:
                    status = stage_cfg.get("status", "PASS")
                    chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                    unit = stage_cfg.get("unit", subcmd)
                    attempt = int(stage_cfg.get("attempt", 1))
                    v = int(stage_cfg.get("v", 1))
                    checks = stage_cfg.get("checks", {
                        "identity": "PASS",
                        "gate-1.1": "PASS",
                        "gate-1.2": "PASS",
                        "gate-1.3": "PASS",
                        "gate-1.4": "PASS",
                        "rg2r-count": "PASS",
                        "exclusions": "PASS",
                        "baseline-skips": "PASS",
                    })
                    base_ns = 1_000_000_000_000_000
                    s_ns = int(stage_cfg.get("started_ns", base_ns + 10_000_000))
                    e_ns = int(stage_cfg.get("ended_ns", base_ns + 20_000_000))
                    res = {
                        "v": v,
                        "chain_id": chain_id,
                        "unit": unit,
                        "attempt": attempt,
                        "status": status,
                        "reasons": stage_cfg.get("reasons", []),
                        "checks": checks,
                        "started_ns": s_ns,
                        "ended_ns": e_ns,
                        "survivors": [],
                    }
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "run2":
        if report_dir:
            attempt_dir = os.path.join(report_dir, subcmd, "a1")
            os.makedirs(attempt_dir, exist_ok=True)
            with open(os.path.join(attempt_dir, f"{subcmd}.log"), "w", encoding="utf-8") as f:
                f.write(f"log for {subcmd}\\n")
            with open(os.path.join(attempt_dir, f"{subcmd}.times"), "w", encoding="utf-8") as f:
                f.write("0.1 0.2 0.3\\n")
            with open(os.path.join(attempt_dir, "run2.jsonl"), "w", encoding="utf-8") as f:
                f.write('{"row": 1, "status": "PASS", "stdout": "scratch/rows/r1/stdout.log"}\\n')

            # Run2 row evidence: MUST BE PRESERVED
            rows_dir = os.path.join(attempt_dir, "scratch", "rows", "r1")
            os.makedirs(rows_dir, exist_ok=True)
            with open(os.path.join(rows_dir, "stdout.log"), "w", encoding="utf-8") as f:
                f.write("row 1 stdout data\\n")
            with open(os.path.join(rows_dir, "exit_file"), "w", encoding="utf-8") as f:
                f.write("0\\n")

            # Expendable scratch
            cache_dir = os.path.join(attempt_dir, "scratch", "cache")
            os.makedirs(cache_dir, exist_ok=True)
            with open(os.path.join(cache_dir, "temp.bin"), "w", encoding="utf-8") as f:
                f.write("cache data")
            tmp_dir = os.path.join(attempt_dir, "run2.tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            with open(os.path.join(tmp_dir, "temp.bin"), "w", encoding="utf-8") as f:
                f.write("temp data")

            if not stage_cfg.get("skip_result"):
                if stage_cfg.get("malformed_result"):
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        f.write("{invalid json syntax")
                else:
                    status = stage_cfg.get("status", "PASS")
                    chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                    unit = stage_cfg.get("unit", subcmd)
                    attempt = int(stage_cfg.get("attempt", 1))
                    v = int(stage_cfg.get("v", 1))
                    checks = stage_cfg.get("checks", {
                        "identity": "PASS",
                        "legs": "PASS",
                        "counts": "PASS",
                    })
                    base_ns = 1_000_000_000_000_000
                    s_ns = int(stage_cfg.get("started_ns", base_ns + 30_000_000))
                    e_ns = int(stage_cfg.get("ended_ns", base_ns + 40_000_000))
                    res = {
                        "v": v,
                        "chain_id": chain_id,
                        "unit": unit,
                        "attempt": attempt,
                        "status": status,
                        "reasons": stage_cfg.get("reasons", []),
                        "checks": checks,
                        "started_ns": s_ns,
                        "ended_ns": e_ns,
                        "survivors": [],
                    }
                    with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                        json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "run3":
        if report_dir:
            run3_dir = os.path.join(report_dir, "run3")
            os.makedirs(run3_dir, exist_ok=True)
            req_file = os.path.join(run3_dir, "required.json")
            if not os.path.exists(req_file):
                required_list = config.get("required_drivers", ["acme", "cookie"])
                with open(req_file, "w", encoding="utf-8") as f:
                    json.dump(required_list, f)

            if driver:
                attempt_dir = os.path.join(run3_dir, driver, "a1")
                os.makedirs(attempt_dir, exist_ok=True)
                with open(os.path.join(attempt_dir, "driver.log"), "w", encoding="utf-8") as f:
                    f.write(f"log for {driver}\\n")
                with open(os.path.join(attempt_dir, "driver.times"), "w", encoding="utf-8") as f:
                    f.write("0.1 0.2\\n")
                with open(os.path.join(attempt_dir, "ledger.jsonl"), "w", encoding="utf-8") as f:
                    f.write('{"ledger": 1}\\n')
                with open(os.path.join(attempt_dir, "shim.json"), "w", encoding="utf-8") as f:
                    json.dump({}, f)

                # Expendable scratch (t, c, s, bin)
                for d in ("t", "c", "s", "bin"):
                    p = os.path.join(attempt_dir, d)
                    os.makedirs(p, exist_ok=True)
                    with open(os.path.join(p, "data.txt"), "w", encoding="utf-8") as f:
                        f.write("temp")
                if "divergence_hex" in stage_cfg:
                    mods = os.path.join(attempt_dir, "s", "invocation", "mods")
                    os.makedirs(mods, exist_ok=True)
                    with open(os.path.join(mods, "divergence.bin"), "wb") as f:
                        f.write(bytes.fromhex(stage_cfg["divergence_hex"]))

                if not stage_cfg.get("skip_result"):
                    if stage_cfg.get("malformed_result"):
                        with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                            f.write("{invalid json syntax")
                    else:
                        status = stage_cfg.get("status", "PASS")
                        chain_id = stage_cfg.get("chain_id", config.get("chain_id", "0123456789abcdef0123456789abcdef"))
                        unit = stage_cfg.get("unit", f"run3/{driver}")
                        attempt = int(stage_cfg.get("attempt", 1))
                        v = int(stage_cfg.get("v", 1))
                        checks = stage_cfg.get("checks", {
                            "census": "PASS",
                            "identity": "PASS",
                            "disk": "PASS",
                            "exit": "PASS",
                            "sentinel": "PASS",
                            "no-refused": "PASS",
                            "skips": "PASS",
                            "ledger": "PASS",
                        })
                        base_ns = 1_000_000_000_000_000
                        s_ns = int(stage_cfg.get("started_ns", base_ns + 50_000_000))
                        e_ns = int(stage_cfg.get("ended_ns", base_ns + 60_000_000))
                        res = {
                            "v": v,
                            "chain_id": chain_id,
                            "unit": unit,
                            "attempt": attempt,
                            "status": status,
                            "reasons": stage_cfg.get("reasons", []),
                            "checks": checks,
                            "started_ns": s_ns,
                            "ended_ns": e_ns,
                            "survivors": [],
                        }
                        with open(os.path.join(attempt_dir, "result.json"), "w", encoding="utf-8") as f:
                            json.dump(res, f)
        sys.exit(exit_code)

    elif subcmd == "final":
        if report_dir:
            required_drivers = config.get("required_drivers", ["acme", "cookie"])
            units = {
                "run1": {"attempt": 1, "status": "PASS"},
                "run2": {"attempt": 1, "status": "PASS"},
            }
            for d in required_drivers:
                units[f"run3/{d}"] = {"attempt": 1, "status": "PASS"}

            pin_data = {}
            pin_file = os.path.join(report_dir, "pin.json")
            if os.path.isfile(pin_file):
                with open(pin_file, "r", encoding="utf-8") as pf:
                    pin_data = json.load(pf)

            final_status = stage_cfg.get("status", "PASS")
            identity = stage_cfg.get("identity", {
                "status": "PASS",
                "p_source_sha": pin_data["p_source_sha"],
                "w_head": pin_data["w_head"],
                "compiler_sha256": pin_data["compiler_sha256"],
            })

            final_data = {
                "v": int(stage_cfg.get("v", 1)),
                "chain_id": config.get("chain_id", pin_data.get("chain_id", "0123456789abcdef0123456789abcdef")),
                "status": final_status,
                "units": stage_cfg.get("units", units),
                "earlier_failures": stage_cfg.get("earlier_failures", []),
                "reasons": stage_cfg.get("reasons", []),
                "limits": stage_cfg.get("limits", [
                    "the platform skips",
                    (
                        "under helpers, observed-source binaries run only in the drivers' "
                        "own artifact blocks (acme, autocert, compress, png, regex, shlex, "
                        "tls, websocket, xz, zip) and in negative mutation proofs; every "
                        "other canonical or positive build runs its artifact consumer; RG2 "
                        "proves observed source bare for all 141"
                    ),
                ]),
                "identity": identity,
            }
            with open(os.path.join(report_dir, "final.json"), "w", encoding="utf-8") as f:
                json.dump(final_data, f)
        sys.exit(exit_code)

    sys.exit(0)

if __name__ == "__main__":
    main()
"""
