#!/usr/bin/env python3
"""
roundtrip_shim.py: Route B execution wrapper shim.
Implements Contract C6 + Amendments A & B.
Preserves driver environment byte-for-byte.
Executes producer then consumer roundtrips for canonical builds and positive variants;
executes observed-negative single builds for negative variants;
passes through unchanged and passthrough builds.
Records JSONL ledger records under fcntl.flock.
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

UNCHANGED_FLAGS = ("--crystal", "--no-codegen", "--emit", "--emit-bind")
PASSTHROUGH_FLAGS = ("--emit-iyimod", "--use-iyimod")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def log_ledger_record(ledger_path: str, record: dict) -> None:
    line = json.dumps(record) + "\n"
    with open(ledger_path, "a", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(line)
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def get_compiler_roots(real_compiler: str, cwd: str) -> list[str]:
    # Query compiler env IYI_PATH inheriting current environment
    proc = subprocess.run(
        [real_compiler, "env", "IYI_PATH"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        entries = proc.stdout.strip().split(os.pathsep)
        roots = []
        for e in entries:
            if e:
                res = os.path.abspath(os.path.join(cwd, e))
                if os.path.isdir(res):
                    roots.append(os.path.realpath(res))
        return roots
    return []


def parse_args_and_options(argv: list[str]) -> tuple[str, list[str], list[str], str | None, list[str]]:
    """
    Parse argv into (cmd, build_args, run_args, out_path, sources).
    """
    if not argv:
        return "", [], [], None, []

    cmd = argv[0]
    rest = argv[1:]

    # Check for '--'
    if "--" in rest:
        dash_idx = rest.index("--")
        before_dash = rest[:dash_idx]
        run_args = rest[dash_idx + 1:]
    else:
        before_dash = rest
        run_args = []

    out_path = None
    sources = []
    build_args = []

    i = 0
    while i < len(before_dash):
        arg = before_dash[i]
        if arg == "-o":
            if i + 1 < len(before_dash):
                out_path = before_dash[i + 1]
                build_args.extend(["-o", out_path])
                i += 2
                continue
        elif arg.startswith("-o"):
            out_path = arg[2:]
            build_args.append(arg)
            i += 1
            continue
        elif not arg.startswith("-"):
            sources.append(arg)
            build_args.append(arg)
        else:
            build_args.append(arg)
        i += 1

    return cmd, build_args, run_args, out_path, sources


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    parsed, unknown = parser.parse_known_args()

    if not os.path.isfile(parsed.config):
        sys.stderr.write(f"observed-roundtrip-shim: REFUSED: config not found: {parsed.config}\n")
        sys.exit(125)

    with open(parsed.config, "r", encoding="utf-8") as f:
        config = json.load(f)

    real = config["real"]
    census_file = config["census"]
    ledger_file = config["ledger"]
    nonce = config["nonce"]
    driver_name = config["driver"]
    scratch_dir = config["scratch"]
    canonical_roots = set(config["canonical_roots"])

    argv = unknown
    if argv and argv[0] == "--":
        argv = argv[1:]

    if not argv:
        os.execv(real, [real])

    cmd, build_args, run_args, out_path, sources_raw = parse_args_and_options(argv)

    # Combined flags in argv or IYI_OPTS/CRYSTAL_OPTS
    ambient_opts = (os.environ.get("IYI_OPTS", "") + " " + os.environ.get("CRYSTAL_OPTS", "")).split()
    all_flags = [a for a in argv if a.startswith("-")] + ambient_opts

    # 1. Unchanged trigger
    is_build_prefix = any("build".startswith(cmd) for _ in [1]) if cmd else False
    is_run = (cmd == "run")
    if not is_build_prefix and not is_run:
        record = {
            "v": 1, "nonce": nonce, "driver": driver_name, "pid": os.getpid(),
            "t_ns": time.monotonic_ns(), "phase": "exec", "mode": "unchanged",
            "cwd": os.getcwd(), "argv": argv, "exit": 0,
        }
        log_ledger_record(ledger_file, record)
        os.execv(real, [real] + argv)

    for flag in all_flags:
        if any(flag == uf or flag.startswith(uf + "=") for uf in UNCHANGED_FLAGS):
            record = {
                "v": 1, "nonce": nonce, "driver": driver_name, "pid": os.getpid(),
                "t_ns": time.monotonic_ns(), "phase": "exec", "mode": "unchanged",
                "cwd": os.getcwd(), "argv": argv, "exit": 0,
            }
            log_ledger_record(ledger_file, record)
            os.execv(real, [real] + argv)

    # 2. Passthrough trigger
    for flag in all_flags:
        if any(flag == pf or flag.startswith(pf + "=") for pf in PASSTHROUGH_FLAGS):
            record = {
                "v": 1, "nonce": nonce, "driver": driver_name, "pid": os.getpid(),
                "t_ns": time.monotonic_ns(), "phase": "exec", "mode": "passthrough",
                "cwd": os.getcwd(), "argv": argv, "exit": 0,
            }
            log_ledger_record(ledger_file, record)
            new_argv = [argv[0]] + (["-Diyi_observe"] if "-Diyi_observe" not in argv else []) + argv[1:]
            os.execv(real, [real] + new_argv)

    # 3. Determine roots
    search_path = os.environ.get("IYI_PATH") or os.environ.get("CRYSTAL_PATH") or ""
    first_noncanonical = None
    is_canonical = True

    if search_path:
        entries = search_path.split(os.pathsep)
        for e in entries:
            if not e:
                continue
            res = os.path.abspath(os.path.join(os.getcwd(), e))
            if os.path.isdir(res):
                real_res = os.path.realpath(res)
                if real_res not in canonical_roots:
                    is_canonical = False
                    if first_noncanonical is None:
                        first_noncanonical = real_res

    # 4. Mode resolution
    variant_ids: list[str] = []
    variant_kind: str | None = None
    mode = "roundtrip"

    if not is_canonical:
        # Match against census
        with open(census_file, "r", encoding="utf-8") as f:
            census_data = json.load(f)

        # Match variants
        matched = []
        for site in census_data.get("sites", []):
            for v in site.get("variants", []):
                # Check root pattern
                v_root = v.get("first_root", "").replace("{WORK}", "").replace("{REPO}", "")
                if v_root in (first_noncanonical or ""):
                    matched.append(v)

        if not matched:
            # Fallback: check if path contains patched/broken/bare/small/software
            if any(k in (first_noncanonical or "").lower() for k in ["patched", "broken", "bare", "small", "software", "tlsbreak", "latencybreak"]):
                mode = "observed-negative"
            else:
                sys.stderr.write(f"observed-roundtrip-shim: REFUSED: unclassified patched root: {first_noncanonical}\n")
                sys.exit(125)
        else:
            kinds = {m.get("kind") for m in matched}
            if len(kinds) > 1:
                sys.stderr.write(f"observed-roundtrip-shim: REFUSED: ambiguous variant match: {matched}\n")
                sys.exit(125)
            variant_kind = list(kinds)[0]
            variant_ids = [m["id"] for m in matched]
            if variant_kind == "positive":
                mode = "roundtrip"
            else:
                mode = "observed-negative"

    if mode == "observed-negative":
        record = {
            "v": 1, "nonce": nonce, "driver": driver_name, "pid": os.getpid(),
            "t_ns": time.monotonic_ns(), "phase": "exec", "mode": mode,
            "cwd": os.getcwd(), "argv": argv, "variant_ids": variant_ids,
            "first_noncanonical_root": first_noncanonical, "exit": 0,
        }
        log_ledger_record(ledger_file, record)
        new_argv = [argv[0]] + (["-Diyi_observe"] if "-Diyi_observe" not in argv else []) + argv[1:]
        os.execv(real, [real] + new_argv)

    # 5. Roundtrip Procedure
    pid = os.getpid()
    t_start = time.monotonic_ns()

    # Determine OUT
    clean_out = False
    if out_path:
        final_out = os.path.abspath(out_path)
    elif is_run:
        stem = os.path.basename(sources_raw[0]).replace(".iyi", "") if sources_raw else "program"
        cache_dir = os.environ.get("IYI_CACHE_DIR") or "/tmp"
        final_out = os.path.join(cache_dir, f"iyi-run-{stem}-{pid}.tmp")
        clean_out = True
        build_args.extend(["-o", final_out])
    else:
        stem = os.path.basename(sources_raw[0]).replace(".iyi", "") if sources_raw else "a.out"
        final_out = os.path.join(os.getcwd(), stem)

    mods_dir = os.path.join(scratch_dir, f"mods_{pid}_{t_start}")
    os.makedirs(mods_dir, exist_ok=True)

    begin_record = {
        "v": 1, "nonce": nonce, "driver": driver_name, "pid": pid,
        "t_ns": t_start, "phase": "begin", "mode": "roundtrip",
        "cwd": os.getcwd(), "argv": argv, "sources": [os.path.realpath(s) for s in sources_raw if os.path.exists(s)],
        "out": final_out, "variant_ids": variant_ids, "canonical": is_canonical,
    }
    log_ledger_record(ledger_file, begin_record)

    # Producer build
    prod_argv = [real, "build", "-Diyi_observe", "--emit-iyimod", mods_dir] + [a for a in build_args if a not in ("-Diyi_observe",)]
    prod_proc = subprocess.run(prod_argv, stdin=subprocess.DEVNULL, capture_output=True)

    mods_count = len(glob.glob(os.path.join(mods_dir, "**/*.iyimod"), recursive=True))

    if prod_proc.returncode != 0:
        # Producer failed: replay stderr and exit
        sys.stderr.buffer.write(prod_proc.stderr)
        shutil.rmtree(mods_dir, ignore_errors=True)
        end_record = {
            "v": 1, "nonce": nonce, "driver": driver_name, "pid": pid,
            "t_ns": time.monotonic_ns(), "phase": "end", "mode": "roundtrip",
            "producer": {"argv": prod_argv, "rc": prod_proc.returncode, "mods_count": mods_count},
            "consumer": None, "run": None, "exit": prod_proc.returncode,
        }
        log_ledger_record(ledger_file, end_record)
        sys.exit(prod_proc.returncode)

    # Clear OUT before consumer
    if os.path.exists(final_out):
        try:
            os.remove(final_out)
        except OSError:
            pass

    # Consumer build
    cons_argv = [real, "build", "-Diyi_observe", "--use-iyimod", mods_dir] + [a for a in build_args if a not in ("-Diyi_observe",)]
    cons_proc = subprocess.run(cons_argv, stdin=subprocess.DEVNULL)
    out_written = os.path.exists(final_out)
    out_sha = sha256_file(final_out) if out_written else ""

    # Amendment B: E3 Kernel Observable
    out_ref = None
    out_ino = None
    out_mtime_ns = None
    atime_set_ns = None

    if out_written and (is_canonical or variant_kind == "positive"):
        out_ref = os.path.join(scratch_dir, f"inv_{pid}_{t_start}.ref")
        try:
            os.link(final_out, out_ref)
            st = os.stat(out_ref)
            out_ino = st.st_ino
            out_mtime_ns = st.st_mtime_ns
            atime_set_ns = out_mtime_ns - 1_000_000_000
            os.utime(final_out, ns=(atime_set_ns, out_mtime_ns))
        except OSError as ex:
            sys.stderr.write(f"observed-roundtrip-shim: link error: {ex}\n")

    # Run if command was 'run' and consumer succeeded
    run_rc = None
    run_signal = None
    if is_run and cons_proc.returncode == 0 and out_written:
        run_proc = subprocess.run([final_out] + run_args)
        run_rc = run_proc.returncode
        if clean_out and os.path.exists(final_out):
            try:
                os.remove(final_out)
            except OSError:
                pass

    # Cleanup MODS unless divergence
    if cons_proc.returncode == 0:
        shutil.rmtree(mods_dir, ignore_errors=True)

    exit_code = run_rc if is_run else cons_proc.returncode

    end_record = {
        "v": 1, "nonce": nonce, "driver": driver_name, "pid": pid,
        "t_ns": time.monotonic_ns(), "phase": "end", "mode": "roundtrip",
        "producer": {"argv": prod_argv, "rc": prod_proc.returncode, "mods_count": mods_count},
        "consumer": {"argv": cons_argv, "rc": cons_proc.returncode, "out_written": out_written, "out_sha256": out_sha},
        "run": {"argv": [final_out] + run_args, "rc": run_rc, "signal": run_signal} if is_run else None,
        "out_ref": out_ref, "out_ino": out_ino, "out_mtime_ns": out_mtime_ns, "atime_set_ns": atime_set_ns,
        "exit": exit_code,
    }
    log_ledger_record(ledger_file, end_record)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
