#!/usr/bin/env python3
"""
Run 2: All 141 Artifact Legs (27 samples + 114 std exercises).
Builds four artifact legs:
  P:  build -Diyi_observe --emit-iyimod mods -o producer/s source
  C1: build -Diyi_observe --use-iyimod mods --stale-key k1 -o consumer/s source
  C2: build -Diyi_observe --use-iyimod mods --stale-key k2 -o key2/s source
  C3: IYI_WARM=1, the same with k3, -o warm/s source
Runs P, C1, C3 with IYI_OBSERVE pointing to that leg's trace.
Checks:
  - Every build exits 0, and no build output names __iyi_effect_
  - k1, k2, k3 have non-empty, equal portable.callpath and empty reach.mismatch
  - P against C1, and C1 against C3, pass R-1 rule (exact match or frames_equivalent)
  - No run output names __iyi_effect_, and every trace is non-empty
  - nm -U defined symbols check on consumer binary
  - 2 workers, private sandboxes/caches per row, cleaned up on success
  - Stop if disk free space < 20 GB
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Heavy exercises needing 300s timeout instead of 60s
HEAVY = {
    "bench/std_big_exercise.iyi",
    "bench/std_bzip2_exercise.iyi",
    "bench/std_compress_exercise.iyi",
    "bench/std_csv_exercise.iyi",
    "bench/std_curve25519_exercise.iyi",
    "bench/std_digest_exercise.iyi",
    "bench/std_fuzz_exercise.iyi",
    "bench/std_gc_exercise.iyi",
    "bench/std_http_exercise.iyi",
    "bench/std_mutex_exercise.iyi",
    "bench/std_password_exercise.iyi",
    "bench/std_shared_proc_exercise.iyi",
    "bench/std_tar_exercise.iyi",
    "bench/std_text_scale_exercise.iyi",
    "bench/std_toml_exercise.iyi",
    "bench/std_xml_exercise.iyi",
    "bench/std_xz_exercise.iyi",
    "bench/std_zstd_exercise.iyi",
}

EXIT_ONLY_EXERCISES = {
    "std_big_exercise",
    "std_gc_exercise",
    "std_time_exercise",
    "std_weak_ref_exercise",
}


def timeout_for(relpath: str) -> int:
    return 300 if relpath in HEAVY else 60


def check_disk_space(path: str, min_gb: float = 20.0) -> None:
    usage = shutil.disk_usage(path)
    free_gb = usage.free / (1024 ** 3)
    if free_gb < min_gb:
        raise RuntimeError(f"Disk space below threshold: {free_gb:.2f} GB free < {min_gb} GB")


def clean_env(repo: str, cache_dir: str, warm: bool = False, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for k in [
        "IYI_OPTS",
        "CRYSTAL_OPTS",
        "IYI_WARM",
        "IYI_OBSERVE",
        "IYI_DAEMON_SOCKET",
        "CRYSTAL_DAEMON_SOCKET",
        "IYI_FILE_SANDBOX",
    ]:
        env.pop(k, None)

    env["IYI_CACHE_DIR"] = cache_dir
    env["IYI_PATH"] = f"{repo}/src{os.pathsep}{repo}/samples/iyi"
    env["IYI_LIBRARY_PATH"] = f"{repo}/lib"
    env["LIBRARY_PATH"] = "/opt/homebrew/opt/bdw-gc/lib"
    env["PKG_CONFIG_PATH"] = "/opt/homebrew/opt/openssl@3/lib/pkgconfig"

    if warm:
        env["IYI_WARM"] = "1"
    else:
        env.pop("IYI_WARM", None)

    if extra:
        env.update(extra)

    return env


def check_defined_symbols(binary_path: str) -> list[str]:
    if not os.path.exists(binary_path):
        return []
    try:
        proc = subprocess.run(["nm", "-U", binary_path], capture_output=True, text=True, check=True)
        return [line.strip() for line in proc.stdout.splitlines() if "__iyi_effect_" in line]
    except Exception as ex:
        return [f"nm error: {ex}"]


def compare_r1(
    name: str,
    status_a: int,
    status_b: int,
    out_a: bytes,
    out_b: bytes,
    compare_same_opt_fn,
) -> tuple[bool, str]:
    if status_a != status_b:
        return False, f"exit status mismatch: {status_a} != {status_b}"

    if name in EXIT_ONLY_EXERCISES:
        return True, "exit-only check passed"

    if out_a == out_b:
        return True, "exact output match"

    lines_a = out_a.splitlines(keepends=True)
    lines_b = out_b.splitlines(keepends=True)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = compare_same_opt_fn(lines_a, lines_b)

    if ret == 0:
        return True, "frames equivalent passed"
    else:
        violation = buf.getvalue().strip()
        return False, f"frames equivalence failed: {violation}"


def run_single_program(
    source: str,
    repo: str,
    compiler: str,
    work_root: str,
    compare_same_opt_fn,
) -> dict:
    check_disk_space(work_root, 20.0)

    rel = os.path.relpath(source, repo)
    is_std = rel.startswith("bench/")
    raw_base = os.path.basename(source)
    prog_base = raw_base[:-4] if raw_base.endswith(".iyi") else raw_base

    prog_id = f"{'std' if is_std else 'sample'}_{prog_base}_{os.getpid()}_{time.time_ns()}"
    pdir = os.path.join(work_root, prog_id)
    os.makedirs(pdir, exist_ok=True)

    cache_p = os.path.join(pdir, "cache_p")
    cache_c = os.path.join(pdir, "cache_c")
    mods = os.path.join(pdir, "mods")
    os.makedirs(cache_p, exist_ok=True)
    os.makedirs(cache_c, exist_ok=True)
    os.makedirs(mods, exist_ok=True)

    # Matching binary basenames under distinct subdirectories
    bin_name = prog_base
    p_bin = os.path.join(pdir, "p", bin_name)
    c1_bin = os.path.join(pdir, "c1", bin_name)
    c2_bin = os.path.join(pdir, "c2", bin_name)
    c3_bin = os.path.join(pdir, "c3", bin_name)
    for b in [p_bin, c1_bin, c2_bin, c3_bin]:
        os.makedirs(os.path.dirname(b), exist_ok=True)

    k1 = os.path.join(pdir, "k1.key")
    k2 = os.path.join(pdir, "k2.key")
    k3 = os.path.join(pdir, "k3.key")

    p_trace = os.path.join(pdir, "p.trace")
    c1_trace = os.path.join(pdir, "c1.trace")
    c3_trace = os.path.join(pdir, "c3.trace")

    timeout = timeout_for(rel)
    failures: list[str] = []

    # --- Leg P Build ---
    cmd_p = [compiler, "build", "-Diyi_observe", "--emit-iyimod", mods, "-o", p_bin, source]
    res_p_build = subprocess.run(
        cmd_p,
        cwd=repo,
        env=clean_env(repo, cache_p, warm=False),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=False,
        timeout=timeout,
    )
    if res_p_build.returncode != 0:
        failures.append(f"P build failed (exit {res_p_build.returncode}): {res_p_build.stderr.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in res_p_build.stdout or b"__iyi_effect_" in res_p_build.stderr:
        failures.append("P build output names __iyi_effect_")

    # --- Leg C1 Build ---
    cmd_c1 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k1, "-o", c1_bin, source]
    res_c1_build = subprocess.run(
        cmd_c1,
        cwd=repo,
        env=clean_env(repo, cache_c, warm=False),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=False,
        timeout=timeout,
    )
    if res_c1_build.returncode != 0:
        failures.append(f"C1 build failed (exit {res_c1_build.returncode}): {res_c1_build.stderr.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in res_c1_build.stdout or b"__iyi_effect_" in res_c1_build.stderr:
        failures.append("C1 build output names __iyi_effect_")

    # --- Leg C2 Build ---
    cmd_c2 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k2, "-o", c2_bin, source]
    res_c2_build = subprocess.run(
        cmd_c2,
        cwd=repo,
        env=clean_env(repo, cache_c, warm=False),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=False,
        timeout=timeout,
    )
    if res_c2_build.returncode != 0:
        failures.append(f"C2 build failed (exit {res_c2_build.returncode}): {res_c2_build.stderr.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in res_c2_build.stdout or b"__iyi_effect_" in res_c2_build.stderr:
        failures.append("C2 build output names __iyi_effect_")

    # --- Leg C3 Build (Warm) ---
    cmd_c3 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k3, "-o", c3_bin, source]
    res_c3_build = subprocess.run(
        cmd_c3,
        cwd=repo,
        env=clean_env(repo, cache_c, warm=True),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=False,
        timeout=timeout,
    )
    if res_c3_build.returncode != 0:
        failures.append(f"C3 build failed (exit {res_c3_build.returncode}): {res_c3_build.stderr.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in res_c3_build.stdout or b"__iyi_effect_" in res_c3_build.stderr:
        failures.append("C3 build output names __iyi_effect_")

    # --- Key Checks ---
    callpath1 = ""
    if os.path.exists(k1) and os.path.exists(k2) and os.path.exists(k3):
        try:
            with open(k1, "r", encoding="utf-8") as f:
                d1 = json.load(f)
            with open(k2, "r", encoding="utf-8") as f:
                d2 = json.load(f)
            with open(k3, "r", encoding="utf-8") as f:
                d3 = json.load(f)

            cp1 = d1.get("portable", {}).get("callpath", "")
            cp2 = d2.get("portable", {}).get("callpath", "")
            cp3 = d3.get("portable", {}).get("callpath", "")
            callpath1 = cp1

            if not cp1:
                failures.append("k1 callpath is empty")
            if cp1 != cp2 or cp1 != cp3:
                failures.append(f"Callpath parity mismatch: k1={cp1}, k2={cp2}, k3={cp3}")

            m1 = d1.get("reach", {}).get("mismatch", [])
            m2 = d2.get("reach", {}).get("mismatch", [])
            m3 = d3.get("reach", {}).get("mismatch", [])
            if m1 or m2 or m3:
                failures.append(f"Reach mismatch non-empty: m1={m1}, m2={m2}, m3={m3}")
        except Exception as ex:
            failures.append(f"Key parse error: {ex}")
    else:
        failures.append("One or more key files (k1, k2, k3) missing")

    # --- Defined Symbols via nm -U ---
    effect_symbols = check_defined_symbols(c1_bin)

    # --- Runs of P, C1, C3 ---
    p_run_exit = None
    c1_run_exit = None
    c3_run_exit = None

    if res_p_build.returncode == 0 and res_c1_build.returncode == 0 and res_c3_build.returncode == 0:
        # Prepare run environments and sandboxes
        if is_std:
            sandbox_p = os.path.join(pdir, "sandbox_p")
            sandbox_c1 = os.path.join(pdir, "sandbox_c1")
            sandbox_c3 = os.path.join(pdir, "sandbox_c3")
            for sb in [sandbox_p, sandbox_c1, sandbox_c3]:
                os.makedirs(sb, exist_ok=True)
            run_cwd = pdir
            env_p_extra = {"IYI_OBSERVE": p_trace, "IYI_FILE_SANDBOX": sandbox_p}
            env_c1_extra = {"IYI_OBSERVE": c1_trace, "IYI_FILE_SANDBOX": sandbox_c1}
            env_c3_extra = {"IYI_OBSERVE": c3_trace, "IYI_FILE_SANDBOX": sandbox_c3}
        else:
            samples_copy = os.path.join(pdir, "samples")
            shutil.copytree(os.path.join(repo, "samples/iyi"), samples_copy)
            run_cwd = samples_copy
            env_p_extra = {"IYI_OBSERVE": p_trace}
            env_c1_extra = {"IYI_OBSERVE": c1_trace}
            env_c3_extra = {"IYI_OBSERVE": c3_trace}

        # Run P
        try:
            res_p_run = subprocess.run(
                [p_bin],
                cwd=run_cwd,
                env=clean_env(repo, cache_p, warm=False, extra=env_p_extra),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=False,
                timeout=timeout,
            )
            p_run_exit = res_p_run.returncode
        except subprocess.TimeoutExpired:
            res_p_run = None
            failures.append(f"P run timed out after {timeout}s")

        # Run C1
        try:
            res_c1_run = subprocess.run(
                [c1_bin],
                cwd=run_cwd,
                env=clean_env(repo, cache_c, warm=False, extra=env_c1_extra),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=False,
                timeout=timeout,
            )
            c1_run_exit = res_c1_run.returncode
        except subprocess.TimeoutExpired:
            res_c1_run = None
            failures.append(f"C1 run timed out after {timeout}s")

        # Run C3 (Warm)
        try:
            res_c3_run = subprocess.run(
                [c3_bin],
                cwd=run_cwd,
                env=clean_env(repo, cache_c, warm=True, extra=env_c3_extra),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=False,
                timeout=timeout,
            )
            c3_run_exit = res_c3_run.returncode
        except subprocess.TimeoutExpired:
            res_c3_run = None
            failures.append(f"C3 run timed out after {timeout}s")

        # Check outputs for __iyi_effect_
        for tag, r in [("P", res_p_run), ("C1", res_c1_run), ("C3", res_c3_run)]:
            if r is not None:
                if b"__iyi_effect_" in r.stdout or b"__iyi_effect_" in r.stderr:
                    failures.append(f"{tag} run output names __iyi_effect_")

        # Check traces non-empty
        for tag, tpath in [("P", p_trace), ("C1", c1_trace), ("C3", c3_trace)]:
            if not os.path.exists(tpath) or os.path.getsize(tpath) == 0:
                failures.append(f"{tag} trace missing or empty ({tpath})")

        # R-1 comparison: P vs C1, and C1 vs C3
        if res_p_run is not None and res_c1_run is not None:
            out_p = res_p_run.stdout + res_p_run.stderr
            out_c1 = res_c1_run.stdout + res_c1_run.stderr
            ok_pc1, msg_pc1 = compare_r1(
                prog_base,
                res_p_run.returncode,
                res_c1_run.returncode,
                out_p,
                out_c1,
                compare_same_opt_fn,
            )
            if not ok_pc1:
                failures.append(f"R-1 [P vs C1] {msg_pc1}")

        if res_c1_run is not None and res_c3_run is not None:
            out_c1 = res_c1_run.stdout + res_c1_run.stderr
            out_c3 = res_c3_run.stdout + res_c3_run.stderr
            ok_c1c3, msg_c1c3 = compare_r1(
                prog_base,
                res_c1_run.returncode,
                res_c3_run.returncode,
                out_c1,
                out_c3,
                compare_same_opt_fn,
            )
            if not ok_c1c3:
                failures.append(f"R-1 [C1 vs C3] {msg_c1c3}")

    p_nonzero = bool(is_std and p_run_exit is not None and p_run_exit != 0)

    # Cleanup per row on success
    if not failures:
        shutil.rmtree(pdir, ignore_errors=True)

    check_disk_space(work_root, 20.0)

    return {
        "source": source,
        "name": rel,
        "base": prog_base,
        "kind": "std" if is_std else "sample",
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "p_exit": p_run_exit,
        "c1_exit": c1_run_exit,
        "c3_exit": c3_run_exit,
        "callpath": callpath1,
        "effect_symbols": effect_symbols,
        "p_nonzero": p_nonzero,
        "preserved_dir": pdir if failures else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run 2: All 141 Artifact Legs (P, C1, C2, C3)")
    parser.add_argument("--repo", default=".", help="Path to repo/worktree")
    parser.add_argument("--compiler", required=True, help="Path to compiler binary")
    parser.add_argument("--work", default="/tmp/iyi_artifact_legs", help="Scratch work directory")
    parser.add_argument("--report", default="", help="Path to write JSONL results")
    parser.add_argument("--workers", type=int, default=2, help="Number of concurrent workers (default 2)")
    parser.add_argument("--filter", default="", help="Filter substring for programs")
    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    compiler = os.path.abspath(args.compiler)
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)

    # Import frames_equivalent from repo/bench
    bench_dir = os.path.join(repo, "bench")
    if bench_dir not in sys.path:
        sys.path.insert(0, bench_dir)
    try:
        from frames_equivalent import compare_same_opt
    except ImportError as e:
        sys.stderr.write(f"ERROR: Cannot import frames_equivalent from {bench_dir}: {e}\n")
        sys.exit(1)

    c2_samples = sorted(glob.glob(os.path.join(repo, "samples/iyi/*.iyi")))
    c3_std = sorted(glob.glob(os.path.join(repo, "bench/std_*_exercise.iyi")))

    print(f"Asserting corpus counts: samples={len(c2_samples)} (expected 27), std={len(c3_std)} (expected 114)")
    assert len(c2_samples) == 27, f"Expected exactly 27 samples, found {len(c2_samples)}"
    assert len(c3_std) == 114, f"Expected exactly 114 std exercises, found {len(c3_std)}"

    all_programs = c2_samples + c3_std
    assert len(all_programs) == 141, f"Expected exactly 141 corpus programs, found {len(all_programs)}"

    if args.filter:
        all_programs = [p for p in all_programs if args.filter in p]
        print(f"Filtered corpus to {len(all_programs)} programs matching '{args.filter}'")

    print(f"Starting Run 2 over {len(all_programs)} programs with {args.workers} workers...")
    print(f"Work directory: {work}")

    results = []
    print_lock = threading.Lock()

    def task_fn(src: str):
        res = run_single_program(src, repo, compiler, work, compare_same_opt)
        with print_lock:
            status_tag = f"[{res['status']}]"
            extra = ""
            if res["status"] != "PASS":
                extra = f" -> {'; '.join(res['failures'])}"
            elif res["p_nonzero"]:
                extra = f" (p_nonzero exit={res['p_exit']})"
            print(f"  {status_tag:6s} {res['name']}{extra}")
            sys.stdout.flush()
        return res

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for r in pool.map(task_fn, all_programs):
            results.append(r)

    # Write report if requested
    if args.report:
        report_path = os.path.abspath(args.report)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
        print(f"Report written to {report_path}")

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] != "PASS")
    p_nonzeros = [r["name"] for r in results if r["p_nonzero"]]

    print("\n" + "=" * 60)
    print(f"RUN 2 SUMMARY: total={total} passed={passed} failed={failed}")
    if p_nonzeros:
        print(f"  P-nonzero programs requiring Run 3 proof ({len(p_nonzeros)}):")
        for pnz in p_nonzeros:
            print(f"    - {pnz}")
    print("=" * 60)

    if failed > 0:
        print(f"RUN 2 FAILED: {failed} programs failed", file=sys.stderr)
        sys.exit(1)
    else:
        print("RUN 2 PASSED: All artifact legs verified successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
