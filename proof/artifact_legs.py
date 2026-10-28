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
  - k1, k2, k3: non-empty equal callpath, empty mismatch, phase=="linked", reach.checked==True
  - P against C1, and C1 against C3, pass R-1 rule:
      * Exit codes equal
      * Four exit-only exercises checked for exit equality only
      * Stdout must be strictly byte-for-byte equal
      * Stderr must be byte-equal or pass frames_equivalent.py CLI subprocess
  - No run output names __iyi_effect_, and every trace is non-empty
  - nm -U defined symbols check on C1, C2, and C3 binaries
  - 2 workers, private sandboxes/caches per row, cleaned up on success
  - Stop if disk free space < 20 GB
  - No assert statements (library rule).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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

BUILD_TIMEOUT = 300
RUN_DEFAULT_TIMEOUT = 60
RUN_HEAVY_TIMEOUT = 300


def run_timeout_for(relpath: str) -> int:
    return RUN_HEAVY_TIMEOUT if relpath in HEAVY else RUN_DEFAULT_TIMEOUT


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


def run_session_proc(
    cmd: list[str],
    cwd: str,
    env: dict[str, str],
    timeout_sec: float,
    stdin_devnull: bool = True,
) -> tuple[int, bytes, bytes, bool]:
    stdin = subprocess.DEVNULL if stdin_devnull else None
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    pgid = proc.pid
    timed_out = False
    stdout = b""
    stderr = b""
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        time.sleep(0.5)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, stdout, stderr, timed_out


def check_defined_symbols(binary_path: str, nm_bin: str = "nm") -> list[str]:
    if not os.path.exists(binary_path):
        raise RuntimeError(f"Binary does not exist for symbol scan: {binary_path}")
    proc = subprocess.run([nm_bin, "-U", binary_path], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"{nm_bin} -U failed (exit {proc.returncode}): {proc.stderr.strip()}")
    symbols = []
    for line in proc.stdout.splitlines():
        if "__iyi_effect_" in line:
            symbols.append(line.strip())
    return symbols


def compare_r1(
    name: str,
    status_a: int,
    status_b: int,
    stdout_a: bytes,
    stderr_a: bytes,
    stdout_b: bytes,
    stderr_b: bytes,
    repo_root: str,
    pdir: str,
    tag: str,
) -> tuple[bool, str]:
    if status_a != status_b:
        return False, f"exit status mismatch: {status_a} != {status_b}"

    if name in EXIT_ONLY_EXERCISES:
        return True, "exit-only check passed"

    # Stdout must be strictly byte-for-byte equal
    if stdout_a != stdout_b:
        diff_len = f"len {len(stdout_a)} != {len(stdout_b)}" if len(stdout_a) != len(stdout_b) else "differing bytes"
        return False, f"stdout mismatch ({diff_len})"

    # Stderr must be byte-equal or satisfy frames_equivalent.py CLI
    if stderr_a == stderr_b:
        return True, "exact stdout and stderr match"

    if platform.system() != "Darwin":
        return False, "stderr differs (frames_equivalent CLI only available on Darwin)"

    # Write per-stream stderr files for frames_equivalent.py subprocess invocation
    stderr_file_a = os.path.join(pdir, f"stderr_{tag}_a.out")
    stderr_file_b = os.path.join(pdir, f"stderr_{tag}_b.out")
    with open(stderr_file_a, "wb") as f:
        f.write(stderr_a)
    with open(stderr_file_b, "wb") as f:
        f.write(stderr_b)

    fe_script = os.path.join(repo_root, "bench/frames_equivalent.py")
    if not os.path.isfile(fe_script):
        raise RuntimeError(f"frames_equivalent.py not found at {fe_script}")

    proc = subprocess.run(
        [sys.executable, fe_script, stderr_file_a, stderr_file_b],
        capture_output=True,
        text=True,
        check=False,
    )

    if proc.returncode == 0:
        return True, "stdout byte-equal and stderr frames equivalent"
    elif proc.returncode == 1:
        violation = proc.stdout.strip() or proc.stderr.strip()
        return False, f"stderr frames equivalence failed: {violation}"
    else:
        raise RuntimeError(f"frames_equivalent.py crashed (exit {proc.returncode}): {proc.stderr.strip()}")


def run_single_program(
    source: str,
    repo: str,
    compiler: str,
    work_root: str,
    nm_bin: str = "nm",
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

    run_timeout = run_timeout_for(rel)
    failures: list[str] = []
    stop_condition: str | None = None

    # --- Leg P Build ---
    cmd_p = [compiler, "build", "-Diyi_observe", "--emit-iyimod", mods, "-o", p_bin, source]
    rc, p_b_out, p_b_err, timed_out = run_session_proc(
        cmd_p, cwd=repo, env=clean_env(repo, cache_p, warm=False), timeout_sec=BUILD_TIMEOUT
    )
    if timed_out:
        failures.append(f"P build timed out after {BUILD_TIMEOUT}s")
    elif rc != 0:
        failures.append(f"P build failed (exit {rc}): {p_b_err.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in p_b_out or b"__iyi_effect_" in p_b_err:
        failures.append("P build output names __iyi_effect_")

    # --- Leg C1 Build ---
    cmd_c1 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k1, "-o", c1_bin, source]
    rc, c1_b_out, c1_b_err, timed_out = run_session_proc(
        cmd_c1, cwd=repo, env=clean_env(repo, cache_c, warm=False), timeout_sec=BUILD_TIMEOUT
    )
    if timed_out:
        failures.append(f"C1 build timed out after {BUILD_TIMEOUT}s")
    elif rc != 0:
        failures.append(f"C1 build failed (exit {rc}): {c1_b_err.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in c1_b_out or b"__iyi_effect_" in c1_b_err:
        failures.append("C1 build output names __iyi_effect_")

    # --- Leg C2 Build ---
    cmd_c2 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k2, "-o", c2_bin, source]
    rc, c2_b_out, c2_b_err, timed_out = run_session_proc(
        cmd_c2, cwd=repo, env=clean_env(repo, cache_c, warm=False), timeout_sec=BUILD_TIMEOUT
    )
    if timed_out:
        failures.append(f"C2 build timed out after {BUILD_TIMEOUT}s")
    elif rc != 0:
        failures.append(f"C2 build failed (exit {rc}): {c2_b_err.decode(errors='replace')[-300:]}")
    if b"__iyi_effect_" in c2_b_out or b"__iyi_effect_" in c2_b_err:
        failures.append("C2 build output names __iyi_effect_")

    # --- Leg C3 Build (Warm) ---
    cmd_c3 = [compiler, "build", "-Diyi_observe", "--use-iyimod", mods, "--stale-key", k3, "-o", c3_bin, source]
    rc, c3_b_out, c3_b_err, timed_out = run_session_proc(
        cmd_c3, cwd=repo, env=clean_env(repo, cache_c, warm=True), timeout_sec=BUILD_TIMEOUT
    )
    if timed_out:
        failures.append(f"C3 build timed out after {BUILD_TIMEOUT}s")
    elif rc != 0:
        err_text = c3_b_err.decode(errors="replace")
        if "cannot name it" in err_text:
            stop_condition = f"C3 warm consumer refused on artifact name: {err_text[-300:]}"
        failures.append(f"C3 build failed (exit {rc}): {err_text[-300:]}")
    if b"__iyi_effect_" in c3_b_out or b"__iyi_effect_" in c3_b_err:
        failures.append("C3 build output names __iyi_effect_")

    # --- Key Checks ---
    callpath1 = ""
    not_reusable_count = 0
    if os.path.exists(k1) and os.path.exists(k2) and os.path.exists(k3):
        try:
            with open(k1, "r", encoding="utf-8") as f:
                d1 = json.load(f)
            with open(k2, "r", encoding="utf-8") as f:
                d2 = json.load(f)
            with open(k3, "r", encoding="utf-8") as f:
                d3 = json.load(f)

            for tag, d in [("k1", d1), ("k2", d2), ("k3", d3)]:
                if d.get("phase") != "linked":
                    failures.append(f"{tag} phase is '{d.get('phase')}', expected 'linked'")
                if not d.get("reach", {}).get("checked"):
                    failures.append(f"{tag} reach.checked is not True")

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

            not_reusable_count = len(d1.get("reach", {}).get("not_reusable", []))

        except Exception as ex:
            failures.append(f"Key parse error: {ex}")
    else:
        failures.append("One or more key files (k1, k2, k3) missing")

    # --- Defined Symbols via nm -U on C1, C2, and C3 ---
    all_effect_symbols: list[str] = []
    for c_tag, c_bin in [("C1", c1_bin), ("C2", c2_bin), ("C3", c3_bin)]:
        if os.path.exists(c_bin):
            try:
                syms = check_defined_symbols(c_bin, nm_bin)
                if syms:
                    stop_condition = f"Defined __iyi_effect_ symbols found in {c_tag} binary: {syms}"
                    failures.append(stop_condition)
                all_effect_symbols.extend([f"{c_tag}:{s}" for s in syms])
            except RuntimeError as ex:
                failures.append(f"{c_tag} symbol scan failed: {ex}")
        else:
            failures.append(f"{c_tag} binary does not exist at {c_bin}")

    # --- Runs of P, C1, C3 ---
    p_run_exit = None
    c1_run_exit = None
    c3_run_exit = None

    builds_ok = (
        os.path.exists(p_bin)
        and os.path.exists(c1_bin)
        and os.path.exists(c3_bin)
        and len(failures) == 0
    )

    if builds_ok:
        # Recreate fresh sandbox / copytree before every single run
        sandbox_dir = os.path.join(pdir, "row_sandbox")

        def reset_sandbox() -> str:
            if os.path.exists(sandbox_dir):
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            if is_std:
                os.makedirs(sandbox_dir, exist_ok=True)
                return sandbox_dir
            else:
                shutil.copytree(os.path.join(repo, "samples/iyi"), sandbox_dir)
                return sandbox_dir

        # Run P
        run_cwd = reset_sandbox()
        env_extra = {"IYI_OBSERVE": p_trace}
        if is_std:
            env_extra["IYI_FILE_SANDBOX"] = sandbox_dir

        rc_p, p_r_out, p_r_err, timed_out = run_session_proc(
            [p_bin], cwd=run_cwd, env=clean_env(repo, cache_p, warm=False, extra=env_extra), timeout_sec=run_timeout
        )
        if timed_out:
            failures.append(f"P run timed out after {run_timeout}s")
        p_run_exit = rc_p

        # Run C1
        run_cwd = reset_sandbox()
        env_extra = {"IYI_OBSERVE": c1_trace}
        if is_std:
            env_extra["IYI_FILE_SANDBOX"] = sandbox_dir

        rc_c1, c1_r_out, c1_r_err, timed_out = run_session_proc(
            [c1_bin], cwd=run_cwd, env=clean_env(repo, cache_c, warm=False, extra=env_extra), timeout_sec=run_timeout
        )
        if timed_out:
            failures.append(f"C1 run timed out after {run_timeout}s")
        c1_run_exit = rc_c1

        # Run C3 (Warm)
        run_cwd = reset_sandbox()
        env_extra = {"IYI_OBSERVE": c3_trace}
        if is_std:
            env_extra["IYI_FILE_SANDBOX"] = sandbox_dir

        rc_c3, c3_r_out, c3_r_err, timed_out = run_session_proc(
            [c3_bin], cwd=run_cwd, env=clean_env(repo, cache_c, warm=True, extra=env_extra), timeout_sec=run_timeout
        )
        if timed_out:
            failures.append(f"C3 run timed out after {run_timeout}s")
        c3_run_exit = rc_c3

        # Check outputs for __iyi_effect_
        for tag, out_b, err_b in [("P", p_r_out, p_r_err), ("C1", c1_r_out, c1_r_err), ("C3", c3_r_out, c3_r_err)]:
            if b"__iyi_effect_" in out_b or b"__iyi_effect_" in err_b:
                failures.append(f"{tag} run output names __iyi_effect_")

        # Check traces non-empty
        for tag, tpath in [("P", p_trace), ("C1", c1_trace), ("C3", c3_trace)]:
            if not os.path.exists(tpath) or os.path.getsize(tpath) == 0:
                failures.append(f"{tag} trace missing or empty ({tpath})")

        # R-1 comparison: P vs C1, and C1 vs C3
        if p_run_exit is not None and c1_run_exit is not None:
            ok_pc1, msg_pc1 = compare_r1(
                prog_base,
                p_run_exit,
                c1_run_exit,
                p_r_out,
                p_r_err,
                c1_r_out,
                c1_r_err,
                repo,
                pdir,
                "pc1",
            )
            if not ok_pc1:
                failures.append(f"R-1 [P vs C1] {msg_pc1}")

        if c1_run_exit is not None and c3_run_exit is not None:
            ok_c1c3, msg_c1c3 = compare_r1(
                prog_base,
                c1_run_exit,
                c3_run_exit,
                c1_r_out,
                c1_r_err,
                c3_r_out,
                c3_r_err,
                repo,
                pdir,
                "c1c3",
            )
            if not ok_c1c3:
                failures.append(f"R-1 [C1 vs C3] {msg_c1c3}")

    p_nonzero = bool(is_std and p_run_exit is not None and p_run_exit != 0)

    # Cleanup per row on success
    if not failures and not stop_condition:
        shutil.rmtree(pdir, ignore_errors=True)

    check_disk_space(work_root, 20.0)

    status = "STOP" if stop_condition else ("PASS" if not failures else "FAIL")

    return {
        "source": source,
        "name": rel,
        "base": prog_base,
        "kind": "std" if is_std else "sample",
        "status": status,
        "failures": failures,
        "stop_condition": stop_condition,
        "p_exit": p_run_exit,
        "c1_exit": c1_run_exit,
        "c3_exit": c3_run_exit,
        "callpath": callpath1,
        "not_reusable_count": not_reusable_count,
        "effect_symbols": all_effect_symbols,
        "p_nonzero": p_nonzero,
        "preserved_dir": pdir if (failures or stop_condition) else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run 2: All 141 Artifact Legs (P, C1, C2, C3)")
    parser.add_argument("--repo", default=".", help="Path to repo/worktree")
    parser.add_argument("--compiler", required=True, help="Path to compiler binary")
    parser.add_argument("--work", default="/tmp/iyi_artifact_legs", help="Scratch work directory")
    parser.add_argument("--report", default="", help="Path to write JSONL results")
    parser.add_argument("--workers", type=int, default=2, help="Number of concurrent workers (default 2)")
    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    compiler = os.path.abspath(args.compiler)
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)

    c2_samples = sorted(glob.glob(os.path.join(repo, "samples/iyi/*.iyi")))
    c3_std = sorted(glob.glob(os.path.join(repo, "bench/std_*_exercise.iyi")))

    print(f"Asserting corpus counts: samples={len(c2_samples)} (expected 27), std={len(c3_std)} (expected 114)")
    if len(c2_samples) != 27:
        raise ValueError(f"Expected exactly 27 samples, found {len(c2_samples)}")
    if len(c3_std) != 114:
        raise ValueError(f"Expected exactly 114 std exercises, found {len(c3_std)}")

    all_programs = c2_samples + c3_std
    if len(all_programs) != 141:
        raise ValueError(f"Expected exactly 141 corpus programs, found {len(all_programs)}")

    print(f"Starting Run 2 over {len(all_programs)} programs with {args.workers} workers...")
    print(f"Work directory: {work}")

    results = []
    print_lock = threading.Lock()

    def task_fn(src: str):
        res = run_single_program(src, repo, compiler, work)
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

    if args.report:
        report_path = os.path.abspath(args.report)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
        print(f"Report written to {report_path}")

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    stops = sum(1 for r in results if r["status"] == "STOP")
    failed = sum(1 for r in results if r["status"] not in ("PASS", "STOP"))
    p_nonzeros = [r["name"] for r in results if r["p_nonzero"]]

    print("\n" + "=" * 60)
    print(f"RUN 2 SUMMARY: total={total} passed={passed} failed={failed} stops={stops}")
    if p_nonzeros:
        print(f"  P-nonzero programs requiring Run 3 proof ({len(p_nonzeros)}):")
        for pnz in p_nonzeros:
            print(f"    - {pnz}")
    print("=" * 60)

    if stops > 0:
        print(f"RUN 2 STOP TRIGGERED: {stops} programs hit stop condition", file=sys.stderr)
        sys.exit(1)
    elif failed > 0:
        print(f"RUN 2 FAILED: {failed} programs failed", file=sys.stderr)
        sys.exit(1)
    else:
        print("RUN 2 PASSED: All artifact legs verified successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
