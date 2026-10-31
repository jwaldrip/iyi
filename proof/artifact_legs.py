#!/usr/bin/env python3
"""Run and retain the four artifact legs for every observed corpus row."""

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
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Sequence


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
DISK_MIN_GB = 20.0

_BUILD_LEGS = ("P", "C1", "C2", "C3")
_RUN_LEGS = ("P", "C1", "C3")


def run_timeout_for(
    relpath: str,
    *,
    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,
    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,
) -> float:
    return run_heavy_timeout if relpath in HEAVY else run_default_timeout


def check_disk_space(path: str, min_gb: float = DISK_MIN_GB) -> None:
    usage = shutil.disk_usage(path)
    free_gb = usage.free / (1024**3)
    if free_gb < min_gb:
        raise RuntimeError(
            f"Disk space below threshold: {free_gb:.2f} GB free < {min_gb:.2f} GB"
        )


def clean_env(repo: str, cache_dir: str, warm: bool = False, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Add only the Run 2 leg variables to the already-scrubbed environment."""
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("IYI_") or key.startswith("CRYSTAL_"):
            env.pop(key, None)

    env["IYI_CACHE_DIR"] = cache_dir
    env["IYI_PATH"] = f"{repo}/src{os.pathsep}{repo}/samples/iyi"
    env["IYI_LIBRARY_PATH"] = f"{repo}/lib"
    env["LIBRARY_PATH"] = "/opt/homebrew/opt/bdw-gc/lib"
    env["PKG_CONFIG_PATH"] = "/opt/homebrew/opt/openssl@3/lib/pkgconfig"

    if warm:
        env["IYI_WARM"] = "1"
    if extra:
        env.update(extra)
    return env


def _kill_process_group(pgid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return


def run_session_proc(cmd: list[str], cwd: str, env: dict[str, str], timeout_sec: float, stdin_devnull: bool = True) -> tuple[int, bytes, bytes, bool]:
    """Run one build or program in its own process group."""
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
    timed_out = False
    stdout = b""
    stderr = b""
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(proc.pid, signal.SIGTERM)
        try:
            stdout, stderr = proc.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, stdout, stderr, timed_out


def check_defined_symbols(binary_path: str, nm_bin: str) -> list[str]:
    if not os.path.exists(binary_path):
        raise RuntimeError(f"binary does not exist for symbol scan: {binary_path}")
    proc = subprocess.run(
        [nm_bin, "-U", binary_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(
            f"{nm_bin} -U failed (exit {proc.returncode}): {detail}"
        )
    return [
        line.strip()
        for line in proc.stdout.splitlines()
        if "__iyi_effect_" in line
    ]


def _compare_frame_stderr(stderr_a: bytes, stderr_b: bytes, repo_root: str, row_dir: str, tag: str) -> tuple[bool, str]:
    stderr_file_a = os.path.join(row_dir, f"stderr_{tag}_a.out")
    stderr_file_b = os.path.join(row_dir, f"stderr_{tag}_b.out")
    with open(stderr_file_a, "wb") as stream:
        stream.write(stderr_a)
    with open(stderr_file_b, "wb") as stream:
        stream.write(stderr_b)

    frames_script = os.path.join(repo_root, "bench/frames_equivalent.py")
    if not os.path.isfile(frames_script):
        raise RuntimeError(f"frames_equivalent.py not found at {frames_script}")

    proc = subprocess.run(
        [sys.executable, frames_script, stderr_file_a, stderr_file_b],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return True, "stdout byte-equal and stderr frames equivalent"
    if proc.returncode == 1:
        violation = proc.stdout.strip() or proc.stderr.strip()
        return False, f"stderr frames equivalence failed: {violation}"
    raise RuntimeError(
        "frames_equivalent.py crashed "
        f"(exit {proc.returncode}): {proc.stderr.strip()}"
    )


def compare_r1(name: str, status_a: int, status_b: int, stdout_a: bytes, stderr_a: bytes, stdout_b: bytes, stderr_b: bytes, repo_root: str, row_dir: str, tag: str) -> tuple[bool, str]:
    if status_a != status_b:
        return False, f"exit status mismatch: {status_a} != {status_b}"

    if name in EXIT_ONLY_EXERCISES:
        return True, "exit-only check passed"

    if stdout_a != stdout_b:
        difference = f"len {len(stdout_a)} != {len(stdout_b)}" if len(stdout_a) != len(stdout_b) else "differing bytes"
        return False, f"stdout mismatch ({difference})"

    if stderr_a == stderr_b:
        return True, "exact stdout and stderr match"

    return _compare_frame_stderr(stderr_a, stderr_b, repo_root, row_dir, tag) if platform.system() == "Darwin" else (False, "stderr differs (frames_equivalent CLI only available on Darwin)")


def _row_identity(source: str, repo: str, work_root: str) -> tuple[str, str, str, bool, str]:
    source_path = os.path.realpath(source)
    repo_path = os.path.realpath(repo)
    relpath = os.path.relpath(source_path, repo_path)
    raw_base = os.path.basename(source_path)
    base = raw_base[:-4] if raw_base.endswith(".iyi") else raw_base
    is_std = relpath.startswith(f"bench{os.sep}")
    row_dir = os.path.join(work_root, "rows", base)
    return source_path, relpath, base, is_std, row_dir


def _empty_row(source: str, repo: str, work_root: str) -> dict:
    source_path, relpath, base, is_std, row_dir = _row_identity(
        source, repo, work_root
    )
    legs = {
        leg: {
            "build": {
                "exit": None,
                "timed_out": False,
                "stdout": _output_path(row_dir, leg, "build", "stdout"),
                "stderr": _output_path(row_dir, leg, "build", "stderr"),
            },
            "run": None,
        }
        for leg in _BUILD_LEGS
    }
    return {
        "source": source_path,
        "name": relpath,
        "base": base,
        "kind": "std" if is_std else "sample",
        "status": "FAIL",
        "failures": [],
        "stop_condition": None,
        "p_exit": None,
        "c1_exit": None,
        "c3_exit": None,
        "callpath": "",
        "not_reusable_count": 0,
        "effect_symbols": [],
        "p_nonzero": False,
        "preserved_dir": row_dir,
        "row_dir": row_dir,
        "legs": legs,
    }


def _output_path(row_dir: str, leg: str, phase: str, stream: str) -> str:
    return os.path.join(row_dir, f"{leg}.{phase}.{stream}")


def _prepare_row_directory(row_dir: str) -> None:
    shutil.rmtree(row_dir, ignore_errors=True)
    os.makedirs(row_dir, exist_ok=True)
    for leg in _BUILD_LEGS:
        for stream in ("stdout", "stderr"):
            with open(_output_path(row_dir, leg, "build", stream), "wb"):
                pass
    for leg in _RUN_LEGS:
        for stream in ("stdout", "stderr"):
            with open(_output_path(row_dir, leg, "run", stream), "wb"):
                pass
        with open(_output_path(row_dir, leg, "run", "exit"), "w", encoding="utf-8") as stream:
            stream.write("NOT-RUN\n")


def _save_process_output(row_dir: str, leg: str, phase: str, stdout: bytes, stderr: bytes, exit_code: int | None = None) -> None:
    with open(_output_path(row_dir, leg, phase, "stdout"), "wb") as stream:
        stream.write(stdout)
    with open(_output_path(row_dir, leg, phase, "stderr"), "wb") as stream:
        stream.write(stderr)
    if phase == "run":
        with open(
            _output_path(row_dir, leg, phase, "exit"),
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write(f"{exit_code}\n")


def _remove_success_scratch(paths: Sequence[str]) -> None:
    for path in paths:
        shutil.rmtree(path, ignore_errors=True)


def _run_row(
    source: str,
    *,
    repo: str,
    compiler: str,
    work_root: str,
    nm_bin: str,
    build_timeout: float = BUILD_TIMEOUT,
    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,
    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,
    disk_min_gb: float = DISK_MIN_GB,
) -> dict:
    result = _empty_row(source, repo, work_root)
    source_path = result["source"]
    relpath = result["name"]
    base = result["base"]
    is_std = result["kind"] == "std"
    row_dir = result["row_dir"]
    run_timeout = run_timeout_for(
        relpath,
        run_default_timeout=run_default_timeout,
        run_heavy_timeout=run_heavy_timeout,
    )

    _prepare_row_directory(row_dir)
    check_disk_space(work_root, disk_min_gb)

    bin_root = os.path.join(row_dir, "bin")
    cache_p = os.path.join(row_dir, "cache_p")
    cache_c = os.path.join(row_dir, "cache_c")
    mods = os.path.join(row_dir, "mods")
    sandbox = os.path.join(row_dir, "sandbox")
    for directory in (bin_root, cache_p, cache_c, mods):
        os.makedirs(directory, exist_ok=True)

    binaries = {
        leg: os.path.join(bin_root, leg.lower(), base)
        for leg in _BUILD_LEGS
    }
    for path in binaries.values():
        os.makedirs(os.path.dirname(path), exist_ok=True)

    key_paths = {
        "C1": os.path.join(row_dir, "k1.key"),
        "C2": os.path.join(row_dir, "k2.key"),
        "C3": os.path.join(row_dir, "k3.key"),
    }
    trace_paths = {
        "P": os.path.join(row_dir, "P.trace"),
        "C1": os.path.join(row_dir, "C1.trace"),
        "C3": os.path.join(row_dir, "C3.trace"),
    }

    commands = {
        "P": [
            compiler,
            "build",
            "-Diyi_observe",
            "--emit-iyimod",
            mods,
            "-o",
            binaries["P"],
            source_path,
        ],
        "C1": [
            compiler,
            "build",
            "-Diyi_observe",
            "--use-iyimod",
            mods,
            "--stale-key",
            key_paths["C1"],
            "-o",
            binaries["C1"],
            source_path,
        ],
        "C2": [
            compiler,
            "build",
            "-Diyi_observe",
            "--use-iyimod",
            mods,
            "--stale-key",
            key_paths["C2"],
            "-o",
            binaries["C2"],
            source_path,
        ],
        "C3": [
            compiler,
            "build",
            "-Diyi_observe",
            "--use-iyimod",
            mods,
            "--stale-key",
            key_paths["C3"],
            "-o",
            binaries["C3"],
            source_path,
        ],
    }

    failures: list[str] = []
    stop_reasons: list[str] = []
    legs: dict[str, dict] = {}
    missing_binaries: set[str] = set()

    def fail(code: str, reason: str) -> None:
        failures.append(f"{code}: {reason}")

    for leg in _BUILD_LEGS:
        warm = leg == "C3"
        cache = cache_p if leg == "P" else cache_c
        rc, stdout, stderr, timed_out = run_session_proc(
            commands[leg],
            cwd=repo,
            env=clean_env(repo, cache, warm=warm),
            timeout_sec=build_timeout,
        )
        _save_process_output(row_dir, leg, "build", stdout, stderr)
        legs[leg] = {
            "build": {
                "argv": commands[leg],
                "exit": rc,
                "timed_out": timed_out,
                "stdout": _output_path(row_dir, leg, "build", "stdout"),
                "stderr": _output_path(row_dir, leg, "build", "stderr"),
            },
            "run": None,
        }

        if timed_out:
            fail(
                f"BUILD-TIMEOUT-{leg}",
                f"{leg} build timed out after {build_timeout}s",
            )
        elif rc != 0:
            stderr_text = stderr.decode(errors="replace")
            detail = stderr_text[-300:]
            fail(
                f"BUILD-EXIT-{leg}",
                f"{leg} build failed (exit {rc}): {detail}",
            )
            if leg == "C3" and "cannot name it" in stderr_text:
                stop_reasons.append(
                    "C3 warm consumer stderr contains 'cannot name it'"
                )
                fail(
                    "C3-CANNOT-NAME",
                    "C3 warm consumer stderr contains 'cannot name it'",
                )
        elif not os.path.isfile(binaries[leg]):
            fail(
                f"BUILD-MISSING-{leg}",
                f"{leg} build exited 0 without binary {binaries[leg]}",
            )
            missing_binaries.add(leg)

        if b"__iyi_effect_" in stdout or b"__iyi_effect_" in stderr:
            fail(
                f"BUILD-EFFECT-{leg}",
                f"{leg} build output names __iyi_effect_",
            )

    key_documents: dict[str, dict] = {}
    missing_keys = [
        os.path.basename(path)
        for path in key_paths.values()
        if not os.path.isfile(path)
    ]
    if missing_keys:
        fail(
            "KEY-MISSING",
            "one or more key files missing: " + ", ".join(sorted(missing_keys)),
        )
    else:
        try:
            for leg, path in key_paths.items():
                with open(path, "r", encoding="utf-8") as stream:
                    document = json.load(stream)
                if not isinstance(document, dict):
                    raise TypeError(f"{os.path.basename(path)} root is not an object")
                key_documents[leg] = document
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as error:
            fail("KEY-PARSE", f"key parse error: {type(error).__name__}: {error}")

    callpath = ""
    not_reusable_count = 0
    if len(key_documents) == 3:
        for leg in ("C1", "C2", "C3"):
            document = key_documents[leg]
            key_name = {"C1": "k1", "C2": "k2", "C3": "k3"}[leg]
            if document.get("phase") != "linked":
                fail(
                    f"KEY-PHASE-{key_name}",
                    f"{key_name} phase is {document.get('phase')!r}, expected 'linked'",
                )
            reach = document.get("reach")
            if not isinstance(reach, dict) or reach.get("checked") is not True:
                fail(
                    f"REACH-CHECKED-{key_name}",
                    f"{key_name} reach.checked is not True",
                )

        callpaths = {
            leg: document.get("portable", {}).get("callpath", "")
            if isinstance(document.get("portable"), dict)
            else ""
            for leg, document in key_documents.items()
        }
        callpath = callpaths["C1"]
        empty_callpaths = [leg for leg, value in callpaths.items() if not value]
        if empty_callpaths:
            fail(
                "CALLPATH-EMPTY",
                "callpath is empty for " + ", ".join(sorted(empty_callpaths)),
            )
        if len(set(callpaths.values())) != 1:
            fail(
                "CALLPATH-PARITY",
                "callpath parity mismatch: "
                + ", ".join(
                    f"{leg}={value!r}" for leg, value in callpaths.items()
                ),
            )

        mismatches: dict[str, object] = {}
        for leg, document in key_documents.items():
            reach = document.get("reach")
            value = reach.get("mismatch") if isinstance(reach, dict) else None
            if value:
                mismatches[leg] = value
        if mismatches:
            fail(
                "REACH-MISMATCH",
                "reach mismatch non-empty: "
                + ", ".join(
                    f"{leg}={value!r}" for leg, value in mismatches.items()
                ),
            )

        not_reusable = key_documents["C1"].get("not_reusable", [])
        if not isinstance(not_reusable, list):
            fail("NOT-REUSABLE-TYPE", "k1 not_reusable is not an array")
        else:
            not_reusable_count = len(not_reusable)

    effect_symbols: list[str] = []
    for leg in ("C1", "C2", "C3"):
        if leg in missing_binaries:
            continue
        try:
            symbols = check_defined_symbols(binaries[leg], nm_bin)
        except RuntimeError as error:
            fail(f"NM-ERROR-{leg}", f"{leg} symbol scan failed: {error}")
            continue
        if symbols:
            tagged = [f"{leg}:{symbol}" for symbol in symbols]
            effect_symbols.extend(tagged)
            reason = f"defined __iyi_effect_ symbols found in {leg} binary: {symbols}"
            fail(f"EFFECT-SYMBOL-{leg}", reason)
            stop_reasons.append(reason)

    run_results: dict[str, tuple[int, bytes, bytes, bool]] = {}
    builds_ok = not failures and not stop_reasons

    def reset_sandbox() -> str:
        shutil.rmtree(sandbox, ignore_errors=True)
        if is_std:
            os.makedirs(sandbox, exist_ok=True)
        else:
            shutil.copytree(os.path.join(repo, "samples", "iyi"), sandbox)
        return sandbox

    run_effect_legs: set[str] = set()
    if builds_ok:
        for leg in _RUN_LEGS:
            run_cwd = reset_sandbox()
            extra = {"IYI_OBSERVE": trace_paths[leg]}
            if is_std:
                extra["IYI_FILE_SANDBOX"] = sandbox
            cache = cache_p if leg == "P" else cache_c
            rc, stdout, stderr, timed_out = run_session_proc(
                [binaries[leg]],
                cwd=run_cwd,
                env=clean_env(repo, cache, warm=leg == "C3", extra=extra),
                timeout_sec=run_timeout,
            )
            _save_process_output(
                row_dir,
                leg,
                "run",
                stdout,
                stderr,
                exit_code=rc,
            )
            run_results[leg] = (rc, stdout, stderr, timed_out)
            legs[leg]["run"] = {
                "argv": [binaries[leg]],
                "cwd": run_cwd,
                "exit": rc,
                "timed_out": timed_out,
                "stdout": _output_path(row_dir, leg, "run", "stdout"),
                "stderr": _output_path(row_dir, leg, "run", "stderr"),
                "exit_file": _output_path(row_dir, leg, "run", "exit"),
            }
            if timed_out:
                fail(
                    f"RUN-TIMEOUT-{leg}",
                    f"{leg} run timed out after {run_timeout}s",
                )
            if b"__iyi_effect_" in stdout or b"__iyi_effect_" in stderr:
                fail(
                    f"RUN-EFFECT-{leg}",
                    f"{leg} run output names __iyi_effect_",
                )
                run_effect_legs.add(leg)

        for leg in _RUN_LEGS:
            trace_path = trace_paths[leg]
            if not os.path.isfile(trace_path) or os.path.getsize(trace_path) == 0:
                fail(
                    f"TRACE-EMPTY-{leg}",
                    f"{leg} trace missing or empty ({trace_path})",
                )

        comparisons = (
            ("P", "C1", "P-C1", "pc1"),
            ("C1", "C3", "C1-C3", "c1c3"),
        )
        for left, right, code_tag, file_tag in comparisons:
            left_result = run_results[left]
            right_result = run_results[right]
            if left_result[3] or right_result[3] or left in run_effect_legs or right in run_effect_legs:
                continue
            ok, message = compare_r1(
                base,
                left_result[0],
                right_result[0],
                left_result[1],
                left_result[2],
                right_result[1],
                right_result[2],
                repo,
                row_dir,
                file_tag,
            )
            if not ok:
                fail(f"R1-{code_tag}", f"R-1 [{code_tag}] {message}")

    p_result = run_results.get("P")
    p_exit = p_result[0] if p_result is not None else None
    c1_result = run_results.get("C1")
    c3_result = run_results.get("C3")
    p_nonzero = bool(
        is_std
        and p_result is not None
        and not p_result[3]
        and p_exit != 0
    )

    stop_condition = "; ".join(stop_reasons) if stop_reasons else None
    status = "STOP" if stop_condition else ("PASS" if not failures else "FAIL")
    scratch_paths = (bin_root, cache_p, cache_c, mods, sandbox)
    if status == "PASS":
        _remove_success_scratch(scratch_paths)

    check_disk_space(work_root, disk_min_gb)

    result.update(
        {
            "status": status,
            "failures": failures,
            "stop_condition": stop_condition,
            "p_exit": p_exit,
            "c1_exit": c1_result[0] if c1_result is not None else None,
            "c3_exit": c3_result[0] if c3_result is not None else None,
            "callpath": callpath,
            "not_reusable_count": not_reusable_count,
            "effect_symbols": effect_symbols,
            "p_nonzero": p_nonzero,
            "preserved_dir": row_dir if status != "PASS" else None,
            "legs": legs,
        }
    )
    return result


def run_row(
    source: str,
    *,
    repo: str,
    compiler: str,
    work_root: str,
    nm_bin: str,
    build_timeout: float = BUILD_TIMEOUT,
    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,
    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,
    disk_min_gb: float = DISK_MIN_GB,
) -> dict:
    """Run one row, converting only OSError and RuntimeError at the row boundary."""
    result = _empty_row(source, repo, work_root)
    try:
        return _run_row(
            source,
            repo=repo,
            compiler=compiler,
            work_root=work_root,
            nm_bin=nm_bin,
            build_timeout=build_timeout,
            run_default_timeout=run_default_timeout,
            run_heavy_timeout=run_heavy_timeout,
            disk_min_gb=disk_min_gb,
        )
    except (OSError, RuntimeError) as error:
        category = "OSERROR" if isinstance(error, OSError) else "RUNTIMEERROR"
        code = f"ROW-{category}"
        result["failures"] = [f"{code}: {type(error).__name__}: {error}"]
        result["status"] = "FAIL"
        result["preserved_dir"] = result["row_dir"]
        return result


def run_rows(
    sources: Sequence[str],
    *,
    repo: str,
    compiler: str,
    work_root: str,
    nm_bin: str,
    workers: int,
    build_timeout: float = BUILD_TIMEOUT,
    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,
    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,
    disk_min_gb: float = DISK_MIN_GB,
) -> list[dict]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                run_row,
                source,
                repo=repo,
                compiler=compiler,
                work_root=work_root,
                nm_bin=nm_bin,
                build_timeout=build_timeout,
                run_default_timeout=run_default_timeout,
                run_heavy_timeout=run_heavy_timeout,
                disk_min_gb=disk_min_gb,
            )
            for source in sources
        ]
        results = [future.result() for future in futures]

    for result in results:
        extra = ""
        if result["status"] != "PASS":
            extra = f" -> {'; '.join(result['failures'])}"
        elif result["p_nonzero"]:
            extra = f" (p_nonzero exit={result['p_exit']})"
        status_tag = f"[{result['status']}]"
        print(f"  {status_tag:6s} {result['name']}{extra}")
        sys.stdout.flush()
    return results


def write_report(report_path: str, rows: Sequence[dict]) -> None:
    directory = os.path.dirname(report_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run 2: all artifact legs (P, C1, C2, C3)"
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--workers", required=True, type=int)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--expect-samples", required=True, type=int)
    parser.add_argument("--expect-std", required=True, type=int)
    parser.add_argument("--expect-total", required=True, type=int)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    build_timeout: float = BUILD_TIMEOUT,
    run_default_timeout: float = RUN_DEFAULT_TIMEOUT,
    run_heavy_timeout: float = RUN_HEAVY_TIMEOUT,
    disk_min_gb: float = DISK_MIN_GB,
) -> int:
    parser = _argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    usage_error = "--workers must be at least 1" if args.workers < 1 else ("expected counts must be non-negative" if min(args.expect_samples, args.expect_std, args.expect_total) < 0 else "")
    if usage_error:
        print(f"artifact_legs: {usage_error}", file=sys.stderr)
        return 2

    repo = os.path.realpath(args.repo)
    compiler = os.path.realpath(args.compiler)
    work = os.path.realpath(args.work)
    report = os.path.realpath(args.report)
    nm_bin = os.path.realpath(args.nm)
    os.makedirs(work, exist_ok=True)

    samples = sorted(glob.glob(os.path.join(repo, "samples", "iyi", "*.iyi")))
    std = sorted(glob.glob(os.path.join(repo, "bench", "std_*_exercise.iyi")))
    sources = samples + std

    count_failures: list[str] = []
    if len(samples) != args.expect_samples:
        count_failures.append(
            f"samples={len(samples)}, expected={args.expect_samples}"
        )
    if len(std) != args.expect_std:
        count_failures.append(f"std={len(std)}, expected={args.expect_std}")
    if len(sources) != args.expect_total:
        count_failures.append(
            f"total={len(sources)}, expected={args.expect_total}"
        )

    print(
        "Corpus counts: "
        f"samples={len(samples)} expected={args.expect_samples}; "
        f"std={len(std)} expected={args.expect_std}; "
        f"total={len(sources)} expected={args.expect_total}"
    )
    if count_failures:
        print(
            "RUN 2 count mismatch: " + "; ".join(count_failures),
            file=sys.stderr,
        )

    rows = run_rows(
        sources,
        repo=repo,
        compiler=compiler,
        work_root=work,
        nm_bin=nm_bin,
        workers=args.workers,
        build_timeout=build_timeout,
        run_default_timeout=run_default_timeout,
        run_heavy_timeout=run_heavy_timeout,
        disk_min_gb=disk_min_gb,
    )
    write_report(report, rows)
    print(f"Report written to {report}")

    passed = sum(row["status"] == "PASS" for row in rows)
    stops = sum(row["status"] == "STOP" for row in rows)
    failed = len(rows) - passed - stops
    print(
        "RUN 2 SUMMARY: "
        f"total={len(rows)} passed={passed} failed={failed} stops={stops}"
    )

    if count_failures or failed or stops:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
