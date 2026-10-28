"""
proofkit.py: Core proof toolkit for iyilang/iyi observed corpus proof.
Contains shared contracts C2, C3, C5, C7, bounded execution, identity checks,
census validation, and ledger verification.

Library rule: Every proofkit function takes explicit paths and values.
No assert statements in non-test modules.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass


class IdentityError(RuntimeError):
    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class CensusValidationError(RuntimeError):
    pass


class LedgerVerificationError(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def check_disk_space(path: str, min_gb: float = 20.0) -> float:
    usage = shutil.disk_usage(path)
    free_gb = usage.free / (1024 ** 3)
    if free_gb < min_gb:
        raise RuntimeError(f"Disk space below threshold: {free_gb:.2f} GB free < {min_gb} GB on {path}")
    return free_gb


def extract_version_stamp(version_output: str) -> str:
    m = re.search(r"\[([0-9a-f]{7,40})\]", version_output)
    if not m:
        raise ValueError(f"Version output does not contain git commit stamp '[...]' : {version_output.strip()}")
    return m.group(1)


def git_cmd(args: list[str], cwd: str) -> str:
    proc = subprocess.run(
        ["git", "-C", cwd] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git -C {cwd} {' '.join(args)} failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def git_clean(cwd: str) -> bool:
    out = git_cmd(["status", "--porcelain"], cwd)
    return len(out) == 0


def git_rev_parse(ref: str, cwd: str) -> str:
    return git_cmd(["rev-parse", ref], cwd)


def git_commit_time(ref: str, cwd: str) -> int:
    out = git_cmd(["log", "-1", "--format=%ct", ref], cwd)
    return int(out)


def git_merge_base_is_ancestor(ancestor: str, descendant: str, cwd: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", cwd, "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def git_diff_name_only(a: str, b: str, cwd: str) -> list[str]:
    out = git_cmd(["diff", "--name-only", a, b], cwd)
    return [line.strip() for line in out.splitlines() if line.strip()]


def git_diff_quiet(a: str, b: str, cwd: str, pathspecs: list[str] | None = None) -> bool:
    cmd = ["git", "-C", cwd, "diff", "--quiet", a, b]
    if pathspecs:
        cmd.extend(["--"] + pathspecs)
    proc = subprocess.run(cmd, capture_output=True, check=False)
    return proc.returncode == 0


def base_env(pin: dict | None = None, stage_extra: dict[str, str] | None = None) -> dict[str, str]:
    """
    Contract C2 + Amendment A: Clean environment for stage processes started directly by run_proof.
    Removes:
      - every key starting with IYI_ or CRYSTAL_
      - PYTHONOPTIMIZE, PYTHONPATH, PYTHONHOME, PYTHONSTARTUP
      - ROUTE_A_DRIVERS, STD_SIBLINGS, SIBLING_MINUTES
    Sets:
      - LIBRARY_PATH=/opt/homebrew/opt/bdw-gc/lib
      - PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
      - PYTHONDONTWRITEBYTECODE=1
    From pin:
      - PATH, HOME
    Stage additions only via stage_extra.
    """
    env = os.environ.copy()

    for k in list(env.keys()):
        if k.startswith("IYI_") or k.startswith("CRYSTAL_"):
            env.pop(k, None)

    for k in [
        "PYTHONOPTIMIZE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "ROUTE_A_DRIVERS",
        "STD_SIBLINGS",
        "SIBLING_MINUTES",
    ]:
        env.pop(k, None)

    env["LIBRARY_PATH"] = "/opt/homebrew/opt/bdw-gc/lib"
    env["PKG_CONFIG_PATH"] = "/opt/homebrew/opt/openssl@3/lib/pkgconfig"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    if pin:
        env["PATH"] = pin["env_path"]
        env["HOME"] = pin["env_home"]

    if stage_extra:
        env.update(stage_extra)

    return env


def compute_canonical_roots(
    w_path: str,
    p_path: str,
    compiler_path: str,
    pin_env: dict[str, str],
) -> list[str]:
    roots: list[str] = []
    for base in (w_path, p_path):
        for relative in ("src", "samples/iyi"):
            candidate = os.path.join(base, relative)
            if os.path.isdir(candidate):
                roots.append(os.path.realpath(candidate))

    proc = subprocess.run(
        [compiler_path, "env", "IYI_PATH"],
        cwd=w_path,
        env=base_env(pin_env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise IdentityError(
            "COMPILER-ENV",
            f"`env IYI_PATH` exited {proc.returncode}: {proc.stderr.strip()}",
        )
    for entry in proc.stdout.strip().split(os.pathsep):
        if not entry:
            continue
        resolved = os.path.realpath(os.path.join(w_path, entry))
        if os.path.isdir(resolved):
            roots.append(resolved)

    return list(dict.fromkeys(roots))


def probe_atime_observable(
    dir_path: str,
    stat_fn: Callable[[str], os.stat_result] = os.stat,
) -> dict[str, int | str]:
    """Prove that executing an inode on the report volume advances its atime."""
    probe_id = secrets.token_hex(8)
    test_exe = os.path.join(dir_path, f"probe-atime-{probe_id}")
    test_ref = os.path.join(dir_path, f"probe-atime-{probe_id}.ref")
    try:
        shutil.copyfile("/usr/bin/true", test_exe)
        os.chmod(test_exe, 0o755)
        original_sha = sha256_file(test_exe)
        os.link(test_exe, test_ref)

        copied = stat_fn(test_exe)
        mtime_ns = copied.st_mtime_ns
        atime_set_ns = mtime_ns - 1_000_000_000
        os.utime(test_exe, ns=(atime_set_ns, mtime_ns))

        before_stat = stat_fn(test_ref)
        after_stat = stat_fn(test_ref)
        if before_stat.st_atime_ns != atime_set_ns:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                "the requested pre-exec atime was not retained",
            )
        if after_stat.st_atime_ns != before_stat.st_atime_ns:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                "a metadata-only stat changed atime",
            )

        executed = subprocess.run(
            [test_exe],
            cwd=dir_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if executed.returncode != 0:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                f"/usr/bin/true copy exited {executed.returncode}",
            )

        after_exec = stat_fn(test_ref)
        if after_exec.st_atime_ns <= mtime_ns:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                "execution did not advance atime past mtime",
            )
        final_sha = sha256_file(test_ref)
        if final_sha != original_sha:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                f"probe bytes changed: expected {original_sha}, got {final_sha}",
            )
        if after_exec.st_ino != copied.st_ino:
            raise IdentityError(
                "EXEC-UNOBSERVABLE",
                "the hard-linked execution probe changed inode",
            )

        return {
            "sha256": original_sha,
            "inode": copied.st_ino,
            "mtime_ns": mtime_ns,
            "atime_set_ns": atime_set_ns,
            "atime_after_exec_ns": after_exec.st_atime_ns,
        }
    except IdentityError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise IdentityError("EXEC-UNOBSERVABLE", str(error)) from error
    finally:
        for path in (test_ref, test_exe):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


def _first_output_line(
    command: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    reason: str,
) -> str:
    proc = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.strip().splitlines()
    if proc.returncode != 0 or not lines:
        detail = proc.stderr.strip() or proc.stdout.strip() or "no output"
        raise IdentityError(
            reason,
            f"{' '.join(command)} exited {proc.returncode}: {detail}",
        )
    return lines[0]

def _nm_version_line(
    nm_path: str,
    *,
    cwd: str,
    env: dict[str, str],
) -> str:
    attempts: list[str] = []
    for argument in ("--version", "-version"):
        proc = subprocess.run(
            [nm_path, argument],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        lines = (proc.stdout.strip() or proc.stderr.strip()).splitlines()
        if proc.returncode == 0 and lines:
            return lines[0]
        attempts.append(
            f"{argument}: exit={proc.returncode} "
            f"output={(proc.stdout.strip() or proc.stderr.strip())!r}"
        )
    raise IdentityError("NO-NM", "; ".join(attempts))


def _census_shas_and_validate(
    w_path: str,
    drivers: Sequence[str],
) -> dict[str, str]:
    census_dir = os.path.join(w_path, "proof", "census")
    expected_files = {f"{driver}.json" for driver in drivers}
    try:
        actual_files = {
            name
            for name in os.listdir(census_dir)
            if name.endswith(".json")
        }
    except OSError as error:
        raise IdentityError("CENSUS-SET", str(error)) from error
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise IdentityError(
            "CENSUS-SET",
            f"missing={missing}, extra={extra}",
        )

    census_shas: dict[str, str] = {}
    for driver in drivers:
        census_path = os.path.join(census_dir, f"{driver}.json")
        try:
            with open(census_path, "r", encoding="utf-8") as census_file:
                census = json.load(census_file)
            validate_census(census, w_path)
        except (
            CensusValidationError,
            json.JSONDecodeError,
            OSError,
            TypeError,
            ValueError,
        ) as error:
            raise IdentityError(
                "CENSUS-INVALID",
                f"{driver}: {error}",
            ) from error
        census_shas[driver] = sha256_file(census_path)
    return census_shas


def inspect_pin_inputs(
    p_path: str,
    w_path: str,
    compiler_path: str,
    drivers: Sequence[str],
) -> dict:
    """Validate every read-only pin precondition and return the pinned facts."""
    p_real = os.path.realpath(p_path)
    w_real = os.path.realpath(w_path)
    c_real = os.path.realpath(compiler_path)
    env_path = os.environ.get("PATH", "")
    env_home = os.environ.get("HOME", "")
    pin_env = {"env_path": env_path, "env_home": env_home}

    try:
        if not git_clean(p_real):
            raise IdentityError("P-DIRTY", p_real)
        if not git_clean(w_real):
            raise IdentityError("W-DIRTY", w_real)
        p_sha = git_rev_parse("HEAD", p_real)
        p_time = git_commit_time("HEAD", p_real)
        w_head = git_rev_parse("HEAD", w_real)
    except IdentityError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise IdentityError("GIT-ERROR", str(error)) from error

    if not git_merge_base_is_ancestor(p_sha, w_head, w_real):
        raise IdentityError(
            "W-NOT-DESCENDANT",
            f"W HEAD {w_head} does not descend from P {p_sha}",
        )
    try:
        diff_files = git_diff_name_only(p_sha, w_head, w_real)
        product_quiet = git_diff_quiet(
            p_sha,
            w_head,
            w_real,
            [".", ":(exclude)proof"],
        )
    except (OSError, RuntimeError) as error:
        raise IdentityError("GIT-ERROR", str(error)) from error
    product_files = [path for path in diff_files if not path.startswith("proof/")]
    if product_files or not product_quiet:
        raise IdentityError(
            "PRODUCT-DIFF",
            f"non-proof paths={product_files}",
        )

    if not os.path.isfile(c_real) or not os.access(c_real, os.X_OK):
        raise IdentityError(
            "COMPILER-NOT-EXECUTABLE",
            c_real,
        )
    try:
        compiler_stat = os.stat(c_real)
        compiler_sha = sha256_file(c_real)
    except OSError as error:
        raise IdentityError("COMPILER-STAT", str(error)) from error
    if compiler_stat.st_mtime_ns <= p_time * 1_000_000_000:
        raise IdentityError(
            "COMPILER-STALE",
            f"mtime_ns={compiler_stat.st_mtime_ns}, p_commit_ns={p_time * 1_000_000_000}",
        )

    clean_env = base_env(pin_env)
    version_line = _first_output_line(
        [c_real, "--version"],
        cwd=w_real,
        env=clean_env,
        reason="COMPILER-VERSION",
    )
    try:
        stamp = extract_version_stamp(version_line)
    except ValueError as error:
        raise IdentityError("COMPILER-STAMP-MISSING", str(error)) from error
    if not p_sha.startswith(stamp):
        raise IdentityError(
            "COMPILER-STAMP-MISMATCH",
            f"stamp={stamp}, p_source_sha={p_sha}",
        )

    timeout_path = shutil.which("timeout", path=env_path)
    if not timeout_path:
        raise IdentityError(
            "NO-TIMEOUT",
            "timeout does not resolve on the pinned PATH",
        )
    timeout_real = os.path.realpath(timeout_path)
    timeout_version = _first_output_line(
        [timeout_real, "--version"],
        cwd=w_real,
        env=clean_env,
        reason="NO-TIMEOUT",
    )

    nm_path = shutil.which("nm", path=env_path)
    if not nm_path:
        raise IdentityError("NO-NM", "nm does not resolve on the pinned PATH")
    nm_real = os.path.realpath(nm_path)
    nm_version = _nm_version_line(
        nm_real,
        cwd=w_real,
        env=clean_env,
    )

    census_shas = _census_shas_and_validate(w_real, drivers)
    canonical_roots = compute_canonical_roots(
        w_real,
        p_real,
        c_real,
        pin_env,
    )

    return {
        "p_path": p_real,
        "p_source_sha": p_sha,
        "p_commit_time": p_time,
        "w_path": w_real,
        "w_head": w_head,
        "compiler_path": c_real,
        "compiler_sha256": compiler_sha,
        "compiler_size": compiler_stat.st_size,
        "compiler_mtime_ns": compiler_stat.st_mtime_ns,
        "compiler_inode": compiler_stat.st_ino,
        "compiler_version_line": version_line,
        "compiler_stamp": stamp,
        "canonical_roots": canonical_roots,
        "env_path": env_path,
        "env_home": env_home,
        "python_path": os.path.realpath(sys.executable),
        "python_version": sys.version.splitlines()[0],
        "nm_path": nm_real,
        "nm_version": nm_version,
        "timeout_path": timeout_real,
        "timeout_version": timeout_version,
        "census_sha256": census_shas,
    }


def _validated_report_dir(
    report_dir: str,
    *,
    require_empty: bool,
    chain_id: str | None = None,
) -> str:
    report_real = os.path.realpath(report_dir)
    match = re.fullmatch(r"/private/tmp/iyp-([0-9a-f]{8})", report_real)
    if not match:
        raise IdentityError(
            "REPORT-DIR-NAME",
            f"{report_real} does not match /private/tmp/iyp-<8 lowercase hex>",
        )
    if chain_id is not None:
        if not re.fullmatch(r"[0-9a-f]{32}", chain_id):
            raise IdentityError("CHAIN-ID", f"invalid chain_id {chain_id!r}")
        if match.group(1) != chain_id[:8]:
            raise IdentityError(
                "REPORT-DIR-CHAIN",
                f"basename suffix {match.group(1)} != chain prefix {chain_id[:8]}",
            )
    if require_empty and os.path.exists(report_real):
        try:
            entries = sorted(os.listdir(report_real))
        except OSError as error:
            raise IdentityError("REPORT-DIR", str(error)) from error
        if entries:
            raise IdentityError(
                "REPORT-DIR-NOT-EMPTY",
                f"{report_real} holds {entries}",
            )
    return report_real


def write_pin(
    report_dir: str,
    p_path: str,
    w_path: str,
    compiler_path: str,
    drivers: Sequence[str],
    chain_id: str | None = None,
    stat_fn: Callable[[str], os.stat_result] = os.stat,
) -> dict:
    """Validate C3/D4/D5 and write the immutable pin once."""
    report_real = _validated_report_dir(
        report_dir,
        require_empty=True,
        chain_id=chain_id,
    )
    facts = inspect_pin_inputs(p_path, w_path, compiler_path, drivers)
    short_chain = os.path.basename(report_real).removeprefix("iyp-")
    if chain_id is None:
        chain_id = short_chain + secrets.token_hex(12)
    report_real = _validated_report_dir(
        report_real,
        require_empty=True,
        chain_id=chain_id,
    )

    created_report_dir = not os.path.exists(report_real)
    try:
        os.makedirs(report_real, exist_ok=True)
        probe_atime_observable(report_real, stat_fn=stat_fn)
        pin_data = {
            **facts,
            "report_dir": report_real,
            "chain_id": chain_id,
        }
        pin_file = os.path.join(report_real, "pin.json")
        with open(pin_file, "x", encoding="utf-8") as output:
            json.dump(pin_data, output, indent=2, sort_keys=True)
            output.write("\n")
        return pin_data
    except IdentityError:
        if created_report_dir:
            try:
                os.rmdir(report_real)
            except OSError:
                pass
        raise
    except (OSError, TypeError, ValueError) as error:
        if created_report_dir:
            try:
                os.rmdir(report_real)
            except OSError:
                pass
        raise IdentityError("PIN-WRITE", str(error)) from error


def load_pin(report_dir: str) -> dict:
    report_real = _validated_report_dir(report_dir, require_empty=False)
    pin_file = os.path.join(report_real, "pin.json")
    if not os.path.isfile(pin_file):
        raise IdentityError("PIN-MISSING", pin_file)
    try:
        with open(pin_file, "r", encoding="utf-8") as source:
            pin = json.load(source)
    except (json.JSONDecodeError, OSError) as error:
        raise IdentityError("PIN-INVALID", str(error)) from error
    chain_id = pin.get("chain_id")
    if not isinstance(chain_id, str):
        raise IdentityError("CHAIN-ID", "pin has no string chain_id")
    _validated_report_dir(
        report_real,
        require_empty=False,
        chain_id=chain_id,
    )
    if pin.get("report_dir") != report_real:
        raise IdentityError(
            "REPORT-DIR-CHAIN",
            f"pin report_dir={pin.get('report_dir')!r}, actual={report_real!r}",
        )
    return pin


def _require_equal(reason: str, label: str, expected: object, got: object) -> None:
    if got != expected:
        raise IdentityError(
            reason,
            f"{label}: expected {expected!r}, got {got!r}",
        )


def check_identity(pin: dict) -> None:
    p_path = pin["p_path"]
    w_path = pin["w_path"]
    compiler_path = pin["compiler_path"]

    _validated_report_dir(
        pin["report_dir"],
        require_empty=False,
        chain_id=pin["chain_id"],
    )
    _require_equal(
        "PATH-CHANGED",
        "PATH",
        pin["env_path"],
        os.environ.get("PATH", ""),
    )

    try:
        current_p_sha = git_rev_parse("HEAD", p_path)
        current_w_head = git_rev_parse("HEAD", w_path)
    except (OSError, RuntimeError) as error:
        raise IdentityError("GIT-ERROR", str(error)) from error
    _require_equal("P-HEAD-CHANGED", "P HEAD", pin["p_source_sha"], current_p_sha)
    if not git_clean(p_path):
        raise IdentityError("P-DIRTY", p_path)
    _require_equal("W-HEAD-CHANGED", "W HEAD", pin["w_head"], current_w_head)
    if not git_clean(w_path):
        raise IdentityError("W-DIRTY", w_path)
    if not git_merge_base_is_ancestor(pin["p_source_sha"], current_w_head, w_path):
        raise IdentityError(
            "W-NOT-DESCENDANT",
            f"W HEAD {current_w_head} does not descend from {pin['p_source_sha']}",
        )
    product_paths = [
        path
        for path in git_diff_name_only(
            pin["p_source_sha"],
            current_w_head,
            w_path,
        )
        if not path.startswith("proof/")
    ]
    if product_paths or not git_diff_quiet(
        pin["p_source_sha"],
        current_w_head,
        w_path,
        [".", ":(exclude)proof"],
    ):
        raise IdentityError("PRODUCT-DIFF", f"non-proof paths={product_paths}")

    if not os.path.isfile(compiler_path) or not os.access(compiler_path, os.X_OK):
        raise IdentityError("COMPILER-NOT-EXECUTABLE", compiler_path)
    try:
        compiler_stat = os.stat(compiler_path)
        compiler_sha = sha256_file(compiler_path)
    except OSError as error:
        raise IdentityError("COMPILER-STAT", str(error)) from error
    _require_equal(
        "COMPILER-SHA-CHANGED",
        "compiler sha256",
        pin["compiler_sha256"],
        compiler_sha,
    )
    _require_equal(
        "COMPILER-SIZE-CHANGED",
        "compiler size",
        pin["compiler_size"],
        compiler_stat.st_size,
    )
    _require_equal(
        "COMPILER-MTIME-CHANGED",
        "compiler mtime_ns",
        pin["compiler_mtime_ns"],
        compiler_stat.st_mtime_ns,
    )
    _require_equal(
        "COMPILER-INODE-CHANGED",
        "compiler inode",
        pin["compiler_inode"],
        compiler_stat.st_ino,
    )

    clean_env = base_env(pin)
    version_line = _first_output_line(
        [compiler_path, "--version"],
        cwd=w_path,
        env=clean_env,
        reason="COMPILER-VERSION",
    )
    _require_equal(
        "COMPILER-VERSION-CHANGED",
        "compiler version line",
        pin["compiler_version_line"],
        version_line,
    )
    try:
        stamp = extract_version_stamp(version_line)
    except ValueError as error:
        raise IdentityError("COMPILER-STAMP-MISSING", str(error)) from error
    _require_equal(
        "COMPILER-STAMP-CHANGED",
        "compiler stamp",
        pin["compiler_stamp"],
        stamp,
    )

    current_census_shas = _census_shas_and_validate(
        w_path,
        tuple(sorted(pin["census_sha256"])),
    )
    _require_equal(
        "CENSUS-CHANGED",
        "census sha256 map",
        pin["census_sha256"],
        current_census_shas,
    )
    roots = compute_canonical_roots(w_path, p_path, compiler_path, pin)
    _require_equal(
        "CANONICAL-ROOTS-CHANGED",
        "canonical roots",
        pin["canonical_roots"],
        roots,
    )

    _require_equal(
        "PYTHON-CHANGED",
        "python realpath",
        pin["python_path"],
        os.path.realpath(sys.executable),
    )
    _require_equal(
        "PYTHON-CHANGED",
        "python version",
        pin["python_version"],
        sys.version.splitlines()[0],
    )

    timeout_path = shutil.which("timeout", path=pin["env_path"])
    if not timeout_path:
        raise IdentityError("NO-TIMEOUT", "timeout disappeared from pinned PATH")
    timeout_real = os.path.realpath(timeout_path)
    _require_equal(
        "TIMEOUT-CHANGED",
        "timeout realpath",
        pin["timeout_path"],
        timeout_real,
    )
    timeout_version = _first_output_line(
        [timeout_real, "--version"],
        cwd=w_path,
        env=clean_env,
        reason="NO-TIMEOUT",
    )
    _require_equal(
        "TIMEOUT-CHANGED",
        "timeout version",
        pin["timeout_version"],
        timeout_version,
    )

    nm_path = shutil.which("nm", path=pin["env_path"])
    if not nm_path:
        raise IdentityError("NO-NM", "nm disappeared from pinned PATH")
    nm_real = os.path.realpath(nm_path)
    _require_equal("NM-CHANGED", "nm realpath", pin["nm_path"], nm_real)
    nm_version = _nm_version_line(
        nm_real,
        cwd=w_path,
        env=clean_env,
    )
    _require_equal(
        "NM-CHANGED",
        "nm version",
        pin["nm_version"],
        nm_version,
    )

@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    timed_out: bool
    survivors: tuple[int, ...]
    interrupted_signal: int | None


class _BoundedSignal(BaseException):
    def __init__(self, signum: int):
        super().__init__(signum)
        self.signum = signum


def _process_group_members(pgid: int, *, exclude: int | None = None) -> tuple[int, ...]:
    ps_path = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
    proc = subprocess.run(
        [ps_path, "-axo", "pid=,pgid="],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ps failed while inspecting process group {pgid}: {proc.stderr.strip()}"
        )
    members: list[int] = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            pid, member_pgid = (int(field) for field in fields)
        except ValueError:
            continue
        if member_pgid == pgid and pid != exclude:
            members.append(pid)
    return tuple(sorted(set(members)))


def _signal_process_group(pgid: int, signum: int) -> None:
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def _wait_for_group_exit(pgid: int, limit_sec: float) -> tuple[int, ...]:
    deadline = time.monotonic() + max(0.0, limit_sec)
    while True:
        members = _process_group_members(pgid)
        if not members or time.monotonic() >= deadline:
            return members
        time.sleep(0.02)


def _stop_leader(proc: subprocess.Popen[bytes], pgid: int, grace_sec: float) -> None:
    _signal_process_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=grace_sec)
    except subprocess.TimeoutExpired:
        _signal_process_group(pgid, signal.SIGKILL)
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"leader {proc.pid} survived SIGKILL"
            ) from error


def _record_and_stop_survivors(
    pgid: int,
    leader_pid: int,
    grace_sec: float,
) -> tuple[int, ...]:
    survivors = _process_group_members(pgid, exclude=leader_pid)
    if not survivors:
        return ()
    _signal_process_group(pgid, signal.SIGTERM)
    remaining = _wait_for_group_exit(pgid, grace_sec)
    if remaining:
        _signal_process_group(pgid, signal.SIGKILL)
        remaining = _wait_for_group_exit(pgid, 5.0)
    if remaining:
        raise RuntimeError(
            f"process group {pgid} retained survivors after SIGKILL: {remaining}"
        )
    return survivors


def _sample_log_growth(
    log_path: str,
    times_path: str,
    stop: threading.Event,
    errors: list[BaseException],
) -> None:
    try:
        last_size = os.path.getsize(log_path)
        with open(times_path, "a", encoding="utf-8", buffering=1) as times_file:
            while not stop.wait(0.05):
                size = os.path.getsize(log_path)
                if size > last_size:
                    times_file.write(f"{time.monotonic_ns()} {size}\n")
                    last_size = size
            final_size = os.path.getsize(log_path)
            times_file.write(f"{time.monotonic_ns()} {final_size}\n")
    except (OSError, ValueError) as error:
        errors.append(error)


def run_bounded(
    cmd: list[str],
    cwd: str,
    env: dict[str, str],
    log: str,
    times: str,
    limit_sec: float | None,
    grace_sec: float = 30.0,
) -> BoundedResult:
    """Run against a log fd; leader exit, never pipe EOF, decides completion."""
    if limit_sec is not None and limit_sec <= 0:
        raise ValueError("limit_sec must be positive or None")
    if grace_sec < 0:
        raise ValueError("grace_sec must be non-negative")

    log_fd = os.open(
        log,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=log_fd,
            start_new_session=True,
        )
    finally:
        os.close(log_fd)

    stop_sampler = threading.Event()
    sampler_errors: list[BaseException] = []
    sampler = threading.Thread(
        target=_sample_log_growth,
        args=(log, times, stop_sampler, sampler_errors),
        name=f"proof-log-sampler-{proc.pid}",
        daemon=False,
    )
    sampler.start()

    previous_handlers: dict[int, object] = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous_handlers[signum] = signal.getsignal(signum)

            def interrupt_handler(
                received: int,
                _frame: object,
            ) -> None:
                raise _BoundedSignal(received)

            signal.signal(signum, interrupt_handler)

    timed_out = False
    interrupted_signal: int | None = None
    survivors: tuple[int, ...] = ()
    try:
        try:
            if limit_sec is None:
                proc.wait()
            else:
                proc.wait(timeout=limit_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            _stop_leader(proc, proc.pid, grace_sec)
        except _BoundedSignal as interrupted:
            interrupted_signal = interrupted.signum
            _stop_leader(proc, proc.pid, grace_sec)

        if proc.poll() is None:
            raise RuntimeError(f"leader {proc.pid} has no exit status")
        survivors = _record_and_stop_survivors(
            proc.pid,
            proc.pid,
            grace_sec,
        )
    finally:
        if proc.poll() is None:
            _stop_leader(proc, proc.pid, grace_sec)
        residual = _process_group_members(proc.pid, exclude=proc.pid)
        if residual:
            _signal_process_group(proc.pid, signal.SIGKILL)
            residual = _wait_for_group_exit(proc.pid, 5.0)
            if residual:
                sampler_errors.append(
                    RuntimeError(
                        f"process group {proc.pid} retained {residual}"
                    )
                )
        stop_sampler.set()
        sampler.join()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    if sampler_errors:
        raise RuntimeError(
            "; ".join(str(error) for error in sampler_errors)
        )
    return BoundedResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        timed_out=timed_out,
        survivors=survivors,
        interrupted_signal=interrupted_signal,
    )


# --- Census & Ledger Verification ---

def validate_census(census_data: dict, repo_root: str) -> None:
    """
    Contract C5 + Amendment B: Fail closed validation of a driver census.
    """
    script_rel = census_data.get("script", "")
    script_path = os.path.join(repo_root, script_rel)
    if not os.path.isfile(script_path):
        raise CensusValidationError(f"Census script not found: {script_path}")

    with open(script_path, "rb") as f:
        script_bytes = f.read()

    expected_sha = sha256_bytes(script_bytes)
    if census_data.get("script_sha256") != expected_sha:
        raise CensusValidationError(
            f"Census script_sha256 mismatch: recorded {census_data.get('script_sha256')}, actual {expected_sha}"
        )

    lines = script_bytes.decode(errors="replace").splitlines()

    # 1. Check all invocations are accounted for
    inv_re = re.compile(r"(\$IYI|\"\$IYI\"|\$\{IYI\})(?![A-Za-z0-9_:])")
    inv_lines = []
    for idx, l in enumerate(lines, 1):
        if not l.strip().startswith("#") and inv_re.search(l):
            inv_lines.append(idx)

    covered_invs = set()
    for site in census_data.get("sites", []):
        for line_num in site.get("lines", []):
            covered_invs.add(line_num)
    for ni in census_data.get("non_invocations", []):
        covered_invs.add(ni.get("line"))

    for inv in inv_lines:
        if inv not in covered_invs:
            raise CensusValidationError(f"Invocation on line {inv} not listed in sites or non_invocations")

    # 2. Check contains literals
    for site in census_data.get("sites", []):
        for c in site.get("contains", []):
            found = False
            for l_num in site.get("lines", []):
                if l_num <= len(lines) and c in lines[l_num - 1]:
                    found = True
                    break
            if not found:
                raise CensusValidationError(f"Site lines {site.get('lines')} do not contain '{c}'")

    # 3. Check pass sentinel
    ps = census_data.get("pass_sentinel", {})
    ps_line = ps.get("line", 0)
    ps_regex = ps.get("regex", "")
    if ps_line <= 0 or ps_line > len(lines):
        raise CensusValidationError(f"Invalid pass sentinel line {ps_line}")
    line_text = lines[ps_line - 1].strip()
    # Strip echo/printf prefix if regex expects the printed content
    content_text = re.sub(r'^(?:echo|printf)\s+["\']?', '', line_text)
    if not re.search(ps_regex, lines[ps_line - 1]) and not re.search(ps_regex, line_text) and not re.search(ps_regex, content_text):
        raise CensusValidationError(f"Pass sentinel line {ps_line} does not match regex '{ps_regex}': {lines[ps_line - 1]}")


def verify_ledger(ledger_path: str, driver: str, census_data: dict, pin: dict, report_dir: str) -> dict[str, int]:
    """
    Contract C7 + Amendment B: Verify Route B driver ledger.
    """
    if not os.path.isfile(ledger_path):
        raise LedgerVerificationError("STALE", f"Ledger file missing: {ledger_path}")

    records = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception as ex:
                    raise LedgerVerificationError("UNFAITHFUL", f"Corrupt ledger line: {ex}")

    if not records:
        raise LedgerVerificationError("STALE", f"Empty ledger: {ledger_path}")

    pin_nonce = pin.get("chain_id")
    target_substr = f"std_{driver}_exercise.iyi"

    found_own_roundtrip = False
    counts: dict[str, int] = {
        "roundtrip": 0, "passthrough": 0, "observed-negative": 0, "unchanged": 0
    }

    # Track open begin records for UNFAITHFUL detection
    open_begins = {}

    for rec in records:
        mode = rec.get("mode", "")
        phase = rec.get("phase", "")
        counts[mode] = counts.get(mode, 0) + 1

        if rec.get("driver") != driver:
            raise LedgerVerificationError("STALE", f"Foreign driver in ledger: {rec.get('driver')}")

        if phase == "begin":
            open_begins[rec.get("pid")] = rec
        elif phase == "end":
            open_begins.pop(rec.get("pid"), None)

            # Check divergence
            prod = rec.get("producer") or {}
            cons = rec.get("consumer") or {}
            if prod.get("rc") == 0 and cons.get("rc", 0) != 0:
                raise LedgerVerificationError("DIVERGENCE", f"Producer 0 with consumer {cons.get('rc')}")
            if cons.get("rc") == 0 and not cons.get("out_written"):
                raise LedgerVerificationError("DIVERGENCE", "Consumer 0 without writing OUT")

            # Check if this was own roundtrip
            if any(target_substr in str(s) for s in rec.get("sources", [])):
                if prod.get("rc") == 0 and cons.get("rc") == 0 and prod.get("mods_count", 0) >= 1 and cons.get("out_sha256"):
                    found_own_roundtrip = True

                    # Amendment B E3: Check kernel observable
                    out_ref = rec.get("out_ref")
                    if out_ref and os.path.exists(out_ref):
                        st = os.stat(out_ref)
                        if st.st_ino != rec.get("out_ino"):
                            raise LedgerVerificationError("NOT-EXECUTED", f"Inode changed on {out_ref}")
                        if st.st_atime_ns <= rec.get("out_mtime_ns"):
                            raise LedgerVerificationError("NOT-EXECUTED", f"atime did not advance past mtime on {out_ref}")
                        if sha256_file(out_ref) != cons.get("out_sha256"):
                            raise LedgerVerificationError("OUT-MODIFIED", f"sha256 changed on {out_ref}")

    if open_begins:
        raise LedgerVerificationError("UNFAITHFUL", f"Unclosed begin records in ledger: {open_begins}")

    if not found_own_roundtrip:
        raise LedgerVerificationError("NOT-ROUNDTRIPPED", f"No verified roundtrip found for {target_substr}")

    return counts
