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
import shlex
import json
import os
import re
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass


class IdentityError(RuntimeError):
    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail




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


def platform_temp_root(pin_env: dict[str, str], *, cwd: str, probe_mktemp: bool) -> str | None:
    """Resolve and optionally prove Amendment E's platform temp root."""
    if platform.system() != "Darwin": return None
    env_path = pin_env.get("env_path", "")
    getconf = shutil.which("getconf", path=env_path)
    if not getconf:
        raise IdentityError(
            "NO-PLATFORM-TMP",
            "getconf does not resolve on the pinned PATH",
        )
    clean_env = base_env(pin_env)
    try:
        completed = subprocess.run(
            [os.path.realpath(getconf), "DARWIN_USER_TEMP_DIR"],
            cwd=cwd,
            env=clean_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise IdentityError(
            "NO-PLATFORM-TMP",
            f"getconf DARWIN_USER_TEMP_DIR failed: {error}",
        ) from error
    lines = completed.stdout.strip().splitlines()
    if completed.returncode != 0 or len(lines) != 1 or not lines[0]:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise IdentityError(
            "NO-PLATFORM-TMP",
            f"getconf DARWIN_USER_TEMP_DIR failed: {detail or 'no output'}",
        )
    root = os.path.realpath(lines[0])
    if not os.path.isdir(root):
        raise IdentityError(
            "NO-PLATFORM-TMP",
            f"getconf returned a non-directory: {root}",
        )
    if not probe_mktemp:
        return root

    mktemp = shutil.which("mktemp", path=env_path)
    if not mktemp:
        raise IdentityError(
            "NO-PLATFORM-TMP",
            "mktemp does not resolve on the pinned PATH",
        )
    probe_tmp = os.path.realpath(
        os.path.join("/tmp", f"iyi-platform-tmp-{secrets.token_hex(8)}")
    )
    created = ""
    try:
        os.makedirs(probe_tmp, exist_ok=False)
        probe_env = base_env(pin_env, {"TMPDIR": probe_tmp})
        probe = subprocess.run(
            [os.path.realpath(mktemp), "-d"],
            cwd=cwd,
            env=probe_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        outputs = probe.stdout.strip().splitlines()
        if probe.returncode != 0 or len(outputs) != 1 or not outputs[0]:
            detail = probe.stderr.strip() or probe.stdout.strip()
            raise IdentityError(
                "PLATFORM-TMP-UNOBSERVABLE",
                f"bare mktemp -d failed: {detail or 'no output'}",
            )
        created = os.path.realpath(outputs[0])
        if not os.path.isdir(created):
            raise IdentityError(
                "PLATFORM-TMP-UNOBSERVABLE",
                f"bare mktemp returned a non-directory: {created}",
            )
        parent = os.path.realpath(os.path.dirname(created))
        if parent != root:
            raise IdentityError(
                "PLATFORM-TMP-UNOBSERVABLE",
                f"bare mktemp parent {parent!r} != platform_tmp {root!r}",
            )
    except OSError as error:
        raise IdentityError(
            "PLATFORM-TMP-UNOBSERVABLE",
            f"bare mktemp -d failed: {error}",
        ) from error
    finally:
        if created:
            shutil.rmtree(created, ignore_errors=True)
        shutil.rmtree(probe_tmp, ignore_errors=True)
    return root


def compute_canonical_roots(w_path: str, p_path: str, compiler_path: str, pin_env: dict[str, str]) -> list[str]:
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


def probe_atime_observable(dir_path: str, stat_fn: Callable[[str], os.stat_result] = os.stat) -> dict[str, int | str]:
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


def _first_output_line(command: list[str], *, cwd: str, env: dict[str, str], reason: str) -> str:
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

def _nm_version_line(nm_path: str, *, cwd: str, env: dict[str, str]) -> str:
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


def _census_shas_and_validate(w_path: str, drivers: Sequence[str]) -> dict[str, str]:
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
            script_relpath = census.get("script", "")
            script_path = os.path.join(w_path, script_relpath)
            with open(script_path, "rb") as script_file:
                script_bytes = script_file.read()
            violations = validate_census(
                census,
                script_bytes,
                script_relpath,
            )
            if violations:
                raise IdentityError(
                    "CENSUS-INVALID",
                    f"{driver}: {json.dumps(violations)}",
                )
        except IdentityError:
            raise
        except (
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
def _census_shas(w_path: str, drivers: Sequence[str]) -> dict[str, str]:
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
    return {
        driver: sha256_file(os.path.join(census_dir, f"{driver}.json"))
        for driver in drivers
    }




def inspect_pin_inputs(p_path: str, w_path: str, compiler_path: str, drivers: Sequence[str]) -> dict:
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
    platform_tmp = platform_temp_root(
        pin_env,
        cwd=w_real,
        probe_mktemp=True,
    )
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
        "platform_tmp": platform_tmp,
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


def _validated_report_dir(report_dir: str, *, require_empty: bool, chain_id: str | None = None) -> str:
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


def write_pin(report_dir: str, p_path: str, w_path: str, compiler_path: str, drivers: Sequence[str], chain_id: str | None = None, stat_fn: Callable[[str], os.stat_result] = os.stat) -> dict:
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
    current_platform_tmp = platform_temp_root(
        pin,
        cwd=w_path,
        probe_mktemp=False,
    )
    _require_equal(
        "PLATFORM-TMP-CHANGED",
        "platform temp root",
        pin["platform_tmp"],
        current_platform_tmp,
    )
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

    current_census_shas = _census_shas(
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


def _parse_process_group_members(output: str, pgid: int, exclude: int | None = None) -> tuple[int, ...]:
    members: list[int] = []
    for line in output.splitlines():
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


def _process_group_members(pgid: int, *, exclude: int | None = None, ps_path: str | None = None) -> tuple[int, ...]:
    ps_path = ps_path or ("/bin/ps" if os.path.exists("/bin/ps") else "ps")
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
    return _parse_process_group_members(
        proc.stdout,
        pgid,
        exclude,
    )


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


def _record_and_stop_survivors(pgid: int, leader_pid: int, grace_sec: float, kill_grace_sec: float = 5.0) -> tuple[int, ...]:
    survivors = _process_group_members(pgid, exclude=leader_pid)
    if not survivors:
        return ()
    _signal_process_group(pgid, signal.SIGTERM)
    remaining = _wait_for_group_exit(pgid, grace_sec)
    if remaining:
        _signal_process_group(pgid, signal.SIGKILL)
        remaining = _wait_for_group_exit(pgid, kill_grace_sec)
    if remaining:
        raise RuntimeError(
            f"process group {pgid} retained survivors after SIGKILL: {remaining}"
        )
    return survivors

def _stop_leader_if_running(proc: subprocess.Popen[bytes], pgid: int, grace_sec: float) -> None:
    if proc.poll() is None:
        _stop_leader(proc, pgid, grace_sec)


def _stop_residual_processes(pgid: int, grace_sec: float = 5.0, exclude: int | None = None) -> list[BaseException]:
    errors: list[BaseException] = []
    residual = _process_group_members(
        pgid,
        exclude=pgid if exclude is None else exclude,
    )
    if residual:
        _signal_process_group(pgid, signal.SIGKILL)
        residual = _wait_for_group_exit(pgid, grace_sec)
        if residual:
            errors.append(
                RuntimeError(
                    f"process group {pgid} retained {residual}"
                )
            )
    return errors


def _sample_log_growth(log_path: str, times_path: str, stop: threading.Event, errors: list[BaseException]) -> None:
    try:
        last_size = os.path.getsize(log_path)
        with open(times_path, "a", encoding="utf-8", buffering=1) as times_file:
            times_file.write(f"{time.monotonic_ns()} 0\n")
            while not stop.wait(0.05):
                size = os.path.getsize(log_path)
                if size > last_size:
                    times_file.write(f"{time.monotonic_ns()} {size}\n")
                    last_size = size
            final_size = os.path.getsize(log_path)
            times_file.write(f"{time.monotonic_ns()} {final_size}\n")
    except (OSError, ValueError) as error:
        errors.append(error)


def run_bounded(cmd: list[str], cwd: str, env: dict[str, str], log: str, times: str, limit_sec: float | None, grace_sec: float = 30.0) -> BoundedResult:
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

            def interrupt_handler(received: int, _frame: object) -> None:
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

        survivors = _record_and_stop_survivors(
            proc.pid,
            proc.pid,
            grace_sec,
        )
    finally:
        _stop_leader_if_running(proc, proc.pid, grace_sec)
        sampler_errors.extend(_stop_residual_processes(proc.pid))
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


RUN1_STD_EXERCISES = 114
RUN1_SIBLINGS = 115
RUN1_CORPUS = 141
RG2R_MIN = 1
RUN2_COUNTS = (27, 114, 141)
DRIVER_LIMIT_SEC = 2100.0
GRACE_SEC = 30.0
DISK_MIN_GB = 20.0

REQUIRED_CHECKS = {
    "run1": (
        "identity",
        "gate-1.1",
        "gate-1.2",
        "gate-1.3",
        "gate-1.4",
        "rg2r-count",
        "exclusions",
        "baseline-skips",
    ),
    "run2": ("identity", "legs", "counts"),
    "run3": (
        "census",
        "identity",
        "disk",
        "exit",
        "sentinel",
        "no-refused",
        "skips",
        "ledger",
    ),
}


def write_result(path: str, record: dict) -> None:
    """Atomically publish a stage result as the attempt's final write."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temporary = os.path.join(
        parent,
        f".{os.path.basename(path)}.{os.getpid()}.{secrets.token_hex(8)}.tmp",
    )
    try:
        with open(temporary, "x", encoding="utf-8") as output:
            json.dump(record, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_result(path: str) -> dict | None:
    """Load one stage result, returning None for absent or invalid content."""
    try:
        with open(path, "r", encoding="utf-8") as source:
            record = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return record if isinstance(record, dict) else None


def recompute_status(record: dict, kind: str) -> str:
    """Recompute a result status from the fixed required-check order."""
    required = REQUIRED_CHECKS.get(kind)
    checks = record.get("checks")
    if required is None or not isinstance(checks, dict):
        return "FAIL"
    for name in required:
        if name in checks and checks[name] != "PASS":
            value = checks[name]
            return value if isinstance(value, str) else "FAIL"
    if any(name not in checks for name in required):
        return "FAIL"
    return "PASS"


# --- Census & Ledger Verification ---

Violation = tuple[str, int, str]

DRIVERS_29 = (
    "acme",
    "autocert",
    "cookie",
    "dns",
    "fileserver",
    "http",
    "router",
    "secure_dns",
    "signal",
    "smtp",
    "sse",
    "term",
    "tls",
    "websocket",
    "bzip2",
    "compress",
    "hpke",
    "math",
    "mlkem",
    "png",
    "regex",
    "shlex",
    "tar",
    "xz",
    "zip",
    "zstd",
    "file",
    "file_utils",
    "fuzz",
)

_INVOCATION_RE = re.compile(
    r'(\$IYI|"\$IYI"|\$\{IYI\})(?![A-Za-z0-9_:])'
)
_SKIP_VOCAB_RE = re.compile(
    r"(?i)skip|unmeasured|unasked|unread|unproven|uncompared|"
    r"unverified|unshown|unplaced|not run|not proven|not measured|"
    r"not compared|not a pass|goes un|go un|could not be fetched|"
    r"cannot be written"
)
_SITE_KINDS = {
    "canonical-own",
    "canonical-other",
    "unchanged",
    "passthrough",
    "negative",
    "positive",
    "mixed",
}
_COMMANDS = {"build", "run", "doc", "fmt"}
_VARIANT_KINDS = {"negative", "positive"}
_TEMPLATE_FIELD_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _violation(violations: list[Violation], rule_id: str, line: int, detail: str) -> None:
    violations.append((rule_id, line if isinstance(line, int) else 0, detail))


def _closed_keys(value: object, required: set[str], path: str, violations: list[Violation], line: int = 0) -> bool:
    if not isinstance(value, dict):
        _violation(
            violations,
            "C5.0-schema",
            line,
            f"{path} must be an object",
        )
        return False
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required)
    if missing:
        _violation(
            violations,
            "C5.0-schema",
            line,
            f"{path} missing keys {missing}",
        )
    if unknown:
        _violation(
            violations,
            "C5.0-schema",
            line,
            f"{path} unknown keys {unknown}",
        )
    return not missing and not unknown


def _source_text(lines: list[str], numbers: object) -> str:
    if not isinstance(numbers, list):
        return ""
    return "\n".join(
        lines[number - 1]
        for number in numbers
        if isinstance(number, int) and 1 <= number <= len(lines)
    )


def _replace_shell_expansions(text: str) -> str | None:
    result: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "`":
            end = index + 1
            escaped = False
            while end < len(text):
                if text[end] == "`" and not escaped:
                    break
                escaped = text[end] == "\\" and not escaped
                if text[end] != "\\":
                    escaped = False
                end += 1
            if end >= len(text):
                return None
            result.append("IYIVAR")
            index = end + 1
            continue
        if char != "$":
            result.append(char)
            index += 1
            continue
        if index + 1 >= len(text):
            result.append(char)
            index += 1
            continue
        opener = text[index + 1]
        if opener in "({":
            closer = ")" if opener == "(" else "}"
            depth = 1
            end = index + 2
            quote: str | None = None
            escaped = False
            while end < len(text):
                current = text[end]
                if escaped:
                    escaped = False
                elif current == "\\" and quote != "'":
                    escaped = True
                elif quote:
                    if current == quote:
                        quote = None
                elif current in "'\"":
                    quote = current
                elif current == opener:
                    depth += 1
                elif current == closer:
                    depth -= 1
                    if depth == 0:
                        break
                end += 1
            if depth:
                return None
            result.append("IYIVAR")
            index = end + 1
            continue
        match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@#?*!-]", text[index:])
        if match:
            result.append("IYIVAR")
            index += len(match.group(0))
            continue
        result.append(char)
        index += 1
    return "".join(result)




def _template_violation(value: object, allowed_vars: set[str], field: str) -> str | None:
    if not isinstance(value, str):
        return f"{field} must be a string"
    if any(char in value for char in ("$", "`", "*", "?", "[")):
        return f"{field} contains forbidden shell syntax: {value!r}"
    placeholders = set(_TEMPLATE_FIELD_RE.findall(value))
    unknown = placeholders - {"REPO", "WORK"} - allowed_vars
    if unknown:
        return f"{field} has undeclared placeholders {sorted(unknown)}"
    residue = _TEMPLATE_FIELD_RE.sub("", value)
    if "{" in residue or "}" in residue:
        return f"{field} has malformed placeholder syntax: {value!r}"
    return None


_SHELL_OPERATORS = (
    ";;&",
    "&&",
    "||",
    ";;",
    ";&",
    "<<",
    ">>",
    "<&",
    ">&",
    "<>",
    ">|",
    "(",
    ")",
    "{",
    "}",
    ";",
    "|",
    "&",
    "<",
    ">",
)
_SHELL_COMMAND_BOUNDARIES = {
    ";",
    "&&",
    "||",
    ";;",
    ";&",
    ";;&",
    "|",
    "&",
    "(",
    ")",
    "{",
    "}",
}
_SHELL_REDIRECTIONS = {"<", ">", "<<", ">>", "<&", ">&", "<>", ">|"}
_SHELL_COMMAND_PREFIXES = {
    "if",
    "elif",
    "while",
    "until",
    "then",
    "else",
    "do",
    "!",
    "time",
    "coproc",
}




def _backtick_span_end(text: str, start: int) -> int | None:
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "`":
            return index + 1
        index += 1
    return None


def _command_substitution_end(text: str, start: int) -> int | None:
    index = start + 2
    depth = 1
    quote: str | None = None
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if char == "$" and index + 1 < len(text) and text[index + 1] == "(":
                end = _command_substitution_end(text, index)
                if end is None:
                    return None
                index = end
                continue
            if char == "`":
                end = _backtick_span_end(text, index)
                if end is None:
                    return None
                index = end
                continue
            index += 1
            continue
        if char == "'":
            quote = "'"
            index += 1
            continue
        if char == '"':
            quote = '"'
            index += 1
            continue
        if char == "`":
            end = _backtick_span_end(text, index)
            if end is None:
                return None
            index = end
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _shell_line_tokens(source: str) -> list[str] | None:
    """Split one shell line, preserving raw words and substitution spans."""
    text = source.rstrip("\r\n")
    tokens: list[str] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] == "#":
            break
        operator = next(
            (item for item in _SHELL_OPERATORS if text.startswith(item, index)),
            None,
        )
        if operator is not None:
            tokens.append(operator)
            index += len(operator)
            continue

        start = index
        quote: str | None = None
        escaped = False
        while index < len(text):
            char = text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if (
                char == "\\"
                and quote is None
                and index + 1 == len(text)
            ):
                text = text[:index]
                break
            if char == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote == "'":
                if char == "'":
                    quote = None
                index += 1
                continue
            if char == "$" and index + 1 < len(text) and text[index + 1] == "(":
                end = _command_substitution_end(text, index)
                if end is None:
                    return None
                index = end
                continue
            if char == "`":
                end = _backtick_span_end(text, index)
                if end is None:
                    return None
                index = end
                continue
            if quote == '"':
                if char == '"':
                    quote = None
                index += 1
                continue
            if char == "'":
                quote = "'"
                index += 1
                continue
            if char == '"':
                quote = '"'
                index += 1
                continue
            if quote is None and (
                char.isspace()
                or any(
                    text.startswith(item, index) for item in _SHELL_OPERATORS
                )
            ):
                break
            index += 1
        if quote is not None or escaped:
            return None
        tokens.append(text[start:index])
    return [token for token in tokens if token]


def _shell_commands_from_tokens(tokens: list[str]) -> list[list[str]]:
    commands: list[list[str]] = []
    current: list[str] = []
    skip_redirection_word = False

    def finish() -> None:
        nonlocal current
        if current:
            commands.append(current)
            current = []

    for token in tokens:
        if token in _SHELL_COMMAND_BOUNDARIES:
            finish()
            skip_redirection_word = False
            continue
        if token in _SHELL_REDIRECTIONS:
            skip_redirection_word = True
            continue
        if skip_redirection_word:
            skip_redirection_word = False
            continue
        if not current:
            if token in _SHELL_COMMAND_PREFIXES or token in {"fi", "done"}:
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                continue
        current.append(token)
    finish()
    return commands


def _shell_commands(source: str) -> list[list[str]]:
    """Return simple commands from one source line as raw shell words."""
    tokens = _shell_line_tokens(source)
    return _shell_commands_from_tokens(tokens) if tokens is not None else []


def _shell_span_bodies(word: str) -> list[str] | None:
    bodies: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(word):
        char = word[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "$" and index + 1 < len(word) and word[index + 1] == "(":
            end = _command_substitution_end(word, index)
            if end is None:
                return None
            bodies.append(word[index + 2:end - 1])
            index = end
            continue
        if char == "`":
            end = _backtick_span_end(word, index)
            if end is None:
                return None
            bodies.append(word[index + 1:end - 1])
            index = end
            continue
        if quote == '"':
            if char == '"':
                quote = None
            index += 1
            continue
        if char == "'":
            quote = "'"
            index += 1
            continue
        if char == '"':
            quote = '"'
            index += 1
            continue
        index += 1
    return None if quote is not None or escaped else bodies


def _unterminated_print_commands(source: str) -> list[list[str]] | None:
    match = re.search(
        r"(?:^|[{};)]|\bthen\b|\belse\b|\bdo\b|&&|\|\|)"
        r"\s*(echo|printf)\b(.*)$",
        source,
    )
    if not match:
        return None
    words = [match.group(1)]
    remainder = match.group(2).strip()
    if remainder:
        words.append(remainder)
    return [words]


def _top_level_print_commands(source: str) -> list[list[str]] | None:
    tokens = _shell_line_tokens(source)
    if tokens is None:
        return _unterminated_print_commands(source)
    return [
        command
        for command in _shell_commands_from_tokens(tokens)
        if command and command[0] in ("echo", "printf")
    ]


def _print_commands(source: str) -> list[list[str]] | None:
    tokens = _shell_line_tokens(source)
    if tokens is None:
        return _unterminated_print_commands(source)
    commands = [
        command
        for command in _shell_commands_from_tokens(tokens)
        if command and command[0] in ("echo", "printf")
    ]
    for token in tokens:
        bodies = _shell_span_bodies(token)
        for body in bodies:
            nested = _print_commands(body)
            commands.extend(nested)
    return commands


def _dequote_print_word(word: str) -> str | None:
    if "$'" in word:
        return None
    expanded = _replace_shell_expansions(word)
    if expanded is None:
        return None
    try:
        values = shlex.split(expanded, posix=True)
    except ValueError:
        return None
    return values[0] if len(values) == 1 else None


def _render_print_words(words: list[str]) -> str | None:
    if not words or words[0] not in ("echo", "printf"):
        return None
    arguments = list(words[1:])
    if words[0] == "echo":
        while arguments and arguments[0] in ("-n", "-e", "-E"):
            arguments.pop(0)
        rendered: list[str] = []
        for word in arguments:
            value = _dequote_print_word(word)
            if value is None:
                return None
            rendered.append(value)
        return " ".join(rendered)

    while arguments and arguments[0].startswith("-") and arguments[0] != "-":
        arguments.pop(0)
    if not arguments:
        return None
    format_string = _dequote_print_word(arguments[0])
    if format_string is None:
        return None
    return re.sub(r"%(?:s|d)", "IYIVAR", format_string).replace("\\n", "")


def _declared_build_lines_for_token(sites: list[dict], lines: list[str], token: str) -> set[int]:
    declared: set[int] = set()
    for site in sites:
        if not isinstance(site, dict) or site.get("command") != "build":
            continue
        site_lines = site.get("lines")
        if not isinstance(site_lines, list):
            continue
        for number in site_lines:
            if not isinstance(number, int) or not 1 <= number <= len(lines):
                continue
            source = lines[number - 1]
            if source.count(token) != 1:
                continue
            if any(
                words[index] == "-o" and words[index + 1] == token
                for words in _shell_commands(source)
                for index in range(len(words) - 1)
            ):
                declared.add(number)
    return declared




_PLATFORM_GUARD_MARKERS = (
    "uname",
    "PSEP",
    "Windows",
    "/proc",
    "/dev/shm",
)
_TOOL_GUARD_MARKERS = (
    "command -v",
    "which ",
    "type ",
    " -c ",
    "import ",
)


def _shell_function_ranges(lines: Sequence[str]) -> tuple[tuple[str, int, int], ...]:
    ranges: list[tuple[str, int, int]] = []
    active_name: str | None = None
    active_start = 0
    for number, source in enumerate(lines, 1):
        if active_name is None:
            match = re.match(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{",
                source,
            )
            if match:
                active_name = match.group(1)
                active_start = number
        elif re.match(r"^\s*}\s*$", source):
            ranges.append((active_name, active_start, number))
            active_name = None
            active_start = 0
    return tuple(ranges)


def _derived_guard_variables(lines: Sequence[str]) -> tuple[set[str], set[str]]:
    platform_variables: set[str] = set()
    tool_variables: set[str] = set()
    assignments = tuple(
        (
            number,
            match.group(1),
            "\n".join(lines[max(0, number - 3) : number]),
        )
        for number, source in enumerate(lines, 1)
        for match in re.finditer(
            r"(?:^|[;()\s])([A-Z][A-Z0-9_]*)=",
            source,
        )
    )
    changed = True
    while changed:
        changed = False
        for _number, name, context in assignments:
            references = set(
                re.findall(
                    r"\$(?:\{)?([A-Z][A-Z0-9_]*)",
                    context,
                )
            )
            if (
                any(marker in context for marker in _PLATFORM_GUARD_MARKERS)
                or bool(references.intersection(platform_variables))
            ) and name not in platform_variables:
                platform_variables.add(name)
                changed = True
            if (
                any(marker in context for marker in _TOOL_GUARD_MARKERS)
                or bool(references.intersection(tool_variables))
            ) and name not in tool_variables:
                tool_variables.add(name)
                changed = True
    return platform_variables, tool_variables


def _platform_skip_guarded(lines: Sequence[str], number: int) -> bool:
    platform_variables, tool_variables = _derived_guard_variables(lines)
    start = max(0, number - 31)
    guard_lines = [
        source
        for source in lines[start : number - 1]
        if re.match(
            r"^\s*(?:if|elif|case)\b|^\s*(?:[^#].*\))\s*$",
            source,
        )
    ]
    guard = "\n".join(guard_lines)
    references = set(
        re.findall(r"\$(?:\{)?([A-Z][A-Z0-9_]*)", guard)
    )
    has_platform = (
        any(marker in guard for marker in _PLATFORM_GUARD_MARKERS)
        or bool(references.intersection(platform_variables))
    )
    has_tool = (
        any(marker in guard for marker in _TOOL_GUARD_MARKERS)
        or bool(references.intersection(tool_variables))
    )
    return has_platform and not has_tool


def _environment_callsite_violations(lines: Sequence[str], invocation_lines: set[int], site_by_line: Mapping[int, dict]) -> tuple[Violation, ...]:
    violations: list[Violation] = []
    functions = _shell_function_ranges(lines)
    for name, first, last in functions:
        function_invocations = tuple(
            number
            for number in sorted(invocation_lines)
            if first <= number <= last
        )
        if not function_invocations:
            continue
        environment_calls: list[int] = []
        for number, source in enumerate(lines, 1):
            if first <= number <= last or source.lstrip().startswith("#"):
                continue
            commands = _shell_commands(source)
            if not any(
                command and command[0] == name
                for command in commands
            ):
                continue
            prefix = "\n".join(lines[max(0, number - 5) : number])
            if re.search(
                r"(?:export\s+)?(?:IYI_PATH|CRYSTAL_PATH)\s*=",
                prefix,
            ):
                environment_calls.append(number)
        if not environment_calls:
            continue
        for invocation_line in function_invocations:
            site = site_by_line.get(invocation_line)
            if isinstance(site, dict) and site.get("kind") == "unchanged":
                continue
            if not isinstance(site, dict) or site.get("kind") not in (
                "mixed",
                "negative",
                "positive",
            ):
                violations.append(
                    (
                        "C5.6-env-call-variant",
                        invocation_line,
                        f"function {name!r} is called with a path override "
                        f"at lines {environment_calls} but its invocation "
                        "site is not mixed, negative or positive",
                    )
                )
    return tuple(violations)


def _validate_census_schema(census: object, violations: list[Violation]) -> None:
    top_keys = {
        "census_version",
        "driver",
        "script",
        "script_sha256",
        "sites",
        "non_invocations",
        "skips",
        "not_skips",
        "pass_sentinel",
        "exec_evidence",
    }
    _closed_keys(census, top_keys, "census", violations)
    if not isinstance(census, dict):
        return

    scalar_types = {
        "census_version": int,
        "driver": str,
        "script": str,
        "script_sha256": str,
        "sites": list,
        "non_invocations": list,
        "skips": list,
        "not_skips": list,
        "pass_sentinel": dict,
        "exec_evidence": list,
    }
    for key, expected in scalar_types.items():
        if not isinstance(census.get(key), expected):
            _violation(
                violations,
                "C5.0-schema",
                0,
                f"census.{key} must be {expected.__name__}",
            )

    sites = census.get("sites")
    for index, site in enumerate(sites if isinstance(sites, list) else []):
        line = (
            site.get("lines", [0])[0]
            if isinstance(site, dict)
            and isinstance(site.get("lines"), list)
            and site["lines"]
            else 0
        )
        if not _closed_keys(
            site,
            {"lines", "command", "kind", "contains", "variants"},
            f"sites[{index}]",
            violations,
            line,
        ):
            continue
        site_valid = (
            isinstance(site["lines"], list)
            and bool(site["lines"])
            and all(isinstance(item, int) for item in site["lines"])
            and isinstance(site["command"], str)
            and site["command"] in _COMMANDS
            and isinstance(site["kind"], str)
            and site["kind"] in _SITE_KINDS
            and isinstance(site["contains"], list)
            and all(isinstance(item, str) for item in site["contains"])
            and isinstance(site["variants"], list)
        )
        if not site_valid:
            _violation(
                violations,
                "C5.0-schema",
                line,
                f"sites[{index}] has invalid field types or enum values",
            )
            continue

        for variant_index, variant in enumerate(site["variants"]):
            variant_path = f"sites[{index}].variants[{variant_index}]"
            if not _closed_keys(
                variant,
                {
                    "id",
                    "kind",
                    "first_root",
                    "vars",
                    "sources",
                    "output",
                    "darwin",
                    "requires",
                    "verdict",
                },
                variant_path,
                violations,
                line,
            ):
                continue
            variant_valid = (
                isinstance(variant["id"], str)
                and isinstance(variant["kind"], str)
                and variant["kind"] in _VARIANT_KINDS
                and isinstance(variant["first_root"], str)
                and isinstance(variant["vars"], dict)
                and isinstance(variant["sources"], list)
                and all(isinstance(item, str) for item in variant["sources"])
                and (
                    variant["output"] is None
                    or isinstance(variant["output"], str)
                )
                and isinstance(variant["darwin"], str)
                and variant["darwin"] in ("required", "platform-excluded")
                and isinstance(variant["requires"], list)
                and all(isinstance(item, str) for item in variant["requires"])
                and isinstance(variant["verdict"], dict)
            )
            if not variant_valid:
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"variant {variant.get('id', variant_index)!r} "
                    "has invalid fields",
                )
                continue

            for name, variable in variant["vars"].items():
                if not isinstance(name, str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*",
                    name,
                ):
                    _violation(
                        violations,
                        "C5.0-schema",
                        line,
                        f"variant variable name {name!r} is invalid",
                    )
                    continue
                if not isinstance(variable, dict):
                    _violation(
                        violations,
                        "C5.0-schema",
                        line,
                        f"variable {name!r} must be an object",
                    )
                    continue
                value_form = set(variable) == {"lines", "values"}
                pattern_form = set(variable) == {
                    "lines",
                    "pattern",
                    "pattern_reason_line",
                }
                if not value_form and not pattern_form:
                    _violation(
                        violations,
                        "C5.0-schema",
                        line,
                        f"variable {name!r} has invalid keys "
                        f"{sorted(variable)}",
                    )
                    continue
                variable_valid = (
                    isinstance(variable["lines"], list)
                    and bool(variable["lines"])
                    and all(
                        isinstance(item, int) for item in variable["lines"]
                    )
                )
                if value_form:
                    variable_valid = (
                        variable_valid
                        and isinstance(variable["values"], list)
                        and bool(variable["values"])
                        and all(
                            isinstance(item, str)
                            for item in variable["values"]
                        )
                    )
                else:
                    variable_valid = (
                        variable_valid
                        and isinstance(variable["pattern"], str)
                        and isinstance(
                            variable["pattern_reason_line"],
                            int,
                        )
                    )
                if not variable_valid:
                    _violation(
                        violations,
                        "C5.0-schema",
                        line,
                        f"variable {name!r} has invalid field types",
                    )

            verdict = variant["verdict"]
            if _closed_keys(
                verdict,
                {"lines", "contains"},
                f"variant {variant['id']!r}.verdict",
                violations,
                line,
            ) and (
                not isinstance(verdict["lines"], list)
                or not verdict["lines"]
                or not all(
                    isinstance(item, int) for item in verdict["lines"]
                )
                or not isinstance(verdict["contains"], list)
                or not verdict["contains"]
                or not all(
                    isinstance(item, str) for item in verdict["contains"]
                )
            ):
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"variant {variant['id']!r} verdict is invalid",
                )

    for key, required in (
        ("non_invocations", {"line", "reason"}),
        ("skips", {"line", "class", "what", "regex", "text"}),
        ("not_skips", {"line", "reason", "text"}),
    ):
        entries = census.get(key)
        for index, item in enumerate(
            entries if isinstance(entries, list) else []
        ):
            line = item.get("line", 0) if isinstance(item, dict) else 0
            if not _closed_keys(
                item,
                required,
                f"{key}[{index}]",
                violations,
                line,
            ):
                continue
            if not isinstance(item["line"], int):
                _violation(
                    violations,
                    "C5.0-schema",
                    0,
                    f"{key}[{index}].line must be an integer",
                )
            if key == "non_invocations" and not isinstance(
                item["reason"],
                str,
            ):
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"{key}[{index}].reason must be a string",
                )
            if key == "skips" and (
                not isinstance(item["class"], str)
                or item["class"] not in ("tool", "platform")
                or not all(
                    isinstance(item[field], str)
                    for field in ("what", "regex", "text")
                )
            ):
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"{key}[{index}] has invalid fields",
                )
            if key == "not_skips" and not all(
                isinstance(item[field], str) for field in ("reason", "text")
            ):
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"{key}[{index}] has invalid fields",
                )

    sentinel = census.get("pass_sentinel")
    if _closed_keys(
        sentinel,
        {"line", "regex", "text"},
        "pass_sentinel",
        violations,
    ):
        if not isinstance(sentinel, dict) or (
            not isinstance(sentinel["line"], int)
            or not isinstance(sentinel["regex"], str)
            or not isinstance(sentinel["text"], str)
        ):
            _violation(
                violations,
                "C5.0-schema",
                0,
                "pass_sentinel has invalid fields",
            )

    evidences = census.get("exec_evidence")
    evidence_keys = {
        "site_line",
        "out_template",
        "name_from_calls",
        "exec_lines",
        "exec_token",
        "verdict_lines",
        "failure_marks",
        "refs_ok",
    }
    for index, evidence in enumerate(
        evidences if isinstance(evidences, list) else []
    ):
        line = (
            evidence.get("site_line", 0)
            if isinstance(evidence, dict)
            else 0
        )
        if not _closed_keys(
            evidence,
            evidence_keys,
            f"exec_evidence[{index}]",
            violations,
            line,
        ):
            continue
        evidence_valid = (
            isinstance(evidence["site_line"], int)
            and isinstance(evidence["out_template"], str)
            and isinstance(evidence["name_from_calls"], dict)
            and all(
                isinstance(key, str)
                and key.isdigit()
                and isinstance(value, str)
                and bool(value)
                for key, value in evidence["name_from_calls"].items()
            )
            and isinstance(evidence["exec_lines"], list)
            and bool(evidence["exec_lines"])
            and all(
                isinstance(item, int) for item in evidence["exec_lines"]
            )
            and isinstance(evidence["exec_token"], str)
            and bool(evidence["exec_token"])
            and isinstance(evidence["verdict_lines"], list)
            and bool(evidence["verdict_lines"])
            and all(
                isinstance(item, int) for item in evidence["verdict_lines"]
            )
            and isinstance(evidence["failure_marks"], list)
            and bool(evidence["failure_marks"])
            and all(
                isinstance(item, str) and bool(item)
                for item in evidence["failure_marks"]
            )
            and isinstance(evidence["refs_ok"], list)
        )
        if not evidence_valid:
            _violation(
                violations,
                "C5.0-schema",
                line,
                f"exec_evidence[{index}] has invalid fields",
            )
            continue

        for ref_index, reference in enumerate(evidence["refs_ok"]):
            if not _closed_keys(
                reference,
                {"line", "kind"},
                f"exec_evidence[{index}].refs_ok[{ref_index}]",
                violations,
                line,
            ):
                continue
            if not isinstance(reference, dict) or (
                not isinstance(reference["line"], int)
                or reference["kind"] != "cleanup"
            ):
                _violation(
                    violations,
                    "C5.0-schema",
                    line,
                    f"exec_evidence[{index}].refs_ok[{ref_index}] "
                    "is invalid",
                )


def validate_census(census: object, script_bytes: bytes, script_relpath: str) -> list[Violation]:
    """Return every C5 and E1 violation for one source-grounded census."""
    violations: list[Violation] = []
    _validate_census_schema(census, violations)
    if not isinstance(census, dict):
        return violations
    if not isinstance(script_bytes, bytes):
        _violation(
            violations,
            "C5.0-schema",
            0,
            "script_bytes must be bytes",
        )
        return violations
    if not isinstance(script_relpath, str):
        _violation(
            violations,
            "C5.0-schema",
            0,
            "script_relpath must be a string",
        )
        return violations

    lines = script_bytes.decode("utf-8", errors="replace").splitlines()
    driver = census.get("driver")
    expected_script = (
        f"bench/std_{driver}_exercise.sh"
        if isinstance(driver, str)
        else ""
    )
    if (
        census.get("census_version") != 1
        or script_relpath != census.get("script")
        or census.get("script") != expected_script
    ):
        _violation(
            violations,
            "C5.0-schema",
            0,
            f"identity mismatch driver={driver!r}, "
            f"script={census.get('script')!r}, input={script_relpath!r}",
        )
    actual_sha = sha256_bytes(script_bytes)
    if census.get("script_sha256") != actual_sha:
        _violation(
            violations,
            "C5.1-sha",
            0,
            f"recorded={census.get('script_sha256')!r}, actual={actual_sha}",
        )

    sites = census.get("sites") if isinstance(census.get("sites"), list) else []
    non_invocations = (
        census.get("non_invocations")
        if isinstance(census.get("non_invocations"), list)
        else []
    )
    claims: dict[int, list[str]] = {}
    declared_site_lines: set[int] = set()
    site_owner_line: dict[int, int] = {}
    site_by_line: dict[int, dict] = {}
    for index, site in enumerate(sites):
        if not isinstance(site, dict) or not isinstance(site.get("lines"), list):
            continue
        owner_line = site["lines"][0] if site["lines"] else 0
        for number in site["lines"]:
            if isinstance(number, int):
                claims.setdefault(number, []).append(f"site[{index}]")
                declared_site_lines.add(number)
                site_owner_line[number] = owner_line
                site_by_line[number] = site
    for index, item in enumerate(non_invocations):
        if isinstance(item, dict) and isinstance(item.get("line"), int):
            claims.setdefault(item["line"], []).append(
                f"non_invocations[{index}]"
            )
    for number, owners in sorted(claims.items()):
        if len(owners) > 1:
            _violation(
                violations,
                "C5.2-duplicate-site",
                number,
                f"line claimed by {owners}",
            )
    invocation_lines = {
        number
        for number, source in enumerate(lines, 1)
        if not source.lstrip().startswith("#")
        and _INVOCATION_RE.search(source)
    }
    for number in sorted(invocation_lines):
        if number not in claims:
            _violation(
                violations,
                "C5.2-unlisted-invocation",
                number,
                "invocation is not listed in a site or non_invocations",
            )
    violations.extend(
        _environment_callsite_violations(
            lines,
            invocation_lines,
            site_by_line,
        )
    )

    variant_ids: set[str] = set()
    evidence_sites: set[int] = set()
    positive_sites: set[int] = set()
    own_sites: set[int] = set()
    for index, site in enumerate(sites):
        if not isinstance(site, dict):
            continue
        site_lines = (
            site.get("lines") if isinstance(site.get("lines"), list) else []
        )
        line = (
            site_lines[0]
            if site_lines and isinstance(site_lines[0], int)
            else 0
        )
        source = _source_text(lines, site_lines)
        contains = (
            site.get("contains")
            if isinstance(site.get("contains"), list)
            else []
        )
        for literal in contains:
            if isinstance(literal, str) and literal not in source:
                _violation(
                    violations,
                    "C5.3-contains",
                    line,
                    f"site[{index}] lacks {literal!r}",
                )
        kind = site.get("kind")
        variants = (
            site.get("variants")
            if isinstance(site.get("variants"), list)
            else []
        )
        if (kind in ("negative", "positive", "mixed")) != bool(variants):
            _violation(
                violations,
                "C5.6-kind-variants",
                line,
                f"kind={kind!r}, variants={len(variants)}",
            )
        is_mixed_own = kind == "mixed" and (
            "$EXERCISE" in source
            or f"std_{driver}_exercise.iyi" in source
        )
        if kind == "canonical-own" or is_mixed_own:
            own_sites.add(line)
        if kind == "positive":
            positive_sites.add(line)
        for variant in variants:
            if not isinstance(variant, dict):
                continue
            variant_id = variant.get("id")
            if isinstance(variant_id, str):
                if variant_id in variant_ids:
                    _violation(
                        violations,
                        "C5.0-schema",
                        line,
                        f"duplicate variant id {variant_id!r}",
                    )
                variant_ids.add(variant_id)
            if kind in ("negative", "positive") and variant.get("kind") != kind:
                _violation(
                    violations,
                    "C5.6-kind-variants",
                    line,
                    f"site kind {kind!r} disagrees with "
                    f"variant {variant.get('kind')!r}",
                )
            variables = (
                variant.get("vars")
                if isinstance(variant.get("vars"), dict)
                else {}
            )
            for name, variable in variables.items():
                if not isinstance(variable, dict):
                    continue
                cited = _source_text(lines, variable.get("lines"))
                values = (
                    variable.get("values")
                    if isinstance(variable.get("values"), list)
                    else []
                )
                for value in values:
                    if isinstance(value, str) and value not in cited:
                        _violation(
                            violations,
                            "C5.3-var-range",
                            line,
                            f"{variant_id}.{name} value {value!r} "
                            "is absent from cited lines",
                        )
                if "pattern" in variable:
                    try:
                        re.compile(variable["pattern"])
                    except (re.error, TypeError) as error:
                        _violation(
                            violations,
                            "C5.3-var-range",
                            line,
                            f"{variant_id}.{name} pattern is invalid: {error}",
                        )
                    reason_line = variable.get("pattern_reason_line")
                    reason_source = (
                        lines[reason_line - 1]
                        if isinstance(reason_line, int)
                        and 1 <= reason_line <= len(lines)
                        else ""
                    )
                    if not reason_source or not re.search(
                        r"\$|`|\(\(",
                        reason_source,
                    ):
                        _violation(
                            violations,
                            "C5.3-var-range",
                            line,
                            f"{variant_id}.{name} reason line does not "
                            "show a dynamic value",
                        )
            allowed_vars = set(variables)
            for field in ("first_root",):
                detail = _template_violation(
                    variant.get(field),
                    allowed_vars,
                    f"{variant_id}.{field}",
                )
                if detail:
                    _violation(
                        violations,
                        "C5.7-template",
                        line,
                        detail,
                    )
            sources = (
                variant.get("sources")
                if isinstance(variant.get("sources"), list)
                else []
            )
            for source_index, template in enumerate(sources):
                detail = _template_violation(
                    template,
                    allowed_vars,
                    f"{variant_id}.sources[{source_index}]",
                )
                if detail:
                    _violation(
                        violations,
                        "C5.7-template",
                        line,
                        detail,
                    )
            if variant.get("output") is not None:
                detail = _template_violation(
                    variant.get("output"),
                    allowed_vars,
                    f"{variant_id}.output",
                )
                if detail:
                    _violation(
                        violations,
                        "C5.7-template",
                        line,
                        detail,
                    )
            verdict = variant.get("verdict")
            if isinstance(verdict, dict):
                verdict_source = _source_text(lines, verdict.get("lines"))
                verdict_literals = (
                    verdict.get("contains")
                    if isinstance(verdict.get("contains"), list)
                    else []
                )
                for literal in verdict_literals:
                    if (
                        isinstance(literal, str)
                        and literal not in verdict_source
                    ):
                        _violation(
                            violations,
                            "C5.3-verdict-literal",
                            line,
                            f"{variant_id} verdict lacks {literal!r}",
                        )

    listed_skip_lines: dict[int, str] = {}
    for key in ("skips", "not_skips"):
        entries = census.get(key) if isinstance(census.get(key), list) else []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(
                entry.get("line"),
                int,
            ):
                continue
            number = entry["line"]
            if number in listed_skip_lines:
                _violation(
                    violations,
                    "C5.0-schema",
                    number,
                    f"skip line listed twice in {listed_skip_lines[number]} "
                    f"and {key}[{index}]",
                )
            listed_skip_lines[number] = f"{key}[{index}]"
            source = lines[number - 1] if 1 <= number <= len(lines) else ""
            if entry.get("text") != source:
                _violation(
                    violations,
                    "C5.0-schema",
                    number,
                    f"{key}[{index}].text is not the cited source line",
                )
            if (
                key == "skips"
                and entry.get("class") == "platform"
                and not _platform_skip_guarded(lines, number)
            ):
                _violation(
                    violations,
                    "C5.4-platform-guard",
                    number,
                    "platform skip is not guarded only by platform state",
                )
    for number, source in enumerate(lines, 1):
        print_commands = _print_commands(source)
        if print_commands is None:
            continue
        for words in print_commands:
            rendered = _render_print_words(words)
            if rendered is None:
                if _SKIP_VOCAB_RE.search(" ".join(words)):
                    _violation(
                        violations,
                        "C5.4-unrenderable",
                        number,
                        "skip-vocabulary print command cannot be rendered",
                    )
                continue
            if (
                _SKIP_VOCAB_RE.search(rendered)
                and number not in listed_skip_lines
            ):
                _violation(
                    violations,
                    "C5.4-unlisted-skip-line",
                    number,
                    f"printed text is skip vocabulary: {rendered!r}",
                )

    skip_entries = (
        census.get("skips") if isinstance(census.get("skips"), list) else []
    )
    for entry in skip_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("line"), int):
            continue
        number = entry["line"]
        source = lines[number - 1] if 1 <= number <= len(lines) else ""
        top_level = _top_level_print_commands(source)
        rendered = (
            _render_print_words(top_level[0])
            if top_level
            else None
        )
        if rendered is None:
            _violation(
                violations,
                "C5.4-unrenderable",
                number,
                "listed skip line has no renderable top-level print",
            )
            continue
        try:
            regex = re.compile(entry.get("regex", ""))
        except (re.error, TypeError) as error:
            _violation(
                violations,
                "C5.4-skip-regex",
                number,
                f"invalid regex: {error}",
            )
            continue
        if "IYIVAR" in str(entry.get("regex", "")):
            _violation(
                violations,
                "C5.4-skip-regex",
                number,
                "skip regex contains literal IYIVAR instead of a wildcard",
            )
            continue
        if not regex.search(rendered):
            _violation(
                violations,
                "C5.4-skip-regex",
                number,
                f"{entry.get('regex')!r} does not match {rendered!r}",
            )

    sentinel = census.get("pass_sentinel")
    if isinstance(sentinel, dict) and isinstance(sentinel.get("line"), int):
        number = sentinel["line"]
        source = lines[number - 1] if 1 <= number <= len(lines) else ""
        if sentinel.get("text") != source:
            _violation(
                violations,
                "C5.0-schema",
                number,
                "pass_sentinel.text is not the cited source line",
            )
        top_level = _top_level_print_commands(source)
        rendered = (
            _render_print_words(top_level[0])
            if top_level
            else None
        )
        if rendered is None:
            _violation(
                violations,
                "C5.4-unrenderable",
                number,
                "pass sentinel has no renderable top-level print",
            )
        else:
            sentinel_regex = sentinel.get("regex", "")
            if "IYIVAR" in str(sentinel_regex):
                _violation(
                    violations,
                    "C5.5-sentinel",
                    number,
                    "sentinel regex contains literal IYIVAR instead of a wildcard",
                )
            else:
                try:
                    matches = bool(re.search(sentinel_regex, rendered))
                except (re.error, TypeError):
                    matches = False
                if not matches:
                    _violation(
                        violations,
                        "C5.5-sentinel",
                        number,
                        f"{sentinel_regex!r} does not match {rendered!r}",
                    )

    evidences = (
        census.get("exec_evidence")
        if isinstance(census.get("exec_evidence"), list)
        else []
    )
    evidences_by_token: dict[str, list[dict]] = {}
    declared_build_lines_by_token: dict[str, set[int]] = {}
    for evidence in evidences:
        if not isinstance(evidence, dict):
            continue
        site_line = evidence.get("site_line")
        token = evidence.get("exec_token")
        if isinstance(token, str):
            evidences_by_token.setdefault(token, []).append(evidence)
            declared_build_lines_by_token.setdefault(
                token,
                _declared_build_lines_for_token(sites, lines, token),
            )

        detail = _template_violation(
            evidence.get("out_template"),
            {"name"},
            f"exec_evidence[{site_line}].out_template",
        )
        if detail:
            _violation(
                violations,
                "C5.7-template",
                site_line,
                detail,
            )

        declared_build_lines = (
            declared_build_lines_by_token.get(token, set())
            if isinstance(token, str)
            else set()
        )
        if not isinstance(site_line, int) or site_line not in declared_build_lines:
            _violation(
                violations,
                "E1-exec-token",
                site_line,
                f"site line is not a declared build with exact -o {token!r}",
            )
        else:
            evidence_sites.add(site_owner_line[site_line])

        exec_lines = (
            evidence.get("exec_lines")
            if isinstance(evidence.get("exec_lines"), list)
            else []
        )
        for number in exec_lines:
            source = (
                lines[number - 1]
                if isinstance(number, int) and 1 <= number <= len(lines)
                else ""
            )
            if (
                not isinstance(number, int)
                or not isinstance(site_line, int)
                or number <= site_line
                or not isinstance(token, str)
                or token not in source
            ):
                _violation(
                    violations,
                    "E1-exec-token",
                    number if isinstance(number, int) else site_line,
                    f"expected {token!r} after site line {site_line}",
                )

        name_from_calls = (
            evidence.get("name_from_calls")
            if isinstance(evidence.get("name_from_calls"), dict)
            else {}
        )
        for call_line, name in name_from_calls.items():
            if (
                not isinstance(call_line, str)
                or not call_line.isdigit()
                or not isinstance(name, str)
            ):
                continue
            number = int(call_line)
            source = lines[number - 1] if 1 <= number <= len(lines) else ""
            if name not in source:
                _violation(
                    violations,
                    "C5.3-var-range",
                    number,
                    f"call name {name!r} is absent from cited line",
                )

        failure_marks = (
            evidence.get("failure_marks")
            if isinstance(evidence.get("failure_marks"), list)
            else []
        )
        valid_marks = [mark for mark in failure_marks if isinstance(mark, str)]
        verdict_lines = (
            evidence.get("verdict_lines")
            if isinstance(evidence.get("verdict_lines"), list)
            else []
        )
        for number in verdict_lines:
            source = (
                lines[number - 1]
                if isinstance(number, int) and 1 <= number <= len(lines)
                else ""
            )
            if isinstance(number, int) and not any(
                mark in source for mark in valid_marks
            ):
                _violation(
                    violations,
                    "E1-verdict-mark",
                    number,
                    f"verdict line lacks one of {valid_marks}",
                )

    for token, token_evidences in evidences_by_token.items():
        allowed_references = set(
            declared_build_lines_by_token.get(token, set())
        )
        for evidence in token_evidences:
            exec_lines = (
                evidence.get("exec_lines")
                if isinstance(evidence.get("exec_lines"), list)
                else []
            )
            allowed_references.update(
                number for number in exec_lines if isinstance(number, int)
            )
            refs_ok = (
                evidence.get("refs_ok")
                if isinstance(evidence.get("refs_ok"), list)
                else []
            )
            allowed_references.update(
                reference["line"]
                for reference in refs_ok
                if isinstance(reference, dict)
                and reference.get("kind") == "cleanup"
                and isinstance(reference.get("line"), int)
            )
        for number, source in enumerate(lines, 1):
            if token in source and number not in allowed_references:
                _violation(
                    violations,
                    "E1-stray-reference",
                    number,
                    f"unlisted reference to exact token {token!r}",
                )

    if not own_sites.intersection(evidence_sites):
        _violation(
            violations,
            "E1-missing",
            min(own_sites) if own_sites else 0,
            "no canonical-own or mixed own-exercise site has exec evidence",
        )
    for number in sorted(positive_sites - evidence_sites):
        _violation(
            violations,
            "E1-missing",
            number,
            "positive site has no exec evidence",
        )

    last_nonblank_line, last_nonblank = next(
        (
            (number, source)
            for number, source in reversed(tuple(enumerate(lines, 1)))
            if source.strip()
        ),
        (0, ""),
    )
    if last_nonblank != "exit $status":
        _violation(
            violations,
            "E1-exit-line",
            last_nonblank_line,
            f"last non-blank line is {last_nonblank!r}",
        )
    return sorted(set(violations), key=lambda item: (item[1], item[0], item[2]))


@dataclass(frozen=True)
class LedgerVerdict:
    statuses: frozenset[str]
    reasons: tuple[str, ...]


def _ledger_add(statuses: set[str], reasons: list[str], status: str, detail: str) -> None:
    statuses.add(status)
    reason = f"{status}: {detail}"
    if reason not in reasons:
        reasons.append(reason)


def _ledger_result(statuses: set[str], reasons: list[str]) -> LedgerVerdict:
    return LedgerVerdict(frozenset(statuses), tuple(reasons))


def _ledger_variant_ids(record: dict) -> tuple[str, ...]:
    values = record.get("variant_ids")
    if not isinstance(values, list):
        return ()
    return tuple(value for value in values if isinstance(value, str))


def _ledger_census_index(census: dict) -> tuple[dict[str, tuple[dict, dict]], dict[int, dict]]:
    variants: dict[str, tuple[dict, dict]] = {}
    sites_by_line: dict[int, dict] = {}
    sites_value = census.get("sites") if isinstance(census, dict) else []
    site_values = sites_value if isinstance(sites_value, list) else ()
    sites = tuple(site for site in site_values if isinstance(site, dict))
    for site in sites:
        lines = site.get("lines")
        line_values = lines if isinstance(lines, list) else ()
        for line in (line for line in line_values if isinstance(line, int)):
            sites_by_line[line] = site
        site_variants = site.get("variants")
        variant_values = site_variants if isinstance(site_variants, list) else ()
        for variant in (
            variant
            for variant in variant_values
            if isinstance(variant, dict)
            and isinstance(variant.get("id"), str)
        ):
            variants[variant["id"]] = (variant, site)
    return variants, sites_by_line


def _ledger_successful_roundtrip(record: dict) -> bool:
    producer = record.get("producer")
    consumer = record.get("consumer")
    mods_count = producer.get("mods_count") if isinstance(producer, dict) else None
    return (
        record.get("phase") == "end"
        and record.get("mode") == "roundtrip"
        and isinstance(producer, dict)
        and producer.get("rc") == 0
        and isinstance(mods_count, int)
        and not isinstance(mods_count, bool)
        and mods_count >= 1
        and isinstance(consumer, dict)
        and consumer.get("rc") == 0
    )


def _ledger_is_own(record: dict, *, driver: str, repo: str) -> bool:
    sources = record.get("sources")
    expected = os.path.realpath(
        os.path.join(repo, "bench", f"std_{driver}_exercise.iyi")
    )
    valid_sources = isinstance(sources, list) and all(
        isinstance(source, str) for source in sources
    )
    source_values = sources if valid_sources else ()
    normalized = [os.path.realpath(source) for source in source_values]
    return (
        record.get("own") is True
        and record.get("canonical") is True
        and normalized == [expected]
    )


def _ledger_binding_values(records: list[dict], variant_id: str, variable: str) -> tuple[object, ...]:
    values: list[object] = []
    for record in records:
        bindings = record.get("bindings")
        variant_bindings = bindings.get(variant_id) if isinstance(bindings, dict) else None
        if isinstance(variant_bindings, dict) and variable in variant_bindings:
            values.append(variant_bindings[variable])
    return tuple(values)


def _ledger_out_regex(template: str, *, work_tmp: str, repo: str, name: str | None, platform_tmp: str | None) -> re.Pattern[str] | None:
    parts: list[str] = []
    cursor = 0
    for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template):
        parts.append(re.escape(template[cursor : match.start()]))
        placeholder = match.group(1)
        if placeholder == "WORK":
            roots = [os.path.realpath(work_tmp)]
            if platform_tmp is not None:
                roots.append(os.path.realpath(platform_tmp))
            root_body = "|".join(
                re.escape(root) for root in dict.fromkeys(roots)
            )
            parts.append(f"(?:{root_body}){re.escape(os.sep)}[^/]+")
        elif placeholder == "REPO":
            parts.append(re.escape(os.path.realpath(repo)))
        elif placeholder == "name" and name is not None:
            parts.append(re.escape(name))
        else:
            return None
        cursor = match.end()
    parts.append(re.escape(template[cursor:]))
    return re.compile("".join(parts))


def _ledger_run_executed(record: dict) -> bool:
    run = record.get("run")
    argv = run.get("argv") if isinstance(run, dict) else None
    return (
        isinstance(run, dict)
        and isinstance(argv, list)
        and bool(argv)
        and record.get("command") == "run"
        and argv[0] == record.get("out")
        and isinstance(run.get("rc"), int)
        and not isinstance(run.get("rc"), bool)
    )


def verify_ledger(ledger_path: str, *, census: dict, driver: str, nonce: str, attempt: int, chain_id: str, work_tmp: str, repo: str, platform_tmp: str | None, stat_fn: Callable[[str], os.stat_result] = os.stat) -> LedgerVerdict:
    """Verify one P2 ledger and return every blocking P4 status."""
    statuses: set[str] = set()
    reasons: list[str] = []

    try:
        with open(ledger_path, "r", encoding="utf-8") as ledger_file:
            raw = ledger_file.read()
    except (OSError, UnicodeError) as error:
        _ledger_add(statuses, reasons, "STALE", f"ledger unreadable: {error}")
        return _ledger_result(statuses, reasons)

    lines = raw.splitlines()
    if not lines or not lines[0].strip():
        _ledger_add(statuses, reasons, "STALE", "ledger is empty")
        return _ledger_result(statuses, reasons)

    try:
        header = json.loads(lines[0])
    except (json.JSONDecodeError, UnicodeError) as error:
        _ledger_add(statuses, reasons, "STALE", "line 1 is not a header")
        _ledger_add(statuses, reasons, "UNFAITHFUL", f"malformed line 1: {error}")
        return _ledger_result(statuses, reasons)

    if (
        not isinstance(header, dict)
        or header.get("v") != 1
        or header.get("kind") != "header"
    ):
        _ledger_add(statuses, reasons, "STALE", "line 1 is not a v1 header")
        return _ledger_result(statuses, reasons)

    expected_header = {
        "nonce": nonce,
        "driver": driver,
        "attempt": attempt,
        "chain_id": chain_id,
    }
    for field, expected in expected_header.items():
        if header.get(field) != expected:
            _ledger_add(
                statuses,
                reasons,
                "STALE",
                f"header {field} is {header.get(field)!r}, expected {expected!r}",
            )
    if "STALE" in statuses:
        return _ledger_result(statuses, reasons)

    records: list[dict] = []
    for line_number, line in enumerate(lines[1:], 2):
        if not line.strip():
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"blank JSONL line {line_number}",
            )
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeError) as error:
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"malformed line {line_number}: {error}",
            )
            continue
        if (
            not isinstance(record, dict)
            or record.get("v") != 1
            or record.get("kind") != "record"
        ):
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"line {line_number} is not a v1 record",
            )
            continue
        records.append(record)

    variant_index, sites_by_line = _ledger_census_index(census)
    pair_records: dict[str, dict[str, list[dict]]] = {}
    end_records: list[tuple[int, dict]] = []

    for record_index, record in enumerate(records):
        label = f"record {record_index + 1}"
        if (
            record.get("nonce") != header["nonce"]
            or record.get("driver") != header["driver"]
        ):
            _ledger_add(
                statuses,
                reasons,
                "STALE",
                f"{label} has a foreign nonce or driver",
            )

        phase = record.get("phase")
        if phase in ("begin", "end"):
            invocation = record.get("inv")
            if not isinstance(invocation, str) or not invocation:
                _ledger_add(
                    statuses,
                    reasons,
                    "UNFAITHFUL",
                    f"{label} has no invocation id",
                )
            else:
                paired = pair_records.setdefault(
                    invocation,
                    {"begin": [], "end": []},
                )
                paired[phase].append(record)
        if phase == "end":
            end_records.append((record_index, record))

        if record.get("interrupted") is True:
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"{label} is marked interrupted",
            )
        run = record.get("run")
        if isinstance(run, dict) and run.get("signal") is not None:
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"{label} records run signal {run.get('signal')!r}",
            )

        mode = record.get("mode")
        variant_kind = record.get("variant_kind")
        if (
            phase == "refused"
            or mode in ("refused", "unclassified")
            or variant_kind in ("unclassified", "ambiguous")
        ):
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} is refused or unclassified",
            )

        if record.get("canonical") is True and mode == "observed-negative":
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} runs a canonical call as observed-negative",
            )

        raw_variant_ids = record.get("variant_ids")
        variant_ids = _ledger_variant_ids(record)
        if raw_variant_ids is not None and (
            not isinstance(raw_variant_ids, list)
            or len(variant_ids) != len(raw_variant_ids)
        ):
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} has malformed variant ids",
            )
        if (
            record.get("canonical") is not True
            and record.get("command") in ("build", "run")
            and not variant_ids
            and mode != "unchanged"
        ):
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} is a non-canonical {record.get('command')} without variant ids",
            )

        unknown_ids = [
            variant_id
            for variant_id in variant_ids
            if variant_id not in variant_index
        ]
        if unknown_ids:
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} has unknown variant ids {unknown_ids!r}",
            )
        census_kinds = {
            variant_index[variant_id][0].get("kind")
            for variant_id in variant_ids
            if variant_id in variant_index
        }
        if census_kinds and (
            len(census_kinds) != 1 or variant_kind not in census_kinds
        ):
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} variant kind {variant_kind!r} disagrees with {sorted(str(kind) for kind in census_kinds)!r}",
            )
        if "positive" in census_kinds and mode == "observed-negative":
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} runs a positive variant as observed-negative",
            )
        if "negative" in census_kinds and mode == "roundtrip":
            _ledger_add(
                statuses,
                reasons,
                "MISCLASSIFIED",
                f"{label} runs a negative variant as roundtrip",
            )

        if phase == "end":
            producer = record.get("producer")
            consumer = record.get("consumer")
            producer_rc = producer.get("rc") if isinstance(producer, dict) else None
            consumer_rc = consumer.get("rc") if isinstance(consumer, dict) else None
            if producer_rc == 0 and consumer_rc != 0:
                _ledger_add(
                    statuses,
                    reasons,
                    "DIVERGENCE",
                    f"{label} producer succeeded and consumer did not",
                )
            if (
                isinstance(consumer, dict)
                and consumer_rc == 0
                and consumer.get("out_written") is not True
            ):
                _ledger_add(
                    statuses,
                    reasons,
                    "DIVERGENCE",
                    f"{label} consumer succeeded without writing OUT",
                )

    for invocation, paired in pair_records.items():
        begins = paired["begin"]
        ends = paired["end"]
        if len(begins) != 1 or len(ends) != 1:
            _ledger_add(
                statuses,
                reasons,
                "UNFAITHFUL",
                f"invocation {invocation!r} has {len(begins)} begin and {len(ends)} end records",
            )
            continue
        begin = begins[0]
        end = ends[0]
        for field, value in begin.items():
            if field not in ("phase", "t_ns") and (
                field not in end or end[field] != value
            ):
                _ledger_add(
                    statuses,
                    reasons,
                    "UNFAITHFUL",
                    f"invocation {invocation!r} changes begin field {field!r}",
                )
                break

    own_roundtrip = any(
        _ledger_is_own(record, driver=driver, repo=repo)
        and _ledger_successful_roundtrip(record)
        and bool(record["consumer"].get("out_sha256"))
        for _, record in end_records
    )
    if not own_roundtrip:
        _ledger_add(
            statuses,
            reasons,
            "NOT-ROUNDTRIPPED",
            f"no successful own roundtrip for std_{driver}_exercise.iyi",
        )

    for variant_id, (variant, _) in variant_index.items():
        if variant.get("darwin") != "required":
            continue
        if not any(
            variant_id in _ledger_variant_ids(record)
            for record in records
        ):
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXERCISED",
                f"required variant {variant_id} has no record",
            )
        variables = variant.get("vars")
        variable_items = variables.items() if isinstance(variables, dict) else ()
        specifications = tuple(
            (variable, specification)
            for variable, specification in variable_items
            if isinstance(specification, dict)
        )
        for variable, specification in specifications:
            observed = _ledger_binding_values(records, variant_id, variable)
            values = specification.get("values")
            if isinstance(values, list):
                for value in values:
                    if value not in observed:
                        _ledger_add(
                            statuses,
                            reasons,
                            "NOT-EXERCISED",
                            f"{variant_id} never binds {variable}={value!r}",
                        )
            elif "pattern" in specification and not observed:
                _ledger_add(
                    statuses,
                    reasons,
                    "NOT-EXERCISED",
                    f"{variant_id} pattern variable {variable} has no record",
                )

        if variant.get("kind") == "positive" and not any(
            variant_id in _ledger_variant_ids(record)
            and _ledger_successful_roundtrip(record)
            for _, record in end_records
        ):
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXERCISED",
                f"positive variant {variant_id} has no successful roundtrip",
            )

    end_by_index = dict(end_records)
    own_indices = {
        index
        for index, record in end_records
        if record.get("own") is True
    }
    positive_indices = {
        index
        for index, record in end_records
        if any(
            variant_id in variant_index
            and variant_index[variant_id][0].get("kind") == "positive"
            for variant_id in _ledger_variant_ids(record)
        )
    }
    scoped_indices = own_indices | positive_indices
    run_executed_indices = {
        index
        for index in scoped_indices
        if _ledger_run_executed(end_by_index[index])
    }
    matched_indices: set[int] = set(run_executed_indices)
    evidences_value = census.get("exec_evidence") if isinstance(census, dict) else []
    evidence_values = evidences_value if isinstance(evidences_value, list) else ()
    evidence_rows = (
        (
            evidence_index,
            evidence,
            sites_by_line.get(evidence.get("site_line")),
        )
        for evidence_index, evidence in enumerate(evidence_values)
        if isinstance(evidence, dict)
        and isinstance(evidence.get("out_template"), str)
        and isinstance(sites_by_line.get(evidence.get("site_line")), dict)
    )
    if not scoped_indices:
        evidence_rows = ()


    for evidence_index, evidence, site in evidence_rows:
        site_kind = site.get("kind")
        site_variants = site.get("variants")
        site_variant_values = site_variants if isinstance(site_variants, list) else ()
        site_variant_ids = {
            variant.get("id")
            for variant in site_variant_values
            if isinstance(variant, dict) and variant.get("kind") == "positive"
        }
        candidate_indices = {
            index
            for index in scoped_indices
            if (
                site_kind in ("canonical-own", "mixed")
                and index in own_indices
            )
            or bool(
                site_variant_ids.intersection(
                    _ledger_variant_ids(end_by_index[index])
                )
            )
        }
        template = evidence["out_template"]
        names = evidence.get("name_from_calls")
        name_values = names.values() if isinstance(names, dict) else ()
        expected_names = tuple(
            name for name in name_values if isinstance(name, str)
        )
        labels: tuple[str | None, ...] = (
            expected_names
            if "{name}" in template
            else (None,)
        )
        evidence_matches: set[int] = set()
        for name in labels:
            pattern = _ledger_out_regex(
                template,
                work_tmp=work_tmp,
                repo=repo,
                name=name,
                platform_tmp=platform_tmp,
            )
            matches = {
                index
                for index in candidate_indices
                if pattern is not None
                and isinstance(end_by_index[index].get("out"), str)
                and pattern.fullmatch(
                    os.path.realpath(end_by_index[index]["out"])
                )
            }
            evidence_matches.update(matches)
            if len(matches) != 1:
                _ledger_add(
                    statuses,
                    reasons,
                    "NOT-EXECUTED",
                    f"evidence {evidence_index} name {name!r} occurs {len(matches)} times",
                )
        if len(evidence_matches) != len(labels):
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXECUTED",
                f"evidence {evidence_index} has {len(evidence_matches)} records, expected {len(labels)}",
            )
        for index in evidence_matches:
            consumer = end_by_index[index].get("consumer")
            if (
                not isinstance(consumer, dict)
                or consumer.get("rc") != 0
                or not consumer.get("out_sha256")
            ):
                _ledger_add(
                    statuses,
                    reasons,
                    "NOT-EXECUTED",
                    f"evidence {evidence_index} record {index + 1} lacks a successful hashed consumer",
                )
        matched_indices.update(evidence_matches)

    for index in sorted(scoped_indices - matched_indices):
        _ledger_add(
            statuses,
            reasons,
            "NOT-EXECUTED",
            f"own or positive record {index + 1} matches no execution evidence",
        )

    stat_targets: list[tuple[int, dict, str]] = []
    for index in sorted(scoped_indices):
        record = end_by_index[index]
        consumer = record.get("consumer")
        if (
            not isinstance(consumer, dict)
            or consumer.get("rc") != 0
            or not consumer.get("out_sha256")
            or _ledger_run_executed(record)
        ):
            continue
        out_ref = record.get("out_ref")
        if not isinstance(out_ref, str) or not out_ref:
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXECUTED",
                f"record {index + 1} has no out_ref",
            )
            continue
        stat_targets.append((index, record, out_ref))

    stat_results: list[tuple[int, dict, str, os.stat_result | None]] = []
    for index, record, out_ref in stat_targets:
        try:
            stat_result = stat_fn(out_ref)
        except Exception as error:
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXECUTED",
                f"record {index + 1} out_ref stat failed: {error}",
            )
            stat_result = None
        stat_results.append((index, record, out_ref, stat_result))

    for index, record, out_ref, stat_result in stat_results:
        if stat_result is None:
            continue
        if getattr(stat_result, "st_ino", None) != record.get("out_ino"):
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXECUTED",
                f"record {index + 1} out_ref inode changed",
            )
        observed_atime = getattr(stat_result, "st_atime_ns", None)
        recorded_mtime = record.get("out_mtime_ns")
        if (
            not isinstance(observed_atime, int)
            or not isinstance(recorded_mtime, int)
            or observed_atime <= recorded_mtime
        ):
            _ledger_add(
                statuses,
                reasons,
                "NOT-EXECUTED",
                f"record {index + 1} out_ref atime did not advance",
            )

    for index, record, out_ref, stat_result in stat_results:
        if stat_result is None:
            continue
        consumer = record.get("consumer")
        expected_sha = consumer.get("out_sha256") if isinstance(consumer, dict) else None
        try:
            observed_sha = sha256_file(out_ref)
        except Exception as error:
            _ledger_add(
                statuses,
                reasons,
                "OUT-MODIFIED",
                f"record {index + 1} out_ref read failed: {error}",
            )
            continue
        if observed_sha != expected_sha:
            _ledger_add(
                statuses,
                reasons,
                "OUT-MODIFIED",
                f"record {index + 1} out_ref sha256 changed",
            )

    return _ledger_result(statuses, reasons)
