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
import select
import shutil
import signal
import subprocess
import sys
import time


class IdentityError(RuntimeError):
    pass


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


def compute_canonical_roots(w_path: str, p_path: str, compiler_path: str) -> list[str]:
    c_list: list[str] = []
    for base in [w_path, p_path]:
        src = os.path.join(base, "src")
        samples = os.path.join(base, "samples/iyi")
        if os.path.isdir(src):
            c_list.append(os.path.realpath(src))
        if os.path.isdir(samples):
            c_list.append(os.path.realpath(samples))

    clean_e = base_env(None)
    proc = subprocess.run(
        [compiler_path, "env", "IYI_PATH"],
        cwd=w_path,
        env=clean_e,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        for entry in proc.stdout.strip().split(os.pathsep):
            if entry:
                resolved = os.path.abspath(os.path.join(w_path, entry))
                if os.path.isdir(resolved):
                    c_list.append(os.path.realpath(resolved))

    seen = set()
    result = []
    for path in c_list:
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def probe_atime_observable(dir_path: str) -> None:
    """
    Contract C3 Amendment B Precondition: Verify filesystem updates atime on execution.
    1. Write tiny executable, hash it, link it, set atime 1s before mtime.
    2. stat leaves atime unchanged.
    3. Executing file moves atime past mtime.
    """
    test_exe = os.path.join(dir_path, f"probe_atime_{time.time_ns()}")
    with open(test_exe, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(test_exe, 0o755)
    try:
        st = os.stat(test_exe)
        mtime_ns = st.st_mtime_ns
        atime_ns = mtime_ns - 1_000_000_000
        os.utime(test_exe, ns=(atime_ns, mtime_ns))

        # Check 2: stat leaves atime unchanged
        st_after_stat = os.stat(test_exe)
        if st_after_stat.st_atime_ns >= mtime_ns:
            raise IdentityError("EXEC-UNOBSERVABLE: stat altered atime")

        # Check 3: execution moves atime past mtime
        subprocess.run([test_exe], check=True, capture_output=True)
        st_after_exec = os.stat(test_exe)
        if st_after_exec.st_atime_ns <= mtime_ns:
            raise IdentityError("EXEC-UNOBSERVABLE: execution did not advance atime past mtime")
    finally:
        if os.path.exists(test_exe):
            os.remove(test_exe)


def write_pin(
    report_dir: str,
    p_path: str,
    w_path: str,
    compiler_path: str,
    chain_id: str | None = None,
) -> dict:
    """
    Contract C3 + Amendments A & B: Write R/pin.json.
    """
    p_real = os.path.realpath(p_path)
    w_real = os.path.realpath(w_path)
    c_real = os.path.realpath(compiler_path)
    r_real = os.path.realpath(report_dir)

    if os.path.exists(r_real):
        entries = os.listdir(r_real)
        if entries:
            raise IdentityError(f"Report directory R is not empty: {r_real} holds {entries}")
    else:
        os.makedirs(r_real, exist_ok=True)

    # Precondition: atime observable on report volume
    probe_atime_observable(r_real)

    if not git_clean(p_real):
        raise IdentityError(f"P worktree is dirty: {p_real}")
    if not git_clean(w_real):
        raise IdentityError(f"W worktree is dirty: {w_real}")

    p_sha = git_rev_parse("HEAD", p_real)
    p_time = git_commit_time("HEAD", p_real)
    w_head = git_rev_parse("HEAD", w_real)

    if not git_merge_base_is_ancestor(p_sha, w_head, w_real):
        raise IdentityError(f"W HEAD {w_head} does not descend from P {p_sha}")

    diff_files = git_diff_name_only(p_sha, w_head, w_real)
    for df in diff_files:
        if not df.startswith("proof/"):
            raise IdentityError(f"Non-proof file differs between P and W: {df}")

    if not git_diff_quiet(p_sha, w_head, w_real, [".", ":(exclude)proof"]):
        raise IdentityError("Product diff between P and W is non-empty")

    if not os.path.isfile(c_real) or not os.access(c_real, os.X_OK):
        raise IdentityError(f"Compiler binary is not executable file: {c_real}")

    c_stat = os.stat(c_real)
    c_sha256 = sha256_file(c_real)
    c_mtime_ns = c_stat.st_mtime_ns
    c_mtime_sec = c_stat.st_mtime

    if c_mtime_sec <= p_time:
        raise IdentityError(
            f"Compiler mtime ({c_mtime_sec}) is not later than P commit time ({p_time})"
        )

    proc_v = subprocess.run([c_real, "--version"], capture_output=True, text=True, check=False)
    if proc_v.returncode != 0:
        raise IdentityError(f"Compiler --version failed: {proc_v.stderr}")

    version_line = proc_v.stdout.strip().splitlines()[0]
    stamp = extract_version_stamp(version_line)
    if not p_sha.startswith(stamp):
        raise IdentityError(f"Compiler stamp [{stamp}] is not prefix of P SHA {p_sha}")

    canonical_roots = compute_canonical_roots(w_real, p_real, c_real)

    census_dir = os.path.join(w_real, "proof/census")
    census_shas: dict[str, str] = {}
    if os.path.isdir(census_dir):
        for fname in sorted(os.listdir(census_dir)):
            if fname.endswith(".json"):
                drv_name = fname[:-5]
                fpath = os.path.join(census_dir, fname)
                census_shas[drv_name] = sha256_file(fpath)

    nm_path = shutil.which("nm")
    if not nm_path:
        raise IdentityError("nm binary not found in PATH")
    nm_real = os.path.realpath(nm_path)
    proc_nm = subprocess.run([nm_real, "--version"], capture_output=True, text=True, check=False)
    nm_version = proc_nm.stdout.strip().splitlines()[0] if proc_nm.stdout.strip() else "unknown"

    if not chain_id:
        chain_id = hashlib.sha256(f"{p_sha}:{w_head}:{time.time_ns()}".encode()).hexdigest()[:8]

    pin_data = {
        "p_path": p_real,
        "p_source_sha": p_sha,
        "p_commit_time": p_time,
        "w_path": w_real,
        "w_head": w_head,
        "compiler_path": c_real,
        "compiler_sha256": c_sha256,
        "compiler_size": c_stat.st_size,
        "compiler_mtime_ns": c_mtime_ns,
        "compiler_inode": c_stat.st_ino,
        "compiler_version_line": version_line,
        "compiler_stamp": stamp,
        "canonical_roots": canonical_roots,
        "env_path": os.environ.get("PATH", ""),
        "env_home": os.environ.get("HOME", ""),
        "python_path": os.path.realpath(sys.executable),
        "python_version": sys.version.splitlines()[0],
        "nm_path": nm_real,
        "nm_version": nm_version,
        "census_sha256": census_shas,
        "chain_id": chain_id,
    }

    pin_file = os.path.join(r_real, "pin.json")
    with open(pin_file, "w", encoding="utf-8") as f:
        json.dump(pin_data, f, indent=2)

    return pin_data


def load_pin(report_dir: str) -> dict:
    pin_file = os.path.join(report_dir, "pin.json")
    if not os.path.isfile(pin_file):
        raise IdentityError(f"Pin file not found: {pin_file}")
    with open(pin_file, "r", encoding="utf-8") as f:
        return json.load(f)


def check_identity(pin: dict) -> None:
    p_path = pin["p_path"]
    w_path = pin["w_path"]
    c_path = pin["compiler_path"]

    curr_p_sha = git_rev_parse("HEAD", p_path)
    if curr_p_sha != pin["p_source_sha"]:
        raise IdentityError(f"P HEAD mutated: expected {pin['p_source_sha']}, got {curr_p_sha}")
    if not git_clean(p_path):
        raise IdentityError(f"P worktree is dirty: {p_path}")

    curr_w_head = git_rev_parse("HEAD", w_path)
    if curr_w_head != pin["w_head"]:
        raise IdentityError(f"W HEAD mutated: expected {pin['w_head']}, got {curr_w_head}")
    if not git_clean(w_path):
        raise IdentityError(f"W worktree is dirty: {w_path}")

    if not git_merge_base_is_ancestor(pin["p_source_sha"], curr_w_head, w_path):
        raise IdentityError(f"W HEAD does not descend from P {pin['p_source_sha']}")

    diff_files = git_diff_name_only(pin["p_source_sha"], curr_w_head, w_path)
    for df in diff_files:
        if not df.startswith("proof/"):
            raise IdentityError(f"Non-proof file modified in W: {df}")

    if not git_diff_quiet(pin["p_source_sha"], curr_w_head, w_path, [".", ":(exclude)proof"]):
        raise IdentityError("Product files in W differ from pinned P")

    curr_c_sha = sha256_file(c_path)
    if curr_c_sha != pin["compiler_sha256"]:
        raise IdentityError(f"Compiler sha256 mutated: expected {pin['compiler_sha256']}, got {curr_c_sha}")

    c_stat = os.stat(c_path)
    if c_stat.st_size != pin["compiler_size"]:
        raise IdentityError(f"Compiler size mutated: expected {pin['compiler_size']}, got {c_stat.st_size}")
    if c_stat.st_mtime_ns != pin["compiler_mtime_ns"]:
        raise IdentityError(f"Compiler mtime_ns mutated: expected {pin['compiler_mtime_ns']}, got {c_stat.st_mtime_ns}")
    if c_stat.st_ino != pin["compiler_inode"]:
        raise IdentityError(f"Compiler inode mutated: expected {pin['compiler_inode']}, got {c_stat.st_ino}")

    proc_v = subprocess.run([c_path, "--version"], capture_output=True, text=True, check=False)
    if proc_v.returncode != 0:
        raise IdentityError(f"Compiler --version failed during identity check: {proc_v.stderr}")
    stamp = extract_version_stamp(proc_v.stdout.strip().splitlines()[0])
    if stamp != pin["compiler_stamp"]:
        raise IdentityError(f"Compiler stamp mutated: expected {pin['compiler_stamp']}, got {stamp}")

    curr_path = os.environ.get("PATH", "")
    if curr_path != pin["env_path"]:
        raise IdentityError(f"PATH environment mutated: expected {pin['env_path']}, got {curr_path}")


def sweep_process_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


def run_bounded(
    cmd: list[str],
    cwd: str,
    env: dict[str, str],
    stdin_data: bytes | None = None,
    timeout_sec: float = 2100.0,
    grace_sec: float = 30.0,
    log_path: str | None = None,
    times_path: str | None = None,
) -> tuple[int, bytes, bytes, bool]:
    times_file = open(times_path, "w", encoding="utf-8") if times_path else None
    log_file = open(log_path, "wb") if log_path else None

    stdin_r = None
    if stdin_data is not None:
        stdin_r, stdin_w = os.pipe()
        os.write(stdin_w, stdin_data)
        os.close(stdin_w)
    else:
        stdin_r = os.open(os.devnull, os.O_RDONLY)

    stdout_r, stdout_w = os.pipe()
    stderr_r, stderr_w = os.pipe()

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdin=stdin_r,
        stdout=stdout_w,
        stderr=stderr_w,
        start_new_session=True,
    )
    os.close(stdin_r)
    os.close(stdout_w)
    os.close(stderr_w)

    pgid = proc.pid
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    bytes_written = 0
    timed_out = False

    start_time = time.monotonic()
    deadline = start_time + timeout_sec

    read_set = [stdout_r, stderr_r]

    while read_set:
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            timed_out = True
            break

        r, _, _ = select.select(read_set, [], [], min(remaining, 1.0))
        for fd in r:
            chunk = os.read(fd, 65536)
            t_ns = time.monotonic_ns()
            if not chunk:
                read_set.remove(fd)
                os.close(fd)
            else:
                if fd == stdout_r:
                    stdout_chunks.append(chunk)
                else:
                    stderr_chunks.append(chunk)

                if log_file:
                    log_file.write(chunk)
                    log_file.flush()
                    bytes_written += len(chunk)
                    if times_file:
                        times_file.write(f"{t_ns} {bytes_written}\n")
                        times_file.flush()

    if timed_out:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        grace_deadline = time.monotonic() + grace_sec
        while time.monotonic() < grace_deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        if proc.poll() is None:
            sweep_process_group(pgid)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass

        for fd in list(read_set):
            try:
                os.close(fd)
            except OSError:
                pass

    else:
        proc.wait()

    if times_file:
        times_file.close()
    if log_file:
        log_file.close()

    sweep_process_group(pgid)

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, b"".join(stdout_chunks), b"".join(stderr_chunks), timed_out


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
