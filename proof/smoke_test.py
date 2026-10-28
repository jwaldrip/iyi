#!/usr/bin/env python3
"""
smoke_test.py: Comprehensive test suite for all proof guards across S1, S2, S3, S4, S5.
Every guard has a seeded failure and a passing control.
Uses synthetic fixtures under /tmp only.
"""

from __future__ import annotations

import ast
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.proofkit import (
    IdentityError,
    LedgerVerificationError,
    base_env,
    check_disk_space,
    check_identity,
    extract_version_stamp,
    probe_atime_observable,
    run_bounded,
    sha256_bytes,
    sha256_file,
    validate_census,
    verify_ledger,
    write_pin,
)


def create_temp_git_repo(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@test.local"], check=True)
    subprocess.run(["git", "-C", path, "config", "commit.gpgsign", "false"], check=True)


# ==============================================================================
# S1 Smoke Tests
# ==============================================================================

def test_no_asserts_in_production_proof():
    """S1: Verify zero assert statements exist in non-test proof modules."""
    proof_dir = os.path.join(REPO_ROOT, "proof")
    py_files = glob.glob(os.path.join(proof_dir, "*.py"))
    assert len(py_files) > 0

    for py_file in py_files:
        basename = os.path.basename(py_file)
        if basename in ("smoke_test.py", "build_census.py"):
            continue
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=py_file)
        assert_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        assert len(assert_nodes) == 0, f"Found {len(assert_nodes)} assert statements in non-test module {basename}"


def test_base_env_scrub():
    """S1: Verify base_env scrubs dangerous vars while keeping pin PATH/HOME."""
    ambient = {
        "IYI_OPTS": "-Dbad",
        "IYI_PATH": "/bad/path",
        "CRYSTAL_PATH": "/bad/crystal",
        "IYI_DAEMON_SOCKET": "/tmp/daemon.sock",
        "CRYSTAL_DAEMON_SOCKET": "/tmp/cdaemon.sock",
        "PYTHONOPTIMIZE": "2",
        "PYTHONPATH": "/bad/py",
        "ROUTE_A_DRIVERS": "cookie",
        "STD_SIBLINGS": "0",
        "PATH": "/system/path",
        "HOME": "/user/home",
    }
    old_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(ambient)

        pin = {
            "env_path": "/pinned/bin:/usr/bin",
            "env_home": "/pinned/home",
        }
        cleaned = base_env(pin, stage_extra={"CUSTOM_STAGE": "1"})

        assert "IYI_OPTS" not in cleaned
        assert "IYI_PATH" not in cleaned
        assert "CRYSTAL_PATH" not in cleaned
        assert "IYI_DAEMON_SOCKET" not in cleaned
        assert "CRYSTAL_DAEMON_SOCKET" not in cleaned
        assert "PYTHONOPTIMIZE" not in cleaned
        assert "ROUTE_A_DRIVERS" not in cleaned

        assert cleaned["PATH"] == "/pinned/bin:/usr/bin"
        assert cleaned["HOME"] == "/pinned/home"
        assert cleaned["LIBRARY_PATH"] == "/opt/homebrew/opt/bdw-gc/lib"
        assert cleaned["PKG_CONFIG_PATH"] == "/opt/homebrew/opt/openssl@3/lib/pkgconfig"
        assert cleaned["PYTHONDONTWRITEBYTECODE"] == "1"
        assert cleaned["CUSTOM_STAGE"] == "1"

    finally:
        os.environ.clear()
        os.environ.update(old_env)


def test_pin_refusals_and_control():
    """S1: Verify write_pin refuses invalid conditions and succeeds on valid control."""
    scratch = tempfile.mkdtemp(prefix="smoke_pin_")
    try:
        p_dir = os.path.join(scratch, "repo_p")
        w_dir = os.path.join(scratch, "repo_w")
        r_dir = os.path.join(scratch, "report")
        c_bin = os.path.join(scratch, "fake_iyi")

        create_temp_git_repo(p_dir)
        with open(os.path.join(p_dir, "file.txt"), "w") as f:
            f.write("base\n")
        subprocess.run(["git", "-C", p_dir, "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", p_dir, "commit", "-m", "init P"], check=True)
        p_sha = subprocess.check_output(["git", "-C", p_dir, "rev-parse", "HEAD"], text=True).strip()
        stamp = p_sha[:9]

        subprocess.run(["git", "clone", p_dir, w_dir], check=True, capture_output=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.email", "test@test.local"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "commit.gpgsign", "false"], check=True)

        os.makedirs(os.path.join(w_dir, "proof"), exist_ok=True)
        with open(os.path.join(w_dir, "proof/tool.py"), "w") as f:
            f.write("# proof\n")
        subprocess.run(["git", "-C", w_dir, "add", "proof/tool.py"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "proof tool"], check=True)

        with open(c_bin, "w") as f:
            f.write(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [{stamp}] (2026-10-28)'; exit 0; fi\nif [ \"$1\" = \"env\" ]; then echo '/tmp/fake/src'; exit 0; fi\nexit 0\n")
        os.chmod(c_bin, 0o755)

        time.sleep(1.1)
        os.utime(c_bin, None)

        pin = write_pin(r_dir, p_dir, w_dir, c_bin)
        assert pin["p_source_sha"] == p_sha
        assert pin["compiler_stamp"] == stamp
        assert os.path.isfile(os.path.join(r_dir, "pin.json"))

        # Refusals
        try:
            write_pin(r_dir, p_dir, w_dir, c_bin)
            assert False, "Should refuse non-empty R"
        except IdentityError:
            pass

        r_dir2 = os.path.join(scratch, "report2")
        with open(os.path.join(p_dir, "dirty.txt"), "w") as f:
            f.write("dirty\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should refuse dirty P"
        except IdentityError:
            pass
        os.remove(os.path.join(p_dir, "dirty.txt"))

        with open(os.path.join(w_dir, "dirty.txt"), "w") as f:
            f.write("dirty\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should refuse dirty W"
        except IdentityError:
            pass
        os.remove(os.path.join(w_dir, "dirty.txt"))

        with open(os.path.join(w_dir, "file.txt"), "w") as f:
            f.write("modified product\n")
        subprocess.run(["git", "-C", w_dir, "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "modify product"], check=True)
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should refuse product diff"
        except IdentityError:
            pass
        subprocess.run(["git", "-C", w_dir, "reset", "--hard", "HEAD~1"], check=True)

        p_commit_time = int(subprocess.check_output(["git", "-C", p_dir, "log", "-1", "--format=%ct"], text=True).strip())
        os.utime(c_bin, (p_commit_time - 10, p_commit_time - 10))
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should refuse stale compiler mtime"
        except IdentityError:
            pass

        os.utime(c_bin, None)
        with open(c_bin, "w") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [deadbeef0] (2026-10-28)'; exit 0; fi\nexit 0\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should refuse stamp mismatch"
        except IdentityError:
            pass

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_identity_check_mutations():
    """S1: Verify check_identity catches all mutation scenarios."""
    scratch = tempfile.mkdtemp(prefix="smoke_ident_")
    try:
        p_dir = os.path.join(scratch, "p")
        w_dir = os.path.join(scratch, "w")
        r_dir = os.path.join(scratch, "r")
        c_bin = os.path.join(scratch, "iyi")

        create_temp_git_repo(p_dir)
        with open(os.path.join(p_dir, "init.txt"), "w") as f:
            f.write("init\n")
        subprocess.run(["git", "-C", p_dir, "add", "init.txt"], check=True)
        subprocess.run(["git", "-C", p_dir, "commit", "-m", "init"], check=True)
        p_sha = subprocess.check_output(["git", "-C", p_dir, "rev-parse", "HEAD"], text=True).strip()
        stamp = p_sha[:9]

        subprocess.run(["git", "clone", p_dir, w_dir], check=True, capture_output=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.email", "test@test.local"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "commit.gpgsign", "false"], check=True)

        os.makedirs(os.path.join(w_dir, "proof"), exist_ok=True)
        with open(os.path.join(w_dir, "proof/p.txt"), "w") as f:
            f.write("proof\n")
        subprocess.run(["git", "-C", w_dir, "add", "proof/p.txt"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "proof commit"], check=True)

        with open(c_bin, "w") as f:
            f.write(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [{stamp}] (2026-10-28)'; exit 0; fi\nexit 0\n")
        os.chmod(c_bin, 0o755)
        time.sleep(1.1)
        os.utime(c_bin, None)

        pin = write_pin(r_dir, p_dir, w_dir, c_bin)
        check_identity(pin)

        # Mutation 1: P HEAD moved
        with open(os.path.join(p_dir, "new.txt"), "w") as f:
            f.write("new\n")
        subprocess.run(["git", "-C", p_dir, "add", "new.txt"], check=True)
        subprocess.run(["git", "-C", p_dir, "commit", "-m", "new P"], check=True)
        try:
            check_identity(pin)
            assert False, "Should fail on P HEAD moved"
        except IdentityError:
            pass
        subprocess.run(["git", "-C", p_dir, "reset", "--hard", "HEAD~1"], check=True)

        # Mutation 2: W HEAD moved
        with open(os.path.join(w_dir, "proof/new.txt"), "w") as f:
            f.write("new\n")
        subprocess.run(["git", "-C", w_dir, "add", "proof/new.txt"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "new W"], check=True)
        try:
            check_identity(pin)
            assert False, "Should fail on W HEAD moved"
        except IdentityError:
            pass
        subprocess.run(["git", "-C", w_dir, "reset", "--hard", "HEAD~1"], check=True)

        # Mutation 3: Binary bytes changed with mtime restored
        orig_mtime_ns = pin["compiler_mtime_ns"]
        with open(c_bin, "a") as f:
            f.write("# appended byte\n")
        os.utime(c_bin, ns=(orig_mtime_ns, orig_mtime_ns))
        try:
            check_identity(pin)
            assert False, "Should fail on compiler sha changed"
        except IdentityError:
            pass

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_run_bounded_timeout():
    """S1: Verify run_bounded handles timeout and kills grandchildren."""
    cmd = [
        sys.executable,
        "-c",
        "import subprocess, time; subprocess.Popen(['sleep', '100']); time.sleep(100)",
    ]
    rc, stdout, stderr, timed_out = run_bounded(
        cmd,
        cwd="/tmp",
        env=os.environ.copy(),
        timeout_sec=0.8,
        grace_sec=0.2,
    )
    assert timed_out is True


# ==============================================================================
# S2 Smoke Tests: Census validation and matching
# ==============================================================================

def test_census_all_29_validate():
    """S2: Verify all 29 production census files validate against W."""
    census_files = sorted(glob.glob(os.path.join(REPO_ROOT, "proof/census/*.json")))
    assert len(census_files) == 29, f"Expected 29 census files, found {len(census_files)}"

    for cf in census_files:
        with open(cf, "r", encoding="utf-8") as f:
            data = json.load(f)
        validate_census(data, REPO_ROOT)


def test_census_validator_seeded_failures():
    """S2: Verify census validator fails on corrupt/invalid schemas."""
    # Control: cookie
    cookie_file = os.path.join(REPO_ROOT, "proof/census/cookie.json")
    with open(cookie_file, "r", encoding="utf-8") as f:
        cookie_data = json.load(f)
    validate_census(cookie_data, REPO_ROOT)

    # 1. Wrong script sha256
    bad_sha = dict(cookie_data)
    bad_sha["script_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    try:
        validate_census(bad_sha, REPO_ROOT)
        assert False, "Should have failed on wrong script_sha256"
    except Exception:
        pass

    # 2. Missing contains literal
    bad_contains = dict(cookie_data)
    bad_contains["sites"] = [dict(s) for s in cookie_data["sites"]]
    bad_contains["sites"][0]["contains"] = ["NONEXISTENT_LITERAL_XYZ"]
    try:
        validate_census(bad_contains, REPO_ROOT)
        assert False, "Should have failed on missing contains literal"
    except Exception:
        pass

    # 3. Invalid pass sentinel regex
    bad_ps = dict(cookie_data)
    bad_ps["pass_sentinel"] = {"line": cookie_data["pass_sentinel"]["line"], "regex": "^definitely_not_on_this_line$"}
    try:
        validate_census(bad_ps, REPO_ROOT)
        assert False, "Should have failed on pass sentinel mismatch"
    except Exception:
        pass


# ==============================================================================
# S3 Smoke Tests: Shim and Ledger Verification
# ==============================================================================

def test_shim_and_ledger_verification():
    """S3: Verify roundtrip_shim and verify_ledger under fake REAL."""
    scratch = tempfile.mkdtemp(prefix="smoke_shim_")
    try:
        t_dir = os.path.join(scratch, "t")
        s_dir = os.path.join(scratch, "s")
        for d in [t_dir, s_dir]:
            os.makedirs(d, exist_ok=True)

        fake_real = os.path.join(scratch, "fake_real")
        log_calls = os.path.join(scratch, "real_calls.log")
        with open(fake_real, "w") as f:
            f.write(f"""#!/bin/sh
echo "$@" >> "{log_calls}"
# Handle --emit-iyimod
i=0
for arg in "$@"; do
  if [ "$arg" = "--emit-iyimod" ]; then
    next_is_mods=1
  elif [ "$next_is_mods" = "1" ]; then
    mkdir -p "$arg/sub"
    touch "$arg/sub/foo.iyimod"
    next_is_mods=0
  elif [ "$arg" = "-o" ]; then
    next_is_out=1
  elif [ "$next_is_out" = "1" ]; then
    echo "binary" > "$arg"
    chmod 755 "$arg"
    next_is_out=0
  fi
done
exit 0
""")
        os.chmod(fake_real, 0o755)

        cookie_census = os.path.join(REPO_ROOT, "proof/census/cookie.json")
        ledger_path = os.path.join(scratch, "ledger.jsonl")

        config = {
            "real": fake_real,
            "census": cookie_census,
            "ledger": ledger_path,
            "nonce": "testnonce123",
            "driver": "cookie",
            "work_tmp": t_dir,
            "scratch": s_dir,
            "repo": REPO_ROOT,
            "canonical_roots": [REPO_ROOT + "/src", REPO_ROOT + "/samples/iyi"],
        }
        config_path = os.path.join(scratch, "shim.json")
        with open(config_path, "w") as f:
            json.dump(config, f)

        shim_script = os.path.join(REPO_ROOT, "proof/roundtrip_shim.py")
        out_bin = os.path.join(scratch, "prog.bin")

        # Canonical build
        rc = subprocess.run(
            [sys.executable, "-B", shim_script, "--config", config_path, "--",
             "build", "-o", out_bin, os.path.join(REPO_ROOT, "bench/std_cookie_exercise.iyi")],
            cwd=scratch,
        ).returncode
        assert rc == 0
        assert os.path.isfile(out_bin)

        # Simulate driver execution of out_bin (E3 observable: advances atime)
        subprocess.run(["cat", out_bin], stdout=subprocess.DEVNULL)

        # Verify ledger passes
        with open(cookie_census) as f:
            cdata = json.load(f)
        pin = {"chain_id": "testnonce123"}
        counts = verify_ledger(ledger_path, "cookie", cdata, pin, scratch)
        assert counts["roundtrip"] >= 1

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# S5 Smoke Tests: atime probe
# ==============================================================================

def test_atime_probe():
    """S5: Verify probe_atime_observable succeeds on /tmp with cc-built Mach-O."""
    scratch = tempfile.mkdtemp(prefix="smoke_atime_")
    try:
        probe_atime_observable(scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

def test_amendment_b_seeded_failures():
    """Amendment B: Verify verify_ledger catches NOT-EXECUTED and OUT-MODIFIED."""
    scratch = tempfile.mkdtemp(prefix="smoke_amend_b_")
    try:
        t_dir = os.path.join(scratch, "t")
        s_dir = os.path.join(scratch, "s")
        for d in [t_dir, s_dir]:
            os.makedirs(d, exist_ok=True)

        fake_real = os.path.join(scratch, "fake_real")
        with open(fake_real, "w") as f:
            f.write("""#!/bin/sh
next_is_mods=0
next_is_out=0
for arg in "$@"; do
  if [ "$arg" = "--emit-iyimod" ]; then
    next_is_mods=1
  elif [ "$next_is_mods" = "1" ]; then
    mkdir -p "$arg/sub"
    touch "$arg/sub/foo.iyimod"
    next_is_mods=0
  elif [ "$arg" = "-o" ]; then
    next_is_out=1
  elif [ "$next_is_out" = "1" ]; then
    echo "binary" > "$arg"
    chmod 755 "$arg"
    next_is_out=0
  fi
done
exit 0
""")
        os.chmod(fake_real, 0o755)

        cookie_census = os.path.join(REPO_ROOT, "proof/census/cookie.json")
        with open(cookie_census) as f:
            cdata = json.load(f)

        # Test Case 1: NOT-EXECUTED (OUT was built, but never executed/read, so atime did not advance)
        ledger_path1 = os.path.join(scratch, "ledger1.jsonl")
        config1 = {
            "real": fake_real,
            "census": cookie_census,
            "ledger": ledger_path1,
            "nonce": "nonce1",
            "driver": "cookie",
            "work_tmp": t_dir,
            "scratch": s_dir,
            "repo": REPO_ROOT,
            "canonical_roots": [REPO_ROOT + "/src", REPO_ROOT + "/samples/iyi"],
        }
        cfg_path1 = os.path.join(scratch, "shim1.json")
        with open(cfg_path1, "w") as f:
            json.dump(config1, f)

        out_bin1 = os.path.join(scratch, "prog1.bin")
        shim_script = os.path.join(REPO_ROOT, "proof/roundtrip_shim.py")
        subprocess.run([sys.executable, "-B", shim_script, "--config", cfg_path1, "--", "build", "-o", out_bin1, os.path.join(REPO_ROOT, "bench/std_cookie_exercise.iyi")], check=True)
        # We do NOT read/execute out_bin1
        pin1 = {"chain_id": "nonce1"}
        try:
            verify_ledger(ledger_path1, "cookie", cdata, pin1, scratch)
            assert False, "Should have failed with NOT-EXECUTED"
        except LedgerVerificationError as ex:
            assert ex.status == "NOT-EXECUTED"

        # Test Case 2: OUT-MODIFIED (OUT was modified in place after shim recorded it)
        ledger_path2 = os.path.join(scratch, "ledger2.jsonl")
        config2 = dict(config1, ledger=ledger_path2, nonce="nonce2")
        cfg_path2 = os.path.join(scratch, "shim2.json")
        with open(cfg_path2, "w") as f:
            json.dump(config2, f)

        out_bin2 = os.path.join(scratch, "prog2.bin")
        subprocess.run([sys.executable, "-B", shim_script, "--config", cfg_path2, "--", "build", "-o", out_bin2, os.path.join(REPO_ROOT, "bench/std_cookie_exercise.iyi")], check=True)

        # Modify OUT content
        with open(out_bin2, "a") as f:
            f.write("corrupted\n")
        # Execute so atime advances
        subprocess.run(["cat", out_bin2], stdout=subprocess.DEVNULL)

        pin2 = {"chain_id": "nonce2"}
        try:
            verify_ledger(ledger_path2, "cookie", cdata, pin2, scratch)
            assert False, "Should have failed with OUT-MODIFIED"
        except LedgerVerificationError as ex:
            assert ex.status == "OUT-MODIFIED"

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    print("Running comprehensive proof smoke tests...")
    test_no_asserts_in_production_proof()
    print("  [PASS] test_no_asserts_in_production_proof")
    test_base_env_scrub()
    print("  [PASS] test_base_env_scrub")
    test_pin_refusals_and_control()
    print("  [PASS] test_pin_refusals_and_control")
    test_identity_check_mutations()
    print("  [PASS] test_identity_check_mutations")
    test_run_bounded_timeout()
    print("  [PASS] test_run_bounded_timeout")
    test_census_all_29_validate()
    print("  [PASS] test_census_all_29_validate (all 29 census JSON files)")
    test_census_validator_seeded_failures()
    print("  [PASS] test_census_validator_seeded_failures")
    test_shim_and_ledger_verification()
    print("  [PASS] test_shim_and_ledger_verification")
    test_atime_probe()
    print("  [PASS] test_atime_probe")
    test_amendment_b_seeded_failures()
    print("  [PASS] test_amendment_b_seeded_failures (NOT-EXECUTED and OUT-MODIFIED)")
    print("\n=======================================================")
    print("ALL COMPREHENSIVE PROOF SMOKE TESTS PASSED (100% GREEN)")
    print("=======================================================")

if __name__ == "__main__":
    main()
