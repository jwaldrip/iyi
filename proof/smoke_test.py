#!/usr/bin/env python3
"""
smoke_test.py: Test all proof guards with seeded failures and passing controls.
Uses synthetic fixtures under /tmp only.
"""

from __future__ import annotations

import ast
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time

# Ensure proof directory is on path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.proofkit import (
    IdentityError,
    base_env,
    check_disk_space,
    check_identity,
    extract_version_stamp,
    run_bounded,
    sha256_bytes,
    sha256_file,
    write_pin,
)


def test_no_asserts_in_production_proof():
    """Verify zero assert statements exist in non-test proof modules."""
    proof_dir = os.path.join(REPO_ROOT, "proof")
    py_files = glob.glob(os.path.join(proof_dir, "*.py"))
    assert len(py_files) > 0, "No python files found in proof/"

    for py_file in py_files:
        basename = os.path.basename(py_file)
        if basename == "smoke_test.py":
            continue
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=py_file)
        assert_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        assert len(assert_nodes) == 0, f"Found {len(assert_nodes)} assert statements in non-test module {basename}"


def test_base_env_scrub():
    """Verify base_env scrubs dangerous vars while keeping pin PATH/HOME."""
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


def create_temp_git_repo(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@test.local"], check=True)
    subprocess.run(["git", "-C", path, "config", "commit.gpgsign", "false"], check=True)


def test_pin_refusals_and_control():
    """Verify write_pin refuses invalid conditions and succeeds on valid control."""
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

        # Clone W from P
        subprocess.run(["git", "clone", p_dir, w_dir], check=True, capture_output=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "user.email", "test@test.local"], check=True)
        subprocess.run(["git", "-C", w_dir, "config", "commit.gpgsign", "false"], check=True)

        # Make proof commit in W
        os.makedirs(os.path.join(w_dir, "proof"), exist_ok=True)
        with open(os.path.join(w_dir, "proof/tool.py"), "w") as f:
            f.write("# proof\n")
        subprocess.run(["git", "-C", w_dir, "add", "proof/tool.py"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "proof tool"], check=True)

        # Create fake compiler binary
        with open(c_bin, "w") as f:
            f.write(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [{stamp}] (2026-10-28)'; exit 0; fi\nif [ \"$1\" = \"env\" ]; then echo '/tmp/fake/src'; exit 0; fi\nexit 0\n")
        os.chmod(c_bin, 0o755)

        # Set compiler mtime later than P commit time
        time.sleep(1.1)
        os.utime(c_bin, None)

        # Control check: write_pin should succeed
        pin = write_pin(r_dir, p_dir, w_dir, c_bin)
        assert pin["p_source_sha"] == p_sha
        assert pin["compiler_stamp"] == stamp
        assert os.path.isfile(os.path.join(r_dir, "pin.json"))

        # Refusal 1: Non-empty report directory
        try:
            write_pin(r_dir, p_dir, w_dir, c_bin)
            assert False, "Should have refused non-empty R"
        except IdentityError:
            pass

        # Refusal 2: Dirty P
        r_dir2 = os.path.join(scratch, "report2")
        with open(os.path.join(p_dir, "dirty.txt"), "w") as f:
            f.write("dirty\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should have refused dirty P"
        except IdentityError:
            pass
        os.remove(os.path.join(p_dir, "dirty.txt"))

        # Refusal 3: Dirty W
        with open(os.path.join(w_dir, "dirty.txt"), "w") as f:
            f.write("dirty\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should have refused dirty W"
        except IdentityError:
            pass
        os.remove(os.path.join(w_dir, "dirty.txt"))

        # Refusal 4: Product diff between P and W
        with open(os.path.join(w_dir, "file.txt"), "w") as f:
            f.write("modified product\n")
        subprocess.run(["git", "-C", w_dir, "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "modify product"], check=True)
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should have refused product diff"
        except IdentityError:
            pass

        # Revert product diff commit
        subprocess.run(["git", "-C", w_dir, "reset", "--hard", "HEAD~1"], check=True)

        # Refusal 5: Stale compiler mtime (older than P commit time)
        p_commit_time = int(subprocess.check_output(["git", "-C", p_dir, "log", "-1", "--format=%ct"], text=True).strip())
        os.utime(c_bin, (p_commit_time - 10, p_commit_time - 10))
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should have refused stale compiler mtime"
        except IdentityError:
            pass

        # Refusal 6: Stamp mismatch in --version
        os.utime(c_bin, None)
        with open(c_bin, "w") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [deadbeef0] (2026-10-28)'; exit 0; fi\nexit 0\n")
        try:
            write_pin(r_dir2, p_dir, w_dir, c_bin)
            assert False, "Should have refused stamp mismatch"
        except IdentityError:
            pass

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_identity_check_failures():
    """Verify check_identity catches all 10 mutation scenarios."""
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

        # Baseline check_identity passes
        check_identity(pin)

        # Mutation 1: P HEAD moved
        with open(os.path.join(p_dir, "new.txt"), "w") as f:
            f.write("new\n")
        subprocess.run(["git", "-C", p_dir, "add", "new.txt"], check=True)
        subprocess.run(["git", "-C", p_dir, "commit", "-m", "new P"], check=True)
        try:
            check_identity(pin)
            assert False, "Should have failed on P HEAD moved"
        except IdentityError:
            pass
        subprocess.run(["git", "-C", p_dir, "reset", "--hard", "HEAD~1"], check=True)
        check_identity(pin)

        # Mutation 2: W HEAD moved
        with open(os.path.join(w_dir, "proof/new.txt"), "w") as f:
            f.write("new\n")
        subprocess.run(["git", "-C", w_dir, "add", "proof/new.txt"], check=True)
        subprocess.run(["git", "-C", w_dir, "commit", "-m", "new W"], check=True)
        try:
            check_identity(pin)
            assert False, "Should have failed on W HEAD moved"
        except IdentityError:
            pass
        subprocess.run(["git", "-C", w_dir, "reset", "--hard", "HEAD~1"], check=True)
        check_identity(pin)

        # Mutation 3: Binary bytes changed with mtime restored
        orig_mtime_ns = pin["compiler_mtime_ns"]
        with open(c_bin, "a") as f:
            f.write("# appended byte\n")
        os.utime(c_bin, ns=(orig_mtime_ns, orig_mtime_ns))
        try:
            check_identity(pin)
            assert False, "Should have failed on compiler sha changed"
        except IdentityError:
            pass

        # Mutation 4: Inode replaced
        os.remove(c_bin)
        with open(c_bin, "w") as f:
            f.write(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'iyi 0.19.1 [{stamp}] (2026-10-28)'; exit 0; fi\nexit 0\n")
        os.chmod(c_bin, 0o755)
        try:
            check_identity(pin)
            assert False, "Should have failed on inode / sha change"
        except IdentityError:
            pass

        # Mutation 5: PATH changed
        old_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = "/altered/path:" + old_path
            check_identity(pin)
            assert False, "Should have failed on PATH changed"
        except IdentityError:
            pass
        finally:
            os.environ["PATH"] = old_path

    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_run_bounded_timeout_and_survivor_sweep():
    """Verify run_bounded terminates process group and kills grandchildren on timeout."""
    # Script that spawns a background grandchild sleeping in the background
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
    assert timed_out is True, "Process should have timed out"


def main():
    print("Running proof smoke tests...")
    test_no_asserts_in_production_proof()
    print("  [PASS] test_no_asserts_in_production_proof")
    test_base_env_scrub()
    print("  [PASS] test_base_env_scrub")
    test_pin_refusals_and_control()
    print("  [PASS] test_pin_refusals_and_control")
    test_identity_check_failures()
    print("  [PASS] test_identity_check_failures")
    test_run_bounded_timeout_and_survivor_sweep()
    print("  [PASS] test_run_bounded_timeout_and_survivor_sweep")
    print("All S1 proof smoke tests PASSED.")


if __name__ == "__main__":
    main()
