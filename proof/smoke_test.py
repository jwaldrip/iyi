#!/usr/bin/env python3
"""
Truthful synthetic proof harness for the native stale-testing acceptance.

Registered fixtures emit machine-auditable seed or control lines. REVIEW_ITEMS
keeps an incomplete repair red until every required seed and control executes.
"""

from __future__ import annotations

import ast
import contextlib
import glob
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from types import SimpleNamespace


if __name__ == "__main__" and sys.flags.optimize:
    print(
        f"smoke_test.py refuses optimized Python: sys.flags.optimize={sys.flags.optimize}",
        file=sys.stderr,
    )
    raise SystemExit(2)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.proofkit import (
    IdentityError,
    base_env,
    check_identity,
    inspect_pin_inputs,
    probe_atime_observable,
    run_bounded,
    write_pin,
)
from proof.run_proof import CORE_29_DRIVERS, cmd_plan, fresh_stage_env


@dataclass(frozen=True)
class Observation:
    expected: object
    got: object
    applied: str = ""


@dataclass(frozen=True)
class Fixture:
    fixture_id: str
    kind: str
    run: Callable[[], Observation]


@dataclass(frozen=True)
class CoverageAudit:
    configuration_errors: tuple[str, ...]
    missing_seed_ids: tuple[str, ...]
    missing_control_ids: tuple[str, ...]
    items_without_executed_seed: tuple[str, ...]
    unmapped_registered_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not (
            self.configuration_errors
            or self.missing_seed_ids
            or self.missing_control_ids
            or self.items_without_executed_seed
            or self.unmapped_registered_ids
        )


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fixture_kind_from_id(fixture_id: str) -> str | None:
    parts = fixture_id.split(".")
    has_seed = "seed" in parts
    has_control = "control" in parts
    if has_seed == has_control:
        return None
    return "seed" if has_seed else "control"


def _coverage_audit(
    review_items: Mapping[str, tuple[str, ...]],
    executed_seed_ids: set[str],
    executed_control_ids: set[str],
    registered_kinds: Mapping[str, str],
) -> CoverageAudit:
    errors: list[str] = []
    all_mapped_ids: set[str] = set()
    required_seed_ids: set[str] = set()
    required_control_ids: set[str] = set()
    items_without_executed_seed: list[str] = []

    for item, fixture_ids in review_items.items():
        if not fixture_ids:
            errors.append(f"{item}: no fixture ids")
            continue

        item_seed_ids: set[str] = set()
        item_control_ids: set[str] = set()
        for fixture_id in fixture_ids:
            all_mapped_ids.add(fixture_id)
            kind = _fixture_kind_from_id(fixture_id)
            if kind == "seed":
                item_seed_ids.add(fixture_id)
                required_seed_ids.add(fixture_id)
            elif kind == "control":
                item_control_ids.add(fixture_id)
                required_control_ids.add(fixture_id)
            else:
                errors.append(f"{item}: fixture id has no single kind: {fixture_id}")

        if not item_seed_ids:
            errors.append(f"{item}: no seed fixture")
        elif not item_seed_ids.intersection(executed_seed_ids):
            items_without_executed_seed.append(item)
        if not item_control_ids:
            errors.append(f"{item}: no control fixture")

    for fixture_id, kind in registered_kinds.items():
        named_kind = _fixture_kind_from_id(fixture_id)
        if kind not in ("seed", "control"):
            errors.append(f"{fixture_id}: invalid registered kind {kind}")
        elif named_kind != kind:
            errors.append(
                f"{fixture_id}: id kind {named_kind!r} disagrees with registered kind {kind!r}"
            )

    return CoverageAudit(
        configuration_errors=tuple(sorted(set(errors))),
        missing_seed_ids=tuple(sorted(required_seed_ids - executed_seed_ids)),
        missing_control_ids=tuple(sorted(required_control_ids - executed_control_ids)),
        items_without_executed_seed=tuple(sorted(set(items_without_executed_seed))),
        unmapped_registered_ids=tuple(sorted(set(registered_kinds) - all_mapped_ids)),
    )


def _isolated_base_env(ambient: Mapping[str, str]) -> dict[str, str]:
    original = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(ambient)
        pin = {
            "env_path": "/pinned/bin:/usr/bin",
            "env_home": "/pinned/home",
        }
        return base_env(pin)
    finally:
        os.environ.clear()
        os.environ.update(original)


def _fixture_unoptimized_control() -> Observation:
    return Observation(expected=0, got=sys.flags.optimize)


def _fixture_optimized_refusal_seed() -> Observation:
    command = [sys.executable, "-B", "-O", os.path.abspath(__file__)]
    child_env = os.environ.copy()
    child_env.pop("PYTHONOPTIMIZE", None)
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
    marker = "smoke_test.py refuses optimized Python: sys.flags.optimize=1"
    got = {
        "returncode": completed.returncode,
        "marker": marker in completed.stderr,
    }
    expected = {"returncode": 2, "marker": True}
    return Observation(
        expected=expected,
        got=got,
        applied=f"argv={_render(command[1:])};stderr_sha256="
        f"{hashlib.sha256(completed.stderr.encode()).hexdigest()}",
    )


def _fixture_env_scrub_seed() -> Observation:
    banned = (
        "IYI_OPTS",
        "IYI_PATH",
        "CRYSTAL_PATH",
        "IYI_DAEMON_SOCKET",
        "CRYSTAL_DAEMON_SOCKET",
        "PYTHONOPTIMIZE",
        "IYI_FORK_PROBE",
    )
    ambient = {
        **{key: f"seed-{key.lower()}" for key in banned},
        "PATH": "/ambient/bin",
        "HOME": "/ambient/home",
    }
    cleaned = _isolated_base_env(ambient)
    applied = sorted(key for key in banned if ambient.get(key))
    got = {
        "applied_keys": applied,
        "remaining_keys": sorted(key for key in banned if key in cleaned),
    }
    expected = {
        "applied_keys": sorted(banned),
        "remaining_keys": [],
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"ambient_keys={','.join(applied)}",
    )


def _fixture_env_preserve_control() -> Observation:
    ambient = {
        "PATH": "/ambient/bin",
        "HOME": "/ambient/home",
    }
    cleaned = _isolated_base_env(ambient)
    got = {
        "PATH": cleaned.get("PATH"),
        "HOME": cleaned.get("HOME"),
    }
    expected = {
        "PATH": "/pinned/bin:/usr/bin",
        "HOME": "/pinned/home",
    }
    return Observation(expected=expected, got=got)


def _assert_count(source: str, filename: str) -> int:
    tree = ast.parse(source, filename=filename)
    return sum(1 for node in ast.walk(tree) if isinstance(node, ast.Assert))


def _fixture_assert_detection_seed() -> Observation:
    control_source = "value = 1\nvalue\n"
    seed_source = "value = 1\nassert value\n"
    count = _assert_count(seed_source, "seed_assert.py")
    control_sha = hashlib.sha256(control_source.encode()).hexdigest()
    seed_sha = hashlib.sha256(seed_source.encode()).hexdigest()
    applied = control_sha != seed_sha
    expected = {
        "assert_count": 1,
        "bytes_differ": True,
    }
    got = {
        "assert_count": count,
        "bytes_differ": applied,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=(
            f"control_sha256={control_sha};seed_sha256={seed_sha};"
            f"bytes_differ={str(applied).lower()}"
        ),
    )


def _fixture_no_production_assert_control() -> Observation:
    proof_dir = os.path.join(REPO_ROOT, "proof")
    counts: dict[str, int] = {}
    for py_file in sorted(glob.glob(os.path.join(proof_dir, "*.py"))):
        basename = os.path.basename(py_file)
        if basename in ("smoke_test.py", "build_census.py"):
            continue
        with open(py_file, "r", encoding="utf-8") as source_file:
            counts[basename] = _assert_count(source_file.read(), py_file)
    got = {
        "asserts": {name: count for name, count in counts.items() if count},
        "files_present": bool(counts),
    }
    expected = {
        "asserts": {},
        "files_present": True,
    }
    return Observation(expected=expected, got=got)


def _fixture_coverage_gap_seed() -> Observation:
    synthetic_items = {
        "synthetic.review": (
            "synthetic.seed.required",
            "synthetic.control.pair",
        )
    }
    audit = _coverage_audit(
        synthetic_items,
        executed_seed_ids=set(),
        executed_control_ids={"synthetic.control.pair"},
        registered_kinds={},
    )
    got = {
        "missing_seed_ids": list(audit.missing_seed_ids),
        "items_without_executed_seed": list(audit.items_without_executed_seed),
    }
    expected = {
        "missing_seed_ids": ["synthetic.seed.required"],
        "items_without_executed_seed": ["synthetic.review"],
    }
    return Observation(
        expected=expected,
        got=got,
        applied="executed_seed_ids=[];removed=synthetic.seed.required",
    )


def _fixture_coverage_complete_control() -> Observation:
    synthetic_items = {
        "synthetic.review": (
            "synthetic.seed.required",
            "synthetic.control.pair",
        )
    }
    audit = _coverage_audit(
        synthetic_items,
        executed_seed_ids={"synthetic.seed.required"},
        executed_control_ids={"synthetic.control.pair"},
        registered_kinds={},
    )
    got = {
        "configuration_errors": list(audit.configuration_errors),
        "missing_seed_ids": list(audit.missing_seed_ids),
        "missing_control_ids": list(audit.missing_control_ids),
        "items_without_executed_seed": list(audit.items_without_executed_seed),
    }
    expected = {
        "configuration_errors": [],
        "missing_seed_ids": [],
        "missing_control_ids": [],
        "items_without_executed_seed": [],
    }
    return Observation(expected=expected, got=got)


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _read_pid(path: str) -> int:
    with open(path, "r", encoding="utf-8") as source:
        return int(source.read())


def _git(cwd: str, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", cwd, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git -C {cwd} {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


class PinFixture:
    def __init__(self) -> None:
        self.scratch = tempfile.mkdtemp(prefix="iyi-o2-pin-", dir="/tmp")
        self.p = os.path.join(self.scratch, "p")
        self.w = os.path.join(self.scratch, "w")
        self.compiler = os.path.join(self.scratch, "iyi")
        while True:
            short_chain = hashlib.sha256(os.urandom(32)).hexdigest()[:8]
            self.report = os.path.join("/tmp", f"iyp-{short_chain}")
            if not os.path.exists(self.report):
                break
        try:
            self._setup()
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            subprocess.SubprocessError,
        ):
            self.cleanup()
            raise

    def __enter__(self) -> PinFixture:
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        shutil.rmtree(self.report, ignore_errors=True)
        shutil.rmtree(self.scratch, ignore_errors=True)

    def _setup(self) -> None:
        os.makedirs(self.p)
        _git(self.p, "init", "-b", "main")
        _git(self.p, "config", "user.name", "Proof Fixture")
        _git(self.p, "config", "user.email", "proof-fixture@example.invalid")
        _git(self.p, "config", "commit.gpgsign", "false")

        census_target = os.path.join(self.p, "proof", "census")
        os.makedirs(census_target)
        copied_scripts: set[str] = set()
        for census_source in sorted(
            glob.glob(os.path.join(REPO_ROOT, "proof", "census", "*.json"))
        ):
            with open(census_source, "r", encoding="utf-8") as source:
                census = json.load(source)
            shutil.copyfile(
                census_source,
                os.path.join(census_target, os.path.basename(census_source)),
            )
            script_relative = census["script"]
            if script_relative in copied_scripts:
                continue
            copied_scripts.add(script_relative)
            script_source = os.path.join(REPO_ROOT, script_relative)
            script_target = os.path.join(self.p, script_relative)
            os.makedirs(os.path.dirname(script_target), exist_ok=True)
            shutil.copyfile(script_source, script_target)

        for relative in ("src/fixture.txt", "samples/iyi/fixture.iyi"):
            target = os.path.join(self.p, relative)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as fixture_file:
                fixture_file.write("fixture\n")

        _git(self.p, "add", ".")
        _git(self.p, "commit", "-m", "fixture base")
        self.p_sha = _git(self.p, "rev-parse", "HEAD")
        self.p_commit_time = int(_git(self.p, "log", "-1", "--format=%ct"))

        completed = subprocess.run(
            ["git", "clone", "--quiet", self.p, self.w],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"git clone failed: {completed.stderr.strip()}")
        _git(self.w, "config", "user.name", "Proof Fixture")
        _git(self.w, "config", "user.email", "proof-fixture@example.invalid")
        _git(self.w, "config", "commit.gpgsign", "false")
        marker = os.path.join(self.w, "proof", "o2-fixture.txt")
        with open(marker, "w", encoding="utf-8") as marker_file:
            marker_file.write("proof-only\n")
        _git(self.w, "add", "proof/o2-fixture.txt")
        _git(self.w, "commit", "-m", "fixture proof delta")
        self.write_compiler(f"iyi fixture [{self.p_sha[:9]}]")

    def write_compiler(self, version_line: str) -> None:
        with open(self.compiler, "w", encoding="utf-8") as compiler_file:
            compiler_file.write(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                f"  printf '%s\\n' '{version_line}'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = \"env\" ] && [ \"$2\" = \"IYI_PATH\" ]; then\n"
                f"  printf '%s\\n' '{os.path.join(self.w, 'src')}'\n"
                "  exit 0\n"
                "fi\n"
                "exit 0\n"
            )
        os.chmod(self.compiler, 0o755)
        compiler_time_ns = (self.p_commit_time + 2) * 1_000_000_000
        os.utime(
            self.compiler,
            ns=(compiler_time_ns, compiler_time_ns),
        )

    def pin(self) -> dict:
        return write_pin(
            self.report,
            self.p,
            self.w,
            self.compiler,
            CORE_29_DRIVERS,
        )


def _identity_reason(call: Callable[[], object]) -> str:
    try:
        call()
    except IdentityError as error:
        return error.reason
    return "NO-REFUSAL"


def _mutate_dirty_w(fixture: PinFixture) -> tuple[bool, str]:
    path = os.path.join(fixture.w, "dirty-w")
    with open(path, "w", encoding="utf-8") as dirty_file:
        dirty_file.write("dirty\n")
    applied = os.path.isfile(path)
    return applied, f"untracked={path};exists={str(applied).lower()}"


def _mutate_dirty_p(fixture: PinFixture) -> tuple[bool, str]:
    path = os.path.join(fixture.p, "dirty-p")
    with open(path, "w", encoding="utf-8") as dirty_file:
        dirty_file.write("dirty\n")
    applied = os.path.isfile(path)
    return applied, f"untracked={path};exists={str(applied).lower()}"


def _mutate_nondescendant(fixture: PinFixture) -> tuple[bool, str]:
    _git(fixture.w, "checkout", "--orphan", "unrelated")
    _git(fixture.w, "rm", "-rf", ".")
    unrelated = os.path.join(fixture.w, "unrelated.txt")
    with open(unrelated, "w", encoding="utf-8") as unrelated_file:
        unrelated_file.write("unrelated\n")
    _git(fixture.w, "add", "unrelated.txt")
    _git(fixture.w, "commit", "-m", "unrelated history")
    applied = subprocess.run(
        [
            "git",
            "-C",
            fixture.w,
            "merge-base",
            "--is-ancestor",
            fixture.p_sha,
            "HEAD",
        ],
        check=False,
        capture_output=True,
    ).returncode == 1
    return applied, f"ancestor_check_failed={str(applied).lower()}"


def _mutate_product_diff(fixture: PinFixture) -> tuple[bool, str]:
    path = os.path.join(fixture.w, "src", "fixture.txt")
    with open(path, "a", encoding="utf-8") as product_file:
        product_file.write("changed\n")
    _git(fixture.w, "add", "src/fixture.txt")
    _git(fixture.w, "commit", "-m", "product mutation")
    changed = _git(
        fixture.w,
        "diff",
        "--name-only",
        fixture.p_sha,
        "HEAD",
    ).splitlines()
    applied = "src/fixture.txt" in changed
    return applied, f"changed_paths={_render(changed)}"


def _mutate_stale_compiler(fixture: PinFixture) -> tuple[bool, str]:
    stale_ns = fixture.p_commit_time * 1_000_000_000
    os.utime(fixture.compiler, ns=(stale_ns, stale_ns))
    got = os.stat(fixture.compiler).st_mtime_ns
    return got == stale_ns, f"mtime_ns={got};p_commit_ns={stale_ns}"


def _mutate_missing_stamp(fixture: PinFixture) -> tuple[bool, str]:
    fixture.write_compiler("iyi fixture without stamp")
    output = subprocess.check_output(
        [fixture.compiler, "--version"],
        text=True,
    ).strip()
    applied = "[" not in output
    return applied, f"version={_render(output)}"


def _mutate_stamp_mismatch(fixture: PinFixture) -> tuple[bool, str]:
    fixture.write_compiler("iyi fixture [deadbeef0]")
    output = subprocess.check_output(
        [fixture.compiler, "--version"],
        text=True,
    ).strip()
    applied = "[deadbeef0]" in output
    return applied, f"version={_render(output)}"


def _mutate_nonempty_report(fixture: PinFixture) -> tuple[bool, str]:
    os.makedirs(fixture.report)
    sentinel = os.path.join(fixture.report, "occupied")
    with open(sentinel, "w", encoding="utf-8") as occupied:
        occupied.write("occupied\n")
    applied = os.path.isfile(sentinel)
    return applied, f"entry={sentinel};exists={str(applied).lower()}"


def _mutate_bad_report_name(fixture: PinFixture) -> tuple[bool, str]:
    fixture.report = os.path.join(
        "/tmp",
        f"not-iyp-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}",
    )
    report_real = os.path.realpath(fixture.report)
    applied = re.fullmatch(r"/private/tmp/iyp-[0-9a-f]{8}", report_real) is None
    return applied, f"report_real={report_real}"


def _pin_reason_seed(
    mutator: Callable[[PinFixture], tuple[bool, str]],
    expected_reason: str,
) -> Observation:
    with PinFixture() as fixture:
        applied, evidence = mutator(fixture)
        reason = _identity_reason(fixture.pin)
    expected = {"applied": True, "reason": expected_reason}
    got = {"applied": applied, "reason": reason}
    return Observation(expected=expected, got=got, applied=evidence)


def _fixture_pin_control() -> Observation:
    with PinFixture() as fixture:
        pin = fixture.pin()
        got = {
            "chain_prefix_matches": os.path.basename(fixture.report)[4:]
            == pin["chain_id"][:8],
            "pin_exists": os.path.isfile(
                os.path.join(fixture.report, "pin.json")
            ),
            "timeout_recorded": bool(pin.get("timeout_path"))
            and bool(pin.get("timeout_version")),
        }
    expected = {
        "chain_prefix_matches": True,
        "pin_exists": True,
        "timeout_recorded": True,
    }
    return Observation(expected=expected, got=got)


def _mutate_p_head(fixture: PinFixture) -> tuple[bool, str]:
    path = os.path.join(fixture.p, "proof-head.txt")
    with open(path, "w", encoding="utf-8") as changed:
        changed.write("changed\n")
    _git(fixture.p, "add", "proof-head.txt")
    _git(fixture.p, "commit", "-m", "move P")
    head = _git(fixture.p, "rev-parse", "HEAD")
    return head != fixture.p_sha, f"old={fixture.p_sha};new={head}"


def _mutate_w_head(fixture: PinFixture) -> tuple[bool, str]:
    old_head = _git(fixture.w, "rev-parse", "HEAD")
    path = os.path.join(fixture.w, "proof", "head-move.txt")
    with open(path, "w", encoding="utf-8") as changed:
        changed.write("changed\n")
    _git(fixture.w, "add", "proof/head-move.txt")
    _git(fixture.w, "commit", "-m", "move W")
    head = _git(fixture.w, "rev-parse", "HEAD")
    return head != old_head, f"old={old_head};new={head}"


def _mutate_compiler_bytes(fixture: PinFixture) -> tuple[bool, str]:
    before = os.stat(fixture.compiler)
    before_sha = _file_sha256(fixture.compiler)
    with open(fixture.compiler, "ab") as compiler_file:
        compiler_file.write(b"\n# byte mutation\n")
    os.utime(
        fixture.compiler,
        ns=(before.st_atime_ns, before.st_mtime_ns),
    )
    after_sha = _file_sha256(fixture.compiler)
    applied = before_sha != after_sha
    return applied, f"before_sha={before_sha};after_sha={after_sha}"


def _mutate_compiler_inode(fixture: PinFixture) -> tuple[bool, str]:
    before = os.stat(fixture.compiler)
    replacement = f"{fixture.compiler}.replacement"
    shutil.copyfile(fixture.compiler, replacement)
    os.chmod(replacement, before.st_mode)
    os.utime(
        replacement,
        ns=(before.st_atime_ns, before.st_mtime_ns),
    )
    os.replace(replacement, fixture.compiler)
    after = os.stat(fixture.compiler)
    applied = before.st_ino != after.st_ino
    return applied, f"before_inode={before.st_ino};after_inode={after.st_ino}"


def _mutate_compiler_mtime(fixture: PinFixture) -> tuple[bool, str]:
    before = os.stat(fixture.compiler)
    changed_mtime = before.st_mtime_ns + 1
    os.utime(
        fixture.compiler,
        ns=(before.st_atime_ns, changed_mtime),
    )
    after = os.stat(fixture.compiler)
    applied = after.st_mtime_ns == changed_mtime
    return applied, (
        f"before_mtime_ns={before.st_mtime_ns};"
        f"after_mtime_ns={after.st_mtime_ns}"
    )


def _identity_reason_seed(
    mutator: Callable[[PinFixture], tuple[bool, str]],
    expected_reason: str,
) -> Observation:
    with PinFixture() as fixture:
        pin = fixture.pin()
        applied, evidence = mutator(fixture)
        reason = _identity_reason(lambda: check_identity(pin))
    expected = {"applied": True, "reason": expected_reason}
    got = {"applied": applied, "reason": reason}
    return Observation(expected=expected, got=got, applied=evidence)


def _fixture_identity_path_seed() -> Observation:
    with PinFixture() as fixture:
        pin = fixture.pin()
        original_path = os.environ.get("PATH")
        changed_path = f"{pin['env_path']}{os.pathsep}/path-mutant"
        try:
            os.environ["PATH"] = changed_path
            reason = _identity_reason(lambda: check_identity(pin))
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
    applied = changed_path != pin["env_path"]
    expected = {"applied": True, "reason": "PATH-CHANGED"}
    got = {"applied": applied, "reason": reason}
    return Observation(
        expected=expected,
        got=got,
        applied=f"pinned={_render(pin['env_path'])};changed={_render(changed_path)}",
    )


def _fixture_identity_control() -> Observation:
    with PinFixture() as fixture:
        pin = fixture.pin()
        reason = _identity_reason(lambda: check_identity(pin))
    return Observation(expected="NO-REFUSAL", got=reason)


def _mutate_plan_census(fixture: PinFixture) -> tuple[bool, str]:
    census_path = os.path.join(fixture.w, "proof", "census", "cookie.json")
    with open(census_path, "r", encoding="utf-8") as source:
        census = json.load(source)
    original = census["script_sha256"]
    census["script_sha256"] = "0" * 64
    with open(census_path, "w", encoding="utf-8") as output:
        json.dump(census, output, indent=2, sort_keys=True)
        output.write("\n")
    _git(fixture.w, "add", "proof/census/cookie.json")
    _git(fixture.w, "commit", "-m", "mutate census")
    applied = original != census["script_sha256"]
    return applied, (
        f"old_sha={original};new_sha={census['script_sha256']};"
        "substitutions=1"
    )


def _plan_reason_seed(
    mutator: Callable[[PinFixture], tuple[bool, str]],
    expected_reason: str,
) -> Observation:
    with PinFixture() as fixture:
        applied, evidence = mutator(fixture)
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                cmd_plan(
                    SimpleNamespace(
                        p=fixture.p,
                        w=fixture.w,
                        compiler=fixture.compiler,
                    )
                )
        except IdentityError as error:
            reason = error.reason
        else:
            reason = "NO-REFUSAL"
        stdout_empty = output.getvalue() == ""
    expected = {
        "applied": True,
        "reason": expected_reason,
        "stdout_empty": True,
    }
    got = {
        "applied": applied,
        "reason": reason,
        "stdout_empty": stdout_empty,
    }
    return Observation(expected=expected, got=got, applied=evidence)


def _fixture_plan_control() -> Observation:
    with PinFixture() as fixture:
        output = io.StringIO()
        report_absent_before = not os.path.exists(fixture.report)
        with contextlib.redirect_stdout(output):
            cmd_plan(
                SimpleNamespace(
                    p=fixture.p,
                    w=fixture.w,
                    compiler=fixture.compiler,
                )
            )
        report_absent_after = not os.path.exists(fixture.report)
        got = {
            "census_validated": "Censuses:  29 validated" in output.getvalue(),
            "report_absent_before": report_absent_before,
            "report_absent_after": report_absent_after,
        }
    expected = {
        "census_validated": True,
        "report_absent_before": True,
        "report_absent_after": True,
    }
    return Observation(expected=expected, got=got)


def _fixture_no_timeout_seed() -> Observation:
    with PinFixture() as fixture:
        tool_dir = os.path.join(fixture.scratch, "without-timeout")
        os.makedirs(tool_dir)
        linked: list[str] = []
        for tool in ("git", "nm"):
            source = shutil.which(tool)
            if not source:
                raise RuntimeError(f"{tool} is unavailable for fixture")
            target = os.path.join(tool_dir, tool)
            os.symlink(source, target)
            linked.append(target)

        original_path = os.environ.get("PATH")
        try:
            os.environ["PATH"] = tool_dir
            timeout_missing = shutil.which("timeout") is None
            reason = _identity_reason(
                lambda: inspect_pin_inputs(
                    fixture.p,
                    fixture.w,
                    fixture.compiler,
                    CORE_29_DRIVERS,
                )
            )
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
    expected = {"applied": True, "reason": "NO-TIMEOUT"}
    got = {"applied": timeout_missing, "reason": reason}
    return Observation(
        expected=expected,
        got=got,
        applied=f"PATH={tool_dir};linked={_render(linked)};timeout=None",
    )

def _process_alive(pid: int) -> bool:
    ps_path = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
    completed = subprocess.run(
        [ps_path, "-p", str(pid), "-o", "stat="],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    state = completed.stdout.strip()
    return completed.returncode == 0 and bool(state) and not state.startswith("Z")


def _bounded_paths(scratch: str, name: str) -> tuple[str, str]:
    return (
        os.path.join(scratch, f"{name}.log"),
        os.path.join(scratch, f"{name}.times"),
    )


def _grandchild_command(pid_file: str, *, leader_sleeps: bool) -> list[str]:
    statements = [
        "import pathlib, subprocess, sys, time",
        (
            "child = subprocess.Popen("
            "[sys.executable, '-c', 'import time; time.sleep(100)'])"
        ),
        f"pathlib.Path({pid_file!r}).write_text(str(child.pid))",
    ]
    if leader_sleeps:
        statements.append("time.sleep(100)")
    return [sys.executable, "-c", "; ".join(statements)]


def _fixture_bounded_control() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-bounded-control-",
        dir="/tmp",
    ) as scratch:
        log_path, times_path = _bounded_paths(scratch, "control")
        result = run_bounded(
            [sys.executable, "-c", "print('bounded-control')"],
            scratch,
            os.environ.copy(),
            log_path,
            times_path,
            None,
            0.1,
        )
        with open(log_path, "rb") as log_file:
            log_bytes = log_file.read()
        with open(times_path, "r", encoding="utf-8") as times_file:
            samples = [
                line.split()
                for line in times_file.read().splitlines()
                if line.strip()
            ]
        final_offset = int(samples[-1][1]) if samples else -1
        got = {
            "final_offset_matches": final_offset == len(log_bytes),
            "interrupted_signal": result.interrupted_signal,
            "returncode": result.returncode,
            "survivors": list(result.survivors),
            "timed_out": result.timed_out,
        }
    expected = {
        "final_offset_matches": True,
        "interrupted_signal": None,
        "returncode": 0,
        "survivors": [],
        "timed_out": False,
    }
    return Observation(expected=expected, got=got)


def _fixture_log_holder_survivor_seed() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-log-holder-",
        dir="/tmp",
    ) as scratch:
        pid_file = os.path.join(scratch, "child.pid")
        log_path, times_path = _bounded_paths(scratch, "holder")
        result = run_bounded(
            _grandchild_command(pid_file, leader_sleeps=False),
            scratch,
            os.environ.copy(),
            log_path,
            times_path,
            2.0,
            0.1,
        )
        child_pid = _read_pid(pid_file)
        applied = os.path.isfile(pid_file)
        got = {
            "applied": applied,
            "child_gone": not _process_alive(child_pid),
            "child_recorded": child_pid in result.survivors,
            "returncode": result.returncode,
            "survivor_count": len(result.survivors),
            "timed_out": result.timed_out,
        }
    expected = {
        "applied": True,
        "child_gone": True,
        "child_recorded": True,
        "returncode": 0,
        "survivor_count": 1,
        "timed_out": False,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"pid_file={pid_file};child_pid={child_pid}",
    )


def _fixture_timeout_grandchild_seed() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-timeout-",
        dir="/tmp",
    ) as scratch:
        pid_file = os.path.join(scratch, "child.pid")
        log_path, times_path = _bounded_paths(scratch, "timeout")
        result = run_bounded(
            _grandchild_command(pid_file, leader_sleeps=True),
            scratch,
            os.environ.copy(),
            log_path,
            times_path,
            0.2,
            0.1,
        )
        child_pid = _read_pid(pid_file)
        applied = os.path.isfile(pid_file)
        got = {
            "applied": applied,
            "child_gone": not _process_alive(child_pid),
            "interrupted_signal": result.interrupted_signal,
            "timed_out": result.timed_out,
        }
    expected = {
        "applied": True,
        "child_gone": True,
        "interrupted_signal": None,
        "timed_out": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"limit_sec=0.2;pid_file={pid_file};child_pid={child_pid}",
    )


def _fixture_interrupt_survivor_seed() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-interrupt-",
        dir="/tmp",
    ) as scratch:
        pid_file = os.path.join(scratch, "child.pid")
        log_path, times_path = _bounded_paths(scratch, "interrupt")

        def send_interrupt() -> None:
            time.sleep(0.2)
            os.kill(os.getpid(), signal.SIGINT)

        sender = threading.Thread(target=send_interrupt, daemon=False)
        sender.start()
        try:
            result = run_bounded(
                _grandchild_command(pid_file, leader_sleeps=True),
                scratch,
                os.environ.copy(),
                log_path,
                times_path,
                5.0,
                0.1,
            )
        finally:
            sender.join()
        child_pid = _read_pid(pid_file)
        applied = os.path.isfile(pid_file)
        got = {
            "applied": applied,
            "child_gone": not _process_alive(child_pid),
            "interrupted_signal": result.interrupted_signal,
            "residual_survivors": [
                pid for pid in result.survivors if _process_alive(pid)
            ],
        }
    expected = {
        "applied": True,
        "child_gone": True,
        "interrupted_signal": signal.SIGINT,
        "residual_survivors": [],
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"signal={signal.SIGINT};pid_file={pid_file};child_pid={child_pid}",
    )


def _fixture_probe_unobservable_seed() -> Observation:
    calls = 0

    def frozen_stat(path: str) -> object:
        nonlocal calls
        calls += 1
        actual = os.stat(path)
        return SimpleNamespace(
            st_atime_ns=actual.st_mtime_ns - 1_000_000_000,
            st_ino=actual.st_ino,
            st_mtime_ns=actual.st_mtime_ns,
        )

    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-atime-seed-",
        dir="/tmp",
    ) as scratch:
        reason = _identity_reason(
            lambda: probe_atime_observable(scratch, stat_fn=frozen_stat)
        )
    got = {
        "reason": reason,
        "seam_called": calls >= 1,
    }
    expected = {
        "reason": "EXEC-UNOBSERVABLE",
        "seam_called": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"stat_fn_calls={calls};forced_atime=mtime-1000000000",
    )


def _fixture_probe_control() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-atime-control-",
        dir="/tmp",
    ) as scratch:
        evidence = probe_atime_observable(scratch)
    got = {
        "atime_advanced": evidence["atime_after_exec_ns"]
        > evidence["mtime_ns"],
        "sha_length": len(evidence["sha256"]),
    }
    expected = {
        "atime_advanced": True,
        "sha_length": 64,
    }
    return Observation(expected=expected, got=got)


def _fixture_gate_env_reused_seed() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-env-seed-",
        dir="/tmp",
    ) as scratch:
        attempt = os.path.join(scratch, "attempt")
        os.makedirs(attempt)
        pin = {
            "env_path": os.environ.get("PATH", ""),
            "env_home": os.environ.get("HOME", ""),
        }
        first = fresh_stage_env(pin, attempt, "gate")
        try:
            fresh_stage_env(pin, attempt, "gate")
        except FileExistsError as error:
            reason = type(error).__name__
        else:
            reason = "NO-REFUSAL"
        applied = os.path.isdir(first["TMPDIR"]) and os.path.isdir(
            first["IYI_CACHE_DIR"]
        )
    expected = {"applied": True, "reason": "FileExistsError"}
    got = {"applied": applied, "reason": reason}
    return Observation(
        expected=expected,
        got=got,
        applied=(
            f"TMPDIR={first['TMPDIR']};"
            f"IYI_CACHE_DIR={first['IYI_CACHE_DIR']}"
        ),
    )


def _fixture_gate_env_fresh_control() -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-env-control-",
        dir="/tmp",
    ) as scratch:
        first_attempt = os.path.join(scratch, "a1")
        second_attempt = os.path.join(scratch, "a2")
        os.makedirs(first_attempt)
        os.makedirs(second_attempt)
        pin = {
            "env_path": os.environ.get("PATH", ""),
            "env_home": os.environ.get("HOME", ""),
        }
        first = fresh_stage_env(pin, first_attempt, "gate")
        second = fresh_stage_env(pin, second_attempt, "gate")
        got = {
            "cache_distinct": first["IYI_CACHE_DIR"]
            != second["IYI_CACHE_DIR"],
            "cache_exists": os.path.isdir(first["IYI_CACHE_DIR"])
            and os.path.isdir(second["IYI_CACHE_DIR"]),
            "tmp_distinct": first["TMPDIR"] != second["TMPDIR"],
            "tmp_exists": os.path.isdir(first["TMPDIR"])
            and os.path.isdir(second["TMPDIR"]),
        }
    expected = {
        "cache_distinct": True,
        "cache_exists": True,
        "tmp_distinct": True,
        "tmp_exists": True,
    }
    return Observation(expected=expected, got=got)


# This map is intentionally literal. A fixture id names either a seeded failure
# or its passing control. The audit below refuses missing, unexecuted, unmapped,
# or ambiguously named fixtures instead of inferring coverage from test names.
REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "review.p0.1.run3-import": (
        "s5.seed.run3-import",
        "s5.control.stage-chain",
    ),
    "review.p0.2.final-always-pass": (
        "s5.seed.final-forged-pass",
        "s5.seed.final-missing-result",
        "s5.control.stage-chain",
    ),
    "review.p0.3.matcher-roots-and-whitelist": (
        "s2.seed.matcher-variable-root",
        "s3.seed.unknown-patched-root",
        "s2.control.matcher-canonical",
    ),
    "review.p0.4.stage-bounds": (
        "s5.seed.run3-driver-timeout",
        "s5.seed.run1-slow-gate",
        "s5.control.stage-chain",
    ),
    "review.p0.5.ledger-census-and-nonce": (
        "s3.seed.ledger-stale-header",
        "s3.seed.ledger-misclassified",
        "s3.seed.ledger-not-exercised",
        "s3.control.ledger",
    ),
    "review.p0.6.census-validator": (
        "s2.seed.validator-schema",
        "s2.seed.validator-duplicate-site",
        "s2.seed.validator-verdict",
        "s2.control.census-all",
    ),
    "review.p0.7.skip-classification": (
        "s5.seed.skip-env-blocked",
        "s5.seed.skip-partial",
        "s5.control.stage-chain",
    ),
    "review.p1.smoke-coverage-and-optimization": (
        "harness.seed.coverage-gap",
        "harness.seed.optimize-refusal",
        "harness.control.coverage-complete",
        "harness.control.unoptimized",
    ),
    "review.p1.atime-probe": (
        "amend-b.seed.probe-unobservable",
        "amend-b.control.real-probe",
    ),
    "review.p1.pin-and-plan": (
        "s1.seed.plan-dirty",
        "s1.seed.plan-stale-compiler",
        "s1.seed.plan-invalid-census",
        "s1.control.plan",
    ),
    "review.p1.shim-run-semantics": (
        "s3.seed.run-consumer-failure",
        "s3.seed.run-signal-death",
        "s3.seed.run-o-executes",
        "s3.seed.implicit-file",
        "s3.seed.run-sandbox",
        "s3.seed.stdin-filename",
        "s3.seed.unknown-option",
        "s3.seed.cross-compile-roundtripped",
        "s3.seed.roots-not-from-real",
        "s3.seed.option-value-as-source",
        "s3.seed.refusal-not-recorded",
        "s3.control.run",
        "s3.control.refusal",
    ),
    "review.p1.run3-prerequisites": (
        "s5.seed.run3-missing-prerequisite",
        "s5.seed.required-mismatch",
        "s5.seed.census-missing-continues",
        "s5.control.stage-chain",
    ),
    "review.p2.fresh-cache-and-tmp": (
        "s5.seed.gate-env-reused",
        "s5.control.gate-env-fresh",
    ),
    "review.p2.rg2r-count": (
        "s5.seed.rg2r-zero",
        "s5.control.stage-chain",
    ),
    "review.p2.exclusions-attempt-location": (
        "s5.seed.exclusions-wrong-location",
        "s5.control.stage-chain",
    ),
    "review.p2.artifact-leg-failures": (
        "s4.seed.row-oserror",
        "s4.seed.nm-unpinned",
        "s4.seed.outputs-missing",
        "s4.seed.not-reusable-nested",
        "s4.control.row",
    ),
    "review.p2.run-bounded-survivors": (
        "s1.seed.timeout-grandchild",
        "s1.seed.log-holder-survivor",
        "s1.control.bounded",
    ),
    "review.p2.report-dir-path": (
        "s1.seed.report-dir-name",
        "s1.control.pin",
    ),
    "review.p2.duplicate-census-sites": (
        "s2.seed.validator-duplicate-site",
        "s2.control.census-all",
    ),
    "review.output.smoke": (
        "harness.seed.optimize-refusal",
        "harness.seed.coverage-gap",
        "harness.control.unoptimized",
    ),
    "review.output.plan": (
        "s1.seed.plan-invalid-census",
        "s1.control.plan",
    ),
    "review.output.census-report": (
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "review.p1.pin-identity-specificity": (
        "s1.seed.pin-missing-stamp",
        "s1.seed.identity-inode",
        "s1.control.identity",
    ),
    "review.p1.validator-specificity": (
        "s2.seed.validator-sha",
        "s2.seed.validator-contains",
        "s2.control.census-all",
    ),
    "review.p1.timeout-grandchild-gone": (
        "s1.seed.timeout-grandchild",
        "s1.control.bounded",
    ),
    "review.p1.shim-seeded-failure": (
        "s3.seed.canonical-argv-drift",
        "s3.control.canonical-build",
    ),
    "review.accepted.pin-and-identity": (
        "s1.seed.identity-binary-bytes",
        "s1.control.identity",
    ),
    "review.accepted.environment-and-refusals": (
        "s1.seed.env-scrub",
        "s5.seed.route-a-drivers",
        "s1.control.env-preserve",
    ),
    "review.accepted.run1": (
        "s5.seed.run1-missing-sentinel",
        "s5.seed.sample-exclusion",
        "s5.seed.p-nonzero-not-added",
        "s5.control.stage-chain",
    ),
    "review.accepted.artifact-legs": (
        "s4.seed.frame-function",
        "s4.seed.symbol-c2",
        "s4.seed.wrong-count",
        "s4.control.row",
    ),
    "review.accepted.shim": (
        "s3.seed.canonical-argv-drift",
        "amend-b.seed.not-executed",
        "s3.control.canonical-build",
    ),
    "review.accepted.verify-ledger": (
        "s3.seed.ledger-divergence",
        "amend-b.seed.copy-modified",
        "s3.control.ledger",
    ),
    "review.accepted.census-content": (
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "contract.s1.environment": (
        "s1.seed.env-scrub",
        "s1.control.env-preserve",
    ),
    "contract.s1.pin-refusals": (
        "s1.seed.pin-dirty-w",
        "s1.seed.pin-dirty-p",
        "s1.seed.pin-nondescendant",
        "s1.seed.pin-product-diff",
        "s1.seed.pin-stale-mtime",
        "s1.seed.pin-missing-stamp",
        "s1.seed.pin-stamp-mismatch",
        "s1.seed.pin-report-nonempty",
        "s1.seed.report-dir-name",
        "s1.control.pin",
    ),
    "contract.s1.identity": (
        "s1.seed.identity-p-head",
        "s1.seed.identity-w-head",
        "s1.seed.identity-binary-bytes",
        "s1.seed.identity-inode",
        "s1.seed.identity-mtime",
        "s1.seed.identity-path",
        "s1.seed.identity-cross-invocation",
        "s1.control.identity",
    ),
    "contract.s1.timeout": (
        "s1.seed.timeout-grandchild",
        "s1.seed.no-timeout",
        "s1.seed.log-holder-survivor",
        "s1.seed.interrupt-survivor",
        "s1.control.bounded",
    ),
    "contract.s1.production-asserts": (
        "s1.seed.ast-detects-assert",
        "s1.control.no-production-assert",
    ),
    "contract.s2.validator": (
        "s2.seed.validator-schema",
        "s2.seed.validator-sha",
        "s2.seed.validator-unlisted-invocation",
        "s2.seed.validator-duplicate-site",
        "s2.seed.validator-contains",
        "s2.seed.validator-verdict",
        "s2.seed.validator-var-range",
        "s2.seed.validator-unlisted-skip",
        "s2.seed.validator-skip-regex",
        "s2.seed.validator-unrenderable",
        "s2.seed.validator-sentinel",
        "s2.seed.validator-kind-variants",
        "s2.seed.validator-template",
        "s2.seed.validator-e1-missing",
        "s2.seed.validator-e1-token",
        "s2.seed.validator-e1-stray-reference",
        "s2.seed.validator-e1-verdict",
        "s2.seed.validator-e1-exit-line",
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "contract.s2.matcher": (
        "s2.seed.matcher-negative-noquestion",
        "s2.seed.matcher-unknown-dir",
        "s2.seed.matcher-outside-attempt",
        "s2.seed.matcher-copied-exercise",
        "s2.seed.matcher-two-same-kind",
        "s2.seed.matcher-conflicting-kinds",
        "s2.seed.matcher-variable-root",
        "s2.control.matcher-canonical",
    ),
    "contract.s3.canonical-build": (
        "s3.seed.canonical-argv-drift",
        "s3.control.canonical-build",
    ),
    "contract.s3.b-prefix": (
        "s3.seed.b-prefix-misparsed",
        "s3.control.canonical-build",
    ),
    "contract.s3.run-without-separator": (
        "s3.seed.run-temp-path",
        "s3.control.run",
    ),
    "contract.s3.run-with-separator": (
        "s3.seed.run-argv-or-rc",
        "s3.control.run",
    ),
    "contract.s3.run-output-only": (
        "s3.seed.run-o-executes",
        "s3.control.run-o",
    ),
    "contract.s3.stdin": (
        "s3.seed.stdin-to-build",
        "s3.control.stdin",
    ),
    "contract.s3.producer-failure": (
        "s3.seed.producer-failure",
        "s3.control.canonical-build",
    ),
    "contract.s3.consumer-failure": (
        "s3.seed.consumer-failure",
        "s3.control.canonical-build",
    ),
    "contract.s3.zero-modules": (
        "s3.seed.zero-modules",
        "s3.control.canonical-build",
    ),
    "contract.s3.passthrough-modes": (
        "s3.seed.passthrough-mutated",
        "s3.control.passthrough",
    ),
    "contract.s3.observe-flag": (
        "s3.seed.observe-duplicate",
        "s3.control.observed-negative",
    ),
    "contract.s3.census-negative": (
        "s3.seed.negative-roundtripped",
        "s3.control.observed-negative",
    ),
    "contract.s3.census-positive": (
        "s3.seed.positive-not-roundtripped",
        "s3.control.positive",
    ),
    "contract.s3.unknown-root": (
        "s3.seed.unknown-patched-root",
        "s3.control.canonical-build",
    ),
    "contract.s3.empty-and-relative-roots": (
        "s3.seed.relative-root-unresolved",
        "s3.control.empty-root",
        "s3.control.relative-root",
    ),
    "contract.s3.signals": (
        "s3.seed.run-signal-death",
        "s3.seed.sigterm-not-forwarded",
        "s3.control.run",
    ),
    "contract.s3.refusals": (
        "s3.seed.implicit-file",
        "s3.seed.run-sandbox",
        "s3.seed.stdin-filename",
        "s3.seed.unknown-option",
        "s3.seed.cross-compile-roundtripped",
        "s3.seed.roots-not-from-real",
        "s3.seed.option-value-as-source",
        "s3.seed.missing-ledger",
        "s3.seed.wrong-nonce",
        "s3.seed.refusal-not-recorded",
        "s3.control.refusal",
    ),
    "contract.s3.parallel-ledger": (
        "s3.seed.parallel-ledger-corruption",
        "s3.control.parallel-ledger",
    ),
    "contract.s3.verify-statuses": (
        "s3.seed.ledger-stale-header",
        "s3.seed.ledger-misclassified",
        "s3.seed.ledger-unfaithful",
        "s3.seed.ledger-divergence",
        "s3.seed.ledger-not-roundtripped",
        "s3.seed.ledger-not-exercised",
        "s3.seed.ledger-positive-negative-only",
        "s3.control.ledger",
    ),
    "contract.s4.callpath": (
        "s4.seed.callpath-k2-diff",
        "s4.seed.callpath-empty",
        "s4.seed.callpath-mismatch",
        "s4.control.row",
    ),
    "contract.s4.keys-and-traces": (
        "s4.seed.phase-not-linked",
        "s4.seed.reach-not-checked",
        "s4.seed.key-file-missing",
        "s4.seed.trace-empty",
        "s4.control.row",
    ),
    "contract.s4.symbol-scan": (
        "s4.seed.symbol-c2",
        "s4.seed.symbol-c3",
        "s4.seed.nm-error",
        "s4.seed.build-output-symbol",
        "s4.control.row",
    ),
    "contract.s4.row-timeout": (
        "s4.seed.build-timeout",
        "s4.seed.run-timeout",
        "s4.control.row",
    ),
    "contract.s4.frame-comparison": (
        "s4.seed.lone-cr",
        "s4.seed.frame-function",
        "s4.seed.frame-moved-byte",
        "s4.seed.exit-code",
        "s4.control.frames",
    ),
    "contract.s4.worker-isolation": (
        "s4.seed.worker-reason-collision",
        "s4.seed.stdout-replaced",
        "s4.control.workers",
    ),
    "contract.s4.counts-under-optimization": (
        "s4.seed.wrong-count",
        "s4.control.counts",
    ),
    "contract.s4.sandbox": (
        "s4.seed.sandbox-leak",
        "s4.control.sandbox",
    ),
    "contract.s5.environment": (
        "s5.seed.gate-env-reused",
        "s5.control.gate-env-fresh",
    ),
    "contract.s5.run1-sentinels": (
        "s5.seed.run1-missing-sentinel",
        "s5.seed.rg2r-zero",
        "s5.seed.rg9-140",
        "s5.seed.sibling-count-114",
        "s5.control.stage-chain",
    ),
    "contract.s5.exclusions": (
        "s5.seed.std-exclusion",
        "s5.seed.sample-exclusion",
        "s5.seed.exclusions-wrong-location",
        "s5.control.stage-chain",
    ),
    "contract.s5.run3-selection": (
        "s5.seed.p-nonzero-not-added",
        "s5.seed.run3-import",
        "s5.control.stage-chain",
    ),
    "contract.s5.driver-timeout": (
        "s5.seed.run3-driver-timeout",
        "s5.control.stage-chain",
    ),
    "contract.s5.skip-classification": (
        "s5.seed.skip-env-blocked",
        "s5.seed.skip-partial",
        "s5.seed.skip-platform",
        "s5.control.stage-chain",
    ),
    "contract.s5.driver-verdict": (
        "s5.seed.driver-missing-sentinel",
        "s5.seed.driver-stale-ledger",
        "s5.control.stage-chain",
    ),
    "contract.s5.refusals-and-identity": (
        "s5.seed.route-a-drivers",
        "s5.seed.binary-changed",
        "s5.control.stage-chain",
    ),
    "contract.s5.continue-after-missing": (
        "s5.seed.driver-missing-continues",
        "s5.seed.census-missing-continues",
        "s5.control.stage-chain",
    ),
    "contract.s5.final": (
        "s5.seed.final-missing-result",
        "s5.seed.final-forged-pass",
        "s5.seed.final-chain-mismatch",
        "s5.seed.final-earlier-failure-omitted",
        "s5.control.stage-chain",
    ),
    "contract.s5.prerequisites": (
        "s5.seed.run3-missing-prerequisite",
        "s5.seed.required-mismatch",
        "s5.control.stage-chain",
    ),
    "amendment-a.1.negative-environment": (
        "amend-a.seed.negative-env-mutated",
        "amend-a.control.negative-env",
    ),
    "amendment-a.2.positive-environment": (
        "amend-a.seed.positive-env-mutated",
        "amend-a.control.positive-env",
    ),
    "amendment-a.3.run-environment": (
        "amend-a.seed.run-env-mutated",
        "amend-a.control.run-env",
    ),
    "amendment-a.4.opts-unchanged": (
        "amend-a.seed.opts-scrubbed",
        "amend-a.control.opts-unchanged",
    ),
    "amendment-a.5.drop-cache": (
        "amend-a.seed.drop-cache",
        "amend-a.control.negative-env",
    ),
    "amendment-b.seed.not-executed": (
        "amend-b.seed.not-executed",
        "amend-b.control.stub-run",
    ),
    "amendment-b.seed.copy-modified": (
        "amend-b.seed.copy-modified",
        "amend-b.control.stub-run",
    ),
    "amendment-b.seed.move-replaced": (
        "amend-b.seed.move-replaced",
        "amend-b.control.stub-run",
    ),
    "amendment-b.seed.exec-token": (
        "amend-b.seed.exec-token",
        "amend-b.control.real-probe",
    ),
    "amendment-b.seed.stray-shasum": (
        "amend-b.seed.stray-shasum",
        "amend-b.control.real-probe",
    ),
    "amendment-b.seed.probe-unobservable": (
        "amend-b.seed.probe-unobservable",
        "amend-b.control.real-probe",
    ),
    "amendment-b.control.stub-run": (
        "amend-b.seed.not-executed",
        "amend-b.control.stub-run",
    ),
    "amendment-b.control.run-form": (
        "amend-b.seed.run-form-not-counted",
        "amend-b.control.run-form",
    ),
    "amendment-b.control.real-probe": (
        "amend-b.seed.probe-unobservable",
        "amend-b.control.real-probe",
    ),
}


FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "harness.seed.optimize-refusal",
        "seed",
        _fixture_optimized_refusal_seed,
    ),
    Fixture(
        "harness.control.unoptimized",
        "control",
        _fixture_unoptimized_control,
    ),
    Fixture(
        "harness.seed.coverage-gap",
        "seed",
        _fixture_coverage_gap_seed,
    ),
    Fixture(
        "harness.control.coverage-complete",
        "control",
        _fixture_coverage_complete_control,
    ),
    Fixture(
        "s1.seed.env-scrub",
        "seed",
        _fixture_env_scrub_seed,
    ),
    Fixture(
        "s1.control.env-preserve",
        "control",
        _fixture_env_preserve_control,
    ),
    Fixture(
        "s1.seed.ast-detects-assert",
        "seed",
        _fixture_assert_detection_seed,
    ),
    Fixture(
        "s1.control.no-production-assert",
        "control",
        _fixture_no_production_assert_control,
    ),
    Fixture(
        "s1.seed.pin-dirty-w",
        "seed",
        partial(_pin_reason_seed, _mutate_dirty_w, "W-DIRTY"),
    ),
    Fixture(
        "s1.seed.pin-dirty-p",
        "seed",
        partial(_pin_reason_seed, _mutate_dirty_p, "P-DIRTY"),
    ),
    Fixture(
        "s1.seed.pin-nondescendant",
        "seed",
        partial(
            _pin_reason_seed,
            _mutate_nondescendant,
            "W-NOT-DESCENDANT",
        ),
    ),
    Fixture(
        "s1.seed.pin-product-diff",
        "seed",
        partial(_pin_reason_seed, _mutate_product_diff, "PRODUCT-DIFF"),
    ),
    Fixture(
        "s1.seed.pin-stale-mtime",
        "seed",
        partial(_pin_reason_seed, _mutate_stale_compiler, "COMPILER-STALE"),
    ),
    Fixture(
        "s1.seed.pin-missing-stamp",
        "seed",
        partial(
            _pin_reason_seed,
            _mutate_missing_stamp,
            "COMPILER-STAMP-MISSING",
        ),
    ),
    Fixture(
        "s1.seed.pin-stamp-mismatch",
        "seed",
        partial(
            _pin_reason_seed,
            _mutate_stamp_mismatch,
            "COMPILER-STAMP-MISMATCH",
        ),
    ),
    Fixture(
        "s1.seed.pin-report-nonempty",
        "seed",
        partial(
            _pin_reason_seed,
            _mutate_nonempty_report,
            "REPORT-DIR-NOT-EMPTY",
        ),
    ),
    Fixture(
        "s1.seed.report-dir-name",
        "seed",
        partial(
            _pin_reason_seed,
            _mutate_bad_report_name,
            "REPORT-DIR-NAME",
        ),
    ),
    Fixture(
        "s1.control.pin",
        "control",
        _fixture_pin_control,
    ),
    Fixture(
        "s1.seed.identity-p-head",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_p_head,
            "P-HEAD-CHANGED",
        ),
    ),
    Fixture(
        "s1.seed.identity-w-head",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_w_head,
            "W-HEAD-CHANGED",
        ),
    ),
    Fixture(
        "s1.seed.identity-binary-bytes",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_compiler_bytes,
            "COMPILER-SHA-CHANGED",
        ),
    ),
    Fixture(
        "s1.seed.identity-inode",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_compiler_inode,
            "COMPILER-INODE-CHANGED",
        ),
    ),
    Fixture(
        "s1.seed.identity-mtime",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_compiler_mtime,
            "COMPILER-MTIME-CHANGED",
        ),
    ),
    Fixture(
        "s1.seed.identity-path",
        "seed",
        _fixture_identity_path_seed,
    ),
    Fixture(
        "s1.seed.identity-cross-invocation",
        "seed",
        partial(
            _identity_reason_seed,
            _mutate_compiler_bytes,
            "COMPILER-SHA-CHANGED",
        ),
    ),
    Fixture(
        "s1.control.identity",
        "control",
        _fixture_identity_control,
    ),
    Fixture(
        "s1.seed.timeout-grandchild",
        "seed",
        _fixture_timeout_grandchild_seed,
    ),
    Fixture(
        "s1.seed.no-timeout",
        "seed",
        _fixture_no_timeout_seed,
    ),
    Fixture(
        "s1.seed.log-holder-survivor",
        "seed",
        _fixture_log_holder_survivor_seed,
    ),
    Fixture(
        "s1.seed.interrupt-survivor",
        "seed",
        _fixture_interrupt_survivor_seed,
    ),
    Fixture(
        "s1.control.bounded",
        "control",
        _fixture_bounded_control,
    ),
    Fixture(
        "s1.seed.plan-dirty",
        "seed",
        partial(_plan_reason_seed, _mutate_dirty_p, "P-DIRTY"),
    ),
    Fixture(
        "s1.seed.plan-stale-compiler",
        "seed",
        partial(
            _plan_reason_seed,
            _mutate_stale_compiler,
            "COMPILER-STALE",
        ),
    ),
    Fixture(
        "s1.seed.plan-invalid-census",
        "seed",
        partial(
            _plan_reason_seed,
            _mutate_plan_census,
            "CENSUS-INVALID",
        ),
    ),
    Fixture(
        "s1.control.plan",
        "control",
        _fixture_plan_control,
    ),
    Fixture(
        "amend-b.seed.probe-unobservable",
        "seed",
        _fixture_probe_unobservable_seed,
    ),
    Fixture(
        "amend-b.control.real-probe",
        "control",
        _fixture_probe_control,
    ),
    Fixture(
        "s5.seed.gate-env-reused",
        "seed",
        _fixture_gate_env_reused_seed,
    ),
    Fixture(
        "s5.control.gate-env-fresh",
        "control",
        _fixture_gate_env_fresh_control,
    ),
)


class Harness:
    def __init__(self) -> None:
        self.executed_seed_ids: set[str] = set()
        self.passed_seed_ids: set[str] = set()
        self.executed_control_ids: set[str] = set()
        self.failed_control_ids: set[str] = set()
        self.execution_errors: list[str] = []

    def run(self, fixture: Fixture) -> None:
        executed = (
            self.executed_seed_ids
            if fixture.kind == "seed"
            else self.executed_control_ids
        )
        if fixture.fixture_id in executed:
            self.execution_errors.append(f"duplicate execution: {fixture.fixture_id}")
            return
        executed.add(fixture.fixture_id)

        try:
            observation = fixture.run()
            if not isinstance(observation, Observation):
                raise TypeError(
                    f"fixture returned {type(observation).__name__}, not Observation"
                )
        except (
            AssertionError,
            LookupError,
            OSError,
            RuntimeError,
            SyntaxError,
            TypeError,
            ValueError,
            subprocess.SubprocessError,
        ) as error:
            observation = Observation(
                expected="fixture completes",
                got=f"{type(error).__name__}: {error}",
                applied=f"fixture_exception={type(error).__name__}",
            )

        if fixture.kind == "seed":
            if not observation.applied:
                observation = Observation(
                    expected={
                        "observation": observation.expected,
                        "harness": "applied evidence present",
                    },
                    got={
                        "observation": observation.got,
                        "harness": "missing applied evidence",
                    },
                    applied="MISSING",
                )
            print(
                f"SEED {fixture.fixture_id} "
                f"expect={_render(observation.expected)} "
                f"got={_render(observation.got)} "
                f"applied={_render(observation.applied)}"
            )
            if observation.got == observation.expected:
                self.passed_seed_ids.add(fixture.fixture_id)
        elif fixture.kind == "control":
            if observation.got == observation.expected:
                print(f"CONTROL {fixture.fixture_id} PASS")
            else:
                print(
                    f"CONTROL {fixture.fixture_id} FAIL "
                    f"expect={_render(observation.expected)} "
                    f"got={_render(observation.got)}"
                )
                self.failed_control_ids.add(fixture.fixture_id)
        else:
            self.execution_errors.append(
                f"{fixture.fixture_id}: invalid kind {fixture.kind}"
            )


def _print_header() -> None:
    head = subprocess.check_output(
        ["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
        text=True,
    ).strip()
    status = subprocess.run(
        [
            "git",
            "-C",
            REPO_ROOT,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if status.returncode != 0:
        raise RuntimeError(
            f"git status failed with {status.returncode}: {status.stderr.strip()}"
        )
    print(f"HEADER executable={_render(sys.executable)}")
    print(f"HEADER version={_render(sys.version)}")
    print(f"HEADER flags={_render(repr(sys.flags))}")
    print(f"HEADER head={head}")
    print(f"HEADER clean={str(not bool(status.stdout)).lower()}")


def main() -> int:
    try:
        _print_header()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"HARNESS ERROR header={_render(f'{type(error).__name__}: {error}')}")
        return 1

    registered_kinds: dict[str, str] = {}
    duplicate_registered_ids: set[str] = set()
    for fixture in FIXTURES:
        if fixture.fixture_id in registered_kinds:
            duplicate_registered_ids.add(fixture.fixture_id)
        registered_kinds[fixture.fixture_id] = fixture.kind

    harness = Harness()
    if duplicate_registered_ids:
        for fixture_id in sorted(duplicate_registered_ids):
            harness.execution_errors.append(
                f"duplicate registered fixture: {fixture_id}"
            )
    else:
        for fixture in FIXTURES:
            harness.run(fixture)

    audit = _coverage_audit(
        REVIEW_ITEMS,
        harness.executed_seed_ids,
        harness.executed_control_ids,
        registered_kinds,
    )
    for error in audit.configuration_errors:
        print(f"COVERAGE configuration_error={_render(error)}")
    for fixture_id in audit.missing_seed_ids:
        print(f"COVERAGE missing_seed={fixture_id}")
    for fixture_id in audit.missing_control_ids:
        print(f"COVERAGE missing_control={fixture_id}")
    for item in audit.items_without_executed_seed:
        print(f"COVERAGE item_without_executed_seed={item}")
    for fixture_id in audit.unmapped_registered_ids:
        print(f"COVERAGE unmapped_registered_fixture={fixture_id}")
    for error in harness.execution_errors:
        print(f"HARNESS execution_error={_render(error)}")

    missed_seed_ids = harness.executed_seed_ids - harness.passed_seed_ids
    print(
        "TOTAL "
        f"seeds_executed={len(harness.executed_seed_ids)} "
        f"seeds_passed={len(harness.passed_seed_ids)} "
        f"seeds_missed={len(missed_seed_ids)} "
        f"seeds_missing={len(audit.missing_seed_ids)} "
        f"controls_executed={len(harness.executed_control_ids)} "
        f"controls_failed={len(harness.failed_control_ids)} "
        f"controls_missing={len(audit.missing_control_ids)}"
    )

    failed = bool(
        missed_seed_ids
        or harness.failed_control_ids
        or harness.execution_errors
        or not audit.passed
    )
    print("HARNESS FAIL" if failed else "HARNESS PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
