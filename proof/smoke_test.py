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
    DRIVERS_29,
    IdentityError,
    base_env,
    check_identity,
    inspect_pin_inputs,
    probe_atime_observable,
    run_bounded,
    validate_census,
    write_pin,
)
from proof.run_proof import cmd_plan, fresh_stage_env
import proof.artifact_legs as legs_mod
import proof.proofkit as proofkit_mod
import proof.roundtrip_shim as shim_mod
import proof.run_proof as stages_mod


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
        if basename == "smoke_test.py":
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
            DRIVERS_29,
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
                    DRIVERS_29,
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


_O3_HISTORICAL_REF = "1f292c3424a8185d05a87d3dc82f73549dfe4878"


def _census_case(driver: str) -> tuple[dict, bytes, str]:
    census_path = os.path.join(REPO_ROOT, "proof", "census", f"{driver}.json")
    with open(census_path, "r", encoding="utf-8") as census_file:
        census = json.load(census_file)
    if not isinstance(census, dict):
        raise TypeError(f"{driver} census is not an object")
    script_relpath = census.get("script")
    if not isinstance(script_relpath, str):
        raise TypeError(f"{driver} census script is not a string")
    script_path = os.path.join(REPO_ROOT, script_relpath)
    with open(script_path, "rb") as script_file:
        script_bytes = script_file.read()
    return census, script_bytes, script_relpath


def _script_lines(script_bytes: bytes) -> list[str]:
    return script_bytes.decode("utf-8").splitlines(keepends=True)


def _line_text(source_line: str) -> str:
    if source_line.endswith("\r\n"):
        return source_line[:-2]
    if source_line.endswith("\n") or source_line.endswith("\r"):
        return source_line[:-1]
    return source_line


def _clone_census(census: dict) -> dict:
    return json.loads(json.dumps(census))


def _rule_ids(violations: list[tuple[str, int, str]]) -> list[str]:
    return sorted({rule_id for rule_id, _line, _detail in violations})


def _find_passing_census(
    purpose: str,
    predicate: Callable[[dict, list[str]], bool],
) -> tuple[str, dict, bytes, str]:
    invalid: dict[str, list[str]] = {}
    for driver in DRIVERS_29:
        census, script_bytes, script_relpath = _census_case(driver)
        violations = validate_census(census, script_bytes, script_relpath)
        if violations:
            invalid[driver] = _rule_ids(violations)
            continue
        lines = _script_lines(script_bytes)
        if predicate(census, lines):
            return driver, census, script_bytes, script_relpath
    raise RuntimeError(
        f"no passing census supports {purpose}; invalid={_render(invalid)}"
    )


def _isolated_validator_seed(
    target_rule: str,
    purpose: str,
    predicate: Callable[[dict, list[str]], bool],
    mutate: Callable[[dict, list[str], str], tuple[str, int]],
    *,
    update_sha: bool = True,
) -> Observation:
    driver, census, script_bytes, script_relpath = _find_passing_census(
        purpose,
        predicate,
    )
    with tempfile.TemporaryDirectory(
        prefix=f"iyi-o3-{driver}-",
        dir="/tmp",
    ) as scratch:
        census_path = os.path.join(scratch, f"{driver}.json")
        script_path = os.path.join(scratch, os.path.basename(script_relpath))
        with open(census_path, "w", encoding="utf-8") as census_file:
            json.dump(census, census_file, indent=2, sort_keys=True)
            census_file.write("\n")
        with open(script_path, "wb") as script_file:
            script_file.write(script_bytes)

        with open(census_path, "r", encoding="utf-8") as census_file:
            control_census = json.load(census_file)
        with open(script_path, "rb") as script_file:
            control_script = script_file.read()
        control_ids = _rule_ids(
            validate_census(
                control_census,
                control_script,
                script_relpath,
            )
        )

        seed_census = _clone_census(control_census)
        seed_lines = _script_lines(control_script)
        census_before = json.dumps(
            seed_census,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        script_before = b"".join(line.encode() for line in seed_lines)
        label, applied_count = mutate(seed_census, seed_lines, driver)
        if applied_count != 1:
            raise RuntimeError(
                f"{purpose} applied {applied_count} changes, expected 1"
            )
        seed_script = b"".join(line.encode() for line in seed_lines)
        if update_sha:
            seed_census["script_sha256"] = hashlib.sha256(
                seed_script
            ).hexdigest()
        census_after = json.dumps(
            seed_census,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        census_changed = census_after != census_before
        script_changed = seed_script != script_before
        if not census_changed and not script_changed:
            raise RuntimeError(f"{purpose} did not change the copied case")

        with open(census_path, "w", encoding="utf-8") as census_file:
            json.dump(seed_census, census_file, indent=2, sort_keys=True)
            census_file.write("\n")
        with open(script_path, "wb") as script_file:
            script_file.write(seed_script)
        with open(census_path, "r", encoding="utf-8") as census_file:
            applied_census = json.load(census_file)
        with open(script_path, "rb") as script_file:
            applied_script = script_file.read()
        seed_ids = _rule_ids(
            validate_census(
                applied_census,
                applied_script,
                script_relpath,
            )
        )

    expected = {"control": [], "seed": [target_rule]}
    got = {"control": control_ids, "seed": seed_ids}
    applied = (
        f"{label};driver={driver};count={applied_count};"
        f"census_changed={str(census_changed).lower()};"
        f"script_changed={str(script_changed).lower()}"
    )
    return Observation(expected=expected, got=got, applied=applied)


def _combine_seed_observations(
    cases: tuple[tuple[str, Observation], ...],
) -> Observation:
    expected = {name: observation.expected for name, observation in cases}
    got = {name: observation.got for name, observation in cases}
    applied = ";".join(
        f"{name}[{observation.applied}]" for name, observation in cases
    )
    return Observation(expected=expected, got=got, applied=applied)


def _each_variant(census: dict):
    for site in census.get("sites", []):
        for variant in site.get("variants", []):
            yield site, variant


def _site_lines(census: dict) -> set[int]:
    return {
        number
        for site in census.get("sites", [])
        for number in site.get("lines", [])
        if isinstance(number, int)
    }


def _non_skip_references(census: dict) -> set[int]:
    references = set(_site_lines(census))
    sentinel = census.get("pass_sentinel", {})
    if isinstance(sentinel.get("line"), int):
        references.add(sentinel["line"])
    for _site, variant in _each_variant(census):
        for variable in variant.get("vars", {}).values():
            references.update(
                number
                for number in variable.get("lines", [])
                if isinstance(number, int)
            )
            reason_line = variable.get("pattern_reason_line")
            if isinstance(reason_line, int):
                references.add(reason_line)
        references.update(
            number
            for number in variant.get("verdict", {}).get("lines", [])
            if isinstance(number, int)
        )
    for evidence in census.get("exec_evidence", []):
        if isinstance(evidence.get("site_line"), int):
            references.add(evidence["site_line"])
        references.update(
            number
            for number in evidence.get("exec_lines", [])
            if isinstance(number, int)
        )
        references.update(
            number
            for number in evidence.get("verdict_lines", [])
            if isinstance(number, int)
        )
        references.update(
            int(number)
            for number in evidence.get("name_from_calls", {})
            if isinstance(number, str) and number.isdigit()
        )
        references.update(
            reference["line"]
            for reference in evidence.get("refs_ok", [])
            if isinstance(reference, dict)
            and isinstance(reference.get("line"), int)
        )
    return references


def _insert_before_final_exit(
    lines: list[str],
    additions: list[str],
) -> int:
    nonblank = [
        index for index, source in enumerate(lines) if source.strip()
    ]
    if not nonblank:
        raise RuntimeError("driver has no non-blank lines")
    exit_index = nonblank[-1]
    if _line_text(lines[exit_index]) != "exit $status":
        raise RuntimeError("driver does not end in exact exit $status")
    newline = "\r\n" if lines[exit_index].endswith("\r\n") else "\n"
    lines[exit_index:exit_index] = [
        addition + newline for addition in additions
    ]
    return exit_index + 1


def _site_kind_for_line(census: dict, line: int) -> str | None:
    for site in census.get("sites", []):
        if line in site.get("lines", []):
            kind = site.get("kind")
            return kind if isinstance(kind, str) else None
    return None

def _has_any_site(census: dict, _lines: list[str]) -> bool:
    return bool(census.get("sites"))


def _has_indented_text(census: dict, _lines: list[str]) -> bool:
    entries = [
        *census.get("skips", []),
        *census.get("not_skips", []),
        census.get("pass_sentinel", {}),
    ]
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("text"), str)
        and entry["text"].startswith((" ", "\t"))
        for entry in entries
    )


def _has_contains(census: dict, _lines: list[str]) -> bool:
    return any(site.get("contains") for site in census.get("sites", []))


def _has_variant_verdict(census: dict, _lines: list[str]) -> bool:
    return any(
        variant.get("verdict", {}).get("contains")
        for _site, variant in _each_variant(census)
    )


def _has_enumerated_variable(census: dict, _lines: list[str]) -> bool:
    return any(
        variable.get("values")
        for _site, variant in _each_variant(census)
        for variable in variant.get("vars", {}).values()
    )


def _has_skip(census: dict, _lines: list[str]) -> bool:
    return bool(census.get("skips"))


def _has_listed_skip(census: dict, _lines: list[str]) -> bool:
    return bool(census.get("skips") or census.get("not_skips"))


def _has_unrenderable_candidate(census: dict, lines: list[str]) -> bool:
    excluded = _non_skip_references(census)
    return any(
        isinstance(entry.get("line"), int)
        and 1 <= entry["line"] <= len(lines)
        and entry["line"] not in excluded
        for entry in census.get("skips", [])
    )


def _has_sentinel(census: dict, _lines: list[str]) -> bool:
    return isinstance(census.get("pass_sentinel"), dict)


def _has_nonvariant_aux_site(census: dict, _lines: list[str]) -> bool:
    evidence_sites = {
        evidence.get("site_line")
        for evidence in census.get("exec_evidence", [])
    }
    return any(
        site.get("kind") in ("canonical-other", "unchanged", "passthrough")
        and not site.get("variants")
        and site.get("lines")
        and site["lines"][0] not in evidence_sites
        for site in census.get("sites", [])
    )


def _has_variant_template(census: dict, _lines: list[str]) -> bool:
    return any(True for _site, _variant in _each_variant(census))


def _has_unique_positive_evidence(
    census: dict,
    _lines: list[str],
) -> bool:
    evidences = census.get("exec_evidence", [])
    token_counts: dict[str, int] = {}
    for evidence in evidences:
        token = evidence.get("exec_token")
        if isinstance(token, str):
            token_counts[token] = token_counts.get(token, 0) + 1
    return any(
        _site_kind_for_line(census, evidence.get("site_line")) == "positive"
        and token_counts.get(evidence.get("exec_token")) == 1
        for evidence in evidences
    )


def _has_exec_token_candidate(census: dict, lines: list[str]) -> bool:
    site_lines = _site_lines(census)
    for evidence in census.get("exec_evidence", []):
        token = evidence.get("exec_token")
        excluded = {
            *site_lines,
            *evidence.get("verdict_lines", []),
            *(
                int(number)
                for number in evidence.get("name_from_calls", {})
                if isinstance(number, str) and number.isdigit()
            ),
            *(
                reference.get("line")
                for reference in evidence.get("refs_ok", [])
                if isinstance(reference, dict)
            ),
        }
        for number in evidence.get("exec_lines", []):
            if (
                isinstance(token, str)
                and isinstance(number, int)
                and 1 <= number <= len(lines)
                and number not in excluded
                and lines[number - 1].count(token) == 1
            ):
                return True
    return False


def _has_evidence(census: dict, _lines: list[str]) -> bool:
    return bool(census.get("exec_evidence"))


def _has_verdict_mark_candidate(census: dict, lines: list[str]) -> bool:
    excluded = set(_site_lines(census))
    for _site, variant in _each_variant(census):
        excluded.update(variant.get("verdict", {}).get("lines", []))
    for evidence in census.get("exec_evidence", []):
        marks = evidence.get("failure_marks", [])
        for number in evidence.get("verdict_lines", []):
            if (
                not isinstance(number, int)
                or not 1 <= number <= len(lines)
                or number in excluded
            ):
                continue
            source = lines[number - 1]
            present = [mark for mark in marks if mark in source]
            if len(present) == 1 and source.count(present[0]) == 1:
                return True
    return False


def _has_name_token_evidence(census: dict, _lines: list[str]) -> bool:
    return any(
        evidence.get("exec_token") == '"$WORK/$name"'
        and evidence.get("out_template") == "{WORK}/{name}"
        for evidence in census.get("exec_evidence", [])
    )


def _mutate_schema_unknown(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    census["o3_unknown_key"] = True
    return "schema-unknown-key", 1


def _mutate_schema_malformed(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    census["sites"][0]["contains"] = None
    return "schema-malformed-contains", 1


def _mutate_text_indentation(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    entries = [
        *census.get("skips", []),
        *census.get("not_skips", []),
        census.get("pass_sentinel", {}),
    ]
    for entry in entries:
        text = entry.get("text")
        if isinstance(text, str) and text.startswith((" ", "\t")):
            entry["text"] = text[1:]
            return f"text-indentation-line-{entry.get('line')}", 1
    return "text-indentation-not-applied", 0


def _mutate_sha(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    census["script_sha256"] = "0" * 64
    return "sha-replaced", 1


def _mutate_unlisted_invocation(
    _census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    line = _insert_before_final_exit(
        lines,
        ['"$IYI" --version >/dev/null'],
    )
    return f"unlisted-invocation-line-{line}", 1


def _mutate_duplicate_site(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    line = census["sites"][0]["lines"][0]
    census["sites"][0]["lines"].append(line)
    return f"duplicate-site-line-{line}", 1


def _mutate_contains(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for site in census.get("sites", []):
        if site.get("contains"):
            site["contains"][0] = "__O3_MISSING_CONTAINS__"
            return f"contains-site-{site['lines'][0]}", 1
    return "contains-not-applied", 0


def _mutate_verdict_literal(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for site, variant in _each_variant(census):
        contains = variant.get("verdict", {}).get("contains", [])
        if contains:
            contains[0] = "__O3_MISSING_VERDICT_LITERAL__"
            return (
                f"verdict-literal-{variant.get('id')}-site-"
                f"{site['lines'][0]}",
                1,
            )
    return "verdict-literal-not-applied", 0


def _mutate_var_range(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for _site, variant in _each_variant(census):
        for name, variable in variant.get("vars", {}).items():
            values = variable.get("values", [])
            if values:
                values[0] = "__O3_VALUE_ABSENT_FROM_SOURCE__"
                return f"var-range-{variant.get('id')}-{name}", 1
    return "var-range-not-applied", 0


def _mutate_unlisted_skip(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for key in ("skips", "not_skips"):
        if census.get(key):
            removed = census[key].pop(0)
            return f"unlisted-skip-{key}-line-{removed['line']}", 1
    return "unlisted-skip-not-applied", 0


def _mutate_skip_regex(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    entry = census["skips"][0]
    entry["regex"] = "(?!)"
    return f"skip-regex-line-{entry['line']}", 1


def _mutate_unrenderable(
    census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    excluded = _non_skip_references(census)
    for entry in census.get("skips", []):
        number = entry.get("line")
        if (
            not isinstance(number, int)
            or not 1 <= number <= len(lines)
            or number in excluded
        ):
            continue
        old_line = lines[number - 1]
        old_text = _line_text(old_line)
        indent = old_text[: len(old_text) - len(old_text.lstrip())]
        newline = old_line[len(old_text):]
        replacement = f'{indent}echo "skip'
        lines[number - 1] = replacement + newline
        entry["text"] = replacement
        return f"unrenderable-line-{number}", 1
    return "unrenderable-not-applied", 0


def _mutate_sentinel(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    line = census["pass_sentinel"]["line"]
    census["pass_sentinel"]["regex"] = "(?!)"
    return f"sentinel-regex-line-{line}", 1


def _mutate_kind_variants(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    evidence_sites = {
        evidence.get("site_line")
        for evidence in census.get("exec_evidence", [])
    }
    for site in census.get("sites", []):
        if (
            site.get("kind") in (
                "canonical-other",
                "unchanged",
                "passthrough",
            )
            and not site.get("variants")
            and site.get("lines")
            and site["lines"][0] not in evidence_sites
        ):
            site["kind"] = "negative"
            return f"kind-variants-site-{site['lines'][0]}", 1
    return "kind-variants-not-applied", 0


def _mutate_template(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for site, variant in _each_variant(census):
        variant["first_root"] += "$O3"
        return (
            f"template-{variant.get('id')}-site-{site['lines'][0]}",
            1,
        )
    return "template-not-applied", 0


def _mutate_e1_missing(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    evidences = census.get("exec_evidence", [])
    token_counts: dict[str, int] = {}
    for evidence in evidences:
        token = evidence.get("exec_token")
        if isinstance(token, str):
            token_counts[token] = token_counts.get(token, 0) + 1
    for index, evidence in enumerate(evidences):
        if (
            _site_kind_for_line(census, evidence.get("site_line"))
            == "positive"
            and token_counts.get(evidence.get("exec_token")) == 1
        ):
            removed = evidences.pop(index)
            return f"e1-missing-site-{removed['site_line']}", 1
    return "e1-missing-not-applied", 0


def _mutate_e1_token(
    census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    site_lines = _site_lines(census)
    for evidence in census.get("exec_evidence", []):
        token = evidence.get("exec_token")
        excluded = {
            *site_lines,
            *evidence.get("verdict_lines", []),
            *(
                int(number)
                for number in evidence.get("name_from_calls", {})
                if isinstance(number, str) and number.isdigit()
            ),
            *(
                reference.get("line")
                for reference in evidence.get("refs_ok", [])
                if isinstance(reference, dict)
            ),
        }
        for number in evidence.get("exec_lines", []):
            if (
                isinstance(token, str)
                and isinstance(number, int)
                and 1 <= number <= len(lines)
                and number not in excluded
                and lines[number - 1].count(token) == 1
            ):
                lines[number - 1] = lines[number - 1].replace(
                    token,
                    '"/tmp/o3-exec-token-removed"',
                    1,
                )
                return f"e1-token-line-{number}", 1
    return "e1-token-not-applied", 0


def _mutate_e1_stray_read(
    census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    token = census["exec_evidence"][0]["exec_token"]
    number = _insert_before_final_exit(
        lines,
        [f"shasum {token} >/dev/null"],
    )
    return f"e1-undeclared-read-line-{number}-token-{token}", 1


def _mutate_e1_undeclared_build(
    census: dict,
    lines: list[str],
    driver: str,
) -> tuple[str, int]:
    base = next(
        evidence
        for evidence in census.get("exec_evidence", [])
        if evidence.get("exec_token") == '"$WORK/$name"'
        and evidence.get("out_template") == "{WORK}/{name}"
    )
    build_line = _insert_before_final_exit(
        lines,
        [
            (
                '"$IYI" build -o "$WORK/$name" '
                f'"$REPO/bench/std_{driver}_exercise.iyi"'
            )
        ],
    )
    census["non_invocations"].append(
        {
            "line": build_line,
            "reason": "O3 seed: compiler output site is not declared",
        }
    )
    return (
        f"e1-undeclared-build-line-{build_line}-token-{base['exec_token']}",
        1,
    )


def _mutate_e1_verdict(
    census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    excluded = set(_site_lines(census))
    for _site, variant in _each_variant(census):
        excluded.update(variant.get("verdict", {}).get("lines", []))
    for evidence in census.get("exec_evidence", []):
        marks = evidence.get("failure_marks", [])
        for number in evidence.get("verdict_lines", []):
            if (
                not isinstance(number, int)
                or not 1 <= number <= len(lines)
                or number in excluded
            ):
                continue
            source = lines[number - 1]
            present = [mark for mark in marks if mark in source]
            if len(present) == 1 and source.count(present[0]) == 1:
                lines[number - 1] = source.replace(
                    present[0],
                    "o3_no_failure_mark",
                    1,
                )
                return f"e1-verdict-line-{number}", 1
    return "e1-verdict-not-applied", 0


def _mutate_e1_exit(
    _census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    nonblank = [
        index for index, source in enumerate(lines) if source.strip()
    ]
    if not nonblank:
        return "e1-exit-not-applied", 0
    index = nonblank[-1]
    old_text = _line_text(lines[index])
    if old_text != "exit $status":
        return "e1-exit-not-applied", 0
    newline = lines[index][len(old_text):]
    lines[index] = "exit 0" + newline
    return f"e1-exit-line-{index + 1}", 1

def _fixture_validator_schema_seed() -> Observation:
    return _combine_seed_observations(
        (
            (
                "unknown-key",
                _isolated_validator_seed(
                    "C5.0-schema",
                    "closed top-level schema",
                    _has_any_site,
                    _mutate_schema_unknown,
                ),
            ),
            (
                "malformed-nested-value",
                _isolated_validator_seed(
                    "C5.0-schema",
                    "malformed nested schema",
                    _has_any_site,
                    _mutate_schema_malformed,
                ),
            ),
            (
                "exact-text-indentation",
                _isolated_validator_seed(
                    "C5.0-schema",
                    "byte-exact text indentation",
                    _has_indented_text,
                    _mutate_text_indentation,
                ),
            ),
        )
    )


def _fixture_validator_rule_seed(
    target_rule: str,
    purpose: str,
    predicate: Callable[[dict, list[str]], bool],
    mutate: Callable[[dict, list[str], str], tuple[str, int]],
    *,
    update_sha: bool = True,
) -> Observation:
    return _isolated_validator_seed(
        target_rule,
        purpose,
        predicate,
        mutate,
        update_sha=update_sha,
    )


def _fixture_validator_e1_stray_seed() -> Observation:
    return _combine_seed_observations(
        (
            (
                "undeclared-read",
                _isolated_validator_seed(
                    "E1-stray-reference",
                    "undeclared read of an exact execution token",
                    _has_evidence,
                    _mutate_e1_stray_read,
                ),
            ),
            (
                "undeclared-build-self-evidence",
                _isolated_validator_seed(
                    "E1-stray-reference",
                    "undeclared compiler build self-legitimized by evidence",
                    _has_name_token_evidence,
                    _mutate_e1_undeclared_build,
                ),
            ),
        )
    )


def _fixture_census_all_control() -> Observation:
    violations_by_driver: dict[str, list[tuple[str, int, str]]] = {}
    for driver in DRIVERS_29:
        census, script_bytes, script_relpath = _census_case(driver)
        violations = validate_census(census, script_bytes, script_relpath)
        if violations:
            violations_by_driver[driver] = violations
            for violation in violations:
                print(
                    "O3-CENSUS "
                    f"driver={driver} violation={_render(violation)}"
                )
    expected = {
        "drivers": list(DRIVERS_29),
        "violations": {},
    }
    got = {
        "drivers": list(DRIVERS_29),
        "violations": violations_by_driver,
    }
    return Observation(expected=expected, got=got)


def _fixture_e1_shared_token_control() -> Observation:
    census, script_bytes, script_relpath = _census_case("cookie")
    violations = validate_census(census, script_bytes, script_relpath)
    token = '"$WORK/$name"'
    blocks = sorted(
        (
            evidence.get("site_line"),
            list(evidence.get("exec_lines", [])),
        )
        for evidence in census.get("exec_evidence", [])
        if evidence.get("exec_token") == token
    )
    expected = {
        "violations": [],
        "token": token,
        "blocks": [(46, [53]), (85, [91])],
    }
    got = {
        "violations": _rule_ids(violations),
        "token": token,
        "blocks": blocks,
    }
    return Observation(expected=expected, got=got)






def _git_show_bytes(ref: str, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", REPO_ROOT, "show", f"{ref}:{path}"],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git show failed for {path}: "
            f"{completed.stderr.decode(errors='replace').strip()}"
        )
    return completed.stdout


def _nested_type_control(
    driver: str,
) -> tuple[dict, bytes, str]:
    census, script_bytes, script_relpath = _census_case(driver)
    if driver == "file" and not census["non_invocations"]:
        evidence_sites = {
            evidence.get("site_line")
            for evidence in census["exec_evidence"]
            if isinstance(evidence, dict)
        }
        auxiliary_index = next(
            index
            for index, site in enumerate(census["sites"])
            if site.get("kind")
            in ("canonical-other", "unchanged", "passthrough")
            and site.get("lines")
            and site["lines"][0] not in evidence_sites
        )
        auxiliary = census["sites"].pop(auxiliary_index)
        census["non_invocations"].extend(
            {
                "line": number,
                "reason": "nested-type control reclassifies an auxiliary invocation",
            }
            for number in auxiliary["lines"]
        )
    control_rules = _rule_ids(
        validate_census(census, script_bytes, script_relpath)
    )
    if control_rules:
        raise RuntimeError(
            f"nested-type {driver} control is invalid: {control_rules}"
        )
    return census, script_bytes, script_relpath


def _nested_type_cases(
    census: dict,
) -> tuple[tuple[str, Callable[[dict], None]], ...]:
    def set_path(*path: object, value: object) -> Callable[[dict], None]:
        def mutate(document: dict) -> None:
            current: object = document
            for segment in path[:-1]:
                current = current[segment]  # type: ignore[index]
            current[path[-1]] = value  # type: ignore[index]

        return mutate

    def append_path(*path: object, value: object) -> Callable[[dict], None]:
        def mutate(document: dict) -> None:
            current: object = document
            for segment in path:
                current = current[segment]  # type: ignore[index]
            current.append(value)  # type: ignore[union-attr]

        return mutate

    variant_site, variant_index, variable_name = next(
        (site_index, item_index, name)
        for site_index, site in enumerate(census["sites"])
        for item_index, variant in enumerate(site["variants"])
        for name, variable in variant["vars"].items()
        if isinstance(variable, dict)
        and isinstance(variable.get("values"), list)
        and variable["values"]
    )
    variant_path = ("sites", variant_site, "variants", variant_index)
    variable_path = (*variant_path, "vars", variable_name)
    return (
        ("census_version.type", set_path("census_version", value="x")),
        ("driver.type", set_path("driver", value=1)),
        ("script.type", set_path("script", value=1)),
        ("script_sha256.type", set_path("script_sha256", value=1)),
        ("sites.type", set_path("sites", value="x")),
        ("sites.append", append_path("sites", value="x")),
        ("non_invocations.type", set_path("non_invocations", value="x")),
        ("non_invocations.append", append_path("non_invocations", value="x")),
        (
            "non_invocations.line.type",
            set_path("non_invocations", 0, "line", value="x"),
        ),
        (
            "non_invocations.reason.type",
            set_path("non_invocations", 0, "reason", value=1),
        ),
        ("skips.type", set_path("skips", value="x")),
        ("skips.append", append_path("skips", value="x")),
        ("skip.line.type", set_path("skips", 0, "line", value="x")),
        ("skip.class.type", set_path("skips", 0, "class", value=1)),
        ("skip.what.type", set_path("skips", 0, "what", value=1)),
        ("skip.regex.type", set_path("skips", 0, "regex", value=1)),
        ("skip.text.type", set_path("skips", 0, "text", value=1)),
        ("not_skips.type", set_path("not_skips", value="x")),
        ("not_skips.append", append_path("not_skips", value="x")),
        (
            "not_skips.line.type",
            set_path("not_skips", 0, "line", value="x"),
        ),
        (
            "not_skips.reason.type",
            set_path("not_skips", 0, "reason", value=1),
        ),
        (
            "not_skips.text.type",
            set_path("not_skips", 0, "text", value=1),
        ),
        ("pass_sentinel.type", set_path("pass_sentinel", value="x")),
        (
            "pass_sentinel.line.type",
            set_path("pass_sentinel", "line", value="x"),
        ),
        (
            "pass_sentinel.regex.type",
            set_path("pass_sentinel", "regex", value=1),
        ),
        (
            "pass_sentinel.text.type",
            set_path("pass_sentinel", "text", value=1),
        ),
        ("exec_evidence.type", set_path("exec_evidence", value="x")),
        ("exec_evidence.append", append_path("exec_evidence", value="x")),
        ("site.lines.type", set_path("sites", 0, "lines", value="x")),
        ("site.lines.append", append_path("sites", 0, "lines", value="x")),
        ("site.command.type", set_path("sites", 0, "command", value=1)),
        ("site.kind.type", set_path("sites", 0, "kind", value=1)),
        ("site.contains.type", set_path("sites", 0, "contains", value="x")),
        ("site.contains.append", append_path("sites", 0, "contains", value=1)),
        ("site.variants.type", set_path("sites", 0, "variants", value="x")),
        ("site.variants.append", append_path("sites", 0, "variants", value="x")),
        ("variant.id.type", set_path(*variant_path, "id", value=1)),
        ("variant.kind.type", set_path(*variant_path, "kind", value=1)),
        ("variant.vars.type", set_path(*variant_path, "vars", value="x")),
        ("variant.var.type", set_path(*variable_path, value="x")),
        (
            "variant.var.lines.type",
            set_path(*variable_path, "lines", value="x"),
        ),
        (
            "variant.var.values.type",
            set_path(*variable_path, "values", value="x"),
        ),
        (
            "variant.var.values.append",
            append_path(*variable_path, "values", value=1),
        ),
        (
            "variant.sources.type",
            set_path(*variant_path, "sources", value="x"),
        ),
        (
            "variant.sources.append",
            append_path(*variant_path, "sources", value=1),
        ),
        (
            "variant.requires.type",
            set_path(*variant_path, "requires", value="x"),
        ),
        (
            "variant.requires.append",
            append_path(*variant_path, "requires", value=1),
        ),
        (
            "variant.verdict.type",
            set_path(*variant_path, "verdict", value="x"),
        ),
        (
            "variant.verdict.lines.type",
            set_path(*variant_path, "verdict", "lines", value="x"),
        ),
        (
            "variant.verdict.lines.append",
            append_path(*variant_path, "verdict", "lines", value="x"),
        ),
        (
            "variant.verdict.contains.type",
            set_path(*variant_path, "verdict", "contains", value="x"),
        ),
        (
            "variant.verdict.contains.append",
            append_path(*variant_path, "verdict", "contains", value=1),
        ),
        (
            "variant.first_root.type",
            set_path(*variant_path, "first_root", value=1),
        ),
        (
            "variant.output.type",
            set_path(*variant_path, "output", value=1),
        ),
        (
            "variant.darwin.type",
            set_path(*variant_path, "darwin", value=1),
        ),
        (
            "evidence.site_line.type",
            set_path("exec_evidence", 0, "site_line", value="x"),
        ),
        (
            "evidence.out_template.type",
            set_path("exec_evidence", 0, "out_template", value=1),
        ),
        (
            "evidence.exec_token.type",
            set_path("exec_evidence", 0, "exec_token", value=1),
        ),
        (
            "evidence.name_from_calls.type",
            set_path("exec_evidence", 0, "name_from_calls", value="x"),
        ),
        (
            "evidence.name_from_calls.append",
            set_path("exec_evidence", 0, "name_from_calls", "x", value=1),
        ),
        (
            "evidence.exec_lines.type",
            set_path("exec_evidence", 0, "exec_lines", value="x"),
        ),
        (
            "evidence.exec_lines.append",
            append_path("exec_evidence", 0, "exec_lines", value="x"),
        ),
        (
            "evidence.verdict_lines.type",
            set_path("exec_evidence", 0, "verdict_lines", value="x"),
        ),
        (
            "evidence.verdict_lines.append",
            append_path("exec_evidence", 0, "verdict_lines", value="x"),
        ),
        (
            "evidence.failure_marks.type",
            set_path("exec_evidence", 0, "failure_marks", value="x"),
        ),
        (
            "evidence.failure_marks.append",
            append_path("exec_evidence", 0, "failure_marks", value=1),
        ),
        (
            "evidence.refs_ok.type",
            set_path("exec_evidence", 0, "refs_ok", value="x"),
        ),
        (
            "evidence.refs_ok.append",
            append_path("exec_evidence", 0, "refs_ok", value="x"),
        ),
    )


def _fixture_validator_nested_types_seed() -> Observation:
    census, script_bytes, script_relpath = _nested_type_control("file")
    outcomes: dict[str, dict[str, bool]] = {}
    applied: list[str] = []
    cases = _nested_type_cases(census)
    for label, mutate in cases:
        changed = _clone_census(census)
        before = json.dumps(changed, sort_keys=True, separators=(",", ":"))
        mutate(changed)
        after = json.dumps(changed, sort_keys=True, separators=(",", ":"))
        if before == after:
            raise RuntimeError(f"nested-type mutation did not change {label}")
        raised = False
        violations: object
        try:
            violations = validate_census(changed, script_bytes, script_relpath)
        except Exception:
            raised = True
            violations = []
        tuples = (
            isinstance(violations, list)
            and all(
                isinstance(item, tuple) and len(item) == 3
                for item in violations
            )
        )
        schema = (
            isinstance(violations, list)
            and any(item[0] == "C5.0-schema" for item in violations)
        )
        outcomes[label] = {
            "raised": raised,
            "tuples": tuples,
            "schema": schema,
        }
        applied.append(f"{label}:{str(before != after).lower()}")

    pattern_census, pattern_script, pattern_relpath = _nested_type_control(
        "compress"
    )
    pattern_site, pattern_variant, pattern_name = next(
        (site_index, variant_index, name)
        for site_index, site in enumerate(pattern_census["sites"])
        for variant_index, variant in enumerate(site["variants"])
        for name, variable in variant["vars"].items()
        if isinstance(variable, dict) and "pattern" in variable
    )
    for label, field in (
        ("variant.var.pattern.type", "pattern"),
        ("variant.var.pattern_reason_line.type", "pattern_reason_line"),
    ):
        changed = _clone_census(pattern_census)
        variable = changed["sites"][pattern_site]["variants"][pattern_variant][
            "vars"
        ][pattern_name]
        variable[field] = 1 if field == "pattern" else "x"
        raised = False
        violations = []
        try:
            violations = validate_census(
                changed,
                pattern_script,
                pattern_relpath,
            )
        except Exception:
            raised = True
        outcomes[label] = {
            "raised": raised,
            "tuples": all(
                isinstance(item, tuple) and len(item) == 3
                for item in violations
            ),
            "schema": any(
                item[0] == "C5.0-schema" for item in violations
            ),
        }
        applied.append(f"{label}:true")

    cleanup_census, cleanup_script, cleanup_relpath = _nested_type_control(
        "http"
    )
    cleanup_evidence = next(
        index
        for index, evidence in enumerate(cleanup_census["exec_evidence"])
        if evidence["refs_ok"]
    )
    for label, field, value in (
        ("evidence.refs_ok.line.type", "line", "x"),
        ("evidence.refs_ok.kind.type", "kind", 1),
    ):
        changed = _clone_census(cleanup_census)
        changed["exec_evidence"][cleanup_evidence]["refs_ok"][0][field] = value
        raised = False
        violations = []
        try:
            violations = validate_census(
                changed,
                cleanup_script,
                cleanup_relpath,
            )
        except Exception:
            raised = True
        outcomes[label] = {
            "raised": raised,
            "tuples": all(
                isinstance(item, tuple) and len(item) == 3
                for item in violations
            ),
            "schema": any(
                item[0] == "C5.0-schema" for item in violations
            ),
        }
        applied.append(f"{label}:true")

    expected_item = {"raised": False, "tuples": True, "schema": True}
    expected = {label: expected_item for label, _mutate in cases}
    expected["variant.var.pattern.type"] = expected_item
    expected["variant.var.pattern_reason_line.type"] = expected_item
    expected["evidence.refs_ok.line.type"] = expected_item
    expected["evidence.refs_ok.kind.type"] = expected_item
    return Observation(
        expected=expected,
        got=outcomes,
        applied=";".join(applied),
    )

def _copied_validator_rules(
    census: dict,
    script_bytes: bytes,
    script_relpath: str,
    prefix: str,
) -> list[str]:
    with tempfile.TemporaryDirectory(prefix=prefix, dir="/tmp") as scratch:
        census_path = os.path.join(scratch, "census.json")
        script_path = os.path.join(scratch, os.path.basename(script_relpath))
        with open(census_path, "w", encoding="utf-8") as census_file:
            json.dump(census, census_file, indent=2, sort_keys=True)
            census_file.write("\n")
        with open(script_path, "wb") as script_file:
            script_file.write(script_bytes)
        with open(census_path, "r", encoding="utf-8") as census_file:
            copied_census = json.load(census_file)
        with open(script_path, "rb") as script_file:
            copied_script = script_file.read()
        return _rule_ids(
            validate_census(copied_census, copied_script, script_relpath)
        )



def _uncited_blank_line(census: dict, lines: list[str]) -> int:
    excluded = _non_skip_references(census)
    for key in ("non_invocations", "skips", "not_skips"):
        excluded.update(
            entry["line"]
            for entry in census.get(key, [])
            if isinstance(entry, dict) and isinstance(entry.get("line"), int)
        )
    return next(
        number
        for number, source in enumerate(lines, 1)
        if not source.strip() and number not in excluded
    )


def _print_fixture(
    source: str,
    *,
    listed: bool,
    regex: str = "",
) -> Observation:
    census, script_bytes, script_relpath = _census_case("compress")
    lines = script_bytes.decode().splitlines()
    number = _uncited_blank_line(census, lines)
    lines[number - 1] = source
    if listed:
        census["skips"].append(
            {
                "line": number,
                "class": "tool",
                "what": "synthetic",
                "regex": regex,
                "text": source,
            }
        )
    changed_script = ("\n".join(lines) + "\n").encode()
    census["script_sha256"] = hashlib.sha256(changed_script).hexdigest()
    return Observation(
        expected=[],
        got=_copied_validator_rules(
            census,
            changed_script,
            script_relpath,
            "iyi-o3-print-",
        ),
        applied=f"line={number};listed={str(listed).lower()}",
    )


def _fixture_print_capture_control() -> Observation:
    return _print_fixture(
        """  unasked="$(printf '%s\\n' "$said" | grep -m1 '^s_server never listened')" """.rstrip(),
        listed=False,
    )


def _fixture_print_capture_seed() -> Observation:
    observation = _print_fixture(
        '  msg="$(echo "skipped: no tool")"',
        listed=False,
    )
    return Observation(
        expected=["C5.4-unlisted-skip-line"],
        got=observation.got,
        applied=observation.applied,
    )


def _fixture_print_case_control() -> Observation:
    return _print_fixture(
        '    *) echo "  the arm: not run here, because $(uname -m) never runs it" ;;',
        listed=True,
        regex=r"^  the arm: not run here, because .* never runs it$",
    )


def _fixture_print_case_regex_seed() -> Observation:
    observation = _print_fixture(
        '    *) echo "  the arm: not run here, because $(uname -m) never runs it" ;;',
        listed=True,
        regex=r"^  the arm: not run here, because .* never runs it ;;$",
    )
    return Observation(
        expected=["C5.4-skip-regex"],
        got=observation.got,
        applied=observation.applied,
    )


def _fixture_print_quoted_punct_control() -> Observation:
    quoted_punctuation = _print_fixture(
        '  echo "a ;; b: skipped"',
        listed=True,
        regex=r"^a ;; b: skipped$",
    )
    unquoted_continuation = _print_fixture(
        '  echo "continuation: skipped" \\',
        listed=True,
        regex=r"^continuation: skipped$",
    )
    quoted_trailing_backslash = _print_fixture(
        '  echo "quoted: skipped\\',
        listed=True,
        regex=r"^quoted: skipped$",
    )
    return Observation(
        expected={
            "quoted-punctuation": [],
            "unquoted-continuation": [],
            "quoted-trailing-backslash": ["C5.4-unrenderable"],
        },
        got={
            "quoted-punctuation": quoted_punctuation.got,
            "unquoted-continuation": unquoted_continuation.got,
            "quoted-trailing-backslash": quoted_trailing_backslash.got,
        },
    )


def _build_site_fixture(*, operand: bool) -> Observation:
    census, script_bytes, script_relpath = _census_case("cookie")
    lines = script_bytes.decode().splitlines()
    number = _uncited_blank_line(census, lines)
    source = (
        '"$IYI" build -o "$WORK/x" "$WORK/$name"'
        if operand
        else '"$IYI" build -o "$WORK/$name" "$WORK/x.iyi"'
    )
    lines[number - 1] = source
    census["sites"].append(
        {
            "lines": [number],
            "command": "build",
            "kind": "canonical-other",
            "contains": ['"$IYI" build -o'],
            "variants": [],
        }
    )
    changed_script = ("\n".join(lines) + "\n").encode()
    census["script_sha256"] = hashlib.sha256(changed_script).hexdigest()
    got = _copied_validator_rules(
        census,
        changed_script,
        script_relpath,
        "iyi-o3-build-site-",
    )
    expected = ["E1-stray-reference"] if operand else []
    return Observation(
        expected=expected,
        got=got,
        applied=f"line={number};operand={str(operand).lower()}",
    )


def _historical_census(driver: str) -> dict:
    completed = subprocess.run(
        [
            "git",
            "-C",
            REPO_ROOT,
            "show",
            f"{_O3_HISTORICAL_REF}:proof/census/{driver}.json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git show failed for {driver}: {completed.stderr.strip()}"
        )
    loaded = json.loads(completed.stdout)
    if not isinstance(loaded, dict):
        raise TypeError(f"historical census {driver} is not an object")
    return loaded


def _fixture_regression_1f_seed() -> Observation:
    findings: dict[str, list[tuple[str, int, str]]] = {}
    seen: list[str] = []
    frozen_sha_mismatch: list[str] = []
    frozen_shas: list[str] = []
    for driver in DRIVERS_29:
        census = _historical_census(driver)
        script_relpath = census.get("script")
        if not isinstance(script_relpath, str):
            raise TypeError(
                f"historical census {driver} has no string script"
            )
        script_bytes = _git_show_bytes(_O3_HISTORICAL_REF, script_relpath)
        frozen_sha = hashlib.sha256(script_bytes).hexdigest()
        frozen_shas.append(f"{driver}:{frozen_sha}")
        if frozen_sha != census.get("script_sha256"):
            frozen_sha_mismatch.append(driver)
        violations = validate_census(census, script_bytes, script_relpath)
        findings[driver] = violations
        seen.append(driver)
        print(f"R1F driver={driver} violations={len(violations)}")
        for violation in violations:
            print(
                f"R1F driver={driver} violation={_render(violation)}"
            )

    def present(
        driver: str,
        rule_id: str,
        *,
        line: int | None = None,
        detail: str | None = None,
    ) -> bool:
        return any(
            got_rule == rule_id
            and (line is None or got_line == line)
            and (detail is None or detail in got_detail)
            for got_rule, got_line, got_detail in findings[driver]
        )

    required = (
        ("dns:E1-verdict-mark", present("dns", "E1-verdict-mark")),
        ("fuzz:E1-exec-token", present("fuzz", "E1-exec-token")),
        (
            "autocert:E1-exec-token",
            present("autocert", "E1-exec-token"),
        ),
        ("signal:E1-missing", present("signal", "E1-missing")),
        ("compress:E1-missing", present("compress", "E1-missing")),
        ("math:E1-missing", present("math", "E1-missing")),
        ("tls:E1-missing", present("tls", "E1-missing")),
        ("file:E1-missing", present("file", "E1-missing")),
        (
            "tls:C5.3-var-range",
            present("tls", "C5.3-var-range"),
        ),
        (
            "dns:noquestion:C5.3-var-range",
            present("dns", "C5.3-var-range", detail="noquestion"),
        ),
        (
            "dns:notcp:C5.3-var-range",
            present("dns", "C5.3-var-range", detail="notcp"),
        ),
        (
            "signal:C5.7-template",
            present("signal", "C5.7-template"),
        ),
        (
            "file_utils:C5.7-template",
            present("file_utils", "C5.7-template"),
        ),
        ("http:C5.7-template", present("http", "C5.7-template")),
        (
            "dns:213:C5.4-skip-regex",
            present("dns", "C5.4-skip-regex", line=213),
        ),
        (
            "dns:218:C5.4-skip-regex",
            present("dns", "C5.4-skip-regex", line=218),
        ),
        (
            "http:962:C5.4-skip-regex",
            present("http", "C5.4-skip-regex", line=962),
        ),
        (
            "compress:485:C5.2-duplicate-site",
            present("compress", "C5.2-duplicate-site", line=485),
        ),
        (
            "png:708:C5.2-duplicate-site",
            present("png", "C5.2-duplicate-site", line=708),
        ),
        (
            "shlex:354:C5.2-duplicate-site",
            present("shlex", "C5.2-duplicate-site", line=354),
        ),
        (
            "websocket:1053:C5.2-duplicate-site",
            present("websocket", "C5.2-duplicate-site", line=1053),
        ),
        (
            "zip:703:C5.2-duplicate-site",
            present("zip", "C5.2-duplicate-site", line=703),
        ),
    )
    missing = [label for label, found in required if not found]
    expected = {
        "drivers": list(DRIVERS_29),
        "missing": [],
        "frozen_sha_mismatch": [],
    }
    got = {
        "drivers": seen,
        "missing": missing,
        "frozen_sha_mismatch": frozen_sha_mismatch,
    }
    applied = (
        f"git-show-ref={_O3_HISTORICAL_REF};"
        f"drivers={len(seen)};"
        f"violations={sum(len(items) for items in findings.values())};"
        f"frozen_shas={','.join(frozen_shas)}"
    )
    return Observation(expected=expected, got=got, applied=applied)


O3_SEED_IDS = (
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
    "s2.seed.validator-nested-types",
    "s2.seed.validator-print-capture-skip",
    "s2.seed.validator-print-case-arm-regex",
    "s2.seed.validator-build-site-operand",
    "s2.seed.regression-1f",
)

O3_CONTROL_IDS = (
    "s2.control.census-all",
    "s2.control.e1-shared-token",
    "s2.control.validator-print-capture",
    "s2.control.validator-print-case-arm",
    "s2.control.validator-print-quoted-punct",
    "s2.control.validator-build-site-aux",
)

O3_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "s2.seed.validator-schema",
        "seed",
        _fixture_validator_schema_seed,
    ),
    Fixture(
        "s2.seed.validator-sha",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.1-sha",
            "script sha",
            _has_any_site,
            _mutate_sha,
            update_sha=False,
        ),
    ),
    Fixture(
        "s2.seed.validator-unlisted-invocation",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.2-unlisted-invocation",
            "unlisted compiler invocation",
            _has_any_site,
            _mutate_unlisted_invocation,
        ),
    ),
    Fixture(
        "s2.seed.validator-duplicate-site",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.2-duplicate-site",
            "duplicate site claim",
            _has_any_site,
            _mutate_duplicate_site,
        ),
    ),
    Fixture(
        "s2.seed.validator-contains",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.3-contains",
            "site contains literal",
            _has_contains,
            _mutate_contains,
        ),
    ),
    Fixture(
        "s2.seed.validator-verdict",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.3-verdict-literal",
            "variant verdict literal",
            _has_variant_verdict,
            _mutate_verdict_literal,
        ),
    ),
    Fixture(
        "s2.seed.validator-var-range",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.3-var-range",
            "enumerated variable range",
            _has_enumerated_variable,
            _mutate_var_range,
        ),
    ),
    Fixture(
        "s2.seed.validator-unlisted-skip",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.4-unlisted-skip-line",
            "unlisted skip vocabulary line",
            _has_listed_skip,
            _mutate_unlisted_skip,
        ),
    ),
    Fixture(
        "s2.seed.validator-skip-regex",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.4-skip-regex",
            "skip regex mismatch",
            _has_skip,
            _mutate_skip_regex,
        ),
    ),
    Fixture(
        "s2.seed.validator-unrenderable",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.4-unrenderable",
            "unrenderable listed skip",
            _has_unrenderable_candidate,
            _mutate_unrenderable,
        ),
    ),
    Fixture(
        "s2.seed.validator-sentinel",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.5-sentinel",
            "pass sentinel mismatch",
            _has_sentinel,
            _mutate_sentinel,
        ),
    ),
    Fixture(
        "s2.seed.validator-kind-variants",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.6-kind-variants",
            "site kind without variants",
            _has_nonvariant_aux_site,
            _mutate_kind_variants,
        ),
    ),
    Fixture(
        "s2.seed.validator-template",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "C5.7-template",
            "forbidden template shell syntax",
            _has_variant_template,
            _mutate_template,
        ),
    ),
    Fixture(
        "s2.seed.validator-e1-missing",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "E1-missing",
            "positive site missing evidence",
            _has_unique_positive_evidence,
            _mutate_e1_missing,
        ),
    ),
    Fixture(
        "s2.seed.validator-e1-token",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "E1-exec-token",
            "execution line exact token",
            _has_exec_token_candidate,
            _mutate_e1_token,
        ),
    ),
    Fixture(
        "s2.seed.validator-e1-stray-reference",
        "seed",
        _fixture_validator_e1_stray_seed,
    ),
    Fixture(
        "s2.seed.validator-e1-verdict",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "E1-verdict-mark",
            "execution verdict failure mark",
            _has_verdict_mark_candidate,
            _mutate_e1_verdict,
        ),
    ),
    Fixture(
        "s2.seed.validator-e1-exit-line",
        "seed",
        partial(
            _fixture_validator_rule_seed,
            "E1-exit-line",
            "exact final exit line",
            _has_any_site,
            _mutate_e1_exit,
        ),
    ),
    Fixture(
        "s2.seed.validator-nested-types",
        "seed",
        _fixture_validator_nested_types_seed,
    ),
    Fixture(
        "s2.seed.validator-print-capture-skip",
        "seed",
        _fixture_print_capture_seed,
    ),
    Fixture(
        "s2.seed.validator-print-case-arm-regex",
        "seed",
        _fixture_print_case_regex_seed,
    ),
    Fixture(
        "s2.seed.validator-build-site-operand",
        "seed",
        partial(_build_site_fixture, operand=True),
    ),
    Fixture(
        "s2.seed.regression-1f",
        "seed",
        _fixture_regression_1f_seed,
    ),
    Fixture(
        "s2.control.census-all",
        "control",
        _fixture_census_all_control,
    ),
    Fixture(
        "s2.control.e1-shared-token",
        "control",
        _fixture_e1_shared_token_control,
    ),
    Fixture(
        "s2.control.validator-print-capture",
        "control",
        _fixture_print_capture_control,
    ),
    Fixture(
        "s2.control.validator-print-case-arm",
        "control",
        _fixture_print_case_control,
    ),
    Fixture(
        "s2.control.validator-print-quoted-punct",
        "control",
        _fixture_print_quoted_punct_control,
    ),
    Fixture(
        "s2.control.validator-build-site-aux",
        "control",
        partial(_build_site_fixture, operand=False),
    ),
)

O3_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o3.C5.0-schema": (
        "s2.seed.validator-schema",
        "s2.seed.validator-nested-types",
        "s2.control.census-all",
    ),
    "o3.C5.1-sha": (
        "s2.seed.validator-sha",
        "s2.control.census-all",
    ),
    "o3.C5.2-unlisted-invocation": (
        "s2.seed.validator-unlisted-invocation",
        "s2.control.census-all",
    ),
    "o3.C5.2-duplicate-site": (
        "s2.seed.validator-duplicate-site",
        "s2.control.census-all",
    ),
    "o3.C5.3-contains": (
        "s2.seed.validator-contains",
        "s2.control.census-all",
    ),
    "o3.C5.3-verdict-literal": (
        "s2.seed.validator-verdict",
        "s2.control.census-all",
    ),
    "o3.C5.3-var-range": (
        "s2.seed.validator-var-range",
        "s2.control.census-all",
    ),
    "o3.C5.4-unlisted-skip-line": (
        "s2.seed.validator-unlisted-skip",
        "s2.control.census-all",
    ),
    "o3.C5.4-skip-regex": (
        "s2.seed.validator-skip-regex",
        "s2.control.census-all",
    ),
    "o3.C5.4-unrenderable": (
        "s2.seed.validator-unrenderable",
        "s2.control.census-all",
    ),
    "o3.C5.5-sentinel": (
        "s2.seed.validator-sentinel",
        "s2.control.census-all",
    ),
    "o3.C5.6-kind-variants": (
        "s2.seed.validator-kind-variants",
        "s2.control.census-all",
    ),
    "o3.C5.7-template": (
        "s2.seed.validator-template",
        "s2.control.census-all",
    ),
    "o3.E1-missing": (
        "s2.seed.validator-e1-missing",
        "s2.control.census-all",
    ),
    "o3.E1-exec-token": (
        "s2.seed.validator-e1-token",
        "s2.control.census-all",
    ),
    "o3.E1-stray-reference": (
        "s2.seed.validator-e1-stray-reference",
        "s2.control.e1-shared-token",
    ),
    "o3.E1-verdict-mark": (
        "s2.seed.validator-e1-verdict",
        "s2.control.census-all",
    ),
    "o3.E1-exit-line": (
        "s2.seed.validator-e1-exit-line",
        "s2.control.census-all",
    ),
    "o3.regression-1f": (
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "o3.e1-cross-site-subcases": (
        "s2.seed.validator-e1-stray-reference",
        "s2.seed.validator-build-site-operand",
        "s2.control.validator-build-site-aux",
        "s2.control.e1-shared-token",
    ),
    "o3.r0-all-violations": (
        "s2.seed.validator-nested-types",
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "o3.r1-print-commands": (
        "s2.seed.validator-print-capture-skip",
        "s2.seed.validator-print-case-arm-regex",
        "s2.control.validator-print-capture",
        "s2.control.validator-print-case-arm",
        "s2.control.validator-print-quoted-punct",
    ),
}


def _merged_review_items(
    *maps: Mapping[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    merged: dict[str, tuple[str, ...]] = {}
    for review_map in maps:
        for key, fixture_ids in review_map.items():
            if key in merged:
                raise RuntimeError(f"duplicate review item {key}")
            merged[key] = fixture_ids
    return merged


# ===== O4: matcher and shim (owner U4). Fixture functions go directly above
# O4_FIXTURES. New review items only in O4_REVIEW_ITEMS, keys "o4.". =====


O4_FIXTURES: tuple[Fixture, ...] = ()
O4_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {}


# ===== O5: ledger verification (owner U5). Keys "o5.". =====


O5_FIXTURES: tuple[Fixture, ...] = ()
O5_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {}


# ===== O6: artifact legs (owner U6). Keys "o6.". =====


_O6_FAKE_COMPILER = r'''#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import time

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "case.json")
with open(CONFIG_PATH, "r", encoding="utf-8") as stream:
    config = json.load(stream)

args = sys.argv[1:]
if "-o" not in args:
    sys.stderr.write("fake compiler: missing -o\n")
    raise SystemExit(2)
output = args[args.index("-o") + 1]
source = args[-1]
source_name = os.path.basename(source)
if "--emit-iyimod" in args:
    leg = "P"
elif "--stale-key" in args:
    key_name = os.path.basename(args[args.index("--stale-key") + 1])
    leg = {"k1.key": "C1", "k2.key": "C2", "k3.key": "C3"}[key_name]
else:
    sys.stderr.write("fake compiler: unknown leg\n")
    raise SystemExit(2)

def source_leg(section):
    return config.get(section, {}).get(source_name, {}).get(leg)

sleep_spec = source_leg("build_sleeps")
if sleep_spec:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    with open(sleep_spec["pid_file"], "w", encoding="utf-8") as stream:
        stream.write(str(child.pid))
    time.sleep(float(sleep_spec.get("seconds", 60)))

failure = source_leg("build_failures")
if failure and not failure.get("after_outputs"):
    sys.stdout.write(failure.get("stdout", ""))
    sys.stderr.write(failure.get("stderr", ""))
    raise SystemExit(int(failure.get("rc", 1)))

if "--emit-iyimod" in args:
    mods = args[args.index("--emit-iyimod") + 1]
    os.makedirs(mods, exist_ok=True)
    with open(os.path.join(mods, "fake.iyimod"), "wb") as stream:
        stream.write(b"module")

def merge(target, patch):
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            merge(target[key], value)
        else:
            target[key] = value

if "--stale-key" in args and leg not in config.get("omit_keys", []):
    key_path = args[args.index("--stale-key") + 1]
    document = {
        "phase": "linked",
        "portable": {"callpath": "portable-callpath"},
        "reach": {"checked": True, "mismatch": []},
        "not_reusable": config.get("default_not_reusable", []),
    }
    merge(document, config.get("key_overrides", {}).get(leg, {}))
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if leg in config.get("malformed_keys", []):
        with open(key_path, "w", encoding="utf-8") as stream:
            stream.write("{")
    elif leg in config.get("nonobject_keys", []):
        with open(key_path, "w", encoding="utf-8") as stream:
            json.dump([], stream)
    else:
        with open(key_path, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)

os.makedirs(os.path.dirname(output), exist_ok=True)
binary = config.get("effect_bins", {}).get(leg) or config.get("default_binary")
if binary:
    shutil.copy2(binary, output)
    os.chmod(output, 0o755)
else:
    program = [
        "#!" + sys.executable,
        "import json",
        "import os",
        "import subprocess",
        "import sys",
        "import time",
        "CONFIG_PATH = " + repr(CONFIG_PATH),
        "LEG = " + repr(leg),
        "SOURCE = " + repr(source_name),
        "with open(CONFIG_PATH, 'r', encoding='utf-8') as stream:",
        "    config = json.load(stream)",
        "trace = os.environ.get('IYI_OBSERVE')",
        "if trace and LEG not in config.get('trace_empty', []):",
        "    with open(trace, 'wb') as stream:",
        "        stream.write(b'trace\\n')",
        "sleep_spec = config.get('run_sleeps', {}).get(SOURCE, {}).get(LEG)",
        "if sleep_spec:",
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
        "    with open(sleep_spec['pid_file'], 'w', encoding='utf-8') as stream:",
        "        stream.write(str(child.pid))",
        "    time.sleep(float(sleep_spec.get('seconds', 60)))",
        "sandbox_mode = config.get('sandbox_mode')",
        "forced_exit = None",
        "if sandbox_mode:",
        "    sandbox = os.environ.get('IYI_FILE_SANDBOX', os.getcwd())",
        "    marker = os.path.join(sandbox, 'p-only.marker')",
        "    before = os.path.exists(marker)",
        "    if sandbox_mode == 'isolation' and LEG == 'P':",
        "        with open(marker, 'w', encoding='utf-8') as stream:",
        "            stream.write('P')",
        "    if sandbox_mode == 'isolation' and LEG == 'C1' and before:",
        "        forced_exit = 23",
        "        sys.stderr.write('sandbox leak\\n')",
        "    event_log = config.get('sandbox_event_log')",
        "    if event_log:",
        "        with open(event_log, 'a', encoding='utf-8') as stream:",
        "            stream.write(f'{LEG}|{sandbox}|before={int(before)}\\n')",
        "    stdout_text = sandbox + '\\n'",
        "else:",
        "    stdout_text = config.get('run_stdout', {}).get(LEG, 'run-output\\n')",
        "sys.stdout.write(stdout_text)",
        "sys.stderr.write(config.get('run_stderr', {}).get(LEG, 'run-error\\n'))",
        "if forced_exit is not None:",
        "    raise SystemExit(forced_exit)",
        "raise SystemExit(int(config.get('run_exits', {}).get(LEG, 0)))",
    ]
    with open(output, "w", encoding="utf-8") as stream:
        stream.write("\n".join(program) + "\n")
    os.chmod(output, 0o755)
if leg in config.get("skip_outputs", []) and os.path.exists(output):
    os.unlink(output)


stdout_text = config.get("build_stdout", {}).get(leg, f"build {leg}\n")
stderr_text = config.get("build_stderr", {}).get(leg, "")
if leg in config.get("build_effect_output", []):
    stderr_text += "__iyi_effect_seed\n"
if failure and failure.get("after_outputs"):
    stdout_text += failure.get("stdout", "")
    stderr_text += failure.get("stderr", "")
sys.stdout.write(stdout_text)
sys.stderr.write(stderr_text)
if failure and failure.get("after_outputs"):
    raise SystemExit(int(failure.get("rc", 1)))
'''


def _o6_write_executable(path: str, source: str) -> str:
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(source)
    os.chmod(path, 0o755)
    return path


def _o6_make_nm(
    root: str,
    *,
    name: str = "pinned-nm",
    rc_by_path: Mapping[str, int] | None = None,
) -> tuple[str, str]:
    log_path = os.path.join(root, f"{name}.jsonl")
    script_path = os.path.join(root, name)
    rc_mapping = dict(rc_by_path or {})
    source = (
        "#!" + sys.executable + "\n"
        "import json\n"
        "import sys\n"
        f"LOG = {log_path!r}\n"
        f"RC_BY_PATH = {rc_mapping!r}\n"
        "with open(LOG, 'a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "target = sys.argv[-1] if len(sys.argv) > 1 else ''\n"
        "for needle, rc in RC_BY_PATH.items():\n"
        "    if needle in target:\n"
        "        raise SystemExit(int(rc))\n"
        "raise SystemExit(0)\n"
    )
    return _o6_write_executable(script_path, source), log_path


def _o6_make_case(
    root: str,
    *,
    sample_names: tuple[str, ...] = ("case.iyi",),
    std_names: tuple[str, ...] = (),
    config: Mapping[str, object] | None = None,
    nm_rc_by_path: Mapping[str, int] | None = None,
) -> SimpleNamespace:
    repo = os.path.join(root, "repo")
    samples = os.path.join(repo, "samples", "iyi")
    bench = os.path.join(repo, "bench")
    os.makedirs(samples, exist_ok=True)
    os.makedirs(bench, exist_ok=True)
    os.makedirs(os.path.join(repo, "src"), exist_ok=True)
    os.makedirs(os.path.join(repo, "lib"), exist_ok=True)
    shutil.copy2(
        os.path.join(REPO_ROOT, "bench", "frames_equivalent.py"),
        os.path.join(bench, "frames_equivalent.py"),
    )

    sources: dict[str, str] = {}
    for name in sample_names:
        path = os.path.join(samples, name)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(f"# sample {name}\n")
        sources[name] = path
    for name in std_names:
        path = os.path.join(bench, name)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(f"# std {name}\n")
        sources[name] = path

    compiler = _o6_write_executable(
        os.path.join(root, "fake-compiler"),
        _O6_FAKE_COMPILER,
    )
    with open(os.path.join(root, "case.json"), "w", encoding="utf-8") as stream:
        json.dump(dict(config or {}), stream, sort_keys=True)
    nm_bin, nm_log = _o6_make_nm(
        root,
        rc_by_path=nm_rc_by_path,
    )
    work = os.path.join(root, "work")
    os.makedirs(work, exist_ok=True)
    return SimpleNamespace(
        root=root,
        repo=repo,
        compiler=compiler,
        nm=nm_bin,
        nm_log=nm_log,
        work=work,
        sources=sources,
    )


def _o6_run_row(
    case: SimpleNamespace,
    source_name: str = "case.iyi",
    *,
    nm_bin: str | None = None,
) -> dict:
    return legs_mod.run_row(
        case.sources[source_name],
        repo=case.repo,
        compiler=case.compiler,
        work_root=case.work,
        nm_bin=nm_bin or case.nm,
    )


def _o6_codes(row: Mapping[str, object]) -> list[str]:
    return sorted(
        {
            str(value).split(":", 1)[0]
            for value in row.get("failures", [])
        }
    )


def _o6_required_output_names() -> tuple[str, ...]:
    names: list[str] = []
    for leg in ("P", "C1", "C2", "C3"):
        names.extend((f"{leg}.build.stdout", f"{leg}.build.stderr"))
    for leg in ("P", "C1", "C3"):
        names.extend(
            (
                f"{leg}.run.stdout",
                f"{leg}.run.stderr",
                f"{leg}.run.exit",
            )
        )
    return tuple(names)


def _o6_row_seed(
    config: Mapping[str, object],
    expected_codes: tuple[str, ...],
    applied: str,
) -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-row-") as root:
        case = _o6_make_case(root, config=config)
        row = _o6_run_row(case)
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
        }
    expected = {
        "status": "FAIL",
        "codes": sorted(expected_codes),
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_o6_row_control() -> Observation:
    not_reusable = [{"category": "control", "reason": "evidence", "site": "x"}]
    with tempfile.TemporaryDirectory(prefix="iyi-o6-control-") as root:
        case = _o6_make_case(
            root,
            config={"default_not_reusable": not_reusable},
        )
        old_scrubbed = os.environ.get("IYI_O6_COVERAGE")
        os.environ["IYI_O6_COVERAGE"] = "remove-me"
        try:
            cleaned = legs_mod.clean_env(case.repo, os.path.join(root, "cache"))
            row = _o6_run_row(case)
        finally:
            if old_scrubbed is None:
                os.environ.pop("IYI_O6_COVERAGE", None)
            else:
                os.environ["IYI_O6_COVERAGE"] = old_scrubbed
        required = _o6_required_output_names()
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "callpath": row["callpath"],
            "not_reusable_count": row["not_reusable_count"],
            "row_dir_kept": os.path.isdir(row["row_dir"]),
            "outputs_kept": sorted(
                name
                for name in required
                if os.path.isfile(os.path.join(row["row_dir"], name))
            ),
            "scratch_removed": all(
                not os.path.lexists(os.path.join(row["row_dir"], name))
                for name in ("bin", "cache_p", "cache_c", "mods", "sandbox")
            ),
            "legs": sorted(row["legs"]),
            "scrubbed_leg_env": "IYI_O6_COVERAGE" not in cleaned,
            "default_timeout": legs_mod.run_timeout_for("samples/iyi/case.iyi"),
            "heavy_timeout": legs_mod.run_timeout_for("bench/std_big_exercise.iyi"),
            "row_keys": sorted(row),
        }
    expected = {
        "status": "PASS",
        "codes": [],
        "callpath": "portable-callpath",
        "not_reusable_count": 1,
        "row_dir_kept": True,
        "outputs_kept": sorted(required),
        "scratch_removed": True,
        "legs": ["C1", "C2", "C3", "P"],
        "scrubbed_leg_env": True,
        "default_timeout": 60,
        "heavy_timeout": 300,
        "row_keys": sorted(
            (
                "source",
                "name",
                "base",
                "kind",
                "status",
                "failures",
                "stop_condition",
                "p_exit",
                "c1_exit",
                "c3_exit",
                "callpath",
                "not_reusable_count",
                "effect_symbols",
                "p_nonzero",
                "preserved_dir",
                "row_dir",
                "legs",
            )
        ),
    }
    return Observation(expected=expected, got=got)


def _fixture_o6_callpath_k2_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"portable": {"callpath": "different"}}}},
        ("CALLPATH-PARITY",),
        "k2.portable.callpath=different",
    )


def _fixture_o6_callpath_empty_seed() -> Observation:
    return _o6_row_seed(
        {
            "key_overrides": {
                leg: {"portable": {"callpath": ""}}
                for leg in ("C1", "C2", "C3")
            }
        },
        ("CALLPATH-EMPTY",),
        "all_three_callpaths=empty",
    )


def _fixture_o6_callpath_mismatch_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"reach": {"mismatch": ["seed"]}}}},
        ("REACH-MISMATCH",),
        "k2.reach.mismatch=[seed]",
    )


def _fixture_o6_phase_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"phase": "checked"}}},
        ("KEY-PHASE-k2",),
        "k2.phase=checked",
    )


def _fixture_o6_reach_checked_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"reach": {"checked": 1}}}},
        ("REACH-CHECKED-k2",),
        "k2.reach.checked=integer_one",
    )


def _fixture_o6_missing_key_seed() -> Observation:
    return _o6_row_seed(
        {"omit_keys": ["C2"]},
        ("KEY-MISSING",),
        "omitted_key=k2.key",
    )


def _fixture_o6_trace_empty_seed() -> Observation:
    return _o6_row_seed(
        {"trace_empty": ["C1"]},
        ("TRACE-EMPTY-C1",),
        "suppressed_trace=C1",
    )


def _o6_compile_binary(root: str, name: str, source: str) -> str:
    cc = shutil.which("cc")
    if cc is None:
        raise RuntimeError("cc is required for the S4 symbol fixture")
    source_path = os.path.join(root, f"{name}.c")
    binary_path = os.path.join(root, name)
    with open(source_path, "w", encoding="utf-8") as stream:
        stream.write(source)
    completed = subprocess.run(
        [cc, source_path, "-o", binary_path],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cc failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return binary_path


def _fixture_o6_symbol_seed(leg: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix=f"iyi-o6-symbol-{leg.lower()}-") as root:
        clean = _o6_compile_binary(
            root,
            "clean",
            "int main(void) { return 0; }\n",
        )
        effect = _o6_compile_binary(
            root,
            "effect",
            "__attribute__((used,noinline)) int __iyi_effect_x(void) { return 0; }\n"
            "int main(void) { return __iyi_effect_x(); }\n",
        )
        case = _o6_make_case(
            root,
            config={
                "default_binary": clean,
                "effect_bins": {leg: effect},
            },
        )
        nm_bin = shutil.which("nm")
        if nm_bin is None:
            raise RuntimeError("nm is required for the S4 symbol fixture")
        row = _o6_run_row(case, nm_bin=nm_bin)
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "symbol_seen": any(
                "___iyi_effect_x" in symbol
                for symbol in row["effect_symbols"]
            ),
            "binary_is_cc_built": os.path.isfile(
                os.path.join(row["row_dir"], "bin", leg.lower(), "case")
            ),
        }
    expected = {
        "status": "STOP",
        "codes": [f"EFFECT-SYMBOL-{leg}"],
        "symbol_seen": True,
        "binary_is_cc_built": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"cc_binary_leg={leg};symbol=___iyi_effect_x",
    )


def _fixture_o6_nm_error_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-nm-error-") as root:
        case = _o6_make_case(
            root,
            nm_rc_by_path={f"{os.sep}bin{os.sep}c2{os.sep}": 7},
        )
        row = _o6_run_row(case)
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
        }
    expected = {
        "status": "FAIL",
        "codes": ["NM-ERROR-C2"],
    }
    return Observation(
        expected=expected,
        got=got,
        applied="pinned_nm_exit=7_for_C2",
    )


def _fixture_o6_build_output_symbol_seed() -> Observation:
    return _o6_row_seed(
        {"build_effect_output": ["P"]},
        ("BUILD-EFFECT-P",),
        "P.build.stderr_contains=__iyi_effect_seed",
    )


def _o6_pid_is_gone(pid_file: str) -> bool:
    if not os.path.isfile(pid_file):
        return False
    with open(pid_file, "r", encoding="utf-8") as stream:
        pid = int(stream.read().strip())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.02)
    return False


@contextlib.contextmanager
def _o6_limits(*, build: int | None = None, run: int | None = None):
    old_build = legs_mod.BUILD_TIMEOUT
    old_run = legs_mod.RUN_DEFAULT_TIMEOUT
    try:
        if build is not None:
            legs_mod.BUILD_TIMEOUT = build
        if run is not None:
            legs_mod.RUN_DEFAULT_TIMEOUT = run
        yield
    finally:
        legs_mod.BUILD_TIMEOUT = old_build
        legs_mod.RUN_DEFAULT_TIMEOUT = old_run


def _o6_read_report(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _fixture_o6_timeout_seed(phase: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix=f"iyi-o6-{phase}-timeout-") as root:
        source_name = f"sleepy_{phase}.iyi"
        pid_file = os.path.join(root, f"{phase}-grandchild.pid")
        config: dict[str, object] = {}
        if phase == "build":
            config["build_sleeps"] = {
                source_name: {
                    "P": {"seconds": 60, "pid_file": pid_file}
                }
            }
            expected_code = "BUILD-TIMEOUT-P"
        else:
            config["run_sleeps"] = {
                source_name: {
                    "P": {"seconds": 60, "pid_file": pid_file}
                }
            }
            expected_code = "RUN-TIMEOUT-P"

        case = _o6_make_case(
            root,
            sample_names=("good.iyi", source_name),
            config=config,
        )
        report = os.path.join(root, "report.jsonl")
        argv = [
            "--repo",
            case.repo,
            "--compiler",
            case.compiler,
            "--work",
            case.work,
            "--report",
            report,
            "--workers",
            "2",
            "--nm",
            case.nm,
            "--expect-samples",
            "2",
            "--expect-std",
            "0",
            "--expect-total",
            "2",
        ]
        with _o6_limits(
            build=2 if phase == "build" else None,
            run=2 if phase == "run" else None,
        ):
            direct_row = _o6_run_row(case, source_name)
            returncode = legs_mod.main(argv)
        rows = _o6_read_report(report)
        by_name = {os.path.basename(row["source"]): row for row in rows}
        got = {
            "returncode": returncode,
            "direct_status": direct_row["status"],
            "direct_codes": _o6_codes(direct_row),
            "order": [os.path.basename(row["source"]) for row in rows],
            "good_status": by_name["good.iyi"]["status"],
            "sleepy_status": by_name[source_name]["status"],
            "sleepy_codes": _o6_codes(by_name[source_name]),
            "grandchild_gone": _o6_pid_is_gone(pid_file),
            "jsonl_rows": len(rows),
        }
    expected = {
        "returncode": 1,
        "direct_status": "FAIL",
        "direct_codes": [expected_code],
        "order": ["good.iyi", source_name],
        "good_status": "PASS",
        "sleepy_status": "FAIL",
        "sleepy_codes": [expected_code],
        "grandchild_gone": True,
        "jsonl_rows": 2,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"{phase}_limit=2;source={source_name};grandchild_pid_file=written",
    )


def _o6_compare(
    root: str,
    *,
    name: str = "case",
    status_a: int = 0,
    status_b: int = 0,
    stdout_a: bytes = b"same\n",
    stderr_a: bytes = b"",
    stdout_b: bytes = b"same\n",
    stderr_b: bytes = b"",
    tag: str = "fixture",
) -> tuple[bool, str]:
    row_dir = os.path.join(root, "row")
    os.makedirs(row_dir, exist_ok=True)
    return legs_mod.compare_r1(
        name,
        status_a,
        status_b,
        stdout_a,
        stderr_a,
        stdout_b,
        stderr_b,
        REPO_ROOT,
        row_dir,
        tag,
    )


def _o6_frame_lines() -> tuple[bytes, bytes]:
    left = (
        b"0 app 0x0000000000000001 "
        b"~proc12@/tmp/src/std/foo.iyi:7 + 8\n"
    )
    equivalent = (
        b"0 app 0x00000000000000ff "
        b"~proc987@/tmp/mods/std/foo.iyimod:7 + 99\n"
    )
    return left, equivalent


def _fixture_o6_frame_control() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-frames-") as root:
        left, equivalent = _o6_frame_lines()
        address_offset_proc = _o6_compare(
            root,
            stderr_a=left,
            stderr_b=equivalent,
            tag="address-offset-proc",
        )
        exit_only = _o6_compare(
            root,
            name="std_big_exercise",
            status_a=7,
            status_b=7,
            stdout_a=b"producer output\n",
            stderr_a=b"producer error\n",
            stdout_b=b"consumer changed output\n",
            stderr_b=b"consumer changed error\n",
            tag="exit-only",
        )
        got = {
            "address_offset_proc": address_offset_proc[0],
            "address_offset_proc_reason": address_offset_proc[1],
            "exit_only_changed_output": exit_only[0],
            "exit_only_reason": exit_only[1],
        }
    expected = {
        "address_offset_proc": True,
        "address_offset_proc_reason": "stdout byte-equal and stderr frames equivalent",
        "exit_only_changed_output": True,
        "exit_only_reason": "exit-only check passed",
    }
    return Observation(expected=expected, got=got)


def _fixture_o6_frame_function_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-frame-function-") as root:
        left, _ = _o6_frame_lines()
        right = left.replace(b"~proc12", b"different_function", 1)
        ok, reason = _o6_compare(root, stderr_a=left, stderr_b=right)
        got = {"ok": ok, "rule": "rule function" in reason}
    return Observation(
        expected={"ok": False, "rule": True},
        got=got,
        applied="frame_function=~proc12->different_function",
    )


def _fixture_o6_frame_text_seed(kind: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix=f"iyi-o6-frame-{kind}-") as root:
        if kind == "lone-cr":
            left = b"payload\r\n"
            right = b"payload\n"
            applied = "stderr_removed_single_CR"
        else:
            left = b"payload abc\n"
            right = b"payload acb\n"
            applied = "stderr_moved_byte=b<->c"
        ok, reason = _o6_compare(root, stderr_a=left, stderr_b=right)
        got = {"ok": ok, "rule": "rule text" in reason}
    return Observation(
        expected={"ok": False, "rule": True},
        got=got,
        applied=applied,
    )


def _fixture_o6_exit_code_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-exit-") as root:
        ok, reason = _o6_compare(root, status_a=0, status_b=9)
        got = {"ok": ok, "reason": reason}
    return Observation(
        expected={"ok": False, "reason": "exit status mismatch: 0 != 9"},
        got=got,
        applied="consumer_exit=9",
    )


def _o6_worker_case(root: str, *, failing: bool) -> tuple[SimpleNamespace, list[dict]]:
    failures: dict[str, object] = {}
    if failing:
        failures = {
            "alpha.iyi": {
                "P": {"rc": 11, "stderr": "alpha-only-reason\n"}
            },
            "beta.iyi": {
                "P": {"rc": 12, "stderr": "beta-only-reason\n"}
            },
        }
    case = _o6_make_case(
        root,
        sample_names=("alpha.iyi", "beta.iyi"),
        config={"build_failures": failures},
    )
    rows = legs_mod.run_rows(
        [case.sources["alpha.iyi"], case.sources["beta.iyi"]],
        repo=case.repo,
        compiler=case.compiler,
        work_root=case.work,
        nm_bin=case.nm,
        workers=2,
    )
    return case, rows


def _fixture_o6_worker_reason_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-workers-") as root:
        _, rows = _o6_worker_case(root, failing=True)
        by_name = {os.path.basename(row["source"]): row for row in rows}
        got = {
            "alpha_codes": _o6_codes(by_name["alpha.iyi"]),
            "beta_codes": _o6_codes(by_name["beta.iyi"]),
            "alpha_has_own_reason": any(
                "alpha-only-reason" in reason
                for reason in by_name["alpha.iyi"]["failures"]
            ),
            "alpha_has_foreign_reason": any(
                "beta-only-reason" in reason
                for reason in by_name["alpha.iyi"]["failures"]
            ),
            "beta_has_own_reason": any(
                "beta-only-reason" in reason
                for reason in by_name["beta.iyi"]["failures"]
            ),
            "beta_has_foreign_reason": any(
                "alpha-only-reason" in reason
                for reason in by_name["beta.iyi"]["failures"]
            ),
        }
    expected = {
        "alpha_codes": ["BUILD-EXIT-P"],
        "beta_codes": ["BUILD-EXIT-P"],
        "alpha_has_own_reason": True,
        "alpha_has_foreign_reason": False,
        "beta_has_own_reason": True,
        "beta_has_foreign_reason": False,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="parallel_failures=alpha:11,beta:12",
    )


def _fixture_o6_stdout_seed() -> Observation:
    original = sys.stdout
    with tempfile.TemporaryDirectory(prefix="iyi-o6-stdout-") as root:
        _, rows = _o6_worker_case(root, failing=True)
        got = {
            "same_object": sys.stdout is original,
            "row_statuses": [row["status"] for row in rows],
        }
    return Observation(
        expected={"same_object": True, "row_statuses": ["FAIL", "FAIL"]},
        got=got,
        applied="parallel_failing_workers=2",
    )


def _fixture_o6_workers_control() -> Observation:
    original = sys.stdout
    with tempfile.TemporaryDirectory(prefix="iyi-o6-workers-control-") as root:
        _, rows = _o6_worker_case(root, failing=False)
        legs_mod._kill_process_group(2**30, signal.SIGTERM)
        got = {
            "same_object": sys.stdout is original,
            "row_statuses": [row["status"] for row in rows],
            "codes": [_o6_codes(row) for row in rows],
            "missing_group_ignored": True,
        }
    return Observation(
        expected={
            "same_object": True,
            "row_statuses": ["PASS", "PASS"],
            "codes": [[], []],
            "missing_group_ignored": True,
        },
        got=got,
    )


def _o6_cli_command(
    root: str,
    *,
    optimized: bool,
    expected_samples: int,
    expected_std: int,
    expected_total: int,
) -> tuple[list[str], str]:
    repo = os.path.join(root, "repo")
    os.makedirs(os.path.join(repo, "samples", "iyi"), exist_ok=True)
    os.makedirs(os.path.join(repo, "bench"), exist_ok=True)
    report = os.path.join(root, "report.jsonl")
    work = os.path.join(root, "work")
    command = [sys.executable, "-B"]
    if optimized:
        command.append("-O")
    command.extend(
        [
            os.path.join(REPO_ROOT, "proof", "artifact_legs.py"),
            "--repo",
            repo,
            "--compiler",
            sys.executable,
            "--work",
            work,
            "--report",
            report,
            "--workers",
            "1",
            "--nm",
            sys.executable,
            "--expect-samples",
            str(expected_samples),
            "--expect-std",
            str(expected_std),
            "--expect-total",
            str(expected_total),
        ]
    )
    return command, report


def _fixture_o6_wrong_count_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-count-seed-") as root:
        command, report = _o6_cli_command(
            root,
            optimized=True,
            expected_samples=1,
            expected_std=1,
            expected_total=2,
        )
        env = os.environ.copy()
        env.pop("PYTHONOPTIMIZE", None)
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        script = os.path.join(REPO_ROOT, "proof", "artifact_legs.py")
        argv = command[command.index(script) + 1 :]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            in_process_returncode = legs_mod.main(argv)
        rows = _o6_read_report(report) if os.path.isfile(report) else []
        got = {
            "returncode": completed.returncode,
            "in_process_returncode": in_process_returncode,
            "count_marker": "RUN 2 count mismatch" in completed.stderr,
            "report_exists": os.path.isfile(report),
            "report_rows": len(rows),
        }
    expected = {
        "returncode": 1,
        "in_process_returncode": 1,
        "count_marker": True,
        "report_exists": True,
        "report_rows": 0,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="python=-O;actual_counts=0,0,0;expected_counts=1,1,2",
    )


def _fixture_o6_counts_control() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-count-control-") as root:
        command, report = _o6_cli_command(
            root,
            optimized=False,
            expected_samples=0,
            expected_std=0,
            expected_total=0,
        )
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        rows = _o6_read_report(report) if os.path.isfile(report) else []
        got = {
            "returncode": completed.returncode,
            "main_summary": "RUN 2 SUMMARY" in completed.stdout,
            "report_exists": os.path.isfile(report),
            "report_rows": len(rows),
        }
    expected = {
        "returncode": 0,
        "main_summary": True,
        "report_exists": True,
        "report_rows": 0,
    }
    return Observation(expected=expected, got=got)


def _fixture_o6_sandbox_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-sandbox-seed-") as root:
        event_log = os.path.join(root, "sandbox-events.log")
        case = _o6_make_case(
            root,
            sample_names=(),
            std_names=("std_sandbox_exercise.iyi",),
            config={
                "sandbox_mode": "isolation",
                "sandbox_event_log": event_log,
            },
        )
        row = _o6_run_row(case, "std_sandbox_exercise.iyi")
        with open(event_log, "r", encoding="utf-8") as stream:
            events = [line.strip().split("|") for line in stream if line.strip()]
        paths = [parts[1] for parts in events]
        before = {parts[0]: parts[2] for parts in events}
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "same_path": len(set(paths)) == 1,
            "p_started_empty": before.get("P") == "before=0",
            "c1_did_not_see_p_file": before.get("C1") == "before=0",
            "c3_started_empty": before.get("C3") == "before=0",
        }
    expected = {
        "status": "PASS",
        "codes": [],
        "same_path": True,
        "p_started_empty": True,
        "c1_did_not_see_p_file": True,
        "c3_started_empty": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="P_writes=p-only.marker;C1_checks_same_sandbox_path",
    )


def _fixture_o6_sandbox_control() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-sandbox-control-") as root:
        event_log = os.path.join(root, "sandbox-events.log")
        case = _o6_make_case(
            root,
            sample_names=(),
            std_names=("std_sandbox_exercise.iyi",),
            config={
                "sandbox_mode": "path-only",
                "sandbox_event_log": event_log,
            },
        )
        row = _o6_run_row(case, "std_sandbox_exercise.iyi")
        run_outputs = []
        for leg in ("P", "C1", "C3"):
            with open(
                os.path.join(row["row_dir"], f"{leg}.run.stdout"),
                "r",
                encoding="utf-8",
            ) as stream:
                run_outputs.append(stream.read())
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "same_printed_path": len(set(run_outputs)) == 1,
            "printed_sandbox": run_outputs[0].strip().endswith(
                os.path.join("rows", "std_sandbox_exercise", "sandbox")
            ),
        }
    expected = {
        "status": "PASS",
        "codes": [],
        "same_printed_path": True,
        "printed_sandbox": True,
    }
    return Observation(expected=expected, got=got)


def _fixture_o6_row_oserror_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-oserror-") as root:
        case = _o6_make_case(root)
        missing = os.path.join(root, "missing-compiler")
        row = legs_mod.run_row(
            case.sources["case.iyi"],
            repo=case.repo,
            compiler=missing,
            work_root=case.work,
            nm_bin=case.nm,
        )
        kept = sorted(
            name
            for name in _o6_required_output_names()
            if os.path.isfile(os.path.join(row["row_dir"], name))
        )
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "outputs_precreated": kept,
        }
    expected = {
        "status": "FAIL",
        "codes": ["ROW-OSERROR"],
        "outputs_precreated": sorted(_o6_required_output_names()),
    }
    return Observation(
        expected=expected,
        got=got,
        applied="compiler_path=missing",
    )


def _fixture_o6_row_runtimeerror_seed() -> Observation:
    old_minimum = legs_mod.DISK_MIN_GB
    try:
        legs_mod.DISK_MIN_GB = float(2**60)
        with tempfile.TemporaryDirectory(prefix="iyi-o6-runtimeerror-") as root:
            case = _o6_make_case(root)
            row = _o6_run_row(case)
            got = {
                "status": row["status"],
                "codes": _o6_codes(row),
                "reason_is_disk": any(
                    "Disk space below threshold" in reason
                    for reason in row["failures"]
                ),
            }
    finally:
        legs_mod.DISK_MIN_GB = old_minimum
    expected = {
        "status": "FAIL",
        "codes": ["ROW-RUNTIMEERROR"],
        "reason_is_disk": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="disk_min_gb=2**60",
    )


def _fixture_o6_nm_pinned_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-nm-pinned-") as root:
        case = _o6_make_case(root)
        trap_dir = os.path.join(root, "trap")
        os.makedirs(trap_dir, exist_ok=True)
        trap_log = os.path.join(root, "trap.log")
        trap_source = (
            "#!" + sys.executable + "\n"
            f"open({trap_log!r}, 'a', encoding='utf-8').write('called\\n')\n"
            "raise SystemExit(99)\n"
        )
        _o6_write_executable(os.path.join(trap_dir, "nm"), trap_source)
        report = os.path.join(root, "report.jsonl")
        argv = [
            "--repo",
            case.repo,
            "--compiler",
            case.compiler,
            "--work",
            case.work,
            "--report",
            report,
            "--workers",
            "1",
            "--nm",
            case.nm,
            "--expect-samples",
            "1",
            "--expect-std",
            "0",
            "--expect-total",
            "1",
        ]
        old_path = os.environ.get("PATH")
        os.environ["PATH"] = trap_dir + os.pathsep + (old_path or "")
        try:
            returncode = legs_mod.main(argv)
        finally:
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
        with open(case.nm_log, "r", encoding="utf-8") as stream:
            pinned_calls = [json.loads(line) for line in stream if line.strip()]
        rows = _o6_read_report(report)
        got = {
            "returncode": returncode,
            "row_status": rows[0]["status"],
            "pinned_calls": len(pinned_calls),
            "all_u_flag": all(call[0] == "-U" for call in pinned_calls),
            "path_nm_called": os.path.exists(trap_log),
        }
    expected = {
        "returncode": 0,
        "row_status": "PASS",
        "pinned_calls": 3,
        "all_u_flag": True,
        "path_nm_called": False,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"PATH_nm={os.path.join(trap_dir, 'nm')};explicit_nm={case.nm}",
    )


def _fixture_o6_outputs_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-outputs-") as root:
        case = _o6_make_case(root)
        row = _o6_run_row(case)
        required = _o6_required_output_names()
        missing = [
            name
            for name in required
            if not os.path.isfile(os.path.join(row["row_dir"], name))
        ]
        run_streams = [
            name
            for name in required
            if ".run." in name
            and os.path.getsize(os.path.join(row["row_dir"], name)) > 0
        ]
        got = {
            "status": row["status"],
            "missing": missing,
            "nonempty_run_files": sorted(run_streams),
            "legs_have_output_paths": all(
                row["legs"][leg]["build"]["stdout"].endswith(
                    f"{leg}.build.stdout"
                )
                for leg in ("P", "C1", "C2", "C3")
            ),
        }
    expected = {
        "status": "PASS",
        "missing": [],
        "nonempty_run_files": sorted(
            name for name in required if ".run." in name
        ),
        "legs_have_output_paths": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"required_output_files={len(required)}",
    )


def _fixture_o6_not_reusable_seed() -> Observation:
    top_level = [{"category": "top", "reason": "kept", "site": "x"}]
    nested = [
        {"category": "nested", "reason": str(index), "site": "x"}
        for index in range(3)
    ]
    with tempfile.TemporaryDirectory(prefix="iyi-o6-not-reusable-") as root:
        case = _o6_make_case(
            root,
            config={
                "default_not_reusable": top_level,
                "key_overrides": {
                    "C1": {"reach": {"not_reusable": nested}}
                },
            },
        )
        row = _o6_run_row(case)
        got = {
            "status": row["status"],
            "count": row["not_reusable_count"],
        }
    return Observation(
        expected={"status": "PASS", "count": 1},
        got=got,
        applied="top_level_count=1;nested_decoy_count=3",
    )


def _fixture_o6_build_missing_seed() -> Observation:
    return _o6_row_seed(
        {"skip_outputs": ["C2"]},
        ("BUILD-MISSING-C2",),
        "C2_build_exit=0;C2_binary=removed",
    )


def _fixture_o6_c3_stop_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-c3-stop-") as root:
        case = _o6_make_case(
            root,
            config={
                "build_failures": {
                    "case.iyi": {
                        "C3": {
                            "rc": 17,
                            "stderr": "cannot name it: seeded artifact\n",
                            "after_outputs": True,
                        }
                    }
                }
            },
        )
        row = _o6_run_row(case)
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "stop_marker": "cannot name it" in (row["stop_condition"] or ""),
        }
    expected = {
        "status": "STOP",
        "codes": ["BUILD-EXIT-C3", "C3-CANNOT-NAME"],
        "stop_marker": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="C3_exit=17;C3_stderr=cannot_name_it",
    )


def _fixture_o6_key_parse_seed(kind: str) -> Observation:
    config = (
        {"malformed_keys": ["C2"]}
        if kind == "json"
        else {"nonobject_keys": ["C2"]}
    )
    return _o6_row_seed(
        config,
        ("KEY-PARSE",),
        f"k2_key_shape={kind}",
    )


def _fixture_o6_portable_type_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"portable": "not-an-object"}}},
        ("CALLPATH-EMPTY", "CALLPATH-PARITY"),
        "k2.portable=string",
    )


def _fixture_o6_reach_type_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C2": {"reach": "not-an-object"}}},
        ("REACH-CHECKED-k2",),
        "k2.reach=string",
    )


def _fixture_o6_not_reusable_type_seed() -> Observation:
    return _o6_row_seed(
        {"key_overrides": {"C1": {"not_reusable": "not-an-array"}}},
        ("NOT-REUSABLE-TYPE",),
        "k1.not_reusable=string",
    )


def _fixture_o6_run_effect_seed() -> Observation:
    return _o6_row_seed(
        {"run_stderr": {"C3": "__iyi_effect_seed\n"}},
        ("RUN-EFFECT-C3",),
        "C3.run.stderr_contains=__iyi_effect_seed",
    )


def _fixture_o6_row_r1_seed() -> Observation:
    return _o6_row_seed(
        {"run_stdout": {"C3": "different-output\n"}},
        ("R1-C1-C3",),
        "C3.run.stdout=different-output",
    )


def _fixture_o6_nm_missing_binary_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-nm-missing-") as root:
        nm_bin, _ = _o6_make_nm(root)
        missing = os.path.join(root, "missing-binary")
        try:
            legs_mod.check_defined_symbols(missing, nm_bin)
        except RuntimeError as error:
            got = {
                "raised": type(error).__name__,
                "reason": str(error),
            }
        else:
            got = {"raised": None, "reason": ""}
    expected = {
        "raised": "RuntimeError",
        "reason": f"binary does not exist for symbol scan: {missing}",
    }
    return Observation(
        expected=expected,
        got=got,
        applied="binary_path=missing",
    )


def _fixture_o6_frame_harness_seed(kind: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix=f"iyi-o6-frame-{kind}-") as root:
        repo = os.path.join(root, "repo")
        row_dir = os.path.join(root, "row")
        os.makedirs(os.path.join(repo, "bench"), exist_ok=True)
        os.makedirs(row_dir, exist_ok=True)
        if kind == "crash":
            script = os.path.join(repo, "bench", "frames_equivalent.py")
            with open(script, "w", encoding="utf-8") as stream:
                stream.write("import sys\nsys.stderr.write('seeded crash\\n')\nraise SystemExit(2)\n")
        left, equivalent = _o6_frame_lines()
        try:
            legs_mod.compare_r1(
                "case",
                0,
                0,
                b"same\n",
                left,
                b"same\n",
                equivalent,
                repo,
                row_dir,
                kind,
            )
        except RuntimeError as error:
            got = {
                "raised": type(error).__name__,
                "missing_marker": "not found" in str(error),
                "crash_marker": "crashed (exit 2)" in str(error),
            }
        else:
            got = {
                "raised": None,
                "missing_marker": False,
                "crash_marker": False,
            }
    expected = {
        "raised": "RuntimeError",
        "missing_marker": kind == "missing",
        "crash_marker": kind == "crash",
    }
    return Observation(
        expected=expected,
        got=got,
        applied=f"frames_equivalent={kind}",
    )


def _fixture_o6_stdout_mismatch_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-stdout-mismatch-") as root:
        ok, reason = _o6_compare(
            root,
            stdout_a=b"abc\n",
            stdout_b=b"ab\n",
        )
        got = {
            "ok": ok,
            "reason": reason,
        }
    return Observation(
        expected={
            "ok": False,
            "reason": "stdout mismatch (len 4 != 3)",
        },
        got=got,
        applied="stdout_removed_byte=c",
    )


def _fixture_o6_cli_required_seed() -> Observation:
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        returncode = legs_mod.main([])
    got = {
        "returncode": returncode,
        "required_marker": "the following arguments are required" in stderr.getvalue(),
    }
    return Observation(
        expected={"returncode": 2, "required_marker": True},
        got=got,
        applied="argv=[]",
    )


def _fixture_o6_cli_workers_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-cli-workers-") as root:
        command, _ = _o6_cli_command(
            root,
            optimized=False,
            expected_samples=0,
            expected_std=0,
            expected_total=0,
        )
        script = os.path.join(REPO_ROOT, "proof", "artifact_legs.py")
        argv = command[command.index(script) + 1 :]
        argv[argv.index("--workers") + 1] = "0"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            returncode = legs_mod.main(argv)
        got = {
            "returncode": returncode,
            "workers_marker": "--workers must be at least 1" in stderr.getvalue(),
        }
    return Observation(
        expected={"returncode": 2, "workers_marker": True},
        got=got,
        applied="workers=0",
    )


def _fixture_o6_cli_negative_count_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-cli-negative-") as root:
        command, _ = _o6_cli_command(
            root,
            optimized=False,
            expected_samples=0,
            expected_std=0,
            expected_total=-1,
        )
        script = os.path.join(REPO_ROOT, "proof", "artifact_legs.py")
        argv = command[command.index(script) + 1 :]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            returncode = legs_mod.main(argv)
        got = {
            "returncode": returncode,
            "count_marker": "expected counts must be non-negative"
            in stderr.getvalue(),
        }
    return Observation(
        expected={"returncode": 2, "count_marker": True},
        got=got,
        applied="expect_total=-1",
    )


def _fixture_o6_p_nonzero_control() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o6-p-nonzero-") as root:
        case = _o6_make_case(
            root,
            sample_names=(),
            std_names=("std_big_exercise.iyi",),
            config={
                "run_exits": {"P": 3, "C1": 3, "C3": 3},
                "run_stdout": {
                    "P": "producer\n",
                    "C1": "consumer-one\n",
                    "C3": "consumer-three\n",
                },
            },
        )
        rows = legs_mod.run_rows(
            [case.sources["std_big_exercise.iyi"]],
            repo=case.repo,
            compiler=case.compiler,
            work_root=case.work,
            nm_bin=case.nm,
            workers=1,
        )
        row = rows[0]
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "p_exit": row["p_exit"],
            "p_nonzero": row["p_nonzero"],
        }
    expected = {
        "status": "PASS",
        "codes": [],
        "p_exit": 3,
        "p_nonzero": True,
    }
    return Observation(expected=expected, got=got)


O6_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "s4.seed.row-oserror",
        "seed",
        _fixture_o6_row_oserror_seed,
    ),
    Fixture(
        "s4.seed.nm-unpinned",
        "seed",
        _fixture_o6_nm_pinned_seed,
    ),
    Fixture(
        "s4.seed.outputs-missing",
        "seed",
        _fixture_o6_outputs_seed,
    ),
    Fixture(
        "s4.seed.not-reusable-nested",
        "seed",
        _fixture_o6_not_reusable_seed,
    ),
    Fixture(
        "s4.seed.callpath-k2-diff",
        "seed",
        _fixture_o6_callpath_k2_seed,
    ),
    Fixture(
        "s4.seed.callpath-empty",
        "seed",
        _fixture_o6_callpath_empty_seed,
    ),
    Fixture(
        "s4.seed.callpath-mismatch",
        "seed",
        _fixture_o6_callpath_mismatch_seed,
    ),
    Fixture(
        "s4.seed.phase-not-linked",
        "seed",
        _fixture_o6_phase_seed,
    ),
    Fixture(
        "s4.seed.reach-not-checked",
        "seed",
        _fixture_o6_reach_checked_seed,
    ),
    Fixture(
        "s4.seed.key-file-missing",
        "seed",
        _fixture_o6_missing_key_seed,
    ),
    Fixture(
        "s4.seed.trace-empty",
        "seed",
        _fixture_o6_trace_empty_seed,
    ),
    Fixture(
        "s4.seed.symbol-c2",
        "seed",
        partial(_fixture_o6_symbol_seed, "C2"),
    ),
    Fixture(
        "s4.seed.symbol-c3",
        "seed",
        partial(_fixture_o6_symbol_seed, "C3"),
    ),
    Fixture(
        "s4.seed.nm-error",
        "seed",
        _fixture_o6_nm_error_seed,
    ),
    Fixture(
        "s4.seed.build-output-symbol",
        "seed",
        _fixture_o6_build_output_symbol_seed,
    ),
    Fixture(
        "s4.seed.build-timeout",
        "seed",
        partial(_fixture_o6_timeout_seed, "build"),
    ),
    Fixture(
        "s4.seed.run-timeout",
        "seed",
        partial(_fixture_o6_timeout_seed, "run"),
    ),
    Fixture(
        "s4.seed.lone-cr",
        "seed",
        partial(_fixture_o6_frame_text_seed, "lone-cr"),
    ),
    Fixture(
        "s4.seed.frame-function",
        "seed",
        _fixture_o6_frame_function_seed,
    ),
    Fixture(
        "s4.seed.frame-moved-byte",
        "seed",
        partial(_fixture_o6_frame_text_seed, "moved-byte"),
    ),
    Fixture(
        "s4.seed.exit-code",
        "seed",
        _fixture_o6_exit_code_seed,
    ),
    Fixture(
        "s4.seed.worker-reason-collision",
        "seed",
        _fixture_o6_worker_reason_seed,
    ),
    Fixture(
        "s4.seed.stdout-replaced",
        "seed",
        _fixture_o6_stdout_seed,
    ),
    Fixture(
        "s4.seed.wrong-count",
        "seed",
        _fixture_o6_wrong_count_seed,
    ),
    Fixture(
        "s4.seed.sandbox-leak",
        "seed",
        _fixture_o6_sandbox_seed,
    ),
    Fixture(
        "o6.seed.row-runtimeerror",
        "seed",
        _fixture_o6_row_runtimeerror_seed,
    ),
    Fixture(
        "o6.seed.build-missing",
        "seed",
        _fixture_o6_build_missing_seed,
    ),
    Fixture(
        "o6.seed.c3-cannot-name",
        "seed",
        _fixture_o6_c3_stop_seed,
    ),
    Fixture(
        "o6.seed.key-json-malformed",
        "seed",
        partial(_fixture_o6_key_parse_seed, "json"),
    ),
    Fixture(
        "o6.seed.key-root-nonobject",
        "seed",
        partial(_fixture_o6_key_parse_seed, "nonobject"),
    ),
    Fixture(
        "o6.seed.portable-nonobject",
        "seed",
        _fixture_o6_portable_type_seed,
    ),
    Fixture(
        "o6.seed.reach-nonobject",
        "seed",
        _fixture_o6_reach_type_seed,
    ),
    Fixture(
        "o6.seed.not-reusable-type",
        "seed",
        _fixture_o6_not_reusable_type_seed,
    ),
    Fixture(
        "o6.seed.run-output-symbol",
        "seed",
        _fixture_o6_run_effect_seed,
    ),
    Fixture(
        "o6.seed.row-r1-mismatch",
        "seed",
        _fixture_o6_row_r1_seed,
    ),
    Fixture(
        "o6.seed.nm-missing-binary",
        "seed",
        _fixture_o6_nm_missing_binary_seed,
    ),
    Fixture(
        "o6.seed.frames-missing-tool",
        "seed",
        partial(_fixture_o6_frame_harness_seed, "missing"),
    ),
    Fixture(
        "o6.seed.frames-tool-crash",
        "seed",
        partial(_fixture_o6_frame_harness_seed, "crash"),
    ),
    Fixture(
        "o6.seed.stdout-length",
        "seed",
        _fixture_o6_stdout_mismatch_seed,
    ),
    Fixture(
        "o6.seed.cli-required",
        "seed",
        _fixture_o6_cli_required_seed,
    ),
    Fixture(
        "o6.seed.cli-workers",
        "seed",
        _fixture_o6_cli_workers_seed,
    ),
    Fixture(
        "o6.seed.cli-negative-count",
        "seed",
        _fixture_o6_cli_negative_count_seed,
    ),
    Fixture(
        "s4.control.row",
        "control",
        _fixture_o6_row_control,
    ),
    Fixture(
        "s4.control.frames",
        "control",
        _fixture_o6_frame_control,
    ),
    Fixture(
        "s4.control.workers",
        "control",
        _fixture_o6_workers_control,
    ),
    Fixture(
        "s4.control.counts",
        "control",
        _fixture_o6_counts_control,
    ),
    Fixture(
        "s4.control.sandbox",
        "control",
        _fixture_o6_sandbox_control,
    ),
    Fixture(
        "o6.control.p-nonzero",
        "control",
        _fixture_o6_p_nonzero_control,
    ),
)
O6_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o6.row-runtimeerror": (
        "o6.seed.row-runtimeerror",
        "s4.control.row",
    ),
    "o6.cli-main": (
        "s4.seed.wrong-count",
        "s4.control.counts",
    ),
    "o6.frame-control-subcases": (
        "s4.seed.frame-function",
        "s4.control.frames",
    ),
    "o6.build-and-stop": (
        "o6.seed.build-missing",
        "o6.seed.c3-cannot-name",
        "s4.control.row",
    ),
    "o6.key-shapes": (
        "o6.seed.key-json-malformed",
        "o6.seed.key-root-nonobject",
        "o6.seed.portable-nonobject",
        "o6.seed.reach-nonobject",
        "o6.seed.not-reusable-type",
        "s4.control.row",
    ),
    "o6.run-output": (
        "o6.seed.run-output-symbol",
        "o6.seed.row-r1-mismatch",
        "s4.control.row",
    ),
    "o6.nm-missing-binary": (
        "o6.seed.nm-missing-binary",
        "s4.control.row",
    ),
    "o6.frame-harness": (
        "o6.seed.frames-missing-tool",
        "o6.seed.frames-tool-crash",
        "o6.seed.stdout-length",
        "s4.control.frames",
    ),
    "o6.cli-usage": (
        "o6.seed.cli-required",
        "o6.seed.cli-workers",
        "o6.seed.cli-negative-count",
        "s4.control.counts",
    ),
    "o6.p-nonzero": (
        "s4.seed.exit-code",
        "o6.control.p-nonzero",
    ),
}


# ===== O7: stages (owner U7). Keys "o7.". =====


O7_FIXTURES: tuple[Fixture, ...] = ()
O7_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {}


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
        "s2.seed.validator-nested-types",
        "s2.seed.validator-print-capture-skip",
        "s2.seed.validator-print-case-arm-regex",
        "s2.seed.validator-build-site-operand",
        "s2.seed.regression-1f",
        "s2.control.census-all",
        "s2.control.e1-shared-token",
        "s2.control.validator-print-capture",
        "s2.control.validator-print-case-arm",
        "s2.control.validator-print-quoted-punct",
        "s2.control.validator-build-site-aux",
    ),
    "o3.r0-all-violations": (
        "s2.seed.validator-nested-types",
        "s2.seed.regression-1f",
        "s2.control.census-all",
    ),
    "o3.r1-print-commands": (
        "s2.seed.validator-print-capture-skip",
        "s2.seed.validator-print-case-arm-regex",
        "s2.control.validator-print-capture",
        "s2.control.validator-print-case-arm",
        "s2.control.validator-print-quoted-punct",
    ),
    "o3.e1-cross-site-subcases": (
        "s2.seed.validator-e1-stray-reference",
        "s2.seed.validator-build-site-operand",
        "s2.control.validator-build-site-aux",
        "s2.control.e1-shared-token",
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
        "s2.seed.validator-e1-token",
        "s2.control.e1-shared-token",
    ),
    "amendment-b.seed.stray-shasum": (
        "s2.seed.validator-e1-stray-reference",
        "s2.control.e1-shared-token",
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

REVIEW_ITEMS = _merged_review_items(
    REVIEW_ITEMS, O4_REVIEW_ITEMS, O5_REVIEW_ITEMS, O6_REVIEW_ITEMS, O7_REVIEW_ITEMS,
)


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
    *O3_FIXTURES,
    *O4_FIXTURES,
    *O5_FIXTURES,
    *O6_FIXTURES,
    *O7_FIXTURES,
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
        except Exception as error:
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


def _run_fixture_suite(
    fixtures: tuple[Fixture, ...],
    review_items: Mapping[str, tuple[str, ...]],
    *,
    scope: str | None = None,
    expected_seed_ids: tuple[str, ...] | None = None,
    expected_control_ids: tuple[str, ...] | None = None,
) -> int:
    try:
        _print_header()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"HARNESS ERROR header={_render(f'{type(error).__name__}: {error}')}")
        return 1

    if scope is not None:
        shared_subcases = (
            " shared_token_subcases="
            "declared-two-site-control,undeclared-read,undeclared-build,"
            "declared-aux-output-control,non-output-operand-negative"
            if scope == "O3"
            else ""
        )
        print(
            f"SCOPE {scope} "
            f"seeds_expected={len(expected_seed_ids or ())} "
            f"controls_expected={len(expected_control_ids or ())}"
            f"{shared_subcases}"
        )

    registered_kinds: dict[str, str] = {}
    duplicate_registered_ids: set[str] = set()
    for fixture in fixtures:
        if fixture.fixture_id in registered_kinds:
            duplicate_registered_ids.add(fixture.fixture_id)
        registered_kinds[fixture.fixture_id] = fixture.kind

    harness = Harness()
    if expected_seed_ids is not None:
        actual_seed_ids = tuple(
            fixture.fixture_id
            for fixture in fixtures
            if fixture.kind == "seed"
        )
        if actual_seed_ids != expected_seed_ids:
            harness.execution_errors.append(
                "seed inventory mismatch: "
                f"expected={_render(expected_seed_ids)} "
                f"got={_render(actual_seed_ids)}"
            )
    if expected_control_ids is not None:
        actual_control_ids = tuple(
            fixture.fixture_id
            for fixture in fixtures
            if fixture.kind == "control"
        )
        if actual_control_ids != expected_control_ids:
            harness.execution_errors.append(
                "control inventory mismatch: "
                f"expected={_render(expected_control_ids)} "
                f"got={_render(actual_control_ids)}"
            )

    if duplicate_registered_ids:
        for fixture_id in sorted(duplicate_registered_ids):
            harness.execution_errors.append(
                f"duplicate registered fixture: {fixture_id}"
            )
    else:
        for fixture in fixtures:
            harness.run(fixture)

    audit = _coverage_audit(
        review_items,
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


def run_o3_suite() -> int:
    """Run only the bounded O3 census validator acceptance inventory."""
    return _run_fixture_suite(
        O3_FIXTURES,
        O3_REVIEW_ITEMS,
        scope="O3",
        expected_seed_ids=O3_SEED_IDS,
        expected_control_ids=O3_CONTROL_IDS,
    )


def main() -> int:
    return _run_fixture_suite(FIXTURES, REVIEW_ITEMS)


if __name__ == "__main__":
    raise SystemExit(main())
