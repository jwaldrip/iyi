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


def _fake_real_compiler(directory: str, *, version_line: str) -> str:
    """Write the stateful fake REAL shared by O4 and the stage fixtures."""
    root = os.path.realpath(directory)
    os.makedirs(root, exist_ok=True)
    default_root = os.path.join(root, "default-root")
    default_cache = os.path.join(root, "default-cache")
    os.makedirs(default_root, exist_ok=True)
    os.makedirs(default_cache, exist_ok=True)
    path = os.path.join(root, "iyi")
    template = r"""#!/usr/bin/env python3
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time

VERSION_LINE = __VERSION_LINE__
DEFAULT_ROOT = __DEFAULT_ROOT__
DEFAULT_CACHE = __DEFAULT_CACHE__

ONE_VALUE = {
    "-D", "--define", "--frame-pointers", "--emit",
    "--x86-asm-syntax", "-f", "--format", "--link-flags",
    "--mcpu", "--mattr", "--mcmodel", "--warnings",
    "--exclude-warnings", "-o", "--output", "--prelude",
    "--iyi-keep", "--emit-bind", "--emit-iyimod", "--use-iyimod",
    "-O", "--threads", "--target", "--stale-key", "--stale-accept",
    "--stale-block", "--stale-dump-elements", "--stdin-filename",
}

def append_json(path, record):
    if not path:
        return
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)

def split_args(args):
    if "--" in args:
        index = args.index("--")
        return args[:index], args[index + 1:]
    return args, []

def option_value(args, *names):
    found = None
    index = 0
    while index < len(args):
        token = args[index]
        for name in names:
            if token == name and index + 1 < len(args):
                found = args[index + 1]
            elif name.startswith("--") and token.startswith(name + "="):
                found = token.split("=", 1)[1]
            elif len(name) == 2 and token.startswith(name) and token != name:
                found = token[len(name):]
        index += 1
    return found

def positional(args):
    values = []
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("-") and token != "-":
            name = token.split("=", 1)[0]
            attached = (
                len(token) > 2
                and token[:2] in {"-D", "-o", "-O", "-f"}
            )
            if name in ONE_VALUE and "=" not in token and not attached:
                index += 2
            else:
                index += 1
            continue
        values.append(token)
        index += 1
    return values

stdin_data = sys.stdin.buffer.read()
args = sys.argv[1:]
before, run_args = split_args(args)
out_before = option_value(before, "-o", "--output")
append_json(
    os.environ.get("FAKE_REAL_LOG"),
    {
        "argv": sys.argv,
        "cwd": os.getcwd(),
        "env": dict(os.environ),
        "stdin_len": len(stdin_data),
        "stdin_sha256": hashlib.sha256(stdin_data).hexdigest(),
        "out_existed_before": bool(out_before and os.path.exists(out_before)),
    },
)


if args == ["--version"] or args == ["version"]:
    print(VERSION_LINE)
    raise SystemExit(0)

if args and args[0] == "env":
    values = {
        "IYI_PATH": os.environ.get(
            "IYI_PATH",
            os.environ.get("CRYSTAL_PATH", DEFAULT_ROOT),
        ),
        "IYI_CACHE_DIR": os.environ.get("IYI_CACHE_DIR", DEFAULT_CACHE),
        "IYI_EXEC_PATH": "",
        "IYI_LIBRARY_PATH": "",
        "IYI_OPTS": os.environ.get("IYI_OPTS", ""),
        "CRYSTAL_VERSION": "fake",
    }
    names = args[1:]
    if not names:
        for name, value in values.items():
            print(f"{name}={shlex.quote(value)}")
    else:
        for name in names:
            if name not in values:
                print(f"env: no such variable: {name}", file=sys.stderr)
                raise SystemExit(2)
            print(values[name])
    raise SystemExit(0)

if not args:
    raise SystemExit(0)
command = args[0]
if not (command == "run" or (command and "build".startswith(command))):
    raise SystemExit(0)

compiler_args, run_args = split_args(args[1:])
emit_dir = option_value(compiler_args, "--emit-iyimod")
use_dir = option_value(compiler_args, "--use-iyimod")
sleep_setting = os.environ.get("FAKE_REAL_SLEEP")
if sleep_setting:
    scope, separator, seconds = sleep_setting.partition(":")
    if not separator:
        scope, seconds = "all", scope
    if (
        scope == "all"
        or (scope == "producer" and emit_dir is not None)
        or (scope == "consumer" and use_dir is not None)
    ):
        time.sleep(float(seconds))
failure = os.environ.get("FAKE_REAL_FAIL")
if failure == "producer" and emit_dir is not None:
    sys.stdout.buffer.write(b"fake producer stdout\n")
    sys.stderr.buffer.write(b"fake producer stderr\n")
    raise SystemExit(71)
if failure == "consumer" and use_dir is not None:
    print("fake consumer failure", file=sys.stderr)
    raise SystemExit(72)

if emit_dir is not None and os.environ.get("FAKE_REAL_ZERO_MODS") != "1":
    os.makedirs(emit_dir, exist_ok=True)
    with open(os.path.join(emit_dir, "fake.iyimod"), "wb") as module:
        module.write(b"fake module\n")

output = option_value(compiler_args, "-o", "--output")
sources = positional(compiler_args)
if output is None:
    stem = os.path.splitext(os.path.basename(sources[0] if sources else "a.iyi"))[0]
    if command == "run":
        cache = os.environ.get("IYI_CACHE_DIR", DEFAULT_CACHE)
        output = os.path.join(cache, f"iyi-run-{stem}-{os.getpid()}.tmp")
    else:
        output = os.path.join(os.getcwd(), stem)
if not os.path.isabs(output):
    output = os.path.join(os.getcwd(), output)
os.makedirs(os.path.dirname(output), exist_ok=True)

program_runtime = r'''import hashlib,json,os,sys,time
data=sys.stdin.buffer.read()
path=os.environ.get("FAKE_PROGRAM_LOG")
if path:
    payload=(json.dumps({"argv":sys.argv[1:],"cwd":os.getcwd(),"env":dict(os.environ),"stdin_len":len(data),"stdin_sha256":hashlib.sha256(data).hexdigest()},sort_keys=True,separators=(",",":"))+"\n").encode()
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    try: os.write(fd,payload)
    finally: os.close(fd)
sleep=os.environ.get("FAKE_PROGRAM_SLEEP")
if sleep: time.sleep(float(sleep))
rc=int(os.environ.get("FAKE_PROGRAM_RC","0"))
if rc < 0:
    os.kill(os.getpid(),-rc)
    time.sleep(1)
raise SystemExit(rc)
'''
program = (
    "#!/bin/sh\nexec "
    + shlex.quote(sys.executable)
    + " -c "
    + shlex.quote(program_runtime)
    + ' "$@"\n'
)
with open(output, "w", encoding="utf-8") as executable:
    executable.write(program)
os.chmod(output, 0o755)

if command == "run" and option_value(compiler_args, "-o", "--output") is None:
    completed = subprocess.run([output, *run_args], check=False)
    try:
        os.unlink(output)
    except FileNotFoundError:
        pass
    raise SystemExit(completed.returncode)
raise SystemExit(0)
"""
    script = (
        template.replace("__VERSION_LINE__", repr(version_line))
        .replace("__DEFAULT_ROOT__", repr(default_root))
        .replace("__DEFAULT_CACHE__", repr(default_cache))
    )
    with open(path, "w", encoding="utf-8") as target:
        target.write(script)
    os.chmod(path, 0o755)
    return os.path.realpath(path)


class _O4FixtureEnvironment:
    def __init__(self) -> None:
        created = tempfile.mkdtemp(prefix="iyi-o4-", dir="/tmp")
        self.root = os.path.realpath(created)
        self.repo = os.path.join(self.root, "repo")
        self.work_tmp = os.path.join(self.root, "t")
        self.scratch = os.path.join(self.root, "s")
        self.cache = os.path.join(self.root, "cache")
        self.fake_dir = os.path.join(self.root, "fake")
        for path in (
            self.repo,
            self.work_tmp,
            self.scratch,
            self.cache,
            self.fake_dir,
        ):
            os.makedirs(path, exist_ok=True)
        self.canonical_root = os.path.join(self.repo, "src")
        self.bench = os.path.join(self.repo, "bench")
        os.makedirs(self.canonical_root, exist_ok=True)
        os.makedirs(self.bench, exist_ok=True)
        self.own_source = os.path.join(self.bench, "std_demo_exercise.iyi")
        self.other_source = os.path.join(self.bench, "other.iyi")
        for path, content in (
            (self.own_source, "puts :own\n"),
            (self.other_source, "puts :other\n"),
        ):
            with open(path, "w", encoding="utf-8") as target:
                target.write(content)
        self.real = _fake_real_compiler(
            self.fake_dir,
            version_line="iyi fake [0123456789abcdef]",
        )
        self.default_root = os.path.join(self.fake_dir, "default-root")
        self.ledger = os.path.join(self.root, "ledger.jsonl")
        self.real_log = os.path.join(self.root, "real.jsonl")
        self.program_log = os.path.join(self.root, "program.jsonl")
        self.census_path = os.path.join(self.root, "census.json")
        self.config_path = os.path.join(self.root, "shim.json")
        self.nonce = "a" * 32
        self.chain_id = "b" * 32
        self.driver = "demo"
        self.census = {
            "census_version": 1,
            "driver": self.driver,
            "sites": [
                {
                    "lines": [1],
                    "command": "build",
                    "kind": "mixed",
                    "variants": [
                        {
                            "id": "demo.negative",
                            "kind": "negative",
                            "first_root": "{WORK}/negative",
                            "vars": {},
                            "sources": [
                                "{REPO}/bench/std_demo_exercise.iyi"
                            ],
                            "output": None,
                        },
                        {
                            "id": "demo.positive",
                            "kind": "positive",
                            "first_root": "{WORK}/positive",
                            "vars": {},
                            "sources": [
                                "{REPO}/bench/std_demo_exercise.iyi"
                            ],
                            "output": None,
                        },
                    ],
                }
            ],
            "exec_evidence": [],
        }
        self.config = {
            "real": self.real,
            "census": os.path.realpath(self.census_path),
            "ledger": self.ledger,
            "nonce": self.nonce,
            "driver": self.driver,
            "work_tmp": os.path.realpath(self.work_tmp),
            "scratch": self.scratch,
            "repo": os.path.realpath(self.repo),
            "canonical_roots": [os.path.realpath(self.canonical_root)],
        }
        self.write_census(self.census)
        self.write_header()
        self.write_config()

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "_O4FixtureEnvironment":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def write_census(self, census: dict) -> None:
        self.census = census
        with open(self.census_path, "w", encoding="utf-8") as target:
            json.dump(census, target, sort_keys=True)

    def write_header(
        self,
        *,
        nonce: str | None = None,
        driver: str | None = None,
    ) -> None:
        header = {
            "v": 1,
            "kind": "header",
            "nonce": self.nonce if nonce is None else nonce,
            "driver": self.driver if driver is None else driver,
            "attempt": 1,
            "chain_id": self.chain_id,
        }
        with open(self.ledger, "w", encoding="utf-8") as target:
            target.write(json.dumps(header, sort_keys=True) + "\n")

    def write_config(self) -> None:
        with open(self.config_path, "w", encoding="utf-8") as target:
            json.dump(self.config, target, sort_keys=True)

    def environment(self, **updates: str | None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in tuple(environment):
            if name.startswith(("IYI_", "CRYSTAL_")) or name.startswith("FAKE_"):
                environment.pop(name, None)
        environment.update(
            {
                "IYI_PATH": self.canonical_root,
                "IYI_CACHE_DIR": self.cache,
                "FAKE_REAL_LOG": self.real_log,
                "FAKE_PROGRAM_LOG": self.program_log,
            }
        )
        for name, value in updates.items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return environment

    def run_in_process(
        self,
        argv: list[str],
        *,
        environment: dict[str, str] | None = None,
    ) -> int | shim_mod.ExecPlan:
        child_env = environment or self.environment()
        previous_cwd = os.getcwd()
        previous_env = os.environ.copy()
        try:
            os.chdir(self.repo)
            os.environ.clear()
            os.environ.update(child_env)
            return shim_mod.run_shim(self.config_path, argv)
        finally:
            os.environ.clear()
            os.environ.update(previous_env)
            os.chdir(previous_cwd)

    def run_process(
        self,
        argv: list[str],
        *,
        environment: dict[str, str] | None = None,
        stdin: bytes = b"",
        shim_path: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                shim_path or os.path.abspath(shim_mod.__file__),
                "--config",
                self.config_path,
                "--",
                *argv,
            ],
            cwd=self.repo,
            env=environment or self.environment(),
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def records(self) -> list[dict]:
        return _o4_read_jsonl(self.ledger)

    def real_calls(self) -> list[dict]:
        return _o4_read_jsonl(self.real_log)

    def program_calls(self) -> list[dict]:
        return _o4_read_jsonl(self.program_log)


def _o4_read_jsonl(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as source:
        for line in source:
            if line.strip():
                records.append(json.loads(line))
    return records


def _o4_phase(records: list[dict], phase: str) -> list[dict]:
    return [
        record
        for record in records
        if record.get("kind") == "record" and record.get("phase") == phase
    ]


@contextlib.contextmanager
def _o4_devnull_stdin():
    saved = os.dup(0)
    null = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(null, 0)
        yield
    finally:
        os.dup2(saved, 0)
        os.close(null)
        os.close(saved)


def _o4_fake_calls(calls: list[dict], marker: str) -> list[dict]:
    return [
        call
        for call in calls
        if len(call.get("argv", [])) > 1 and marker in call["argv"]
    ]


def _o4_matcher_fixture(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        repo = fixture.repo
        work = fixture.work_tmp
        driver_work = os.path.join(work, "driver-work")
        source = fixture.own_source
        base_variant = {
            "id": "negative.one",
            "kind": "negative",
            "first_root": "{WORK}/{dir}",
            "vars": {"dir": {"lines": [1, 1], "values": ["noquestion"]}},
            "sources": ["{REPO}/bench/std_demo_exercise.iyi"],
            "output": None,
        }
        variants = [base_variant]
        first_root = os.path.join(driver_work, "noquestion")
        sources = [source]
        output = None
        if case == "unknown-dir":
            first_root = os.path.join(driver_work, "unknown")
        elif case == "outside-attempt":
            first_root = os.path.join(fixture.root, "outside", "noquestion")
        elif case == "copied-exercise":
            copied = os.path.join(fixture.root, "copy", "std_demo_exercise.iyi")
            os.makedirs(os.path.dirname(copied), exist_ok=True)
            shutil.copyfile(source, copied)
            sources = [copied]
        elif case == "two-same-kind":
            variants.append({**base_variant, "id": "negative.two"})
        elif case == "conflicting-kinds":
            variants.append(
                {**base_variant, "id": "positive.two", "kind": "positive"}
            )
        elif case == "variable-root":
            base_variant = {
                **base_variant,
                "id": "negative.variable",
                "sources": [
                    "{REPO}/bench/std_{driver}_exercise.iyi"
                ],
                "vars": {
                    "dir": {
                        "lines": [1, 1],
                        "values": ["noquestion"],
                    },
                    "driver": {
                        "lines": [1, 1],
                        "values": ["demo"],
                    },
                },
                "output": "{WORK}/{dir}/result",
            }
            variants = [base_variant]
            output = os.path.join(driver_work, "noquestion", "result")
        census = {
            "sites": [
                {
                    "command": "build",
                    "kind": "mixed",
                    "variants": variants,
                }
            ]
        }
        result = shim_mod.match_variants(
            census,
            "build",
            first_root,
            sources,
            output,
            work,
            repo,
        )
        status, ids, kind, bindings = result
        got = {
            "status": status,
            "ids": ids,
            "kind": kind,
            "bindings": bindings,
        }
        if case in ("unknown-dir", "outside-attempt", "copied-exercise"):
            expected = {
                "status": "unclassified",
                "ids": [],
                "kind": None,
                "bindings": {},
            }
        elif case == "two-same-kind":
            expected = {
                "status": "matched",
                "ids": ["negative.one", "negative.two"],
                "kind": "negative",
                "bindings": {
                    "negative.one": {"dir": "noquestion"},
                    "negative.two": {"dir": "noquestion"},
                },
            }
        elif case == "conflicting-kinds":
            expected = {
                "status": "ambiguous",
                "ids": ["negative.one", "positive.two"],
                "kind": None,
                "bindings": {
                    "negative.one": {"dir": "noquestion"},
                    "positive.two": {"dir": "noquestion"},
                },
            }
        elif case == "variable-root":
            expected = {
                "status": "matched",
                "ids": ["negative.variable"],
                "kind": "negative",
                "bindings": {
                    "negative.variable": {
                        "dir": "noquestion",
                        "driver": "demo",
                    }
                },
            }
        else:
            expected = {
                "status": "matched",
                "ids": ["negative.one"],
                "kind": "negative",
                "bindings": {
                    "negative.one": {"dir": "noquestion"}
                },
            }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"case={case};root={os.path.realpath(first_root)};"
                f"sources={_render([os.path.realpath(path) for path in sources])}"
            ),
        )


def _o4_matcher_canonical_control() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        invocation = shim_mod.parse_invocation(
            ["build", "-o", os.path.join(fixture.root, "out"), fixture.own_source]
        )
        classification = shim_mod.classify(
            fixture.census,
            invocation,
            [fixture.canonical_root],
            [fixture.canonical_root],
            [fixture.own_source],
            os.path.join(fixture.root, "out"),
            fixture.work_tmp,
            fixture.repo,
        )
        got = {
            "mode": classification.mode,
            "canonical": classification.canonical,
            "variant_ids": list(classification.variant_ids),
        }
        return Observation(
            expected={
                "mode": "roundtrip",
                "canonical": True,
                "variant_ids": [],
            },
            got=got,
        )


def _o4_normalized_roundtrip_call(call: dict) -> list[str]:
    argv = list(call["argv"][1:])
    for marker in ("--emit-iyimod", "--use-iyimod"):
        if marker in argv:
            index = argv.index(marker)
            argv[index : index + 2] = [marker, "<MODS>"]
    return argv


def _o4_canonical_build(*, through_main: bool) -> dict:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "canonical-out")
        argv = ["build", "-o", output, fixture.own_source]
        if through_main:
            completed = fixture.run_process(argv)
            rc = completed.returncode
        else:
            result = fixture.run_in_process(argv)
            rc = result if isinstance(result, int) else -999
        calls = fixture.real_calls()
        producers = _o4_fake_calls(calls, "--emit-iyimod")
        consumers = _o4_fake_calls(calls, "--use-iyimod")
        records = fixture.records()
        begin = _o4_phase(records, "begin")
        end = _o4_phase(records, "end")
        producer_argv = (
            _o4_normalized_roundtrip_call(producers[0]) if producers else []
        )
        consumer_argv = (
            _o4_normalized_roundtrip_call(consumers[0]) if consumers else []
        )
        same_mods = False
        if producers and consumers:
            producer_raw = producers[0]["argv"]
            consumer_raw = consumers[0]["argv"]
            same_mods = (
                producer_raw[producer_raw.index("--emit-iyimod") + 1]
                == consumer_raw[consumer_raw.index("--use-iyimod") + 1]
            )
        return {
            "rc": rc,
            "producer_argv": producer_argv,
            "consumer_argv": consumer_argv,
            "same_mods": same_mods,
            "consumer_saw_old_out": (
                consumers[0].get("out_existed_before") if consumers else None
            ),
            "paired": (
                len(begin) == 1
                and len(end) == 1
                and begin[0].get("inv") == end[0].get("inv")
                and begin[0].get("argv") == end[0].get("argv")
            ),
        }


def _o4_canonical_seed() -> Observation:
    got = _o4_canonical_build(through_main=False)
    producer = got.get("producer_argv", [])
    consumer = got.get("consumer_argv", [])
    expected = {
        "rc": 0,
        "producer_argv": producer,
        "consumer_argv": consumer,
        "same_mods": True,
        "consumer_saw_old_out": False,
        "paired": True,
    }
    exact = (
        producer[:4] == ["build", "-Diyi_observe", "--emit-iyimod", "<MODS>"]
        and consumer[:4]
        == ["build", "-Diyi_observe", "--use-iyimod", "<MODS>"]
        and producer[4:] == consumer[4:]
    )
    got = {**got, "exact_only_documented_insertions": exact}
    expected["exact_only_documented_insertions"] = True
    return Observation(
        expected=expected,
        got=got,
        applied="canonical argv checked token-for-token around emit/use insertion",
    )


def _o4_canonical_control() -> Observation:
    got = _o4_canonical_build(through_main=True)
    producer = got.get("producer_argv", [])
    consumer = got.get("consumer_argv", [])
    expected = {
        "rc": 0,
        "producer_argv": producer,
        "consumer_argv": consumer,
        "same_mods": True,
        "consumer_saw_old_out": False,
        "paired": True,
    }
    return Observation(expected=expected, got=got)


def _o4_b_prefix_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "b-out")
        result = fixture.run_in_process(
            ["b", "-o", output, fixture.own_source]
        )
        calls = [
            call
            for call in fixture.real_calls()
            if "--emit-iyimod" in call.get("argv", [])
            or "--use-iyimod" in call.get("argv", [])
        ]
        got = {
            "rc": result,
            "command_words": [call["argv"][1] for call in calls],
        }
        return Observation(
            expected={"rc": 0, "command_words": ["b", "b"]},
            got=got,
            applied="command_word=b",
        )


def _o4_run_fixture(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        environment = fixture.environment()
        argv = ["run", fixture.own_source]
        stdin = b""
        if case in ("argv-or-rc", "control"):
            environment["FAKE_PROGRAM_RC"] = "3"
            argv.extend(["--", "alpha", "two words"])
        elif case == "stdin":
            argv.extend(["--", "stdin-case"])
            stdin = b"stdin reaches only the program\n"
        elif case == "run-o":
            argv = [
                "run",
                "-o",
                os.path.join(fixture.root, "run-o"),
                fixture.own_source,
            ]
        completed = fixture.run_process(argv, environment=environment, stdin=stdin)
        end_records = _o4_phase(fixture.records(), "end")
        end = end_records[-1] if end_records else {}
        program_calls = fixture.program_calls()
        build_calls = [
            call
            for call in fixture.real_calls()
            if "--emit-iyimod" in call.get("argv", [])
            or "--use-iyimod" in call.get("argv", [])
        ]
        if case == "temp-path":
            out = end.get("out")
            got = {
                "rc": completed.returncode,
                "name_ok": bool(
                    isinstance(out, str)
                    and re.fullmatch(
                        r"iyi-run-std_demo_exercise-[0-9]+\\.tmp",
                        os.path.basename(out),
                    )
                ),
                "deleted": isinstance(out, str) and not os.path.exists(out),
                "run_args": (end.get("run") or {}).get("argv", [])[1:],
            }
            expected = {
                "rc": 0,
                "name_ok": True,
                "deleted": True,
                "run_args": [],
            }
        elif case in ("argv-or-rc", "control"):
            got = {
                "rc": completed.returncode,
                "program_args": (
                    program_calls[-1].get("argv") if program_calls else None
                ),
                "ledger_rc": (end.get("run") or {}).get("rc"),
                "ledger_signal": (end.get("run") or {}).get("signal"),
            }
            expected = {
                "rc": 3,
                "program_args": ["alpha", "two words"],
                "ledger_rc": 3,
                "ledger_signal": None,
            }
        elif case == "run-o":
            got = {
                "rc": completed.returncode,
                "program_calls": len(program_calls),
                "run_record": end.get("run"),
                "out_exists": os.path.isfile(os.path.join(fixture.root, "run-o")),
            }
            expected = {
                "rc": 0,
                "program_calls": 0,
                "run_record": None,
                "out_exists": True,
            }
        else:
            expected_sha = hashlib.sha256(stdin).hexdigest()
            got = {
                "rc": completed.returncode,
                "build_stdin": [
                    (call.get("stdin_len"), call.get("stdin_sha256"))
                    for call in build_calls
                ],
                "program_stdin": (
                    (
                        program_calls[-1].get("stdin_len"),
                        program_calls[-1].get("stdin_sha256"),
                    )
                    if program_calls
                    else None
                ),
            }
            expected = {
                "rc": 0,
                "build_stdin": [
                    (0, hashlib.sha256(b"").hexdigest()),
                    (0, hashlib.sha256(b"").hexdigest()),
                ],
                "program_stdin": (len(stdin), expected_sha),
            }
        return Observation(
            expected=expected,
            got=got,
            applied=f"run-case={case};stdin_sha256={hashlib.sha256(stdin).hexdigest()}",
        )


def _o4_producer_failure_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        environment = fixture.environment(FAKE_REAL_FAIL="producer")
        output = os.path.join(fixture.root, "producer-fail")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                ["build", "-o", output, fixture.own_source],
                environment=environment,
            )
        consumers = _o4_fake_calls(fixture.real_calls(), "--use-iyimod")
        end = _o4_phase(fixture.records(), "end")
        got = {
            "rc": result,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "consumer_calls": len(consumers),
            "consumer_record": end[-1].get("consumer") if end else "missing",
        }
        return Observation(
            expected={
                "rc": 71,
                "stdout": "fake producer stdout\n",
                "stderr": "fake producer stderr\n",
                "consumer_calls": 0,
                "consumer_record": None,
            },
            got=got,
            applied="FAKE_REAL_FAIL=producer",
        )


def _o4_evidence_census(
    fixture: _O4FixtureEnvironment,
    *,
    command: str,
    name: str,
) -> dict:
    census = {
        "census_version": 1,
        "driver": fixture.driver,
        "sites": [
            {
                "lines": [1],
                "command": command,
                "kind": "canonical-own",
                "variants": [],
            }
        ],
        "exec_evidence": [
            {
                "site_line": 1,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {"1": name},
            }
        ],
    }
    fixture.write_census(census)
    return census


def _o4_verify(
    fixture: _O4FixtureEnvironment,
    census: dict,
) -> frozenset[str]:
    verdict = proofkit_mod.verify_ledger(
        fixture.ledger,
        census=census,
        driver=fixture.driver,
        nonce=fixture.nonce,
        attempt=1,
        chain_id=fixture.chain_id,
        work_tmp=fixture.work_tmp,
        repo=fixture.repo,
    )
    return verdict.statuses


def _o4_consumer_failure_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        evidence_dir = os.path.join(fixture.work_tmp, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        own_out = os.path.join(evidence_dir, "own")
        census = _o4_evidence_census(fixture, command="build", name="own")
        control = fixture.run_in_process(
            ["build", "-o", own_out, fixture.own_source]
        )
        subprocess.run(
            [own_out],
            cwd=fixture.repo,
            env=fixture.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        failed = fixture.run_in_process(
            [
                "build",
                "-o",
                os.path.join(fixture.root, "consumer-fail"),
                fixture.other_source,
            ],
            environment=fixture.environment(FAKE_REAL_FAIL="consumer"),
        )
        statuses = _o4_verify(fixture, census)
        got = {
            "control_rc": control,
            "failure_rc": failed,
            "statuses": sorted(statuses),
        }
        return Observation(
            expected={
                "control_rc": 0,
                "failure_rc": 72,
                "statuses": ["DIVERGENCE"],
            },
            got=got,
            applied="second canonical-other consumer has FAKE_REAL_FAIL=consumer",
        )


def _o4_run_consumer_failure_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        completed = fixture.run_process(
            ["run", fixture.own_source, "--", "must-not-run"],
            environment=fixture.environment(FAKE_REAL_FAIL="consumer"),
        )
        end = _o4_phase(fixture.records(), "end")
        record = end[-1] if end else {}
        got = {
            "rc": completed.returncode,
            "consumer_rc": (record.get("consumer") or {}).get("rc"),
            "run": record.get("run"),
            "program_calls": len(fixture.program_calls()),
        }
        return Observation(
            expected={
                "rc": 72,
                "consumer_rc": 72,
                "run": None,
                "program_calls": 0,
            },
            got=got,
            applied="run consumer has FAKE_REAL_FAIL=consumer",
        )


def _o4_own_run_verifier_seed(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        cache = os.path.join(fixture.work_tmp, "run-cache")
        os.makedirs(cache, exist_ok=True)
        updates: dict[str, str | None] = {"IYI_CACHE_DIR": cache}
        if case == "zero-modules":
            updates["FAKE_REAL_ZERO_MODS"] = "1"
            expected_rc = 0
            expected_statuses = ["NOT-ROUNDTRIPPED"]
        else:
            updates["FAKE_PROGRAM_RC"] = "-9"
            expected_rc = 1
            expected_statuses = ["UNFAITHFUL"]
        stderr = io.StringIO()
        with _o4_devnull_stdin(), contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                ["run", fixture.own_source],
                environment=fixture.environment(**updates),
            )
        end = _o4_phase(fixture.records(), "end")
        name = ""
        if end and isinstance(end[-1].get("out"), str):
            name = os.path.basename(end[-1]["out"])
        census = _o4_evidence_census(fixture, command="run", name=name)
        statuses = _o4_verify(fixture, census)
        death_sentence = (
            None
            if case == "zero-modules"
            else "iyi: the program was killed by signal 9 "
            "(received and didn't handle signal KILL (9))\n"
        )
        got = {
            "rc": result,
            "statuses": sorted(statuses),
            "run_signal": (
                (end[-1].get("run") or {}).get("signal") if end else None
            ),
            "death_sentence": (
                None
                if case == "zero-modules"
                else stderr.getvalue()
            ),
        }
        expected = {
            "rc": expected_rc,
            "statuses": expected_statuses,
            "run_signal": None if case == "zero-modules" else 9,
            "death_sentence": death_sentence,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                "FAKE_REAL_ZERO_MODS=1"
                if case == "zero-modules"
                else "FAKE_PROGRAM_RC=-9"
            ),
        )


def _o4_exec_plan_fixture(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "exec-out")
        environment = fixture.environment()
        argv = ["build", "-o", output, fixture.own_source]
        if case in ("passthrough", "passthrough-control"):
            argv = [
                "build",
                "--emit-iyimod",
                os.path.join(fixture.root, "external-mods"),
                "-o",
                output,
                fixture.own_source,
            ]
        elif case == "observe-duplicate":
            negative = os.path.join(fixture.work_tmp, "driver-work", "negative")
            os.makedirs(negative, exist_ok=True)
            environment["IYI_PATH"] = negative
            argv.insert(1, "-Diyi_observe")
        elif case in ("negative", "negative-control"):
            negative = os.path.join(fixture.work_tmp, "driver-work", "negative")
            os.makedirs(negative, exist_ok=True)
            environment["IYI_PATH"] = negative
        elif case == "cross-compile":
            argv = ["run", "--cross-compile", fixture.own_source]
        if case == "passthrough-control":
            completed = fixture.run_process(argv, environment=environment)
            records = _o4_phase(fixture.records(), "exec")
            build_calls = [
                call
                for call in fixture.real_calls()
                if len(call.get("argv", [])) > 1
                and call["argv"][1] == "build"
            ]
            got = {
                "rc": completed.returncode,
                "mode": records[-1].get("mode") if records else None,
                "observe_count": (
                    build_calls[-1]["argv"].count("-Diyi_observe")
                    if build_calls
                    else 0
                ),
            }
            expected = {"rc": 0, "mode": "passthrough", "observe_count": 1}
        else:
            result = fixture.run_in_process(argv, environment=environment)
            record = _o4_phase(fixture.records(), "exec")
            got = {
                "is_plan": isinstance(result, shim_mod.ExecPlan),
                "mode": record[-1].get("mode") if record else None,
                "argv": list(result.argv) if isinstance(result, shim_mod.ExecPlan) else [],
            }
            if case == "cross-compile":
                expected_argv = argv
                expected_mode = "unchanged"
            else:
                expected_argv = list(argv)
                if "-Diyi_observe" not in expected_argv:
                    expected_argv.insert(1, "-Diyi_observe")
                expected_mode = (
                    "observed-negative"
                    if case in ("negative", "negative-control", "observe-duplicate")
                    else "passthrough"
                )
            expected = {
                "is_plan": True,
                "mode": expected_mode,
                "argv": expected_argv,
            }
            if case == "passthrough":
                unchanged_inputs = [
                    ["doc", fixture.own_source],
                    ["fmt", fixture.own_source],
                    ["env", "IYI_PATH"],
                    ["build", "--no-codegen", fixture.own_source],
                ]
                unchanged: list[dict[str, object]] = []
                for unchanged_argv in unchanged_inputs:
                    unchanged_result = fixture.run_in_process(
                        unchanged_argv,
                        environment=environment,
                    )
                    unchanged_records = _o4_phase(fixture.records(), "exec")
                    unchanged.append(
                        {
                            "is_plan": isinstance(
                                unchanged_result,
                                shim_mod.ExecPlan,
                            ),
                            "mode": (
                                unchanged_records[-1].get("mode")
                                if unchanged_records
                                else None
                            ),
                            "argv": (
                                list(unchanged_result.argv)
                                if isinstance(unchanged_result, shim_mod.ExecPlan)
                                else []
                            ),
                        }
                    )
                exact_unchanged = [
                    {
                        "is_plan": True,
                        "mode": "unchanged",
                        "argv": unchanged_argv,
                    }
                    for unchanged_argv in unchanged_inputs
                ]
                got["unchanged"] = unchanged
                expected["unchanged"] = exact_unchanged
        return Observation(
            expected=expected,
            got=got,
            applied=f"exec-mode-case={case}",
        )


def _o4_positive_fixture(*, control: bool) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        positive = os.path.join(fixture.work_tmp, "driver-work", "positive")
        os.makedirs(positive, exist_ok=True)
        output = os.path.join(fixture.root, "positive-out")
        result = fixture.run_in_process(
            ["build", "-o", output, fixture.own_source],
            environment=fixture.environment(IYI_PATH=positive),
        )
        records = _o4_phase(fixture.records(), "end")
        end = records[-1] if records else {}
        got = {
            "rc": result,
            "variant_ids": end.get("variant_ids"),
            "variant_kind": end.get("variant_kind"),
            "producer_rc": (end.get("producer") or {}).get("rc"),
            "consumer_rc": (end.get("consumer") or {}).get("rc"),
        }
        return Observation(
            expected={
                "rc": 0,
                "variant_ids": ["demo.positive"],
                "variant_kind": "positive",
                "producer_rc": 0,
                "consumer_rc": 0,
            },
            got=got,
            applied="" if control else "IYI_PATH selects census positive root",
        )


def _o4_unknown_root_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        unknown = os.path.join(fixture.work_tmp, "driver-work", "unknown")
        os.makedirs(unknown, exist_ok=True)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                [
                    "build",
                    "-o",
                    os.path.join(fixture.root, "unknown-out"),
                    fixture.own_source,
                ],
                environment=fixture.environment(IYI_PATH=unknown),
            )
        records = _o4_phase(fixture.records(), "refused")
        compiler_calls = [
            call
            for call in fixture.real_calls()
            if len(call.get("argv", [])) > 1
            and (
                call["argv"][1] == "run"
                or "build".startswith(call["argv"][1])
            )
        ]
        got = {
            "rc": result,
            "refused": "REFUSED unclassified variant match" in stderr.getvalue(),
            "recorded": len(records),
            "compiler_calls": len(compiler_calls),
        }
        return Observation(
            expected={
                "rc": 125,
                "refused": True,
                "recorded": 1,
                "compiler_calls": 0,
            },
            got=got,
            applied=f"unknown_root={unknown}",
        )


def _o4_root_fixture(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "root-out")
        environment = fixture.environment()
        if case == "empty":
            environment["IYI_PATH"] = ""
        else:
            relative = "relative-root"
            resolved = os.path.join(fixture.repo, relative)
            os.makedirs(resolved, exist_ok=True)
            fixture.config["canonical_roots"].append(os.path.realpath(resolved))
            fixture.write_config()
            environment["IYI_PATH"] = relative
        result = fixture.run_in_process(
            ["build", "-o", output, fixture.own_source],
            environment=environment,
        )
        end = _o4_phase(fixture.records(), "end")
        got = {
            "rc": result,
            "canonical": end[-1].get("canonical") if end else None,
            "first_noncanonical_root": (
                end[-1].get("first_noncanonical_root") if end else "missing"
            ),
        }
        return Observation(
            expected={
                "rc": 0,
                "canonical": True,
                "first_noncanonical_root": None,
            },
            got=got,
            applied=f"root-case={case}",
        )


def _o4_sigterm_forwarded_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        program_started = threading.Event()

        def send_term() -> None:
            for _ in range(500):
                if (
                    os.path.isfile(fixture.program_log)
                    and os.path.getsize(fixture.program_log) > 0
                ):
                    program_started.set()
                    time.sleep(0.05)
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                time.sleep(0.01)

        sender = threading.Thread(target=send_term)
        sender.start()
        stderr = io.StringIO()
        with _o4_devnull_stdin(), contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                ["run", fixture.own_source],
                environment=fixture.environment(FAKE_PROGRAM_SLEEP="30"),
            )
        sender.join()
        end = _o4_phase(fixture.records(), "end")
        got = {
            "program_started": program_started.is_set(),
            "rc": result,
            "run_signal": (
                (end[-1].get("run") or {}).get("signal") if end else None
            ),
        }
        return Observation(
            expected={"program_started": True, "rc": 1, "run_signal": 15},
            got=got,
            applied="SIGTERM sent to shim while fake program was sleeping",
        )

def _o4_build_signal_forwarded_seed() -> Observation:
    got: dict[str, object] = {}
    for phase, marker in (
        ("producer", "--emit-iyimod"),
        ("consumer", "--use-iyimod"),
    ):
        with _O4FixtureEnvironment() as fixture:
            child_started = threading.Event()

            def send_term() -> None:
                for _ in range(500):
                    if os.path.isfile(fixture.real_log):
                        with open(fixture.real_log, "r", encoding="utf-8") as source:
                            if marker in source.read():
                                child_started.set()
                                time.sleep(0.05)
                                os.kill(os.getpid(), signal.SIGTERM)
                                return
                    time.sleep(0.01)

            sender = threading.Thread(target=send_term)
            sender.start()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = fixture.run_in_process(
                    [
                        "build",
                        "-o",
                        os.path.join(fixture.root, f"{phase}-signal-out"),
                        fixture.own_source,
                    ],
                    environment=fixture.environment(
                        FAKE_REAL_SLEEP=f"{phase}:30"
                    ),
                )
            sender.join()
            end = _o4_phase(fixture.records(), "end")
            record = end[-1] if end else {}
            got[phase] = {
                "child_started": child_started.is_set(),
                "rc": result,
                "interrupted": record.get("interrupted"),
                "producer_rc": (record.get("producer") or {}).get("rc"),
                "consumer_rc": (
                    (record.get("consumer") or {}).get("rc")
                    if record.get("consumer") is not None
                    else None
                ),
            }
    expected = {
        "producer": {
            "child_started": True,
            "rc": 143,
            "interrupted": True,
            "producer_rc": -15,
            "consumer_rc": None,
        },
        "consumer": {
            "child_started": True,
            "rc": 143,
            "interrupted": True,
            "producer_rc": 0,
            "consumer_rc": -15,
        },
    }
    return Observation(
        expected=expected,
        got=got,
        applied="SIGTERM forwarded once during producer and once during consumer",
    )


def _o4_refusal_fixture(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "refusal-out")
        argv = ["build", "-o", output, fixture.own_source]
        if case == "implicit-file":
            argv = [fixture.own_source]
        elif case == "run-sandbox":
            argv = ["run", "--sandbox", fixture.own_source]
        elif case == "stdin-filename":
            argv = ["build", "--stdin-filename", "virtual.iyi", fixture.own_source]
        elif case in ("unknown-option", "refusal-recorded", "control"):
            argv = ["build", "--not-a-real-option", fixture.own_source]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(argv)
        records = _o4_phase(fixture.records(), "refused")
        got = {
            "rc": result,
            "refused_marker": "observed-roundtrip-shim: REFUSED " in stderr.getvalue(),
            "records": len(records),
            "mode": records[-1].get("mode") if records else None,
            "exit": records[-1].get("exit") if records else None,
        }
        return Observation(
            expected={
                "rc": 125,
                "refused_marker": True,
                "records": 1,
                "mode": "refused",
                "exit": 125,
            },
            got=got,
            applied=f"unsupported-form={case}",
        )


def _o4_roots_from_real_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        environment = fixture.environment(IYI_PATH=None, CRYSTAL_PATH=None)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                [
                    "build",
                    "-o",
                    os.path.join(fixture.root, "default-root-out"),
                    fixture.own_source,
                ],
                environment=environment,
            )
        records = _o4_phase(fixture.records(), "refused")
        got = {
            "rc": result,
            "root": (
                records[-1].get("first_noncanonical_root") if records else None
            ),
            "ambient_has_path": "IYI_PATH" in environment,
        }
        return Observation(
            expected={
                "rc": 125,
                "root": os.path.realpath(fixture.default_root),
                "ambient_has_path": False,
            },
            got=got,
            applied="ambient IYI_PATH absent while REAL env returns its default root",
        )


def _o4_option_value_source_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        prelude = os.path.join(fixture.root, "prelude.iyi")
        with open(prelude, "w", encoding="utf-8") as target:
            target.write("prelude\n")
        result = fixture.run_in_process(
            [
                "build",
                "--prelude",
                prelude,
                "-o",
                os.path.join(fixture.root, "option-out"),
                fixture.own_source,
            ]
        )
        end = _o4_phase(fixture.records(), "end")
        got = {
            "rc": result,
            "sources": end[-1].get("sources") if end else None,
        }
        return Observation(
            expected={
                "rc": 0,
                "sources": [os.path.realpath(fixture.own_source)],
            },
            got=got,
            applied=f"--prelude value={prelude}",
        )


def _o4_header_refusal_seed(case: str) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        if case == "missing":
            os.unlink(fixture.ledger)
            original_lines = None
        else:
            fixture.write_header(nonce="c" * 32)
            original_lines = len(fixture.records())
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = fixture.run_in_process(
                ["build", "-o", os.path.join(fixture.root, "out"), fixture.own_source]
            )
        final_lines = (
            len(fixture.records()) if os.path.isfile(fixture.ledger) else None
        )
        got = {
            "rc": result,
            "marker": "observed-roundtrip-shim: REFUSED " in stderr.getvalue(),
            "original_lines": original_lines,
            "final_lines": final_lines,
        }
        expected = {
            "rc": 125,
            "marker": True,
            "original_lines": original_lines,
            "final_lines": original_lines,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=f"header-case={case}",
        )


def _o4_parallel_fixture(*, count: int, seed: bool) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        environment = fixture.environment()
        processes: list[subprocess.Popen[bytes]] = []
        for index in range(count):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        os.path.abspath(shim_mod.__file__),
                        "--config",
                        fixture.config_path,
                        "--",
                        "build",
                        "--emit-iyimod",
                        os.path.join(fixture.root, f"mods-{index}"),
                        "-o",
                        os.path.join(fixture.root, f"out-{index}"),
                        fixture.own_source,
                    ],
                    cwd=fixture.repo,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
        returncodes = []
        for process in processes:
            process.communicate()
            returncodes.append(process.returncode)
        records = fixture.records()
        record_lines = [
            record for record in records if record.get("kind") == "record"
        ]
        invocations = {record.get("inv") for record in record_lines}
        got = {
            "returncodes": returncodes,
            "json_lines": len(records),
            "record_lines": len(record_lines),
            "unique_invocations": len(invocations),
        }
        expected = {
            "returncodes": [0] * count,
            "json_lines": count + 1,
            "record_lines": count,
            "unique_invocations": count,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"parallel_processes={count}"
                if seed
                else ""
            ),
        )


def _o4_amend_environment(case: str, *, control: bool) -> Observation:
    with _O4FixtureEnvironment() as fixture:
        x_cache = os.path.join(fixture.root, "driver-cache")
        y_tmp = os.path.join(fixture.root, "driver-tmp")
        os.makedirs(x_cache, exist_ok=True)
        os.makedirs(y_tmp, exist_ok=True)
        common = {
            "IYI_CACHE_DIR": x_cache,
            "IYI_OPTS": "-Dsmoke",
            "TMPDIR": y_tmp,
            "FOO": "1",
        }
        output = os.path.join(fixture.root, f"amend-{case}")
        if case == "negative":
            root = os.path.join(fixture.work_tmp, "driver-work", "negative")
            os.makedirs(root, exist_ok=True)
            environment = fixture.environment(IYI_PATH=root, **common)
            completed = fixture.run_process(
                ["build", "-o", output, fixture.own_source],
                environment=environment,
            )
            calls = [
                call
                for call in fixture.real_calls()
                if len(call.get("argv", [])) > 1
                and "build".startswith(call["argv"][1])
            ]
            seen = calls[-1] if calls else {}
            got = {
                "rc": completed.returncode,
                "variables": {
                    key: seen.get("env", {}).get(key)
                    for key in ("IYI_PATH", "IYI_CACHE_DIR", "IYI_OPTS", "TMPDIR", "FOO")
                },
                "argv": seen.get("argv", [])[1:],
            }
            expected_argv = [
                "build",
                "-Diyi_observe",
                "-o",
                output,
                fixture.own_source,
            ]
            expected = {
                "rc": 0,
                "variables": {
                    "IYI_PATH": root,
                    "IYI_CACHE_DIR": x_cache,
                    "IYI_OPTS": "-Dsmoke",
                    "TMPDIR": y_tmp,
                    "FOO": "1",
                },
                "argv": expected_argv,
            }
        elif case == "positive":
            root = os.path.join(fixture.work_tmp, "driver-work", "positive")
            os.makedirs(root, exist_ok=True)
            environment = fixture.environment(IYI_PATH=root, **common)
            completed = fixture.run_process(
                ["build", "-o", output, fixture.own_source],
                environment=environment,
            )
            calls = [
                call
                for call in fixture.real_calls()
                if "--emit-iyimod" in call.get("argv", [])
                or "--use-iyimod" in call.get("argv", [])
            ]
            variables = [
                {
                    key: call.get("env", {}).get(key)
                    for key in ("IYI_PATH", "IYI_CACHE_DIR", "IYI_OPTS", "TMPDIR", "FOO")
                }
                for call in calls
            ]
            normalized = [
                _o4_normalized_roundtrip_call(call) for call in calls
            ]
            got = {
                "rc": completed.returncode,
                "variables": variables,
                "argv": normalized,
                "same_mods": (
                    len(calls) == 2
                    and calls[0]["argv"][calls[0]["argv"].index("--emit-iyimod") + 1]
                    == calls[1]["argv"][calls[1]["argv"].index("--use-iyimod") + 1]
                ),
            }
            expected_variables = {
                "IYI_PATH": root,
                "IYI_CACHE_DIR": x_cache,
                "IYI_OPTS": "-Dsmoke",
                "TMPDIR": y_tmp,
                "FOO": "1",
            }
            expected = {
                "rc": 0,
                "variables": [expected_variables, expected_variables],
                "argv": [
                    [
                        "build",
                        "-Diyi_observe",
                        "--emit-iyimod",
                        "<MODS>",
                        "-o",
                        output,
                        fixture.own_source,
                    ],
                    [
                        "build",
                        "-Diyi_observe",
                        "--use-iyimod",
                        "<MODS>",
                        "-o",
                        output,
                        fixture.own_source,
                    ],
                ],
                "same_mods": True,
            }
        elif case == "run":
            environment = fixture.environment(**common)
            completed = fixture.run_process(
                ["run", fixture.own_source, "--", "one", "two"],
                environment=environment,
            )
            programs = fixture.program_calls()
            shim_artifacts = [
                name
                for name in os.listdir(y_tmp)
                if name.startswith(("mods", "inv", "out.ref"))
            ]
            got = {
                "rc": completed.returncode,
                "tmpdir": (
                    programs[-1].get("env", {}).get("TMPDIR")
                    if programs
                    else None
                ),
                "argv": programs[-1].get("argv") if programs else None,
                "shim_artifacts": shim_artifacts,
            }
            expected = {
                "rc": 0,
                "tmpdir": y_tmp,
                "argv": ["one", "two"],
                "shim_artifacts": [],
            }
        else:
            environment = fixture.environment(
                IYI_OPTS="--no-codegen",
                IYI_CACHE_DIR=x_cache,
                TMPDIR=y_tmp,
                FOO="1",
            )
            received = ["build", "-o", output, fixture.own_source]
            completed = fixture.run_process(received, environment=environment)
            calls = [
                call
                for call in fixture.real_calls()
                if len(call.get("argv", [])) > 1
                and "build".startswith(call["argv"][1])
            ]
            record = _o4_phase(fixture.records(), "exec")
            got = {
                "rc": completed.returncode,
                "argv": calls[-1].get("argv", [])[1:] if calls else None,
                "opts": (
                    calls[-1].get("env", {}).get("IYI_OPTS")
                    if calls
                    else None
                ),
                "mode": record[-1].get("mode") if record else None,
            }
            expected = {
                "rc": 0,
                "argv": received,
                "opts": "--no-codegen",
                "mode": "unchanged",
            }
        return Observation(
            expected=expected,
            got=got,
            applied="" if control else f"environment-preservation-case={case}",
        )


def _o4_drop_cache_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        with open(shim_mod.__file__, "r", encoding="utf-8") as source:
            control_source = source.read()
        needle = (
            "def _exec_real(plan: ExecPlan) -> NoReturn:\n"
            "    os.execv(plan.real, [plan.real, *plan.argv])\n"
        )
        replacement = (
            "def _exec_real(plan: ExecPlan) -> NoReturn:\n"
            "    os.environ.pop(\"IYI_CACHE_DIR\", None)\n"
            "    os.execv(plan.real, [plan.real, *plan.argv])\n"
        )
        replacements = control_source.count(needle)
        mutant_source = control_source.replace(needle, replacement)
        mutant = os.path.join(fixture.root, "drop_cache_shim.py")
        with open(mutant, "w", encoding="utf-8") as target:
            target.write(mutant_source)
        root = os.path.join(fixture.work_tmp, "driver-work", "negative")
        os.makedirs(root, exist_ok=True)
        cache = os.path.join(fixture.root, "driver-cache")
        os.makedirs(cache, exist_ok=True)
        completed = fixture.run_process(
            [
                "build",
                "-o",
                os.path.join(fixture.root, "drop-cache-out"),
                fixture.own_source,
            ],
            environment=fixture.environment(
                IYI_PATH=root,
                IYI_CACHE_DIR=cache,
            ),
            shim_path=mutant,
        )
        calls = [
            call
            for call in fixture.real_calls()
            if len(call.get("argv", [])) > 1
            and "build".startswith(call["argv"][1])
        ]
        cache_present = (
            "IYI_CACHE_DIR" in calls[-1].get("env", {}) if calls else True
        )
        control_sha = hashlib.sha256(control_source.encode()).hexdigest()
        mutant_sha = hashlib.sha256(mutant_source.encode()).hexdigest()
        got = {
            "rc": completed.returncode,
            "replacements": replacements,
            "bytes_differ": control_sha != mutant_sha,
            "cache_present": cache_present,
        }
        return Observation(
            expected={
                "rc": 0,
                "replacements": 1,
                "bytes_differ": True,
                "cache_present": False,
            },
            got=got,
            applied=(
                f"control_sha256={control_sha};mutant_sha256={mutant_sha};"
                f"replacements={replacements};mutant_executed={bool(calls)}"
            ),
        )


def _o4_config_header_refusals_seed() -> Observation:
    passed: set[str] = set()
    mutations: list[str] = []
    with _O4FixtureEnvironment() as fixture:
        control = json.loads(json.dumps(fixture.config))

        def config_case(
            name: str,
            value: object,
            fragment: str,
            *,
            raw: bool = False,
        ) -> str:
            path = os.path.join(fixture.root, f"config-{name}.json")
            with open(path, "w", encoding="utf-8") as target:
                if raw:
                    target.write(str(value))
                else:
                    json.dump(value, target, sort_keys=True)
            try:
                shim_mod.load_config(path)
            except shim_mod.ConfigError as error:
                if fragment in str(error):
                    passed.add(name)
            with open(path, "rb") as mutated:
                digest = hashlib.sha256(mutated.read()).hexdigest()
            mutations.append(f"{name}:{digest}")
            return path

        invalid_config_path = config_case(
            "unreadable-json",
            "{",
            "config unreadable",
            raw=True,
        )
        config_case("not-object", [], "config is not an object")
        missing = json.loads(json.dumps(control))
        missing.pop("driver")
        config_case("key-set", missing, "config keys differ")
        non_string = json.loads(json.dumps(control))
        non_string["driver"] = 1
        config_case("non-string", non_string, "config driver is not a string")
        roots_scalar = json.loads(json.dumps(control))
        roots_scalar["canonical_roots"] = "root"
        config_case(
            "roots-scalar",
            roots_scalar,
            "config canonical_roots is not a string list",
        )
        roots_item = json.loads(json.dumps(control))
        roots_item["canonical_roots"] = [1]
        config_case(
            "roots-item",
            roots_item,
            "config canonical_roots is not a string list",
        )
        bad_nonce = json.loads(json.dumps(control))
        bad_nonce["nonce"] = "BAD"
        config_case(
            "nonce",
            bad_nonce,
            "config nonce is not 32 lowercase hex characters",
        )
        nonreal_repo = json.loads(json.dumps(control))
        nonreal_repo["repo"] = os.path.join(fixture.repo, ".")
        config_case(
            "nonreal-repo",
            nonreal_repo,
            "config repo is not a realpath",
        )
        relative_ledger = json.loads(json.dumps(control))
        relative_ledger["ledger"] = "ledger.jsonl"
        config_case(
            "relative-ledger",
            relative_ledger,
            "config ledger and scratch must be absolute",
        )
        nonreal_root = json.loads(json.dumps(control))
        nonreal_root["canonical_roots"] = [
            os.path.join(fixture.canonical_root, ".")
        ]
        config_case(
            "nonreal-root",
            nonreal_root,
            "config canonical_roots contains a non-realpath",
        )

        def header_case(name: str, payload: object, fragment: str, *, raw: bool = False) -> None:
            path = os.path.join(fixture.root, f"header-{name}.jsonl")
            with open(path, "w", encoding="utf-8") as target:
                if raw:
                    target.write(str(payload))
                elif payload is not None:
                    target.write(json.dumps(payload, sort_keys=True) + "\n")
            try:
                shim_mod.read_header(
                    path,
                    nonce=fixture.nonce,
                    driver=fixture.driver,
                )
            except shim_mod.ConfigError as error:
                if fragment in str(error):
                    passed.add(name)
            with open(path, "rb") as mutated:
                digest = hashlib.sha256(mutated.read()).hexdigest()
            mutations.append(f"{name}:{digest}")

        good_header = {
            "v": 1,
            "kind": "header",
            "nonce": fixture.nonce,
            "driver": fixture.driver,
            "attempt": 1,
            "chain_id": fixture.chain_id,
        }
        header_case("header-empty", None, "ledger header is missing")
        header_case("header-json", "{", "ledger header is invalid JSON", raw=True)
        header_case("header-shape", [], "ledger header shape is invalid")
        bad_version = dict(good_header)
        header_case(
            "header-key-shape",
            {},
            "ledger header shape is invalid",
        )
        bad_version["v"] = 2
        header_case(
            "header-version",
            bad_version,
            "ledger header version or kind is invalid",
        )
        bad_attempt = dict(good_header)
        bad_attempt["attempt"] = True
        header_case(
            "header-attempt",
            bad_attempt,
            "ledger header attempt is invalid",
        )
        bad_chain = dict(good_header)
        bad_chain["chain_id"] = ""
        header_case(
            "header-chain",
            bad_chain,
            "ledger header chain_id is invalid",
        )
        bad_header_nonce = dict(good_header)
        bad_header_nonce["nonce"] = "c" * 32
        header_case(
            "header-nonce",
            bad_header_nonce,
            "ledger header nonce does not match config",
        )
        bad_driver = dict(good_header)
        bad_driver["driver"] = "other"
        header_case(
            "header-driver",
            bad_driver,
            "ledger header driver does not match config",
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            bad_run = shim_mod.run_shim(invalid_config_path, [])
        if bad_run == 125 and "REFUSED config unreadable" in stderr.getvalue():
            passed.add("run-shim-config")
    expected = {
        "unreadable-json",
        "not-object",
        "key-set",
        "non-string",
        "roots-scalar",
        "roots-item",
        "nonce",
        "nonreal-repo",
        "relative-ledger",
        "nonreal-root",
        "header-empty",
        "header-json",
        "header-shape",
        "header-version",
        "header-attempt",
        "header-chain",
        "header-nonce",
        "header-driver",
        "run-shim-config",
        "header-key-shape",
    }
    return Observation(
        expected=sorted(expected),
        got=sorted(passed),
        applied=";".join(mutations),
    )


def _o4_config_header_control() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        config = shim_mod.load_config(fixture.config_path)
        header = shim_mod.read_header(
            fixture.ledger,
            nonce=fixture.nonce,
            driver=fixture.driver,
        )
        got = {
            "config_keys": sorted(config),
            "header_kind": header.get("kind"),
            "attempt": header.get("attempt"),
        }
        return Observation(
            expected={
                "config_keys": sorted(shim_mod.CONFIG_KEYS),
                "header_kind": "header",
                "attempt": 1,
            },
            got=got,
        )


def _o4_parser_and_io_refusals_seed() -> Observation:
    passed: set[str] = set()
    details: list[str] = []

    def invocation_error(name: str, argv: list[str], fragment: str) -> None:
        try:
            shim_mod.parse_invocation(argv)
        except shim_mod.InvocationError as error:
            if fragment in str(error):
                passed.add(name)
                details.append(f"{name}:{error}")

    no_args = shim_mod.parse_invocation([])
    if no_args.command == "" and not no_args.argv:
        passed.add("parse-empty")
    attached = shim_mod.parse_invocation(["build", "-oattached", "source.iyi"])
    if attached.output == "attached" and attached.sources == ("source.iyi",):
        passed.add("attached-output")
    equals = shim_mod.parse_invocation(
        ["build", "--output=equals", "source.iyi"]
    )
    if equals.output == "equals" and equals.sources == ("source.iyi",):
        passed.add("equals-output")
    optional_empty = shim_mod.parse_invocation(["build", "--emit"])
    if optional_empty.sources == ():
        passed.add("optional-empty")
    optional_value = shim_mod.parse_invocation(["build", "--emit", "llvm"])
    if optional_value.sources == ():
        passed.add("optional-value")
    invocation_error(
        "missing-value",
        ["build", "-o"],
        "option requires a value",
    )
    invocation_error(
        "run-build-only",
        ["run", "--target", "x", "source.iyi"],
        "build-only option on run",
    )
    invocation_error(
        "unknown-equals",
        ["build", "--unknown=value", "source.iyi"],
        "unknown option",
    )
    separated_observe = shim_mod.parse_invocation(
        ["build", "-D", "iyi_observe", "source.iyi"]
    )
    observed_exec = shim_mod.build_exec_argv(separated_observe)
    observed_producer = shim_mod.build_producer_argv(
        separated_observe,
        "/mods",
        "/out",
    )
    if (
        observed_exec == list(separated_observe.argv)
        and observed_producer.count("-Diyi_observe") == 0
        and observed_producer.count("iyi_observe") == 1
    ):
        passed.add("observe-separated")

    ambient_cases = (
        ("ambient-quote", "build", "'unterminated", "cannot parse IYI_OPTS"),
        ("ambient-positional", "build", "word", "may not contain positional"),
        ("ambient-separator", "build", "--", "may not contain --"),
        ("ambient-unknown", "build", "--unknown", "unknown option"),
        ("ambient-build-only", "run", "--target x", "build-only option on run"),
        (
            "ambient-stdin",
            "build",
            "--stdin-filename virtual.iyi",
            "--stdin-filename is unsupported",
        ),
    )
    for name, command, opts, reason in ambient_cases:
        with _O4FixtureEnvironment() as fixture:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = fixture.run_in_process(
                    [command, fixture.own_source],
                    environment=fixture.environment(IYI_OPTS=opts),
                )
            refused = _o4_phase(fixture.records(), "refused")
            if (
                result == 125
                and refused
                and reason in str(refused[-1].get("reason"))
            ):
                passed.add(name)
                details.append(f"{name}:{reason}")

    valid_modes = (
        ("emit-equals", ["build", "--emit=llvm", "source.iyi"], "unchanged"),
        (
            "emit-bind-equals",
            ["build", "--emit-bind=mods", "source.iyi"],
            "unchanged",
        ),
        (
            "use-equals",
            ["build", "--use-iyimod=mods", "source.iyi"],
            "passthrough",
        ),
        ("crystal", ["build", "--crystal", "source.iyi"], "unchanged"),
    )
    with _O4FixtureEnvironment() as fixture:
        for name, argv, expected_mode in valid_modes:
            parsed = shim_mod.parse_invocation(argv)
            classified = shim_mod.classify(
                fixture.census,
                parsed,
                [fixture.canonical_root],
                [fixture.canonical_root],
                [os.path.realpath(os.path.join(fixture.repo, "source.iyi"))],
                os.path.join(fixture.root, "out"),
                fixture.work_tmp,
                fixture.repo,
            )
            if classified.mode == expected_mode:
                passed.add(name)
        ambient_optional = shim_mod.classify(
            fixture.census,
            shim_mod.parse_invocation(["build", "source.iyi"]),
            [fixture.canonical_root],
            [fixture.canonical_root],
            [os.path.join(fixture.repo, "source.iyi")],
            os.path.join(fixture.root, "out"),
            fixture.work_tmp,
            fixture.repo,
            ambient_tokens=("--emit", "llvm"),
        )
        if ambient_optional.mode == "unchanged":
            passed.add("ambient-optional")
        ambient_bare_optional = shim_mod.classify(
            fixture.census,
            shim_mod.parse_invocation(["build", "source.iyi"]),
            [fixture.canonical_root],
            [fixture.canonical_root],
            [os.path.join(fixture.repo, "source.iyi")],
            os.path.join(fixture.root, "out"),
            fixture.work_tmp,
            fixture.repo,
            ambient_tokens=("--emit",),
        )
        if ambient_bare_optional.mode == "unchanged":
            passed.add("ambient-bare-optional")
        if shim_mod._realpath_from_cwd(
            "relative.iyi",
            fixture.repo,
        ) == os.path.join(fixture.repo, "relative.iyi"):
            passed.add("relative-path-helper")
        if shim_mod._source_paths(
            shim_mod.parse_invocation(["build", "relative.iyi"]),
            fixture.repo,
        ) == (os.path.join(fixture.repo, "relative.iyi"),):
            passed.add("relative-source-helper")

        scripts = os.path.join(fixture.root, "compiler-env")
        os.makedirs(scripts, exist_ok=True)

        def script(name: str, body: str) -> str:
            path = os.path.join(scripts, name)
            with open(path, "w", encoding="utf-8") as target:
                target.write("#!/bin/sh\n" + body)
            os.chmod(path, 0o755)
            return path

        try:
            shim_mod.compiler_env(os.path.join(scripts, "missing"), fixture.repo)
        except shim_mod.InvocationError as error:
            if "compiler env failed" in str(error):
                passed.add("env-oserror")
        failing = script("failing", "echo bad >&2\nexit 5\n")
        try:
            shim_mod.compiler_env(failing, fixture.repo)
        except shim_mod.InvocationError as error:
            if "compiler env exited 5: bad" in str(error):
                passed.add("env-exit")
        one_line = script("one-line", "printf 'one\\n'\n")
        try:
            shim_mod.compiler_env(one_line, fixture.repo)
        except shim_mod.InvocationError as error:
            if "returned 1 lines, expected 2" in str(error):
                passed.add("env-lines")
        os.makedirs(os.path.join(fixture.repo, "relative-root"), exist_ok=True)
        os.makedirs(os.path.join(fixture.repo, "relative-cache"), exist_ok=True)
        relative = script(
            "relative",
            "printf 'relative-root\\nrelative-cache\\n'\n",
        )
        environment = shim_mod.compiler_env(relative, fixture.repo)
        if environment == shim_mod.CompilerEnvironment(
            (os.path.join(fixture.repo, "relative-root"),),
            os.path.join(fixture.repo, "relative-cache"),
        ):
            passed.add("env-relative")

        invalid_census = os.path.join(fixture.root, "invalid-census.json")
        with open(invalid_census, "w", encoding="utf-8") as target:
            target.write("{")
        try:
            shim_mod._load_census(invalid_census)
        except shim_mod.InvocationError as error:
            if "census unreadable" in str(error):
                passed.add("census-json")
        list_census = os.path.join(fixture.root, "list-census.json")
        with open(list_census, "w", encoding="utf-8") as target:
            json.dump([], target)
        try:
            shim_mod._load_census(list_census)
        except shim_mod.InvocationError as error:
            if "census is not an object" in str(error):
                passed.add("census-object")

        doc = shim_mod.parse_invocation(["doc"])
        if shim_mod.compute_out(
            doc,
            cwd=fixture.repo,
            cache_dir=fixture.cache,
        ) is None:
            passed.add("out-nonbuild")
        no_source = shim_mod.parse_invocation(["build"])
        if shim_mod.compute_out(
            no_source,
            cwd=fixture.repo,
            cache_dir=fixture.cache,
        ) == os.path.join(fixture.repo, "a"):
            passed.add("out-no-source")
        run = shim_mod.parse_invocation(["run", fixture.own_source])
        try:
            shim_mod.compute_out(run, cwd=fixture.repo, cache_dir="")
        except shim_mod.InvocationError as error:
            if "empty IYI_CACHE_DIR" in str(error):
                passed.add("out-empty-cache")

        missing_config = dict(fixture.config)
        missing_config["ledger"] = os.path.join(fixture.root, "gone-ledger")
        refusal_stderr = io.StringIO()
        invocation = shim_mod.parse_invocation(
            ["build", "-o", os.path.join(fixture.root, "x"), fixture.own_source]
        )
        with contextlib.redirect_stderr(refusal_stderr):
            refused_rc = shim_mod._record_refusal(
                missing_config,
                invocation,
                "forced missing ledger",
                inv="f" * 32,
            )
        if refused_rc == 125 and "REFUSED forced missing ledger" in refusal_stderr.getvalue():
            passed.add("refusal-write-oserror")

        byte_buffer = io.BytesIO()
        text_stream = io.TextIOWrapper(byte_buffer, encoding="utf-8")
        shim_mod._write_bytes(text_stream, b"binary-path")
        text_stream.detach()
        if byte_buffer.getvalue() == b"binary-path":
            passed.add("binary-stream")

        sentences = {
            "death-memory": shim_mod._death_sentence(signal.SIGSEGV),
            "death-int": shim_mod._death_sentence(signal.SIGINT),
            "death-ill": shim_mod._death_sentence(signal.SIGILL),
            "death-fpe": shim_mod._death_sentence(signal.SIGFPE),
            "death-unknown": shim_mod._death_sentence(999),
        }
        if "memory fault" in sentences["death-memory"]:
            passed.add("death-memory")
        if "was interrupted" in sentences["death-int"]:
            passed.add("death-int")
        if "invalid instruction" in sentences["death-ill"]:
            passed.add("death-ill")
        if "floating-point" in sentences["death-fpe"]:
            passed.add("death-fpe")
        if "signal 999" in sentences["death-unknown"]:
            passed.add("death-unknown")

    expected = {
        "parse-empty",
        "attached-output",
        "equals-output",
        "optional-empty",
        "optional-value",
        "missing-value",
        "run-build-only",
        "unknown-equals",
        "observe-separated",
        "ambient-optional",
        "ambient-bare-optional",
        "relative-path-helper",
        "relative-source-helper",
        *(name for name, _command, _opts, _reason in ambient_cases),
        *(name for name, _argv, _mode in valid_modes),
        "env-oserror",
        "env-exit",
        "env-lines",
        "env-relative",
        "census-json",
        "census-object",
        "out-nonbuild",
        "out-no-source",
        "out-empty-cache",
        "refusal-write-oserror",
        "binary-stream",
        "death-memory",
        "death-int",
        "death-ill",
        "death-fpe",
        "death-unknown",
    }
    return Observation(
        expected=sorted(expected),
        got=sorted(passed),
        applied=";".join(details) or "parser and I/O negative subcases applied",
    )


def _o4_parser_control() -> Observation:
    invocation = shim_mod.parse_invocation(
        ["b", "-Dsmoke", "-o", "out", "one.iyi", "two.iyi"]
    )
    got = {
        "command_word": invocation.command_word,
        "command": invocation.command,
        "sources": list(invocation.sources),
        "output": invocation.output,
    }
    return Observation(
        expected={
            "command_word": "b",
            "command": "build",
            "sources": ["one.iyi", "two.iyi"],
            "output": "out",
        },
        got=got,
    )


def _o4_matcher_malformed_seed() -> Observation:
    passed: set[str] = set()
    with _O4FixtureEnvironment() as fixture:
        driver_work = os.path.join(fixture.work_tmp, "driver-work")
        root = os.path.join(driver_work, "12", "12")
        output = os.path.join(driver_work, "12", "out")
        pattern_variant = {
            "id": "pattern",
            "kind": "negative",
            "first_root": "{WORK}/{n}/{n}",
            "vars": {
                "n": {
                    "pattern": "[0-9]+",
                    "pattern_reason_line": 1,
                }
            },
            "sources": ["{REPO}/bench/std_demo_exercise.iyi"],
            "output": "{WORK}/{n}/out",
        }
        pattern_census = {
            "sites": [
                {
                    "command": "build",
                    "variants": [pattern_variant],
                }
            ]
        }
        status, ids, kind, bindings = shim_mod.match_variants(
            pattern_census,
            "build",
            root,
            [fixture.own_source],
            output,
            fixture.work_tmp,
            fixture.repo,
        )
        if (
            status == "matched"
            and ids == ["pattern"]
            and kind == "negative"
            and bindings == {"pattern": {"n": "12"}}
        ):
            passed.add("pattern-repeat")
        repeated_work, _groups = shim_mod._template_regex(
            "{WORK}/{WORK}",
            variables={},
            bound={},
            work_tmp=fixture.work_tmp,
            repo=fixture.repo,
        )
        if repeated_work.pattern:
            passed.add("repeated-work")

        malformed_cases = {
            "none-root": ({}, None, [fixture.own_source], None),
            "site-nondict": (
                {"sites": [None]},
                root,
                [fixture.own_source],
                None,
            ),
            "wrong-command": (
                {"sites": [{"command": "run", "variants": [pattern_variant]}]},
                root,
                [fixture.own_source],
                output,
            ),
            "variant-nondict": (
                {"sites": [{"command": "build", "variants": [None]}]},
                root,
                [fixture.own_source],
                output,
            ),
            "variant-shape": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [{"id": 1}],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "source-count": (
                pattern_census,
                root,
                [fixture.own_source, fixture.other_source],
                output,
            ),
            "root-nonstr": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [{**pattern_variant, "first_root": None}],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "unknown-placeholder": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [
                                {
                                    **pattern_variant,
                                    "first_root": "{WORK}/{unknown}",
                                }
                            ],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "variable-nondict": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [
                                {
                                    **pattern_variant,
                                    "vars": {"n": "bad"},
                                }
                            ],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "variable-empty": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [
                                {
                                    **pattern_variant,
                                    "vars": {"n": {}},
                                }
                            ],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "variable-regex": (
                {
                    "sites": [
                        {
                            "command": "build",
                            "variants": [
                                {
                                    **pattern_variant,
                                    "vars": {"n": {"pattern": "("}},
                                }
                            ],
                        }
                    ]
                },
                root,
                [fixture.own_source],
                output,
            ),
            "output-missing": (
                pattern_census,
                root,
                [fixture.own_source],
                None,
            ),
            "output-mismatch": (
                pattern_census,
                root,
                [fixture.own_source],
                os.path.join(driver_work, "12", "wrong"),
            ),
        }
        for name, (census, candidate_root, sources, candidate_output) in malformed_cases.items():
            result = shim_mod.match_variants(
                census,
                "build",
                candidate_root,
                sources,
                candidate_output,
                fixture.work_tmp,
                fixture.repo,
            )
            if result == ("unclassified", [], None, {}):
                passed.add(name)
    expected = {"pattern-repeat", "repeated-work", *malformed_cases}
    return Observation(
        expected=sorted(expected),
        got=sorted(passed),
        applied="malformed matcher cases=" + ",".join(sorted(malformed_cases)),
    )


def _o4_matcher_pattern_control() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        root = os.path.join(fixture.work_tmp, "driver-work", "7")
        census = {
            "sites": [
                {
                    "command": "build",
                    "variants": [
                        {
                            "id": "pattern-control",
                            "kind": "negative",
                            "first_root": "{WORK}/{n}",
                            "vars": {"n": {"pattern": "[0-9]+"}},
                            "sources": [
                                "{REPO}/bench/std_demo_exercise.iyi"
                            ],
                            "output": None,
                        }
                    ],
                }
            ]
        }
        got = shim_mod.match_variants(
            census,
            "build",
            root,
            [fixture.own_source],
            None,
            fixture.work_tmp,
            fixture.repo,
        )
        return Observation(
            expected=(
                "matched",
                ["pattern-control"],
                "negative",
                {"pattern-control": {"n": "7"}},
            ),
            got=got,
        )


def _o4_e3_error_seed() -> Observation:
    with _O4FixtureEnvironment() as fixture:
        output = os.path.join(fixture.root, "e3-out")
        invocation = shim_mod.parse_invocation(
            ["build", "-o", output, fixture.own_source]
        )
        classification = shim_mod.classify(
            fixture.census,
            invocation,
            [fixture.canonical_root],
            [fixture.canonical_root],
            [fixture.own_source],
            output,
            fixture.work_tmp,
            fixture.repo,
        )
        inv = "e" * 32
        candidate = os.path.join(fixture.scratch, inv, "out.ref")
        os.makedirs(candidate, exist_ok=True)
        previous_cwd = os.getcwd()
        previous_env = os.environ.copy()
        try:
            os.chdir(fixture.repo)
            os.environ.clear()
            os.environ.update(fixture.environment())
            result = shim_mod.run_roundtrip(
                fixture.config,
                invocation,
                classification,
                output,
                roots=[fixture.canonical_root],
                sources=[fixture.own_source],
                ambient_tokens=(),
                inv=inv,
            )
        finally:
            os.environ.clear()
            os.environ.update(previous_env)
            os.chdir(previous_cwd)
        end = _o4_phase(fixture.records(), "end")
        record = end[-1] if end else {}
        got = {
            "rc": result,
            "out_ref": record.get("out_ref"),
            "has_e3_error": bool(record.get("e3_error")),
            "candidate_is_directory": os.path.isdir(candidate),
        }
        return Observation(
            expected={
                "rc": 0,
                "out_ref": None,
                "has_e3_error": True,
                "candidate_is_directory": True,
            },
            got=got,
            applied=f"precreated out.ref directory at {candidate}",
        )


O4_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "s2.seed.matcher-negative-noquestion",
        "seed",
        partial(_o4_matcher_fixture, "negative-noquestion"),
    ),
    Fixture(
        "s2.seed.matcher-unknown-dir",
        "seed",
        partial(_o4_matcher_fixture, "unknown-dir"),
    ),
    Fixture(
        "s2.seed.matcher-outside-attempt",
        "seed",
        partial(_o4_matcher_fixture, "outside-attempt"),
    ),
    Fixture(
        "s2.seed.matcher-copied-exercise",
        "seed",
        partial(_o4_matcher_fixture, "copied-exercise"),
    ),
    Fixture(
        "s2.seed.matcher-two-same-kind",
        "seed",
        partial(_o4_matcher_fixture, "two-same-kind"),
    ),
    Fixture(
        "s2.seed.matcher-conflicting-kinds",
        "seed",
        partial(_o4_matcher_fixture, "conflicting-kinds"),
    ),
    Fixture(
        "s2.seed.matcher-variable-root",
        "seed",
        partial(_o4_matcher_fixture, "variable-root"),
    ),
    Fixture(
        "s2.control.matcher-canonical",
        "control",
        _o4_matcher_canonical_control,
    ),
    Fixture("s3.seed.canonical-argv-drift", "seed", _o4_canonical_seed),
    Fixture("s3.control.canonical-build", "control", _o4_canonical_control),
    Fixture("s3.seed.b-prefix-misparsed", "seed", _o4_b_prefix_seed),
    Fixture(
        "s3.seed.run-temp-path",
        "seed",
        partial(_o4_run_fixture, "temp-path"),
    ),
    Fixture(
        "s3.seed.run-argv-or-rc",
        "seed",
        partial(_o4_run_fixture, "argv-or-rc"),
    ),
    Fixture(
        "s3.seed.run-consumer-failure",
        "seed",
        _o4_run_consumer_failure_seed,
    ),
    Fixture(
        "s3.seed.run-o-executes",
        "seed",
        partial(_o4_run_fixture, "run-o"),
    ),
    Fixture("s3.control.run", "control", partial(_o4_run_fixture, "control")),
    Fixture("s3.control.run-o", "control", partial(_o4_run_fixture, "run-o")),
    Fixture("s3.seed.stdin-to-build", "seed", partial(_o4_run_fixture, "stdin")),
    Fixture("s3.control.stdin", "control", partial(_o4_run_fixture, "stdin")),
    Fixture("s3.seed.producer-failure", "seed", _o4_producer_failure_seed),
    Fixture("s3.seed.consumer-failure", "seed", _o4_consumer_failure_seed),
    Fixture(
        "s3.seed.zero-modules",
        "seed",
        partial(_o4_own_run_verifier_seed, "zero-modules"),
    ),
    Fixture(
        "s3.seed.passthrough-mutated",
        "seed",
        partial(_o4_exec_plan_fixture, "passthrough"),
    ),
    Fixture(
        "s3.control.passthrough",
        "control",
        partial(_o4_exec_plan_fixture, "passthrough-control"),
    ),
    Fixture(
        "s3.seed.observe-duplicate",
        "seed",
        partial(_o4_exec_plan_fixture, "observe-duplicate"),
    ),
    Fixture(
        "s3.seed.negative-roundtripped",
        "seed",
        partial(_o4_exec_plan_fixture, "negative"),
    ),
    Fixture(
        "s3.control.observed-negative",
        "control",
        partial(_o4_exec_plan_fixture, "negative-control"),
    ),
    Fixture(
        "s3.seed.positive-not-roundtripped",
        "seed",
        partial(_o4_positive_fixture, control=False),
    ),
    Fixture(
        "s3.control.positive",
        "control",
        partial(_o4_positive_fixture, control=True),
    ),
    Fixture("s3.seed.unknown-patched-root", "seed", _o4_unknown_root_seed),
    Fixture(
        "s3.seed.relative-root-unresolved",
        "seed",
        partial(_o4_root_fixture, "relative"),
    ),
    Fixture(
        "s3.control.empty-root",
        "control",
        partial(_o4_root_fixture, "empty"),
    ),
    Fixture(
        "s3.control.relative-root",
        "control",
        partial(_o4_root_fixture, "relative"),
    ),
    Fixture(
        "s3.seed.run-signal-death",
        "seed",
        partial(_o4_own_run_verifier_seed, "signal"),
    ),
    Fixture(
        "s3.seed.sigterm-not-forwarded",
        "seed",
        _o4_sigterm_forwarded_seed,
    ),
    Fixture(
        "s3.seed.implicit-file",
        "seed",
        partial(_o4_refusal_fixture, "implicit-file"),
    ),
    Fixture(
        "s3.seed.run-sandbox",
        "seed",
        partial(_o4_refusal_fixture, "run-sandbox"),
    ),
    Fixture(
        "s3.seed.stdin-filename",
        "seed",
        partial(_o4_refusal_fixture, "stdin-filename"),
    ),
    Fixture(
        "s3.seed.unknown-option",
        "seed",
        partial(_o4_refusal_fixture, "unknown-option"),
    ),
    Fixture(
        "s3.seed.cross-compile-roundtripped",
        "seed",
        partial(_o4_exec_plan_fixture, "cross-compile"),
    ),
    Fixture("s3.seed.roots-not-from-real", "seed", _o4_roots_from_real_seed),
    Fixture(
        "s3.seed.option-value-as-source",
        "seed",
        _o4_option_value_source_seed,
    ),
    Fixture(
        "s3.seed.missing-ledger",
        "seed",
        partial(_o4_header_refusal_seed, "missing"),
    ),
    Fixture(
        "s3.seed.wrong-nonce",
        "seed",
        partial(_o4_header_refusal_seed, "nonce"),
    ),
    Fixture(
        "s3.seed.refusal-not-recorded",
        "seed",
        partial(_o4_refusal_fixture, "refusal-recorded"),
    ),
    Fixture(
        "s3.control.refusal",
        "control",
        partial(_o4_refusal_fixture, "control"),
    ),
    Fixture(
        "s3.seed.parallel-ledger-corruption",
        "seed",
        partial(_o4_parallel_fixture, count=8, seed=True),
    ),
    Fixture(
        "s3.control.parallel-ledger",
        "control",
        partial(_o4_parallel_fixture, count=2, seed=False),
    ),
    Fixture(
        "amend-a.seed.negative-env-mutated",
        "seed",
        partial(_o4_amend_environment, "negative", control=False),
    ),
    Fixture(
        "amend-a.control.negative-env",
        "control",
        partial(_o4_amend_environment, "negative", control=True),
    ),
    Fixture(
        "amend-a.seed.positive-env-mutated",
        "seed",
        partial(_o4_amend_environment, "positive", control=False),
    ),
    Fixture(
        "amend-a.control.positive-env",
        "control",
        partial(_o4_amend_environment, "positive", control=True),
    ),
    Fixture(
        "amend-a.seed.run-env-mutated",
        "seed",
        partial(_o4_amend_environment, "run", control=False),
    ),
    Fixture(
        "amend-a.control.run-env",
        "control",
        partial(_o4_amend_environment, "run", control=True),
    ),
    Fixture(
        "amend-a.seed.opts-scrubbed",
        "seed",
        partial(_o4_amend_environment, "opts", control=False),
    ),
    Fixture(
        "amend-a.control.opts-unchanged",
        "control",
        partial(_o4_amend_environment, "opts", control=True),
    ),
    Fixture("amend-a.seed.drop-cache", "seed", _o4_drop_cache_seed),
    Fixture(
        "o4.seed.config-header-refusals",
        "seed",
        _o4_config_header_refusals_seed,
    ),
    Fixture(
        "o4.control.config-header",
        "control",
        _o4_config_header_control,
    ),
    Fixture(
        "o4.seed.parser-io-refusals",
        "seed",
        _o4_parser_and_io_refusals_seed,
    ),
    Fixture(
        "o4.control.parser",
        "control",
        _o4_parser_control,
    ),
    Fixture(
        "o4.seed.matcher-malformed",
        "seed",
        _o4_matcher_malformed_seed,
    ),
    Fixture(
        "o4.control.matcher-pattern",
        "control",
        _o4_matcher_pattern_control,
    ),
    Fixture(
        "o4.seed.e3-error",
        "seed",
        _o4_e3_error_seed,
    ),
    Fixture(
        "o4.seed.build-signal-forwarded",
        "seed",
        _o4_build_signal_forwarded_seed,
    ),
)
O4_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o4.matcher": (
        "s2.seed.matcher-variable-root",
        "s2.seed.matcher-conflicting-kinds",
        "s2.control.matcher-canonical",
    ),
    "o4.argv-and-roundtrip": (
        "s3.seed.canonical-argv-drift",
        "s3.seed.b-prefix-misparsed",
        "s3.control.canonical-build",
    ),
    "o4.run-semantics": (
        "s3.seed.run-consumer-failure",
        "s3.seed.run-o-executes",
        "s3.seed.run-signal-death",
        "s3.control.run",
    ),
    "o4.refusals": (
        "s3.seed.implicit-file",
        "s3.seed.unknown-option",
        "s3.seed.refusal-not-recorded",
        "s3.control.refusal",
    ),
    "o4.environment": (
        "amend-a.seed.drop-cache",
        "amend-a.seed.positive-env-mutated",
        "amend-a.control.negative-env",
    ),
    "o4.main-process-paths": (
        "s3.seed.passthrough-mutated",
        "s3.control.passthrough",
        "s3.control.canonical-build",
    ),
    "o4.config-header-defensive": (
        "o4.seed.config-header-refusals",
        "o4.control.config-header",
    ),
    "o4.parser-io-defensive": (
        "o4.seed.parser-io-refusals",
        "o4.control.parser",
    ),
    "o4.matcher-defensive": (
        "o4.seed.matcher-malformed",
        "o4.control.matcher-pattern",
    ),
    "o4.e3-error": (
        "o4.seed.e3-error",
        "s3.control.canonical-build",
    ),
    "o4.build-signals": (
        "o4.seed.build-signal-forwarded",
        "s3.control.canonical-build",
    ),
}


# ===== O5: ledger verification (owner U5). Keys "o5.". =====




def _o5_census() -> dict:
    return {
        "census_version": 1,
        "driver": "demo",
        "sites": [
            {
                "lines": [10],
                "command": "run",
                "kind": "canonical-own",
                "variants": [],
            },
            {
                "lines": [15],
                "command": "build",
                "kind": "negative",
                "variants": [
                    {
                        "id": "demo.negative.platform-excluded",
                        "kind": "negative",
                        "first_root": "{WORK}/excluded",
                        "vars": {"value": {"values": ["excluded"]}},
                        "sources": ["{REPO}/bench/std_demo_exercise.iyi"],
                        "output": "{WORK}/excluded",
                        "darwin": "platform-excluded",
                        "requires": ["python3"],
                        "verdict": {
                            "lines": [15],
                            "contains": ["status=1"],
                        },
                    }
                ],
            },
        ],
        "exec_evidence": [
            {
                "site_line": 10,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {"11": "own"},
            }
        ],
    }


def _o5_add_variant(
    census: dict,
    *,
    variant_id: str,
    kind: str,
    variables: dict,
    evidence_name: str | None = None,
) -> None:
    site_line = 20 + len(census["sites"])
    site = {
        "lines": [site_line],
        "command": "run",
        "kind": kind,
        "variants": [
            {
                "id": variant_id,
                "kind": kind,
                "first_root": "{WORK}/patched",
                "vars": variables,
                "sources": ["{REPO}/bench/std_demo_exercise.iyi"],
                "output": "{WORK}/{name}",
                "darwin": "required",
                "requires": ["python3"],
                "verdict": {"lines": [site_line], "contains": ["status=1"]},
            }
        ],
    }
    census["sites"].append(site)
    if evidence_name is not None:
        census["exec_evidence"].append(
            {
                "site_line": site_line,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {str(site_line + 1): evidence_name},
            }
        )


def _o5_pair(
    *,
    nonce: str,
    driver: str,
    invocation: str,
    repo: str,
    out: str,
    own: bool,
    canonical: bool = True,
    variant_ids: tuple[str, ...] = (),
    variant_kind: str | None = None,
    bindings: dict | None = None,
    mods_count: int = 1,
    consumer_rc: int = 0,
    run_form: bool = True,
) -> list[dict]:
    source = os.path.realpath(
        os.path.join(repo, "bench", f"std_{driver}_exercise.iyi")
    )
    if not own:
        source = os.path.realpath(os.path.join(repo, "bench", "helper.iyi"))
    common = {
        "v": 1,
        "kind": "record",
        "nonce": nonce,
        "driver": driver,
        "inv": invocation,
        "pid": 100,
        "t_ns": 1,
        "mode": "roundtrip",
        "command": "run" if run_form else "build",
        "cwd": repo,
        "argv": ["run" if run_form else "build", source],
        "env_seen": {
            "IYI_PATH": None,
            "CRYSTAL_PATH": None,
            "IYI_CACHE_DIR": None,
            "IYI_OPTS": None,
            "CRYSTAL_OPTS": None,
        },
        "roots": [],
        "canonical": canonical,
        "first_noncanonical_root": None if canonical else os.path.dirname(out),
        "variant_ids": list(variant_ids),
        "variant_kind": variant_kind,
        "bindings": bindings or {},
        "sources": [source],
        "out": out,
        "own": own,
        "reason": None,
    }
    begin = dict(common, phase="begin")
    consumer_sha = "a" * 64 if consumer_rc == 0 else None
    end = dict(
        common,
        phase="end",
        producer={"argv": ["fake", "build"], "rc": 0, "mods_count": mods_count},
        consumer={
            "argv": ["fake", "build"],
            "rc": consumer_rc,
            "out_written": consumer_rc == 0,
            "out_sha256": consumer_sha,
        },
        run=(
            {"argv": [out], "rc": 0, "signal": None}
            if run_form and consumer_rc == 0
            else None
        ),
        out_ref=None,
        out_ino=None,
        out_mtime_ns=None,
        atime_set_ns=None,
        e3_error=None,
        interrupted=False,
        exit=consumer_rc,
    )
    return [begin, end]


def _o5_exec_record(
    *,
    nonce: str,
    driver: str,
    invocation: str,
    mode: str,
    command: str,
    canonical: bool,
    variant_ids: tuple[str, ...] = (),
    variant_kind: str | None = None,
    bindings: dict | None = None,
    phase: str = "exec",
) -> dict:
    return {
        "v": 1,
        "kind": "record",
        "nonce": nonce,
        "driver": driver,
        "inv": invocation,
        "pid": 200,
        "t_ns": 2,
        "phase": phase,
        "mode": mode,
        "command": command,
        "cwd": "/",
        "argv": [command],
        "env_seen": {},
        "roots": [],
        "canonical": canonical,
        "first_noncanonical_root": None if canonical else "/patched",
        "variant_ids": list(variant_ids),
        "variant_kind": variant_kind,
        "bindings": bindings or {},
        "sources": [],
        "out": None,
        "own": False,
        "reason": None,
        "interrupted": False,
        "run": None,
        "exit": 0,
    }


def _o5_descriptor(
    *,
    include_header: bool,
    header: dict,
    census: dict,
    records: list[dict],
    raw_tail: tuple[str, ...],
) -> bytes:
    return json.dumps(
        {
            "include_header": include_header,
            "header": header,
            "census": census,
            "records": records,
            "raw_tail": raw_tail,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _o5_write_ledger(
    path: str,
    *,
    include_header: bool,
    header: dict,
    records: list[dict],
    raw_tail: tuple[str, ...] = (),
) -> None:
    lines = []
    if include_header:
        lines.append(json.dumps(header, sort_keys=True))
    lines.extend(json.dumps(record, sort_keys=True) for record in records)
    lines.extend(raw_tail)
    with open(path, "w", encoding="utf-8") as ledger_file:
        ledger_file.write("\n".join(lines) + "\n")


def _o5_verify(
    ledger_path: str,
    *,
    census: dict,
    repo: str,
    work_tmp: str,
    stat_fn: Callable[[str], os.stat_result] = os.stat,
) -> proofkit_mod.LedgerVerdict:
    return proofkit_mod.verify_ledger(
        ledger_path,
        census=census,
        driver="demo",
        nonce="nonce-1",
        attempt=1,
        chain_id="12345678" + "a" * 24,
        work_tmp=work_tmp,
        repo=repo,
        stat_fn=stat_fn,
    )


def _o5_ledger_fixture(case: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o5-ledger-") as root:
        repo = os.path.join(root, "repo")
        work_tmp = os.path.join(root, "t")
        work = os.path.join(work_tmp, "w0")
        os.makedirs(os.path.join(repo, "bench"))
        os.makedirs(work)
        ledger_path = os.path.join(root, "ledger.jsonl")
        header = {
            "v": 1,
            "kind": "header",
            "nonce": "nonce-1",
            "driver": "demo",
            "attempt": 1,
            "chain_id": "12345678" + "a" * 24,
        }
        census = _o5_census()
        records = _o5_pair(
            nonce="nonce-1",
            driver="demo",
            invocation="own-1",
            repo=repo,
            out=os.path.join(work, "own"),
            own=True,
        )
        include_header = True
        raw_tail: tuple[str, ...] = ()
        file_mode = "normal"
        control = _o5_descriptor(
            include_header=include_header,
            header=header,
            census=census,
            records=records,
            raw_tail=raw_tail,
        ) + b"\0normal"
        expected: tuple[str, ...] = ()
        detail = "unmodified passing ledger"

        if case == "ledger-stale-header":
            header["nonce"] = "stale-nonce"
            expected = ("STALE",)
            detail = "header nonce changed"
        elif case in ("ledger-misclassified", "canonical-observed-negative"):
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation=f"{case}-1",
                    mode="observed-negative",
                    command="build",
                    canonical=True,
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "canonical exec appended in observed-negative mode"
        elif case == "ledger-unfaithful":
            records.pop(0)
            expected = ("UNFAITHFUL",)
            detail = "begin record removed"
        elif case == "ledger-divergence":
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="divergent-helper",
                    repo=repo,
                    out=os.path.join(work, "helper"),
                    own=False,
                    consumer_rc=7,
                    run_form=False,
                )
            )
            expected = ("DIVERGENCE",)
            detail = "canonical-other consumer changed to exit 7"
        elif case == "ledger-not-roundtripped":
            records[1]["producer"]["mods_count"] = 0
            expected = ("NOT-ROUNDTRIPPED",)
            detail = "own producer mods_count changed from 1 to 0"
        elif case == "own-source-copy":
            copied_source = os.path.join(
                repo,
                "copied",
                "std_demo_exercise.iyi",
            )
            for record in records:
                record["sources"] = [copied_source]
            expected = ("NOT-ROUNDTRIPPED",)
            detail = "own source changed to a same-named noncanonical copy"
        elif case == "consumer-no-out":
            divergent = _o5_pair(
                nonce="nonce-1",
                driver="demo",
                invocation="consumer-no-out",
                repo=repo,
                out=os.path.join(work, "helper-no-out"),
                own=False,
            )
            divergent[1]["consumer"]["out_written"] = False
            records.extend(divergent)
            expected = ("DIVERGENCE",)
            detail = "canonical-other consumer succeeded without writing OUT"
        elif case == "ledger-not-exercised":
            _o5_add_variant(
                census,
                variant_id="demo.negative.missing",
                kind="negative",
                variables={"flavor": {"values": ["required"]}},
            )
            expected = ("NOT-EXERCISED",)
            detail = "required enumerated value added without a record"
        elif case == "ledger-positive-negative-only":
            _o5_add_variant(
                census,
                variant_id="demo.positive.only-negative",
                kind="positive",
                variables={"flavor": {"values": ["fast"]}},
                evidence_name="positive-negative-only",
            )
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="positive-as-negative",
                    mode="observed-negative",
                    command="build",
                    canonical=False,
                    variant_ids=("demo.positive.only-negative",),
                    variant_kind="positive",
                    bindings={
                        "demo.positive.only-negative": {"flavor": "fast"}
                    },
                )
            )
            expected = ("MISCLASSIFIED", "NOT-EXECUTED", "NOT-EXERCISED")
            detail = "positive variant represented only by observed-negative exec"
        elif case == "file-missing":
            file_mode = "missing"
            expected = ("STALE",)
            detail = "ledger file omitted"
        elif case == "file-empty":
            file_mode = "empty"
            expected = ("STALE",)
            detail = "ledger file truncated to zero bytes"
        elif case == "header-malformed":
            file_mode = "malformed-header"
            expected = ("STALE", "UNFAITHFUL")
            detail = "header line replaced by malformed JSON"
        elif case == "header-missing":
            include_header = False
            expected = ("STALE",)
            detail = "header line removed"
        elif case == "header-attempt":
            header["attempt"] = 2
            expected = ("STALE",)
            detail = "header attempt changed from 1 to 2"
        elif case == "header-chain":
            header["chain_id"] = "87654321" + "b" * 24
            expected = ("STALE",)
            detail = "header chain_id changed"
        elif case == "header-driver":
            header["driver"] = "foreign-driver"
            expected = ("STALE",)
            detail = "header driver changed"
        elif case == "record-foreign-nonce":
            for record in records:
                record["nonce"] = "foreign-nonce"
            expected = ("STALE",)
            detail = "paired records' nonce changed"
        elif case == "record-foreign-driver":
            for record in records:
                record["driver"] = "foreign-driver"
            expected = ("STALE",)
            detail = "paired records' driver changed"
        elif case == "refused-record":
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="refused-1",
                    mode="refused",
                    command="build",
                    canonical=False,
                    phase="refused",
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "refused record appended"
        elif case == "unclassified-record":
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="unclassified-record",
                    mode="unclassified",
                    command="fmt",
                    canonical=False,
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "unclassified exec record appended"
        elif case == "noncanonical-without-ids":
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="unclassified-1",
                    mode="observed-negative",
                    command="build",
                    canonical=False,
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "non-canonical build appended without variant ids"
        elif case == "unknown-variant-id":
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="unknown-variant-1",
                    mode="observed-negative",
                    command="build",
                    canonical=False,
                    variant_ids=("demo.unknown",),
                    variant_kind="negative",
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "unknown variant id appended"
        elif case == "malformed-variant-ids":
            malformed_ids = _o5_exec_record(
                nonce="nonce-1",
                driver="demo",
                invocation="malformed-variant-ids",
                mode="observed-negative",
                command="build",
                canonical=False,
            )
            malformed_ids["variant_ids"] = "not-a-list"
            records.append(malformed_ids)
            expected = ("MISCLASSIFIED",)
            detail = "variant_ids changed from a list to a string"
        elif case == "variant-kind-mismatch":
            _o5_add_variant(
                census,
                variant_id="demo.negative.kind",
                kind="negative",
                variables={},
            )
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="variant-kind-mismatch",
                    mode="observed-negative",
                    command="build",
                    canonical=False,
                    variant_ids=("demo.negative.kind",),
                    variant_kind="positive",
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "record variant_kind changed away from census kind"
        elif case == "negative-roundtrip":
            _o5_add_variant(
                census,
                variant_id="demo.negative.roundtrip",
                kind="negative",
                variables={},
            )
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="negative-roundtrip",
                    repo=repo,
                    out=os.path.join(work, "negative-roundtrip"),
                    own=False,
                    canonical=False,
                    variant_ids=("demo.negative.roundtrip",),
                    variant_kind="negative",
                )
            )
            expected = ("MISCLASSIFIED",)
            detail = "negative variant appended in roundtrip mode"
        elif case == "unpaired-end":
            records.append(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="end-only",
                    repo=repo,
                    out=os.path.join(work, "helper"),
                    own=False,
                )[1]
            )
            expected = ("UNFAITHFUL",)
            detail = "end record appended without its begin"
        elif case == "interrupted":
            interrupted = _o5_exec_record(
                nonce="nonce-1",
                driver="demo",
                invocation="interrupted-1",
                mode="unchanged",
                command="fmt",
                canonical=True,
            )
            interrupted["interrupted"] = True
            records.append(interrupted)
            expected = ("UNFAITHFUL",)
            detail = "exec record marked interrupted"
        elif case == "run-signal":
            records[1]["run"]["signal"] = 15
            expected = ("UNFAITHFUL",)
            detail = "run signal changed from null to 15"
        elif case == "malformed-line":
            raw_tail = ("{not-json",)
            expected = ("UNFAITHFUL",)
            detail = "one malformed JSON line appended"
        elif case == "blank-line":
            raw_tail = ("",)
            expected = ("UNFAITHFUL",)
            detail = "blank JSONL line appended"
        elif case == "invalid-record":
            records.append({"v": 1, "kind": "not-record"})
            expected = ("UNFAITHFUL",)
            detail = "non-record JSON object appended"
        elif case == "missing-inv":
            del records[1]["inv"]
            expected = ("UNFAITHFUL",)
            detail = "end record invocation id removed"
        elif case == "pair-field-drift":
            records[1]["cwd"] = os.path.join(repo, "drifted")
            expected = ("UNFAITHFUL",)
            detail = "end record cwd changed away from its begin"
        elif case == "e2-name-repeated":
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="own-duplicate",
                    repo=repo,
                    out=os.path.join(work, "own"),
                    own=True,
                )
            )
            expected = ("NOT-EXECUTED",)
            detail = "second own record reuses the declared output name"
        elif case == "e2-count-short":
            census["exec_evidence"][0]["name_from_calls"]["12"] = "second"
            expected = ("NOT-EXECUTED",)
            detail = "second declared output name added without a record"
        elif case == "e2-consumer-unhashed":
            records[1]["consumer"]["out_sha256"] = None
            expected = ("NOT-EXECUTED", "NOT-ROUNDTRIPPED")
            detail = "own consumer hash changed from a digest to null"
        elif case == "e2-unmatched-own":
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="own-unmatched",
                    repo=repo,
                    out=os.path.join(work, "stray"),
                    own=True,
                )
            )
            expected = ("NOT-EXECUTED",)
            detail = "extra own output does not match execution evidence"
        elif case == "e2-unknown-placeholder":
            census["exec_evidence"][0]["out_template"] = "{WORK}/{unknown}"
            expected = ("NOT-EXECUTED",)
            detail = "execution evidence name placeholder changed to unknown"
        elif case == "e2-repo-template-control":
            repo_out = os.path.join(repo, "own")
            for record in records:
                record["out"] = repo_out
            records[1]["run"]["argv"][0] = repo_out
            census["exec_evidence"][0]["out_template"] = "{REPO}/own"
            census["exec_evidence"][0]["name_from_calls"] = {}
            detail = "passing static {REPO} execution-evidence template"
        elif case == "value-missing":
            _o5_add_variant(
                census,
                variant_id="demo.negative.values",
                kind="negative",
                variables={"flavor": {"values": ["red", "blue"]}},
            )
            records.append(
                _o5_exec_record(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="value-red",
                    mode="observed-negative",
                    command="build",
                    canonical=False,
                    variant_ids=("demo.negative.values",),
                    variant_kind="negative",
                    bindings={"demo.negative.values": {"flavor": "red"}},
                )
            )
            expected = ("NOT-EXERCISED",)
            detail = "blue value omitted while red remains covered"
        elif case == "pattern-var-unexercised":
            _o5_add_variant(
                census,
                variant_id="demo.negative.pattern",
                kind="negative",
                variables={
                    "mutation": {
                        "pattern": "[1-9][0-9]*",
                        "pattern_reason_line": 20,
                    }
                },
            )
            expected = ("NOT-EXERCISED",)
            detail = "required pattern variable added without a record"
        elif case == "positive-no-success":
            _o5_add_variant(
                census,
                variant_id="demo.positive.no-success",
                kind="positive",
                variables={},
                evidence_name="positive",
            )
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="positive-no-success",
                    repo=repo,
                    out=os.path.join(work, "positive"),
                    own=False,
                    canonical=False,
                    variant_ids=("demo.positive.no-success",),
                    variant_kind="positive",
                    mods_count=0,
                )
            )
            expected = ("NOT-EXERCISED",)
            detail = "positive producer mods_count changed from 1 to 0"
        elif case == "variant-coverage-control":
            _o5_add_variant(
                census,
                variant_id="demo.negative.covered",
                kind="negative",
                variables={
                    "flavor": {"values": ["red", "blue"]},
                    "mutation": {
                        "pattern": "[1-9][0-9]*",
                        "pattern_reason_line": 20,
                    },
                },
            )
            for flavor, mutation in (("red", "1"), ("blue", "2")):
                records.append(
                    _o5_exec_record(
                        nonce="nonce-1",
                        driver="demo",
                        invocation=f"covered-{flavor}",
                        mode="observed-negative",
                        command="build",
                        canonical=False,
                        variant_ids=("demo.negative.covered",),
                        variant_kind="negative",
                        bindings={
                            "demo.negative.covered": {
                                "flavor": flavor,
                                "mutation": mutation,
                            }
                        },
                    )
                )
            detail = "all enumerated and pattern bindings are represented"
        elif case == "positive-success-control":
            _o5_add_variant(
                census,
                variant_id="demo.positive.success",
                kind="positive",
                variables={},
                evidence_name="positive",
            )
            records.extend(
                _o5_pair(
                    nonce="nonce-1",
                    driver="demo",
                    invocation="positive-success",
                    repo=repo,
                    out=os.path.join(work, "positive"),
                    own=False,
                    canonical=False,
                    variant_ids=("demo.positive.success",),
                    variant_kind="positive",
                )
            )
            detail = "positive variant has a successful hashed roundtrip"
        elif case == "run-form-not-counted":
            records[1]["run"]["argv"][0] = os.path.join(work, "other")
            expected = ("NOT-EXECUTED",)
            detail = "run argv[0] changed away from OUT"
        elif case not in (
            "control",
            "e2-repo-template-control",
            "variant-coverage-control",
            "positive-success-control",
        ):
            raise ValueError(f"unknown O5 ledger fixture case: {case}")

        seeded = _o5_descriptor(
            include_header=include_header,
            header=header,
            census=census,
            records=records,
            raw_tail=raw_tail,
        ) + b"\0" + file_mode.encode()
        if file_mode == "normal":
            _o5_write_ledger(
                ledger_path,
                include_header=include_header,
                header=header,
                records=records,
                raw_tail=raw_tail,
            )
        elif file_mode == "empty":
            with open(ledger_path, "wb"):
                pass
        elif file_mode == "malformed-header":
            with open(ledger_path, "w", encoding="utf-8") as ledger_file:
                ledger_file.write("{malformed-header\n")
        elif file_mode != "missing":
            raise ValueError(f"unknown O5 ledger file mode: {file_mode}")
        verdict = _o5_verify(
            ledger_path,
            census=census,
            repo=repo,
            work_tmp=work_tmp,
        )
        is_control = case in (
            "control",
            "e2-repo-template-control",
            "variant-coverage-control",
            "positive-success-control",
        )
        return Observation(
            expected=expected,
            got=tuple(sorted(verdict.statuses)),
            applied=(
                ""
                if is_control
                else f"serialized_input_changed={str(seeded != control).lower()}; {detail}"
            ),
        )


def _o5_e3_fixture(case: str) -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o5-e3-") as root:
        repo = os.path.join(root, "repo")
        work_tmp = os.path.join(root, "t")
        work = os.path.join(work_tmp, "w0")
        os.makedirs(os.path.join(repo, "bench"))
        os.makedirs(work)
        out = os.path.join(work, "own")
        out_ref = os.path.join(root, "own.ref")
        shutil.copyfile("/usr/bin/true", out)
        os.chmod(out, 0o755)
        os.link(out, out_ref)
        linked = os.stat(out_ref)
        recorded_mtime = linked.st_mtime_ns
        with open(out, "rb") as executable:
            expected_sha = hashlib.sha256(executable.read()).hexdigest()
        atime_set = recorded_mtime - 1_000_000_000
        os.utime(out, ns=(atime_set, recorded_mtime))

        census = _o5_census()
        records = _o5_pair(
            nonce="nonce-1",
            driver="demo",
            invocation="own-e3",
            repo=repo,
            out=out,
            own=True,
            run_form=False,
        )
        end = records[1]
        end["consumer"]["out_sha256"] = expected_sha
        end["out_ref"] = out_ref
        end["out_ino"] = linked.st_ino
        end["out_mtime_ns"] = recorded_mtime
        end["atime_set_ns"] = atime_set
        ledger_path = os.path.join(root, "ledger.jsonl")
        header = {
            "v": 1,
            "kind": "header",
            "nonce": "nonce-1",
            "driver": "demo",
            "attempt": 1,
            "chain_id": "12345678" + "a" * 24,
        }
        stat_calls: list[str] = []
        expected_statuses: tuple[str, ...] = ()
        detail = "hard-linked /usr/bin/true executed before verification"

        def observing_stat(path: str) -> os.stat_result:
            stat_calls.append(path)
            return os.stat(path)

        stat_fn: Callable[[str], os.stat_result] = observing_stat
        if case == "control":
            completed = subprocess.run(
                [out],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"hard-linked /usr/bin/true control exited {completed.returncode}"
                )
        elif case == "ref-missing":
            end["out_ref"] = None
            expected_statuses = ("NOT-EXECUTED",)
            detail = "seed did not execute; out_ref changed to null"
        elif case == "inode-changed":
            os.unlink(out_ref)
            shutil.copyfile(out, out_ref)
            os.chmod(out_ref, 0o755)
            replacement = os.stat(out_ref)
            os.utime(
                out_ref,
                ns=(recorded_mtime + 1_000_000_000, recorded_mtime),
            )
            expected_statuses = ("NOT-EXECUTED",)
            detail = (
                "seed did not execute; "
                f"inode_changed={replacement.st_ino != linked.st_ino}"
            )
        elif case == "atime-not-advanced":
            expected_statuses = ("NOT-EXECUTED",)
            detail = "seed did not execute; atime remains at the shim-set value"
        elif case == "sha-changed":
            os.utime(
                out_ref,
                ns=(recorded_mtime + 1_000_000_000, recorded_mtime),
            )

            def mutating_stat(path: str) -> os.stat_result:
                stat_calls.append(path)
                before_read = os.stat(path)
                with open(path, "ab") as executable:
                    executable.write(b"o5-after-stat")
                return before_read

            stat_fn = mutating_stat
            expected_statuses = ("OUT-MODIFIED",)
            detail = "seed did not execute; stat_fn mutates bytes after stat"
        elif case == "copy-modified":
            with open(out_ref, "r+b") as executable:
                executable.seek(0)
                executable.write(b"o5-in-place")
            modified = os.stat(out_ref)
            os.utime(
                out_ref,
                ns=(
                    recorded_mtime + 1_000_000_000,
                    modified.st_mtime_ns,
                ),
            )
            expected_statuses = ("OUT-MODIFIED",)
            detail = "seed did not execute; hard-linked OUT overwritten in place"
        elif case == "stat-failed":
            def failing_stat(path: str) -> os.stat_result:
                stat_calls.append(path)
                raise OSError("seeded stat failure")

            stat_fn = failing_stat
            expected_statuses = ("NOT-EXECUTED",)
            detail = "seed did not execute; stat_fn raises after recording its call"
        elif case == "read-failed":
            os.utime(
                out_ref,
                ns=(recorded_mtime + 1_000_000_000, recorded_mtime),
            )

            def removing_stat(path: str) -> os.stat_result:
                stat_calls.append(path)
                before_read = os.stat(path)
                os.unlink(path)
                return before_read

            stat_fn = removing_stat
            expected_statuses = ("OUT-MODIFIED",)
            detail = "seed did not execute; stat_fn removes OUT after stat"
        else:
            raise ValueError(f"unknown O5 E3 fixture case: {case}")

        _o5_write_ledger(
            ledger_path,
            include_header=True,
            header=header,
            records=records,
        )
        verdict = _o5_verify(
            ledger_path,
            census=census,
            repo=repo,
            work_tmp=work_tmp,
            stat_fn=stat_fn,
        )
        try:
            current_atime = (
                os.stat(out_ref).st_atime_ns
                if isinstance(end.get("out_ref"), str)
                else None
            )
        except OSError:
            current_atime = None
        expected_calls = 0 if case == "ref-missing" else 1
        return Observation(
            expected={
                "statuses": expected_statuses,
                "stat_calls": expected_calls,
                "control_atime_advanced": True if case == "control" else None,
            },
            got={
                "statuses": tuple(sorted(verdict.statuses)),
                "stat_calls": len(stat_calls),
                "control_atime_advanced": (
                    current_atime > recorded_mtime
                    if case == "control" and current_atime is not None
                    else None
                ),
            },
            applied=("" if case == "control" else f"{detail}; stat_calls={len(stat_calls)}"),
        )


O5_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "s3.seed.ledger-stale-header",
        "seed",
        partial(_o5_ledger_fixture, "ledger-stale-header"),
    ),
    Fixture(
        "s3.seed.ledger-misclassified",
        "seed",
        partial(_o5_ledger_fixture, "ledger-misclassified"),
    ),
    Fixture(
        "s3.seed.ledger-unfaithful",
        "seed",
        partial(_o5_ledger_fixture, "ledger-unfaithful"),
    ),
    Fixture(
        "s3.seed.ledger-divergence",
        "seed",
        partial(_o5_ledger_fixture, "ledger-divergence"),
    ),
    Fixture(
        "o5.seed.consumer-no-out",
        "seed",
        partial(_o5_ledger_fixture, "consumer-no-out"),
    ),
    Fixture(
        "s3.seed.ledger-not-roundtripped",
        "seed",
        partial(_o5_ledger_fixture, "ledger-not-roundtripped"),
    ),
    Fixture(
        "o5.seed.own-source-copy",
        "seed",
        partial(_o5_ledger_fixture, "own-source-copy"),
    ),
    Fixture(
        "s3.seed.ledger-not-exercised",
        "seed",
        partial(_o5_ledger_fixture, "ledger-not-exercised"),
    ),
    Fixture(
        "s3.seed.ledger-positive-negative-only",
        "seed",
        partial(_o5_ledger_fixture, "ledger-positive-negative-only"),
    ),
    Fixture(
        "s3.control.ledger",
        "control",
        partial(_o5_ledger_fixture, "control"),
    ),
    Fixture(
        "o5.seed.file-missing",
        "seed",
        partial(_o5_ledger_fixture, "file-missing"),
    ),
    Fixture(
        "o5.seed.file-empty",
        "seed",
        partial(_o5_ledger_fixture, "file-empty"),
    ),
    Fixture(
        "o5.seed.header-malformed",
        "seed",
        partial(_o5_ledger_fixture, "header-malformed"),
    ),
    Fixture(
        "o5.seed.header-missing",
        "seed",
        partial(_o5_ledger_fixture, "header-missing"),
    ),
    Fixture(
        "o5.seed.header-attempt",
        "seed",
        partial(_o5_ledger_fixture, "header-attempt"),
    ),
    Fixture(
        "o5.seed.header-chain",
        "seed",
        partial(_o5_ledger_fixture, "header-chain"),
    ),
    Fixture(
        "o5.seed.header-driver",
        "seed",
        partial(_o5_ledger_fixture, "header-driver"),
    ),
    Fixture(
        "o5.seed.record-foreign-nonce",
        "seed",
        partial(_o5_ledger_fixture, "record-foreign-nonce"),
    ),
    Fixture(
        "o5.seed.record-foreign-driver",
        "seed",
        partial(_o5_ledger_fixture, "record-foreign-driver"),
    ),
    Fixture(
        "o5.seed.refused-record",
        "seed",
        partial(_o5_ledger_fixture, "refused-record"),
    ),
    Fixture(
        "o5.seed.unclassified-record",
        "seed",
        partial(_o5_ledger_fixture, "unclassified-record"),
    ),
    Fixture(
        "o5.seed.noncanonical-without-ids",
        "seed",
        partial(_o5_ledger_fixture, "noncanonical-without-ids"),
    ),
    Fixture(
        "o5.seed.canonical-observed-negative",
        "seed",
        partial(_o5_ledger_fixture, "canonical-observed-negative"),
    ),
    Fixture(
        "o5.seed.unknown-variant-id",
        "seed",
        partial(_o5_ledger_fixture, "unknown-variant-id"),
    ),
    Fixture(
        "o5.seed.malformed-variant-ids",
        "seed",
        partial(_o5_ledger_fixture, "malformed-variant-ids"),
    ),
    Fixture(
        "o5.seed.variant-kind-mismatch",
        "seed",
        partial(_o5_ledger_fixture, "variant-kind-mismatch"),
    ),
    Fixture(
        "o5.seed.negative-roundtrip",
        "seed",
        partial(_o5_ledger_fixture, "negative-roundtrip"),
    ),
    Fixture(
        "o5.seed.unpaired-end",
        "seed",
        partial(_o5_ledger_fixture, "unpaired-end"),
    ),
    Fixture(
        "o5.seed.interrupted",
        "seed",
        partial(_o5_ledger_fixture, "interrupted"),
    ),
    Fixture(
        "o5.seed.run-signal",
        "seed",
        partial(_o5_ledger_fixture, "run-signal"),
    ),
    Fixture(
        "o5.seed.malformed-line",
        "seed",
        partial(_o5_ledger_fixture, "malformed-line"),
    ),
    Fixture(
        "o5.seed.blank-line",
        "seed",
        partial(_o5_ledger_fixture, "blank-line"),
    ),
    Fixture(
        "o5.seed.invalid-record",
        "seed",
        partial(_o5_ledger_fixture, "invalid-record"),
    ),
    Fixture(
        "o5.seed.missing-inv",
        "seed",
        partial(_o5_ledger_fixture, "missing-inv"),
    ),
    Fixture(
        "o5.seed.pair-field-drift",
        "seed",
        partial(_o5_ledger_fixture, "pair-field-drift"),
    ),
    Fixture(
        "o5.seed.e2-name-repeated",
        "seed",
        partial(_o5_ledger_fixture, "e2-name-repeated"),
    ),
    Fixture(
        "o5.seed.e2-count-short",
        "seed",
        partial(_o5_ledger_fixture, "e2-count-short"),
    ),
    Fixture(
        "o5.seed.e2-consumer-unhashed",
        "seed",
        partial(_o5_ledger_fixture, "e2-consumer-unhashed"),
    ),
    Fixture(
        "o5.seed.e2-unmatched-own",
        "seed",
        partial(_o5_ledger_fixture, "e2-unmatched-own"),
    ),
    Fixture(
        "o5.seed.e2-unknown-placeholder",
        "seed",
        partial(_o5_ledger_fixture, "e2-unknown-placeholder"),
    ),
    Fixture(
        "o5.control.e2-repo-template",
        "control",
        partial(_o5_ledger_fixture, "e2-repo-template-control"),
    ),
    Fixture(
        "o5.seed.e3-ref-missing",
        "seed",
        partial(_o5_e3_fixture, "ref-missing"),
    ),
    Fixture(
        "o5.seed.e3-inode-changed",
        "seed",
        partial(_o5_e3_fixture, "inode-changed"),
    ),
    Fixture(
        "o5.seed.e3-atime-not-advanced",
        "seed",
        partial(_o5_e3_fixture, "atime-not-advanced"),
    ),
    Fixture(
        "o5.seed.e3-sha-changed",
        "seed",
        partial(_o5_e3_fixture, "sha-changed"),
    ),
    Fixture(
        "o5.seed.e3-stat-failed",
        "seed",
        partial(_o5_e3_fixture, "stat-failed"),
    ),
    Fixture(
        "o5.seed.e3-read-failed",
        "seed",
        partial(_o5_e3_fixture, "read-failed"),
    ),
    Fixture(
        "o5.seed.value-missing",
        "seed",
        partial(_o5_ledger_fixture, "value-missing"),
    ),
    Fixture(
        "o5.seed.pattern-var-unexercised",
        "seed",
        partial(_o5_ledger_fixture, "pattern-var-unexercised"),
    ),
    Fixture(
        "o5.seed.positive-no-success",
        "seed",
        partial(_o5_ledger_fixture, "positive-no-success"),
    ),
    Fixture(
        "o5.control.variant-coverage",
        "control",
        partial(_o5_ledger_fixture, "variant-coverage-control"),
    ),
    Fixture(
        "o5.control.positive-success",
        "control",
        partial(_o5_ledger_fixture, "positive-success-control"),
    ),
    Fixture(
        "o5.control.e2-e3",
        "control",
        partial(_o5_e3_fixture, "control"),
    ),
    Fixture(
        "amend-b.seed.not-executed",
        "seed",
        partial(_o5_e3_fixture, "atime-not-advanced"),
    ),
    Fixture(
        "amend-b.seed.copy-modified",
        "seed",
        partial(_o5_e3_fixture, "copy-modified"),
    ),
    Fixture(
        "amend-b.seed.move-replaced",
        "seed",
        partial(_o5_e3_fixture, "inode-changed"),
    ),
    Fixture(
        "amend-b.seed.run-form-not-counted",
        "seed",
        partial(_o5_ledger_fixture, "run-form-not-counted"),
    ),
    Fixture(
        "amend-b.control.stub-run",
        "control",
        partial(_o5_e3_fixture, "control"),
    ),
    Fixture(
        "amend-b.control.run-form",
        "control",
        partial(_o5_ledger_fixture, "control"),
    ),
)
O5_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o5.header": (
        "o5.seed.file-missing",
        "o5.seed.file-empty",
        "o5.seed.header-malformed",
        "o5.seed.header-missing",
        "o5.seed.header-attempt",
        "o5.seed.header-chain",
        "o5.seed.header-driver",
        "o5.seed.record-foreign-nonce",
        "o5.seed.record-foreign-driver",
        "s3.control.ledger",
    ),
    "o5.classification": (
        "o5.seed.refused-record",
        "o5.seed.unclassified-record",
        "o5.seed.noncanonical-without-ids",
        "o5.seed.canonical-observed-negative",
        "o5.seed.unknown-variant-id",
        "o5.seed.malformed-variant-ids",
        "o5.seed.variant-kind-mismatch",
        "o5.seed.negative-roundtrip",
        "s3.control.ledger",
    ),
    "o5.faithful": (
        "o5.seed.unpaired-end",
        "o5.seed.interrupted",
        "o5.seed.run-signal",
        "o5.seed.malformed-line",
        "o5.seed.blank-line",
        "o5.seed.invalid-record",
        "o5.seed.missing-inv",
        "o5.seed.pair-field-drift",
        "s3.control.ledger",
    ),
    "o5.divergence": (
        "o5.seed.consumer-no-out",
        "s3.control.ledger",
    ),
    "o5.not-roundtripped": (
        "s3.seed.ledger-not-roundtripped",
        "o5.seed.own-source-copy",
        "s3.control.ledger",
    ),
    "o5.e2": (
        "o5.seed.e2-name-repeated",
        "o5.seed.e2-count-short",
        "o5.seed.e2-consumer-unhashed",
        "o5.seed.e2-unmatched-own",
        "o5.seed.e2-unknown-placeholder",
        "o5.control.e2-repo-template",
        "o5.control.e2-e3",
    ),
    "o5.e3": (
        "o5.seed.e3-ref-missing",
        "o5.seed.e3-inode-changed",
        "o5.seed.e3-atime-not-advanced",
        "o5.seed.e3-sha-changed",
        "o5.seed.e3-stat-failed",
        "o5.seed.e3-read-failed",
        "o5.control.e2-e3",
    ),
    "o5.not-exercised": (
        "o5.seed.value-missing",
        "o5.seed.pattern-var-unexercised",
        "o5.seed.positive-no-success",
        "o5.control.variant-coverage",
        "o5.control.positive-success",
        "s3.control.ledger",
    ),
}


# ===== O6: artifact legs (owner U6). Keys "o6.". =====


O6_FIXTURES: tuple[Fixture, ...] = ()
O6_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {}


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


_COVERAGE_SOURCES: dict[str, str] = {
    "proof.proofkit": "proofkit.py",
    "proof.run_proof": "run_proof.py",
    "proof.artifact_legs": "artifact_legs.py",
    "proof.roundtrip_shim": "roundtrip_shim.py",
}
_COVERAGE_BOOTSTRAP = r"""
import os
import sys
import trace
import threading

repo, coverdir = sys.argv[1:3]
os.chdir(repo)
if repo not in sys.path:
    sys.path.insert(0, repo)

required_fresh = {
    "proof.smoke_test",
    "proof.proofkit",
    "proof.run_proof",
    "proof.artifact_legs",
    "proof.roundtrip_shim",
}
premature = sorted(required_fresh.intersection(sys.modules))
if premature:
    raise RuntimeError(f"coverage modules imported before trace: {premature}")

tracer = trace.Trace(
    count=1,
    trace=0,
    ignoredirs=[sys.prefix, sys.exec_prefix],
)
namespace = {}
threading.settrace(tracer.globaltrace)
try:
    tracer.runctx(
        "from proof import smoke_test as _smoke_test\n"
        "_suite_status = _smoke_test.main([])\n",
        namespace,
        namespace,
    )
finally:
    threading.settrace(None)
    results = tracer.results()
    target_paths = {
        os.path.realpath(os.path.join(repo, "proof", filename))
        for filename in (
            "proofkit.py",
            "run_proof.py",
            "artifact_legs.py",
            "roundtrip_shim.py",
        )
    }
    for key in tuple(results.counts):
        if os.path.realpath(key[0]) not in target_paths:
            del results.counts[key]
    results.write_results(
        show_missing=True,
        summary=False,
        coverdir=coverdir,
    )

raise SystemExit(namespace.get("_suite_status", 1))
"""


# Each entry is:
# (module, first_line, last_line, subprocess_fixture_id, observable).
ALLOWLIST: tuple[tuple[str, int, int, str, str], ...] = (
    (
        "proof.roundtrip_shim",
        1340,
        1341,
        "s3.control.passthrough",
        "subprocess main dispatches passthrough ExecPlan to the sole os.execv "
        "site; fake REAL records preserved argv and environment",
    ),
    (
        "proof.roundtrip_shim",
        1344,
        1355,
        "s3.control.passthrough",
        "subprocess parses --config/-- in main and takes the ExecPlan branch",
    ),
    (
        "proof.roundtrip_shim",
        1356,
        1356,
        "s3.control.canonical-build",
        "subprocess main returns the canonical producer/consumer roundtrip rc",
    ),
    (
        "proof.roundtrip_shim",
        1359,
        1360,
        "s3.control.canonical-build",
        "top-level entry raises SystemExit from the exercised "
        "main-to-roundtrip path",
    ),
    (
        "proof.run_proof",
        1568,
        1574,
        "o7.seed.run-proof-optimize-refusal",
        "python -B -O proof/run_proof.py --help enters the nested optimize "
        "guard, prints the exact refusal, and exits 2",
    ),
    (
        "proof.run_proof",
        1575,
        1575,
        "o7.control.run-proof-optimize",
        "python -B proof/run_proof.py --help reaches the normal direct-script "
        "main handoff and exits 0",
    ),
)


def _main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if not isinstance(test, ast.Compare):
        return False
    return (
        isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _raises_system_exit_main(node: ast.AST) -> bool:
    if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
        return False
    call = node.exc
    if not isinstance(call.func, ast.Name) or call.func.id != "SystemExit":
        return False
    if len(call.args) != 1 or call.keywords:
        return False
    argument = call.args[0]
    return (
        isinstance(argument, ast.Call)
        and isinstance(argument.func, ast.Name)
        and argument.func.id == "main"
        and not argument.args
        and not argument.keywords
    )


def _raises_system_exit_two(node: ast.AST) -> bool:
    if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
        return False
    call = node.exc
    return (
        isinstance(call.func, ast.Name)
        and call.func.id == "SystemExit"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == 2
        and not call.keywords
    )


def _optimize_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (
        isinstance(test, ast.Attribute)
        and test.attr == "optimize"
        and isinstance(test.value, ast.Attribute)
        and test.value.attr == "flags"
        and isinstance(test.value.value, ast.Name)
        and test.value.value.id == "sys"
    )


def _node_contains(node: ast.AST, first: int, last: int) -> bool:
    return (
        getattr(node, "lineno", 0) <= first
        and last <= getattr(node, "end_lineno", 0)
    )


def _os_execv_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execv"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    )


def _allowlist_ast_errors(
    executed_fixture_ids: set[str],
    missing_lines: Mapping[str, tuple[int, ...]],
) -> tuple[str, ...]:
    errors: list[str] = []
    trees: dict[str, ast.Module] = {}
    source_line_counts: dict[str, int] = {}
    allowed_nodes: dict[str, tuple[ast.AST, ...]] = {}
    shim_exec_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None

    for module, filename in _COVERAGE_SOURCES.items():
        path = os.path.join(REPO_ROOT, "proof", filename)
        try:
            with open(path, "r", encoding="utf-8") as source_file:
                source = source_file.read()
            tree = ast.parse(source, filename=path)
        except (OSError, SyntaxError) as error:
            errors.append(f"{module}: AST unavailable: {type(error).__name__}: {error}")
            continue

        trees[module] = tree
        source_line_counts[module] = len(source.splitlines())
        guards = tuple(node for node in tree.body if _main_guard(node))
        shim_functions: tuple[ast.AST, ...] = ()
        if module == "proof.roundtrip_shim":
            shim_functions = tuple(
                node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in {"main", "_exec_real"}
            )
            exec_functions = tuple(
                node
                for node in shim_functions
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "_exec_real"
            )
            if len(exec_functions) != 1:
                errors.append(
                    "proof.roundtrip_shim: expected exactly one top-level "
                    "_exec_real function"
                )
            else:
                shim_exec_function = exec_functions[0]
        allowed_nodes[module] = (*guards, *shim_functions)

        for guard in guards:
            body = guard.body
            if module == "proof.run_proof":
                if not body or not _raises_system_exit_main(body[-1]):
                    errors.append(
                        "proof.run_proof: __main__ must end with "
                        "raise SystemExit(main())"
                    )
                    continue
                prefix = body[:-1]
                if (
                    len(prefix) != 1
                    or not _optimize_guard(prefix[0])
                    or prefix[0].orelse
                    or not prefix[0].body
                    or not _raises_system_exit_two(prefix[0].body[-1])
                ):
                    errors.append(
                        "proof.run_proof: only the -O refusal may precede "
                        "raise SystemExit(main()) in __main__"
                    )
            elif len(body) != 1 or not _raises_system_exit_main(body[0]):
                errors.append(
                    f"{module}: __main__ must contain only "
                    "raise SystemExit(main())"
                )

    exec_sites: list[tuple[str, ast.Call]] = []
    for module, tree in trees.items():
        exec_sites.extend(
            (module, node)
            for node in ast.walk(tree)
            if _os_execv_call(node)
        )
    if len(exec_sites) != 1:
        errors.append(
            "P10 requires exactly one os.execv site across the covered modules; "
            f"found {len(exec_sites)}"
        )
    elif (
        exec_sites[0][0] != "proof.roundtrip_shim"
        or shim_exec_function is None
        or not _node_contains(
            shim_exec_function,
            exec_sites[0][1].lineno,
            exec_sites[0][1].end_lineno or exec_sites[0][1].lineno,
        )
    ):
        errors.append(
            "the only os.execv site must be inside "
            "proof.roundtrip_shim._exec_real"
        )

    registered_fixture_ids = {fixture.fixture_id for fixture in FIXTURES}
    seen_entries: set[tuple[str, int, int, str, str]] = set()
    validated_entries: list[tuple[str, int, int, str, str]] = []
    for index, entry in enumerate(ALLOWLIST):
        label = f"ALLOWLIST[{index}]"
        if not isinstance(entry, tuple) or len(entry) != 5:
            errors.append(f"{label}: expected a five-element tuple")
            continue
        module, first, last, fixture_id, observable = entry
        if not isinstance(module, str) or module not in _COVERAGE_SOURCES:
            errors.append(f"{label}: unknown module {module!r}")
            continue
        if (
            not isinstance(first, int)
            or isinstance(first, bool)
            or not isinstance(last, int)
            or isinstance(last, bool)
            or first < 1
            or last < first
        ):
            errors.append(f"{label}: invalid line range {first!r}..{last!r}")
            continue
        if last > source_line_counts.get(module, 0):
            errors.append(
                f"{label}: line range {first}..{last} exceeds {module}"
            )
            continue
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"{label}: subprocess fixture id must be nonempty")
            continue
        if (
            not isinstance(observable, str)
            or not observable.strip()
            or "\n" in observable
            or "\r" in observable
        ):
            errors.append(f"{label}: observable must be one nonempty line")
            continue
        if entry in seen_entries:
            errors.append(f"{label}: duplicate entry")
            continue
        seen_entries.add(entry)

        containing_nodes = tuple(
            node
            for node in allowed_nodes.get(module, ())
            if _node_contains(node, first, last)
        )
        if not containing_nodes:
            errors.append(
                f"{label}: {module}:{first}-{last} is outside P10 glue"
            )
        if fixture_id not in registered_fixture_ids:
            errors.append(f"{label}: unregistered fixture {fixture_id}")
        elif fixture_id not in executed_fixture_ids:
            errors.append(f"{label}: fixture did not run: {fixture_id}")
        if not any(
            first <= line <= last for line in missing_lines.get(module, ())
        ):
            errors.append(f"{label}: entry covers no missing executable line")
        validated_entries.append(entry)

    if len(exec_sites) == 1:
        exec_module, exec_node = exec_sites[0]
        if not any(
            module == exec_module and first <= exec_node.lineno <= last
            for module, first, last, _fixture_id, _observable in validated_entries
        ):
            errors.append("the os.execv line has no P10 allowlist entry")

    return tuple(errors)


def _executed_fixture_ids(output: str) -> set[str]:
    return {
        match.group(1)
        for match in re.finditer(
            r"^(?:SEED|CONTROL) ([^\s]+)(?:\s|$)",
            output,
            flags=re.MULTILINE,
        )
    }


def _listing_candidate(trace_dir: str, module: str) -> str | None:
    stem = _COVERAGE_SOURCES[module][:-3]
    matches = tuple(
        path
        for path in glob.glob(
            os.path.join(trace_dir, "**", "*.cover"),
            recursive=True,
        )
        if (
            os.path.basename(path) in {f"{stem}.cover", f"{stem}.py.cover"}
            or os.path.basename(path).endswith(f".{stem}.cover")
            or os.path.basename(path).endswith(f".{stem}.py.cover")
        )
    )
    return matches[0] if len(matches) == 1 else None


def _write_child_output(stream: io.TextIOBase, output: str) -> None:
    if not output:
        return
    stream.write(output)
    if not output.endswith("\n"):
        stream.write("\n")
    stream.flush()


def _run_coverage_gate(directory: str) -> int:
    coverage_dir = os.path.abspath(directory)
    listing_paths = {
        module: os.path.join(coverage_dir, f"{module}.cover")
        for module in _COVERAGE_SOURCES
    }
    try:
        os.makedirs(coverage_dir, exist_ok=True)
        for listing_path in listing_paths.values():
            try:
                os.unlink(listing_path)
            except FileNotFoundError:
                pass
        trace_dir = tempfile.mkdtemp(prefix=".trace-", dir=coverage_dir)
    except OSError as error:
        print(
            f"COVERAGE gate_error={_render(f'{type(error).__name__}: {error}')}"
        )
        print("COVERAGE GATE FAIL")
        return 1

    try:
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    _COVERAGE_BOOTSTRAP,
                    REPO_ROOT,
                    trace_dir,
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as error:
            print(
                "COVERAGE gate_error="
                f"{_render(f'{type(error).__name__}: {error}')}"
            )
            print("COVERAGE GATE FAIL")
            return 1

        _write_child_output(sys.stdout, completed.stdout)
        _write_child_output(sys.stderr, completed.stderr)
        executed_fixture_ids = _executed_fixture_ids(completed.stdout)

        listing_errors: list[str] = []
        missing_lines: dict[str, tuple[int, ...]] = {}
        for module, listing_path in listing_paths.items():
            candidate = _listing_candidate(trace_dir, module)
            if candidate is None:
                missing_lines[module] = ()
                listing_errors.append(f"{module}: annotated listing missing")
                print(
                    f"COVERAGE module={module} missing_lines=UNKNOWN "
                    "listing_missing=true"
                )
                continue
            try:
                with open(candidate, "r", encoding="utf-8") as source:
                    listing = source.read()
                with open(listing_path, "w", encoding="utf-8") as target:
                    target.write(listing)
            except OSError as error:
                missing_lines[module] = ()
                listing_errors.append(
                    f"{module}: {type(error).__name__}: {error}"
                )
                print(
                    f"COVERAGE module={module} missing_lines=UNKNOWN "
                    "listing_missing=true"
                )
                continue

            module_missing = tuple(
                line_number
                for line_number, line in enumerate(listing.splitlines(), 1)
                if line.startswith(">>>>>>")
            )
            missing_lines[module] = module_missing
            print(
                f"COVERAGE module={module} "
                f"missing_lines={len(module_missing)} "
                f"listing={listing_path}"
            )

        ast_errors = _allowlist_ast_errors(
            executed_fixture_ids,
            missing_lines,
        )
        uncovered: list[tuple[str, int]] = []
        for module, line_numbers in missing_lines.items():
            for line_number in line_numbers:
                if not any(
                    entry_module == module
                    and first <= line_number <= last
                    for (
                        entry_module,
                        first,
                        last,
                        _fixture_id,
                        _observable,
                    ) in ALLOWLIST
                ):
                    uncovered.append((module, line_number))

        for error in listing_errors:
            print(f"COVERAGE listing_error={_render(error)}")
        for error in ast_errors:
            print(f"COVERAGE allowlist_error={_render(error)}")
        for module, line_number in uncovered:
            print(f"COVERAGE unallowlisted={module}:{line_number}")
        for module, first, last, fixture_id, observable in ALLOWLIST:
            print(
                f"COVERAGE allowlisted={module}:{first}-{last} "
                f"fixture={fixture_id} observable={_render(observable)}"
            )
        if completed.returncode != 0:
            print(f"COVERAGE suite_exit={completed.returncode}")

        failed = bool(
            completed.returncode != 0
            or listing_errors
            or ast_errors
            or uncovered
        )
        print("COVERAGE GATE FAIL" if failed else "COVERAGE GATE PASS")
        return 1 if failed else 0
    finally:
        shutil.rmtree(trace_dir, ignore_errors=True)


def main(argv: list[str] | tuple[str, ...] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _run_fixture_suite(FIXTURES, REVIEW_ITEMS)
    if (
        len(args) == 2
        and args[0] == "--coverage"
        and isinstance(args[1], str)
        and bool(args[1])
    ):
        return _run_coverage_gate(args[1])
    print("usage: smoke_test.py [--coverage DIR]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
