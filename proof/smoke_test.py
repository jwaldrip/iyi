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
import shlex
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
sys.dont_write_bytecode = True
sys.pycache_prefix = os.path.join(
    tempfile.gettempdir(),
    f"iyi-proof-pycache-{os.getpid()}-{os.urandom(8).hex()}",
)

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
            "platform_tmp_recorded": (
                isinstance(pin.get("platform_tmp"), str)
                and os.path.isdir(pin["platform_tmp"])
                if sys.platform == "darwin"
                else pin.get("platform_tmp") is None
            ),
        }
    expected = {
        "chain_prefix_matches": True,
        "pin_exists": True,
        "timeout_recorded": True,
        "platform_tmp_recorded": True,
    }
    return Observation(expected=expected, got=got)

def _fixture_platform_tmp_changed_seed() -> Observation:
    with PinFixture() as fixture:
        pin = fixture.pin()
        original = pin["platform_tmp"]
        replacement = (
            fixture.scratch
            if original != fixture.scratch
            else fixture.report
        )
        pin["platform_tmp"] = os.path.realpath(replacement)
        reason = _identity_reason(lambda: check_identity(pin))
    return Observation(
        expected={"applied": True, "reason": "PLATFORM-TMP-CHANGED"},
        got={
            "applied": pin["platform_tmp"] != original,
            "reason": reason,
        },
        applied=f"old={original};new={pin['platform_tmp']}",
    )


def _fixture_platform_tmp_probe_seed() -> Observation:
    if sys.platform != "darwin":
        return Observation(expected=True, got=True, applied="non-Darwin")
    with PinFixture() as fixture:
        tool_dir = os.path.join(fixture.scratch, "platform-tools")
        expected_root = os.path.join(fixture.scratch, "expected-platform")
        foreign_root = os.path.join(fixture.scratch, "foreign-platform")
        os.makedirs(tool_dir)
        os.makedirs(expected_root)
        os.makedirs(foreign_root)
        for tool in ("git", "nm", "timeout"):
            source = shutil.which(tool)
            if not source:
                raise RuntimeError(f"{tool} is unavailable for fixture")
            os.symlink(source, os.path.join(tool_dir, tool))
        getconf = os.path.join(tool_dir, "getconf")
        _o6_write_executable(
            getconf,
            "#!/bin/sh\n"
            f"printf '%s\\n' {shlex.quote(expected_root)}\n",
        )
        probe_path = os.path.join(foreign_root, "probe-created")
        mktemp = os.path.join(tool_dir, "mktemp")
        _o6_write_executable(
            mktemp,
            "#!/bin/sh\n"
            f"/bin/mkdir {shlex.quote(probe_path)}\n"
            f"printf '%s\\n' {shlex.quote(probe_path)}\n",
        )
        original_path = os.environ.get("PATH")
        try:
            os.environ["PATH"] = tool_dir
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
    return Observation(
        expected="PLATFORM-TMP-UNOBSERVABLE",
        got=reason,
        applied=(
            f"getconf={expected_root};"
            f"mktemp-parent={foreign_root}"
        ),
    )


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
            "probe_shown": "Probe:" in output.getvalue()
            and "atime=" in output.getvalue(),
            "report_absent_before": report_absent_before,
            "report_absent_after": report_absent_after,
        }
    expected = {
        "census_validated": True,
        "probe_shown": True,
        "report_absent_before": True,
        "report_absent_after": True,
    }
    return Observation(expected=expected, got=got)


def _fixture_no_timeout_seed() -> Observation:
    with PinFixture() as fixture:
        tool_dir = os.path.join(fixture.scratch, "without-timeout")
        os.makedirs(tool_dir)
        linked: list[str] = []
        tools = ["git", "nm"]
        if sys.platform == "darwin":
            tools.extend(("getconf", "mktemp"))
        for tool in tools:
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


def _grandchild_command(
    pid_file: str,
    *,
    leader_sleeps: bool,
    child_ignores_term: bool = False,
) -> list[str]:
    child_source = [
        "import os, pathlib, signal, time",
    ]
    if child_ignores_term:
        child_source.append(
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)"
        )
    child_source.extend(
        [
            f"pathlib.Path({pid_file!r}).write_text(str(os.getpid()))",
            "time.sleep(100)",
        ]
    )
    statements = [
        "import subprocess, sys, time",
        f"subprocess.Popen([sys.executable, '-c', {('; '.join(child_source))!r}])",
    ]
    if child_ignores_term:
        statements.append("time.sleep(0.1)")
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
            _grandchild_command(
                pid_file,
                leader_sleeps=False,
                child_ignores_term=True,
            ),
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

def _fixture_probe_stat_mutates_seed() -> Observation:
    calls = 0

    def mutating_stat(path: str) -> object:
        nonlocal calls
        calls += 1
        actual = os.stat(path)
        return SimpleNamespace(
            st_atime_ns=(
                actual.st_atime_ns + 1 if calls == 3 else actual.st_atime_ns
            ),
            st_ino=actual.st_ino,
            st_mtime_ns=actual.st_mtime_ns,
        )

    with tempfile.TemporaryDirectory(
        prefix="iyi-o2-atime-stat-seed-",
        dir="/tmp",
    ) as scratch:
        reason = _identity_reason(
            lambda: probe_atime_observable(
                scratch,
                stat_fn=mutating_stat,
            )
        )
    return Observation(
        expected={"reason": "EXEC-UNOBSERVABLE", "stat_calls": 3},
        got={"reason": reason, "stat_calls": calls},
        applied="third stat atime advanced by one nanosecond",
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

def _has_regex_env_call(census: dict, _lines: list[str]) -> bool:
    return (
        census.get("driver") == "regex"
        and any(
            isinstance(site, dict)
            and site.get("lines") == [231]
            and site.get("kind") == "mixed"
            for site in census.get("sites", [])
        )
    )


def _mutate_env_call_classification(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for site in census.get("sites", []):
        if isinstance(site, dict) and site.get("lines") == [231]:
            site["kind"] = "canonical-other"
            site["variants"] = []
            return "regex-231-mixed->canonical-other", 1
    return "regex-231-site-missing", 0


def _has_wildcard_skip(census: dict, _lines: list[str]) -> bool:
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("regex"), str)
        and ".*?" in entry["regex"]
        for entry in census.get("skips", [])
    )


def _mutate_skip_to_iyivar(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for entry in census.get("skips", []):
        regex = entry.get("regex") if isinstance(entry, dict) else None
        if isinstance(regex, str) and ".*?" in regex:
            entry["regex"] = regex.replace(".*?", "IYIVAR", 1)
            return f"skip-{entry.get('line')}-wildcard->IYIVAR", 1
    return "wildcard-skip-missing", 0


def _has_tool_guard_skip(census: dict, _lines: list[str]) -> bool:
    return (
        census.get("driver") == "regex"
        and any(
            isinstance(entry, dict)
            and entry.get("line") == 51
            and entry.get("class") == "tool"
            for entry in census.get("skips", [])
        )
    )


def _mutate_tool_skip_to_platform(
    census: dict,
    _lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    for entry in census.get("skips", []):
        if isinstance(entry, dict) and entry.get("line") == 51:
            entry["class"] = "platform"
            return "regex-51-tool->platform", 1
    return "regex-51-skip-missing", 0


def _fixture_validator_env_call_seed() -> Observation:
    return _isolated_validator_seed(
        "C5.6-env-call-variant",
        "function callsite path override classification",
        _has_regex_env_call,
        _mutate_env_call_classification,
    )


def _fixture_validator_iyivar_seed() -> Observation:
    return _isolated_validator_seed(
        "C5.4-skip-regex",
        "skip wildcard cannot be literal IYIVAR",
        _has_wildcard_skip,
        _mutate_skip_to_iyivar,
    )


def _fixture_validator_platform_guard_seed() -> Observation:
    return _isolated_validator_seed(
        "C5.4-platform-guard",
        "tool guard cannot be classified as platform",
        _has_tool_guard_skip,
        _mutate_tool_skip_to_platform,
    )


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
        self.platform_tmp = os.path.join(self.root, "platform-tmp")
        self.scratch = os.path.join(self.root, "s")
        self.cache = os.path.join(self.root, "cache")
        self.fake_dir = os.path.join(self.root, "fake")
        for path in (
            self.repo,
            self.work_tmp,
            self.platform_tmp,
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
        with open(
            os.path.join(self.bench, "std_demo_exercise.sh"),
            "w",
            encoding="utf-8",
        ) as target:
            target.write(
                '"$IYI" build "$REPO/bench/std_demo_exercise.iyi"\n'
            )
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
            "script": "bench/std_demo_exercise.sh",
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
            "platform_tmp": os.path.realpath(self.platform_tmp),
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
        platform_for_match = (
            None if case == "t-null" else fixture.platform_tmp
        )
        if case == "platform-root":
            first_root = os.path.join(
                fixture.platform_tmp,
                "driver-work",
                "noquestion",
            )
        elif case == "platform-two-level":
            first_root = os.path.join(
                fixture.platform_tmp,
                "outer",
                "driver-work",
                "noquestion",
            )
        elif case == "t-two-level":
            first_root = os.path.join(
                fixture.work_tmp,
                "outer",
                "driver-work",
                "noquestion",
            )
        elif case == "unknown-dir":
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
            platform_tmp=platform_for_match,
        )
        status, ids, kind, bindings = result
        got = {
            "status": status,
            "ids": ids,
            "kind": kind,
            "bindings": bindings,
        }
        if case in (
            "unknown-dir",
            "outside-attempt",
            "copied-exercise",
            "platform-two-level",
            "t-two-level",
        ):
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
            platform_tmp=fixture.platform_tmp,
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
                        r"iyi-run-std_demo_exercise-[0-9]+\.tmp",
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
        platform_tmp=fixture.config["platform_tmp"],
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
        with tempfile.TemporaryFile() as captured_stderr:
            original_stderr = os.dup(2)
            try:
                os.dup2(captured_stderr.fileno(), 2)
                failed = fixture.run_in_process(
                    [
                        "build",
                        "-o",
                        os.path.join(fixture.root, "consumer-fail"),
                        fixture.other_source,
                    ],
                    environment=fixture.environment(
                        FAKE_REAL_FAIL="consumer"
                    ),
                )
            finally:
                os.dup2(original_stderr, 2)
                os.close(original_stderr)
            captured_stderr.seek(0)
            failure_stderr = captured_stderr.read().decode(
                "utf-8",
                errors="replace",
            )
        statuses = _o4_verify(fixture, census)
        got = {
            "control_rc": control,
            "failure_rc": failed,
            "statuses": sorted(statuses),
            "stderr_captured": failure_stderr == "fake consumer failure\n",
        }
        return Observation(
            expected={
                "control_rc": 0,
                "failure_rc": 72,
                "statuses": ["DIVERGENCE"],
                "stderr_captured": True,
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
        platform_type = json.loads(json.dumps(control))
        platform_type["platform_tmp"] = 1
        config_case(
            "platform-type",
            platform_type,
            "config platform_tmp is not a string or null",
        )
        platform_nonreal = json.loads(json.dumps(control))
        platform_nonreal["platform_tmp"] = os.path.join(
            fixture.platform_tmp,
            ".",
        )
        config_case(
            "platform-nonreal",
            platform_nonreal,
            "config platform_tmp is not a realpath",
        )
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
        "platform-type",
        "platform-nonreal",
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
                platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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
                platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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
            platform_tmp=fixture.platform_tmp,
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


def _o4_main_usage_seed() -> Observation:
    completed = subprocess.run(
        [sys.executable, "-B", shim_mod.__file__],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return Observation(
        expected={
            "returncode": 125,
            "stdout": "",
            "usage": True,
        },
        got={
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "usage": (
                "usage: roundtrip_shim.py --config PATH -- ARGS..."
                in completed.stderr
            ),
        },
        applied="subprocess omitted --config and compiler argv",
    )


O4_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "o4.seed.main-usage-refusal",
        "seed",
        _o4_main_usage_seed,
    ),
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
    "o4.main-usage-refusal": (
        "o4.seed.main-usage-refusal",
        "s3.control.canonical-build",
    ),
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
        "script": "bench/std_demo_exercise.sh",
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
    effective_variables = json.loads(json.dumps(variables))
    if (
        kind == "positive"
        and evidence_name is not None
        and "name" not in effective_variables
    ):
        effective_variables["name"] = {"values": [evidence_name]}
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
                "vars": effective_variables,
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

def _o5_add_auxiliary_evidence(census: dict) -> None:
    census["sites"].extend(
        [
            {
                "lines": [30],
                "command": "build",
                "kind": "canonical-other",
                "variants": [],
            },
            {
                "lines": [35],
                "command": "build",
                "kind": "mixed",
                "variants": [
                    {
                        "id": "demo.negative.auxiliary",
                        "kind": "negative",
                        "first_root": "{WORK}/patched",
                        "vars": {},
                        "sources": ["{WORK}/auxiliary.iyi"],
                        "output": "{WORK}/auxiliary",
                        "darwin": "platform-excluded",
                        "requires": ["python3"],
                        "verdict": {
                            "lines": [35],
                            "contains": ["status=1"],
                        },
                    }
                ],
            },
        ]
    )
    census["exec_evidence"].extend(
        [
            {
                "site_line": 30,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {"31": "canonical-helper"},
            },
            {
                "site_line": 35,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {"36": "mixed-helper"},
            },
        ]
    )


def _o5_add_mixed_own_evidence(census: dict) -> None:
    census["sites"].append(
        {
            "lines": [40],
            "command": "build",
            "kind": "mixed",
            "variants": [
                {
                    "id": "demo.negative.mixed-own",
                    "kind": "negative",
                    "first_root": "{WORK}/patched",
                    "vars": {},
                    "sources": [
                        "{REPO}/bench/std_demo_exercise.iyi"
                    ],
                    "output": "{WORK}/mixed-own-negative",
                    "darwin": "platform-excluded",
                    "requires": ["python3"],
                    "verdict": {
                        "lines": [40],
                        "contains": ["status=1"],
                    },
                }
            ],
        }
    )
    census["exec_evidence"].append(
        {
            "site_line": 40,
            "out_template": "{WORK}/{name}",
            "name_from_calls": {"41": "mixed-own"},
        }
    )


def _o5_add_split_positive_evidence(census: dict) -> None:
    census["sites"].append(
        {
            "lines": [45],
            "command": "build",
            "kind": "positive",
            "variants": [
                {
                    "id": "demo.positive.required",
                    "kind": "positive",
                    "first_root": "{WORK}/{dir}",
                    "vars": {
                        "dir": {
                            "values": ["required-positive"],
                        }
                    },
                    "sources": ["{WORK}/{dir}.iyi"],
                    "output": "{WORK}/{dir}",
                    "darwin": "required",
                    "requires": ["python3"],
                    "verdict": {
                        "lines": [45],
                        "contains": ["status=1"],
                    },
                },
                {
                    "id": "demo.positive.platform-excluded",
                    "kind": "positive",
                    "first_root": "{WORK}/{dir}",
                    "vars": {
                        "dir": {
                            "values": ["excluded-positive"],
                        }
                    },
                    "sources": ["{WORK}/{dir}.iyi"],
                    "output": "{WORK}/{dir}",
                    "darwin": "platform-excluded",
                    "requires": ["python3"],
                    "verdict": {
                        "lines": [45],
                        "contains": ["status=1"],
                    },
                },
            ],
        }
    )
    census["exec_evidence"].append(
        {
            "site_line": 45,
            "out_template": "{WORK}/{name}",
            "name_from_calls": {
                "46": "required-positive",
                "47": "excluded-positive",
            },
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

def _o5_positive_build_pair(
    *,
    root: str,
    repo: str,
    work: str,
    name: str,
    variant_id: str,
    consumer_hashed: bool = True,
) -> list[dict]:
    out = os.path.join(work, name)
    out_ref = os.path.join(root, f"{name}.ref")
    shutil.copyfile("/usr/bin/true", out)
    os.chmod(out, 0o755)
    os.link(out, out_ref)
    linked = os.stat(out_ref)
    with open(out, "rb") as executable:
        digest = hashlib.sha256(executable.read()).hexdigest()
    atime_set = linked.st_mtime_ns - 1_000_000_000
    os.utime(
        out_ref,
        ns=(linked.st_mtime_ns + 1_000_000_000, linked.st_mtime_ns),
    )
    pair = _o5_pair(
        nonce="nonce-1",
        driver="demo",
        invocation=f"positive-{name}",
        repo=repo,
        out=out,
        own=False,
        canonical=False,
        variant_ids=(variant_id,),
        variant_kind="positive",
        bindings={variant_id: {"dir": name}},
        run_form=False,
    )
    end = pair[1]
    end["consumer"]["out_sha256"] = digest if consumer_hashed else None
    end["out_ref"] = out_ref
    end["out_ino"] = linked.st_ino
    end["out_mtime_ns"] = linked.st_mtime_ns
    end["atime_set_ns"] = atime_set
    return pair


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
    platform_tmp: str | None = None,
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
        platform_tmp=platform_tmp,
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
        driver_lines = [""] * 80
        driver_lines[9] = (
            '"$IYI" run "$REPO/bench/std_demo_exercise.iyi"'
        )
        driver_lines[14] = "status=1"
        driver_lines[29] = '"$IYI" build helper.iyi'
        driver_lines[34] = '"$IYI" build auxiliary.iyi'
        driver_lines[39] = (
            '"$IYI" build "$REPO/bench/std_demo_exercise.iyi"'
        )
        driver_lines[44] = '"$IYI" build positive.iyi'
        driver_lines[45] = "required-positive"
        driver_lines[46] = "excluded-positive"
        with open(
            os.path.join(repo, "bench", "std_demo_exercise.sh"),
            "w",
            encoding="utf-8",
        ) as output:
            output.write("\n".join(driver_lines) + "\n")
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
        elif case == "unchanged-noncanonical-http":
            refbreak = os.path.join(work, "refbreak")
            source = os.path.join(work, "captures.iyi")
            out = os.path.join(work, "refused")
            unchanged = _o5_exec_record(
                nonce="nonce-1",
                driver="demo",
                invocation="http-1384-unchanged",
                mode="unchanged",
                command="build",
                canonical=False,
            )
            unchanged["argv"] = [
                "build",
                "--no-codegen",
                "-o",
                out,
                source,
            ]
            unchanged["roots"] = [refbreak]
            unchanged["first_noncanonical_root"] = refbreak
            unchanged["sources"] = [source]
            unchanged["out"] = out
            records.append(unchanged)
            detail = (
                "http:1384 unchanged non-canonical --no-codegen build "
                "appended without variant ids"
            )
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
                    run_form=False,
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
        elif case == "auxiliary-evidence-control":
            _o5_add_auxiliary_evidence(census)
            detail = "auxiliary canonical-other and mixed evidence omitted"
        elif case == "source-unreadable":
            os.unlink(
                os.path.join(
                    repo,
                    "bench",
                    "std_demo_exercise.sh",
                )
            )
            expected = ("UNFAITHFUL",)
            detail = "validated driver source removed before verification"
        elif case == "source-script-mismatch":
            census["script"] = "bench/not-the-demo-driver.sh"
            expected = ("UNFAITHFUL",)
            detail = "census script association changed"
        elif case == "mixed-own-missing":
            _o5_add_mixed_own_evidence(census)
            expected = ("NOT-EXECUTED",)
            detail = "source-grounded mixed-own evidence name omitted"
        elif case in (
            "positive-missing",
            "positive-wrong-association",
            "positive-ambiguous-association",
            "excluded-positive-absent",
            "excluded-positive-present",
            "excluded-positive-unexecuted",
        ):
            _o5_add_split_positive_evidence(census)
            if case == "positive-ambiguous-association":
                site = census["sites"][-1]
                site["variants"].append(
                    {
                        "id": "demo.positive.ambiguous",
                        "kind": "positive",
                        "first_root": "{WORK}/{dir}",
                        "vars": {
                            "dir": {
                                "pattern": "required-.*",
                            }
                        },
                        "sources": ["{WORK}/{dir}.iyi"],
                        "output": "{WORK}/{dir}",
                        "darwin": "platform-excluded",
                        "requires": ["python3"],
                        "verdict": {
                            "lines": [45],
                            "contains": ["status=1"],
                        },
                    }
                )
            required_id = "demo.positive.required"
            excluded_id = "demo.positive.platform-excluded"
            if case != "positive-missing":
                if case == "positive-wrong-association":
                    records.extend(
                        _o5_positive_build_pair(
                            root=root,
                            repo=repo,
                            work=work,
                            name="required-positive",
                            variant_id=excluded_id,
                        )
                    )
                else:
                    records.extend(
                        _o5_positive_build_pair(
                            root=root,
                            repo=repo,
                            work=work,
                            name="required-positive",
                            variant_id=required_id,
                        )
                    )
            if case in (
                "excluded-positive-present",
                "excluded-positive-unexecuted",
            ):
                records.extend(
                    _o5_positive_build_pair(
                        root=root,
                        repo=repo,
                        work=work,
                        name="excluded-positive",
                        variant_id=excluded_id,
                        consumer_hashed=(
                            case != "excluded-positive-unexecuted"
                        ),
                    )
                )
            if case in (
                "positive-missing",
                "positive-wrong-association",
            ):
                expected = ("NOT-EXECUTED", "NOT-EXERCISED")
            elif case in (
                "positive-ambiguous-association",
                "excluded-positive-unexecuted",
            ):
                expected = ("NOT-EXECUTED",)
            detail = case.replace("-", " ")
        elif case in (
            "required-no-vars-missing",
            "required-no-vars-control",
        ):
            variant_id = "demo.negative.no-vars"
            _o5_add_variant(
                census,
                variant_id=variant_id,
                kind="negative",
                variables={},
            )
            if case == "required-no-vars-control":
                records.append(
                    _o5_exec_record(
                        nonce="nonce-1",
                        driver="demo",
                        invocation="negative-no-vars",
                        mode="observed-negative",
                        command="build",
                        canonical=False,
                        variant_ids=(variant_id,),
                        variant_kind="negative",
                    )
                )
                detail = "required no-vars variant has one bound record"
            else:
                expected = ("NOT-EXERCISED",)
                detail = "required no-vars variant has no bound record"
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
                    bindings={
                        "demo.positive.no-success": {
                            "name": "positive",
                        }
                    },
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
                    bindings={
                        "demo.positive.success": {
                            "name": "positive",
                        }
                    },
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
            "auxiliary-evidence-control",
            "excluded-positive-absent",
            "excluded-positive-present",
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
        driver_lines = [""] * 20
        driver_lines[9] = (
            '"$IYI" run "$REPO/bench/std_demo_exercise.iyi"'
        )
        driver_lines[14] = "status=1"
        with open(
            os.path.join(repo, "bench", "std_demo_exercise.sh"),
            "w",
            encoding="utf-8",
        ) as output:
            output.write("\n".join(driver_lines) + "\n")
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


def _deferred_amend_b_fixture(case: str) -> Observation:
    return _o7_amend_b_fixture(case)


def _source_role_discriminator_fixture(seeded: bool) -> Observation:
    shapes = {
        "compress": 370,
        "regex": 231,
        "file": 560,
    }
    got: dict[str, bool] = {}
    for driver, site_line in shapes.items():
        census, script_bytes, _relpath = _census_case(driver)
        lines = script_bytes.decode("utf-8").splitlines()
        site = next(
            site
            for site in census["sites"]
            if site.get("lines", [None])[0] == site_line
        )
        if seeded and driver == "regex":
            lines[site_line - 1] = (
                '"$IYI" build "$REPO/bench/std_regex_exercise.iyi"'
            )
        got[driver] = proofkit_mod._site_is_own_evidence(
            site,
            lines,
            driver,
        )
    return Observation(
        expected={
            "compress": False,
            "regex": seeded,
            "file": False,
        },
        got=got,
        applied=(
            "regex:231 source changed to exact own exercise"
            if seeded
            else ""
        ),
    )


def _file_split_matcher_fixture(
    site_line: int,
    seeded: bool,
) -> Observation:
    census, _script, _relpath = _census_case("file")
    cases = {
        169: (
            "run",
            ("predictable", "file.negative.169.required"),
            ("follows", "file.negative.169.platform-excluded"),
        ),
        230: (
            "run",
            ("star_sep", "file.negative.230.required"),
            (
                "dir_onto_file",
                "file.negative.230.platform-excluded",
            ),
        ),
        428: (
            "run",
            ("touch_unread", "file.negative.428.required"),
            (
                "append_seek",
                "file.negative.428.platform-excluded",
            ),
        ),
        628: (
            "build",
            ("nul_cut", "file.positive.628.required"),
            (
                "realpath_through",
                "file.positive.628.platform-excluded",
            ),
        ),
    }
    command, required_case, excluded_case = cases[site_line]
    with tempfile.TemporaryDirectory(
        prefix=f"iyi-file-match-{site_line}-"
    ) as root:
        work_tmp = os.path.join(root, "t")
        work = os.path.join(work_tmp, "w0")
        os.makedirs(work)

        def classify(value: str):
            first_root = os.path.join(work, value)
            if site_line == 628:
                sources = [os.path.join(work, f"{value}-prog.iyi")]
                output = os.path.join(work, f"{value}-prog")
            else:
                sources = [
                    os.path.join(
                        REPO_ROOT,
                        "bench",
                        "std_file_exercise.iyi",
                    )
                ]
                output = None
            return shim_mod.match_variants(
                census,
                command,
                first_root,
                sources,
                output,
                work_tmp,
                REPO_ROOT,
                platform_tmp=None,
            )

        if seeded:
            status, ids, _kind, _bindings = classify("undeclared")
            expected = {"status": "unclassified", "ids": []}
            got = {"status": status, "ids": ids}
        else:
            got = {}
            expected = {}
            for label, (value, variant_id) in (
                ("required", required_case),
                ("excluded", excluded_case),
            ):
                status, ids, kind, _bindings = classify(value)
                got[label] = {
                    "status": status,
                    "ids": ids,
                    "kind": kind,
                }
                expected[label] = {
                    "status": "matched",
                    "ids": [variant_id],
                    "kind": (
                        "positive" if site_line == 628 else "negative"
                    ),
                }
    return Observation(
        expected=expected,
        got=got,
        applied=(
            f"site={site_line};value=undeclared"
            if seeded
            else ""
        ),
    )


def _file_touch_skip_fixture(seeded: bool) -> Observation:
    census, _script, _relpath = _census_case("file")
    entry = next(
        skip
        for skip in census["skips"]
        if skip.get("line") == 529
    )
    baseline = {
        (
            "file",
            str(entry["class"]),
            str(entry["what"]),
            str(entry["regex"]),
        )
    }
    log_text = (
        "  touch and exists? of a file its owner may not read: "
        "not measured, this user reads it all the same"
        if seeded
        else ""
    )
    status, reasons = stages_mod._classify_driver_skips(
        census,
        log_text,
        baseline,
    )
    return Observation(
        expected={
            "status": "ENV-BLOCKED" if seeded else "PASS",
            "tool_named": seeded,
        },
        got={
            "status": status,
            "tool_named": any(
                "tool skip file: tool" in reason
                for reason in reasons
            ),
        },
        applied="file:529 tool skip emitted" if seeded else "",
    )


O5_FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        "o5.seed.source-role-own-mutation",
        "seed",
        partial(_source_role_discriminator_fixture, True),
    ),
    Fixture(
        "o5.control.source-role-auxiliary",
        "control",
        partial(_source_role_discriminator_fixture, False),
    ),
    Fixture(
        "o5.seed.file-169-undeclared",
        "seed",
        partial(_file_split_matcher_fixture, 169, True),
    ),
    Fixture(
        "o5.control.file-169-split",
        "control",
        partial(_file_split_matcher_fixture, 169, False),
    ),
    Fixture(
        "o5.seed.file-230-undeclared",
        "seed",
        partial(_file_split_matcher_fixture, 230, True),
    ),
    Fixture(
        "o5.control.file-230-split",
        "control",
        partial(_file_split_matcher_fixture, 230, False),
    ),
    Fixture(
        "o5.seed.file-428-undeclared",
        "seed",
        partial(_file_split_matcher_fixture, 428, True),
    ),
    Fixture(
        "o5.control.file-428-split",
        "control",
        partial(_file_split_matcher_fixture, 428, False),
    ),
    Fixture(
        "o5.seed.file-628-undeclared",
        "seed",
        partial(_file_split_matcher_fixture, 628, True),
    ),
    Fixture(
        "o5.control.file-628-split",
        "control",
        partial(_file_split_matcher_fixture, 628, False),
    ),
    Fixture(
        "o5.seed.file-touch-unread-env-blocked",
        "seed",
        partial(_file_touch_skip_fixture, True),
    ),
    Fixture(
        "o5.control.file-touch-unread",
        "control",
        partial(_file_touch_skip_fixture, False),
    ),
    Fixture(
        "o5.control.auxiliary-evidence",
        "control",
        partial(_o5_ledger_fixture, "auxiliary-evidence-control"),
    ),
    Fixture(
        "o5.seed.source-unreadable",
        "seed",
        partial(_o5_ledger_fixture, "source-unreadable"),
    ),
    Fixture(
        "o5.seed.source-script-mismatch",
        "seed",
        partial(_o5_ledger_fixture, "source-script-mismatch"),
    ),
    Fixture(
        "o5.seed.mixed-own-missing",
        "seed",
        partial(_o5_ledger_fixture, "mixed-own-missing"),
    ),
    Fixture(
        "o5.seed.positive-missing",
        "seed",
        partial(_o5_ledger_fixture, "positive-missing"),
    ),
    Fixture(
        "o5.seed.positive-wrong-association",
        "seed",
        partial(_o5_ledger_fixture, "positive-wrong-association"),
    ),
    Fixture(
        "o5.seed.positive-ambiguous-association",
        "seed",
        partial(_o5_ledger_fixture, "positive-ambiguous-association"),
    ),
    Fixture(
        "o5.control.excluded-positive-absent",
        "control",
        partial(_o5_ledger_fixture, "excluded-positive-absent"),
    ),
    Fixture(
        "o5.control.excluded-positive-present",
        "control",
        partial(_o5_ledger_fixture, "excluded-positive-present"),
    ),
    Fixture(
        "o5.seed.excluded-positive-unexecuted",
        "seed",
        partial(_o5_ledger_fixture, "excluded-positive-unexecuted"),
    ),
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
        "o5.seed.unchanged-noncanonical-http",
        "seed",
        partial(_o5_ledger_fixture, "unchanged-noncanonical-http"),
    ),
    Fixture(
        "o5.seed.required-no-vars-missing",
        "seed",
        partial(_o5_ledger_fixture, "required-no-vars-missing"),
    ),
    Fixture(
        "o5.control.required-no-vars",
        "control",
        partial(_o5_ledger_fixture, "required-no-vars-control"),
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
        partial(_deferred_amend_b_fixture, "not-executed"),
    ),
    Fixture(
        "amend-b.seed.copy-modified",
        "seed",
        partial(_deferred_amend_b_fixture, "copy-modified"),
    ),
    Fixture(
        "amend-b.seed.move-replaced",
        "seed",
        partial(_deferred_amend_b_fixture, "move-replaced"),
    ),
    Fixture(
        "amend-b.seed.run-form-not-counted",
        "seed",
        partial(_deferred_amend_b_fixture, "run-form-not-counted"),
    ),
    Fixture(
        "amend-b.control.stub-run",
        "control",
        partial(_deferred_amend_b_fixture, "control"),
    ),
    Fixture(
        "amend-b.control.run-form",
        "control",
        partial(_deferred_amend_b_fixture, "run-form"),
    ),
)
O5_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o5.file-platform-splits": (
        "o5.seed.file-169-undeclared",
        "o5.control.file-169-split",
        "o5.seed.file-230-undeclared",
        "o5.control.file-230-split",
        "o5.seed.file-428-undeclared",
        "o5.control.file-428-split",
        "o5.seed.file-628-undeclared",
        "o5.control.file-628-split",
    ),
    "o5.file-touch-unread-skip": (
        "o5.seed.file-touch-unread-env-blocked",
        "o5.control.file-touch-unread",
    ),
    "o5.source-evidence-scope": (
        "o5.seed.source-role-own-mutation",
        "o5.control.source-role-auxiliary",
        "o5.seed.source-unreadable",
        "o5.seed.source-script-mismatch",
        "o5.seed.mixed-own-missing",
        "o5.seed.positive-missing",
        "o5.seed.positive-wrong-association",
        "o5.seed.positive-ambiguous-association",
        "o5.seed.e2-name-repeated",
        "o5.seed.e2-unmatched-own",
        "o5.control.auxiliary-evidence",
        "o5.control.positive-success",
    ),
    "o5.excluded-positive-evidence": (
        "o5.seed.excluded-positive-unexecuted",
        "o5.control.excluded-positive-absent",
        "o5.control.excluded-positive-present",
    ),
    "o5.amendment-f-unchanged": (
        "o5.seed.unchanged-noncanonical-http",
        "o5.seed.noncanonical-without-ids",
        "s3.control.ledger",
    ),
    "o5.required-variant-record": (
        "o5.seed.required-no-vars-missing",
        "o5.control.required-no-vars",
    ),
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
    disk_min_gb: float = 0.0,
) -> dict:
    return legs_mod.run_row(
        case.sources[source_name],
        repo=case.repo,
        compiler=case.compiler,
        work_root=case.work,
        nm_bin=nm_bin or case.nm,
        disk_min_gb=disk_min_gb,
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
            returncode = legs_mod.main(argv, disk_min_gb=0.0)
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
        disk_min_gb=0.0,
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
            in_process_returncode = legs_mod.main(
                argv,
                disk_min_gb=0.0,
            )
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
            disk_min_gb=0.0,
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
    with tempfile.TemporaryDirectory(prefix="iyi-o6-runtimeerror-") as root:
        case = _o6_make_case(root)
        row = _o6_run_row(case, disk_min_gb=float(2**60))
        got = {
            "status": row["status"],
            "codes": _o6_codes(row),
            "reason_is_disk": any(
                "Disk space below threshold" in reason
                for reason in row["failures"]
            ),
        }
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
            returncode = legs_mod.main(argv, disk_min_gb=0.0)
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
                            "stderr": (
                                "cannot name it: seeded artifact\n"
                                + ("x" * 400)
                                + "\n"
                            ),
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
        applied="C3_exit=17;cannot_name_precedes_400_trailing_bytes",
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
            disk_min_gb=0.0,
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


def _stage_real_compiler(directory: str, *, version_line: str) -> str:
    fake = _fake_real_compiler(
        os.path.join(directory, "fake"),
        version_line=version_line,
    )
    path = os.path.join(directory, "iyi")
    source = f"""#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys

REAL = {fake!r}
args = sys.argv[1:]
completed = subprocess.run([REAL, *args], check=False)
if completed.returncode == 0 and args and (
    args[0] == "run" or (args[0] and "build".startswith(args[0]))
):
    output = None
    for index, token in enumerate(args):
        if token in ("-o", "--output") and index + 1 < len(args):
            output = args[index + 1]
        elif token.startswith("--output="):
            output = token.split("=", 1)[1]
        elif token.startswith("-o") and token != "-o":
            output = token[2:]
    if output:
        if not os.path.isabs(output):
            output = os.path.join(os.getcwd(), output)
        shutil.copyfile("/usr/bin/true", output)
        os.chmod(output, 0o755)
raise SystemExit(completed.returncode)
"""
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as output:
        output.write(source)
    os.chmod(path, 0o755)
    return os.path.realpath(path)


def _stage_driver_census(
    driver: str,
    scenario: str,
) -> tuple[bytes, dict]:
    source = f"$REPO/bench/std_{driver}_exercise.iyi"
    name = f"{driver}-plain"
    lines = [
        "#!/bin/bash",
        'REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
    ]
    if scenario == "driver-timeout":
        lines.append("sleep 30")
    elif scenario == "driver-interrupt":
        lines.extend(
            [
                "printf '%s\\n' ready >\"$TMPDIR/interrupt-ready\"",
                "sleep 30",
            ]
        )
    lines.extend(
        [
            "status=0",
            'WORK="$(mktemp -d)"',
            f"name={name}",
        ]
    )
    if scenario in ("copy-modified", "move-replaced"):
        lines.extend(
            [
                'other="$WORK/other"',
                'cp /bin/echo "$other"',
                'chmod +x "$other"',
            ]
        )

    build_line = (
        f'if ! "$IYI" build -o "$WORK/$name" "{source}"; then'
    )
    if scenario == "run3-import":
        lines.extend(
            [
                "if false; then",
                build_line,
                "  status=1",
                'elif ! "$WORK/$name"; then',
                "  status=1",
                "fi",
                "fi",
            ]
        )
    elif scenario == "not-executed":
        lines.extend(
            [
                build_line,
                "  status=1",
                "fi",
                "if false; then",
                '  if ! "$WORK/$name"; then',
                "    status=1",
                "  fi",
                "fi",
            ]
        )
    elif scenario in ("copy-modified", "move-replaced"):
        operation = (
            'cat "$other" >"$WORK/${name}"'
            if scenario == "copy-modified"
            else 'mv "$other" "$WORK/${name}"'
        )
        lines.extend(
            [
                build_line,
                "  status=1",
                "else",
                f"  {operation}",
                '  if ! "$WORK/$name"; then',
                "    status=1",
                "  fi",
                "fi",
            ]
        )
        lines.append("status=0")
    else:
        lines.extend(
            [
                build_line,
                "  status=1",
                'elif ! "$WORK/$name"; then',
                "  status=1",
                "fi",
            ]
        )

    run_line: str | None = None
    if scenario in ("run-form", "run-form-not-counted"):
        run_line = f'if ! "$IYI" run "{source}"; then'
        lines.extend([run_line, "  status=1", "fi"])

    if scenario in ("stale-ledger", "run-form-not-counted"):
        lines.extend(
            [
                'ledger="$(dirname -- "$TMPDIR")/ledger.jsonl"',
                'python3 - "$ledger" <<\'PY\'',
                "import json",
                "import sys",
                "path = sys.argv[1]",
                'with open(path, "r", encoding="utf-8") as source_file:',
                "    rows = [json.loads(line) for line in source_file]",
            ]
        )
        if scenario == "stale-ledger":
            lines.append('rows[0]["nonce"] = "0" * 32')
        else:
            lines.extend(
                [
                    "target = next(",
                    "    row for row in reversed(rows)",
                    '    if row.get("phase") == "end"',
                    '    and row.get("command") == "run"',
                    ")",
                    'target["run"]["argv"][0] = "tampered"',
                ]
            )
        lines.extend(
            [
                'with open(path, "w", encoding="utf-8") as output_file:',
                "    for row in rows:",
                '        output_file.write(json.dumps(row) + "\\n")',
                "PY",
            ]
        )

    skip_entry: dict[str, object] | None = None
    if scenario == "skip-env-blocked":
        skip_text = 'echo "fixture tool skipped"'
        lines.append(skip_text)
        skip_entry = {
            "class": "tool",
            "what": "fixture tool",
            "regex": "^fixture tool skipped$",
            "text": skip_text,
        }
    elif scenario in ("skip-partial", "skip-platform"):
        skip_text = 'echo "fixture platform skipped"'
        lines.extend(
            [
                'if [ -n "$(uname -s)" ]; then',
                skip_text,
                "fi",
            ]
        )
        skip_entry = {
            "class": "platform",
            "what": "fixture platform",
            "regex": "^fixture platform skipped$",
            "text": skip_text,
        }
    if scenario == "driver-refused-log":
        lines.append(
            'echo "observed-roundtrip-shim: REFUSED fixture refusal"'
        )
    if scenario == "post-driver-identity":
        lines.append(
            "python3 -c 'import json,os,sys; "
            "os.utime(json.load(open(sys.argv[1]))[\"real\"])' "
            "\"$(dirname -- \"$TMPDIR\")/shim.json\""
        )

    if scenario == "driver-nonzero":
        lines.append("status=7")
    sentinel_text = 'echo "the std/stage exercise holds"'
    if scenario == "missing-sentinel":
        sentinel_text = 'true || echo "the std/stage exercise holds"'
    lines.extend([sentinel_text, "exit $status"])

    def line_number(text: str) -> int:
        return lines.index(text) + 1

    build_number = line_number(build_line)
    exec_candidates = [
        index + 1
        for index, line in enumerate(lines)
        if index + 1 > build_number
        and '"$WORK/$name"' in line
        and line != build_line
    ]
    status_lines = [
        index + 1
        for index, line in enumerate(lines)
        if index + 1 > build_number and "status=1" in line
    ]
    sites = [
        {
            "lines": [build_number],
            "command": "build",
            "kind": "canonical-own",
            "contains": [build_line],
            "variants": [],
        }
    ]
    if run_line is not None:
        sites.append(
            {
                "lines": [line_number(run_line)],
                "command": "run",
                "kind": "canonical-own",
                "contains": [run_line],
                "variants": [],
            }
        )
    script = "\n".join(lines) + "\n"
    script_bytes = script.encode()
    census = {
        "census_version": 1,
        "driver": driver,
        "script": f"bench/std_{driver}_exercise.sh",
        "script_sha256": hashlib.sha256(script_bytes).hexdigest(),
        "sites": sites,
        "non_invocations": [],
        "skips": (
            [
                {
                    "line": line_number(skip_entry["text"]),
                    **skip_entry,
                }
            ]
            if skip_entry is not None
            else []
        ),
        "not_skips": [],
        "pass_sentinel": {
            "line": line_number(sentinel_text),
            "regex": "^the std/stage exercise holds$",
            "text": sentinel_text,
        },
        "exec_evidence": [
            {
                "site_line": build_number,
                "out_template": "{WORK}/{name}",
                "name_from_calls": {
                    str(line_number(f"name={name}")): name,
                },
                "exec_lines": [exec_candidates[0]],
                "exec_token": '"$WORK/$name"',
                "verdict_lines": status_lines,
                "failure_marks": ["status=1"],
                "refs_ok": [],
            }
        ],
    }
    return script_bytes, census


def _stage_stub_payloads(
    scenario: str,
    fixture_root: str = "",
) -> dict[str, bytes]:
    rg2r_count = 0 if scenario == "rg2r-zero" else 1
    exclusion = ""
    if scenario == "sample-exclusion":
        exclusion = (
            "printf '%s\\n' '  [excluded after calibration] "
            "samples/hello.iyi: fixture sample'\n"
        )
    elif scenario == "std-exclusion":
        exclusion = (
            "printf '%s\\n' '  [excluded after calibration] "
            "bench/std_missing_exercise.iyi: fixture std'\n"
        )
    elif scenario == "final-required-rerun":
        exclusion = (
            "if [ -f \"$PWD/../final-required-flip\" ]; then\n"
            "  printf '%s\\n' '  [excluded after calibration] "
            "bench/std_extra_exercise.iyi: calibration differed'\n"
            "fi\n"
        )
    gate_sleep = ""
    if scenario == "run1-slow-gate":
        gate_sleep = "sleep 0.2\n"
    elif scenario == "d4-stage-interrupt":
        gate_sleep = (
            "printf '%s\\n' ready >\"$TMPDIR/interrupt-ready\"\n"
            "sleep 30\n"
        )
    bash_path = os.path.join(fixture_root, "gate-tools", "bash")
    if scenario == "gate2-oserror":
        gate1_tail = f"/bin/rm -f {shlex.quote(bash_path)}\n"
    elif scenario == "gate1-identity":
        gate1_tail = "touch \"$IYI\"\n"
    else:
        gate1_tail = ""
    gate_exit = 7 if scenario == "gate1-fail" else 0
    stale_equivalence = (
        "#!/bin/bash\n"
        "set -u\n"
        f"{gate_sleep}"
        "echo 'RG2 PASSED: fixture'\n"
        "echo 'RG2a PASSED: fixture'\n"
        f"echo 'RG2r PASSED: all {rg2r_count} probes'\n"
        "echo 'RG5 trace half PASSED: fixture'\n"
        f"{exclusion}"
        f"{gate1_tail}"
        f"exit {gate_exit}\n"
    )
    observe_sentinel = (
        "fixture observe sentinel missing"
        if scenario == "run1-missing-sentinel"
        else "OK: bench/std_observe_exercise.sh passed all checks"
    )
    observe_prefix = (
        "printf '%s\\n' ready >\"$TMPDIR/interrupt-ready\"\n"
        "sleep 30\n"
        if scenario == "interrupt-gate2"
        else ""
    )
    if scenario == "gate3-oserror":
        observe_tail = "/bin/mkdir \"$(dirname -- \"$TMPDIR\")/rg9_work\"\n"
    elif scenario == "gate2-identity":
        observe_tail = "touch \"$IYI\"\n"
    else:
        observe_tail = ""
    std_observe = (
        "#!/bin/bash\n"
        f"{observe_prefix}"
        f"echo '{observe_sentinel}'\n"
        f"{observe_tail}"
        "exit 0\n"
    )
    rg9_count = 140 if scenario == "rg9-140" else 141
    rg9_prefix = (
        "import os, time\n"
        "open(os.path.join(os.environ['TMPDIR'], 'interrupt-ready'), 'w').write('ready')\n"
        "time.sleep(30)\n"
        if scenario == "interrupt-gate3"
        else ""
    )
    if scenario == "gate2-oserror":
        rg9_tail = (
            "import os\n"
            f"os.symlink('/bin/bash', {bash_path!r})\n"
        )
    elif scenario == "gate4-oserror":
        rg9_tail = f"import os\nos.unlink({bash_path!r})\n"
    elif scenario == "gate3-identity":
        rg9_tail = "import os\nos.utime(os.environ['IYI'])\n"
    else:
        rg9_tail = ""
    stale_rg9 = (
        "#!/usr/bin/env python3\n"
        f"{rg9_prefix}"
        f"print('RG9 PASSED: {rg9_count} corpus programs')\n"
        f"{rg9_tail}"
    )
    sibling_count = 114 if scenario == "sibling-count-114" else 115
    sibling_lines = ["-- running sibling: std_stage_exercise.sh"]
    sibling_lines.extend(
        f"-- running sibling: std_fixture_{number:03d}_exercise.sh"
        for number in range(1, sibling_count)
    )
    exercise_prefix = (
        "printf '%s\\n' ready >\"$TMPDIR/interrupt-ready\"\n"
        "sleep 30\n"
        if scenario == "interrupt-gate4"
        else ""
    )
    exercise_tail = (
        "touch \"$IYI\"\n"
        if scenario == "gate4-identity"
        else ""
    )
    std_exercise = (
        "#!/bin/bash\n"
        f"{exercise_prefix}"
        "echo 'Standard library foundation: traits, cmp, enumerable'\n"
        "echo 'all 114 exercises answer the same from source and from artifacts'\n"
        + "".join(f"echo '{line}'\n" for line in sibling_lines)
        + f"echo '== shard 1 of 1: {sibling_count} of {sibling_count} sibling exercises'\n"
        + exercise_tail
        + "exit 0\n"
    )
    stage_scenarios = {
        "run3-import",
        "driver-timeout",
        "driver-interrupt",
        "driver-nonzero",
        "missing-sentinel",
        "stale-ledger",
        "skip-env-blocked",
        "skip-partial",
        "skip-platform",
        "not-executed",
        "copy-modified",
        "move-replaced",
        "run-form",
        "run-form-not-counted",
        "driver-refused-log",
        "post-driver-identity",
    }
    stage_scenario = scenario if scenario in stage_scenarios else "control"
    stage_driver_bytes, stage_census = _stage_driver_census(
        "stage",
        stage_scenario,
    )
    extra_driver_payloads: dict[str, bytes] = {}
    if scenario == "driver-missing":
        missing_bytes, missing_census = _stage_driver_census(
            "missingdriver",
            "control",
        )
        extra_driver_payloads = {
            "bench/std_missingdriver_exercise.sh": missing_bytes,
            "bench/std_missingdriver_exercise.iyi": b'puts "missing fixture"\n',
            "proof/census/missingdriver.json": (
                json.dumps(missing_census, indent=2, sort_keys=True) + "\n"
            ).encode(),
        }
    run2_status = {
        "run2-stop": "STOP",
        "run2-fail": "FAIL",
    }.get(scenario, "PASS")
    run2_drop_sample = scenario == "run2-count"
    run2_write_report = scenario != "run2-missing-report"
    run2_returncode = (
        1
        if scenario in ("run2-stop", "run2-fail", "run2-missing-report")
        else 0
    )
    artifact_legs = (
        "#!/usr/bin/env python3\n"
        "import argparse\n"
        "import json\n"
        "import os\n"
        "import time\n"
        f"STATUS = {run2_status!r}\n"
        f"DROP_SAMPLE = {run2_drop_sample!r}\n"
        f"WRITE_REPORT = {run2_write_report!r}\n"
        f"RETURN_CODE = {run2_returncode}\n"
        f"INTERRUPT = {scenario == 'run2-interrupt'!r}\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--repo', required=True)\n"
        "parser.add_argument('--compiler', required=True)\n"
        "parser.add_argument('--work', required=True)\n"
        "parser.add_argument('--report', required=True)\n"
        "parser.add_argument('--workers', required=True)\n"
        "parser.add_argument('--nm', required=True)\n"
        "parser.add_argument('--expect-samples', type=int, required=True)\n"
        "parser.add_argument('--expect-std', type=int, required=True)\n"
        "parser.add_argument('--expect-total', type=int, required=True)\n"
        "args = parser.parse_args()\n"
        "if INTERRUPT:\n"
        "    open(os.path.join(os.environ['TMPDIR'], 'interrupt-ready'), 'w').write('ready')\n"
        "    time.sleep(30)\n"
        "rows = []\n"
        "sample_count = args.expect_samples - (1 if DROP_SAMPLE else 0)\n"
        "for index in range(sample_count):\n"
        "    rows.append({'kind':'sample','base':f'sample_{index}',"
        "'name':f'samples/iyi/sample_{index}.iyi','status':STATUS,"
        "'p_nonzero':False})\n"
        "for index in range(args.expect_std):\n"
        "    base = 'std_stage_exercise' if index == 0 else "
        "f'std_fixture_{index:03d}_exercise'\n"
        "    rows.append({'kind':'std','base':base,"
        "'name':f'bench/{base}.iyi','status':STATUS,"
        "'p_nonzero':False})\n"
        "if WRITE_REPORT:\n"
        "    with open(args.report, 'w', encoding='utf-8') as output:\n"
        "        for row in rows:\n"
        "            output.write(json.dumps(row) + '\\n')\n"
        "raise SystemExit(RETURN_CODE)\n"
    )
    return {
        "bench/stale_equivalence.sh": stale_equivalence.encode(),
        "bench/std_observe_exercise.sh": std_observe.encode(),
        "bench/stale_rg9.py": stale_rg9.encode(),
        "bench/std_exercise.sh": std_exercise.encode(),
        "bench/std_stage_exercise.sh": stage_driver_bytes,
        "bench/std_stage_exercise.iyi": b'puts "stage fixture"\n',
        "proof/census/stage.json": (
            json.dumps(stage_census, indent=2, sort_keys=True) + "\n"
        ).encode(),
        "proof/artifact_legs.py": artifact_legs.encode(),
        **extra_driver_payloads,
    }


def _o7_load_json(path: str):
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)

def _capture_stderr(call: Callable[[], object]) -> tuple[object, str]:
    python_stderr = io.StringIO()
    with tempfile.TemporaryFile(
        mode="w+",
        encoding="utf-8",
    ) as native_stderr:
        saved_stderr = os.dup(2)
        try:
            os.dup2(native_stderr.fileno(), 2)
            with contextlib.redirect_stderr(python_stderr):
                result = call()
        finally:
            os.dup2(saved_stderr, 2)
            os.close(saved_stderr)
        native_stderr.seek(0)
        captured = python_stderr.getvalue() + native_stderr.read()
    return result, captured


class StageFixture(PinFixture):
    def __init__(self, scenario: str = "control") -> None:
        self.scenario = scenario
        self.drivers = (
            ("missingdriver", "stage")
            if scenario == "driver-missing"
            else ("stage",)
        )
        self.stub_difference_count = 0
        self.missing_driver_target = ""
        super().__init__()
    def __enter__(self) -> StageFixture:
        return self


    def _setup(self) -> None:
        super()._setup()
        shutil.rmtree(self.w)

        proof_target = os.path.join(self.p, "proof")
        os.makedirs(proof_target, exist_ok=True)
        for census_path in glob.glob(
            os.path.join(proof_target, "census", "*.json")
        ):
            os.unlink(census_path)

        for source in sorted(glob.glob(os.path.join(REPO_ROOT, "proof", "*.py"))):
            if os.path.basename(source) == "artifact_legs.py":
                continue
            shutil.copyfile(
                source,
                os.path.join(proof_target, os.path.basename(source)),
            )

        control_payloads = _stage_stub_payloads(
            "control",
            self.scratch,
        )
        payloads = _stage_stub_payloads(
            self.scenario,
            self.scratch,
        )
        shared_paths = set(control_payloads).intersection(payloads)
        self.stub_difference_count = sum(
            payloads[path] != control_payloads[path] for path in shared_paths
        ) + len(set(payloads) - set(control_payloads))
        for relative, content in payloads.items():
            target = os.path.join(self.p, relative)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as output:
                output.write(content)
            if relative.endswith((".sh", ".py")):
                os.chmod(target, 0o755)
        if self.scenario == "driver-missing":
            linked_script = os.path.join(
                self.p,
                "bench",
                "std_missingdriver_exercise.sh",
            )
            self.missing_driver_target = os.path.join(
                self.scratch,
                "missingdriver-target.sh",
            )
            shutil.copyfile(linked_script, self.missing_driver_target)
            os.chmod(self.missing_driver_target, 0o755)
            os.unlink(linked_script)
            os.symlink(self.missing_driver_target, linked_script)


        _git(self.p, "add", ".")
        _git(self.p, "commit", "-m", f"stage fixture {self.scenario}")
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
        marker = os.path.join(self.w, "proof", "stage-fixture.txt")
        with open(marker, "w", encoding="utf-8") as output:
            output.write("stage fixture proof delta\n")
        _git(self.w, "add", "proof/stage-fixture.txt")
        _git(self.w, "commit", "-m", "stage fixture proof delta")
        self.compiler = _stage_real_compiler(
            os.path.join(self.scratch, "stage-real"),
            version_line=f"iyi fixture [{self.p_sha[:9]}]",
        )
        compiler_time_ns = (self.p_commit_time + 2) * 1_000_000_000
        os.utime(
            self.compiler,
            ns=(compiler_time_ns, compiler_time_ns),
        )

    def pin(self) -> dict:
        return proofkit_mod.write_pin(
            self.report,
            self.p,
            self.w,
            self.compiler,
            self.drivers,
        )

    def args(self, *, driver: str = "") -> SimpleNamespace:
        return SimpleNamespace(report_dir=self.report, driver=driver)

    def write_run2_prerequisite(self, *, p_nonzero: bool = False) -> str:
        attempt = os.path.join(self.report, "run2", "a1")
        os.makedirs(attempt, exist_ok=True)
        report = os.path.join(attempt, "run2.jsonl")
        row = {
            "kind": "std",
            "base": (
                "std_extra_exercise"
                if p_nonzero
                else "std_stage_exercise"
            ),
            "name": (
                "bench/std_extra_exercise.iyi"
                if p_nonzero
                else "bench/std_stage_exercise.iyi"
            ),
            "status": "PASS",
            "p_nonzero": p_nonzero,
        }
        with open(report, "w", encoding="utf-8") as output:
            output.write(json.dumps(row) + "\n")
        return report

    def write_prerequisites(
        self,
        *,
        exclusions: list[dict[str, str]] | None = None,
        baseline: list[dict[str, str]] | None = None,
        p_nonzero: bool = False,
    ) -> tuple[str, str, str]:
        run1 = os.path.join(self.report, "run1", "a1")
        os.makedirs(run1, exist_ok=True)
        exclusions_path = os.path.join(run1, "exclusions.json")
        baseline_path = os.path.join(run1, "baseline_skips.json")
        with open(exclusions_path, "w", encoding="utf-8") as output:
            json.dump(exclusions or [], output)
        with open(baseline_path, "w", encoding="utf-8") as output:
            json.dump(baseline or [], output)
        run2_path = self.write_run2_prerequisite(p_nonzero=p_nonzero)
        return exclusions_path, baseline_path, run2_path

    def write_input_result(
        self,
        unit: str,
        attempt: int,
        *,
        checks: dict[str, str],
        status: str,
        chain_id: str | None = None,
        started_ns: int = 1,
        ended_ns: int = 2,
    ) -> str:
        parent = os.path.join(self.report, *unit.split("/"))
        attempt_dir = os.path.join(parent, f"a{attempt}")
        os.makedirs(attempt_dir, exist_ok=True)
        path = os.path.join(attempt_dir, "result.json")
        record = {
            "v": 1,
            "chain_id": chain_id or self.pin_data["chain_id"],
            "unit": unit,
            "attempt": attempt,
            "status": status,
            "reasons": [] if status == "PASS" else ["fixture failure"],
            "checks": checks,
            "started_ns": started_ns,
            "ended_ns": ended_ns,
            "survivors": [],
        }
        with open(path, "w", encoding="utf-8") as output:
            json.dump(record, output, sort_keys=True)
            output.write("\n")
        return path

    def prepare_final_inputs(self, *, two_run1_attempts: bool = False) -> None:
        self.pin_data = self.pin()
        run1_checks = {
            name: "PASS" for name in proofkit_mod.REQUIRED_CHECKS["run1"]
        }
        run2_checks = {
            name: "PASS" for name in proofkit_mod.REQUIRED_CHECKS["run2"]
        }
        run3_checks = {
            name: "PASS" for name in proofkit_mod.REQUIRED_CHECKS["run3"]
        }
        first_attempt = 9 if two_run1_attempts else 1
        self.write_input_result(
            "run1",
            first_attempt,
            checks=run1_checks,
            status="PASS",
            started_ns=1,
            ended_ns=2,
        )
        if two_run1_attempts:
            self.write_input_result(
                "run1",
                10,
                checks=run1_checks,
                status="PASS",
                started_ns=3,
                ended_ns=4,
            )
        self.write_input_result(
            "run2",
            1,
            checks=run2_checks,
            status="PASS",
            started_ns=5,
            ended_ns=6,
        )
        required_dir = os.path.join(self.report, "run3")
        os.makedirs(required_dir, exist_ok=True)
        with open(
            os.path.join(required_dir, "required.json"),
            "w",
            encoding="utf-8",
        ) as output:
            json.dump(["stage"], output)
        self.write_input_result(
            "run3/stage",
            1,
            checks=run3_checks,
            status="PASS",
            started_ns=7,
            ended_ns=8,
        )
        latest_run1 = 10 if two_run1_attempts else 1
        latest_run1_dir = os.path.join(
            self.report,
            "run1",
            f"a{latest_run1}",
        )
        with open(
            os.path.join(latest_run1_dir, "exclusions.json"),
            "w",
            encoding="utf-8",
        ) as output:
            json.dump([], output)
        with open(
            os.path.join(latest_run1_dir, "baseline_skips.json"),
            "w",
            encoding="utf-8",
        ) as output:
            json.dump([], output)
        with open(
            os.path.join(self.report, "run2", "a1", "run2.jsonl"),
            "w",
            encoding="utf-8",
        ):
            pass


def _stage_result(report: str, unit: str) -> dict:
    attempt = stages_mod.latest_attempt_dir(
        os.path.join(report, *unit.split("/"))
    )
    if attempt is None:
        return {}
    result = proofkit_mod.load_result(os.path.join(attempt, "result.json"))
    return result or {}


def _scenario_applied(fixture: StageFixture) -> str:
    if fixture.stub_difference_count != 1:
        raise RuntimeError(
            f"scenario {fixture.scenario!r} changed "
            f"{fixture.stub_difference_count} stub files, expected exactly one"
        )
    return (
        f"scenario={fixture.scenario};stub_files_changed=1;"
        "bytes_differ=true"
    )


def _run1_seed(
    scenario: str,
    check_name: str,
    expected_check: str,
    expected_status: str = "FAIL",
) -> Observation:
    with StageFixture(scenario) as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(fixture.args(), disk_min_gb=0.0)
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "check": result.get("checks", {}).get(check_name),
        }
        expected = {
            "returncode": 0 if expected_status == "PASS" else 1,
            "status": expected_status,
            "check": expected_check,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=_scenario_applied(fixture),
        )


def _fixture_stage_chain_control() -> Observation:
    with StageFixture() as fixture:
        fixture.pin_data = fixture.pin()
        run1_return = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        run2_return = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=0.0,
        )
        run3_return = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=5.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        stage = _stage_result(fixture.report, "run3/stage")
        final_return = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        got = {
            "run1": run1_return,
            "run2": run2_return,
            "run3": run3_return,
            "run3_status": stage.get("status"),
            "run3_ledger": stage.get("checks", {}).get("ledger"),
            "final": final_return,
            "status": final.get("status"),
            "earlier_failures": final.get("earlier_failures"),
        }
        expected = {
            "run1": 0,
            "run2": 0,
            "run3": 0,
            "run3_status": "PASS",
            "run3_ledger": "PASS",
            "final": 0,
            "status": "PASS",
            "earlier_failures": [],
        }
        if got != expected:
            got["diagnostic"] = _o7_ledger_diagnostic(
                fixture,
                "stage",
            )
        return Observation(expected=expected, got=got)


def _fixture_run1_control() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(fixture.args(), disk_min_gb=0.0)
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "attempt_files": all(
                os.path.isfile(
                    os.path.join(
                        fixture.report,
                        "run1",
                        "a1",
                        filename,
                    )
                )
                for filename in (
                    "exclusions.json",
                    "baseline_skips.json",
                    "result.json",
                )
            ),
        }
        expected = {
            "returncode": 0,
            "status": "PASS",
            "attempt_files": True,
        }
        return Observation(expected=expected, got=got)


def _fixture_run1_slow_gate_seed() -> Observation:
    with StageFixture("run1-slow-gate") as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        result = _stage_result(fixture.report, "run1")
        attempt = stages_mod.latest_attempt_dir(
            os.path.join(fixture.report, "run1")
        )
        with open(
            os.path.join(attempt, "run1_1.times"),
            "r",
            encoding="utf-8",
        ) as source:
            samples = [line.strip() for line in source if line.strip()]
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "gate": result.get("checks", {}).get("gate-1.1"),
            "initial_zero": bool(samples)
            and samples[0].split()[-1] == "0",
            "sample_count_at_least_2": len(samples) >= 2,
        }
    return Observation(
        expected={
            "returncode": 0,
            "status": "PASS",
            "gate": "PASS",
            "initial_zero": True,
            "sample_count_at_least_2": True,
        },
        got=got,
        applied=_scenario_applied(fixture),
    )


def _fixture_gate1_fail_seed() -> Observation:
    return _run1_seed("gate1-fail", "gate-1.1", "FAIL")




def _fixture_run1_identity_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        with open(fixture.compiler, "a", encoding="utf-8") as output:
            output.write("\n# run1 identity mutation\n")
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "identity": result.get("checks", {}).get("identity"),
        }
        expected = {
            "returncode": 1,
            "status": "INVALID",
            "identity": "INVALID",
        }
        return Observation(
            expected=expected,
            got=got,
            applied="compiler bytes changed once after pin",
        )


def _fixture_run1_disk_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=2**60,
        )
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "identity": result.get("checks", {}).get("identity"),
        }
        expected = {
            "returncode": 1,
            "status": "STOP",
            "identity": "STOP",
        }
        return Observation(
            expected=expected,
            got=got,
            applied="disk_min_gb raised to 2**60",
        )


def _fixture_rg2r_zero_seed() -> Observation:
    return _run1_seed("rg2r-zero", "rg2r-count", "FAIL")


def _fixture_run1_missing_sentinel_seed() -> Observation:
    return _run1_seed(
        "run1-missing-sentinel",
        "gate-1.2",
        "FAIL",
    )


def _fixture_rg9_140_seed() -> Observation:
    return _run1_seed("rg9-140", "gate-1.3", "FAIL")


def _fixture_sibling_count_114_seed() -> Observation:
    return _run1_seed("sibling-count-114", "gate-1.4", "FAIL")


def _fixture_sample_exclusion_seed() -> Observation:
    with StageFixture("sample-exclusion") as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(fixture.args(), disk_min_gb=0.0)
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "check": result.get("checks", {}).get("exclusions"),
            "reason": any(
                str(reason).startswith(
                    "UNEXPLAINED-SAMPLE-EXCLUSION: samples/hello.iyi"
                )
                for reason in result.get("reasons", [])
            ),
        }
        expected = {
            "returncode": 1,
            "status": "FAIL",
            "check": "FAIL",
            "reason": True,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=_scenario_applied(fixture),
        )


def _fixture_exclusions_wrong_location_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        wrong_path = os.path.join(fixture.report, "run1", "exclusions.json")
        os.makedirs(os.path.dirname(wrong_path), exist_ok=True)
        sentinel = b"wrong-location-sentinel\n"
        with open(wrong_path, "wb") as output:
            output.write(sentinel)
        returncode = stages_mod.cmd_run1(fixture.args(), disk_min_gb=0.0)
        attempt = stages_mod.latest_attempt_dir(
            os.path.join(fixture.report, "run1")
        )
        with open(wrong_path, "rb") as source:
            unchanged = source.read() == sentinel
        got = {
            "returncode": returncode,
            "wrong_location_untouched": unchanged,
            "attempt_exclusions": bool(
                attempt
                and os.path.isfile(os.path.join(attempt, "exclusions.json"))
            ),
            "attempt_baseline": bool(
                attempt
                and os.path.isfile(
                    os.path.join(attempt, "baseline_skips.json")
                )
            ),
        }
        expected = {
            "returncode": 0,
            "wrong_location_untouched": True,
            "attempt_exclusions": True,
            "attempt_baseline": True,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"created={wrong_path};bytes={len(sentinel)};"
                f"exists={str(os.path.isfile(wrong_path)).lower()}"
            ),
        )


def _fixture_std_exclusion_seed() -> Observation:
    with StageFixture("std-exclusion") as fixture:
        fixture.pin()
        stages_mod.cmd_run1(fixture.args(), disk_min_gb=0.0)
        fixture.write_run2_prerequisite()
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        required = _o7_load_json(
            os.path.join(fixture.report, "run3", "required.json")
        )
        missing = _stage_result(fixture.report, "run3/missing")
        got = {
            "returncode": returncode,
            "required": required,
            "missing_status": missing.get("status"),
        }
        expected = {
            "returncode": 1,
            "required": ["stage", "missing"],
            "missing_status": "CENSUS-MISSING",
        }
        return Observation(
            expected=expected,
            got=got,
            applied=_scenario_applied(fixture),
        )


def _fixture_run2_identity_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        with open(fixture.compiler, "a", encoding="utf-8") as output:
            output.write("\n# run2 identity mutation\n")
        returncode = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=0.0,
        )
        result = _stage_result(fixture.report, "run2")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "identity": result.get("checks", {}).get("identity"),
        }
        expected = {
            "returncode": 1,
            "status": "INVALID",
            "identity": "INVALID",
        }
        return Observation(
            expected=expected,
            got=got,
            applied="compiler bytes changed once after pin",
        )


def _fixture_run2_disk_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=2**60,
        )
        result = _stage_result(fixture.report, "run2")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "identity": result.get("checks", {}).get("identity"),
        }
        expected = {
            "returncode": 1,
            "status": "STOP",
            "identity": "STOP",
        }
        return Observation(
            expected=expected,
            got=got,
            applied="disk_min_gb raised to 2**60",
        )


def _run2_scenario_seed(
    scenario: str,
    *,
    status: str,
    legs: str,
    counts: str,
) -> Observation:
    with StageFixture(scenario) as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=0.0,
        )
        result = _stage_result(fixture.report, "run2")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "legs": result.get("checks", {}).get("legs"),
            "counts": result.get("checks", {}).get("counts"),
        }
        expected = {
            "returncode": 1,
            "status": status,
            "legs": legs,
            "counts": counts,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=_scenario_applied(fixture),
        )


def _fixture_run2_stop_seed() -> Observation:
    return _run2_scenario_seed(
        "run2-stop",
        status="STOP",
        legs="STOP",
        counts="PASS",
    )


def _fixture_run2_fail_seed() -> Observation:
    return _run2_scenario_seed(
        "run2-fail",
        status="FAIL",
        legs="FAIL",
        counts="PASS",
    )


def _fixture_run2_count_seed() -> Observation:
    return _run2_scenario_seed(
        "run2-count",
        status="FAIL",
        legs="PASS",
        counts="FAIL",
    )


def _fixture_run2_missing_report_seed() -> Observation:
    return _run2_scenario_seed(
        "run2-missing-report",
        status="FAIL",
        legs="FAIL",
        counts="FAIL",
    )


def _fixture_p_nonzero_not_added_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        _exclusions, _baseline, run2_path = fixture.write_prerequisites(
            p_nonzero=True
        )
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        required = _o7_load_json(
            os.path.join(fixture.report, "run3", "required.json")
        )
        extra = _stage_result(fixture.report, "run3/extra")
        got = {
            "returncode": returncode,
            "required": required,
            "extra_status": extra.get("status"),
        }
        expected = {
            "returncode": 1,
            "required": ["stage", "extra"],
            "extra_status": "CENSUS-MISSING",
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"run2={run2_path};field=p_nonzero;"
                "control=false;seed=true;changed_rows=1"
            ),
        )


def _numbered_prerequisites(
    fixture: StageFixture,
    *,
    remove_latest_baseline: bool,
) -> tuple[str, str, str]:
    fixture.write_prerequisites()
    run1_root = os.path.join(fixture.report, "run1")
    run2_root = os.path.join(fixture.report, "run2")
    os.rename(
        os.path.join(run1_root, "a1"),
        os.path.join(run1_root, "a9"),
    )
    shutil.copytree(
        os.path.join(run1_root, "a9"),
        os.path.join(run1_root, "a10"),
    )
    os.rename(
        os.path.join(run2_root, "a1"),
        os.path.join(run2_root, "a10"),
    )
    latest_run1 = os.path.join(run1_root, "a10")
    exclusions = os.path.join(latest_run1, "exclusions.json")
    baseline = os.path.join(latest_run1, "baseline_skips.json")
    run2 = os.path.join(run2_root, "a10", "run2.jsonl")
    if remove_latest_baseline:
        os.unlink(baseline)
    return exclusions, baseline, run2


def _fixture_run3_prerequisite_control() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        expected_paths = _numbered_prerequisites(
            fixture,
            remove_latest_baseline=False,
        )
        got = stages_mod._run3_prerequisites(fixture.report)
        return Observation(expected=expected_paths, got=got)


def _fixture_run3_missing_prerequisite_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        _exclusions, baseline, _run2 = _numbered_prerequisites(
            fixture,
            remove_latest_baseline=True,
        )
        returncode, stderr = _capture_stderr(
            lambda: stages_mod.cmd_run3(
                fixture.args(),
                drivers=fixture.drivers,
                disk_min_gb=0.0,
            )
        )
        got = {
            "returncode": returncode,
            "required_exists": os.path.exists(
                os.path.join(fixture.report, "run3", "required.json")
            ),
            "stderr_captured": stderr.startswith(
                "REFUSED run3 requires latest run1"
            ),
        }
        expected = {
            "returncode": 2,
            "required_exists": False,
            "stderr_captured": True,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"latest_attempt=10;removed={baseline};"
                f"exists={str(os.path.exists(baseline)).lower()}"
            ),
        )


def _fixture_required_match_control() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        exclusions, _baseline, run2 = fixture.write_prerequisites()
        got = stages_mod._compute_required_drivers(
            fixture.drivers,
            exclusions,
            run2,
        )
        return Observation(expected=["stage"], got=got)


def _fixture_required_mismatch_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        required_path = os.path.join(
            fixture.report,
            "run3",
            "required.json",
        )
        os.makedirs(os.path.dirname(required_path), exist_ok=True)
        with open(required_path, "w", encoding="utf-8") as output:
            json.dump(["other"], output)
        returncode, stderr = _capture_stderr(
            lambda: stages_mod.cmd_run3(
                fixture.args(),
                drivers=fixture.drivers,
                disk_min_gb=0.0,
            )
        )
        invalid = _stage_result(fixture.report, "run3/other")
        with open(required_path, "r", encoding="utf-8") as source:
            frozen = json.load(source)
        got = {
            "returncode": returncode,
            "status": invalid.get("status"),
            "frozen": frozen,
            "stderr_captured": stderr.startswith(
                "Run 3 INVALID: required.json mismatch"
            ),
        }
        expected = {
            "returncode": 1,
            "status": "INVALID",
            "frozen": ["other"],
            "stderr_captured": True,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=f"created={required_path};value=['other']",
        )


def _fixture_binary_changed_seed() -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        before = _file_sha256(fixture.compiler)
        with open(fixture.compiler, "a", encoding="utf-8") as output:
            output.write("\n# changed after pin\n")
        after = _file_sha256(fixture.compiler)
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            disk_min_gb=0.0,
        )
        stage = _stage_result(fixture.report, "run3/stage")
        got = {
            "returncode": returncode,
            "status": stage.get("status"),
            "identity": stage.get("checks", {}).get("identity"),
        }
        expected = {
            "returncode": 1,
            "status": "INVALID",
            "identity": "INVALID",
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"before_sha={before};after_sha={after};"
                f"bytes_differ={str(before != after).lower()}"
            ),
        )


def _fixture_route_a_drivers_seed() -> Observation:
    original = os.environ.pop("ROUTE_A_DRIVERS", None)
    before = os.environ.get("ROUTE_A_DRIVERS")
    os.environ["ROUTE_A_DRIVERS"] = "cookie"
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            got = stages_mod.main(["plan"])
    finally:
        if original is None:
            os.environ.pop("ROUTE_A_DRIVERS", None)
        else:
            os.environ["ROUTE_A_DRIVERS"] = original
    return Observation(
        expected=2,
        got=got,
        applied=(
            f"ROUTE_A_DRIVERS={before!r}->'cookie';"
            f"changed={str(before != 'cookie').lower()};main_called=true"
        ),
    )


def _fixture_route_a_control() -> Observation:
    with StageFixture() as fixture:
        fixture.prepare_final_inputs()
        got = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        return Observation(expected=0, got=got)


def _final_seed(kind: str) -> Observation:
    with StageFixture() as fixture:
        fixture.prepare_final_inputs(
            two_run1_attempts=(kind == "earlier-failure")
        )
        applied = ""
        if kind == "forged-pass":
            path = os.path.join(
                fixture.report,
                "run1",
                "a1",
                "result.json",
            )
            record = _o7_load_json(path)
            before = json.dumps(record, sort_keys=True)
            record["checks"]["gate-1.2"] = "FAIL"
            with open(path, "w", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True)
            after = json.dumps(record, sort_keys=True)
            applied = (
                f"field=checks.gate-1.2;before=PASS;after=FAIL;"
                f"bytes_differ={str(before != after).lower()}"
            )
        elif kind == "missing-result":
            path = os.path.join(
                fixture.report,
                "run2",
                "a1",
                "result.json",
            )
            os.unlink(path)
            applied = f"removed={path};exists={str(os.path.exists(path)).lower()}"
        elif kind == "chain-mismatch":
            path = os.path.join(
                fixture.report,
                "run1",
                "a1",
                "result.json",
            )
            record = _o7_load_json(path)
            old_chain = record["chain_id"]
            record["chain_id"] = "0" * 32
            with open(path, "w", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True)
            applied = (
                f"chain={old_chain}->{'0' * 32};"
                f"changed={str(old_chain != record['chain_id']).lower()}"
            )
        elif kind == "earlier-failure":
            path = os.path.join(
                fixture.report,
                "run1",
                "a9",
                "result.json",
            )
            record = _o7_load_json(path)
            record["checks"]["gate-1.1"] = "FAIL"
            record["status"] = "FAIL"
            record["reasons"] = ["fixture earlier failure"]
            with open(path, "w", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True)
            applied = f"replaced_one_earlier_result={path};status=FAIL"
        else:
            raise ValueError(f"unknown final seed {kind}")

        returncode = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        if kind == "earlier-failure":
            got = {
                "returncode": returncode,
                "status": final.get("status"),
                "latest_attempt": final.get("units", {})
                .get("run1", {})
                .get("attempt"),
                "listed": {
                    "unit": "run1",
                    "attempt": 9,
                    "status": "FAIL",
                }
                in final.get("earlier_failures", []),
            }
            expected = {
                "returncode": 0,
                "status": "PASS",
                "latest_attempt": 10,
                "listed": True,
            }
        else:
            reason_fragment = {
                "forged-pass": "forged status",
                "missing-result": "missing or unreadable",
                "chain-mismatch": "chain_id mismatch",
            }[kind]
            got = {
                "returncode": returncode,
                "status": final.get("status"),
                "reason": any(
                    reason_fragment in str(reason)
                    for reason in final.get("reasons", [])
                ),
            }
            expected = {"returncode": 1, "status": "FAIL", "reason": True}
        return Observation(expected=expected, got=got, applied=applied)

def _fixture_final_required_rerun_seed() -> Observation:
    with StageFixture("final-required-rerun") as fixture:
        fixture.pin()
        run1 = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        run2 = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=0.0,
        )
        run3 = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        control_final = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        control_record = _o7_load_json(
            os.path.join(fixture.report, "final.json")
        )

        flip = os.path.join(
            fixture.scratch,
            "final-required-flip",
        )
        with open(flip, "w", encoding="utf-8") as output:
            output.write("enabled\n")
        rerun1 = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        seeded_final = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        seeded_record = _o7_load_json(
            os.path.join(fixture.report, "final.json")
        )
        got = {
            "run1": run1,
            "run2": run2,
            "run3": run3,
            "control_rc": control_final,
            "control_status": control_record.get("status"),
            "rerun1": rerun1,
            "seed_rc": seeded_final,
            "seed_status": seeded_record.get("status"),
            "required_mismatch": any(
                "required.json mismatch" in str(reason)
                for reason in seeded_record.get("reasons", [])
            ),
            "freshness": any(
                "not newer than latest run1/run2" in str(reason)
                for reason in seeded_record.get("reasons", [])
            ),
        }
    return Observation(
        expected={
            "run1": 0,
            "run2": 0,
            "run3": 0,
            "control_rc": 0,
            "control_status": "PASS",
            "rerun1": 0,
            "seed_rc": 1,
            "seed_status": "FAIL",
            "required_mismatch": True,
            "freshness": True,
        },
        got=got,
        applied=(
            f"created={flip};latest_run1=a2;"
            "required_before=['stage'];required_after=['stage','extra']"
        ),
    )


def _fixture_identity_field_guard(case: str, seeded: bool) -> Observation:
    reasons = {
        "m01": "PYTHON-CHANGED",
        "m02": "CENSUS-CHANGED",
        "m03": "CANONICAL-ROOTS-CHANGED",
        "m04": "TIMEOUT-CHANGED",
        "m05": "NM-CHANGED",
        "m19": "PYTHON-CHANGED",
    }
    with PinFixture() as fixture:
        pin = fixture.pin()
        checked = json.loads(json.dumps(pin))
        applied = "control pin unchanged"
        if seeded:
            if case == "m01":
                checked["python_path"] = fixture.compiler
                applied = "python_path replaced with fixture compiler"
            elif case == "m02":
                driver = sorted(checked["census_sha256"])[0]
                checked["census_sha256"][driver] = "0" * 64
                applied = f"census_sha256[{driver}] replaced"
            elif case == "m03":
                checked["canonical_roots"] = []
                applied = "canonical_roots cleared"
            elif case == "m04":
                checked["timeout_path"] = checked["nm_path"]
                applied = "timeout_path replaced with nm_path"
            elif case == "m05":
                checked["nm_path"] = checked["timeout_path"]
                applied = "nm_path replaced with timeout_path"
            elif case == "m19":
                checked["python_version"] = "fixture-python-version"
                applied = "python_version replaced"
            else:
                raise ValueError(f"unknown identity guard {case}")
        reason = _identity_reason(
            lambda: proofkit_mod.check_identity(checked)
        )
    return Observation(
        expected=reasons[case] if seeded else "NO-REFUSAL",
        got=reason,
        applied=applied if seeded else "",
    )


def _fixture_run3_disk_guard(seeded: bool) -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=(2**60 if seeded else 0.0),
        )
        record = _stage_result(fixture.report, "run3/stage")
        attempt = stages_mod.latest_attempt_dir(
            os.path.join(fixture.report, "run3", "stage")
        )
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "disk": record.get("checks", {}).get("disk"),
            "driver_ran": bool(
                attempt
                and os.path.exists(os.path.join(attempt, "driver.log"))
            ),
        }
    expected = (
        {
            "returncode": 1,
            "status": "STOP",
            "disk": "STOP",
            "driver_ran": False,
        }
        if seeded
        else {
            "returncode": 0,
            "status": "PASS",
            "disk": "PASS",
            "driver_ran": True,
        }
    )
    return Observation(
        expected=expected,
        got=got,
        applied="disk_min_gb=2**60" if seeded else "",
    )


def _fixture_post_driver_identity_guard(seeded: bool) -> Observation:
    scenario = "post-driver-identity" if seeded else "control"
    with StageFixture(scenario) as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        record = _stage_result(fixture.report, "run3/stage")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "identity": record.get("checks", {}).get("identity"),
            "reason": any(
                "COMPILER-MTIME-CHANGED" in str(reason)
                for reason in record.get("reasons", [])
            ),
        }
    expected = (
        {
            "returncode": 1,
            "status": "INVALID",
            "identity": "INVALID",
            "reason": True,
        }
        if seeded
        else {
            "returncode": 0,
            "status": "PASS",
            "identity": "PASS",
            "reason": False,
        }
    )
    return Observation(
        expected=expected,
        got=got,
        applied=(
            "driver touches compiler mtime after sentinel"
            if seeded
            else ""
        ),
    )


def _fixture_final_identity_guard(seeded: bool) -> Observation:
    with StageFixture() as fixture:
        fixture.prepare_final_inputs()
        original_path = os.environ.get("PATH", "")
        try:
            if seeded:
                os.environ["PATH"] = (
                    original_path + os.pathsep + fixture.scratch
                )
            returncode = stages_mod.cmd_final(
                fixture.args(),
                drivers=fixture.drivers,
            )
        finally:
            os.environ["PATH"] = original_path
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        got = {
            "returncode": returncode,
            "status": final.get("status"),
            "identity": final.get("identity", {}).get("status"),
        }
    expected = (
        {"returncode": 1, "status": "INVALID", "identity": "INVALID"}
        if seeded
        else {"returncode": 0, "status": "PASS", "identity": "PASS"}
    )
    return Observation(
        expected=expected,
        got=got,
        applied="PATH appended before final" if seeded else "",
    )


def _fixture_final_binding_guard(
    field: str,
    seeded: bool,
) -> Observation:
    with StageFixture() as fixture:
        fixture.prepare_final_inputs()
        path = os.path.join(
            fixture.report,
            "run3",
            "stage",
            "a1",
            "result.json",
        )
        if seeded:
            record = _o7_load_json(path)
            record[field] = "run3/other" if field == "unit" else 2
            with open(path, "w", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True)
        returncode = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        fragment = "unit mismatch" if field == "unit" else "attempt mismatch"
        got = {
            "returncode": returncode,
            "status": final.get("status"),
            "reason": any(
                fragment in str(reason)
                for reason in final.get("reasons", [])
            ),
        }
    expected = (
        {"returncode": 1, "status": "FAIL", "reason": True}
        if seeded
        else {"returncode": 0, "status": "PASS", "reason": False}
    )
    return Observation(
        expected=expected,
        got=got,
        applied=f"run3 result {field} changed" if seeded else "",
    )


def _fixture_final_required_guard(seeded: bool) -> Observation:
    with StageFixture() as fixture:
        fixture.prepare_final_inputs()
        required_path = os.path.join(
            fixture.report,
            "run3",
            "required.json",
        )
        if seeded:
            with open(required_path, "w", encoding="utf-8") as output:
                json.dump([], output)
        returncode = stages_mod.cmd_final(
            fixture.args(),
            drivers=fixture.drivers,
        )
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        got = {
            "returncode": returncode,
            "status": final.get("status"),
            "reason": any(
                "required.json mismatch" in str(reason)
                for reason in final.get("reasons", [])
            ),
        }
    expected = (
        {"returncode": 1, "status": "FAIL", "reason": True}
        if seeded
        else {"returncode": 0, "status": "PASS", "reason": False}
    )
    return Observation(
        expected=expected,
        got=got,
        applied="required.json changed from ['stage'] to []" if seeded else "",
    )


def _fixture_run3_refused_guard(seeded: bool) -> Observation:
    scenario = "driver-refused-log" if seeded else "control"
    with StageFixture(scenario) as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=30.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        record = _stage_result(fixture.report, "run3/stage")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "no_refused": record.get("checks", {}).get("no-refused"),
        }
    expected = (
        {
            "returncode": 1,
            "status": "MISCLASSIFIED",
            "no_refused": "MISCLASSIFIED",
        }
        if seeded
        else {
            "returncode": 0,
            "status": "PASS",
            "no_refused": "PASS",
        }
    )
    return Observation(
        expected=expected,
        got=got,
        applied="driver emits one shim REFUSED line" if seeded else "",
    )


def _fixture_run3_census_guard(seeded: bool) -> Observation:
    with StageFixture() as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        if seeded:
            census_path = os.path.join(
                fixture.w,
                "proof",
                "census",
                "stage.json",
            )
            census = _o7_load_json(census_path)
            census["script_sha256"] = "0" * 64
            with open(census_path, "w", encoding="utf-8") as output:
                json.dump(census, output, sort_keys=True)
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=1.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        record = _stage_result(fixture.report, "run3/stage")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "census": record.get("checks", {}).get("census"),
        }
    expected = (
        {"returncode": 1, "status": "FAIL", "census": "FAIL"}
        if seeded
        else {"returncode": 0, "status": "PASS", "census": "PASS"}
    )
    return Observation(
        expected=expected,
        got=got,
        applied="stage census script_sha256 changed" if seeded else "",
    )


def _fixture_baseline_header_guard(seeded: bool) -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-baseline-header-") as root:
        census_dir = os.path.join(root, "proof", "census")
        os.makedirs(census_dir)
        with open(
            os.path.join(census_dir, "stage.json"),
            "w",
            encoding="utf-8",
        ) as output:
            json.dump(
                {
                    "driver": "stage",
                    "skips": [
                        {
                            "regex": "^fixture platform skipped$",
                            "class": "platform",
                            "what": "fixture platform",
                        }
                    ],
                },
                output,
            )
        header = (
            "-- running sibling std_stage_exercise.sh"
            if seeded
            else "-- running sibling: std_stage_exercise.sh"
        )
        hits = stages_mod._baseline_skip_hits(
            root,
            f"{header}\nfixture platform skipped\n",
        )
    return Observation(
        expected=0 if seeded else 1,
        got=len(hits),
        applied="sibling header colon removed" if seeded else "",
    )


def _fixture_final_forged_pass_seed() -> Observation:
    return _final_seed("forged-pass")


def _fixture_final_missing_result_seed() -> Observation:
    return _final_seed("missing-result")


def _fixture_final_chain_mismatch_seed() -> Observation:
    return _final_seed("chain-mismatch")


def _fixture_final_earlier_failure_seed() -> Observation:
    return _final_seed("earlier-failure")


def _fixture_run_proof_optimize_seed() -> Observation:
    script = os.path.join(REPO_ROOT, "proof", "run_proof.py")
    control = [sys.executable, "-B", script, "--help"]
    command = [sys.executable, "-B", "-O", script, "--help"]
    env = os.environ.copy()
    env.pop("PYTHONOPTIMIZE", None)
    env.pop("ROUTE_A_DRIVERS", None)
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    got = {
        "returncode": completed.returncode,
        "stderr": completed.stderr.strip(),
    }
    expected = {
        "returncode": 2,
        "stderr": "run_proof: refusing to run under python -O / PYTHONOPTIMIZE",
    }
    return Observation(
        expected=expected,
        got=got,
        applied=(
            f"control_argv={control!r};seed_argv={command!r};"
            "inserted_token=-O"
        ),
    )


def _fixture_run_proof_optimize_control() -> Observation:
    script = os.path.join(REPO_ROOT, "proof", "run_proof.py")
    env = os.environ.copy()
    env.pop("PYTHONOPTIMIZE", None)
    env.pop("ROUTE_A_DRIVERS", None)
    completed = subprocess.run(
        [sys.executable, "-B", script, "--help"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return Observation(expected=0, got=completed.returncode)


def _fixture_d4_stage_interrupt_seed() -> Observation:
    with StageFixture("d4-stage-interrupt") as fixture:
        fixture.pin()
        marker = os.path.join(
            fixture.report,
            "run1",
            "a1",
            "run1_1.tmp",
            "interrupt-ready",
        )
        marker_seen = threading.Event()

        def send_term() -> None:
            for _ in range(500):
                if os.path.isfile(marker):
                    marker_seen.set()
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                time.sleep(0.01)

        sender = threading.Thread(target=send_term)
        sender.start()
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        sender.join()
        result = _stage_result(fixture.report, "run1")
        survivor_pids = result.get("survivors", [])
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "reason": "interrupted by signal 15" in result.get("reasons", []),
            "survivors_gone": all(
                not _process_alive(pid) for pid in survivor_pids
            ),
        }
        expected = {
            "returncode": 1,
            "status": "FAIL",
            "reason": True,
            "survivors_gone": True,
        }
        return Observation(
            expected=expected,
            got=got,
            applied=(
                f"marker_seen={str(marker_seen.is_set()).lower()};"
                "sigterm_sent=true;"
                f"{_scenario_applied(fixture)}"
            ),
        )


def _o7_skip_record(scenario: str) -> dict[str, str]:
    if scenario == "skip-env-blocked":
        return {
            "driver": "stage",
            "class": "tool",
            "what": "fixture tool",
            "regex": "^fixture tool skipped$",
        }
    return {
        "driver": "stage",
        "class": "platform",
        "what": "fixture platform",
        "regex": "^fixture platform skipped$",
    }


def _o7_ledger_diagnostic(
    fixture: StageFixture,
    driver: str,
) -> dict[str, object]:
    attempt_dir = stages_mod.latest_attempt_dir(
        os.path.join(fixture.report, "run3", driver)
    )
    if attempt_dir is None:
        return {"error": "attempt missing"}
    config_path = os.path.join(attempt_dir, "shim.json")
    ledger_path = os.path.join(attempt_dir, "ledger.jsonl")
    census_path = os.path.join(
        fixture.w,
        "proof",
        "census",
        f"{driver}.json",
    )
    if not all(
        os.path.isfile(path)
        for path in (config_path, ledger_path, census_path)
    ):
        return {
            "error": "shim inputs missing",
            "attempt": attempt_dir,
        }
    try:
        config = _o7_load_json(config_path)
        census = _o7_load_json(census_path)
        verdict = proofkit_mod.verify_ledger(
            ledger_path,
            census=census,
            driver=driver,
            nonce=config["nonce"],
            attempt=int(os.path.basename(attempt_dir)[1:]),
            chain_id=fixture.pin_data["chain_id"],
            work_tmp=config["work_tmp"],
            repo=fixture.w,
            platform_tmp=config["platform_tmp"],
        )
        records: list[dict[str, object]] = []
        with open(ledger_path, "r", encoding="utf-8") as ledger:
            for line in ledger:
                value = json.loads(line)
                if not isinstance(value, dict):
                    continue
                records.append(
                    {
                        key: value.get(key)
                        for key in (
                            "kind",
                            "phase",
                            "command",
                            "mode",
                            "own",
                            "canonical",
                            "variant_ids",
                            "bindings",
                            "sources",
                            "out",
                            "producer",
                            "consumer",
                            "run",
                            "out_ref",
                            "out_ino",
                            "out_mtime_ns",
                            "atime_set_ns",
                        )
                    }
                )
        refs: list[dict[str, object]] = []
        for record in records:
            out_ref = record.get("out_ref")
            if not isinstance(out_ref, str):
                continue
            stat = os.stat(out_ref)
            refs.append(
                {
                    "path": out_ref,
                    "ino": stat.st_ino,
                    "atime_ns": stat.st_atime_ns,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": _file_sha256(out_ref),
                }
            )
        return {
            "statuses": sorted(verdict.statuses),
            "reasons": list(verdict.reasons),
            "records": records[:5],
            "refs": refs,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return {"error": f"{type(error).__name__}: {error}"}


def _o7_run3_case(
    scenario: str,
    *,
    drivers: tuple[str, ...] | None = None,
    baseline: list[dict[str, str]] | None = None,
    limit_sec: float = 5.0,
    remove_driver_script: bool = False,
) -> tuple[int, dict[str, dict], str]:
    with StageFixture(scenario) as fixture:
        expected_changes = (
            3
            if scenario == "driver-missing"
            else (0 if scenario == "control" else 2)
        )
        if fixture.stub_difference_count != expected_changes:
            raise RuntimeError(
                f"scenario {scenario!r} changed "
                f"{fixture.stub_difference_count} stub files, "
                f"expected {expected_changes}"
            )
        fixture.pin_data = fixture.pin()
        removed = ""
        if remove_driver_script:
            removed = fixture.missing_driver_target
            if not removed:
                raise RuntimeError("driver-missing fixture has no symlink target")
            os.unlink(removed)
        fixture.write_prerequisites(baseline=baseline)
        selected = drivers or fixture.drivers
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=selected,
            driver_limit_sec=limit_sec,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        results = {
            driver: _stage_result(fixture.report, f"run3/{driver}")
            for driver in selected
        }
        for driver, result in results.items():
            result["_ledger_diagnostic"] = _o7_ledger_diagnostic(
                fixture,
                driver,
            )
        applied = (
            f"scenario={scenario};"
            f"drivers={selected!r};"
            f"stub_files_changed={fixture.stub_difference_count};"
            f"removed={removed or 'none'}"
        )
        return returncode, results, applied


def _fixture_run3_import_seed() -> Observation:
    returncode, results, applied = _o7_run3_case("run3-import")
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "ledger": stage.get("checks", {}).get("ledger"),
        "exit": stage.get("checks", {}).get("exit"),
    }
    expected = {
        "returncode": 1,
        "status": "NOT-ROUNDTRIPPED",
        "ledger": "NOT-ROUNDTRIPPED",
        "exit": "PASS",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_run3_timeout_seed() -> Observation:
    returncode, results, applied = _o7_run3_case(
        "driver-timeout",
        limit_sec=0.1,
    )
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "exit": stage.get("checks", {}).get("exit"),
    }
    expected = {
        "returncode": 1,
        "status": "TIMEOUT",
        "exit": "TIMEOUT",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_skip_env_blocked_seed() -> Observation:
    baseline = [_o7_skip_record("skip-env-blocked")]
    returncode, results, applied = _o7_run3_case(
        "skip-env-blocked",
        baseline=baseline,
    )
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "skips": stage.get("checks", {}).get("skips"),
    }
    expected = {
        "returncode": 1,
        "status": "ENV-BLOCKED",
        "skips": "ENV-BLOCKED",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_skip_partial_seed() -> Observation:
    returncode, results, applied = _o7_run3_case("skip-partial")
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "skips": stage.get("checks", {}).get("skips"),
    }
    expected = {
        "returncode": 1,
        "status": "PARTIAL",
        "skips": "PARTIAL",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_skip_platform_seed() -> Observation:
    baseline = [_o7_skip_record("skip-platform")]
    returncode, results, applied = _o7_run3_case(
        "skip-platform",
        baseline=baseline,
    )
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "skips": stage.get("checks", {}).get("skips"),
        "limit_named": any(
            str(reason).startswith("platform limit stage:")
            for reason in stage.get("reasons", [])
        ),
    }
    expected = {
        "returncode": 0,
        "status": "PASS",
        "skips": "PASS",
        "limit_named": True,
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_driver_missing_sentinel_seed() -> Observation:
    returncode, results, applied = _o7_run3_case("missing-sentinel")
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "sentinel": stage.get("checks", {}).get("sentinel"),
        "ledger": stage.get("checks", {}).get("ledger"),
    }
    expected = {
        "returncode": 1,
        "status": "FAIL",
        "sentinel": "FAIL",
        "ledger": "PASS",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_driver_stale_ledger_seed() -> Observation:
    returncode, results, applied = _o7_run3_case("stale-ledger")
    stage = results["stage"]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "ledger": stage.get("checks", {}).get("ledger"),
    }
    expected = {
        "returncode": 1,
        "status": "STALE",
        "ledger": "STALE",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_census_missing_continues_seed() -> Observation:
    returncode, results, applied = _o7_run3_case(
        "control",
        drivers=("missing", "stage"),
    )
    got = {
        "returncode": returncode,
        "missing": results["missing"].get("status"),
        "stage": results["stage"].get("status"),
    }
    expected = {
        "returncode": 1,
        "missing": "CENSUS-MISSING",
        "stage": "PASS",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _fixture_driver_missing_continues_seed() -> Observation:
    returncode, results, applied = _o7_run3_case(
        "driver-missing",
        remove_driver_script=True,
    )
    got = {
        "returncode": returncode,
        "missing": results["missingdriver"].get("status"),
        "stage": results["stage"].get("status"),
    }
    expected = {
        "returncode": 1,
        "missing": "FAIL",
        "stage": "PASS",
    }
    return Observation(expected=expected, got=got, applied=applied)


def _o7_amend_b_fixture(case: str) -> Observation:
    scenario = {
        "control": "control",
        "run-form": "run-form",
        "not-executed": "not-executed",
        "copy-modified": "copy-modified",
        "move-replaced": "move-replaced",
        "run-form-not-counted": "run-form-not-counted",
    }[case]
    returncode, results, applied = _o7_run3_case(scenario)
    stage = results["stage"]
    expected_status = {
        "control": "PASS",
        "run-form": "PASS",
        "not-executed": "NOT-EXECUTED",
        "copy-modified": "OUT-MODIFIED",
        "move-replaced": "NOT-EXECUTED",
        "run-form-not-counted": "NOT-EXECUTED",
    }[case]
    got = {
        "returncode": returncode,
        "status": stage.get("status"),
        "ledger": stage.get("checks", {}).get("ledger"),
    }
    expected = {
        "returncode": 0 if expected_status == "PASS" else 1,
        "status": expected_status,
        "ledger": expected_status,
    }
    if got != expected:
        got["diagnostic"] = stage.get("_ledger_diagnostic")
    return Observation(
        expected=expected,
        got=got,
        applied="" if expected_status == "PASS" else applied,
    )


def _fixture_all_control() -> Observation:
    with StageFixture() as fixture:
        fixture.pin_data = fixture.pin()
        returncode = stages_mod.cmd_all(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=5.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        final = _o7_load_json(os.path.join(fixture.report, "final.json"))
        expected = {"returncode": 0, "status": "PASS"}
        got = {
            "returncode": returncode,
            "status": final.get("status"),
        }
        if got != expected:
            got["diagnostic"] = _o7_ledger_diagnostic(
                fixture,
                "stage",
            )
        return Observation(expected=expected, got=got)


def _fixture_pin_command_control() -> Observation:
    with PinFixture() as fixture:
        args = SimpleNamespace(
            report_dir=fixture.report,
            p=fixture.p,
            w=fixture.w,
            compiler=fixture.compiler,
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            returncode = stages_mod.cmd_pin(
                args,
                drivers=proofkit_mod.DRIVERS_29,
            )
        pin = proofkit_mod.load_pin(fixture.report)
        return Observation(
            expected={"returncode": 0, "chain": True},
            got={
                "returncode": returncode,
                "chain": pin.get("chain_id") in stdout.getvalue(),
            },
        )


def _fixture_shim_parser_edges_seed() -> Observation:
    invocation = shim_mod.parse_invocation(
        ["run", "fixture.iyi", "--", "alpha"]
    )
    refusal = ""
    try:
        shim_mod._recognized_option_tokens(
            ("--prelude",),
            command="build",
            allow_positionals=False,
        )
    except shim_mod.InvocationError as error:
        refusal = str(error)
    got = {
        "separator": invocation.has_separator,
        "run_args": list(invocation.run_args),
        "sources": list(invocation.sources),
        "refusal": refusal,
    }
    expected = {
        "separator": True,
        "run_args": ["alpha"],
        "sources": ["fixture.iyi"],
        "refusal": "option requires a value: --prelude",
    }
    return Observation(
        expected=expected,
        got=got,
        applied="separator inserted once; ambient option value removed once",
    )


def _fixture_main_identity_refusal_seed() -> Observation:
    while True:
        suffix = hashlib.sha256(os.urandom(32)).hexdigest()[:8]
        report = os.path.join("/tmp", f"iyp-{suffix}")
        if not os.path.exists(report):
            break
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        returncode = stages_mod.main(
            ["final", "--report-dir", report]
        )
    got = {
        "returncode": returncode,
        "pin_missing": "REFUSED PIN-MISSING:" in stderr.getvalue(),
    }
    expected = {"returncode": 1, "pin_missing": True}
    return Observation(
        expected=expected,
        got=got,
        applied=f"report={report};pin_json=absent",
    )








def _fixture_artifact_session_kill_seed() -> Observation:
    with tempfile.TemporaryDirectory(prefix="iyi-o7-artifact-kill-") as root:
        command = [
            "/bin/sh",
            "-c",
            "trap '' TERM; exec /bin/sleep 30",
        ]
        returncode, stdout, stderr, timed_out = legs_mod.run_session_proc(
            command,
            root,
            os.environ.copy(),
            0.05,
        )
    got = {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }
    expected = {
        "returncode": -signal.SIGKILL,
        "stdout": b"",
        "stderr": b"",
        "timed_out": True,
    }
    return Observation(
        expected=expected,
        got=got,
        applied="child ignores SIGTERM; timeout forces SIGKILL",
    )










def _proofkit_isolated_edge(case: str) -> Observation:
    applied = f"isolated proofkit edge={case}"
    got = False

    def reason(call: Callable[[], object]) -> str:
        try:
            call()
        except proofkit_mod.IdentityError as error:
            return error.reason
        return "NO-REFUSAL"

    if case in {
        "identity-p-dirty",
        "identity-w-dirty",
        "identity-product-diff",
        "identity-compiler-missing",
        "identity-stamp-missing",
    }:
        with PinFixture() as fixture:
            pin = fixture.pin()
            if case == "identity-p-dirty":
                with open(
                    os.path.join(fixture.p, "dirty"),
                    "w",
                    encoding="utf-8",
                ) as output:
                    output.write("dirty")
                got = reason(lambda: proofkit_mod.check_identity(pin)) == "P-DIRTY"
            elif case == "identity-w-dirty":
                with open(
                    os.path.join(fixture.w, "dirty"),
                    "w",
                    encoding="utf-8",
                ) as output:
                    output.write("dirty")
                got = reason(lambda: proofkit_mod.check_identity(pin)) == "W-DIRTY"
            elif case == "identity-product-diff":
                target = os.path.join(fixture.w, "src", "guard.txt")
                with open(target, "w", encoding="utf-8") as output:
                    output.write("changed")
                _git(fixture.w, "add", "src/guard.txt")
                _git(fixture.w, "commit", "-m", "fixture product change")
                pin["w_head"] = _git(fixture.w, "rev-parse", "HEAD")
                got = (
                    reason(lambda: proofkit_mod.check_identity(pin))
                    == "PRODUCT-DIFF"
                )
            elif case == "identity-compiler-missing":
                os.unlink(fixture.compiler)
                got = (
                    reason(lambda: proofkit_mod.check_identity(pin))
                    == "COMPILER-NOT-EXECUTABLE"
                )
            else:
                fixture.write_compiler("fixture version without stamp")
                compiler_stat = os.stat(fixture.compiler)
                pin.update(
                    {
                        "compiler_sha256": _file_sha256(fixture.compiler),
                        "compiler_size": compiler_stat.st_size,
                        "compiler_mtime_ns": compiler_stat.st_mtime_ns,
                        "compiler_inode": compiler_stat.st_ino,
                        "compiler_version_line": "fixture version without stamp",
                    }
                )
                got = (
                    reason(lambda: proofkit_mod.check_identity(pin))
                    == "COMPILER-STAMP-MISSING"
                )
        return Observation(expected=True, got=got, applied=applied)

    with tempfile.TemporaryDirectory(prefix="iyi-proofkit-edge-") as root:
        if case == "git-error":
            try:
                proofkit_mod.git_cmd(["status"], root)
            except RuntimeError:
                got = True
        elif case.startswith("platform-"):
            tool_dir = os.path.join(root, "tools")
            platform_root = os.path.join(root, "platform")
            os.makedirs(tool_dir)
            os.makedirs(platform_root)
            getconf = os.path.join(tool_dir, "getconf")
            mktemp = os.path.join(tool_dir, "mktemp")
            if case != "platform-getconf-missing":
                if case == "platform-getconf-oserror":
                    _o6_write_executable(
                        getconf,
                        "#!/no/such/interpreter\n",
                    )
                elif case == "platform-getconf-status":
                    _o6_write_executable(getconf, "#!/bin/sh\nexit 7\n")
                elif case == "platform-getconf-nondir":
                    _o6_write_executable(
                        getconf,
                        "#!/bin/sh\nprintf '/no/such/platform\\n'\n",
                    )
                else:
                    _o6_write_executable(
                        getconf,
                        "#!/bin/sh\n"
                        f"printf '%s\\n' {shlex.quote(platform_root)}\n",
                    )
            if case not in {
                "platform-getconf-missing",
                "platform-getconf-oserror",
                "platform-getconf-status",
                "platform-getconf-nondir",
                "platform-mktemp-missing",
            }:
                created = os.path.join(platform_root, "created")
                if case == "platform-mktemp-oserror":
                    _o6_write_executable(
                        mktemp,
                        "#!/no/such/interpreter\n",
                    )
                elif case == "platform-mktemp-status":
                    _o6_write_executable(mktemp, "#!/bin/sh\nexit 7\n")
                elif case == "platform-mktemp-nondir":
                    _o6_write_executable(
                        mktemp,
                        "#!/bin/sh\n"
                        f"printf '%s\\n' {shlex.quote(created)}\n",
                    )
                else:
                    _o6_write_executable(
                        mktemp,
                        "#!/bin/sh\n"
                        f"/bin/mkdir {shlex.quote(created)}\n"
                        f"printf '%s\\n' {shlex.quote(created)}\n",
                    )
            expected_reason = (
                "PLATFORM-TMP-UNOBSERVABLE"
                if case.startswith("platform-mktemp-")
                and case != "platform-mktemp-missing"
                else "NO-PLATFORM-TMP"
            )
            got = (
                reason(
                    lambda: proofkit_mod.platform_temp_root(
                        {
                            "env_path": tool_dir,
                            "env_home": root,
                        },
                        cwd=root,
                        probe_mktemp=True,
                    )
                )
                == expected_reason
            )
        elif case in {"compiler-env", "roots-empty"}:
            compiler = _o6_write_executable(
                os.path.join(root, "compiler"),
                (
                    "#!/bin/sh\nexit 7\n"
                    if case == "compiler-env"
                    else "#!/bin/sh\nprintf ':\\n'\n"
                ),
            )
            w_path = os.path.join(root, "w")
            p_path = os.path.join(root, "p")
            os.makedirs(w_path)
            os.makedirs(p_path)
            if case == "compiler-env":
                got = (
                    reason(
                        lambda: proofkit_mod.compute_canonical_roots(
                            w_path,
                            p_path,
                            compiler,
                            {
                                "env_path": os.environ.get("PATH", ""),
                                "env_home": root,
                            },
                        )
                    )
                    == "COMPILER-ENV"
                )
            else:
                got = (
                    proofkit_mod.compute_canonical_roots(
                        w_path,
                        p_path,
                        compiler,
                        {
                            "env_path": os.environ.get("PATH", ""),
                            "env_home": root,
                        },
                    )
                    == []
                )
        elif case.startswith("probe-"):
            calls = 0
            initial_mtime = 0

            def probe_stat(path: str):
                nonlocal calls, initial_mtime
                calls += 1
                current = os.stat(path)
                if calls == 1:
                    initial_mtime = current.st_mtime_ns
                    if case == "probe-oserror":
                        os.unlink(path)
                        os.unlink(f"{path}.ref")
                        raise OSError("fixture probe failure")
                if case == "probe-atime-retention" and calls == 2:
                    return SimpleNamespace(
                        st_atime_ns=current.st_mtime_ns,
                        st_mtime_ns=current.st_mtime_ns,
                        st_ino=current.st_ino,
                    )
                if case == "probe-exec-failure" and calls == 3:
                    with open(path, "w", encoding="utf-8") as output:
                        output.write("#!/bin/sh\nexit 7\n")
                    os.chmod(path, 0o755)
                    return os.stat(path)
                if case == "probe-sha" and calls == 4:
                    with open(path, "ab") as output:
                        output.write(b"x")
                    return SimpleNamespace(
                        st_atime_ns=initial_mtime + 1,
                        st_mtime_ns=initial_mtime,
                        st_ino=current.st_ino,
                    )
                if case == "probe-inode" and calls == 4:
                    return SimpleNamespace(
                        st_atime_ns=initial_mtime + 1,
                        st_mtime_ns=initial_mtime,
                        st_ino=current.st_ino + 1,
                    )
                return current

            got = (
                reason(
                    lambda: proofkit_mod.probe_atime_observable(
                        root,
                        stat_fn=probe_stat,
                    )
                )
                == "EXEC-UNOBSERVABLE"
            )
        elif case in {"first-output", "nm-output"}:
            tool = _o6_write_executable(
                os.path.join(root, "bad-tool"),
                "#!/bin/sh\nexit 7\n",
            )
            got = (
                reason(
                    lambda: (
                        proofkit_mod._first_output_line(
                            [tool],
                            cwd=root,
                            env=os.environ.copy(),
                            reason="BAD-OUTPUT",
                        )
                        if case == "first-output"
                        else proofkit_mod._nm_version_line(
                            tool,
                            cwd=root,
                            env=os.environ.copy(),
                        )
                    )
                )
                == ("BAD-OUTPUT" if case == "first-output" else "NO-NM")
            )
        elif case in {
            "census-set",
            "census-invalid",
            "census-shas-set",
        }:
            census_root = os.path.join(root, "repo")
            census_dir = os.path.join(census_root, "proof", "census")
            os.makedirs(census_dir)
            if case == "census-invalid":
                with open(
                    os.path.join(census_dir, "demo.json"),
                    "w",
                    encoding="utf-8",
                ) as output:
                    output.write("{")
                call = lambda: proofkit_mod._census_shas_and_validate(
                    census_root,
                    ("demo",),
                )
                expected_reason = "CENSUS-INVALID"
            elif case == "census-shas-set":
                call = lambda: proofkit_mod._census_shas(
                    census_root,
                    ("demo",),
                )
                expected_reason = "CENSUS-SET"
            else:
                call = lambda: proofkit_mod._census_shas_and_validate(
                    os.path.join(root, "missing"),
                    ("demo",),
                )
                expected_reason = "CENSUS-SET"
            got = reason(call) == expected_reason
        elif case in {
            "pin-load-invalid",
            "pin-load-chain",
            "pin-load-report",
        }:
            suffix = {
                "pin-load-invalid": "aa000001",
                "pin-load-chain": "aa000002",
                "pin-load-report": "aa000003",
            }[case]
            report = os.path.join("/tmp", f"iyp-{suffix}")
            shutil.rmtree(report, ignore_errors=True)
            os.makedirs(report)
            try:
                with open(
                    os.path.join(report, "pin.json"),
                    "w",
                    encoding="utf-8",
                ) as output:
                    if case == "pin-load-invalid":
                        output.write("{")
                    elif case == "pin-load-chain":
                        json.dump({"chain_id": None}, output)
                    else:
                        json.dump(
                            {
                                "chain_id": suffix + "0" * 24,
                                "report_dir": "/private/tmp/other",
                            },
                            output,
                        )
                got = (
                    reason(lambda: proofkit_mod.load_pin(report))
                    == (
                        "PIN-INVALID"
                        if case == "pin-load-invalid"
                        else (
                            "CHAIN-ID"
                            if case == "pin-load-chain"
                            else "REPORT-DIR-CHAIN"
                        )
                    )
                )
            finally:
                shutil.rmtree(report, ignore_errors=True)
        elif case == "signal-missing":
            proofkit_mod._signal_process_group(
                2_000_000_000,
                signal.SIGTERM,
            )
            got = True
        elif case == "sampler-oserror":
            errors: list[BaseException] = []
            proofkit_mod._sample_log_growth(
                os.path.join(root, "missing.log"),
                os.path.join(root, "times"),
                threading.Event(),
                errors,
            )
            got = bool(errors)
        elif case in {"limit-invalid", "grace-invalid"}:
            try:
                proofkit_mod.run_bounded(
                    [sys.executable, "-c", "pass"],
                    root,
                    os.environ.copy(),
                    os.path.join(root, "log"),
                    os.path.join(root, "times"),
                    0 if case == "limit-invalid" else None,
                    -1 if case == "grace-invalid" else 0.0,
                )
            except ValueError:
                got = True
        elif case in {"status-unknown", "status-missing"}:
            got = (
                proofkit_mod.recompute_status(
                    (
                        {}
                        if case == "status-unknown"
                        else {"checks": {"identity": "PASS"}}
                    ),
                    "unknown" if case == "status-unknown" else "run2",
                )
                == "FAIL"
            )
        elif case.startswith("parser-"):
            parser_results = {
                "parser-backtick": (
                    proofkit_mod._replace_shell_expansions("`date`")
                    == "IYIVAR"
                ),
                "parser-trailing-dollar": (
                    proofkit_mod._replace_shell_expansions("$") == "$"
                ),
                "parser-open-brace": (
                    proofkit_mod._replace_shell_expansions("${value") is None
                ),
                "parser-nested-command": (
                    proofkit_mod._command_substitution_end(
                        '$(echo "$(date)")',
                        0,
                    )
                    == len('$(echo "$(date)")')
                ),
                "parser-nested-backtick": (
                    proofkit_mod._command_substitution_end(
                        '$(echo "a `date` c")',
                        0,
                    )
                    == len('$(echo "a `date` c")')
                ),
                "parser-dequote": (
                    proofkit_mod._dequote_print_word("$'x'") is None
                ),
                "parser-render": (
                    proofkit_mod._render_print_words(["printf"]) is None
                ),
            }
            got = parser_results[case]
        else:
            raise ValueError(f"unknown isolated proofkit edge {case}")
    return Observation(expected=True, got=got, applied=applied)


def _proofkit_more_edge(case: str) -> Observation:
    applied = f"isolated proofkit edge={case}"
    got = False

    def reason(call: Callable[[], object]) -> str:
        try:
            call()
        except proofkit_mod.IdentityError as error:
            return error.reason
        return "NO-REFUSAL"

    if case in {
        "inspect-compiler-missing",
        "inspect-compiler-stat",
        "inspect-no-nm",
        "identity-git-error",
        "identity-compiler-stat",
        "identity-not-descendant",
        "identity-no-timeout",
        "identity-no-nm",
        "pin-write-probe",
        "pin-write-probe-dirty",
        "pin-write-type",
        "pin-write-dirty",
    }:
        with PinFixture() as fixture:
            if case == "inspect-compiler-missing":
                got = (
                    reason(
                        lambda: proofkit_mod.inspect_pin_inputs(
                            fixture.p,
                            fixture.w,
                            os.path.join(fixture.scratch, "missing"),
                            DRIVERS_29,
                        )
                    )
                    == "COMPILER-NOT-EXECUTABLE"
                )
            elif case == "inspect-compiler-stat":
                compiler = os.path.join(fixture.scratch, "execute-only")
                with open(compiler, "w", encoding="utf-8") as output:
                    output.write("#!/bin/sh\nexit 0\n")
                os.chmod(compiler, 0o100)
                try:
                    got = (
                        reason(
                            lambda: proofkit_mod.inspect_pin_inputs(
                                fixture.p,
                                fixture.w,
                                compiler,
                                DRIVERS_29,
                            )
                        )
                        == "COMPILER-STAT"
                    )
                finally:
                    os.chmod(compiler, 0o700)
            elif case == "inspect-no-nm":
                tool_dir = os.path.join(fixture.scratch, "inspect-tools")
                os.makedirs(tool_dir)
                for tool in ("git", "timeout", "getconf", "mktemp"):
                    source = shutil.which(tool)
                    if source:
                        os.symlink(source, os.path.join(tool_dir, tool))
                original_path = os.environ.get("PATH", "")
                try:
                    os.environ["PATH"] = tool_dir
                    got = (
                        reason(
                            lambda: proofkit_mod.inspect_pin_inputs(
                                fixture.p,
                                fixture.w,
                                fixture.compiler,
                                DRIVERS_29,
                            )
                        )
                        == "NO-NM"
                    )
                finally:
                    os.environ["PATH"] = original_path
            elif case in {
                "pin-write-probe",
                "pin-write-probe-dirty",
                "pin-write-type",
                "pin-write-dirty",
            }:
                report = os.path.join(
                    "/tmp",
                    {
                        "pin-write-probe": "iyp-bb000001",
                        "pin-write-probe-dirty": "iyp-bb000004",
                        "pin-write-type": "iyp-bb000002",
                        "pin-write-dirty": "iyp-bb000003",
                    }[case],
                )
                shutil.rmtree(report, ignore_errors=True)

                class BadStat:
                    @property
                    def st_mtime_ns(self):
                        if case == "pin-write-dirty":
                            with open(
                                os.path.join(report, "held"),
                                "w",
                                encoding="utf-8",
                            ) as output:
                                output.write("held")
                        raise TypeError("fixture stat type failure")

                def failed_stat(_path):
                    if case in {
                        "pin-write-probe",
                        "pin-write-probe-dirty",
                    }:
                        if case == "pin-write-probe-dirty":
                            with open(
                                os.path.join(report, "held"),
                                "w",
                                encoding="utf-8",
                            ) as output:
                                output.write("held")
                        raise OSError("fixture stat failure")
                    return BadStat()

                try:
                    got = (
                        reason(
                            lambda: proofkit_mod.write_pin(
                                report,
                                fixture.p,
                                fixture.w,
                                fixture.compiler,
                                DRIVERS_29,
                                stat_fn=failed_stat,
                            )
                        )
                        == (
                            "EXEC-UNOBSERVABLE"
                            if case in {
                                "pin-write-probe",
                                "pin-write-probe-dirty",
                            }
                            else "PIN-WRITE"
                        )
                    )
                finally:
                    shutil.rmtree(report, ignore_errors=True)
            elif case == "identity-git-error":
                pin = fixture.pin()
                os.unlink(os.path.join(fixture.p, ".git", "HEAD"))
                got = (
                    reason(lambda: proofkit_mod.check_identity(pin))
                    == "GIT-ERROR"
                )
            elif case == "identity-compiler-stat":
                pin = fixture.pin()
                os.chmod(fixture.compiler, 0o100)
                try:
                    got = (
                        reason(lambda: proofkit_mod.check_identity(pin))
                        == "COMPILER-STAT"
                    )
                finally:
                    os.chmod(fixture.compiler, 0o700)
            elif case == "identity-not-descendant":
                pin = fixture.pin()
                _git(fixture.w, "checkout", "--orphan", "fixture-orphan")
                _git(
                    fixture.w,
                    "commit",
                    "--allow-empty",
                    "-m",
                    "fixture orphan",
                )
                pin["w_head"] = _git(fixture.w, "rev-parse", "HEAD")
                got = (
                    reason(lambda: proofkit_mod.check_identity(pin))
                    == "W-NOT-DESCENDANT"
                )
            else:
                tool_dir = os.path.join(fixture.scratch, "identity-tools")
                os.makedirs(tool_dir)
                for tool in ("git", "nm", "timeout", "getconf", "mktemp"):
                    source = shutil.which(tool)
                    if source:
                        os.symlink(source, os.path.join(tool_dir, tool))
                original_path = os.environ.get("PATH", "")
                try:
                    os.environ["PATH"] = tool_dir
                    pin = fixture.pin()
                    missing = (
                        "timeout"
                        if case == "identity-no-timeout"
                        else "nm"
                    )
                    os.unlink(os.path.join(tool_dir, missing))
                    got = (
                        reason(lambda: proofkit_mod.check_identity(pin))
                        == (
                            "NO-TIMEOUT"
                            if missing == "timeout"
                            else "NO-NM"
                        )
                    )
                finally:
                    os.environ["PATH"] = original_path
        return Observation(expected=True, got=got, applied=applied)

    with tempfile.TemporaryDirectory(prefix="iyi-proofkit-more-") as root:
        if case == "census-validate-mismatch":
            os.makedirs(os.path.join(root, "proof", "census"))
            got = (
                reason(
                    lambda: proofkit_mod._census_shas_and_validate(
                        root,
                        ("demo",),
                    )
                )
                == "CENSUS-SET"
            )
        elif case == "census-shas-missing":
            got = (
                reason(
                    lambda: proofkit_mod._census_shas(
                        os.path.join(root, "missing"),
                        ("demo",),
                    )
                )
                == "CENSUS-SET"
            )
        elif case == "inspect-git-error":
            compiler = _o6_write_executable(
                os.path.join(root, "compiler"),
                "#!/bin/sh\nexit 0\n",
            )
            got = (
                reason(
                    lambda: proofkit_mod.inspect_pin_inputs(
                        os.path.join(root, "not-p"),
                        os.path.join(root, "not-w"),
                        compiler,
                        (),
                    )
                )
                == "GIT-ERROR"
            )
        elif case == "inspect-diff-error":
            with PinFixture() as fixture:
                tool_dir = os.path.join(root, "tools")
                os.makedirs(tool_dir)
                real_git = shutil.which("git")
                if not real_git:
                    raise RuntimeError("git unavailable for diff fixture")
                _o6_write_executable(
                    os.path.join(tool_dir, "git"),
                    "#!/bin/sh\n"
                    "case \"$*\" in\n"
                    "  *'diff --name-only'*) exit 7 ;;\n"
                    "esac\n"
                    f"exec {shlex.quote(real_git)} \"$@\"\n",
                )
                original_path = os.environ.get("PATH", "")
                try:
                    os.environ["PATH"] = (
                        tool_dir + os.pathsep + original_path
                    )
                    try:
                        proofkit_mod.inspect_pin_inputs(
                            fixture.p,
                            fixture.w,
                            fixture.compiler,
                            DRIVERS_29,
                        )
                    except proofkit_mod.IdentityError as error:
                        got = (
                            error.reason == "GIT-ERROR"
                            and "diff --name-only" in error.detail
                        )
                finally:
                    os.environ["PATH"] = original_path
        elif case in {
            "report-chain-invalid",
            "report-chain-mismatch",
            "report-listdir",
        }:
            report = os.path.join("/tmp", "iyp-cc000001")
            shutil.rmtree(report, ignore_errors=True)
            if case == "report-listdir":
                os.makedirs(report)
                os.chmod(report, 0)
            try:
                got = (
                    reason(
                        lambda: proofkit_mod._validated_report_dir(
                            report,
                            require_empty=(case == "report-listdir"),
                            chain_id=(
                                "bad"
                                if case == "report-chain-invalid"
                                else (
                                    "d" * 32
                                    if case == "report-chain-mismatch"
                                    else None
                                )
                            ),
                        )
                    )
                    == (
                        "REPORT-DIR"
                        if case == "report-listdir"
                        else (
                            "CHAIN-ID"
                            if case == "report-chain-invalid"
                            else "REPORT-DIR-CHAIN"
                        )
                    )
                )
            finally:
                if os.path.exists(report):
                    os.chmod(report, 0o700)
                    shutil.rmtree(report, ignore_errors=True)
        elif case == "process-wait":
            process = subprocess.Popen(
                ["/bin/sleep", "0.05"],
                start_new_session=True,
            )
            waiter = threading.Thread(target=process.wait)
            waiter.start()
            try:
                got = proofkit_mod._wait_for_group_exit(
                    process.pid,
                    1.0,
                ) == ()
            finally:
                waiter.join()
        elif case == "process-stop":
            ready = os.path.join(root, "stop-ready")
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    f"trap '' TERM; : > {shlex.quote(ready)}; "
                    "exec /bin/sleep 30",
                ],
                start_new_session=True,
            )
            while not os.path.exists(ready):
                time.sleep(0.005)
            proofkit_mod._stop_leader(process, process.pid, 0.01)
            got = process.poll() is not None
        elif case == "process-leader-survives":
            class NeverStops:
                pid = 2_000_000_000

                def wait(self, timeout=None):
                    raise subprocess.TimeoutExpired("fixture", timeout)

            try:
                proofkit_mod._stop_leader(
                    NeverStops(),
                    NeverStops.pid,
                    0.0,
                )
            except RuntimeError:
                got = True
        elif case == "process-zombie-remains":
            ready = os.path.join(root, "zombie-ready")
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    f"trap '' TERM; : > {shlex.quote(ready)}; "
                    "exec /bin/sleep 30",
                ],
                start_new_session=True,
            )
            while not os.path.exists(ready):
                time.sleep(0.005)
            try:
                try:
                    proofkit_mod._record_and_stop_survivors(
                        process.pid,
                        -1,
                        0.01,
                        0.01,
                    )
                except RuntimeError:
                    got = True
            finally:
                process.wait()
        elif case == "process-finally-stop":
            class Running:
                pid = 2_000_000_000

                def __init__(self):
                    self.returncode = None

                def poll(self):
                    return self.returncode

                def wait(self, timeout=None):
                    self.returncode = 0
                    return 0

            process = Running()
            proofkit_mod._stop_leader_if_running(
                process,
                process.pid,
                0.0,
            )
            got = process.returncode == 0
        elif case == "process-residual-zombie":
            ready = os.path.join(root, "residual-cleanup-ready")
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    f": > {shlex.quote(ready)}; exec /bin/sleep 30",
                ],
                start_new_session=True,
            )
            while not os.path.exists(ready):
                time.sleep(0.005)
            try:
                got = bool(
                    proofkit_mod._stop_residual_processes(
                        process.pid,
                        0.01,
                        exclude=-1,
                    )
                )
            finally:
                process.wait()
        elif case == "process-parse":
            got = proofkit_mod._parse_process_group_members(
                "bad\nx y\n10 20\n",
                20,
            ) == (10,)
        elif case == "process-ps-status":
            ps = _o6_write_executable(
                os.path.join(root, "bad-ps"),
                "#!/bin/sh\nexit 7\n",
            )
            try:
                proofkit_mod._process_group_members(
                    1,
                    ps_path=ps,
                )
            except RuntimeError:
                got = True
        elif case == "run-bounded-sampler-error":
            times_path = os.path.join(root, "times-dir")
            os.makedirs(times_path)
            try:
                proofkit_mod.run_bounded(
                    [sys.executable, "-c", "pass"],
                    root,
                    os.environ.copy(),
                    os.path.join(root, "sampler-error.log"),
                    times_path,
                    None,
                    0.01,
                )
            except RuntimeError:
                got = True
        elif case == "validator-env-unchanged":
            got = proofkit_mod._environment_callsite_violations(
                (
                    "helper() {",
                    "  \"$IYI\" build source.iyi",
                    "}",
                    "IYI_PATH=/patched helper",
                ),
                {2},
                {2: {"kind": "unchanged"}},
            ) == ()
        elif case.startswith("schema-"):
            census, script_bytes, script_relpath = _census_case("cookie")
            if case == "schema-nonobject":
                got = bool(
                    proofkit_mod.validate_census(
                        [],
                        script_bytes,
                        script_relpath,
                    )
                )
            elif case == "schema-bytes":
                got = bool(
                    proofkit_mod.validate_census(
                        census,
                        "not-bytes",
                        script_relpath,
                    )
                )
            elif case == "schema-path":
                got = bool(
                    proofkit_mod.validate_census(
                        census,
                        script_bytes,
                        7,
                    )
                )
            elif case == "schema-missing-key":
                mutated = _clone_census(census)
                mutated.pop("driver")
                got = "C5.0-schema" in _rule_ids(
                    proofkit_mod.validate_census(
                        mutated,
                        script_bytes,
                        script_relpath,
                    )
                )
            elif case == "schema-duplicate-variant":
                mutated = _clone_census(census)
                target = next(
                    site
                    for site in mutated["sites"]
                    if site.get("variants")
                )
                target["variants"].append(
                    _clone_census({"v": target["variants"][0]})["v"]
                )
                got = "C5.0-schema" in _rule_ids(
                    proofkit_mod.validate_census(
                        mutated,
                        script_bytes,
                        script_relpath,
                    )
                )
            elif case == "schema-duplicate-skip":
                mutated = _clone_census(census)
                mutated["skips"].append(
                    _clone_census({"v": mutated["skips"][0]})["v"]
                )
                got = "C5.0-schema" in _rule_ids(
                    proofkit_mod.validate_census(
                        mutated,
                        script_bytes,
                        script_relpath,
                    )
                )
            elif case == "schema-sentinel-iyivar":
                mutated = _clone_census(census)
                mutated["pass_sentinel"]["regex"] = "IYIVAR"
                got = "C5.5-sentinel" in _rule_ids(
                    proofkit_mod.validate_census(
                        mutated,
                        script_bytes,
                        script_relpath,
                    )
                )
            elif case in {
                "schema-skip-unrenderable",
                "schema-sentinel-unrenderable",
            }:
                mutated = _clone_census(census)
                lines = script_bytes.decode("utf-8").splitlines()
                target = (
                    mutated["skips"][0]
                    if case == "schema-skip-unrenderable"
                    else mutated["pass_sentinel"]
                )
                index = target["line"] - 1
                lines[index] = "true"
                changed = ("\n".join(lines) + "\n").encode()
                target["text"] = "true"
                mutated["script_sha256"] = hashlib.sha256(
                    changed
                ).hexdigest()
                expected_rule = (
                    "C5.4-unrenderable"
                    if case == "schema-skip-unrenderable"
                    else "C5.4-unrenderable"
                )
                got = expected_rule in _rule_ids(
                    proofkit_mod.validate_census(
                        mutated,
                        changed,
                        script_relpath,
                    )
                )
        elif case in {
            "parser-command-open",
            "parser-backtick-open",
            "parser-echo-option",
            "parser-printf-option",
            "parser-template-brace",
            "parser-shlex-error",
            "parser-literal-dollar",
            "parser-render-command",
            "parser-backtick-unclosed",
            "parser-nested-expansion",
            "parser-nested-command-open",
            "parser-nested-backtick-open",
            "parser-unquoted-backtick",
            "parser-unquoted-backtick-open",
            "parser-dequote-expansion-open",
        }:
            got = {
                "parser-command-open": (
                    proofkit_mod._shell_span_bodies('"$(echo"') is None
                ),
                "parser-backtick-open": (
                    proofkit_mod._shell_span_bodies("`date") is None
                ),
                "parser-shlex-error": (
                    proofkit_mod._dequote_print_word("'") is None
                ),
                "parser-literal-dollar": (
                    proofkit_mod._replace_shell_expansions("$%") == "$%"
                ),
                "parser-render-command": (
                    proofkit_mod._render_print_words(["not-print"]) is None
                ),
                "parser-backtick-unclosed": (
                    proofkit_mod._replace_shell_expansions("`date") is None
                ),
                "parser-nested-expansion": (
                    proofkit_mod._replace_shell_expansions("${a{b}}")
                    == "IYIVAR"
                ),
                "parser-nested-command-open": (
                    proofkit_mod._command_substitution_end(
                        '$(echo "$(broken',
                        0,
                    )
                    is None
                ),
                "parser-nested-backtick-open": (
                    proofkit_mod._command_substitution_end(
                        '$(echo "`broken)',
                        0,
                    )
                    is None
                ),
                "parser-unquoted-backtick": (
                    proofkit_mod._command_substitution_end(
                        '$(echo `date`)',
                        0,
                    )
                    == len('$(echo `date`)')
                ),
                "parser-unquoted-backtick-open": (
                    proofkit_mod._command_substitution_end(
                        '$(echo `date)',
                        0,
                    )
                    is None
                ),
                "parser-dequote-expansion-open": (
                    proofkit_mod._dequote_print_word("${value") is None
                ),
                "parser-echo-option": (
                    proofkit_mod._render_print_words(
                        ["echo", "-n", "ok"]
                    )
                    == "ok"
                ),
                "parser-printf-option": (
                    proofkit_mod._render_print_words(
                        ["printf", "-v", "ok"]
                    )
                    == "ok"
                ),
                "parser-template-brace": (
                    proofkit_mod._template_violation(
                        "{broken",
                        set(),
                        "fixture",
                    )
                    is not None
                ),
            }[case]
        else:
            raise ValueError(f"unknown additional proofkit edge {case}")
    return Observation(expected=True, got=got, applied=applied)


def _runner_isolated_edge(case: str) -> Observation:
    applied = f"isolated runner edge={case}"
    got = False
    if case.startswith("run1-missing-"):
        relative = {
            "run1-missing-gate1": "bench/stale_equivalence.sh",
            "run1-missing-gate2": "bench/std_observe_exercise.sh",
            "run1-missing-gate3": "bench/stale_rg9.py",
            "run1-missing-gate4": "bench/std_exercise.sh",
        }[case]
        with StageFixture() as fixture:
            fixture.pin()
            os.unlink(os.path.join(fixture.w, relative))
            got = (
                stages_mod.cmd_run1(
                    fixture.args(),
                    disk_min_gb=0.0,
                )
                == 1
            )
        return Observation(expected=True, got=got, applied=applied)

    if case in {
        "run3-prerequisite-invalid",
        "run3-required-unreadable",
        "run3-required-type",
        "run3-requested-refusal",
        "final-required-missing",
        "final-required-type",
    }:
        with StageFixture() as fixture:
            if case.startswith("run3-"):
                fixture.pin()
                _exclusions, baseline, _run2 = fixture.write_prerequisites()
                args = fixture.args()
                if case == "run3-prerequisite-invalid":
                    with open(baseline, "w", encoding="utf-8") as output:
                        json.dump({}, output)
                elif case in {
                    "run3-required-unreadable",
                    "run3-required-type",
                }:
                    required_path = os.path.join(
                        fixture.report,
                        "run3",
                        "required.json",
                    )
                    os.makedirs(os.path.dirname(required_path), exist_ok=True)
                    with open(required_path, "w", encoding="utf-8") as output:
                        if case == "run3-required-unreadable":
                            output.write("{")
                        else:
                            json.dump({}, output)
                else:
                    args.driver = "other"
                returncode, stderr = _capture_stderr(
                    lambda: stages_mod.cmd_run3(
                        args,
                        drivers=fixture.drivers,
                        disk_min_gb=0.0,
                    )
                )
                got = (
                    returncode == (2 if case in {
                        "run3-prerequisite-invalid",
                        "run3-requested-refusal",
                    } else 1)
                    and bool(stderr)
                )
            else:
                fixture.prepare_final_inputs()
                required_path = os.path.join(
                    fixture.report,
                    "run3",
                    "required.json",
                )
                if case == "final-required-missing":
                    os.unlink(required_path)
                else:
                    with open(required_path, "w", encoding="utf-8") as output:
                        json.dump({}, output)
                got = (
                    stages_mod.cmd_final(
                        fixture.args(),
                        drivers=fixture.drivers,
                    )
                    == 1
                )
        return Observation(expected=True, got=got, applied=applied)

    with tempfile.TemporaryDirectory(prefix="iyi-runner-edge-") as root:
        if case == "attempts-missing":
            got = stages_mod._attempt_entries(
                os.path.join(root, "missing")
            ) == []
        elif case == "attempt-invalid":
            try:
                stages_mod._attempt_number(os.path.join(root, "invalid"))
            except ValueError:
                got = True
        elif case == "skip-malformed":
            hits = stages_mod._skip_hits(
                {
                    "driver": "stage",
                    "skips": [
                        7,
                        {"regex": 7},
                        {"regex": "[", "class": "tool", "what": "bad"},
                        {
                            "regex": "^hit$",
                            "class": "platform",
                            "what": "hit",
                        },
                    ],
                },
                "hit",
            )
            got = len(hits) == 1 and hits[0]["what"] == "hit"
        elif case == "baseline-census-type":
            census_dir = os.path.join(root, "proof", "census")
            os.makedirs(census_dir)
            with open(
                os.path.join(census_dir, "stage.json"),
                "w",
                encoding="utf-8",
            ) as output:
                json.dump([], output)
            try:
                stages_mod._baseline_skip_hits(
                    root,
                    "-- running sibling: std_stage_exercise.sh\n",
                )
            except ValueError:
                got = True
        elif case.startswith("rows-"):
            rows = os.path.join(root, "rows.jsonl")
            content = {
                "rows-blank": "\n{\"kind\":\"std\"}\n",
                "rows-json": "{\n",
                "rows-object": "[]\n",
            }[case]
            with open(rows, "w", encoding="utf-8") as output:
                output.write(content)
            if case == "rows-blank":
                got = stages_mod._read_run2_rows(rows) == [{"kind": "std"}]
            else:
                try:
                    stages_mod._read_run2_rows(rows)
                except ValueError:
                    got = True
        elif case.startswith("required-"):
            exclusions = os.path.join(root, "exclusions.json")
            run2 = os.path.join(root, "run2.jsonl")
            with open(run2, "w", encoding="utf-8") as output:
                output.write(
                    '{"p_nonzero":true}\n'
                    if case == "required-p-nonzero"
                    else "{}\n"
                )
            value = {
                "required-exclusions-type": {},
                "required-exclusions-entry": [7],
                "required-exclusions-program": [{}],
                "required-p-nonzero": [],
            }[case]
            with open(exclusions, "w", encoding="utf-8") as output:
                json.dump(value, output)
            try:
                stages_mod._compute_required_drivers(
                    ("stage",),
                    exclusions,
                    run2,
                )
            except ValueError:
                got = True
        elif case.startswith("baseline-"):
            value = {} if case == "baseline-type" else [7]
            try:
                stages_mod._baseline_keys(value)
            except ValueError:
                got = True
        elif case == "prerequisites-missing":
            got = stages_mod._run3_prerequisites(root) is None
        elif case == "record-missing":
            got = (
                stages_mod._validate_record(
                    None,
                    pin={"chain_id": "chain"},
                    unit="run1",
                    attempt=1,
                    kind="run1",
                )[0]
                == "FAIL"
            )
        elif case == "record-shape":
            status, reasons = stages_mod._validate_record(
                {
                    "v": 0,
                    "chain_id": "other",
                    "unit": "wrong",
                    "attempt": 2,
                    "status": "PASS",
                    "reasons": None,
                    "checks": {},
                    "started_ns": "bad",
                    "ended_ns": "bad",
                    "survivors": None,
                },
                pin={"chain_id": "chain"},
                unit="run1",
                attempt=1,
                kind="run1",
            )
            got = status == "FAIL" and len(reasons) >= 4
        elif case == "final-no-attempt":
            got = (
                stages_mod._collect_final_unit(
                    {"chain_id": "chain"},
                    os.path.join(root, "missing"),
                    "run1",
                    "run1",
                )[0]["status"]
                == "FAIL"
            )
        elif case == "latest-missing":
            got = stages_mod._latest_record(root, "missing") is None
        elif case == "latest-interrupt-missing":
            got = not stages_mod._latest_was_interrupted(root, "missing")
        else:
            raise ValueError(f"unknown isolated runner edge {case}")
    return Observation(expected=True, got=got, applied=applied)


def _runner_more_edge(case: str) -> Observation:
    applied = f"isolated runner edge={case}"
    got = False
    if case == "run1-baseline-error":
        with StageFixture() as fixture:
            fixture.pin()
            baseline_root = os.path.join(
                fixture.scratch,
                "baseline-root",
            )
            census_dir = os.path.join(
                baseline_root,
                "proof",
                "census",
            )
            os.makedirs(census_dir)
            with open(
                os.path.join(census_dir, "stage.json"),
                "w",
                encoding="utf-8",
            ) as output:
                json.dump([], output)
            returncode = stages_mod.cmd_run1(
                fixture.args(),
                disk_min_gb=0.0,
                baseline_w_path=baseline_root,
            )
            record = _stage_result(fixture.report, "run1")
            got = (
                returncode == 1
                and record.get("checks", {}).get("baseline-skips") == "FAIL"
            )
        return Observation(expected=True, got=got, applied=applied)

    if case in {"run3-setup-error", "run3-execution-error"}:
        with StageFixture() as fixture:
            pin = fixture.pin()
            path = os.path.join(
                fixture.scratch,
                "setup-file" if case == "run3-setup-error" else "driver-log",
            )
            if case == "run3-setup-error":
                with open(path, "w", encoding="utf-8") as output:
                    output.write("not a directory")
                setup_base = path
                driver_log_path = None
            else:
                os.makedirs(path)
                setup_base = None
                driver_log_path = path
            record = stages_mod._run_one_driver(
                fixture.report,
                pin,
                "stage",
                set(),
                driver_limit_sec=30.0,
                grace_sec=0.1,
                disk_min_gb=0.0,
                stat_fn=os.stat,
                setup_base=setup_base,
                driver_log_path=driver_log_path,
            )
            got = (
                record.get("status") == "FAIL"
                and record.get("checks", {}).get("exit") == "FAIL"
            )
        return Observation(expected=True, got=got, applied=applied)

    if case in {
        "run3-census-type",
        "run3-census-script-type",
        "run3-census-unreadable",
    }:
        with StageFixture() as fixture:
            pin = fixture.pin()
            census_path = os.path.join(
                fixture.w,
                "proof",
                "census",
                "stage.json",
            )
            census = _o7_load_json(census_path)
            with open(census_path, "w", encoding="utf-8") as output:
                if case == "run3-census-type":
                    json.dump([], output)
                elif case == "run3-census-script-type":
                    census["script"] = None
                    json.dump(census, output)
                else:
                    output.write("{")
            record = stages_mod._run_one_driver(
                fixture.report,
                pin,
                "stage",
                set(),
                driver_limit_sec=30.0,
                grace_sec=0.1,
                disk_min_gb=0.0,
                stat_fn=os.stat,
            )
            got = (
                record.get("status") == "FAIL"
                and record.get("checks", {}).get("census") == "FAIL"
            )
        return Observation(expected=True, got=got, applied=applied)

    if case == "run3-driver-nonzero":
        with StageFixture("driver-nonzero") as fixture:
            fixture.pin()
            fixture.write_prerequisites()
            returncode = stages_mod.cmd_run3(
                fixture.args(),
                drivers=fixture.drivers,
                driver_limit_sec=30.0,
                grace_sec=0.1,
                disk_min_gb=0.0,
            )
            record = _stage_result(fixture.report, "run3/stage")
            got = (
                returncode == 1
                and record.get("status") == "FAIL"
                and record.get("checks", {}).get("exit") == "FAIL"
            )
        return Observation(expected=True, got=got, applied=applied)

    if case in {
        "final-prerequisites-missing",
        "final-recompute-error",
    }:
        with StageFixture() as fixture:
            fixture.prepare_final_inputs()
            latest_run1 = stages_mod.latest_attempt_dir(
                os.path.join(fixture.report, "run1")
            )
            if case == "final-prerequisites-missing":
                os.unlink(
                    os.path.join(latest_run1, "baseline_skips.json")
                )
            else:
                with open(
                    os.path.join(latest_run1, "exclusions.json"),
                    "w",
                    encoding="utf-8",
                ) as output:
                    json.dump({}, output)
            returncode = stages_mod.cmd_final(
                fixture.args(),
                drivers=fixture.drivers,
            )
            final = _o7_load_json(
                os.path.join(fixture.report, "final.json")
            )
            fragment = (
                "are unavailable"
                if case == "final-prerequisites-missing"
                else "cannot be recomputed"
            )
            got = (
                returncode == 1
                and any(
                    fragment in str(reason)
                    for reason in final.get("reasons", [])
                )
            )
        return Observation(expected=True, got=got, applied=applied)

    if case in {"all-run1-stop", "all-run2-stop"}:
        scenario = "run2-stop" if case == "all-run2-stop" else "control"
        with StageFixture(scenario) as fixture:
            fixture.pin()
            returncode = stages_mod.cmd_all(
                fixture.args(),
                drivers=fixture.drivers,
                driver_limit_sec=30.0,
                grace_sec=0.1,
                disk_min_gb=(
                    2**60 if case == "all-run1-stop" else 0.0
                ),
            )
            got = returncode == 1
        return Observation(expected=True, got=got, applied=applied)

    if case in {
        "all-run3-refusal",
        "all-required-missing",
        "all-required-nonstr",
        "all-driver-stop",
    }:
        with StageFixture() as fixture:
            fixture.pin()
            args = fixture.args()
            required_path: str | None = None
            if case == "all-run3-refusal":
                args.driver = "other"
            elif case == "all-required-missing":
                required_path = os.path.join(
                    fixture.scratch,
                    "missing-required.json",
                )
            elif case == "all-required-nonstr":
                required_path = os.path.join(
                    fixture.scratch,
                    "nonstr-required.json",
                )
                with open(required_path, "w", encoding="utf-8") as output:
                    json.dump([7], output)
            def run_all() -> int:
                return stages_mod.cmd_all(
                    args,
                    drivers=fixture.drivers,
                    driver_limit_sec=30.0,
                    grace_sec=0.1,
                    disk_min_gb=0.0,
                    required_path=required_path,
                    run3_disk_min_gb=(
                        2**60 if case == "all-driver-stop" else None
                    ),
                )

            stderr_captured = True
            if case == "all-run3-refusal":
                returncode, stderr = _capture_stderr(run_all)
                stderr_captured = (
                    "REFUSED driver 'other' is not in required.json"
                    in stderr
                )
            else:
                returncode = run_all()
            expected_returncode = {
                "all-run3-refusal": 2,
                "all-driver-stop": 1,
            }.get(case, 0)
            got = (
                returncode == expected_returncode
                and stderr_captured
            )
        return Observation(expected=True, got=got, applied=applied)

    with tempfile.TemporaryDirectory(prefix="iyi-runner-more-") as root:
        checks = {
            name: "PASS"
            for name in proofkit_mod.REQUIRED_CHECKS[
                "run1" if case == "final-recorded-reason" else "run2"
            ]
        }
        checks[next(iter(checks))] = "FAIL"
        unit = "run1" if case == "final-recorded-reason" else "run2"
        parent = os.path.join(root, unit, "a1")
        os.makedirs(parent)
        record = {
            "v": 1,
            "chain_id": "c" * 32,
            "unit": unit,
            "attempt": 1,
            "status": "FAIL",
            "reasons": (
                ["fixture recorded reason"]
                if case == "final-recorded-reason"
                else []
            ),
            "checks": checks,
            "started_ns": 1,
            "ended_ns": 2,
            "survivors": [],
        }
        proofkit_mod.write_result(
            os.path.join(parent, "result.json"),
            record,
        )
        if case in {"final-recorded-reason", "final-status-reason"}:
            _latest, _earlier, reasons = stages_mod._collect_final_unit(
                {"chain_id": "c" * 32},
                os.path.join(root, unit),
                unit,
                "run1" if unit == "run1" else "run2",
            )
            got = bool(reasons)
        elif case == "latest-interrupted":
            record["unit"] = "run3/stage"
            record["reasons"] = ["interrupted by signal 2"]
            target = os.path.join(root, "run3", "stage", "a1")
            os.makedirs(target)
            proofkit_mod.write_result(
                os.path.join(target, "result.json"),
                record,
            )
            got = stages_mod._latest_was_interrupted(
                root,
                os.path.join("run3", "stage"),
            )
        else:
            raise ValueError(f"unknown runner-more edge {case}")
    return Observation(expected=True, got=got, applied=applied)


def _fixture_run1_gate_oserror(gate: int) -> Observation:
    scenario = "control" if gate in (1, 3) else f"gate{gate}-oserror"
    with StageFixture(scenario) as fixture:
        tool_dir = os.path.join(fixture.scratch, "gate-tools")
        os.makedirs(tool_dir)
        bash_source = ""
        for tool in (
            "bash",
            "git",
            "nm",
            "timeout",
            "getconf",
            "mktemp",
            "python3",
        ):
            source = shutil.which(tool)
            if not source:
                raise RuntimeError(f"{tool} unavailable for gate fixture")
            if tool == "bash":
                bash_source = source
            os.symlink(source, os.path.join(tool_dir, tool))
        original_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = tool_dir
            fixture.pin()
            rg9_work_path: str | None = None
            if gate == 3:
                rg9_work_path = os.path.join(
                    fixture.scratch,
                    "rg9-work-collision",
                )
                with open(rg9_work_path, "w", encoding="utf-8") as output:
                    output.write("existing path")
            restorer: threading.Thread | None = None
            if gate == 1:
                os.unlink(os.path.join(tool_dir, "bash"))
                def restore_bash() -> None:
                    gate_log = os.path.join(
                        fixture.report,
                        "run1",
                        "a1",
                        "run1_1.log",
                    )
                    while not os.path.exists(gate_log):
                        time.sleep(0.001)
                    time.sleep(0.01)
                    os.symlink(
                        bash_source,
                        os.path.join(tool_dir, "bash"),
                    )

                restorer = threading.Thread(target=restore_bash)
                restorer.start()
            returncode = stages_mod.cmd_run1(
                fixture.args(),
                disk_min_gb=0.0,
                rg9_work_path=rg9_work_path,
            )
            if restorer is not None:
                restorer.join()
        finally:
            os.environ["PATH"] = original_path
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "reason": any(
                f"gate 1.{gate} error:" in str(reason)
                for reason in result.get("reasons", [])
            ),
        }
    return Observation(
        expected={"returncode": 1, "status": "FAIL", "reason": True},
        got=got,
        applied=(
            "existing rg9_work file path"
            if gate == 3
            else f"removed gate {gate} executable prerequisite"
        ),
    )


def _fixture_run1_gate_interrupt(gate: int) -> Observation:
    scenario = f"interrupt-gate{gate}"
    with StageFixture(scenario) as fixture:
        fixture.pin()
        marker = os.path.join(
            fixture.report,
            "run1",
            "a1",
            f"run1_{gate}.tmp",
            "interrupt-ready",
        )
        marker_seen = threading.Event()

        def send_term() -> None:
            for _ in range(500):
                if os.path.isfile(marker):
                    marker_seen.set()
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                time.sleep(0.01)

        sender = threading.Thread(target=send_term)
        sender.start()
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        sender.join()
        result = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": result.get("status"),
            "reason": f"interrupted by signal {signal.SIGTERM}"
            in result.get("reasons", []),
            "marker": marker_seen.is_set(),
        }
    return Observation(
        expected={
            "returncode": 1,
            "status": "FAIL",
            "reason": True,
            "marker": True,
        },
        got=got,
        applied=f"SIGTERM delivered during gate 1.{gate}",
    )


def _fixture_run2_interrupt_edge() -> Observation:
    with StageFixture("run2-interrupt") as fixture:
        fixture.pin()
        marker = os.path.join(
            fixture.report,
            "run2",
            "a1",
            "run2.tmp",
            "interrupt-ready",
        )
        seen = threading.Event()

        def send_term() -> None:
            for _ in range(500):
                if os.path.isfile(marker):
                    seen.set()
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                time.sleep(0.01)

        sender = threading.Thread(target=send_term)
        sender.start()
        returncode = stages_mod.cmd_run2(
            fixture.args(),
            disk_min_gb=0.0,
        )
        sender.join()
        record = _stage_result(fixture.report, "run2")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "legs": record.get("checks", {}).get("legs"),
            "reason": f"interrupted by signal {signal.SIGTERM}"
            in record.get("reasons", []),
            "marker": seen.is_set(),
        }
    return Observation(
        expected={
            "returncode": 1,
            "status": "FAIL",
            "legs": "FAIL",
            "reason": True,
            "marker": True,
        },
        got=got,
        applied="SIGTERM delivered during Run 2 artifact process",
    )


def _fixture_run3_interrupt_edge() -> Observation:
    with StageFixture("driver-interrupt") as fixture:
        fixture.pin()
        fixture.write_prerequisites()
        marker = os.path.join(
            fixture.report,
            "run3",
            "stage",
            "a1",
            "t",
            "interrupt-ready",
        )
        seen = threading.Event()

        def send_term() -> None:
            for _ in range(500):
                if os.path.isfile(marker):
                    seen.set()
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                time.sleep(0.01)

        sender = threading.Thread(target=send_term)
        sender.start()
        returncode = stages_mod.cmd_run3(
            fixture.args(),
            drivers=fixture.drivers,
            driver_limit_sec=30.0,
            grace_sec=0.1,
            disk_min_gb=0.0,
        )
        sender.join()
        record = _stage_result(fixture.report, "run3/stage")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "exit": record.get("checks", {}).get("exit"),
            "reason": f"interrupted by signal {signal.SIGTERM}"
            in record.get("reasons", []),
            "marker": seen.is_set(),
        }
    return Observation(
        expected={
            "returncode": 1,
            "status": "FAIL",
            "exit": "FAIL",
            "reason": True,
            "marker": True,
        },
        got=got,
        applied="SIGTERM delivered during Run 3 driver",
    )


def _fixture_run1_post_gate_identity(gate: int) -> Observation:
    with StageFixture(f"gate{gate}-identity") as fixture:
        fixture.pin()
        returncode = stages_mod.cmd_run1(
            fixture.args(),
            disk_min_gb=0.0,
        )
        record = _stage_result(fixture.report, "run1")
        got = {
            "returncode": returncode,
            "status": record.get("status"),
            "identity": record.get("checks", {}).get("identity"),
            "reason": any(
                "COMPILER-MTIME-CHANGED" in str(reason)
                for reason in record.get("reasons", [])
            ),
        }
    return Observation(
        expected={
            "returncode": 1,
            "status": "INVALID",
            "identity": "INVALID",
            "reason": True,
        },
        got=got,
        applied=f"compiler mtime changed after gate 1.{gate}",
    )


O7_FIXTURES: tuple[Fixture, ...] = (
    Fixture("o7.seed.rp2-run1-baseline-error", "seed", partial(_runner_more_edge, "run1-baseline-error")),
    Fixture("o7.seed.rp2-run3-setup-error", "seed", partial(_runner_more_edge, "run3-setup-error")),
    Fixture("o7.seed.rp2-run3-execution-error", "seed", partial(_runner_more_edge, "run3-execution-error")),
    Fixture("o7.seed.rp2-run3-census-type", "seed", partial(_runner_more_edge, "run3-census-type")),
    Fixture("o7.seed.rp2-run3-census-script-type", "seed", partial(_runner_more_edge, "run3-census-script-type")),
    Fixture("o7.seed.rp2-run3-census-unreadable", "seed", partial(_runner_more_edge, "run3-census-unreadable")),
    Fixture("o7.seed.rp2-run3-driver-nonzero", "seed", partial(_runner_more_edge, "run3-driver-nonzero")),
    Fixture("o7.seed.rp2-final-recorded-reason", "seed", partial(_runner_more_edge, "final-recorded-reason")),
    Fixture("o7.seed.rp2-final-status-reason", "seed", partial(_runner_more_edge, "final-status-reason")),
    Fixture("o7.seed.rp2-final-prerequisites-missing", "seed", partial(_runner_more_edge, "final-prerequisites-missing")),
    Fixture("o7.seed.rp2-final-recompute-error", "seed", partial(_runner_more_edge, "final-recompute-error")),
    Fixture("o7.seed.rp2-latest-interrupted", "seed", partial(_runner_more_edge, "latest-interrupted")),
    Fixture("o7.seed.rp2-all-run1-stop", "seed", partial(_runner_more_edge, "all-run1-stop")),
    Fixture("o7.seed.rp2-all-run2-stop", "seed", partial(_runner_more_edge, "all-run2-stop")),
    Fixture("o7.seed.rp2-all-run3-refusal", "seed", partial(_runner_more_edge, "all-run3-refusal")),
    Fixture("o7.seed.rp2-all-required-missing", "seed", partial(_runner_more_edge, "all-required-missing")),
    Fixture("o7.seed.rp2-all-required-nonstr", "seed", partial(_runner_more_edge, "all-required-nonstr")),
    Fixture("o7.seed.rp2-all-driver-stop", "seed", partial(_runner_more_edge, "all-driver-stop")),
    Fixture("o7.seed.rp-gate1-post-identity", "seed", partial(_fixture_run1_post_gate_identity, 1)),
    Fixture("o7.seed.rp-gate2-post-identity", "seed", partial(_fixture_run1_post_gate_identity, 2)),
    Fixture("o7.seed.rp-gate3-post-identity", "seed", partial(_fixture_run1_post_gate_identity, 3)),
    Fixture("o7.seed.rp-gate4-post-identity", "seed", partial(_fixture_run1_post_gate_identity, 4)),
    Fixture("o7.seed.rp-run2-interrupt", "seed", _fixture_run2_interrupt_edge),
    Fixture("o7.seed.rp-run3-interrupt", "seed", _fixture_run3_interrupt_edge),
    Fixture("o7.seed.rp-gate1-oserror", "seed", partial(_fixture_run1_gate_oserror, 1)),
    Fixture("o7.seed.rp-gate2-oserror", "seed", partial(_fixture_run1_gate_oserror, 2)),
    Fixture("o7.seed.rp-gate3-oserror", "seed", partial(_fixture_run1_gate_oserror, 3)),
    Fixture("o7.seed.rp-gate4-oserror", "seed", partial(_fixture_run1_gate_oserror, 4)),
    Fixture("o7.seed.rp-gate2-interrupt", "seed", partial(_fixture_run1_gate_interrupt, 2)),
    Fixture("o7.seed.rp-gate3-interrupt", "seed", partial(_fixture_run1_gate_interrupt, 3)),
    Fixture("o7.seed.rp-gate4-interrupt", "seed", partial(_fixture_run1_gate_interrupt, 4)),
    Fixture("o7.seed.pk2-census-validate-mismatch", "seed", partial(_proofkit_more_edge, "census-validate-mismatch")),
    Fixture("o7.seed.pk2-census-shas-missing", "seed", partial(_proofkit_more_edge, "census-shas-missing")),
    Fixture("o7.seed.pk2-inspect-git-error", "seed", partial(_proofkit_more_edge, "inspect-git-error")),
    Fixture("o7.seed.pk2-inspect-compiler-missing", "seed", partial(_proofkit_more_edge, "inspect-compiler-missing")),
    Fixture("o7.seed.pk2-pin-write-probe", "seed", partial(_proofkit_more_edge, "pin-write-probe")),
    Fixture("o7.seed.pk2-pin-write-probe-dirty", "seed", partial(_proofkit_more_edge, "pin-write-probe-dirty")),
    Fixture("o7.seed.pk2-inspect-diff-error", "seed", partial(_proofkit_more_edge, "inspect-diff-error")),
    Fixture("o7.seed.pk2-inspect-compiler-stat", "seed", partial(_proofkit_more_edge, "inspect-compiler-stat")),
    Fixture("o7.seed.pk2-inspect-no-nm", "seed", partial(_proofkit_more_edge, "inspect-no-nm")),
    Fixture("o7.seed.pk2-pin-write-type", "seed", partial(_proofkit_more_edge, "pin-write-type")),
    Fixture("o7.seed.pk2-pin-write-dirty", "seed", partial(_proofkit_more_edge, "pin-write-dirty")),
    Fixture("o7.seed.pk2-identity-git-error", "seed", partial(_proofkit_more_edge, "identity-git-error")),
    Fixture("o7.seed.pk2-identity-compiler-stat", "seed", partial(_proofkit_more_edge, "identity-compiler-stat")),
    Fixture("o7.seed.pk2-schema-missing-key", "seed", partial(_proofkit_more_edge, "schema-missing-key")),
    Fixture("o7.seed.pk2-schema-skip-unrenderable", "seed", partial(_proofkit_more_edge, "schema-skip-unrenderable")),
    Fixture("o7.seed.pk2-schema-sentinel-unrenderable", "seed", partial(_proofkit_more_edge, "schema-sentinel-unrenderable")),
    Fixture("o7.seed.pk2-parser-shlex-error", "seed", partial(_proofkit_more_edge, "parser-shlex-error")),
    Fixture("o7.seed.pk2-parser-literal-dollar", "seed", partial(_proofkit_more_edge, "parser-literal-dollar")),
    Fixture("o7.seed.pk2-parser-render-command", "seed", partial(_proofkit_more_edge, "parser-render-command")),
    Fixture("o7.seed.pk2-parser-backtick-unclosed", "seed", partial(_proofkit_more_edge, "parser-backtick-unclosed")),
    Fixture("o7.seed.pk2-parser-nested-expansion", "seed", partial(_proofkit_more_edge, "parser-nested-expansion")),
    Fixture("o7.seed.pk2-parser-nested-command-open", "seed", partial(_proofkit_more_edge, "parser-nested-command-open")),
    Fixture("o7.seed.pk2-parser-nested-backtick-open", "seed", partial(_proofkit_more_edge, "parser-nested-backtick-open")),
    Fixture("o7.seed.pk2-parser-unquoted-backtick", "seed", partial(_proofkit_more_edge, "parser-unquoted-backtick")),
    Fixture("o7.seed.pk2-parser-unquoted-backtick-open", "seed", partial(_proofkit_more_edge, "parser-unquoted-backtick-open")),
    Fixture("o7.seed.pk2-parser-dequote-expansion-open", "seed", partial(_proofkit_more_edge, "parser-dequote-expansion-open")),
    Fixture("o7.seed.pk2-identity-not-descendant", "seed", partial(_proofkit_more_edge, "identity-not-descendant")),
    Fixture("o7.seed.pk2-identity-no-timeout", "seed", partial(_proofkit_more_edge, "identity-no-timeout")),
    Fixture("o7.seed.pk2-identity-no-nm", "seed", partial(_proofkit_more_edge, "identity-no-nm")),
    Fixture("o7.seed.pk2-report-chain-invalid", "seed", partial(_proofkit_more_edge, "report-chain-invalid")),
    Fixture("o7.seed.pk2-report-chain-mismatch", "seed", partial(_proofkit_more_edge, "report-chain-mismatch")),
    Fixture("o7.seed.pk2-report-listdir", "seed", partial(_proofkit_more_edge, "report-listdir")),
    Fixture("o7.seed.pk2-process-wait", "seed", partial(_proofkit_more_edge, "process-wait")),
    Fixture("o7.seed.pk2-process-stop", "seed", partial(_proofkit_more_edge, "process-stop")),
    Fixture("o7.seed.pk2-process-leader-survives", "seed", partial(_proofkit_more_edge, "process-leader-survives")),
    Fixture("o7.seed.pk2-process-zombie-remains", "seed", partial(_proofkit_more_edge, "process-zombie-remains")),
    Fixture("o7.seed.pk2-process-finally-stop", "seed", partial(_proofkit_more_edge, "process-finally-stop")),
    Fixture("o7.seed.pk2-process-residual-zombie", "seed", partial(_proofkit_more_edge, "process-residual-zombie")),
    Fixture("o7.seed.pk2-process-parse", "seed", partial(_proofkit_more_edge, "process-parse")),
    Fixture("o7.seed.pk2-process-ps-status", "seed", partial(_proofkit_more_edge, "process-ps-status")),
    Fixture("o7.seed.pk2-run-bounded-sampler-error", "seed", partial(_proofkit_more_edge, "run-bounded-sampler-error")),
    Fixture("o7.seed.pk2-validator-env-unchanged", "seed", partial(_proofkit_more_edge, "validator-env-unchanged")),
    Fixture("o7.seed.pk2-schema-nonobject", "seed", partial(_proofkit_more_edge, "schema-nonobject")),
    Fixture("o7.seed.pk2-schema-bytes", "seed", partial(_proofkit_more_edge, "schema-bytes")),
    Fixture("o7.seed.pk2-schema-path", "seed", partial(_proofkit_more_edge, "schema-path")),
    Fixture("o7.seed.pk2-schema-duplicate-variant", "seed", partial(_proofkit_more_edge, "schema-duplicate-variant")),
    Fixture("o7.seed.pk2-schema-duplicate-skip", "seed", partial(_proofkit_more_edge, "schema-duplicate-skip")),
    Fixture("o7.seed.pk2-schema-sentinel-iyivar", "seed", partial(_proofkit_more_edge, "schema-sentinel-iyivar")),
    Fixture("o7.seed.pk2-parser-command-open", "seed", partial(_proofkit_more_edge, "parser-command-open")),
    Fixture("o7.seed.pk2-parser-backtick-open", "seed", partial(_proofkit_more_edge, "parser-backtick-open")),
    Fixture("o7.seed.pk2-parser-echo-option", "seed", partial(_proofkit_more_edge, "parser-echo-option")),
    Fixture("o7.seed.pk2-parser-printf-option", "seed", partial(_proofkit_more_edge, "parser-printf-option")),
    Fixture("o7.seed.pk2-parser-template-brace", "seed", partial(_proofkit_more_edge, "parser-template-brace")),
    Fixture("o7.seed.rp-run1-missing-gate1", "seed", partial(_runner_isolated_edge, "run1-missing-gate1")),
    Fixture("o7.seed.rp-run1-missing-gate2", "seed", partial(_runner_isolated_edge, "run1-missing-gate2")),
    Fixture("o7.seed.rp-run1-missing-gate3", "seed", partial(_runner_isolated_edge, "run1-missing-gate3")),
    Fixture("o7.seed.rp-run1-missing-gate4", "seed", partial(_runner_isolated_edge, "run1-missing-gate4")),
    Fixture("o7.seed.rp-run3-prerequisite-invalid", "seed", partial(_runner_isolated_edge, "run3-prerequisite-invalid")),
    Fixture("o7.seed.rp-run3-required-unreadable", "seed", partial(_runner_isolated_edge, "run3-required-unreadable")),
    Fixture("o7.seed.rp-run3-required-type", "seed", partial(_runner_isolated_edge, "run3-required-type")),
    Fixture("o7.seed.rp-run3-requested-refusal", "seed", partial(_runner_isolated_edge, "run3-requested-refusal")),
    Fixture("o7.seed.rp-final-required-missing", "seed", partial(_runner_isolated_edge, "final-required-missing")),
    Fixture("o7.seed.rp-final-required-type", "seed", partial(_runner_isolated_edge, "final-required-type")),
    Fixture("o7.seed.rp-attempts-missing", "seed", partial(_runner_isolated_edge, "attempts-missing")),
    Fixture("o7.seed.rp-attempt-invalid", "seed", partial(_runner_isolated_edge, "attempt-invalid")),
    Fixture("o7.seed.rp-skip-malformed", "seed", partial(_runner_isolated_edge, "skip-malformed")),
    Fixture("o7.seed.rp-baseline-census-type", "seed", partial(_runner_isolated_edge, "baseline-census-type")),
    Fixture("o7.seed.rp-rows-blank", "seed", partial(_runner_isolated_edge, "rows-blank")),
    Fixture("o7.seed.rp-rows-json", "seed", partial(_runner_isolated_edge, "rows-json")),
    Fixture("o7.seed.rp-rows-object", "seed", partial(_runner_isolated_edge, "rows-object")),
    Fixture("o7.seed.rp-required-exclusions-type", "seed", partial(_runner_isolated_edge, "required-exclusions-type")),
    Fixture("o7.seed.rp-required-exclusions-entry", "seed", partial(_runner_isolated_edge, "required-exclusions-entry")),
    Fixture("o7.seed.rp-required-exclusions-program", "seed", partial(_runner_isolated_edge, "required-exclusions-program")),
    Fixture("o7.seed.rp-required-p-nonzero", "seed", partial(_runner_isolated_edge, "required-p-nonzero")),
    Fixture("o7.seed.rp-baseline-type", "seed", partial(_runner_isolated_edge, "baseline-type")),
    Fixture("o7.seed.rp-baseline-entry", "seed", partial(_runner_isolated_edge, "baseline-entry")),
    Fixture("o7.seed.rp-prerequisites-missing", "seed", partial(_runner_isolated_edge, "prerequisites-missing")),
    Fixture("o7.seed.rp-record-missing", "seed", partial(_runner_isolated_edge, "record-missing")),
    Fixture("o7.seed.rp-record-shape", "seed", partial(_runner_isolated_edge, "record-shape")),
    Fixture("o7.seed.rp-final-no-attempt", "seed", partial(_runner_isolated_edge, "final-no-attempt")),
    Fixture("o7.seed.rp-latest-missing", "seed", partial(_runner_isolated_edge, "latest-missing")),
    Fixture("o7.seed.rp-latest-interrupt-missing", "seed", partial(_runner_isolated_edge, "latest-interrupt-missing")),
    Fixture("o7.seed.pk-git-error", "seed", partial(_proofkit_isolated_edge, "git-error")),
    Fixture("o7.seed.pk-platform-getconf-missing", "seed", partial(_proofkit_isolated_edge, "platform-getconf-missing")),
    Fixture("o7.seed.pk-platform-getconf-oserror", "seed", partial(_proofkit_isolated_edge, "platform-getconf-oserror")),
    Fixture("o7.seed.pk-platform-getconf-status", "seed", partial(_proofkit_isolated_edge, "platform-getconf-status")),
    Fixture("o7.seed.pk-platform-getconf-nondir", "seed", partial(_proofkit_isolated_edge, "platform-getconf-nondir")),
    Fixture("o7.seed.pk-platform-mktemp-missing", "seed", partial(_proofkit_isolated_edge, "platform-mktemp-missing")),
    Fixture("o7.seed.pk-platform-mktemp-oserror", "seed", partial(_proofkit_isolated_edge, "platform-mktemp-oserror")),
    Fixture("o7.seed.pk-platform-mktemp-status", "seed", partial(_proofkit_isolated_edge, "platform-mktemp-status")),
    Fixture("o7.seed.pk-platform-mktemp-nondir", "seed", partial(_proofkit_isolated_edge, "platform-mktemp-nondir")),
    Fixture("o7.seed.pk-compiler-env", "seed", partial(_proofkit_isolated_edge, "compiler-env")),
    Fixture("o7.seed.pk-roots-empty", "seed", partial(_proofkit_isolated_edge, "roots-empty")),
    Fixture("o7.seed.pk-probe-atime-retention", "seed", partial(_proofkit_isolated_edge, "probe-atime-retention")),
    Fixture("o7.seed.pk-probe-exec-failure", "seed", partial(_proofkit_isolated_edge, "probe-exec-failure")),
    Fixture("o7.seed.pk-probe-sha", "seed", partial(_proofkit_isolated_edge, "probe-sha")),
    Fixture("o7.seed.pk-probe-inode", "seed", partial(_proofkit_isolated_edge, "probe-inode")),
    Fixture("o7.seed.pk-probe-oserror", "seed", partial(_proofkit_isolated_edge, "probe-oserror")),
    Fixture("o7.seed.pk-first-output", "seed", partial(_proofkit_isolated_edge, "first-output")),
    Fixture("o7.seed.pk-nm-output", "seed", partial(_proofkit_isolated_edge, "nm-output")),
    Fixture("o7.seed.pk-census-set", "seed", partial(_proofkit_isolated_edge, "census-set")),
    Fixture("o7.seed.pk-census-invalid", "seed", partial(_proofkit_isolated_edge, "census-invalid")),
    Fixture("o7.seed.pk-census-shas-set", "seed", partial(_proofkit_isolated_edge, "census-shas-set")),
    Fixture("o7.seed.pk-pin-load-invalid", "seed", partial(_proofkit_isolated_edge, "pin-load-invalid")),
    Fixture("o7.seed.pk-pin-load-chain", "seed", partial(_proofkit_isolated_edge, "pin-load-chain")),
    Fixture("o7.seed.pk-pin-load-report", "seed", partial(_proofkit_isolated_edge, "pin-load-report")),
    Fixture("o7.seed.pk-identity-p-dirty", "seed", partial(_proofkit_isolated_edge, "identity-p-dirty")),
    Fixture("o7.seed.pk-identity-w-dirty", "seed", partial(_proofkit_isolated_edge, "identity-w-dirty")),
    Fixture("o7.seed.pk-identity-product-diff", "seed", partial(_proofkit_isolated_edge, "identity-product-diff")),
    Fixture("o7.seed.pk-identity-compiler-missing", "seed", partial(_proofkit_isolated_edge, "identity-compiler-missing")),
    Fixture("o7.seed.pk-identity-stamp-missing", "seed", partial(_proofkit_isolated_edge, "identity-stamp-missing")),
    Fixture("o7.seed.pk-signal-missing", "seed", partial(_proofkit_isolated_edge, "signal-missing")),
    Fixture("o7.seed.pk-sampler-oserror", "seed", partial(_proofkit_isolated_edge, "sampler-oserror")),
    Fixture("o7.seed.pk-limit-invalid", "seed", partial(_proofkit_isolated_edge, "limit-invalid")),
    Fixture("o7.seed.pk-grace-invalid", "seed", partial(_proofkit_isolated_edge, "grace-invalid")),
    Fixture("o7.seed.pk-status-unknown", "seed", partial(_proofkit_isolated_edge, "status-unknown")),
    Fixture("o7.seed.pk-status-missing", "seed", partial(_proofkit_isolated_edge, "status-missing")),
    Fixture("o7.seed.pk-parser-backtick", "seed", partial(_proofkit_isolated_edge, "parser-backtick")),
    Fixture("o7.seed.pk-parser-trailing-dollar", "seed", partial(_proofkit_isolated_edge, "parser-trailing-dollar")),
    Fixture("o7.seed.pk-parser-open-brace", "seed", partial(_proofkit_isolated_edge, "parser-open-brace")),
    Fixture("o7.seed.pk-parser-nested-command", "seed", partial(_proofkit_isolated_edge, "parser-nested-command")),
    Fixture("o7.seed.pk-parser-nested-backtick", "seed", partial(_proofkit_isolated_edge, "parser-nested-backtick")),
    Fixture("o7.seed.pk-parser-dequote", "seed", partial(_proofkit_isolated_edge, "parser-dequote")),
    Fixture("o7.seed.pk-parser-render", "seed", partial(_proofkit_isolated_edge, "parser-render")),
    Fixture(
        "o7.seed.validator-env-call-variant",
        "seed",
        _fixture_validator_env_call_seed,
    ),
    Fixture(
        "o7.seed.validator-iyivar",
        "seed",
        _fixture_validator_iyivar_seed,
    ),
    Fixture(
        "o7.seed.validator-platform-guard",
        "seed",
        _fixture_validator_platform_guard_seed,
    ),
    Fixture(
        "o7.seed.final-required-rerun",
        "seed",
        _fixture_final_required_rerun_seed,
    ),
    Fixture(
        "o7.seed.guard-m01-python-realpath",
        "seed",
        partial(_fixture_identity_field_guard, "m01", True),
    ),
    Fixture(
        "o7.control.guard-m01-python-realpath",
        "control",
        partial(_fixture_identity_field_guard, "m01", False),
    ),
    Fixture(
        "o7.seed.guard-m02-census-changed",
        "seed",
        partial(_fixture_identity_field_guard, "m02", True),
    ),
    Fixture(
        "o7.control.guard-m02-census-changed",
        "control",
        partial(_fixture_identity_field_guard, "m02", False),
    ),
    Fixture(
        "o7.seed.guard-m03-canonical-roots",
        "seed",
        partial(_fixture_identity_field_guard, "m03", True),
    ),
    Fixture(
        "o7.control.guard-m03-canonical-roots",
        "control",
        partial(_fixture_identity_field_guard, "m03", False),
    ),
    Fixture(
        "o7.seed.guard-m04-timeout-realpath",
        "seed",
        partial(_fixture_identity_field_guard, "m04", True),
    ),
    Fixture(
        "o7.control.guard-m04-timeout-realpath",
        "control",
        partial(_fixture_identity_field_guard, "m04", False),
    ),
    Fixture(
        "o7.seed.guard-m05-nm-realpath",
        "seed",
        partial(_fixture_identity_field_guard, "m05", True),
    ),
    Fixture(
        "o7.control.guard-m05-nm-realpath",
        "control",
        partial(_fixture_identity_field_guard, "m05", False),
    ),
    Fixture(
        "o7.seed.guard-m19-python-version",
        "seed",
        partial(_fixture_identity_field_guard, "m19", True),
    ),
    Fixture(
        "o7.control.guard-m19-python-version",
        "control",
        partial(_fixture_identity_field_guard, "m19", False),
    ),
    Fixture(
        "o7.seed.guard-m08-run3-disk",
        "seed",
        partial(_fixture_run3_disk_guard, True),
    ),
    Fixture(
        "o7.control.guard-m08-run3-disk",
        "control",
        partial(_fixture_run3_disk_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m10-post-driver-identity",
        "seed",
        partial(_fixture_post_driver_identity_guard, True),
    ),
    Fixture(
        "o7.control.guard-m10-post-driver-identity",
        "control",
        partial(_fixture_post_driver_identity_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m11-final-identity",
        "seed",
        partial(_fixture_final_identity_guard, True),
    ),
    Fixture(
        "o7.control.guard-m11-final-identity",
        "control",
        partial(_fixture_final_identity_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m12-final-unit",
        "seed",
        partial(_fixture_final_binding_guard, "unit", True),
    ),
    Fixture(
        "o7.control.guard-m12-final-unit",
        "control",
        partial(_fixture_final_binding_guard, "unit", False),
    ),
    Fixture(
        "o7.seed.guard-m13-final-attempt",
        "seed",
        partial(_fixture_final_binding_guard, "attempt", True),
    ),
    Fixture(
        "o7.control.guard-m13-final-attempt",
        "control",
        partial(_fixture_final_binding_guard, "attempt", False),
    ),
    Fixture(
        "o7.seed.guard-m20-final-required",
        "seed",
        partial(_fixture_final_required_guard, True),
    ),
    Fixture(
        "o7.control.guard-m20-final-required",
        "control",
        partial(_fixture_final_required_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m07-run3-no-refused",
        "seed",
        partial(_fixture_run3_refused_guard, True),
    ),
    Fixture(
        "o7.control.guard-m07-run3-no-refused",
        "control",
        partial(_fixture_run3_refused_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m09-run3-census",
        "seed",
        partial(_fixture_run3_census_guard, True),
    ),
    Fixture(
        "o7.control.guard-m09-run3-census",
        "control",
        partial(_fixture_run3_census_guard, False),
    ),
    Fixture(
        "o7.seed.guard-m14-baseline-header",
        "seed",
        partial(_fixture_baseline_header_guard, True),
    ),
    Fixture(
        "o7.control.guard-m14-baseline-header",
        "control",
        partial(_fixture_baseline_header_guard, False),
    ),
    Fixture(
        "s5.control.stage-chain",
        "control",
        _fixture_stage_chain_control,
    ),
    Fixture(
        "o7.control.matcher-platform-work",
        "control",
        partial(_o4_matcher_fixture, "platform-root"),
    ),
    Fixture(
        "o7.control.matcher-t-work",
        "control",
        partial(_o4_matcher_fixture, "t-null"),
    ),
    Fixture(
        "o7.seed.matcher-platform-two-level",
        "seed",
        partial(_o4_matcher_fixture, "platform-two-level"),
    ),
    Fixture(
        "o7.seed.matcher-t-two-level",
        "seed",
        partial(_o4_matcher_fixture, "t-two-level"),
    ),
    Fixture(
        "o7.seed.matcher-outside-both",
        "seed",
        partial(_o4_matcher_fixture, "outside-attempt"),
    ),
    Fixture(
        "o7.seed.platform-tmp-changed",
        "seed",
        _fixture_platform_tmp_changed_seed,
    ),
    Fixture(
        "o7.seed.platform-tmp-probe",
        "seed",
        _fixture_platform_tmp_probe_seed,
    ),
    Fixture(
        "o7.control.all",
        "control",
        _fixture_all_control,
    ),
    Fixture(
        "o7.control.pin-command",
        "control",
        _fixture_pin_command_control,
    ),
    Fixture(
        "o7.seed.shim-parser-edges",
        "seed",
        _fixture_shim_parser_edges_seed,
    ),
    Fixture(
        "o7.seed.artifact-session-kill",
        "seed",
        _fixture_artifact_session_kill_seed,
    ),
    Fixture(
        "o7.seed.main-identity-refusal",
        "seed",
        _fixture_main_identity_refusal_seed,
    ),
    Fixture(
        "o7.control.run1",
        "control",
        _fixture_run1_control,
    ),
    Fixture(
        "s5.seed.run1-slow-gate",
        "seed",
        _fixture_run1_slow_gate_seed,
    ),
    Fixture(
        "o7.seed.coverage-run1-gate1-fail",
        "seed",
        _fixture_gate1_fail_seed,
    ),
    Fixture(
        "o7.seed.coverage-run1-identity",
        "seed",
        _fixture_run1_identity_seed,
    ),
    Fixture(
        "o7.seed.coverage-run1-disk",
        "seed",
        _fixture_run1_disk_seed,
    ),
    Fixture(
        "s5.seed.rg2r-zero",
        "seed",
        _fixture_rg2r_zero_seed,
    ),
    Fixture(
        "s5.seed.exclusions-wrong-location",
        "seed",
        _fixture_exclusions_wrong_location_seed,
    ),
    Fixture(
        "s5.seed.run1-missing-sentinel",
        "seed",
        _fixture_run1_missing_sentinel_seed,
    ),
    Fixture(
        "s5.seed.rg9-140",
        "seed",
        _fixture_rg9_140_seed,
    ),
    Fixture(
        "s5.seed.sibling-count-114",
        "seed",
        _fixture_sibling_count_114_seed,
    ),
    Fixture(
        "s5.seed.sample-exclusion",
        "seed",
        _fixture_sample_exclusion_seed,
    ),
    Fixture(
        "s5.seed.std-exclusion",
        "seed",
        _fixture_std_exclusion_seed,
    ),
    Fixture(
        "s5.seed.p-nonzero-not-added",
        "seed",
        _fixture_p_nonzero_not_added_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-identity",
        "seed",
        _fixture_run2_identity_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-disk",
        "seed",
        _fixture_run2_disk_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-stop",
        "seed",
        _fixture_run2_stop_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-fail",
        "seed",
        _fixture_run2_fail_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-count",
        "seed",
        _fixture_run2_count_seed,
    ),
    Fixture(
        "o7.seed.coverage-run2-missing-report",
        "seed",
        _fixture_run2_missing_report_seed,
    ),
    Fixture(
        "o7.control.run3-prerequisite",
        "control",
        _fixture_run3_prerequisite_control,
    ),
    Fixture(
        "s5.seed.run3-missing-prerequisite",
        "seed",
        _fixture_run3_missing_prerequisite_seed,
    ),
    Fixture(
        "o7.control.required-selection",
        "control",
        _fixture_required_match_control,
    ),
    Fixture(
        "s5.seed.required-mismatch",
        "seed",
        _fixture_required_mismatch_seed,
    ),
    Fixture(
        "s5.seed.binary-changed",
        "seed",
        _fixture_binary_changed_seed,
    ),
    Fixture(
        "s5.seed.run3-import",
        "seed",
        _fixture_run3_import_seed,
    ),
    Fixture(
        "s5.seed.run3-driver-timeout",
        "seed",
        _fixture_run3_timeout_seed,
    ),
    Fixture(
        "s5.seed.skip-env-blocked",
        "seed",
        _fixture_skip_env_blocked_seed,
    ),
    Fixture(
        "s5.seed.skip-partial",
        "seed",
        _fixture_skip_partial_seed,
    ),
    Fixture(
        "s5.seed.skip-platform",
        "seed",
        _fixture_skip_platform_seed,
    ),
    Fixture(
        "s5.seed.driver-missing-sentinel",
        "seed",
        _fixture_driver_missing_sentinel_seed,
    ),
    Fixture(
        "s5.seed.driver-stale-ledger",
        "seed",
        _fixture_driver_stale_ledger_seed,
    ),
    Fixture(
        "s5.seed.census-missing-continues",
        "seed",
        _fixture_census_missing_continues_seed,
    ),
    Fixture(
        "s5.seed.driver-missing-continues",
        "seed",
        _fixture_driver_missing_continues_seed,
    ),
    Fixture(
        "o7.control.route-a",
        "control",
        _fixture_route_a_control,
    ),
    Fixture(
        "s5.seed.route-a-drivers",
        "seed",
        _fixture_route_a_drivers_seed,
    ),
    Fixture(
        "s5.seed.final-forged-pass",
        "seed",
        _fixture_final_forged_pass_seed,
    ),
    Fixture(
        "s5.seed.final-missing-result",
        "seed",
        _fixture_final_missing_result_seed,
    ),
    Fixture(
        "s5.seed.final-chain-mismatch",
        "seed",
        _fixture_final_chain_mismatch_seed,
    ),
    Fixture(
        "s5.seed.final-earlier-failure-omitted",
        "seed",
        _fixture_final_earlier_failure_seed,
    ),
    Fixture(
        "o7.control.run-proof-optimize",
        "control",
        _fixture_run_proof_optimize_control,
    ),
    Fixture(
        "o7.seed.run-proof-optimize-refusal",
        "seed",
        _fixture_run_proof_optimize_seed,
    ),
    Fixture(
        "o7.seed.d4-stage-interrupt",
        "seed",
        _fixture_d4_stage_interrupt_seed,
    ),
)

O7_REVIEW_ITEMS: dict[str, tuple[str, ...]] = {
    "o7.run1-gate-isolated-edges": (
        "o7.seed.rp-run2-interrupt",
        "o7.seed.rp-run3-interrupt",
        "o7.seed.rp-gate1-post-identity",
        "o7.seed.rp-gate2-post-identity",
        "o7.seed.rp-gate3-post-identity",
        "o7.seed.rp-gate4-post-identity",
        "o7.seed.rp-gate1-oserror",
        "o7.seed.rp-gate2-oserror",
        "o7.seed.rp-gate3-oserror",
        "o7.seed.rp-gate4-oserror",
        "o7.seed.rp-gate2-interrupt",
        "o7.seed.rp-gate3-interrupt",
        "o7.seed.rp-gate4-interrupt",
        "o7.control.run1",
    ),
    "o7.proofkit-more-isolated-edges": (
        "o7.seed.pk2-census-validate-mismatch",
        "o7.seed.pk2-census-shas-missing",
        "o7.seed.pk2-inspect-git-error",
        "o7.seed.pk2-inspect-compiler-missing",
        "o7.seed.pk2-pin-write-probe",
        "o7.seed.pk2-pin-write-probe-dirty",
        "o7.seed.pk2-inspect-diff-error",
        "o7.seed.pk2-inspect-compiler-stat",
        "o7.seed.pk2-inspect-no-nm",
        "o7.seed.pk2-pin-write-type",
        "o7.seed.pk2-pin-write-dirty",
        "o7.seed.pk2-identity-git-error",
        "o7.seed.pk2-identity-compiler-stat",
        "o7.seed.pk2-schema-missing-key",
        "o7.seed.pk2-schema-skip-unrenderable",
        "o7.seed.pk2-schema-sentinel-unrenderable",
        "o7.seed.pk2-parser-shlex-error",
        "o7.seed.pk2-parser-literal-dollar",
        "o7.seed.pk2-parser-render-command",
        "o7.seed.pk2-parser-backtick-unclosed",
        "o7.seed.pk2-parser-nested-expansion",
        "o7.seed.pk2-parser-nested-command-open",
        "o7.seed.pk2-parser-nested-backtick-open",
        "o7.seed.pk2-parser-unquoted-backtick",
        "o7.seed.pk2-parser-unquoted-backtick-open",
        "o7.seed.pk2-parser-dequote-expansion-open",
        "o7.seed.pk2-identity-not-descendant",
        "o7.seed.pk2-identity-no-timeout",
        "o7.seed.pk2-identity-no-nm",
        "o7.seed.pk2-report-chain-invalid",
        "o7.seed.pk2-report-chain-mismatch",
        "o7.seed.pk2-report-listdir",
        "o7.seed.pk2-process-wait",
        "o7.seed.pk2-process-stop",
        "o7.seed.pk2-process-leader-survives",
        "o7.seed.pk2-process-zombie-remains",
        "o7.seed.pk2-process-finally-stop",
        "o7.seed.pk2-process-residual-zombie",
        "o7.seed.pk2-process-parse",
        "o7.seed.pk2-process-ps-status",
        "o7.seed.pk2-run-bounded-sampler-error",
        "o7.seed.pk2-validator-env-unchanged",
        "o7.seed.pk2-schema-nonobject",
        "o7.seed.pk2-schema-bytes",
        "o7.seed.pk2-schema-path",
        "o7.seed.pk2-schema-duplicate-variant",
        "o7.seed.pk2-schema-duplicate-skip",
        "o7.seed.pk2-schema-sentinel-iyivar",
        "o7.seed.pk2-parser-command-open",
        "o7.seed.pk2-parser-backtick-open",
        "o7.seed.pk2-parser-echo-option",
        "o7.seed.pk2-parser-printf-option",
        "o7.seed.pk2-parser-template-brace",
        "s1.control.pin",
        "s2.control.census-all",
    ),
    "o7.runner-isolated-edges": (
        "o7.seed.rp2-run1-baseline-error",
        "o7.seed.rp2-run3-setup-error",
        "o7.seed.rp2-run3-execution-error",
        "o7.seed.rp2-run3-census-type",
        "o7.seed.rp2-run3-census-script-type",
        "o7.seed.rp2-run3-census-unreadable",
        "o7.seed.rp2-run3-driver-nonzero",
        "o7.seed.rp2-final-recorded-reason",
        "o7.seed.rp2-final-status-reason",
        "o7.seed.rp2-final-prerequisites-missing",
        "o7.seed.rp2-final-recompute-error",
        "o7.seed.rp2-latest-interrupted",
        "o7.seed.rp2-all-run1-stop",
        "o7.seed.rp2-all-run2-stop",
        "o7.seed.rp2-all-run3-refusal",
        "o7.seed.rp2-all-required-missing",
        "o7.seed.rp2-all-required-nonstr",
        "o7.seed.rp2-all-driver-stop",
        "o7.seed.rp-run1-missing-gate1",
        "o7.seed.rp-run1-missing-gate2",
        "o7.seed.rp-run1-missing-gate3",
        "o7.seed.rp-run1-missing-gate4",
        "o7.seed.rp-run3-prerequisite-invalid",
        "o7.seed.rp-run3-required-unreadable",
        "o7.seed.rp-run3-required-type",
        "o7.seed.rp-run3-requested-refusal",
        "o7.seed.rp-final-required-missing",
        "o7.seed.rp-final-required-type",
        "o7.seed.rp-attempts-missing",
        "o7.seed.rp-attempt-invalid",
        "o7.seed.rp-skip-malformed",
        "o7.seed.rp-baseline-census-type",
        "o7.seed.rp-rows-blank",
        "o7.seed.rp-rows-json",
        "o7.seed.rp-rows-object",
        "o7.seed.rp-required-exclusions-type",
        "o7.seed.rp-required-exclusions-entry",
        "o7.seed.rp-required-exclusions-program",
        "o7.seed.rp-required-p-nonzero",
        "o7.seed.rp-baseline-type",
        "o7.seed.rp-baseline-entry",
        "o7.seed.rp-prerequisites-missing",
        "o7.seed.rp-record-missing",
        "o7.seed.rp-record-shape",
        "o7.seed.rp-final-no-attempt",
        "o7.seed.rp-latest-missing",
        "o7.seed.rp-latest-interrupt-missing",
        "s1.control.pin",
        "s5.control.stage-chain",
    ),
    "o7.proofkit-isolated-edges": (
        "o7.seed.pk-git-error",
        "o7.seed.pk-platform-getconf-missing",
        "o7.seed.pk-platform-getconf-oserror",
        "o7.seed.pk-platform-getconf-status",
        "o7.seed.pk-platform-getconf-nondir",
        "o7.seed.pk-platform-mktemp-missing",
        "o7.seed.pk-platform-mktemp-oserror",
        "o7.seed.pk-platform-mktemp-status",
        "o7.seed.pk-platform-mktemp-nondir",
        "o7.seed.pk-compiler-env",
        "o7.seed.pk-roots-empty",
        "o7.seed.pk-probe-atime-retention",
        "o7.seed.pk-probe-exec-failure",
        "o7.seed.pk-probe-sha",
        "o7.seed.pk-probe-inode",
        "o7.seed.pk-probe-oserror",
        "o7.seed.pk-first-output",
        "o7.seed.pk-nm-output",
        "o7.seed.pk-census-set",
        "o7.seed.pk-census-invalid",
        "o7.seed.pk-census-shas-set",
        "o7.seed.pk-pin-load-invalid",
        "o7.seed.pk-pin-load-chain",
        "o7.seed.pk-pin-load-report",
        "o7.seed.pk-identity-p-dirty",
        "o7.seed.pk-identity-w-dirty",
        "o7.seed.pk-identity-product-diff",
        "o7.seed.pk-identity-compiler-missing",
        "o7.seed.pk-identity-stamp-missing",
        "o7.seed.pk-signal-missing",
        "o7.seed.pk-sampler-oserror",
        "o7.seed.pk-limit-invalid",
        "o7.seed.pk-grace-invalid",
        "o7.seed.pk-status-unknown",
        "o7.seed.pk-status-missing",
        "o7.seed.pk-parser-backtick",
        "o7.seed.pk-parser-trailing-dollar",
        "o7.seed.pk-parser-open-brace",
        "o7.seed.pk-parser-nested-command",
        "o7.seed.pk-parser-nested-backtick",
        "o7.seed.pk-parser-dequote",
        "o7.seed.pk-parser-render",
        "s1.control.pin",
        "amend-b.control.real-probe",
        "s2.control.census-all",
    ),
    "o7.validator-env-call-variant": (
        "o7.seed.validator-env-call-variant",
        "s2.control.census-all",
    ),
    "o7.validator-iyivar": (
        "o7.seed.validator-iyivar",
        "s2.control.census-all",
    ),
    "o7.validator-platform-guard": (
        "o7.seed.validator-platform-guard",
        "s2.control.census-all",
    ),
    "o7.final-required-rerun": (
        "o7.seed.final-required-rerun",
        "s5.control.stage-chain",
    ),
    "o7.guard-m01-python-realpath": (
        "o7.seed.guard-m01-python-realpath",
        "o7.control.guard-m01-python-realpath",
    ),
    "o7.guard-m02-census-changed": (
        "o7.seed.guard-m02-census-changed",
        "o7.control.guard-m02-census-changed",
    ),
    "o7.guard-m03-canonical-roots": (
        "o7.seed.guard-m03-canonical-roots",
        "o7.control.guard-m03-canonical-roots",
    ),
    "o7.guard-m04-timeout-realpath": (
        "o7.seed.guard-m04-timeout-realpath",
        "o7.control.guard-m04-timeout-realpath",
    ),
    "o7.guard-m05-nm-realpath": (
        "o7.seed.guard-m05-nm-realpath",
        "o7.control.guard-m05-nm-realpath",
    ),
    "o7.guard-m19-python-version": (
        "o7.seed.guard-m19-python-version",
        "o7.control.guard-m19-python-version",
    ),
    "o7.guard-m08-run3-disk": (
        "o7.seed.guard-m08-run3-disk",
        "o7.control.guard-m08-run3-disk",
    ),
    "o7.guard-m10-post-driver-identity": (
        "o7.seed.guard-m10-post-driver-identity",
        "o7.control.guard-m10-post-driver-identity",
    ),
    "o7.guard-m11-final-identity": (
        "o7.seed.guard-m11-final-identity",
        "o7.control.guard-m11-final-identity",
    ),
    "o7.guard-m12-final-unit": (
        "o7.seed.guard-m12-final-unit",
        "o7.control.guard-m12-final-unit",
    ),
    "o7.guard-m13-final-attempt": (
        "o7.seed.guard-m13-final-attempt",
        "o7.control.guard-m13-final-attempt",
    ),
    "o7.guard-m20-final-required": (
        "o7.seed.guard-m20-final-required",
        "o7.control.guard-m20-final-required",
    ),
    "o7.guard-m07-run3-no-refused": (
        "o7.seed.guard-m07-run3-no-refused",
        "o7.control.guard-m07-run3-no-refused",
    ),
    "o7.guard-m09-run3-census": (
        "o7.seed.guard-m09-run3-census",
        "o7.control.guard-m09-run3-census",
    ),
    "o7.guard-m14-baseline-header": (
        "o7.seed.guard-m14-baseline-header",
        "o7.control.guard-m14-baseline-header",
    ),
    "o7.amendment-e-work-roots": (
        "o7.seed.matcher-platform-two-level",
        "o7.seed.matcher-t-two-level",
        "o7.seed.matcher-outside-both",
        "o7.seed.platform-tmp-changed",
        "o7.seed.platform-tmp-probe",
        "o7.control.matcher-platform-work",
        "o7.control.matcher-t-work",
    ),
    "o7.main-identity-refusal": (
        "o7.seed.main-identity-refusal",
        "o7.control.route-a",
    ),
    "o7.all-command": (
        "s5.seed.run3-driver-timeout",
        "o7.control.all",
    ),
    "o7.pin-command": (
        "s1.seed.pin-report-nonempty",
        "o7.control.pin-command",
    ),
    "o7.shim-parser-edges": (
        "o7.seed.shim-parser-edges",
        "s3.control.run",
    ),
    "o7.artifact-session-kill": (
        "o7.seed.artifact-session-kill",
        "s4.control.row",
    ),
    "o7.final": (
        "s5.seed.final-forged-pass",
        "s5.seed.final-missing-result",
        "s5.seed.final-chain-mismatch",
        "s5.seed.final-earlier-failure-omitted",
        "s5.control.stage-chain",
    ),
    "o7.run1-gates": (
        "s5.seed.run1-slow-gate",
        "o7.seed.coverage-run1-gate1-fail",
        "o7.seed.coverage-run1-identity",
        "o7.seed.coverage-run1-disk",
        "s5.seed.rg2r-zero",
        "s5.seed.run1-missing-sentinel",
        "s5.seed.rg9-140",
        "s5.seed.sibling-count-114",
        "o7.control.run1",
    ),
    "o7.run1-artifacts": (
        "s5.seed.exclusions-wrong-location",
        "s5.seed.sample-exclusion",
        "o7.control.run1",
    ),
    "o7.run2-branches": (
        "o7.seed.coverage-run2-identity",
        "o7.seed.coverage-run2-disk",
        "o7.seed.coverage-run2-stop",
        "o7.seed.coverage-run2-fail",
        "o7.seed.coverage-run2-count",
        "o7.seed.coverage-run2-missing-report",
        "s5.control.stage-chain",
    ),
    "o7.run3-selection": (
        "s5.seed.std-exclusion",
        "s5.seed.p-nonzero-not-added",
        "o7.control.required-selection",
    ),
    "o7.run3-setup": (
        "s5.seed.run3-missing-prerequisite",
        "s5.seed.required-mismatch",
        "s5.seed.binary-changed",
        "o7.control.run3-prerequisite",
    ),
    "o7.run3-end-to-end": (
        "s5.seed.run3-import",
        "s5.seed.run3-driver-timeout",
        "s5.seed.skip-env-blocked",
        "s5.seed.skip-partial",
        "s5.seed.skip-platform",
        "s5.seed.driver-missing-sentinel",
        "s5.seed.driver-stale-ledger",
        "s5.seed.census-missing-continues",
        "s5.seed.driver-missing-continues",
        "s5.control.stage-chain",
    ),
    "o7.route-a-refusal": (
        "s5.seed.route-a-drivers",
        "o7.control.route-a",
    ),
    "o7.optimize-refusal": (
        "o7.seed.run-proof-optimize-refusal",
        "o7.control.run-proof-optimize",
    ),
    "o7.d4-stage-interrupt": (
        "o7.seed.d4-stage-interrupt",
        "o7.control.run1",
    ),
}


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
        "amend-b.seed.probe-stat-mutates",
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
        "amend-b.seed.probe-stat-mutates",
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
        "amend-b.seed.probe-stat-mutates",
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
        "amend-b.seed.probe-stat-mutates",
        "seed",
        _fixture_probe_stat_mutates_seed,
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
        1240,
        1241,
        "s3.control.passthrough",
        "subprocess main dispatches passthrough ExecPlan to the sole os.execv "
        "site; fake REAL records preserved argv and environment",
    ),
    (
        "proof.roundtrip_shim",
        1244,
        1255,
        "s3.control.passthrough",
        "subprocess parses --config/-- in main and takes the ExecPlan branch",
    ),
    (
        "proof.roundtrip_shim",
        1256,
        1256,
        "s3.control.canonical-build",
        "subprocess main returns the canonical producer/consumer roundtrip rc",
    ),
    (
        "proof.roundtrip_shim",
        1259,
        1260,
        "s3.control.canonical-build",
        "top-level entry raises SystemExit from the exercised "
        "main-to-roundtrip path",
    ),
    (
        "proof.run_proof",
        1524,
        1530,
        "o7.seed.run-proof-optimize-refusal",
        "python -B -O proof/run_proof.py --help enters the nested optimize "
        "guard, prints the exact refusal, and exits 2",
    ),
    (
        "proof.run_proof",
        1531,
        1531,
        "o7.control.run-proof-optimize",
        "python -B proof/run_proof.py --help reaches the normal direct-script "
        "main handoff and exits 0",
    ),
    (
        "proof.artifact_legs",
        797,
        798,
        "s4.control.counts",
        "python -B proof/artifact_legs.py with an empty zero-count corpus "
        "reaches the direct-script main handoff, reports a passing summary, "
        "and exits 0",
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
                    "-X",
                    f"pycache_prefix={os.path.join(trace_dir, 'pycache')}",
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
