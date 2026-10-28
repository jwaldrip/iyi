#!/usr/bin/env python3
"""
Truthful synthetic proof harness for the native stale-testing acceptance.

Registered fixtures emit machine-auditable seed or control lines. REVIEW_ITEMS
keeps an incomplete repair red until every required seed and control executes.
"""

from __future__ import annotations

import ast
import glob
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass


if __name__ == "__main__" and sys.flags.optimize:
    print(
        f"smoke_test.py refuses optimized Python: sys.flags.optimize={sys.flags.optimize}",
        file=sys.stderr,
    )
    raise SystemExit(2)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.proofkit import base_env


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
