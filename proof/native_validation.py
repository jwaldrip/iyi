#!/usr/bin/env python3
"""
Narrow native validation helper for Remote Strict Controller.

Executed in a fresh subprocess to validate native stage records and final results
against W, verifying that imported modules originate strictly from W.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
from typing import Any, Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.remote_strict_fixtures import FINAL_LIMITS


class ModuleOriginError(Exception):
    """Raised when imported proof modules do not originate from expected W path."""


def verify_module_origins(w_path: str) -> tuple[Any, Any]:
    """
    Import proof.proofkit and proof.run_proof ensuring they originate strictly within w_path/proof.
    Returns (proofkit_mod, run_proof_mod).
    """
    if not w_path:
        raise ModuleOriginError("w_path is empty or None")

    w_real = os.path.realpath(w_path)
    proof_dir = os.path.join(w_real, "proof")

    if not os.path.isdir(proof_dir):
        raise ModuleOriginError(
            f"MISSING-W-MODULE: W proof directory does not exist: {proof_dir}"
        )

    for mod_filename in ("proofkit.py", "run_proof.py"):
        mod_file = os.path.join(proof_dir, mod_filename)
        if not os.path.isfile(mod_file):
            raise ModuleOriginError(
                f"MISSING-W-MODULE: Canonical {mod_filename} not found in {proof_dir}"
            )

    # Invalidate and reload proof modules in sys.modules to ensure clean import from w_real
    for mod_name in list(sys.modules.keys()):
        if mod_name == "proof" or mod_name.startswith("proof.") or mod_name in ("proofkit", "run_proof"):
            del sys.modules[mod_name]

    # Prepend W path so 'proof.proofkit' resolves to w_real/proof/proofkit.py
    if sys.path[0] != w_real:
        sys.path.insert(0, w_real)

    try:
        proofkit_mod = importlib.import_module("proof.proofkit")
    except Exception as exc:
        raise ModuleOriginError(f"FAILED-TO-IMPORT: proof.proofkit from {proof_dir}: {exc}") from exc

    try:
        run_proof_mod = importlib.import_module("proof.run_proof")
    except Exception as exc:
        raise ModuleOriginError(f"FAILED-TO-IMPORT: proof.run_proof from {proof_dir}: {exc}") from exc

    # Strictly verify module files originate from w_real/proof/
    for mod, expected_filename in ((proofkit_mod, "proofkit.py"), (run_proof_mod, "run_proof.py")):
        mod_file = getattr(mod, "__file__", None)
        if not mod_file:
            raise ModuleOriginError(f"MODULE-ORIGIN-VIOLATION: {expected_filename} has no __file__")
        mod_file_real = os.path.realpath(mod_file)
        expected_file_real = os.path.realpath(os.path.join(proof_dir, expected_filename))

        if mod_file_real != expected_file_real:
            raise ModuleOriginError(
                f"MODULE-ORIGIN-VIOLATION: {expected_filename} imported from {mod_file_real} "
                f"which does not match expected {expected_file_real}"
            )

        try:
            common = os.path.commonpath([w_real, mod_file_real])
            if common != w_real:
                raise ModuleOriginError(
                    f"MODULE-ORIGIN-VIOLATION: {expected_filename} imported from {mod_file_real} "
                    f"outside w_path {w_real}"
                )
        except ValueError as exc:
            raise ModuleOriginError(
                f"MODULE-ORIGIN-VIOLATION: Path comparison error for {expected_filename}: {exc}"
            ) from exc

    # Verify proofkit used by run_proof_mod also originates from W
    rp_pk = getattr(run_proof_mod, "proofkit", None)
    if rp_pk is not None:
        rp_pk_file = getattr(rp_pk, "__file__", None)
        if rp_pk_file:
            rp_pk_real = os.path.realpath(rp_pk_file)
            expected_pk = os.path.realpath(os.path.join(proof_dir, "proofkit.py"))
            if rp_pk_real != expected_pk:
                raise ModuleOriginError(
                    f"MODULE-ORIGIN-VIOLATION: run_proof uses proofkit from {rp_pk_real} != {expected_pk}"
                )

    return proofkit_mod, run_proof_mod


def _latest_record(report_dir: str, unit: str) -> dict[str, Any] | None:
    """Find the numerically highest attempt result in report_dir/unit."""
    unit_dir = os.path.join(report_dir, unit)
    if not os.path.isdir(unit_dir):
        return None

    highest_attempt = -1
    best_record_path: str | None = None
    try:
        for entry in os.listdir(unit_dir):
            m = re.fullmatch(r"a([1-9][0-9]*)", entry)
            if m:
                att = int(m.group(1))
                res_path = os.path.join(unit_dir, entry, "result.json")
                if att > highest_attempt and os.path.isfile(res_path):
                    highest_attempt = att
                    best_record_path = res_path
    except OSError:
        return None

    if best_record_path:
        try:
            with open(best_record_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            return None
    return None


def validate_record_native(
    record: dict[str, Any] | None,
    *,
    pin: dict[str, Any],
    unit: str,
    attempt: int,
    kind: str,
    w_path: str,
) -> tuple[str, list[str]]:
    """
    Validate stage result record schema, identity, attempt, and required checks.
    Uses canonical proofkit and run_proof imported strictly from w_path.
    Returns (status, reasons).
    """
    proofkit_mod, run_proof_mod = verify_module_origins(w_path)

    if record is None:
        return "FAIL", [f"{unit} attempt {attempt} result is missing or unreadable"]

    reasons: list[str] = []
    started_ns = record.get("started_ns")
    ended_ns = record.get("ended_ns")

    shape_ok = (
        record.get("v") == 1
        and isinstance(record.get("reasons"), list)
        and isinstance(record.get("checks"), dict)
        and isinstance(started_ns, int)
        and not isinstance(started_ns, bool)
        and isinstance(ended_ns, int)
        and not isinstance(ended_ns, bool)
        and isinstance(record.get("survivors"), list)
    )
    if not shape_ok:
        reasons.append(f"{unit} attempt {attempt} has an invalid result shape")

    if record.get("chain_id") != pin.get("chain_id"):
        reasons.append(f"{unit} attempt {attempt} chain_id mismatch")

    if record.get("unit") != unit:
        reasons.append(f"{unit} attempt {attempt} unit mismatch")

    if record.get("attempt") != attempt:
        reasons.append(f"{unit} attempt {attempt} path/result attempt mismatch")

    # Canonical status recomputation from W module
    recompute_fn = getattr(run_proof_mod, "recompute_status", None) or getattr(proofkit_mod, "recompute_status", None)
    if recompute_fn is not None:
        computed = str(recompute_fn(record, kind))
    else:
        # Fallback to W's internal _validate_record if available
        val_fn = getattr(run_proof_mod, "_validate_record", None)
        if val_fn is not None:
            return val_fn(record, pin=pin, unit=unit, attempt=attempt, kind=kind)
        computed = "FAIL"

    stored_status = record.get("status")
    if stored_status != computed:
        reasons.append(
            f"{unit} attempt {attempt} forged status "
            f"stored={stored_status!r} recomputed={computed!r}"
        )

    if reasons:
        return "FAIL", reasons
    return computed, []


def validate_final_native(
    final_data: dict[str, Any] | None,
    *,
    pin: dict[str, Any],
    required_drivers: Sequence[str],
    w_path: str,
    report_dir: str | None = None,
) -> tuple[bool, list[str]]:
    """
    Validate final.json structure, chain identity, and complete required driver inventory.
    Strictly verifies W module origins and returns (is_valid, reasons).
    """
    proofkit_mod, run_proof_mod = verify_module_origins(w_path)

    if final_data is None:
        return False, ["final.json is missing or unreadable"]

    reasons: list[str] = []
    if final_data.get("v") != 1:
        reasons.append(f"final.json version is {final_data.get('v')!r} (expected 1)")

    if final_data.get("chain_id") != pin.get("chain_id"):
        reasons.append(
            f"final.json chain_id {final_data.get('chain_id')!r} != pin chain_id {pin.get('chain_id')!r}"
        )

    # Validate identity dict matching pin
    identity = final_data.get("identity")
    if not isinstance(identity, dict):
        reasons.append("final.json missing or invalid identity dictionary")
    else:
        if identity.get("status") != "PASS":
            reasons.append(f"final.json identity status is {identity.get('status')!r} (expected 'PASS')")

        for k in ("p_source_sha", "w_head", "compiler_sha256"):
            if k in pin and identity.get(k) != pin[k]:
                reasons.append(
                    f"final.json identity {k} {identity.get(k)!r} != pin {pin[k]!r}"
                )

    # Validate limits matching canonical limits
    canonical_limits = getattr(run_proof_mod, "_FINAL_LIMITS", None) or FINAL_LIMITS
    limits = final_data.get("limits")
    if not isinstance(limits, list) or list(limits) != list(canonical_limits):
        reasons.append("final.json limits mismatch canonical final limits")

    # Validate status
    status = final_data.get("status")
    if status != "PASS":
        reasons.append(f"final.json status is {status!r} (expected 'PASS')")

    # Validate units dictionary
    units = final_data.get("units")
    if not isinstance(units, dict):
        reasons.append("final.json units is not a dictionary")
        return False, reasons

    # Validate core stages
    for core_unit in ("run1", "run2"):
        if core_unit not in units:
            reasons.append(f"final.json units missing core stage {core_unit!r}")
        else:
            u_info = units[core_unit]
            if (
                not isinstance(u_info, dict)
                or u_info.get("status") != "PASS"
                or not isinstance(u_info.get("attempt"), int)
                or u_info.get("attempt") < 1
            ):
                reasons.append(f"final.json stage {core_unit!r} status is not PASS or invalid attempt: {u_info}")

    # Validate exact required inventory with exact run3/<driver> keys
    for driver in required_drivers:
        key = f"run3/{driver}"
        if key not in units:
            reasons.append(f"final.json units missing required driver {driver!r} (expected key {key!r})")
        else:
            u_info = units[key]
            if (
                not isinstance(u_info, dict)
                or u_info.get("status") != "PASS"
                or not isinstance(u_info.get("attempt"), int)
                or u_info.get("attempt") < 1
            ):
                reasons.append(f"final.json required driver {driver!r} status is not PASS or invalid attempt: {u_info}")

    # Reject bare driver aliases (e.g. 'cookie' instead of 'run3/cookie')
    for driver in required_drivers:
        if driver in units:
            reasons.append(f"final.json units contains bare driver alias {driver!r} without run3/ prefix")

    # Reject unexpected extra units
    expected_keys = {"run1", "run2"} | {f"run3/{d}" for d in required_drivers}
    extra_keys = set(units.keys()) - expected_keys
    if extra_keys:
        reasons.append(f"final.json units contains unexpected units: {sorted(extra_keys)!r}")

    # Validate prerequisite ordering and timestamps if report_dir is available
    if report_dir and os.path.isdir(report_dir):
        run1_rec = _latest_record(report_dir, "run1")
        run2_rec = _latest_record(report_dir, "run2")
        prereq_ends = (
            run1_rec.get("ended_ns") if isinstance(run1_rec, dict) else None,
            run2_rec.get("ended_ns") if isinstance(run2_rec, dict) else None,
        )
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in prereq_ends):
            reasons.append("latest run1/run2 results have no valid ended_ns")
        else:
            latest_prereq_end = max(prereq_ends)  # type: ignore
            for driver in required_drivers:
                unit_key = f"run3/{driver}"
                rec = _latest_record(report_dir, unit_key)
                started_ns = rec.get("started_ns") if isinstance(rec, dict) else None
                if (
                    not isinstance(started_ns, int)
                    or isinstance(started_ns, bool)
                    or started_ns <= latest_prereq_end
                ):
                    reasons.append(f"{unit_key} latest attempt is not newer than latest run1/run2")

    if reasons:
        return False, reasons
    return True, []


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Narrow native validation helper")
    parser.add_argument("--mode", choices=["record", "final"], required=True)
    parser.add_argument("--w", required=True, help="Path to clean W checkout")
    parser.add_argument("--pin", required=True, help="Path to pin.json")
    parser.add_argument("--record", help="Path to stage result.json")
    parser.add_argument("--unit", help="Unit name")
    parser.add_argument("--attempt", type=int, help="Attempt number")
    parser.add_argument("--kind", help="Stage kind (run1, run2, run3)")
    parser.add_argument("--final", help="Path to final.json")
    parser.add_argument("--required", help="Path to required.json")
    parser.add_argument("--report-dir", help="Path to report_dir for checking prerequisite ordering")
    args = parser.parse_args(argv)

    try:
        with open(args.pin, "r", encoding="utf-8") as f:
            pin = json.load(f)
    except Exception as exc:
        print(json.dumps({"valid": False, "status": "FAIL", "reasons": [f"Failed to load pin: {exc}"], "error": f"Failed to load pin: {exc}"}))
        return 1

    if args.mode == "record":
        if not args.record or not args.unit or args.attempt is None or not args.kind:
            err = "Missing required arguments for mode=record"
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err], "error": err}))
            return 2

        record: dict[str, Any] | None = None
        if os.path.isfile(args.record):
            try:
                with open(args.record, "r", encoding="utf-8") as f:
                    record = json.load(f)
            except Exception as exc:
                err = f"Failed to read record: {exc}"
                print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err], "error": err}))
                return 1

        try:
            status, reasons = validate_record_native(
                record,
                pin=pin,
                unit=args.unit,
                attempt=args.attempt,
                kind=args.kind,
                w_path=args.w,
            )
            is_valid = (status == "PASS" and not reasons)
            out = {
                "valid": is_valid,
                "status": status,
                "reasons": reasons,
                "error": None if is_valid else (reasons[0] if reasons else "Validation rejected"),
            }
            print(json.dumps(out))
            return 0 if is_valid else 3
        except ModuleOriginError as exc:
            err_msg = str(exc)
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err_msg], "error": err_msg}))
            return 4
        except Exception as exc:
            err_msg = f"Validation exception: {exc}"
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err_msg], "error": err_msg}))
            return 1

    elif args.mode == "final":
        if not args.final or not args.required:
            err = "Missing required arguments for mode=final"
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err], "error": err}))
            return 2

        final_data: dict[str, Any] | None = None
        if os.path.isfile(args.final):
            try:
                with open(args.final, "r", encoding="utf-8") as f:
                    final_data = json.load(f)
            except Exception as exc:
                err = f"Failed to read final: {exc}"
                print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err], "error": err}))
                return 1

        try:
            with open(args.required, "r", encoding="utf-8") as f:
                required_drivers = json.load(f)
        except Exception as exc:
            err = f"Failed to read required.json: {exc}"
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err], "error": err}))
            return 1

        try:
            is_valid, reasons = validate_final_native(
                final_data,
                pin=pin,
                required_drivers=required_drivers,
                w_path=args.w,
                report_dir=args.report_dir or (os.path.dirname(args.final) if args.final else None),
            )
            out = {
                "valid": is_valid,
                "status": final_data.get("status") if (final_data and is_valid) else "FAIL",
                "reasons": reasons,
                "error": None if is_valid else (reasons[0] if reasons else "Final validation rejected"),
            }
            print(json.dumps(out))
            return 0 if is_valid else 3
        except ModuleOriginError as exc:
            err_msg = str(exc)
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err_msg], "error": err_msg}))
            return 4
        except Exception as exc:
            err_msg = f"Final validation exception: {exc}"
            print(json.dumps({"valid": False, "status": "FAIL", "reasons": [err_msg], "error": err_msg}))
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
