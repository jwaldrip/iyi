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
import sys
from typing import Any, Sequence

# Canonical check names matching W proofkit.py:1180-1202
REQUIRED_CHECKS: dict[str, tuple[str, ...]] = {
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


class ModuleOriginError(Exception):
    """Raised when imported proof modules do not originate from expected W path."""


def verify_module_origins(w_path: str) -> tuple[Any, Any]:
    """
    Import proofkit and run_proof ensuring they originate strictly within w_path.
    Returns (proofkit_mod, run_proof_mod).
    """
    w_real = os.path.realpath(w_path)
    proof_dir = os.path.join(w_real, "proof")

    # Prepend W proof directory to sys.path
    if proof_dir not in sys.path:
        sys.path.insert(0, proof_dir)
    if w_real not in sys.path:
        sys.path.insert(1, w_real)

    # Invalidate and reload proof modules to ensure clean import
    for mod_name in ("proofkit", "run_proof"):
        if mod_name in sys.modules:
            del sys.modules[mod_name]

    try:
        proofkit_mod = importlib.import_module("proofkit")
    except ImportError:
        proofkit_mod = None

    try:
        run_proof_mod = importlib.import_module("run_proof")
    except ImportError:
        run_proof_mod = None

    for mod, name in ((proofkit_mod, "proofkit"), (run_proof_mod, "run_proof")):
        if mod is not None and getattr(mod, "__file__", None):
            mod_file_real = os.path.realpath(mod.__file__)
            try:
                common = os.path.commonpath([w_real, mod_file_real])
                if common != w_real:
                    raise ModuleOriginError(
                        f"MODULE-ORIGIN-VIOLATION: {name} imported from {mod_file_real} "
                        f"which is outside w_path {w_real}"
                    )
            except ValueError as exc:
                raise ModuleOriginError(
                    f"MODULE-ORIGIN-VIOLATION: {name} path error: {exc}"
                ) from exc

    return proofkit_mod, run_proof_mod


def recompute_native_status(record: dict[str, Any], kind: str, w_path: str | None = None) -> str:
    """
    Recompute stage status from required checks.
    Uses W's proofkit.recompute_status if available, else reference implementation.
    """
    if w_path:
        try:
            proofkit_mod, _ = verify_module_origins(w_path)
            if proofkit_mod and hasattr(proofkit_mod, "recompute_status"):
                return str(proofkit_mod.recompute_status(record, kind))
        except ModuleOriginError:
            raise
        except Exception:
            pass

    required = REQUIRED_CHECKS.get(kind)
    checks = record.get("checks")
    if required is None or not isinstance(checks, dict):
        return "FAIL"
    for name in required:
        if name in checks and checks[name] != "PASS":
            val = checks[name]
            return str(val) if isinstance(val, str) else "FAIL"
    if any(name not in checks for name in required):
        return "FAIL"
    return "PASS"


def validate_record_native(
    record: dict[str, Any] | None,
    *,
    pin: dict[str, Any],
    unit: str,
    attempt: int,
    kind: str,
    w_path: str | None = None,
) -> tuple[str, list[str]]:
    """
    Validate stage result record schema, identity, attempt, and required checks.
    Ensures status is not forged and returns (status, reasons).
    """
    if record is None:
        return "FAIL", [f"{unit} attempt {attempt} result is missing or unreadable"]

    if w_path:
        proofkit_mod, run_proof_mod = verify_module_origins(w_path)
        if run_proof_mod and hasattr(run_proof_mod, "_validate_record"):
            return run_proof_mod._validate_record(
                record,
                pin=pin,
                unit=unit,
                attempt=attempt,
                kind=kind,
            )

    reasons: list[str] = []
    shape_ok = (
        record.get("v") == 1
        and isinstance(record.get("reasons"), list)
        and isinstance(record.get("checks"), dict)
        and isinstance(record.get("started_ns"), int)
        and isinstance(record.get("ended_ns"), int)
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

    computed = recompute_native_status(record, kind, w_path=w_path)
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
    w_path: str | None = None,
) -> tuple[bool, list[str]]:
    """
    Validate final.json structure, chain identity, and complete required driver inventory.
    Returns (is_valid, reasons).
    """
    if final_data is None:
        return False, ["final.json is missing or unreadable"]

    reasons: list[str] = []
    if final_data.get("v") != 1:
        reasons.append(f"final.json version is {final_data.get('v')!r} (expected 1)")

    if final_data.get("chain_id") != pin.get("chain_id"):
        reasons.append(
            f"final.json chain_id {final_data.get('chain_id')!r} != pin chain_id {pin.get('chain_id')!r}"
        )

    for sha_key in ("p_sha", "w_sha", "compiler_sha"):
        if sha_key in pin and sha_key in final_data:
            if final_data[sha_key] != pin[sha_key]:
                reasons.append(
                    f"final.json {sha_key} {final_data[sha_key]!r} != pin {pin[sha_key]!r}"
                )

    status = final_data.get("status")
    if status != "PASS":
        reasons.append(f"final.json status is {status!r} (expected 'PASS')")

    units = final_data.get("units")
    if not isinstance(units, dict):
        reasons.append("final.json units is not a dictionary")
        return False, reasons

    # Validate run1 and run2
    for core_unit in ("run1", "run2"):
        if core_unit not in units:
            reasons.append(f"final.json units missing core stage {core_unit!r}")
        else:
            u_info = units[core_unit]
            if not isinstance(u_info, dict) or u_info.get("status") != "PASS":
                reasons.append(f"final.json stage {core_unit!r} status is not PASS: {u_info}")

    # Validate all required drivers in frozen inventory
    for driver in required_drivers:
        key = f"run3/{driver}"
        matched = False
        if key in units:
            matched = True
            u_info = units[key]
        elif driver in units:
            matched = True
            u_info = units[driver]

        if not matched:
            reasons.append(f"final.json units missing required driver {driver!r}")
        else:
            if not isinstance(u_info, dict) or u_info.get("status") != "PASS":
                reasons.append(f"final.json required driver {driver!r} status is not PASS: {u_info}")

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
    args = parser.parse_args(argv)

    try:
        with open(args.pin, "r", encoding="utf-8") as f:
            pin = json.load(f)
    except Exception as exc:
        print(json.dumps({"valid": False, "error": f"Failed to load pin: {exc}"}))
        return 1

    if args.mode == "record":
        if not args.record or not args.unit or args.attempt is None or not args.kind:
            print(json.dumps({"valid": False, "error": "Missing required arguments for mode=record"}))
            return 2

        record: dict[str, Any] | None = None
        if os.path.isfile(args.record):
            try:
                with open(args.record, "r", encoding="utf-8") as f:
                    record = json.load(f)
            except Exception as exc:
                print(json.dumps({"valid": False, "error": f"Failed to read record: {exc}"}))
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
            }
            print(json.dumps(out))
            return 0 if is_valid else 3
        except ModuleOriginError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}))
            return 4
        except Exception as exc:
            print(json.dumps({"valid": False, "error": f"Validation exception: {exc}"}))
            return 1

    elif args.mode == "final":
        if not args.final or not args.required:
            print(json.dumps({"valid": False, "error": "Missing required arguments for mode=final"}))
            return 2

        final_data: dict[str, Any] | None = None
        if os.path.isfile(args.final):
            try:
                with open(args.final, "r", encoding="utf-8") as f:
                    final_data = json.load(f)
            except Exception as exc:
                print(json.dumps({"valid": False, "error": f"Failed to read final: {exc}"}))
                return 1

        try:
            with open(args.required, "r", encoding="utf-8") as f:
                required_drivers = json.load(f)
        except Exception as exc:
            print(json.dumps({"valid": False, "error": f"Failed to read required.json: {exc}"}))
            return 1

        try:
            is_valid, reasons = validate_final_native(
                final_data,
                pin=pin,
                required_drivers=required_drivers,
                w_path=args.w,
            )
            out = {
                "valid": is_valid,
                "status": final_data.get("status") if final_data else "NONE",
                "reasons": reasons,
            }
            print(json.dumps(out))
            return 0 if is_valid else 3
        except ModuleOriginError as exc:
            print(json.dumps({"valid": False, "error": str(exc)}))
            return 4
        except Exception as exc:
            print(json.dumps({"valid": False, "error": f"Final validation exception: {exc}"}))
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
